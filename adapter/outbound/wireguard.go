package outbound

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/atomic"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/proxydialer"
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/component/slowdown"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/dns"
	"github.com/metacubex/mihomo/log"

	amnezia "github.com/metacubex/amneziawg-go/device"
	wireguard "github.com/metacubex/sing-wireguard"
	wgconn "github.com/metacubex/wireguard-go/conn"
	"github.com/metacubex/wireguard-go/device"

	"github.com/metacubex/sing/common/debug"
	E "github.com/metacubex/sing/common/exceptions"
	M "github.com/metacubex/sing/common/metadata"
)

type wireguardGoDevice interface {
	Close()
	IpcSet(uapiConf string) error
}

// wireGuardBind 抽象 UDP（sing ClientBind）与 TCP（自定义）两种 transport，
// 统一暴露 wireguard-go conn.Bind 及 ClientBind 的附加方法。
type wireGuardBind interface {
	wgconn.Bind
	SetConnectAddr(netip.AddrPort)
	SetReservedForEndpoint(netip.AddrPort, [3]byte)
	ResetReservedForEndpoint()
	SetParseReserved(bool)
}

type WireGuard struct {
	*Base
	bind      wireGuardBind
	device    wireguardGoDevice
	tunDevice wireguard.Device
	resolver  resolver.Resolver

	initOk        atomic.Bool
	initMutex     sync.Mutex
	initErr       error
	option        WireGuardOption
	connectAddr   M.Socksaddr
	localPrefixes []netip.Prefix

	serverAddrMap   map[M.Socksaddr]netip.AddrPort
	serverAddrTime  atomic.TypedValue[time.Time]
	serverAddrMutex sync.Mutex

	// busyFail 记录连续业务失败（业务 dial 超时/隧道内连接失败）次数。
	// 达到阈值（busyFailThreshold）时视为隧道 unhealthy，主动失效底层
	// TCP 连接并触发受控重连，解决"连接看似存在但数据面无响应"的静默断链。
	busyFail        atomic.Int32
	busyFailResetAt atomic.Int64 // unix nano，距上次失败超过窗口则重置计数
	corplinkRecoveryAt atomic.Int64 // unix nano，限制故障风暴期间的会话刷新频率
}

// busyFailThreshold 为业务连续失败触发重建的阈值。
const busyFailThreshold = 3

// busyFailWindow 为业务失败计数窗口：窗口内累计达到阈值才触发重建，
// 超过窗口未失败则重置，避免瞬时抖动误触发。
const busyFailWindow = 30 * time.Second

// tunnelFailureDialTimeout bounds the tunnel establishment portion of a
// business dial. The normal mihomo TCP timeout is too long when the TCP
// wrapper is connected but WireGuard never completes its handshake.
const tunnelFailureDialTimeoutValue = 3 * time.Second

func tunnelFailureDialTimeout() time.Duration { return tunnelFailureDialTimeoutValue }

// isTunnelFailure 判断业务错误是否属于"隧道数据面失败"（应触发重建）。
// DNS 解析失败/超时属于外部解析问题，不应误判为隧道不可用而反复重建。
func isTunnelFailure(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	// DNS 相关失败不计入隧道健康
	if strings.Contains(msg, "dns") || strings.Contains(msg, "resolve") ||
		strings.Contains(msg, "dns-query") || strings.Contains(msg, "no such host") {
		return false
	}
	// Do not classify every dial timeout as a tunnel failure. A target site can
	// be slow/unreachable while the shared WireGuard transport is healthy;
	// invalidating the transport after three unrelated target failures creates
	// the observed self-inflicted reconnect storm. Only explicit transport
	// failure markers are allowed to tear down the shared TCP-WireGuard link.
	for _, marker := range []string{
		"tunnel unavailable",
		"tunnel not ready",
		"handshake timeout",
		"use of closed network connection",
		"broken pipe",
		"connection reset by peer",
		"connection refused",
	} {
		if strings.Contains(msg, marker) {
			return true
		}
	}
	return false
}

// waitTunnelReady 等待当前 TCP 连接完成 WireGuard 握手（隧道 ready）。
// 返回 true 表示就绪；false 表示超时或连接不存在。仅 TCP 模式使用。
func (w *WireGuard) waitTunnelReady(ctx context.Context) bool {
	if !w.option.TCP {
		return true
	}
	tcpBind, ok := w.bind.(interface {
		IsConnReady(string) bool
	})
	if !ok {
		return true
	}
	ep := w.connectAddr.String()
	// 连接不存在（尚未建立）时直接放行，让 Send 触发建连
	if !tcpBind.IsConnReady(ep) {
		if waiter, ok := w.bind.(interface {
			WaitConnReady(string, time.Duration) bool
		}); ok {
			return waiter.WaitConnReady(ep, tunnelFailureDialTimeout())
		}
		// 等待 ready 或超时
		deadline := time.NewTimer(tunnelFailureDialTimeout())
		defer deadline.Stop()
		for {
			if tcpBind.IsConnReady(ep) {
				return true
			}
			select {
			case <-ctx.Done():
				return false
			case <-deadline.C:
				return false
			case <-time.After(200 * time.Millisecond):
			}
		}
	}
	return true
}

// registerBusyFailure 登记一次业务失败；达到阈值时返回 true（调用方触发重建）。
func (w *WireGuard) registerBusyFailure() bool {
	now := time.Now().UnixNano()
	last := w.busyFailResetAt.Load()
	if now-last > int64(busyFailWindow) {
		w.busyFailResetAt.Store(now)
		w.busyFail.Store(0)
	}
	n := w.busyFail.Add(1)
	if n >= busyFailThreshold {
		// 达到阈值：重置计数，下次成功后从 0 开始
		w.busyFail.Store(0)
		return true
	}
	return false
}

// recordBusySuccess 业务成功时清零失败计数。
func (w *WireGuard) recordBusySuccess() {
	w.busyFail.Store(0)
	w.busyFailResetAt.Store(time.Now().UnixNano())
}

// invalidateTunnelForBusyFailure 业务连续失败时失效隧道底层连接并触发重建。
func (w *WireGuard) invalidateTunnelForBusyFailure() {
	if w.option.TCP {
		if tcpBind, ok := w.bind.(interface {
			InvalidateEndpoint(string)
		}); ok {
			ep := w.connectAddr.String()
			log.Warnln("[WG](%s) tunnel unhealthy: %d consecutive business failures, invalidating TCP connection %s",
				w.option.Name, busyFailThreshold, ep)
			tcpBind.InvalidateEndpoint(ep)
			// Corplink can rotate the assigned tunnel IP/server peer while the
			// process is alive. Re-dialing TCP with the old wg_info repeatedly
			// produces the misleading pattern "TCP connected, handshake timeout".
			// Refresh the session parameters before the next connection attempt.
			w.refreshCorplinkAfterTunnelFailure()
		}
	}
}

func (w *WireGuard) refreshCorplinkAfterTunnelFailure() {
	if w.option.Corplink.APIServer == "" || w.device == nil {
		return
	}
	now := time.Now().UnixNano()
	last := w.corplinkRecoveryAt.Load()
	if last != 0 && now-last < int64(15*time.Second) {
		return
	}
	if !w.serverAddrMutex.TryLock() {
		return
	}
	defer w.serverAddrMutex.Unlock()
	// Re-check after acquiring the lock so concurrent failed dials coalesce
	// into one refresh instead of repeatedly rewriting the live WG device.
	now = time.Now().UnixNano()
	last = w.corplinkRecoveryAt.Load()
	if last != 0 && now-last < int64(15*time.Second) {
		return
	}
	w.corplinkRecoveryAt.Store(now)
	if err := refreshCorplinkOption(&w.option); err != nil {
		log.Warnln("[WG](%s) corplink refresh after tunnel failure failed: %v", w.option.Name, err)
		return
	}
	ipcConf, err := w.genIpcConf(context.Background(), true)
	if err != nil {
		log.Warnln("[WG](%s) failed to rebuild peer config after corplink refresh: %v", w.option.Name, err)
		return
	}
	if err := w.device.IpcSet(ipcConf); err != nil {
		log.Warnln("[WG](%s) failed to apply refreshed peer config: %v", w.option.Name, err)
		return
	}
	w.serverAddrTime.Store(time.Now())
	log.Infoln("[WG](%s) applied refreshed corplink peer parameters after tunnel failure", w.option.Name)
}

type WireGuardOption struct {
	BasicOption
	WireGuardPeerOption
	Name       string `proxy:"name"`
	Ip         string `proxy:"ip,omitempty"`
	Ipv6       string `proxy:"ipv6,omitempty"`
	PrivateKey string `proxy:"private-key"`
	Workers    int    `proxy:"workers,omitempty"`
	MTU        int    `proxy:"mtu,omitempty"`
	UDP        bool   `proxy:"udp,omitempty"`
	// TCP 使 wireguard 走 TCP transport（兼容 corplink-rs 的 TCP 封装），
	// 用于公司内部仅开放 TCP 的节点。默认 false（标准 UDP）。
	TCP                 bool `proxy:"tcp,omitempty"`
	PersistentKeepalive int  `proxy:"persistent-keepalive,omitempty"`

	// Corplink 认证（可选）：启用后启动时调用 corplink /vpn/conn API
	// 获取当前会话分配的隧道 IP 与服务器公钥，自动覆盖 ip/public-key。
	Corplink CorplinkOption `proxy:"corplink,omitempty"`

	AmneziaWGOption *AmneziaWGOption `proxy:"amnezia-wg-option,omitempty"`

	Peers []WireGuardPeerOption `proxy:"peers,omitempty"`

	RemoteDnsResolve bool     `proxy:"remote-dns-resolve,omitempty"`
	Dns              []string `proxy:"dns,omitempty"`

	RefreshServerIPInterval int `proxy:"refresh-server-ip-interval,omitempty"`
}

type WireGuardPeerOption struct {
	Server       string   `proxy:"server,omitempty"`
	Port         int      `proxy:"port,omitempty"`
	PublicKey    string   `proxy:"public-key,omitempty"`
	PreSharedKey string   `proxy:"pre-shared-key,omitempty"`
	Reserved     []uint8  `proxy:"reserved,omitempty"`
	AllowedIPs   []string `proxy:"allowed-ips,omitempty"`
}

type AmneziaWGOption struct {
	JC    int    `proxy:"jc,omitempty"`
	JMin  int    `proxy:"jmin,omitempty"`
	JMax  int    `proxy:"jmax,omitempty"`
	S1    int    `proxy:"s1,omitempty"`
	S2    int    `proxy:"s2,omitempty"`
	S3    int    `proxy:"s3,omitempty"`    // AmneziaWG v1.5 and v2
	S4    int    `proxy:"s4,omitempty"`    // AmneziaWG v1.5 and v2
	H1    string `proxy:"h1,omitempty"`    // In AmneziaWG v1.x, it was uint32, but our WeaklyTypedInput can handle this situation
	H2    string `proxy:"h2,omitempty"`    // In AmneziaWG v1.x, it was uint32, but our WeaklyTypedInput can handle this situation
	H3    string `proxy:"h3,omitempty"`    // In AmneziaWG v1.x, it was uint32, but our WeaklyTypedInput can handle this situation
	H4    string `proxy:"h4,omitempty"`    // In AmneziaWG v1.x, it was uint32, but our WeaklyTypedInput can handle this situation
	I1    string `proxy:"i1,omitempty"`    // AmneziaWG v1.5 and v2
	I2    string `proxy:"i2,omitempty"`    // AmneziaWG v1.5 and v2
	I3    string `proxy:"i3,omitempty"`    // AmneziaWG v1.5 and v2
	I4    string `proxy:"i4,omitempty"`    // AmneziaWG v1.5 and v2
	I5    string `proxy:"i5,omitempty"`    // AmneziaWG v1.5 and v2
	J1    string `proxy:"j1,omitempty"`    // AmneziaWG v1.5 only (removed in v2)
	J2    string `proxy:"j2,omitempty"`    // AmneziaWG v1.5 only (removed in v2)
	J3    string `proxy:"j3,omitempty"`    // AmneziaWG v1.5 only (removed in v2)
	Itime int64  `proxy:"itime,omitempty"` // AmneziaWG v1.5 only (removed in v2)
}

type wgSingErrorHandler struct {
	name string
}

var _ E.Handler = (*wgSingErrorHandler)(nil)

func (w wgSingErrorHandler) NewError(ctx context.Context, err error) {
	if E.IsClosedOrCanceled(err) {
		log.SingLogger.Debug(fmt.Sprintf("[WG](%s) connection closed: %s", w.name, err))
		return
	}
	log.SingLogger.Error(fmt.Sprintf("[WG](%s) %s", w.name, err))
}

type wgNetDialer struct {
	tunDevice wireguard.Device
}

var _ dialer.NetDialer = (*wgNetDialer)(nil)

func (d wgNetDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.tunDevice.DialContext(ctx, network, M.ParseSocksaddr(address).Unwrap())
}

func (option WireGuardPeerOption) Addr() M.Socksaddr {
	return M.ParseSocksaddrHostPort(option.Server, uint16(option.Port))
}

func (option WireGuardOption) Prefixes() ([]netip.Prefix, error) {
	localPrefixes := make([]netip.Prefix, 0, 2)
	if len(option.Ip) > 0 {
		if !strings.Contains(option.Ip, "/") {
			option.Ip = option.Ip + "/32"
		}
		if prefix, err := netip.ParsePrefix(option.Ip); err == nil {
			localPrefixes = append(localPrefixes, prefix)
		} else {
			return nil, E.Cause(err, "ip address parse error")
		}
	}
	if len(option.Ipv6) > 0 {
		if !strings.Contains(option.Ipv6, "/") {
			option.Ipv6 = option.Ipv6 + "/128"
		}
		if prefix, err := netip.ParsePrefix(option.Ipv6); err == nil {
			localPrefixes = append(localPrefixes, prefix)
		} else {
			return nil, E.Cause(err, "ipv6 address parse error")
		}
	}
	if len(localPrefixes) == 0 {
		return nil, E.New("missing local address")
	}
	return localPrefixes, nil
}

func NewWireGuard(option WireGuardOption) (*WireGuard, error) {
	outbound := &WireGuard{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         net.JoinHostPort(option.Server, strconv.Itoa(option.Port)),
			Type:         C.WireGuard,
			ProviderName: option.ProviderName,
			UDP:          option.UDP,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
	}
	outbound.dialer = option.NewDialer(outbound.DialOptions())
	singDialer := proxydialer.NewSingDialer(proxydialer.NewSlowDownDialer(outbound.dialer, slowdown.New()))

	var reserved [3]uint8
	if len(option.Reserved) > 0 {
		if len(option.Reserved) != 3 {
			return nil, E.New("invalid reserved value, required 3 bytes, got ", len(option.Reserved))
		}
		copy(reserved[:], option.Reserved)
	}
	var isConnect bool
	if len(option.Peers) < 2 {
		isConnect = true
		if len(option.Peers) == 1 {
			outbound.connectAddr = option.Peers[0].Addr()
		} else {
			outbound.connectAddr = option.Addr()
		}
	}
	if option.TCP {
		// TCP transport：直接连服务器（不依赖 sing dialer），兼容 corplink-rs 的 TCP 封装
		target := outbound.connectAddr
		log.Infoln("[WG](%s) using TCP transport, target=%s", option.Name, target)
		if option.Corplink.APIServer != "" {
			log.Infoln("[WG](%s) corplink auth enabled: api=%s cookie=%s", option.Name, option.Corplink.APIServer, option.Corplink.CookieFile)
		} else {
			log.Infoln("[WG](%s) corplink auth NOT enabled", option.Name)
		}
		outbound.bind = newTCPWireGuardBind(context.Background(), func(ctx context.Context) (net.Conn, error) {
			d := net.Dialer{}
			nc, err := d.DialContext(ctx, "tcp", target.String())
			if err != nil {
				return nil, err
			}
			return nc, nil
		})
	} else {
		outbound.bind = wireguard.NewClientBind(context.Background(), wgSingErrorHandler{outbound.Name()}, singDialer, isConnect, outbound.connectAddr.AddrPort(), reserved)
	}

	var err error
	outbound.localPrefixes, err = option.Prefixes()
	if err != nil {
		return nil, err
	}

	{
		bytes, err := base64.StdEncoding.DecodeString(option.PrivateKey)
		if err != nil {
			return nil, E.Cause(err, "decode private key")
		}
		option.PrivateKey = hex.EncodeToString(bytes)
	}

	if len(option.Peers) > 0 {
		for i := range option.Peers {
			peer := &option.Peers[i] // we need modify option here
			bytes, err := base64.StdEncoding.DecodeString(peer.PublicKey)
			if err != nil {
				return nil, E.Cause(err, "decode public key for peer ", i)
			}
			peer.PublicKey = hex.EncodeToString(bytes)

			if peer.PreSharedKey != "" {
				bytes, err := base64.StdEncoding.DecodeString(peer.PreSharedKey)
				if err != nil {
					return nil, E.Cause(err, "decode pre shared key for peer ", i)
				}
				peer.PreSharedKey = hex.EncodeToString(bytes)
			}

			if len(peer.AllowedIPs) == 0 {
				return nil, E.New("missing allowed_ips for peer ", i)
			}

			if len(peer.Reserved) > 0 {
				if len(peer.Reserved) != 3 {
					return nil, E.New("invalid reserved value for peer ", i, ", required 3 bytes, got ", len(peer.Reserved))
				}
			}
		}
	} else {
		{
			bytes, err := base64.StdEncoding.DecodeString(option.PublicKey)
			if err != nil {
				return nil, E.Cause(err, "decode peer public key")
			}
			option.PublicKey = hex.EncodeToString(bytes)
		}
		if option.PreSharedKey != "" {
			bytes, err := base64.StdEncoding.DecodeString(option.PreSharedKey)
			if err != nil {
				return nil, E.Cause(err, "decode pre shared key")
			}
			option.PreSharedKey = hex.EncodeToString(bytes)
		}
	}

	// corplink 认证：在创建 wireguard 栈设备前调用 corplink /vpn/conn API
	// 获取当前会话分配的隧道 IP 与服务器公钥，覆盖节点配置。
	// 此时 option.PublicKey 已统一为 hex 格式，fetch 返回的 hex 直接可用。
	if option.Corplink.APIServer != "" {
		if err := refreshCorplinkOption(&option); err != nil {
			return nil, err
		}
		outbound.localPrefixes, err = option.Prefixes()
		if err != nil {
			return nil, err
		}
		// 启动 cookie 过期检测：即将过期时自动执行 corplink --refresh-cookie
		corplinkCookieWatchdog(option.Corplink)
	}
	outbound.option = option

	mtu := option.MTU
	if mtu == 0 {
		mtu = 1408
	}
	if len(outbound.localPrefixes) == 0 {
		return nil, E.New("missing local address")
	}
	outbound.tunDevice, err = wireguard.NewStackDevice(outbound.localPrefixes, uint32(mtu))
	if err != nil {
		return nil, E.Cause(err, "create WireGuard device")
	}
	logger := &device.Logger{
		Verbosef: func(format string, args ...interface{}) {
			log.SingLogger.Debug(fmt.Sprintf("[WG](%s) %s", option.Name, fmt.Sprintf(format, args...)))
		},
		Errorf: func(format string, args ...interface{}) {
			log.SingLogger.Error(fmt.Sprintf("[WG](%s) %s", option.Name, fmt.Sprintf(format, args...)))
		},
	}
	if option.AmneziaWGOption != nil {
		outbound.bind.SetParseReserved(false) // AmneziaWG don't need parse reserved
		outbound.device = amnezia.NewDevice(outbound.tunDevice, outbound.bind, logger, option.Workers)
	} else {
		outbound.device = device.NewDevice(outbound.tunDevice, outbound.bind, logger, option.Workers)
		// 握手监听：握手永久失败时主动失效底层 TCP 连接（仅 wg-fork device 支持）。
		// 解决"TCP 连接仍在但 WireGuard 数据面无响应"导致的静默断链。
		if option.TCP {
			if wd, ok := outbound.device.(interface {
				SetHandshakeListener(func(string))
				SetHandshakeCompleteListener(func(string))
			}); ok {
				if tcpBind, ok := outbound.bind.(interface {
					InvalidateEndpoint(string)
					MarkConnReady(string)
				}); ok {
					wd.SetHandshakeListener(func(endpoint string) {
						log.Warnln("[WG](%s) handshake failed for %s, invalidating TCP connection", option.Name, endpoint)
						tcpBind.InvalidateEndpoint(endpoint)
					})
					// 握手完成：标记隧道 ready。TCP connected 不等于隧道可用，
					// 业务只有在握手完成后才允许放行。
					wd.SetHandshakeCompleteListener(func(endpoint string) {
						tcpBind.MarkConnReady(endpoint)
					})
				}
			}
		}
	}

	var has6 bool
	for _, address := range outbound.localPrefixes {
		if !address.Addr().Unmap().Is4() {
			has6 = true
			break
		}
	}

	if option.RemoteDnsResolve && len(option.Dns) > 0 {
		nss, err := dns.ParseNameServer(option.Dns)
		if err != nil {
			return nil, err
		}
		// DoH 通道策略：
		// - 海外 DoH (1.1.1.1/8.8.8.8) 走 SG-Node 隧道：本机直连被墙，但隧道内
		//   能拿到 chatgpt.com 等域名的真实 IP（国内 DoH 会返回污染 IP）。
		// - 国内 DoH (223.5.5.5 等) 直连：解析国内域名快，作为兜底避免隧道
		//   抖动时全部超时。
		// 通过 server 地址区分：1.1.1.1 / 8.8.8.8 走隧道，其余直连。
		for i := range nss {
			addr := nss[i].Addr
			if strings.Contains(addr, "1.1.1.1") || strings.Contains(addr, "8.8.8.8") ||
				strings.Contains(addr, "1.0.0.1") {
				nss[i].ProxyAdapter = outbound
			}
		}
		outbound.resolver = dns.NewResolver(dns.Config{
			Main: nss,
			IPv6: has6,
		})
	}

	return outbound, nil
}

func (w *WireGuard) resolve(ctx context.Context, address M.Socksaddr) (netip.AddrPort, error) {
	if address.Addr.IsValid() {
		return address.AddrPort(), nil
	}
	udpAddr, err := resolveUDPAddr(ctx, "udp", address.String(), w.prefer)
	if err != nil {
		return netip.AddrPort{}, err
	}
	// net.ResolveUDPAddr maybe return 4in6 address, so unmap at here
	addrPort := udpAddr.AddrPort()
	return netip.AddrPortFrom(addrPort.Addr().Unmap(), addrPort.Port()), nil
}

func (w *WireGuard) init(ctx context.Context) error {
	err := w.init0(ctx)
	if err != nil {
		log.Warnln("[WG](%s) init0 error: %v", w.option.Name, err)
		return err
	}
	w.updateServerAddr(ctx)
	return nil
}

func (w *WireGuard) init0(ctx context.Context) error {
	if w.initOk.Load() {
		return nil
	}
	w.initMutex.Lock()
	defer w.initMutex.Unlock()
	// double check like sync.Once
	if w.initOk.Load() {
		return nil
	}
	if w.initErr != nil {
		return w.initErr
	}
	log.Debugln("[WG](%s) initializing", w.option.Name)

	w.bind.ResetReservedForEndpoint()
	w.serverAddrMap = make(map[M.Socksaddr]netip.AddrPort)
	ipcConf, err := w.genIpcConf(ctx, false)
	if err != nil {
		// !!! do not set initErr here !!!
		// let us can retry domain resolve in next time
		return err
	}

	if debug.Enabled {
		log.SingLogger.Trace(fmt.Sprintf("[WG](%s) created wireguard ipc conf: \n %s", w.option.Name, ipcConf))
	}
	err = w.device.IpcSet(ipcConf)
	if err != nil {
		log.Warnln("[WG](%s) IpcSet error: %v", w.option.Name, err)
		w.initErr = E.Cause(err, "setup wireguard")
		return w.initErr
	}
	w.serverAddrTime.Store(time.Now())

	err = w.tunDevice.Start()
	if err != nil {
		log.Warnln("[WG](%s) tunDevice.Start error: %v", w.option.Name, err)
		w.initErr = err
		return w.initErr
	}
	log.Infoln("[WG](%s) tunDevice started", w.option.Name)

	w.initOk.Store(true)
	return nil
}

func (w *WireGuard) updateServerAddr(ctx context.Context) {
	if w.option.RefreshServerIPInterval != 0 && time.Since(w.serverAddrTime.Load()) > time.Second*time.Duration(w.option.RefreshServerIPInterval) {
		if w.serverAddrMutex.TryLock() {
			defer w.serverAddrMutex.Unlock()
			ipcConf, err := w.genIpcConf(ctx, true)
			if err != nil {
				log.Warnln("[WG](%s)UpdateServerAddr failed to generate wireguard ipc conf: %s", w.option.Name, err)
				return
			}
			err = w.device.IpcSet(ipcConf)
			if err != nil {
				log.Warnln("[WG](%s)UpdateServerAddr failed to update wireguard ipc conf: %s", w.option.Name, err)
				return
			}
			w.serverAddrTime.Store(time.Now())
		}
	}
}

// refreshCorplinkOption 调用 corplink /vpn/conn API 获取当前会话分配的隧道 IP
// 与服务器公钥，并覆盖节点配置（ip / public-key / mtu）。在创建 wireguard
// 栈设备前调用，保证 local prefixes 与 MTU 使用服务器下发的正确值。
// 若首次 fetch 失败且配置了 corplink-refresh-command，会先执行刷新命令
// 再重试一次，使 cookie 过期场景可以自愈。
func refreshCorplinkOption(option *WireGuardOption) error {
	opt := option.Corplink
	if opt.PublicKey == "" {
		opt.PublicKey = option.PublicKey
	}
	info, err := fetchCorplinkWgInfo(opt)
	if err != nil && opt.RefreshCommand != "" {
		log.Warnln("[WG-Corplink] fetch failed (%v), trying refresh command: %s", err, opt.RefreshCommand)
		if rerr := runCorplinkRefresh(opt.RefreshCommand); rerr != nil {
			log.Warnln("[WG-Corplink] refresh command failed: %v", rerr)
			return E.Cause(err, "corplink fetch peer info")
		}
		info, err = fetchCorplinkWgInfo(opt)
	}
	if err != nil {
		return E.Cause(err, "corplink fetch peer info")
	}
	if info.IP != "" {
		option.Ip = info.IP
	}
	if info.ServerPubKeyHex != "" {
		option.PublicKey = info.ServerPubKeyHex
	}
	if info.MTU != 0 {
		// TCP-WireGuard adds framing overhead outside the WireGuard packet.
		// Corplink reports the inner MTU (currently 1400), but that value can
		// black-hole the first larger data packets on the TCP path. Keep a
		// conservative ceiling until path-MTU discovery is available.
		option.MTU = info.MTU
		if option.TCP && option.MTU > 1280 {
			option.MTU = 1280
		}
	}
	log.Infoln("[WG](%s) corplink refreshed: ip=%s public_key=%s mtu=%d", option.Name, option.Ip, option.PublicKey, option.MTU)
	return nil
}

func (w *WireGuard) genIpcConf(ctx context.Context, updateOnly bool) (string, error) {
	ipcConf := ""
	if !updateOnly {
		ipcConf += "private_key=" + w.option.PrivateKey + "\n"
		if w.option.AmneziaWGOption != nil {
			if w.option.AmneziaWGOption.JC != 0 {
				ipcConf += "jc=" + strconv.Itoa(w.option.AmneziaWGOption.JC) + "\n"
			}
			if w.option.AmneziaWGOption.JMin != 0 {
				ipcConf += "jmin=" + strconv.Itoa(w.option.AmneziaWGOption.JMin) + "\n"
			}
			if w.option.AmneziaWGOption.JMax != 0 {
				ipcConf += "jmax=" + strconv.Itoa(w.option.AmneziaWGOption.JMax) + "\n"
			}
			if w.option.AmneziaWGOption.S1 != 0 {
				ipcConf += "s1=" + strconv.Itoa(w.option.AmneziaWGOption.S1) + "\n"
			}
			if w.option.AmneziaWGOption.S2 != 0 {
				ipcConf += "s2=" + strconv.Itoa(w.option.AmneziaWGOption.S2) + "\n"
			}
			if w.option.AmneziaWGOption.S3 != 0 {
				ipcConf += "s3=" + strconv.Itoa(w.option.AmneziaWGOption.S3) + "\n"
			}
			if w.option.AmneziaWGOption.S4 != 0 {
				ipcConf += "s4=" + strconv.Itoa(w.option.AmneziaWGOption.S4) + "\n"
			}
			if w.option.AmneziaWGOption.H1 != "" {
				ipcConf += "h1=" + w.option.AmneziaWGOption.H1 + "\n"
			}
			if w.option.AmneziaWGOption.H2 != "" {
				ipcConf += "h2=" + w.option.AmneziaWGOption.H2 + "\n"
			}
			if w.option.AmneziaWGOption.H3 != "" {
				ipcConf += "h3=" + w.option.AmneziaWGOption.H3 + "\n"
			}
			if w.option.AmneziaWGOption.H4 != "" {
				ipcConf += "h4=" + w.option.AmneziaWGOption.H4 + "\n"
			}
			if w.option.AmneziaWGOption.I1 != "" {
				ipcConf += "i1=" + w.option.AmneziaWGOption.I1 + "\n"
			}
			if w.option.AmneziaWGOption.I2 != "" {
				ipcConf += "i2=" + w.option.AmneziaWGOption.I2 + "\n"
			}
			if w.option.AmneziaWGOption.I3 != "" {
				ipcConf += "i3=" + w.option.AmneziaWGOption.I3 + "\n"
			}
			if w.option.AmneziaWGOption.I4 != "" {
				ipcConf += "i4=" + w.option.AmneziaWGOption.I4 + "\n"
			}
			if w.option.AmneziaWGOption.I5 != "" {
				ipcConf += "i5=" + w.option.AmneziaWGOption.I5 + "\n"
			}
			if w.option.AmneziaWGOption.J1 != "" {
				ipcConf += "j1=" + w.option.AmneziaWGOption.J1 + "\n"
			}
			if w.option.AmneziaWGOption.J2 != "" {
				ipcConf += "j2=" + w.option.AmneziaWGOption.J2 + "\n"
			}
			if w.option.AmneziaWGOption.J3 != "" {
				ipcConf += "j3=" + w.option.AmneziaWGOption.J3 + "\n"
			}
			if w.option.AmneziaWGOption.Itime != 0 {
				ipcConf += "itime=" + strconv.FormatInt(int64(w.option.AmneziaWGOption.Itime), 10) + "\n"
			}
		}
	}
	if len(w.option.Peers) > 0 {
		for i, peer := range w.option.Peers {
			peerAddr := peer.Addr()
			destination, err := w.resolve(ctx, peerAddr)
			if err != nil {
				return "", E.Cause(err, "resolve endpoint domain for peer ", i)
			}
			if w.serverAddrMap[peerAddr] != destination {
				w.serverAddrMap[peerAddr] = destination
			} else if updateOnly {
				continue
			}

			if len(w.option.Peers) == 1 { // must call SetConnectAddr if isConnect == true
				w.bind.SetConnectAddr(destination)
			}
			ipcConf += "public_key=" + peer.PublicKey + "\n"
			if updateOnly {
				ipcConf += "update_only=true\n"
			}
			ipcConf += "endpoint=" + destination.String() + "\n"
			if len(peer.Reserved) > 0 {
				var reserved [3]uint8
				copy(reserved[:], peer.Reserved)
				w.bind.SetReservedForEndpoint(destination, reserved)
			}
			if updateOnly {
				continue
			}
			if peer.PreSharedKey != "" {
				ipcConf += "preshared_key=" + peer.PreSharedKey + "\n"
			}
			for _, allowedIP := range peer.AllowedIPs {
				ipcConf += "allowed_ip=" + allowedIP + "\n"
			}
			if w.option.PersistentKeepalive != 0 {
				ipcConf += fmt.Sprintf("persistent_keepalive_interval=%d\n", w.option.PersistentKeepalive)
			}
		}
	} else {
		destination, err := w.resolve(ctx, w.connectAddr)
		if err != nil {
			return "", E.Cause(err, "resolve endpoint domain")
		}
		if w.serverAddrMap[w.connectAddr] != destination {
			w.serverAddrMap[w.connectAddr] = destination
		} else if updateOnly {
			return "", nil
		}
		w.bind.SetConnectAddr(destination) // must call SetConnectAddr if isConnect == true
		ipcConf += "public_key=" + w.option.PublicKey + "\n"
		if updateOnly {
			ipcConf += "update_only=true\n"
		}
		ipcConf += "endpoint=" + destination.String() + "\n"
		if updateOnly {
			return ipcConf, nil
		}
		if w.option.PreSharedKey != "" {
			ipcConf += "preshared_key=" + w.option.PreSharedKey + "\n"
		}
		var has4, has6 bool
		for _, address := range w.localPrefixes {
			if address.Addr().Is4() {
				has4 = true
			} else {
				has6 = true
			}
		}
		if has4 {
			ipcConf += "allowed_ip=0.0.0.0/0\n"
		}
		if has6 {
			ipcConf += "allowed_ip=::/0\n"
		}

		if w.option.PersistentKeepalive != 0 {
			ipcConf += fmt.Sprintf("persistent_keepalive_interval=%d\n", w.option.PersistentKeepalive)
		}
	}
	return ipcConf, nil
}

// Close implements C.ProxyAdapter
func (w *WireGuard) Close() error {
	if w.device != nil {
		w.device.Close()
	}
	return nil
}

func (w *WireGuard) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	var conn net.Conn
	if err = w.init(ctx); err != nil {
		if isTunnelFailure(err) && w.registerBusyFailure() {
			w.invalidateTunnelForBusyFailure()
		}
		return nil, err
	}
	if !metadata.Resolved() || w.resolver != nil {
		r := resolver.DefaultResolver
		if w.resolver != nil {
			r = w.resolver
		}
		options := w.DialOptions()
		options = append(options, dialer.WithResolver(r))
		options = append(options, dialer.WithNetDialer(wgNetDialer{tunDevice: w.tunDevice}))
		dialCtx, cancel := w.tunnelDialContext(ctx)
		conn, err = dialer.NewDialer(options...).DialContext(dialCtx, "tcp", metadata.RemoteAddress())
		cancel()
	} else {
		dialCtx, cancel := w.tunnelDialContext(ctx)
		conn, err = w.tunDevice.DialContext(dialCtx, "tcp", M.SocksaddrFrom(metadata.DstIP, metadata.DstPort).Unwrap())
		cancel()
	}
	if err != nil {
		// 业务 dial 失败：区分 DNS 失败与隧道数据面失败。
		// 仅隧道数据面失败累计到阈值才触发重建，避免 DNS 抖动反复重建。
		if isTunnelFailure(err) && w.registerBusyFailure() {
			w.invalidateTunnelForBusyFailure()
		}
		return nil, err
	}
	if conn == nil {
		if w.registerBusyFailure() {
			w.invalidateTunnelForBusyFailure()
		}
		return nil, E.New("conn is nil")
	}
	// TCP 建连成功，但需等待 WireGuard 握手完成（隧道 ready）业务才可用
	if !w.waitTunnelReady(ctx) {
		log.Warnln("[WG](%s) tunnel not ready within %v after TCP connect, treating as failure", w.option.Name, tunnelFailureDialTimeout())
		_ = conn.Close()
		if w.registerBusyFailure() {
			w.invalidateTunnelForBusyFailure()
		}
		return nil, E.New("tunnel not ready: WireGuard handshake timeout")
	}
	w.recordBusySuccess()
	return NewConn(conn, w), nil
}

func (w *WireGuard) tunnelDialContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if !w.option.TCP {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, tunnelFailureDialTimeout())
}

func (w *WireGuard) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (_ C.PacketConn, err error) {
	var pc net.PacketConn
	if err = w.init(ctx); err != nil {
		if isTunnelFailure(err) && w.registerBusyFailure() {
			w.invalidateTunnelForBusyFailure()
		}
		return nil, err
	}
	if err = w.ResolveUDP(ctx, metadata); err != nil {
		// DNS 解析失败不计入隧道健康
		return nil, err
	}
	pc, err = w.tunDevice.ListenPacket(ctx, M.SocksaddrFrom(metadata.DstIP, metadata.DstPort).Unwrap())
	if err != nil {
		if isTunnelFailure(err) && w.registerBusyFailure() {
			w.invalidateTunnelForBusyFailure()
		}
		return nil, err
	}
	if pc == nil {
		if w.registerBusyFailure() {
			w.invalidateTunnelForBusyFailure()
		}
		return nil, E.New("packetConn is nil")
	}
	w.recordBusySuccess()
	return NewPacketConn(pc, w), nil
}

func (w *WireGuard) ResolveUDP(ctx context.Context, metadata *C.Metadata) error {
	if (!metadata.Resolved() || w.resolver != nil) && metadata.Host != "" {
		r := resolver.DefaultResolver
		if w.resolver != nil {
			r = w.resolver
		}
		ip, err := resolveIPWithResolver(ctx, metadata.Host, w.prefer, r)
		if err != nil {
			return fmt.Errorf("can't resolve ip: %w", err)
		}
		metadata.DstIP = ip
	}
	return nil
}

// ProxyInfo implements C.ProxyAdapter
func (w *WireGuard) ProxyInfo() C.ProxyInfo {
	info := w.Base.ProxyInfo()
	info.DialerProxy = w.option.DialerProxy
	return info
}

// IsL3Protocol implements C.ProxyAdapter
func (w *WireGuard) IsL3Protocol(metadata *C.Metadata) bool {
	return true
}

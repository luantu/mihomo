package outbound

// TCP wireguard bind - 复用 corplink-rs 的 TCP 封装协议（与公司 SG/INT 节点兼容）。
// 每个数据包用 4 字节小端长度前缀 + 密文，经一条 TCP 连接承载。

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/log"

	wgconn "github.com/metacubex/wireguard-go/conn"
)

const tcpMaxSegmentSize = 65535

// tcpDialTimeout bounds a single TCP dial attempt so a stuck endpoint fails
// fast instead of hanging until the OS-level connect timeout.
const tcpDialTimeout = 5 * time.Second

// tcpDialBackoffBase, tcpDialBackoffMax define the exponential backoff applied
// per endpoint after consecutive dial failures: base*2^(count-1) capped at max.
const (
	tcpDialBackoffBase = time.Second
	tcpDialBackoffMax  = 30 * time.Second
)

// tcpKeepAlivePeriod 为 TCP 连接层 Keep-Alive 探测周期。中间设备/服务端静默
// 回收连接时，OS 会通过探测发现半开连接，避免连接停留在 ESTABLISHED 但实际
// 不可用。15s 探测 + 系统默认重试次数可在 1 分钟内发现死连接。
const tcpKeepAlivePeriod = 15 * time.Second

// tcpStaleTimeout 为连接"静默失效"判定阈值：超过该时长未收到任何有效
// WireGuard 帧（含 keepalive），判定连接 stale 并主动清理。corplink 隧道
// persistent-keepalive 为 25s，正常连接每 25s 必有数据帧，故 90s 阈值足够
// 保守，既能捕获半开/静默断链，又不会误伤正常空闲连接。
const tcpStaleTimeout = 90 * time.Second

// errBadFrameLength 表示解析到异常的 TCP WireGuard 帧长度，
// 读循环应跳过该帧继续处理，而不是终止整条隧道连接。
var errBadFrameLength = errors.New("invalid TCP WireGuard frame length")

type tcpReqLen [4]byte

func (l *tcpReqLen) Len() int {
	return int(l[0]) + int(l[1])<<8 + int(l[2])<<16 + int(l[3])<<24
}

func (l *tcpReqLen) FromLen(length int) {
	l[0] = byte(length & 0xff)
	l[1] = byte(length >> 8 & 0xff)
	l[2] = byte(length >> 16 & 0xff)
	l[3] = byte(length >> 24 & 0xff)
}

type tcpRecvData struct {
	buff     []byte
	size     int
	endpoint wgconn.Endpoint
}

type tcpConnState struct {
	conn    *net.TCPConn
	writeMu sync.Mutex
	// lastRecv 记录最近一次收到有效 WireGuard 帧的时间（unix 纳秒）。
	// 供空闲检测判定连接是否"静默失效"（TCP 仍 ESTABLISHED 但数据面无响应）。
	lastRecv atomic.Int64
	// createdAt 记录连接建立时间（unix 纳秒）。用于握手回调的保护窗口：
	// 新建立的连接在 tcpConnStartupGuard 内不响应历史握手失败回调，
	// 避免旧连接的 giving-up 回调误杀刚重建的新连接。
	createdAt atomic.Int64
	// ready 标记 WireGuard 握手是否已完成（隧道数据面可用）。
	// TCP connected 不等于隧道可用；握手完成后由握手成功回调置 true。
	ready     atomic.Bool
	readyCh   chan struct{}
	readyOnce sync.Once
	// connID 为连接唯一序号，用于日志跟踪与代次保护（清理时避免误删新连接）。
	connID uint64
}

func newTCPConnState(conn *net.TCPConn, connID uint64) *tcpConnState {
	state := &tcpConnState{conn: conn, readyCh: make(chan struct{}), connID: connID}
	state.lastRecv.Store(time.Now().UnixNano())
	state.createdAt.Store(time.Now().UnixNano())
	return state
}

func (s *tcpConnState) markReady() {
	if s.ready.CompareAndSwap(false, true) {
		s.readyOnce.Do(func() { close(s.readyCh) })
	}
}

func (s *tcpConnState) waitReady(timeout time.Duration) bool {
	if s.ready.Load() {
		return true
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-s.readyCh:
		return s.ready.Load()
	case <-timer.C:
		return false
	}
}

// tcpConnStartupGuard 为连接建立后的"启动保护期"：期间忽略握手失败回调，
// 避免重建竞态下误杀新连接。30s 覆盖握手发起 + 首次响应所需时间。
const tcpConnStartupGuard = 30 * time.Second

type tcpWireGuardBind struct {
	ctx    context.Context
	dialer func(context.Context) (net.Conn, error)

	tcpConnMap sync.Map // string -> *tcpConnState
	listener   net.Listener
	recvChan   chan *tcpRecvData
	closeChan  chan struct{}
	closed     atomic.Bool
	closeOnce  sync.Once

	// mu guards the single-flight dial + per-endpoint backoff state so that
	// only one goroutine establishes a TCP connection at a time, and broken
	// tunnels fail fast and back off instead of causing a dial storm.
	mu        sync.Mutex
	lastFail  map[string]time.Time
	failCount map[string]uint32
	dialing   map[string]bool
	dialDone  map[string]chan struct{}
	connSeq   atomic.Uint64 // 连接代次分配器
}

var _ wgconn.Bind = (*tcpWireGuardBind)(nil)

func newTCPWireGuardBind(ctx context.Context, dialFn func(context.Context) (net.Conn, error)) *tcpWireGuardBind {
	return &tcpWireGuardBind{
		ctx:       ctx,
		dialer:    dialFn,
		recvChan:  make(chan *tcpRecvData, 4096),
		lastFail:  make(map[string]time.Time),
		failCount: make(map[string]uint32),
		dialing:   make(map[string]bool),
		dialDone:  make(map[string]chan struct{}),
	}
}

func (t *tcpWireGuardBind) Open(port uint16) ([]wgconn.ReceiveFunc, uint16, error) {
	t.closed.Store(false)
	t.closeOnce = sync.Once{}
	t.closeChan = make(chan struct{})

	// 与 corplink-rs 一致：同时监听端口，接收服务器回调连接（双向隧道）
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, 0, err
	}
	t.listener = ln
	go t.accept()
	return []wgconn.ReceiveFunc{t.receive}, uint16(ln.Addr().(*net.TCPAddr).Port), nil
}

func (t *tcpWireGuardBind) accept() {
	for {
		conn, err := t.listener.Accept()
		if err != nil {
			return
		}
		tcpConn, ok := conn.(*net.TCPConn)
		if !ok {
			_ = conn.Close()
			continue
		}
		configureTCPConn(tcpConn)
		addrPort := tcpConn.RemoteAddr().(*net.TCPAddr).AddrPort()
		endpoint := &wgconn.StdNetEndpoint{AddrPort: addrPort}
		state := newTCPConnState(tcpConn, t.connSeq.Add(1))
		t.tcpConnMap.Store(endpoint.DstToString(), state)
		t.handleConn(state, endpoint, t.closeChan)
	}
}

func readTCPFrame(r io.Reader) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	frameLen := tcpReqLen(lenBuf)
	size := frameLen.Len()
	if size <= 0 || size > tcpMaxSegmentSize {
		// 与 corplink-rs 一致：坏帧跳过，不终止读循环，
		// 避免因一次错位解析导致整条隧道反复重建。
		return nil, errBadFrameLength
	}
	buff := make([]byte, size)
	if _, err := io.ReadFull(r, buff); err != nil {
		return nil, err
	}
	return buff, nil
}

func writeFull(w io.Writer, buffer []byte) error {
	for len(buffer) > 0 {
		n, err := w.Write(buffer)
		if err != nil {
			return err
		}
		if n <= 0 || n > len(buffer) {
			return io.ErrShortWrite
		}
		buffer = buffer[n:]
	}
	return nil
}

// configureTCPConn 统一配置新建的 TCP 连接：
//   - NoDelay：禁用 Nagle，降低 WireGuard 小包延迟。
//   - KeepAlive：启用 TCP Keep-Alive，探测中间设备/服务端静默回收造成的半开连接。
//     SetKeepAlivePeriod 在 Windows 上由系统底层生效，macOS/Linux 均支持。
func configureTCPConn(conn *net.TCPConn) {
	_ = conn.SetNoDelay(true)
	_ = conn.SetKeepAlive(true)
	_ = conn.SetKeepAlivePeriod(tcpKeepAlivePeriod)
}

// invalidateConn 统一处理连接失效：关闭 TCP、从连接表移除、记录日志。
// 调用方负责在失效后触发重连（Send 的下一次 getConn 会重新 dial）。
// 用 CompareAndDelete(endpoint, state) 保证只删除匹配的当前连接，
// 避免旧连接的清理逻辑误删新建立的连接（连接代次保护）。
func (t *tcpWireGuardBind) invalidateConn(endpoint wgconn.Endpoint, state *tcpConnState, reason string) {
	key := endpoint.DstToString()
	if !t.tcpConnMap.CompareAndDelete(key, state) {
		// map 中已是新连接，说明旧连接的清理不应影响当前连接
		log.Debugln("[WG-TCP] skip invalidating %s: connection superseded", key)
		return
	}
	_ = state.conn.Close()
	state.readyOnce.Do(func() { close(state.readyCh) })
	log.Infoln("[WG-TCP] connection invalidated conn_id=%d %s reason=%s", state.connID, key, reason)
}

// recordEndpointFailure records failures after TCP establishment as well as
// failures during TCP dialing. A TCP socket is not a usable WireGuard tunnel
// until the handshake completes, so handshake failures must participate in
// the same backoff policy.
func (t *tcpWireGuardBind) recordEndpointFailure(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.lastFail[key] = time.Now()
	t.failCount[key]++
}

func (t *tcpWireGuardBind) recordEndpointSuccess(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.lastFail, key)
	delete(t.failCount, key)
}

// InvalidateEndpoint 按 endpoint 字符串（"ip:port"）失效对应 TCP 连接。
// 供 wireguard device 层的握手失败回调使用：握手永久失败说明数据面已不可用，
// 主动清理底层 TCP 连接，让下一次 Send 触发重建。
// 刚建立（< tcpConnStartupGuard）的连接不响应，避免旧连接的历史回调误杀新连接。
func (t *tcpWireGuardBind) InvalidateEndpoint(endpoint string) {
	if endpoint == "" {
		return
	}
	v, ok := t.tcpConnMap.Load(endpoint)
	if !ok {
		return
	}
	state, ok := v.(*tcpConnState)
	if !ok || state == nil {
		return
	}
	created := time.Unix(0, state.createdAt.Load())
	if time.Since(created) < tcpConnStartupGuard {
		log.Debugln("[WG-TCP] skip invalidating %s: connection too young (age=%v)", endpoint, time.Since(created))
		return
	}
	t.recordEndpointFailure(endpoint)
	t.invalidateConn(stateEndpoint{key: endpoint}, state, "handshake failed")
}

// MarkConnReady 标记 endpoint 对应的 TCP 连接已完成 WireGuard 握手（隧道可用）。
// 供 wireguard device 层的握手成功回调使用。只有握手完成后业务才允许放行。
func (t *tcpWireGuardBind) MarkConnReady(endpoint string) {
	if endpoint == "" {
		return
	}
	if v, ok := t.tcpConnMap.Load(endpoint); ok {
		if state, ok := v.(*tcpConnState); ok && state != nil {
			if !state.ready.Load() {
				state.markReady()
				t.recordEndpointSuccess(endpoint)
				log.Infoln("[WG-TCP] tunnel ready conn_id=%d %s (WireGuard handshake completed)", state.connID, endpoint)
			}
		}
	}
}

// WaitConnReady waits on the connection generation's shared readiness signal.
// It avoids one polling timer per business request during handshake stalls.
func (t *tcpWireGuardBind) WaitConnReady(endpoint string, timeout time.Duration) bool {
	v, ok := t.tcpConnMap.Load(endpoint)
	if !ok {
		return false
	}
	state, ok := v.(*tcpConnState)
	if !ok || state == nil {
		return false
	}
	return state.waitReady(timeout)
}

// IsConnReady 返回 endpoint 对应连接是否已完成握手（隧道可用）。
func (t *tcpWireGuardBind) IsConnReady(endpoint string) bool {
	if endpoint == "" {
		return false
	}
	if v, ok := t.tcpConnMap.Load(endpoint); ok {
		if state, ok := v.(*tcpConnState); ok && state != nil {
			return state.ready.Load()
		}
	}
	return false
}

// stateEndpoint 适配 invalidateConn 的 wgconn.Endpoint 参数：仅用于从连接表
// 按键删除，DstToString 返回构造时传入的 key。
type stateEndpoint struct {
	key string
}

func (e stateEndpoint) DstToString() string { return e.key }
func (e stateEndpoint) DstToBytes() []byte  { return []byte(e.key) }
func (e stateEndpoint) DstIP() netip.Addr   { return netip.Addr{} }
func (e stateEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }
func (e stateEndpoint) SrcToString() string { return "" }
func (e stateEndpoint) ClearSrc()           {}

func (t *tcpWireGuardBind) handleConn(state *tcpConnState, endpoint wgconn.Endpoint, closeChan <-chan struct{}) {
	go func() {
		// 连接关闭（服务器断开/网络中断/主动失效）时清理 map 项与连接，
		// 下次 Send 会通过 getConn 自动重建。
		defer t.invalidateConn(endpoint, state, "connection closed")

		for {
			buff, err := readTCPFrame(state.conn)
			if err != nil {
				if errors.Is(err, errBadFrameLength) {
					log.Debugln("[WG-TCP] skip bad frame from %s", endpoint.DstToString())
					continue
				}
				if !t.closed.Load() && err != io.EOF {
					log.Warnln("[WG-TCP] receive from %s stopped: %v", endpoint.DstToString(), err)
				}
				return
			}
			state.lastRecv.Store(time.Now().UnixNano())
			mt := uint32(0)
			if len(buff) >= 4 {
				mt = uint32(buff[0]) | uint32(buff[1])<<8 | uint32(buff[2])<<16 | uint32(buff[3])<<24
			}
			log.Debugln("[WG-TCP] received frame len=%d type=%d conn_id=%d from %s", len(buff), mt, state.connID, endpoint.DstToString())
			select {
			case <-closeChan:
				return
			case t.recvChan <- &tcpRecvData{buff: buff, size: len(buff), endpoint: endpoint}:
			}
		}
	}()

	// 空闲监控：检测"静默断链"——TCP 连接仍 ESTABLISHED，但长时间收不到任何
	// WireGuard 帧（含 keepalive），说明数据面已无响应。超时后主动失效并重建。
	// 这是 readTCPFrame 阻塞在 Read 上无法感知的场景。
	// 注意：仅当连接已 ready（握手完成）后才启用 stale 判定，避免新建立的
	// 连接在握手完成前被误判为空闲而杀掉。
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-closeChan:
				return
			case <-t.ctx.Done():
				return
			case <-ticker.C:
				if !state.ready.Load() {
					// 尚未握手完成，不做 stale 判定
					continue
				}
				last := time.Unix(0, state.lastRecv.Load())
				idle := time.Since(last)
				if idle > tcpStaleTimeout && !t.closed.Load() {
					log.Warnln("[WG-TCP] connection stale idle=%v conn_id=%d from %s, invalidating", idle, state.connID, endpoint.DstToString())
					t.invalidateConn(endpoint, state, fmt.Sprintf("stale idle=%v", idle))
					return
				}
			}
		}
	}()
}

// backoffRemainingLocked returns the remaining backoff wait for the endpoint,
// or 0 if it may dial again. Caller must hold mu.
func (t *tcpWireGuardBind) backoffRemainingLocked(key string) time.Duration {
	count := t.failCount[key]
	if count == 0 {
		return 0
	}
	delay := tcpDialBackoffBase
	for i := uint32(1); i < count; i++ {
		delay *= 2
		if delay >= tcpDialBackoffMax {
			delay = tcpDialBackoffMax
			break
		}
	}
	remaining := delay - time.Since(t.lastFail[key])
	if remaining < 0 {
		return 0
	}
	return remaining
}

func (t *tcpWireGuardBind) getConn(endpoint wgconn.Endpoint) (*tcpConnState, error) {
	key := endpoint.DstToString()
	if v, ok := t.tcpConnMap.Load(key); ok {
		return v.(*tcpConnState), nil
	}
	return t.dialSingleFlight(endpoint, key)
}

func (t *tcpWireGuardBind) dialSingleFlight(endpoint wgconn.Endpoint, key string) (*tcpConnState, error) {
	t.mu.Lock()
	if t.dialing[key] {
		// 已有 goroutine 正在 dial：等它完成，然后复用已建立的连接（或重试）
		ch := t.dialDone[key]
		t.mu.Unlock()
		select {
		case <-ch:
		case <-t.closeChan:
			return nil, net.ErrClosed
		case <-t.ctx.Done():
			return nil, net.ErrClosed
		}
		if v, ok := t.tcpConnMap.Load(key); ok {
			return v.(*tcpConnState), nil
		}
		return t.dialSingleFlight(endpoint, key)
	}

	if remaining := t.backoffRemainingLocked(key); remaining > 0 {
		t.mu.Unlock()
		log.Warnln("[WG-TCP] tunnel unavailable: backing off dialing %s for %v", key, remaining)
		return nil, fmt.Errorf("tunnel unavailable: backing off dialing %s for %v", key, remaining)
	}

	t.dialing[key] = true
	t.dialDone[key] = make(chan struct{})
	t.mu.Unlock()

	log.Infoln("[WG-TCP] dialing %s", key)
	dialCtx, cancel := context.WithTimeout(t.ctx, tcpDialTimeout)
	raw, err := t.dialer(dialCtx)
	cancel()
	if err == nil {
		select {
		case <-t.closeChan:
			_ = raw.Close()
			err = net.ErrClosed
		default:
		}
	}

	t.mu.Lock()
	delete(t.dialing, key)
	ch := t.dialDone[key]
	delete(t.dialDone, key)
	var state *tcpConnState
	if err != nil {
		t.lastFail[key] = time.Now()
		t.failCount[key]++
	} else {
		tcpConn, ok := raw.(*net.TCPConn)
		if !ok {
			_ = raw.Close()
			err = fmt.Errorf("TCP WireGuard dialer returned %T, want *net.TCPConn", raw)
			t.lastFail[key] = time.Now()
			t.failCount[key]++
		} else {
			configureTCPConn(tcpConn)
			state = newTCPConnState(tcpConn, t.connSeq.Add(1))
			t.handleConn(state, endpoint, t.closeChan)
			t.tcpConnMap.Store(key, state)
		}
	}
	t.mu.Unlock()
	close(ch)

	if err != nil {
		log.Warnln("[WG-TCP] dial %s failed: %v", key, err)
		return nil, err
	}
	log.Infoln("[WG-TCP] connected conn_id=%d to %s (TCP established, awaiting handshake)", state.connID, key)
	return state, nil
}

func (t *tcpWireGuardBind) Send(bufs [][]byte, endpoint wgconn.Endpoint) error {
	for _, b := range bufs {
		mt := uint32(0)
		if len(b) >= 4 {
			mt = uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
		}
		log.Debugln("[WG-TCP] send len=%d type=%d to %s", len(b), mt, endpoint.DstToString())
	}
	state, err := t.getConn(endpoint)
	if err != nil {
		return err
	}
	total := 0
	for _, b := range bufs {
		total += 4 + len(b)
	}
	buffer := make([]byte, 0, total)
	for _, b := range bufs {
		var l tcpReqLen
		l.FromLen(len(b))
		buffer = append(buffer, l[:]...)
		buffer = append(buffer, b...)
	}
	state.writeMu.Lock()
	err = writeFull(state.conn, buffer)
	state.writeMu.Unlock()
	if err != nil {
		// 写失败说明连接已不可用：统一失效处理，下次 Send 会重新 dial。
		t.invalidateConn(endpoint, state, fmt.Sprintf("write error: %v", err))
	}
	return err
}

func (t *tcpWireGuardBind) receive(bufs [][]byte, sizes []int, eps []wgconn.Endpoint) (int, error) {
	select {
	case <-t.closeChan:
		return 0, net.ErrClosed
	case data := <-t.recvChan:
		if data == nil {
			return 0, net.ErrClosed
		}
		n := copy(bufs[0], data.buff[:data.size])
		sizes[0] = n
		eps[0] = data.endpoint
		return 1, nil
	}
}

func (t *tcpWireGuardBind) Close() error {
	t.closeOnce.Do(func() {
		t.closed.Store(true)
		if t.closeChan != nil {
			close(t.closeChan)
		}
		if t.listener != nil {
			_ = t.listener.Close()
		}
		t.tcpConnMap.Range(func(k, v interface{}) bool {
			if state, ok := v.(*tcpConnState); ok {
				_ = state.conn.Close()
			}
			t.tcpConnMap.Delete(k)
			return true
		})
	})
	return nil
}

func (t *tcpWireGuardBind) SetMark(mark uint32) error { return nil }

func (t *tcpWireGuardBind) BatchSize() int { return 1 }

func (t *tcpWireGuardBind) ParseEndpoint(s string) (wgconn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &wgconn.StdNetEndpoint{AddrPort: ap}, nil
}

// 兼容 ClientBind 的附加方法（TCP 模式无实际语义，空实现即可）
func (t *tcpWireGuardBind) SetConnectAddr(addrPort netip.AddrPort)         {}
func (t *tcpWireGuardBind) SetReservedForEndpoint(netip.AddrPort, [3]byte) {}
func (t *tcpWireGuardBind) ResetReservedForEndpoint()                      {}
func (t *tcpWireGuardBind) SetParseReserved(bool)                          {}

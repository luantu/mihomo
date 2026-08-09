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

	"github.com/metacubex/mihomo/log"

	wgconn "github.com/metacubex/wireguard-go/conn"
)

const tcpMaxSegmentSize = 65535

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
}

type tcpWireGuardBind struct {
	ctx    context.Context
	dialer func(context.Context) (net.Conn, error)

	tcpConnMap sync.Map // string -> *tcpConnState
	listener   net.Listener
	recvChan   chan *tcpRecvData
	closeChan  chan struct{}
	closed     atomic.Bool
	closeOnce  sync.Once

	mu sync.Mutex
}

var _ wgconn.Bind = (*tcpWireGuardBind)(nil)

func newTCPWireGuardBind(ctx context.Context, dialFn func(context.Context) (net.Conn, error)) *tcpWireGuardBind {
	return &tcpWireGuardBind{
		ctx:      ctx,
		dialer:   dialFn,
		recvChan: make(chan *tcpRecvData, 4096),
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
		tcpConn.SetNoDelay(true)
		addrPort := tcpConn.RemoteAddr().(*net.TCPAddr).AddrPort()
		endpoint := &wgconn.StdNetEndpoint{AddrPort: addrPort}
		state := &tcpConnState{conn: tcpConn}
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

func (t *tcpWireGuardBind) handleConn(state *tcpConnState, endpoint wgconn.Endpoint, closeChan <-chan struct{}) {
	go func() {
		defer state.conn.Close()
		defer t.tcpConnMap.CompareAndDelete(endpoint.DstToString(), state)

		for {
			buff, err := readTCPFrame(state.conn)
			if err != nil {
				if errors.Is(err, errBadFrameLength) {
					log.Debugln("[WG-TCP] skip bad frame from %s", endpoint.DstToString())
					continue
				}
				if !t.closed.Load() && err != io.EOF {
					log.Debugln("[WG-TCP] receive from %s stopped: %v", endpoint.DstToString(), err)
				}
				return
			}
			mt := uint32(0)
			if len(buff) >= 4 {
				mt = uint32(buff[0]) | uint32(buff[1])<<8 | uint32(buff[2])<<16 | uint32(buff[3])<<24
			}
			log.Debugln("[WG-TCP] received frame len=%d type=%d from %s", len(buff), mt, endpoint.DstToString())
			select {
			case <-closeChan:
				return
			case t.recvChan <- &tcpRecvData{buff: buff, size: len(buff), endpoint: endpoint}:
			}
		}
	}()
}

func (t *tcpWireGuardBind) getConn(endpoint wgconn.Endpoint) (*tcpConnState, error) {
	if v, ok := t.tcpConnMap.Load(endpoint.DstToString()); ok {
		return v.(*tcpConnState), nil
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	if v, ok := t.tcpConnMap.Load(endpoint.DstToString()); ok {
		return v.(*tcpConnState), nil
	}

	log.Infoln("[WG-TCP] dialing %s", endpoint.DstToString())
	raw, err := t.dialer(t.ctx)
	if err != nil {
		log.Warnln("[WG-TCP] dial %s failed: %v", endpoint.DstToString(), err)
		return nil, err
	}
	tcpConn, ok := raw.(*net.TCPConn)
	if !ok {
		_ = raw.Close()
		return nil, fmt.Errorf("TCP WireGuard dialer returned %T, want *net.TCPConn", raw)
	}
	tcpConn.SetNoDelay(true)
	state := &tcpConnState{conn: tcpConn}
	t.handleConn(state, endpoint, t.closeChan)
	t.tcpConnMap.Store(endpoint.DstToString(), state)
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
		t.tcpConnMap.CompareAndDelete(endpoint.DstToString(), state)
		_ = state.conn.Close()
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

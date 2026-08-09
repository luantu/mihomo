package outbound

// TCP wireguard bind - 复用 corplink-rs 的 TCP 封装协议（与公司 SG/INT 节点兼容）。
// 每个数据包用 4 字节小端长度前缀 + 密文，经一条 TCP 连接承载。

import (
	"context"
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

type tcpWireGuardBind struct {
	ctx    context.Context
	dialer func(context.Context) (net.Conn, error)

	tcpConnMap sync.Map // string -> *net.TCPConn
	listener   net.Listener
	recvChan   chan *tcpRecvData
	closeChan  chan struct{}
	closed     atomic.Bool

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
		tcpConn := conn.(*net.TCPConn)
		tcpConn.SetNoDelay(true)
		addrPort := tcpConn.RemoteAddr().(*net.TCPAddr).AddrPort()
		endpoint := &wgconn.StdNetEndpoint{AddrPort: addrPort}
		t.tcpConnMap.Store(endpoint.DstToString(), tcpConn)
		t.handleConn(tcpConn, endpoint)
	}
}

func (t *tcpWireGuardBind) handleConn(conn *net.TCPConn, endpoint wgconn.Endpoint) {
	go func() {
		defer conn.Close()
		defer t.tcpConnMap.Delete(endpoint.DstToString())

		var lenBuf [4]byte
		for {
			_, err := io.ReadFull(conn, lenBuf[:])
			if err != nil {
				return
			}
			l := tcpReqLen(lenBuf)
			size := l.Len()
			if size > tcpMaxSegmentSize || size < 0 {
				continue
			}
			buff := make([]byte, size)
			n, err := io.ReadFull(conn, buff)
			if err != nil {
				return
			}
			if n != size {
				continue
			}
			select {
			case <-t.closeChan:
				return
			case t.recvChan <- &tcpRecvData{buff: buff, size: size, endpoint: endpoint}:
			}
		}
	}()
}

func (t *tcpWireGuardBind) getConn(endpoint wgconn.Endpoint) (*net.TCPConn, error) {
	if v, ok := t.tcpConnMap.Load(endpoint.DstToString()); ok {
		return v.(*net.TCPConn), nil
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	if v, ok := t.tcpConnMap.Load(endpoint.DstToString()); ok {
		return v.(*net.TCPConn), nil
	}

	log.Infoln("[WG-TCP] dialing %s", endpoint.DstToString())
	raw, err := t.dialer(t.ctx)
	if err != nil {
		log.Warnln("[WG-TCP] dial %s failed: %v", endpoint.DstToString(), err)
		return nil, err
	}
	tcpConn := raw.(*net.TCPConn)
	tcpConn.SetNoDelay(true)
	t.handleConn(tcpConn, endpoint)
	t.tcpConnMap.Store(endpoint.DstToString(), tcpConn)
	return tcpConn, nil
}

func (t *tcpWireGuardBind) Send(bufs [][]byte, endpoint wgconn.Endpoint) error {
	for _, b := range bufs {
		mt := uint32(0)
		if len(b) >= 4 {
			mt = uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
		}
		log.Infoln("[WG-TCP] Send len=%d type=%d to %s", len(b), mt, endpoint.DstToString())
	}
	log.Infoln("[WG-TCP] Send %d bufs to %s", len(bufs), endpoint.DstToString())
	c, err := t.getConn(endpoint)
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
	_, err = c.Write(buffer)
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
	t.closed.Store(true)
	if t.closeChan != nil {
		close(t.closeChan)
	}
	t.tcpConnMap.Range(func(k, v interface{}) bool {
		if c, ok := v.(*net.TCPConn); ok {
			_ = c.Close()
		}
		t.tcpConnMap.Delete(k)
		return true
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
func (t *tcpWireGuardBind) SetConnectAddr(addrPort netip.AddrPort) {}
func (t *tcpWireGuardBind) SetReservedForEndpoint(netip.AddrPort, [3]byte) {}
func (t *tcpWireGuardBind) ResetReservedForEndpoint()              {}
func (t *tcpWireGuardBind) SetParseReserved(bool)                  {}

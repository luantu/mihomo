package outbound

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"
	"testing"
	"time"
)

type shortWriter struct {
	max int
	buf bytes.Buffer
}

func (w *shortWriter) Write(p []byte) (int, error) {
	if len(p) > w.max {
		p = p[:w.max]
	}
	return w.buf.Write(p)
}

func TestWriteFullHandlesShortWrites(t *testing.T) {
	w := &shortWriter{max: 3}
	want := []byte("length-prefixed-wireguard-frame")
	if err := writeFull(w, want); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(w.buf.Bytes(), want) {
		t.Fatalf("got %q, want %q", w.buf.Bytes(), want)
	}
}

func TestReadTCPFrameHandlesFragmentedInput(t *testing.T) {
	payload := []byte{4, 0, 0, 0, 1, 2, 3, 4}
	r := &oneByteReader{r: bytes.NewReader(payload)}
	got, err := readTCPFrame(r)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload[4:]) {
		t.Fatalf("got %v, want %v", got, payload[4:])
	}
}

func TestReadTCPFrameRejectsInvalidLength(t *testing.T) {
	for _, input := range [][]byte{
		{0, 0, 0, 0},
		{0, 0, 1, 0},
	} {
		if _, err := readTCPFrame(bytes.NewReader(input)); err == nil {
			t.Fatalf("readTCPFrame(%v) unexpectedly succeeded", input)
		}
	}
}

func TestWriteFullRejectsNoProgress(t *testing.T) {
	err := writeFull(zeroWriter{}, []byte("data"))
	if !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("got %v, want io.ErrShortWrite", err)
	}
}

func TestTCPWireGuardBindCloseIsIdempotentAndClosesListener(t *testing.T) {
	bind := newTCPWireGuardBind(context.Background(), func(context.Context) (net.Conn, error) {
		return nil, errors.New("unexpected dial")
	})
	_, port, err := bind.Open(0)
	if err != nil {
		if errors.Is(err, syscall.EPERM) {
			t.Skip("sandbox does not permit opening a TCP listener")
		}
		t.Fatal(err)
	}
	if err := bind.Close(); err != nil {
		t.Fatal(err)
	}
	if err := bind.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}

	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(port)), 100*time.Millisecond)
	if err == nil {
		_ = conn.Close()
		t.Fatal("listener still accepted connections after Close")
	}
}

func TestHandshakeFailureEntersDialBackoff(t *testing.T) {
	bind := newTCPWireGuardBind(context.Background(), nil)
	key := "220.250.13.174:34080"

	bind.recordEndpointFailure(key)
	bind.mu.Lock()
	got := bind.backoffRemainingLocked(key)
	bind.mu.Unlock()
	if got <= 0 {
		t.Fatalf("handshake failure did not enter dial backoff: %v", got)
	}
}

func TestTCPConnStateReadySignal(t *testing.T) {
	state := newTCPConnState(nil, 1)
	go func() {
		if !state.waitReady(time.Second) {
			t.Errorf("ready wait returned false")
		}
	}()
	state.markReady()
}

func TestTunnelFailureDialTimeoutIsShort(t *testing.T) {
	if got := tunnelFailureDialTimeout(); got != 3*time.Second {
		t.Fatalf("got %v, want 3s", got)
	}
}

func TestTargetTimeoutDoesNotInvalidateTunnel(t *testing.T) {
	if isTunnelFailure(context.DeadlineExceeded) {
		t.Fatal("target timeout must not be treated as a shared tunnel failure")
	}
	if !isTunnelFailure(errors.New("tunnel not ready: WireGuard handshake timeout")) {
		t.Fatal("handshake timeout must invalidate the tunnel")
	}
}

type oneByteReader struct{ r io.Reader }

func (r *oneByteReader) Read(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return r.r.Read(p)
}

type zeroWriter struct{}

func (zeroWriter) Write([]byte) (int, error) { return 0, nil }

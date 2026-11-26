//go:build postgres

package testutil

import (
	"net"
	"sync"
	"testing"
)

// Blackhole is a listener on loopback that accepts every connection and never
// answers it, like a server whose host is up and whose process hangs. A test
// uses it to check that a connect ends within its limit and not with the
// operating system's TCP timeout.
type Blackhole struct {
	ln    net.Listener
	mu    sync.Mutex
	conns []net.Conn
}

// NewBlackhole listens on addr, a host:port on loopback ("127.0.0.1:0" for a
// free port). It stops, and closes what it accepted, when the test ends.
func NewBlackhole(t testing.TB, addr string) *Blackhole {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("listen on %s: %v", addr, err)
	}
	b := &Blackhole{ln: ln}
	go b.accept()
	t.Cleanup(b.close)
	return b
}

// Addr is the address the listener is bound to, as host:port.
func (b *Blackhole) Addr() string { return b.ln.Addr().String() }

// HostPort returns the host and the port of Addr.
func (b *Blackhole) HostPort(t testing.TB) (string, int) {
	t.Helper()
	host, port, err := net.SplitHostPort(b.Addr())
	if err != nil {
		t.Fatal(err)
	}
	n, err := net.LookupPort("tcp", port)
	if err != nil {
		t.Fatal(err)
	}
	return host, n
}

func (b *Blackhole) accept() {
	for {
		c, err := b.ln.Accept()
		if err != nil {
			return
		}
		b.mu.Lock()
		b.conns = append(b.conns, c)
		b.mu.Unlock()
	}
}

func (b *Blackhole) close() {
	_ = b.ln.Close()
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, c := range b.conns {
		_ = c.Close()
	}
	b.conns = nil
}

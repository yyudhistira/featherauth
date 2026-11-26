//go:build postgres

package testutil

import (
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
)

// sslRequestCode is the code of the SSLRequest message a client sends before
// its startup message when it asks for TLS (PostgreSQL protocol, section
// "SSLRequest").
const sslRequestCode = 80877103

// PostgresProxy is a TCP proxy on loopback in front of a Postgres server. A
// test stops it to make the database unreachable for the service, and starts
// it again on the same port. With a server TLS configuration it answers a
// client's SSLRequest with TLS, so a test can put a certificate authority of its
// own in front of the server; without one, the traffic passes through as it is.
type PostgresProxy struct {
	target    string
	serverTLS *tls.Config

	mu    sync.Mutex
	addr  string
	ln    net.Listener
	conns map[net.Conn]struct{}
}

// NewPostgresProxy starts a proxy that forwards to target, a host:port, on a
// free port of 127.0.0.1. It is stopped when the test ends.
func NewPostgresProxy(t testing.TB, target string, serverTLS *tls.Config) *PostgresProxy {
	t.Helper()
	p := &PostgresProxy{target: target, serverTLS: serverTLS, addr: "127.0.0.1:0", conns: map[net.Conn]struct{}{}}
	p.Start(t)
	t.Cleanup(p.Stop)
	return p
}

// Port is the port the proxy listens on. It is the same after a Stop and a
// Start.
func (p *PostgresProxy) Port() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, port, _ := net.SplitHostPort(p.addr)
	n, _ := strconv.Atoi(port)
	return n
}

// Start listens on the proxy's port, or on a new one the first time. It does
// nothing when the proxy listens already.
func (p *PostgresProxy) Start(t testing.TB) {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ln != nil {
		return
	}
	ln, err := net.Listen("tcp", p.addr)
	if err != nil {
		t.Fatalf("listen on %s: %v", p.addr, err)
	}
	p.ln = ln
	p.addr = ln.Addr().String()
	go p.accept(ln)
}

// Stop closes the listener and every connection through the proxy, so the
// service sees the database go away.
func (p *PostgresProxy) Stop() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ln != nil {
		_ = p.ln.Close()
		p.ln = nil
	}
	for c := range p.conns {
		_ = c.Close()
	}
	p.conns = map[net.Conn]struct{}{}
}

func (p *PostgresProxy) accept(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return // the listener was closed by Stop
		}
		p.track(c)
		go p.serve(c)
	}
}

// track records a connection so that Stop can close it. A connection accepted
// after Stop is closed at once.
func (p *PostgresProxy) track(c net.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ln == nil {
		_ = c.Close()
		return
	}
	p.conns[c] = struct{}{}
}

func (p *PostgresProxy) untrack(c net.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.conns, c)
}

// serve forwards one client connection to the server.
func (p *PostgresProxy) serve(client net.Conn) {
	defer func() {
		_ = client.Close()
		p.untrack(client)
	}()
	head := make([]byte, 8)
	if _, err := io.ReadFull(client, head); err != nil {
		return
	}
	var conn net.Conn = client
	if p.serverTLS != nil && binary.BigEndian.Uint32(head[4:]) == sslRequestCode {
		if _, err := client.Write([]byte{'S'}); err != nil {
			return
		}
		tc := tls.Server(client, p.serverTLS)
		if err := tc.Handshake(); err != nil {
			return
		}
		conn = tc
		head = nil // the client sends its startup message again, over TLS
	}
	server, err := net.Dial("tcp", p.target)
	if err != nil {
		return
	}
	p.track(server)
	defer func() {
		_ = server.Close()
		p.untrack(server)
	}()
	if head != nil {
		if _, err := server.Write(head); err != nil {
			return
		}
	}
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(server, conn)
		_ = server.Close()
		close(done)
	}()
	_, _ = io.Copy(conn, server)
	_ = conn.Close()
	<-done
}

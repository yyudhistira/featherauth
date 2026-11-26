package oidc

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/logx"
	"github.com/yyudhistira/featherauth/internal/secure"
)

// Covers: FR-43, SEC-35
// Acceptance: Back-channel logout (part)
// The worker's client has the design's 5-second timeout and follows no redirect:
// a redirect is the answer, not a target.
func TestDeliverClientHasTheTimeoutAndRefusesRedirects(t *testing.T) {
	c := clock.NewFake(time.Date(2026, 11, 19, 9, 0, 0, 0, time.UTC))
	d := NewDeliverer(DeliverConfig{Clock: c, Rand: secure.Default, Log: logx.New(nil, 0, c)})
	if d.client.Timeout != 5*time.Second {
		t.Fatalf("timeout %v, want 5s", d.client.Timeout)
	}
	err := d.client.CheckRedirect(&http.Request{}, nil)
	if err != http.ErrUseLastResponse {
		t.Fatalf("CheckRedirect = %v, want ErrUseLastResponse", err)
	}
}

// endless is a response body of limit bytes that counts the bytes read from it.
type endless struct {
	limit, read int
}

func (e *endless) Read(p []byte) (int, error) {
	if e.read >= e.limit {
		return 0, io.EOF
	}
	n := len(p)
	if rest := e.limit - e.read; n > rest {
		n = rest
	}
	for i := 0; i < n; i++ {
		p[i] = 'x'
	}
	e.read += n
	return n, nil
}

// bodyTransport answers every request with a 200 whose body is body.
type bodyTransport struct{ body *endless }

func (b bodyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(b.body), Request: req}, nil
}

// Covers: FR-43
// Acceptance: Back-channel logout (part)
// A response body is read up to 64 KB and no further, however long it is.
func TestDiscardedBodyIsReadUpTo64KB(t *testing.T) {
	c := clock.NewFake(time.Date(2026, 11, 19, 9, 0, 0, 0, time.UTC))
	body := &endless{limit: 1 << 20}
	d := NewDeliverer(DeliverConfig{Clock: c, Rand: secure.Default, Log: logx.New(&bytes.Buffer{}, slog.LevelDebug, c), Transport: bodyTransport{body}})
	status, err := d.post(context.Background(), "https://receiver.example.test/logout", "token")
	if err != nil || status != http.StatusOK {
		t.Fatalf("post = %d, %v", status, err)
	}
	if body.read != 64<<10 {
		t.Fatalf("read %d bytes of the body, want 64 KB", body.read)
	}
}

// Covers: FR-43
// Acceptance: Back-channel logout (part)
// A tick that arrives after a stop starts no round and claims no row.
func TestTickAfterStopStartsNoRound(t *testing.T) {
	c := clock.NewFake(time.Date(2026, 11, 19, 9, 0, 0, 0, time.UTC))
	d := NewDeliverer(DeliverConfig{Source: config.Static(nil), Clock: c, Rand: secure.Default, Log: logx.New(&bytes.Buffer{}, slog.LevelDebug, c)})
	d.Start()
	if err := d.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	d.tick()
	if d.rounds != 0 {
		t.Fatalf("%d rounds started after the stop", d.rounds)
	}
}

// closingTransport counts the calls to CloseIdleConnections.
type closingTransport struct{ closed int }

func (c *closingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, http.ErrNotSupported
}

func (c *closingTransport) CloseIdleConnections() { c.closed++ }

// Covers: FR-43
// Acceptance: Back-channel logout (part)
// A stop releases the idle connections of the worker's transport.
func TestStopClosesIdleConnections(t *testing.T) {
	c := clock.NewFake(time.Date(2026, 11, 19, 9, 0, 0, 0, time.UTC))
	tr := &closingTransport{}
	d := NewDeliverer(DeliverConfig{Source: config.Static(nil), Clock: c, Rand: secure.Default, Log: logx.New(&bytes.Buffer{}, slog.LevelDebug, c), Transport: tr})
	d.Start()
	if err := d.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if tr.closed != 1 {
		t.Fatalf("CloseIdleConnections called %d times, want once", tr.closed)
	}
}

// gatedSource is a configuration source whose Current waits for the test, so a
// round stays in flight; it counts the rounds that have started (each round reads
// the configuration first).
type gatedSource struct {
	mu      sync.Mutex
	started int
	gate    chan struct{}
}

func (g *gatedSource) Current() *config.Snapshot {
	g.mu.Lock()
	g.started++
	g.mu.Unlock()
	<-g.gate
	return nil
}

func (g *gatedSource) rounds() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.started
}

// Covers: FR-43
// A tick that finds a round in flight starts none (the next round starts only when
// the round before has ended, NFR-15), and the ticks that came meanwhile are not
// lost: one round follows the one that ended.
func TestTickDuringARoundStartsNoSecondRound(t *testing.T) {
	c := clock.NewFake(time.Date(2026, 11, 19, 9, 0, 0, 0, time.UTC))
	src := &gatedSource{gate: make(chan struct{})}
	d := NewDeliverer(DeliverConfig{Source: src, Clock: c, Rand: secure.Default, Log: logx.New(&bytes.Buffer{}, slog.LevelDebug, c)})
	d.Start()
	t.Cleanup(func() { _ = d.Stop(context.Background()) })
	var open sync.Once
	openGate := func() { open.Do(func() { close(src.gate) }) }
	t.Cleanup(openGate) // runs before the Stop above, so a failed test does not hang

	c.Advance(deliverEvery) // the first round starts and waits in Current
	d.mu.Lock()
	first := d.rounds
	d.mu.Unlock()
	if first != 1 {
		t.Fatalf("%d rounds after the first tick, want 1", first)
	}
	c.Advance(deliverEvery) // two ticks while it runs
	c.Advance(deliverEvery)
	d.mu.Lock()
	during := d.rounds
	d.mu.Unlock()
	if during != 1 {
		t.Fatalf("%d rounds in flight after more ticks, want 1: a round started before the one before ended", during)
	}
	openGate()
	if err := d.Idle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := src.rounds(); n != 2 {
		t.Fatalf("%d rounds in all, want the first and one that follows the ticks that came meanwhile", n)
	}
}

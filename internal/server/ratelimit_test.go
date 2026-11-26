package server_test

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/logx"
	"github.com/yyudhistira/featherauth/internal/server"
	"github.com/yyudhistira/featherauth/internal/testutil"
	"github.com/yyudhistira/featherauth/internal/testutil/configdir"
)

func newConfigDir(t *testing.T, serverYAML string) (*config.Loader, *configdir.Dir) {
	t.Helper()
	return testutil.NewConfigDir(t, serverYAML, map[string]string{"main": testutil.MinimalRealm("main")})
}

type limitEnv struct {
	l   *server.Limiter
	clk *clock.Fake
	h   http.Handler
	hit int
}

func newLimitEnv(t *testing.T, serverYAML string) (*limitEnv, *config.Loader, *configdir.Dir) {
	t.Helper()
	src, dir := newConfigDir(t, serverYAML)
	e := &limitEnv{clk: clock.NewFake(testStart)}
	e.l = server.NewLimiter(src, e.clk, logx.New(io.Discard, slog.LevelInfo, e.clk))
	e.h = server.ClientIPMiddleware(src)(e.l.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		e.hit++
		w.WriteHeader(http.StatusOK)
	})))
	return e, src, dir
}

func (e *limitEnv) from(ip string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", "/main/token", nil)
	r.RemoteAddr = ip + ":4000"
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, r)
	return rec
}

// Covers: SEC-11 (part)
// Acceptance: Rate limit (part)
func TestThe31stRequestInAMinuteGets429(t *testing.T) {
	e, _, _ := newLimitEnv(t, serverDefault)
	for i := 1; i <= 30; i++ {
		if rec := e.from("192.0.2.1"); rec.Code != http.StatusOK {
			t.Fatalf("request %d: status %d", i, rec.Code)
		}
		e.clk.Advance(10 * time.Millisecond) // 30 requests within 0.3 seconds
	}
	rec := e.from("192.0.2.1")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("the 31st request: status %d", rec.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil ||
		body["error"] != "temporarily_unavailable" || body["error_description"] != "too many requests" {
		t.Errorf("body %q", rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("content type %q", ct)
	}
	if e.hit != 30 {
		t.Errorf("the handler ran %d times", e.hit)
	}
	if rec := e.from("192.0.2.2"); rec.Code != http.StatusOK {
		t.Errorf("another address: status %d", rec.Code)
	}
}

func TestRateLimitRefills(t *testing.T) {
	e, _, _ := newLimitEnv(t, serverDefault)
	for range 30 {
		e.from("192.0.2.1")
	}
	if rec := e.from("192.0.2.1"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status %d", rec.Code)
	}
	e.clk.Advance(2 * time.Second) // 30 a minute is one token every 2 seconds
	if rec := e.from("192.0.2.1"); rec.Code != http.StatusOK {
		t.Errorf("after a token came back: status %d", rec.Code)
	}
	if rec := e.from("192.0.2.1"); rec.Code != http.StatusTooManyRequests {
		t.Errorf("only one token came back: status %d", rec.Code)
	}
}

func TestRateLimitUsesTheClientIPNotTheProxy(t *testing.T) {
	e, _, _ := newLimitEnv(t, "public_url: https://auth.example.com\ntrusted_proxies: [\"127.0.0.1/32\"]\nrate_limit:\n  per_ip_per_minute: 2\n")
	via := func(client string) int {
		r := httptest.NewRequest("GET", "/main/token", nil)
		r.RemoteAddr = "127.0.0.1:4000"
		r.Header.Set("X-Forwarded-For", client)
		rec := httptest.NewRecorder()
		e.h.ServeHTTP(rec, r)
		return rec.Code
	}
	for range 2 {
		if c := via("198.51.100.1"); c != http.StatusOK {
			t.Fatalf("status %d", c)
		}
	}
	if c := via("198.51.100.1"); c != http.StatusTooManyRequests {
		t.Errorf("third request of one client: status %d", c)
	}
	if c := via("198.51.100.2"); c != http.StatusOK {
		t.Errorf("another client behind the same proxy: status %d", c)
	}
}

func TestRateLimitIsLive(t *testing.T) {
	e, src, dir := newLimitEnv(t, serverDefault)
	for range 30 {
		e.from("192.0.2.1")
	}
	if rec := e.from("192.0.2.1"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status %d", rec.Code)
	}
	set := func(n int) {
		dir.Server(t, "public_url: https://auth.example.com\nrate_limit:\n  per_ip_per_minute: "+strconv.Itoa(n)+"\n")
		if res := src.Reload(t.Context()); !res.Applied {
			t.Fatalf("reload: %+v", res)
		}
	}
	set(2)
	for i := range 2 {
		if rec := e.from("192.0.2.1"); rec.Code != http.StatusOK {
			t.Fatalf("after lowering to 2, request %d: status %d", i+1, rec.Code)
		}
	}
	if rec := e.from("192.0.2.1"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("after lowering to 2, third request: status %d", rec.Code)
	}
	set(0) // 0 disables
	for range 100 {
		if rec := e.from("192.0.2.1"); rec.Code != http.StatusOK {
			t.Fatalf("disabled: status %d", rec.Code)
		}
	}
	if n := e.l.Len(); n != 0 {
		t.Errorf("a disabled limiter keeps %d entries", n)
	}
	set(1)
	e.from("192.0.2.1")
	if rec := e.from("192.0.2.1"); rec.Code != http.StatusTooManyRequests {
		t.Errorf("after enabling again: status %d", rec.Code)
	}
}

// Covers: SEC-11 (part)
// Acceptance: Rate limit (part)
func TestIdleEntriesAreEvictedOnTheClock(t *testing.T) {
	e, _, _ := newLimitEnv(t, serverDefault)
	for i := range 1000 {
		a := netip.AddrFrom4([4]byte{10, 0, byte(i / 256), byte(i % 256)})
		e.from(a.String())
	}
	if n := e.l.Len(); n != 1000 {
		t.Fatalf("got %d entries", n)
	}
	e.clk.Advance(30 * time.Second)
	e.from("192.0.2.1") // active again, so it stays
	e.clk.Advance(45 * time.Second)
	if n := e.l.Len(); n != 1 {
		t.Fatalf("after the others were idle for a minute: %d entries, want 1", n)
	}
	e.clk.Advance(2 * time.Minute)
	if n := e.l.Len(); n != 0 {
		t.Fatalf("after everyone was idle: %d entries", n)
	}
	// An evicted address starts with a full bucket, and a new entry restarts
	// the sweeps.
	for range 30 {
		if rec := e.from("10.0.0.1"); rec.Code != http.StatusOK {
			t.Fatalf("status %d", rec.Code)
		}
	}
	e.clk.Advance(2 * time.Minute)
	if n := e.l.Len(); n != 0 {
		t.Fatalf("sweeps did not restart: %d entries", n)
	}
}

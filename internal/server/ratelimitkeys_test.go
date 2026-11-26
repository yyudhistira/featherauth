package server_test

import (
	"fmt"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/server"
	"github.com/yyudhistira/featherauth/internal/testutil"
)

// wiredLimiter is the real router over stub handlers, with the real limiter
// writing to the router's log and reading the router's clock.
func wiredLimiter(t *testing.T, serverYAML string) (*env, *server.Limiter) {
	t.Helper()
	src := testutil.NewConfig(t, serverYAML, map[string]string{"main": testutil.RealmYAML("main", wiringClients)})
	var lim *server.Limiter
	e := newEnvSrc(t, src, func(m *server.Middleware) {
		lim = server.NewLimiter(src, m.Clock, m.Logger)
		m.Limit = lim.Middleware()
	})
	return e, lim
}

// hit sends a request to the token endpoint from addr and returns the status.
func hit(e *env, addr string) int {
	a := netip.MustParseAddr(addr)
	return e.req("GET", "/main/token", netip.AddrPortFrom(a, 4000).String()).Code
}

// fillKeys counts n new keys at lim: IPv4 addresses from 10.0.0.0 up. A key
// that is already held is counted again, so calling it twice refreshes it.
func fillKeys(t *testing.T, lim *server.Limiter, n int) {
	t.Helper()
	for i := range n {
		a := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
		if !lim.Allow(t.Context(), a) {
			t.Fatalf("key %d (%v) refused", i, a)
		}
	}
}

// lastClientIP is the client_ip of the last request line of the log.
func lastClientIP(t *testing.T, e *env) any {
	t.Helper()
	var ip any
	for _, l := range e.log.lines(t) {
		if l["msg"] == "request" {
			ip = l["client_ip"]
		}
	}
	return ip
}

// warnings counts the warning lines of the log.
func warnings(t *testing.T, e *env) int {
	t.Helper()
	n := 0
	for _, l := range e.log.lines(t) {
		if l["level"] == "WARN" {
			n++
		}
	}
	return n
}

// warningLine returns the first warning line of the log, or nil.
func warningLine(t *testing.T, e *env) map[string]any {
	t.Helper()
	for _, l := range e.log.lines(t) {
		if l["level"] == "WARN" {
			return l
		}
	}
	return nil
}

// Covers: SEC-24
// Acceptance: Rate limit keys
func TestRateLimitKeys(t *testing.T) {
	t.Run("31 addresses of one /64 share one count", func(t *testing.T) {
		e, _ := wiredLimiter(t, serverDefault)
		for i := 1; i <= 30; i++ {
			if c := hit(e, fmt.Sprintf("2001:db8:1:2::%x", i)); c != http.StatusOK {
				t.Fatalf("address %d of the /64: status %d", i, c)
			}
		}
		if c := hit(e, "2001:db8:1:2::1f"); c != http.StatusTooManyRequests {
			t.Fatalf("the 31st address of the /64: status %d, want 429", c)
		}
		if ip := lastClientIP(t, e); ip != "2001:db8:1:2::1f" {
			t.Errorf("the log shows client_ip %v, want the full address", ip)
		}
	})

	t.Run("two prefixes are counted apart", func(t *testing.T) {
		e, _ := wiredLimiter(t, serverDefault)
		for i := 1; i <= 30; i++ {
			if c := hit(e, fmt.Sprintf("2001:db8:1:3::%x", i)); c != http.StatusOK {
				t.Fatalf("address %d of the first /64: status %d", i, c)
			}
		}
		if c := hit(e, "2001:db8:1:3::1f"); c != http.StatusTooManyRequests {
			t.Fatalf("the first /64 is used up: status %d, want 429", c)
		}
		if c := hit(e, "2001:db8:1:4::1"); c != http.StatusOK {
			t.Errorf("the second /64 after 30 requests in the first: status %d, want 200", c)
		}
	})

	t.Run("a mapped address shares the count of its IPv4 address", func(t *testing.T) {
		e, _ := wiredLimiter(t, serverDefault)
		for i := range 30 {
			addr := "192.0.2.7"
			if i%2 == 1 {
				addr = "::ffff:192.0.2.7"
			}
			if c := hit(e, addr); c != http.StatusOK {
				t.Fatalf("request %d from %s: status %d", i+1, addr, c)
			}
		}
		if c := hit(e, "::ffff:192.0.2.7"); c != http.StatusTooManyRequests {
			t.Fatalf("the 31st request of the address: status %d, want 429", c)
		}
		if c := hit(e, "192.0.2.8"); c != http.StatusOK {
			t.Errorf("another IPv4 address: status %d", c)
		}
	})

	t.Run("a full table refuses new keys until the idle keys are gone", func(t *testing.T) {
		e, lim := wiredLimiter(t, serverDefault)
		fillKeys(t, lim, 100000) // at t0, the start of the clock
		if n := lim.Len(); n != 100000 {
			t.Fatalf("after 100,000 keys the limiter holds %d", n)
		}
		const newKey = "2001:db8:9:9::5"
		if c := hit(e, newKey); c != http.StatusTooManyRequests {
			t.Fatalf("a new key while the table is full: status %d, want 429", c)
		}
		if ip := lastClientIP(t, e); ip != newKey {
			t.Errorf("the log shows client_ip %v, want the full address %s", ip, newKey)
		}
		if n := warnings(t, e); n != 1 {
			t.Fatalf("after the first refusal: %d warnings, want 1", n)
		}
		if w := warningLine(t, e); w == nil || w["table_size"] != float64(100000) {
			t.Errorf("the warning line %v, want table_size 100000 (a number, not redacted)", w)
		}

		e.clk.Advance(time.Second)
		if c := hit(e, newKey); c != http.StatusTooManyRequests {
			t.Fatalf("a second later: status %d, want 429", c)
		}
		if n := warnings(t, e); n != 1 {
			t.Errorf("within the minute: %d warnings, want 1", n)
		}

		e.clk.Advance(29 * time.Second)
		fillKeys(t, lim, 100000) // every key is used again at t0+30s
		e.clk.Advance(31 * time.Second)
		if c := hit(e, newKey); c != http.StatusTooManyRequests {
			t.Fatalf("a minute later, the keys are still in use: status %d, want 429", c)
		}
		if n := warnings(t, e); n != 2 {
			t.Errorf("a minute after the first warning: %d warnings, want 2", n)
		}

		e.clk.Advance(30 * time.Second) // t0+91s: the keys of t0+30s are a minute old
		if c := hit(e, newKey); c != http.StatusOK {
			t.Fatalf("after the idle keys were removed: status %d, want 200", c)
		}
		if n := lim.Len(); n != 1 {
			t.Errorf("after the sweep the limiter holds %d keys, want 1", n)
		}
	})
}

// Covers: SEC-24 (part)
func TestFullTableSweepsAtMostOncePerSecond(t *testing.T) {
	e, lim := wiredLimiter(t, serverDefault)
	hit(e, "192.0.2.1") // t0: this key starts the sweep timer, which fires at t0+60s
	e.clk.Advance(500 * time.Millisecond)
	fillKeys(t, lim, 99999) // the table is full at t0+0.5s
	hit(e, "192.0.2.1")     // and this key was used at t0+0.5s too
	if n := lim.Len(); n != 100000 {
		t.Fatalf("before the timer: %d keys, want 100,000", n)
	}

	e.clk.Advance(59*time.Second + 700*time.Millisecond) // t0+60.2s: the timer found nothing idle
	if n := lim.Len(); n != 100000 {
		t.Fatalf("after the timer: %d keys, want 100,000 (none is a minute old)", n)
	}
	if c := hit(e, "2001:db8:a::1"); c != http.StatusTooManyRequests {
		t.Fatalf("t0+60.2s: status %d, want 429 (the sweep finds no idle key)", c)
	}

	e.clk.Advance(400 * time.Millisecond) // t0+60.6s: the keys of t0+0.5s are idle, but the last sweep was 0.4s ago
	if c := hit(e, "2001:db8:a::2"); c != http.StatusTooManyRequests {
		t.Fatalf("t0+60.6s: status %d, want 429 (no second sweep within a second)", c)
	}

	e.clk.Advance(700 * time.Millisecond) // t0+61.3s: a second has passed since the last sweep
	if c := hit(e, "2001:db8:a::3"); c != http.StatusOK {
		t.Fatalf("t0+61.3s: status %d, want 200", c)
	}
	if n := lim.Len(); n != 1 {
		t.Errorf("after the sweep the limiter holds %d keys, want 1", n)
	}
}

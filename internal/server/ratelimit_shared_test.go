package server_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/logx"
	"github.com/yyudhistira/featherauth/internal/server"
	"github.com/yyudhistira/featherauth/internal/testutil"
)

// limitSource returns a configuration whose per_ip_per_minute is n.
func limitSource(t *testing.T, n int) config.Source {
	t.Helper()
	return testutil.NewConfig(t, fmt.Sprintf("public_url: https://auth.example.com\nrate_limit:\n  per_ip_per_minute: %d\n", n),
		map[string]string{"main": testutil.RealmYAML("main", wiringClients)})
}

// counterFunc is a Counter that runs fn; it stands in for a count that fails
// or hangs.
type counterFunc func(ctx context.Context, key string, window time.Time) (int64, error)

func (f counterFunc) Hit(ctx context.Context, key string, window time.Time) (int64, error) {
	return f(ctx, key, window)
}

// allowerKind is one implementation of the limiter, for the shared contract.
type allowerKind struct {
	name string
	make func(t *testing.T, src config.Source, clk *clock.Fake) server.Allower
}

var allowerKinds = []allowerKind{
	{name: "memory", make: func(t *testing.T, src config.Source, clk *clock.Fake) server.Allower {
		return server.NewLimiter(src, clk, logx.New(new(bytes.Buffer), slog.LevelError, clk))
	}},
	{name: "database", make: func(t *testing.T, src config.Source, clk *clock.Fake) server.Allower {
		st := testutil.NewStore(t)
		return server.NewSharedLimiter(src, clk, logx.New(new(bytes.Buffer), slog.LevelError, clk), server.StoreCounter(st))
	}},
}

// ip parses an address for the tests.
func ip(s string) netip.Addr { return netip.MustParseAddr(s) }

// Covers: SEC-11 (part), SEC-24 (part), FR-53 (part)
// Acceptance: Shared rate limit (part)
//
// The two implementations of the limiter agree on what they share: the client
// key (an IPv4 address, the /64 of an IPv6 address, an IPv4-mapped address as
// its IPv4 address), zero disables the limit, and the answer over the limit is
// 429.
func TestLimitersShareTheContract(t *testing.T) {
	for _, k := range allowerKinds {
		t.Run(k.name, func(t *testing.T) {
			t.Run("31st request from one address is refused", func(t *testing.T) {
				a := k.make(t, limitSource(t, 30), clock.NewFake(testStart))
				for i := 1; i <= 30; i++ {
					if !a.Allow(t.Context(), ip("192.0.2.10")) {
						t.Fatalf("request %d refused", i)
					}
				}
				if a.Allow(t.Context(), ip("192.0.2.10")) {
					t.Fatal("the 31st request was allowed")
				}
				if !a.Allow(t.Context(), ip("192.0.2.11")) {
					t.Fatal("another address is refused")
				}
			})
			t.Run("addresses of one /64 share one count, another /64 counts apart", func(t *testing.T) {
				a := k.make(t, limitSource(t, 30), clock.NewFake(testStart))
				for i := 1; i <= 30; i++ {
					if !a.Allow(t.Context(), ip(fmt.Sprintf("2001:db8:1::%x", i))) {
						t.Fatalf("address %d of the /64 refused", i)
					}
				}
				if a.Allow(t.Context(), ip("2001:db8:1::ffff")) {
					t.Fatal("the 31st address of the /64 was allowed")
				}
				if !a.Allow(t.Context(), ip("2001:db8:2::1")) {
					t.Fatal("another /64 is refused")
				}
			})
			t.Run("an IPv4-mapped address shares the count of its IPv4 address", func(t *testing.T) {
				a := k.make(t, limitSource(t, 30), clock.NewFake(testStart))
				for i := 1; i <= 30; i++ {
					if !a.Allow(t.Context(), ip("192.0.2.20")) {
						t.Fatalf("request %d refused", i)
					}
				}
				if a.Allow(t.Context(), ip("::ffff:192.0.2.20")) {
					t.Fatal("the mapped address was counted apart from its IPv4 address")
				}
			})
			t.Run("zero disables the limit", func(t *testing.T) {
				a := k.make(t, limitSource(t, 0), clock.NewFake(testStart))
				for i := 0; i < 100; i++ {
					if !a.Allow(t.Context(), ip("192.0.2.30")) {
						t.Fatalf("request %d refused with the limit at 0", i+1)
					}
				}
			})
			t.Run("the answer over the limit is 429", func(t *testing.T) {
				a := k.make(t, limitSource(t, 1), clock.NewFake(testStart))
				h := server.LimitWith(a)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
				first := httptest.NewRecorder()
				h.ServeHTTP(first, httptest.NewRequest(http.MethodPost, "/main/token", nil))
				second := httptest.NewRecorder()
				h.ServeHTTP(second, httptest.NewRequest(http.MethodPost, "/main/token", nil))
				if first.Code != http.StatusOK || second.Code != http.StatusTooManyRequests {
					t.Fatalf("answers %d and %d, want 200 then 429", first.Code, second.Code)
				}
			})
		})
	}
}

// Covers: FR-53 (part)
// Acceptance: Shared rate limit (part)
//
// The count is per minute of the service clock: the next minute starts from zero.
func TestSharedLimitStartsFromZeroInTheNextMinute(t *testing.T) {
	clk := clock.NewFake(testStart)
	a := server.NewSharedLimiter(limitSource(t, 2), clk, logx.New(new(bytes.Buffer), slog.LevelError, clk), server.StoreCounter(testutil.NewStore(t)))
	for i := 0; i < 2; i++ {
		if !a.Allow(t.Context(), ip("192.0.2.40")) {
			t.Fatalf("request %d refused", i+1)
		}
	}
	if a.Allow(t.Context(), ip("192.0.2.40")) {
		t.Fatal("the third request in the minute was allowed")
	}
	clk.Advance(time.Minute)
	if !a.Allow(t.Context(), ip("192.0.2.40")) {
		t.Fatal("the next minute did not start from zero")
	}
}

// A count that fails is counted by the instance's own limiter instead, and the
// failure is logged once a minute, not once a request.
//
// Covers: FR-53 (part)
// Acceptance: Shared rate limit (part)
func TestFailingCountFallsBackToTheOwnLimiterAndLogsOncePerMinute(t *testing.T) {
	clk := clock.NewFake(testStart)
	var logs bytes.Buffer
	failing := counterFunc(func(context.Context, string, time.Time) (int64, error) {
		return 0, errors.New("database is down")
	})
	a := server.NewSharedLimiter(limitSource(t, 30), clk, logx.New(&logs, slog.LevelInfo, clk), failing)
	for i := 1; i <= 30; i++ {
		if !a.Allow(t.Context(), ip("192.0.2.50")) {
			t.Fatalf("request %d refused by the own limiter", i)
		}
	}
	if a.Allow(t.Context(), ip("192.0.2.50")) {
		t.Fatal("the 31st request was allowed while the count fails")
	}
	if n := strings.Count(logs.String(), "rate limit count failed"); n != 1 {
		t.Fatalf("%d failure lines in the first minute, want 1: %s", n, logs.String())
	}
	clk.Advance(time.Minute)
	a.Allow(t.Context(), ip("192.0.2.51"))
	if n := strings.Count(logs.String(), "rate limit count failed"); n != 2 {
		t.Fatalf("%d failure lines after a minute, want 2", n)
	}
}

// A count that takes longer than a second is given up at the second: the request
// is counted by the own limiter, as for a failure.
//
// Covers: FR-53 (part)
// Acceptance: Shared rate limit (part)
func TestHungCountIsGivenUpAfterOneSecond(t *testing.T) {
	clk := clock.NewFake(testStart)
	started := make(chan struct{})
	gaveUp := make(chan error, 1)
	hanging := counterFunc(func(ctx context.Context, _ string, _ time.Time) (int64, error) {
		close(started)
		<-ctx.Done()
		gaveUp <- ctx.Err()
		return 0, ctx.Err()
	})
	a := server.NewSharedLimiter(limitSource(t, 30), clk, logx.New(new(bytes.Buffer), slog.LevelError, clk), hanging)
	done := make(chan bool, 1)
	go func() { done <- a.Allow(t.Context(), ip("192.0.2.60")) }()

	<-started
	clk.Advance(time.Second - time.Nanosecond)
	select {
	case <-gaveUp:
		t.Fatal("the count was given up before a second")
	default:
	}
	clk.Advance(time.Nanosecond)
	if err := <-gaveUp; !errors.Is(err, context.Canceled) {
		t.Fatalf("the count ended with %v, want it cancelled", err)
	}
	if !<-done {
		t.Fatal("the own limiter refused the first request after the count gave up")
	}
}

// A client that goes away cancels its request: the count is cancelled with it,
// the own limiter decides silently, and no failure is logged.
//
// Covers: FR-53 (part)
func TestCancelledRequestIsNotACountFailure(t *testing.T) {
	clk := clock.NewFake(testStart)
	var logs bytes.Buffer
	cancelled := counterFunc(func(ctx context.Context, _ string, _ time.Time) (int64, error) {
		<-ctx.Done()
		return 0, ctx.Err()
	})
	a := server.NewSharedLimiter(limitSource(t, 1), clk, logx.New(&logs, slog.LevelInfo, clk), cancelled)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if !a.Allow(ctx, ip("192.0.2.80")) {
		t.Fatal("the own limiter refused the first request of a cancelled client")
	}
	if a.Allow(ctx, ip("192.0.2.80")) {
		t.Fatal("the own limiter did not count the cancelled request")
	}
	if strings.Contains(logs.String(), "rate limit count failed") {
		t.Fatalf("a cancelled client was logged as a failed count: %s", logs.String())
	}
}

// The failure line carries the error value, so logx cleans the URLs of an
// error from an outgoing call; the message keeps no query.
//
// Covers: SEC-13 (part)
func TestCountFailureLogsTheErrorValueCleaned(t *testing.T) {
	clk := clock.NewFake(testStart)
	var logs bytes.Buffer
	urlErr := &url.Error{Op: "Post", URL: "https://db.example/write?code=fixture-query-code", Err: errors.New("refused")}
	failing := counterFunc(func(context.Context, string, time.Time) (int64, error) { return 0, urlErr })
	a := server.NewSharedLimiter(limitSource(t, 30), clk, logx.New(&logs, slog.LevelInfo, clk), failing)
	a.Allow(t.Context(), ip("192.0.2.81"))
	if !strings.Contains(logs.String(), "rate limit count failed") {
		t.Fatalf("the failure is not logged: %s", logs.String())
	}
	if strings.Contains(logs.String(), "fixture-query-code") {
		t.Fatalf("the query of the error is in the log: %s", logs.String())
	}
}

// A count that answers in time is the count: the request over the shared limit
// is refused even when the own limiter would allow it.
//
// Covers: FR-53 (part)
// Acceptance: Shared rate limit (part)
func TestCountInTimeDecidesTheRequest(t *testing.T) {
	clk := clock.NewFake(testStart)
	over := counterFunc(func(context.Context, string, time.Time) (int64, error) { return 31, nil })
	a := server.NewSharedLimiter(limitSource(t, 30), clk, logx.New(new(bytes.Buffer), slog.LevelError, clk), over)
	if a.Allow(t.Context(), ip("192.0.2.70")) {
		t.Fatal("the 31st request of the shared count was allowed")
	}
}

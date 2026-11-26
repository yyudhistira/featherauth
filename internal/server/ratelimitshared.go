package server

import (
	"context"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/store"
)

// statementLimit is how long the shared count may take before the request is
// counted by the instance's own limiter instead (FR-53).
const statementLimit = time.Second

// Counter adds one request to the shared count of a key in a window (a minute
// of the service clock) and returns the count of that window. StoreCounter is
// the database's; a test may supply another.
type Counter interface {
	Hit(ctx context.Context, key string, window time.Time) (int64, error)
}

// StoreCounter counts in the rate_limits table of st, in one write transaction.
func StoreCounter(st store.Store) Counter { return storeCounter{st} }

type storeCounter struct{ st store.Store }

func (c storeCounter) Hit(ctx context.Context, key string, window time.Time) (int64, error) {
	var n int64
	err := c.st.Write(ctx, func(tx store.Tx) (err error) {
		n, err = tx.RateLimits().Hit(ctx, key, window)
		return err
	})
	return n, err
}

// SharedLimiter is the rate limit with rate_limit.store database (FR-53): the
// count of each key and minute is kept by the database, so that every instance
// of one database counts the same requests. A count that fails, or takes longer
// than a second, is replaced by the instance's own limiter for that request, and
// the failure is logged once a minute; login is never refused by an outage of
// the shared count, and the limit is never dropped either.
type SharedLimiter struct {
	src    config.Source
	clock  clock.Clock
	log    *slog.Logger
	counts Counter
	own    *Limiter

	mu     sync.Mutex
	warned time.Time // when a failure was last logged
}

var _ Allower = (*SharedLimiter)(nil)

// NewSharedLimiter returns a SharedLimiter that counts in counts and reads
// per_ip_per_minute from src. Its fallback is a Limiter of its own.
func NewSharedLimiter(src config.Source, c clock.Clock, log *slog.Logger, counts Counter) *SharedLimiter {
	return &SharedLimiter{src: src, clock: c, log: log, counts: counts, own: NewLimiter(src, c, log)}
}

// Allow reports whether a request from ip may go on, and counts it in the
// shared count. A limit of 0 disables the limit, without a count.
func (s *SharedLimiter) Allow(ctx context.Context, ip netip.Addr) bool {
	limit := s.src.Current().Server().RateLimit.PerIPPerMinute
	if limit <= 0 {
		return true
	}
	now := s.clock.Now()
	n, err := s.count(ctx, rateKey(ip).String(), now.UTC().Truncate(time.Minute))
	if err != nil {
		// A client that went away cancels the request's context: that is not a
		// failure of the count, so the own limiter decides and nothing is logged.
		if ctx.Err() == nil {
			s.failed(ctx, err)
		}
		return s.own.Allow(ctx, ip)
	}
	return n <= int64(limit)
}

// count runs the shared count with the statement limit: a count still running
// at the limit is cancelled and returns the cancellation.
func (s *SharedLimiter) count(ctx context.Context, key string, window time.Time) (int64, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	t := s.clock.AfterFunc(statementLimit, cancel)
	defer t.Stop()
	return s.counts.Hit(ctx, key, window)
}

// failed logs a failed count at most once a minute.
func (s *SharedLimiter) failed(ctx context.Context, err error) {
	now := s.clock.Now()
	s.mu.Lock()
	warn := s.warned.IsZero() || now.Sub(s.warned) >= warnEvery
	if warn {
		s.warned = now
	}
	s.mu.Unlock()
	if warn {
		// The error value, not its text: logx cleans the URLs of an error value
		// and does not inspect free text (SEC-13).
		s.log.LogAttrs(ctx, slog.LevelWarn, "rate limit count failed; this instance counts its own requests for now",
			slog.Any("error", err))
	}
}

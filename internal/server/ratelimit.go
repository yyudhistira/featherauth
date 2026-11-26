package server

import (
	"context"
	"log/slog"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/config"
)

const (
	// idleAfter is how long a key must be quiet before its entry goes: a
	// bucket refills completely within a minute whatever the limit, so an idle
	// entry is the same as a new one.
	idleAfter = time.Minute

	// maxKeys is the number of keys the limiter remembers at most (SEC-24). It
	// is a fixed number, not an option.
	maxKeys = 100000

	// sweepEvery is the least time between two sweeps that a request from a
	// new key starts while the table is full.
	sweepEvery = time.Second

	// warnEvery is the least time between two warnings that the table is full.
	warnEvery = time.Minute
)

// rateKey returns the key a client address is counted under (SEC-24): the
// address itself for IPv4 (an IPv4-mapped IPv6 address is its IPv4 address),
// and the /64 prefix for IPv6, because one IPv6 host normally controls a whole
// /64. The zone is dropped. The zero address is its own key.
func rateKey(ip netip.Addr) netip.Addr {
	ip = ip.Unmap().WithZone("")
	if !ip.Is6() {
		return ip
	}
	p, _ := ip.Prefix(64) // 64 is a valid length for an IPv6 address
	return p.Addr()
}

// Limiter is the rate limit of SEC-11 and SEC-24: a token bucket per client
// key (see rateKey), one shared by the endpoints it is applied to, in memory.
// The limit is read from the snapshot at every request. Idle entries are
// swept on the clock.
type Limiter struct {
	src   config.Source
	clock clock.Clock
	log   *slog.Logger

	mu      sync.Mutex
	limit   int // per minute; the limit the entries were made for
	entries map[netip.Addr]*entry
	sweep   clock.Timer // pending sweep, nil when there are no entries
	swept   time.Time   // when a request from a new key last swept the table
	warned  time.Time   // when the table was last reported full
}

type entry struct {
	lim  *rate.Limiter
	seen time.Time
}

// NewLimiter returns a Limiter that reads per_ip_per_minute from src and logs
// through log.
func NewLimiter(src config.Source, c clock.Clock, log *slog.Logger) *Limiter {
	return &Limiter{src: src, clock: c, log: log, entries: map[netip.Addr]*entry{}}
}

// Len is the number of keys the limiter remembers.
func (l *Limiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.entries)
}

// Allow reports whether a request from ip may go on, and counts it. While the
// table is full, a request from a key it does not hold is refused; the refusal
// is logged at most once a minute.
func (l *Limiter) Allow(ctx context.Context, ip netip.Addr) bool {
	limit := l.src.Current().Server().RateLimit.PerIPPerMinute
	ok, warn := l.allow(rateKey(ip), limit, l.clock.Now())
	if warn {
		l.log.LogAttrs(ctx, slog.LevelWarn, "rate limit table full", slog.Int("table_size", maxKeys))
	}
	return ok
}

// allow counts a request under key. It returns whether the request may go on,
// and whether the caller should log that the table is full.
func (l *Limiter) allow(key netip.Addr, limit int, now time.Time) (ok, warn bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if limit != l.limit {
		l.limit = limit
		clear(l.entries)
	}
	if limit <= 0 {
		return true, false
	}
	e, held := l.entries[key]
	if !held {
		if len(l.entries) >= maxKeys && !l.makeRoom(now) {
			if now.Sub(l.warned) >= warnEvery {
				l.warned = now
				warn = true
			}
			return false, warn
		}
		e = &entry{lim: rate.NewLimiter(rate.Limit(float64(limit)/time.Minute.Seconds()), limit)}
		l.entries[key] = e
	}
	e.seen = now
	if l.sweep == nil {
		l.sweep = l.clock.AfterFunc(idleAfter, l.sweepIdle)
	}
	return e.lim.AllowN(now, 1), false
}

// makeRoom sweeps the idle keys out of a full table, at most once a second,
// and reports whether the table has room for a new key.
func (l *Limiter) makeRoom(now time.Time) bool {
	if now.Sub(l.swept) >= sweepEvery {
		l.swept = now
		l.dropIdle(now)
	}
	return len(l.entries) < maxKeys
}

// dropIdle removes the entries that have been quiet for idleAfter.
func (l *Limiter) dropIdle(now time.Time) {
	for key, e := range l.entries {
		if now.Sub(e.seen) >= idleAfter {
			delete(l.entries, key)
		}
	}
}

// sweepIdle drops the idle entries and schedules the next sweep while any
// remain.
func (l *Limiter) sweepIdle() {
	now := l.clock.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.dropIdle(now)
	l.sweep = nil
	if len(l.entries) > 0 {
		l.sweep = l.clock.AfterFunc(idleAfter, l.sweepIdle)
	}
}

// Allower is the rate limit the middleware applies: Limiter (the instance's own
// counts, in memory) and SharedLimiter (counts in the database) implement it.
type Allower interface {
	Allow(ctx context.Context, ip netip.Addr) bool
}

var _ Allower = (*Limiter)(nil)

// Middleware answers 429 to a request over the limit. The address is the one
// ClientIPMiddleware resolved; without it the connection's address is used.
func (l *Limiter) Middleware() func(http.Handler) http.Handler { return LimitWith(l) }

// LimitWith is the middleware of a limiter: it answers 429 to a request the
// limiter refuses.
func LimitWith(a Allower) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip, ok := ClientIPFrom(r.Context())
			if !ok {
				ip = connAddr(r.RemoteAddr)
			}
			if !a.Allow(r.Context(), ip) {
				kind := KindAPI
				if info, ok := FromContext(r.Context()); ok {
					kind = info.Kind
				}
				writeError(w, kind, http.StatusTooManyRequests, "temporarily_unavailable", "too many requests")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

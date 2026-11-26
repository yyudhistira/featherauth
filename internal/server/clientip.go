package server

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"

	"github.com/yyudhistira/featherauth/internal/config"
)

// ClientIP returns the address of the client of r. The connection's address is
// the client unless it lies in trusted (the proxies of trusted_proxies); then
// X-Forwarded-For is read from right to left, skipping addresses in trusted,
// and the first other address is the client. A header that is absent, made only
// of trusted addresses, or holding an entry that is not an address, gives the
// connection's address. The result is the zero Addr when the connection's
// address cannot be parsed.
func ClientIP(r *http.Request, trusted []netip.Prefix) netip.Addr {
	conn := connAddr(r.RemoteAddr)
	if !conn.IsValid() || !inPrefixes(conn, trusted) {
		return conn
	}
	var entries []string
	for _, v := range r.Header.Values("X-Forwarded-For") {
		entries = append(entries, strings.Split(v, ",")...)
	}
	for i := len(entries) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(entries[i]))
		if err != nil {
			return conn
		}
		a = a.Unmap().WithZone("")
		if !inPrefixes(a, trusted) {
			return a
		}
	}
	return conn
}

func connAddr(remote string) netip.Addr {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return a.Unmap().WithZone("")
}

func inPrefixes(a netip.Addr, ps []netip.Prefix) bool {
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

type clientIPKey struct{}

// ClientIPFrom returns the client address that ClientIPMiddleware put in ctx.
func ClientIPFrom(ctx context.Context) (netip.Addr, bool) {
	a, ok := ctx.Value(clientIPKey{}).(netip.Addr)
	return a, ok
}

// trustedCache holds the parsed trusted_proxies of one snapshot.
type trustedCache struct {
	snap     *config.Snapshot
	prefixes []netip.Prefix
}

// trustedProxies parses trusted_proxies once per snapshot.
type trustedProxies struct{ cache atomic.Pointer[trustedCache] }

func (t *trustedProxies) of(snap *config.Snapshot) []netip.Prefix {
	if c := t.cache.Load(); c != nil && c.snap == snap {
		return c.prefixes
	}
	var ps []netip.Prefix
	for _, s := range snap.Server().TrustedProxies {
		if p, err := netip.ParsePrefix(s); err == nil { // validated at load
			ps = append(ps, p)
		}
	}
	t.cache.Store(&trustedCache{snap: snap, prefixes: ps})
	return ps
}

// withClientIP returns r with the client address in its context.
func withClientIP(r *http.Request, ip netip.Addr) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), clientIPKey{}, ip))
}

// ClientIPMiddleware resolves the client address of every request with the
// trusted_proxies of the current snapshot (a live option) and puts it in the
// request context. The Router does the same itself, first of all, so that its
// log and its rate limit see the same address.
func ClientIPMiddleware(src config.Source) func(http.Handler) http.Handler {
	var tp trustedProxies
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, withClientIP(r, ClientIP(r, tp.of(src.Current()))))
		})
	}
}

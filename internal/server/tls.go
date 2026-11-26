package server

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
)

// Certificate is the certificate pair of built-in TLS (tls.mode files). The
// HTTPS listener asks it for the pair at each handshake, so a pair loaded again
// is served from the next handshake on, without a restart.
type Certificate struct {
	load func() (*tls.Certificate, error)
	log  *slog.Logger
	cur  atomic.Pointer[tls.Certificate]
	mu   sync.Mutex // serialises Reload
}

// NewCertificate loads the first pair with load. It fails when load does.
func NewCertificate(load func() (*tls.Certificate, error), log *slog.Logger) (*Certificate, error) {
	pair, err := load()
	if err != nil {
		return nil, err
	}
	c := &Certificate{load: load, log: log}
	c.cur.Store(pair)
	return c, nil
}

// LogValue logs the state of the pair and never its key: whether a pair is
// served, and when its certificate expires.
func (c *Certificate) LogValue() slog.Value {
	pair := c.cur.Load()
	if pair == nil || pair.Leaf == nil {
		return slog.GroupValue(slog.Bool("served", pair != nil))
	}
	return slog.GroupValue(slog.Bool("served", true), slog.Time("not_after", pair.Leaf.NotAfter.UTC()))
}

// GetCertificate returns the pair being served. It is the GetCertificate of the
// listener's tls.Config.
func (c *Certificate) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return c.cur.Load(), nil
}

// Reload loads the pair again and serves it from the next handshake on. A pair
// that cannot be loaded is logged, the pair being served stays, and Reload
// returns the error. The log never holds key material: the error describes the
// file and the reason.
func (c *Certificate) Reload(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	pair, err := c.load()
	if err != nil {
		c.log.ErrorContext(ctx, "cannot load the certificate pair; the previous pair keeps serving", "error", err)
		return err
	}
	c.cur.Store(pair)
	c.log.InfoContext(ctx, "certificate loaded")
	return nil
}

// Redirect answers every request with a 301 to the same path and query under
// publicURL, the https origin of the service. The target is built from the
// path and the query of the request URL, never from the Host header or from
// the request target as sent, so an absolute-form request cannot choose the
// host it is sent to. The nosniff header is set on the answers of this
// handler; net/http's own answers (for a malformed request, for example) are
// written before any handler runs and carry no header, as with the router.
func Redirect(publicURL string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		target := r.URL.EscapedPath()
		if target == "" {
			target = "/"
		}
		if r.URL.RawQuery != "" {
			target += "?" + r.URL.RawQuery
		}
		http.Redirect(w, r, publicURL+target, http.StatusMovedPermanently)
	})
}

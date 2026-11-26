// Package server is the HTTP foundation: it routes requests from the
// configured path templates to the endpoint handlers, answers the health
// endpoints and the errors of its own, recovers panics and writes the request
// log. It knows no endpoint logic.
package server

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/logx"
)

// MaxBodyBytes is the largest request body the service reads (64 KB).
const MaxBodyBytes = 64 << 10

// Kind says how the router answers its own errors on an endpoint.
type Kind int

// The kinds of endpoints: API endpoints answer OAuth error JSON, browser
// endpoints answer an HTML page.
const (
	KindAPI Kind = iota
	KindBrowser
)

// Handlers has one method per endpoint. The router calls it only for a path
// that matches the configured template of a known realm; the realm, the
// provider of the path and the configuration snapshot are in the request
// context (FromContext). Methods and endpoint logic are the handler's.
type Handlers interface {
	Discovery(http.ResponseWriter, *http.Request)
	Authorize(http.ResponseWriter, *http.Request)
	Callback(http.ResponseWriter, *http.Request)
	// CallbackContinue is the callback path followed by /continue.
	CallbackContinue(http.ResponseWriter, *http.Request)
	Token(http.ResponseWriter, *http.Request)
	Userinfo(http.ResponseWriter, *http.Request)
	JWKS(http.ResponseWriter, *http.Request)
	Logout(http.ResponseWriter, *http.Request)
	Revoke(http.ResponseWriter, *http.Request)
	Sessions(http.ResponseWriter, *http.Request)
	AccountDelete(http.ResponseWriter, *http.Request)
	Assets(http.ResponseWriter, *http.Request)
	ProviderEvents(http.ResponseWriter, *http.Request)
	DataDeletion(http.ResponseWriter, *http.Request)
}

// Pinger reports whether the database can be reached; store.Store has it.
type Pinger interface {
	Ping(ctx context.Context) error
}

// Middleware is what the router needs besides the configuration and the
// handlers.
type Middleware struct {
	// Logger writes the request log and the panic log; required.
	Logger *slog.Logger
	// Clock times requests; required.
	Clock clock.Clock
	// Ready is pinged by /readyz; nil means always ready.
	Ready Pinger
	// Limit is applied to authorize, callback, continue, token and provider
	// events (SEC-11), after the client address is resolved; nil means no
	// limit. Limiter.Middleware is the one to use.
	Limit func(http.Handler) http.Handler
	// CORS is applied to the API endpoints; nil means none. CORS() is the one
	// to use.
	CORS func(http.Handler) http.Handler
}

// Info is what the router knows about a request once it is routed.
type Info struct {
	Endpoint string
	Kind     Kind
	// Snapshot is the one configuration snapshot of this request.
	Snapshot *config.Snapshot
	// Realm is nil for the health endpoints.
	Realm *config.Realm
	// Provider is the {provider} of the path, empty when it has none.
	Provider config.ProviderKey
}

type infoKey struct{}

// FromContext returns the routing information of the request.
func FromContext(ctx context.Context) (Info, bool) {
	i, ok := ctx.Value(infoKey{}).(*Info)
	if !ok {
		return Info{}, false
	}
	return *i, true
}

// Router routes requests; use NewHandler.
type Router struct {
	src      config.Source
	h        Handlers
	log      *slog.Logger
	clock    clock.Clock
	ready    Pinger
	mw       Middleware
	trusted  trustedProxies
	tbl      atomic.Pointer[table]
	shutdown atomic.Bool
}

var _ http.Handler = (*Router)(nil)

// NewHandler returns the router. The route table is built from the snapshot
// of the first request and rebuilt when the source gives another snapshot
// (a reload).
func NewHandler(src config.Source, h Handlers, mw Middleware) *Router {
	return &Router{src: src, h: h, log: mw.Logger, clock: mw.Clock, ready: mw.Ready, mw: mw}
}

// BeginShutdown makes /readyz answer 503 from now on.
func (rt *Router) BeginShutdown() { rt.shutdown.Store(true) }

// table returns the route table of snap.
func (rt *Router) table(snap *config.Snapshot) *table {
	if t := rt.tbl.Load(); t != nil && t.snap == snap {
		return t
	}
	t := buildTable(snap, rt.h, rt.mw)
	rt.tbl.Store(t)
	return t
}

// ServeHTTP implements http.Handler. It sets X-Content-Type-Options: nosniff
// first, so every answer of the router carries it: the endpoints', the
// router's own and the health endpoints' (SEC-29). net/http's own answers (for
// a malformed request, for example) are written before the router runs and
// carry no header; the router cannot reach them.
func (rt *Router) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rt.serve(w, r, false)
}

// HealthHandler is the router for a listener that serves the health endpoints
// only: the loopback listener of built-in TLS (tls.mode files). /healthz and
// /readyz answer as they do in the router; every other path is a plain 404. It
// shares the router's shutdown state, and its answers are logged the same way.
func (rt *Router) HealthHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rt.serve(w, r, true)
	})
}

func (rt *Router) serve(w http.ResponseWriter, r *http.Request, healthOnly bool) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	snap := rt.src.Current()
	ip := ClientIP(r, rt.trusted.of(snap))
	info := &Info{Snapshot: snap}
	r = withClientIP(r.WithContext(context.WithValue(r.Context(), infoKey{}, info)), ip)
	sw := &statusWriter{ResponseWriter: w}
	start := rt.clock.Now()

	defer func() {
		line := logx.RequestLine{
			Method:   r.Method,
			Path:     logx.Path(r.URL),
			Status:   sw.status(),
			Duration: rt.clock.Now().Sub(start),
		}
		if ip.IsValid() {
			line.ClientIP = ip.String()
		}
		if info.Realm != nil {
			line.Realm = string(info.Realm.Name)
		}
		logx.Request(r.Context(), rt.log, line)
	}()
	defer rt.recoverPanic(sw, r, info)

	switch r.URL.Path {
	case "/healthz", "/readyz":
		info.Endpoint = strings.TrimPrefix(r.URL.Path, "/")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			sw.Header().Set("Allow", http.MethodGet+", "+http.MethodHead)
			sw.Header().Set("Content-Type", "text/plain; charset=utf-8")
			sw.Header().Set("Cache-Control", "no-store")
			sw.WriteHeader(http.StatusMethodNotAllowed)
			_, _ = io.WriteString(sw, "method not allowed\n")
			return
		}
		if info.Endpoint == "healthz" {
			rt.healthz(sw)
		} else {
			rt.readyz(sw, r)
		}
		return
	}

	if healthOnly {
		http.NotFound(sw, r)
		return
	}
	m, ok := rt.table(snap).match(r.URL.Path)
	if !ok {
		http.NotFound(sw, r)
		return
	}
	info.Endpoint, info.Kind, info.Provider = m.route.name, m.route.kind, m.provider
	realm, ok := snap.Realm(m.realm)
	if !ok {
		writeError(sw, info.Kind, http.StatusNotFound, "invalid_request", "unknown realm")
		return
	}
	info.Realm = realm

	m.route.handler.ServeHTTP(sw, r)
}

// limitBody reads the request body up to MaxBodyBytes and puts it back, so
// that the handler sees a body that fits; a larger one is answered 413.
func limitBody(w http.ResponseWriter, r *http.Request, k Kind) bool {
	if r.Body == nil || r.Body == http.NoBody {
		return true
	}
	if r.ContentLength > MaxBodyBytes {
		writeError(w, k, http.StatusRequestEntityTooLarge, "invalid_request", "request body too large")
		return false
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, MaxBodyBytes+1))
	_ = r.Body.Close()
	if len(b) > MaxBodyBytes {
		writeError(w, k, http.StatusRequestEntityTooLarge, "invalid_request", "request body too large")
		return false
	}
	if err != nil {
		writeError(w, k, http.StatusBadRequest, "invalid_request", "the request body could not be read")
		return false
	}
	r.Body = io.NopCloser(bytes.NewReader(b))
	return true
}

func (rt *Router) healthz(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.WriteString(w, "ok\n")
}

func (rt *Router) readyz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if rt.shutdown.Load() {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, "shutting down\n")
		return
	}
	if rt.ready != nil {
		if err := rt.ready.Ping(r.Context()); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, "not ready\n")
			return
		}
	}
	_, _ = io.WriteString(w, "ok\n")
}

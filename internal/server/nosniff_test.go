package server_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yyudhistira/featherauth/internal/server"
	"github.com/yyudhistira/featherauth/internal/testutil"
)

const nosniffRateYAML = "public_url: https://auth.example.com\nrate_limit:\n  per_ip_per_minute: 1\n"

// readyWired is wired with a readiness check that is ready's Ping.
func readyWired(t *testing.T, serverYAML string, ready pinger) *env {
	t.Helper()
	src := testutil.NewConfig(t, serverYAML, map[string]string{"main": testutil.RealmYAML("main", wiringClients)})
	return newEnvSrc(t, src, func(m *server.Middleware) {
		m.Ready = ready
		m.Limit = server.NewLimiter(src, m.Clock, m.Logger).Middleware()
		m.CORS = server.CORS()
	})
}

// Covers: SEC-29
// Acceptance: nosniff on every response
func TestEveryRouterAnswerCarriesNosniff(t *testing.T) {
	big := strings.Repeat("a", 64<<10+1)
	tests := []struct {
		name   string
		yaml   string
		ready  pinger
		prep   func(*env)
		method string
		path   string
		hdr    []string
		body   string
		code   int
	}{
		{name: "unmatched path", yaml: serverDefault, method: "GET", path: "/nowhere", code: http.StatusNotFound},
		{name: "unknown realm, API", yaml: serverDefault, method: "POST", path: "/nope/token", code: http.StatusNotFound},
		{name: "unknown realm, browser", yaml: serverDefault, method: "GET", path: "/nope/authorize", code: http.StatusNotFound},
		{name: "healthz", yaml: serverDefault, method: "GET", path: "/healthz", code: http.StatusOK},
		{name: "healthz HEAD", yaml: serverDefault, method: "HEAD", path: "/healthz", code: http.StatusOK},
		{name: "healthz 405", yaml: serverDefault, method: "POST", path: "/healthz", code: http.StatusMethodNotAllowed},
		{name: "readyz", yaml: serverDefault, method: "GET", path: "/readyz", code: http.StatusOK},
		{name: "readyz shutting down", yaml: serverDefault, prep: func(e *env) { e.rt.BeginShutdown() }, method: "GET", path: "/readyz", code: http.StatusServiceUnavailable},
		{name: "readyz database down", yaml: serverDefault, ready: pinger(func() error { return errors.New("database down") }), method: "GET", path: "/readyz", code: http.StatusServiceUnavailable},
		{name: "body too large, API", yaml: serverDefault, method: "POST", path: "/main/token", body: big, code: http.StatusRequestEntityTooLarge},
		{name: "body too large, browser", yaml: serverDefault, method: "POST", path: "/main/authorize", body: big, code: http.StatusRequestEntityTooLarge},
		{name: "rate limit, API", yaml: nosniffRateYAML, prep: func(e *env) { e.do("POST", "/main/token", "") }, method: "POST", path: "/main/token", code: http.StatusTooManyRequests},
		{name: "rate limit, browser", yaml: nosniffRateYAML, prep: func(e *env) { e.do("GET", "/main/authorize", "") }, method: "GET", path: "/main/authorize", code: http.StatusTooManyRequests},
		{name: "CORS preflight, API", yaml: serverDefault, method: "OPTIONS", path: "/main/token", hdr: []string{"Origin", "https://app.example.com", "Access-Control-Request-Method", "POST"}, code: http.StatusNoContent},
		{name: "panic, API", yaml: serverDefault, prep: panicking, method: "POST", path: "/main/token", code: http.StatusInternalServerError},
		{name: "panic, browser", yaml: serverDefault, prep: panicking, method: "GET", path: "/main/authorize", code: http.StatusInternalServerError},
		{name: "handler answer, API", yaml: serverDefault, method: "GET", path: "/main/jwks.json", code: http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := wired(t, tt.yaml)
			if tt.ready != nil {
				e = readyWired(t, tt.yaml, tt.ready)
			}
			if tt.prep != nil {
				tt.prep(e)
			}
			req := httptest.NewRequest(tt.method, tt.path, strings.NewReader(tt.body))
			req.RemoteAddr = "192.0.2.10:4000"
			for i := 0; i+1 < len(tt.hdr); i += 2 {
				req.Header.Set(tt.hdr[i], tt.hdr[i+1])
			}
			rec := httptest.NewRecorder()
			e.rt.ServeHTTP(rec, req)
			if rec.Code != tt.code {
				t.Fatalf("status %d, want %d", rec.Code, tt.code)
			}
			if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
				t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
			}
		})
	}
}

// panicking makes every handler panic.
func panicking(e *env) {
	e.h.run = func(http.ResponseWriter, *http.Request) { panic("x") }
}

// Covers: SEC-29
// Acceptance: nosniff on every response (part)
func TestNosniffIsSetBeforeTheHandlerRuns(t *testing.T) {
	e := wired(t, serverDefault)
	var seen string
	e.h.run = func(w http.ResponseWriter, _ *http.Request) {
		seen = w.Header().Get("X-Content-Type-Options")
		w.WriteHeader(http.StatusOK)
	}
	e.req("GET", "/main/jwks.json", "192.0.2.1:1")
	if seen != "nosniff" {
		t.Errorf("the handler saw X-Content-Type-Options %q, want nosniff", seen)
	}
}

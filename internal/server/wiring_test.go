package server_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yyudhistira/featherauth/internal/server"
	"github.com/yyudhistira/featherauth/internal/testutil"
)

const (
	wiringClients = `clients:
  web:
    redirect_uris: [https://app.example.com/callback]
    web_origins: [https://app.example.com]
`
	serverWithProxy = "public_url: https://auth.example.com\ntrusted_proxies: [\"127.0.0.1/32\"]\nrate_limit:\n  per_ip_per_minute: 2\n"
)

// wired is the real router with the real limiter and CORS middleware over
// stub handlers.
func wired(t *testing.T, serverYAML string) *env {
	t.Helper()
	src := testutil.NewConfig(t, serverYAML, map[string]string{"main": testutil.RealmYAML("main", wiringClients)})
	e := newEnvSrc(t, src, func(m *server.Middleware) {
		m.Limit = server.NewLimiter(src, m.Clock, m.Logger).Middleware()
		m.CORS = server.CORS()
	})
	return e
}

func (e *env) req(method, target, remote string, hdr ...string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, nil)
	r.RemoteAddr = remote
	for i := 0; i+1 < len(hdr); i += 2 {
		r.Header.Set(hdr[i], hdr[i+1])
	}
	rec := httptest.NewRecorder()
	e.rt.ServeHTTP(rec, r)
	return rec
}

var (
	browserEndpoints = map[string]string{
		"authorize": "/main/authorize", "callback": "/main/callback/google", "continue": "/main/callback/google/continue",
		"logout": "/main/logout", "assets": "/main/assets/style.css", "data_deletion": "/main/data-deletion",
	}
	apiEndpoints = map[string]string{
		"discovery": "/main/.well-known/openid-configuration", "token": "/main/token", "userinfo": "/main/userinfo",
		"jwks": "/main/jwks.json", "account_delete": "/main/account", "provider_events": "/main/events/apple",
		"revoke": "/main/revoke",
	}
)

// Covers: SEC-11 (part)
// Acceptance: Client IP (part)
func TestClientIPIsResolvedBeforeRateLimitingAndLogging(t *testing.T) {
	e := wired(t, serverWithProxy)
	via := func(client string) int {
		return e.req("POST", "/main/token", "127.0.0.1:4000", "X-Forwarded-For", "6.6.6.6, "+client).Code
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
	// A forged header from an address that is not a trusted proxy changes
	// nothing: the connection is the client.
	for range 2 {
		e.req("POST", "/main/token", "192.0.2.9:4000", "X-Forwarded-For", "203.0.113.1")
	}
	if c := e.req("POST", "/main/token", "192.0.2.9:4000", "X-Forwarded-For", "203.0.113.2").Code; c != http.StatusTooManyRequests {
		t.Errorf("a forged header from an untrusted address got status %d", c)
	}

	var ips []any
	for _, l := range e.log.lines(t) {
		ips = append(ips, l["client_ip"])
	}
	want := []any{"198.51.100.1", "198.51.100.1", "198.51.100.1", "198.51.100.2", "192.0.2.9", "192.0.2.9", "192.0.2.9"}
	if len(ips) != len(want) {
		t.Fatalf("log client_ip %v", ips)
	}
	for i := range want {
		if ips[i] != want[i] {
			t.Errorf("line %d client_ip %v, want %v (the 429 line included)", i, ips[i], want[i])
		}
	}
}

func TestOnlyTheEndpointsOfSEC11AreRateLimited(t *testing.T) {
	limited := map[string]bool{"authorize": true, "callback": true, "continue": true, "token": true, "provider_events": true, "revoke": true}
	all := map[string]string{}
	for k, v := range browserEndpoints {
		all[k] = v
	}
	for k, v := range apiEndpoints {
		all[k] = v
	}
	for name, path := range all {
		t.Run(name, func(t *testing.T) {
			e := wired(t, "public_url: https://auth.example.com\nrate_limit:\n  per_ip_per_minute: 1\n")
			first := e.req("GET", path, "192.0.2.1:1")
			second := e.req("GET", path, "192.0.2.1:1")
			if first.Code != http.StatusOK {
				t.Fatalf("first request: status %d", first.Code)
			}
			if limited[name] && second.Code != http.StatusTooManyRequests {
				t.Errorf("second request: status %d, want 429", second.Code)
			}
			if !limited[name] && second.Code != http.StatusOK {
				t.Errorf("second request: status %d, want 200 (no limit on this endpoint)", second.Code)
			}
		})
	}
	// The health endpoints are never limited, and the limit is shared: one
	// address, one budget across the endpoints.
	e := wired(t, "public_url: https://auth.example.com\nrate_limit:\n  per_ip_per_minute: 1\n")
	for range 3 {
		if c := e.req("GET", "/healthz", "192.0.2.1:1").Code; c != http.StatusOK {
			t.Errorf("/healthz status %d", c)
		}
	}
	e.req("GET", "/main/token", "192.0.2.1:1")
	if c := e.req("GET", "/main/authorize", "192.0.2.1:1").Code; c != http.StatusTooManyRequests {
		t.Errorf("authorize after token from the same address: status %d, want 429", c)
	}
}

func TestRateLimitAnswersInTheFormatOfTheEndpoint(t *testing.T) {
	e := wired(t, "public_url: https://auth.example.com\nrate_limit:\n  per_ip_per_minute: 1\n")
	e.req("GET", "/main/authorize", "192.0.2.1:1")
	rec := e.req("GET", "/main/authorize", "192.0.2.1:1")
	if rec.Code != http.StatusTooManyRequests || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html") {
		t.Errorf("browser endpoint: status %d, type %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	if rec.Header().Get("Content-Security-Policy") == "" {
		t.Error("the 429 page of a browser endpoint has no security headers")
	}
	e.req("POST", "/main/events/apple", "192.0.2.2:1")
	rec = e.req("POST", "/main/events/apple", "192.0.2.2:1")
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Content-Type") != "application/json" {
		t.Errorf("API endpoint: status %d, type %q", rec.Code, rec.Header().Get("Content-Type"))
	}
}

// Covers: SEC-13 (part)
func TestRequestLogHasThePathWithoutQueryAndNoSecrets(t *testing.T) {
	e := wired(t, serverDefault)
	rec := e.req("GET", "/main/callback/google?code=CODE-1&state=STATE-1&id_token_hint=HINT-1&login_hint=me@example.com", "192.0.2.1:1",
		"Authorization", "Bearer TOKEN-1", "Cookie", "fa_state_x=STATE-1", "X-Forwarded-For", "203.0.113.9")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	e.req("POST", "/main/token", "192.0.2.1:1", "Authorization", "Basic c2VjcmV0")
	lines := e.log.lines(t)
	if len(lines) != 2 {
		t.Fatalf("%d lines: %v", len(lines), lines)
	}
	l := lines[0]
	allowed := map[string]bool{"time": true, "level": true, "msg": true, "method": true, "path": true, "status": true, "duration_ms": true, "realm": true, "client_ip": true}
	for k := range l {
		if !allowed[k] {
			t.Errorf("unexpected field %q in the request log", k)
		}
	}
	if l["path"] != "/main/callback/google" || l["method"] != "GET" || l["status"] != float64(200) || l["realm"] != "main" {
		t.Errorf("line %v", l)
	}
	raw := mustJSON(lines)
	for _, secret := range []string{"CODE-1", "STATE-1", "HINT-1", "me@example.com", "TOKEN-1", "c2VjcmV0", "fa_state_x", "203.0.113.9"} {
		if strings.Contains(raw, secret) {
			t.Errorf("the log holds %q: %s", secret, raw)
		}
	}
}

// Covers: SEC-12 (part)
// Acceptance: Browser headers (part)
func TestBrowserOnlySecurityHeaders(t *testing.T) {
	e := wired(t, serverDefault)
	headers := []string{"Strict-Transport-Security", "Content-Security-Policy", "X-Content-Type-Options", "X-Robots-Tag", "Referrer-Policy"}
	for name, path := range browserEndpoints {
		rec := e.req("GET", path, "192.0.2.1:1")
		for _, h := range headers {
			if rec.Header().Get(h) == "" {
				t.Errorf("%s: no %s", name, h)
			}
		}
		if rec.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("%s: Cache-Control = %q", name, rec.Header().Get("Cache-Control"))
		}
		if !strings.Contains(rec.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
			t.Errorf("%s: CSP %q", name, rec.Header().Get("Content-Security-Policy"))
		}
	}
	// nosniff is on every response (SEC-29), so API endpoints are checked
	// only for the headers that stay browser-only.
	browserOnly := []string{"Strict-Transport-Security", "Content-Security-Policy", "X-Robots-Tag", "Referrer-Policy"}
	for name, path := range apiEndpoints {
		rec := e.req("GET", path, "192.0.2.1:1")
		for _, h := range browserOnly {
			if v := rec.Header().Get(h); v != "" {
				t.Errorf("%s: %s = %q on an API endpoint", name, h, v)
			}
		}
	}
	for _, path := range []string{"/healthz", "/readyz", "/nowhere"} {
		rec := e.req("GET", path, "192.0.2.1:1")
		if rec.Header().Get("Content-Security-Policy") != "" || rec.Header().Get("Strict-Transport-Security") != "" {
			t.Errorf("%s carries browser headers", path)
		}
	}
}

func TestAHandlerCanReplaceTheContentSecurityPolicy(t *testing.T) {
	e := wired(t, serverDefault)
	e.h.run = func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'none'")
		w.WriteHeader(http.StatusOK)
	}
	rec := e.req("GET", "/main/callback/apple", "192.0.2.1:1")
	if got := rec.Header().Get("Content-Security-Policy"); got != "default-src 'none'" {
		t.Errorf("CSP %q", got)
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("the other browser headers are gone")
	}
}

// Covers: FR-26 (part), SEC-18 (part)
// Acceptance: CORS (part)
func TestCORSOnlyOnAPIEndpoints(t *testing.T) {
	const origin = "https://app.example.com"
	e := wired(t, serverDefault)

	for _, name := range []string{"discovery", "jwks"} {
		rec := e.req("GET", apiEndpoints[name], "192.0.2.1:1", "Origin", origin)
		if rec.Header().Get("Access-Control-Allow-Origin") != origin {
			t.Errorf("%s: no CORS headers", name)
		}
	}
	for _, name := range []string{"token", "userinfo"} {
		rec := e.req("OPTIONS", apiEndpoints[name], "192.0.2.1:1", "Origin", origin, "Access-Control-Request-Method", "POST")
		if rec.Code != http.StatusNoContent || rec.Header().Get("Access-Control-Allow-Origin") != origin {
			t.Errorf("%s preflight: status %d, headers %v", name, rec.Code, rec.Header())
		}
	}
	// Browser endpoints and the rest get no CORS handling: the preflight
	// reaches the handler and nothing is added.
	for name, path := range browserEndpoints {
		before := e.h.count()
		rec := e.req("OPTIONS", path, "192.0.2.1:1", "Origin", origin, "Access-Control-Request-Method", "GET")
		if e.h.count() != before+1 {
			t.Errorf("%s: the preflight did not reach the handler", name)
		}
		for k := range rec.Header() {
			if strings.HasPrefix(k, "Access-Control-") || k == "Vary" {
				t.Errorf("%s: %s on a browser endpoint", name, k)
			}
		}
		rec = e.req("GET", path, "192.0.2.1:1", "Origin", origin)
		if rec.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Errorf("%s: Access-Control-Allow-Origin on a browser endpoint", name)
		}
	}
	for _, name := range []string{"account_delete", "provider_events"} {
		rec := e.req("GET", apiEndpoints[name], "192.0.2.1:1", "Origin", origin)
		if rec.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Errorf("%s: CORS headers on an endpoint no browser app calls", name)
		}
	}
}

func TestPreflightsDoNotUseUpTheRateLimit(t *testing.T) {
	e := wired(t, "public_url: https://auth.example.com\nrate_limit:\n  per_ip_per_minute: 1\n")
	for range 5 {
		rec := e.req("OPTIONS", "/main/token", "192.0.2.1:1", "Origin", "https://app.example.com", "Access-Control-Request-Method", "POST")
		if rec.Code != http.StatusNoContent {
			t.Fatalf("preflight: status %d", rec.Code)
		}
	}
	if c := e.req("POST", "/main/token", "192.0.2.1:1").Code; c != http.StatusOK {
		t.Errorf("the POST after the preflights: status %d", c)
	}
}

func TestPanicInTheWholeChainIsLoggedWithTheClientIP(t *testing.T) {
	e := wired(t, serverWithProxy)
	e.h.run = func(http.ResponseWriter, *http.Request) { panic("x") }
	rec := e.req("GET", "/main/authorize", "127.0.0.1:1", "X-Forwarded-For", "198.51.100.5")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status %d", rec.Code)
	}
	if rec.Header().Get("Content-Security-Policy") == "" {
		t.Error("the 500 page of a browser endpoint has no security headers")
	}
	var found bool
	for _, l := range e.log.lines(t) {
		if l["msg"] == "request" && l["client_ip"] == "198.51.100.5" && l["status"] == float64(500) {
			found = true
		}
	}
	if !found {
		t.Errorf("no request line with the client IP: %v", e.log.lines(t))
	}
}

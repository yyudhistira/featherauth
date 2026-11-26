package server_test

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/logx"
	"github.com/yyudhistira/featherauth/internal/server"
	"github.com/yyudhistira/featherauth/internal/testutil/tlscert"
)

// servingPair returns the tls.Certificate of a fresh pair.
func servingPair(t *testing.T) *tls.Certificate {
	t.Helper()
	p := tlscert.New(t, "auth.example.com")
	c, err := tls.X509KeyPair(p.CertPEM, p.KeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return &c
}

// loadResult is one answer of a scripted load.
type loadResult struct {
	pair *tls.Certificate
	err  error
}

// scripted returns a load function that gives rs in turn, then repeats the last.
func scripted(rs ...loadResult) func() (*tls.Certificate, error) {
	i := 0
	return func() (*tls.Certificate, error) {
		r := rs[i]
		if i < len(rs)-1 {
			i++
		}
		return r.pair, r.err
	}
}

// Covers: FR-52 (part), SEC-41 (part)
// Acceptance: Built-in TLS with files (part)
func TestCertificateServesTheLoadedPairAndKeepsItOnAFailure(t *testing.T) {
	a, b := servingPair(t), servingPair(t)
	boom := errors.New("the key does not match the certificate")
	var logs bytes.Buffer
	log := logx.New(&logs, slog.LevelInfo, clock.Real())

	if _, err := server.NewCertificate(scripted(loadResult{err: boom}), log); err == nil {
		t.Fatal("NewCertificate succeeded when the first load failed")
	}
	c, err := server.NewCertificate(scripted(loadResult{pair: a}, loadResult{err: boom}, loadResult{pair: b}), log)
	if err != nil {
		t.Fatal(err)
	}
	got := func() *tls.Certificate {
		p, err := c.GetCertificate(&tls.ClientHelloInfo{})
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	if got() != a {
		t.Fatal("the first pair is not served")
	}

	// A failed reload is logged and the previous pair stays.
	if err := c.Reload(t.Context()); !errors.Is(err, boom) {
		t.Fatalf("Reload returned %v, want the load error", err)
	}
	if got() != a {
		t.Fatal("a failed reload replaced the pair")
	}
	if !strings.Contains(logs.String(), "cannot load the certificate pair") {
		t.Errorf("the failed reload is not logged: %s", logs.String())
	}

	if err := c.Reload(t.Context()); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if got() != b {
		t.Fatal("a reload did not serve the new pair")
	}
	if !strings.Contains(logs.String(), "certificate loaded") {
		t.Errorf("the reload is not logged: %s", logs.String())
	}
	if strings.Contains(logs.String(), "PRIVATE KEY") {
		t.Error("the log holds key material")
	}
}

// Covers: FR-52 (part), SEC-29
// Acceptance: Built-in TLS with files (part)
func TestRedirectAnswersWithTheSameURLUnderPublicURL(t *testing.T) {
	tests := []struct {
		name   string
		method string
		target string
		host   string // the Host header, empty for the default
		want   string
	}{
		{name: "GET keeps the path and the query", method: "GET", target: "/main/authorize?client_id=web&state=x", host: "evil.example",
			want: "https://auth.example.com/main/authorize?client_id=web&state=x"},
		{name: "POST keeps the path", method: "POST", target: "/main/token", want: "https://auth.example.com/main/token"},
		{name: "the root", method: "GET", target: "/", want: "https://auth.example.com/"},
		{name: "a path prefix", method: "GET", target: "/auth/main/.well-known/openid-configuration", want: "https://auth.example.com/auth/main/.well-known/openid-configuration"},
		{name: "absolute-form target keeps only the path and query", method: "GET", target: "http://evil.example/main/authorize?client_id=web", want: "https://auth.example.com/main/authorize?client_id=web"},
	}
	h := server.Redirect("https://auth.example.com")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.target, nil)
			if tt.host != "" {
				req.Host = tt.host
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusMovedPermanently {
				t.Fatalf("status %d, want 301", rec.Code)
			}
			if got := rec.Header().Get("Location"); got != tt.want {
				t.Errorf("Location %q, want %q", got, tt.want)
			}
			if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
				t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
			}
		})
	}
}

// The loopback listener of built-in TLS serves the health endpoints of the
// router and answers 404 for every other path, with the router's own headers
// and the same shutdown behaviour.
//
// Covers: FR-52 (part), SEC-41 (part), SEC-29 (part)
// Acceptance: Built-in TLS with files (part)
func TestHealthHandlerAnswersOnlyTheHealthEndpoints(t *testing.T) {
	e := wired(t, serverDefault)
	h := e.rt.HealthHandler()
	tests := []struct {
		name   string
		method string
		path   string
		code   int
	}{
		{name: "healthz", method: "GET", path: "/healthz", code: http.StatusOK},
		{name: "readyz", method: "GET", path: "/readyz", code: http.StatusOK},
		{name: "readyz HEAD", method: "HEAD", path: "/readyz", code: http.StatusOK},
		{name: "readyz with POST", method: "POST", path: "/readyz", code: http.StatusMethodNotAllowed},
		{name: "authorize", method: "GET", path: "/main/authorize", code: http.StatusNotFound},
		{name: "discovery", method: "GET", path: "/main/.well-known/openid-configuration", code: http.StatusNotFound},
		{name: "the root", method: "GET", path: "/", code: http.StatusNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(tt.method, tt.path, nil))
			if rec.Code != tt.code {
				t.Fatalf("status %d, want %d", rec.Code, tt.code)
			}
			if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
				t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
			}
		})
	}

	e.rt.BeginShutdown()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("readyz after BeginShutdown: %d, want 503", rec.Code)
	}
}

// The certificate holds a private key, so it logs through its LogValue only:
// neither logged directly nor nested in a map does the key appear.
//
// Covers: SEC-13 (part)
func TestCertificateLogsNoKeyMaterial(t *testing.T) {
	p := tlscert.New(t, "auth.example.com")
	c, err := server.NewCertificate(func() (*tls.Certificate, error) {
		pair, err := tls.X509KeyPair(p.CertPEM, p.KeyPEM)
		return &pair, err
	}, logx.New(io.Discard, slog.LevelError, clock.Real()))
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	log := logx.New(&logs, slog.LevelInfo, clock.Real())
	log.Info("served", "certificate", c)
	log.Info("served", "map", map[string]any{"certificate": c})
	out := logs.String()
	if !strings.Contains(out, "not_after") {
		t.Fatalf("the certificate logs nothing of its state: %s", out)
	}
	for _, line := range strings.Split(string(p.KeyPEM), "\n") {
		if len(line) >= 16 && !strings.HasPrefix(line, "-----") && strings.Contains(out, line) {
			t.Fatalf("the log holds a line of the key: %q", line)
		}
	}
	if strings.Contains(out, "PRIVATE KEY") {
		t.Fatal("the log holds the key")
	}
}

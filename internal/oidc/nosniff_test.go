package oidc_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/yyudhistira/featherauth/internal/testutil/server"
)

// Covers: SEC-29
// Acceptance: nosniff on every response
func TestEveryResponseCarriesNosniff(t *testing.T) {
	e := server.New(t)
	form := http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}
	tests := []struct {
		name   string
		method string
		url    string
		body   string
		header http.Header
		code   int
	}{
		{"discovery", http.MethodGet, server.Issuer + "/.well-known/openid-configuration", "", nil, http.StatusOK},
		{"jwks", http.MethodGet, server.Issuer + "/jwks.json", "", nil, http.StatusOK},
		{"token error", http.MethodPost, server.Issuer + "/token", "", form, http.StatusBadRequest},
		{"userinfo error", http.MethodGet, server.Issuer + "/userinfo", "", nil, http.StatusUnauthorized},
		{"asset", http.MethodGet, server.Issuer + "/assets/style.css", "", nil, http.StatusOK},
		{"healthz", http.MethodGet, server.PublicURL + "/healthz", "", nil, http.StatusOK},
		{"router 404", http.MethodGet, server.PublicURL + "/nowhere", "", nil, http.StatusNotFound},
		{"endpoint 405", http.MethodGet, server.Issuer + "/token", "", nil, http.StatusMethodNotAllowed},
		{"router 413", http.MethodPost, server.Issuer + "/token", strings.Repeat("a", 64<<10+1), form, http.StatusRequestEntityTooLarge},
	}
	c := e.NewClient()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := c.Request(t, tt.method, tt.url, tt.body, tt.header)
			if r.Code != tt.code {
				t.Fatalf("status %d, want %d: %s", r.Code, tt.code, r.Body)
			}
			if got := r.Header.Get("X-Content-Type-Options"); got != "nosniff" {
				t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
			}
		})
	}
}

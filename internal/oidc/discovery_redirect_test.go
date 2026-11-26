package oidc_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yyudhistira/featherauth/internal/testutil/server"
)

// A provider whose discovery answers 302 is unavailable: the login ends with
// temporarily_unavailable, and the server the redirect names is never called
// (SEC-26).
//
// Covers: SEC-26 (part)
// Acceptance: Provider redirects and audiences (part)
func TestDiscoveryRedirectEndsTheLoginAsUnavailable(t *testing.T) {
	e := server.New(t)
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("the service followed a discovery redirect to %s", r.URL.Path)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(elsewhere.Close)
	e.Mocks["corp"].RedirectTo("discovery", elsewhere.URL+"/elsewhere")
	flowUser(e, "corp", "9001", "ann@example.com", true)
	if got := flowLoginError(t, e, server.ClientQuery, "corp"); got != "temporarily_unavailable" {
		t.Fatalf("login error = %q, want temporarily_unavailable", got)
	}
}

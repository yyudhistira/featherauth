package server_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/yyudhistira/featherauth/internal/server"
	"github.com/yyudhistira/featherauth/internal/testutil"
)

// Covers: FR-21 (part), FR-58 (part)
// Acceptance: Wrong method (part)
func TestAllowMethods(t *testing.T) {
	e := newEnv(t, serverDefault, map[string]string{"main": testutil.MinimalRealm("main")}, nil)
	var allowed bool
	e.h.run = func(w http.ResponseWriter, r *http.Request) {
		if allowed = server.AllowMethods(w, r, http.MethodGet, http.MethodPost); allowed {
			w.WriteHeader(http.StatusNoContent)
		}
	}
	tests := []struct {
		name, method, path string
		status             int
		json               bool
		allow              string
	}{
		{"GET on a browser endpoint", "GET", "/main/authorize", 204, false, ""},
		{"POST on a browser endpoint", "POST", "/main/authorize", 204, false, ""},
		{"PUT on a browser endpoint", "PUT", "/main/authorize", 405, false, "GET, POST"},
		{"DELETE on a browser endpoint", "DELETE", "/main/authorize", 405, false, "GET, POST"},
		{"PATCH on a browser endpoint", "PATCH", "/main/authorize", 405, false, "GET, POST"},
		{"OPTIONS on a browser endpoint", "OPTIONS", "/main/authorize", 405, false, "GET, POST"},
		{"HEAD on a browser endpoint", "HEAD", "/main/authorize", 405, false, "GET, POST"},
		{"GET on an API endpoint", "GET", "/main/token", 204, true, ""},
		{"PUT on an API endpoint", "PUT", "/main/token", 405, true, "GET, POST"},
		{"DELETE on an API endpoint", "DELETE", "/main/token", 405, true, "GET, POST"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := e.do(tt.method, tt.path, "")
			if rec.Code != tt.status {
				t.Fatalf("status %d, want %d", rec.Code, tt.status)
			}
			if got := rec.Header().Get("Allow"); got != tt.allow {
				t.Errorf("Allow = %q, want %q", got, tt.allow)
			}
			if tt.status != http.StatusMethodNotAllowed {
				if !allowed {
					t.Error("AllowMethods refused an accepted method")
				}
				return
			}
			if allowed {
				t.Error("AllowMethods accepted a method it was not given")
			}
			if rec.Header().Get("Cache-Control") != "no-store" {
				t.Errorf("Cache-Control = %q", rec.Header().Get("Cache-Control"))
			}
			if tt.json {
				var m map[string]string
				if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
					t.Fatalf("body is not JSON: %q", rec.Body)
				}
				if m["error"] != "invalid_request" || m["error_description"] != "method not allowed" ||
					rec.Header().Get("Content-Type") != "application/json" {
					t.Errorf("body %v, content type %q", m, rec.Header().Get("Content-Type"))
				}
				return
			}
			if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
				t.Errorf("content type %q, want HTML", ct)
			}
			if tt.method != "HEAD" && !strings.Contains(rec.Body.String(), "Method Not Allowed") {
				t.Errorf("body %q", rec.Body)
			}
		})
	}
}

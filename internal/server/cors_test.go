package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/testutil"
)

const corsClients = `clients:
  web:
    redirect_uris: [https://app.example.com/callback]
    web_origins: [https://app.example.com]
  spa:
    redirect_uris: [https://spa.example.com/callback]
    web_origins: [https://spa.example.com, https://spa2.example.com:8443]
  mobile:
    redirect_uris: ["com.example.app:/callback"]
`

func corsRealm(t *testing.T) *config.Realm {
	t.Helper()
	src := testutil.NewConfig(t, "public_url: https://auth.example.com\n", map[string]string{"main": testutil.RealmYAML("main", corsClients)})
	r, ok := src.Current().Realm("main")
	if !ok {
		t.Fatal("no realm")
	}
	return r
}

// corsRequest builds a request that the router would have routed to endpoint.
func corsRequest(realm *config.Realm, endpoint, method, origin string, hdr ...string) *http.Request {
	r := httptest.NewRequest(method, "/main/"+endpoint, nil)
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		r.Header.Set(hdr[i], hdr[i+1])
	}
	info := &Info{Endpoint: endpoint, Kind: KindAPI, Realm: realm}
	return r.WithContext(context.WithValue(r.Context(), infoKey{}, info))
}

func serveCORS(h http.Handler, r *http.Request) (*httptest.ResponseRecorder, bool) {
	called := false
	rec := httptest.NewRecorder()
	CORS()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		h.ServeHTTP(w, r)
	})).ServeHTTP(rec, r)
	return rec, called
}

var ok200 = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

// Covers: FR-26 (part), SEC-18 (part)
// Acceptance: CORS (part)
func TestCORSOnDiscoveryAndJWKSAllowsAnyClientOrigin(t *testing.T) {
	realm := corsRealm(t)
	for _, ep := range []string{"discovery", "jwks"} {
		for _, tt := range []struct {
			origin string
			allow  bool
		}{
			{"https://app.example.com", true},
			{"https://spa.example.com", true},
			{"https://spa2.example.com:8443", true},
			{"https://evil.example.com", false},
			{"https://app.example.com:444", false},
			{"http://app.example.com", false},
			{"https://APP.example.com", false},
			{"null", false},
			{"", false},
		} {
			rec, called := serveCORS(ok200, corsRequest(realm, ep, "GET", tt.origin))
			if !called || rec.Code != http.StatusOK {
				t.Fatalf("%s %q: handler called %v, status %d", ep, tt.origin, called, rec.Code)
			}
			got := rec.Header().Get("Access-Control-Allow-Origin")
			if tt.allow && got != tt.origin || !tt.allow && got != "" {
				t.Errorf("%s from %q: Access-Control-Allow-Origin = %q", ep, tt.origin, got)
			}
			if rec.Header().Get("Access-Control-Allow-Origin") == "*" {
				t.Errorf("%s: wildcard origin", ep)
			}
			if !strings.Contains(rec.Header().Get("Vary"), "Origin") {
				t.Errorf("%s from %q: no Vary: Origin", ep, tt.origin)
			}
		}
	}
}

// Covers: FR-26 (part), SEC-18 (part)
// Acceptance: CORS (part)
func TestCORSPreflight(t *testing.T) {
	realm := corsRealm(t)
	methods := map[string]string{
		"token":     "POST, OPTIONS",
		"revoke":    "POST, OPTIONS",
		"userinfo":  "GET, POST, OPTIONS",
		"jwks":      "GET, OPTIONS",
		"discovery": "GET, OPTIONS",
	}
	for ep, want := range methods {
		t.Run(ep, func(t *testing.T) {
			// An origin of any client of the realm passes the preflight.
			for _, origin := range []string{"https://app.example.com", "https://spa.example.com"} {
				rec, called := serveCORS(ok200, corsRequest(realm, ep, "OPTIONS", origin,
					"Access-Control-Request-Method", "POST", "Access-Control-Request-Headers", "authorization"))
				if called {
					t.Errorf("%s: the preflight reached the handler", origin)
				}
				if rec.Code != http.StatusNoContent {
					t.Errorf("%s: status %d", origin, rec.Code)
				}
				h := rec.Header()
				wantHeaders := "Authorization, Content-Type"
				if ep == "token" || ep == "userinfo" {
					wantHeaders = "Authorization, Content-Type, DPoP" // FR-44: these take a DPoP proof
				}
				if h.Get("Access-Control-Allow-Origin") != origin || h.Get("Access-Control-Allow-Methods") != want ||
					h.Get("Access-Control-Allow-Headers") != wantHeaders || !strings.Contains(h.Get("Vary"), "Origin") {
					t.Errorf("%s: headers %v", origin, h)
				}
			}
			// Any other origin gets an answer without CORS headers.
			for _, origin := range []string{"https://evil.example.com", "null", ""} {
				rec, called := serveCORS(ok200, corsRequest(realm, ep, "OPTIONS", origin, "Access-Control-Request-Method", "POST"))
				if called || rec.Code != http.StatusNoContent {
					t.Errorf("%q: called %v, status %d", origin, called, rec.Code)
				}
				for k := range rec.Header() {
					if strings.HasPrefix(k, "Access-Control-") {
						t.Errorf("%q: %s sent", origin, k)
					}
				}
			}
		})
	}
}

func TestCORSOptionsWithoutARequestMethodIsNotAPreflight(t *testing.T) {
	realm := corsRealm(t)
	rec, called := serveCORS(ok200, corsRequest(realm, "token", "OPTIONS", "https://app.example.com"))
	if !called || rec.Code != http.StatusOK || rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("called %v, status %d, headers %v", called, rec.Code, rec.Header())
	}
}

// Covers: FR-26 (part), SEC-18 (part)
// Acceptance: CORS (part)
func TestCORSOnTokenAndUserinfoWaitsForTheClient(t *testing.T) {
	// The actual request is checked against the client the handler
	// authenticated, so the middleware itself adds no allow-origin header.
	realm := corsRealm(t)
	for _, ep := range []string{"token", "userinfo"} {
		rec, called := serveCORS(ok200, corsRequest(realm, ep, "POST", "https://app.example.com"))
		if !called || rec.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Errorf("%s: called %v, headers %v", ep, called, rec.Header())
		}
		if !strings.Contains(rec.Header().Get("Vary"), "Origin") {
			t.Errorf("%s: no Vary: Origin", ep)
		}
	}
}

// Covers: FR-26 (part), SEC-18 (part)
// Acceptance: CORS (part)
func TestAllowOriginChecksTheClient(t *testing.T) {
	realm := corsRealm(t)
	web, spa, mobile := realm.Clients["web"], realm.Clients["spa"], realm.Clients["mobile"]
	tests := []struct {
		name   string
		client *config.Client
		origin string
		want   bool
	}{
		{"own origin", web, "https://app.example.com", true},
		{"second origin of the client", spa, "https://spa2.example.com:8443", true},
		{"another client's origin", web, "https://spa.example.com", false},
		{"unregistered origin", web, "https://evil.example.com", false},
		{"a client with no origins", mobile, "https://app.example.com", false},
		{"no client", nil, "https://app.example.com", false},
		{"no Origin header is not a CORS request", web, "", true},
		{"no Origin header, no client", nil, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := corsRequest(realm, "token", "POST", tt.origin)
			w := httptest.NewRecorder()
			if got := AllowOrigin(w, r, tt.client); got != tt.want {
				t.Fatalf("AllowOrigin = %v, want %v", got, tt.want)
			}
			acao := w.Header().Get("Access-Control-Allow-Origin")
			if tt.want && tt.origin != "" && acao != tt.origin || (!tt.want || tt.origin == "") && acao != "" {
				t.Errorf("Access-Control-Allow-Origin = %q", acao)
			}
			if tt.origin != "" && !strings.Contains(w.Header().Get("Vary"), "Origin") {
				t.Error("no Vary: Origin")
			}
		})
	}
}

// Covers: FR-26 (part), SEC-18 (part)
// Acceptance: CORS (part)
func TestPreflightFromAnotherClientsOriginPassesButItsPOSTIsRefused(t *testing.T) {
	realm := corsRealm(t)
	const origin = "https://spa.example.com" // registered by spa, not by web

	rec, _ := serveCORS(ok200, corsRequest(realm, "token", "OPTIONS", origin, "Access-Control-Request-Method", "POST"))
	if rec.Header().Get("Access-Control-Allow-Origin") != origin || rec.Header().Get("Access-Control-Allow-Methods") != "POST, OPTIONS" {
		t.Fatalf("the preflight is refused: %v", rec.Header())
	}

	// The POST authenticates as web.
	var allowed bool
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		allowed = AllowOrigin(w, r, realm.Clients["web"])
		w.WriteHeader(http.StatusOK)
	})
	rec, _ = serveCORS(h, corsRequest(realm, "token", "POST", origin))
	if allowed || rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("the POST is not refused: allowed %v, headers %v", allowed, rec.Header())
	}
	// And as spa it is allowed.
	h = func(w http.ResponseWriter, r *http.Request) { allowed = AllowOrigin(w, r, realm.Clients["spa"]) }
	rec, _ = serveCORS(h, corsRequest(realm, "token", "POST", origin))
	if !allowed || rec.Header().Get("Access-Control-Allow-Origin") != origin {
		t.Errorf("spa: allowed %v, headers %v", allowed, rec.Header())
	}
}

func TestVaryOriginIsNotAddedTwice(t *testing.T) {
	realm := corsRealm(t)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { AllowOrigin(w, r, realm.Clients["web"]) })
	rec, _ := serveCORS(h, corsRequest(realm, "token", "POST", "https://app.example.com"))
	if got := rec.Header().Values("Vary"); len(got) != 1 || got[0] != "Origin" {
		t.Errorf("Vary = %v", got)
	}
	// An existing Vary value stays.
	h = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Vary", "Accept-Encoding")
		AllowOrigin(w, r, realm.Clients["web"])
	}
	rec, _ = serveCORS(h, corsRequest(realm, "token", "POST", "https://app.example.com"))
	if got := strings.Join(rec.Header().Values("Vary"), ","); !strings.Contains(got, "Accept-Encoding") || !strings.Contains(got, "Origin") {
		t.Errorf("Vary = %q", got)
	}
}

func TestCORSIgnoresUnroutedRequests(t *testing.T) {
	r := httptest.NewRequest("OPTIONS", "/x", nil)
	r.Header.Set("Origin", "https://app.example.com")
	r.Header.Set("Access-Control-Request-Method", "POST")
	rec, called := serveCORS(ok200, r)
	if !called || rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("called %v, headers %v", called, rec.Header())
	}
	// A routed request of an endpoint without CORS (the middleware is meant
	// for API endpoints) is passed on too.
	realm := corsRealm(t)
	rec, called = serveCORS(ok200, corsRequest(realm, "account_delete", "OPTIONS", "https://app.example.com", "Access-Control-Request-Method", "DELETE"))
	if !called || rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("account_delete: called %v, headers %v", called, rec.Header())
	}
}

package oidc_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/logx"
	"github.com/yyudhistira/featherauth/internal/oidc"
	"github.com/yyudhistira/featherauth/internal/server"
	"github.com/yyudhistira/featherauth/internal/testutil/configdir"
	"github.com/yyudhistira/featherauth/internal/token"
)

const jwksRealm = `name: main
tokens:
  algorithm: ES256
keys:
  - { kid: rsa-new, file: secrets/rsa-new.pem, state: active }
  - { kid: rsa-old, file: secrets/rsa-old.pem, state: verify_only }
  - { kid: ec-new, file: secrets/ec-new.pem, state: active }
  - { kid: ec-old, file: secrets/ec-old.pem, state: verify_only }
providers:
  google:
    enabled: true
    client_id: 1234.apps.googleusercontent.com
    client_secret_file: secrets/google_secret
clients:
  web:
    redirect_uris: [https://app.example.com/callback]
`

// jwksHandlers is a server.Handlers whose JWKS endpoint is the real one.
type jwksHandlers struct {
	*deliverHandlers
	j *oidc.JWKS
}

var _ server.Handlers = jwksHandlers{}

func (h jwksHandlers) JWKS(w http.ResponseWriter, r *http.Request) { h.j.ServeHTTP(w, r) }

func jwksSetup(t *testing.T) (*server.Router, *config.Loader) {
	t.Helper()
	d := configdir.New(t)
	d.Server(t, "public_url: https://auth.example.com\n")
	d.Realm(t, "main", jwksRealm)
	for _, f := range []string{"rsa-new", "rsa-old"} {
		d.RSAKey(t, "secrets/"+f+".pem")
	}
	for _, f := range []string{"ec-new", "ec-old"} {
		d.AppleKey(t, "secrets/"+f+".pem")
	}
	d.Secret(t, "secrets/google_secret")
	clk := clock.NewFake(testStart)
	l, err := config.NewLoader(d.Root, clk, nil)
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}
	h := jwksHandlers{deliverHandlers: &deliverHandlers{}, j: oidc.NewJWKS()}
	return server.NewHandler(l, h, server.Middleware{Logger: logx.New(&strings.Builder{}, 0, clk), Clock: clk}), l
}

// Covers: FR-10 (part)
// Acceptance: JWKS content
// Acceptance: Cache headers
func TestJWKSServesEveryKeyWithUseAlgKidAndCacheHeader(t *testing.T) {
	rt, l := jwksSetup(t)
	rec := fetchDiscovery(rt, "/main/jwks.json")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	if got := rec.Header().Get("Cache-Control"); got != "public, max-age=300" {
		t.Errorf("Cache-Control = %q", got)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q", got)
	}
	var doc struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"rsa-new": "RS256", "rsa-old": "RS256", "ec-new": "ES256", "ec-old": "ES256"}
	if len(doc.Keys) != len(want) {
		t.Fatalf("got %d keys, want %d", len(doc.Keys), len(want))
	}
	for _, k := range doc.Keys {
		kid, _ := k["kid"].(string)
		if k["use"] != "sig" || k["alg"] != want[kid] || want[kid] == "" {
			t.Errorf("key %v: want use sig, alg %q", k, want[kid])
		}
		delete(want, kid)
		for _, priv := range []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"} {
			if _, found := k[priv]; found {
				t.Errorf("key %q carries private member %q", kid, priv)
			}
		}
	}
	snap := l.Current()
	realm, _ := snap.Realm("main")
	ks, err := token.NewKeySet(realm, snap.Secrets())
	if err != nil {
		t.Fatal(err)
	}
	if rec.Body.String() != string(ks.JWKS()) {
		t.Error("the body is not the key set's JWKS")
	}
}

// Covers: FR-10 (part), FR-21 (part)
func TestJWKSUnknownRealm(t *testing.T) {
	rt, _ := jwksSetup(t)
	if rec := fetchDiscovery(rt, "/nope/jwks.json"); rec.Code != http.StatusNotFound {
		t.Errorf("status %d", rec.Code)
	}
}

// Covers: FR-10 (part)
func TestJWKSWithoutRoutingContext(t *testing.T) {
	rec := httptest.NewRecorder()
	oidc.NewJWKS().ServeHTTP(rec, httptest.NewRequest("GET", "/x", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status %d", rec.Code)
	}
}

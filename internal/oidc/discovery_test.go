package oidc_test

import (
	"bytes"
	"context"
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
	"github.com/yyudhistira/featherauth/internal/testutil"
)

const (
	discServerDefault  = "public_url: https://auth.example.com\n"
	discServerPrefix   = "public_url: https://auth.example.com\nurls:\n  path_prefix: /auth\n"
	discServerKeycloak = `public_url: https://auth.example.com
urls:
  path_prefix: /auth
  issuer: "{prefix}/realms/{realm}"
  endpoints:
    authorize: "{prefix}/realms/{realm}/protocol/openid-connect/auth"
    token: "{prefix}/realms/{realm}/protocol/openid-connect/token"
    userinfo: "{prefix}/realms/{realm}/protocol/openid-connect/userinfo"
    jwks: "{prefix}/realms/{realm}/protocol/openid-connect/certs"
    logout: "{prefix}/realms/{realm}/protocol/openid-connect/logout"
    callback: "{prefix}/realms/{realm}/broker/{provider}/endpoint"
`
)

// discoveryHandlers is a server.Handlers whose discovery endpoint is the real
// one.
type discoveryHandlers struct {
	*deliverHandlers
	d *oidc.Discovery
}

var _ server.Handlers = discoveryHandlers{}

func (h discoveryHandlers) Discovery(w http.ResponseWriter, r *http.Request) { h.d.ServeHTTP(w, r) }

func discoveryRouter(t *testing.T, src config.Source) *server.Router {
	t.Helper()
	clk := clock.NewFake(testStart)
	h := discoveryHandlers{deliverHandlers: &deliverHandlers{}, d: oidc.NewDiscovery()}
	return server.NewHandler(src, h, server.Middleware{Logger: logx.New(&strings.Builder{}, 0, clk), Clock: clk})
}

func fetchDiscovery(rt *server.Router, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", path, nil)
	req.RemoteAddr = "192.0.2.10:4000"
	rec := httptest.NewRecorder()
	rt.ServeHTTP(rec, req)
	return rec
}

var discoveryLayouts = []struct {
	name, server, path, golden string
}{
	{"default", discServerDefault, "/main/.well-known/openid-configuration", "discovery_default.golden.json"},
	{"prefix", discServerPrefix, "/auth/main/.well-known/openid-configuration", "discovery_prefix.golden.json"},
	{"keycloak", discServerKeycloak, "/auth/realms/main/.well-known/openid-configuration", "discovery_keycloak.golden.json"},
}

// Covers: FR-01 (part), FR-29 (part)
// Acceptance: Discovery content
func TestDiscoveryGolden(t *testing.T) {
	for _, l := range discoveryLayouts {
		t.Run(l.name, func(t *testing.T) {
			src := testutil.NewConfig(t, l.server, map[string]string{"main": testutil.MinimalRealm("main")})
			rec := fetchDiscovery(discoveryRouter(t, src), l.path)
			if rec.Code != http.StatusOK {
				t.Fatalf("status %d: %s", rec.Code, rec.Body)
			}
			var pretty bytes.Buffer
			if err := json.Indent(&pretty, rec.Body.Bytes(), "", "  "); err != nil {
				t.Fatalf("not JSON: %v", err)
			}
			pretty.WriteByte('\n')
			golden(t, l.golden, pretty.Bytes())
		})
	}
}

// Covers: FR-01 (part), FR-29 (part)
// Acceptance: Discovery content
// Acceptance: Issuer with prefix (part)
func TestDiscoveryFields(t *testing.T) {
	required := []string{"issuer", "authorization_endpoint", "token_endpoint", "userinfo_endpoint", "jwks_uri",
		"end_session_endpoint", "revocation_endpoint", "token_endpoint_auth_methods_supported",
		"revocation_endpoint_auth_methods_supported", "response_types_supported",
		"subject_types_supported", "id_token_signing_alg_values_supported", "scopes_supported", "claims_supported",
		"response_modes_supported", "grant_types_supported", "code_challenge_methods_supported",
		"authorization_response_iss_parameter_supported", "request_parameter_supported",
		"request_uri_parameter_supported", "claims_parameter_supported",
		"backchannel_logout_supported", "backchannel_logout_session_supported"}
	for _, l := range discoveryLayouts {
		t.Run(l.name, func(t *testing.T) {
			src := testutil.NewConfig(t, l.server, map[string]string{"main": testutil.MinimalRealm("main")})
			rec := fetchDiscovery(discoveryRouter(t, src), l.path)
			var doc map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
				t.Fatal(err)
			}
			for _, f := range required {
				if _, ok := doc[f]; !ok {
					t.Errorf("field %s missing", f)
				}
			}
			if len(doc) != len(required) {
				t.Errorf("%d fields, want %d", len(doc), len(required))
			}
			if got := doc["id_token_signing_alg_values_supported"]; !jsonEq(got, []any{"RS256"}) {
				t.Errorf("id_token_signing_alg_values_supported = %v", got)
			}
			for _, f := range []string{"request_parameter_supported", "request_uri_parameter_supported", "claims_parameter_supported"} {
				if doc[f] != false {
					t.Errorf("%s = %v, want false", f, doc[f])
				}
			}
			if doc["authorization_response_iss_parameter_supported"] != true {
				t.Errorf("authorization_response_iss_parameter_supported = %v", doc["authorization_response_iss_parameter_supported"])
			}
			// The issuer is the URL the document was fetched under, has no
			// trailing slash and is the realm's issuer, the iss of its tokens.
			realm, _ := src.Current().Realm("main")
			iss, _ := doc["issuer"].(string)
			if want := "https://auth.example.com" + strings.TrimSuffix(l.path, "/.well-known/openid-configuration"); iss != want {
				t.Errorf("issuer %q, want %q", iss, want)
			}
			if iss != realm.Issuer() || strings.HasSuffix(iss, "/") {
				t.Errorf("issuer %q, realm issuer %q", iss, realm.Issuer())
			}
			for f, e := range map[string]config.Endpoint{
				"authorization_endpoint": config.EndpointAuthorize, "token_endpoint": config.EndpointToken,
				"userinfo_endpoint": config.EndpointUserinfo, "jwks_uri": config.EndpointJWKS,
				"end_session_endpoint": config.EndpointLogout,
			} {
				if doc[f] != realm.EndpointURL(e, "") {
					t.Errorf("%s = %v, want %s", f, doc[f], realm.EndpointURL(e, ""))
				}
			}
		})
	}
}

func jsonEq(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}

// Covers: FR-01 (part)
// Acceptance: Cache headers (part)
func TestDiscoveryHeaders(t *testing.T) {
	src := testutil.NewConfig(t, discServerDefault, map[string]string{"main": testutil.MinimalRealm("main")})
	rec := fetchDiscovery(discoveryRouter(t, src), "/main/.well-known/openid-configuration")
	if got := rec.Header().Get("Cache-Control"); got != "public, max-age=300" {
		t.Errorf("Cache-Control = %q", got)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q", got)
	}
}

// Covers: FR-01 (part), FR-22 (part)
func TestDiscoveryClaimsFollowRealmAndSnapshot(t *testing.T) {
	l, d := testutil.NewConfigDir(t, discServerDefault, map[string]string{"main": testutil.MinimalRealm("main")})
	rt := discoveryRouter(t, l)
	claims := func() []any {
		rec := fetchDiscovery(rt, "/main/.well-known/openid-configuration")
		var doc map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
			t.Fatal(err)
		}
		return doc["claims_supported"].([]any)
	}
	before := claims()
	if !jsonEq(before, claims()) {
		t.Fatal("two requests of one snapshot differ")
	}
	if s := string(mustJSON(before)); strings.Contains(s, "allowed-origins") {
		t.Fatalf("default claims list %s", s)
	}
	testutil.WriteRealm(t, d, "main", testutil.RealmYAML("main", testutil.DefaultClients+"user_data:\n  claims: [email, allowed-origins]\n"))
	if res := l.Reload(context.Background()); !res.Applied {
		t.Fatalf("reload: %+v", res)
	}
	after := string(mustJSON(claims()))
	if !strings.Contains(after, "allowed-origins") || strings.Contains(after, "preferred_username") {
		t.Errorf("claims after reload %s", after)
	}
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }

// Covers: FR-01 (part)
func TestDiscoveryUnknownRealm(t *testing.T) {
	src := testutil.NewConfig(t, discServerDefault, map[string]string{"main": testutil.MinimalRealm("main")})
	rec := fetchDiscovery(discoveryRouter(t, src), "/nope/.well-known/openid-configuration")
	if rec.Code != http.StatusNotFound {
		t.Errorf("status %d", rec.Code)
	}
}

// Covers: FR-01 (part)
func TestDiscoveryWithoutRoutingContext(t *testing.T) {
	rec := httptest.NewRecorder()
	oidc.NewDiscovery().ServeHTTP(rec, httptest.NewRequest("GET", "/x", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status %d", rec.Code)
	}
}

// Covers: FR-44 (part)
// Acceptance: DPoP binding (part)
// A realm with a client whose dpop option is not off lists the proof algorithms.
func TestDiscoveryGoldenDPoP(t *testing.T) {
	realm := testutil.RealmYAML("main", "clients:\n  app:\n    dpop: allowed\n    redirect_uris: [https://app.example.com/callback]\n")
	src := testutil.NewConfig(t, discServerDefault, map[string]string{"main": realm})
	rec := fetchDiscovery(discoveryRouter(t, src), "/main/.well-known/openid-configuration")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, rec.Body.Bytes(), "", "  "); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	pretty.WriteByte('\n')
	golden(t, "discovery_dpop.golden.json", pretty.Bytes())
}

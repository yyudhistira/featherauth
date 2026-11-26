package oidc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/logx"
	"github.com/yyudhistira/featherauth/internal/provider"
	"github.com/yyudhistira/featherauth/internal/provider/providertest"
	"github.com/yyudhistira/featherauth/internal/secure"
	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/testutil"
	"github.com/yyudhistira/featherauth/internal/testutil/mockidp"
)

var loginStart = time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)

// loginEnv is a realm whose five providers are served by mock identity
// providers, reached through the real registry.
type loginEnv struct {
	realm *config.Realm
	reg   *provider.Pool
	st    store.Store
	clk   *clock.Fake
	auth  *Authorize
	mocks map[config.ProviderKey]*mockidp.Server
}

func newLoginEnv(t *testing.T, serverYAML string) loginEnv {
	t.Helper()
	clk := clock.NewFake(loginStart)
	mocks := map[config.ProviderKey]*mockidp.Server{
		"google":   mockidp.New(t, clk, mockidp.Google),
		"apple":    mockidp.New(t, clk, mockidp.Apple),
		"github":   mockidp.New(t, clk, mockidp.GitHub),
		"facebook": mockidp.New(t, clk, mockidp.Facebook),
		"corp":     mockidp.New(t, clk, mockidp.Generic),
	}
	u := func(k config.ProviderKey) string { return mocks[k].URL() }
	providers := `  google:
    enabled: true
    client_id: client-id
    client_secret_file: secrets/main/google_secret
    endpoints: {authorize: "` + u("google") + `/authorize", token: "` + u("google") + `/token", jwks: "` + u("google") + `/jwks"}
  apple:
    enabled: true
    client_id: client-id
    team_id: TEAM123456
    key_id: KEY1234567
    private_key_file: secrets/main/apple.p8
    endpoints: {authorize: "` + u("apple") + `/authorize", token: "` + u("apple") + `/token", jwks: "` + u("apple") + `/jwks"}
  github:
    enabled: true
    client_id: client-id
    client_secret_file: secrets/main/github_secret
    endpoints: {authorize: "` + u("github") + `/login/oauth/authorize", token: "` + u("github") + `/login/oauth/access_token"}
  facebook:
    enabled: true
    client_id: client-id
    client_secret_file: secrets/main/facebook_secret
    endpoints: {authorize: "` + u("facebook") + `/dialog/oauth", token: "` + u("facebook") + `/oauth/access_token"}
  corp:
    type: oidc
    enabled: true
    client_id: client-id
    client_secret_file: secrets/main/corp_secret
    issuer: "` + u("corp") + `"
`
	if serverYAML == "" {
		serverYAML = testutil.ProvidersServerYAML
	}
	l, _ := testutil.NewProviderConfigWithServer(t, serverYAML, providers, "google", "github", "facebook", "corp")
	realm, ok := l.Current().Realm("main")
	if !ok {
		t.Fatal("realm main missing")
	}
	st := testutil.NewStore(t)
	log := logx.New(&bytes.Buffer{}, slog.LevelDebug, clk)
	reg := provider.NewPool(l, clk, log)
	return loginEnv{
		realm: realm, reg: reg, st: st, clk: clk, mocks: mocks,
		auth: NewAuthorize(AuthorizeConfig{Store: st, Clock: clk}),
	}
}

func (e loginEnv) start(t *testing.T, key config.ProviderKey, req AuthRequest) loginStarted {
	t.Helper()
	p, ok := e.reg.Get(e.realm.Name, key)
	if !ok {
		t.Fatalf("provider %s is not available", key)
	}
	req.Realm = e.realm
	got, err := e.auth.startLogin(context.Background(), req, key, p)
	if err != nil {
		t.Fatalf("startLogin: %v", err)
	}
	return got
}

func baseRequest() AuthRequest {
	return AuthRequest{
		ClientID: "web", RedirectURI: "https://app.example.com/callback", State: "client-state", Nonce: "client-nonce",
		CodeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", ResponseMode: ModeFragment,
	}
}

func s256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// Covers: SEC-08 (part)
// Acceptance: State cookie (part)
func TestStartLoginSetsTheStateCookie(t *testing.T) {
	tests := []struct {
		name, server, realmPath, want string
	}{
		{"https", "", "/main/callback/", "Path=/main/callback/; Max-Age=600; HttpOnly; Secure; SameSite=Lax"},
		{"local development without https", "public_url: http://127.0.0.1:8080\nrequire_https: false\n", "/main/callback/",
			"Path=/main/callback/; Max-Age=600; HttpOnly; SameSite=Lax"},
		{"keycloak layout", "public_url: https://auth.example.com\nurls:\n  path_prefix: /auth\n  issuer: \"{prefix}/realms/{realm}\"\n  endpoints:\n    callback: \"{prefix}/realms/{realm}/broker/{provider}/endpoint\"\n",
			"/auth/realms/main/broker/", "Path=/auth/realms/main/broker/; Max-Age=600; HttpOnly; Secure; SameSite=Lax"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newLoginEnv(t, tt.server)
			got := env.start(t, "google", baseRequest())
			state := got.state
			sum := secure.HashOf(state)
			wantName := "fa_state_" + string(sum[:8])
			if got.cookie == nil || got.cookie.Name != wantName || got.cookie.Value != state {
				t.Fatalf("cookie %+v, want name %s and the state as its value", got.cookie, wantName)
			}
			if want := wantName + "=" + state + "; " + tt.want; got.cookie.String() != want {
				t.Errorf("Set-Cookie\n got %s\nwant %s", got.cookie.String(), want)
			}
			if got.cookie.SameSite != http.SameSiteLaxMode || got.cookie.Domain != "" {
				t.Errorf("cookie %+v", got.cookie)
			}
		})
	}
}

// Covers: SEC-08 (part)
func TestStartLoginStoresTheRequest(t *testing.T) {
	env := newLoginEnv(t, "")
	req := baseRequest()
	ten := 10 * time.Second
	req.MaxAge = &ten
	got := env.start(t, "google", req)

	if len(got.state) != 22 {
		t.Errorf("state %q is not 128 bits", got.state)
	}
	loc, err := url.Parse(got.location)
	if err != nil {
		t.Fatal(err)
	}
	q := loc.Query()
	if q.Get("state") != got.state || strings.HasPrefix(got.location, env.mocks["google"].URL()+"/authorize?") == false {
		t.Errorf("location %s", got.location)
	}

	ctx := context.Background()
	var row store.AuthRequest
	if err := env.st.Read(ctx, func(tx store.Tx) error {
		var err error
		row, err = tx.AuthRequests().Get(ctx, store.AuthRequestID(got.state))
		return err
	}); err != nil {
		t.Fatalf("the request is not stored under the state: %v", err)
	}
	var realmID store.RealmID
	if err := env.st.Read(ctx, func(tx store.Tx) error {
		var err error
		realmID, err = tx.Realms().Find(ctx, "main")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if row.RealmID != realmID || row.ClientID != "web" || row.RedirectURI != req.RedirectURI ||
		row.ClientState != "client-state" || row.Nonce != "client-nonce" || row.CodeChallenge != req.CodeChallenge ||
		row.ResponseMode != "fragment" || row.Provider != "google" {
		t.Errorf("row %+v", row)
	}
	if row.MaxAge == nil || *row.MaxAge != ten {
		t.Errorf("max_age %v", row.MaxAge)
	}
	if want := loginStart.Add(10 * time.Minute); !row.ExpiresAt.Equal(want) {
		t.Errorf("expires %v, want %v", row.ExpiresAt, want)
	}
	if len(row.ProviderNonce) != 22 || row.ProviderNonce == row.Nonce || row.ProviderNonce != q.Get("nonce") {
		t.Errorf("provider nonce %q, URL nonce %q", row.ProviderNonce, q.Get("nonce"))
	}
	if len(row.ProviderPKCEVerifier) != 43 || q.Get("code_challenge") != s256(row.ProviderPKCEVerifier) {
		t.Errorf("provider verifier %q, challenge %q", row.ProviderPKCEVerifier, q.Get("code_challenge"))
	}
	if row.ProviderPKCEVerifier == req.CodeChallenge || row.ProviderNonce == req.CodeChallenge {
		t.Error("the provider values are the client's")
	}
}

// Covers: SEC-08 (part)
func TestStartLoginNeedsNoClientValues(t *testing.T) {
	env := newLoginEnv(t, "")
	req := AuthRequest{ClientID: "web", RedirectURI: "https://app.example.com/callback", ResponseMode: ModeQuery}
	got := env.start(t, "github", req)
	ctx := context.Background()
	var row store.AuthRequest
	if err := env.st.Read(ctx, func(tx store.Tx) error {
		var err error
		row, err = tx.AuthRequests().Get(ctx, store.AuthRequestID(got.state))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if row.ClientState != "" || row.Nonce != "" || row.CodeChallenge != "" || row.MaxAge != nil || row.Provider != "github" {
		t.Errorf("row %+v", row)
	}
}

// Covers: SEC-08 (part)
func TestStartLoginStatesAreUnique(t *testing.T) {
	env := newLoginEnv(t, "")
	seen := map[string]bool{}
	for i := 0; i < 20; i++ {
		got := env.start(t, "google", baseRequest())
		if seen[got.state] {
			t.Fatalf("state %q repeated", got.state)
		}
		seen[got.state] = true
	}
}

func TestStartLoginStoreFailure(t *testing.T) {
	env := newLoginEnv(t, "")
	boom := errors.New("disk full")
	env.auth = NewAuthorize(AuthorizeConfig{Store: failingWrites{env.st, boom}, Clock: env.clk})
	p, _ := env.reg.Get("main", "google")
	req := baseRequest()
	req.Realm = env.realm
	if _, err := env.auth.startLogin(context.Background(), req, "google", p); !errors.Is(err, boom) {
		t.Errorf("error %v, want the store's", err)
	}
	failing := &failingRandom{}
	env.auth = NewAuthorize(AuthorizeConfig{Store: env.st, Clock: env.clk, Random: failing})
	if _, err := env.auth.startLogin(context.Background(), req, "google", p); err == nil {
		t.Error("a failing random source went unnoticed")
	}
}

type failingWrites struct {
	store.Store
	err error
}

func (f failingWrites) Write(context.Context, func(store.Tx) error) error { return f.err }

type failingRandom struct{}

func (failingRandom) Read([]byte) (int, error) { return 0, errors.New("no entropy") }

// Covers: FR-02 (part)
// Acceptance: Login hints (part)
func TestStartLoginPassesTheHintsToEachProvider(t *testing.T) {
	zero := time.Duration(0)
	reqs := []struct {
		name string
		mod  func(*AuthRequest)
	}{
		{"none", func(*AuthRequest) {}},
		{"prompt=login", func(r *AuthRequest) { r.Prompt = "login" }},
		{"max_age=0", func(r *AuthRequest) { r.MaxAge = &zero }},
		{"prompt=select_account", func(r *AuthRequest) { r.Prompt = "select_account" }},
		{"prompt=consent", func(r *AuthRequest) { r.Prompt = "consent" }},
		{"login_hint", func(r *AuthRequest) { r.LoginHint = "ann@example.com" }},
	}
	type want struct {
		present url.Values
		absent  []string
	}
	tests := map[config.ProviderKey][]want{
		"google": {
			{nil, []string{"prompt", "max_age", "login_hint"}},
			{url.Values{"prompt": {"select_account"}}, []string{"max_age"}},
			{url.Values{"prompt": {"select_account"}}, []string{"max_age"}},
			{url.Values{"prompt": {"select_account"}}, nil},
			{url.Values{"prompt": {"consent"}}, nil},
			{url.Values{"login_hint": {"ann@example.com"}}, []string{"prompt"}},
		},
		"apple": {
			{nil, []string{"prompt", "max_age", "login_hint"}},
			{nil, []string{"prompt", "max_age", "login_hint"}},
			{nil, []string{"prompt", "max_age", "login_hint"}},
			{nil, []string{"prompt", "max_age", "login_hint"}},
			{nil, []string{"prompt", "max_age", "login_hint"}},
			{nil, []string{"prompt", "max_age", "login_hint"}},
		},
		"github": {
			{nil, []string{"prompt", "max_age", "login_hint"}},
			{url.Values{"prompt": {"select_account"}}, []string{"max_age"}},
			{url.Values{"prompt": {"select_account"}}, []string{"max_age"}},
			{url.Values{"prompt": {"select_account"}}, nil},
			{nil, []string{"prompt", "max_age"}},
			{nil, []string{"login_hint"}},
		},
		"facebook": {
			{nil, []string{"auth_type", "prompt", "max_age", "login_hint"}},
			{url.Values{"auth_type": {"reauthenticate"}}, []string{"prompt", "max_age"}},
			{url.Values{"auth_type": {"reauthenticate"}}, []string{"prompt", "max_age"}},
			{nil, []string{"auth_type", "prompt", "max_age"}},
			{nil, []string{"auth_type", "prompt", "max_age"}},
			{nil, []string{"login_hint"}},
		},
		"corp": {
			{nil, []string{"prompt", "max_age", "login_hint"}},
			{url.Values{"prompt": {"login"}}, nil},
			{url.Values{"max_age": {"0"}}, nil},
			{url.Values{"prompt": {"select_account"}}, nil},
			{url.Values{"prompt": {"consent"}}, nil},
			{url.Values{"login_hint": {"ann@example.com"}}, nil},
		},
	}
	env := newLoginEnv(t, "")
	for key, wants := range tests {
		for i, rq := range reqs {
			t.Run(string(key)+"/"+rq.name, func(t *testing.T) {
				req := baseRequest()
				rq.mod(&req)
				got := env.start(t, key, req)
				// The provider (the mock) receives exactly the mapped parameters.
				providertest.Authorize(t, got.location)
				auths := env.mocks[key].Authorizations()
				params := auths[len(auths)-1].Params
				for k, v := range wants[i].present {
					if params.Get(k) != v[0] {
						t.Errorf("%s = %q, want %q (received %v)", k, params.Get(k), v[0], params)
					}
				}
				for _, k := range wants[i].absent {
					if params.Has(k) {
						t.Errorf("%s = %q was sent, want none", k, params.Get(k))
					}
				}
				if params.Get("state") != got.state {
					t.Errorf("the provider received state %q, want %q", params.Get("state"), got.state)
				}
			})
		}
	}
}

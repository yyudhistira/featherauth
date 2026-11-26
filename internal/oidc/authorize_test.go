package oidc_test

import (
	"bytes"
	"context"
	"errors"
	"html"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/logx"
	"github.com/yyudhistira/featherauth/internal/oidc"
	"github.com/yyudhistira/featherauth/internal/provider"
	"github.com/yyudhistira/featherauth/internal/secure"
	"github.com/yyudhistira/featherauth/internal/server"
	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/store/audit"
	"github.com/yyudhistira/featherauth/internal/testutil"
	"github.com/yyudhistira/featherauth/internal/testutil/mockidp"
	tsrv "github.com/yyudhistira/featherauth/internal/testutil/server"
	"github.com/yyudhistira/featherauth/internal/token"
	"github.com/yyudhistira/featherauth/internal/user"
)

const issuer = "https://auth.example.com/main"

// authzHandlers is a server.Handlers whose authorize endpoint is the real one.
type authzHandlers struct {
	*deliverHandlers
	a  *oidc.Authorize
	cb *oidc.Callback
}

var _ server.Handlers = authzHandlers{}

func (h authzHandlers) Authorize(w http.ResponseWriter, r *http.Request) { h.a.ServeHTTP(w, r) }
func (h authzHandlers) Callback(w http.ResponseWriter, r *http.Request)  { h.cb.ServeCallback(w, r) }
func (h authzHandlers) CallbackContinue(w http.ResponseWriter, r *http.Request) {
	h.cb.ServeContinue(w, r)
}

// authzEnv is the whole authorize endpoint behind the router, over the real
// store and registry, with two mock identity providers: github and a generic
// OpenID provider (corp).
type authzEnv struct {
	rt    *server.Router
	st    store.Store
	fs    *testutil.FaultStore
	clk   *clock.Fake
	gh    *mockidp.Server
	idp   *mockidp.Server
	apple *mockidp.Server
	codes *token.Codes
	reg   provider.Registry
	src   config.Source
	log   *slog.Logger
	logs  *bytes.Buffer
	// path is the database file of st, for tests that read its rows.
	path string
}

// Provider blocks of the realm; %GH% and %IDP% are the mock servers' URLs.
var authzProviderBlocks = map[string]string{
	"github": `  github:
    enabled: true
    client_id: client-id
    client_secret_file: secrets/main/github_secret
    endpoints: {authorize: "%GH%/login/oauth/authorize", token: "%GH%/login/oauth/access_token"}
`,
	"corp": `  corp:
    type: oidc
    enabled: true
    display_name: Corp
    client_id: client-id
    client_secret_file: secrets/main/corp_secret
    issuer: "%IDP%"
`,
	"stealth": `  stealth:
    type: oidc
    enabled: true
    hidden: true
    client_id: client-id
    client_secret_file: secrets/main/corp_secret
    issuer: "%IDP%"
`,
	"off": `  off:
    type: oidc
    client_id: client-id
    client_secret_file: secrets/main/corp_secret
    issuer: "%IDP%"
`,
	// Nothing listens on the discovery address: the provider is listed but cannot be built.
	"apple": `  apple:
    enabled: true
    client_id: client-id
    team_id: TEAM123456
    key_id: KEY1234567
    private_key_file: secrets/main/apple.p8
    endpoints: {authorize: "%APPLE%/authorize", token: "%APPLE%/token", jwks: "%APPLE%/jwks"}
`,
	// Stands in for Google, whose issuer is fixed: a generic provider that trusts its emails.
	"trusted": `  trusted:
    type: oidc
    enabled: true
    trust_email: true
    client_id: client-id
    client_secret_file: secrets/main/corp_secret
    issuer: "%IDP%"
`,
	// A GitHub that gives up after 100ms.
	"slow": `  slow:
    type: github
    enabled: true
    client_id: client-id
    client_secret_file: secrets/main/github_secret
    timeout: 100ms
    endpoints: {authorize: "%GH%/login/oauth/authorize", token: "%GH%/login/oauth/access_token"}
`,
	"broken": `  broken:
    type: oidc
    enabled: true
    client_id: client-id
    client_secret_file: secrets/main/corp_secret
    issuer: "http://127.0.0.1:9"
`,
}

func newAuthzEnv(t *testing.T, providers ...string) *authzEnv {
	t.Helper()
	return newAuthzEnvWith(t, authzServerYAML, "", providers...)
}

// newAuthzEnvWith is newAuthzEnv with the server settings serverYAML and the
// options mainExtra added to the realm main (before its keys).
func newAuthzEnvWith(t *testing.T, serverYAML, mainExtra string, providers ...string) *authzEnv {
	t.Helper()
	clk := clock.NewFake(testStart)
	e := &authzEnv{
		clk: clk, logs: &bytes.Buffer{},
		gh:    mockidp.New(t, clk, mockidp.GitHub),
		idp:   mockidp.New(t, clk, mockidp.Generic),
		apple: mockidp.New(t, clk, mockidp.Apple),
	}
	for _, m := range []*mockidp.Server{e.gh, e.idp, e.apple} {
		m.SetSecretCheck(func(string) error { return nil }) // the secrets of the files are random
	}
	var blocks strings.Builder
	for _, p := range providers {
		blocks.WriteString(authzProviderBlocks[p])
	}
	yaml := strings.NewReplacer("%GH%", e.gh.URL(), "%IDP%", e.idp.URL(), "%APPLE%", e.apple.URL()).Replace(blocks.String())
	realm := func(name, extra string) string {
		return "name: " + name + "\n" + extra +
			"keys:\n  - { kid: " + name + "-1, file: secrets/" + name + "/signing.pem, state: active }\n" +
			"providers:\n" + yaml + authzClients
	}
	src := testutil.NewConfigWithSecrets(t, serverYAML,
		map[string]string{"main": realm("main", mainExtra), "closed": realm("closed", "enabled: false\n")},
		"secrets/main/srv_secret", "secrets/main/github_secret", "secrets/main/corp_secret", "secrets/main/apple.p8")
	e.st, e.path = testutil.NewStoreFile(t)
	e.fs = testutil.NewFaultStore(e.st)
	log := logx.New(e.logs, slog.LevelDebug, clk)
	pool := provider.NewPool(src, clk, log)
	reg := tsrv.Registry{Registry: pool, Adapters: map[config.ProviderKey]provider.Provider{
		"github": tsrv.GitHub(t, e.gh, "https://auth.example.com/main/callback/github"),
		"apple":  tsrv.Apple(t, clk, e.apple, "https://auth.example.com/main/callback/apple"),
	}}
	a := oidc.NewAuthorize(oidc.AuthorizeConfig{Registry: reg, Store: e.fs, Clock: clk, Log: log,
		Verifier: token.NewVerifier(clk, src.Current().Secrets()), Codes: e.codes})
	users := user.NewService(e.fs, audit.NewWriter(e.fs, log, clk, secure.Default), log, clk, secure.Default)
	e.codes = token.NewCodes(e.fs, token.NewIssuer(clk, secure.Default, src.Current().Secrets()), clk, secure.Default)
	e.reg, e.src, e.log = reg, src, log
	box, err := secure.NewBox(src.Current().Secrets().EncryptionKeys())
	if err != nil {
		t.Fatal(err)
	}
	cb := oidc.NewCallback(oidc.CallbackConfig{Registry: reg, Store: e.fs, Clock: clk, Log: log, Users: users, Codes: e.codes, Box: box})
	e.rt = server.NewHandler(src, authzHandlers{&deliverHandlers{}, a, cb}, server.Middleware{Logger: log, Clock: clk})
	return e
}

func (e *authzEnv) do(method, target string, form url.Values) *httptest.ResponseRecorder {
	var req *http.Request
	if method == "POST" {
		req = httptest.NewRequest(method, target, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req = httptest.NewRequest(method, target, nil)
	}
	req.RemoteAddr = "192.0.2.10:4000"
	rec := httptest.NewRecorder()
	e.rt.ServeHTTP(rec, req)
	return rec
}

func (e *authzEnv) get(v url.Values) *httptest.ResponseRecorder {
	r, _ := e.src.Current().Realm("main")
	return e.do("GET", r.EndpointPath(config.EndpointAuthorize, "")+"?"+v.Encode(), nil)
}

func (e *authzEnv) post(v url.Values) *httptest.ResponseRecorder {
	return e.do("POST", "/main/authorize", v)
}

// stored counts (and removes) the logins in progress.
func (e *authzEnv) stored(t *testing.T) int64 {
	t.Helper()
	var n int64
	err := e.st.Write(context.Background(), func(tx store.Tx) error {
		var err error
		n, err = tx.AuthRequests().DeleteExpired(context.Background(), e.clk.Now().Add(1000*time.Hour))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

var hiddenField = regexp.MustCompile(`<input type="hidden" name="([^"]*)" value="([^"]*)">`)

// result is what the client receives from an authorization endpoint answer in
// the given mode: the values of the redirect's query or fragment, or of the
// form_post page.
func result(t *testing.T, rec *httptest.ResponseRecorder, mode oidc.ResponseMode) url.Values {
	t.Helper()
	switch mode {
	case oidc.ModeQuery, oidc.ModeFragment:
		if rec.Code != http.StatusFound {
			t.Fatalf("%s: status %d, want 302; body %s", mode, rec.Code, rec.Body)
		}
		u, err := url.Parse(rec.Header().Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		if mode == oidc.ModeQuery {
			if u.Fragment != "" {
				t.Errorf("query mode put values in the fragment: %s", u)
			}
			return u.Query()
		}
		if len(u.Query()) != 0 {
			t.Errorf("fragment mode put values in the query: %s", u)
		}
		v, err := url.ParseQuery(u.Fragment)
		if err != nil {
			t.Fatal(err)
		}
		return v
	default:
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "<form") {
			t.Fatalf("form_post: status %d, body %s", rec.Code, rec.Body)
		}
		out := url.Values{}
		for _, m := range hiddenField.FindAllStringSubmatch(rec.Body.String(), -1) {
			out.Add(html.UnescapeString(m[1]), html.UnescapeString(m[2]))
		}
		return out
	}
}

// wantPage checks an error page: no redirect, no cookie, nothing stored.
func wantPage(t *testing.T, e *authzEnv, rec *httptest.ResponseRecorder, status int) {
	t.Helper()
	if rec.Code != status {
		t.Errorf("status %d, want %d", rec.Code, status)
	}
	if loc := rec.Header().Get("Location"); loc != "" {
		t.Errorf("redirected to %s", loc)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("content type %q, want HTML", ct)
	}
	if rec.Header().Get("Set-Cookie") != "" {
		t.Errorf("cookie set: %v", rec.Header().Values("Set-Cookie"))
	}
	if n := e.stored(t); n != 0 {
		t.Errorf("%d logins stored", n)
	}
}

var authzReqs = []struct {
	name string
	mode oidc.ResponseMode
}{
	{"query", oidc.ModeQuery}, {"fragment", oidc.ModeFragment}, {"form_post", oidc.ModeFormPost},
}

// Covers: FR-02 (part)
// Acceptance: Authorize methods
func TestAuthorizeGetAndPostGiveTheSameResult(t *testing.T) {
	cases := []struct {
		name string
		v    url.Values
	}{
		{"a login", goodRequest("provider", "github")},
		{"a request error", goodRequest("scope", "profile")},
		{"a prompt=none answer", goodRequest("prompt", "none")},
		{"a page error", goodRequest("client_id", "nobody")},
		{"the chooser", goodRequest()},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			e := newAuthzEnv(t, "github", "corp")
			byGet := e.get(tt.v)
			n := e.stored(t)
			byPost := e.post(tt.v)
			if m := e.stored(t); m != n {
				t.Errorf("GET stored %d logins, POST %d", n, m)
			}
			if byGet.Code != byPost.Code {
				t.Fatalf("GET %d, POST %d", byGet.Code, byPost.Code)
			}
			if tt.name == "a login" {
				// The state, nonce and challenge are random; the rest is the same.
				g, p := mustURL(t, byGet.Header().Get("Location")), mustURL(t, byPost.Header().Get("Location"))
				gq, pq := g.Query(), p.Query()
				for _, k := range []string{"state", "code_challenge"} {
					gq.Del(k)
					pq.Del(k)
				}
				if g.Path != p.Path || g.Host != p.Host || gq.Encode() != pq.Encode() {
					t.Errorf("GET %s\nPOST %s", g, p)
				}
				return
			}
			if byGet.Header().Get("Location") != byPost.Header().Get("Location") || byGet.Body.String() != byPost.Body.String() {
				t.Errorf("GET %d %q\n%s\nPOST %d %q\n%s", byGet.Code, byGet.Header().Get("Location"), byGet.Body,
					byPost.Code, byPost.Header().Get("Location"), byPost.Body)
			}
		})
	}
}

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// Covers: FR-02 (part)
// Acceptance: Authorize methods
func TestAuthorizePostIgnoresTheQueryAndNeedsAForm(t *testing.T) {
	e := newAuthzEnv(t, "github")
	// A form POST reads the body only.
	req := httptest.NewRequest("POST", "/main/authorize?"+goodRequest().Encode(), strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	e.rt.ServeHTTP(rec, req)
	wantPage(t, e, rec, 400)
	// Another content type has no form.
	req = httptest.NewRequest("POST", "/main/authorize", strings.NewReader(goodRequest().Encode()))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	e.rt.ServeHTTP(rec, req)
	wantPage(t, e, rec, 400)
	// A body that is not a form is a page error.
	req = httptest.NewRequest("POST", "/main/authorize", strings.NewReader("client_id=%zz"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	e.rt.ServeHTTP(rec, req)
	wantPage(t, e, rec, 400)
}

// Covers: FR-21 (part), FR-58 (part)
// Acceptance: Wrong method (part)
func TestAuthorizeRefusesOtherMethods(t *testing.T) {
	e := newAuthzEnv(t, "github")
	for _, m := range []string{"PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "TRACE"} {
		t.Run(m, func(t *testing.T) {
			rec := e.do(m, "/main/authorize?"+goodRequest("provider", "github").Encode(), nil)
			wantPage(t, e, rec, http.StatusMethodNotAllowed)
			if got := rec.Header().Get("Allow"); got != "GET, POST" {
				t.Errorf("Allow = %q", got)
			}
			if m != "HEAD" && !strings.Contains(rec.Body.String(), "Method Not Allowed") {
				t.Errorf("body %q", rec.Body)
			}
			if n := len(e.gh.Requests()); n != 0 {
				t.Errorf("the provider received %d requests", n)
			}
		})
	}
}

// Covers: FR-02 (part), FR-03 (part)
// Acceptance: Request errors
func TestAuthorizeRequestErrors(t *testing.T) {
	pages := []struct {
		name string
		v    url.Values
	}{
		{"client_id missing", goodRequest("client_id", "-")},
		{"client_id unknown", goodRequest("client_id", "nobody")},
		{"client_id repeated", withExtra(goodRequest(), "client_id", "web")},
		{"redirect_uri missing", goodRequest("redirect_uri", "-")},
		{"redirect_uri repeated", withExtra(goodRequest(), "redirect_uri", "https://app.example.com/callback")},
		{"redirect_uri not an exact match", goodRequest("redirect_uri", "https://app.example.com/callback/")},
		{"response_mode unsupported", goodRequest("response_mode", "web_message")},
	}
	for _, tt := range pages {
		t.Run(tt.name, func(t *testing.T) {
			e := newAuthzEnv(t, "github", "corp")
			for _, m := range []string{"GET", "POST"} {
				var rec *httptest.ResponseRecorder
				if m == "GET" {
					rec = e.get(tt.v)
				} else {
					rec = e.post(tt.v)
				}
				wantPage(t, e, rec, http.StatusBadRequest)
				if !strings.Contains(rec.Body.String(), "The request is not valid") {
					t.Errorf("the page does not explain: %s", rec.Body)
				}
			}
		})
	}

	redirects := []struct {
		name string
		v    url.Values
		code string
	}{
		{"response_type missing", goodRequest("response_type", "-"), "invalid_request"},
		{"another parameter repeated", withExtra(goodRequest(), "nonce", "again"), "invalid_request"},
		{"response_type other than code", goodRequest("response_type", "token"), "unsupported_response_type"},
		{"scope missing", goodRequest("scope", "-"), "invalid_scope"},
		{"scope without openid", goodRequest("scope", "profile"), "invalid_scope"},
		{"request present", goodRequest("request", "x"), "request_not_supported"},
		{"request_uri present", goodRequest("request_uri", "https://x.example.com"), "request_uri_not_supported"},
		{"prompt=none with another prompt", goodRequest("prompt", "none login"), "invalid_request"},
		{"max_age not a number", goodRequest("max_age", "x"), "invalid_request"},
		{"max_age negative", goodRequest("max_age", "-5"), "invalid_request"},
		{"code_challenge_method plain", goodRequest("code_challenge_method", "plain"), "invalid_request"},
		{"code_challenge without a method", goodRequest("code_challenge_method", "-"), "invalid_request"},
		{"code_challenge of the wrong size", goodRequest("code_challenge", "short"), "invalid_request"},
		{"no code_challenge for a client that requires one", goodRequest("code_challenge", "-", "code_challenge_method", "-"), "invalid_request"},
		{"prompt=none", goodRequest("prompt", "none"), "login_required"},
	}
	for _, mode := range authzReqs {
		for _, withState := range []bool{true, false} {
			for _, tt := range redirects {
				name := tt.name + "/" + mode.name
				if !withState {
					name += "/no state"
				}
				t.Run(name, func(t *testing.T) {
					e := newAuthzEnv(t, "github", "corp")
					v := cloneValues(tt.v)
					v.Set("response_mode", mode.name)
					if !withState {
						v.Del("state")
					}
					for _, rec := range []*httptest.ResponseRecorder{e.get(v), e.post(v)} {
						got := result(t, rec, mode.mode)
						if got.Get("error") != tt.code || got.Get("error_description") == "" || got.Get("iss") != issuer {
							t.Errorf("result %v, want error %s with a description and iss", got, tt.code)
						}
						if withState && got.Get("state") != "st-1" || !withState && got.Has("state") {
							t.Errorf("state %q (sent: %v)", got.Get("state"), withState)
						}
						if got.Has("code") {
							t.Errorf("a code was issued: %v", got)
						}
						if rec.Header().Get("Set-Cookie") != "" {
							t.Error("a state cookie was set")
						}
					}
					if n := e.stored(t); n != 0 {
						t.Errorf("%d logins stored", n)
					}
					if n := len(e.gh.Requests()) + len(e.idp.Requests()); n != 0 {
						t.Errorf("a provider was contacted %d times", n)
					}
				})
			}
		}
	}
}

// Covers: FR-02 (part)
// Acceptance: Request errors
func TestAuthorizeDeliversToTheClientsResponseMode(t *testing.T) {
	e := newAuthzEnv(t, "github", "corp")
	v := goodRequest("client_id", "frag", "redirect_uri", "https://frag.example.com/callback", "scope", "-")
	got := result(t, e.get(v), oidc.ModeFragment)
	if got.Get("error") != "invalid_scope" {
		t.Errorf("fragment client: %v", got)
	}
	v = goodRequest("client_id", "posting", "redirect_uri", "https://post.example.com/callback", "scope", "-")
	if got := result(t, e.get(v), oidc.ModeFormPost); got.Get("error") != "invalid_scope" {
		t.Errorf("form_post client: %v", got)
	}
	// The request's response_mode wins.
	v.Set("response_mode", "query")
	if got := result(t, e.get(v), oidc.ModeQuery); got.Get("error") != "invalid_scope" {
		t.Errorf("request mode: %v", got)
	}
}

// Covers: FR-02 (part)
// Acceptance: prompt=none
func TestAuthorizePromptNone(t *testing.T) {
	for _, mode := range authzReqs {
		t.Run(mode.name, func(t *testing.T) {
			e := newAuthzEnv(t, "github", "corp")
			got := result(t, e.get(goodRequest("prompt", "none", "response_mode", mode.name)), mode.mode)
			if got.Get("error") != "login_required" || got.Get("state") != "st-1" || got.Get("iss") != issuer {
				t.Errorf("result %v", got)
			}
			if e.stored(t) != 0 || len(e.gh.Requests())+len(e.idp.Requests()) != 0 {
				t.Error("prompt=none started a login")
			}
		})
	}
	t.Run("an unregistered redirect URI shows the page", func(t *testing.T) {
		e := newAuthzEnv(t, "github", "corp")
		rec := e.get(goodRequest("prompt", "none", "redirect_uri", "https://evil.example.com/cb"))
		wantPage(t, e, rec, http.StatusBadRequest)
	})
	t.Run("prompt=login is the normal flow", func(t *testing.T) {
		e := newAuthzEnv(t, "github", "corp")
		rec := e.get(goodRequest("prompt", "login", "provider", "github"))
		if loc := rec.Header().Get("Location"); rec.Code != http.StatusFound || !strings.HasPrefix(loc, e.gh.URL()+"/login/oauth/authorize?") {
			t.Errorf("status %d, Location %q", rec.Code, loc)
		}
		if got := mustURL(t, rec.Header().Get("Location")).Query().Get("prompt"); got != "select_account" {
			t.Errorf("the provider got prompt %q", got)
		}
	})
}

// Covers: FR-02 (part)
// Acceptance: Scope handling (part)
func TestAuthorizeScopeHandling(t *testing.T) {
	e := newAuthzEnv(t, "github")
	// A request without openid is refused ...
	got := result(t, e.get(goodRequest("scope", "profile email")), oidc.ModeQuery)
	if got.Get("error") != "invalid_scope" {
		t.Errorf("result %v", got)
	}
	// ... and one with other scopes next to openid goes on; they are ignored.
	rec := e.get(goodRequest("scope", "openid profile foo"))
	if loc := rec.Header().Get("Location"); rec.Code != http.StatusFound || !strings.HasPrefix(loc, e.gh.URL()+"/login/oauth/authorize?") {
		t.Fatalf("status %d, Location %q", rec.Code, loc)
	}
	if e.stored(t) != 1 {
		t.Error("the login was not stored")
	}
}

// Covers: FR-03, SEC-02 (part)
// Acceptance: Redirect URI
func TestAuthorizeRedirectURIs(t *testing.T) {
	native := func(uri string) url.Values {
		return goodRequest("client_id", "native", "redirect_uri", uri)
	}
	t.Run("unregistered", func(t *testing.T) {
		e := newAuthzEnv(t, "github")
		wantPage(t, e, e.get(goodRequest("redirect_uri", "https://evil.example.com/callback")), 400)
	})
	t.Run("a loopback port change is accepted for a public client", func(t *testing.T) {
		e := newAuthzEnv(t, "github")
		rec := e.get(native("http://127.0.0.1:54321/cb"))
		if rec.Code != http.StatusFound || !strings.HasPrefix(rec.Header().Get("Location"), e.gh.URL()) {
			t.Fatalf("status %d, Location %q", rec.Code, rec.Header().Get("Location"))
		}
		state := mustURL(t, rec.Header().Get("Location")).Query().Get("state")
		var row store.AuthRequest
		if err := e.st.Read(context.Background(), func(tx store.Tx) error {
			var err error
			row, err = tx.AuthRequests().Get(context.Background(), store.AuthRequestID(state))
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if row.RedirectURI != "http://127.0.0.1:54321/cb" {
			t.Errorf("the login keeps the redirect URI %q", row.RedirectURI)
		}
	})
	t.Run("another loopback path is refused", func(t *testing.T) {
		e := newAuthzEnv(t, "github")
		wantPage(t, e, e.get(native("http://127.0.0.1:54321/other")), 400)
	})
	t.Run("a confidential client cannot use a loopback URI", func(t *testing.T) {
		e := newAuthzEnv(t, "github")
		wantPage(t, e, e.get(goodRequest("client_id", "srv", "redirect_uri", "http://127.0.0.1:54321/cb")), 400)
	})
}

// Covers: SEC-01 (part)
// Acceptance: PKCE for every client
func TestAuthorizeRequiresPKCEForEveryClient(t *testing.T) {
	cases := []struct {
		name string
		v    url.Values
		code string
	}{
		{"a default confidential client without a challenge", goodRequest("client_id", "srv", "redirect_uri", "https://srv.example.com/callback",
			"code_challenge", "-", "code_challenge_method", "-"), "invalid_request"},
		{"a default public client without a challenge", goodRequest("code_challenge", "-", "code_challenge_method", "-"), "invalid_request"},
		{"a challenge without a method", goodRequest("client_id", "srv", "redirect_uri", "https://srv.example.com/callback",
			"code_challenge_method", "-"), "invalid_request"},
		{"a challenge without a method for a public client", goodRequest("code_challenge_method", "-"), "invalid_request"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			e := newAuthzEnv(t, "github")
			got := result(t, e.get(tt.v), oidc.ModeQuery)
			if got.Get("error") != tt.code || got.Get("state") != "st-1" || got.Get("iss") != issuer {
				t.Errorf("result %v", got)
			}
			if e.stored(t) != 0 {
				t.Error("a login was stored")
			}
		})
	}
	t.Run("a confidential client with a challenge goes on", func(t *testing.T) {
		e := newAuthzEnv(t, "github")
		rec := e.get(goodRequest("client_id", "srv", "redirect_uri", "https://srv.example.com/callback"))
		if rec.Code != http.StatusFound || !strings.HasPrefix(rec.Header().Get("Location"), e.gh.URL()) {
			t.Errorf("status %d, Location %q", rec.Code, rec.Header().Get("Location"))
		}
	})
	t.Run("a client that does not require PKCE may send none", func(t *testing.T) {
		e := newAuthzEnv(t, "github")
		rec := e.get(goodRequest("client_id", "legacy", "redirect_uri", "https://legacy.example.com/callback",
			"code_challenge", "-", "code_challenge_method", "-"))
		if rec.Code != http.StatusFound || !strings.HasPrefix(rec.Header().Get("Location"), e.gh.URL()) {
			t.Errorf("status %d, Location %q", rec.Code, rec.Header().Get("Location"))
		}
	})
}

// Covers: FR-04 (part)
// Acceptance: Single provider
func TestAuthorizeSingleProvider(t *testing.T) {
	t.Run("one visible provider redirects straight to it", func(t *testing.T) {
		e := newAuthzEnv(t, "github")
		rec := e.get(goodRequest())
		if loc := rec.Header().Get("Location"); rec.Code != http.StatusFound || !strings.HasPrefix(loc, e.gh.URL()+"/login/oauth/authorize?") {
			t.Fatalf("status %d, Location %q", rec.Code, loc)
		}
		if e.stored(t) != 1 {
			t.Error("the login was not stored")
		}
	})
	t.Run("two visible providers show the chooser", func(t *testing.T) {
		e := newAuthzEnv(t, "github", "corp")
		rec := e.get(goodRequest())
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `class="providers"`) || rec.Header().Get("Location") != "" {
			t.Fatalf("status %d, body %s", rec.Code, rec.Body)
		}
		if rec.Header().Get("Set-Cookie") != "" || e.stored(t) != 0 {
			t.Error("the chooser stored a login or set a cookie")
		}
	})
	t.Run("one visible and one hidden provider redirect to the visible one", func(t *testing.T) {
		e := newAuthzEnv(t, "github", "stealth")
		rec := e.get(goodRequest())
		if loc := rec.Header().Get("Location"); rec.Code != http.StatusFound || !strings.HasPrefix(loc, e.gh.URL()) {
			t.Errorf("status %d, Location %q", rec.Code, loc)
		}
	})
	t.Run("an unknown hint shows the chooser and is logged", func(t *testing.T) {
		e := newAuthzEnv(t, "github", "corp")
		rec := e.get(goodRequest("provider", "nope"))
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `class="providers"`) {
			t.Fatalf("status %d, body %s", rec.Code, rec.Body)
		}
		if !strings.Contains(e.logs.String(), `"provider":"nope"`) {
			t.Errorf("the hint is not logged:\n%s", e.logs)
		}
	})
	t.Run("the second hint name selects a provider", func(t *testing.T) {
		e := newAuthzEnv(t, "github", "corp")
		rec := e.get(goodRequest("idp", "github"))
		if loc := rec.Header().Get("Location"); rec.Code != http.StatusFound || !strings.HasPrefix(loc, e.gh.URL()) {
			t.Errorf("status %d, Location %q", rec.Code, loc)
		}
	})
}

var chooserLink = regexp.MustCompile(`href="(/main/authorize\?[^"]*)"`)

// Covers: FR-04 (part)
// Acceptance: Chooser links
func TestAuthorizeChooserLinksLeadStraightToEachProvider(t *testing.T) {
	e := newAuthzEnv(t, "github", "corp")
	original := goodRequest("response_mode", "fragment", "prompt", "login", "login_hint", "ann@example.com", "ui_locales", "nl")
	rec := e.post(original)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	links := chooserLink.FindAllStringSubmatch(rec.Body.String(), -1)
	if len(links) != 2 {
		t.Fatalf("%d links in %s", len(links), rec.Body)
	}
	if e.stored(t) != 0 || len(e.gh.Requests())+len(e.idp.Requests()) != 0 {
		t.Error("something happened before the choice")
	}
	targets := map[string]string{"github": e.gh.URL() + "/login/oauth/authorize?", "corp": e.idp.URL() + "/authorize?"}
	for _, m := range links {
		href := html.UnescapeString(m[1])
		q := mustURL(t, href).Query()
		want := cloneValues(original)
		want.Set("provider", q.Get("provider"))
		if q.Encode() != want.Encode() {
			t.Errorf("link %s keeps\n got %v\nwant %v", href, q, want)
		}
		got := e.do("GET", href, nil)
		if loc := got.Header().Get("Location"); got.Code != http.StatusFound || !strings.HasPrefix(loc, targets[q.Get("provider")]) {
			t.Errorf("%s: status %d, Location %q, want a redirect to %s", q.Get("provider"), got.Code, loc, targets[q.Get("provider")])
		}
	}
	if e.stored(t) != 2 {
		t.Error("each choice stores its own login")
	}
}

// Covers: FR-02 (part), SEC-08 (part)
func TestAuthorizeStartsTheLogin(t *testing.T) {
	e := newAuthzEnv(t, "github", "corp")
	rec := e.get(goodRequest("provider", "github", "response_mode", "form_post", "max_age", "30"))
	if rec.Code != http.StatusFound {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	loc := mustURL(t, rec.Header().Get("Location"))
	q := loc.Query()
	if loc.Host != mustURL(t, e.gh.URL()).Host || q.Get("client_id") != "client-id" ||
		q.Get("redirect_uri") != "https://auth.example.com/main/callback/github" {
		t.Errorf("Location %s", loc)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != oidc.StateCookieName(q.Get("state")) || cookies[0].Value != q.Get("state") ||
		cookies[0].Path != "/main/callback/" || cookies[0].MaxAge != 600 || !cookies[0].HttpOnly || !cookies[0].Secure ||
		cookies[0].SameSite != http.SameSiteLaxMode {
		t.Errorf("cookies %+v", cookies)
	}
	var row store.AuthRequest
	if err := e.st.Read(context.Background(), func(tx store.Tx) error {
		var err error
		row, err = tx.AuthRequests().Get(context.Background(), store.AuthRequestID(q.Get("state")))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if row.ClientID != "web" || row.ClientState != "st-1" || row.ResponseMode != "form_post" || row.Provider != "github" ||
		row.MaxAge == nil || *row.MaxAge != 30*time.Second || row.Nonce != "n-1" {
		t.Errorf("row %+v", row)
	}
}

// Covers: FR-02 (part)
func TestAuthorizeProviderFailures(t *testing.T) {
	t.Run("a provider that is down is temporarily unavailable", func(t *testing.T) {
		e := newAuthzEnv(t, "broken", "github")
		for _, mode := range authzReqs {
			got := result(t, e.get(goodRequest("provider", "broken", "response_mode", mode.name)), mode.mode)
			if got.Get("error") != "temporarily_unavailable" || got.Get("state") != "st-1" || got.Get("iss") != issuer {
				t.Errorf("%s: result %v", mode.name, got)
			}
		}
		if e.stored(t) != 0 {
			t.Error("a login was stored")
		}
	})
	t.Run("a store failure is a server_error", func(t *testing.T) {
		e := newAuthzEnv(t, "github")
		e.fs.FailWrite = errors.New("disk full")
		rec := e.get(goodRequest())
		got := result(t, rec, oidc.ModeQuery)
		if got.Get("error") != "server_error" || got.Get("state") != "st-1" || got.Get("iss") != issuer {
			t.Errorf("result %v", got)
		}
		if rec.Header().Get("Set-Cookie") != "" {
			t.Error("a cookie was set for a login that was not stored")
		}
		if strings.Contains(e.logs.String(), "disk full") == false {
			t.Errorf("the failure is not logged:\n%s", e.logs)
		}
	})
	t.Run("a disabled realm shows the error page", func(t *testing.T) {
		e := newAuthzEnv(t, "github")
		rec := e.do("GET", "/closed/authorize?"+goodRequest().Encode(), nil)
		wantPage(t, e, rec, http.StatusForbidden)
		if !strings.Contains(rec.Body.String(), "Sign-in is not available right now.") {
			t.Errorf("body %s", rec.Body)
		}
	})
}

// Covers: SEC-13 (part)
func TestAuthorizeLogsNoSecret(t *testing.T) {
	e := newAuthzEnv(t, "github", "corp")
	const logState, logNonce = "state-unlikely-4711", "nonce-unlikely-4711"
	e.get(goodRequest("provider", "nope", "login_hint", "ann@example.com", "state", logState, "nonce", logNonce))
	rec := e.get(goodRequest("provider", "github", "login_hint", "ann@example.com", "state", logState, "nonce", logNonce))
	e.get(goodRequest("scope", "-", "state", logState, "nonce", logNonce))
	e.get(goodRequest("client_id", "nobody", "state", logState, "nonce", logNonce))
	state := mustURL(t, rec.Header().Get("Location")).Query().Get("state")
	for _, secret := range []string{state, logState, logNonce, challenge, "ann@example.com"} {
		if strings.Contains(e.logs.String(), secret) {
			t.Errorf("the log holds %q:\n%s", secret, e.logs)
		}
	}
}

// Covers: FR-02 (part)
// Acceptance: Authorize request details
func TestAuthorizeRequestDetails(t *testing.T) {
	e := newAuthzEnv(t, "github")
	frag := func(v url.Values) url.Values {
		v.Set("client_id", "frag")
		v.Set("redirect_uri", "https://frag.example.com/callback")
		return v
	}
	// A repeated response_mode: invalid_request in the client's mode (fragment here).
	got := result(t, e.get(withExtra(frag(goodRequest("response_mode", "query")), "response_mode", "query")), oidc.ModeFragment)
	if got.Get("error") != "invalid_request" || got.Get("state") != "st-1" {
		t.Errorf("repeated response_mode: %v", got)
	}
	// A repeated state: invalid_request without state.
	got = result(t, e.get(withExtra(goodRequest(), "state", "again")), oidc.ModeQuery)
	if got.Get("error") != "invalid_request" || got.Has("state") {
		t.Errorf("repeated state: %v", got)
	}
	// max_age: digits only, in range.
	if rec := e.get(goodRequest("max_age", "007")); rec.Code != http.StatusFound || !strings.HasPrefix(rec.Header().Get("Location"), e.gh.URL()) {
		t.Errorf("max_age=007: status %d, Location %q", rec.Code, rec.Header().Get("Location"))
	}
	for _, v := range []string{"9223372037", "+5"} {
		if got := result(t, e.get(goodRequest("max_age", v)), oidc.ModeQuery); got.Get("error") != "invalid_request" {
			t.Errorf("max_age=%s: %v", v, got)
		}
	}
	e.stored(t)
	// prompt: unknown values are ignored, the first of the known ones is passed on.
	rec := e.get(goodRequest("prompt", "create login consent"))
	if rec.Code != http.StatusFound {
		t.Fatalf("prompt: status %d", rec.Code)
	}
	if p := mustURL(t, rec.Header().Get("Location")).Query().Get("prompt"); p != "select_account" {
		t.Errorf("the provider received prompt %q, want select_account (the mapping of login)", p)
	}
	e.stored(t)
	// A POST whose body is not a form.
	req := httptest.NewRequest("POST", "/main/authorize", strings.NewReader("client_id=%zz"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	bad := httptest.NewRecorder()
	e.rt.ServeHTTP(bad, req)
	wantPage(t, e, bad, http.StatusBadRequest)
	// A disabled realm.
	wantPage(t, e, e.do("GET", "/closed/authorize?"+goodRequest().Encode(), nil), http.StatusForbidden)
}

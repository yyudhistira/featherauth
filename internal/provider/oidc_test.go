package provider_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/provider"
	"github.com/yyudhistira/featherauth/internal/provider/providertest"
	"github.com/yyudhistira/featherauth/internal/testutil/mockidp"
)

func newOIDC(t *testing.T, env providertest.Env, mod func(*provider.OIDCOptions)) *provider.OIDC {
	t.Helper()
	opts := provider.OIDCOptions{
		Issuer: env.Server.URL(), ClientID: env.Server.ClientID(), ClientSecret: env.Server.ClientSecret(),
		RedirectURI: env.RedirectURI, Scopes: []string{"openid", "email", "profile"},
		Timeout: env.Timeout, Clock: env.Clock,
	}
	if env.UserInfo {
		opts.Endpoints.Userinfo = env.Server.URL() + "/userinfo"
	}
	if mod != nil {
		mod(&opts)
	}
	p, err := provider.NewOIDC(context.Background(), opts)
	if err != nil {
		t.Fatalf("NewOIDC: %v", err)
	}
	return p
}

var _ provider.Provider = (*provider.OIDC)(nil)

// Covers: FR-14 (part), SEC-03 (part)
// Acceptance: Provider adapters (part)
// Acceptance: Login hints (part)
func TestOIDCKeepsTheProviderContract(t *testing.T) {
	zero := 0
	providertest.Run(t, providertest.Case{
		Profile:  mockidp.Generic,
		OIDC:     true,
		PKCE:     true,
		UserInfo: true,
		New: func(t *testing.T, env providertest.Env) provider.Provider {
			return newOIDC(t, env, nil)
		},
		Hints: []providertest.Hint{
			{Name: "none", Absent: []string{"prompt", "max_age", "login_hint"}},
			{Name: "login", Opts: provider.AuthOptions{Prompt: "login", MaxAge: &zero, LoginHint: "ann@example.com"},
				Want: url.Values{"prompt": {"login"}, "max_age": {"0"}, "login_hint": {"ann@example.com"}}},
			{Name: "select_account", Opts: provider.AuthOptions{Prompt: "select_account"},
				Want: url.Values{"prompt": {"select_account"}}, Absent: []string{"max_age", "login_hint"}},
			{Name: "consent", Opts: provider.AuthOptions{Prompt: "consent"},
				Want: url.Values{"prompt": {"consent"}}, Absent: []string{"max_age", "login_hint"}},
		},
	})
}

// Covers: FR-14 (part)
// Acceptance: Provider config (part)
func TestOIDCEndpointOverridesNeedNoDiscovery(t *testing.T) {
	srv := mockidp.New(t, clock.NewFake(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)), mockidp.Generic)
	u := srv.URL()
	p, err := provider.NewOIDC(context.Background(), provider.OIDCOptions{
		Issuer: u, ClientID: "client-id", ClientSecret: "client-secret", RedirectURI: "https://x.example/cb",
		Endpoints: provider.OIDCEndpoints{Authorize: u + "/custom-authorize", Token: u + "/token", JWKS: u + "/jwks"},
		Timeout:   time.Second, Clock: clock.NewFake(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := p.AuthURL("s", "n", "c", provider.AuthOptions{}); !strings.HasPrefix(got, u+"/custom-authorize?") {
		t.Errorf("AuthURL = %q, want the overridden endpoint", got)
	}
	for _, r := range srv.Requests() {
		if r.Path == "/.well-known/openid-configuration" {
			t.Error("discovery was fetched although every endpoint was overridden")
		}
	}
}

// This tests config decoding: the adapter reports the provider's claim as it is
// and the link rule (SEC-04) is applied by the user package.
//
// Covers: SEC-04 (part)
// Acceptance: No unsafe link (part)
func TestOIDCTrustEmailDefaultsToFalse(t *testing.T) {
	r, ds := config.DecodeRealm("r.yaml", []byte("name: r\nproviders:\n  corp: {type: oidc, issuer: \"https://idp.example\"}\n"))
	if r == nil {
		t.Fatalf("decode: %v", ds)
	}
	if r.Providers["corp"].TrustEmail {
		t.Error("trust_email is true by default for an oidc provider")
	}
}

// Covers: FR-14 (part), SEC-03 (part)
// Acceptance: No unsafe link (part)
func TestOIDCMissingEmailVerifiedMeansUnverified(t *testing.T) {
	providertest.Run(t, providertest.Case{
		Profile: mockidp.Generic, OIDC: true, PKCE: true,
		New:  func(t *testing.T, env providertest.Env) provider.Provider { return newOIDC(t, env, nil) },
		User: mockidp.User{Sub: "sub-2", Email: "bob@example.com", Name: "Bob"}, // no email_verified claim
		Want: provider.Identity{Subject: "sub-2", Email: "bob@example.com", Name: "Bob"},
	})
}

// Covers: FR-14 (part)
// Acceptance: Login hints (part)
func TestOIDCPassesAuthTimeThrough(t *testing.T) {
	at := time.Date(2029, 12, 31, 23, 0, 0, 0, time.UTC)
	providertest.Run(t, providertest.Case{
		Profile: mockidp.Generic, OIDC: true, PKCE: true,
		New:  func(t *testing.T, env providertest.Env) provider.Provider { return newOIDC(t, env, nil) },
		User: mockidp.User{Sub: "sub-3", Email: "cy@example.com", EmailVerified: true, Name: "Cy", AuthTime: at},
		Want: provider.Identity{Subject: "sub-3", Email: "cy@example.com", EmailVerified: true, Name: "Cy", AuthTime: at},
	})
}

func newDirect(t *testing.T, prof mockidp.Profile, mod func(*provider.OIDCOptions)) (*provider.OIDC, *mockidp.Server) {
	t.Helper()
	return newDirectWithTimeout(t, prof, mod, 5*time.Second)
}

// newDirectWithTimeout is newDirect with the provider timeout given; only a
// case that waits for the timeout asks for a short one.
func newDirectWithTimeout(t *testing.T, prof mockidp.Profile, mod func(*provider.OIDCOptions), timeout time.Duration) (*provider.OIDC, *mockidp.Server) {
	t.Helper()
	clk := clock.NewFake(time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC))
	srv := mockidp.New(t, clk, prof)
	srv.SetUser(mockidp.User{Sub: "sub-1", Email: "ann@example.com", EmailVerified: true})
	env := providertest.Env{Server: srv, Clock: clk, RedirectURI: "https://featherauth.example/cb", Timeout: timeout}
	return newOIDC(t, env, mod), srv
}

// Covers: FR-14 (part)
func TestOIDCNeedsAPositiveTimeout(t *testing.T) {
	srv := mockidp.New(t, clock.NewFake(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)), mockidp.Generic)
	for _, d := range []time.Duration{0, -time.Second} {
		_, err := provider.NewOIDC(context.Background(), provider.OIDCOptions{
			Issuer: srv.URL(), ClientID: "client-id", RedirectURI: "https://x.example/cb", Timeout: d,
			Clock: clock.NewFake(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)),
		})
		if err == nil {
			t.Errorf("NewOIDC accepted Timeout %v", d)
		}
	}
}

// Covers: FR-14 (part)
func TestOIDCDiscoveryFailure(t *testing.T) {
	srv := mockidp.New(t, clock.NewFake(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)), mockidp.Generic)
	_, err := provider.NewOIDC(context.Background(), provider.OIDCOptions{
		Issuer: srv.URL() + "/no-such-issuer", ClientID: "client-id", RedirectURI: "https://x.example/cb",
		Timeout: time.Second, Clock: clock.NewFake(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)),
	})
	if err == nil {
		t.Error("NewOIDC succeeded although discovery failed")
	}
}

// Covers: FR-05 (part), FR-14 (part)
// Acceptance: Provider timeout (part)
func TestOIDCExchangeFailures(t *testing.T) {
	ctx := context.Background()
	t.Run("no code", func(t *testing.T) {
		p, srv := newDirect(t, mockidp.Generic, nil)
		if _, err := p.Exchange(ctx, provider.Callback{}, "v", "n"); err == nil || errors.Is(err, provider.ErrUnavailable) {
			t.Errorf("error = %v, want a plain error", err)
		}
		if srv.TokenCalls() != 0 {
			t.Error("the token endpoint was called without a code")
		}
	})
	t.Run("token 5xx is unavailable", func(t *testing.T) {
		p, srv := newDirect(t, mockidp.Generic, nil)
		srv.FailToken(1)
		if _, err := p.Exchange(ctx, provider.Callback{Code: "c"}, "v", "n"); !errors.Is(err, provider.ErrUnavailable) {
			t.Errorf("error = %v, want ErrUnavailable", err)
		}
	})
	t.Run("token timeout is unavailable", func(t *testing.T) {
		p, srv := newDirectWithTimeout(t, mockidp.Generic, nil, 50*time.Millisecond)
		srv.Block()
		if _, err := p.Exchange(ctx, provider.Callback{Code: "c"}, "v", "n"); !errors.Is(err, provider.ErrUnavailable) {
			t.Errorf("error = %v, want ErrUnavailable", err)
		}
	})
	t.Run("token 4xx is not unavailable", func(t *testing.T) {
		p, _ := newDirect(t, mockidp.Generic, nil)
		_, err := p.Exchange(ctx, provider.Callback{Code: "unknown"}, "v", "n")
		if err == nil || errors.Is(err, provider.ErrUnavailable) || errors.Is(err, provider.ErrCancelled) {
			t.Errorf("error = %v, want a plain error", err)
		}
	})
	t.Run("no ID token", func(t *testing.T) {
		// The GitHub profile answers the token call without an ID token.
		clk := clock.NewFake(time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC))
		srv := mockidp.New(t, clk, mockidp.GitHub)
		u := srv.URL()
		p, err := provider.NewOIDC(ctx, provider.OIDCOptions{
			Issuer: u, ClientID: srv.ClientID(), ClientSecret: srv.ClientSecret(), RedirectURI: "https://featherauth.example/cb",
			Endpoints: provider.OIDCEndpoints{Authorize: u + "/login/oauth/authorize", Token: u + "/login/oauth/access_token", JWKS: u + "/jwks"},
			Timeout:   time.Second, Clock: clk,
		})
		if err != nil {
			t.Fatal(err)
		}
		code := loginCode(t, p)
		if _, err := p.Exchange(ctx, provider.Callback{Code: code}, "", "n"); err == nil || errors.Is(err, provider.ErrUnavailable) {
			t.Errorf("error = %v, want a plain error", err)
		}
	})
}

// Covers: FR-14 (part)
// Acceptance: No unsafe link (part)
func TestOIDCStringEmailVerifiedIsUnverified(t *testing.T) {
	providertest.Run(t, providertest.Case{
		Profile: mockidp.Generic, OIDC: true, PKCE: true,
		New:  func(t *testing.T, env providertest.Env) provider.Provider { return newOIDC(t, env, nil) },
		User: mockidp.User{Sub: "sub-4", Email: "di@example.com", EmailVerified: "true", Name: "Di"},
		Want: provider.Identity{Subject: "sub-4", Email: "di@example.com", Name: "Di"},
	})
}

// loginCode runs the authorize step at the mock without PKCE and returns the code.
func loginCode(t *testing.T, p provider.Provider) string {
	t.Helper()
	c := &http.Client{Timeout: time.Second, Transport: &http.Transport{}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, p.AuthURL("s", "n", "", provider.AuthOptions{}), nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || loc.Query().Get("code") == "" {
		t.Fatalf("no code in the authorize answer: %v %v", resp.Status, err)
	}
	return loc.Query().Get("code")
}

// Covers: FR-14 (part), SEC-03 (part)
func TestOIDCClaimTypes(t *testing.T) {
	exchange := func(t *testing.T, mutate func(map[string]any)) (provider.Identity, error) {
		t.Helper()
		p, srv := newDirect(t, mockidp.Generic, nil)
		code := loginCode(t, p)
		srv.SetIDTokenClaims(func(c map[string]any) { c["nonce"] = "n"; mutate(c) })
		return p.Exchange(context.Background(), provider.Callback{Code: code}, "", "n")
	}

	// An auth_time that is present but not a usable number fails the exchange
	// with a plain error: it feeds the max_age check, so it is not guessed.
	for _, c := range []struct {
		name string
		v    any
	}{{"string", "yesterday"}, {"object", map[string]any{"a": 1}}, {"huge", 1e30}, {"negative", -5}} {
		t.Run("auth_time "+c.name+" fails", func(t *testing.T) {
			_, err := exchange(t, func(m map[string]any) { m["auth_time"] = c.v })
			if err == nil || errors.Is(err, provider.ErrUnavailable) || errors.Is(err, provider.ErrCancelled) || errors.Is(err, provider.ErrRefused) {
				t.Errorf("error = %v, want a plain error", err)
			}
		})
	}
	t.Run("auth_time null is absent", func(t *testing.T) {
		id, err := exchange(t, func(m map[string]any) { m["auth_time"] = nil })
		if err != nil || !id.AuthTime.IsZero() {
			t.Errorf("identity %+v, error %v; want no auth_time and no error", id, err)
		}
	})

	// Wrong-typed email, name and email_verified are tolerated: they are only
	// profile data, and a value we cannot read is treated as not given (a
	// non-boolean email_verified is unverified), never trusted.
	t.Run("wrong-typed profile claims are ignored", func(t *testing.T) {
		id, err := exchange(t, func(m map[string]any) { m["email"] = 7; m["name"] = []string{"x"}; m["email_verified"] = 1 })
		if err != nil {
			t.Fatal(err)
		}
		if id.Email != "" || id.Name != "" || id.EmailVerified || id.Subject != "sub-1" {
			t.Errorf("identity = %+v", id)
		}
	})
}

// userinfoLogin runs a login against the mock with the adapter's user-info
// endpoint set to url (or the mock's own when url is empty) and returns what
// Exchange gave. idClaims changes the ID token's claims after the login.
func userinfoLogin(t *testing.T, userinfoURL string, idClaims func(map[string]any)) (provider.Identity, *mockidp.Server, error) {
	t.Helper()
	return userinfoLoginWithTimeout(t, userinfoURL, idClaims, 5*time.Second)
}

// userinfoLoginWithTimeout is userinfoLogin with the provider timeout given.
func userinfoLoginWithTimeout(t *testing.T, userinfoURL string, idClaims func(map[string]any), timeout time.Duration) (provider.Identity, *mockidp.Server, error) {
	t.Helper()
	clk := clock.NewFake(time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC))
	srv := mockidp.New(t, clk, mockidp.Generic)
	srv.SetUser(mockidp.User{Sub: "sub-1", Email: "ann@example.com", EmailVerified: true, Name: "Ann Example"})
	env := providertest.Env{Server: srv, Clock: clk, RedirectURI: "https://featherauth.example/cb", Timeout: timeout}
	if userinfoURL == "mock" {
		userinfoURL = srv.URL() + "/userinfo"
	}
	a := newOIDC(t, env, func(o *provider.OIDCOptions) { o.Endpoints.Userinfo = userinfoURL })
	code := loginCode(t, a)
	srv.SetIDTokenClaims(func(c map[string]any) {
		c["nonce"] = "n"
		if idClaims != nil {
			idClaims(c)
		}
	})
	id, err := a.Exchange(context.Background(), provider.Callback{Code: code}, "", "n")
	return id, srv, err
}

func userinfoCalls(srv *mockidp.Server) int {
	n := 0
	for _, r := range srv.Requests() {
		if r.Path == "/userinfo" {
			n++
		}
	}
	return n
}

func dropProfile(c map[string]any) {
	delete(c, "email")
	delete(c, "email_verified")
	delete(c, "name")
}

// Covers: FR-14 (part), SEC-03 (part)
// Acceptance: Provider user info (part)
func TestOIDCUserinfoIsCalledOnlyWhenSet(t *testing.T) {
	id, srv, err := userinfoLogin(t, "", dropProfile)
	if err != nil {
		t.Fatal(err)
	}
	if userinfoCalls(srv) != 0 {
		t.Error("the user-info endpoint was called although none is configured (the mock's discovery lists one)")
	}
	if id.Email != "" || id.Name != "" || id.EmailVerified {
		t.Errorf("identity %+v, want only what the ID token has", id)
	}
}

// Covers: FR-14 (part), SEC-03 (part)
// Acceptance: Provider user info (part)
func TestOIDCUserinfoFillsMissingClaims(t *testing.T) {
	id, srv, err := userinfoLogin(t, "mock", dropProfile)
	if err != nil {
		t.Fatal(err)
	}
	if userinfoCalls(srv) != 1 {
		t.Fatalf("%d user-info calls, want 1", userinfoCalls(srv))
	}
	want := provider.Identity{Subject: "sub-1", Email: "ann@example.com", EmailVerified: true, Name: "Ann Example"}
	if id != want {
		t.Errorf("identity %+v, want %+v", id, want)
	}
	// the call carries the access token as a bearer token
	for _, r := range srv.Requests() {
		if r.Path == "/userinfo" && !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("Authorization = %q", r.Header.Get("Authorization"))
		}
	}
}

// Covers: FR-14 (part), SEC-03 (part)
// Acceptance: Provider user info (part)
func TestOIDCUserinfoNeverOverridesTheIDToken(t *testing.T) {
	// The ID token has an email (unverified), a name and no email_verified
	// claim at all; user info offers a verified address and another name.
	id, _, err := userinfoLogin(t, "mock", func(c map[string]any) {
		c["email"] = "id@example.com"
		c["name"] = "ID Name"
		delete(c, "email_verified")
	})
	if err != nil {
		t.Fatal(err)
	}
	// the email and name stay the ID token's; a verified flag for a different
	// address is not taken
	if id.Email != "id@example.com" || id.Name != "ID Name" || id.EmailVerified {
		t.Errorf("identity %+v", id)
	}

	// An ID token claim that is present, even false, is kept.
	id, _, err = userinfoLogin(t, "mock", func(c map[string]any) { c["email_verified"] = false })
	if err != nil || id.EmailVerified || id.Email != "ann@example.com" {
		t.Errorf("identity %+v, error %v", id, err)
	}
}

// Covers: FR-14 (part), SEC-03 (part)
// Acceptance: Provider user info (part)
func TestOIDCUserinfoSubMismatchIsRefused(t *testing.T) {
	_, _, err := userinfoLogin(t, "mock", func(c map[string]any) { c["sub"] = "someone-else" })
	if !errors.Is(err, provider.ErrRefused) {
		t.Errorf("error = %v, want ErrRefused", err)
	}
}

// Covers: FR-14 (part), SEC-03 (part)
// Acceptance: Provider user info (part)
func TestOIDCUserinfoFailures(t *testing.T) {
	for _, c := range []struct {
		name        string
		handle      func(w http.ResponseWriter, r *http.Request)
		unavailable bool
		timeout     time.Duration // the provider timeout; 0 is the generous one
	}{
		{"5xx", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(502) }, true, 0},
		{"4xx", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(401) }, false, 0},
		{"not JSON", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("SECRET-BODY")) }, false, 0},
		{"JSON of the wrong shape", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`["SECRET-BODY"]`)) }, false, 0},
		{"no sub", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"email":"x@example.com"}`)) }, false, 0},
		{"timeout", func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }, true, 100 * time.Millisecond},
	} {
		t.Run(c.name, func(t *testing.T) {
			api := httptest.NewServer(http.HandlerFunc(c.handle))
			defer api.Close()
			timeout := c.timeout
			if timeout == 0 {
				timeout = 5 * time.Second
			}
			_, _, err := userinfoLoginWithTimeout(t, api.URL+"/userinfo", dropProfile, timeout)
			if err == nil {
				t.Fatal("Exchange succeeded")
			}
			if errors.Is(err, provider.ErrUnavailable) != c.unavailable {
				t.Errorf("error = %v, unavailable want %v", err, c.unavailable)
			}
			if strings.Contains(err.Error(), "SECRET-BODY") {
				t.Errorf("the error holds the response body: %v", err)
			}
		})
	}
}

// Covers: FR-14 (part), SEC-03 (part)
// Acceptance: Provider user info (part)
func TestOIDCUserinfoEmailVerifiedNeedsARealTrue(t *testing.T) {
	for _, c := range []struct {
		name string
		body string
		want bool
	}{
		{"true", `"email_verified":true`, true},
		{"string true", `"email_verified":"true"`, false},
		{"number", `"email_verified":1`, false},
		{"false", `"email_verified":false`, false},
		{"missing", `"x":1`, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(`{"sub":"sub-1","email":"ann@example.com",` + c.body + `}`))
			}))
			defer api.Close()
			id, _, err := userinfoLogin(t, api.URL, dropProfile)
			if err != nil || id.EmailVerified != c.want || id.Email != "ann@example.com" {
				t.Errorf("identity %+v, error %v", id, err)
			}
		})
	}
}

// Covers: FR-14 (part), SEC-03 (part)
// Acceptance: Provider user info (part)
func TestOIDCUserinfoFillsWrongTypedOrEmptyClaims(t *testing.T) {
	// A claim of the wrong type or an empty one counts as lacking, so user
	// info fills it. email_verified is not in the ID token at all here.
	for _, c := range []struct {
		name  string
		email any
		nm    any
	}{{"wrong types", 7, []string{"x"}}, {"empty strings", "", ""}} {
		t.Run(c.name, func(t *testing.T) {
			id, _, err := userinfoLogin(t, "mock", func(m map[string]any) {
				m["email"], m["name"] = c.email, c.nm
				delete(m, "email_verified")
			})
			want := provider.Identity{Subject: "sub-1", Email: "ann@example.com", EmailVerified: true, Name: "Ann Example"}
			if err != nil || id != want {
				t.Errorf("identity %+v, error %v; want %+v", id, err, want)
			}
		})
	}
}

// x/oauth2 refuses a token response without an access_token first, so this
// test pins the outcome (a plain error and no call to the user-info endpoint);
// the guard in fillFromUserinfo is defence in depth behind it.
//
// Covers: FR-14 (part), SEC-03 (part)
// Acceptance: Provider user info (part)
func TestOIDCUserinfoNeedsAnAccessToken(t *testing.T) {
	var calls int
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++ }))
	defer api.Close()
	// a token endpoint that answers with an ID token but no access token
	clk := clock.NewFake(time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC))
	srv := mockidp.New(t, clk, mockidp.Generic)
	srv.SetUser(mockidp.User{Sub: "sub-1", Email: "ann@example.com", EmailVerified: true})
	env := providertest.Env{Server: srv, Clock: clk, RedirectURI: "https://featherauth.example/cb", Timeout: time.Second}
	tokenProxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		req, _ := http.NewRequestWithContext(r.Context(), r.Method, srv.URL()+"/token", strings.NewReader(r.PostForm.Encode()))
		req.Header = r.Header.Clone()
		resp, err := (&http.Client{Timeout: time.Second, Transport: &http.Transport{}}).Do(req)
		if err != nil {
			w.WriteHeader(502)
			return
		}
		defer resp.Body.Close()
		var m map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&m)
		m["access_token"] = ""
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(m)
	}))
	defer tokenProxy.Close()
	a := newOIDC(t, env, func(o *provider.OIDCOptions) {
		o.Endpoints = provider.OIDCEndpoints{
			Authorize: srv.URL() + "/authorize", Token: tokenProxy.URL, JWKS: srv.URL() + "/jwks", Userinfo: api.URL,
		}
	})
	code := loginCode(t, a)
	srv.SetIDTokenClaims(func(c map[string]any) { c["nonce"] = "n" })
	_, err := a.Exchange(context.Background(), provider.Callback{Code: code}, "", "n")
	if err == nil || errors.Is(err, provider.ErrUnavailable) || errors.Is(err, provider.ErrRefused) {
		t.Errorf("error = %v, want a plain error", err)
	}
	if calls != 0 {
		t.Errorf("the user-info endpoint was called %d times without an access token", calls)
	}
}

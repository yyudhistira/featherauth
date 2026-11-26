package provider_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/logx"
	"github.com/yyudhistira/featherauth/internal/provider"
	"github.com/yyudhistira/featherauth/internal/provider/providertest"
	"github.com/yyudhistira/featherauth/internal/testutil/mockidp"
)

var _ provider.Provider = (*provider.GitHub)(nil)

func githubOpts(env providertest.Env) provider.GitHubOptions {
	u := env.Server.URL()
	return provider.GitHubOptions{
		ClientID: env.Server.ClientID(), ClientSecret: env.Server.ClientSecret(), RedirectURI: env.RedirectURI,
		Scopes: []string{"read:user", "user:email"}, PKCE: true, AllowSignup: true, RequireVerifiedEmail: true,
		AuthorizeURL: u + "/login/oauth/authorize", TokenURL: u + "/login/oauth/access_token",
		UserURL: u + "/user", EmailsURL: u + "/user/emails", Timeout: env.Timeout,
	}
}

func newGitHub(t *testing.T, env providertest.Env, mod func(*provider.GitHubOptions)) *provider.GitHub {
	t.Helper()
	o := githubOpts(env)
	if mod != nil {
		mod(&o)
	}
	p, err := provider.NewGitHub(o)
	if err != nil {
		t.Fatalf("NewGitHub: %v", err)
	}
	return p
}

func githubEnv(t *testing.T, u mockidp.User) (providertest.Env, *mockidp.Server) {
	t.Helper()
	clk := clock.NewFake(time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC))
	srv := mockidp.New(t, clk, mockidp.GitHub)
	srv.SetUser(u)
	return providertest.Env{Server: srv, Clock: clk, RedirectURI: "https://featherauth.example/realm/callback/github", Timeout: 5 * time.Second}, srv
}

var annGitHub = mockidp.User{
	Sub: "12345", Name: "Ann Example",
	Emails: []mockidp.Email{{Email: "other@example.com", Verified: true}, {Email: "ann@example.com", Primary: true, Verified: true}},
}

var githubVerifier = strings.Repeat("v", 43)

// githubLogin runs the authorize step with a PKCE challenge for githubVerifier.
func githubLogin(t *testing.T, p provider.Provider) provider.Callback {
	t.Helper()
	sum := sha256.Sum256([]byte(githubVerifier))
	q := providertest.Authorize(t, p.AuthURL("s", "", base64.RawURLEncoding.EncodeToString(sum[:]), provider.AuthOptions{}))
	if q.Get("code") == "" {
		t.Fatalf("no code: %v", q)
	}
	return provider.Callback{Code: q.Get("code")}
}

func githubExchange(t *testing.T, p provider.Provider) (provider.Identity, error) {
	t.Helper()
	return p.Exchange(context.Background(), githubLogin(t, p), githubVerifier, "")
}

// Covers: FR-14 (part), SEC-03 (part)
// Acceptance: Provider adapters (part)
// Acceptance: Login hints (part)
func TestGitHubKeepsTheProviderContract(t *testing.T) {
	zero := 0
	providertest.Run(t, providertest.Case{
		Profile: mockidp.GitHub, OIDC: false, PKCE: true,
		New:  func(t *testing.T, env providertest.Env) provider.Provider { return newGitHub(t, env, nil) },
		User: annGitHub,
		Want: provider.Identity{Subject: "12345", Email: "ann@example.com", EmailVerified: true, Name: "Ann Example"},
		Hints: []providertest.Hint{
			{Name: "none", Absent: []string{"prompt", "max_age", "login_hint", "allow_signup"}},
			{Name: "prompt=login", Opts: provider.AuthOptions{Prompt: "login"}, Want: url.Values{"prompt": {"select_account"}}},
			{Name: "max_age", Opts: provider.AuthOptions{MaxAge: &zero}, Want: url.Values{"prompt": {"select_account"}}, Absent: []string{"max_age"}},
			{Name: "prompt=select_account", Opts: provider.AuthOptions{Prompt: "select_account"}, Want: url.Values{"prompt": {"select_account"}}},
			{Name: "prompt=consent", Opts: provider.AuthOptions{Prompt: "consent"}, Absent: []string{"prompt"}},
			{Name: "login_hint", Opts: provider.AuthOptions{LoginHint: "ann@example.com"}, Absent: []string{"login_hint", "prompt"}},
		},
	})
}

// Covers: SEC-03 (part)
// Acceptance: Provider adapters (part)
func TestGitHubHeadersOnEveryCall(t *testing.T) {
	env, srv := githubEnv(t, annGitHub)
	p := newGitHub(t, env, nil)
	if _, err := githubExchange(t, p); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, r := range srv.Requests() {
		switch r.Path {
		case "/login/oauth/access_token", "/user", "/user/emails":
			seen[r.Path] = true
			if ua := r.Header.Get("User-Agent"); ua == "" || strings.HasPrefix(ua, "Go-http-client") {
				t.Errorf("%s: User-Agent = %q", r.Path, ua)
			}
			if r.Path == "/login/oauth/access_token" && r.Header.Get("Accept") != "application/json" {
				t.Errorf("token call Accept = %q, want application/json", r.Header.Get("Accept"))
			}
		}
	}
	for _, path := range []string{"/login/oauth/access_token", "/user", "/user/emails"} {
		if !seen[path] {
			t.Errorf("%s was not called", path)
		}
	}
}

// Covers: SEC-03 (part)
// Acceptance: Provider adapters (part)
func TestGitHubAuthURLOptions(t *testing.T) {
	env, _ := githubEnv(t, annGitHub)
	for _, c := range []struct {
		name  string
		mod   func(*provider.GitHubOptions)
		want  url.Values
		avoid []string
	}{
		{"allow_signup false is sent", func(o *provider.GitHubOptions) { o.AllowSignup = false }, url.Values{"allow_signup": {"false"}}, nil},
		{"allow_signup true is not sent", nil, nil, []string{"allow_signup"}},
		{"pkce on sends the challenge", nil, url.Values{"code_challenge": {"chal"}, "code_challenge_method": {"S256"}}, nil},
		{"pkce off sends none", func(o *provider.GitHubOptions) { o.PKCE = false }, nil, []string{"code_challenge", "code_challenge_method"}},
		{"scopes", func(o *provider.GitHubOptions) { o.Scopes = []string{"user:email"} }, url.Values{"scope": {"user:email"}}, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := newGitHub(t, env, c.mod)
			u, err := url.Parse(p.AuthURL("st", "ignored-nonce", "chal", provider.AuthOptions{}))
			if err != nil {
				t.Fatal(err)
			}
			q := u.Query()
			for k, v := range c.want {
				if q.Get(k) != v[0] {
					t.Errorf("%s = %q, want %q", k, q.Get(k), v[0])
				}
			}
			for _, k := range c.avoid {
				if q.Has(k) {
					t.Errorf("%s is sent: %q", k, q.Get(k))
				}
			}
			if q.Get("state") != "st" || q.Get("redirect_uri") != env.RedirectURI || q.Has("nonce") {
				t.Errorf("query = %v", q)
			}
		})
	}
}

// Covers: SEC-03 (part)
// Acceptance: Provider adapters (part)
func TestGitHubVerifiedEmailRules(t *testing.T) {
	unverifiedPrimary := []mockidp.Email{{Email: "a@example.com", Primary: true}, {Email: "b@example.com", Verified: true}}
	for _, c := range []struct {
		name    string
		emails  []mockidp.Email
		require bool
		refused bool
		want    provider.Identity
	}{
		{"primary verified is used", annGitHub.Emails, true, false,
			provider.Identity{Subject: "12345", Email: "ann@example.com", EmailVerified: true, Name: "Ann Example"}},
		{"no emails, required", nil, true, true, provider.Identity{}},
		{"primary unverified, required", unverifiedPrimary, true, true, provider.Identity{}},
		{"primary unverified, not required", unverifiedPrimary, false, false,
			provider.Identity{Subject: "12345", Email: "a@example.com", Name: "Ann Example"}},
		{"no emails, not required", nil, false, false, provider.Identity{Subject: "12345", Name: "Ann Example"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			u := annGitHub
			u.Emails = c.emails
			env, _ := githubEnv(t, u)
			p := newGitHub(t, env, func(o *provider.GitHubOptions) { o.RequireVerifiedEmail = c.require })
			id, err := githubExchange(t, p)
			if c.refused {
				if !errors.Is(err, provider.ErrRefused) {
					t.Errorf("error = %v, want ErrRefused", err)
				}
				return
			}
			if err != nil || id != c.want {
				t.Errorf("identity %+v, error %v; want %+v", id, err, c.want)
			}
		})
	}
}

// Covers: SEC-03 (part)
// Acceptance: Provider adapters (part)
func TestGitHubNumericIDIsTheSubject(t *testing.T) {
	u := annGitHub
	u.Sub = "9007199254740993" // beyond float64 precision: read as a number, not a float
	env, _ := githubEnv(t, u)
	id, err := githubExchange(t, newGitHub(t, env, nil))
	if err != nil || id.Subject != "9007199254740993" {
		t.Errorf("identity %+v, error %v", id, err)
	}
}

// Covers: FR-05 (part)
// Acceptance: Provider timeout (part)
func TestGitHubAPIFailures(t *testing.T) {
	for _, c := range []struct {
		name        string
		user, mails func(w http.ResponseWriter)
		unavailable bool
	}{
		{"user 5xx", func(w http.ResponseWriter) { w.WriteHeader(502) }, nil, true},
		{"emails 5xx", nil, func(w http.ResponseWriter) { w.WriteHeader(500) }, true},
		{"user 401", func(w http.ResponseWriter) { w.WriteHeader(401) }, nil, false},
		{"emails 403", nil, func(w http.ResponseWriter) { w.WriteHeader(403) }, false},
		{"user not JSON", func(w http.ResponseWriter) { _, _ = w.Write([]byte("<html>SECRET-BODY")) }, nil, false},
		{"user without id", func(w http.ResponseWriter) { _, _ = w.Write([]byte(`{"login":"x"}`)) }, nil, false},
		{"id 1.5", func(w http.ResponseWriter) { _, _ = w.Write([]byte(`{"id":1.5}`)) }, nil, false},
		{"id 1e3", func(w http.ResponseWriter) { _, _ = w.Write([]byte(`{"id":1e3}`)) }, nil, false},
		{"id -5", func(w http.ResponseWriter) { _, _ = w.Write([]byte(`{"id":-5}`)) }, nil, false},
		{"id 0", func(w http.ResponseWriter) { _, _ = w.Write([]byte(`{"id":0}`)) }, nil, false},
		{"id 007", func(w http.ResponseWriter) { _, _ = w.Write([]byte(`{"id":007}`)) }, nil, false},
		{"id as a string", func(w http.ResponseWriter) { _, _ = w.Write([]byte(`{"id":"12345"}`)) }, nil, false},
		{"id as text", func(w http.ResponseWriter) { _, _ = w.Write([]byte(`{"id":"abc"}`)) }, nil, false},
		{"id null", func(w http.ResponseWriter) { _, _ = w.Write([]byte(`{"id":null}`)) }, nil, false},
		{"emails not JSON", nil, func(w http.ResponseWriter) { _, _ = w.Write([]byte("SECRET-BODY")) }, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			env, _ := githubEnv(t, annGitHub)
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch {
				case r.URL.Path == "/user" && c.user != nil:
					c.user(w)
				case r.URL.Path == "/user/emails" && c.mails != nil:
					c.mails(w)
				case r.URL.Path == "/user":
					_, _ = w.Write([]byte(`{"id":12345,"name":"Ann"}`))
				default:
					_, _ = w.Write([]byte(`[{"email":"ann@example.com","primary":true,"verified":true}]`))
				}
			}))
			defer api.Close()
			p := newGitHub(t, env, func(o *provider.GitHubOptions) {
				o.UserURL, o.EmailsURL = api.URL+"/user", api.URL+"/user/emails"
			})
			_, err := githubExchange(t, p)
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

// Covers: FR-05 (part)
// Acceptance: Provider timeout (part)
func TestGitHubAPITimeoutIsUnavailable(t *testing.T) {
	env, _ := githubEnv(t, annGitHub)
	env.Timeout = 50 * time.Millisecond // this case waits for the timeout
	release := make(chan struct{})
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer api.Close()
	defer close(release)
	p := newGitHub(t, env, func(o *provider.GitHubOptions) { o.UserURL = api.URL + "/user" })
	if _, err := githubExchange(t, p); !errors.Is(err, provider.ErrUnavailable) {
		t.Errorf("error = %v, want ErrUnavailable", err)
	}
}

// Covers: FR-14 (part)
func TestGitHubDefaultsAndBadOptions(t *testing.T) {
	good := provider.GitHubOptions{ClientID: "id", ClientSecret: "s", RedirectURI: "https://x.example/cb", Timeout: time.Second}
	p, err := provider.NewGitHub(good)
	if err != nil {
		t.Fatal(err)
	}
	if got := p.AuthURL("s", "", "", provider.AuthOptions{}); !strings.HasPrefix(got, "https://github.com/login/oauth/authorize?") {
		t.Errorf("AuthURL = %q", got)
	}
	if p.Name() != "github" {
		t.Errorf("Name = %q", p.Name())
	}
	for name, mod := range map[string]func(*provider.GitHubOptions){
		"no client id":     func(o *provider.GitHubOptions) { o.ClientID = "" },
		"no timeout":       func(o *provider.GitHubOptions) { o.Timeout = 0 },
		"negative timeout": func(o *provider.GitHubOptions) { o.Timeout = -time.Second },
		"no redirect":      func(o *provider.GitHubOptions) { o.RedirectURI = "" },
	} {
		o := good
		mod(&o)
		if _, err := provider.NewGitHub(o); err == nil {
			t.Errorf("%s: NewGitHub accepted the options", name)
		}
	}
}

// Covers: SEC-13 (part)
func TestGitHubLogsNoSecret(t *testing.T) {
	const secret = "FAKE-GITHUB-SECRET-77c1"
	p, err := provider.NewGitHub(provider.GitHubOptions{ClientID: "id", ClientSecret: secret, RedirectURI: "https://x.example/cb", Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	for name, v := range map[string]any{"pointer": p, "value": *p} {
		var buf bytes.Buffer
		log := logx.New(&buf, slog.LevelDebug, clock.NewFake(time.Unix(0, 0)))
		log.Info("direct", "adapter", v)
		log.Info("nested", "details", map[string]any{"adapter": v})
		if strings.Contains(buf.String(), secret) || !strings.Contains(buf.String(), "github") {
			t.Errorf("%s: log = %s", name, buf.String())
		}
	}
}

// Covers: FR-14 (part), SEC-03 (part)
// Acceptance: Provider user info (part)
func TestGitHubUserURLReplacesOnlyTheUserCall(t *testing.T) {
	env, srv := githubEnv(t, annGitHub)
	var calls int
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("User-Agent") == "" || r.Header.Get("Authorization") == "" {
			w.WriteHeader(400)
			return
		}
		_, _ = w.Write([]byte(`{"id":4242,"name":"Custom User"}`))
	}))
	defer api.Close()
	p := newGitHub(t, env, func(o *provider.GitHubOptions) { o.UserURL = api.URL + "/custom/user" })
	id, err := githubExchange(t, p)
	if err != nil || id.Subject != "4242" || id.Name != "Custom User" || id.Email != "ann@example.com" {
		t.Fatalf("identity %+v, error %v", id, err)
	}
	if calls != 1 {
		t.Errorf("the override was called %d times, want 1", calls)
	}
	var user, emails int
	for _, r := range srv.Requests() {
		switch r.Path {
		case "/user":
			user++
		case "/user/emails":
			emails++
		}
	}
	if user != 0 || emails != 1 {
		t.Errorf("default /user called %d times, /user/emails %d times; want 0 and 1", user, emails)
	}
}

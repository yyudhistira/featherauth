package provider_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/logx"
	"github.com/yyudhistira/featherauth/internal/provider"
	"github.com/yyudhistira/featherauth/internal/provider/providertest"
	"github.com/yyudhistira/featherauth/internal/testutil/mockidp"
)

var _ provider.Provider = (*provider.Facebook)(nil)

func newFacebook(t *testing.T, env providertest.Env, mod func(*provider.FacebookOptions)) *provider.Facebook {
	t.Helper()
	u := env.Server.URL()
	o := provider.FacebookOptions{
		ClientID: env.Server.ClientID(), ClientSecret: env.Server.ClientSecret(), RedirectURI: env.RedirectURI,
		GraphVersion: "v26.0", Scopes: []string{"public_profile", "email"}, Fields: []string{"id", "name", "email"},
		AuthorizeURL: u + "/dialog/oauth", TokenURL: u + "/oauth/access_token", GraphURL: u,
		Timeout: env.Timeout, Clock: env.Clock,
	}
	if mod != nil {
		mod(&o)
	}
	p, err := provider.NewFacebook(o)
	if err != nil {
		t.Fatalf("NewFacebook: %v", err)
	}
	return p
}

func facebookEnv(t *testing.T, u mockidp.User) (providertest.Env, *mockidp.Server) {
	t.Helper()
	clk := clock.NewFake(time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC))
	srv := mockidp.New(t, clk, mockidp.Facebook)
	srv.SetUser(u)
	return providertest.Env{Server: srv, Clock: clk, RedirectURI: "https://featherauth.example/realm/callback/facebook", Timeout: 5 * time.Second}, srv
}

var annFacebook = mockidp.User{Sub: "10001", Name: "Ann Example", Email: "ann@example.com"}

func facebookExchange(t *testing.T, p provider.Provider) (provider.Identity, error) {
	t.Helper()
	q := providertest.Authorize(t, p.AuthURL("s", "", "", provider.AuthOptions{}))
	if q.Get("code") == "" {
		t.Fatalf("no code: %v", q)
	}
	return p.Exchange(context.Background(), provider.Callback{Code: q.Get("code")}, "", "")
}

// Covers: FR-14 (part), SEC-03 (part)
// Acceptance: Provider adapters (part)
// Acceptance: Login hints (part)
func TestFacebookKeepsTheProviderContract(t *testing.T) {
	zero := 0
	providertest.Run(t, providertest.Case{
		Profile: mockidp.Facebook, OIDC: false, PKCE: false,
		New:  func(t *testing.T, env providertest.Env) provider.Provider { return newFacebook(t, env, nil) },
		User: annFacebook,
		// Facebook gives no verified flag, so the email is never verified.
		Want: provider.Identity{Subject: "10001", Email: "ann@example.com", Name: "Ann Example"},
		Hints: []providertest.Hint{
			{Name: "none", Absent: []string{"auth_type", "prompt", "max_age", "login_hint"}},
			{Name: "prompt=login", Opts: provider.AuthOptions{Prompt: "login"},
				Want: url.Values{"auth_type": {"reauthenticate"}}, Absent: []string{"prompt"}},
			{Name: "max_age", Opts: provider.AuthOptions{MaxAge: &zero},
				Want: url.Values{"auth_type": {"reauthenticate"}}, Absent: []string{"max_age"}},
			{Name: "prompt=select_account", Opts: provider.AuthOptions{Prompt: "select_account"}, Absent: []string{"auth_type", "prompt"}},
			{Name: "prompt=consent", Opts: provider.AuthOptions{Prompt: "consent"}, Absent: []string{"auth_type", "prompt"}},
			{Name: "login_hint", Opts: provider.AuthOptions{LoginHint: "ann@example.com"}, Absent: []string{"auth_type", "login_hint"}},
		},
	})
}

// Covers: SEC-03 (part)
// Acceptance: Provider adapters (part)
func TestFacebookGraphCallsCarryTheAppSecretProof(t *testing.T) {
	env, srv := facebookEnv(t, annFacebook)
	p := newFacebook(t, env, nil)
	if _, err := facebookExchange(t, p); err != nil {
		t.Fatal(err)
	}
	var graph int
	for _, r := range srv.Requests() {
		switch r.Path {
		case "/oauth/access_token":
			if r.Method != http.MethodGet || r.Query.Get("code") == "" || r.Query.Get("redirect_uri") != env.RedirectURI {
				t.Errorf("token call = %s %v, want a GET with the code and redirect_uri", r.Method, r.Query)
			}
		case "/me":
			graph++
			tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			mac := hmac.New(sha256.New, []byte(srv.ClientSecret()))
			mac.Write([]byte(tok))
			if tok == "" || r.Query.Get("appsecret_proof") != hex.EncodeToString(mac.Sum(nil)) {
				t.Errorf("/me appsecret_proof = %q, want the HMAC-SHA256 of the access token", r.Query.Get("appsecret_proof"))
			}
			if r.Query.Has("access_token") {
				t.Error("the access token is in the URL")
			}
			if r.Query.Get("fields") != "id,name,email" {
				t.Errorf("fields = %q", r.Query.Get("fields"))
			}
		}
	}
	if graph != 1 {
		t.Errorf("%d Graph calls, want 1", graph)
	}
}

// Covers: SEC-03 (part)
// Acceptance: Provider adapters (part)
func TestFacebookFieldsAlwaysIncludeID(t *testing.T) {
	for _, c := range []struct {
		fields []string
		want   string
	}{{[]string{"email"}, "id,email"}, {[]string{"name", "id"}, "name,id"}, {nil, "id,name,email"}} {
		env, srv := facebookEnv(t, annFacebook)
		p := newFacebook(t, env, func(o *provider.FacebookOptions) { o.Fields = c.fields })
		if _, err := facebookExchange(t, p); err != nil {
			t.Fatal(err)
		}
		for _, r := range srv.Requests() {
			if r.Path == "/me" && r.Query.Get("fields") != c.want {
				t.Errorf("fields %v sent as %q, want %q", c.fields, r.Query.Get("fields"), c.want)
			}
		}
	}
}

// Covers: SEC-03 (part)
// Acceptance: Provider adapters (part)
func TestFacebookRequireEmail(t *testing.T) {
	noEmail := mockidp.User{Sub: "10001", Name: "Ann Example"}
	for _, c := range []struct {
		name    string
		user    mockidp.User
		require bool
		refused bool
	}{
		{"email, required", annFacebook, true, false},
		{"no email, required", noEmail, true, true},
		{"no email, not required", noEmail, false, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			env, _ := facebookEnv(t, c.user)
			p := newFacebook(t, env, func(o *provider.FacebookOptions) { o.RequireEmail = c.require })
			id, err := facebookExchange(t, p)
			if c.refused {
				if !errors.Is(err, provider.ErrRefused) {
					t.Errorf("error = %v, want ErrRefused", err)
				}
				return
			}
			if err != nil || id.Subject != "10001" || id.EmailVerified {
				t.Errorf("identity %+v, error %v", id, err)
			}
		})
	}
}

// Covers: FR-05 (part)
// Acceptance: Provider timeout (part)
func TestFacebookGraphFailures(t *testing.T) {
	for _, c := range []struct {
		name        string
		handle      func(w http.ResponseWriter)
		unavailable bool
	}{
		{"5xx", func(w http.ResponseWriter) { w.WriteHeader(503) }, true},
		{"OAuthException", func(w http.ResponseWriter) {
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"error":{"message":"SECRET-BODY","type":"OAuthException","code":190}}`))
		}, false},
		{"not JSON", func(w http.ResponseWriter) { _, _ = w.Write([]byte("SECRET-BODY")) }, false},
		{"no id", func(w http.ResponseWriter) { _, _ = w.Write([]byte(`{"name":"Ann"}`)) }, false},
		{"id not a string", func(w http.ResponseWriter) { _, _ = w.Write([]byte(`{"id":{"a":1}}`)) }, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			env, _ := facebookEnv(t, annFacebook)
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				c.handle(w)
			}))
			defer api.Close()
			p := newFacebook(t, env, func(o *provider.FacebookOptions) { o.GraphURL = api.URL })
			_, err := facebookExchange(t, p)
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

	t.Run("timeout", func(t *testing.T) {
		env, _ := facebookEnv(t, annFacebook)
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
		p := newFacebook(t, env, func(o *provider.FacebookOptions) { o.GraphURL = api.URL })
		if _, err := facebookExchange(t, p); !errors.Is(err, provider.ErrUnavailable) {
			t.Errorf("error = %v, want ErrUnavailable", err)
		}
	})
}

// Covers: FR-14 (part)
func TestFacebookDefaultsAndBadOptions(t *testing.T) {
	good := provider.FacebookOptions{
		ClientID: "id", ClientSecret: "s", RedirectURI: "https://x.example/cb", GraphVersion: "v26.0", Timeout: time.Second,
		Scopes: []string{"public_profile", "email"}, Clock: clock.NewFake(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)),
	}
	p, err := provider.NewFacebook(good)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(p.AuthURL("st", "nonce-ignored", "chal-ignored", provider.AuthOptions{}))
	q := u.Query()
	if u.Scheme+"://"+u.Host+u.Path != "https://www.facebook.com/v26.0/dialog/oauth" ||
		q.Get("scope") != "public_profile,email" || q.Get("state") != "st" || q.Get("client_id") != "id" ||
		q.Has("nonce") || q.Has("code_challenge") {
		t.Errorf("AuthURL = %s", u)
	}
	if p.Name() != "facebook" {
		t.Errorf("Name = %q", p.Name())
	}
	for name, mod := range map[string]func(*provider.FacebookOptions){
		"no client id":     func(o *provider.FacebookOptions) { o.ClientID = "" },
		"no client secret": func(o *provider.FacebookOptions) { o.ClientSecret = "" },
		"no redirect":      func(o *provider.FacebookOptions) { o.RedirectURI = "" },
		"no version":       func(o *provider.FacebookOptions) { o.GraphVersion = "" },
		"no timeout":       func(o *provider.FacebookOptions) { o.Timeout = 0 },
		"no clock":         func(o *provider.FacebookOptions) { o.Clock = nil },
		"negative timeout": func(o *provider.FacebookOptions) { o.Timeout = -time.Second },
	} {
		o := good
		mod(&o)
		if _, err := provider.NewFacebook(o); err == nil {
			t.Errorf("%s: NewFacebook accepted the options", name)
		}
	}
}

// Covers: SEC-04 (part)
// Acceptance: No unsafe link (part)
func TestFacebookTrustEmailDefaultsToFalse(t *testing.T) {
	// The adapter never reports a verified email; the config default is false too.
	r, ds := config.DecodeRealm("r.yaml", []byte("name: r\nproviders:\n  facebook: {}\n"))
	if r == nil {
		t.Fatalf("decode: %v", ds)
	}
	if r.Providers["facebook"].TrustEmail {
		t.Error("trust_email is true by default for facebook")
	}
}

// Covers: SEC-13 (part)
func TestFacebookLogsNoSecret(t *testing.T) {
	const secret = "FAKE-FACEBOOK-SECRET-31d8"
	p, err := provider.NewFacebook(provider.FacebookOptions{
		ClientID: "id", ClientSecret: secret, RedirectURI: "https://x.example/cb", GraphVersion: "v26.0", Timeout: time.Second,
		Clock: clock.NewFake(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)),
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, v := range map[string]any{"pointer": p, "value": *p} {
		var buf bytes.Buffer
		log := logx.New(&buf, slog.LevelDebug, clock.NewFake(time.Unix(0, 0)))
		log.Info("direct", "adapter", v)
		log.Info("nested", "details", map[string]any{"adapter": v})
		if strings.Contains(buf.String(), secret) || !strings.Contains(buf.String(), "facebook") {
			t.Errorf("%s: log = %s", name, buf.String())
		}
	}
}

// Covers: FR-14 (part), SEC-03 (part)
// Acceptance: Provider user info (part)
func TestFacebookMeURLReplacesTheIdentityCall(t *testing.T) {
	env, srv := facebookEnv(t, annFacebook)
	var paths []string
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path+"?"+r.URL.Query().Get("fields"))
		if r.URL.Query().Get("appsecret_proof") == "" {
			w.WriteHeader(400)
			return
		}
		_, _ = w.Write([]byte(`{"id":"777","name":"Custom Me","email":"me@example.com"}`))
	}))
	defer api.Close()
	p := newFacebook(t, env, func(o *provider.FacebookOptions) { o.MeURL = api.URL + "/custom/me" })
	id, err := facebookExchange(t, p)
	if err != nil || id.Subject != "777" || id.Email != "me@example.com" {
		t.Fatalf("identity %+v, error %v", id, err)
	}
	if len(paths) != 1 || paths[0] != "/custom/me?id,name,email" {
		t.Errorf("identity calls = %v", paths)
	}
	for _, r := range srv.Requests() {
		if r.Path == "/me" {
			t.Error("the default /me URL was called")
		}
	}
}

// Covers: FR-14 (part)
// Acceptance: Provider user info (part)
func TestFacebookMeURLWithAQueryKeepsItAndAddsTheRest(t *testing.T) {
	for _, c := range []struct{ name, suffix string }{{"no query", "/me"}, {"with a query", "/me?locale=en"}} {
		t.Run(c.name, func(t *testing.T) {
			env, _ := facebookEnv(t, annFacebook)
			var q url.Values
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				q = r.URL.Query()
				_, _ = w.Write([]byte(`{"id":"1"}`))
			}))
			defer api.Close()
			p := newFacebook(t, env, func(o *provider.FacebookOptions) { o.MeURL = api.URL + c.suffix })
			if _, err := facebookExchange(t, p); err != nil {
				t.Fatal(err)
			}
			if q.Get("fields") == "" || q.Get("appsecret_proof") == "" {
				t.Errorf("query = %v, want fields and appsecret_proof", q)
			}
			if strings.Contains(c.suffix, "?") && q.Get("locale") != "en" {
				t.Errorf("the override's own query was lost: %v", q)
			}
		})
	}
}

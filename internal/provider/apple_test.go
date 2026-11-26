package provider_test

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/provider"
	"github.com/yyudhistira/featherauth/internal/provider/providertest"
	"github.com/yyudhistira/featherauth/internal/testutil"
	"github.com/yyudhistira/featherauth/internal/testutil/mockidp"
)

var (
	_ provider.Provider = (*provider.Apple)(nil)
	_ provider.Revoker  = (*provider.Apple)(nil)
)

// appleFixture builds the adapter against the mock. The mock accepts a client
// secret only when it is a valid JWT signed by the test key with the claims
// of Apple's client secret; checks counts the secrets it saw.
type appleFixture struct {
	checks atomic.Int64
}

func newApple(t testing.TB, env providertest.Env, mod func(*provider.AppleOptions)) (*provider.Apple, *appleFixture) {
	t.Helper()
	key, pemKey := testutil.ECKey(t)
	f := &appleFixture{}
	clientID := env.Server.ClientID() // not inside the check: the mock holds its lock there
	env.Server.SetSecretCheck(func(secret string) error {
		f.checks.Add(1)
		return checkAppleSecret(secret, &key.PublicKey, clientID, env.Clock.Now())
	})
	u := env.Server.URL()
	opts := provider.AppleOptions{
		OIDCOptions: provider.OIDCOptions{
			ClientID: env.Server.ClientID(), RedirectURI: env.RedirectURI, Scopes: []string{"name", "email"},
			Endpoints:  provider.OIDCEndpoints{Authorize: u + "/authorize", Token: u + "/token", JWKS: u + "/jwks"},
			Algorithms: []string{"ES256"}, // the mock signs with ES256
			Timeout:    env.Timeout, Clock: env.Clock,
		},
		TeamID: "TEAM123456", KeyID: "KEY1234567", PrivateKeyPEM: pemKey, Lifetime: 5 * time.Minute,
		StoreRefreshToken: true, RevokeURL: u + "/revoke",
	}
	if mod != nil {
		mod(&opts)
	}
	p, err := provider.NewApple(context.Background(), opts)
	if err != nil {
		t.Fatalf("NewApple: %v", err)
	}
	return p, f
}

func checkAppleSecret(secret string, pub *ecdsa.PublicKey, servicesID string, now time.Time) error {
	payload, err := jws.Verify([]byte(secret), jws.WithKey(jwa.ES256(), pub))
	if err != nil {
		return err
	}
	var c map[string]any
	if err := json.Unmarshal(payload, &c); err != nil {
		return err
	}
	if c["iss"] != "TEAM123456" || c["sub"] != servicesID || c["aud"] != "https://appleid.apple.com" ||
		c["iat"] != float64(now.Unix()) || c["exp"] != float64(now.Add(5*time.Minute).Unix()) {
		return errors.New("the client secret claims are wrong")
	}
	msg, err := jws.Parse([]byte(secret))
	if err != nil {
		return err
	}
	if kid, _ := msg.Signatures()[0].ProtectedHeaders().KeyID(); kid != "KEY1234567" {
		return errors.New("the client secret kid is wrong")
	}
	return nil
}

func appleEnv(t testing.TB) (providertest.Env, *mockidp.Server) {
	t.Helper()
	clk := clock.NewFake(time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC))
	srv := mockidp.New(t, clk, mockidp.Apple)
	return providertest.Env{Server: srv, Clock: clk, RedirectURI: "https://featherauth.example/realm/callback/apple", Timeout: 5 * time.Second}, srv
}

// Covers: FR-14 (part), SEC-03 (part)
// Acceptance: Provider adapters (part)
// Acceptance: Login hints (part)
func TestAppleKeepsTheProviderContract(t *testing.T) {
	zero := 0
	providertest.Run(t, providertest.Case{
		Profile: mockidp.Apple, OIDC: true, PKCE: false, RefreshToken: true,
		CancelCode: "user_cancelled_authorize",
		New: func(t *testing.T, env providertest.Env) provider.Provider {
			p, _ := newApple(t, env, nil)
			return p
		},
		Hints: []providertest.Hint{
			{Name: "form_post and scope", Want: url.Values{"response_mode": {"form_post"}, "scope": {"name email"}}},
			// Apple's web sign-in always asks the user to confirm: nothing is passed.
			{Name: "nothing is passed on", Opts: provider.AuthOptions{Prompt: "login", MaxAge: &zero, LoginHint: "ann@example.com"},
				Absent: []string{"prompt", "max_age", "login_hint"}},
			{Name: "select_account", Opts: provider.AuthOptions{Prompt: "select_account"}, Absent: []string{"prompt"}},
			{Name: "consent", Opts: provider.AuthOptions{Prompt: "consent"}, Absent: []string{"prompt"}},
		},
	})
}

func appleLogin(t *testing.T, p provider.Provider) provider.Callback {
	t.Helper()
	q := providertest.Authorize(t, p.AuthURL("s", "n", "", provider.AuthOptions{}))
	if q.Get("code") == "" {
		t.Fatalf("no code: %v", q)
	}
	return provider.Callback{Code: q.Get("code"), IDToken: q.Get("id_token"), User: q.Get("user")}
}

// Covers: SEC-03 (part)
// Acceptance: Provider adapters (part)
func TestAppleEmailVerifiedForms(t *testing.T) {
	for _, c := range []struct {
		name string
		v    any
		want bool
	}{{"bool true", true, true}, {"string true", "true", true}, {"string false", "false", false}, {"bool false", false, false}, {"missing", nil, false}} {
		t.Run(c.name, func(t *testing.T) {
			env, srv := appleEnv(t)
			srv.SetUser(mockidp.User{Sub: "a1", Email: "ann@privaterelay.appleid.com", EmailVerified: c.v, IsPrivateEmail: "true"})
			p, _ := newApple(t, env, nil)
			id, err := p.Exchange(context.Background(), appleLogin(t, p), "", "n")
			if err != nil {
				t.Fatal(err)
			}
			if id.EmailVerified != c.want || id.Email != "ann@privaterelay.appleid.com" {
				t.Errorf("identity = %+v", id)
			}
		})
	}
}

// Covers: SEC-03 (part)
// Acceptance: Apple callback (part)
// Acceptance: Apple name (part)
func TestAppleNameOnlyFromTheUserJSON(t *testing.T) {
	env, srv := appleEnv(t)
	srv.SetUser(mockidp.User{Sub: "a1", Email: "ann@example.com", EmailVerified: true, Name: "Ann Real"})
	p, _ := newApple(t, env, nil)
	cb := appleLogin(t, p)

	// The user JSON gives the name; its email is unsigned and ignored.
	withUser := cb
	withUser.User = `{"name":{"firstName":"Zed","lastName":"Quinn"},"email":"evil@example.com"}`
	id, err := p.Exchange(context.Background(), withUser, "", "n")
	if err != nil {
		t.Fatal(err)
	}
	if id.Name != "Zed Quinn" || id.Email != "ann@example.com" {
		t.Errorf("identity = %+v, want the name from user and the email from the ID token", id)
	}

	// Without the user JSON there is no name, although the ID token has a name claim.
	cb2 := appleLogin(t, p)
	cb2.User = ""
	id, err = p.Exchange(context.Background(), cb2, "", "n")
	if err != nil {
		t.Fatal(err)
	}
	if id.Name != "" {
		t.Errorf("name = %q, want none", id.Name)
	}

	// An unreadable user JSON is ignored, not an error.
	cb3 := appleLogin(t, p)
	cb3.User = "{not json"
	if id, err = p.Exchange(context.Background(), cb3, "", "n"); err != nil || id.Name != "" {
		t.Errorf("identity %+v, error %v", id, err)
	}
}

// Covers: SEC-03 (part)
// Acceptance: Apple callback (part)
func TestApplePostedIDTokenMustHaveTheSameSub(t *testing.T) {
	env, srv := appleEnv(t)
	srv.SetUser(mockidp.User{Sub: "a1", Email: "ann@example.com", EmailVerified: true})
	p, _ := newApple(t, env, nil)

	cb := appleLogin(t, p)
	srv.SetUser(mockidp.User{Sub: "someone-else", Email: "ann@example.com", EmailVerified: true})
	cb.IDToken = srv.IDToken("n") // valid, signed, but for another subject
	if _, err := p.Exchange(context.Background(), cb, "", "n"); !errors.Is(err, provider.ErrRefused) {
		t.Errorf("a different posted sub: error = %v, want ErrRefused", err)
	}

	srv.SetUser(mockidp.User{Sub: "a1", Email: "ann@example.com", EmailVerified: true})
	cb = appleLogin(t, p)
	cb.IDToken = "not.a.jwt"
	if _, err := p.Exchange(context.Background(), cb, "", "n"); err == nil {
		t.Error("an invalid posted ID token was accepted")
	}

	// Without a posted id_token only the token endpoint's is used.
	cb = appleLogin(t, p)
	cb.IDToken = ""
	if _, err := p.Exchange(context.Background(), cb, "", "n"); err != nil {
		t.Errorf("no posted ID token: %v", err)
	}
}

// Covers: SEC-03 (part)
// Acceptance: Provider adapters (part)
func TestAppleGeneratesTheClientSecretPerRequest(t *testing.T) {
	env, srv := appleEnv(t)
	srv.SetUser(mockidp.User{Sub: "a1", Email: "ann@example.com", EmailVerified: true})
	p, f := newApple(t, env, nil)
	if _, err := p.Exchange(context.Background(), appleLogin(t, p), "", "n"); err != nil {
		t.Fatal(err)
	}
	env.Clock.(*clock.Fake).Advance(time.Hour)
	srv.SetUser(mockidp.User{Sub: "a1", Email: "ann@example.com", EmailVerified: true})
	// the ID token's exp is an hour after the first login: log in again later
	if _, err := p.Exchange(context.Background(), appleLogin(t, p), "", "n"); err != nil {
		t.Fatal(err)
	}
	if n := f.checks.Load(); n != 2 {
		t.Errorf("the mock checked %d client secrets, want 2 (one per exchange, each valid at its own time)", n)
	}
	for _, r := range srv.Requests() {
		if r.Path == "/token" && (r.Form.Get("client_secret") == "" || r.Header.Get("Authorization") != "") {
			t.Errorf("the client secret is not sent in the form: %v", r.Header)
		}
	}
}

// Covers: SEC-03 (part)
func TestAppleRefreshTokenOnlyWhenStored(t *testing.T) {
	for _, store := range []bool{true, false} {
		env, srv := appleEnv(t)
		srv.SetUser(mockidp.User{Sub: "a1", Email: "ann@example.com", EmailVerified: true})
		p, _ := newApple(t, env, func(o *provider.AppleOptions) { o.StoreRefreshToken = store })
		id, err := p.Exchange(context.Background(), appleLogin(t, p), "", "n")
		if err != nil {
			t.Fatal(err)
		}
		if (id.RefreshToken != "") != store {
			t.Errorf("store_refresh_token=%v: refresh token %q", store, id.RefreshToken)
		}
	}
}

// Covers: FR-05 (part)
// Acceptance: Provider error or cancel (part)
func TestAppleCancelCodes(t *testing.T) {
	env, _ := appleEnv(t)
	p, _ := newApple(t, env, nil)
	for code, cancelled := range map[string]bool{"user_cancelled_authorize": true, "access_denied": true, "invalid_request": false} {
		_, err := p.Exchange(context.Background(), provider.Callback{Error: code}, "", "n")
		if errors.Is(err, provider.ErrCancelled) != cancelled || err == nil {
			t.Errorf("error %q gave %v, cancelled want %v", code, err, cancelled)
		}
	}
}

// Covers: FR-13 (part)
// Acceptance: Provider adapters (part)
func TestAppleRevoke(t *testing.T) {
	env, srv := appleEnv(t)
	p, f := newApple(t, env, nil)
	if err := p.Revoke(context.Background(), "refresh-abc"); err != nil {
		t.Fatal(err)
	}
	revs := srv.Revocations()
	if len(revs) != 1 || revs[0].Token != "refresh-abc" || revs[0].Hint != "refresh_token" || strings.Count(revs[0].Secret, ".") != 2 {
		t.Fatalf("revocations = %+v", revs)
	}
	if f.checks.Load() != 1 {
		t.Errorf("the client secret was not checked: %d", f.checks.Load())
	}

	// The timeout is part of the provider's client, so a short one is a second provider.
	short := env
	short.Timeout = 50 * time.Millisecond
	ps, _ := newApple(t, short, nil)
	srv.Block()
	if err := ps.Revoke(context.Background(), "refresh-def"); !errors.Is(err, provider.ErrUnavailable) {
		t.Errorf("a timeout gave %v, want ErrUnavailable", err)
	}
	srv.Unblock()

	// a refused secret is an error that is not ErrUnavailable
	srv.SetSecretCheck(func(string) error { return errors.New("no") })
	if err := p.Revoke(context.Background(), "refresh-ghi"); err == nil || errors.Is(err, provider.ErrUnavailable) {
		t.Errorf("a refused revoke gave %v", err)
	}
}

// Covers: FR-14 (part)
func TestAppleDefaultsNeedNoNetwork(t *testing.T) {
	_, pemKey := testutil.ECKey(t)
	p, err := provider.NewApple(context.Background(), provider.AppleOptions{
		OIDCOptions: provider.OIDCOptions{
			ClientID: "com.example.web", RedirectURI: "https://x.example/cb", Scopes: []string{"name", "email"},
			Timeout: time.Second, Clock: clock.NewFake(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)),
		},
		TeamID: "T", KeyID: "K", PrivateKeyPEM: pemKey, Lifetime: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := p.AuthURL("s", "n", "", provider.AuthOptions{}); !strings.HasPrefix(got, "https://appleid.apple.com/auth/authorize?") {
		t.Errorf("AuthURL = %q", got)
	}
	if p.Name() != "apple" {
		t.Errorf("Name = %q", p.Name())
	}
}

// Covers: FR-14 (part)
func TestAppleRejectsBadOptions(t *testing.T) {
	_, pemKey := testutil.ECKey(t)
	base := provider.AppleOptions{
		OIDCOptions: provider.OIDCOptions{
			ClientID: "com.example.web", RedirectURI: "https://x.example/cb", Timeout: time.Second,
			Clock: clock.NewFake(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)),
		},
		TeamID: "T", KeyID: "K", PrivateKeyPEM: pemKey, Lifetime: time.Minute,
	}
	for name, mod := range map[string]func(*provider.AppleOptions){
		"no key":      func(o *provider.AppleOptions) { o.PrivateKeyPEM = nil },
		"no lifetime": func(o *provider.AppleOptions) { o.Lifetime = 0 },
		"no timeout":  func(o *provider.AppleOptions) { o.Timeout = 0 },
		"no client":   func(o *provider.AppleOptions) { o.ClientID = "" },
	} {
		o := base
		mod(&o)
		if _, err := provider.NewApple(context.Background(), o); err == nil {
			t.Errorf("%s: NewApple accepted the options", name)
		}
	}
}

// Covers: SEC-03 (part)
func TestAppleAcceptsOnlyRS256ByDefault(t *testing.T) {
	env, srv := appleEnv(t)
	srv.SetUser(mockidp.User{Sub: "a1", Email: "ann@example.com", EmailVerified: true})
	// the mock signs with ES256, which Apple does not use: refused by default
	p, _ := newApple(t, env, func(o *provider.AppleOptions) { o.Algorithms = nil })
	if _, err := p.Exchange(context.Background(), appleLogin(t, p), "", "n"); err == nil {
		t.Error("an ES256 ID token was accepted by the default Apple algorithms")
	}
}

// Covers: FR-14 (part)
// Acceptance: Provider user info (part)
func TestAppleIgnoresTheUserinfoEndpoint(t *testing.T) {
	env, srv := appleEnv(t)
	srv.SetUser(mockidp.User{Sub: "a1", Email: "ann@example.com", EmailVerified: true})
	p, _ := newApple(t, env, func(o *provider.AppleOptions) { o.Endpoints.Userinfo = srv.URL() + "/userinfo" })
	if _, err := p.Exchange(context.Background(), appleLogin(t, p), "", "n"); err != nil {
		t.Fatal(err)
	}
	for _, r := range srv.Requests() {
		if r.Path == "/userinfo" {
			t.Error("Apple called a user-info endpoint")
		}
	}
}

// The authorize URL carries Apple's scopes joined by one space in the
// configured order, and no scope parameter when there are none; the response
// mode is form_post in every case (FR-56).
//
// Covers: FR-56 (part)
// Acceptance: Apple scopes in the authorize URL
func TestAppleScopesInTheAuthorizeURL(t *testing.T) {
	for _, c := range []struct {
		name       string
		scopes     []string
		want       string
		wantAbsent bool
	}{
		{"default pair", []string{"name", "email"}, "name email", false},
		{"email alone", []string{"email"}, "email", false},
		{"reversed", []string{"email", "name"}, "email name", false},
		{"nil", nil, "", true},
		{"empty", []string{}, "", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			env, _ := appleEnv(t)
			p, _ := newApple(t, env, func(o *provider.AppleOptions) { o.Scopes = c.scopes })
			u, err := url.Parse(p.AuthURL("s", "n", "", provider.AuthOptions{}))
			if err != nil {
				t.Fatal(err)
			}
			q := u.Query()
			if _, has := q["scope"]; has == c.wantAbsent || q.Get("scope") != c.want {
				t.Errorf("scope = %q (present %v), want %q (absent %v)", q.Get("scope"), has, c.want, c.wantAbsent)
			}
			if q.Get("response_mode") != "form_post" {
				t.Errorf("response_mode = %q, want form_post", q.Get("response_mode"))
			}
		})
	}
}

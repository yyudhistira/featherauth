// Package providertest is the contract every provider adapter must pass. Each
// adapter's tests call Run with a Case that says which kind of provider it is.
// It is test support and only tests may import it.
package providertest

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/provider"
	"github.com/yyudhistira/featherauth/internal/testutil/mockidp"
)

// Env is what the suite gives Case.New to build an adapter against the mock.
type Env struct {
	Server      *mockidp.Server
	Clock       clock.Clock
	RedirectURI string        // the callback URL the adapter must send as redirect_uri
	Timeout     time.Duration // the provider timeout the adapter is built with; the suite does not check that its client applies it (the adapters' timeout tests do: OIDC, which Google uses too, Apple, Facebook and GitHub)
	// UserInfo is true when the adapter must call the user-info endpoint, at
	// Server.URL() + "/userinfo" (see Case.UserInfo).
	UserInfo bool
}

// Hint is one row of the design's Login hints table: what the adapter puts on
// the authorize URL for the options.
type Hint struct {
	Name   string
	Opts   provider.AuthOptions
	Want   url.Values // parameters that must be on the URL with exactly these values
	Absent []string   // parameters that must not be on the URL
}

// Case describes the adapter under test.
type Case struct {
	Profile mockidp.Profile
	// OIDC is true for adapters that validate an ID token (nonce, aud, iss, exp).
	OIDC bool
	// PKCE is true when the adapter sends the challenge and the verifier.
	PKCE bool
	// New builds the adapter. It must use its own http.Client with env.Timeout
	// and never the default client.
	New func(t *testing.T, env Env) provider.Provider
	// User is the account the mock signs in and Want the identity the adapter
	// must return for it. Both are optional; a default account is used.
	User mockidp.User
	Want provider.Identity
	// RefreshToken is true when the adapter returns the provider's refresh
	// token (Apple); the suite then checks it is not empty.
	RefreshToken bool
	// CancelCode is the error code the provider sends when the user cancels;
	// empty means access_denied.
	CancelCode string
	// Hints are the login hint mappings the design gives for this provider.
	Hints []Hint
	// UserInfo is true when the adapter calls a user-info endpoint for a
	// login. Its New must then set the endpoint from env.UserInfo, and the
	// suite checks a 302 from it.
	UserInfo bool
}

const (
	verifier     = "the-pkce-verifier-0123456789-abcdefghijklmnopqrstuvwxyz"
	state        = "state-1"
	nonce        = "nonce-1"
	callbackPath = "https://featherauth.example/realm/callback/test"
	// generousTimeout is the provider timeout of every case: a loopback call under
	// -race and parallel load must not time out by chance.
	generousTimeout = 5 * time.Second
)

func challenge() string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// failingTransport fails the test for every request: it replaces
// http.DefaultTransport, so an adapter that falls back to http.DefaultClient
// (go-oidc and x/oauth2 do unless they get a client) is caught.
type failingTransport struct{ t testing.TB }

func (f failingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	f.t.Errorf("a request used http.DefaultTransport (the adapter's own client was not used): %s %s", r.Method, r.URL.Redacted())
	return nil, errors.New("providertest: http.DefaultTransport is not allowed")
}

// guardDefaultTransport swaps http.DefaultTransport for failingTransport until
// the test ends. It changes a global, so the test and its callers must not use
// t.Parallel.
func guardDefaultTransport(t testing.TB) {
	t.Helper()
	orig := http.DefaultTransport
	http.DefaultTransport = failingTransport{t}
	t.Cleanup(func() { http.DefaultTransport = orig })
}

func (c Case) user() mockidp.User {
	if c.User.Sub != "" {
		return c.User
	}
	return mockidp.User{Sub: "sub-1", Email: "ann@example.com", EmailVerified: true, Name: "Ann Example"}
}

func (c Case) want() provider.Identity {
	if c.Want.Subject != "" {
		return c.Want
	}
	return provider.Identity{Subject: "sub-1", Email: "ann@example.com", EmailVerified: true, Name: "Ann Example"}
}

// setup starts a mock server and builds the adapter.
func (c Case) setup(t *testing.T) (provider.Provider, *mockidp.Server, *clock.Fake) {
	t.Helper()
	return c.setupWith(t, false, generousTimeout)
}

// setupWith is setup with the user-info endpoint enabled or not, and the
// provider timeout given.
func (c Case) setupWith(t *testing.T, userInfo bool, timeout time.Duration) (provider.Provider, *mockidp.Server, *clock.Fake) {
	t.Helper()
	clk := clock.NewFake(time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC))
	srv := mockidp.New(t, clk, c.Profile)
	srv.SetUser(c.user())
	p := c.New(t, Env{Server: srv, Clock: clk, RedirectURI: callbackPath, Timeout: timeout, UserInfo: userInfo})
	if p == nil {
		t.Fatal("Case.New returned nil")
	}
	return p, srv, clk
}

// formField matches a hidden input of the form_post page the mock serves.
var formField = regexp.MustCompile(`<input type="hidden" name="([^"]*)" value="([^"]*)">`)

// Authorize follows the authorize URL at the mock without following the
// redirect, and returns what the provider sent to the callback: the query of
// the redirect, or the fields of a form_post page.
func Authorize(t *testing.T, authURL string) url.Values {
	t.Helper()
	client := &http.Client{
		Timeout:       5 * time.Second,
		Transport:     &http.Transport{},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	defer client.CloseIdleConnections()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, authURL, nil)
	if err != nil {
		t.Fatalf("authorize URL %q: %v", authURL, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK && strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") {
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if err != nil {
			t.Fatalf("authorize: %v", err)
		}
		out := url.Values{}
		for _, m := range formField.FindAllStringSubmatch(string(body), -1) {
			out.Set(html.UnescapeString(m[1]), html.UnescapeString(m[2]))
		}
		return out
	}
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize answered %d, want 302 or a form_post page (the authorize URL is wrong)", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("authorize redirect: %v", err)
	}
	return loc.Query()
}

// login runs the authorize step and returns the callback it produced.
func (c Case) login(t *testing.T, p provider.Provider) provider.Callback {
	t.Helper()
	q := Authorize(t, p.AuthURL(state, nonce, challenge(), provider.AuthOptions{}))
	if q.Get("state") != state {
		t.Fatalf("callback state = %q, want %q", q.Get("state"), state)
	}
	if q.Get("code") == "" {
		t.Fatalf("the authorize step gave no code: %v", q)
	}
	return provider.Callback{Code: q.Get("code"), IDToken: q.Get("id_token"), User: q.Get("user")}
}

func (c Case) verifier() string {
	if c.PKCE {
		return verifier
	}
	return ""
}

func isNone(err error) bool {
	return !errors.Is(err, provider.ErrCancelled) && !errors.Is(err, provider.ErrUnavailable) && !errors.Is(err, provider.ErrRefused)
}

// Run checks that the adapter of c keeps the provider contract.
//
// Every subtest runs with http.DefaultTransport replaced by one that fails the
// test, so a call that does not go through the adapter's own client is found.
// That swaps a global: a test that calls Run must not call t.Parallel, and no
// other test in the same binary may run in parallel with it.
func Run(t *testing.T, c Case) {
	t.Helper()
	guardDefaultTransport(t)
	sub := func(name string, fn func(t *testing.T)) {
		t.Run(name, func(t *testing.T) { t.Helper(); fn(t) })
	}

	sub("AuthURL", func(t *testing.T) {
		p, srv, _ := c.setup(t)
		if p.Name() == "" {
			t.Error("Name is empty")
		}
		u, err := url.Parse(p.AuthURL(state, nonce, challenge(), provider.AuthOptions{}))
		if err != nil {
			t.Fatal(err)
		}
		q := u.Query()
		if q.Get("state") != state {
			t.Errorf("state = %q, want %q", q.Get("state"), state)
		}
		if q.Get("redirect_uri") != callbackPath {
			t.Errorf("redirect_uri = %q, want the callback URL %q", q.Get("redirect_uri"), callbackPath)
		}
		if c.OIDC && q.Get("nonce") != nonce {
			t.Errorf("nonce = %q, want %q", q.Get("nonce"), nonce)
		}
		if c.PKCE {
			if q.Get("code_challenge") != challenge() {
				t.Errorf("code_challenge = %q, want %q", q.Get("code_challenge"), challenge())
			}
			if q.Get("code_challenge_method") != "S256" {
				t.Errorf("code_challenge_method = %q, want S256", q.Get("code_challenge_method"))
			}
		} else if q.Has("code_challenge") {
			t.Error("code_challenge is sent although the case says the adapter has no PKCE")
		}
		if got := u.Scheme + "://" + u.Host; got != srv.URL() {
			t.Errorf("the authorize URL points at %q, want the provider %q", got, srv.URL())
		}
	})

	sub("ExchangeReturnsIdentity", func(t *testing.T) {
		p, _, _ := c.setup(t)
		got, err := p.Exchange(context.Background(), c.login(t, p), c.verifier(), nonce)
		if err != nil {
			t.Fatalf("Exchange: %v", err)
		}
		w := c.want()
		if got.Subject != w.Subject || got.Email != w.Email || got.EmailVerified != w.EmailVerified ||
			got.Name != w.Name || !got.AuthTime.Equal(w.AuthTime) || (got.RefreshToken != "") != c.RefreshToken {
			t.Errorf("identity = %+v, want %+v", got, w)
		}
	})

	sub("Cancel", func(t *testing.T) {
		p, srv, _ := c.setup(t)
		code := c.CancelCode
		if code == "" {
			code = "access_denied"
		}
		srv.SetAuthorizeError(code)
		q := Authorize(t, p.AuthURL(state, nonce, challenge(), provider.AuthOptions{}))
		if q.Get("error") != code {
			t.Fatalf("the provider did not answer %s: %v", code, q)
		}
		_, err := p.Exchange(context.Background(), provider.Callback{Error: q.Get("error")}, c.verifier(), nonce)
		if !errors.Is(err, provider.ErrCancelled) {
			t.Errorf("Exchange error = %v, want ErrCancelled", err)
		}
		if n := srv.TokenCalls(); n != 0 {
			t.Errorf("the token endpoint was called %d times for a cancel", n)
		}
	})

	sub("OtherProviderError", func(t *testing.T) {
		p, srv, _ := c.setup(t)
		_, err := p.Exchange(context.Background(), provider.Callback{Error: "server_error"}, c.verifier(), nonce)
		if err == nil || !isNone(err) {
			t.Errorf("Exchange error = %v, want an error that is none of the sentinels (a server_error)", err)
		}
		if code, _ := provider.MapError(err); err != nil && code != "server_error" {
			t.Errorf("MapError code = %q, want server_error", code)
		}
		if n := srv.TokenCalls(); n != 0 {
			t.Errorf("the token endpoint was called %d times for a provider error", n)
		}
	})

	// The timeout is applied when the token call has arrived at the blocked mock,
	// by cancelling the exchange's context: no real timer runs against the request
	// path, so the case cannot time out before its call reaches the provider. A
	// cancelled or expired context is the same failure to the adapter (tokenError
	// maps both to ErrUnavailable), and the case still asserts ErrUnavailable and
	// one token call that is not retried.
	sub("TimeoutIsUnavailableAndNotRetried", func(t *testing.T) {
		p, srv, _ := c.setup(t)
		cb := c.login(t, p)
		srv.Block()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan error, 1)
		go func() {
			_, err := p.Exchange(ctx, cb, c.verifier(), nonce)
			done <- err
		}()
		<-srv.Blocked()
		cancel()
		if err := <-done; !errors.Is(err, provider.ErrUnavailable) {
			t.Fatalf("Exchange error = %v, want ErrUnavailable", err)
		}
		if n := srv.TokenCalls(); n != 1 {
			t.Errorf("the token endpoint was called %d times, want 1 (the code exchange is never retried)", n)
		}
	})

	sub("CancelledContextFails", func(t *testing.T) {
		p, srv, _ := c.setup(t)
		cb := c.login(t, p)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := p.Exchange(ctx, cb, c.verifier(), nonce); err == nil {
			t.Error("Exchange succeeded with a cancelled context")
		}
		if n := srv.TokenCalls(); n > 1 {
			t.Errorf("the token endpoint was called %d times, want at most 1", n)
		}
	})

	sub("FailedCodeExchangeIsNotRetried", func(t *testing.T) {
		p, srv, _ := c.setup(t)
		_, err := p.Exchange(context.Background(), provider.Callback{Code: "unknown-code"}, c.verifier(), nonce)
		if err == nil {
			t.Fatal("Exchange accepted an unknown code")
		}
		if n := srv.TokenCalls(); n != 1 {
			t.Errorf("the token endpoint was called %d times, want 1", n)
		}
	})

	sub("TokenServerErrorIsNotRetried", func(t *testing.T) {
		p, srv, _ := c.setup(t)
		cb := c.login(t, p)
		srv.FailToken(1)
		_, err := p.Exchange(context.Background(), cb, c.verifier(), nonce)
		if err == nil {
			t.Fatal("Exchange succeeded although the token endpoint answered 500")
		}
		if errors.Is(err, provider.ErrCancelled) {
			t.Errorf("a token endpoint failure is reported as a cancel: %v", err)
		}
		if n := srv.TokenCalls(); n != 1 {
			t.Errorf("the token endpoint was called %d times, want 1 (never retried)", n)
		}
	})

	if c.PKCE {
		sub("WrongVerifierRefused", func(t *testing.T) {
			p, _, _ := c.setup(t)
			_, err := p.Exchange(context.Background(), c.login(t, p), verifier+"-other", nonce)
			if err == nil {
				t.Error("Exchange succeeded with a verifier that does not match the challenge")
			}
		})
	}

	if c.OIDC {
		c.runOIDC(t, sub)
		c.runAudience(t, sub)
	}
	c.runRedirects(t, sub)

	for _, h := range c.Hints {
		sub("Hint/"+h.Name, func(t *testing.T) {
			p, _, _ := c.setup(t)
			u, err := url.Parse(p.AuthURL(state, nonce, challenge(), h.Opts))
			if err != nil {
				t.Fatal(err)
			}
			q := u.Query()
			for k, v := range h.Want {
				if got := q[k]; len(got) != len(v) || (len(v) > 0 && got[0] != v[0]) {
					t.Errorf("%s = %v, want %v", k, got, v)
				}
			}
			for _, k := range h.Absent {
				if q.Has(k) {
					t.Errorf("%s = %v is sent, want it absent", k, q[k])
				}
			}
		})
	}
}

func (c Case) runOIDC(t *testing.T, sub func(string, func(*testing.T))) {
	rejected := []struct {
		name  string
		claim func(clk clock.Clock) func(map[string]any)
	}{
		{"BadNonceClaim", func(clock.Clock) func(map[string]any) {
			return func(m map[string]any) { m["nonce"] = "another-nonce" }
		}},
		{"MissingNonceClaim", func(clock.Clock) func(map[string]any) {
			return func(m map[string]any) { delete(m, "nonce") }
		}},
		{"BadAud", func(clock.Clock) func(map[string]any) {
			return func(m map[string]any) { m["aud"] = "another-client" }
		}},
		{"BadIss", func(clock.Clock) func(map[string]any) {
			return func(m map[string]any) { m["iss"] = "https://evil.example" }
		}},
		{"ExpiredExp", func(clk clock.Clock) func(map[string]any) {
			return func(m map[string]any) { m["exp"] = clk.Now().Add(-time.Hour).Unix() }
		}},
	}
	for _, r := range rejected {
		sub(r.name+"Rejected", func(t *testing.T) {
			p, srv, clk := c.setup(t)
			cb := c.login(t, p)
			srv.SetIDTokenClaims(r.claim(clk))
			got, err := p.Exchange(context.Background(), cb, c.verifier(), nonce)
			if err == nil {
				t.Fatalf("Exchange accepted the ID token, identity %+v", got)
			}
			if errors.Is(err, provider.ErrCancelled) {
				t.Errorf("a bad ID token is reported as a cancel: %v", err)
			}
			if got != (provider.Identity{}) {
				t.Errorf("an identity %+v is returned with the error", got)
			}
		})
	}

	sub("NonceArgumentChecked", func(t *testing.T) {
		p, _, _ := c.setup(t)
		_, err := p.Exchange(context.Background(), c.login(t, p), c.verifier(), "not-the-nonce-of-this-login")
		if err == nil {
			t.Error("Exchange accepted an ID token whose nonce is not the one expected")
		}
	})

	sub("KeyFetchRetriedOnce", func(t *testing.T) {
		p, srv, _ := c.setup(t)
		cb := c.login(t, p)
		srv.FailJWKS(1)
		if _, err := p.Exchange(context.Background(), cb, c.verifier(), nonce); err != nil {
			t.Fatalf("Exchange after one failed key fetch: %v", err)
		}
		if n := srv.JWKSCalls(); n != 2 {
			t.Errorf("the key endpoint was called %d times, want 2 (one retry)", n)
		}
	})

	sub("KeyFetchFailsAfterOneRetry", func(t *testing.T) {
		p, srv, _ := c.setup(t)
		cb := c.login(t, p)
		srv.FailJWKS(5)
		_, err := p.Exchange(context.Background(), cb, c.verifier(), nonce)
		if !errors.Is(err, provider.ErrUnavailable) {
			t.Errorf("Exchange error = %v, want ErrUnavailable", err)
		}
		if n := srv.JWKSCalls(); n != 2 {
			t.Errorf("the key endpoint was called %d times, want 2 (one retry, no more)", n)
		}
	})
}

// elsewhere starts a server that fails the test when it is called: the target
// of a redirect that the adapter must not follow.
func elsewhere(t *testing.T) string {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("the adapter followed a redirect to %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(ts.Close)
	return ts.URL + "/elsewhere"
}

// runRedirects checks that no call to the provider follows an HTTP redirect
// (SEC-26): a 302 from each endpoint the adapter calls is a failure of that
// call, and the server it names is never called.
func (c Case) runRedirects(t *testing.T, sub func(string, func(*testing.T))) {
	sub("RedirectOfTokenEndpointIsAFailure", func(t *testing.T) {
		p, srv, _ := c.setup(t)
		cb := c.login(t, p)
		target := elsewhere(t)
		srv.RedirectTo("token", target)
		_, err := p.Exchange(context.Background(), cb, c.verifier(), nonce)
		if err == nil || !isNone(err) {
			t.Errorf("Exchange error = %v, want a server_error (a failure that is none of the sentinels)", err)
		}
	})

	if c.OIDC {
		sub("RedirectOfKeyEndpointIsUnavailable", func(t *testing.T) {
			p, srv, _ := c.setup(t)
			cb := c.login(t, p)
			srv.RedirectTo("jwks", elsewhere(t))
			_, err := p.Exchange(context.Background(), cb, c.verifier(), nonce)
			if !errors.Is(err, provider.ErrUnavailable) {
				t.Errorf("Exchange error = %v, want ErrUnavailable (the keys could not be fetched)", err)
			}
		})
	}

	if c.UserInfo {
		sub("RedirectOfUserInfoIsAFailure", func(t *testing.T) {
			p, srv, _ := c.setupWith(t, true, generousTimeout)
			cb := c.login(t, p)
			srv.RedirectTo("userinfo", elsewhere(t))
			_, err := p.Exchange(context.Background(), cb, c.verifier(), nonce)
			if err == nil || !isNone(err) {
				t.Errorf("Exchange error = %v, want a server_error", err)
			}
		})
	}

	if c.Profile == mockidp.GitHub || c.Profile == mockidp.Facebook {
		sub("RedirectOfAPIIsAFailure", func(t *testing.T) {
			p, srv, _ := c.setup(t)
			cb := c.login(t, p)
			srv.RedirectTo("api", elsewhere(t))
			_, err := p.Exchange(context.Background(), cb, c.verifier(), nonce)
			if err == nil || !isNone(err) {
				t.Errorf("Exchange error = %v, want a server_error", err)
			}
		})
	}

	probe, _, _ := c.setup(t)
	if _, ok := probe.(provider.Revoker); ok {
		sub("RedirectOfRevokeEndpointIsAFailure", func(t *testing.T) {
			p, srv, _ := c.setup(t)
			rv := p.(provider.Revoker)
			srv.RedirectTo("revoke", elsewhere(t))
			if err := rv.Revoke(context.Background(), "refresh-token"); err == nil {
				t.Error("Revoke succeeded although the revoke endpoint redirected")
			}
		})
	}
}

// runAudience checks the azp and audience rule of an ID token (SEC-26, OIDC
// Core 3.1.3.7): an azp that is present must be our client id, and a token with
// more than one audience must have one.
func (c Case) runAudience(t *testing.T, sub func(string, func(*testing.T))) {
	rows := []struct {
		name   string
		aud    func(cid string) any
		azp    func(cid string) (any, bool) // the azp claim, and whether it is set
		accept bool
	}{
		{"TwoAudiencesWithoutAzpRejected",
			func(cid string) any { return []any{cid, "another-client"} },
			func(string) (any, bool) { return nil, false }, false},
		{"TwoAudiencesWithOurAzpAccepted",
			func(cid string) any { return []any{cid, "another-client"} },
			func(cid string) (any, bool) { return cid, true }, true},
		{"TwoAudiencesWithAnotherAzpRejected",
			func(cid string) any { return []any{cid, "another-client"} },
			func(string) (any, bool) { return "another-client", true }, false},
		{"OneAudienceWithAnotherAzpRejected",
			func(cid string) any { return cid },
			func(string) (any, bool) { return "another-client", true }, false},
		{"TwoAudiencesWithNumberAzpRejected",
			func(cid string) any { return []any{cid, "another-client"} },
			func(string) (any, bool) { return 123, true }, false},
		{"TwoAudiencesWithArrayAzpRejected",
			func(cid string) any { return []any{cid, "another-client"} },
			func(cid string) (any, bool) { return []any{cid}, true }, false},
		{"TwoAudiencesWithEmptyAzpRejected",
			func(cid string) any { return []any{cid, "another-client"} },
			func(string) (any, bool) { return "", true }, false},
	}
	for _, r := range rows {
		sub(r.name, func(t *testing.T) {
			p, srv, _ := c.setup(t)
			cb := c.login(t, p)
			cid := srv.ClientID() // read before the claims hook runs under the mock's lock
			srv.SetIDTokenClaims(func(m map[string]any) {
				m["aud"] = r.aud(cid)
				if v, set := r.azp(cid); set {
					m["azp"] = v
				} else {
					delete(m, "azp")
				}
			})
			got, err := p.Exchange(context.Background(), cb, c.verifier(), nonce)
			if r.accept {
				if err != nil {
					t.Fatalf("Exchange: %v", err)
				}
				if got.Subject != c.want().Subject {
					t.Errorf("subject = %q, want %q", got.Subject, c.want().Subject)
				}
				return
			}
			if err == nil {
				t.Fatalf("Exchange accepted the ID token, identity %+v", got)
			}
			if got != (provider.Identity{}) {
				t.Errorf("an identity %+v is returned with the error", got)
			}
		})
	}
}

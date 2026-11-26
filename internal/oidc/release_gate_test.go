package oidc_test

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/secure"
	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/testutil/mockidp"
	"github.com/yyudhistira/featherauth/internal/testutil/server"
)

// The tests of this file close acceptance rows and requirements that earlier
// steps proved in parts: each one runs the whole service in process and
// asserts every pass condition of its row or requirement.

// Covers: FR-02 (part)
// Acceptance: Scope handling
func TestScopeHandlingEndToEnd(t *testing.T) {
	e := server.New(t)
	app := server.ClientQuery
	t.Run("a request without openid is refused", func(t *testing.T) {
		got := e.Login(t, app, "scope", "profile email").Values
		if got.Get("error") != "invalid_scope" || got.Get("code") != "" {
			t.Errorf("result %v", got)
		}
	})
	t.Run("other scopes next to openid are ignored and the scope claim is openid", func(t *testing.T) {
		res := e.Login(t, app, "scope", "openid profile foo")
		if res.Values.Get("error") != "" || res.Values.Get("code") == "" {
			t.Fatalf("result %v", res.Values)
		}
		tk := wantTokens(t, post(t, e, server.CodeForm(app, res), nil))
		if tk.Scope != "openid" {
			t.Errorf("scope in the token response %q", tk.Scope)
		}
		if got := decodeJWT(t, tk.AccessToken).str("scope"); got != "openid" {
			t.Errorf("scope claim of the access token %q", got)
		}
	})
}

// Covers: FR-22 (part)
// Acceptance: Scopes do not filter claims
func TestScopesDoNotFilterClaimsEndToEnd(t *testing.T) {
	e := server.New(t)
	app := server.ClientQuery
	tk := wantTokens(t, post(t, e, server.CodeForm(app, e.Login(t, app, "scope", "openid")), nil))
	claims := map[string]map[string]any{
		"access token": decodeJWT(t, tk.AccessToken).claims,
		"ID token":     decodeJWT(t, tk.IDToken).claims,
		"userinfo":     claimsOf(t, userinfo(t, e, http.MethodGet, tk.AccessToken, nil)),
	}
	for name, m := range claims {
		for _, k := range []string{"name", "email", "preferred_username"} {
			if m[k] == nil || m[k] == "" {
				t.Errorf("%s: claim %s missing in %v", name, k, m)
			}
		}
	}
}

// Covers: FR-22 (part)
// Acceptance: User data
func TestUserDataAttributesEndToEnd(t *testing.T) {
	e := server.New(t)
	e.Reload(t, func(y string) string {
		return strings.Replace(y, "keys:\n", "user_data:\n  attributes: [email]\nkeys:\n", 1)
	})
	app := server.ClientQuery
	tk := wantTokens(t, post(t, e, server.CodeForm(app, e.Login(t, app)), nil))

	ctx := context.Background()
	var stored store.User
	err := e.Store.Read(ctx, func(tx store.Tx) error {
		rid, err := tx.Realms().Find(ctx, "main")
		if err != nil {
			return err
		}
		ident, err := tx.Identities().Find(ctx, rid, "google", "1001")
		if err != nil {
			return err
		}
		stored, err = tx.Users().Get(ctx, rid, ident.UserID)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if stored.Name != "" || stored.Email != "ann@example.com" {
		t.Errorf("stored user: name %q, email %q", stored.Name, stored.Email)
	}
	claims := map[string]map[string]any{
		"access token": decodeJWT(t, tk.AccessToken).claims,
		"ID token":     decodeJWT(t, tk.IDToken).claims,
		"userinfo":     claimsOf(t, userinfo(t, e, http.MethodGet, tk.AccessToken, nil)),
	}
	for name, m := range claims {
		if m["name"] != nil {
			t.Errorf("%s emits a name: %v", name, m)
		}
		if m["sub"] == nil || m["sub"] == "" {
			t.Errorf("%s has no sub: %v", name, m)
		}
	}
}

// Every endpoint of the table in HTTP endpoints gets each method it does not
// accept, HEAD and OPTIONS included: 405, an Allow header with exactly the
// table's methods (plus OPTIONS for token, revocation, userinfo and sessions),
// the error body of its kind, and nothing changed; discovery and the JWKS answer
// every method; the health endpoints answer 405 with Allow: GET, HEAD and a
// plain-text body, and 200 to GET and HEAD.
//
// Covers: FR-21 (part), FR-58
// Acceptance: Wrong method
func TestWrongMethodOnEveryEndpoint(t *testing.T) {
	e := server.New(t)
	app := server.ClientDelete
	tk := wantTokens(t, post(t, e, server.CodeForm(app, e.Login(t, app)), nil))
	unused := e.Login(t, app) // a code the wrong methods must not use up

	endpoints := []struct {
		name, path, allow string
		json              bool
	}{
		{"authorize", "/authorize", "GET, POST", false},
		{"callback", "/callback/google", "GET, POST", false},
		{"callback continue", "/callback/apple/continue", "GET", false},
		{"token", "/token", "POST, OPTIONS", true},
		{"revocation", "/revoke", "POST, OPTIONS", true},
		{"sessions", "/sessions", "GET, OPTIONS", true},
		{"userinfo", "/userinfo", "GET, POST, OPTIONS", true},
		{"logout", "/logout", "GET, POST", false},
		{"account", "/account", "DELETE", true},
		{"events", "/events/apple", "POST", true},
		{"data deletion", "/data-deletion", "GET", false},
	}
	form := url.Values{"refresh_token": {tk.RefreshToken}, "id_token_hint": {tk.IDToken}, "client_id": {app.ID}}
	for _, ep := range endpoints {
		accepted := strings.Split(ep.allow, ", ")
		for _, m := range []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions} {
			if contains(accepted, m) {
				continue
			}
			t.Run(ep.name+" "+m, func(t *testing.T) {
				h := http.Header{"Authorization": {"Bearer " + tk.AccessToken}}
				r := e.NewClient().Request(t, m, server.Issuer+ep.path, form.Encode(), h)
				if r.Code != http.StatusMethodNotAllowed || r.Header.Get("Allow") != ep.allow {
					t.Fatalf("status %d, Allow %q, want 405 and %q", r.Code, r.Header.Get("Allow"), ep.allow)
				}
				ct := r.Header.Get("Content-Type")
				if m == http.MethodHead {
					return // a HEAD answer has no body
				}
				if ep.json && (!strings.HasPrefix(ct, "application/json") || !strings.Contains(r.Body, `"invalid_request"`) || !strings.Contains(r.Body, "method not allowed")) {
					t.Errorf("API body %q (%s)", r.Body, ct)
				}
				if !ep.json && (!strings.HasPrefix(ct, "text/html") || !strings.Contains(r.Body, "<html")) {
					t.Errorf("browser body %q (%s)", r.Body, ct)
				}
			})
		}
	}
	t.Run("assets", func(t *testing.T) {
		for _, m := range []string{http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions} {
			r := e.NewClient().Request(t, m, server.Issuer+"/assets/style.css", "", nil)
			if r.Code != http.StatusMethodNotAllowed || r.Header.Get("Allow") != "GET" || !strings.HasPrefix(r.Header.Get("Content-Type"), "text/html") {
				t.Errorf("%s: status %d, headers %v", m, r.Code, r.Header)
			}
		}
	})
	t.Run("health endpoints", func(t *testing.T) {
		for _, p := range []string{"/healthz", "/readyz"} {
			for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions} {
				r := e.NewClient().Request(t, m, server.PublicURL+p, "", nil)
				if r.Code != http.StatusMethodNotAllowed || r.Header.Get("Allow") != "GET, HEAD" ||
					!strings.HasPrefix(r.Header.Get("Content-Type"), "text/plain") || strings.TrimSpace(r.Body) != "method not allowed" {
					t.Errorf("%s %s: status %d, headers %v, body %q", m, p, r.Code, r.Header, r.Body)
				}
			}
			for _, m := range []string{http.MethodGet, http.MethodHead} {
				if r := e.NewClient().Request(t, m, server.PublicURL+p, "", nil); r.Code != http.StatusOK {
					t.Errorf("%s %s: status %d", m, p, r.Code)
				}
			}
		}
	})
	t.Run("discovery and the JWKS answer every method", func(t *testing.T) {
		for _, p := range []string{"/.well-known/openid-configuration", "/jwks.json"} {
			for _, m := range []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
				if r := e.NewClient().Request(t, m, server.Issuer+p, "", nil); r.Code != http.StatusOK {
					t.Errorf("%s %s: status %d", m, p, r.Code)
				}
			}
		}
	})
	t.Run("nothing was changed", func(t *testing.T) {
		if r := userinfo(t, e, http.MethodGet, tk.AccessToken, nil); r.Code != 200 {
			t.Errorf("the user or the token is gone: %d %s", r.Code, r.Body)
		}
		wantTokens(t, refresh(t, e, app, tk.RefreshToken))
		wantTokens(t, post(t, e, server.CodeForm(app, unused), nil))
	})
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// Condition to test, SEC-01: S256 for every client, public and confidential:
// the S256 and "no challenge" subtests; plain never accepted and a challenge
// without a method rejected: their subtests, for the legacy client too;
// require_pkce false as a documented exception: the warning subtest; a sent
// challenge always verified and a verifier for a code without a challenge
// rejected: the last two subtests.
//
// Covers: SEC-01
func TestPKCEIsRequiredAndVerifiedForEveryClient(t *testing.T) {
	e := server.New(t)
	public, confidential, legacy := server.ClientQuery, server.ClientConfidential, server.ClientLegacy
	noChallenge := []string{"code_challenge", "-", "code_challenge_method", "-"}

	t.Run("S256 works for a public and for a confidential client", func(t *testing.T) {
		exchange(t, e, public)
		exchangeConfidential(t, e, confidential)
	})
	t.Run("no challenge is refused for every client that requires PKCE", func(t *testing.T) {
		for _, app := range []server.App{public, confidential} {
			if got := e.Login(t, app, noChallenge...).Values.Get("error"); got != "invalid_request" {
				t.Errorf("%s: error %q", app.ID, got)
			}
		}
	})
	t.Run("plain is never accepted", func(t *testing.T) {
		for _, app := range []server.App{public, confidential, legacy} {
			if got := e.Login(t, app, "code_challenge_method", "plain").Values.Get("error"); got != "invalid_request" {
				t.Errorf("%s: error %q", app.ID, got)
			}
		}
	})
	t.Run("a challenge without a method is not read as plain", func(t *testing.T) {
		for _, app := range []server.App{public, confidential, legacy} {
			if got := e.Login(t, app, "code_challenge_method", "-").Values.Get("error"); got != "invalid_request" {
				t.Errorf("%s: error %q", app.ID, got)
			}
		}
	})
	t.Run("require_pkce false is an exception with a warning for each client type", func(t *testing.T) {
		pub := checkClients(t, "clients:\n  app:\n    require_pkce: false\n    refresh_idle_lifetime: 24h\n    session_max_lifetime: 720h\n    redirect_uris: [https://app.example.com/callback]\n")
		if len(pub) != 1 || pub[0].Severity != config.Warning || !strings.Contains(pub[0].Message, "RFC 9700 section 2.1.1") {
			t.Errorf("public client: %v", pub)
		}
		con := checkClients(t, "clients:\n  app:\n"+confidentialClient+"    require_pkce: false\n")
		if len(con) != 1 || con[0].Severity != config.Warning {
			t.Errorf("confidential client: %v", con)
		}
		wantTokens(t, post(t, e, server.CodeForm(legacy, e.Login(t, legacy, noChallenge...), "code_verifier", "-"), nil))
	})
	t.Run("a challenge that is sent is always verified", func(t *testing.T) {
		wantError(t, post(t, e, server.CodeForm(legacy, e.Login(t, legacy), "code_verifier", strings.Repeat("a", 43)), nil), 400, "invalid_grant")
		wantError(t, post(t, e, server.CodeForm(legacy, e.Login(t, legacy), "code_verifier", "-"), nil), 400, "invalid_grant")
		wantTokens(t, post(t, e, server.CodeForm(legacy, e.Login(t, legacy)), nil))
	})
	t.Run("a verifier for a code issued without a challenge is refused", func(t *testing.T) {
		wantError(t, post(t, e, server.CodeForm(legacy, e.Login(t, legacy, noChallenge...)), nil), 400, "invalid_grant")
	})
}

// Condition to test, SEC-02: exact match, no wildcards: "only an exact match"
// and the load-time wildcard subtest; loopback redirects of a public client
// vary only in port (127.0.0.1 and [::1]): the loopback subtests; a
// confidential client cannot use loopback: its subtest; registered URIs
// validated at load: the two config subtests.
//
// Covers: SEC-02
func TestRedirectURIsMatchExactlyAndWildcardsAreRefused(t *testing.T) {
	e := server.New(t)
	e.Reload(t, func(y string) string {
		return strings.Replace(y, "clients:\n", "clients:\n  native:\n    redirect_uris: [\"http://127.0.0.1:8080/cb\", \"http://[::1]:8080/cb\"]\n", 1)
	})
	authorize := func(clientID, uri string) server.Response {
		q := server.Authorize(server.App{ID: clientID, RedirectURI: uri}, "google")
		return e.NewClient().Do(t, http.MethodGet, server.Issuer+"/authorize?"+q.Encode(), nil)
	}
	toProvider := func(r server.Response) bool {
		return r.Code == http.StatusFound && strings.HasPrefix(r.Header.Get("Location"), e.Mocks["google"].URL())
	}
	if r := authorize("web", "https://app.example.com/callback"); !toProvider(r) {
		t.Fatalf("the registered URI: %d %v", r.Code, r.Header)
	}
	refused := func(t *testing.T, r server.Response) {
		t.Helper()
		if r.Code != http.StatusBadRequest || r.Header.Get("Location") != "" {
			t.Errorf("status %d, Location %q; want an error page and no redirect", r.Code, r.Header.Get("Location"))
		}
	}
	t.Run("only an exact match is accepted", func(t *testing.T) {
		for _, uri := range []string{
			"https://app.example.com/callback/", "https://app.example.com/Callback", "https://APP.example.com/callback",
			"https://app.example.com/callback?x=1", "http://app.example.com/callback", "https://app.example.com:8443/callback",
			"https://app.example.com/callbac", "https://app.example.com/callback/extra", "https://evil.example.com/callback",
			"https://*.example.com/callback", "https://app.example.com/*",
		} {
			refused(t, authorize("web", uri))
		}
	})
	t.Run("a loopback URI of a public client varies only in the port", func(t *testing.T) {
		for _, uri := range []string{"http://127.0.0.1:8080/cb", "http://127.0.0.1:54321/cb", "http://127.0.0.1/cb",
			"http://[::1]:8080/cb", "http://[::1]:54321/cb", "http://[::1]/cb"} {
			if r := authorize("native", uri); !toProvider(r) {
				t.Errorf("%s: %d %v", uri, r.Code, r.Header)
			}
		}
		for _, uri := range []string{"http://127.0.0.1:54321/other", "http://127.0.0.1:54321/cb?x=1", "http://localhost:8080/cb", "http://127.0.0.2:8080/cb", "https://127.0.0.1:8080/cb",
			"http://[::1]:54321/other", "http://[::1]:54321/cb?x=1", "http://[::2]:8080/cb", "https://[::1]:8080/cb", "http://[::1]:54321/cb/"} {
			refused(t, authorize("native", uri))
		}
	})
	t.Run("a confidential client cannot use a loopback URI", func(t *testing.T) {
		refused(t, authorize("srv", "http://127.0.0.1:54321/callback"))
		refused(t, authorize("srv", "http://[::1]:54321/callback"))
		for _, uri := range []string{"http://127.0.0.1:8080/cb", "http://[::1]:8080/cb"} {
			ds := checkClients(t, "clients:\n  app:\n    type: confidential\n    client_secret_file: secrets/other/client_secret\n    redirect_uris: [\""+uri+"\"]\n")
			if len(ds) != 1 || ds[0].Severity != config.Error {
				t.Errorf("%s: diagnostics %v", uri, ds)
			}
		}
	})
	t.Run("wildcards are refused at load", func(t *testing.T) {
		for _, uri := range []string{"https://*.example.com/cb", "https://app.example.com/*"} {
			ds := checkClients(t, "clients:\n  app:\n    redirect_uris: ["+uri+"]\n")
			if len(ds) != 1 || ds[0].Severity != config.Error || !strings.Contains(ds[0].Message, "wildcard") {
				t.Errorf("%s: diagnostics %v", uri, ds)
			}
		}
	})
}

// Condition to test, SEC-06: a 256-bit random secret (43 characters, two
// tokens differ), hashed at rest, bound to its client: the first subtest;
// rotated with reuse detection (public client): the second; opaque or jwt with
// typ refresh+jwt and aud the issuer: the third; lifetimes per realm and
// client: the fourth; a reused login code revokes the session: the last.
//
// Covers: SEC-06
func TestRefreshTokenRecordsEndToEnd(t *testing.T) {
	app := server.ClientQuery
	t.Run("a 256-bit random secret, hashed at rest, bound to its client", func(t *testing.T) {
		e := server.New(t)
		tk := exchange(t, e, app)
		if len(tk.RefreshToken) != 43 || strings.Contains(tk.RefreshToken, ".") {
			t.Errorf("refresh token %q is not 32 random bytes in base64url", tk.RefreshToken)
		}
		if other := exchange(t, e, app); other.RefreshToken == tk.RefreshToken {
			t.Error("two logins got the same refresh token")
		}
		ctx := context.Background()
		var row store.RefreshToken
		err := e.Store.Read(ctx, func(tx store.Tx) error {
			rid, err := tx.Realms().Find(ctx, "main")
			if err != nil {
				return err
			}
			row, err = tx.RefreshTokens().FindByHash(ctx, rid, secure.HashOf(tk.RefreshToken))
			return err
		})
		if err != nil || row.ClientID != config.ClientID(app.ID) || string(row.TokenHash) == tk.RefreshToken {
			t.Fatalf("row %+v, error %v", row, err)
		}
		for _, f := range []string{e.DatabasePath, e.DatabasePath + "-wal"} {
			b, err := os.ReadFile(f)
			if err == nil && strings.Contains(string(b), tk.RefreshToken) {
				t.Errorf("%s holds the refresh token in clear", f)
			}
		}
		wantError(t, refresh(t, e, server.ClientLegacy, tk.RefreshToken), 400, "invalid_grant")
		wantTokens(t, refresh(t, e, app, tk.RefreshToken))
	})
	t.Run("rotated with reuse detection", func(t *testing.T) {
		e := server.New(t)
		first := exchange(t, e, app)
		second := wantTokens(t, refresh(t, e, app, first.RefreshToken))
		if second.RefreshToken == first.RefreshToken {
			t.Fatal("not rotated")
		}
		e.Clock.Advance(time.Minute) // past refresh_reuse_grace
		wantError(t, refresh(t, e, app, first.RefreshToken), 400, "invalid_grant")
		wantError(t, refresh(t, e, app, second.RefreshToken), 400, "invalid_grant")
	})
	t.Run("handed out as opaque or jwt", func(t *testing.T) {
		e := server.New(t, server.WithRefreshFormat("jwt"))
		tk := exchange(t, e, app)
		rt := decodeJWT(t, tk.RefreshToken)
		if rt.header["typ"] != "refresh+jwt" || rt.str("aud") != server.Issuer {
			t.Errorf("refresh token %v %v", rt.header, rt.claims)
		}
		wantTokens(t, refresh(t, e, app, tk.RefreshToken))
	})
	t.Run("lifetimes per realm and per client", func(t *testing.T) {
		e := server.New(t, server.WithTokenSetting("refresh_idle_lifetime: 48h"))
		if tk := exchange(t, e, app); tk.RefreshExpiresIn != 48*3600 {
			t.Errorf("realm lifetime: refresh_expires_in %d", tk.RefreshExpiresIn)
		}
		if tk := exchange(t, e, server.ClientLong); tk.RefreshExpiresIn != 17520*3600 {
			t.Errorf("client lifetime: refresh_expires_in %d", tk.RefreshExpiresIn)
		}
	})
	t.Run("a reused login code revokes the session made from it", func(t *testing.T) {
		e := server.New(t)
		res := e.Login(t, app)
		tk := wantTokens(t, post(t, e, server.CodeForm(app, res), nil))
		wantError(t, post(t, e, server.CodeForm(app, res), nil), 400, "invalid_grant")
		wantError(t, refresh(t, e, app, tk.RefreshToken), 400, "invalid_grant")
	})
}

// Covers: FR-14 (part), FR-18 (part)
// Acceptance: Provider discovery down
func TestProviderDiscoveryDownEndToEnd(t *testing.T) {
	e := server.New(t)
	app := server.ClientQuery
	corp := e.Mocks["corp"]
	corp.SetUser(mockidp.User{Sub: "c1", Name: "Cy Corp", Email: "cy@example.com", EmailVerified: true})
	up := corp.URL()
	const down = "http://127.0.0.1:1"
	setIssuer := func(from, to string) {
		t.Helper()
		e.Reload(t, func(y string) string { return strings.Replace(y, `issuer: "`+from+`"`, `issuer: "`+to+`"`, 1) })
	}
	// The issuer cannot be reached when the configuration is loaded: the
	// configuration is valid (Reload fails the test otherwise) and the
	// provider stays listed.
	setIssuer(up, down)
	chooser := e.NewClient().Do(t, http.MethodGet, server.Issuer+"/authorize?"+server.Authorize(app, "").Encode(), nil)
	if chooser.Code != http.StatusOK || !strings.Contains(chooser.Body, "Corp") {
		t.Errorf("chooser: %d, lists Corp: %v", chooser.Code, strings.Contains(chooser.Body, "Corp"))
	}
	// The first login ends with a temporarily_unavailable redirect.
	first := e.NewClient().Login(t, server.Authorize(app, "corp"))
	if first.Values.Get("error") != "temporarily_unavailable" || first.Values.Get("state") != "st-1" {
		t.Fatalf("first login: %v", first.Values)
	}
	// The issuer comes back; 30 seconds later the login works.
	setIssuer(down, up)
	e.Clock.Advance(30 * time.Second)
	later := e.NewClient().Login(t, server.Authorize(app, "corp"))
	if later.Values.Get("error") != "" || later.Values.Get("code") == "" {
		t.Fatalf("later login: %v", later.Values)
	}

	// A reload while an exchange with the provider is running does not
	// disturb it.
	c := e.NewClient()
	start := c.Do(t, http.MethodGet, server.Issuer+"/authorize?"+server.Authorize(app, "corp").Encode(), nil)
	atProvider := c.Do(t, http.MethodGet, start.Header.Get("Location"), nil)
	callback := atProvider.Header.Get("Location")
	if !strings.HasPrefix(callback, server.Issuer+"/callback/corp") {
		t.Fatalf("the provider sent the browser to %q", callback)
	}
	corp.Block()
	done := make(chan server.Response, 1)
	go func() { done <- c.Do(t, http.MethodGet, callback, nil) }()
	<-corp.Blocked() // the exchange is at the provider
	e.Reload(t, func(y string) string {
		return strings.Replace(y, `issuer: "`+up+`"`, `issuer: "`+up+`"`+"\n    timeout: 20s", 1)
	})
	corp.Unblock()
	r := <-done
	if loc := r.Header.Get("Location"); r.Code != http.StatusFound || !strings.HasPrefix(loc, app.RedirectURI+"?") || !strings.Contains(loc, "code=") {
		t.Errorf("the running exchange was disturbed: %d %v", r.Code, r.Header)
	}
}

package oidc_test

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/provider"
	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/testutil/mockidp"
	"github.com/yyudhistira/featherauth/internal/testutil/server"
)

// Full flows: the whole service in process, every step over HTTP.

// flowUser makes the mock identity provider of key sign in this person.
func flowUser(e *server.Env, key, sub, email string, verified any) {
	u := mockidp.User{
		Sub: sub, Name: "Ann Lee", Email: email, EmailVerified: verified,
		Emails: []mockidp.Email{{Email: email, Primary: true, Verified: verified == true}},
	}
	e.Mocks[key].SetUser(u)
}

// flowSignIn logs the person in at the provider as the client and trades the
// code over HTTP; it returns the tokens.
func flowSignIn(t *testing.T, e *server.Env, app server.App, key string, kv ...string) server.Tokens {
	t.Helper()
	res := e.NewClient().Login(t, server.Authorize(app, key, kv...))
	if res.Values.Get("code") == "" {
		t.Fatalf("no code: %v", res.Values)
	}
	return wantTokens(t, post(t, e, server.CodeForm(app, res), nil))
}

// flowLoginError is the error of a login that ends at the client.
func flowLoginError(t *testing.T, e *server.Env, app server.App, key string) string {
	t.Helper()
	res := e.NewClient().Login(t, server.Authorize(app, key))
	if res.Values.Has("code") {
		t.Fatalf("a code was issued: %v", res.Values)
	}
	return res.Values.Get("error")
}

func subOf(t *testing.T, tk server.Tokens) string {
	t.Helper()
	return decodeJWT(t, tk.IDToken).claims["sub"].(string)
}

// flowAudit returns every audit row of the realm.
func flowAudit(t *testing.T, e *server.Env) []store.AuditEvent {
	t.Helper()
	ctx := context.Background()
	var rows []store.AuditEvent
	err := e.Store.Read(ctx, func(tx store.Tx) error {
		rid, err := tx.Realms().Find(ctx, "main")
		if err != nil {
			return err
		}
		rows, err = tx.Audit().List(ctx, rid, e.Clock.Now().Add(-24*time.Hour))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func flowCount(rows []store.AuditEvent, action string) int {
	n := 0
	for _, r := range rows {
		if r.Action == action {
			n++
		}
	}
	return n
}

// userinfoClaims calls /userinfo of the realm at its configured URL.
func flowUserinfo(t *testing.T, e *server.Env, access string) map[string]any {
	t.Helper()
	r := e.NewClient().Request(t, http.MethodGet, e.Realm.EndpointURL(config.EndpointUserinfo, ""), "",
		http.Header{"Authorization": {"Bearer " + access}})
	return claimsOf(t, r)
}

// The matrix: every provider with every client type and response mode goes
// through login, token, userinfo, refresh and logout. The logs of each run
// (at log_level debug) are scanned for secrets, JWTs, emails and URLs with a
// query or fragment.
//
// Covers: SEC-13
// Acceptance: Secrets and logs (part)
// Covers: FR-35 (part)
// Acceptance: Postgres service (part)
//
// This is the closing test of SEC-13. Condition by condition, the tests that
// assert it:
//   - logs are structured JSON, hold no secret of the list and no email at
//     debug level, and URLs have no query or fragment: this matrix, scanning
//     every line of every run (and TestLogScanFindsWhatItLooksFor,
//     TestLogScanFailsOnLiveOutput prove the scan can fail);
//   - the user id and the client IP are the only personal data, also in audit
//     lines: wantUserIDsInLogs here (request lines) and
//     TestAuditLinesHoldUserIDsNotEmails (audit line with user_id);
//     logx.TestAuditLine (fields of an audit line);
//   - the key list, its normalization and every shape and depth: logx
//     TestRedactsSensitiveKeysInEveryShape, TestLogValuerInsideContainers,
//     TestMapsWithOtherKeysHaveTheirValuesCleaned, and the secret-holding
//     types' LogValuer tests (token, store, provider, config, user, secure);
//   - URLs without query or fragment, and URLs inside errors of outgoing
//     calls: logx TestURLsLoseQueryAndFragment, TestPathDropsQuery,
//     TestErrorsFromOutgoingCallsLoseQuery; request log records the path
//     only: server TestRequestLogHasThePathWithoutQueryAndNoSecrets;
//   - the documented proxies log the path, not the query: deploy
//     TestNginxExampleLogsPathNotQuery and TestOpsCheckProxy.
func TestFullFlowMatrix(t *testing.T) {
	forEachFlowDriver(t, func(t *testing.T, o []server.Option) {
		apps := append(slices.Clone(server.Clients), server.ClientConfidential)
		for _, key := range server.Providers {
			for _, app := range apps {
				t.Run(key+"/"+app.ID+"/"+app.Mode, func(t *testing.T) {
					t.Parallel()
					e := flowNew(t, o)
					flowUser(e, key, "101", "ann@example.com", true)

					// login in the client's response mode, with state and iss
					const state, nonce = "state-fixture-7f3a91", "nonce-fixture-4c2e68"
					browser := e.NewClient()
					res := browser.Login(t, server.Authorize(app, key, "state", state, "nonce", nonce))
					if res.Mode != app.Mode || res.URL != app.RedirectURI {
						t.Fatalf("delivered by %s to %s", res.Mode, res.URL)
					}
					if res.Values.Get("state") != state || res.Values.Get("iss") != server.Issuer || res.Values.Get("code") == "" {
						t.Fatalf("result %v", res.Values)
					}

					// token
					form := server.CodeForm(app, res)
					if app.ID == server.ClientConfidential.ID {
						form.Set("client_secret", e.Secret(app.ID))
					}
					tk := wantTokens(t, post(t, e, form, nil))
					id := decodeJWT(t, tk.IDToken)
					if id.claims["iss"] != server.Issuer || id.claims["aud"] != app.ID || id.claims["nonce"] != nonce {
						t.Fatalf("id token %v", id.claims)
					}
					if at := decodeJWT(t, tk.AccessToken); at.header["typ"] != "at+jwt" || at.claims["sub"] != id.claims["sub"] {
						t.Fatalf("access token %v %v", at.header, at.claims)
					}

					// userinfo
					if got := flowUserinfo(t, e, tk.AccessToken); got["sub"] != id.claims["sub"] || got["email"] != "ann@example.com" {
						t.Fatalf("userinfo %v", got)
					}

					// refresh: the token is rotated and the subject is the same
					refreshing := func(rt string) url.Values { return e.RefreshForm(app, rt) }
					next := wantTokens(t, post(t, e, refreshing(tk.RefreshToken), nil))
					if next.RefreshToken == tk.RefreshToken || subOf(t, next) != id.claims["sub"] {
						t.Fatal("refresh did not rotate or changed the subject")
					}
					// the refreshed access token works at userinfo
					if got := flowUserinfo(t, e, next.AccessToken); got["sub"] != id.claims["sub"] {
						t.Fatalf("userinfo with the refreshed token %v", got)
					}
					// inside the reuse grace the old token yields another successor
					retry := wantTokens(t, post(t, e, refreshing(tk.RefreshToken), nil))
					if retry.RefreshToken == next.RefreshToken || retry.RefreshToken == tk.RefreshToken {
						t.Fatal("a replay inside the grace window did not give a fresh successor")
					}

					// logout with the ID token hint ends the session: every refresh token of it is dead
					wantSignedOut(t, logout(t, e, http.MethodPost, url.Values{"id_token_hint": {next.IDToken}}, nil))
					for _, rt := range []string{next.RefreshToken, retry.RefreshToken} {
						wantError(t, post(t, e, refreshing(rt), nil), 400, "invalid_grant")
					}

					// failures and a hint in a query string, for the log scan: the
					// used code again, a bad bearer token, a logout by GET
					wantError(t, post(t, e, form, nil), 400, "invalid_grant")
					const badBearer = "bearer-fixture-b81d05"
					if r := e.NewClient().Request(t, http.MethodGet, e.Realm.EndpointURL(config.EndpointUserinfo, ""), "",
						http.Header{"Authorization": {"Bearer " + badBearer}}); r.Code != 401 {
						t.Fatalf("userinfo with a bad bearer token: %d", r.Code)
					}
					logout(t, e, http.MethodGet, url.Values{"id_token_hint": {retry.IDToken}}, nil)

					secrets := []string{
						state, nonce, badBearer, res.Values.Get("code"), form.Get("code_verifier"), form.Get("client_secret"),
						tk.AccessToken, tk.RefreshToken, tk.IDToken, next.AccessToken, next.RefreshToken, next.IDToken,
						retry.AccessToken, retry.RefreshToken, retry.IDToken, "ann@example.com",
					}
					for _, c := range browser.Cookies() {
						secrets = append(secrets, c.Value)
					}
					if secret := form.Get("client_secret"); secret != "" {
						basic := app.ID + ":" + secret
						secrets = append(secrets, base64.StdEncoding.EncodeToString([]byte(basic)),
							base64.RawURLEncoding.EncodeToString([]byte(basic)), base64.URLEncoding.EncodeToString([]byte(basic)))
					}
					wantCleanLogs(t, e, secrets...)
					wantUserIDsInLogs(t, e.Logs.String(), false)
				})
			}
		}
	})
}

// After the reuse grace window a replayed refresh token revokes the whole
// session, successors included.
//
// Covers: FR-08 (part)
func TestRefreshReplayAfterTheGraceWindow(t *testing.T) {
	forEachFlowDriver(t, func(t *testing.T, o []server.Option) {
		for _, app := range append(slices.Clone(server.Clients), server.ClientConfidential) {
			t.Run(app.ID, func(t *testing.T) {
				e := flowNew(t, o)
				flowUser(e, "google", "201", "ann@example.com", true)
				res := e.NewClient().Login(t, server.Authorize(app, "google"))
				f := server.CodeForm(app, res)
				rf := func(rt string) url.Values { return e.RefreshForm(app, rt) }
				if app.ID == server.ClientConfidential.ID {
					f.Set("client_secret", e.Secret(app.ID))
				}
				tk := wantTokens(t, post(t, e, f, nil))
				next := wantTokens(t, post(t, e, rf(tk.RefreshToken), nil))
				e.Clock.Advance(31 * time.Second) // the default refresh_reuse_grace is 30s
				wantError(t, post(t, e, rf(tk.RefreshToken), nil), 400, "invalid_grant")
				wantError(t, post(t, e, rf(next.RefreshToken), nil), 400, "invalid_grant")
			})
		}
	})
}

// Providers enabled from config alone, GitHub, Facebook and a generic oidc
// one, each log in.
//
// Covers: FR-14
// Acceptance: Provider config
func TestProvidersFromConfigOnly(t *testing.T) {
	forEachFlowDriver(t, func(t *testing.T, o []server.Option) {
		e := flowNew(t, o)
		for i, key := range []string{"github", "facebook", "corp"} {
			if !e.Realm.Providers[config.ProviderKey(key)].Enabled {
				t.Fatalf("%s is not enabled by the configuration", key)
			}
			flowUser(e, key, "8001", key+"@example.com", true)
			tk := flowSignIn(t, e, server.ClientQuery, key)
			if subOf(t, tk) == "" {
				t.Fatalf("%s: no subject", key)
			}
			if _, err := identityOf(t, e, config.ProviderKey(key), "8001"); err != nil {
				t.Fatalf("%s (%d): no identity: %v", key, i, err)
			}
		}
		if got := e.Realm.Providers["corp"].Type; got != "oidc" {
			t.Fatalf("corp is of type %q", got)
		}
	})
}

// A second realm rejects every artefact of the first: its code, refresh token,
// access token and ID token hint; in both directions.
//
// Covers: FR-21, SEC-16
// Acceptance: Realm isolation
func TestRealmIsolation(t *testing.T) {
	forEachFlowDriver(t, func(t *testing.T, o []server.Option) {
		e := flowNew(t, o)
		other := e.AddRealm(t, "other")
		app := server.ClientQuery
		flowUser(e, "corp", "601", "ann@example.com", true)

		for _, dir := range []struct{ from, to *config.Realm }{{e.Realm, other}, {other, e.Realm}} {
			t.Run(string(dir.from.Name)+" to "+string(dir.to.Name), func(t *testing.T) {
				c := e.NewClient()
				login := func() server.Result {
					return c.LoginAt(t, dir.from.EndpointURL(config.EndpointAuthorize, ""), server.Authorize(app, "corp"))
				}
				tokenURL := dir.to.EndpointURL(config.EndpointToken, "")
				postTo := func(form url.Values) server.Response {
					return c.Request(t, http.MethodPost, tokenURL, form.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
				}
				// the code
				res := login()
				wantError(t, postTo(server.CodeForm(app, res)), 400, "invalid_grant")
				// the refresh token
				fromToken := dir.from.EndpointURL(config.EndpointToken, "")
				grant := func() server.Tokens {
					res := login()
					r := c.Request(t, http.MethodPost, fromToken, server.CodeForm(app, res).Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
					return wantTokens(t, r)
				}
				tk := grant()
				wantError(t, postTo(server.RefreshForm(app, tk.RefreshToken)), 400, "invalid_grant")
				// the access token and the ID token as bearer
				ui := c.Request(t, http.MethodGet, dir.to.EndpointURL(config.EndpointUserinfo, ""), "", http.Header{"Authorization": {"Bearer " + tk.AccessToken}})
				wantBearerError(t, ui, 401, invalidTokenHeader, "invalid_token")
				// the ID token hint at logout
				lo := c.Request(t, http.MethodPost, dir.to.EndpointURL(config.EndpointLogout, ""),
					url.Values{"id_token_hint": {tk.IDToken}}.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
				wantRefusal(t, lo)
				// nothing was used up: the artefacts still work in their own realm
				if r := c.Request(t, http.MethodGet, dir.from.EndpointURL(config.EndpointUserinfo, ""), "", http.Header{"Authorization": {"Bearer " + tk.AccessToken}}); r.Code != 200 {
					t.Fatalf("own userinfo %d", r.Code)
				}
				wantTokens(t, c.Request(t, http.MethodPost, fromToken, server.RefreshForm(app, tk.RefreshToken).Encode(),
					http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}))
			})
		}
	})
}

// The same person in two realms is two users with different subjects.
//
// Covers: FR-21
// Acceptance: Multi-realm users
func TestOneAccountInTwoRealmsHasTwoSubjects(t *testing.T) {
	forEachFlowDriver(t, func(t *testing.T, o []server.Option) {
		e := flowNew(t, o)
		other := e.AddRealm(t, "other")
		flowUser(e, "corp", "601", "ann@example.com", true)
		app := server.ClientQuery
		subs := map[string]string{}
		for _, r := range []*config.Realm{e.Realm, other} {
			c := e.NewClient()
			res := c.LoginAt(t, r.EndpointURL(config.EndpointAuthorize, ""), server.Authorize(app, "corp"))
			tk := wantTokens(t, c.Request(t, http.MethodPost, r.EndpointURL(config.EndpointToken, ""), server.CodeForm(app, res).Encode(),
				http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}))
			subs[string(r.Name)] = subOf(t, tk)
			ui := c.Request(t, http.MethodGet, r.EndpointURL(config.EndpointUserinfo, ""), "", http.Header{"Authorization": {"Bearer " + tk.AccessToken}})
			if claimsOf(t, ui)["sub"] != subs[string(r.Name)] {
				t.Fatalf("userinfo of %s", r.Name)
			}
		}
		if subs["main"] == "" || subs["other"] == "" || subs["main"] == subs["other"] {
			t.Fatalf("subjects %v", subs)
		}
		ctx := context.Background()
		err := e.Store.Read(ctx, func(tx store.Tx) error {
			for _, name := range []config.RealmName{"main", "other"} {
				rid, err := tx.Realms().Find(ctx, name)
				if err != nil {
					return err
				}
				if _, err := tx.Identities().Find(ctx, rid, "corp", "601"); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("each realm has its own identity row: %v", err)
		}
	})
}

// discoveryDoc fetches the discovery document of the realm.
func flowDiscovery(t *testing.T, e *server.Env) map[string]any {
	t.Helper()
	r := e.NewClient().Request(t, http.MethodGet, e.Realm.Issuer()+"/.well-known/openid-configuration", "", nil)
	return claimsOf(t, r)
}

// Under a path prefix the tokens carry the issuer discovery gives.
//
// Covers: FR-01
// Acceptance: Issuer with prefix
func TestIssuerWithPrefix(t *testing.T) {
	forEachFlowDriver(t, func(t *testing.T, o []server.Option) {
		e := flowNew(t, o, server.WithServerSetting("urls:\n  path_prefix: /auth\n"))
		const iss = "https://auth.example.com/auth/main"
		disc := flowDiscovery(t, e)
		if disc["issuer"] != iss {
			t.Fatalf("discovery issuer %v", disc["issuer"])
		}
		flowUser(e, "google", "201", "ann@example.com", true)
		res := e.NewClient().Login(t, server.Authorize(server.ClientQuery, "google"))
		if res.Values.Get("iss") != iss || res.Values.Get("code") == "" {
			t.Fatalf("result %v", res.Values)
		}
		tk := wantTokens(t, post(t, e, server.CodeForm(server.ClientQuery, res), nil))
		for name, raw := range map[string]string{"access": tk.AccessToken, "id": tk.IDToken} {
			if got := decodeJWT(t, raw).claims["iss"]; got != disc["issuer"] {
				t.Errorf("%s token iss %v, discovery %v", name, got, disc["issuer"])
			}
		}
		if r := e.NewClient().Request(t, http.MethodGet, server.PublicURL+"/main/authorize", "", nil); r.Code != 404 {
			t.Errorf("the path without the prefix answers %d", r.Code)
		}
	})
}

const keycloakServerYAML = `urls:
  issuer: /realms/{realm}
  endpoints:
    authorize: /realms/{realm}/protocol/openid-connect/auth
    token: /realms/{realm}/protocol/openid-connect/token
    userinfo: /realms/{realm}/protocol/openid-connect/userinfo
    jwks: /realms/{realm}/protocol/openid-connect/certs
    logout: /realms/{realm}/protocol/openid-connect/logout
    callback: /realms/{realm}/broker/{provider}/endpoint
login:
  provider_hint_params: [kc_idp_hint, provider]
logout:
  redirect_params: [redirect_uri, post_logout_redirect_uri]
`

// The Keycloak layout with JWT refresh tokens: every endpoint works at its
// configured path and name, discovery advertises the paths, the default
// paths answer 404.
//
// Covers: FR-28, FR-29
// Acceptance: Non-default URLs and token format
func TestKeycloakLayoutAndJWTRefreshTokens(t *testing.T) {
	forEachFlowDriver(t, func(t *testing.T, o []server.Option) {
		e := flowNew(t, o, server.WithServerSetting(keycloakServerYAML), server.WithRefreshFormat("jwt"))
		e.Reload(t, func(y string) string {
			return strings.Replace(y, "  web:\n    redirect_uris: [https://app.example.com/callback]\n",
				"  web:\n    redirect_uris: [https://app.example.com/callback]\n    post_logout_redirect_uris: ["+bye+"]\n", 1)
		})
		app := server.ClientQuery
		const base = server.PublicURL + "/realms/main"
		disc := flowDiscovery(t, e)
		for k, want := range map[string]string{
			"issuer":                 base,
			"authorization_endpoint": base + "/protocol/openid-connect/auth",
			"token_endpoint":         base + "/protocol/openid-connect/token",
			"userinfo_endpoint":      base + "/protocol/openid-connect/userinfo",
			"jwks_uri":               base + "/protocol/openid-connect/certs",
			"end_session_endpoint":   base + "/protocol/openid-connect/logout",
		} {
			if disc[k] != want {
				t.Errorf("discovery %s = %v, want %s", k, disc[k], want)
			}
		}

		// the provider hint under the configured name, the callback at the configured path
		e.Mocks["google"].SetUser(mockidp.User{Sub: "201", Name: "Ann Lee", Email: "ann@example.com", EmailVerified: true})
		c := e.NewClient()
		res := c.Login(t, server.Authorize(app, "", "kc_idp_hint", "google"))
		if res.Values.Get("code") == "" || res.Values.Get("iss") != base {
			t.Fatalf("result %v", res.Values)
		}
		if got := e.Mocks["google"].Authorizations(); len(got) == 0 || !strings.HasSuffix(got[len(got)-1].Params.Get("redirect_uri"), "/realms/main/broker/google/endpoint") {
			t.Fatalf("authorizations %v", got)
		}
		form := server.CodeForm(app, res)
		tk := wantTokens(t, c.Request(t, http.MethodPost, base+"/protocol/openid-connect/token", form.Encode(),
			http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}))
		rt := decodeJWT(t, tk.RefreshToken)
		if rt.header["typ"] != "refresh+jwt" || rt.claims["iss"] != base || rt.claims["typ"] != "Refresh" {
			t.Fatalf("refresh token %v %v", rt.header, rt.claims)
		}
		if got := flowUserinfo(t, e, tk.AccessToken); got["email"] != "ann@example.com" {
			t.Fatalf("userinfo %v", got)
		}
		if r := c.Request(t, http.MethodGet, base+"/protocol/openid-connect/certs", "", nil); r.Code != 200 || !strings.Contains(r.Body, `"keys"`) {
			t.Fatalf("jwks %d %q", r.Code, r.Body)
		}
		refreshed := wantTokens(t, c.Request(t, http.MethodPost, base+"/protocol/openid-connect/token", server.RefreshForm(app, tk.RefreshToken).Encode(),
			http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}))
		if decodeJWT(t, refreshed.RefreshToken).header["typ"] != "refresh+jwt" {
			t.Fatal("the refreshed token is not a JWT")
		}
		// logout with the return URL under the configured name
		lo := c.Request(t, http.MethodGet, base+"/protocol/openid-connect/logout?"+url.Values{
			"id_token_hint": {refreshed.IDToken}, "redirect_uri": {bye}, "state": {"s"},
		}.Encode(), "", nil)
		if lo.Code != http.StatusFound || !strings.HasPrefix(lo.Header.Get("Location"), bye) {
			t.Fatalf("logout %d %v", lo.Code, lo.Header)
		}
		wantError(t, c.Request(t, http.MethodPost, base+"/protocol/openid-connect/token", server.RefreshForm(app, refreshed.RefreshToken).Encode(),
			http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}), 400, "invalid_grant")

		// the default paths and the default hint name do not exist
		for _, p := range []string{"/main/authorize", "/main/token", "/main/userinfo", "/main/jwks.json", "/main/logout", "/main/.well-known/openid-configuration"} {
			if r := c.Request(t, http.MethodGet, server.PublicURL+p, "", nil); r.Code != 404 {
				t.Errorf("%s answers %d", p, r.Code)
			}
		}
		// a name in login.provider_hint_params skips the chooser ("provider" is in the list)
		if res := c.Login(t, server.Authorize(app, "", "provider", "google")); res.Values.Get("code") == "" {
			t.Fatalf("the hint under the name provider did not log in: %v", res.Values)
		}
		// a name that is in neither list is ignored, so the chooser shows, and its
		// buttons use the first name of the list
		chooser := c.Request(t, http.MethodGet, base+"/protocol/openid-connect/auth?"+server.Authorize(app, "", "idp", "google").Encode(), "", nil)
		if chooser.Code != 200 || !strings.Contains(chooser.Body, "kc_idp_hint=google") {
			t.Fatalf("a hint under an unlisted name: status %d, want the chooser with kc_idp_hint buttons", chooser.Code)
		}
	})
}

// userClaims are the user claims an access token, an ID token or /userinfo may carry.
var flowUserClaims = []string{"name", "email", "email_verified", "preferred_username", "allowed-origins"}

func flowPresent(m map[string]any) []string {
	var got []string
	for _, k := range flowUserClaims {
		if _, ok := m[k]; ok {
			got = append(got, k)
		}
	}
	slices.Sort(got)
	return got
}

// Claims end to end: the default four, then the list with allowed-origins.
//
// Covers: FR-22
// Acceptance: Claims selection
func TestClaimsSelectionEndToEnd(t *testing.T) {
	forEachFlowDriver(t, func(t *testing.T, o []server.Option) {
		e := flowNew(t, o)
		flowUser(e, "google", "201", "ann@example.com", true)
		check := func(t *testing.T, app server.App, want []string, origins []any) {
			t.Helper()
			tk := flowSignIn(t, e, app, "google")
			for name, m := range map[string]map[string]any{
				"access":   decodeJWT(t, tk.AccessToken).claims,
				"id":       decodeJWT(t, tk.IDToken).claims,
				"userinfo": flowUserinfo(t, e, tk.AccessToken),
			} {
				if got := flowPresent(m); !slices.Equal(got, want) {
					t.Errorf("%s claims %v, want %v", name, got, want)
				}
				if origins != nil {
					if got, _ := m["allowed-origins"].([]any); !slices.Equal(got, origins) {
						t.Errorf("%s allowed-origins %v", name, m["allowed-origins"])
					}
				}
			}
			for _, k := range []string{"iss", "sub", "aud", "exp", "iat", "auth_time", "sid", "nonce"} {
				if _, ok := decodeJWT(t, tk.IDToken).claims[k]; !ok {
					t.Errorf("the ID token has no %s", k)
				}
			}
			for _, k := range []string{"iss", "sub", "aud", "client_id", "azp", "exp", "iat", "jti", "auth_time", "sid", "scope", "nonce"} {
				if _, ok := decodeJWT(t, tk.AccessToken).claims[k]; !ok {
					t.Errorf("the access token has no %s", k)
				}
			}
		}
		t.Run("default", func(t *testing.T) {
			check(t, server.ClientQuery, []string{"email", "email_verified", "name", "preferred_username"}, nil)
		})
		t.Run("with allowed-origins", func(t *testing.T) {
			e.Reload(t, func(y string) string {
				return strings.Replace(y, "clients:\n", "user_data:\n  claims: [name, email, email_verified, preferred_username, allowed-origins]\nclients:\n", 1)
			})
			check(t, server.ClientQuery, []string{"allowed-origins", "email", "email_verified", "name", "preferred_username"},
				[]any{"https://app.example.com"})
			// a client without web origins gets no such claim
			check(t, server.ClientFormPost, []string{"email", "email_verified", "name", "preferred_username"}, nil)
		})
	})
}

// The person that the linking rows sign in.
func flowGmail(address string) string { return address + "@gmail.com" }

// Google then Apple with the same verified Gmail address is one user with two
// identities and an audit entry; the address in another case and with spaces
// is the same.
//
// Covers: FR-12, SEC-04
// Acceptance: Auto-link
// Acceptance: Email case
func TestAutoLinkEndToEnd(t *testing.T) {
	forEachFlowDriver(t, func(t *testing.T, o []server.Option) {
		e := flowNew(t, o)
		app := server.ClientQuery
		flowUser(e, "google", "201", "Foo@gmail.com", true)
		first := flowSignIn(t, e, app, "google")
		flowUser(e, "apple", "301", " foo@gmail.com ", "true") // Apple's string form, another case, spaces
		second := flowSignIn(t, e, app, "apple")
		if subOf(t, first) != subOf(t, second) {
			t.Fatalf("two users: %s and %s", subOf(t, first), subOf(t, second))
		}
		for _, id := range []struct{ prov, sub string }{{"google", "201"}, {"apple", "301"}} {
			if _, err := identityOf(t, e, config.ProviderKey(id.prov), id.sub); err != nil {
				t.Errorf("no %s identity: %v", id.prov, err)
			}
		}
		rows := flowAudit(t, e)
		if flowCount(rows, "identity.auto_link") != 1 {
			t.Fatalf("audit rows %v", rows)
		}
		for _, r := range rows {
			if r.Action == "identity.auto_link" && r.Actor != "provider:apple" {
				t.Errorf("actor %q", r.Actor)
			}
		}
		// a third login through the first provider changes nothing
		flowSignIn(t, e, app, "google")
		if flowCount(flowAudit(t, e), "identity.auto_link") != 1 {
			t.Fatal("a second auto-link row")
		}
	})
}

// An address on a company domain is not linked until the domain is added.
//
// Covers: SEC-04
// Acceptance: Auto-link domains
func TestAutoLinkDomainsEndToEnd(t *testing.T) {
	forEachFlowDriver(t, func(t *testing.T, o []server.Option) {
		e := flowNew(t, o)
		app := server.ClientQuery
		flowUser(e, "google", "201", "ann@example.com", true)
		flowUser(e, "github", "401", "ann@example.com", true)
		a := flowSignIn(t, e, app, "google")
		b := flowSignIn(t, e, app, "github")
		if subOf(t, a) == subOf(t, b) {
			t.Fatal("linked on a company domain")
		}
		if got := flowUserinfo(t, e, b.AccessToken); got["email_verified"] == true {
			t.Fatalf("the second user is verified: %v", got)
		}
		if flowCount(flowAudit(t, e), "identity.auto_link") != 0 {
			t.Fatal("an auto-link row")
		}

		e.Reload(t, func(y string) string {
			return strings.Replace(y, "clients:\n", "user_data:\n  auto_link_domains: [example.com]\nclients:\n", 1)
		})
		flowUser(e, "google", "202", "bob@example.com", true)
		flowUser(e, "github", "402", "bob@example.com", true)
		c := flowSignIn(t, e, app, "google")
		d := flowSignIn(t, e, app, "github")
		if subOf(t, c) != subOf(t, d) {
			t.Fatal("not linked after the domain was added")
		}
		if flowCount(flowAudit(t, e), "identity.auto_link") != 1 {
			t.Fatal("no auto-link row")
		}
	})
}

// With auto_link off a new user whose verified email is held by another user
// is created unverified.
//
// Covers: FR-12
// Acceptance: One verified email
func TestOneVerifiedEmailEndToEnd(t *testing.T) {
	forEachFlowDriver(t, func(t *testing.T, o []server.Option) {
		e := flowNew(t, o)
		app := server.ClientQuery
		e.Reload(t, func(y string) string {
			return strings.Replace(y, "  apple:\n    enabled: true\n", "  apple:\n    enabled: true\n    auto_link: false\n", 1)
		})
		flowUser(e, "google", "201", flowGmail("ann"), true)
		flowUser(e, "apple", "301", flowGmail("ann"), true)
		a := flowSignIn(t, e, app, "google")
		b := flowSignIn(t, e, app, "apple")
		if subOf(t, a) == subOf(t, b) {
			t.Fatal("linked although auto_link is off")
		}
		if got := flowUserinfo(t, e, a.AccessToken); got["email_verified"] != true {
			t.Fatalf("the first user lost its verification: %v", got)
		}
		if got := flowUserinfo(t, e, b.AccessToken); got["email_verified"] == true || got["email"] != flowGmail("ann") {
			t.Fatalf("the second user: %v", got)
		}
	})
}

// A new email at the provider: import keeps the user's, force changes it
// unless another verified user holds it.
//
// Covers: FR-12
// Acceptance: Email change
func TestEmailChangeEndToEnd(t *testing.T) {
	forEachFlowDriver(t, func(t *testing.T, o []server.Option) {
		app := server.ClientQuery
		email := func(t *testing.T, e *server.Env, tk server.Tokens) any {
			return flowUserinfo(t, e, tk.AccessToken)["email"]
		}
		t.Run("import", func(t *testing.T) {
			e := flowNew(t, o)
			flowUser(e, "google", "201", flowGmail("old"), true)
			flowSignIn(t, e, app, "google")
			flowUser(e, "google", "201", flowGmail("new"), true)
			tk := flowSignIn(t, e, app, "google")
			if email(t, e, tk) != flowGmail("old") {
				t.Fatalf("the user's email changed: %v", email(t, e, tk))
			}
		})
		t.Run("force", func(t *testing.T) {
			e := flowNew(t, o)
			e.Reload(t, func(y string) string {
				return strings.Replace(y, "  google:\n    enabled: true\n", "  google:\n    enabled: true\n    sync_mode: force\n", 1)
			})
			flowUser(e, "google", "201", flowGmail("old"), true)
			flowSignIn(t, e, app, "google")
			flowUser(e, "google", "201", flowGmail("new"), true)
			tk := flowSignIn(t, e, app, "google")
			if email(t, e, tk) != flowGmail("new") {
				t.Fatalf("the user's email did not change: %v", email(t, e, tk))
			}
		})
		t.Run("force, held by another verified user", func(t *testing.T) {
			e := flowNew(t, o)
			e.Reload(t, func(y string) string {
				return strings.Replace(y, "  google:\n    enabled: true\n", "  google:\n    enabled: true\n    sync_mode: force\n", 1)
			})
			flowUser(e, "google", "202", flowGmail("held"), true)
			flowSignIn(t, e, app, "google")
			flowUser(e, "google", "201", flowGmail("old"), true)
			flowSignIn(t, e, app, "google")
			before := e.Logs.Len()
			flowUser(e, "google", "201", flowGmail("held"), true)
			tk := flowSignIn(t, e, app, "google")
			if email(t, e, tk) != flowGmail("old") {
				t.Fatalf("the email moved to a second holder: %v", email(t, e, tk))
			}
			if !strings.Contains(e.Logs.String()[before:], `"level":"WARN"`) {
				t.Fatalf("the conflict was not logged:\n%s", e.Logs.String()[before:])
			}
		})
	})
}

// An unverified email, Facebook and a generic provider with the defaults link
// nothing.
//
// Covers: SEC-04
// Acceptance: No unsafe link
func TestNoUnsafeLinkEndToEnd(t *testing.T) {
	forEachFlowDriver(t, func(t *testing.T, o []server.Option) {
		e := flowNew(t, o)
		app := server.ClientQuery
		addr := flowGmail("ann")
		flowUser(e, "google", "201", addr, true)
		subs := []string{subOf(t, flowSignIn(t, e, app, "google"))}
		for _, p := range []struct {
			key      string
			verified any
		}{{"apple", false}, {"facebook", nil}, {"corp", true}} {
			flowUser(e, p.key, "7001", addr, p.verified)
			subs = append(subs, subOf(t, flowSignIn(t, e, app, p.key)))
		}
		for i, a := range subs {
			for _, b := range subs[i+1:] {
				if a == b {
					t.Fatalf("two logins share a user: %v", subs)
				}
			}
		}
		if flowCount(flowAudit(t, e), "identity.auto_link") != 0 {
			t.Fatal("an auto-link row")
		}
	})
}

// Apple's private relay address does not link; the second Apple login returns
// to the first Apple user.
//
// Covers: FR-12
// Acceptance: Apple private relay
func TestApplePrivateRelayEndToEnd(t *testing.T) {
	forEachFlowDriver(t, func(t *testing.T, o []server.Option) {
		e := flowNew(t, o)
		app := server.ClientQuery
		const relay = "abc123@privaterelay.appleid.com"
		e.Mocks["apple"].SetUser(mockidp.User{Sub: "301", Name: "Ann", Email: relay, EmailVerified: true, IsPrivateEmail: "true"})
		first := flowSignIn(t, e, app, "apple")
		flowUser(e, "google", "201", relay, true)
		google := flowSignIn(t, e, app, "google")
		again := flowSignIn(t, e, app, "apple")
		if subOf(t, first) == subOf(t, google) {
			t.Fatal("the relay address linked to Google")
		}
		if subOf(t, first) != subOf(t, again) {
			t.Fatal("the second Apple login is another user")
		}
	})
}

// The login hints reach each provider as the design lists, over a full login.
//
// Covers: FR-02
// Acceptance: Login hints
func TestLoginHintsEndToEnd(t *testing.T) {
	forEachFlowDriver(t, func(t *testing.T, o []server.Option) {
		type want = url.Values
		zero := []string{"max_age", "0"}
		requests := []struct {
			name string
			kv   []string
			// the parameters each provider receives; the others must be absent
			want map[string]want
		}{
			{"prompt=login", []string{"prompt", "login"}, map[string]want{
				"google": {"prompt": {"select_account"}}, "github": {"prompt": {"select_account"}},
				"facebook": {"auth_type": {"reauthenticate"}}, "corp": {"prompt": {"login"}}}},
			{"max_age=0", zero, map[string]want{
				"google": {"prompt": {"select_account"}}, "github": {"prompt": {"select_account"}},
				"facebook": {"auth_type": {"reauthenticate"}}, "corp": {"max_age": {"0"}}}},
			{"prompt=select_account", []string{"prompt", "select_account"}, map[string]want{
				"google": {"prompt": {"select_account"}}, "github": {"prompt": {"select_account"}},
				"corp": {"prompt": {"select_account"}}}},
			{"prompt=consent with max_age", []string{"prompt", "consent", "max_age", "0"}, map[string]want{
				"google": {"prompt": {"select_account consent"}}, "github": {"prompt": {"select_account"}},
				"facebook": {"auth_type": {"reauthenticate"}}, "corp": {"prompt": {"consent"}, "max_age": {"0"}}}},
			{"several prompt values: the first is passed on", []string{"prompt", "select_account login"}, map[string]want{
				"google": {"prompt": {"select_account"}}, "github": {"prompt": {"select_account"}},
				"corp": {"prompt": {"select_account"}}}},
			{"an unknown prompt value is ignored", []string{"prompt", "foo"}, map[string]want{}},
			{"an unknown value beside a known one", []string{"prompt", "foo consent"}, map[string]want{
				"google": {"prompt": {"consent"}}, "corp": {"prompt": {"consent"}}}},
			{"prompt=consent", []string{"prompt", "consent"}, map[string]want{
				"google": {"prompt": {"consent"}}, "corp": {"prompt": {"consent"}}}},
			{"login_hint", []string{"login_hint", "ann@example.com"}, map[string]want{
				"google": {"login_hint": {"ann@example.com"}}, "corp": {"login_hint": {"ann@example.com"}}}},
		}
		hintParams := []string{"prompt", "max_age", "login_hint", "auth_type"}
		for _, rq := range requests {
			for _, key := range server.Providers {
				t.Run(rq.name+"/"+key, func(t *testing.T) {
					e := flowNew(t, o)
					flowUser(e, key, "101", "ann@example.com", true)
					res := e.NewClient().Login(t, server.Authorize(server.ClientQuery, key, rq.kv...))
					if res.Values.Get("code") == "" {
						t.Fatalf("result %v", res.Values)
					}
					auths := e.Mocks[key].Authorizations()
					if len(auths) != 1 {
						t.Fatalf("%d authorize requests", len(auths))
					}
					got := auths[0].Params
					for _, name := range hintParams {
						w := rq.want[key][name]
						if g := got[name]; !slices.Equal(g, w) {
							t.Errorf("%s = %v, want %v", name, g, w)
						}
					}
				})
			}
		}

		t.Run("an old auth_time fails with login_required", func(t *testing.T) {
			e := flowNew(t, o)
			u := mockidp.User{Sub: "101", Email: "ann@example.com", EmailVerified: true, AuthTime: e.Clock.Now().Add(-time.Hour)}
			e.Mocks["corp"].SetUser(u)
			res := e.NewClient().Login(t, server.Authorize(server.ClientQuery, "corp", "max_age", "300"))
			if res.Values.Get("error") != "login_required" || res.Values.Has("code") {
				t.Fatalf("result %v", res.Values)
			}
			u.AuthTime = e.Clock.Now().Add(-time.Minute)
			e.Mocks["corp"].SetUser(u)
			if res := e.NewClient().Login(t, server.Authorize(server.ClientQuery, "corp", "max_age", "300")); res.Values.Get("code") == "" {
				t.Fatalf("a recent auth_time failed: %v", res.Values)
			}
		})
	})
}

// Provider adapters over HTTP: what the adapters refuse is refused in a full
// login, and what they accept signs in.
//
// Covers: SEC-03, FR-14
// Acceptance: Provider adapters
func TestProviderAdaptersOverHTTP(t *testing.T) {
	forEachFlowDriver(t, func(t *testing.T, o []server.Option) {
		app := server.ClientQuery
		t.Run("Apple email_verified as a string and as a boolean", func(t *testing.T) {
			for _, v := range []any{"true", true} {
				e := flowNew(t, o)
				flowUser(e, "apple", "301", flowGmail("ann"), v)
				tk := flowSignIn(t, e, app, "apple")
				if got := flowUserinfo(t, e, tk.AccessToken); got["email_verified"] != true {
					t.Errorf("%v: userinfo %v", v, got)
				}
			}
		})
		badClaims := []struct {
			name string
			fn   func(map[string]any, time.Time)
		}{
			{"aud", func(c map[string]any, _ time.Time) { c["aud"] = "someone-else" }},
			{"iss", func(c map[string]any, _ time.Time) { c["iss"] = "https://evil.example.com" }},
			{"exp", func(c map[string]any, now time.Time) { c["exp"] = now.Add(-time.Hour).Unix() }},
			{"nonce", func(c map[string]any, _ time.Time) { c["nonce"] = "another" }},
		}
		for _, key := range []string{"apple", "google", "corp"} {
			for _, bad := range badClaims {
				t.Run(key+" with a bad "+bad.name, func(t *testing.T) {
					e := flowNew(t, o)
					flowUser(e, key, "101", "ann@example.com", true)
					e.Mocks[key].SetIDTokenClaims(func(c map[string]any) { bad.fn(c, e.Clock.Now()) })
					if got := flowLoginError(t, e, app, key); got == "" {
						t.Fatal("the login was not refused")
					}
					e.Mocks[key].SetIDTokenClaims(nil)
					flowSignIn(t, e, app, key) // the same login works without the fault
				})
			}
		}
		t.Run("Google hosted domain", func(t *testing.T) {
			e := flowNew(t, o, server.WithGoogleOptions(func(o *provider.GoogleOptions) { o.HostedDomain = "example.com" }))
			e.Mocks["google"].SetUser(mockidp.User{Sub: "201", Email: "ann@example.com", EmailVerified: true, HD: "other.example.org"})
			if got := flowLoginError(t, e, app, "google"); got != "access_denied" {
				t.Fatalf("the wrong hd gave %q", got)
			}
			e.Mocks["google"].SetUser(mockidp.User{Sub: "201", Email: "ann@example.com", EmailVerified: true, HD: "example.com"})
			flowSignIn(t, e, app, "google")
			if auths := e.Mocks["google"].Authorizations(); auths[0].Params.Get("hd") != "example.com" {
				t.Errorf("hd not sent: %v", auths[0].Params)
			}
		})
		t.Run("GitHub without a verified address", func(t *testing.T) {
			e := flowNew(t, o)
			e.Mocks["github"].SetUser(mockidp.User{Sub: "401", Name: "Ann", Email: "ann@example.com", Emails: []mockidp.Email{{Email: "ann@example.com", Primary: true}}})
			if got := flowLoginError(t, e, app, "github"); got != "access_denied" {
				t.Fatalf("got %q", got)
			}
		})
		t.Run("GitHub sends allow_signup=false and a User-Agent", func(t *testing.T) {
			e := flowNew(t, o, server.WithGitHubOptions(func(o *provider.GitHubOptions) { o.AllowSignup = false }))
			flowUser(e, "github", "401", "ann@example.com", true)
			flowSignIn(t, e, app, "github") // the mock refuses a call without a User-Agent
			if auths := e.Mocks["github"].Authorizations(); auths[0].Params.Get("allow_signup") != "false" {
				t.Errorf("allow_signup: %v", auths[0].Params)
			}
		})
		t.Run("Facebook without an email", func(t *testing.T) {
			e := flowNew(t, o, server.WithFacebookOptions(func(o *provider.FacebookOptions) { o.RequireEmail = true }))
			e.Mocks["facebook"].SetUser(mockidp.User{Sub: "501", Name: "Ann"})
			if got := flowLoginError(t, e, app, "facebook"); got != "access_denied" {
				t.Fatalf("got %q", got)
			}
			flowUser(e, "facebook", "501", "ann@example.com", nil)
			flowSignIn(t, e, app, "facebook") // the mock refuses a call without a valid appsecret_proof
		})
		t.Run("Apple's client secret", func(t *testing.T) {
			e := flowNew(t, o)
			flowUser(e, "apple", "301", "ann@example.com", true)
			flowSignIn(t, e, app, "apple")
			var secret string
			for _, r := range e.Mocks["apple"].Requests() {
				if r.Method == http.MethodPost && strings.HasSuffix(r.Path, "/token") && r.Form.Get("grant_type") == "authorization_code" {
					secret = r.Form.Get("client_secret")
				}
			}
			if secret == "" {
				t.Fatal("no client secret was sent")
			}
			j := decodeJWT(t, secret)
			if j.header["kid"] != "KEY1234567" || j.header["alg"] != "ES256" {
				t.Errorf("header %v", j.header)
			}
			if j.claims["iss"] != "TEAM123456" || j.claims["sub"] != e.Mocks["apple"].ClientID() || j.claims["aud"] != "https://appleid.apple.com" {
				t.Errorf("claims %v", j.claims)
			}
			iat, _ := j.claims["iat"].(float64)
			exp, _ := j.claims["exp"].(float64)
			if iat == 0 || exp <= iat {
				t.Errorf("iat %v exp %v", j.claims["iat"], j.claims["exp"])
			}
		})
		t.Run("Facebook calls carry appsecret_proof", func(t *testing.T) {
			e := flowNew(t, o)
			flowUser(e, "facebook", "501", "ann@example.com", nil)
			flowSignIn(t, e, app, "facebook")
			n := 0
			for _, r := range e.Mocks["facebook"].Requests() {
				if strings.Contains(r.Path, "/me") {
					n++
					if r.Query.Get("appsecret_proof") == "" {
						t.Errorf("a Graph call without appsecret_proof: %v", r.Query)
					}
				}
			}
			if n == 0 {
				t.Fatal("no Graph call")
			}
		})
		t.Run("GitHub calls carry User-Agent", func(t *testing.T) {
			e := flowNew(t, o)
			flowUser(e, "github", "401", "ann@example.com", true)
			flowSignIn(t, e, app, "github")
			n := 0
			for _, r := range e.Mocks["github"].Requests() {
				// every call the service makes: the token exchange and the API; not the
				// user's own browser visit to the authorize page
				if !strings.Contains(r.Path, "authorize") {
					n++
					if ua := r.Header.Get("User-Agent"); ua == "" || strings.HasPrefix(ua, "Go-http-client") {
						t.Errorf("%s with User-Agent %q", r.Path, ua)
					}
				}
			}
			if n < 3 {
				t.Fatalf("%d GitHub calls, want the token exchange, /user and /user/emails", n)
			}
		})
	})
}

// CORS on every endpoint kind: token, userinfo, JWKS and discovery, from a
// registered and an unregistered origin, and the preflight and POST from
// another client's origin.
//
// Covers: FR-26, SEC-18
// Acceptance: CORS
func TestCORSOnEveryEndpointKind(t *testing.T) {
	forEachFlowDriver(t, func(t *testing.T, o []server.Option) {
		const own, other, stranger = "https://app.example.com", "https://frag.example.com", "https://evil.example.com"
		app := server.ClientQuery
		e := flowNew(t, o)
		flowUser(e, "google", "201", "ann@example.com", true)
		c := e.NewClient()
		at := func(ep config.Endpoint) string { return e.Realm.EndpointURL(ep, "") }
		req := func(method, u, origin string, h http.Header, body string) server.Response {
			hh := http.Header{"Origin": {origin}}
			for k, v := range h {
				hh[k] = v
			}
			return c.Request(t, method, u, body, hh)
		}
		allowed := func(r server.Response, origin string) bool {
			return r.Header.Get("Access-Control-Allow-Origin") == origin && r.Header.Get("Vary") == "Origin" &&
				r.Header.Get("Access-Control-Allow-Origin") != "*"
		}
		blocked := func(r server.Response) bool { return r.Header.Get("Access-Control-Allow-Origin") == "" }

		// preflights: methods per endpoint kind, for any client's registered origin
		for _, tc := range []struct {
			name, url, methods string
		}{
			{"token", at(config.EndpointToken), "POST, OPTIONS"},
			{"userinfo", at(config.EndpointUserinfo), "GET, POST, OPTIONS"},
			{"jwks", at(config.EndpointJWKS), "GET, OPTIONS"},
			{"discovery", e.Realm.Issuer() + "/.well-known/openid-configuration", "GET, OPTIONS"},
		} {
			for _, origin := range []string{own, other} {
				r := req(http.MethodOptions, tc.url, origin, http.Header{"Access-Control-Request-Method": {"POST"}}, "")
				if r.Code != http.StatusNoContent || !allowed(r, origin) || r.Header.Get("Access-Control-Allow-Methods") != tc.methods {
					t.Errorf("%s preflight from %s: %d %v", tc.name, origin, r.Code, r.Header)
				}
			}
			if r := req(http.MethodOptions, tc.url, stranger, http.Header{"Access-Control-Request-Method": {"POST"}}, ""); !blocked(r) {
				t.Errorf("%s preflight from a stranger: %v", tc.name, r.Header)
			}
		}

		// the calls themselves
		login := func() server.Result { return c.Login(t, server.Authorize(app, "google")) }
		form := func(res server.Result) string { return server.CodeForm(app, res).Encode() }
		ct := http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}
		res := login()
		if r := req(http.MethodPost, at(config.EndpointToken), stranger, ct, form(res)); r.Code != 400 || !blocked(r) {
			t.Errorf("token from a stranger: %d %v", r.Code, r.Header)
		}
		if r := req(http.MethodPost, at(config.EndpointToken), other, ct, form(res)); r.Code != 400 || !blocked(r) || r.Tokens(t).Error != "invalid_request" {
			t.Errorf("token from another client's origin: %d %v %s", r.Code, r.Header, r.Body)
		}
		r := req(http.MethodPost, at(config.EndpointToken), own, ct, form(res)) // the code was not used up
		tk := wantTokens(t, r)
		if !allowed(r, own) {
			t.Errorf("token from the registered origin: %v", r.Header)
		}
		bearer := http.Header{"Authorization": {"Bearer " + tk.AccessToken}}
		if r := req(http.MethodGet, at(config.EndpointUserinfo), own, bearer, ""); r.Code != 200 || !allowed(r, own) {
			t.Errorf("userinfo from the registered origin: %d %v", r.Code, r.Header)
		}
		if r := req(http.MethodGet, at(config.EndpointUserinfo), stranger, bearer, ""); r.Code != 200 || !blocked(r) || r.Header.Get("Vary") != "Origin" {
			t.Errorf("userinfo from a stranger: %d %v", r.Code, r.Header)
		}
		if r := req(http.MethodGet, at(config.EndpointUserinfo), own, http.Header{"Authorization": {"Bearer nope"}}, ""); r.Code != 401 || !blocked(r) {
			t.Errorf("userinfo with a bad token: %d %v", r.Code, r.Header)
		}
		for name, u := range map[string]string{"jwks": at(config.EndpointJWKS), "discovery": e.Realm.Issuer() + "/.well-known/openid-configuration"} {
			if r := req(http.MethodGet, u, other, nil, ""); r.Code != 200 || !allowed(r, other) {
				t.Errorf("%s from a registered origin: %d %v", name, r.Code, r.Header)
			}
			if r := req(http.MethodGet, u, stranger, nil, ""); r.Code != 200 || !blocked(r) {
				t.Errorf("%s from a stranger: %d %v", name, r.Code, r.Header)
			}
		}
	})
}

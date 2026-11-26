package oidc_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/testutil/server"
	"github.com/yyudhistira/featherauth/internal/token"
)

// endSetup makes a browser with the single sign-on session on, signed in at web
// (corp) and then at frag without the provider: the browser session has two token
// sessions, A (web) and B (frag). It returns the browser and the grants of A and B.
func endSetup(t *testing.T, e *server.Env) (*server.Client, *token.Grant, *token.Grant) {
	t.Helper()
	ssoOn(t, e)
	corpUser(e, "201")
	c := e.NewClient()
	a := e.Exchange(t, server.ClientQuery, c.Login(t, server.Authorize(server.ClientQuery, "corp")))
	before := contacts(e, "corp")
	b := e.Exchange(t, server.ClientFragment, c.Login(t, server.Authorize(server.ClientFragment, "")))
	if contacts(e, "corp") != before {
		t.Fatal("the second client was not answered from the browser session")
	}
	return c, a, b
}

// refreshes reports whether the refresh token still gives tokens.
func refreshes(t *testing.T, e *server.Env, app server.App, rt string) bool {
	t.Helper()
	return post(t, e, server.RefreshForm(app, rt), nil).Code == http.StatusOK
}

// wantNextAuthorizeToProvider checks that the next authorization request of the
// browser goes to the provider, as it does once the browser session has ended.
func wantNextAuthorizeToProvider(t *testing.T, e *server.Env, c *server.Client) {
	t.Helper()
	before := contacts(e, "corp")
	c.Login(t, server.Authorize(server.ClientFragment, "corp"))
	if contacts(e, "corp") != before+1 {
		t.Fatal("the next authorization request did not go to the provider")
	}
}

// Covers: FR-45 (part), SEC-37 (part)
// Acceptance: Single sign-on end
// The browser session ends, and its row is deleted, when an RP-initiated logout
// arrives with the cookie (the cookie is cleared; without a hint no token session
// is revoked), when a token session that came from it is revoked for any reason,
// when the user is disabled or deleted or all the user's sessions are revoked, and
// when the identity is unlinked or its provider says the user is gone. Each time
// the next authorization request goes to the provider.
func TestSingleSignOnEnd(t *testing.T) {
	forEachFlowDriver(t, func(t *testing.T, o []server.Option) {
		logoutURL := func(e *server.Env) string { return e.Realm.EndpointURL(config.EndpointLogout, "") }

		t.Run("an RP-initiated logout with the cookie and no hint ends only the browser session", func(t *testing.T) {
			e := flowNew(t, o)
			c, a, b := endSetup(t, e)
			cookie := browserCookie(c)
			resp := c.Do(t, http.MethodGet, logoutURL(e), nil)
			wantCookieCleared(t, resp)
			if _, ok := browserRow(t, e, cookie); ok {
				t.Fatal("the browser session is still stored after the logout")
			}
			if !refreshes(t, e, server.ClientQuery, a.RefreshToken) || !refreshes(t, e, server.ClientFragment, b.RefreshToken) {
				t.Fatal("a logout without a hint revoked a token session")
			}
			wantNextAuthorizeToProvider(t, e, c)
		})

		t.Run("a store that cannot end the browser session fails the logout and keeps the cookie", func(t *testing.T) {
			e := flowNew(t, o)
			c, _, _ := endSetup(t, e)
			cookie := browserCookie(c)
			e.Faults.Fail("SSOSessions.Delete", context.DeadlineExceeded)
			resp := c.Do(t, http.MethodGet, logoutURL(e), nil)
			if resp.Code < 500 {
				t.Fatalf("status %d, want a server error page", resp.Code)
			}
			for _, sc := range resp.Header.Values("Set-Cookie") {
				if strings.HasPrefix(sc, "fa_sso_main=;") {
					t.Errorf("the cookie was cleared although the session was not ended: %s", sc)
				}
			}
			if _, ok := browserRow(t, e, cookie); !ok {
				t.Error("the browser session is gone after a failed logout")
			}
		})

		t.Run("an RP-initiated logout with a hint also revokes its token session, and not the other client's", func(t *testing.T) {
			e := flowNew(t, o)
			c, a, b := endSetup(t, e)
			cookie := browserCookie(c)
			resp := c.Do(t, http.MethodGet, logoutURL(e)+"?id_token_hint="+a.IDToken, nil)
			wantCookieCleared(t, resp)
			if _, ok := browserRow(t, e, cookie); ok {
				t.Fatal("the browser session is still stored after the logout")
			}
			if refreshes(t, e, server.ClientQuery, a.RefreshToken) {
				t.Fatal("the hinted token session still refreshes")
			}
			if !refreshes(t, e, server.ClientFragment, b.RefreshToken) {
				t.Fatal("the other client's token session, started from the same browser session, was revoked")
			}
			wantNextAuthorizeToProvider(t, e, c)
		})

		t.Run("a logout by refresh token from the app's own code ends the browser session", func(t *testing.T) {
			e := flowNew(t, o)
			c, a, _ := endSetup(t, e)
			cookie := browserCookie(c)
			if resp := c.Do(t, http.MethodPost, logoutURL(e), map[string][]string{"refresh_token": {a.RefreshToken}, "client_id": {"web"}}); resp.Code != http.StatusNoContent {
				t.Fatalf("refresh logout: %d", resp.Code)
			}
			if _, ok := browserRow(t, e, cookie); ok {
				t.Fatal("the browser session of the revoked token session is still stored")
			}
			wantNextAuthorizeToProvider(t, e, c)
		})

		t.Run("a logout by the refresh token of a silent use ends the browser session too", func(t *testing.T) {
			e := flowNew(t, o)
			c, _, b := endSetup(t, e)
			cookie := browserCookie(c)
			if resp := c.Do(t, http.MethodPost, logoutURL(e), map[string][]string{"refresh_token": {b.RefreshToken}, "client_id": {"frag"}}); resp.Code != http.StatusNoContent {
				t.Fatalf("refresh logout of the silent use: %d", resp.Code)
			}
			if _, ok := browserRow(t, e, cookie); ok {
				t.Fatal("the browser session of the silent use's token session is still stored")
			}
		})

		t.Run("a bearer logout ends the browser session of its token session", func(t *testing.T) {
			e := flowNew(t, o)
			c, a, _ := endSetup(t, e)
			cookie := browserCookie(c)
			resp := c.Request(t, http.MethodPost, logoutURL(e), "", http.Header{"Authorization": {"Bearer " + a.AccessToken}})
			if resp.Code != http.StatusNoContent {
				t.Fatalf("bearer logout: %d", resp.Code)
			}
			if _, ok := browserRow(t, e, cookie); ok {
				t.Fatal("the browser session of the logged out token session is still stored")
			}
			wantNextAuthorizeToProvider(t, e, c)
		})

		t.Run("the revocation endpoint ends the browser session of its token session", func(t *testing.T) {
			e := flowNew(t, o)
			c, a, _ := endSetup(t, e)
			cookie := browserCookie(c)
			resp := c.Do(t, http.MethodPost, e.Realm.EndpointURL(config.EndpointRevoke, ""),
				map[string][]string{"token": {a.RefreshToken}, "client_id": {"web"}})
			if resp.Code != http.StatusOK {
				t.Fatalf("revoke: %d %s", resp.Code, resp.Body)
			}
			if _, ok := browserRow(t, e, cookie); ok {
				t.Fatal("the browser session of the revoked token session is still stored")
			}
			wantNextAuthorizeToProvider(t, e, c)
		})

		t.Run("a refresh token reuse ends the browser session", func(t *testing.T) {
			e := flowNew(t, o)
			c, a, _ := endSetup(t, e)
			cookie := browserCookie(c)
			rotated := wantTokens(t, post(t, e, server.RefreshForm(server.ClientQuery, a.RefreshToken), nil))
			e.Clock.Advance(e.Realm.Tokens.RefreshReuseGrace.Std() + 1)
			if reused := post(t, e, server.RefreshForm(server.ClientQuery, a.RefreshToken), nil); reused.Code == http.StatusOK {
				t.Fatal("a reused refresh token after the grace window was accepted")
			}
			if _, ok := browserRow(t, e, cookie); ok {
				t.Fatal("the browser session of the reused token session is still stored")
			}
			if refreshes(t, e, server.ClientQuery, rotated.RefreshToken) {
				t.Fatal("the session of the reuse still refreshes")
			}
			wantNextAuthorizeToProvider(t, e, c)
		})

		t.Run("session revoke --session ends the browser session of that token session", func(t *testing.T) {
			e := flowNew(t, o)
			c, a, _ := endSetup(t, e)
			cookie := browserCookie(c)
			uid := store.UserID(subjectOf(t, a.AccessToken))
			if _, err := e.Users.RevokeSession(context.Background(), "admin", "main", uid, store.SessionID(decodeJWT(t, a.AccessToken).str("sid"))); err != nil {
				t.Fatal(err)
			}
			if _, ok := browserRow(t, e, cookie); ok {
				t.Fatal("the browser session of the revoked session is still stored")
			}
			wantNextAuthorizeToProvider(t, e, c)
		})

		t.Run("session revoke without --session ends every browser session of the user", func(t *testing.T) {
			e := flowNew(t, o)
			c, a, _ := endSetup(t, e)
			cookie := browserCookie(c)
			if _, err := e.Users.RevokeSessions(context.Background(), "admin", "main", store.UserID(subjectOf(t, a.AccessToken))); err != nil {
				t.Fatal(err)
			}
			if _, ok := browserRow(t, e, cookie); ok {
				t.Fatal("the browser session of the user survived the session revoke")
			}
			wantNextAuthorizeToProvider(t, e, c)
		})

		t.Run("a session logout ends the browser session of the named session", func(t *testing.T) {
			e := flowNew(t, o)
			c, a, _ := endSetup(t, e)
			e.Reload(t, func(y string) string {
				return strings.Replace(y, "  web:\n    redirect_uris: [https://app.example.com/callback]\n",
					"  web:\n    allow_session_management: true\n    redirect_uris: [https://app.example.com/callback]\n", 1)
			})
			cookie := browserCookie(c)
			sid := decodeJWT(t, a.AccessToken).str("sid")
			resp := c.Request(t, http.MethodPost, logoutURL(e), "session="+sid,
				http.Header{"Authorization": {"Bearer " + a.AccessToken}, "Content-Type": {"application/x-www-form-urlencoded"}})
			if resp.Code != http.StatusNoContent {
				t.Fatalf("session logout: %d %s", resp.Code, resp.Body)
			}
			if _, ok := browserRow(t, e, cookie); ok {
				t.Fatal("the browser session of the ended session is still stored")
			}
			wantNextAuthorizeToProvider(t, e, c)
		})

		t.Run("sign out everywhere ends every browser session of the user", func(t *testing.T) {
			e := flowNew(t, o)
			c, a, _ := endSetup(t, e)
			e.Reload(t, func(y string) string {
				return strings.Replace(y, "  web:\n    redirect_uris: [https://app.example.com/callback]\n",
					"  web:\n    allow_session_management: true\n    redirect_uris: [https://app.example.com/callback]\n", 1)
			})
			cookie := browserCookie(c)
			resp := c.Request(t, http.MethodPost, logoutURL(e), "all_sessions=true",
				http.Header{"Authorization": {"Bearer " + a.AccessToken}, "Content-Type": {"application/x-www-form-urlencoded"}})
			if resp.Code != http.StatusNoContent {
				t.Fatalf("sign out everywhere: %d %s", resp.Code, resp.Body)
			}
			if _, ok := browserRow(t, e, cookie); ok {
				t.Fatal("the browser session survived sign out everywhere")
			}
			wantNextAuthorizeToProvider(t, e, c)
		})

		t.Run("disabling the user ends the browser sessions", func(t *testing.T) {
			e := flowNew(t, o)
			c, a, _ := endSetup(t, e)
			cookie := browserCookie(c)
			e.DisableUser(t, store.UserID(subjectOf(t, a.AccessToken)), true)
			if _, ok := browserRow(t, e, cookie); ok {
				t.Fatal("the browser session of the disabled user is still stored")
			}
			wantNextAuthorizeToProvider(t, e, c)
		})

		t.Run("consent revoked for the identity ends the browser sessions of the user", func(t *testing.T) {
			e := flowNew(t, o)
			c, a, _ := endSetup(t, e)
			cookie := browserCookie(c)
			if err := e.Users.ConsentRevoked(context.Background(), "main", "corp", "201"); err != nil {
				t.Fatal(err)
			}
			if _, ok := browserRow(t, e, cookie); ok {
				t.Fatal("the browser session survived consent revoked")
			}
			if refreshes(t, e, server.ClientQuery, a.RefreshToken) {
				t.Fatal("consent revoked left a token session refreshing")
			}
			wantNextAuthorizeToProvider(t, e, c)
		})
		appleConsentRevokedEnds(t)
		appleAccountDeleteEnds(t)
		metaDeletionEnds(t)
		realmWideRevokeEnds(t, o)
	})
}

// Covers: FR-45 (part), SEC-37 (part)
// Acceptance: Single sign-on session (part)
// The phase's wiring, with the real service: one browser, two clients. The login at
// the first client, a silent login at the second client without the provider, a
// logout from the first client's own code, and the next authorization request of
// the second client goes to the provider.
func TestSingleSignOnWiring(t *testing.T) {
	forEachFlowDriver(t, func(t *testing.T, o []server.Option) {
		e := flowNew(t, o)
		ssoOn(t, e)
		corpUser(e, "201")
		c := e.NewClient()
		web := e.Exchange(t, server.ClientQuery, c.Login(t, server.Authorize(server.ClientQuery, "corp")))
		before := contacts(e, "corp")
		frag := c.Login(t, server.Authorize(server.ClientFragment, "", "prompt", "none"))
		if frag.Values.Get("code") == "" || contacts(e, "corp") != before {
			t.Fatalf("silent login at the second client: %v", frag.Values)
		}
		fragTokens := e.Exchange(t, server.ClientFragment, frag)
		if subjectOf(t, fragTokens.AccessToken) != subjectOf(t, web.AccessToken) {
			t.Fatal("the silent login is for another user")
		}
		logout := e.Realm.EndpointURL(config.EndpointLogout, "")
		if resp := c.Do(t, http.MethodPost, logout, map[string][]string{"refresh_token": {web.RefreshToken}, "client_id": {"web"}}); resp.Code != http.StatusNoContent {
			t.Fatalf("logout from the first client's code: %d", resp.Code)
		}
		if none := c.Login(t, server.Authorize(server.ClientFragment, "", "prompt", "none")); none.Values.Get("error") != "login_required" {
			t.Fatalf("prompt=none after the logout: %v", none.Values)
		}
		wantNextAuthorizeToProvider(t, e, c)
	})
}

// realmWideRevokeEnds is the realm-wide revocation: every browser session of the
// realm ends, of every user.
func realmWideRevokeEnds(t *testing.T, o []server.Option) {
	t.Helper()
	e := flowNew(t, o)
	c, _, _ := endSetup(t, e)
	cookie := browserCookie(c)
	if _, err := e.Users.RevokeRealmSessions(context.Background(), "admin", "main"); err != nil {
		t.Fatal(err)
	}
	if _, ok := browserRow(t, e, cookie); ok {
		t.Fatal("the browser session survived the realm-wide revocation")
	}
	wantNextAuthorizeToProvider(t, e, c)
}

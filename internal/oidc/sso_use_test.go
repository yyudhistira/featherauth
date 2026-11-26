package oidc_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/secure"
	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/testutil/mockidp"
	"github.com/yyudhistira/featherauth/internal/testutil/server"
	"github.com/yyudhistira/featherauth/internal/user"
)

// ssoOn turns the single sign-on session of the realm main on.
func ssoOn(t *testing.T, e *server.Env) {
	t.Helper()
	e.Reload(t, func(y string) string {
		return strings.Replace(y, "name: main\n", "name: main\nsso:\n  enabled: true\n", 1)
	})
}

// corpUser makes the mock provider "corp" sign in the person with this sub.
func corpUser(e *server.Env, sub string) {
	e.Mocks["corp"].SetUser(mockidp.User{Sub: sub, Name: "Ann Lee", Email: "ann@example.com", EmailVerified: true,
		Emails: []mockidp.Email{{Email: "ann@example.com", Primary: true, Verified: true}}})
}

// contacts counts the authorization requests the mock provider has had.
func contacts(e *server.Env, key string) int { return len(e.Mocks[key].Authorizations()) }

// browserCookie is the single sign-on cookie of the browser, or "".
func browserCookie(c *server.Client) string {
	for _, ck := range c.Cookies() {
		if ck.Name == "fa_sso_main" {
			return ck.Value
		}
	}
	return ""
}

// browserRow reads the stored browser session of the cookie value in realm main.
func browserRow(t *testing.T, e *server.Env, value string) (store.SSOSession, bool) {
	t.Helper()
	var row store.SSOSession
	var found bool
	err := e.Store.Read(context.Background(), func(tx store.Tx) error {
		rid, err := tx.Realms().Find(context.Background(), "main")
		if err != nil {
			return err
		}
		row, err = tx.SSOSessions().Find(context.Background(), rid, secure.HashOf(value))
		found = err == nil
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return row, found
}

// wantCookieCleared checks that the answer deletes the single sign-on cookie of
// the realm main: an expired cookie of the same name and path.
func wantCookieCleared(t *testing.T, r server.Response) {
	t.Helper()
	for _, sc := range r.Header.Values("Set-Cookie") {
		if strings.HasPrefix(sc, "fa_sso_main=;") && strings.Contains(sc, "Max-Age=0") && strings.Contains(sc, "Path=/main") {
			return
		}
	}
	t.Errorf("the browser session cookie is not cleared: %v", r.Header.Values("Set-Cookie"))
}

// wantCookieSet checks that the answer sets the browser session cookie again with
// the value, the realm's path, the idle lifetime as Max-Age and the attributes of
// SEC-37.
func wantCookieSet(t *testing.T, r server.Response, value string) {
	t.Helper()
	for _, sc := range r.Header.Values("Set-Cookie") {
		if strings.HasPrefix(sc, "fa_sso_main="+value+";") && strings.Contains(sc, "Max-Age=28800") &&
			strings.Contains(sc, "Path=/main") && strings.Contains(sc, "HttpOnly") && strings.Contains(sc, "Secure") &&
			strings.Contains(sc, "SameSite=Lax") {
			return
		}
	}
	t.Errorf("the browser session cookie is not set again: %v", r.Header.Values("Set-Cookie"))
}

// fragmentValues reads the values of a redirect whose result is in the fragment.
func fragmentValues(t *testing.T, location string) url.Values {
	t.Helper()
	_, frag, ok := strings.Cut(location, "#")
	if !ok {
		t.Fatalf("no fragment in %s", location)
	}
	v, err := url.ParseQuery(frag)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// subjectOf is the sub claim of a token.
func subjectOf(t *testing.T, raw string) string {
	t.Helper()
	return decodeJWT(t, raw).str("sub")
}

// firstLogin makes the first login of a fresh browser at corp, with the single
// sign-on session on. The code is returned unexchanged: the test trades it once.
func firstLogin(t *testing.T, e *server.Env) (*server.Client, server.Result) {
	t.Helper()
	c := e.NewClient()
	res := c.Login(t, server.Authorize(server.ClientQuery, "corp"))
	if res.Values.Get("code") == "" {
		t.Fatalf("the first login gave no code: %v", res.Values)
	}
	return c, res
}

// Covers: FR-45 (part), SEC-37 (part)
// Acceptance: Single sign-on session
// The conditions of Use: a usable browser session answers the request with a code,
// without the chooser and without the provider; every other request goes to the
// provider, and a cookie that names no usable session is deleted.
func TestSingleSignOnSessionUse(t *testing.T) {
	forEachFlowDriver(t, func(t *testing.T, o []server.Option) {
		t.Run("a second client from the same browser gets a code with no provider contact", func(t *testing.T) {
			e := flowNew(t, o)
			ssoOn(t, e)
			corpUser(e, "201")
			c, first := firstLogin(t, e)
			firstAuth := decodeJWT(t, e.Exchange(t, server.ClientQuery, first).IDToken).unix("auth_time")
			before := contacts(e, "corp")
			e.Clock.Advance(time.Minute)
			resp := c.Do(t, http.MethodGet, e.Realm.EndpointURL(config.EndpointAuthorize, "")+"?"+server.Authorize(server.ClientFragment, "").Encode(), nil)
			if resp.Code != http.StatusFound || !strings.Contains(resp.Header.Get("Location"), "#") {
				t.Fatalf("second request: %d %s", resp.Code, resp.Header.Get("Location"))
			}
			wantCookieSet(t, resp, browserCookie(c))
			if storesValue(t, e.DatabasePath, browserCookie(c)) {
				t.Error("the browser session cookie value is stored in the database")
			}
			second := server.Result{Mode: "fragment", Values: fragmentValues(t, resp.Header.Get("Location"))}
			if second.Values.Get("code") == "" {
				t.Fatalf("second request gave no code: %v", second.Values)
			}
			if got := contacts(e, "corp"); got != before {
				t.Fatalf("the provider was contacted %d times for a usable session", got-before)
			}
			idt := decodeJWT(t, e.Exchange(t, server.ClientFragment, second).IDToken)
			if !idt.unix("auth_time").Equal(firstAuth) {
				t.Errorf("auth_time = %v, want the first login's %v", idt.unix("auth_time"), firstAuth)
			}
			if idt.str("sid") == "" {
				t.Error("the new token session has no sid")
			}
			row, ok := browserRow(t, e, browserCookie(c))
			if !ok || !row.LastUsedAt.Equal(e.Clock.Now()) || !row.ExpiresAt.Equal(e.Clock.Now().Add(8*time.Hour)) {
				t.Errorf("row after the use = %+v, want last use now and expiry now+8h", row)
			}
		})

		t.Run("a use moves the expiry on, but not past the maximum lifetime", func(t *testing.T) {
			e := flowNew(t, o)
			e.Reload(t, func(y string) string {
				return strings.Replace(y, "name: main\n", "name: main\nsso:\n  enabled: true\n  max_lifetime: 1h\n", 1)
			})
			corpUser(e, "201")
			c, _ := firstLogin(t, e)
			created := e.Clock.Now()
			cookie := browserCookie(c)
			e.Clock.Advance(30 * time.Minute)
			if res := c.Login(t, server.Authorize(server.ClientFragment, "")); res.Values.Get("code") == "" {
				t.Fatalf("the use gave no code: %v", res.Values)
			}
			row, ok := browserRow(t, e, cookie)
			if !ok || !row.ExpiresAt.Equal(created.Add(time.Hour)) || !row.LastUsedAt.Equal(e.Clock.Now()) {
				t.Fatalf("row after the use = %+v, want the expiry at the maximum (%v) and the last use now", row, created.Add(time.Hour))
			}
		})

		t.Run("prompt login, select_account and consent go to the provider", func(t *testing.T) {
			e := flowNew(t, o)
			ssoOn(t, e)
			corpUser(e, "201")
			c, _ := firstLogin(t, e)
			for _, p := range []string{"login", "select_account", "consent"} {
				before := contacts(e, "corp")
				c.Login(t, server.Authorize(server.ClientFragment, "corp", "prompt", p))
				if contacts(e, "corp") != before+1 {
					t.Errorf("prompt=%s did not go to the provider", p)
				}
			}
		})

		t.Run("max_age is compared with the session's age", func(t *testing.T) {
			e := flowNew(t, o)
			ssoOn(t, e)
			corpUser(e, "201")
			c, _ := firstLogin(t, e)
			e.Clock.Advance(time.Minute)
			before := contacts(e, "corp")
			if res := c.Login(t, server.Authorize(server.ClientFragment, "", "max_age", "120")); res.Values.Get("code") == "" {
				t.Fatalf("max_age 120 with a session of 60s: %v", res.Values)
			}
			if contacts(e, "corp") != before {
				t.Fatal("a max_age not less than the session's age went to the provider")
			}
			c.Login(t, server.Authorize(server.ClientFragment, "corp", "max_age", "30"))
			if contacts(e, "corp") != before+1 {
				t.Fatal("a max_age less than the session's age did not go to the provider")
			}
		})

		t.Run("a provider hint for another provider goes to that provider", func(t *testing.T) {
			e := flowNew(t, o)
			ssoOn(t, e)
			corpUser(e, "201")
			e.Mocks["google"].SetUser(mockidp.User{Sub: "g-201", Name: "Ann Lee", Email: "ann@example.com", EmailVerified: true})
			c, _ := firstLogin(t, e)
			beforeCorp, beforeGoogle := contacts(e, "corp"), contacts(e, "google")
			c.Login(t, server.Authorize(server.ClientFragment, "google"))
			if contacts(e, "google") != beforeGoogle+1 || contacts(e, "corp") != beforeCorp {
				t.Fatal("a hint for another provider did not go to that provider alone")
			}
		})

		t.Run("login_hint plays no part", func(t *testing.T) {
			e := flowNew(t, o)
			ssoOn(t, e)
			corpUser(e, "201")
			c, _ := firstLogin(t, e)
			before := contacts(e, "corp")
			res := c.Login(t, server.Authorize(server.ClientFragment, "", "login_hint", "someone@else.example"))
			if res.Values.Get("code") == "" || contacts(e, "corp") != before {
				t.Fatalf("login_hint: %v, provider contacts %d", res.Values, contacts(e, "corp")-before)
			}
		})

		t.Run("an id_token_hint of another user is ignored without prompt=none", func(t *testing.T) {
			e := flowNew(t, o)
			ssoOn(t, e)
			corpUser(e, "201")
			c, first := firstLogin(t, e)
			ownSub := subjectOf(t, e.Exchange(t, server.ClientQuery, first).IDToken)
			corpUser(e, "202")
			otherHint := e.Exchange(t, server.ClientQuery, e.NewClient().Login(t, server.Authorize(server.ClientQuery, "corp"))).IDToken
			corpUser(e, "201")
			before := contacts(e, "corp")
			res := c.Login(t, server.Authorize(server.ClientFragment, "", "id_token_hint", otherHint))
			if res.Values.Get("code") == "" || contacts(e, "corp") != before {
				t.Fatalf("hint of another user: %v, provider contacts %d", res.Values, contacts(e, "corp")-before)
			}
			if sub := subjectOf(t, e.Exchange(t, server.ClientFragment, res).IDToken); sub != ownSub {
				t.Errorf("the code is for sub %q, want the session's user %q", sub, ownSub)
			}
		})

		t.Run("a form POST without the cookie goes to the provider", func(t *testing.T) {
			e := flowNew(t, o)
			ssoOn(t, e)
			corpUser(e, "201")
			firstLogin(t, e)
			bare := e.NewClient()
			resp := bare.Request(t, http.MethodPost, e.Realm.EndpointURL(config.EndpointAuthorize, ""),
				server.Authorize(server.ClientFragment, "corp").Encode(),
				http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
			if resp.Code != http.StatusFound || !strings.HasPrefix(resp.Header.Get("Location"), e.Mocks["corp"].URL()) {
				t.Fatalf("POST without the cookie: %d %s", resp.Code, resp.Header.Get("Location"))
			}
		})

		t.Run("a client with sso false goes to the provider", func(t *testing.T) {
			e := flowNew(t, o)
			ssoOn(t, e)
			e.Reload(t, func(y string) string {
				return strings.Replace(y, "  frag:\n    response_mode: fragment\n", "  frag:\n    sso: false\n    response_mode: fragment\n", 1)
			})
			corpUser(e, "201")
			c, _ := firstLogin(t, e)
			before := contacts(e, "corp")
			c.Login(t, server.Authorize(server.ClientFragment, "corp"))
			if contacts(e, "corp") != before+1 {
				t.Fatal("a client with sso false was answered from the browser session")
			}
		})

		t.Run("after sso.idle_lifetime without use the session is not used", func(t *testing.T) {
			e := flowNew(t, o)
			ssoOn(t, e)
			corpUser(e, "201")
			c, _ := firstLogin(t, e)
			e.Clock.Advance(8*time.Hour + time.Second)
			before := contacts(e, "corp")
			c.Login(t, server.Authorize(server.ClientFragment, "corp"))
			if contacts(e, "corp") != before+1 {
				t.Fatal("an idle session was used")
			}
		})

		t.Run("the session of an identity the user no longer holds goes to the provider", func(t *testing.T) {
			e := flowNew(t, o)
			ssoOn(t, e)
			corpUser(e, "201")
			c, res := firstLogin(t, e)
			sub := subjectOf(t, e.Exchange(t, server.ClientQuery, res).AccessToken)
			if err := e.Users.Unlink(context.Background(), "admin", "main", store.UserID(sub), "corp", "201"); err != nil {
				t.Fatal(err)
			}
			before := contacts(e, "corp")
			c.Login(t, server.Authorize(server.ClientFragment, "corp"))
			if contacts(e, "corp") != before+1 {
				t.Fatal("a session whose identity was unlinked was used")
			}
		})

		t.Run("a disabled user goes to the provider", func(t *testing.T) {
			e := flowNew(t, o)
			ssoOn(t, e)
			corpUser(e, "201")
			c, res := firstLogin(t, e)
			e.DisableUser(t, store.UserID(subjectOf(t, e.Exchange(t, server.ClientQuery, res).AccessToken)), true)
			before := contacts(e, "corp")
			c.Login(t, server.Authorize(server.ClientFragment, "corp"))
			if contacts(e, "corp") != before+1 {
				t.Fatal("a disabled user's session was used")
			}
		})

		t.Run("a deleted user goes to the provider", func(t *testing.T) {
			e := flowNew(t, o)
			ssoOn(t, e)
			corpUser(e, "201")
			c, res := firstLogin(t, e)
			uid := subjectOf(t, e.Exchange(t, server.ClientQuery, res).AccessToken)
			if err := e.Users.Delete(context.Background(), "admin", "main", store.UserID(uid), user.DeleteOptions{}); err != nil {
				t.Fatal(err)
			}
			before := contacts(e, "corp")
			c.Login(t, server.Authorize(server.ClientFragment, "corp"))
			if contacts(e, "corp") != before+1 {
				t.Fatal("a deleted user's session was used")
			}
		})

		t.Run("the cookie path of the Keycloak-style layout is the common directory of its paths", func(t *testing.T) {
			e := flowNew(t, o, server.WithServerSetting(keycloakServerYAML))
			ssoOn(t, e)
			corpUser(e, "201")
			c := e.NewClient()
			res := c.Login(t, server.Authorize(server.ClientQuery, "corp", "kc_idp_hint", "corp"))
			if res.Values.Get("code") == "" {
				t.Fatalf("the keycloak-style login gave no code: %v", res.Values)
			}
			resp := c.Do(t, http.MethodGet, e.Realm.EndpointURL(config.EndpointAuthorize, "")+"?"+server.Authorize(server.ClientFragment, "").Encode(), nil)
			var path string
			for _, sc := range resp.Header.Values("Set-Cookie") {
				if strings.HasPrefix(sc, "fa_sso_main=") {
					for _, part := range strings.Split(sc, ";") {
						if strings.HasPrefix(strings.TrimSpace(part), "Path=") {
							path = strings.TrimSpace(part)
						}
					}
				}
			}
			if path != "Path=/realms/main/protocol/openid-connect" {
				t.Fatalf("the cookie path is %q, want the common directory of the authorize and logout paths", path)
			}
		})

		t.Run("a provider disabled since the login is not used", func(t *testing.T) {
			e := flowNew(t, o)
			ssoOn(t, e)
			corpUser(e, "201")
			c, _ := firstLogin(t, e)
			e.Reload(t, func(y string) string {
				return strings.Replace(y, "    type: oidc\n    enabled: true\n    display_name: Corp", "    type: oidc\n    enabled: false\n    display_name: Corp", 1)
			})
			before := contacts(e, "corp")
			resp := c.Do(t, http.MethodGet, e.Realm.EndpointURL(config.EndpointAuthorize, "")+"?"+server.Authorize(server.ClientFragment, "").Encode(), nil)
			if resp.Code != http.StatusOK || contacts(e, "corp") != before {
				t.Fatalf("a disabled provider's session was used: status %d", resp.Code)
			}
		})

		t.Run("a cookie that names no session is deleted and the request goes on", func(t *testing.T) {
			e := flowNew(t, o)
			ssoOn(t, e)
			corpUser(e, "201")
			resp := e.NewClient().Request(t, http.MethodGet, e.Realm.EndpointURL(config.EndpointAuthorize, "")+"?"+server.Authorize(server.ClientFragment, "corp").Encode(), "",
				http.Header{"Cookie": {"fa_sso_main=not-a-session"}})
			wantCookieCleared(t, resp)
			if resp.Code != http.StatusFound || !strings.HasPrefix(resp.Header.Get("Location"), e.Mocks["corp"].URL()) {
				t.Fatalf("the request did not go on to the provider: %d", resp.Code)
			}
		})

		t.Run("a store that cannot read the session gives server_error and no code", func(t *testing.T) {
			e := flowNew(t, o)
			ssoOn(t, e)
			corpUser(e, "201")
			c, _ := firstLogin(t, e)
			e.Faults.Fail("SSOSessions.Find", context.DeadlineExceeded)
			before := contacts(e, "corp")
			res := c.Login(t, server.Authorize(server.ClientFragment, ""))
			if res.Values.Get("error") != "server_error" || res.Values.Has("code") || contacts(e, "corp") != before {
				t.Fatalf("a failing read: %v, provider contacts %d", res.Values, contacts(e, "corp")-before)
			}
		})

		t.Run("a store that cannot issue the code gives server_error and moves nothing on", func(t *testing.T) {
			e := flowNew(t, o)
			ssoOn(t, e)
			corpUser(e, "201")
			c, _ := firstLogin(t, e)
			cookie := browserCookie(c)
			row, _ := browserRow(t, e, cookie)
			e.Faults.Fail("AuthCodes.Create", context.DeadlineExceeded)
			res := c.Login(t, server.Authorize(server.ClientFragment, ""))
			if res.Values.Get("error") != "server_error" || res.Values.Has("code") {
				t.Fatalf("a failing code issue: %v", res.Values)
			}
			if after, _ := browserRow(t, e, cookie); !after.LastUsedAt.Equal(row.LastUsedAt) {
				t.Error("the browser session moved on although no code was issued")
			}
		})

		t.Run("a store that cannot move the session on gives server_error and no code", func(t *testing.T) {
			e := flowNew(t, o)
			ssoOn(t, e)
			corpUser(e, "201")
			c, _ := firstLogin(t, e)
			e.Faults.Fail("SSOSessions.Touch", context.DeadlineExceeded)
			res := c.Login(t, server.Authorize(server.ClientFragment, ""))
			if res.Values.Get("error") != "server_error" || res.Values.Has("code") {
				t.Fatalf("a failing touch: %v", res.Values)
			}
		})

		t.Run("with sso.enabled false a cookie is ignored and deleted", func(t *testing.T) {
			e := flowNew(t, o)
			corpUser(e, "201")
			resp := e.NewClient().Request(t, http.MethodGet, e.Realm.EndpointURL(config.EndpointAuthorize, "")+"?"+server.Authorize(server.ClientFragment, "corp").Encode(), "",
				http.Header{"Cookie": {"fa_sso_main=anything"}})
			wantCookieCleared(t, resp)
		})
		unusableCases(t, o)
		requestConditionCases(t, o)
		ssoFalseSecondClientCase(t, o)
		sessionBoundaryCases(t, o)
	})
}

// Covers: FR-45 (part), SEC-37 (part)
// Acceptance: Silent login
// prompt=none: a usable browser session answers with a code, without one
// login_required; an id_token_hint of another user gives login_required; a hint
// that does not verify is ignored; with sso.enabled false it is login_required.
func TestSilentLoginRows(t *testing.T) {
	forEachFlowDriver(t, func(t *testing.T, o []server.Option) {
		t.Run("a usable session gives a code, with no provider contact", func(t *testing.T) {
			e := flowNew(t, o)
			ssoOn(t, e)
			corpUser(e, "201")
			c, _ := firstLogin(t, e)
			before := contacts(e, "corp")
			res := c.Login(t, server.Authorize(server.ClientFragment, "", "prompt", "none"))
			if res.Values.Get("code") == "" || contacts(e, "corp") != before {
				t.Fatalf("prompt=none with a session: %v, provider contacts %d", res.Values, contacts(e, "corp")-before)
			}
		})

		t.Run("without a session it is login_required, with no provider contact", func(t *testing.T) {
			e := flowNew(t, o)
			ssoOn(t, e)
			corpUser(e, "201")
			before := contacts(e, "corp")
			res := e.NewClient().Login(t, server.Authorize(server.ClientQuery, "corp", "prompt", "none"))
			if res.Values.Get("error") != "login_required" || res.Values.Has("code") || contacts(e, "corp") != before {
				t.Fatalf("prompt=none without a session: %v", res.Values)
			}
		})

		t.Run("an id_token_hint of the same user gives a code", func(t *testing.T) {
			e := flowNew(t, o)
			ssoOn(t, e)
			corpUser(e, "201")
			c, first := firstLogin(t, e)
			hint := e.Exchange(t, server.ClientQuery, first).IDToken
			res := c.Login(t, server.Authorize(server.ClientFragment, "", "prompt", "none", "id_token_hint", hint))
			if res.Values.Get("code") == "" {
				t.Fatalf("the same user's hint: %v", res.Values)
			}
		})

		t.Run("an id_token_hint of another user gives login_required", func(t *testing.T) {
			e := flowNew(t, o)
			ssoOn(t, e)
			corpUser(e, "201")
			c, _ := firstLogin(t, e)
			corpUser(e, "202")
			hint := e.Exchange(t, server.ClientQuery, e.NewClient().Login(t, server.Authorize(server.ClientQuery, "corp"))).IDToken
			corpUser(e, "201")
			before := contacts(e, "corp")
			res := c.Login(t, server.Authorize(server.ClientFragment, "", "prompt", "none", "id_token_hint", hint))
			if res.Values.Get("error") != "login_required" || res.Values.Has("code") || contacts(e, "corp") != before {
				t.Fatalf("another user's hint: %v", res.Values)
			}
		})

		t.Run("a hint that does not verify is ignored", func(t *testing.T) {
			e := flowNew(t, o)
			ssoOn(t, e)
			corpUser(e, "201")
			c, _ := firstLogin(t, e)
			res := c.Login(t, server.Authorize(server.ClientFragment, "", "prompt", "none", "id_token_hint", "not.a.token"))
			if res.Values.Get("code") == "" {
				t.Fatalf("an unverifiable hint changed the answer: %v", res.Values)
			}
		})

		t.Run("with sso.enabled false it is login_required", func(t *testing.T) {
			e := flowNew(t, o)
			corpUser(e, "201")
			c := e.NewClient()
			c.Login(t, server.Authorize(server.ClientQuery, "corp"))
			res := c.Login(t, server.Authorize(server.ClientFragment, "", "prompt", "none"))
			if res.Values.Get("error") != "login_required" {
				t.Fatalf("prompt=none with sso.enabled false: %v", res.Values)
			}
		})
		deletedBeforeCodeCase(t, o)
	})
}

package oidc_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/testutil/mockidp"
	"github.com/yyudhistira/featherauth/internal/testutil/server"
)

// toProvider checks that the one-hop answer of an authorization request is a
// redirect to the mock provider key: the request went on to the provider unchanged.
func toProvider(t *testing.T, e *server.Env, r server.Response, key string) {
	t.Helper()
	if r.Code != http.StatusFound || !strings.HasPrefix(r.Header.Get("Location"), e.Mocks[key].URL()) {
		t.Fatalf("the request did not go to the provider %s: %d %s", key, r.Code, r.Header.Get("Location"))
	}
}

// keepsCookie checks that the answer neither sets nor clears the browser session
// cookie.
func keepsCookie(t *testing.T, r server.Response) {
	t.Helper()
	for _, sc := range r.Header.Values("Set-Cookie") {
		if strings.HasPrefix(sc, "fa_sso_main=") {
			t.Fatalf("the browser session cookie was changed by a request it does not apply to: %s", sc)
		}
	}
}

// userDirect changes the stored user with the store, bypassing the manager and
// with it the End paths: a raw write the use-time checks must still refuse.
func userDirect(t *testing.T, e *server.Env, uid store.UserID, change func(*store.User)) {
	t.Helper()
	ctx := context.Background()
	err := e.Store.Write(ctx, func(tx store.Tx) error {
		rid, err := tx.Realms().Find(ctx, "main")
		if err != nil {
			return err
		}
		u, err := tx.Users().Get(ctx, rid, uid)
		if err != nil {
			return err
		}
		change(&u)
		return tx.Users().Update(ctx, u)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// userIDOf is the stored user id of the login's code.
func userIDOf(t *testing.T, e *server.Env, res server.Result) store.UserID {
	t.Helper()
	return store.UserID(subjectOf(t, e.Exchange(t, server.ClientQuery, res).AccessToken))
}

// Covers: FR-45 (part), SEC-37 (part)
// Acceptance: Single sign-on session (part)
// A browser session that cannot be used by itself is refused at use time, whatever
// ended it: the request goes to the provider and the cookie is deleted. The
// checks run on rows changed directly in the store, so the End paths do not
// delete the session first.
func unusableCases(t *testing.T, o []server.Option) {
	{
		t.Run("a disabled user", func(t *testing.T) {
			e := flowNew(t, o)
			ssoOn(t, e)
			corpUser(e, "201")
			c, res := firstLogin(t, e)
			userDirect(t, e, userIDOf(t, e, res), func(u *store.User) { u.DisabledAt = e.Clock.Now() })
			r := c.Do(t, http.MethodGet, e.Realm.EndpointURL(config.EndpointAuthorize, "")+"?"+server.Authorize(server.ClientFragment, "corp").Encode(), nil)
			toProvider(t, e, r, "corp")
			wantCookieCleared(t, r)
		})
		t.Run("a missing user", func(t *testing.T) {
			e := flowNew(t, o)
			ssoOn(t, e)
			corpUser(e, "201")
			c, _ := firstLogin(t, e)
			e.Faults.Fail("Users.Get", store.ErrNotFound)
			r := c.Do(t, http.MethodGet, e.Realm.EndpointURL(config.EndpointAuthorize, "")+"?"+server.Authorize(server.ClientFragment, "corp").Encode(), nil)
			toProvider(t, e, r, "corp")
			wantCookieCleared(t, r)
		})
		t.Run("a missing identity", func(t *testing.T) {
			e := flowNew(t, o)
			ssoOn(t, e)
			corpUser(e, "201")
			c, _ := firstLogin(t, e)
			ident, err := identityOf(t, e, "corp", "201")
			if err != nil {
				t.Fatal(err)
			}
			if err := e.Store.Write(context.Background(), func(tx store.Tx) error {
				rid, err := tx.Realms().Find(context.Background(), "main")
				if err != nil {
					return err
				}
				return tx.Identities().Delete(context.Background(), rid, ident.ID)
			}); err != nil {
				t.Fatal(err)
			}
			r := c.Do(t, http.MethodGet, e.Realm.EndpointURL(config.EndpointAuthorize, "")+"?"+server.Authorize(server.ClientFragment, "corp").Encode(), nil)
			toProvider(t, e, r, "corp")
			wantCookieCleared(t, r)
		})
		t.Run("a provider disabled since the login", func(t *testing.T) {
			e := flowNew(t, o)
			ssoOn(t, e)
			corpUser(e, "201")
			c, _ := firstLogin(t, e)
			e.Reload(t, func(y string) string {
				return strings.Replace(y, "    type: oidc\n    enabled: true\n    display_name: Corp", "    type: oidc\n    enabled: false\n    display_name: Corp", 1)
			})
			r := c.Do(t, http.MethodGet, e.Realm.EndpointURL(config.EndpointAuthorize, "")+"?"+server.Authorize(server.ClientFragment, "").Encode(), nil)
			wantCookieCleared(t, r)
			if r.Header.Get("Location") != "" && strings.Contains(r.Header.Get("Location"), "code=") {
				t.Fatal("a code was issued from a disabled provider's session")
			}
		})
		t.Run("sso.enabled reloaded to false with a real cookie: provider path, cookie cleared, no code", func(t *testing.T) {
			e := flowNew(t, o)
			ssoOn(t, e)
			corpUser(e, "201")
			c, _ := firstLogin(t, e)
			cookie := browserCookie(c)
			e.Reload(t, func(y string) string { return strings.Replace(y, "sso:\n  enabled: true\n", "", 1) })
			r := c.Do(t, http.MethodGet, e.Realm.EndpointURL(config.EndpointAuthorize, "")+"?"+server.Authorize(server.ClientFragment, "corp").Encode(), nil)
			toProvider(t, e, r, "corp")
			wantCookieCleared(t, r)
			if strings.Contains(r.Header.Get("Location"), "code=") {
				t.Fatal("a code was issued with sso.enabled false")
			}
			if cookie == "" {
				t.Fatal("the first login set no cookie")
			}
		})
		t.Run("an expired session (now equal to its expiry)", func(t *testing.T) {
			e := flowNew(t, o)
			ssoOn(t, e)
			corpUser(e, "201")
			c, _ := firstLogin(t, e)
			e.Clock.Advance(8 * time.Hour)
			r := c.Do(t, http.MethodGet, e.Realm.EndpointURL(config.EndpointAuthorize, "")+"?"+server.Authorize(server.ClientFragment, "corp").Encode(), nil)
			toProvider(t, e, r, "corp")
			wantCookieCleared(t, r)
		})
	}
}

// Covers: FR-45 (part), SEC-37 (part)
// Acceptance: Single sign-on session (part)
// A request whose own conditions rule the session out (the client's sso, the
// prompt, max_age, a hint naming another provider) goes on to the provider as without a session,
// and leaves the browser session and its cookie alone. Another client of the same
// browser keeps its silent login.
func requestConditionCases(t *testing.T, o []server.Option) {
	{
		cases := []struct {
			name   string
			change func(e *server.Env)
			req    func() []string
			clock  time.Duration
			mock   string
		}{
			{"the client has sso false", func(e *server.Env) {
				e.Reload(t, func(y string) string {
					return strings.Replace(y, "  frag:\n    response_mode: fragment\n", "  frag:\n    sso: false\n    response_mode: fragment\n", 1)
				})
			}, func() []string { return []string{"provider", "corp"} }, 0, "corp"},
			{"prompt=login", nil, func() []string { return []string{"provider", "corp", "prompt", "login"} }, 0, "corp"},
			{"prompt=select_account", nil, func() []string { return []string{"provider", "corp", "prompt", "select_account"} }, 0, "corp"},
			{"prompt=consent", nil, func() []string { return []string{"provider", "corp", "prompt", "consent"} }, 0, "corp"},
			{"max_age exceeds the session's age", nil, func() []string { return []string{"provider", "corp", "max_age", "30"} }, time.Minute, "corp"},
			{"a hint naming another provider", func(e *server.Env) {
				e.Mocks["google"].SetUser(mockidp.User{Sub: "g-201", Name: "Ann Lee", Email: "ann@example.com", EmailVerified: true})
			}, func() []string { return []string{"provider", "google"} }, 0, "google"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				e := flowNew(t, o)
				ssoOn(t, e)
				corpUser(e, "201")
				c, _ := firstLogin(t, e)
				cookie := browserCookie(c)
				if tc.change != nil {
					tc.change(e)
				}
				e.Clock.Advance(tc.clock)
				r := c.Do(t, http.MethodGet, e.Realm.EndpointURL(config.EndpointAuthorize, "")+"?"+server.Authorize(server.ClientFragment, "", tc.req()...).Encode(), nil)
				toProvider(t, e, r, tc.mock)
				keepsCookie(t, r)
				if _, ok := browserRow(t, e, cookie); !ok {
					t.Fatal("the browser session was ended by a request it does not apply to")
				}
			})
		}
	}
}

// Covers: FR-45 (part), SEC-37 (part)
// Acceptance: Single sign-on session (part)
// The client with sso false does not end the browser session: a second client of
// the same browser still gets its silent login.
func ssoFalseSecondClientCase(t *testing.T, o []server.Option) {
	{
		e := flowNew(t, o)
		ssoOn(t, e)
		corpUser(e, "201")
		c, _ := firstLogin(t, e)
		e.Reload(t, func(y string) string {
			return strings.Replace(y, "  frag:\n    response_mode: fragment\n", "  frag:\n    sso: false\n    response_mode: fragment\n", 1)
		})
		c.Login(t, server.Authorize(server.ClientFragment, "corp"))
		before := contacts(e, "corp")
		res := c.Login(t, server.Authorize(server.ClientQuery, "", "prompt", "none"))
		if res.Values.Get("code") == "" || contacts(e, "corp") != before {
			t.Fatalf("the second client lost its silent login after an sso false request: %v", res.Values)
		}
	}
}

// Covers: FR-45 (part), SEC-37 (part)
// Acceptance: Single sign-on session (part)
// The boundaries of the rules: a session is expired at exactly its expiry, a
// max_age equal to the session's age is used and one less is not.
func sessionBoundaryCases(t *testing.T, o []server.Option) {
	{
		t.Run("one second before the idle expiry is still usable", func(t *testing.T) {
			e := flowNew(t, o)
			ssoOn(t, e)
			corpUser(e, "201")
			c, _ := firstLogin(t, e)
			e.Clock.Advance(8*time.Hour - time.Second)
			before := contacts(e, "corp")
			if res := c.Login(t, server.Authorize(server.ClientFragment, "")); res.Values.Get("code") == "" || contacts(e, "corp") != before {
				t.Fatalf("one second before the expiry: %v", res.Values)
			}
		})
		t.Run("now equal to the idle expiry is expired", func(t *testing.T) {
			e := flowNew(t, o)
			ssoOn(t, e)
			corpUser(e, "201")
			c, _ := firstLogin(t, e)
			e.Clock.Advance(8 * time.Hour)
			before := contacts(e, "corp")
			c.Login(t, server.Authorize(server.ClientFragment, "corp"))
			if contacts(e, "corp") != before+1 {
				t.Fatal("a session at exactly its expiry was used")
			}
		})
		t.Run("a max_age equal to the session's age is used", func(t *testing.T) {
			e := flowNew(t, o)
			ssoOn(t, e)
			corpUser(e, "201")
			c, _ := firstLogin(t, e)
			e.Clock.Advance(time.Minute)
			before := contacts(e, "corp")
			if res := c.Login(t, server.Authorize(server.ClientFragment, "", "max_age", "60")); res.Values.Get("code") == "" || contacts(e, "corp") != before {
				t.Fatalf("max_age equal to the age: %v", res.Values)
			}
		})
		t.Run("a max_age one second less than the session's age is not used", func(t *testing.T) {
			e := flowNew(t, o)
			ssoOn(t, e)
			corpUser(e, "201")
			c, _ := firstLogin(t, e)
			e.Clock.Advance(time.Minute)
			before := contacts(e, "corp")
			c.Login(t, server.Authorize(server.ClientFragment, "corp", "max_age", "59"))
			if contacts(e, "corp") != before+1 {
				t.Fatal("max_age below the session's age was used")
			}
		})
	}
}

// Covers: FR-45 (part), SEC-37 (part)
// Acceptance: Single sign-on session (part)
// A session that a logout deletes between the read and the code gives no code: the
// move-on comes first, and a row that is gone sends the request to the provider
// (prompt=none: login_required).
func deletedBeforeCodeCase(t *testing.T, o []server.Option) {
	{
		e := flowNew(t, o)
		ssoOn(t, e)
		corpUser(e, "201")
		c, _ := firstLogin(t, e)
		e.Faults.Fail("SSOSessions.Touch", store.ErrNotFound)
		r := c.Do(t, http.MethodGet, e.Realm.EndpointURL(config.EndpointAuthorize, "")+"?"+server.Authorize(server.ClientFragment, "corp").Encode(), nil)
		toProvider(t, e, r, "corp")
		wantCookieCleared(t, r)
		e.Faults.Fail("SSOSessions.Touch", store.ErrNotFound)
		none := c.Login(t, server.Authorize(server.ClientFragment, "", "prompt", "none"))
		if none.Values.Get("error") != "login_required" || none.Values.Has("code") {
			t.Fatalf("prompt=none after the row was gone: %v", none.Values)
		}
	}
}

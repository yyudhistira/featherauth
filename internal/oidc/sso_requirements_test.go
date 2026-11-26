package oidc_test

import (
	"context"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/secure"
	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/testutil/server"
)

// rawDeleteIdentity deletes an identity row with the store, bypassing the manager
// and the End paths.
func rawDeleteIdentity(t *testing.T, e *server.Env, id store.IdentityID) {
	t.Helper()
	ctx := context.Background()
	if err := e.Store.Write(ctx, func(tx store.Tx) error {
		rid, err := tx.Realms().Find(ctx, "main")
		if err != nil {
			return err
		}
		return tx.Identities().Delete(ctx, rid, id)
	}); err != nil {
		t.Fatal(err)
	}
}

// setCookieValue returns the value of the named cookie that the answer sets, or "".
func setCookieValue(r server.Response, name string) string {
	for _, sc := range r.Header.Values("Set-Cookie") {
		if strings.HasPrefix(sc, name+"=") {
			v, _, _ := strings.Cut(strings.TrimPrefix(sc, name+"="), ";")
			return v
		}
	}
	return ""
}

// Covers: FR-45, SEC-37
// The browser session of single sign-on, clause by clause, in one flow of the
// whole service. FR-45: a completed login starts a browser session; a request that
// meets the conditions is answered from it, also with prompt=none; a logout with
// the cookie ends it. SEC-37: the cookie is HttpOnly, Secure and SameSite=Lax; its
// value is random with 256 bits and stored only as a hash; it is honoured only for
// an enabled user who still holds the identity and a client with sso: true; it ends
// with a revocation of a token session that came from it; it is never honoured
// against prompt=login, select_account, consent or an exceeded max_age.
func TestSingleSignOnRequirements(t *testing.T) {
	forEachFlowDriver(t, func(t *testing.T, o []server.Option) {
		e := flowNew(t, o)
		ssoOn(t, e)
		corpUser(e, "201")
		fragAuthorize := func(extra ...string) string {
			return e.Realm.EndpointURL(config.EndpointAuthorize, "") + "?" + server.Authorize(server.ClientFragment, "", extra...).Encode()
		}
		corpAuthorize := func(app server.App, extra ...string) string {
			return e.Realm.EndpointURL(config.EndpointAuthorize, "") + "?" + server.Authorize(app, "corp", extra...).Encode()
		}

		// FR-45: a completed login starts a browser session. The three hops are the
		// browser's own: the authorization, the provider and the callback, whose answer
		// carries the cookie.
		c := e.NewClient()
		hop1 := c.Do(t, http.MethodGet, corpAuthorize(server.ClientQuery), nil)
		if hop1.Code != http.StatusFound || !strings.HasPrefix(hop1.Header.Get("Location"), e.Mocks["corp"].URL()) {
			t.Fatalf("the first request did not go to the provider: %d %s", hop1.Code, hop1.Header.Get("Location"))
		}
		hop2 := c.Do(t, http.MethodGet, hop1.Header.Get("Location"), nil)
		hop3 := c.Do(t, http.MethodGet, hop2.Header.Get("Location"), nil)
		if hop3.Code != http.StatusFound || !strings.Contains(hop3.Header.Get("Location"), "code=") {
			t.Fatalf("the callback gave no code: %d %s", hop3.Code, hop3.Header.Get("Location"))
		}
		value := setCookieValue(hop3, "fa_sso_main")
		if value == "" {
			t.Fatal("the completed login set no browser session cookie")
		}

		// SEC-37: HttpOnly, Secure, SameSite=Lax, the idle lifetime as Max-Age, the realm's path.
		wantCookieSet(t, hop3, value)
		// SEC-37: 256 random bits, and only the hash is stored.
		raw, err := base64.RawURLEncoding.DecodeString(value)
		if err != nil || len(raw) != 32 {
			t.Errorf("the cookie value holds %d bytes of randomness, want 32 (%v)", len(raw), err)
		}
		row, ok := browserRow(t, e, value)
		if !ok || row.IDHash != secure.HashOf(value) {
			t.Fatalf("the stored row %+v is not the hash of the cookie value", row)
		}
		if storesValue(t, e.DatabasePath, value) {
			t.Error("the cookie value is stored in the database")
		}

		// FR-45: a request that meets the conditions is answered from the session, with
		// no chooser and no provider; the cookie is set again.
		before := contacts(e, "corp")
		use := c.Do(t, http.MethodGet, fragAuthorize(), nil)
		if use.Code != http.StatusFound || !strings.Contains(use.Header.Get("Location"), "code=") {
			t.Fatalf("the request was not answered with a code: %d %s", use.Code, use.Header.Get("Location"))
		}
		if contacts(e, "corp") != before {
			t.Error("the provider was contacted for a request the session answers")
		}
		wantCookieSet(t, use, value)

		// FR-45: also with prompt=none.
		none := c.Do(t, http.MethodGet, fragAuthorize("prompt", "none"), nil)
		if none.Code != http.StatusFound || !strings.Contains(none.Header.Get("Location"), "code=") || contacts(e, "corp") != before {
			t.Fatalf("prompt=none was not answered from the session: %d %s", none.Code, none.Header.Get("Location"))
		}

		// SEC-37: never honoured against prompt=login, select_account, consent or an
		// exceeded max_age. The cookie stays and the request goes to the provider.
		e.Clock.Advance(time.Minute) // the session is a minute old
		for _, extra := range [][]string{{"prompt", "login"}, {"prompt", "select_account"}, {"prompt", "consent"}, {"max_age", "30"}} {
			r := c.Do(t, http.MethodGet, corpAuthorize(server.ClientFragment, extra...), nil)
			if r.Code != http.StatusFound || !strings.HasPrefix(r.Header.Get("Location"), e.Mocks["corp"].URL()) {
				t.Errorf("%v was answered from the session: %d %s", extra, r.Code, r.Header.Get("Location"))
			}
			keepsCookie(t, r)
		}

		// SEC-37: honoured only for a client with sso: true.
		e.Reload(t, func(y string) string {
			return strings.Replace(y, "  frag:\n    response_mode: fragment\n", "  frag:\n    sso: false\n    response_mode: fragment\n", 1)
		})
		if r := c.Do(t, http.MethodGet, corpAuthorize(server.ClientFragment), nil); !strings.HasPrefix(r.Header.Get("Location"), e.Mocks["corp"].URL()) {
			t.Errorf("a client with sso false was answered from the session: %s", r.Header.Get("Location"))
		}
		e.Reload(t, func(y string) string {
			return strings.Replace(y, "  frag:\n    sso: false\n    response_mode: fragment\n", "  frag:\n    response_mode: fragment\n", 1)
		})

		// SEC-37: honoured only for an enabled user.
		uid := row.UserID
		userDirect(t, e, uid, func(u *store.User) { u.DisabledAt = e.Clock.Now() })
		r := c.Do(t, http.MethodGet, corpAuthorize(server.ClientFragment), nil)
		if !strings.HasPrefix(r.Header.Get("Location"), e.Mocks["corp"].URL()) {
			t.Errorf("a disabled user's session was honoured: %s", r.Header.Get("Location"))
		}
		wantCookieCleared(t, r)
		userDirect(t, e, uid, func(u *store.User) { u.DisabledAt = time.Time{} })

		// SEC-37: honoured only while the user still holds the identity.
		c2, _ := firstLogin(t, e)
		ident, err := identityOf(t, e, "corp", "201")
		if err != nil {
			t.Fatal(err)
		}
		rawDeleteIdentity(t, e, ident.ID)
		if r := c2.Do(t, http.MethodGet, corpAuthorize(server.ClientFragment), nil); !strings.HasPrefix(r.Header.Get("Location"), e.Mocks["corp"].URL()) {
			t.Errorf("a session whose identity is gone was honoured: %s", r.Header.Get("Location"))
		}

		// FR-45: a logout with the cookie ends the session.
		c3, _ := firstLogin(t, e)
		cookie3 := browserCookie(c3)
		wantCookieCleared(t, c3.Do(t, http.MethodGet, e.Realm.EndpointURL(config.EndpointLogout, ""), nil))
		if _, ok := browserRow(t, e, cookie3); ok {
			t.Error("the logout with the cookie left the browser session stored")
		}
		if n := c3.Do(t, http.MethodGet, fragAuthorize("prompt", "none"), nil); !strings.Contains(n.Header.Get("Location"), "error=login_required") {
			t.Errorf("prompt=none after the logout: %s", n.Header.Get("Location"))
		}

		// SEC-37: it ends with a revocation of a token session that came from it.
		c4 := e.NewClient()
		res4 := c4.Login(t, server.Authorize(server.ClientQuery, "corp"))
		cookie4 := browserCookie(c4)
		g4 := e.Exchange(t, server.ClientQuery, res4)
		if rv := c4.Do(t, http.MethodPost, e.Realm.EndpointURL(config.EndpointRevoke, ""),
			map[string][]string{"token": {g4.RefreshToken}, "client_id": {"web"}}); rv.Code != http.StatusOK {
			t.Fatalf("revoke: %d", rv.Code)
		}
		if _, ok := browserRow(t, e, cookie4); ok {
			t.Error("the revocation of the token session left its browser session stored")
		}
	})
}

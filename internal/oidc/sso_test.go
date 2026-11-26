package oidc_test

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/oidc"
	"github.com/yyudhistira/featherauth/internal/secure"
	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/testutil"
)

// ssoRealm turns the single sign-on session of the realm main on.
const ssoRealm = "sso:\n  enabled: true\n"

// ssoCookieName is the browser session cookie of the realm main.
const ssoCookieName = "fa_sso_main"

// ssoCookies returns the browser session cookies that the answer sets.
func ssoCookies(rec *httptest.ResponseRecorder) []*http.Cookie {
	var out []*http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == ssoCookieName {
			out = append(out, c)
		}
	}
	return out
}

// ssoRow reads the browser session stored under the hash of cookie in the realm
// main; ok is false when there is none.
func (e *authzEnv) ssoRow(t *testing.T, cookie string) (row store.SSOSession, ok bool) {
	t.Helper()
	ctx := context.Background()
	err := e.st.Read(ctx, func(tx store.Tx) error {
		rid, err := tx.Realms().Find(ctx, "main")
		if err != nil {
			return err
		}
		row, err = tx.SSOSessions().Find(ctx, rid, secure.HashOf(cookie))
		return err
	})
	switch {
	case errors.Is(err, store.ErrNotFound):
		return store.SSOSession{}, false
	case err != nil:
		t.Fatalf("reading the browser session: %v", err)
	}
	return row, true
}

// tokenSSOHash returns the browser session hash kept by the refresh token raw.
func (e *authzEnv) tokenSSOHash(t *testing.T, raw string) secure.Hash {
	t.Helper()
	ctx := context.Background()
	var h secure.Hash
	err := e.st.Read(ctx, func(tx store.Tx) error {
		rid, err := tx.Realms().Find(ctx, "main")
		if err != nil {
			return err
		}
		rt, err := tx.RefreshTokens().FindByHash(ctx, rid, secure.HashOf(raw))
		h = rt.SSOIDHash
		return err
	})
	if err != nil {
		t.Fatalf("reading the refresh token: %v", err)
	}
	return h
}

// storesValue reports whether a cell of any table of the database file at path
// holds value, or a text that contains it.
func storesValue(t *testing.T, path, value string) bool {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	for _, table := range testutil.SQLiteTables(t, path) {
		rows, err := db.Query(`SELECT * FROM "` + table + `"`)
		if err != nil {
			t.Fatal(err)
		}
		cols, err := rows.Columns()
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				t.Fatal(err)
			}
			for _, v := range vals {
				if s, ok := v.(string); ok && strings.Contains(s, value) {
					_ = rows.Close()
					return true
				}
				if b, ok := v.([]byte); ok && strings.Contains(string(b), value) {
					_ = rows.Close()
					return true
				}
			}
		}
		_ = rows.Close()
	}
	return false
}

// Covers: FR-45 (part), SEC-37 (part)
// Acceptance: Single sign-on start
// A completed login with sso.enabled starts a browser session for a client with
// sso: true: the cookie is fa_sso_ plus the realm name with the attributes of
// SEC-37 and the path of the common directory of the authorize and logout paths,
// and the table holds only the hash of its value. A login from the same browser
// replaces the earlier session. With sso.enabled false, or for a client with
// sso: false, there is no cookie and no row. A store that fails at the start
// gives server_error and no code.
func TestSingleSignOnStart(t *testing.T) {
	t.Run("default layout: cookie, stored hash and the token session", func(t *testing.T) {
		e := newAuthzEnvWith(t, authzServerYAML, ssoRealm, "corp")
		e.idp.SetUser(ann("ann@example.com"))
		now := e.clk.Now()
		l := e.begin(t, "corp", goodRequest("provider", "corp"))
		rec := e.callback(l.target, l.cookie)
		got := result(t, rec, oidc.ModeQuery)
		if got.Has("error") || got.Get("code") == "" {
			t.Fatalf("the login did not complete: %v", got)
		}
		cookies := ssoCookies(rec)
		if len(cookies) != 1 {
			t.Fatalf("browser session cookies = %d, want 1 (%v)", len(cookies), rec.Header().Values("Set-Cookie"))
		}
		ck := cookies[0]
		if !ck.HttpOnly || !ck.Secure || ck.SameSite != http.SameSiteLaxMode {
			t.Errorf("attributes HttpOnly %v, Secure %v, SameSite %v; want HttpOnly, Secure and Lax", ck.HttpOnly, ck.Secure, ck.SameSite)
		}
		if ck.MaxAge != int((8 * time.Hour).Seconds()) {
			t.Errorf("Max-Age = %d, want the idle lifetime of 8h", ck.MaxAge)
		}
		if ck.Path != "/main" {
			t.Errorf("Path = %q, want /main", ck.Path)
		}
		if len(ck.Value) != 43 { // 256 random bits, unpadded base64url
			t.Errorf("cookie value of %d characters, want 43", len(ck.Value))
		}

		row, ok := e.ssoRow(t, ck.Value)
		if !ok {
			t.Fatal("no browser session row under the hash of the cookie value")
		}
		ident, err := e.identityOf(t, "corp", "42")
		if err != nil {
			t.Fatal(err)
		}
		if row.IDHash != secure.HashOf(ck.Value) || row.IdentityID != ident.ID || row.Provider != "corp" ||
			!row.CreatedAt.Equal(now) || !row.LastUsedAt.Equal(now) || !row.ExpiresAt.Equal(now.Add(8*time.Hour)) ||
			row.UserID != ident.UserID {
			t.Errorf("row = %+v, want the hash of the value, the login's identity and times now, now and now+8h", row)
		}
		if storesValue(t, e.path, ck.Value) {
			t.Error("the cookie value is stored in the database")
		}

		g := e.exchange(t, got, "web", "https://app.example.com/callback")
		if h := e.tokenSSOHash(t, g.RefreshToken); h != secure.HashOf(ck.Value) {
			t.Errorf("the token session's SSOIDHash = %q, want the hash of the cookie", h)
		}
	})

	t.Run("keycloak-style layout: the path is the common directory", func(t *testing.T) {
		e := newAuthzEnvWith(t, "public_url: https://auth.example.com\n"+keycloakServerYAML, ssoRealm, "corp")
		e.idp.SetUser(ann("ann@example.com"))
		l := e.begin(t, "corp", goodRequest("kc_idp_hint", "corp"))
		cookies := ssoCookies(e.callback(l.target, l.cookie))
		if len(cookies) != 1 {
			t.Fatalf("browser session cookies = %d, want 1", len(cookies))
		}
		if got, want := cookies[0].Path, "/realms/main/protocol/openid-connect"; got != want {
			t.Errorf("Path = %q, want %q", got, want)
		}
		if _, ok := e.ssoRow(t, cookies[0].Value); !ok {
			t.Error("no browser session row for the keycloak-style login")
		}
	})

	t.Run("a second login from the same browser replaces the first session", func(t *testing.T) {
		e := newAuthzEnvWith(t, authzServerYAML, ssoRealm, "corp")
		e.idp.SetUser(ann("ann@example.com"))
		first := e.begin(t, "corp", goodRequest("provider", "corp"))
		old := ssoCookies(e.callback(first.target, first.cookie))
		if len(old) != 1 {
			t.Fatalf("the first login set %d browser session cookies", len(old))
		}
		second := e.begin(t, "corp", goodRequest("provider", "corp"))
		rec := e.callback(second.target, second.cookie, old[0])
		cookies := ssoCookies(rec)
		if len(cookies) != 1 || cookies[0].Value == old[0].Value {
			t.Fatalf("the second login set cookies %v, want one new value", cookies)
		}
		if _, ok := e.ssoRow(t, old[0].Value); ok {
			t.Error("the first browser session is still stored after the second login")
		}
		if _, ok := e.ssoRow(t, cookies[0].Value); !ok {
			t.Error("no row for the browser session of the second login")
		}
		if n := testutil.SQLiteRowCounts(t, e.path)["sso_sessions"]; n != 1 {
			t.Errorf("browser session rows = %d, want 1", n)
		}
	})

	t.Run("the maximum lifetime comes first: the session expires at it", func(t *testing.T) {
		e := newAuthzEnvWith(t, authzServerYAML, "sso:\n  enabled: true\n  max_lifetime: 1h\n", "corp")
		e.idp.SetUser(ann("ann@example.com"))
		now := e.clk.Now()
		l := e.begin(t, "corp", goodRequest("provider", "corp"))
		cookies := ssoCookies(e.callback(l.target, l.cookie))
		if len(cookies) != 1 {
			t.Fatalf("browser session cookies = %d, want 1", len(cookies))
		}
		row, ok := e.ssoRow(t, cookies[0].Value)
		if !ok || !row.ExpiresAt.Equal(now.Add(time.Hour)) {
			t.Fatalf("row %+v, want expiry at the 1h maximum", row)
		}
		if cookies[0].MaxAge != int((8 * time.Hour).Seconds()) {
			t.Errorf("Max-Age = %d, want the idle lifetime of 8h, not the maximum", cookies[0].MaxAge)
		}
	})

	t.Run("sso.enabled false: no cookie and no row", func(t *testing.T) {
		e := newAuthzEnvWith(t, authzServerYAML, "", "corp")
		e.idp.SetUser(ann("ann@example.com"))
		l := e.begin(t, "corp", goodRequest("provider", "corp"))
		rec := e.callback(l.target, l.cookie)
		if got := result(t, rec, oidc.ModeQuery); got.Get("code") == "" {
			t.Fatalf("no code: %v", got)
		}
		if n := len(ssoCookies(rec)); n != 0 {
			t.Errorf("%d browser session cookies with sso.enabled false", n)
		}
		if n := testutil.SQLiteRowCounts(t, e.path)["sso_sessions"]; n != 0 {
			t.Errorf("browser session rows = %d with sso.enabled false", n)
		}
	})

	t.Run("a client with sso false: no cookie and no row", func(t *testing.T) {
		e := newAuthzEnvWith(t, authzServerYAML, ssoRealm, "corp")
		e.idp.SetUser(ann("ann@example.com"))
		l := e.begin(t, "corp", goodRequest("provider", "corp", "client_id", "ssooff", "redirect_uri", "https://off.example.com/callback"))
		rec := e.callback(l.target, l.cookie)
		if got := result(t, rec, oidc.ModeQuery); got.Get("code") == "" {
			t.Fatalf("no code: %v", got)
		}
		if n := len(ssoCookies(rec)); n != 0 {
			t.Errorf("%d browser session cookies for a client with sso false", n)
		}
		if n := testutil.SQLiteRowCounts(t, e.path)["sso_sessions"]; n != 0 {
			t.Errorf("browser session rows = %d for a client with sso false", n)
		}
	})

	t.Run("Secure follows the state cookie: not set on a plain http development server", func(t *testing.T) {
		e := newAuthzEnvWith(t, "public_url: http://auth.example.com\nrequire_https: false\nlogin:\n  provider_hint_params: [provider, idp]\n", ssoRealm, "corp")
		e.idp.SetUser(ann("ann@example.com"))
		l := e.begin(t, "corp", goodRequest("provider", "corp"))
		cookies := ssoCookies(e.callback(l.target, l.cookie))
		if len(cookies) != 1 || cookies[0].Secure {
			t.Fatalf("cookies %v, want one that is not Secure", cookies)
		}
	})

	t.Run("a store that cannot end the earlier session fails the login and keeps it", func(t *testing.T) {
		e := newAuthzEnvWith(t, authzServerYAML, ssoRealm, "corp")
		e.idp.SetUser(ann("ann@example.com"))
		first := e.begin(t, "corp", goodRequest("provider", "corp"))
		old := ssoCookies(e.callback(first.target, first.cookie))
		if len(old) != 1 {
			t.Fatalf("the first login set %d browser session cookies", len(old))
		}
		e.fs.Fail("SSOSessions.Delete", context.DeadlineExceeded)
		second := e.begin(t, "corp", goodRequest("provider", "corp"))
		rec := e.callback(second.target, second.cookie, old[0])
		got := result(t, rec, oidc.ModeQuery)
		if got.Get("error") != "server_error" || got.Has("code") || len(ssoCookies(rec)) != 0 {
			t.Errorf("result %v and cookies %v, want server_error, no code and no cookie", got, ssoCookies(rec))
		}
		if _, ok := e.ssoRow(t, old[0].Value); !ok {
			t.Error("the earlier browser session was lost although the second login failed")
		}
	})

	t.Run("a failed create keeps the earlier session: the delete and the create are one transaction", func(t *testing.T) {
		e := newAuthzEnvWith(t, authzServerYAML, ssoRealm, "corp")
		e.idp.SetUser(ann("ann@example.com"))
		first := e.begin(t, "corp", goodRequest("provider", "corp"))
		old := ssoCookies(e.callback(first.target, first.cookie))
		if len(old) != 1 {
			t.Fatalf("the first login set %d browser session cookies", len(old))
		}
		e.fs.Fail("SSOSessions.Create", context.DeadlineExceeded)
		second := e.begin(t, "corp", goodRequest("provider", "corp"))
		rec := e.callback(second.target, second.cookie, old[0])
		if got := result(t, rec, oidc.ModeQuery); got.Get("error") != "server_error" {
			t.Errorf("result %v, want server_error", got)
		}
		if _, ok := e.ssoRow(t, old[0].Value); !ok {
			t.Error("the earlier browser session was deleted although the new one was not stored")
		}
		if n := testutil.SQLiteRowCounts(t, e.path)["sso_sessions"]; n != 1 {
			t.Errorf("browser session rows = %d, want the earlier one only", n)
		}
	})

	t.Run("an identity of another user fails the login and starts no session", func(t *testing.T) {
		e := newAuthzEnvWith(t, authzServerYAML, ssoRealm, "corp")
		e.idp.SetUser(ann("ann@example.com"))
		l := e.begin(t, "corp", goodRequest("provider", "corp"))
		// Resolve reads the identity once; the session's own lookup is the second read.
		e.fs.SwapFind(2, "u-of-someone-else")
		rec := e.callback(l.target, l.cookie)
		got := result(t, rec, oidc.ModeQuery)
		if got.Get("error") != "server_error" || got.Has("code") {
			t.Errorf("result %v, want server_error and no code", got)
		}
		if n := len(ssoCookies(rec)); n != 0 {
			t.Errorf("%d browser session cookies for another user's identity", n)
		}
		if n := testutil.SQLiteRowCounts(t, e.path)["sso_sessions"]; n != 0 {
			t.Errorf("browser session rows = %d for another user's identity", n)
		}
	})

	t.Run("a store that fails at the start gives server_error and no code", func(t *testing.T) {
		e := newAuthzEnvWith(t, authzServerYAML, ssoRealm, "corp")
		e.idp.SetUser(ann("ann@example.com"))
		e.fs.Fail("SSOSessions.Create", context.DeadlineExceeded)
		l := e.begin(t, "corp", goodRequest("provider", "corp"))
		rec := e.callback(l.target, l.cookie)
		got := result(t, rec, oidc.ModeQuery)
		if got.Get("error") != "server_error" || got.Has("code") {
			t.Errorf("result %v, want server_error and no code", got)
		}
		if n := len(ssoCookies(rec)); n != 0 {
			t.Errorf("%d browser session cookies after a failed start", n)
		}
		if n := testutil.SQLiteRowCounts(t, e.path)["sso_sessions"]; n != 0 {
			t.Errorf("browser session rows = %d after a failed start", n)
		}
	})
}

// identityOf returns the stored identity of a provider subject in the realm main.
func (e *authzEnv) identityOf(t *testing.T, prov, sub string) (store.Identity, error) {
	t.Helper()
	var ident store.Identity
	err := e.st.Read(context.Background(), func(tx store.Tx) error {
		rid, err := tx.Realms().Find(context.Background(), "main")
		if err != nil {
			return err
		}
		ident, err = tx.Identities().Find(context.Background(), rid, config.ProviderKey(prov), sub)
		return err
	})
	return ident, err
}

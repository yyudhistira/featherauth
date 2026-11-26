package oidc_test

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/testutil/server"
	"github.com/yyudhistira/featherauth/internal/user"
)

// signOutEnv starts the service with the "web" client allowed to manage
// sessions; the "frag" client is not.
func signOutEnv(t *testing.T) *server.Env {
	t.Helper()
	e := server.New(t)
	e.Reload(t, func(y string) string {
		return strings.Replace(y, "  web:\n    redirect_uris: [https://app.example.com/callback]\n",
			"  web:\n    redirect_uris: [https://app.example.com/callback]\n    allow_session_management: true\n", 1)
	})
	return e
}

// signOut sends the bearer logout of tk with the given form.
func signOut(t *testing.T, e *server.Env, tk server.Tokens, v url.Values) server.Response {
	t.Helper()
	return logout(t, e, http.MethodPost, v, http.Header{"Authorization": {"Bearer " + tk.AccessToken}})
}

// sessionAudit returns the user.sessions_revoked rows.
func sessionAudit(t *testing.T, e *server.Env) []store.AuditEvent {
	t.Helper()
	var out []store.AuditEvent
	err := e.Store.Read(context.Background(), func(tx store.Tx) error {
		rid, err := tx.Realms().Find(context.Background(), "main")
		if err != nil {
			return err
		}
		rows, err := tx.Audit().List(context.Background(), rid, time.Time{})
		for _, r := range rows {
			if r.Action == "user.sessions_revoked" {
				out = append(out, r)
			}
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// wantNoStoreHeaders checks the no-store headers of an answer.
func wantNoStoreHeaders(t *testing.T, r server.Response) {
	t.Helper()
	if r.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control %q on status %d, want no-store", r.Header.Get("Cache-Control"), r.Code)
	}
}

// wantFragRevoked checks that a refresh token of the frag client is revoked.
func wantFragRevoked(t *testing.T, e *server.Env, rt string) {
	t.Helper()
	wantRevoked(t, e, server.ClientFragment, rt)
}

// Covers: FR-39
// Acceptance: Sign out everywhere
func TestSignOutEverywhere(t *testing.T) {
	app, frag := server.ClientQuery, server.ClientFragment

	t.Run("a client with the option ends every session of the user", func(t *testing.T) {
		e := signOutEnv(t)
		a1 := exchange(t, e, app)
		a2 := exchange(t, e, app)
		f1 := exchange(t, e, frag)
		gone := exchange(t, e, app) // a session that ended before does not count
		wantTokens(t, refresh(t, e, app, gone.RefreshToken))
		_ = signOut(t, e, gone, nil)
		before := len(sessionAudit(t, e))
		total := auditRows(t, e)
		writes := e.Faults.Writes()
		e.Logs.Reset()

		r := signOut(t, e, a1, url.Values{"all_sessions": {"true"}})
		if r.Code != http.StatusNoContent || r.Body != "" {
			t.Fatalf("status %d body %q, want 204", r.Code, r.Body)
		}
		wantNoStoreHeaders(t, r)
		if n := e.Faults.Writes() - writes; n != 1 {
			t.Errorf("%d write transactions, want 1", n)
		}
		wantRevoked(t, e, app, a1.RefreshToken)
		wantRevoked(t, e, app, a2.RefreshToken)
		wantFragRevoked(t, e, f1.RefreshToken)
		rows := sessionAudit(t, e)
		if len(rows) != before+1 || auditRows(t, e) != total+1 {
			t.Fatalf("%d sessions_revoked rows (before %d), %d rows in all (before %d), want one more", len(rows), before, auditRows(t, e), total)
		}
		last := rows[len(rows)-1]
		if last.Actor != "system" || fmt.Sprint(last.Details["sessions"]) != "3" || len(last.Details) != 1 {
			t.Errorf("audit row actor %q details %v, want system and {sessions: 3}", last.Actor, last.Details)
		}
		if logs := e.Logs.String(); strings.Contains(logs, a1.AccessToken) || strings.Contains(logs, a1.RefreshToken) {
			t.Errorf("the log holds a token: %s", logs)
		}
	})
	t.Run("a second time, with no session left, is 204 with no audit row", func(t *testing.T) {
		e := signOutEnv(t)
		a1 := exchange(t, e, app)
		exchange(t, e, frag)
		if r := signOut(t, e, a1, url.Values{"all_sessions": {"true"}}); r.Code != 204 {
			t.Fatalf("first: %d", r.Code)
		}
		rows := len(sessionAudit(t, e))
		r := signOut(t, e, a1, url.Values{"all_sessions": {"true"}})
		if r.Code != http.StatusNoContent {
			t.Fatalf("second: %d %q", r.Code, r.Body)
		}
		wantNoStoreHeaders(t, r)
		if got := len(sessionAudit(t, e)); got != rows {
			t.Errorf("%d rows, want %d", got, rows)
		}
	})
	t.Run("a client without the option is refused and nothing is revoked", func(t *testing.T) {
		e := signOutEnv(t)
		a1 := exchange(t, e, app)
		f1 := exchange(t, e, frag)
		total, writes := auditRows(t, e), e.Faults.Writes()
		r := signOut(t, e, f1, url.Values{"all_sessions": {"true"}})
		if r.Code != http.StatusForbidden || r.Header.Get("WWW-Authenticate") != `Bearer error="insufficient_scope"` || wantJSONError(t, r) != "insufficient_scope" {
			t.Fatalf("status %d headers %v body %q", r.Code, r.Header, r.Body)
		}
		wantNoStoreHeaders(t, r)
		if n := e.Faults.Writes() - writes; n != 0 || auditRows(t, e) != total {
			t.Errorf("%d write transactions, audit rows %d (was %d)", n, auditRows(t, e), total)
		}
		wantAlive(t, e, app, a1.RefreshToken)
		wantTokens(t, refresh(t, e, frag, f1.RefreshToken))
	})
	t.Run("a client removed since the token was issued counts as without the option", func(t *testing.T) {
		e := signOutEnv(t)
		a1 := exchange(t, e, app)
		e.Reload(t, func(y string) string {
			return strings.Replace(y, "  web:\n    redirect_uris: [https://app.example.com/callback]\n    allow_session_management: true\n    web_origins: [https://app.example.com]\n", "", 1)
		})
		if _, ok := e.Realm.Clients["web"]; ok {
			t.Fatal("client not removed")
		}
		r := signOut(t, e, a1, url.Values{"all_sessions": {"true"}})
		if r.Code != http.StatusForbidden || wantJSONError(t, r) != "insufficient_scope" {
			t.Errorf("status %d body %q", r.Code, r.Body)
		}
		wantNoStoreHeaders(t, r)
	})
	t.Run("a value other than true is invalid_request from any client", func(t *testing.T) {
		for _, client := range []server.App{app, frag} {
			for _, val := range []string{"yes", "false", "1", "True", "TRUE", " true", "true "} {
				e := signOutEnv(t)
				tk := exchange(t, e, client)
				other := exchange(t, e, app)
				total, writes := auditRows(t, e), e.Faults.Writes()
				r := signOut(t, e, tk, url.Values{"all_sessions": {val}})
				if r.Code != http.StatusBadRequest || wantJSONError(t, r) != "invalid_request" {
					t.Errorf("%s %q: status %d body %q", client.ID, val, r.Code, r.Body)
				}
				wantNoStoreHeaders(t, r)
				if n := e.Faults.Writes() - writes; n != 0 || auditRows(t, e) != total {
					t.Errorf("%s %q: %d write transactions", client.ID, val, n)
				}
				wantAlive(t, e, app, other.RefreshToken)
			}
		}
	})
	t.Run("the field twice is invalid_request", func(t *testing.T) {
		for _, vals := range [][]string{{"true", "true"}, {"true", ""}, {"", ""}} {
			e := signOutEnv(t)
			tk := exchange(t, e, app)
			r := signOut(t, e, tk, url.Values{"all_sessions": vals})
			if r.Code != http.StatusBadRequest || wantJSONError(t, r) != "invalid_request" {
				t.Errorf("%q: status %d body %q", vals, r.Code, r.Body)
			}
			wantNoStoreHeaders(t, r)
			wantAlive(t, e, app, tk.RefreshToken)
		}
	})
	t.Run("an empty or absent field ends only the token's session", func(t *testing.T) {
		for _, v := range []url.Values{nil, {"all_sessions": {""}}} {
			e := signOutEnv(t)
			tk := exchange(t, e, app)
			other := exchange(t, e, app)
			f1 := exchange(t, e, frag)
			total := auditRows(t, e)
			r := signOut(t, e, tk, v)
			if r.Code != http.StatusNoContent {
				t.Fatalf("%v: status %d", v, r.Code)
			}
			wantRevoked(t, e, app, tk.RefreshToken)
			wantAlive(t, e, app, other.RefreshToken)
			wantTokens(t, refresh(t, e, frag, f1.RefreshToken))
			if auditRows(t, e) != total {
				t.Errorf("%v: an audit row was written", v)
			}
		}
	})
	t.Run("with a refresh_token the field is ignored, also a bad value", func(t *testing.T) {
		for _, val := range []string{"true", "yes", ""} {
			e := signOutEnv(t)
			tk := exchange(t, e, app)
			other := exchange(t, e, app)
			total := auditRows(t, e)
			r := logout(t, e, http.MethodPost, url.Values{"refresh_token": {tk.RefreshToken}, "client_id": {app.ID}, "all_sessions": {val}}, nil)
			if r.Code != http.StatusNoContent {
				t.Fatalf("%q: status %d %q", val, r.Code, r.Body)
			}
			wantRevoked(t, e, app, tk.RefreshToken)
			wantAlive(t, e, app, other.RefreshToken)
			if auditRows(t, e) != total {
				t.Errorf("%q: an audit row was written", val)
			}
		}
		// A refresh token also wins over a Bearer header.
		e := signOutEnv(t)
		tk := exchange(t, e, app)
		other := exchange(t, e, app)
		r := logout(t, e, http.MethodPost, url.Values{"refresh_token": {tk.RefreshToken}, "client_id": {app.ID}, "all_sessions": {"true"}},
			http.Header{"Authorization": {"Bearer " + other.AccessToken}})
		if r.Code != 204 {
			t.Fatalf("status %d", r.Code)
		}
		wantAlive(t, e, app, other.RefreshToken)
	})
	t.Run("a GET ignores the field", func(t *testing.T) {
		e := signOutEnv(t)
		tk := exchange(t, e, app)
		other := exchange(t, e, app)
		total := auditRows(t, e)
		wantSignedOut(t, logout(t, e, http.MethodGet, url.Values{"id_token_hint": {tk.IDToken}, "all_sessions": {"true"}}, nil))
		wantRevoked(t, e, app, tk.RefreshToken)
		wantAlive(t, e, app, other.RefreshToken)
		if auditRows(t, e) != total {
			t.Error("an audit row was written")
		}
	})
	t.Run("a bad access token is invalid_token", func(t *testing.T) {
		e := signOutEnv(t)
		tk := exchange(t, e, app)
		bad := tk
		bad.AccessToken = "garbage"
		r := signOut(t, e, bad, url.Values{"all_sessions": {"true"}})
		if r.Code != 401 || r.Header.Get("WWW-Authenticate") != `Bearer error="invalid_token"` {
			t.Errorf("status %d headers %v", r.Code, r.Header)
		}
		wantNoStoreHeaders(t, r)
		e.Clock.Advance(time.Hour)
		if r := signOut(t, e, tk, url.Values{"all_sessions": {"true"}}); r.Code != 401 {
			t.Errorf("expired token: status %d", r.Code)
		}
	})
	t.Run("a disabled user is invalid_token", func(t *testing.T) {
		e := signOutEnv(t)
		tk := exchange(t, e, app)
		e.SetDisabled(t, true)
		r := signOut(t, e, tk, url.Values{"all_sessions": {"true"}})
		if r.Code != 401 || wantJSONError(t, r) != "invalid_token" {
			t.Errorf("status %d body %q", r.Code, r.Body)
		}
	})
	t.Run("a user deleted after the token check is invalid_token", func(t *testing.T) {
		e := signOutEnv(t)
		tk := exchange(t, e, app)
		e.Faults.FailWrite = user.ErrNotFound
		r := signOut(t, e, tk, url.Values{"all_sessions": {"true"}})
		e.Faults.FailWrite = nil
		if r.Code != 401 || wantJSONError(t, r) != "invalid_token" {
			t.Errorf("status %d body %q", r.Code, r.Body)
		}
		wantNoStoreHeaders(t, r)
		wantAlive(t, e, app, tk.RefreshToken)
	})
	t.Run("a store failure revokes nothing and is answered with no-store", func(t *testing.T) {
		for _, row := range []struct {
			name   string
			fail   func(e *server.Env)
			clear  func(e *server.Env)
			status int
			code   string
		}{
			{"unavailable write", func(e *server.Env) { e.Faults.FailWrite = store.ErrUnavailable }, func(e *server.Env) { e.Faults.FailWrite = nil }, 503, "temporarily_unavailable"},
			{"failing write", func(e *server.Env) { e.Faults.FailWrite = fmt.Errorf("disk on fire") }, func(e *server.Env) { e.Faults.FailWrite = nil }, 500, "server_error"},
			{"revoke fails", func(e *server.Env) { e.Faults.Fail("Refresh.RevokeSession", store.ErrUnavailable) }, func(e *server.Env) { e.Faults.Fail("Refresh.RevokeSession", nil) }, 503, "temporarily_unavailable"},
			{"audit row fails", func(e *server.Env) { e.Faults.Fail("Audit.Insert", fmt.Errorf("disk on fire")) }, func(e *server.Env) { e.Faults.Fail("Audit.Insert", nil) }, 500, "server_error"},
		} {
			t.Run(row.name, func(t *testing.T) {
				e := signOutEnv(t)
				tk := exchange(t, e, app)
				other := exchange(t, e, app)
				row.fail(e)
				r := signOut(t, e, tk, url.Values{"all_sessions": {"true"}})
				row.clear(e)
				if r.Code != row.status || wantJSONError(t, r) != row.code {
					t.Errorf("status %d body %q", r.Code, r.Body)
				}
				wantNoStoreHeaders(t, r)
				if n := len(sessionAudit(t, e)); n != 0 {
					t.Errorf("%d audit rows", n)
				}
				wantAlive(t, e, app, tk.RefreshToken) // the whole change rolled back
				wantAlive(t, e, app, other.RefreshToken)
			})
		}
	})
}

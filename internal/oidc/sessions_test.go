package oidc_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/testutil/mockidp"
	"github.com/yyudhistira/featherauth/internal/testutil/server"
)

// sessionsGET reads the sessions path with the access token given (none when
// empty) and the extra headers.
func sessionsGET(t *testing.T, e *server.Env, access string, h http.Header) server.Response {
	t.Helper()
	hh := http.Header{}
	if access != "" {
		hh.Set("Authorization", "Bearer "+access)
	}
	for k, v := range h {
		hh[k] = v
	}
	return e.NewClient().Request(t, http.MethodGet, server.Issuer+"/sessions", "", hh)
}

// exchangeAs signs in another Google user (another subject) and exchanges the
// code for its tokens.
func exchangeAs(t *testing.T, e *server.Env, app server.App, sub, email string) server.Tokens {
	t.Helper()
	e.Mocks["google"].SetUser(mockidp.User{Sub: sub, Name: "Bob Lee", Email: email, EmailVerified: true})
	res := e.NewClient().Login(t, server.Authorize(app, "google"))
	return wantTokens(t, post(t, e, server.CodeForm(app, res), nil))
}

// listedSession is one entry of the sessions list.
type listedSession struct {
	SessionID  string    `json:"session_id"`
	ClientID   string    `json:"client_id"`
	StartedAt  time.Time `json:"started_at"`
	AuthTime   time.Time `json:"auth_time"`
	LastUsedAt time.Time `json:"last_used_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	Current    bool      `json:"current"`
}

// listOf decodes a 200 answer of the sessions path; the keys must be exactly
// the seven fields of the design.
func listOf(t *testing.T, r server.Response) []listedSession {
	t.Helper()
	if r.Code != http.StatusOK {
		t.Fatalf("status %d body %q, want 200", r.Code, r.Body)
	}
	var raw []map[string]any
	if err := json.Unmarshal([]byte(r.Body), &raw); err != nil {
		t.Fatalf("body %q: %v", r.Body, err)
	}
	want := []string{"auth_time", "client_id", "current", "expires_at", "last_used_at", "session_id", "started_at"}
	for _, m := range raw {
		if len(m) != len(want) {
			t.Fatalf("entry %v, want exactly the keys %v", m, want)
		}
		for _, k := range want {
			if _, ok := m[k]; !ok {
				t.Fatalf("entry %v lacks %s", m, k)
			}
		}
	}
	var out []listedSession
	if err := json.Unmarshal([]byte(r.Body), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// Covers: FR-42
// Acceptance: Sessions endpoint
func TestSessionsListsTheLiveSessionsOfEveryClient(t *testing.T) {
	app, frag := server.ClientQuery, server.ClientFragment
	e := signOutEnv(t)
	exchange(t, e, app) // ends up expired below
	e.Clock.Advance(800 * time.Hour)
	a := exchange(t, e, app)
	b := exchange(t, e, app)
	f := exchange(t, e, frag)

	r := sessionsGET(t, e, a.AccessToken, nil)
	list := listOf(t, r)
	wantNoStoreHeaders(t, r)
	if strings.Contains(r.Body, a.AccessToken) || strings.Contains(r.Body, a.RefreshToken) {
		t.Errorf("the body holds a token: %s", r.Body)
	}
	want := map[string]string{ // session id -> client id
		sidOf(t, a.AccessToken): app.ID,
		sidOf(t, b.AccessToken): app.ID,
		sidOf(t, f.AccessToken): frag.ID,
	}
	if len(list) != len(want) {
		t.Fatalf("%d sessions, want the %d live ones (the expired one is left out): %+v", len(list), len(want), list)
	}
	for _, s := range list {
		client, ok := want[s.SessionID]
		if !ok {
			t.Errorf("session %s is not one of the user's live sessions", s.SessionID)
			continue
		}
		if s.ClientID != client {
			t.Errorf("session %s has client %s, want %s", s.SessionID, s.ClientID, client)
		}
		if s.Current != (s.SessionID == sidOf(t, a.AccessToken)) {
			t.Errorf("session %s: current %v", s.SessionID, s.Current)
		}
		if s.StartedAt.IsZero() || s.AuthTime.IsZero() || s.LastUsedAt.IsZero() || !s.ExpiresAt.After(e.Clock.Now()) {
			t.Errorf("session %+v: times", s)
		}
	}
}

// Covers: FR-42
// Acceptance: Sessions endpoint
func TestSessionsWithoutTheOptionIsInsufficientScope(t *testing.T) {
	e := signOutEnv(t)
	a := exchange(t, e, server.ClientQuery)
	f := exchange(t, e, server.ClientFragment)
	r := sessionsGET(t, e, f.AccessToken, nil)
	if r.Code != http.StatusForbidden || r.Header.Get("WWW-Authenticate") != `Bearer error="insufficient_scope"` || wantJSONError(t, r) != "insufficient_scope" {
		t.Fatalf("status %d headers %v body %q", r.Code, r.Header, r.Body)
	}
	wantNoStoreHeaders(t, r)
	wantAlive(t, e, server.ClientQuery, a.RefreshToken)
	wantAlive(t, e, server.ClientFragment, f.RefreshToken)
}

// Covers: FR-42
// Acceptance: Sessions endpoint
func TestSessionsBearerErrors(t *testing.T) {
	t.Run("no token, a garbled one and an expired one are invalid_token", func(t *testing.T) {
		e := signOutEnv(t)
		tk := exchange(t, e, server.ClientQuery)
		for _, access := range []string{"", "garbage"} {
			r := sessionsGET(t, e, access, nil)
			if r.Code != 401 || r.Header.Get("WWW-Authenticate") != `Bearer error="invalid_token"` || wantJSONError(t, r) != "invalid_token" {
				t.Errorf("%q: status %d headers %v body %q", access, r.Code, r.Header, r.Body)
			}
			wantNoStoreHeaders(t, r)
		}
		e.Clock.Advance(time.Hour)
		if r := sessionsGET(t, e, tk.AccessToken, nil); r.Code != 401 {
			t.Errorf("expired token: status %d", r.Code)
		}
	})
	t.Run("a disabled user is invalid_token", func(t *testing.T) {
		e := signOutEnv(t)
		tk := exchange(t, e, server.ClientQuery)
		e.SetDisabled(t, true)
		if r := sessionsGET(t, e, tk.AccessToken, nil); r.Code != 401 || wantJSONError(t, r) != "invalid_token" {
			t.Errorf("status %d body %q", r.Code, r.Body)
		}
	})
	t.Run("a store failure is answered with no-store", func(t *testing.T) {
		for _, row := range []struct {
			name   string
			err    error
			status int
			code   string
		}{
			{"unavailable", store.ErrUnavailable, 503, "temporarily_unavailable"},
			{"failing", fmt.Errorf("disk on fire"), 500, "server_error"},
		} {
			t.Run(row.name, func(t *testing.T) {
				e := signOutEnv(t)
				tk := exchange(t, e, server.ClientQuery)
				e.Faults.Fail("Refresh.UserLiveSessions", row.err)
				r := sessionsGET(t, e, tk.AccessToken, nil)
				e.Faults.Fail("Refresh.UserLiveSessions", nil)
				if r.Code != row.status || wantJSONError(t, r) != row.code {
					t.Errorf("status %d body %q", r.Code, r.Body)
				}
				wantNoStoreHeaders(t, r)
			})
		}
	})
}

// Covers: FR-42
// Acceptance: Sessions endpoint
func TestSessionsWrongMethodAndEmptyList(t *testing.T) {
	e := signOutEnv(t)
	tk := exchange(t, e, server.ClientQuery)
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		r := e.NewClient().Request(t, m, server.Issuer+"/sessions", "", http.Header{"Authorization": {"Bearer " + tk.AccessToken}})
		if r.Code != http.StatusMethodNotAllowed || r.Header.Get("Allow") != "GET, OPTIONS" {
			t.Errorf("%s: status %d Allow %q", m, r.Code, r.Header.Get("Allow"))
		}
		wantNoStoreHeaders(t, r)
	}
	// A session ended by its own logout leaves no live session: the list is [].
	if r := signOut(t, e, tk, nil); r.Code != http.StatusNoContent {
		t.Fatalf("logout: %d", r.Code)
	}
	r := sessionsGET(t, e, tk.AccessToken, nil)
	if r.Code != http.StatusOK || strings.TrimSpace(r.Body) != "[]" {
		t.Errorf("status %d body %q, want an empty list", r.Code, r.Body)
	}
}

// Covers: FR-42
// Acceptance: Sessions endpoint
func TestSessionsCORSAsUserinfo(t *testing.T) {
	const own, other = "https://app.example.com", "https://frag.example.com"
	e := signOutEnv(t)
	tk := exchange(t, e, server.ClientQuery)
	origin := func(o string) http.Header { return http.Header{"Origin": {o}} }

	t.Run("preflight", func(t *testing.T) {
		r := e.NewClient().Request(t, http.MethodOptions, server.Issuer+"/sessions", "", http.Header{
			"Origin": {own}, "Access-Control-Request-Method": {"GET"},
		})
		if r.Code != 204 || r.Header.Get("Access-Control-Allow-Origin") != own || r.Header.Get("Access-Control-Allow-Methods") != "GET, OPTIONS" {
			t.Errorf("%d %v", r.Code, r.Header)
		}
	})
	t.Run("from the token's client origin", func(t *testing.T) {
		r := sessionsGET(t, e, tk.AccessToken, origin(own))
		listOf(t, r)
		if r.Header.Get("Access-Control-Allow-Origin") != own || r.Header.Get("Vary") != "Origin" {
			t.Errorf("headers %v", r.Header)
		}
	})
	t.Run("from another client's origin, and from an unregistered one, get no allow header", func(t *testing.T) {
		for _, o := range []string{other, "https://evil.example.com"} {
			r := sessionsGET(t, e, tk.AccessToken, origin(o))
			listOf(t, r)
			if r.Header.Get("Access-Control-Allow-Origin") != "" || r.Header.Get("Vary") != "Origin" {
				t.Errorf("%s: headers %v", o, r.Header)
			}
		}
	})
	t.Run("an invalid token gets no allow header", func(t *testing.T) {
		r := sessionsGET(t, e, "garbage", origin(own))
		if r.Code != 401 || r.Header.Get("Access-Control-Allow-Origin") != "" {
			t.Errorf("%d %v", r.Code, r.Header)
		}
	})
}

// Covers: FR-42
// Acceptance: Sessions endpoint
func TestBearerLogoutEndsOneSessionOfTheUser(t *testing.T) {
	app, frag := server.ClientQuery, server.ClientFragment

	t.Run("another session of the user ends with one audit row", func(t *testing.T) {
		e := signOutEnv(t)
		a := exchange(t, e, app)
		b := exchange(t, e, app)
		f := exchange(t, e, frag)
		before, total, writes := len(sessionAudit(t, e)), auditRows(t, e), e.Faults.Writes()
		r := signOut(t, e, a, url.Values{"session": {sidOf(t, b.AccessToken)}})
		if r.Code != http.StatusNoContent || r.Body != "" {
			t.Fatalf("status %d body %q, want 204", r.Code, r.Body)
		}
		wantNoStoreHeaders(t, r)
		if n := e.Faults.Writes() - writes; n != 1 {
			t.Errorf("%d write transactions, want 1", n)
		}
		wantRevoked(t, e, app, b.RefreshToken)
		wantAlive(t, e, app, a.RefreshToken)
		wantAlive(t, e, frag, f.RefreshToken)
		rows := sessionAudit(t, e)
		if len(rows) != before+1 || auditRows(t, e) != total+1 {
			t.Fatalf("%d sessions_revoked rows (before %d), %d rows in all (before %d)", len(rows), before, auditRows(t, e), total)
		}
		last := rows[len(rows)-1]
		if last.Actor != "system" || fmt.Sprint(last.Details["sessions"]) != "1" || len(last.Details) != 1 {
			t.Errorf("audit row actor %q details %v, want system and {sessions: 1}", last.Actor, last.Details)
		}
	})
	t.Run("a session of another client of the user, and the token's own one", func(t *testing.T) {
		e := signOutEnv(t)
		a := exchange(t, e, app)
		f := exchange(t, e, frag)
		if r := signOut(t, e, a, url.Values{"session": {sidOf(t, f.AccessToken)}}); r.Code != http.StatusNoContent {
			t.Fatalf("other client: status %d", r.Code)
		}
		wantRevoked(t, e, frag, f.RefreshToken)
		if r := signOut(t, e, a, url.Values{"session": {sidOf(t, a.AccessToken)}}); r.Code != http.StatusNoContent {
			t.Fatalf("own session: status %d", r.Code)
		}
		wantRevoked(t, e, app, a.RefreshToken)
	})
	t.Run("a session already revoked is 204 with no audit row", func(t *testing.T) {
		e := signOutEnv(t)
		a := exchange(t, e, app)
		b := exchange(t, e, app)
		if r := signOut(t, e, a, url.Values{"session": {sidOf(t, b.AccessToken)}}); r.Code != http.StatusNoContent {
			t.Fatalf("first: %d", r.Code)
		}
		rows := len(sessionAudit(t, e))
		r := signOut(t, e, a, url.Values{"session": {sidOf(t, b.AccessToken)}})
		if r.Code != http.StatusNoContent || r.Body != "" {
			t.Fatalf("second: %d %q", r.Code, r.Body)
		}
		wantNoStoreHeaders(t, r)
		if got := len(sessionAudit(t, e)); got != rows {
			t.Errorf("%d rows, want %d", got, rows)
		}
	})
	t.Run("a session of another user or an unknown one is invalid_request and revokes nothing", func(t *testing.T) {
		for _, session := range []string{"other", "nope"} {
			e := signOutEnv(t)
			a := exchange(t, e, app)
			other := exchangeAs(t, e, app, "2002", "bob@example.com")
			sid := session
			if session == "other" {
				sid = sidOf(t, other.AccessToken)
			}
			total := auditRows(t, e)
			r := signOut(t, e, a, url.Values{"session": {sid}})
			if r.Code != http.StatusBadRequest || wantJSONError(t, r) != "invalid_request" {
				t.Errorf("%s: status %d body %q", session, r.Code, r.Body)
			}
			wantNoStoreHeaders(t, r)
			if auditRows(t, e) != total {
				t.Errorf("%s: an audit row was written", session)
			}
			wantAlive(t, e, app, a.RefreshToken)
			wantAlive(t, e, app, other.RefreshToken)
		}
	})
	t.Run("the field with all_sessions, or repeated, is invalid_request from any client, and no write starts", func(t *testing.T) {
		for _, client := range []server.App{app, frag} {
			e := signOutEnv(t)
			tk := exchange(t, e, client)
			other := exchange(t, e, app)
			writes := e.Faults.Writes()
			for _, v := range []url.Values{
				{"session": {sidOf(t, other.AccessToken)}, "all_sessions": {"true"}},
				{"session": {sidOf(t, other.AccessToken), sidOf(t, tk.AccessToken)}},
			} {
				r := signOut(t, e, tk, v)
				if r.Code != http.StatusBadRequest || wantJSONError(t, r) != "invalid_request" {
					t.Errorf("%s %v: status %d body %q", client.ID, v, r.Code, r.Body)
				}
				wantNoStoreHeaders(t, r)
			}
			if n := e.Faults.Writes() - writes; n != 0 {
				t.Errorf("%s: %d write transactions", client.ID, n)
			}
			wantAlive(t, e, app, other.RefreshToken)
		}
	})
	t.Run("an empty field is absent: the token's own session ends", func(t *testing.T) {
		e := signOutEnv(t)
		a := exchange(t, e, app)
		b := exchange(t, e, app)
		if r := signOut(t, e, a, url.Values{"session": {""}}); r.Code != http.StatusNoContent {
			t.Fatalf("status %d", r.Code)
		}
		wantRevoked(t, e, app, a.RefreshToken)
		wantAlive(t, e, app, b.RefreshToken)
	})
	t.Run("a client without the option is insufficient_scope and revokes nothing", func(t *testing.T) {
		e := signOutEnv(t)
		a := exchange(t, e, app)
		f := exchange(t, e, frag)
		total := auditRows(t, e)
		r := signOut(t, e, f, url.Values{"session": {sidOf(t, a.AccessToken)}})
		if r.Code != http.StatusForbidden || r.Header.Get("WWW-Authenticate") != `Bearer error="insufficient_scope"` || wantJSONError(t, r) != "insufficient_scope" {
			t.Fatalf("status %d headers %v body %q", r.Code, r.Header, r.Body)
		}
		wantNoStoreHeaders(t, r)
		wantAlive(t, e, app, a.RefreshToken)
		wantAlive(t, e, frag, f.RefreshToken)
		if auditRows(t, e) != total {
			t.Error("an audit row was written")
		}
	})
	t.Run("with a refresh_token the field is ignored", func(t *testing.T) {
		e := signOutEnv(t)
		a := exchange(t, e, app)
		b := exchange(t, e, app)
		r := logout(t, e, http.MethodPost, url.Values{"refresh_token": {b.RefreshToken}, "client_id": {app.ID}, "session": {sidOf(t, a.AccessToken)}}, nil)
		if r.Code != http.StatusNoContent {
			t.Fatalf("status %d %q", r.Code, r.Body)
		}
		wantRevoked(t, e, app, b.RefreshToken)
		wantAlive(t, e, app, a.RefreshToken)
	})
	t.Run("a bad access token is invalid_token before the fields are read", func(t *testing.T) {
		e := signOutEnv(t)
		tk := exchange(t, e, app)
		tk.AccessToken = "garbage"
		r := signOut(t, e, tk, url.Values{"session": {"x"}, "all_sessions": {"true"}})
		if r.Code != 401 || wantJSONError(t, r) != "invalid_token" {
			t.Errorf("status %d body %q", r.Code, r.Body)
		}
		wantNoStoreHeaders(t, r)
	})
	t.Run("a user deleted after the token check is invalid_token", func(t *testing.T) {
		e := signOutEnv(t)
		a := exchange(t, e, app)
		b := exchange(t, e, app)
		e.Faults.FailWrite = store.ErrNotFound
		r := signOut(t, e, a, url.Values{"session": {sidOf(t, b.AccessToken)}})
		e.Faults.FailWrite = nil
		if r.Code != 401 || wantJSONError(t, r) != "invalid_token" {
			t.Errorf("status %d body %q", r.Code, r.Body)
		}
		wantNoStoreHeaders(t, r)
		wantAlive(t, e, app, b.RefreshToken)
	})
	t.Run("a store failure revokes nothing and is answered with no-store", func(t *testing.T) {
		for _, row := range []struct {
			name   string
			err    error
			status int
			code   string
		}{
			{"unavailable", store.ErrUnavailable, 503, "temporarily_unavailable"},
			{"failing", fmt.Errorf("disk on fire"), 500, "server_error"},
		} {
			t.Run(row.name, func(t *testing.T) {
				e := signOutEnv(t)
				a := exchange(t, e, app)
				b := exchange(t, e, app)
				e.Faults.Fail("Refresh.RevokeSession", row.err)
				r := signOut(t, e, a, url.Values{"session": {sidOf(t, b.AccessToken)}})
				e.Faults.Fail("Refresh.RevokeSession", nil)
				if r.Code != row.status || wantJSONError(t, r) != row.code {
					t.Errorf("status %d body %q", r.Code, r.Body)
				}
				wantNoStoreHeaders(t, r)
				if n := len(sessionAudit(t, e)); n != 0 {
					t.Errorf("%d audit rows", n)
				}
				wantAlive(t, e, app, b.RefreshToken)
			})
		}
	})
}

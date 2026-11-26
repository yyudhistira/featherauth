package oidc_test

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/testutil/server"
	"github.com/yyudhistira/featherauth/internal/token"
)

// receiverURI is the back-channel logout URI of the web client in these tests.
const receiverURI = "https://receiver.example.com/logout"

// backchannelEnv starts the service with the web client's back-channel logout
// URI, its session management and its account deletion; frag has none of them.
func backchannelEnv(t *testing.T) *server.Env {
	t.Helper()
	e := server.New(t)
	e.Reload(t, func(y string) string {
		return strings.Replace(y, "  web:\n    redirect_uris: [https://app.example.com/callback]\n    web_origins: [https://app.example.com]\n",
			"  web:\n    redirect_uris: [https://app.example.com/callback]\n    web_origins: [https://app.example.com]\n"+
				"    allow_session_management: true\n    allow_account_delete: true\n    backchannel_logout_uri: "+receiverURI+"\n", 1)
	})
	if got := e.Realm.Clients[config.ClientID("web")].BackchannelLogoutURI; got != receiverURI {
		t.Fatalf("the URI is %q", got)
	}
	return e
}

// queuedRow is one row of logout_notifications.
type queuedRow struct{ Session, Client, User string }

// queuedRows reads logout_notifications from the service's database file. The
// tests read the table directly, because a claim would move the rows.
func queuedRows(t *testing.T, e *server.Env) []queuedRow {
	t.Helper()
	db, err := sql.Open("sqlite", e.DatabasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	rows, err := db.Query(`SELECT session_id, client_id, user_id FROM logout_notifications ORDER BY session_id`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []queuedRow
	for rows.Next() {
		var r queuedRow
		if err := rows.Scan(&r.Session, &r.Client, &r.User); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// queuedSessions counts the rows of each session.
func queuedSessions(t *testing.T, e *server.Env) map[string]int {
	t.Helper()
	out := map[string]int{}
	for _, r := range queuedRows(t, e) {
		out[r.Session]++
	}
	return out
}

// newlyQueued returns the rows added since before, by session.
func newlyQueued(before, after map[string]int) map[string]int {
	out := map[string]int{}
	for s, n := range after {
		if d := n - before[s]; d != 0 {
			out[s] = d
		}
	}
	return out
}

// jwtClaim returns a claim of a token, read without verifying it.
func jwtClaim(t *testing.T, jwt, name string) string {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(strings.Split(jwt, ".")[1])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return fmt.Sprint(m[name])
}

// Covers: FR-43 (part), SEC-35 (part)
// Acceptance: Back-channel logout (part)
// Every kind of revocation of a session of a client with the URI queues one row
// for that session, with its client and user; the frag client, which has no
// URI, queues none.
func TestRevocationsQueueOneRowPerSession(t *testing.T) {
	app, frag := server.ClientQuery, server.ClientFragment
	// step runs one revocation of a fresh login and wants the rows it queues.
	type step struct {
		name string
		run  func(t *testing.T, e *server.Env, a, b, f server.Tokens) // what to revoke
		want func(a, b, f server.Tokens) map[string]int               // the sessions it queues
	}
	sid := func(tk server.Tokens) string { return jwtClaim(t, tk.AccessToken, "sid") }
	steps := []step{
		{"the logout with id_token_hint", func(t *testing.T, e *server.Env, a, b, f server.Tokens) {
			wantSignedOut(t, logout(t, e, http.MethodGet, url.Values{"id_token_hint": {a.IDToken}}, nil))
		}, func(a, b, f server.Tokens) map[string]int { return map[string]int{sid(a): 1} }},
		{"the logout by refresh token", func(t *testing.T, e *server.Env, a, b, f server.Tokens) {
			if r := logout(t, e, http.MethodPost, url.Values{"refresh_token": {a.RefreshToken}, "client_id": {app.ID}}, nil); r.Code != 204 {
				t.Fatalf("status %d", r.Code)
			}
		}, func(a, b, f server.Tokens) map[string]int { return map[string]int{sid(a): 1} }},
		{"the bearer logout", func(t *testing.T, e *server.Env, a, b, f server.Tokens) {
			if r := signOut(t, e, a, nil); r.Code != 204 {
				t.Fatalf("status %d", r.Code)
			}
		}, func(a, b, f server.Tokens) map[string]int { return map[string]int{sid(a): 1} }},
		{"the session field", func(t *testing.T, e *server.Env, a, b, f server.Tokens) {
			if r := signOut(t, e, a, url.Values{"session": {sid(b)}}); r.Code != 204 {
				t.Fatalf("status %d", r.Code)
			}
		}, func(a, b, f server.Tokens) map[string]int { return map[string]int{sid(b): 1} }},
		{"sign out everywhere", func(t *testing.T, e *server.Env, a, b, f server.Tokens) {
			if r := signOut(t, e, a, url.Values{"all_sessions": {"true"}}); r.Code != 204 {
				t.Fatalf("status %d", r.Code)
			}
		}, func(a, b, f server.Tokens) map[string]int { return map[string]int{sid(a): 1, sid(b): 1} }},
		{"the revocation endpoint", func(t *testing.T, e *server.Env, a, b, f server.Tokens) {
			wantRevokeAnswer(t, revoke(t, e, revokeForm(app, a.RefreshToken), nil))
		}, func(a, b, f server.Tokens) map[string]int { return map[string]int{sid(a): 1} }},
		{"a reuse of a rotated refresh token", func(t *testing.T, e *server.Env, a, b, f server.Tokens) {
			// Rotation alone queues nothing; the reuse after the grace window ends the session.
			wantTokens(t, refresh(t, e, app, a.RefreshToken))
			e.Clock.Advance(time.Minute)
			if r := refresh(t, e, app, a.RefreshToken); r.Code != 400 {
				t.Fatalf("reuse: status %d", r.Code)
			}
		}, func(a, b, f server.Tokens) map[string]int { return map[string]int{sid(a): 1} }},
		{"an expired session", func(t *testing.T, e *server.Env, a, b, f server.Tokens) {
			e.Clock.Advance(800 * time.Hour) // the refresh tokens expired
			wantRevokeAnswer(t, revoke(t, e, revokeForm(app, a.RefreshToken), nil))
		}, func(a, b, f server.Tokens) map[string]int { return map[string]int{sid(a): 1} }},
		{"disabling the user", func(t *testing.T, e *server.Env, a, b, f server.Tokens) {
			e.DisableUser(t, store.UserID(jwtClaim(t, a.IDToken, "sub")), true)
		}, func(a, b, f server.Tokens) map[string]int { return map[string]int{sid(a): 1, sid(b): 1} }},
		{"deleting the user", func(t *testing.T, e *server.Env, a, b, f server.Tokens) {
			if r := deleteAccountWith(t, e, http.MethodDelete, a.AccessToken); r.Code != 204 {
				t.Fatalf("status %d %q", r.Code, r.Body)
			}
		}, func(a, b, f server.Tokens) map[string]int { return map[string]int{sid(a): 1, sid(b): 1} }},
	}
	for _, st := range steps {
		t.Run(st.name, func(t *testing.T) {
			e := backchannelEnv(t)
			a := exchange(t, e, app)
			b := exchange(t, e, app)
			f := exchange(t, e, frag)
			before := queuedSessions(t, e)
			st.run(t, e, a, b, f)
			got := newlyQueued(before, queuedSessions(t, e))
			if want := st.want(a, b, f); !reflect.DeepEqual(got, want) {
				t.Fatalf("queued %v, want %v", got, want)
			}
			for _, r := range queuedRows(t, e) {
				if r.Client != app.ID || r.User != jwtClaim(t, a.IDToken, "sub") && r.User != jwtClaim(t, b.IDToken, "sub") {
					t.Errorf("row %+v: want the web client and the user of the login", r)
				}
			}
		})
	}
}

// Covers: FR-43 (part)
// Acceptance: Back-channel logout (part)
// A session revoked before queues nothing again, and nothing is queued for a
// client without the URI.
func TestNoRowForASessionRevokedBeforeOrWithoutTheURI(t *testing.T) {
	app, frag := server.ClientQuery, server.ClientFragment
	e := backchannelEnv(t)
	a := exchange(t, e, app)
	if r := signOut(t, e, a, nil); r.Code != 204 {
		t.Fatalf("first logout: %d", r.Code)
	}
	before := queuedSessions(t, e)
	if r := signOut(t, e, a, nil); r.Code != 204 {
		t.Fatalf("second logout: %d", r.Code)
	}
	wantRevokeAnswer(t, revoke(t, e, revokeForm(app, a.RefreshToken), nil))
	if got := newlyQueued(before, queuedSessions(t, e)); len(got) != 0 {
		t.Fatalf("a session revoked before queued again: %v", got)
	}

	f := exchange(t, e, frag)
	before = queuedSessions(t, e)
	if r := signOut(t, e, f, nil); r.Code != 204 {
		t.Fatalf("frag logout: %d", r.Code)
	}
	if got := newlyQueued(before, queuedSessions(t, e)); len(got) != 0 {
		t.Fatalf("a client without the URI queued %v", got)
	}
}

// Covers: SEC-35 (part)
// Acceptance: Logout token is not a credential
// A logout token is no credential: a bearer request is 401 invalid_token, an
// id_token_hint is refused on the error page, and the revocation endpoint answers
// 200 and changes nothing.
func TestLogoutTokenIsNotACredential(t *testing.T) {
	app := server.ClientQuery
	e := backchannelEnv(t)
	tk := exchange(t, e, app)
	raw, err := e.Issuer.Logout(e.Realm, e.Realm.Clients[config.ClientID("web")], token.UserID(jwtClaim(t, tk.IDToken, "sub")), token.SessionID(sidOf(t, tk.AccessToken)), "jti-1")
	if err != nil {
		t.Fatal(err)
	}

	r := userinfo(t, e, http.MethodGet, raw, nil)
	if r.Code != 401 || r.Header.Get("WWW-Authenticate") != `Bearer error="invalid_token"` || wantJSONError(t, r) != "invalid_token" {
		t.Errorf("bearer: status %d headers %v body %q", r.Code, r.Header, r.Body)
	}
	wantRefusal(t, logout(t, e, http.MethodGet, url.Values{"id_token_hint": {raw}}, nil))
	wantRevokeAnswer(t, revoke(t, e, revokeForm(app, raw), nil))
	wantAlive(t, e, app, tk.RefreshToken)
}

// Covers: FR-43 (part)
// Acceptance: Back-channel logout (part)
// Using a login code twice ends the session it came from, and the session's
// back-channel logout is queued in the same transaction.
func TestCodeReuseQueuesTheSession(t *testing.T) {
	app := server.ClientQuery
	e := backchannelEnv(t)
	res := e.Login(t, app)
	tk := wantTokens(t, post(t, e, server.CodeForm(app, res), nil))
	before := queuedSessions(t, e)
	if r := post(t, e, server.CodeForm(app, res), nil); r.Code != 400 {
		t.Fatalf("second use of the code: status %d body %q", r.Code, r.Body)
	}
	if got, want := newlyQueued(before, queuedSessions(t, e)), map[string]int{sidOf(t, tk.AccessToken): 1}; !reflect.DeepEqual(got, want) {
		t.Fatalf("queued %v, want %v", got, want)
	}
}

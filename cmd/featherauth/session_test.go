package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/secure"
	"github.com/yyudhistira/featherauth/internal/store"
)

// addSessionToken stores a refresh token of a user of the admin env's realm.
// The default token is active from two hours before t0 until an hour after;
// fn may change it.
func (e *adminEnv) addSessionToken(t *testing.T, id, token, session string, user store.UserID, fn func(*store.RefreshToken)) {
	t.Helper()
	ctx := context.Background()
	r := store.RefreshToken{
		ID: store.RefreshTokenID(id), RealmID: "r1", UserID: user, ClientID: "app",
		TokenHash: secure.HashOf(token), SessionID: store.SessionID(session),
		SessionStartedAt: t0.Add(-2 * time.Hour), AuthTime: t0.Add(-3 * time.Hour),
		CreatedAt: t0.Add(-10 * time.Minute), ExpiresAt: t0.Add(time.Hour),
	}
	if fn != nil {
		fn(&r)
	}
	if err := e.svc.Write(ctx, func(tx store.Tx) error { return tx.RefreshTokens().Insert(ctx, r) }); err != nil {
		t.Fatal(err)
	}
}

// listedSessions runs `session list <realm> <user>` and returns its rows as
// generic JSON objects, so the test sees the keys the command prints.
func (e *adminEnv) listedSessions(t *testing.T, user string) []map[string]any {
	t.Helper()
	r := e.run(t, "session", "list", "main", user)
	if r.code != 0 {
		t.Fatalf("session list %s: %+v", user, r)
	}
	var rows []map[string]any
	if err := json.Unmarshal([]byte(r.stdout), &rows); err != nil {
		t.Fatalf("session list %s is not a JSON list: %v: %s", user, err, r.stdout)
	}
	return rows
}

// sessionIDsOf returns the session_id of each row.
func sessionIDsOf(rows []map[string]any) []string {
	ids := make([]string, 0, len(rows))
	for _, row := range rows {
		ids = append(ids, fmt.Sprint(row["session_id"]))
	}
	return ids
}

// assertOneAuditLine checks that a successful revoke printed nothing on stdout
// and exactly one audit line on stderr, for the action.
func assertOneAuditLine(t *testing.T, r result, action string) {
	t.Helper()
	if r.stdout != "" {
		t.Fatalf("stdout %q, want nothing", r.stdout)
	}
	lines := strings.Split(strings.TrimRight(r.stderr, "\n"), "\n")
	if len(lines) != 1 || !strings.Contains(lines[0], `"audit":true`) || !strings.Contains(lines[0], `"action":"`+action+`"`) {
		t.Fatalf("stderr %q, want exactly one %s audit line", r.stderr, action)
	}
}

// Covers: FR-20 (part), FR-39 (part)
// Acceptance: Session commands
func TestSessionCommandsAcceptanceRow(t *testing.T) {
	forEachDB(t, func(t *testing.T, d dbDriver) {
		e := newAdminEnv(t, d)
		e.addSessionToken(t, "a1", "tok-a1", "s-a", "u1", nil)
		e.addSessionToken(t, "b1", "tok-b1", "s-b", "u1", func(r *store.RefreshToken) {
			r.ClientID, r.SessionStartedAt, r.CreatedAt, r.ExpiresAt = "web", t0.Add(-time.Hour), t0.Add(-5*time.Minute), t0.Add(2*time.Hour)
		})
		e.addSessionToken(t, "x1", "tok-x1", "s-x", "u1", func(r *store.RefreshToken) { r.ExpiresAt = t0.Add(-time.Minute) })
		e.addSessionToken(t, "o1", "tok-o1", "s-o", "u2", nil)

		// Two live sessions with the listed fields; the expired one is not listed.
		rows := e.listedSessions(t, "u1")
		if got := sessionIDsOf(rows); len(got) != 2 || got[0] != "s-a" || got[1] != "s-b" {
			t.Fatalf("listed sessions %v, want [s-a s-b]", got)
		}
		wantKeys := []string{"auth_time", "client_id", "expires_at", "last_used_at", "session_id", "started_at"}
		for _, row := range rows {
			if len(row) != len(wantKeys) {
				t.Fatalf("row %v has keys other than %v", row, wantKeys)
			}
			for _, k := range wantKeys {
				if _, ok := row[k]; !ok {
					t.Fatalf("row %v has no %q", row, k)
				}
			}
		}
		first := rows[0]
		if first["client_id"] != "app" || first["started_at"] != "2026-03-01T10:00:00Z" ||
			first["auth_time"] != "2026-03-01T09:00:00Z" || first["last_used_at"] != "2026-03-01T11:50:00Z" ||
			first["expires_at"] != "2026-03-01T13:00:00Z" {
			t.Fatalf("session s-a = %v", first)
		}

		// One session revoked and audited.
		before := len(e.audit(t))
		r := e.run(t, "session", "revoke", "main", "u1", "--session", "s-a")
		if r.code != 0 {
			t.Fatalf("revoke one: %+v", r)
		}
		assertOneAuditLine(t, r, "user.sessions_revoked")
		ev := lastAction(t, e)
		if ev.Action != "user.sessions_revoked" || ev.Actor != "admin" || ev.UserID != "u1" || fmt.Sprint(ev.Details["sessions"]) != "1" {
			t.Fatalf("audit row = %+v", ev)
		}
		if got := sessionIDsOf(e.listedSessions(t, "u1")); len(got) != 1 || got[0] != "s-b" {
			t.Fatalf("after revoking s-a the user lists %v, want [s-b]", got)
		}

		// All of the user's sessions, revoked and audited once; the second run
		// changes and audits nothing.
		r = e.run(t, "session", "revoke", "main", "u1")
		if r.code != 0 {
			t.Fatalf("revoke all of u1: %+v", r)
		}
		assertOneAuditLine(t, r, "user.sessions_revoked")
		if ev := lastAction(t, e); ev.Action != "user.sessions_revoked" || fmt.Sprint(ev.Details["sessions"]) != "1" {
			t.Fatalf("audit row = %+v", ev)
		}
		afterFirst := len(e.audit(t))
		if afterFirst != before+2 {
			t.Fatalf("%d audit rows, want %d", afterFirst, before+2)
		}
		if r := e.run(t, "session", "revoke", "main", "u1"); r.code != 0 || r.stdout != "" || r.stderr != "" {
			t.Fatalf("second revoke of u1: %+v", r)
		}
		if len(e.audit(t)) != afterFirst {
			t.Fatal("the second run of session revoke wrote an audit row")
		}

		// Every session of the realm, with one realm row.
		r = e.run(t, "session", "revoke", "main", "--all")
		if r.code != 0 {
			t.Fatalf("revoke --all: %+v", r)
		}
		assertOneAuditLine(t, r, "realm.sessions_revoked")
		ev = lastAction(t, e)
		if ev.Action != "realm.sessions_revoked" || ev.Actor != "admin" || ev.UserID != "" || fmt.Sprint(ev.Details["sessions"]) != "1" {
			t.Fatalf("realm audit row = %+v", ev)
		}
		if got := sessionIDsOf(e.listedSessions(t, "u2")); len(got) != 0 {
			t.Fatalf("u2 still lists %v after --all", got)
		}
		if r := e.run(t, "session", "revoke", "main", "--all"); r.code != 0 || len(e.audit(t)) != afterFirst+1 {
			t.Fatalf("second --all: %+v, %d audit rows", r, len(e.audit(t)))
		}

		// Usage error: --all with a user id.
		n := len(e.audit(t))
		if r := e.run(t, "session", "revoke", "main", "u1", "--all"); r.code != 2 {
			t.Fatalf("--all with a user id: exit %d, want 2 (%+v)", r.code, r)
		}
		if len(e.audit(t)) != n {
			t.Fatal("a usage error wrote an audit row")
		}
		// Failure: an unknown user, and an unknown realm, exit 1.
		if r := e.run(t, "session", "list", "main", "u9"); r.code != 1 {
			t.Fatalf("unknown user: exit %d, want 1 (%+v)", r.code, r)
		}
		if r := e.run(t, "session", "revoke", "main", "u9"); r.code != 1 {
			t.Fatalf("revoke for an unknown user: exit %d, want 1 (%+v)", r.code, r)
		}
		// Failure: an unknown realm exits 1 for every form, with no output and no audit row.
		n = len(e.audit(t))
		for _, args := range [][]string{
			{"session", "list", "nope", "u1"},
			{"session", "revoke", "nope", "u1"},
			{"session", "revoke", "nope", "--all"},
		} {
			if r := e.run(t, args...); r.code != 1 || r.stdout != "" {
				t.Fatalf("%v: %+v, want exit 1 and no output", args, r)
			}
		}
		if len(e.audit(t)) != n {
			t.Fatal("a refused command for an unknown realm wrote an audit row")
		}
	})
}

// Covers: FR-39 (part)
func TestSessionRevokeOfAnotherUsersOrAnUnknownSessionExitsOne(t *testing.T) {
	forEachDB(t, func(t *testing.T, d dbDriver) {
		e := newAdminEnv(t, d)
		e.addSessionToken(t, "o1", "tok-o1", "s-o", "u2", nil)
		n := len(e.audit(t))
		for _, sess := range []string{"s-o", "nope"} {
			r := e.run(t, "session", "revoke", "main", "u1", "--session", sess)
			if r.code != 1 {
				t.Fatalf("revoke %s for u1: exit %d, want 1 (%+v)", sess, r.code, r)
			}
		}
		if len(e.audit(t)) != n {
			t.Fatal("a refused revoke wrote an audit row")
		}
		if got := sessionIDsOf(e.listedSessions(t, "u2")); len(got) != 1 || got[0] != "s-o" {
			t.Fatalf("u2's session changed: %v", got)
		}
	})
}

// Covers: FR-39 (part)
func TestSessionRevokeOfARevokedOrExpiredSessionChangesNothing(t *testing.T) {
	forEachDB(t, func(t *testing.T, d dbDriver) {
		e := newAdminEnv(t, d)
		e.addSessionToken(t, "a1", "tok-a1", "s-a", "u1", nil)
		e.addSessionToken(t, "x1", "tok-x1", "s-x", "u1", func(r *store.RefreshToken) { r.ExpiresAt = t0.Add(-time.Minute) })
		if r := e.run(t, "session", "revoke", "main", "u1", "--session", "s-a"); r.code != 0 {
			t.Fatalf("first revoke: %+v", r)
		}
		n := len(e.audit(t))
		for _, sess := range []string{"s-a", "s-x"} {
			r := e.run(t, "session", "revoke", "main", "u1", "--session", sess)
			if r.code != 0 || r.stdout != "" || r.stderr != "" {
				t.Fatalf("revoke of %s (not active): %+v", sess, r)
			}
		}
		if len(e.audit(t)) != n {
			t.Fatal("a revoke of a session that is not active wrote an audit row")
		}
	})
}

// Covers: FR-20 (part), FR-39 (part)
func TestSessionListOfAUserWithNoSessionIsAnEmptyList(t *testing.T) {
	forEachDB(t, func(t *testing.T, d dbDriver) {
		e := newAdminEnv(t, d)
		r := e.run(t, "session", "list", "main", "u1")
		if r.code != 0 || strings.TrimSpace(r.stdout) != "[]" {
			t.Fatalf("empty list: %+v", r)
		}
	})
}

// Covers: FR-20 (part), FR-39 (part)
func TestSessionCommandUsageErrorsExitTwo(t *testing.T) {
	forEachDB(t, func(t *testing.T, d dbDriver) {
		cases := map[string][]string{
			"no subcommand":                              {"session"},
			"unknown subcommand":                         {"session", "bogus"},
			"list without arguments":                     {"session", "list"},
			"list without a user":                        {"session", "list", "main"},
			"list with extra":                            {"session", "list", "main", "u1", "extra"},
			"list with a flag":                           {"session", "list", "main", "u1", "--session", "s-a"},
			"revoke without arguments":                   {"session", "revoke"},
			"revoke without a user":                      {"session", "revoke", "main"},
			"revoke with extra":                          {"session", "revoke", "main", "u1", "extra"},
			"revoke --session alone":                     {"session", "revoke", "main", "u1", "--session"},
			"revoke empty --session":                     {"session", "revoke", "main", "u1", "--session", ""},
			"revoke --all with a user id":                {"session", "revoke", "main", "u1", "--all"},
			"revoke --all with a user id after the flag": {"session", "revoke", "main", "--all", "u1"},
			"revoke --all with --session":                {"session", "revoke", "main", "--all", "--session", "s-a"},
			"revoke with an unknown flag":                {"session", "revoke", "main", "u1", "--bogus"},
		}
		for name, args := range cases {
			t.Run(name, func(t *testing.T) {
				e := newAdminEnv(t, d)
				e.addSessionToken(t, "a1", "tok-a1", "s-a", "u1", nil)
				n := len(e.audit(t))
				r := e.run(t, args...)
				if r.code != 2 || r.stdout != "" {
					t.Fatalf("%v: %+v, want exit 2 and no output", args, r)
				}
				if len(e.audit(t)) != n {
					t.Fatalf("%v wrote an audit row", args)
				}
				if got := sessionIDsOf(e.listedSessions(t, "u1")); len(got) != 1 {
					t.Fatalf("%v changed the sessions: %v", args, got)
				}
			})
		}
	})
}

// Covers: FR-39 (part)
func TestSessionCommandsPrintNoEmailOrTokenHash(t *testing.T) {
	forEachDB(t, func(t *testing.T, d dbDriver) {
		e := newAdminEnv(t, d)
		e.addSessionToken(t, "a1", "tok-secret-a", "s-a", "u1", nil)
		e.addSessionToken(t, "b1", "tok-secret-b", "s-b", "u1", nil)
		hash := string(secure.HashOf("tok-secret-a"))
		outs := []result{
			e.run(t, "session", "list", "main", "u1"),
			e.run(t, "session", "revoke", "main", "u1", "--session", "s-a"),
			e.run(t, "session", "revoke", "main", "--all"),
		}
		for _, r := range outs {
			if r.code != 0 {
				t.Fatalf("%+v", r)
			}
			for _, secret := range []string{"Ann@Example.org", "ann@example.org", "bob@example.org", hash, "tok-secret-a"} {
				if strings.Contains(r.stdout, secret) || strings.Contains(r.stderr, secret) {
					t.Fatalf("output holds %q: %+v", secret, r)
				}
			}
		}
	})
}

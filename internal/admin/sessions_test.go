package admin_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/admin"
	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/secure"
	"github.com/yyudhistira/featherauth/internal/store"
)

// addRefresh stores a refresh token of the user in the session of this env's
// realm. The default token is active from two hours before start and expires
// an hour after it; fn may change it.
func (e *env) addRefresh(t *testing.T, id, token, session string, user store.UserID, fn func(*store.RefreshToken)) {
	t.Helper()
	ctx := context.Background()
	r := store.RefreshToken{
		ID: store.RefreshTokenID(id), RealmID: e.realm, UserID: user, ClientID: "app",
		TokenHash: secure.HashOf(token), SessionID: store.SessionID(session),
		SessionStartedAt: start.Add(-2 * time.Hour), AuthTime: start.Add(-3 * time.Hour),
		CreatedAt: start.Add(-10 * time.Minute), ExpiresAt: start.Add(time.Hour),
	}
	if fn != nil {
		fn(&r)
	}
	err := e.st.Write(ctx, func(tx store.Tx) error { return tx.RefreshTokens().Insert(ctx, r) })
	if err != nil {
		t.Fatal(err)
	}
}

// revokedAt returns the revocation time of the refresh token with that id.
func (e *env) revokedAt(t *testing.T, id string) time.Time {
	t.Helper()
	ctx := context.Background()
	var r store.RefreshToken
	err := e.st.Read(ctx, func(tx store.Tx) (err error) {
		r, err = tx.RefreshTokens().FindByID(ctx, e.realm, store.RefreshTokenID(id))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return r.RevokedAt
}

// sessionIDs returns the ids of the sessions ListSessions lists for the user.
func (e *env) sessionIDs(t *testing.T, user string) []string {
	t.Helper()
	ss, err := e.ops.ListSessions(context.Background(), "main", store.UserID(user))
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]string, 0, len(ss))
	for _, s := range ss {
		ids = append(ids, string(s.SessionID))
	}
	return ids
}

// sessionsSetup gives u1 two active sessions and one expired one, and u2 one
// active session.
func sessionsSetup(t *testing.T, e *env) {
	t.Helper()
	e.addUser(t, "u1", "ann@example.org", true)
	e.addUser(t, "u2", "bob@example.org", false)
	e.addRefresh(t, "a1", "tok-a1", "s-a", "u1", nil)
	e.addRefresh(t, "b1", "tok-b1", "s-b", "u1", func(r *store.RefreshToken) {
		r.ClientID, r.SessionStartedAt, r.CreatedAt = "web", start.Add(-time.Hour), start.Add(-5*time.Minute)
	})
	e.addRefresh(t, "x1", "tok-x1", "s-x", "u1", func(r *store.RefreshToken) { r.ExpiresAt = start.Add(-time.Minute) })
	e.addRefresh(t, "o1", "tok-o1", "s-o", "u2", nil)
}

// Covers: FR-39 (part)
func TestListSessionsIsTheActiveSessionsOfTheUser(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	sessionsSetup(t, e)
	e.addUser(t, "u3", "cy@example.org", false)

	got, err := e.ops.ListSessions(ctx, "main", "u1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("u1 has %d live sessions, want 2 (the expired one is left out): %+v", len(got), got)
	}
	first := got[0]
	if first.SessionID != "s-a" || first.ClientID != "app" || !first.StartedAt.Equal(start.Add(-2*time.Hour)) ||
		!first.AuthTime.Equal(start.Add(-3*time.Hour)) || !first.LastUsedAt.Equal(start.Add(-10*time.Minute)) ||
		!first.ExpiresAt.Equal(start.Add(time.Hour)) {
		t.Fatalf("first session = %+v", first)
	}
	if got[1].SessionID != "s-b" || got[1].ClientID != "web" {
		t.Fatalf("second session = %+v", got[1])
	}
	if ids := e.sessionIDs(t, "u2"); len(ids) != 1 || ids[0] != "s-o" {
		t.Fatalf("u2 sessions = %v", ids)
	}
	if ids := e.sessionIDs(t, "u3"); len(ids) != 0 {
		t.Fatalf("u3 has no session, got %v", ids)
	}
	for _, c := range []struct {
		name         string
		realm, user  string
		wantNotFound bool
	}{
		{"unknown user", "main", "nobody", true},
		{"unknown realm", "nope", "u1", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := e.ops.ListSessions(ctx, config.RealmName(c.realm), store.UserID(c.user))
			if !errors.Is(err, admin.ErrNotFound) {
				t.Fatalf("ListSessions = %v, want ErrNotFound", err)
			}
		})
	}
}

// Covers: FR-39 (part)
func TestRevokeOneSessionEndsItAndAuditsOnce(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	sessionsSetup(t, e)
	before := len(e.events(t))

	n, err := e.ops.RevokeSessions(ctx, "admin", "main", "u1", "s-a")
	if err != nil || n != 1 {
		t.Fatalf("RevokeSessions = %d, %v; want 1, nil", n, err)
	}
	if !e.revokedAt(t, "a1").Equal(start) {
		t.Fatalf("s-a token revoked at %v, want %v", e.revokedAt(t, "a1"), start)
	}
	if ids := e.sessionIDs(t, "u1"); len(ids) != 1 || ids[0] != "s-b" {
		t.Fatalf("u1 sessions after the revoke = %v, want [s-b]", ids)
	}
	if ids := e.sessionIDs(t, "u2"); len(ids) != 1 {
		t.Fatalf("u2's session changed: %v", ids)
	}
	evs := e.events(t)
	if len(evs) != before+1 {
		t.Fatalf("%d audit rows, want one more", len(evs)-before)
	}
	ev := e.lastEvent(t)
	if ev.Action != admin.ActionSessionsRevoked || ev.Actor != "admin" || ev.UserID != "u1" ||
		fmt.Sprint(ev.Details["sessions"]) != "1" {
		t.Fatalf("audit row = %+v", ev)
	}
}

// Covers: FR-39 (part)
func TestRevokeAllSessionsOfTheUserTwiceAuditsOnce(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	sessionsSetup(t, e)

	n, err := e.ops.RevokeSessions(ctx, "admin", "main", "u1", "")
	if err != nil || n != 2 {
		t.Fatalf("RevokeSessions = %d, %v; want 2, nil", n, err)
	}
	ev := e.lastEvent(t)
	if ev.Action != admin.ActionSessionsRevoked || ev.UserID != "u1" || fmt.Sprint(ev.Details["sessions"]) != "2" {
		t.Fatalf("audit row = %+v", ev)
	}
	before := len(e.events(t))
	n, err = e.ops.RevokeSessions(ctx, "admin", "main", "u1", "")
	if err != nil || n != 0 {
		t.Fatalf("second RevokeSessions = %d, %v; want 0, nil", n, err)
	}
	if len(e.events(t)) != before {
		t.Fatal("the second revoke wrote an audit row")
	}
	if ids := e.sessionIDs(t, "u2"); len(ids) != 1 {
		t.Fatalf("u2's session changed: %v", ids)
	}
}

// Covers: FR-39 (part)
func TestRevokeSessionsRefusesWhatIsNotAnActiveSessionOfTheUser(t *testing.T) {
	for _, c := range []struct {
		name, realm, user, session string
		notFound                   bool
	}{
		{"unknown user", "main", "nobody", "", true},
		{"unknown realm", "nope", "u1", "", true},
		{"another user's session", "main", "u1", "s-o", true},
		{"unknown session", "main", "u1", "nope", true},
		{"a revoked session of the user", "main", "u1", "s-revoked", false},
		{"an expired session of the user", "main", "u1", "s-x", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			ctx := context.Background()
			sessionsSetup(t, e)
			e.addRefresh(t, "r1", "tok-r1", "s-revoked", "u1", func(r *store.RefreshToken) { r.RevokedAt = start.Add(-time.Minute) })
			before := len(e.events(t))

			n, err := e.ops.RevokeSessions(ctx, "admin", config.RealmName(c.realm), store.UserID(c.user), store.SessionID(c.session))
			if c.notFound {
				if !errors.Is(err, admin.ErrNotFound) || n != 0 {
					t.Fatalf("RevokeSessions = %d, %v; want ErrNotFound", n, err)
				}
			} else if err != nil || n != 0 {
				t.Fatalf("RevokeSessions = %d, %v; want 0, nil", n, err)
			}
			if len(e.events(t)) != before {
				t.Fatal("a refused or no-op revoke wrote an audit row")
			}
			if ids := e.sessionIDs(t, "u1"); len(ids) != 2 {
				t.Fatalf("u1's live sessions changed: %v", ids)
			}
			if ids := e.sessionIDs(t, "u2"); len(ids) != 1 {
				t.Fatalf("u2's live sessions changed: %v", ids)
			}
			if !e.revokedAt(t, "o1").IsZero() {
				t.Fatal("another user's token was revoked")
			}
		})
	}
}

// Covers: FR-39 (part)
func TestRevokeRealmSessionsRevokesEveryUserOnce(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	sessionsSetup(t, e)

	n, err := e.ops.RevokeRealmSessions(ctx, "admin", "main")
	if err != nil || n != 3 {
		t.Fatalf("RevokeRealmSessions = %d, %v; want 3, nil", n, err)
	}
	ev := e.lastEvent(t)
	if ev.Action != admin.ActionRealmSessionsRevoked || ev.Actor != "admin" || ev.UserID != "" ||
		fmt.Sprint(ev.Details["sessions"]) != "3" {
		t.Fatalf("audit row = %+v", ev)
	}
	if ids := e.sessionIDs(t, "u1"); len(ids) != 0 {
		t.Fatalf("u1 still has sessions %v", ids)
	}
	if ids := e.sessionIDs(t, "u2"); len(ids) != 0 {
		t.Fatalf("u2 still has sessions %v", ids)
	}
	before := len(e.events(t))
	n, err = e.ops.RevokeRealmSessions(ctx, "admin", "main")
	if err != nil || n != 0 {
		t.Fatalf("second RevokeRealmSessions = %d, %v; want 0, nil", n, err)
	}
	if len(e.events(t)) != before {
		t.Fatal("the second realm revoke wrote an audit row")
	}
	if _, err := e.ops.RevokeRealmSessions(ctx, "admin", "nope"); !errors.Is(err, admin.ErrNotFound) {
		t.Fatalf("unknown realm: %v", err)
	}
}

// Covers: FR-39 (part)
func TestSessionOperationsLogNoEmailOrSecret(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.addUser(t, "u1", "ann@example.org", true)
	e.addRefresh(t, "a1", "tok-secret-a", "session-secret-a", "u1", nil)
	e.addRefresh(t, "b1", "tok-secret-b", "session-secret-b", "u1", nil)

	if _, err := e.ops.ListSessions(ctx, "main", "u1"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.ops.RevokeSessions(ctx, "admin", "main", "u1", "session-secret-a"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.ops.RevokeRealmSessions(ctx, "admin", "main"); err != nil {
		t.Fatal(err)
	}
	var sb strings.Builder
	sb.WriteString(e.log.String())
	for _, ev := range e.events(t) {
		fmt.Fprintf(&sb, "%v %v", ev.Action, ev.Details)
	}
	out := sb.String()
	if out == "" {
		t.Fatal("no audit line was logged")
	}
	for _, secret := range []string{"ann@example.org", "session-secret-a", "session-secret-b", "tok-secret-a", string(secure.HashOf("tok-secret-a"))} {
		if strings.Contains(out, secret) {
			t.Fatalf("the log or the audit rows hold %q", secret)
		}
	}
}

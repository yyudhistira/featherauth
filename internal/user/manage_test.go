package user_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/provider"
	"github.com/yyudhistira/featherauth/internal/secure"
	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/store/audit"
	"github.com/yyudhistira/featherauth/internal/testutil"
	"github.com/yyudhistira/featherauth/internal/user"
)

type fakeRevoker struct {
	tokens []string
	err    error
}

func (f *fakeRevoker) Revoke(_ context.Context, tok string) error {
	f.tokens = append(f.tokens, tok)
	return f.err
}

var _ provider.Revoker = (*fakeRevoker)(nil)

func newKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	if _, err := secure.Default.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

func newBox(t *testing.T, keys ...[]byte) *secure.Box {
	t.Helper()
	b, err := secure.NewBox(keys)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type mgrEnv struct {
	*env
	mgr  *user.Manager
	rev  *fakeRevoker
	path string // the SQLite file of the store, read by the queued helper
}

// realmOf is the configuration the test manager sees: the test realm, when the
// test has one (noConfig turns it off).
func (e *env) realmOf(noConfig bool) user.RealmOf {
	return func(name config.RealmName) (*config.Realm, bool) {
		if noConfig || name != "main" {
			return nil, false
		}
		return e.realm, true
	}
}

func (e *env) manager(st store.Store, box *secure.Box, rev *fakeRevoker) *user.Manager {
	w := audit.NewWriter(st, e.svcLog(), e.clock, secure.Default)
	revokers := func(realm, prov string) provider.Revoker {
		if realm == "main" && prov == "apple" && rev != nil {
			return rev
		}
		return nil
	}
	return user.NewManager(st, w, box, revokers, e.svcLog(), e.clock, secure.Default, e.realmOf(false))
}

func newMgrEnv(t *testing.T, box *secure.Box) *mgrEnv {
	t.Helper()
	st, path := testutil.NewStoreFile(t)
	e := newEnvWith(t, st)
	e.realm.Clients = map[config.ClientID]*config.Client{
		"app":  {BackchannelLogoutURI: "https://receiver.example.com/logout"},
		"frag": {}, // no URI: its sessions queue nothing
	}
	rev := &fakeRevoker{}
	return &mgrEnv{env: e, mgr: e.manager(st, box, rev), rev: rev, path: path}
}

// queued counts the logout notifications of each session, read from the store's file.
func (m *mgrEnv) queued(t *testing.T) map[string]int {
	t.Helper()
	db, err := sql.Open("sqlite", m.path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	rows, err := db.Query(`SELECT session_id FROM logout_notifications`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]int{}
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		out[s]++
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// seed makes a user with a Google and an Apple identity (the Apple one holds
// a sealed provider token) and two refresh tokens, plus another user with one.
func (m *mgrEnv) seed(t *testing.T, box *secure.Box, token string) (u, other *store.User) {
	t.Helper()
	u = m.must("google", trusted(), ident("g1", "ann@gmail.com", true))
	m.must("apple", trusted(), ident("a1", "ann@gmail.com", true))
	other = m.must("github", untrusted(), ident("h1", "bob@example.org", true))
	ctx := context.Background()
	sealed := ""
	if box != nil {
		var err error
		if sealed, err = box.Seal([]byte(token)); err != nil {
			t.Fatal(err)
		}
	}
	err := m.st.Write(ctx, func(tx store.Tx) error {
		ai, err := tx.Identities().Find(ctx, u.RealmID, "apple", "a1")
		if err != nil {
			return err
		}
		if err := tx.Identities().SetProviderToken(ctx, u.RealmID, ai.ID, sealed); err != nil {
			return err
		}
		for i, row := range []struct {
			user store.UserID
			tok  string
		}{{u.ID, "tok1"}, {u.ID, "tok2"}, {other.ID, "tok3"}} {
			err := tx.RefreshTokens().Insert(ctx, store.RefreshToken{
				ID: store.RefreshTokenID("rt" + string(rune('a'+i))), RealmID: u.RealmID, UserID: row.user, ClientID: "app",
				TokenHash: secure.HashOf(row.tok), SessionID: store.SessionID("s" + string(rune('a'+i))),
				SessionStartedAt: m.clock.Now(), AuthTime: m.clock.Now(), ExpiresAt: m.clock.Now().Add(time.Hour),
				CreatedAt: m.clock.Now(),
			})
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return u, other
}

func (m *mgrEnv) refresh(t *testing.T, tok string) (store.RefreshToken, error) {
	t.Helper()
	var rt store.RefreshToken
	err := m.st.Read(context.Background(), func(tx store.Tx) (err error) {
		rt, err = tx.RefreshTokens().FindByHash(context.Background(), m.realmID(), secure.HashOf(tok))
		return err
	})
	return rt, err
}

func (m *mgrEnv) userGone(t *testing.T, u *store.User) bool {
	t.Helper()
	err := m.st.Read(context.Background(), func(tx store.Tx) error {
		_, err := tx.Users().Get(context.Background(), u.RealmID, u.ID)
		if !errors.Is(err, store.ErrNotFound) {
			return errors.New("user still there")
		}
		return nil
	})
	return err == nil
}

// changes returns the audit rows of the operations under test, leaving out the
// auto-link that the seed writes.
func (m *mgrEnv) changes() []store.AuditEvent {
	var out []store.AuditEvent
	for _, a := range m.audits() {
		if a.Action != user.ActionAutoLink {
			out = append(out, a)
		}
	}
	return out
}

func (m *mgrEnv) actions() []string {
	var out []string
	for _, a := range m.changes() {
		out = append(out, a.Action)
	}
	return out
}

func (m *mgrEnv) auditLines() int { return strings.Count(m.log.String(), `"audit":true`) }

func ctx() context.Context { return context.Background() }

// Covers: FR-13 (part)
// Acceptance: Account deletion (part)
func TestDeleteRemovesEverythingAndRevokesOnce(t *testing.T) {
	box := newBox(t, newKey(t))
	m := newMgrEnv(t, box)
	u, other := m.seed(t, box, "APPLE-REFRESH")
	m.log.Reset()
	if err := m.mgr.Delete(ctx(), "admin", "main", u.ID, user.DeleteOptions{RevokeAtProvider: true}); err != nil {
		t.Fatal(err)
	}
	if !m.userGone(t, u) {
		t.Fatal("user still exists")
	}
	if ids := m.identities(u); len(ids) != 0 {
		t.Fatalf("identities left: %d", len(ids))
	}
	for _, tok := range []string{"tok1", "tok2"} {
		if _, err := m.refresh(t, tok); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("%s: err = %v, want deleted", tok, err)
		}
	}
	if _, err := m.refresh(t, "tok3"); err != nil {
		t.Errorf("another user's token: %v", err)
	}
	if len(m.rev.tokens) != 1 || m.rev.tokens[0] != "APPLE-REFRESH" {
		t.Fatalf("revoker calls = %v", m.rev.tokens)
	}
	rows := m.changes()
	if len(rows) != 1 || rows[0].Action != "user.delete" || rows[0].Actor != "admin" || rows[0].UserID != u.ID {
		t.Fatalf("audit = %+v", rows)
	}
	if m.auditLines() != 1 {
		t.Errorf("audit lines = %d", m.auditLines())
	}
	if out := m.log.String(); strings.Contains(out, "APPLE-REFRESH") || strings.Contains(out, "ann@gmail.com") {
		t.Errorf("log holds a secret or an email: %s", out)
	}
	if _, err := m.refresh(t, "tok3"); err != nil || other == nil {
		t.Fatal("other user damaged")
	}
	// A second deletion finds nothing.
	err := m.mgr.Delete(ctx(), "admin", "main", u.ID, user.DeleteOptions{RevokeAtProvider: true})
	if !errors.Is(err, user.ErrNotFound) {
		t.Fatalf("second delete = %v", err)
	}
}

// Covers: FR-13 (part)
func TestDeleteWithoutProviderRevoke(t *testing.T) {
	box := newBox(t, newKey(t))
	m := newMgrEnv(t, box)
	u, _ := m.seed(t, box, "APPLE-REFRESH")
	if err := m.mgr.Delete(ctx(), "provider:apple", "main", u.ID, user.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	if len(m.rev.tokens) != 0 || !m.userGone(t, u) {
		t.Fatalf("revoker calls = %v, gone = %v", m.rev.tokens, m.userGone(t, u))
	}
	if rows := m.changes(); len(rows) != 1 || rows[0].Actor != "provider:apple" {
		t.Fatalf("audit = %+v", rows)
	}
}

// Covers: SEC-10 (part)
// Acceptance: Encryption key rotation (part)
func TestDeleteAcrossEncryptionKeyRotation(t *testing.T) {
	oldKey, newK := newKey(t), newKey(t)
	t.Run("old key kept", func(t *testing.T) {
		m := newMgrEnv(t, newBox(t, newK, oldKey))
		u, _ := m.seed(t, newBox(t, oldKey), "APPLE-REFRESH") // sealed with the old key
		if err := m.mgr.Delete(ctx(), "admin", "main", u.ID, user.DeleteOptions{RevokeAtProvider: true}); err != nil {
			t.Fatal(err)
		}
		if len(m.rev.tokens) != 1 || m.rev.tokens[0] != "APPLE-REFRESH" {
			t.Fatalf("revoker calls = %v", m.rev.tokens)
		}
	})
	t.Run("old key removed", func(t *testing.T) {
		m := newMgrEnv(t, newBox(t, newK))
		u, _ := m.seed(t, newBox(t, oldKey), "APPLE-REFRESH")
		m.log.Reset()
		if err := m.mgr.Delete(ctx(), "admin", "main", u.ID, user.DeleteOptions{RevokeAtProvider: true}); err != nil {
			t.Fatalf("deletion must complete: %v", err)
		}
		if len(m.rev.tokens) != 0 || !m.userGone(t, u) {
			t.Fatalf("revoker calls = %v, gone = %v", m.rev.tokens, m.userGone(t, u))
		}
		out := m.log.String()
		if !strings.Contains(out, `"level":"WARN"`) || !strings.Contains(out, "decrypt") || strings.Contains(out, "APPLE-REFRESH") {
			t.Errorf("log = %s", out)
		}
	})
	t.Run("no box", func(t *testing.T) {
		m := newMgrEnv(t, nil)
		u, _ := m.seed(t, newBox(t, oldKey), "APPLE-REFRESH")
		if err := m.mgr.Delete(ctx(), "admin", "main", u.ID, user.DeleteOptions{RevokeAtProvider: true}); err != nil {
			t.Fatal(err)
		}
		if len(m.rev.tokens) != 0 || !strings.Contains(m.log.String(), `"level":"WARN"`) {
			t.Fatalf("calls %v, log %s", m.rev.tokens, m.log.String())
		}
	})
}

// Covers: FR-13 (part)
func TestDeleteWhenProviderRevokeFails(t *testing.T) {
	box := newBox(t, newKey(t))
	m := newMgrEnv(t, box)
	u, _ := m.seed(t, box, "APPLE-REFRESH")
	m.rev.err = errors.New("apple is down")
	m.log.Reset()
	if err := m.mgr.Delete(ctx(), "admin", "main", u.ID, user.DeleteOptions{RevokeAtProvider: true}); err != nil {
		t.Fatalf("deletion must complete: %v", err)
	}
	if !m.userGone(t, u) || !strings.Contains(m.log.String(), `"level":"WARN"`) {
		t.Fatalf("gone %v, log %s", m.userGone(t, u), m.log.String())
	}
}

// Covers: FR-13 (part)
func TestDeleteWithoutRevokerForProvider(t *testing.T) {
	box := newBox(t, newKey(t))
	m := newMgrEnv(t, box)
	u, _ := m.seed(t, box, "APPLE-REFRESH")
	mgr := m.manager(m.st, box, nil) // no revoker for any provider
	if err := mgr.Delete(ctx(), "admin", "main", u.ID, user.DeleteOptions{RevokeAtProvider: true}); err != nil {
		t.Fatal(err)
	}
	if !m.userGone(t, u) {
		t.Fatal("user still exists")
	}
}

// Covers: FR-23 (part)
// Acceptance: User admin (part)
func TestDeleteUnknownUserAndRealm(t *testing.T) {
	m := newMgrEnv(t, nil)
	m.seed(t, nil, "")
	if err := m.mgr.Delete(ctx(), "admin", "main", "nope", user.DeleteOptions{}); !errors.Is(err, user.ErrNotFound) {
		t.Fatalf("unknown user = %v", err)
	}
	if err := m.mgr.Delete(ctx(), "admin", "other", "nope", user.DeleteOptions{}); !errors.Is(err, user.ErrNotFound) {
		t.Fatalf("unknown realm = %v", err)
	}
}

// Covers: FR-23 (part)
// Acceptance: User admin (part)
func TestDisableRevokesSessionsAndEnableDoesNotRestoreThem(t *testing.T) {
	m := newMgrEnv(t, nil)
	u, _ := m.seed(t, nil, "")
	m.log.Reset()
	if err := m.mgr.Disable(ctx(), "admin", "main", u.ID); err != nil {
		t.Fatal(err)
	}
	for tok, revoked := range map[string]bool{"tok1": true, "tok2": true, "tok3": false} {
		rt, err := m.refresh(t, tok)
		if err != nil || rt.RevokedAt.IsZero() == revoked {
			t.Fatalf("%s: %+v, %v, want revoked=%v", tok, rt, err, revoked)
		}
	}
	if got := m.stored(u); got.DisabledAt.IsZero() {
		t.Fatal("user not disabled")
	}
	if _, err := m.resolve("google", trusted(), ident("g1", "ann@gmail.com", true)); !errors.Is(err, user.ErrDisabled) {
		t.Fatalf("login of a disabled user = %v", err)
	}
	// Disabling again changes and audits nothing.
	if err := m.mgr.Disable(ctx(), "admin", "main", u.ID); err != nil {
		t.Fatal(err)
	}

	m.clock.Advance(time.Minute)
	if err := m.mgr.Enable(ctx(), "admin", "main", u.ID); err != nil {
		t.Fatal(err)
	}
	if got := m.stored(u); !got.DisabledAt.IsZero() {
		t.Fatal("user still disabled")
	}
	for _, tok := range []string{"tok1", "tok2"} {
		if rt, err := m.refresh(t, tok); err != nil || rt.RevokedAt.IsZero() {
			t.Fatalf("%s: old refresh token works again after enable: %+v, %v", tok, rt, err)
		}
	}
	if err := m.mgr.Enable(ctx(), "admin", "main", u.ID); err != nil { // idempotent
		t.Fatal(err)
	}
	want := []string{"user.disable", "user.enable"}
	got := m.actions()
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] || m.auditLines() != 2 {
		t.Fatalf("actions = %v, lines = %d", got, m.auditLines())
	}
	if _, err := m.resolve("google", trusted(), ident("g1", "ann@gmail.com", true)); err != nil {
		t.Fatalf("login after enable: %v", err)
	}
}

// Covers: FR-23 (part)
// Acceptance: User admin (part)
func TestLinkAndUnlinkAreAudited(t *testing.T) {
	m := newMgrEnv(t, nil)
	u, other := m.seed(t, nil, "")
	m.log.Reset()
	if err := m.mgr.Link(ctx(), "admin", "main", u.ID, "github", "h-new"); err != nil {
		t.Fatal(err)
	}
	if got, err := m.resolve("github", untrusted(), ident("h-new", "", false)); err != nil || got.ID != u.ID {
		t.Fatalf("login through the linked identity = %v, %v", got, err)
	}
	// An identity already held, by this user or another, cannot be linked again.
	for _, sub := range []string{"h-new", "h1"} {
		if err := m.mgr.Link(ctx(), "admin", "main", u.ID, "github", sub); !errors.Is(err, user.ErrConflict) {
			t.Fatalf("link of %s = %v, want ErrConflict", sub, err)
		}
	}
	if err := m.mgr.Link(ctx(), "admin", "main", "nope", "github", "x"); !errors.Is(err, user.ErrNotFound) {
		t.Fatalf("link to an unknown user = %v", err)
	}
	// Unlinking another user's identity finds nothing.
	if err := m.mgr.Unlink(ctx(), "admin", "main", u.ID, "github", "h1"); !errors.Is(err, user.ErrNotFound) {
		t.Fatalf("unlink of another user's identity = %v", err)
	}
	if err := m.mgr.Unlink(ctx(), "admin", "main", u.ID, "github", "h-new"); err != nil {
		t.Fatal(err)
	}
	if err := m.mgr.Unlink(ctx(), "admin", "main", u.ID, "github", "h-new"); !errors.Is(err, user.ErrNotFound) {
		t.Fatalf("second unlink = %v", err)
	}
	if err := m.mgr.Unlink(ctx(), "admin", "main", "nope", "github", "h-new"); !errors.Is(err, user.ErrNotFound) {
		t.Fatalf("unlink for an unknown user = %v", err)
	}
	var link, unlink int
	for _, a := range m.changes() {
		switch a.Action {
		case "identity.link":
			link++
			if a.Actor != "admin" || a.UserID != u.ID || a.Details["provider"] != "github" {
				t.Errorf("link row = %+v", a)
			}
		case "identity.unlink":
			unlink++
			if a.Actor != "admin" || a.UserID != u.ID || a.Details["provider"] != "github" {
				t.Errorf("unlink row = %+v", a)
			}
		}
	}
	if link != 1 || unlink != 1 || m.auditLines() != 2 {
		t.Fatalf("link %d unlink %d lines %d", link, unlink, m.auditLines())
	}
	if other == nil {
		t.Fatal("setup")
	}
}

// Covers: FR-13 (part), FR-23 (part)
func TestManagerStoreFailures(t *testing.T) {
	boxKey := newKey(t)
	scenarios := []struct {
		name string
		ops  []string
		run  func(m *user.Manager, u *store.User) error
	}{
		{"delete", []string{"Realms.Find", "Users.Get", "Identities.ListByUser", "Users.Delete", "Refresh.DeleteUser", "Audit.Insert"},
			func(m *user.Manager, u *store.User) error {
				return m.Delete(ctx(), "admin", "main", u.ID, user.DeleteOptions{RevokeAtProvider: true})
			}},
		{"disable", []string{"Users.Get", "Users.Update", "Refresh.RevokeUser", "Audit.Insert"},
			func(m *user.Manager, u *store.User) error { return m.Disable(ctx(), "admin", "main", u.ID) }},
		{"revoke sessions", []string{"Realms.Find", "Users.Get", "Refresh.RevokeSession", "Audit.Insert"},
			func(m *user.Manager, u *store.User) error {
				_, err := m.RevokeSessions(ctx(), "system", "main", u.ID)
				return err
			}},
		{"link", []string{"Users.Get", "Identities.Create", "Audit.Insert"},
			func(m *user.Manager, u *store.User) error {
				return m.Link(ctx(), "admin", "main", u.ID, "github", "h-new")
			}},
		{"unlink", []string{"Identities.Find", "Identities.Delete", "Audit.Insert"},
			func(m *user.Manager, u *store.User) error {
				return m.Unlink(ctx(), "admin", "main", u.ID, "apple", "a1")
			}},
		{"consent revoked", []string{"Identities.Find", "Identities.SetProviderToken", "Refresh.RevokeUser", "Audit.Insert"},
			func(m *user.Manager, u *store.User) error { return m.ConsentRevoked(ctx(), "main", "apple", "a1") }},
		{"account deleted, other identity", []string{"Identities.Find", "Identities.ListByUser", "Identities.Delete", "Refresh.RevokeUser", "Audit.Insert"},
			func(m *user.Manager, u *store.User) error { return m.AccountDeleted(ctx(), "main", "apple", "a1") }},
	}
	for _, sc := range scenarios {
		for _, op := range sc.ops {
			t.Run(sc.name+" "+op, func(t *testing.T) {
				box := newBox(t, boxKey)
				m := newMgrEnv(t, box)
				u, _ := m.seed(t, box, "APPLE-REFRESH")
				m.log.Reset()
				f := testutil.NewFaultStore(m.st)
				f.Fail(op, errInjected)
				rev := &fakeRevoker{}
				err := sc.run(m.manager(f, box, rev), u)
				if !errors.Is(err, errInjected) {
					t.Fatalf("err = %v, want the store failure", err)
				}
				if len(rev.tokens) != 0 || m.auditLines() != 0 || len(m.changes()) != 0 {
					t.Errorf("a failed change left effects: revoker %v, lines %d, rows %d", rev.tokens, m.auditLines(), len(m.changes()))
				}
				if m.userGone(t, u) {
					t.Error("user deleted by a failed change")
				}
			})
		}
	}
	t.Run("unavailable store", func(t *testing.T) {
		m := newMgrEnv(t, nil)
		u, _ := m.seed(t, nil, "")
		f := testutil.NewFaultStore(m.st)
		f.FailWrite = store.ErrUnavailable
		err := m.manager(f, nil, nil).Disable(ctx(), "admin", "main", u.ID)
		if !errors.Is(err, store.ErrUnavailable) {
			t.Fatalf("err = %v", err)
		}
	})
}

// Covers: FR-39
// Acceptance: Sign out everywhere (part)
func TestRevokeSessionsEndsEveryLiveSessionOfTheUser(t *testing.T) {
	m := newMgrEnv(t, nil)
	u, _ := m.seed(t, nil, "")
	m.log.Reset()
	n, err := m.mgr.RevokeSessions(ctx(), "system", "main", u.ID)
	if err != nil || n != 2 {
		t.Fatalf("RevokeSessions = %d, %v, want 2", n, err)
	}
	for tok, revoked := range map[string]bool{"tok1": true, "tok2": true, "tok3": false} { // tok3 is another user's
		rt, err := m.refresh(t, tok)
		if err != nil || rt.RevokedAt.IsZero() == revoked {
			t.Fatalf("%s: %+v, %v, want revoked=%v", tok, rt, err, revoked)
		}
	}
	rows := m.changes()
	if len(rows) != 1 || rows[0].Action != user.ActionSessionsRevoked || rows[0].Actor != "system" || rows[0].UserID != u.ID ||
		len(rows[0].Details) != 1 || rows[0].Details["sessions"] != float64(2) && rows[0].Details["sessions"] != 2 || m.auditLines() != 1 {
		t.Fatalf("audit rows %+v, lines %d", rows, m.auditLines())
	}
	// Nothing is left: no change and no row.
	if n, err := m.mgr.RevokeSessions(ctx(), "system", "main", u.ID); err != nil || n != 0 {
		t.Fatalf("second RevokeSessions = %d, %v, want 0", n, err)
	}
	if len(m.changes()) != 1 || m.auditLines() != 1 {
		t.Errorf("a second call wrote a row: %d rows, %d lines", len(m.changes()), m.auditLines())
	}
}

// Covers: FR-39
// Acceptance: Sign out everywhere (part)
func TestRevokeSessionsLeavesExpiredSessionsAndUnknownTargets(t *testing.T) {
	m := newMgrEnv(t, nil)
	u, _ := m.seed(t, nil, "")
	m.clock.Advance(2 * time.Hour) // the refresh tokens expired an hour ago
	if n, err := m.mgr.RevokeSessions(ctx(), "system", "main", u.ID); err != nil || n != 0 {
		t.Fatalf("RevokeSessions of expired sessions = %d, %v, want 0", n, err)
	}
	if len(m.changes()) != 0 {
		t.Errorf("rows %+v", m.changes())
	}
	if _, err := m.mgr.RevokeSessions(ctx(), "system", "main", "nobody"); !errors.Is(err, user.ErrNotFound) {
		t.Errorf("unknown user: %v", err)
	}
	if _, err := m.mgr.RevokeSessions(ctx(), "system", "nowhere", u.ID); !errors.Is(err, user.ErrNotFound) {
		t.Errorf("unknown realm: %v", err)
	}
}

// Covers: FR-42
// Acceptance: Sessions endpoint (part)
func TestRevokeSessionEndsOneOwnSessionOnce(t *testing.T) {
	m := newMgrEnv(t, nil)
	u, _ := m.seed(t, nil, "")
	m.log.Reset()
	n, err := m.mgr.RevokeSession(ctx(), "system", "main", u.ID, "sa")
	if err != nil || n != 1 {
		t.Fatalf("RevokeSession = %d, %v, want 1", n, err)
	}
	for tok, revoked := range map[string]bool{"tok1": true, "tok2": false, "tok3": false} {
		rt, err := m.refresh(t, tok)
		if err != nil || rt.RevokedAt.IsZero() == revoked {
			t.Fatalf("%s: %+v, %v, want revoked=%v", tok, rt, err, revoked)
		}
	}
	rows := m.changes()
	if len(rows) != 1 || rows[0].Action != user.ActionSessionsRevoked || rows[0].Actor != "system" || rows[0].UserID != u.ID ||
		len(rows[0].Details) != 1 || fmt.Sprint(rows[0].Details["sessions"]) != "1" || m.auditLines() != 1 {
		t.Fatalf("audit rows %+v, lines %d", rows, m.auditLines())
	}
	// Ended already: no change and no row.
	if n, err := m.mgr.RevokeSession(ctx(), "system", "main", u.ID, "sa"); err != nil || n != 0 {
		t.Fatalf("second RevokeSession = %d, %v, want 0", n, err)
	}
	if len(m.changes()) != 1 {
		t.Errorf("a second call wrote a row")
	}
	// Another user's session, an unknown one: ErrSessionNotFound, which is also ErrNotFound.
	for _, session := range []store.SessionID{"sc", "nope"} {
		_, err := m.mgr.RevokeSession(ctx(), "system", "main", u.ID, session)
		if !errors.Is(err, user.ErrSessionNotFound) || !errors.Is(err, user.ErrNotFound) {
			t.Errorf("session %s: %v, want ErrSessionNotFound", session, err)
		}
	}
	if rt, err := m.refresh(t, "tok3"); err != nil || !rt.RevokedAt.IsZero() {
		t.Errorf("another user's session was revoked: %+v, %v", rt, err)
	}
	// An unknown user is ErrNotFound but not a missing session.
	if _, err := m.mgr.RevokeSession(ctx(), "system", "main", "nobody", "sb"); !errors.Is(err, user.ErrNotFound) || errors.Is(err, user.ErrSessionNotFound) {
		t.Errorf("unknown user: %v", err)
	}
	if len(m.changes()) != 1 {
		t.Errorf("a refused call wrote a row")
	}
}

// Covers: FR-43 (part)
// Acceptance: Back-channel logout (part)
// Each call that ends sessions queues one row for each ended session of a client
// with the URI: the session commands, the disabling and the deletion of a user,
// and the provider events that revoke.
func TestRevocationsQueueTheEndedSessions(t *testing.T) {
	t.Run("one session, then nothing more, then an unknown one", func(t *testing.T) {
		m := newMgrEnv(t, nil)
		u, _ := m.seed(t, nil, "")
		if _, err := m.mgr.RevokeSession(ctx(), "system", "main", u.ID, "sa"); err != nil {
			t.Fatal(err)
		}
		if got := m.queued(t); !reflect.DeepEqual(got, map[string]int{"sa": 1}) {
			t.Fatalf("queued %v, want sa once", got)
		}
		if _, err := m.mgr.RevokeSession(ctx(), "system", "main", u.ID, "sa"); err != nil {
			t.Fatal(err)
		}
		if _, err := m.mgr.RevokeSession(ctx(), "system", "main", u.ID, "sc"); !errors.Is(err, user.ErrSessionNotFound) {
			t.Fatalf("another user's session: %v", err)
		}
		if got := m.queued(t); !reflect.DeepEqual(got, map[string]int{"sa": 1}) {
			t.Fatalf("queued %v after the repeats, want sa once", got)
		}
	})
	t.Run("every live session of the user", func(t *testing.T) {
		m := newMgrEnv(t, nil)
		u, _ := m.seed(t, nil, "")
		if _, err := m.mgr.RevokeSessions(ctx(), "system", "main", u.ID); err != nil {
			t.Fatal(err)
		}
		if got := m.queued(t); !reflect.DeepEqual(got, map[string]int{"sa": 1, "sb": 1}) {
			t.Fatalf("queued %v, want the two sessions of the user", got)
		}
	})
	t.Run("disabling the user, then deleting another", func(t *testing.T) {
		m := newMgrEnv(t, nil)
		u, other := m.seed(t, nil, "")
		if err := m.mgr.Disable(ctx(), "admin", "main", u.ID); err != nil {
			t.Fatal(err)
		}
		if got := m.queued(t); !reflect.DeepEqual(got, map[string]int{"sa": 1, "sb": 1}) {
			t.Fatalf("disable queued %v", got)
		}
		if err := m.mgr.Delete(ctx(), "admin", "main", other.ID, user.DeleteOptions{}); err != nil {
			t.Fatal(err)
		}
		if got := m.queued(t); !reflect.DeepEqual(got, map[string]int{"sa": 1, "sb": 1, "sc": 1}) {
			t.Fatalf("delete of the other user queued %v", got)
		}
	})
	t.Run("deleting the user queues its live sessions", func(t *testing.T) {
		m := newMgrEnv(t, nil)
		u, _ := m.seed(t, nil, "")
		if err := m.mgr.Delete(ctx(), "admin", "main", u.ID, user.DeleteOptions{}); err != nil {
			t.Fatal(err)
		}
		if got := m.queued(t); !reflect.DeepEqual(got, map[string]int{"sa": 1, "sb": 1}) {
			t.Fatalf("queued %v, want the sessions of the deleted user", got)
		}
	})
	t.Run("a provider's consent revoked, and its account deleted", func(t *testing.T) {
		m := newMgrEnv(t, nil)
		m.seed(t, nil, "")
		if err := m.mgr.ConsentRevoked(ctx(), "main", "apple", "a1"); err != nil {
			t.Fatal(err)
		}
		if got := m.queued(t); !reflect.DeepEqual(got, map[string]int{"sa": 1, "sb": 1}) {
			t.Fatalf("consent revoked queued %v", got)
		}
	})
}

// Covers: FR-43 (part)
// Acceptance: Back-channel logout (part)
// Without the realm's configuration a revocation keeps its plain behaviour: it ends
// the session, queues no logout notification and logs one warning.
func TestRevocationWithoutTheRealmConfiguration(t *testing.T) {
	m := newMgrEnv(t, nil)
	u, _ := m.seed(t, nil, "")
	noConfig := user.NewManager(m.st, audit.NewWriter(m.st, m.svcLog(), m.clock, secure.Default), nil, nil, m.svcLog(), m.clock, secure.Default, m.realmOf(true))
	if n, err := noConfig.RevokeSession(ctx(), "system", "main", u.ID, "sa"); err != nil || n != 1 {
		t.Fatalf("RevokeSession without the configuration = %d, %v, want 1 and no error", n, err)
	}
	if rt, err := m.refresh(t, "tok1"); err != nil || rt.RevokedAt.IsZero() {
		t.Fatalf("the session was not revoked: %+v, %v", rt, err)
	}
	if got := m.queued(t); len(got) != 0 {
		t.Fatalf("queued %v", got)
	}
	if !strings.Contains(m.log.String(), "back-channel logout not queued") {
		t.Fatalf("no warning in the log: %s", m.log.String())
	}
	m.clock.Advance(2 * time.Hour) // every token expired: nothing to end
	if n, err := noConfig.RevokeSessions(ctx(), "system", "main", u.ID); err != nil || n != 0 {
		t.Fatalf("RevokeSessions with nothing live = %d, %v, want 0 and no error", n, err)
	}
}

// Covers: FR-43 (part)
// Acceptance: Back-channel logout (part)
// Every session of the realm ends at once, with one audit row and the logouts
// of the sessions of the clients with the URI.
func TestRevokeRealmSessionsQueuesEverySessionAndAuditsOnce(t *testing.T) {
	m := newMgrEnv(t, nil)
	m.seed(t, nil, "")
	if n, err := m.mgr.RevokeRealmSessions(ctx(), "system", "main"); err != nil || n != 3 {
		t.Fatalf("RevokeRealmSessions = %d, %v, want 3", n, err)
	}
	if got := m.queued(t); !reflect.DeepEqual(got, map[string]int{"sa": 1, "sb": 1, "sc": 1}) {
		t.Fatalf("queued %v, want every session", got)
	}
	rows := m.changes()
	if len(rows) != 1 || rows[0].Action != user.ActionRealmSessionsRevoked || rows[0].UserID != "" || fmt.Sprint(rows[0].Details["sessions"]) != "3" {
		t.Fatalf("audit rows %+v, want one realm row with 3 sessions", rows)
	}
	if n, err := m.mgr.RevokeRealmSessions(ctx(), "system", "main"); err != nil || n != 0 || len(m.changes()) != 1 {
		t.Fatalf("second call = %d, %v, with %d rows, want nothing new", n, err, len(m.changes()))
	}
	if _, err := m.mgr.RevokeRealmSessions(ctx(), "system", "nowhere"); !errors.Is(err, user.ErrNotFound) {
		t.Fatalf("unknown realm: %v", err)
	}
}

// Covers: FR-43 (part)
// Acceptance: Back-channel logout (part)
// A failure while a revocation queues its logouts rolls the whole change back:
// the sessions stay live, nothing is audited and nothing is queued.
func TestRevocationFailuresRollBack(t *testing.T) {
	type run struct {
		name string
		call func(m *user.Manager, u store.UserID) error
	}
	sessionCalls := []run{
		{"RevokeSession", func(m *user.Manager, u store.UserID) error {
			_, err := m.RevokeSession(ctx(), "system", "main", u, "sa")
			return err
		}},
		{"RevokeSessions", func(m *user.Manager, u store.UserID) error {
			_, err := m.RevokeSessions(ctx(), "system", "main", u)
			return err
		}},
		{"RevokeRealmSessions", func(m *user.Manager, u store.UserID) error {
			_, err := m.RevokeRealmSessions(ctx(), "system", "main")
			return err
		}},
	}
	cases := []struct {
		op    string
		calls []run
	}{
		{"Refresh.RevokeSession", sessionCalls},
		{"Logout.Enqueue", sessionCalls},
		{"Refresh.RevokeUser", []run{
			{"Disable", func(m *user.Manager, u store.UserID) error { return m.Disable(ctx(), "admin", "main", u) }},
			{"ConsentRevoked", func(m *user.Manager, u store.UserID) error {
				return m.ConsentRevoked(ctx(), "main", "apple", "a1")
			}},
		}},
		{"Refresh.DeleteUser", []run{
			{"Delete", func(m *user.Manager, u store.UserID) error {
				return m.Delete(ctx(), "admin", "main", u, user.DeleteOptions{})
			}},
		}},
	}
	for _, c := range cases {
		for _, r := range c.calls {
			t.Run(c.op+" in "+r.name, func(t *testing.T) {
				m := newMgrEnv(t, nil)
				u, _ := m.seed(t, nil, "")
				faults := testutil.NewFaultStore(m.st)
				mgr := m.env.manager(faults, nil, nil)
				faults.Fail(c.op, errors.New("disk on fire"))
				if err := r.call(mgr, u.ID); err == nil {
					t.Fatal("the call succeeded despite the failure")
				}
				faults.Fail(c.op, nil)
				for _, tok := range []string{"tok1", "tok2"} {
					if rt, err := m.refresh(t, tok); err != nil || !rt.RevokedAt.IsZero() {
						t.Errorf("%s was revoked by the failed call: %+v, %v", tok, rt, err)
					}
				}
				if len(m.changes()) != 0 || len(m.queued(t)) != 0 {
					t.Errorf("a failed call left audit rows %+v or logouts %v", m.changes(), m.queued(t))
				}
			})
		}
	}
}

// Covers: FR-43 (part)
// Acceptance: Back-channel logout (part)
// A provider's account-delete event queues the logouts of the sessions it ends:
// the user is deleted when the identity was its only one, and the identity is
// unlinked (its sessions are revoked) when the user has others.
func TestAccountDeletedQueuesTheEndedSessions(t *testing.T) {
	t.Run("the only identity: the user is deleted", func(t *testing.T) {
		m := newMgrEnv(t, nil)
		m.seed(t, nil, "")
		if err := m.mgr.AccountDeleted(ctx(), "main", "github", "h1"); err != nil {
			t.Fatal(err)
		}
		if got := m.queued(t); !reflect.DeepEqual(got, map[string]int{"sc": 1}) {
			t.Fatalf("queued %v, want the session of the deleted user", got)
		}
	})
	t.Run("another identity: the identity is unlinked", func(t *testing.T) {
		m := newMgrEnv(t, nil)
		m.seed(t, nil, "")
		if err := m.mgr.AccountDeleted(ctx(), "main", "apple", "a1"); err != nil {
			t.Fatal(err)
		}
		if got := m.queued(t); !reflect.DeepEqual(got, map[string]int{"sa": 1, "sb": 1}) {
			t.Fatalf("queued %v, want the user's sessions", got)
		}
	})
}

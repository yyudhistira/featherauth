package user_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/provider"
	"github.com/yyudhistira/featherauth/internal/testutil"
	"github.com/yyudhistira/featherauth/internal/user"
)

// Covers: FR-31, SEC-22
// Acceptance: Apple events (part)
func TestConsentRevokedRevokesSessionsAndDropsTheToken(t *testing.T) {
	box := newBox(t, newKey(t))
	m := newMgrEnv(t, box)
	u, _ := m.seed(t, box, "APPLE-REFRESH")
	m.log.Reset()
	if err := m.mgr.ConsentRevoked(ctx(), "main", "apple", "a1"); err != nil {
		t.Fatal(err)
	}
	// The user and both identities stay; only the Apple token is gone.
	if m.userGone(t, u) {
		t.Fatal("the user was deleted")
	}
	ids := m.identities(u)
	if len(ids) != 2 {
		t.Fatalf("identities = %d, want 2", len(ids))
	}
	for _, id := range ids {
		if id.ProviderRefreshTokenEnc != "" {
			t.Errorf("%s keeps a provider token", id.Provider)
		}
	}
	for _, tok := range []string{"tok1", "tok2"} {
		if rt, err := m.refresh(t, tok); err != nil || rt.RevokedAt.IsZero() {
			t.Errorf("%s: %+v %v, want revoked", tok, rt, err)
		}
	}
	if rt, err := m.refresh(t, "tok3"); err != nil || !rt.RevokedAt.IsZero() {
		t.Errorf("another user's token: %+v %v", rt, err)
	}
	if len(m.rev.tokens) != 0 {
		t.Errorf("the token was revoked at Apple: %v", m.rev.tokens)
	}
	rows := m.changes()
	if len(rows) != 1 || rows[0].Action != "identity.consent_revoked" || rows[0].Actor != "provider:apple" ||
		rows[0].UserID != u.ID || rows[0].Details["provider"] != "apple" {
		t.Fatalf("audit = %+v", rows)
	}
	if m.auditLines() != 1 {
		t.Errorf("audit lines = %d", m.auditLines())
	}
	if out := m.log.String(); strings.Contains(out, "APPLE-REFRESH") || strings.Contains(out, "ann@gmail.com") {
		t.Errorf("log holds a secret or an email: %s", out)
	}
	// A later Apple login returns to the same account.
	if got, err := m.resolve("apple", trusted(), ident("a1", "ann@gmail.com", true)); err != nil || got.ID != u.ID {
		t.Fatalf("login after consent-revoked = %v, %v", got, err)
	}
	// The same event again changes nothing.
	before := m.identities(u)
	if err := m.mgr.ConsentRevoked(ctx(), "main", "apple", "a1"); err != nil {
		t.Fatal(err)
	}
	after := m.identities(u)
	if len(after) != len(before) || m.userGone(t, u) {
		t.Fatal("the repeat changed the user")
	}
	if rt, _ := m.refresh(t, "tok1"); rt.RevokedAt.IsZero() {
		t.Error("tok1 is live again")
	}
}

// Covers: FR-31, SEC-22
// Acceptance: Apple events (part)
func TestConsentRevokedUnknownSubject(t *testing.T) {
	m := newMgrEnv(t, nil)
	m.seed(t, nil, "")
	m.log.Reset()
	for _, c := range []struct{ realm, prov, sub string }{
		{"main", "apple", "nope"}, {"main", "google", "a1"}, {"other", "apple", "a1"},
	} {
		if err := m.mgr.ConsentRevoked(ctx(), config.RealmName(c.realm), config.ProviderKey(c.prov), c.sub); !errors.Is(err, user.ErrNotFound) {
			t.Errorf("%+v: err = %v, want ErrNotFound", c, err)
		}
	}
	if len(m.changes()) != 0 || m.auditLines() != 0 {
		t.Errorf("changes %v, lines %d", m.changes(), m.auditLines())
	}
}

// Covers: FR-31, SEC-22
// Acceptance: Apple events (part)
func TestAccountDeletedForAnAppleOnlyUserDeletesTheUser(t *testing.T) {
	box := newBox(t, newKey(t))
	m := newMgrEnv(t, box)
	_, other := m.seed(t, box, "")
	solo := m.must("apple", untrusted(), ident("a2", "carol@example.org", true))
	m.log.Reset()
	if err := m.mgr.AccountDeleted(ctx(), "main", "apple", "a2"); err != nil {
		t.Fatal(err)
	}
	if !m.userGone(t, solo) {
		t.Fatal("the user is still there")
	}
	if len(m.rev.tokens) != 0 {
		t.Errorf("revoked at Apple: %v", m.rev.tokens)
	}
	if _, err := m.refresh(t, "tok3"); err != nil || other == nil {
		t.Error("another user was damaged")
	}
	rows := m.changes()
	if len(rows) != 1 || rows[0].Action != "user.delete" || rows[0].Actor != "provider:apple" || rows[0].UserID != solo.ID ||
		rows[0].Details["revoke_at_provider"] != false {
		t.Fatalf("audit = %+v", rows)
	}
	// Repeated: the user is gone, so nothing is found and nothing is audited.
	if err := m.mgr.AccountDeleted(ctx(), "main", "apple", "a2"); !errors.Is(err, user.ErrNotFound) {
		t.Fatalf("repeat = %v, want ErrNotFound", err)
	}
	if len(m.changes()) != 1 {
		t.Errorf("audit rows = %d after the repeat", len(m.changes()))
	}
}

// Covers: FR-31, SEC-22
// Acceptance: Apple events (part)
func TestAccountDeletedForAUserWithAnotherIdentityUnlinksApple(t *testing.T) {
	box := newBox(t, newKey(t))
	m := newMgrEnv(t, box)
	u, _ := m.seed(t, box, "APPLE-REFRESH")
	m.log.Reset()
	if err := m.mgr.AccountDeleted(ctx(), "main", "apple", "a1"); err != nil {
		t.Fatal(err)
	}
	if m.userGone(t, u) {
		t.Fatal("the user was deleted")
	}
	ids := m.identities(u)
	if len(ids) != 1 || ids[0].Provider != "google" {
		t.Fatalf("identities = %+v, want only Google", ids)
	}
	for _, tok := range []string{"tok1", "tok2"} {
		if rt, err := m.refresh(t, tok); err != nil || rt.RevokedAt.IsZero() {
			t.Errorf("%s: %+v %v, want revoked", tok, rt, err)
		}
	}
	if len(m.rev.tokens) != 0 {
		t.Errorf("revoked at Apple: %v", m.rev.tokens)
	}
	rows := m.changes()
	if len(rows) != 1 || rows[0].Action != "identity.unlink" || rows[0].Actor != "provider:apple" ||
		rows[0].UserID != u.ID || rows[0].Details["provider"] != "apple" {
		t.Fatalf("audit = %+v", rows)
	}
	if err := m.mgr.AccountDeleted(ctx(), "main", "apple", "a1"); !errors.Is(err, user.ErrNotFound) {
		t.Fatalf("repeat = %v, want ErrNotFound", err)
	}
	if len(m.changes()) != 1 {
		t.Errorf("audit rows = %d after the repeat", len(m.changes()))
	}
}

// providerEvent is an event of the apple provider with the given id, which
// expires an hour from the fake clock's now.
func (m *mgrEnv) providerEvent(typ, sub, id string) provider.Event {
	return provider.Event{Set: provider.EventSetApple, Type: typ, Subject: sub, ID: id, Expires: m.clock.Now().Add(time.Hour)}
}

// applyOne applies one event of the apple provider through ProviderEvents and
// returns its result.
func applyOne(mgr *user.Manager, ev provider.Event) (user.EventResult, error) {
	res, err := mgr.ProviderEvents(ctx(), "main", "apple", []provider.Event{ev})
	if err != nil || len(res) != 1 {
		return 0, err
	}
	return res[0], nil
}

// Covers: FR-31, SEC-22, SEC-27
// Acceptance: Event replay (part)
func TestProviderEventIsActedOnceAndTheRepeatChangesNothing(t *testing.T) {
	box := newBox(t, newKey(t))
	m := newMgrEnv(t, box)
	m.seed(t, box, "APPLE-REFRESH")
	m.log.Reset()
	ev := m.providerEvent("consent-revoked", "a1", "j1")
	res, err := applyOne(m.mgr, ev)
	if err != nil || res != user.EventApplied {
		t.Fatalf("first notification: %v, %v; want applied", res, err)
	}
	if n := len(m.changes()); n != 1 {
		t.Fatalf("audit rows after the first = %d, want 1", n)
	}
	res, err = applyOne(m.mgr, ev)
	if err != nil || res != user.EventRepeated {
		t.Fatalf("the same payload again: %v, %v; want repeated", res, err)
	}
	if n := len(m.changes()); n != 1 {
		t.Fatalf("audit rows after the repeat = %d, want 1", n)
	}
	if rt, err := m.refresh(t, "tok1"); err != nil || rt.RevokedAt.IsZero() {
		t.Fatalf("tok1 after the repeat: %+v %v, want revoked", rt, err)
	}
	res, err = applyOne(m.mgr, m.providerEvent("consent-revoked", "a1", "j2"))
	if err != nil || res != user.EventApplied {
		t.Fatalf("a second notification: %v, %v; want applied", res, err)
	}
	if n := len(m.changes()); n != 2 {
		t.Fatalf("audit rows after a second notification = %d, want 2", n)
	}
}

// Covers: FR-31, SEC-22, SEC-27
// Acceptance: Event replay (part)
func TestProviderEventFailedActionRemembersNothing(t *testing.T) {
	box := newBox(t, newKey(t))
	m := newMgrEnv(t, box)
	solo := m.must("apple", trusted(), ident("a2", "carol@example.org", true))
	m.log.Reset()
	f := testutil.NewFaultStore(m.st)
	f.Fail("Users.Delete", errInjected)
	mgr := m.manager(f, box, &fakeRevoker{})
	ev := m.providerEvent("account-delete", "a2", "j1")
	if _, err := applyOne(mgr, ev); !errors.Is(err, errInjected) {
		t.Fatalf("err = %v, want the store failure", err)
	}
	if len(m.changes()) != 0 || m.auditLines() != 0 || m.userGone(t, solo) {
		t.Fatal("the failed action left an effect")
	}
	f.Fail("Users.Delete", nil)
	res, err := applyOne(mgr, ev)
	if err != nil || res != user.EventApplied {
		t.Fatalf("the retry: %v, %v; want applied", res, err)
	}
	if !m.userGone(t, solo) {
		t.Fatal("the retry did not delete the user")
	}
	if got := m.actions(); len(got) != 1 || got[0] != "user.delete" {
		t.Fatalf("audit actions = %v", got)
	}
}

// Covers: FR-31, SEC-22
// Acceptance: Apple events (part)
func TestProviderEventAccountDeletedIsTheSameAction(t *testing.T) {
	box := newBox(t, newKey(t))
	m := newMgrEnv(t, box)
	solo := m.must("apple", trusted(), ident("a2", "carol@example.org", true))
	m.log.Reset()
	res, err := applyOne(m.mgr, m.providerEvent("account-deleted", "a2", "j1"))
	if err != nil || res != user.EventApplied {
		t.Fatalf("account-deleted: %v, %v; want applied", res, err)
	}
	if !m.userGone(t, solo) {
		t.Fatal("the user is still there")
	}
}

// Covers: FR-31, SEC-22, SEC-27
// Acceptance: Event replay (part)
func TestProviderEventResultsWithoutAnAction(t *testing.T) {
	box := newBox(t, newKey(t))
	m := newMgrEnv(t, box)
	m.seed(t, box, "APPLE-REFRESH")
	m.log.Reset()
	for _, c := range []struct {
		name string
		ev   provider.Event
		want user.EventResult
	}{
		{"unknown subject", m.providerEvent("consent-revoked", "nobody", "j1"), user.EventUnknownSubject},
		{"unknown type", m.providerEvent("something-new", "a1", "j2"), user.EventUnknownType},
		{"email change", m.providerEvent("email-disabled", "a1", "j3"), user.EventLogOnly},
		{"unknown subject again", m.providerEvent("consent-revoked", "nobody", "j1"), user.EventRepeated},
	} {
		t.Run(c.name, func(t *testing.T) {
			res, err := applyOne(m.mgr, c.ev)
			if err != nil || res != c.want {
				t.Fatalf("result %v, %v; want %v", res, err, c.want)
			}
		})
	}
	if n := len(m.changes()); n != 0 {
		t.Errorf("%d audit rows, want none", n)
	}
	if rt, err := m.refresh(t, "tok1"); err != nil || !rt.RevokedAt.IsZero() {
		t.Errorf("the session was changed: %+v %v", rt, err)
	}
}

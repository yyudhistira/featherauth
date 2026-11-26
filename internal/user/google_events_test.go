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

// googleEvent is an event of a Google token, which expires a day from the fake
// clock's now.
func (m *mgrEnv) googleEvent(typ, sub, state, id string) provider.Event {
	return provider.Event{Set: provider.EventSetGoogle, Type: typ, Subject: sub, State: state, ID: id, Expires: m.clock.Now().Add(24 * time.Hour)}
}

// Covers: FR-48, SEC-39 (part), FR-31 (part)
// Acceptance: Google security events (part)
// Each provider's set acts only on its own types: a Google account-delete or
// consent-revoked is unknown and changes nothing, and an Apple sessions-revoked
// or tokens-revoked is unknown and revokes nothing.
func TestEachProvidersSetActsOnlyOnItsOwnTypes(t *testing.T) {
	box := newBox(t, newKey(t))
	m := newMgrEnv(t, box)
	u, _ := m.seed(t, box, "")
	m.log.Reset()
	meta := provider.Event{Set: provider.EventSetMeta, Type: "consent-revoked", Subject: "g1", ID: "x-7", Expires: m.clock.Now().Add(time.Hour)}
	cases := []struct {
		name string
		prov config.ProviderKey
		ev   provider.Event
	}{
		{"google account-delete", "google", m.googleEvent("account-delete", "g1", "", "x-1")},
		{"google consent-revoked", "google", m.googleEvent("consent-revoked", "g1", "", "x-2")},
		{"google email-disabled", "google", m.googleEvent("email-disabled", "g1", "", "x-3")},
		{"apple sessions-revoked", "apple", m.providerEvent("sessions-revoked", "a1", "x-4")},
		{"apple tokens-revoked", "apple", m.providerEvent("tokens-revoked", "a1", "x-5")},
		{"apple account-disabled", "apple", m.providerEvent("account-disabled", "a1", "x-6")},
		{"meta consent-revoked", "apple", meta},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res, err := m.mgr.ProviderEvents(ctx(), "main", c.prov, []provider.Event{c.ev})
			if err != nil || len(res) != 1 || res[0] != user.EventUnknownType {
				t.Fatalf("results %v, %v; want unknown type", res, err)
			}
		})
	}
	if len(m.changes()) != 0 || m.userGone(t, u) || len(m.identities(u)) != 2 {
		t.Errorf("a type of another set changed something: %v", m.changes())
	}
	if rt, err := m.refresh(t, "tok1"); err != nil || !rt.RevokedAt.IsZero() {
		t.Errorf("tok1 after foreign types: %+v %v", rt, err)
	}
}

// Covers: FR-48, SEC-39 (part)
// Acceptance: Google security events (part)
func TestGoogleSessionsRevokedEndsTheSessionsAndBrowserSessions(t *testing.T) {
	box := newBox(t, newKey(t))
	m := newMgrEnv(t, box)
	u, other := m.seed(t, box, "")
	m.browserFor(t, u, "google", "g1", "ck-google")
	m.browserFor(t, u, "apple", "a1", "ck-apple")
	m.browserFor(t, other, "github", "h1", "ck-other")
	m.log.Reset()
	res, err := m.mgr.ProviderEvents(ctx(), "main", "google", []provider.Event{m.googleEvent("sessions-revoked", "g1", "", "set-1")})
	if err != nil || len(res) != 1 || res[0] != user.EventApplied {
		t.Fatalf("results %v, %v; want applied", res, err)
	}
	// The user and both identities stay; the refresh tokens and the browser
	// sessions of the user end, and another user's do not.
	if m.userGone(t, u) || len(m.identities(u)) != 2 {
		t.Fatal("the user or an identity was removed")
	}
	for _, tok := range []string{"tok1", "tok2"} {
		if rt, err := m.refresh(t, tok); err != nil || rt.RevokedAt.IsZero() {
			t.Errorf("%s: %+v %v, want revoked", tok, rt, err)
		}
	}
	if rt, err := m.refresh(t, "tok3"); err != nil || !rt.RevokedAt.IsZero() {
		t.Errorf("another user's token: %+v %v", rt, err)
	}
	if m.browserExists(t, u, "ck-google") || m.browserExists(t, u, "ck-apple") {
		t.Error("a browser session of the user is still there")
	}
	if !m.browserExists(t, other, "ck-other") {
		t.Error("another user's browser session was deleted")
	}
	rows := m.changes()
	if len(rows) != 1 || rows[0].Action != "identity.sessions_revoked" || rows[0].Actor != "provider:google" ||
		rows[0].UserID != u.ID || rows[0].Details["provider"] != "google" || rows[0].Details["event"] != "sessions-revoked" {
		t.Fatalf("audit = %+v", rows)
	}
	if out := m.log.String(); strings.Contains(out, "tok1") || strings.Contains(out, "ann@gmail.com") {
		t.Errorf("log holds a secret or an email: %s", out)
	}
}

// Covers: FR-48, SEC-39 (part)
// Acceptance: Google security events (part)
func TestGoogleTwoRevokingEventsOfOneTokenWriteOneRow(t *testing.T) {
	box := newBox(t, newKey(t))
	m := newMgrEnv(t, box)
	u, _ := m.seed(t, box, "")
	m.log.Reset()
	res, err := m.mgr.ProviderEvents(ctx(), "main", "google", []provider.Event{
		m.googleEvent("sessions-revoked", "g1", "", "set-1"),
		m.googleEvent("tokens-revoked", "g1", "", "set-1"),
	})
	if err != nil || len(res) != 2 || res[0] != user.EventApplied || res[1] != user.EventApplied {
		t.Fatalf("results %v, %v; want both applied", res, err)
	}
	// The second revocation ends nothing new, so only the first one is audited.
	rows := m.changes()
	if len(rows) != 1 || rows[0].UserID != u.ID || rows[0].Action != "identity.sessions_revoked" {
		t.Fatalf("audit = %+v, want one identity.sessions_revoked", rows)
	}
}

// Covers: FR-48, SEC-39 (part)
// Acceptance: Google security events (part)
func TestGoogleEventsThatOnlyLogChangeNothing(t *testing.T) {
	box := newBox(t, newKey(t))
	m := newMgrEnv(t, box)
	u, _ := m.seed(t, box, "")
	m.log.Reset()
	res, err := m.mgr.ProviderEvents(ctx(), "main", "google", []provider.Event{
		m.googleEvent("token-revoked", "", "", "set-2"),
		m.googleEvent("account-enabled", "g1", "", "set-2"),
		m.googleEvent("account-credential-change-required", "g1", "", "set-2"),
		m.googleEvent("verification", "", "check-1", "set-2"),
	})
	if err != nil {
		t.Fatal(err)
	}
	for i, r := range res {
		if r != user.EventLogOnly {
			t.Errorf("event %d: result %v, want logged only", i, r)
		}
	}
	if len(m.changes()) != 0 || m.userGone(t, u) || len(m.identities(u)) != 2 {
		t.Error("a logged event changed something")
	}
	if rt, err := m.refresh(t, "tok1"); err != nil || !rt.RevokedAt.IsZero() {
		t.Errorf("tok1 after logged events: %+v %v", rt, err)
	}
}

// Covers: FR-48, SEC-39 (part)
// Acceptance: Google security events (part)
func TestGoogleUnknownSubjectsAndTypesChangeNothing(t *testing.T) {
	box := newBox(t, newKey(t))
	m := newMgrEnv(t, box)
	m.seed(t, box, "")
	m.log.Reset()
	cases := []struct {
		name string
		ev   provider.Event
		want user.EventResult
	}{
		{"unknown subject", m.googleEvent("sessions-revoked", "nobody", "", "set-3"), user.EventUnknownSubject},
		{"no subject", m.googleEvent("account-disabled", "", "", "set-4"), user.EventUnknownSubject},
		{"unknown type", m.googleEvent("something-new", "g1", "", "set-5"), user.EventUnknownType},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res, err := m.mgr.ProviderEvents(ctx(), "main", "google", []provider.Event{c.ev})
			if err != nil || len(res) != 1 || res[0] != c.want {
				t.Fatalf("results %v, %v; want %v", res, err, c.want)
			}
		})
	}
	if len(m.changes()) != 0 {
		t.Errorf("changes %v", m.changes())
	}
	if rt, err := m.refresh(t, "tok1"); err != nil || !rt.RevokedAt.IsZero() {
		t.Errorf("tok1 after unknown events: %+v %v", rt, err)
	}
}

// Covers: FR-48, SEC-39 (part), SEC-27
// Acceptance: Google security events (part)
func TestGoogleTokenIsActedOnceAndFailedRevocationRemembersNothing(t *testing.T) {
	for _, op := range []string{"Refresh.RevokeUser", "SSOSessions.DeleteByIdentity", "SSOSessions.DeleteByUser"} {
		t.Run(op, func(t *testing.T) {
			box := newBox(t, newKey(t))
			m := newMgrEnv(t, box)
			u, _ := m.seed(t, box, "")
			m.log.Reset()
			f := testutil.NewFaultStore(m.st)
			f.Fail(op, errInjected)
			mgr := m.manager(f, box, &fakeRevoker{})
			evs := []provider.Event{m.googleEvent("sessions-revoked", "g1", "", "set-6")}
			if _, err := mgr.ProviderEvents(ctx(), "main", "google", evs); !errors.Is(err, errInjected) {
				t.Fatalf("err = %v, want the store failure", err)
			}
			if len(m.changes()) != 0 || m.userGone(t, u) {
				t.Fatal("the failed revocation left an effect")
			}
			if rt, err := m.refresh(t, "tok1"); err != nil || !rt.RevokedAt.IsZero() {
				t.Fatalf("tok1 after the failure: %+v %v, want live", rt, err)
			}
			f.Fail(op, nil)
			res, err := mgr.ProviderEvents(ctx(), "main", "google", evs)
			if err != nil || len(res) != 1 || res[0] != user.EventApplied {
				t.Fatalf("the retry: %v, %v; want applied", res, err)
			}
			// The token is remembered now: its repeat changes nothing.
			res, err = mgr.ProviderEvents(ctx(), "main", "google", evs)
			if err != nil || len(res) != 1 || res[0] != user.EventRepeated {
				t.Fatalf("the repeat: %v, %v; want repeated", res, err)
			}
			if len(m.changes()) != 1 {
				t.Errorf("audit rows = %d, want 1", len(m.changes()))
			}
		})
	}
}

// Covers: FR-48 (part)
// Acceptance: Google security events (part)
func TestProviderEventsWithNoEventsDoNothing(t *testing.T) {
	m := newMgrEnv(t, nil)
	res, err := m.mgr.ProviderEvents(ctx(), "main", "google", nil)
	if err != nil || len(res) != 0 {
		t.Fatalf("results %v, %v; want none", res, err)
	}
}

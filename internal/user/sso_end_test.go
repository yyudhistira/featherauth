package user_test

import (
	"context"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/secure"
	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/testutil"
	"github.com/yyudhistira/featherauth/internal/user"
)

// browserFor makes a browser session of the user, made with the identity of
// prov and sub, for the cookie value cookie.
func (m *mgrEnv) browserFor(t *testing.T, u *store.User, prov config.ProviderKey, sub, cookie string) {
	t.Helper()
	now := m.clock.Now()
	err := m.st.Write(ctx(), func(tx store.Tx) error {
		ident, err := tx.Identities().Find(ctx(), u.RealmID, prov, sub)
		if err != nil {
			return err
		}
		return tx.SSOSessions().Create(ctx(), store.SSOSession{
			IDHash: secure.HashOf(cookie), RealmID: u.RealmID, UserID: u.ID, IdentityID: ident.ID, Provider: prov,
			AuthTime: now, CreatedAt: now, LastUsedAt: now, ExpiresAt: now.Add(time.Hour),
		})
	})
	if err != nil {
		t.Fatal(err)
	}
}

// tokenFrom adds a refresh token of the user's session that came from the
// browser session of cookie.
func (m *mgrEnv) tokenFrom(t *testing.T, u *store.User, session store.SessionID, cookie, tok string) {
	t.Helper()
	now := m.clock.Now()
	err := m.st.Write(ctx(), func(tx store.Tx) error {
		return tx.RefreshTokens().Insert(ctx(), store.RefreshToken{
			ID: store.RefreshTokenID("rt-" + tok), RealmID: u.RealmID, UserID: u.ID, ClientID: "app",
			TokenHash: secure.HashOf(tok), SessionID: session, SessionStartedAt: now, AuthTime: now,
			ExpiresAt: now.Add(time.Hour), CreatedAt: now, SSOIDHash: secure.HashOf(cookie),
		})
	})
	if err != nil {
		t.Fatal(err)
	}
}

// browserExists reports whether the browser session of cookie is stored in the
// realm of u.
func (m *mgrEnv) browserExists(t *testing.T, u *store.User, cookie string) bool {
	t.Helper()
	var found bool
	err := m.st.Read(ctx(), func(tx store.Tx) error {
		_, err := tx.SSOSessions().Find(ctx(), u.RealmID, secure.HashOf(cookie))
		found = err == nil
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return found
}

// Covers: FR-45 (part), SEC-37 (part)
// Acceptance: Single sign-on end (part)
// A disabled user's browser sessions end, and no other user's.
func TestDisableEndsTheBrowserSessionsOfTheUser(t *testing.T) {
	m := newMgrEnv(t, nil)
	u, other := m.seed(t, nil, "")
	m.browserFor(t, u, "google", "g1", "cookie-u")
	m.browserFor(t, other, "github", "h1", "cookie-other")
	if err := m.mgr.Disable(ctx(), "admin", "main", u.ID); err != nil {
		t.Fatal(err)
	}
	if m.browserExists(t, u, "cookie-u") {
		t.Fatal("a browser session of the disabled user is still stored")
	}
	if !m.browserExists(t, other, "cookie-other") {
		t.Fatal("another user's browser session ended with the disable")
	}
}

// Covers: FR-45 (part), SEC-37 (part)
// Acceptance: Single sign-on end (part)
// Sign out everywhere (all the user's sessions) ends every browser session of the
// user, and a session command without --session ends it the same way.
func TestRevokeSessionsEndsEveryBrowserSessionOfTheUser(t *testing.T) {
	m := newMgrEnv(t, nil)
	u, other := m.seed(t, nil, "")
	m.browserFor(t, u, "google", "g1", "cookie-u")
	m.browserFor(t, other, "github", "h1", "cookie-other")
	if _, err := m.mgr.RevokeSessions(ctx(), "admin", "main", u.ID); err != nil {
		t.Fatal(err)
	}
	if m.browserExists(t, u, "cookie-u") {
		t.Fatal("a browser session of the user survived sign out everywhere")
	}
	if !m.browserExists(t, other, "cookie-other") {
		t.Fatal("another user's browser session ended with sign out everywhere")
	}
}

// Covers: FR-45 (part), SEC-37 (part)
// Acceptance: Single sign-on end (part)
// Revoking one token session ends the browser session it came from, and only that
// one: another session of the same user keeps its browser session.
func TestRevokeSessionEndsTheBrowserSessionItCameFrom(t *testing.T) {
	m := newMgrEnv(t, nil)
	u, _ := m.seed(t, nil, "")
	m.browserFor(t, u, "google", "g1", "cookie-one")
	m.browserFor(t, u, "apple", "a1", "cookie-two")
	m.tokenFrom(t, u, "sso-session-one", "cookie-one", "tok-one")
	m.tokenFrom(t, u, "sso-session-two", "cookie-two", "tok-two")
	if _, err := m.mgr.RevokeSession(ctx(), "admin", "main", u.ID, "sso-session-one"); err != nil {
		t.Fatal(err)
	}
	if m.browserExists(t, u, "cookie-one") {
		t.Fatal("the browser session of the revoked token session is still stored")
	}
	if !m.browserExists(t, u, "cookie-two") {
		t.Fatal("the browser session of another token session ended")
	}
}

// Covers: FR-45 (part), SEC-37 (part)
// Acceptance: Single sign-on end (part)
// A realm-wide revocation ends every browser session of the realm.
func TestRevokeRealmSessionsEndsEveryBrowserSessionOfTheRealm(t *testing.T) {
	m := newMgrEnv(t, nil)
	u, other := m.seed(t, nil, "")
	m.browserFor(t, u, "google", "g1", "cookie-u")
	m.browserFor(t, other, "github", "h1", "cookie-other")
	if _, err := m.mgr.RevokeRealmSessions(ctx(), "admin", "main"); err != nil {
		t.Fatal(err)
	}
	if m.browserExists(t, u, "cookie-u") || m.browserExists(t, other, "cookie-other") {
		t.Fatal("a browser session of the realm survived the realm-wide revocation")
	}
}

// Covers: FR-45 (part), SEC-37 (part)
// Acceptance: Single sign-on end (part)
// Unlinking an identity ends the browser sessions made with it, and only those.
func TestUnlinkEndsTheBrowserSessionsMadeWithTheIdentity(t *testing.T) {
	m := newMgrEnv(t, nil)
	u, _ := m.seed(t, nil, "")
	m.browserFor(t, u, "apple", "a1", "cookie-apple")
	m.browserFor(t, u, "google", "g1", "cookie-google")
	if err := m.mgr.Unlink(ctx(), "admin", "main", u.ID, "apple", "a1"); err != nil {
		t.Fatal(err)
	}
	if m.browserExists(t, u, "cookie-apple") {
		t.Fatal("the browser session made with the unlinked identity is still stored")
	}
	if !m.browserExists(t, u, "cookie-google") {
		t.Fatal("the browser session made with another identity ended")
	}
}

// Covers: FR-45 (part), SEC-37 (part)
// Acceptance: Single sign-on end (part)
// Apple's consent-revoked ends every browser session of the user who holds the
// identity, the identity's and the others alike.
func TestConsentRevokedEndsTheBrowserSessionsOfTheUser(t *testing.T) {
	m := newMgrEnv(t, nil)
	u, other := m.seed(t, nil, "")
	m.browserFor(t, u, "apple", "a1", "cookie-apple")
	m.browserFor(t, u, "google", "g1", "cookie-google")
	m.browserFor(t, other, "github", "h1", "cookie-other")
	if err := m.mgr.ConsentRevoked(ctx(), "main", "apple", "a1"); err != nil {
		t.Fatal(err)
	}
	if m.browserExists(t, u, "cookie-apple") || m.browserExists(t, u, "cookie-google") {
		t.Fatal("a browser session of the user survived consent-revoked")
	}
	if !m.browserExists(t, other, "cookie-other") {
		t.Fatal("another user's browser session ended with consent-revoked")
	}
}

// Covers: FR-45 (part), SEC-37 (part)
// Acceptance: Single sign-on end (part)
// An account-delete that leaves the user with another identity ends the browser
// sessions made with the deleted identity and the user's other ones (its sessions
// are revoked); the last identity's account-delete deletes the user and every
// browser session with it.
func TestAccountDeleteEndsTheBrowserSessions(t *testing.T) {
	t.Run("another identity remains", func(t *testing.T) {
		m := newMgrEnv(t, nil)
		u, _ := m.seed(t, nil, "")
		m.browserFor(t, u, "apple", "a1", "cookie-apple")
		m.browserFor(t, u, "google", "g1", "cookie-google")
		if err := m.mgr.AccountDeleted(ctx(), "main", "apple", "a1"); err != nil {
			t.Fatal(err)
		}
		if m.browserExists(t, u, "cookie-apple") || m.browserExists(t, u, "cookie-google") {
			t.Fatal("a browser session of the user survived an account-delete that unlinked an identity")
		}
	})
	t.Run("the only identity: the user goes", func(t *testing.T) {
		m := newMgrEnv(t, nil)
		_, other := m.seed(t, nil, "")
		m.browserFor(t, other, "github", "h1", "cookie-other")
		if err := m.mgr.AccountDeleted(ctx(), "main", "github", "h1"); err != nil {
			t.Fatal(err)
		}
		if m.browserExists(t, other, "cookie-other") {
			t.Fatal("the browser session of a deleted user is still stored")
		}
	})
}

// Covers: FR-45 (part), SEC-37 (part)
// Acceptance: Single sign-on end (part)
// Deleting the user ends its browser sessions.
func TestDeleteEndsTheBrowserSessionsOfTheUser(t *testing.T) {
	m := newMgrEnv(t, nil)
	u, other := m.seed(t, nil, "")
	m.browserFor(t, u, "google", "g1", "cookie-u")
	m.browserFor(t, other, "github", "h1", "cookie-other")
	if err := m.mgr.Delete(ctx(), "admin", "main", u.ID, user.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	if m.browserExists(t, u, "cookie-u") {
		t.Fatal("the browser session of the deleted user is still stored")
	}
	if !m.browserExists(t, other, "cookie-other") {
		t.Fatal("another user's browser session ended with the delete")
	}
}

// Covers: FR-45 (part), SEC-37 (part)
// Acceptance: Single sign-on end (part)
// A failure to end the browser sessions of a change fails the change as a whole:
// the identity stays linked and the sessions stay stored.
func TestBrowserSessionEndFailuresRollBack(t *testing.T) {
	t.Run("unlink", func(t *testing.T) {
		m := newMgrEnv(t, nil)
		u, _ := m.seed(t, nil, "")
		m.browserFor(t, u, "apple", "a1", "cookie-apple")
		fs := testutil.NewFaultStore(m.st)
		fs.Fail("SSOSessions.DeleteByIdentity", context.DeadlineExceeded)
		mgr := m.env.manager(fs, nil, m.rev)
		if err := mgr.Unlink(ctx(), "admin", "main", u.ID, "apple", "a1"); err == nil {
			t.Fatal("the unlink succeeded although its browser session was not ended")
		}
		if !m.browserExists(t, u, "cookie-apple") {
			t.Fatal("the browser session was lost")
		}
	})
	t.Run("consent revoked", func(t *testing.T) {
		m := newMgrEnv(t, nil)
		m.seed(t, nil, "")
		fs := testutil.NewFaultStore(m.st)
		fs.Fail("SSOSessions.DeleteByUser", context.DeadlineExceeded)
		mgr := m.env.manager(fs, nil, m.rev)
		if err := mgr.ConsentRevoked(ctx(), "main", "google", "g1"); err == nil {
			t.Fatal("consent revoked succeeded although its browser sessions were not ended")
		}
		if rt, err := m.refresh(t, "tok1"); err != nil || !rt.RevokedAt.IsZero() {
			t.Fatalf("the token session changed although the change failed: %+v, %v", rt, err)
		}
	})
	t.Run("disable", func(t *testing.T) {
		m := newMgrEnv(t, nil)
		u, _ := m.seed(t, nil, "")
		fs := testutil.NewFaultStore(m.st)
		fs.Fail("SSOSessions.DeleteByUser", context.DeadlineExceeded)
		mgr := m.env.manager(fs, nil, m.rev)
		if err := mgr.Disable(ctx(), "admin", "main", u.ID); err == nil {
			t.Fatal("the disable succeeded although its browser sessions were not ended")
		}
		if got := m.stored(u); !got.DisabledAt.IsZero() {
			t.Fatal("the user is disabled although the change failed")
		}
	})
	t.Run("sign out everywhere", func(t *testing.T) {
		m := newMgrEnv(t, nil)
		u, _ := m.seed(t, nil, "")
		fs := testutil.NewFaultStore(m.st)
		fs.Fail("SSOSessions.DeleteByUser", context.DeadlineExceeded)
		mgr := m.env.manager(fs, nil, m.rev)
		if _, err := mgr.RevokeSessions(ctx(), "admin", "main", u.ID); err == nil {
			t.Fatal("sign out everywhere succeeded although its browser sessions were not ended")
		}
		if rt, err := m.refresh(t, "tok1"); err != nil || !rt.RevokedAt.IsZero() {
			t.Fatalf("a token session was revoked although the change failed: %+v, %v", rt, err)
		}
	})
	t.Run("delete", func(t *testing.T) {
		m := newMgrEnv(t, nil)
		u, _ := m.seed(t, nil, "")
		fs := testutil.NewFaultStore(m.st)
		fs.Fail("SSOSessions.DeleteByUser", context.DeadlineExceeded)
		mgr := m.env.manager(fs, nil, m.rev)
		if err := mgr.Delete(ctx(), "admin", "main", u.ID, user.DeleteOptions{}); err == nil {
			t.Fatal("the delete succeeded although its browser sessions were not ended")
		}
		if m.userGone(t, u) {
			t.Fatal("the user is gone although the change failed")
		}
	})
	t.Run("account delete of the only identity", func(t *testing.T) {
		m := newMgrEnv(t, nil)
		_, other := m.seed(t, nil, "")
		fs := testutil.NewFaultStore(m.st)
		fs.Fail("SSOSessions.DeleteByUser", context.DeadlineExceeded)
		mgr := m.env.manager(fs, nil, m.rev)
		if err := mgr.AccountDeleted(ctx(), "main", "github", "h1"); err == nil {
			t.Fatal("the account delete succeeded although its browser sessions were not ended")
		}
		if m.userGone(t, other) {
			t.Fatal("the user is gone although the change failed")
		}
	})
	t.Run("account delete of one of several identities", func(t *testing.T) {
		m := newMgrEnv(t, nil)
		m.seed(t, nil, "")
		fs := testutil.NewFaultStore(m.st)
		fs.Fail("SSOSessions.DeleteByIdentity", context.DeadlineExceeded)
		mgr := m.env.manager(fs, nil, m.rev)
		if err := mgr.AccountDeleted(ctx(), "main", "apple", "a1"); err == nil {
			t.Fatal("the account delete succeeded although its browser sessions were not ended")
		}
		if _, err := m.resolve("apple", trusted(), ident("a1", "ann@gmail.com", true)); err != nil {
			t.Fatalf("the identity was unlinked although the change failed: %v", err)
		}
	})
	t.Run("realm-wide revocation", func(t *testing.T) {
		m := newMgrEnv(t, nil)
		u, _ := m.seed(t, nil, "")
		m.browserFor(t, u, "google", "g1", "cookie-u")
		fs := testutil.NewFaultStore(m.st)
		fs.Fail("SSOSessions.DeleteByRealm", context.DeadlineExceeded)
		mgr := m.env.manager(fs, nil, m.rev)
		if _, err := mgr.RevokeRealmSessions(ctx(), "admin", "main"); err == nil {
			t.Fatal("the realm-wide revocation succeeded although its browser sessions were not ended")
		}
		if !m.browserExists(t, u, "cookie-u") {
			t.Fatal("the browser session was lost")
		}
	})
}

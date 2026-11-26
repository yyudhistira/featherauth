package storetest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/secure"
	"github.com/yyudhistira/featherauth/internal/store"
)

// newSSOSession is a browser session of user and identity in realm r1, for the
// cookie value cookie; the store keeps only its hash.
func newSSOSession(cookie string, user store.UserID, identity store.IdentityID) store.SSOSession {
	return store.SSOSession{
		IDHash: secure.HashOf(cookie), RealmID: "r1", UserID: user, IdentityID: identity,
		Provider: "google", AuthTime: epoch.Add(-time.Minute), CreatedAt: epoch,
		LastUsedAt: epoch, ExpiresAt: epoch.Add(8 * time.Hour),
	}
}

// findSSO reads the browser session of the hash of cookie in realm.
func findSSO(t *testing.T, s store.Store, realm store.RealmID, cookie string) (store.SSOSession, error) {
	t.Helper()
	var got store.SSOSession
	err := s.Read(context.Background(), func(tx store.Tx) error {
		var err error
		got, err = tx.SSOSessions().Find(context.Background(), realm, secure.HashOf(cookie))
		return err
	})
	return got, err
}

// Covers: FR-45 (part), SEC-37 (part)
// Acceptance: Single sign-on start (part)
// testSSOSessionsCRUD: a browser session is found by the hash of its cookie
// value, in its own realm only, and an earlier one is not replaced by a repeat
// of its hash; Touch moves the last use and the expiry; Delete ends it and a
// repeat is not an error.
func testSSOSessionsCRUD(t *testing.T, s store.Store) {
	ctx := context.Background()
	ensure(t, s, "r", "r1")
	createUser(t, s, newUser("r1", "u1", "a@example.com", true))
	ssn := newSSOSession("cookie-1", "u1", "i1")
	mustWrite(t, s, func(tx store.Tx) error { return tx.SSOSessions().Create(ctx, ssn) })

	got, err := findSSO(t, s, "r1", "cookie-1")
	if err != nil || got != ssn {
		t.Fatalf("Find = %+v, %v, want %+v", got, err, ssn)
	}
	if err := write(t, s, func(tx store.Tx) error { return tx.SSOSessions().Create(ctx, ssn) }); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("Create of an existing hash = %v, want ErrConflict", err)
	}
	if _, err := findSSO(t, s, "r1", "unknown"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Find of an unknown cookie = %v, want ErrNotFound", err)
	}
	if _, err := findSSO(t, s, "r2", "cookie-1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Find through another realm = %v, want ErrNotFound", err)
	}

	used, expires := epoch.Add(time.Hour), epoch.Add(9*time.Hour)
	mustWrite(t, s, func(tx store.Tx) error {
		return tx.SSOSessions().Touch(ctx, "r1", secure.HashOf("cookie-1"), used, expires)
	})
	got, err = findSSO(t, s, "r1", "cookie-1")
	if err != nil || got.LastUsedAt != used || got.ExpiresAt != expires || got.CreatedAt != epoch || got.AuthTime != ssn.AuthTime {
		t.Fatalf("after Touch = %+v, %v; want last use %v and expiry %v only", got, err, used, expires)
	}
	if err := write(t, s, func(tx store.Tx) error {
		return tx.SSOSessions().Touch(ctx, "r1", secure.HashOf("unknown"), used, expires)
	}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Touch of an unknown cookie = %v, want ErrNotFound", err)
	}
	if err := write(t, s, func(tx store.Tx) error {
		return tx.SSOSessions().Touch(ctx, "r2", secure.HashOf("cookie-1"), used, expires)
	}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Touch through another realm = %v, want ErrNotFound", err)
	}

	// Delete of another realm's hash changes nothing; a repeat is not an error.
	mustWrite(t, s, func(tx store.Tx) error { return tx.SSOSessions().Delete(ctx, "r2", secure.HashOf("cookie-1")) })
	if _, err := findSSO(t, s, "r1", "cookie-1"); err != nil {
		t.Fatalf("Delete through another realm removed the session: %v", err)
	}
	for i := 0; i < 2; i++ {
		mustWrite(t, s, func(tx store.Tx) error { return tx.SSOSessions().Delete(ctx, "r1", secure.HashOf("cookie-1")) })
	}
	if _, err := findSSO(t, s, "r1", "cookie-1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("after Delete = %v, want ErrNotFound", err)
	}
}

// Covers: FR-45 (part), SEC-37 (part)
// Acceptance: Single sign-on start (part)
// testSSOSessionsDeleteByUserAndIdentity: DeleteByUser removes the rows of that
// user and DeleteByIdentity the rows made with that identity, each in its realm
// only; neither is an error when nothing matches.
func testSSOSessionsDeleteByUserAndIdentity(t *testing.T, s store.Store) {
	ctx := context.Background()
	ensure(t, s, "r", "r1")
	ensure(t, s, "o", "r2")
	createUser(t, s, newUser("r1", "u1", "a@example.com", true))
	createUser(t, s, newUser("r1", "u2", "b@example.com", true))
	createUser(t, s, newUser("r2", "u3", "c@example.com", true))
	rows := map[string]store.SSOSession{
		"a": newSSOSession("a", "u1", "i1"),
		"b": newSSOSession("b", "u1", "i2"),
		"c": newSSOSession("c", "u2", "i3"),
	}
	other := newSSOSession("d", "u3", "i4")
	other.RealmID = "r2"
	mustWrite(t, s, func(tx store.Tx) error {
		for _, name := range []string{"a", "b", "c"} {
			if err := tx.SSOSessions().Create(ctx, rows[name]); err != nil {
				return err
			}
		}
		return tx.SSOSessions().Create(ctx, other)
	})

	mustWrite(t, s, func(tx store.Tx) error { return tx.SSOSessions().DeleteByUser(ctx, "r1", "u1") })
	for _, c := range []string{"a", "b"} {
		if _, err := findSSO(t, s, "r1", c); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("session %s of the deleted user = %v, want ErrNotFound", c, err)
		}
	}
	if _, err := findSSO(t, s, "r1", "c"); err != nil {
		t.Fatalf("another user's session was deleted: %v", err)
	}
	mustWrite(t, s, func(tx store.Tx) error { return tx.SSOSessions().DeleteByUser(ctx, "r1", "u1") })
	// u2 holds a session in r1: deleting u2 in realm r2 leaves it, as does an
	// unknown user in r1.
	mustWrite(t, s, func(tx store.Tx) error { return tx.SSOSessions().DeleteByUser(ctx, "r2", "u2") })
	if _, err := findSSO(t, s, "r1", "c"); err != nil {
		t.Fatalf("DeleteByUser in another realm removed the session of r1's user: %v", err)
	}
	mustWrite(t, s, func(tx store.Tx) error { return tx.SSOSessions().DeleteByUser(ctx, "r1", "unknown") })
	if _, err := findSSO(t, s, "r1", "c"); err != nil {
		t.Fatalf("DeleteByUser of an unknown user removed another user's session: %v", err)
	}

	mustWrite(t, s, func(tx store.Tx) error { return tx.SSOSessions().DeleteByIdentity(ctx, "r1", "i3") })
	if _, err := findSSO(t, s, "r1", "c"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("session of the unlinked identity = %v, want ErrNotFound", err)
	}
	mustWrite(t, s, func(tx store.Tx) error { return tx.SSOSessions().DeleteByIdentity(ctx, "r1", "i3") })
	// The identity i4 of realm r2 is not realm r1's: its session stays.
	mustWrite(t, s, func(tx store.Tx) error { return tx.SSOSessions().DeleteByIdentity(ctx, "r1", "i4") })
	if _, err := findSSO(t, s, "r2", "d"); err != nil {
		t.Fatalf("another realm's session was deleted by identity: %v", err)
	}
}

// Covers: FR-45 (part), SEC-37 (part)
// Acceptance: Single sign-on start (part)
// testSSOSessionsDeletedWithUser: deleting the user deletes its browser sessions
// by the foreign key, as it deletes its identities.
func testSSOSessionsDeletedWithUser(t *testing.T, s store.Store) {
	ctx := context.Background()
	ensure(t, s, "r", "r1")
	createUser(t, s, newUser("r1", "u1", "a@example.com", true))
	createUser(t, s, newUser("r1", "u2", "b@example.com", true))
	mustWrite(t, s, func(tx store.Tx) error {
		if err := tx.SSOSessions().Create(ctx, newSSOSession("gone", "u1", "i1")); err != nil {
			return err
		}
		return tx.SSOSessions().Create(ctx, newSSOSession("kept", "u2", "i2"))
	})
	mustWrite(t, s, func(tx store.Tx) error { return tx.Users().Delete(ctx, "r1", "u1") })
	if _, err := findSSO(t, s, "r1", "gone"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("session of the deleted user = %v, want ErrNotFound", err)
	}
	if _, err := findSSO(t, s, "r1", "kept"); err != nil {
		t.Fatalf("another user's session was deleted with the user: %v", err)
	}
}

// Covers: FR-45 (part), SEC-37 (part)
// Acceptance: Single sign-on start (part)
// testSSOSessionsDeleteExpired: the cleanup removes the rows at or past their
// expiry; a row one second before its expiry stays. Find still returns an
// expired row until the cleanup runs (the caller checks the expiry).
func testSSOSessionsDeleteExpired(t *testing.T, s store.Store) {
	ctx := context.Background()
	ensure(t, s, "r", "r1")
	createUser(t, s, newUser("r1", "u1", "a@example.com", true))
	now := epoch.Add(time.Hour)
	live, edge, old := newSSOSession("live", "u1", "i1"), newSSOSession("edge", "u1", "i1"), newSSOSession("old", "u1", "i1")
	live.ExpiresAt, edge.ExpiresAt, old.ExpiresAt = now.Add(time.Second), now, now.Add(-time.Second)
	mustWrite(t, s, func(tx store.Tx) error {
		for _, r := range []store.SSOSession{live, edge, old} {
			if err := tx.SSOSessions().Create(ctx, r); err != nil {
				return err
			}
		}
		return nil
	})
	if _, err := findSSO(t, s, "r1", "old"); err != nil {
		t.Fatalf("an expired session is not found before the cleanup: %v", err)
	}
	if n := deleteExpired(t, s, func(tx store.Tx) (int64, error) { return tx.SSOSessions().DeleteExpired(ctx, now) }); n != 2 {
		t.Fatalf("DeleteExpired = %d, want 2", n)
	}
	if _, err := findSSO(t, s, "r1", "live"); err != nil {
		t.Fatalf("the live session was removed: %v", err)
	}
	for _, c := range []string{"edge", "old"} {
		if _, err := findSSO(t, s, "r1", c); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("Find(%s) after the cleanup = %v, want ErrNotFound", c, err)
		}
	}
}

// Covers: FR-45 (part), SEC-37 (part)
// Acceptance: Single sign-on start (part)
// testAuthCodeAndRefreshSSOIDHash: a login code and a refresh token keep the
// hash of the browser session they came from, and read back empty when none.
func testAuthCodeAndRefreshSSOIDHash(t *testing.T, s store.Store) {
	ctx := context.Background()
	withSSO := newAuthCode("code-sso")
	withSSO.SSOIDHash = secure.HashOf("cookie-x")
	mustWrite(t, s, func(tx store.Tx) error { return tx.AuthCodes().Create(ctx, withSSO) })
	mustWrite(t, s, func(tx store.Tx) error { return tx.AuthCodes().Create(ctx, newAuthCode("code-plain")) })
	for code, want := range map[string]secure.Hash{"code-sso": withSSO.SSOIDHash, "code-plain": ""} {
		var got store.AuthCode
		mustWrite(t, s, func(tx store.Tx) (err error) {
			got, err = tx.AuthCodes().Consume(ctx, secure.HashOf(code), epoch)
			return err
		})
		if got.SSOIDHash != want {
			t.Fatalf("SSOIDHash of %s = %q, want %q", code, got.SSOIDHash, want)
		}
	}

	bound := newRefresh("t-sso", "tok-sso", "s-sso")
	bound.SSOIDHash = secure.HashOf("cookie-y")
	insertRefresh(t, s, bound, newRefresh("t-plain-sso", "tok-plain-sso", "s-plain"))
	for tok, want := range map[string]secure.Hash{"tok-sso": bound.SSOIDHash, "tok-plain-sso": ""} {
		got, err := findRefresh(t, s, "r1", tok)
		if err != nil {
			t.Fatal(err)
		}
		if got.SSOIDHash != want {
			t.Fatalf("SSOIDHash of %s = %q, want %q", tok, got.SSOIDHash, want)
		}
	}
}

// Covers: FR-45 (part), SEC-37 (part)
// Acceptance: Single sign-on end (part)
// testSSOSessionsDeleteByRealm: DeleteByRealm removes the browser sessions of
// that realm only.
func testSSOSessionsDeleteByRealm(t *testing.T, s store.Store) {
	ctx := context.Background()
	ensure(t, s, "r", "r1")
	ensure(t, s, "o", "r2")
	createUser(t, s, newUser("r1", "u1", "a@example.com", true))
	createUser(t, s, newUser("r2", "u2", "b@example.com", true))
	other := newSSOSession("other", "u2", "i2")
	other.RealmID = "r2"
	mustWrite(t, s, func(tx store.Tx) error {
		if err := tx.SSOSessions().Create(ctx, newSSOSession("mine", "u1", "i1")); err != nil {
			return err
		}
		return tx.SSOSessions().Create(ctx, other)
	})
	mustWrite(t, s, func(tx store.Tx) error { return tx.SSOSessions().DeleteByRealm(ctx, "r1") })
	if _, err := findSSO(t, s, "r1", "mine"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a session of the realm after DeleteByRealm = %v, want ErrNotFound", err)
	}
	if _, err := findSSO(t, s, "r2", "other"); err != nil {
		t.Fatalf("a session of another realm was deleted: %v", err)
	}
}

// Covers: FR-45 (part), SEC-37 (part)
// Acceptance: Single sign-on end (part)
// testRefreshEndedCarriesSSOHash: a session that a revocation ends reports the
// hash of the browser session it came from, so that the browser session ends with
// it; a session without one reports none.
func testRefreshEndedCarriesSSOHash(t *testing.T, s store.Store) {
	ctx := context.Background()
	withSSO := newRefresh("t-sso-end", "tok-sso-end", "s-sso")
	withSSO.SSOIDHash = secure.HashOf("cookie-end")
	insertRefresh(t, s, withSSO, newRefresh("t-plain-end", "tok-plain-end", "s-plain-end"))
	var sso, plain store.Ended
	mustWrite(t, s, func(tx store.Tx) (err error) {
		sso, err = tx.RefreshTokens().RevokeSession(ctx, "r1", "s-sso", epoch)
		if err != nil {
			return err
		}
		plain, err = tx.RefreshTokens().RevokeSession(ctx, "r1", "s-plain-end", epoch)
		return err
	})
	if len(sso.Sessions) != 1 || sso.Sessions[0].SSOIDHash != withSSO.SSOIDHash {
		t.Fatalf("ended session = %+v, want the browser session hash of the token session", sso.Sessions)
	}
	if len(plain.Sessions) != 1 || plain.Sessions[0].SSOIDHash != "" {
		t.Fatalf("ended session without a browser session = %+v, want an empty hash", plain.Sessions)
	}
}

// Covers: FR-45 (part), SEC-37 (part)
// Acceptance: Single sign-on end (part)
// testRefreshUserEndsCarrySSOHash: a revocation of all a user's sessions and the
// deletion of a user's rows report the browser session hash of each ended session,
// as RevokeSession does, so that every ended browser session is ended with them.
func testRefreshUserEndsCarrySSOHash(t *testing.T, s store.Store) {
	ctx := context.Background()
	revoked := newRefresh("t-revoke-user", "tok-revoke-user", "s-revoke")
	revoked.SSOIDHash = secure.HashOf("cookie-revoke-user")
	deleted := newRefresh("t-delete-user", "tok-delete-user", "s-delete")
	deleted.UserID = "u2"
	deleted.SSOIDHash = secure.HashOf("cookie-delete-user")
	insertRefresh(t, s, revoked, deleted)
	var ru, du store.Ended
	mustWrite(t, s, func(tx store.Tx) (err error) {
		ru, err = tx.RefreshTokens().RevokeUser(ctx, "r1", "u1", epoch)
		if err != nil {
			return err
		}
		du, err = tx.RefreshTokens().DeleteUser(ctx, "r1", "u2")
		return err
	})
	if len(ru.Sessions) != 1 || ru.Sessions[0].SSOIDHash != revoked.SSOIDHash {
		t.Fatalf("RevokeUser ended %+v, want the browser session hash of its session", ru.Sessions)
	}
	if len(du.Sessions) != 1 || du.Sessions[0].SSOIDHash != deleted.SSOIDHash {
		t.Fatalf("DeleteUser ended %+v, want the browser session hash of its session", du.Sessions)
	}
}

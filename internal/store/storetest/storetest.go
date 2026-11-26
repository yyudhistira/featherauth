// Package storetest is the contract suite every store.Store implementation
// must pass. Run it with a factory that returns a fresh, empty, migrated store.
package storetest

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/secure"
	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/testutil"
)

// Factory returns a fresh store and closes it when the test ends.
type Factory func(t testing.TB) store.Store

var epoch = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

// Run runs every contract test against stores made by newStore.
func Run(t *testing.T, newStore Factory) {
	t.Helper()
	for _, c := range []struct {
		name string
		fn   func(*testing.T, store.Store)
	}{
		{"RealmsEnsure", testRealmsEnsure},
		{"RealmsFind", testRealmsFind},
		{"UsersCreateGetUpdateDelete", testUsersCRUD},
		{"UsersNullableFields", testUsersNullable},
		{"UsersRealmIsolation", testUsersRealmIsolation},
		{"VerifiedEmailUnique", testVerifiedEmailUnique},
		{"SameEmailInTwoRealms", testSameEmailInTwoRealms},
		{"FindAndListByEmailKey", testFindAndList},
		{"IdentitiesCRUD", testIdentitiesCRUD},
		{"IdentityProviderSubUnique", testIdentityUnique},
		{"IdentitiesSealedBy", testIdentitiesSealedBy},
		{"IdentitiesReplaceProviderToken", testIdentitiesReplaceProviderToken},
		{"DeleteUserCascades", testDeleteCascades},
		{"AuthRequestsCRUD", testAuthRequests},
		{"AuthCodeConsume", testAuthCodeConsume},
		{"AuthCodeConsumeConcurrent", testAuthCodeConsumeConcurrent},
		{"HandoffTake", testHandoffTake},
		{"HandoffCreateReplacesTheLogin", testHandoffReplacesLogin},
		{"RefreshTokensInsertFind", testRefreshInsertFind},
		{"RefreshTokensMarkReplaced", testRefreshMarkReplaced},
		{"RefreshTokensExtend", testRefreshExtend},
		{"RefreshTokensFindByID", testRefreshFindByID},
		{"RefreshTokensDeleteUser", testRefreshDeleteUser},
		{"RefreshTokensRotateConcurrent", testRefreshRotateConcurrent},
		{"RefreshTokensRevokeSession", testRefreshRevokeSession},
		{"RefreshTokensRevokeOthers", testRefreshRevokeOthers},
		{"RefreshTokensRevokeUser", testRefreshRevokeUser},
		{"RefreshTokensReportEndedSessions", testRefreshReportEndedSessions},
		{"RefreshTokensDeleteUserReportsOnlyLiveSessions", testRefreshDeleteUserReportsOnlyLiveSessions},
		{"RefreshTokensDPoPJKT", testRefreshDPoPJKT},
		{"LogoutNotificationsCRUD", testLogoutNotificationsCRUD},
		{"LogoutNotificationsSchedule", testLogoutNotificationsSchedule},
		{"LogoutNotificationsCancelled", testLogoutNotificationsCancelled},
		{"RefreshTokensSessionLive", testRefreshSessionLive},
		{"RefreshTokensLiveSessions", testRefreshLiveSessions},
		{"RefreshTokensHasSession", testRefreshHasSession},
		{"RefreshTokensDeleteExpired", testRefreshDeleteExpired},
		{"AuthRequestsDeleteExpired", testAuthRequestsDeleteExpired},
		{"AuthCodesDeleteExpired", testAuthCodesDeleteExpired},
		{"HandoffsDeleteExpired", testHandoffsDeleteExpired},
		{"ProviderEventsRemember", testProviderEventsRemember},
		{"ProviderEventsDeleteExpired", testProviderEventsDeleteExpired},
		{"ProviderEventsRememberConcurrent", testProviderEventsRememberConcurrent},
		{"SSOSessionsCRUD", testSSOSessionsCRUD},
		{"SSOSessionsDeleteByUserAndIdentity", testSSOSessionsDeleteByUserAndIdentity},
		{"SSOSessionsDeletedWithUser", testSSOSessionsDeletedWithUser},
		{"SSOSessionsDeleteExpired", testSSOSessionsDeleteExpired},
		{"AuthCodeAndRefreshSSOIDHash", testAuthCodeAndRefreshSSOIDHash},
		{"SSOSessionsDeleteByRealm", testSSOSessionsDeleteByRealm},
		{"RefreshTokensEndedCarriesSSOHash", testRefreshEndedCarriesSSOHash},
		{"RefreshTokensUserEndsCarrySSOHash", testRefreshUserEndsCarrySSOHash},
		{"DPoPProofsUse", testDPoPProofsUse},
		{"DPoPProofsDeleteExpired", testDPoPProofsDeleteExpired},
		{"RateLimitsHit", testRateLimitsHit},
		{"RateLimitsDeleteBefore", testRateLimitsDeleteBefore},
		{"AuditInsertList", testAuditInsertList},
		{"AuditDetailsRoundTrip", testAuditDetails},
	} {
		t.Run(c.name, func(t *testing.T) { c.fn(t, newStore(t)) })
	}
	RunConcurrency(t, newStore)
}

// RunConcurrency runs the cases of concurrent writes and of retries: the
// verified email race, the forced deadlocks and the unique violations. Run runs
// them too. A test of one driver that closes a trace row can run them with its
// own cases, so that the row is proved in one test.
func RunConcurrency(t *testing.T, newStore Factory) {
	t.Helper()
	for _, c := range []struct {
		name string
		fn   func(*testing.T, store.Store)
	}{
		{"VerifiedEmailRaceConcurrent", testVerifiedEmailRace},
		{"WriteRunsAgainOnForcedFault", testWriteRunsAgain},
		{"WriteGivesUpAfterThreeFaults", testWriteGivesUp},
		{"WriteRunsAgainOnceOnUniqueViolation", testWriteRunsAgainOnUnique},
		{"WriteUniqueViolationRepeatedIsConflict", testWriteUniqueRepeated},
		{"WriteOtherUniqueViolationIsNotRun", testWriteOtherUniqueNotRun},
	} {
		t.Run(c.name, func(t *testing.T) { c.fn(t, newStore(t)) })
	}
}

func write(t *testing.T, s store.Store, fn func(store.Tx) error) error {
	t.Helper()
	return s.Write(context.Background(), fn)
}

func mustWrite(t *testing.T, s store.Store, fn func(store.Tx) error) {
	t.Helper()
	if err := write(t, s, fn); err != nil {
		t.Fatal(err)
	}
}

func mustRead(t *testing.T, s store.Store, fn func(store.Tx) error) {
	t.Helper()
	if err := s.Read(context.Background(), fn); err != nil {
		t.Fatal(err)
	}
}

func ensure(t *testing.T, s store.Store, name config.RealmName, id store.RealmID) {
	t.Helper()
	mustWrite(t, s, func(tx store.Tx) error {
		got, err := tx.Realms().Ensure(context.Background(), name, id, epoch)
		if err == nil && got != id {
			t.Fatalf("Ensure(%q) = %q, want %q", name, got, id)
		}
		return err
	})
}

func newUser(realm store.RealmID, id, email string, verified bool) store.User {
	return store.User{
		ID: store.UserID(id), RealmID: realm,
		Email: email, EmailKey: email, EmailVerified: verified,
		Name: "Name " + id, CreatedAt: epoch, UpdatedAt: epoch,
	}
}

func createUser(t *testing.T, s store.Store, u store.User) {
	t.Helper()
	mustWrite(t, s, func(tx store.Tx) error { return tx.Users().Create(context.Background(), u) })
}

func testRealmsEnsure(t *testing.T, s store.Store) {
	ctx := context.Background()
	ensure(t, s, "a", "id-a")
	mustWrite(t, s, func(tx store.Tx) error {
		again, err := tx.Realms().Ensure(ctx, "a", "other-id", epoch.Add(time.Hour))
		if err != nil {
			return err
		}
		if again != "id-a" {
			t.Fatalf("second Ensure = %q, want the first id", again)
		}
		b, err := tx.Realms().Ensure(ctx, "b", "id-b", epoch)
		if err != nil {
			return err
		}
		if b != "id-b" || b == again {
			t.Fatalf("new realm id = %q", b)
		}
		return nil
	})
}

func testRealmsFind(t *testing.T, s store.Store) {
	ctx := context.Background()
	mustRead(t, s, func(tx store.Tx) error {
		if _, err := tx.Realms().Find(ctx, "a"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("Find of an unknown realm = %v, want ErrNotFound", err)
		}
		return nil
	})
	ensure(t, s, "a", "id-a")
	mustRead(t, s, func(tx store.Tx) error {
		id, err := tx.Realms().Find(ctx, "a")
		if err != nil || id != "id-a" {
			t.Fatalf("Find = %q, %v", id, err)
		}
		if _, err := tx.Realms().Find(ctx, "b"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("Find of another realm = %v", err)
		}
		return nil
	})
}

func testUsersCRUD(t *testing.T, s store.Store) {
	ctx := context.Background()
	ensure(t, s, "r", "r1")
	u := newUser("r1", "u1", "A@Example.com", true)
	u.Email = "A@Example.com"
	u.EmailKey = "a@example.com"
	createUser(t, s, u)

	mustRead(t, s, func(tx store.Tx) error {
		got, err := tx.Users().Get(ctx, "r1", "u1")
		if err != nil {
			return err
		}
		if got != u {
			t.Fatalf("Get = %+v, want %+v", got, u)
		}
		return nil
	})

	u.Name = "New"
	u.EmailVerified = false
	u.DisabledAt = epoch.Add(time.Minute)
	u.UpdatedAt = epoch.Add(time.Hour)
	mustWrite(t, s, func(tx store.Tx) error { return tx.Users().Update(ctx, u) })
	mustRead(t, s, func(tx store.Tx) error {
		got, err := tx.Users().Get(ctx, "r1", "u1")
		if err != nil {
			return err
		}
		if got != u {
			t.Fatalf("after Update = %+v, want %+v", got, u)
		}
		return nil
	})

	missing := newUser("r1", "nope", "", false)
	err := write(t, s, func(tx store.Tx) error { return tx.Users().Update(ctx, missing) })
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Update missing = %v, want ErrNotFound", err)
	}
	err = write(t, s, func(tx store.Tx) error { return tx.Users().Create(ctx, u) })
	if !errors.Is(err, store.ErrConflict) {
		t.Fatalf("Create duplicate id = %v, want ErrConflict", err)
	}

	mustWrite(t, s, func(tx store.Tx) error { return tx.Users().Delete(ctx, "r1", "u1") })
	err = s.Read(ctx, func(tx store.Tx) error {
		_, err := tx.Users().Get(ctx, "r1", "u1")
		return err
	})
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Get after Delete = %v, want ErrNotFound", err)
	}
	err = write(t, s, func(tx store.Tx) error { return tx.Users().Delete(ctx, "r1", "u1") })
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Delete missing = %v, want ErrNotFound", err)
	}
}

func testUsersNullable(t *testing.T, s store.Store) {
	ctx := context.Background()
	ensure(t, s, "r", "r1")
	u := store.User{ID: "u1", RealmID: "r1", CreatedAt: epoch, UpdatedAt: epoch}
	createUser(t, s, u)
	mustRead(t, s, func(tx store.Tx) error {
		got, err := tx.Users().Get(ctx, "r1", "u1")
		if err != nil {
			return err
		}
		if got != u {
			t.Fatalf("Get = %+v, want %+v", got, u)
		}
		return nil
	})
	// Two verified users without an email do not collide.
	u2 := u
	u2.ID = "u2"
	u2.EmailVerified = true
	u3 := u2
	u3.ID = "u3"
	createUser(t, s, u2)
	createUser(t, s, u3)
}

func testUsersRealmIsolation(t *testing.T, s store.Store) {
	ctx := context.Background()
	ensure(t, s, "a", "ra")
	ensure(t, s, "b", "rb")
	createUser(t, s, newUser("ra", "u1", "x@example.com", true))
	mustRead(t, s, func(tx store.Tx) error {
		if _, err := tx.Users().Get(ctx, "rb", "u1"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("Get in the other realm = %v, want ErrNotFound", err)
		}
		return nil
	})
	err := write(t, s, func(tx store.Tx) error { return tx.Users().Delete(ctx, "rb", "u1") })
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Delete in the other realm = %v, want ErrNotFound", err)
	}
	u := newUser("rb", "u1", "", false)
	err = write(t, s, func(tx store.Tx) error { return tx.Users().Update(ctx, u) })
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Update in the other realm = %v, want ErrNotFound", err)
	}
}

func testVerifiedEmailUnique(t *testing.T, s store.Store) {
	ctx := context.Background()
	ensure(t, s, "r", "r1")
	createUser(t, s, newUser("r1", "u1", "a@example.com", true))
	err := write(t, s, func(tx store.Tx) error {
		return tx.Users().Create(ctx, newUser("r1", "u2", "a@example.com", true))
	})
	if !errors.Is(err, store.ErrConflict) {
		t.Fatalf("second verified user = %v, want ErrConflict", err)
	}
	// Unverified duplicates are allowed, also next to a verified user.
	createUser(t, s, newUser("r1", "u3", "a@example.com", false))
	createUser(t, s, newUser("r1", "u4", "a@example.com", false))
	// Verifying one of them while another user holds the email conflicts.
	v := newUser("r1", "u3", "a@example.com", true)
	err = write(t, s, func(tx store.Tx) error { return tx.Users().Update(ctx, v) })
	if !errors.Is(err, store.ErrConflict) {
		t.Fatalf("Update to a duplicate verified email = %v, want ErrConflict", err)
	}
}

func testSameEmailInTwoRealms(t *testing.T, s store.Store) {
	ensure(t, s, "a", "ra")
	ensure(t, s, "b", "rb")
	createUser(t, s, newUser("ra", "u1", "a@example.com", true))
	createUser(t, s, newUser("rb", "u2", "a@example.com", true))
}

func testFindAndList(t *testing.T, s store.Store) {
	ctx := context.Background()
	ensure(t, s, "a", "ra")
	ensure(t, s, "b", "rb")
	createUser(t, s, newUser("ra", "u1", "a@example.com", false))
	createUser(t, s, newUser("ra", "u2", "a@example.com", true))
	createUser(t, s, newUser("ra", "u3", "other@example.com", true))
	createUser(t, s, newUser("rb", "u4", "a@example.com", true))
	mustRead(t, s, func(tx store.Tx) error {
		v, err := tx.Users().FindVerifiedByEmailKey(ctx, "ra", "a@example.com")
		if err != nil {
			return err
		}
		if v.ID != "u2" {
			t.Fatalf("FindVerifiedByEmailKey = %q, want u2", v.ID)
		}
		if _, err := tx.Users().FindVerifiedByEmailKey(ctx, "ra", "none@example.com"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("FindVerifiedByEmailKey none = %v, want ErrNotFound", err)
		}
		list, err := tx.Users().ListByEmailKey(ctx, "ra", "a@example.com")
		if err != nil {
			return err
		}
		if len(list) != 2 || list[0].ID != "u1" || list[1].ID != "u2" {
			t.Fatalf("ListByEmailKey = %+v, want u1, u2", list)
		}
		list, err = tx.Users().ListByEmailKey(ctx, "ra", "none@example.com")
		if err != nil || len(list) != 0 {
			t.Fatalf("ListByEmailKey none = %v, %v", list, err)
		}
		return nil
	})
}

func newIdentity(realm store.RealmID, id string, user store.UserID, provider config.ProviderKey, sub string) store.Identity {
	return store.Identity{
		ID: store.IdentityID(id), RealmID: realm, UserID: user,
		Provider: provider, ProviderSub: sub,
		Email: "i@example.com", EmailVerified: true, CreatedAt: epoch,
	}
}

func createIdentity(t *testing.T, s store.Store, i store.Identity) {
	t.Helper()
	mustWrite(t, s, func(tx store.Tx) error { return tx.Identities().Create(context.Background(), i) })
}

func testIdentitiesCRUD(t *testing.T, s store.Store) {
	ctx := context.Background()
	ensure(t, s, "r", "r1")
	createUser(t, s, newUser("r1", "u1", "a@example.com", true))
	createUser(t, s, newUser("r1", "u2", "b@example.com", true))
	i1 := newIdentity("r1", "i1", "u1", "google", "sub1")
	i2 := newIdentity("r1", "i2", "u1", "github", "sub2")
	createIdentity(t, s, i1)
	createIdentity(t, s, i2)
	createIdentity(t, s, newIdentity("r1", "i3", "u2", "google", "sub3"))

	mustRead(t, s, func(tx store.Tx) error {
		got, err := tx.Identities().Find(ctx, "r1", "google", "sub1")
		if err != nil {
			return err
		}
		if got != i1 {
			t.Fatalf("Find = %+v, want %+v", got, i1)
		}
		if _, err := tx.Identities().Find(ctx, "r1", "google", "nope"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("Find missing = %v, want ErrNotFound", err)
		}
		list, err := tx.Identities().ListByUser(ctx, "r1", "u1")
		if err != nil {
			return err
		}
		if len(list) != 2 || list[0] != i1 || list[1] != i2 {
			t.Fatalf("ListByUser = %+v", list)
		}
		return nil
	})

	i1.Email = "changed@example.com"
	i1.EmailVerified = false
	mustWrite(t, s, func(tx store.Tx) error { return tx.Identities().Update(ctx, i1) })
	mustWrite(t, s, func(tx store.Tx) error {
		return tx.Identities().SetProviderToken(ctx, "r1", "i1", "sealed-token")
	})
	i1.ProviderRefreshTokenEnc = "sealed-token"
	mustRead(t, s, func(tx store.Tx) error {
		got, err := tx.Identities().Find(ctx, "r1", "google", "sub1")
		if err != nil {
			return err
		}
		if got != i1 {
			t.Fatalf("after Update and SetProviderToken = %+v, want %+v", got, i1)
		}
		return nil
	})
	mustWrite(t, s, func(tx store.Tx) error { return tx.Identities().SetProviderToken(ctx, "r1", "i1", "") })
	mustRead(t, s, func(tx store.Tx) error {
		got, err := tx.Identities().Find(ctx, "r1", "google", "sub1")
		if err != nil {
			return err
		}
		if got.ProviderRefreshTokenEnc != "" {
			t.Fatalf("token after clearing = %q", got.ProviderRefreshTokenEnc)
		}
		return nil
	})

	for name, fn := range map[string]func(store.Tx) error{
		"Update":           func(tx store.Tx) error { return tx.Identities().Update(ctx, newIdentity("r1", "nope", "u1", "x", "y")) },
		"SetProviderToken": func(tx store.Tx) error { return tx.Identities().SetProviderToken(ctx, "r1", "nope", "x") },
		"Delete":           func(tx store.Tx) error { return tx.Identities().Delete(ctx, "r1", "nope") },
	} {
		if err := write(t, s, fn); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("%s missing = %v, want ErrNotFound", name, err)
		}
	}

	mustWrite(t, s, func(tx store.Tx) error { return tx.Identities().Delete(ctx, "r1", "i2") })
	mustRead(t, s, func(tx store.Tx) error {
		list, err := tx.Identities().ListByUser(ctx, "r1", "u1")
		if err != nil {
			return err
		}
		if len(list) != 1 || list[0].ID != "i1" {
			t.Fatalf("ListByUser after Delete = %+v", list)
		}
		return nil
	})
}

// sealedFixture creates the realms r1 and r2 and the identities the sealed
// token tests use: values of the key ids aaaaaaaa and bbbbbbbb, one without a
// value, one of another realm, and user ids that sort differently by bytes and
// by locale.
func sealedFixture(t *testing.T, s store.Store) {
	t.Helper()
	ensure(t, s, "one", "r1")
	ensure(t, s, "two", "r2")
	for _, u := range []struct {
		realm store.RealmID
		id    string
	}{{"r1", "u1"}, {"r1", "B-user"}, {"r1", "a-user"}, {"r2", "u9"}} {
		createUser(t, s, newUser(u.realm, u.id, u.id+"@example.com", false))
	}
	for _, i := range []struct {
		realm       store.RealmID
		id, user    string
		provider    config.ProviderKey
		sub, sealed string
	}{
		{"r1", "i1", "u1", "google", "s1", "aaaaaaaa.one"},
		{"r1", "i2", "B-user", "apple", "s2", "aaaaaaaa.two"},
		{"r1", "i3", "a-user", "apple", "s3", "aaaaaaaa.three"},
		{"r1", "i4", "a-user", "facebook", "s4", "bbbbbbbb.four"},
		{"r1", "i5", "u1", "github", "s5", ""},
		{"r1", "i6", "u1", "oidc", "s6", "aaaaaaaaa.longer-id"},
		{"r1", "i7", "u1", "other", "s7", "aaaaaaaa"},
		{"r2", "i8", "u9", "apple", "s8", "aaaaaaaa.other-realm"},
	} {
		id := newIdentity(i.realm, i.id, store.UserID(i.user), i.provider, i.sub)
		id.ProviderRefreshTokenEnc = i.sealed
		createIdentity(t, s, id)
	}
}

// SealedBy lists the identities of the realm whose stored value starts with the
// key id and a dot, in the order user id, provider, subject by bytes.
func testIdentitiesSealedBy(t *testing.T, s store.Store) {
	ctx := context.Background()
	sealedFixture(t, s)
	list := func(realm store.RealmID, key string) []store.SealedIdentity {
		var out []store.SealedIdentity
		mustRead(t, s, func(tx store.Tx) (err error) {
			out, err = tx.Identities().SealedBy(ctx, realm, key)
			return err
		})
		return out
	}
	got := list("r1", "aaaaaaaa")
	// B-user sorts before a-user by bytes, then the user's providers by name.
	want := []store.SealedIdentity{
		{ID: "i2", RealmID: "r1", UserID: "B-user", Provider: "apple", Subject: "s2", Value: "aaaaaaaa.two"},
		{ID: "i3", RealmID: "r1", UserID: "a-user", Provider: "apple", Subject: "s3", Value: "aaaaaaaa.three"},
		{ID: "i1", RealmID: "r1", UserID: "u1", Provider: "google", Subject: "s1", Value: "aaaaaaaa.one"},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("SealedBy aaaaaaaa = %+v, want %+v", got, want)
	}
	if got := list("r1", "bbbbbbbb"); len(got) != 1 || got[0].ID != "i4" {
		t.Fatalf("SealedBy bbbbbbbb = %+v", got)
	}
	if got := list("r2", "aaaaaaaa"); len(got) != 1 || got[0].ID != "i8" {
		t.Fatalf("SealedBy r2 = %+v", got)
	}
	// The match is a literal prefix: no wildcard, no other key id.
	for _, k := range []string{"cccccccc", "aaaaaaa_", "aaaaaaa%", "%"} {
		if got := list("r1", k); len(got) != 0 {
			t.Fatalf("SealedBy %q = %+v, want none", k, got)
		}
	}
	if got := list("nope", "aaaaaaaa"); len(got) != 0 {
		t.Fatalf("SealedBy unknown realm = %+v", got)
	}
}

// ReplaceProviderToken writes only when the value is still the one given.
func testIdentitiesReplaceProviderToken(t *testing.T, s store.Store) {
	ctx := context.Background()
	sealedFixture(t, s)
	replace := func(realm store.RealmID, id, old, next string) bool {
		var ok bool
		mustWrite(t, s, func(tx store.Tx) (err error) {
			ok, err = tx.Identities().ReplaceProviderToken(ctx, realm, store.IdentityID(id), old, next)
			return err
		})
		return ok
	}
	owner := map[string]store.UserID{"i1": "u1", "i2": "B-user"}
	value := func(id string) string {
		var v string
		mustRead(t, s, func(tx store.Tx) error {
			list, err := tx.Identities().ListByUser(ctx, "r1", owner[id])
			for _, i := range list {
				if string(i.ID) == id {
					v = i.ProviderRefreshTokenEnc
				}
			}
			return err
		})
		return v
	}
	if !replace("r1", "i1", "aaaaaaaa.one", "bbbbbbbb.new") || value("i1") != "bbbbbbbb.new" {
		t.Fatalf("replace of the current value: value %q", value("i1"))
	}
	// A stale old value changes nothing.
	if replace("r1", "i1", "aaaaaaaa.one", "cccccccc.x") || value("i1") != "bbbbbbbb.new" {
		t.Fatalf("replace of a stale value: value %q", value("i1"))
	}
	// Another realm's identity is not touched.
	if replace("r2", "i2", "aaaaaaaa.two", "x") || value("i2") != "aaaaaaaa.two" {
		t.Fatalf("replace in another realm: value %q", value("i2"))
	}
	// An unknown identity is no match, not an error.
	if replace("r1", "nope", "a", "b") {
		t.Fatal("replace of an unknown identity reported a change")
	}
	// An empty next value clears the token (NULL); an old value that is none
	// matches no row, so a dropped token is never brought back.
	if !replace("r1", "i1", "bbbbbbbb.new", "") || value("i1") != "" {
		t.Fatalf("clear: value %q", value("i1"))
	}
	if replace("r1", "i1", "bbbbbbbb.new", "aaaaaaaa.back") || value("i1") != "" {
		t.Fatalf("replace after a clear: value %q", value("i1"))
	}
	if replace("r1", "i1", "", "aaaaaaaa.back") || value("i1") != "" {
		t.Fatalf("replace of an empty old value: value %q", value("i1"))
	}
}

func testIdentityUnique(t *testing.T, s store.Store) {
	ctx := context.Background()
	ensure(t, s, "a", "ra")
	ensure(t, s, "b", "rb")
	createUser(t, s, newUser("ra", "u1", "a@example.com", true))
	createUser(t, s, newUser("ra", "u2", "b@example.com", true))
	createUser(t, s, newUser("rb", "u3", "c@example.com", true))
	createIdentity(t, s, newIdentity("ra", "i1", "u1", "google", "sub"))
	err := write(t, s, func(tx store.Tx) error {
		return tx.Identities().Create(ctx, newIdentity("ra", "i2", "u2", "google", "sub"))
	})
	if !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate (realm, provider, sub) = %v, want ErrConflict", err)
	}
	// The same sub at another provider or in another realm is fine.
	createIdentity(t, s, newIdentity("ra", "i3", "u2", "github", "sub"))
	createIdentity(t, s, newIdentity("rb", "i4", "u3", "google", "sub"))
}

func testDeleteCascades(t *testing.T, s store.Store) {
	ctx := context.Background()
	ensure(t, s, "r", "r1")
	createUser(t, s, newUser("r1", "u1", "a@example.com", true))
	createIdentity(t, s, newIdentity("r1", "i1", "u1", "google", "sub1"))
	createIdentity(t, s, newIdentity("r1", "i2", "u1", "github", "sub2"))
	mustWrite(t, s, func(tx store.Tx) error { return tx.Users().Delete(ctx, "r1", "u1") })
	mustRead(t, s, func(tx store.Tx) error {
		if _, err := tx.Identities().Find(ctx, "r1", "google", "sub1"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("identity after user delete = %v, want ErrNotFound", err)
		}
		list, err := tx.Identities().ListByUser(ctx, "r1", "u1")
		if err != nil || len(list) != 0 {
			t.Fatalf("ListByUser after cascade = %v, %v", list, err)
		}
		return nil
	})
}

func newAuthRequest(id string) store.AuthRequest {
	return store.AuthRequest{
		ID: store.AuthRequestID(id), RealmID: "r1", ClientID: "app", RedirectURI: "https://app.example/cb",
		ClientState: "client-state", Nonce: "nonce", ProviderNonce: "provider-nonce",
		CodeChallenge: "challenge", ResponseMode: "query", Provider: "google",
		ProviderPKCEVerifier: "verifier", ExpiresAt: epoch.Add(10 * time.Minute),
	}
}

func testAuthRequests(t *testing.T, s store.Store) {
	ctx := context.Background()
	maxAge := 300 * time.Second
	zero := time.Duration(0)
	withAge, withZero, without := newAuthRequest("a1"), newAuthRequest("a2"), newAuthRequest("a3")
	withAge.MaxAge, withZero.MaxAge = &maxAge, &zero
	without.Nonce, without.CodeChallenge, without.ClientState = "", "", ""
	for _, ar := range []store.AuthRequest{withAge, withZero, without} {
		mustWrite(t, s, func(tx store.Tx) error { return tx.AuthRequests().Create(ctx, ar) })
	}
	mustRead(t, s, func(tx store.Tx) error {
		for _, want := range []store.AuthRequest{withAge, withZero, without} {
			got, err := tx.AuthRequests().Get(ctx, want.ID)
			if err != nil {
				return err
			}
			if (got.MaxAge == nil) != (want.MaxAge == nil) || got.MaxAge != nil && *got.MaxAge != *want.MaxAge {
				t.Fatalf("%s: MaxAge = %v, want %v", want.ID, got.MaxAge, want.MaxAge)
			}
			got.MaxAge, want.MaxAge = nil, nil
			if got != want {
				t.Fatalf("Get = %+v, want %+v", got, want)
			}
		}
		if _, err := tx.AuthRequests().Get(ctx, "missing"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("Get missing = %v, want ErrNotFound", err)
		}
		return nil
	})
	err := write(t, s, func(tx store.Tx) error { return tx.AuthRequests().Create(ctx, withAge) })
	if !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate Create = %v, want ErrConflict", err)
	}
	mustWrite(t, s, func(tx store.Tx) error { return tx.AuthRequests().Delete(ctx, "a1") })
	mustRead(t, s, func(tx store.Tx) error {
		if _, err := tx.AuthRequests().Get(ctx, "a1"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("Get after Delete = %v, want ErrNotFound", err)
		}
		return nil
	})
	err = write(t, s, func(tx store.Tx) error { return tx.AuthRequests().Delete(ctx, "a1") })
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("second Delete = %v, want ErrNotFound", err)
	}
}

func newAuthCode(code string) store.AuthCode {
	return store.AuthCode{
		CodeHash: secure.HashOf(code), RealmID: "r1", UserID: "u1", SessionID: "sess-1",
		SessionStartedAt: epoch.Add(-time.Hour), ClientID: "app", RedirectURI: "https://app.example/cb",
		CodeChallenge: "challenge", Nonce: "nonce", AuthTime: epoch.Add(-time.Minute),
		ExpiresAt: epoch.Add(time.Minute),
	}
}

func consume(t *testing.T, s store.Store, code string, now time.Time) (store.AuthCode, error) {
	t.Helper()
	var got store.AuthCode
	err := write(t, s, func(tx store.Tx) (err error) {
		got, err = tx.AuthCodes().Consume(context.Background(), secure.HashOf(code), now)
		return err
	})
	return got, err
}

func usedSession(t *testing.T, err error) store.SessionID {
	t.Helper()
	var ue *store.UsedError
	if !errors.As(err, &ue) {
		t.Fatalf("error %v does not carry a session id", err)
	}
	return ue.SessionID
}

func testAuthCodeConsume(t *testing.T, s store.Store) {
	ctx := context.Background()
	c, noChallenge := newAuthCode("code-1"), newAuthCode("code-2")
	noChallenge.CodeChallenge, noChallenge.Nonce = "", ""
	expiring := newAuthCode("code-3")
	for _, ac := range []store.AuthCode{c, noChallenge, expiring} {
		mustWrite(t, s, func(tx store.Tx) error { return tx.AuthCodes().Create(ctx, ac) })
	}
	if err := write(t, s, func(tx store.Tx) error { return tx.AuthCodes().Create(ctx, c) }); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate Create = %v, want ErrConflict", err)
	}

	got, err := consume(t, s, "code-1", epoch)
	if err != nil {
		t.Fatalf("first Consume: %v", err)
	}
	want := c
	want.UsedAt = epoch
	if got != want {
		t.Fatalf("Consume = %+v, want %+v", got, want)
	}
	_, err = consume(t, s, "code-1", epoch.Add(time.Second))
	if !errors.Is(err, store.ErrUsed) || usedSession(t, err) != "sess-1" {
		t.Fatalf("second Consume = %v, want ErrUsed with session sess-1", err)
	}
	// The used error also names the user and the client of the code.
	var ue *store.UsedError
	if !errors.As(err, &ue) || ue.UserID != "u1" || ue.ClientID != "app" {
		t.Fatalf("used error = %+v, want user u1 and client app", ue)
	}
	// A used code stays used after it has expired.
	_, err = consume(t, s, "code-1", epoch.Add(time.Hour))
	if !errors.Is(err, store.ErrUsed) {
		t.Fatalf("Consume of a used, expired code = %v, want ErrUsed", err)
	}

	got, err = consume(t, s, "code-2", epoch)
	if err != nil || got.CodeChallenge != "" || got.Nonce != "" {
		t.Fatalf("Consume without challenge = %+v, %v", got, err)
	}

	// Expired at the expiry instant and after; the expired code is not marked used.
	if _, err = consume(t, s, "code-3", c.ExpiresAt); !errors.Is(err, store.ErrExpired) {
		t.Fatalf("Consume at expiry = %v, want ErrExpired", err)
	}
	if _, err = consume(t, s, "code-3", c.ExpiresAt.Add(time.Hour)); !errors.Is(err, store.ErrExpired) {
		t.Fatalf("Consume after expiry = %v, want ErrExpired", err)
	}
	if _, err = consume(t, s, "code-3", c.ExpiresAt.Add(-time.Second)); err != nil {
		t.Fatalf("Consume just before expiry = %v", err)
	}
	if _, err = consume(t, s, "unknown", epoch); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Consume unknown = %v, want ErrNotFound", err)
	}
}

func testAuthCodeConsumeConcurrent(t *testing.T, s store.Store) {
	ctx := context.Background()
	mustWrite(t, s, func(tx store.Tx) error { return tx.AuthCodes().Create(ctx, newAuthCode("race")) })
	const workers = 50
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		success int
		used    int
		others  []error
	)
	start := make(chan struct{})
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			var got store.AuthCode
			err := s.Write(ctx, func(tx store.Tx) (err error) {
				got, err = tx.AuthCodes().Consume(ctx, secure.HashOf("race"), epoch)
				return err
			})
			mu.Lock()
			defer mu.Unlock()
			var ue *store.UsedError
			switch {
			case err == nil && got.SessionID == "sess-1":
				success++
			case errors.Is(err, store.ErrUsed) && errors.As(err, &ue) && ue.SessionID == "sess-1":
				used++
			default:
				others = append(others, err)
			}
		}()
	}
	close(start)
	wg.Wait()
	if success != 1 || used != workers-1 || len(others) != 0 {
		t.Fatalf("success=%d used=%d other errors=%v, want 1, %d, none", success, used, others, workers-1)
	}
}

func testHandoffTake(t *testing.T, s store.Store) {
	ctx := context.Background()
	h := store.Handoff{IDHash: secure.HashOf("h1"), AuthRequestID: "a1", Payload: `{"x":1}`, ExpiresAt: epoch.Add(time.Minute)}
	mustWrite(t, s, func(tx store.Tx) error { return tx.Handoffs().Create(ctx, h) })
	if err := write(t, s, func(tx store.Tx) error { return tx.Handoffs().Create(ctx, h) }); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate Create = %v, want ErrConflict", err)
	}
	take := func(id string, now time.Time) (store.Handoff, error) {
		var got store.Handoff
		err := write(t, s, func(tx store.Tx) (err error) {
			got, err = tx.Handoffs().Take(ctx, secure.HashOf(id), now)
			return err
		})
		return got, err
	}
	got, err := take("h1", epoch)
	if err != nil || got != h {
		t.Fatalf("Take = %+v, %v, want %+v", got, err, h)
	}
	if _, err = take("h1", epoch); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("second Take = %v, want ErrNotFound", err)
	}
	h2 := h
	h2.IDHash = secure.HashOf("h2")
	mustWrite(t, s, func(tx store.Tx) error { return tx.Handoffs().Create(ctx, h2) })
	if _, err = take("h2", h2.ExpiresAt); !errors.Is(err, store.ErrExpired) {
		t.Fatalf("Take at expiry = %v, want ErrExpired", err)
	}
	if _, err = take("unknown", epoch); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Take unknown = %v, want ErrNotFound", err)
	}
}

// testHandoffReplacesLogin: a second Create for a login replaces its first
// handoff, whose id stops working; another login's handoff is kept.
func testHandoffReplacesLogin(t *testing.T, s store.Store) {
	ctx := context.Background()
	first := store.Handoff{IDHash: secure.HashOf("first"), AuthRequestID: "a1", Payload: "p1", ExpiresAt: epoch.Add(time.Minute)}
	other := store.Handoff{IDHash: secure.HashOf("other"), AuthRequestID: "a2", Payload: "p3", ExpiresAt: epoch.Add(time.Minute)}
	second := store.Handoff{IDHash: secure.HashOf("second"), AuthRequestID: "a1", Payload: "p2", ExpiresAt: epoch.Add(2 * time.Minute)}
	mustWrite(t, s, func(tx store.Tx) error { return tx.Handoffs().Create(ctx, first) })
	mustWrite(t, s, func(tx store.Tx) error { return tx.Handoffs().Create(ctx, other) })
	mustWrite(t, s, func(tx store.Tx) error { return tx.Handoffs().Create(ctx, second) })
	take := func(id string) (store.Handoff, error) {
		var got store.Handoff
		err := write(t, s, func(tx store.Tx) (err error) {
			got, err = tx.Handoffs().Take(ctx, secure.HashOf(id), epoch)
			return err
		})
		return got, err
	}
	if _, err := take("first"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the replaced handoff: Take = %v, want ErrNotFound", err)
	}
	if got, err := take("second"); err != nil || got != second {
		t.Fatalf("the replacing handoff: Take = %+v, %v, want %+v", got, err, second)
	}
	if got, err := take("other"); err != nil || got != other {
		t.Fatalf("another login's handoff: Take = %+v, %v, want %+v", got, err, other)
	}
}

func newRefresh(id, token, session string) store.RefreshToken {
	return store.RefreshToken{
		ID: store.RefreshTokenID(id), RealmID: "r1", UserID: "u1", ClientID: "app",
		TokenHash: secure.HashOf(token), SessionID: store.SessionID(session),
		SessionStartedAt: epoch, AuthTime: epoch.Add(-time.Minute), Nonce: "nonce-1",
		ExpiresAt: epoch.Add(time.Hour), CreatedAt: epoch,
	}
}

func insertRefresh(t *testing.T, s store.Store, rows ...store.RefreshToken) {
	t.Helper()
	mustWrite(t, s, func(tx store.Tx) error {
		for _, r := range rows {
			if err := tx.RefreshTokens().Insert(context.Background(), r); err != nil {
				return err
			}
		}
		return nil
	})
}

func findRefresh(t *testing.T, s store.Store, realm store.RealmID, token string) (store.RefreshToken, error) {
	t.Helper()
	var got store.RefreshToken
	err := s.Read(context.Background(), func(tx store.Tx) (err error) {
		got, err = tx.RefreshTokens().FindByHash(context.Background(), realm, secure.HashOf(token))
		return err
	})
	return got, err
}

func testRefreshInsertFind(t *testing.T, s store.Store) {
	ctx := context.Background()
	a := newRefresh("t1", "tok1", "sess-1")
	insertRefresh(t, s, a)
	got, err := findRefresh(t, s, "r1", "tok1")
	if err != nil || got != a {
		t.Fatalf("FindByHash = %+v, %v, want %+v", got, err, a)
	}
	if err := write(t, s, func(tx store.Tx) error { return tx.RefreshTokens().Insert(ctx, a) }); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate id = %v, want ErrConflict", err)
	}
	dup := newRefresh("t2", "tok1", "sess-1")
	if err := write(t, s, func(tx store.Tx) error { return tx.RefreshTokens().Insert(ctx, dup) }); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate hash = %v, want ErrConflict", err)
	}
	if _, err := findRefresh(t, s, "r1", "unknown"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown = %v, want ErrNotFound", err)
	}
	// A token of one realm is not found through another.
	if _, err := findRefresh(t, s, "r2", "tok1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("other realm = %v, want ErrNotFound", err)
	}
	// Empty nonce is stored as NULL and read back empty.
	b := newRefresh("t3", "tok3", "sess-1")
	b.Nonce = ""
	insertRefresh(t, s, b)
	if got, err := findRefresh(t, s, "r1", "tok3"); err != nil || got != b {
		t.Fatalf("FindByHash without nonce = %+v, %v, want %+v", got, err, b)
	}
}

func testRefreshMarkReplaced(t *testing.T, s store.Store) {
	ctx := context.Background()
	insertRefresh(t, s, newRefresh("t1", "tok1", "sess-1"))
	mark := func(id, succ string) error {
		return write(t, s, func(tx store.Tx) error {
			return tx.RefreshTokens().MarkReplaced(ctx, store.RefreshTokenID(id), store.RefreshTokenID(succ))
		})
	}
	if err := mark("t1", "t2"); err != nil {
		t.Fatalf("first MarkReplaced = %v", err)
	}
	if err := mark("t1", "t3"); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("second MarkReplaced = %v, want ErrConflict", err)
	}
	if err := mark("nope", "t3"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown MarkReplaced = %v, want ErrNotFound", err)
	}
	got, err := findRefresh(t, s, "r1", "tok1")
	if err != nil || got.ReplacedBy != "t2" {
		t.Fatalf("ReplacedBy = %q, %v, want t2", got.ReplacedBy, err)
	}
}

func testRefreshFindByID(t *testing.T, s store.Store) {
	ctx := context.Background()
	a := newRefresh("t1", "tok1", "sess-1")
	a.ExpiresAt = epoch.Add(-time.Hour) // expired rows are found too
	insertRefresh(t, s, a)
	find := func(realm store.RealmID, id store.RefreshTokenID) (store.RefreshToken, error) {
		var got store.RefreshToken
		err := s.Read(ctx, func(tx store.Tx) error {
			var err error
			got, err = tx.RefreshTokens().FindByID(ctx, realm, id)
			return err
		})
		return got, err
	}
	if got, err := find("r1", "t1"); err != nil || got != a {
		t.Fatalf("FindByID = %+v, %v, want %+v", got, err, a)
	}
	if _, err := find("r1", "nope"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown = %v, want ErrNotFound", err)
	}
	if _, err := find("r2", "t1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("other realm = %v, want ErrNotFound", err)
	}
}

func testRefreshExtend(t *testing.T, s store.Store) {
	ctx := context.Background()
	insertRefresh(t, s, newRefresh("t1", "tok1", "sess-1"))
	later := epoch.Add(48 * time.Hour)
	err := write(t, s, func(tx store.Tx) error {
		return tx.RefreshTokens().Extend(ctx, "r1", "t1", later)
	})
	if err != nil {
		t.Fatalf("Extend = %v", err)
	}
	got, err := findRefresh(t, s, "r1", "tok1")
	if err != nil || !got.ExpiresAt.Equal(later) {
		t.Fatalf("ExpiresAt = %v, %v, want %v", got.ExpiresAt, err, later)
	}
	err = write(t, s, func(tx store.Tx) error {
		return tx.RefreshTokens().Extend(ctx, "r1", "nope", later)
	})
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown Extend = %v, want ErrNotFound", err)
	}
	err = write(t, s, func(tx store.Tx) error {
		return tx.RefreshTokens().Extend(ctx, "other", "t1", later)
	})
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Extend in another realm = %v, want ErrNotFound", err)
	}
}

func testRefreshRotateConcurrent(t *testing.T, s store.Store) {
	ctx := context.Background()
	insertRefresh(t, s, newRefresh("t1", "tok1", "sess-1"))
	const workers = 20
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		winners  []string
		observed int
		others   []error
	)
	start := make(chan struct{})
	for i := range workers {
		succ := store.RefreshTokenID("succ-" + string(rune('a'+i)))
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			err := s.Write(ctx, func(tx store.Tx) error { return tx.RefreshTokens().MarkReplaced(ctx, "t1", succ) })
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				winners = append(winners, string(succ))
			case errors.Is(err, store.ErrConflict):
				observed++
			default:
				others = append(others, err)
			}
		}()
	}
	close(start)
	wg.Wait()
	if len(winners) != 1 || observed != workers-1 || len(others) != 0 {
		t.Fatalf("winners=%v observed=%d other errors=%v, want one winner and %d observers", winners, observed, others, workers-1)
	}
	got, err := findRefresh(t, s, "r1", "tok1")
	if err != nil || string(got.ReplacedBy) != winners[0] {
		t.Fatalf("ReplacedBy = %q, %v, want the winner %q", got.ReplacedBy, err, winners[0])
	}
}

func testRefreshRevokeSession(t *testing.T, s store.Store) {
	other := newRefresh("o1", "tokO", "sess-2")
	otherRealm := newRefresh("x1", "tokX", "sess-1")
	otherRealm.RealmID = "r2"
	insertRefresh(t, s, newRefresh("t1", "tok1", "sess-1"), newRefresh("t2", "tok2", "sess-1"), other, otherRealm)
	t0 := epoch.Add(time.Minute)
	// RevokeSession reports how many tokens it ended: the two of the session.
	if n := revokeSession(t, s, "r1", "sess-1", t0).Tokens; n != 2 {
		t.Fatalf("RevokeSession ended %d tokens, want 2", n)
	}
	for _, tok := range []string{"tok1", "tok2"} {
		got, err := findRefresh(t, s, "r1", tok)
		if err != nil || !got.RevokedAt.Equal(t0) {
			t.Fatalf("%s: RevokedAt = %v, %v, want %v", tok, got.RevokedAt, err, t0)
		}
	}
	for _, c := range []struct {
		realm store.RealmID
		tok   string
	}{{"r1", "tokO"}, {"r2", "tokX"}} {
		got, err := findRefresh(t, s, c.realm, c.tok)
		if err != nil || !got.RevokedAt.IsZero() {
			t.Fatalf("%s must stay active: %v, %v", c.tok, got.RevokedAt, err)
		}
	}
	// Revoking again keeps the first revocation time, is not an error and
	// ends nothing.
	if n := revokeSession(t, s, "r1", "sess-1", t0.Add(time.Hour)).Tokens; n != 0 {
		t.Fatalf("second RevokeSession ended %d tokens, want 0", n)
	}
	if got, _ := findRefresh(t, s, "r1", "tok1"); !got.RevokedAt.Equal(t0) {
		t.Fatalf("second revoke changed RevokedAt to %v", got.RevokedAt)
	}
	// An unknown session is not an error and ends nothing.
	if n := revokeSession(t, s, "r1", "none", t0).Tokens; n != 0 {
		t.Fatalf("RevokeSession of an unknown session ended %d tokens, want 0", n)
	}
	// An expired token that is not revoked yet is ended too.
	expired := newRefresh("t3", "tok3", "sess-3")
	expired.ExpiresAt = epoch.Add(-time.Hour)
	insertRefresh(t, s, expired)
	if n := revokeSession(t, s, "r1", "sess-3", t0).Tokens; n != 1 {
		t.Fatalf("RevokeSession ended %d tokens of an expired session, want 1", n)
	}
}

// revokeSession runs RefreshTokens.RevokeSession in its own write transaction
// and returns what it ended.
func revokeSession(t *testing.T, s store.Store, realm store.RealmID, sess store.SessionID, now time.Time) store.Ended {
	t.Helper()
	var n store.Ended
	mustWrite(t, s, func(tx store.Tx) error {
		var err error
		n, err = tx.RefreshTokens().RevokeSession(context.Background(), realm, sess, now)
		return err
	})
	return n
}

// testRefreshSessionLive: a session is live while one of its refresh tokens
// is not revoked; the lookup is scoped to the realm.
func testRefreshSessionLive(t *testing.T, s store.Store) {
	ctx := context.Background()
	otherRealm := newRefresh("x1", "tokX", "sess-4")
	otherRealm.RealmID = "r2"
	insertRefresh(t, s, newRefresh("t1", "tok1", "sess-1"), newRefresh("t2", "tok2", "sess-2"), otherRealm)
	revokeSession(t, s, "r1", "sess-2", epoch)
	live := func(realm store.RealmID, session store.SessionID) bool {
		t.Helper()
		var ok bool
		err := s.Read(ctx, func(tx store.Tx) (err error) {
			ok, err = tx.RefreshTokens().SessionLive(ctx, realm, session)
			return err
		})
		if err != nil {
			t.Fatalf("SessionLive(%s, %s): %v", realm, session, err)
		}
		return ok
	}
	for _, c := range []struct {
		name    string
		realm   store.RealmID
		session store.SessionID
		want    bool
	}{
		{"an unrevoked session", "r1", "sess-1", true},
		{"a revoked session", "r1", "sess-2", false},
		{"an unknown session", "r1", "none", false},
		{"another realm's session", "r1", "sess-4", false},
		{"the session in its own realm", "r2", "sess-4", true},
	} {
		if got := live(c.realm, c.session); got != c.want {
			t.Errorf("%s: SessionLive = %v, want %v", c.name, got, c.want)
		}
	}
}

// testRefreshLiveSessions: a session is listed while one of its refresh tokens
// is neither revoked nor expired at the query time (a token that expires at
// exactly that time is not). Each session is described by its newest such
// token, the listing is scoped to the realm and the user, and it is ordered by
// the start of the session, then by id.
func testRefreshLiveSessions(t *testing.T, s store.Store) {
	ctx := context.Background()
	now := epoch.Add(time.Minute)
	at := func(d time.Duration) time.Time { return epoch.Add(d) }
	row := func(id, token, session string, user store.UserID, fn func(*store.RefreshToken)) store.RefreshToken {
		r := newRefresh(id, token, session)
		r.UserID = user
		fn(&r)
		return r
	}
	insertRefresh(t, s,
		// sess-old: rotated once; its successor is the live token.
		row("o1", "tokO1", "sess-old", "u1", func(r *store.RefreshToken) { r.RevokedAt = at(30 * time.Second) }),
		row("o2", "tokO2", "sess-old", "u1", func(r *store.RefreshToken) {
			r.CreatedAt, r.ExpiresAt = at(30*time.Second), at(2*time.Hour)
		}),
		row("e1", "tokE1", "sess-early", "u1", func(r *store.RefreshToken) {
			r.SessionStartedAt, r.ClientID, r.CreatedAt = at(-time.Hour), "web", at(-5*time.Minute)
		}),
		// sess-mixed: the newest token is expired, so the newest active one counts.
		row("m1", "tokM1", "sess-mixed", "u1", func(r *store.RefreshToken) {
			r.SessionStartedAt, r.CreatedAt = at(-2*time.Hour), at(-20*time.Minute)
		}),
		row("m2", "tokM2", "sess-mixed", "u1", func(r *store.RefreshToken) {
			r.SessionStartedAt, r.CreatedAt, r.ExpiresAt = at(-2*time.Hour), at(10*time.Second), now.Add(-time.Second)
		}),
		row("x1", "tokX1", "sess-expired", "u1", func(r *store.RefreshToken) { r.ExpiresAt = now.Add(-time.Second) }),
		row("x2", "tokX2", "sess-edge", "u1", func(r *store.RefreshToken) { r.ExpiresAt = now }),
		row("x3", "tokX3", "sess-revoked", "u1", func(r *store.RefreshToken) { r.RevokedAt = at(20 * time.Second) }),
		row("x4", "tokX4", "sess-other", "u2", func(r *store.RefreshToken) {}),
		row("x5", "tokX5", "sess-r2", "u1", func(r *store.RefreshToken) { r.RealmID = "r2" }),
	)
	type want struct {
		id, client          string
		started, authTime   time.Time
		lastUsed, expiresAt time.Time
	}
	check := func(realm store.RealmID, user store.UserID, fetch func(tx store.Tx) ([]store.LiveSession, error), wants []want) {
		t.Helper()
		var got []store.LiveSession
		err := s.Read(ctx, func(tx store.Tx) (err error) {
			got, err = fetch(tx)
			return err
		})
		if err != nil {
			t.Fatalf("live sessions of %s/%s: %v", realm, user, err)
		}
		if len(got) != len(wants) {
			t.Fatalf("live sessions of %s/%s: got %d, want %d (%+v)", realm, user, len(got), len(wants), got)
		}
		for i, w := range wants {
			g := got[i]
			if string(g.SessionID) != w.id || string(g.ClientID) != w.client || !g.StartedAt.Equal(w.started) ||
				!g.AuthTime.Equal(w.authTime) || !g.LastUsedAt.Equal(w.lastUsed) || !g.ExpiresAt.Equal(w.expiresAt) {
				t.Errorf("session %d of %s/%s = %+v, want %+v", i, realm, user, g, w)
			}
		}
	}
	authTime := epoch.Add(-time.Minute)
	check("r1", "u1", func(tx store.Tx) ([]store.LiveSession, error) {
		return tx.RefreshTokens().UserLiveSessions(ctx, "r1", "u1", now)
	}, []want{
		{"sess-mixed", "app", at(-2 * time.Hour), authTime, at(-20 * time.Minute), at(time.Hour)},
		{"sess-early", "web", at(-time.Hour), authTime, at(-5 * time.Minute), at(time.Hour)},
		{"sess-old", "app", epoch, authTime, at(30 * time.Second), at(2 * time.Hour)},
	})
	check("r1", "u2", func(tx store.Tx) ([]store.LiveSession, error) {
		return tx.RefreshTokens().UserLiveSessions(ctx, "r1", "u2", now)
	}, []want{
		{"sess-other", "app", epoch, authTime, epoch, at(time.Hour)},
	})
	check("r1", "", func(tx store.Tx) ([]store.LiveSession, error) {
		return tx.RefreshTokens().RealmLiveSessions(ctx, "r1", now)
	}, []want{
		{"sess-mixed", "app", at(-2 * time.Hour), authTime, at(-20 * time.Minute), at(time.Hour)},
		{"sess-early", "web", at(-time.Hour), authTime, at(-5 * time.Minute), at(time.Hour)},
		{"sess-old", "app", epoch, authTime, at(30 * time.Second), at(2 * time.Hour)},
		{"sess-other", "app", epoch, authTime, epoch, at(time.Hour)},
	})
	check("r2", "", func(tx store.Tx) ([]store.LiveSession, error) {
		return tx.RefreshTokens().RealmLiveSessions(ctx, "r2", now)
	}, []want{
		{"sess-r2", "app", epoch, authTime, epoch, at(time.Hour)},
	})
	// Nothing is active after the last expiry.
	check("r1", "u1", func(tx store.Tx) ([]store.LiveSession, error) {
		return tx.RefreshTokens().UserLiveSessions(ctx, "r1", "u1", at(2*time.Hour))
	}, nil)
}

// testRefreshHasSession: a session belongs to a user whatever its state; the
// lookup is scoped to the realm and to the user.
func testRefreshHasSession(t *testing.T, s store.Store) {
	ctx := context.Background()
	other := newRefresh("x1", "tokX", "sess-other")
	other.UserID = "u2"
	r2 := newRefresh("x2", "tokR", "sess-r2")
	r2.RealmID = "r2"
	revoked := newRefresh("x3", "tokV", "sess-revoked")
	insertRefresh(t, s, newRefresh("t1", "tok1", "sess-1"), other, r2, revoked)
	revokeSession(t, s, "r1", "sess-revoked", epoch)
	has := func(realm store.RealmID, user store.UserID, session store.SessionID) bool {
		t.Helper()
		var ok bool
		err := s.Read(ctx, func(tx store.Tx) (err error) {
			ok, err = tx.RefreshTokens().HasSession(ctx, realm, user, session)
			return err
		})
		if err != nil {
			t.Fatalf("HasSession(%s, %s, %s): %v", realm, user, session, err)
		}
		return ok
	}
	for _, c := range []struct {
		name    string
		realm   store.RealmID
		user    store.UserID
		session store.SessionID
		want    bool
	}{
		{"an active session of the user", "r1", "u1", "sess-1", true},
		{"a revoked session of the user", "r1", "u1", "sess-revoked", true},
		{"a session of another user", "r1", "u1", "sess-other", false},
		{"a session of the user in another realm", "r1", "u1", "sess-r2", false},
		{"the session in its own realm", "r2", "u1", "sess-r2", true},
		{"an unknown session", "r1", "u1", "none", false},
	} {
		if got := has(c.realm, c.user, c.session); got != c.want {
			t.Errorf("%s: HasSession = %v, want %v", c.name, got, c.want)
		}
	}
}

func testRefreshRevokeOthers(t *testing.T, s store.Store) {
	ctx := context.Background()
	insertRefresh(t, s, newRefresh("t1", "tok1", "sess-1"), newRefresh("t2", "tok2", "sess-1"),
		newRefresh("t3", "tok3", "sess-1"), newRefresh("o1", "tokO", "sess-2"))
	t0 := epoch.Add(time.Minute)
	mustWrite(t, s, func(tx store.Tx) error { return tx.RefreshTokens().RevokeOthers(ctx, "r1", "sess-1", "t2", t0) })
	for tok, revoked := range map[string]bool{"tok1": true, "tok2": false, "tok3": true, "tokO": false} {
		got, err := findRefresh(t, s, "r1", tok)
		if err != nil || got.RevokedAt.IsZero() == revoked {
			t.Fatalf("%s: RevokedAt = %v, %v, want revoked=%v", tok, got.RevokedAt, err, revoked)
		}
	}
	// A second revoke keeps the first revoked_at of the rows already revoked.
	t1 := t0.Add(time.Minute)
	mustWrite(t, s, func(tx store.Tx) error { return tx.RefreshTokens().RevokeOthers(ctx, "r1", "sess-1", "t3", t1) })
	for tok, want := range map[string]time.Time{"tok1": t0, "tok2": t1, "tok3": t0} {
		got, err := findRefresh(t, s, "r1", tok)
		if err != nil || !got.RevokedAt.Equal(want) {
			t.Fatalf("%s: RevokedAt = %v, %v, want %v", tok, got.RevokedAt, err, want)
		}
	}
}

func testRefreshRevokeUser(t *testing.T, s store.Store) {
	ctx := context.Background()
	mine1 := newRefresh("t1", "tok1", "sess-1")
	mine2 := newRefresh("t2", "tok2", "sess-2")
	notMine := newRefresh("t3", "tok3", "sess-3")
	notMine.UserID = "u2"
	otherRealm := newRefresh("t4", "tok4", "sess-4")
	otherRealm.RealmID = "r2"
	insertRefresh(t, s, mine1, mine2, notMine, otherRealm)
	t0 := epoch.Add(time.Minute)
	mustWrite(t, s, func(tx store.Tx) error { _, err := tx.RefreshTokens().RevokeUser(ctx, "r1", "u1", t0); return err })
	for tok, revoked := range map[string]bool{"tok1": true, "tok2": true, "tok3": false} {
		got, err := findRefresh(t, s, "r1", tok)
		if err != nil || !got.RevokedAt.Equal(t0) != !revoked {
			t.Fatalf("%s: RevokedAt = %v, %v, want revoked=%v", tok, got.RevokedAt, err, revoked)
		}
	}
	if got, _ := findRefresh(t, s, "r2", "tok4"); !got.RevokedAt.IsZero() {
		t.Fatalf("a user of another realm with the same id was revoked")
	}
	// A repeated call keeps the first revoked_at.
	t1 := t0.Add(time.Minute)
	mustWrite(t, s, func(tx store.Tx) error { _, err := tx.RefreshTokens().RevokeUser(ctx, "r1", "u1", t1); return err })
	for _, tok := range []string{"tok1", "tok2"} {
		if got, err := findRefresh(t, s, "r1", tok); err != nil || !got.RevokedAt.Equal(t0) {
			t.Fatalf("%s: RevokedAt = %v, %v, want %v kept", tok, got.RevokedAt, err, t0)
		}
	}
}

func testRefreshDeleteUser(t *testing.T, s store.Store) {
	ctx := context.Background()
	mine1 := newRefresh("t1", "tok1", "sess-1")
	mine2 := newRefresh("t2", "tok2", "sess-2")
	notMine := newRefresh("t3", "tok3", "sess-3")
	notMine.UserID = "u2"
	otherRealm := newRefresh("t4", "tok4", "sess-4")
	otherRealm.RealmID = "r2"
	insertRefresh(t, s, mine1, mine2, notMine, otherRealm)
	mustWrite(t, s, func(tx store.Tx) error { _, err := tx.RefreshTokens().DeleteUser(ctx, "r1", "u1"); return err })
	for tok, gone := range map[string]bool{"tok1": true, "tok2": true, "tok3": false} {
		_, err := findRefresh(t, s, "r1", tok)
		if gone != errors.Is(err, store.ErrNotFound) {
			t.Fatalf("%s: err = %v, want gone=%v", tok, err, gone)
		}
	}
	if _, err := findRefresh(t, s, "r2", "tok4"); err != nil {
		t.Fatalf("a user of another realm with the same id lost a token: %v", err)
	}
	// Nothing to delete is not an error.
	mustWrite(t, s, func(tx store.Tx) error { _, err := tx.RefreshTokens().DeleteUser(ctx, "r1", "u1"); return err })
}

func testRefreshDeleteExpired(t *testing.T, s store.Store) {
	ctx := context.Background()
	live := newRefresh("t1", "tok1", "sess-1")
	edge := newRefresh("t2", "tok2", "sess-1")
	edge.ExpiresAt = epoch.Add(time.Minute)
	old := newRefresh("t3", "tok3", "sess-1")
	old.ExpiresAt = epoch.Add(time.Second)
	insertRefresh(t, s, live, edge, old)
	var n int64
	mustWrite(t, s, func(tx store.Tx) (err error) {
		n, err = tx.RefreshTokens().DeleteExpired(ctx, epoch.Add(time.Minute))
		return err
	})
	if n != 2 {
		t.Fatalf("DeleteExpired = %d, want 2", n)
	}
	if _, err := findRefresh(t, s, "r1", "tok1"); err != nil {
		t.Fatalf("live token removed: %v", err)
	}
	for _, tok := range []string{"tok2", "tok3"} {
		if _, err := findRefresh(t, s, "r1", tok); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("%s = %v, want ErrNotFound", tok, err)
		}
	}
}

func deleteExpired(t *testing.T, s store.Store, del func(store.Tx) (int64, error)) int64 {
	t.Helper()
	var n int64
	mustWrite(t, s, func(tx store.Tx) (err error) {
		n, err = del(tx)
		return err
	})
	return n
}

func testAuthRequestsDeleteExpired(t *testing.T, s store.Store) {
	ctx := context.Background()
	now := epoch.Add(time.Hour)
	live, edge, old := newAuthRequest("live"), newAuthRequest("edge"), newAuthRequest("old")
	live.ExpiresAt, edge.ExpiresAt, old.ExpiresAt = now.Add(time.Second), now, now.Add(-time.Second)
	for _, r := range []store.AuthRequest{live, edge, old} {
		mustWrite(t, s, func(tx store.Tx) error { return tx.AuthRequests().Create(ctx, r) })
	}
	if n := deleteExpired(t, s, func(tx store.Tx) (int64, error) { return tx.AuthRequests().DeleteExpired(ctx, now) }); n != 2 {
		t.Fatalf("DeleteExpired = %d, want 2", n)
	}
	for id, want := range map[store.AuthRequestID]error{"live": nil, "edge": store.ErrNotFound, "old": store.ErrNotFound} {
		err := s.Read(ctx, func(tx store.Tx) error { _, err := tx.AuthRequests().Get(ctx, id); return err })
		if !errors.Is(err, want) {
			t.Fatalf("Get(%s) = %v, want %v", id, err, want)
		}
	}
}

func testAuthCodesDeleteExpired(t *testing.T, s store.Store) {
	ctx := context.Background()
	now := epoch.Add(time.Hour)
	live, edge, old := newAuthCode("live"), newAuthCode("edge"), newAuthCode("old")
	live.ExpiresAt, edge.ExpiresAt, old.ExpiresAt = now.Add(time.Second), now, now.Add(-time.Second)
	for _, c := range []store.AuthCode{live, edge, old} {
		mustWrite(t, s, func(tx store.Tx) error { return tx.AuthCodes().Create(ctx, c) })
	}
	if n := deleteExpired(t, s, func(tx store.Tx) (int64, error) { return tx.AuthCodes().DeleteExpired(ctx, now) }); n != 2 {
		t.Fatalf("DeleteExpired = %d, want 2", n)
	}
	// An unused live code is still there: consuming it works. The others are gone.
	for code, want := range map[string]error{"live": nil, "edge": store.ErrNotFound, "old": store.ErrNotFound} {
		_, err := consume(t, s, code, now.Add(-time.Hour))
		if !errors.Is(err, want) {
			t.Fatalf("Consume(%s) = %v, want %v", code, err, want)
		}
	}
}

func testHandoffsDeleteExpired(t *testing.T, s store.Store) {
	ctx := context.Background()
	now := epoch.Add(time.Hour)
	for name, exp := range map[string]time.Time{"live": now.Add(time.Second), "edge": now, "old": now.Add(-time.Second)} {
		h := store.Handoff{IDHash: secure.HashOf(name), AuthRequestID: store.AuthRequestID(name), Payload: "p", ExpiresAt: exp}
		mustWrite(t, s, func(tx store.Tx) error { return tx.Handoffs().Create(ctx, h) })
	}
	if n := deleteExpired(t, s, func(tx store.Tx) (int64, error) { return tx.Handoffs().DeleteExpired(ctx, now) }); n != 2 {
		t.Fatalf("DeleteExpired = %d, want 2", n)
	}
	for name, want := range map[string]error{"live": nil, "edge": store.ErrNotFound, "old": store.ErrNotFound} {
		err := s.Write(ctx, func(tx store.Tx) error {
			_, err := tx.Handoffs().Take(ctx, secure.HashOf(name), now.Add(-time.Hour))
			return err
		})
		if !errors.Is(err, want) {
			t.Fatalf("Take(%s) = %v, want %v", name, err, want)
		}
	}
}

// rememberEvent calls Remember in its own write transaction.
func rememberEvent(t *testing.T, s store.Store, realm store.RealmID, prov config.ProviderKey, id string, exp time.Time) bool {
	t.Helper()
	var first bool
	mustWrite(t, s, func(tx store.Tx) (err error) {
		first, err = tx.ProviderEvents().Remember(context.Background(), realm, prov, secure.HashOf(id), exp)
		return err
	})
	return first
}

// Covers: FR-44 (part)
// Acceptance: DPoP binding (part)
// testRefreshDPoPJKT: a refresh token keeps the key thumbprint its session is
// bound to, and an unbound one reads back as empty.
func testRefreshDPoPJKT(t *testing.T, s store.Store) {
	bound := newRefresh("t-bound", "tok-bound", "s-1")
	bound.DPoPJKT = "thumb-1"
	insertRefresh(t, s, bound, newRefresh("t-plain", "tok-plain", "s-2"))
	for tok, want := range map[string]string{"tok-bound": "thumb-1", "tok-plain": ""} {
		got, err := findRefresh(t, s, "r1", tok)
		if err != nil {
			t.Fatal(err)
		}
		if got.DPoPJKT != want {
			t.Fatalf("DPoPJKT of %s = %q, want %q", tok, got.DPoPJKT, want)
		}
	}
}

// Covers: SEC-36 (part)
// Acceptance: DPoP proof (part)
// testDPoPProofsUse: the first Use of a hash reports true and a repeat false; a
// hash of another key or jti is new; a write that fails after Use leaves the
// hash unused.
func testDPoPProofsUse(t *testing.T, s store.Store) {
	ctx := context.Background()
	exp := epoch.Add(time.Hour)
	for _, c := range []struct {
		name string
		hash string
		want bool
	}{
		{"new proof", "proof-1", true},
		{"repeat", "proof-1", false},
		{"another proof", "proof-2", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			var first bool
			mustWrite(t, s, func(tx store.Tx) (err error) {
				first, err = tx.DPoPProofs().Use(ctx, secure.HashOf(c.hash), exp)
				return err
			})
			if first != c.want {
				t.Fatalf("Use = %v, want %v", first, c.want)
			}
		})
	}
	err := write(t, s, func(tx store.Tx) error {
		if _, err := tx.DPoPProofs().Use(ctx, secure.HashOf("proof-3"), exp); err != nil {
			return err
		}
		return errors.New("the action failed")
	})
	if err == nil {
		t.Fatal("the failing write returned no error")
	}
	var first bool
	mustWrite(t, s, func(tx store.Tx) (err error) {
		first, err = tx.DPoPProofs().Use(ctx, secure.HashOf("proof-3"), exp)
		return err
	})
	if !first {
		t.Fatal("a hash of a rolled back write is remembered")
	}
}

// Covers: SEC-36 (part)
// Acceptance: DPoP proof (part)
// testDPoPProofsDeleteExpired: a proof stays remembered after its expiry until
// DeleteExpired removes it. A proof at exactly its expiry is kept (the job
// deletes only what is strictly past it); the live one stays.
func testDPoPProofsDeleteExpired(t *testing.T, s store.Store) {
	ctx := context.Background()
	now := epoch.Add(time.Hour)
	for name, exp := range map[string]time.Time{"live": now.Add(time.Second), "edge": now, "old": now.Add(-time.Second)} {
		useDPoPProof(t, s, name, exp)
	}
	if useDPoPProof(t, s, "old", now) {
		t.Fatal("an expired proof is not remembered before the job runs")
	}
	if n := deleteExpired(t, s, func(tx store.Tx) (int64, error) { return tx.DPoPProofs().DeleteExpired(ctx, now) }); n != 1 {
		t.Fatalf("DeleteExpired = %d, want 1", n)
	}
	if useDPoPProof(t, s, "live", now) {
		t.Fatal("the live proof was deleted")
	}
	if useDPoPProof(t, s, "edge", now) {
		t.Fatal("the proof at its expiry was deleted")
	}
	if !useDPoPProof(t, s, "old", now.Add(time.Hour)) {
		t.Fatal("the proof past its expiry is still remembered after the job")
	}
}

// Covers: FR-53 (part)
// testRateLimitsHit: one request counts once in its key and window, the
// statement returns the count of that window, and keys and windows count apart.
func testRateLimitsHit(t *testing.T, s store.Store) {
	ctx := context.Background()
	w1 := epoch.Truncate(time.Minute)
	w2 := w1.Add(time.Minute)
	hit := func(key string, w time.Time) int64 {
		t.Helper()
		var n int64
		mustWrite(t, s, func(tx store.Tx) (err error) {
			n, err = tx.RateLimits().Hit(ctx, key, w)
			return err
		})
		return n
	}
	for want := int64(1); want <= 3; want++ {
		if got := hit("203.0.113.7", w1); got != want {
			t.Fatalf("hit %d of a key in one minute counted %d", want, got)
		}
	}
	if got := hit("203.0.113.8", w1); got != 1 {
		t.Errorf("another key counted %d, want 1", got)
	}
	if got := hit("203.0.113.7", w2); got != 1 {
		t.Errorf("the next minute counted %d, want 1", got)
	}
}

// Covers: FR-53 (part)
// testRateLimitsDeleteBefore: the windows that start before the given minute
// are deleted and counted; the current window keeps its count.
func testRateLimitsDeleteBefore(t *testing.T, s store.Store) {
	ctx := context.Background()
	w0 := epoch.Truncate(time.Minute)
	w1, w2 := w0.Add(time.Minute), w0.Add(2*time.Minute)
	for key, w := range map[string]time.Time{"old": w0, "current": w1, "next": w2} {
		mustWrite(t, s, func(tx store.Tx) error {
			_, err := tx.RateLimits().Hit(ctx, key, w)
			return err
		})
	}
	var n int64
	mustWrite(t, s, func(tx store.Tx) (err error) {
		n, err = tx.RateLimits().DeleteBefore(ctx, w1)
		return err
	})
	if n != 1 {
		t.Fatalf("DeleteBefore removed %d windows, want 1", n)
	}
	var kept int64
	mustWrite(t, s, func(tx store.Tx) (err error) {
		kept, err = tx.RateLimits().Hit(ctx, "current", w1)
		return err
	})
	if kept != 2 {
		t.Errorf("the current window counts %d after the job, want 2", kept)
	}
	var fresh int64
	mustWrite(t, s, func(tx store.Tx) (err error) {
		fresh, err = tx.RateLimits().Hit(ctx, "old", w0)
		return err
	})
	if fresh != 1 {
		t.Errorf("a deleted window counts %d again, want 1", fresh)
	}
}

// useDPoPProof calls Use for the hash of id and reports whether it was new.
func useDPoPProof(t *testing.T, s store.Store, id string, exp time.Time) bool {
	t.Helper()
	var first bool
	mustWrite(t, s, func(tx store.Tx) (err error) {
		first, err = tx.DPoPProofs().Use(context.Background(), secure.HashOf(id), exp)
		return err
	})
	return first
}

// testProviderEventsRemember: the first Remember of an id reports true and a
// repeat false, for the same realm and provider only; a write that fails after
// Remember leaves nothing remembered.
func testProviderEventsRemember(t *testing.T, s store.Store) {
	ctx := context.Background()
	exp := epoch.Add(time.Hour)
	for _, c := range []struct {
		name  string
		realm store.RealmID
		prov  config.ProviderKey
		id    string
		want  bool
	}{
		{"new id", "r1", "apple", "jti-1", true},
		{"repeat", "r1", "apple", "jti-1", false},
		{"another id", "r1", "apple", "jti-2", true},
		{"another provider", "r1", "google", "jti-1", true},
		{"another realm", "r2", "apple", "jti-1", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := rememberEvent(t, s, c.realm, c.prov, c.id, exp); got != c.want {
				t.Fatalf("Remember = %v, want %v", got, c.want)
			}
		})
	}
	err := write(t, s, func(tx store.Tx) error {
		if _, err := tx.ProviderEvents().Remember(ctx, "r1", "apple", secure.HashOf("jti-3"), exp); err != nil {
			return err
		}
		return errors.New("the action failed")
	})
	if err == nil {
		t.Fatal("the failing write returned no error")
	}
	if !rememberEvent(t, s, "r1", "apple", "jti-3", exp) {
		t.Fatal("an id of a rolled back write is remembered")
	}
}

// testProviderEventsDeleteExpired: an id stays remembered after its expiry until
// DeleteExpired removes it. An id at exactly its expiry is kept (the job deletes
// only what is strictly past it), so an event still accepted at that instant is
// recognised as a repeat; the live one stays.
func testProviderEventsDeleteExpired(t *testing.T, s store.Store) {
	ctx := context.Background()
	now := epoch.Add(time.Hour)
	for name, exp := range map[string]time.Time{"live": now.Add(time.Second), "edge": now, "old": now.Add(-time.Second)} {
		rememberEvent(t, s, "r1", "apple", name, exp)
	}
	if rememberEvent(t, s, "r1", "apple", "old", now) {
		t.Fatal("an expired id is not remembered before the job runs")
	}
	if n := deleteExpired(t, s, func(tx store.Tx) (int64, error) { return tx.ProviderEvents().DeleteExpired(ctx, now) }); n != 1 {
		t.Fatalf("DeleteExpired = %d, want 1", n)
	}
	if rememberEvent(t, s, "r1", "apple", "live", now) {
		t.Fatal("the live id was deleted")
	}
	if rememberEvent(t, s, "r1", "apple", "edge", now) {
		t.Fatal("the id at its expiry was deleted")
	}
	if !rememberEvent(t, s, "r1", "apple", "old", now.Add(time.Hour)) {
		t.Fatal("the id past its expiry is still remembered after the job")
	}
}

// testProviderEventsRememberConcurrent: two writers that remember the same
// payload at once get one first and one repeat (a repeat is not an error).
func testProviderEventsRememberConcurrent(t *testing.T, s store.Store) {
	ctx := context.Background()
	const workers = 20
	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		first int
		other []error
	)
	start := make(chan struct{})
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			var got bool
			err := s.Write(ctx, func(tx store.Tx) (err error) {
				got, err = tx.ProviderEvents().Remember(ctx, "r1", "apple", secure.HashOf("same-payload"), epoch.Add(time.Hour))
				return err
			})
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err != nil:
				other = append(other, err)
			case got:
				first++
			}
		}()
	}
	close(start)
	wg.Wait()
	if first != 1 || len(other) != 0 {
		t.Fatalf("first=%d errors=%v, want exactly one first and no errors", first, other)
	}
}

func newAudit(id string, realm store.RealmID, at time.Time) store.AuditEvent {
	return store.AuditEvent{
		ID: id, RealmID: realm, Actor: "admin", Action: "user.disable", UserID: "u1",
		Details: map[string]any{"reason": "test"}, CreatedAt: at,
	}
}

func listAudit(t *testing.T, s store.Store, realm store.RealmID, since time.Time) []store.AuditEvent {
	t.Helper()
	var got []store.AuditEvent
	mustRead(t, s, func(tx store.Tx) (err error) {
		got, err = tx.Audit().List(context.Background(), realm, since)
		return err
	})
	return got
}

func testAuditInsertList(t *testing.T, s store.Store) {
	ctx := context.Background()
	b := newAudit("b", "r1", epoch.Add(time.Minute))
	a := newAudit("a", "r1", epoch)
	c := newAudit("c", "r1", epoch.Add(time.Minute)) // same second as b: ordered by id
	other := newAudit("d", "r2", epoch)
	noUser := newAudit("e", "r1", epoch.Add(2*time.Minute))
	noUser.UserID, noUser.Details = "", nil
	for _, e := range []store.AuditEvent{b, a, c, other, noUser} {
		mustWrite(t, s, func(tx store.Tx) error { return tx.Audit().Insert(ctx, e) })
	}
	if err := write(t, s, func(tx store.Tx) error { return tx.Audit().Insert(ctx, a) }); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate Insert = %v, want ErrConflict", err)
	}

	var ids []string
	for _, e := range listAudit(t, s, "r1", epoch) {
		ids = append(ids, e.ID)
	}
	if want := []string{"a", "b", "c", "e"}; !equalStrings(ids, want) {
		t.Fatalf("List = %v, want %v (oldest first, this realm only)", ids, want)
	}
	// since is inclusive.
	ids = nil
	for _, e := range listAudit(t, s, "r1", epoch.Add(time.Minute)) {
		ids = append(ids, e.ID)
	}
	if want := []string{"b", "c", "e"}; !equalStrings(ids, want) {
		t.Fatalf("List since = %v, want %v", ids, want)
	}
	got := listAudit(t, s, "r1", epoch)[0]
	if got.ID != "a" || got.RealmID != "r1" || got.Actor != "admin" || got.Action != "user.disable" ||
		got.UserID != "u1" || !got.CreatedAt.Equal(epoch) || got.CreatedAt.Location() != time.UTC {
		t.Fatalf("List[0] = %+v", got)
	}
	last := listAudit(t, s, "r1", epoch)[3]
	if last.UserID != "" || len(last.Details) != 0 {
		t.Fatalf("event without user or details = %+v", last)
	}
	if got := listAudit(t, s, "none", epoch); len(got) != 0 {
		t.Fatalf("unknown realm = %v", got)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func testAuditDetails(t *testing.T, s store.Store) {
	e := newAudit("a", "r1", epoch)
	e.Details = map[string]any{"provider": "google", "linked": true, "count": float64(2),
		"nested": map[string]any{"k": "v"}}
	mustWrite(t, s, func(tx store.Tx) error { return tx.Audit().Insert(context.Background(), e) })
	got := listAudit(t, s, "r1", epoch)[0].Details
	nested, _ := got["nested"].(map[string]any)
	if got["provider"] != "google" || got["linked"] != true || got["count"] != float64(2) || nested["k"] != "v" {
		t.Fatalf("details = %v", got)
	}
}

// testVerifiedEmailRace makes 20 logins with one verified email at once, in
// five rounds with a new email each round: the first round opens the pool's
// connections, so the later rounds overlap more. Each login looks for the
// verified holder first, as a login does, and creates its user verified only
// when there is none. Every login succeeds; exactly one user holds the email.
func testVerifiedEmailRace(t *testing.T, s store.Store) {
	ctx := context.Background()
	ensure(t, s, "r1", "realm-1")
	const workers = 20
	for round := range 5 {
		email := fmt.Sprintf("ann%d@example.com", round)
		var (
			wg   sync.WaitGroup
			mu   sync.Mutex
			errs []error
		)
		start := make(chan struct{})
		for i := range workers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				err := write(t, s, func(tx store.Tx) error {
					_, err := tx.Users().FindVerifiedByEmailKey(ctx, "realm-1", email)
					verified := errors.Is(err, store.ErrNotFound)
					if err != nil && !verified {
						return err
					}
					return tx.Users().Create(ctx, newUser("realm-1", fmt.Sprintf("u-%d-%d", round, i), email, verified))
				})
				mu.Lock()
				defer mu.Unlock()
				if err != nil {
					errs = append(errs, err)
				}
			}()
		}
		close(start)
		wg.Wait()
		if len(errs) != 0 {
			t.Fatalf("round %d: logins that failed: %v", round, errs)
		}
		var users []store.User
		mustRead(t, s, func(tx store.Tx) error {
			var err error
			users, err = tx.Users().ListByEmailKey(ctx, "realm-1", email)
			return err
		})
		verified := 0
		for _, u := range users {
			if u.EmailVerified {
				verified++
			}
		}
		if len(users) != workers || verified != 1 {
			t.Fatalf("round %d: %d users with the email, %d verified; want %d and 1", round, len(users), verified, workers)
		}
	}
}

// realmRun is a write that names a realm after the run that makes it, so a test
// can tell which run's row is left: the id is "run-<n>".
func realmRun(ctx context.Context, tx store.Tx, runs *int) error {
	*runs++
	_, err := tx.Realms().Ensure(ctx, "forced", store.RealmID("run-"+strconv.Itoa(*runs)), epoch)
	return err
}

// realmLeft returns the id of the realm "forced", or "" when it has no row.
func realmLeft(t *testing.T, s store.Store) store.RealmID {
	t.Helper()
	var id store.RealmID
	err := s.Read(context.Background(), func(tx store.Tx) error {
		var err error
		id, err = tx.Realms().Find(context.Background(), "forced")
		return err
	})
	if errors.Is(err, store.ErrNotFound) {
		return ""
	}
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// A deadlock once: the second run succeeds and the first run's row is gone.
func testWriteRunsAgain(t *testing.T, s store.Store) {
	f := testutil.NewFaultStore(s)
	f.AbortRuns(1, &pgconn.PgError{Code: "40P01"})
	runs := 0
	if err := f.Write(context.Background(), func(tx store.Tx) error { return realmRun(context.Background(), tx, &runs) }); err != nil {
		t.Fatalf("Write = %v, want success on the second run", err)
	}
	if runs != 2 {
		t.Fatalf("runs = %d, want 2", runs)
	}
	if got := realmLeft(t, s); got != "run-2" {
		t.Fatalf("realm id = %q, want run-2: the first run's row is left", got)
	}
}

// A deadlock three times: the store gives up after the third run with
// ErrUnavailable and keeps no row.
func testWriteGivesUp(t *testing.T, s store.Store) {
	f := testutil.NewFaultStore(s)
	f.AbortRuns(3, &pgconn.PgError{Code: "40P01"})
	runs := 0
	err := f.Write(context.Background(), func(tx store.Tx) error { return realmRun(context.Background(), tx, &runs) })
	if !errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("Write = %v, want ErrUnavailable", err)
	}
	if runs != 3 {
		t.Fatalf("runs = %d, want 3", runs)
	}
	if got := realmLeft(t, s); got != "" {
		t.Fatalf("realm id = %q after three failed runs, want none", got)
	}
}

// A once-only key violated once is run again, and the second run succeeds.
func testWriteRunsAgainOnUnique(t *testing.T, s store.Store) {
	f := testutil.NewFaultStore(s)
	f.AbortRuns(1, &pgconn.PgError{Code: "23505", ConstraintName: "users_verified_email_key"})
	runs := 0
	if err := f.Write(context.Background(), func(tx store.Tx) error { return realmRun(context.Background(), tx, &runs) }); err != nil {
		t.Fatalf("Write = %v, want success on the second run", err)
	}
	if runs != 2 || realmLeft(t, s) != "run-2" {
		t.Fatalf("runs = %d, realm = %q; want 2 and run-2", runs, realmLeft(t, s))
	}
}

// A once-only key violated by the second run too is the conflict, not 503. The
// real path first: a second verified user with the first one's email. Postgres
// runs the function twice and SQLite once (its violation is not retried); both
// end in ErrConflict. The exact count on Postgres is in its own test. Then the
// injected path: a repeated violation is returned as it is after two runs.
func testWriteUniqueRepeated(t *testing.T, s store.Store) {
	ctx := context.Background()
	ensure(t, s, "r-unique", "realm-u")
	createUser(t, s, newUser("realm-u", "uq-1", "bo@example.com", true))
	runs := 0
	err := write(t, s, func(tx store.Tx) error {
		runs++
		return tx.Users().Create(ctx, newUser("realm-u", "uq-2", "bo@example.com", true))
	})
	if !errors.Is(err, store.ErrConflict) || errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("second verified user = %v, want ErrConflict and not ErrUnavailable", err)
	}
	if runs < 1 || runs > 2 {
		t.Fatalf("runs = %d, want 1 or 2", runs)
	}

	f := testutil.NewFaultStore(s)
	abort := &pgconn.PgError{Code: "23505", ConstraintName: "identities_provider_sub"}
	f.AbortRuns(2, abort)
	runs = 0
	err = f.Write(ctx, func(tx store.Tx) error { return realmRun(ctx, tx, &runs) })
	if !errors.Is(err, abort) || errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("Write = %v, want the violation itself, not ErrUnavailable", err)
	}
	if runs != 2 || realmLeft(t, s) != "" {
		t.Fatalf("runs = %d, realm = %q; want 2 and none", runs, realmLeft(t, s))
	}
}

// A unique key that is not once-only is not run again.
func testWriteOtherUniqueNotRun(t *testing.T, s store.Store) {
	f := testutil.NewFaultStore(s)
	abort := &pgconn.PgError{Code: "23505", ConstraintName: "users_pkey"}
	f.AbortRuns(1, abort)
	runs := 0
	err := f.Write(context.Background(), func(tx store.Tx) error { return realmRun(context.Background(), tx, &runs) })
	if !errors.Is(err, abort) {
		t.Fatalf("Write = %v, want the violation", err)
	}
	if runs != 1 {
		t.Fatalf("runs = %d, want 1", runs)
	}
}

// Covers: FR-43 (part)
// Acceptance: Back-channel logout (part)
// The revoking calls report each session they ended, once, with its client and
// user: a session counts when one of its tokens was not revoked before the call,
// expired or not. The token count is kept for the callers that count.
func testRefreshReportEndedSessions(t *testing.T, s store.Store) {
	ctx := context.Background()
	live := newRefresh("t1", "tok1", "sess-1")
	sibling := newRefresh("t2", "tok2", "sess-1")
	done := newRefresh("t3", "tok3", "sess-2")
	other := newRefresh("t4", "tok4", "sess-3")
	other.UserID, other.ClientID = "u2", "frag"
	expired := newRefresh("t5", "tok5", "sess-4")
	expired.ExpiresAt = epoch.Add(-time.Hour)
	insertRefresh(t, s, live, sibling, done, other, expired)
	t0 := epoch.Add(time.Minute)
	// sess-2 ends before the user's revocation, so it is not reported again.
	revokeSession(t, s, "r1", "sess-2", t0)

	var got store.Ended
	mustWrite(t, s, func(tx store.Tx) (err error) {
		got, err = tx.RefreshTokens().RevokeUser(ctx, "r1", "u1", t0)
		return err
	})
	want := []store.EndedSession{
		{SessionID: "sess-1", ClientID: "app", UserID: "u1"},
		{SessionID: "sess-4", ClientID: "app", UserID: "u1"},
	}
	if got.Tokens != 3 || !slices.Equal(sortedSessions(got.Sessions), want) {
		t.Fatalf("RevokeUser = %+v, want 3 tokens and sessions %+v", got, want)
	}
	// Nothing is left to end: no session and no token.
	if again := revokeSession(t, s, "r1", "sess-1", t0); again.Tokens != 0 || len(again.Sessions) != 0 {
		t.Fatalf("second RevokeSession = %+v, want nothing", again)
	}

	var deleted store.Ended
	mustWrite(t, s, func(tx store.Tx) (err error) {
		deleted, err = tx.RefreshTokens().DeleteUser(ctx, "r1", "u2")
		return err
	})
	if deleted.Tokens != 1 || !slices.Equal(deleted.Sessions, []store.EndedSession{{SessionID: "sess-3", ClientID: "frag", UserID: "u2"}}) {
		t.Fatalf("DeleteUser = %+v, want the live session of the user", deleted)
	}
	mustWrite(t, s, func(tx store.Tx) error {
		again, err := tx.RefreshTokens().DeleteUser(ctx, "r1", "u2")
		if err != nil || len(again.Sessions) != 0 {
			t.Errorf("second DeleteUser = %+v, %v, want nothing", again, err)
		}
		return err
	})
}

// sortedSessions returns a copy of the sessions ordered by session id, for the
// comparison of a result that does not promise an order.
func sortedSessions(ss []store.EndedSession) []store.EndedSession {
	out := slices.Clone(ss)
	slices.SortFunc(out, func(a, b store.EndedSession) int { return strings.Compare(string(a.SessionID), string(b.SessionID)) })
	return out
}

// Covers: FR-43 (part)
// Acceptance: Back-channel logout (part)
func testLogoutNotificationsCRUD(t *testing.T, s store.Store) {
	ctx := context.Background()
	a := store.LogoutNotification{ID: "n1", RealmID: "r1", ClientID: "app", UserID: "u1", SessionID: "sess-1", NextAttemptAt: epoch, CreatedAt: epoch}
	b := store.LogoutNotification{ID: "n2", RealmID: "r1", ClientID: "app", UserID: "u1", SessionID: "sess-2", NextAttemptAt: epoch.Add(time.Hour), CreatedAt: epoch}
	mustWrite(t, s, func(tx store.Tx) error {
		if err := tx.LogoutNotifications().Enqueue(ctx, a); err != nil {
			return err
		}
		return tx.LogoutNotifications().Enqueue(ctx, b)
	})
	if err := s.Write(ctx, func(tx store.Tx) error { return tx.LogoutNotifications().Enqueue(ctx, a) }); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("Enqueue of an existing id: %v, want ErrConflict", err)
	}

	claim := func(now time.Time, limit int) []store.LogoutNotification {
		t.Helper()
		var rows []store.LogoutNotification
		mustWrite(t, s, func(tx store.Tx) (err error) {
			rows, err = tx.LogoutNotifications().Claim(ctx, now, limit)
			return err
		})
		return rows
	}
	if rows := claim(epoch.Add(-time.Second), 10); len(rows) != 0 {
		t.Fatalf("a row is due before its time: %+v", rows)
	}
	rows := claim(epoch, 1)
	if len(rows) != 1 || rows[0].ID != "n1" || rows[0].Attempts != 0 || rows[0].ClientID != "app" ||
		rows[0].UserID != "u1" || rows[0].SessionID != "sess-1" || rows[0].RealmID != "r1" || !rows[0].NextAttemptAt.Equal(epoch) {
		t.Fatalf("Claim with limit 1 = %+v", rows)
	}
	if rows := claim(epoch, 10); len(rows) != 0 {
		t.Fatalf("a claimed row is due again at once: %+v", rows)
	}
	// The first try is counted: the next one is a minute later.
	if rows := claim(epoch.Add(time.Minute), 10); len(rows) != 1 || rows[0].ID != "n1" || rows[0].Attempts != 1 {
		t.Fatalf("the second try = %+v, want n1 with 1 attempt", rows)
	}
	mustWrite(t, s, func(tx store.Tx) error { return tx.LogoutNotifications().Done(ctx, "n1") })
	if rows := claim(epoch.Add(2*time.Hour), 10); len(rows) != 1 || rows[0].ID != "n2" || rows[0].Attempts != 0 {
		t.Fatalf("after Done, due rows = %+v, want only n2", rows)
	}
	mustWrite(t, s, func(tx store.Tx) error { return tx.LogoutNotifications().Drop(ctx, "n2") })
	mustWrite(t, s, func(tx store.Tx) error {
		// A missing id is not an error.
		if err := tx.LogoutNotifications().Done(ctx, "n2"); err != nil {
			return err
		}
		return tx.LogoutNotifications().Drop(ctx, "nope")
	})
	if rows := claim(epoch.Add(3*time.Hour), 10); len(rows) != 0 {
		t.Fatalf("rows left after Done and Drop: %+v", rows)
	}
}

// Covers: FR-43 (part)
// Acceptance: Back-channel logout (part)
// The tries of a row are 1, 5, 30 and 120 minutes apart after the first try
// (the first, second, third and fourth); a row that has made 5 tries is due at
// once again, so the worker can drop it.
func testLogoutNotificationsSchedule(t *testing.T, s store.Store) {
	ctx := context.Background()
	mustWrite(t, s, func(tx store.Tx) error {
		return tx.LogoutNotifications().Enqueue(ctx, store.LogoutNotification{ID: "n1", RealmID: "r1", ClientID: "app", UserID: "u1", SessionID: "sess-1", NextAttemptAt: epoch, CreatedAt: epoch})
	})
	claim := func(now time.Time) []store.LogoutNotification {
		t.Helper()
		var rows []store.LogoutNotification
		mustWrite(t, s, func(tx store.Tx) (err error) {
			rows, err = tx.LogoutNotifications().Claim(ctx, now, 10)
			return err
		})
		return rows
	}
	now := epoch
	gaps := []time.Duration{time.Minute, 5 * time.Minute, 30 * time.Minute, 2 * time.Hour}
	for i, gap := range gaps {
		rows := claim(now)
		if len(rows) != 1 || rows[0].Attempts != i {
			t.Fatalf("try %d at %v: %+v, want one row with %d attempts", i+1, now, rows, i)
		}
		if rows := claim(now.Add(gap - time.Second)); len(rows) != 0 {
			t.Fatalf("try %d is due %v early", i+2, time.Second)
		}
		now = now.Add(gap)
	}
	// The fifth try: 4 attempts before it, and no later try is scheduled.
	rows := claim(now)
	if len(rows) != 1 || rows[0].Attempts != 4 {
		t.Fatalf("the fifth try at %v: %+v, want 4 attempts before it", now, rows)
	}
	if rows := claim(now); len(rows) != 1 || rows[0].Attempts != 5 {
		t.Fatalf("a row with 5 attempts is not due at once: %+v", rows)
	}
}

// Covers: FR-43 (part)
// Acceptance: Back-channel logout (part)
// A cancelled context makes every logout notification call and the revoking call
// fail, so none of them can write a row the caller did not get back.
func testLogoutNotificationsCancelled(t *testing.T, s store.Store) {
	insertRefresh(t, s, newRefresh("t1", "tok1", "sess-1"))
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	n := store.LogoutNotification{ID: "n1", RealmID: "r1", ClientID: "app", UserID: "u1", SessionID: "sess-1", NextAttemptAt: epoch, CreatedAt: epoch}
	err := s.Write(context.Background(), func(tx store.Tx) error {
		if err := tx.LogoutNotifications().Enqueue(cancelled, n); err == nil {
			t.Error("Enqueue ignored a cancelled context")
		}
		if _, err := tx.LogoutNotifications().Claim(cancelled, epoch, 1); err == nil {
			t.Error("Claim ignored a cancelled context")
		}
		if err := tx.LogoutNotifications().Done(cancelled, "n1"); err == nil {
			t.Error("Done ignored a cancelled context")
		}
		if err := tx.LogoutNotifications().Drop(cancelled, "n1"); err == nil {
			t.Error("Drop ignored a cancelled context")
		}
		if _, err := tx.RefreshTokens().RevokeUser(cancelled, "r1", "u1", epoch); err == nil {
			t.Error("RevokeUser ignored a cancelled context")
		}
		return errors.New("end the transaction")
	})
	if err == nil {
		t.Fatal("the transaction committed")
	}
	if got, _ := findRefresh(t, s, "r1", "tok1"); !got.RevokedAt.IsZero() {
		t.Fatal("a cancelled revocation was committed")
	}
}

// Covers: FR-43 (part)
// Acceptance: Back-channel logout (part)
// DeleteUser counts every row it deletes, but reports only the sessions that had
// a live row: a session revoked before is not reported again.
func testRefreshDeleteUserReportsOnlyLiveSessions(t *testing.T, s store.Store) {
	ctx := context.Background()
	revokedRow := newRefresh("t1", "tok1", "sess-a")
	revokedRow.UserID = "u3"
	liveRow := newRefresh("t2", "tok2", "sess-b")
	liveRow.UserID = "u3"
	insertRefresh(t, s, revokedRow, liveRow)
	revokeSession(t, s, "r1", "sess-a", epoch.Add(time.Minute))
	var got store.Ended
	mustWrite(t, s, func(tx store.Tx) (err error) {
		got, err = tx.RefreshTokens().DeleteUser(ctx, "r1", "u3")
		return err
	})
	want := []store.EndedSession{{SessionID: "sess-b", ClientID: "app", UserID: "u3"}}
	if got.Tokens != 2 || !slices.Equal(sortedSessions(got.Sessions), want) {
		t.Fatalf("DeleteUser = %+v, want 2 tokens deleted and only sess-b reported", got)
	}
}

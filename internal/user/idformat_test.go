package user_test

import (
	"context"
	"errors"
	"regexp"
	"testing"

	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/store"
)

var (
	uuidV4Re = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	ulidRe   = regexp.MustCompile(`^[0-9A-HJKMNP-TV-Z]{26}$`)
)

func (e *env) identityID(t *testing.T, provider, subject string) string {
	t.Helper()
	var id string
	err := e.st.Read(context.Background(), func(tx store.Tx) error {
		ident, err := tx.Identities().Find(context.Background(), e.realmID(), config.ProviderKey(provider), subject)
		id = string(ident.ID)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// A first login creates a user whose id follows user_data.id_format; the
// identity id is always a ULID; users keep their ids when the option changes.
//
// Covers: FR-12 (part), FR-22 (part)
func TestFirstLoginUserIDFollowsIDFormat(t *testing.T) {
	for _, tc := range []struct {
		name, format string
		re           *regexp.Regexp
	}{
		{"empty is the default uuid", "", uuidV4Re},
		{"uuid", "uuid", uuidV4Re},
		{"ulid", "ulid", ulidRe},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			e.realm.UserData.IDFormat = tc.format
			u := e.must("google", trusted(), ident("g1", "ann@gmail.com", true))
			if !tc.re.MatchString(string(u.ID)) {
				t.Fatalf("user id %q does not match %v", u.ID, tc.re)
			}
			if id := e.identityID(t, "google", "g1"); !ulidRe.MatchString(id) {
				t.Fatalf("identity id %q is not a ULID", id)
			}

			// Switch the format: the same person keeps the id, another gets the new format.
			other, otherRe := "ulid", ulidRe
			if tc.format == "ulid" {
				other, otherRe = "uuid", uuidV4Re
			}
			e.realm.UserData.IDFormat = other
			again := e.must("google", trusted(), ident("g1", "ann@gmail.com", true))
			if again.ID != u.ID {
				t.Fatalf("second login id %q, want %q", again.ID, u.ID)
			}
			bob := e.must("google", trusted(), ident("g2", "bob@gmail.com", true))
			if !otherRe.MatchString(string(bob.ID)) {
				t.Fatalf("new user id %q does not match %v", bob.ID, otherRe)
			}
			if id := e.identityID(t, "google", "g2"); !ulidRe.MatchString(id) {
				t.Fatalf("identity id %q is not a ULID", id)
			}
		})
	}
}

// An unknown format is an error and writes no user.
//
// Covers: FR-22 (part)
func TestUnknownIDFormatCreatesNothing(t *testing.T) {
	e := newEnv(t)
	e.realm.UserData.IDFormat = "snowflake"
	if _, err := e.resolve("google", trusted(), ident("g1", "ann@gmail.com", true)); err == nil {
		t.Fatal("want an error for an unknown id format")
	}
	var n int
	err := e.st.Read(context.Background(), func(tx store.Tx) error {
		// The realm row is made in the same transaction, so it is gone too.
		rid, err := tx.Realms().Find(context.Background(), e.realm.Name)
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		us, err := tx.Users().ListByEmailKey(context.Background(), rid, "ann@gmail.com")
		n = len(us)
		return err
	})
	if err != nil || n != 0 {
		t.Fatalf("%d users written (%v)", n, err)
	}
}

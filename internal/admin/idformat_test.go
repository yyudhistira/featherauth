package admin_test

import (
	"context"
	"regexp"
	"strings"
	"testing"

	"github.com/yyudhistira/featherauth/internal/admin"
	"github.com/yyudhistira/featherauth/internal/store"
)

var (
	uuidV4Re = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	ulidRe   = regexp.MustCompile(`^[0-9A-HJKMNP-TV-Z]{26}$`)
)

// An import row without id gets an id in the option's format; an id given in
// the file is kept whatever its format.
//
// Covers: FR-27 (part), FR-22 (part)
func TestImportIDFollowsIDFormat(t *testing.T) {
	const given = "01HZZZZZZZZZZZZZZZZZZZZZZZ"
	const givenUUID = "123e4567-e89b-42d3-a456-426614174000"
	for _, tc := range []struct {
		name, format string
		re           *regexp.Regexp
		keep         string
	}{
		{"empty is uuid", "", uuidV4Re, given},
		{"uuid", "uuid", uuidV4Re, given},
		{"ulid", "ulid", ulidRe, givenUUID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			ctx := context.Background()
			file := `[
 {"email":"new@example.org","name":"New","identities":[{"provider":"google","subject":"n1"}]},
 {"id":"imp1","email":"one@example.org","identities":[{"provider":"google","subject":"o1"}]},
 {"id":"` + tc.keep + `","email":"keep@example.org","identities":[{"provider":"google","subject":"k1"}]}
]`
			rep, err := e.ops.Import(ctx, "main", strings.NewReader(file), admin.ImportOptions{IDFormat: tc.format})
			if err != nil || rep.Created != 3 {
				t.Fatalf("report %+v, %v", rep, err)
			}
			e.user(t, "imp1")
			e.user(t, tc.keep)
			var fresh []string
			for _, ev := range e.events(t) {
				if id := string(ev.UserID); id != "imp1" && id != tc.keep {
					fresh = append(fresh, id)
				}
			}
			if len(fresh) != 1 || !tc.re.MatchString(fresh[0]) {
				t.Fatalf("new user ids %v, want one matching %v", fresh, tc.re)
			}
			if u := e.user(t, fresh[0]); u.Email != "new@example.org" {
				t.Fatalf("user %+v", u)
			}
		})
	}
}

// An unknown format is an error that writes nothing.
//
// Covers: FR-27 (part), FR-22 (part)
func TestImportUnknownIDFormatWritesNothing(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	file := `[{"email":"new@example.org","identities":[{"provider":"google","subject":"n1"}]}]`
	if _, err := e.ops.Import(ctx, "main", strings.NewReader(file), admin.ImportOptions{IDFormat: "snowflake"}); err == nil {
		t.Fatal("want an error for an unknown id format")
	}
	if n := len(e.events(t)); n != 0 {
		t.Fatalf("%d audit rows written", n)
	}
	var n int
	err := e.st.Read(ctx, func(tx store.Tx) error {
		us, err := tx.Users().ListByEmailKey(ctx, e.realm, "new@example.org")
		n = len(us)
		return err
	})
	if err != nil || n != 0 {
		t.Fatalf("%d users written (%v)", n, err)
	}
}

// A second import of a row without id finds the user by its identity, whatever
// the format is now.
//
// Covers: FR-27 (part), FR-22 (part)
func TestImportAgainWithAnotherFormatFindsTheUser(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	file := `[{"email":"new@example.org","identities":[{"provider":"google","subject":"n1"}]}]`
	rep, err := e.ops.Import(ctx, "main", strings.NewReader(file), admin.ImportOptions{IDFormat: "uuid"})
	if err != nil || rep.Created != 1 {
		t.Fatalf("first import %+v, %v", rep, err)
	}
	rep, err = e.ops.Import(ctx, "main", strings.NewReader(file), admin.ImportOptions{IDFormat: "ulid"})
	if err != nil || rep.Created != 0 || rep.Existing != 1 {
		t.Fatalf("second import %+v, %v", rep, err)
	}
	var n int
	err = e.st.Read(ctx, func(tx store.Tx) error {
		us, err := tx.Users().ListByEmailKey(ctx, e.realm, "new@example.org")
		n = len(us)
		return err
	})
	if err != nil || n != 1 {
		t.Fatalf("%d users (%v)", n, err)
	}
}

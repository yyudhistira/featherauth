package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/testutil/mockidp"
	"github.com/yyudhistira/featherauth/internal/testutil/server"
)

var (
	idUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	idULID = regexp.MustCompile(`^[0-9A-HJKMNP-TV-Z]{26}$`)
)

// idTokenSub reads the sub of an ID token without verifying it: the token
// came straight from the service under test.
func idTokenSub(t *testing.T, idToken string) string {
	t.Helper()
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %d parts", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var c struct {
		Sub string `json:"sub"`
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	return c.Sub
}

// The format of the ids of the users the realm creates follows
// user_data.id_format, for a first login and for an import row without id.
//
// Covers: FR-22
// Acceptance: User id format
func TestUserIDFormat(t *testing.T) {
	ctx := context.Background()
	e := server.New(t)
	env := serviceConfigDir(t, e)

	// userGet checks that `user get` shows the user with that id.
	userGet := func(id string) {
		t.Helper()
		r := execAt(t, e.Clock, env, "user", "get", "main", id)
		if r.code != 0 {
			t.Fatalf("user get %q: %+v", id, r)
		}
		var u struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal([]byte(r.stdout), &u); err != nil || u.ID != id {
			t.Fatalf("user get printed %q (%v), want %q", r.stdout, err, id)
		}
	}
	// login signs a new person in through Google and returns the sub of the
	// ID token, after checking that the access token, /userinfo and `user get`
	// show the same id. A first login writes no audit row (only an auto-link
	// does), so the audit lines are checked on imports below.
	login := func(sub, email string) string {
		t.Helper()
		e.Mocks["google"].SetUser(mockidp.User{Sub: sub, Name: "Pat", Email: email, EmailVerified: true})
		res := e.NewClient().Login(t, server.Authorize(server.ClientQuery, "google"))
		g := e.Exchange(t, server.ClientQuery, res)
		got := idTokenSub(t, g.IDToken)
		if at := idTokenSub(t, g.AccessToken); at != got {
			t.Fatalf("access token sub %q, ID token sub %q", at, got)
		}
		ui := e.NewClient().Request(t, http.MethodGet, server.Issuer+"/userinfo", "", http.Header{"Authorization": {"Bearer " + g.AccessToken}})
		var claims struct {
			Sub string `json:"sub"`
		}
		if err := json.Unmarshal([]byte(ui.Body), &claims); err != nil || ui.Code != 200 || claims.Sub != got {
			t.Fatalf("/userinfo %d %q (%v), want sub %q", ui.Code, ui.Body, err, got)
		}
		userGet(got)
		return got
	}
	importRows := func(name, rows string) string {
		t.Helper()
		file := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(file, []byte(rows), 0o600); err != nil {
			t.Fatal(err)
		}
		r := execAt(t, e.Clock, env, "import", file, "--realm", "main")
		if r.code != 0 || !strings.Contains(r.stdout, `"created": 2`) {
			t.Fatalf("import: %+v", r)
		}
		return r.stderr
	}
	// importedID finds the user of a provider identity in the store.
	importedID := func(sub string) string {
		t.Helper()
		var uid string
		err := e.Store.Read(ctx, func(tx store.Tx) error {
			rid, err := tx.Realms().Find(ctx, "main")
			if err != nil {
				return err
			}
			ident, err := tx.Identities().Find(ctx, rid, "google", sub)
			uid = string(ident.UserID)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		return uid
	}
	row := func(id, email, sub string) string {
		idField := ""
		if id != "" {
			idField = `"id":"` + id + `",`
		}
		return `{` + idField + `"email":"` + email + `","identities":[{"provider":"google","subject":"` + sub + `"}]}`
	}

	// A realm without id_format: UUIDs.
	first := login("g-1", "pat@example.org")
	if !idUUID.MatchString(first) {
		t.Fatalf("first login sub %q is not a version 4 UUID", first)
	}
	lines := importRows("a.json", "["+row("", "i1@example.org", "i-1")+","+row("kc-1", "i2@example.org", "i-2")+"]")
	uuidImported := importedID("i-1")
	userGet(uuidImported)
	userGet("kc-1")
	if !idUUID.MatchString(uuidImported) {
		t.Fatalf("imported id %q is not a version 4 UUID", uuidImported)
	}
	if importedID("i-2") != "kc-1" {
		t.Fatalf("imported id %q was not kept", importedID("i-2"))
	}
	if !strings.Contains(lines, uuidImported) {
		t.Fatalf("no audit line carries the id %q: %s", uuidImported, lines)
	}

	// ulid after a reload: new users get ULIDs, earlier users keep their ids.
	e.Reload(t, func(yaml string) string { return yaml + "\nuser_data:\n  id_format: ulid\n" })
	second := login("g-2", "sam@example.org")
	if !idULID.MatchString(second) {
		t.Fatalf("sub %q after the change is not a ULID", second)
	}
	lines = importRows("b.json", "["+row("", "i3@example.org", "i-3")+","+row("0123456789abcdef", "i4@example.org", "i-4")+"]")
	ulidImported := importedID("i-3")
	userGet(ulidImported)
	userGet("0123456789abcdef")
	if !idULID.MatchString(ulidImported) {
		t.Fatalf("imported id %q is not a ULID", ulidImported)
	}
	if importedID("i-4") != "0123456789abcdef" {
		t.Fatalf("imported id %q was not kept", importedID("i-4"))
	}
	if !strings.Contains(lines, ulidImported) {
		t.Fatalf("no audit line carries the id %q: %s", ulidImported, lines)
	}
	if got := login("g-1", "pat@example.org"); got != first {
		t.Fatalf("the first user's sub changed from %q to %q", first, got)
	}
	if importedID("i-1") != uuidImported {
		t.Fatal("an imported user's id changed")
	}

	// An unknown value is a configuration error naming the allowed values.
	ds := e.ReloadDiagnostics(t, func(yaml string) string { return strings.Replace(yaml, "id_format: ulid", "id_format: snowflake", 1) })
	if len(ds) != 1 || !strings.Contains(ds[0].Message, "uuid, ulid") {
		t.Fatalf("diagnostics %+v", ds)
	}
}

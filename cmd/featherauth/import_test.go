package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/testutil/mockidp"
	"github.com/yyudhistira/featherauth/internal/testutil/server"
)

const usersFile = `[
 {"id":"kc-1","email":"Ann@Gmail.com","email_verified":true,"name":"Ann","identities":[{"provider":"google","subject":"g1"}]},
 {"email":"bob@example.org","name":"Bob","disabled":true,"identities":[{"provider":"apple","subject":"a1"}]},
 {"email":"cy@example.org","email_verified":false,"name":"Cy"}
]`

type importEnv struct {
	dir, db, file, backups string
	env                    map[string]string
	svc                    store.Store
}

// newImportEnv is a valid configuration directory (realm "example") whose
// database.yaml names a new database of the driver, with a store open on it.
func newImportEnv(t *testing.T, d dbDriver, content string) *importEnv {
	t.Helper()
	dir := initDir(t)
	backups := filepath.Join(filepath.Dir(dir), "backups")
	db := d.provision(t, dir, backups)
	file := filepath.Join(t.TempDir(), "users.json")
	if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	svc := openConfiguredDatabase(t, dir)
	return &importEnv{dir: dir, db: db, backups: backups, file: file, svc: svc, env: map[string]string{"FEATHERAUTH_CONFIG_DIR": dir}}
}

func (e *importEnv) users(t *testing.T) map[string]store.User {
	t.Helper()
	ctx := context.Background()
	out := map[string]store.User{}
	err := e.svc.Read(ctx, func(tx store.Tx) error {
		rid, err := tx.Realms().Find(ctx, "example")
		if err != nil {
			if err == store.ErrNotFound {
				return nil
			}
			return err
		}
		for _, key := range []string{"ann@gmail.com", "bob@example.org", "cy@example.org"} {
			us, err := tx.Users().ListByEmailKey(ctx, rid, key)
			if err != nil {
				return err
			}
			for _, u := range us {
				out[u.EmailKey] = u
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// Importing a file twice gives the same ids and no duplicates, and the report
// lists the skipped rows.
//
// Covers: FR-20 (part), FR-27
// Acceptance: CLI commands (part)
// Acceptance: Import
func TestImportTwiceGivesTheSameIDs(t *testing.T) {
	forEachDB(t, func(t *testing.T, d dbDriver) {
		e := newImportEnv(t, d, usersFile)
		r := exec(t, e.env, "import", e.file, "--realm", "example")
		if r.code != 0 {
			t.Fatalf("%+v", r)
		}
		var rep importReport
		if err := json.Unmarshal([]byte(r.stdout), &rep); err != nil || rep.Created != 2 || rep.Existing != 0 || len(rep.Skipped) != 1 || rep.Skipped[0] != 3 {
			t.Fatalf("report %s, %v", r.stdout, err)
		}
		// One audit line for each user written, on standard error.
		if n := strings.Count(r.stderr, `"action":"user.import"`); n != 2 {
			t.Fatalf("%d audit lines: %s", n, r.stderr)
		}
		first := e.users(t)
		if len(first) != 2 || first["ann@gmail.com"].ID != "kc-1" || first["ann@gmail.com"].Email != "Ann@Gmail.com" ||
			first["bob@example.org"].ID == "" || first["bob@example.org"].DisabledAt.IsZero() {
			t.Fatalf("users %+v", first)
		}

		r = exec(t, e.env, "import", e.file, "--realm", "example")
		if r.code != 0 || !strings.Contains(r.stdout, `"created": 0`) || !strings.Contains(r.stdout, `"existing": 2`) {
			t.Fatalf("second run %+v", r)
		}
		second := e.users(t)
		if len(second) != 2 || second["ann@gmail.com"].ID != first["ann@gmail.com"].ID || second["bob@example.org"].ID != first["bob@example.org"].ID {
			t.Fatalf("ids changed or users duplicated: %+v", second)
		}
	})
}

// With --include-without-identity the user without identities is imported too.
//
// Covers: FR-27 (part)
// Acceptance: Import without identity (part)
func TestImportIncludeWithoutIdentity(t *testing.T) {
	forEachDB(t, func(t *testing.T, d dbDriver) {
		e := newImportEnv(t, d, usersFile)
		r := exec(t, e.env, "import", e.file, "--realm", "example", "--include-without-identity")
		if r.code != 0 || !strings.Contains(r.stdout, `"created": 3`) || !strings.Contains(r.stdout, `"skipped": []`) {
			t.Fatalf("%+v", r)
		}
		if len(e.users(t)) != 3 {
			t.Fatal("the user without identities was not imported")
		}
		// The flag may come before the file as well.
		if r := exec(t, e.env, "import", "--realm", "example", "--include-without-identity", e.file); r.code != 0 || !strings.Contains(r.stdout, `"existing": 3`) {
			t.Fatalf("%+v", r)
		}
	})
}

// Covers: FR-20 (part), FR-27 (part)
// Acceptance: CLI commands (part)
func TestImportErrors(t *testing.T) {
	forEachDB(t, func(t *testing.T, d dbDriver) {
		e := newImportEnv(t, d, usersFile)
		bad := filepath.Join(t.TempDir(), "bad.json")
		if err := os.WriteFile(bad, []byte(`[{"email":"ok@example.org","identities":[{"provider":"google","subject":"x"}]},{"email":"bad@example.org","identities":[{"provider":"","subject":"y"}]}]`), 0o600); err != nil {
			t.Fatal(err)
		}
		tests := []struct {
			name string
			args []string
			code int
		}{
			{"invalid file", []string{"import", bad, "--realm", "example"}, 1},
			{"missing file", []string{"import", filepath.Join(t.TempDir(), "none.json"), "--realm", "example"}, 1},
			{"realm not in the configuration", []string{"import", e.file, "--realm", "other"}, 1},
			{"reserved realm", []string{"import", e.file, "--realm", "admin"}, 1},
			{"no file", []string{"import", "--realm", "example"}, 2},
			{"no realm", []string{"import", e.file}, 2},
			{"two files", []string{"import", e.file, e.file, "--realm", "example"}, 2},
			{"unknown flag", []string{"import", e.file, "--realm", "example", "--bogus"}, 2},
			{"no arguments", []string{"import"}, 2},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				r := exec(t, e.env, tc.args...)
				if r.code != tc.code || r.stderr == "" {
					t.Fatalf("%+v", r)
				}
				if tc.code == 2 && r.stdout != "" {
					t.Fatalf("stdout %q", r.stdout)
				}
			})
		}
		// The invalid file wrote nothing, not even its valid first row.
		if n := len(e.users(t)); n != 0 {
			t.Fatalf("%d users written by failed imports", n)
		}
		var found bool
		_ = e.svc.Read(context.Background(), func(tx store.Tx) error {
			_, err := tx.Realms().Find(context.Background(), "example")
			found = err == nil
			return nil
		})
		if found {
			t.Fatal("a failed import created the realm row")
		}
	})
}

// Covers: FR-27 (part)
// Acceptance: Import (part)
func TestImportFailureNamesTheRow(t *testing.T) {
	forEachDB(t, func(t *testing.T, d dbDriver) {
		e := newImportEnv(t, d, `[{"email":"a@example.org","identities":[{"provider":"google","subject":""}]}]`)
		r := exec(t, e.env, "import", e.file, "--realm", "example")
		if r.code != 1 || !strings.Contains(r.stderr, "row 1") {
			t.Fatalf("%+v", r)
		}
	})
}

// A user imported without identities is linked at the first social login on
// an auto-link domain, through the real service.
//
// Covers: FR-27
// Acceptance: Import without identity
func TestImportedUserWithoutIdentityIsLinkedAtFirstLogin(t *testing.T) {
	ctx := context.Background()
	file := filepath.Join(t.TempDir(), "users.json")
	if err := os.WriteFile(file, []byte(`[{"id":"kc-77","email":"Pat@Gmail.com","email_verified":true,"name":"Pat"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	loginAs := func(e *server.Env, sub string) {
		e.Mocks["google"].SetUser(mockidp.User{Sub: sub, Name: "Pat", Email: "pat@gmail.com", EmailVerified: true})
		e.NewClient().Login(t, server.Authorize(server.ClientQuery, "google"))
	}
	owner := func(e *server.Env, sub string) string {
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

	// Without the flag the user is skipped, and the login creates another user.
	e := server.New(t)
	env := serviceConfigDir(t, e)
	r := execAt(t, e.Clock, env, "import", file, "--realm", "main")
	if r.code != 0 || !strings.Contains(r.stdout, `"created": 0`) || !strings.Contains(r.stdout, `"skipped": [`) {
		t.Fatalf("%+v", r)
	}
	loginAs(e, "g-1")
	if got := owner(e, "g-1"); got == "kc-77" {
		t.Fatal("a skipped user was linked")
	}

	// With the flag the first login links the identity to the imported user.
	e = server.New(t)
	env = serviceConfigDir(t, e)
	if r := execAt(t, e.Clock, env, "import", file, "--realm", "main", "--include-without-identity"); r.code != 0 || !strings.Contains(r.stdout, `"created": 1`) {
		t.Fatalf("%+v", r)
	}
	loginAs(e, "g-1")
	if got := owner(e, "g-1"); got != "kc-77" {
		t.Fatalf("the login created user %q instead of linking to kc-77", got)
	}
}

// Every subcommand of FR-20 against one test configuration directory, each
// with its expected output or effect.
//
// Covers: FR-20
// Acceptance: CLI commands
func TestEverySubcommandOfFR20(t *testing.T) {
	forEachDB(t, func(t *testing.T, d dbDriver) {
		e := newImportEnv(t, d, usersFile)
		ready := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		defer ready.Close()
		env := map[string]string{"FEATHERAUTH_CONFIG_DIR": e.dir, "FEATHERAUTH_LISTEN": strings.TrimPrefix(ready.URL, "http://")}
		run := func(args ...string) result {
			t.Helper()
			r := exec(t, env, args...)
			if r.code != 0 {
				t.Fatalf("%v: %+v", args, r)
			}
			return r
		}

		// version prints the build version.
		if got := strings.TrimSpace(run("version").stdout); got != version {
			t.Errorf("version printed %q", got)
		}

		// config init writes the example files; config check accepts a valid directory.
		fresh := filepath.Join(t.TempDir(), "fresh")
		run("config", "init", fresh)
		for _, f := range []string{"server.yaml", "database.yaml", "realms/example.yaml", "locales/en.yaml.example"} {
			if _, err := os.Stat(filepath.Join(fresh, f)); err != nil {
				t.Errorf("config init did not write %s", f)
			}
		}
		if got := strings.TrimSpace(run("config", "check", e.dir).stdout); got != "ok" {
			t.Errorf("config check printed %q", got)
		}

		// keys generate creates a 0600 file: a PEM key, and a base64 encryption key.
		rsaFile, encFile := filepath.Join(t.TempDir(), "k.pem"), filepath.Join(t.TempDir(), "enc")
		run("keys", "generate", rsaFile)
		run("keys", "generate", "--type", "encryption", encFile)
		for file, prefix := range map[string]string{rsaFile: "-----BEGIN PRIVATE KEY-----", encFile: ""} {
			if mode(t, file) != 0o600 || !strings.HasPrefix(read(t, file), prefix) {
				t.Errorf("%s: mode %04o", file, mode(t, file))
			}
		}

		// healthcheck prints ready when the service answers 200 on /readyz.
		if got := strings.TrimSpace(run("healthcheck").stdout); got != "ready" {
			t.Errorf("healthcheck printed %q", got)
		}

		// import prints its report, and the users are there.
		var rep importReport
		if err := json.Unmarshal([]byte(run("import", e.file, "--realm", "example").stdout), &rep); err != nil || rep.Created != 2 || len(rep.Skipped) != 1 {
			t.Errorf("import report %+v, %v", rep, err)
		}
		if got := run("user", "list", "example", "--email", "ann@gmail.com").stdout; !strings.Contains(got, `"id": "kc-1"`) {
			t.Errorf("user list printed %s", got)
		}
		if got := run("user", "get", "example", "kc-1").stdout; !strings.Contains(got, `"name": "Ann"`) {
			t.Errorf("user get printed %s", got)
		}

		// user update, disable, enable, link, unlink: each has its effect.
		run("user", "update", "example", "kc-1", "--name", "Anne")
		if got := run("user", "get", "example", "kc-1").stdout; !strings.Contains(got, `"name": "Anne"`) {
			t.Errorf("update: %s", got)
		}
		run("user", "disable", "example", "kc-1")
		if got := run("user", "get", "example", "kc-1").stdout; !strings.Contains(got, `"disabled": true`) {
			t.Errorf("disable: %s", got)
		}
		run("user", "enable", "example", "kc-1")
		if got := run("user", "get", "example", "kc-1").stdout; !strings.Contains(got, `"disabled": false`) {
			t.Errorf("enable: %s", got)
		}
		run("user", "link", "example", "kc-1", "github", "gh-1")
		if got := run("user", "get", "example", "kc-1").stdout; !strings.Contains(got, `"subject": "gh-1"`) {
			t.Errorf("link: %s", got)
		}
		run("user", "unlink", "example", "kc-1", "github", "gh-1")
		if got := run("user", "get", "example", "kc-1").stdout; strings.Contains(got, `"subject": "gh-1"`) {
			t.Errorf("unlink: %s", got)
		}

		// backup creates a snapshot in the directory (SQLite); the other drivers
		// refuse it and write nothing.
		if d.snapshots {
			snap := strings.TrimPrefix(strings.TrimSpace(run("backup").stdout), "wrote ")
			if entries, err := os.ReadDir(e.backups); err != nil || len(entries) != 1 || filepath.Join(e.backups, entries[0].Name()) != snap {
				t.Errorf("backup directory %v, %v; printed %q", entries, err, snap)
			}
		} else if r := exec(t, env, "backup"); r.code != 1 || !strings.Contains(r.stderr, "pg_dump") {
			t.Errorf("backup: %+v", r)
		} else if _, err := os.Stat(e.backups); err == nil {
			t.Error("backup created the snapshot directory")
		}

		// user delete removes the user: get then exits 1.
		run("user", "delete", "example", "kc-1")
		if r := exec(t, env, "user", "get", "example", "kc-1"); r.code != 1 {
			t.Errorf("get after delete: %+v", r)
		}

		// A failing check exits non-zero.
		writeConfig(t, e.dir, "server.yaml", "public_url: https://auth.example.com\nbogus: 1\n")
		if r := exec(t, env, "config", "check", e.dir); r.code == 0 || !strings.Contains(r.stdout, "bogus") {
			t.Errorf("a failing check: %+v", r)
		}
	})
}

// Edge cases of the file argument: a directory and text that is not JSON.
// Each exits 1 and writes nothing.
//
// Covers: FR-27 (part)
// Acceptance: Import (part)
func TestImportRefusesUnusableFiles(t *testing.T) {
	forEachDB(t, func(t *testing.T, d dbDriver) {
		e := newImportEnv(t, d, usersFile)
		dir := t.TempDir()
		notJSON := filepath.Join(dir, "users.txt")
		if err := os.WriteFile(notJSON, []byte("name,email\nAnn,ann@example.org\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		for name, file := range map[string]string{"a directory": dir, "not JSON": notJSON} {
			t.Run(name, func(t *testing.T) {
				r := exec(t, e.env, "import", file, "--realm", "example", "--include-without-identity")
				if r.code != 1 || r.stderr == "" || r.stdout != "" {
					t.Fatalf("%+v", r)
				}
				if n := len(e.users(t)); n != 0 {
					t.Fatalf("%d users written", n)
				}
			})
		}
		found := false
		_ = e.svc.Read(context.Background(), func(tx store.Tx) error {
			_, err := tx.Realms().Find(context.Background(), "example")
			found = err == nil
			return nil
		})
		if found {
			t.Fatal("a refused file created the realm row")
		}
	})
}

// A leading UTF-8 byte order mark, as some editors write, is ignored.
//
// Covers: FR-27 (part)
// Acceptance: Import (part)
func TestImportAcceptsAByteOrderMark(t *testing.T) {
	forEachDB(t, func(t *testing.T, d dbDriver) {
		e := newImportEnv(t, d, "\xef\xbb\xbf"+usersFile)
		r := exec(t, e.env, "import", e.file, "--realm", "example")
		var rep importReport
		if r.code != 0 || json.Unmarshal([]byte(r.stdout), &rep) != nil || rep.Created != 2 {
			t.Fatalf("%+v", r)
		}
		if len(e.users(t)) != 2 {
			t.Fatal("the users of a file with a byte order mark were not imported")
		}
	})
}

// An invalid configuration is reported with its diagnostics (file, line and
// reason), not only with a hint.
//
// Covers: FR-27 (part)
// Acceptance: Import (part)
func TestImportShowsTheConfigurationDiagnostics(t *testing.T) {
	forEachDB(t, func(t *testing.T, d dbDriver) {
		e := newImportEnv(t, d, usersFile)
		writeConfig(t, e.dir, "server.yaml", "public_url: https://auth.example.com\nbogus: 1\n")
		r := exec(t, e.env, "import", e.file, "--realm", "example")
		if r.code != 1 || !strings.Contains(r.stderr, "server.yaml:2") || !strings.Contains(r.stderr, "bogus") || !strings.Contains(r.stderr, "config check") {
			t.Fatalf("%+v", r)
		}
		if len(e.users(t)) != 0 {
			t.Fatal("an import ran on an invalid configuration")
		}
	})
}

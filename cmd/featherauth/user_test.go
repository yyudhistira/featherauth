package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/testutil/configdir"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/secure"
	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/testutil"
)

var t0 = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

// adminEnv is a configuration directory whose database.yaml names a new
// database of the driver, a store open on that database as a running service
// would hold it, and a realm "main" with two users.
type adminEnv struct {
	dir, db, backups string
	svc              store.Store
	clock            *clock.Fake
	env              map[string]string
}

// newAdminEnv returns an admin environment with a loadable configuration: the
// realm main with a signing key. The revocation commands read it for the
// clients' logout URIs.
func newAdminEnv(t *testing.T, d dbDriver) *adminEnv {
	t.Helper()
	return newAdminEnvWith(t, d, true)
}

// newAdminEnvWith returns an admin environment; withConfig false leaves the
// directory with database.yaml only, which is no configuration at all.
func newAdminEnvWith(t *testing.T, d dbDriver, withConfig bool) *adminEnv {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "conf")
	if withConfig {
		cfg := configdir.New(t)
		cfg.Server(t, "public_url: https://auth.example.com\n")
		cfg.Realm(t, "main", "name: main\nkeys:\n  - {kid: rsa1, file: secrets/main/rsa.pem, state: active}\n")
		cfg.RSAKey(t, "secrets/main/rsa.pem")
		dir = cfg.Root
	}
	e := &adminEnv{dir: dir, backups: filepath.Join(root, "backups")}
	e.env = map[string]string{"FEATHERAUTH_CONFIG_DIR": e.dir}
	e.clock = clock.NewFake(t0)
	e.db = d.provision(t, e.dir, e.backups)
	svc := openConfiguredDatabase(t, e.dir)
	e.svc = svc
	ctx := context.Background()
	err := svc.Write(ctx, func(tx store.Tx) error {
		if _, err := tx.Realms().Ensure(ctx, "main", "r1", t0); err != nil {
			return err
		}
		for _, u := range []store.User{
			{ID: "u1", RealmID: "r1", Email: "Ann@Example.org", EmailKey: "ann@example.org", EmailVerified: true, Name: "Ann", CreatedAt: t0, UpdatedAt: t0},
			{ID: "u2", RealmID: "r1", Email: "bob@example.org", EmailKey: "bob@example.org", Name: "Bob", CreatedAt: t0, UpdatedAt: t0},
		} {
			if err := tx.Users().Create(ctx, u); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func writeConfig(t *testing.T, dir, name, content string) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := mkdirWrite(p, content); err != nil {
		t.Fatal(err)
	}
}

func (e *adminEnv) run(t *testing.T, args ...string) result {
	t.Helper()
	e.clock.Advance(time.Second) // audit rows sort by time
	return execAt(t, e.clock, e.env, args...)
}

func (e *adminEnv) user(t *testing.T, id string) store.User {
	t.Helper()
	var u store.User
	err := e.svc.Read(context.Background(), func(tx store.Tx) (err error) {
		u, err = tx.Users().Get(context.Background(), "r1", store.UserID(id))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func (e *adminEnv) audit(t *testing.T) []store.AuditEvent {
	t.Helper()
	var evs []store.AuditEvent
	err := e.svc.Read(context.Background(), func(tx store.Tx) (err error) {
		evs, err = tx.Audit().List(context.Background(), "r1", time.Unix(0, 0))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return evs
}

func lastAction(t *testing.T, e *adminEnv) store.AuditEvent {
	t.Helper()
	evs := e.audit(t)
	if len(evs) == 0 {
		t.Fatal("no audit row")
	}
	return evs[len(evs)-1]
}

// Covers: FR-20 (part), FR-23 (part)
// Acceptance: CLI commands (part)
func TestUserGetAndList(t *testing.T) {
	forEachDB(t, func(t *testing.T, d dbDriver) {
		e := newAdminEnv(t, d)
		if r := e.run(t, "user", "link", "main", "u1", "google", "g1"); r.code != 0 {
			t.Fatal(r)
		}
		r := e.run(t, "user", "get", "main", "u1")
		if r.code != 0 {
			t.Fatalf("%+v", r)
		}
		var got struct {
			ID            string `json:"id"`
			Email         string `json:"email"`
			EmailVerified bool   `json:"email_verified"`
			Name          string `json:"name"`
			Disabled      bool   `json:"disabled"`
			Identities    []struct{ Provider, Subject string }
		}
		if err := json.Unmarshal([]byte(r.stdout), &got); err != nil {
			t.Fatalf("%v: %s", err, r.stdout)
		}
		if got.ID != "u1" || got.Email != "Ann@Example.org" || !got.EmailVerified || got.Name != "Ann" || got.Disabled ||
			len(got.Identities) != 1 || got.Identities[0].Provider != "google" || got.Identities[0].Subject != "g1" {
			t.Fatalf("got %+v", got)
		}
		if strings.Contains(r.stdout, "provider_refresh_token") {
			t.Fatal("output holds a token field")
		}

		r = e.run(t, "user", "list", "main", "--email", " ANN@example.org ")
		var list []struct {
			ID string `json:"id"`
		}
		if r.code != 0 || json.Unmarshal([]byte(r.stdout), &list) != nil || len(list) != 1 || list[0].ID != "u1" {
			t.Fatalf("%+v", r)
		}
		r = e.run(t, "user", "list", "main", "--email", "nobody@example.org")
		if r.code != 0 || strings.TrimSpace(r.stdout) != "[]" {
			t.Fatalf("empty list: %+v", r)
		}
	})
}

// Covers: FR-20 (part), FR-23 (part)
// Acceptance: CLI commands (part)
// Acceptance: User admin (part)
func TestUserUpdate(t *testing.T) {
	forEachDB(t, func(t *testing.T, d dbDriver) {
		e := newAdminEnv(t, d)
		r := e.run(t, "user", "update", "main", "u2", "--name", "Robert", "--email", "rob@example.org", "--email-verified", "true")
		if r.code != 0 {
			t.Fatalf("%+v", r)
		}
		u := e.user(t, "u2")
		if u.Name != "Robert" || u.Email != "rob@example.org" || !u.EmailVerified {
			t.Fatalf("user %+v", u)
		}
		ev := lastAction(t, e)
		if ev.Actor != "admin" || ev.Action != "user.update" || ev.UserID != "u2" {
			t.Fatalf("audit %+v", ev)
		}
		// The audit line goes to standard error, without the values.
		if !strings.Contains(r.stderr, `"audit":true`) || !strings.Contains(r.stderr, "user.update") ||
			strings.Contains(r.stderr, "Robert") || strings.Contains(r.stderr, "rob@example.org") {
			t.Fatalf("stderr %q", r.stderr)
		}
	})
}

// --disabled is routed to Disable and Enable.
//
// Covers: FR-20 (part), FR-23 (part)
// Acceptance: CLI commands (part)
// Acceptance: User admin (part)
func TestUserUpdateDisabledRoutesToDisableAndEnable(t *testing.T) {
	forEachDB(t, func(t *testing.T, d dbDriver) {
		e := newAdminEnv(t, d)
		if r := e.run(t, "user", "update", "main", "u1", "--disabled", "true"); r.code != 0 {
			t.Fatalf("%+v", r)
		}
		if e.user(t, "u1").DisabledAt.IsZero() || lastAction(t, e).Action != "user.disable" {
			t.Fatal("not disabled and audited")
		}
		if r := e.run(t, "user", "update", "main", "u1", "--name", "Anna", "--disabled", "false"); r.code != 0 {
			t.Fatalf("%+v", r)
		}
		u := e.user(t, "u1")
		if !u.DisabledAt.IsZero() || u.Name != "Anna" {
			t.Fatalf("user %+v", u)
		}
		acts := []string{}
		for _, ev := range e.audit(t) {
			acts = append(acts, ev.Action)
		}
		// The update and the enable of one command share an instant, so their order is not fixed.
		sort.Strings(acts)
		if strings.Join(acts, ",") != "user.disable,user.enable,user.update" {
			t.Fatalf("audit actions %v", acts)
		}
	})
}

// Covers: FR-20 (part), FR-23 (part)
// Acceptance: CLI commands (part)
// Acceptance: User admin (part)
func TestUserDisableEnableDeleteLinkUnlink(t *testing.T) {
	forEachDB(t, func(t *testing.T, d dbDriver) {
		e := newAdminEnv(t, d)
		for _, step := range []struct {
			action string
			args   []string
		}{
			{"user.disable", []string{"user", "disable", "main", "u1"}},
			{"user.enable", []string{"user", "enable", "main", "u1"}},
			{"identity.link", []string{"user", "link", "main", "u1", "google", "g1"}},
			{"identity.unlink", []string{"user", "unlink", "main", "u1", "google", "g1"}},
			{"user.delete", []string{"user", "delete", "main", "u1", "--skip-revocation"}},
		} {
			r := e.run(t, step.args...)
			if r.code != 0 || !strings.Contains(r.stderr, step.action) {
				t.Fatalf("%v: %+v", step.args, r)
			}
			if ev := lastAction(t, e); ev.Action != step.action || ev.Actor != "admin" {
				t.Fatalf("%v: audit %+v", step.args, ev)
			}
		}
		if r := e.run(t, "user", "get", "main", "u1"); r.code != 1 {
			t.Fatalf("deleted user: %+v", r)
		}
	})
}

// Covers: FR-20 (part), FR-23 (part)
// Acceptance: CLI commands (part)
func TestUserCommandErrors(t *testing.T) {
	forEachDB(t, func(t *testing.T, d dbDriver) {
		e := newAdminEnv(t, d)
		if r := e.run(t, "user", "link", "main", "u1", "google", "g1"); r.code != 0 {
			t.Fatal(r)
		}
		tests := []struct {
			name string
			args []string
			code int
		}{
			{"unknown user", []string{"user", "get", "main", "nope"}, 1},
			{"unknown realm", []string{"user", "get", "other", "u1"}, 1},
			{"link already linked", []string{"user", "link", "main", "u2", "google", "g1"}, 1},
			{"unlink not linked", []string{"user", "unlink", "main", "u2", "google", "g1"}, 1},
			{"link empty subject", []string{"user", "link", "main", "u1", "google", ""}, 1},
			{"second verified holder", []string{"user", "update", "main", "u2", "--email", "ann@example.org", "--email-verified", "true"}, 1},
			{"no subcommand", []string{"user"}, 2},
			{"unknown subcommand", []string{"user", "nope", "main"}, 2},
			{"get without id", []string{"user", "get", "main"}, 2},
			{"get with extra", []string{"user", "get", "main", "u1", "x"}, 2},
			{"list without email", []string{"user", "list", "main"}, 2},
			{"list without realm", []string{"user", "list"}, 2},
			{"delete with an unknown flag", []string{"user", "delete", "main", "u1", "--bogus"}, 2},
			{"delete with a stray argument", []string{"user", "delete", "main", "u1", "x", "--skip-revocation"}, 2},
			{"update without flags", []string{"user", "update", "main", "u1"}, 2},
			{"update bad bool", []string{"user", "update", "main", "u1", "--disabled", "maybe"}, 2},
			{"update unknown flag", []string{"user", "update", "main", "u1", "--bogus", "x"}, 2},
			{"update positional after flags", []string{"user", "update", "main", "u1", "--name", "x", "y"}, 2},
			{"link without subject", []string{"user", "link", "main", "u1", "google"}, 2},
			{"disable without id", []string{"user", "disable", "main"}, 2},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				r := e.run(t, tc.args...)
				if r.code != tc.code || r.stderr == "" {
					t.Fatalf("%+v", r)
				}
				if tc.code == 2 && r.stdout != "" {
					t.Fatalf("usage error wrote stdout %q", r.stdout)
				}
			})
		}
		if u := e.user(t, "u2"); u.Email != "bob@example.org" || u.EmailVerified {
			t.Fatalf("a failed command changed the user: %+v", u)
		}
	})
}

// Covers: FR-20 (part), FR-23 (part)
// Acceptance: CLI commands (part)
func TestUserCommandsNeedADatabase(t *testing.T) {
	dir := t.TempDir()
	writeConfig(t, dir, "database.yaml", "driver: postgres\n")
	env := map[string]string{"FEATHERAUTH_CONFIG_DIR": dir}
	if r := exec(t, env, "user", "get", "main", "u1"); r.code != 1 || r.stderr == "" {
		t.Fatalf("postgres: %+v", r)
	}
	writeConfig(t, dir, "database.yaml", "driver: sqlite\nbogus: 1\n")
	if r := exec(t, env, "user", "get", "main", "u1"); r.code != 1 || r.stderr == "" {
		t.Fatalf("invalid database.yaml: %+v", r)
	}
	if r := exec(t, map[string]string{"FEATHERAUTH_CONFIG_DIR": filepath.Join(dir, "none")}, "backup"); r.code != 1 {
		t.Fatalf("no directory: %+v", r)
	}
}

// The commands run while a service holds the same database and writes to it.
//
// Covers: FR-20 (part), FR-23 (part), FR-24 (part)
// Acceptance: CLI commands (part)
// Acceptance: User admin (part)
func TestUserCommandsWhileAServiceUsesTheDatabase(t *testing.T) {
	forEachDB(t, func(t *testing.T, d dbDriver) {
		e := newAdminEnv(t, d)
		ctx := context.Background()
		stop := make(chan struct{})
		var wg sync.WaitGroup
		var mu sync.Mutex
		var first error
		record := func(err error) { // the first failure only: nothing to drain
			mu.Lock()
			if first == nil {
				first = err
			}
			mu.Unlock()
		}
		wg.Add(1)
		go func() { // the service: reads and writes until the commands are done
			defer wg.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				record(e.svc.Write(ctx, func(tx store.Tx) error {
					u, err := tx.Users().Get(ctx, "r1", "u2")
					if err != nil {
						return err
					}
					u.UpdatedAt = t0.Add(time.Duration(i) * time.Second)
					return tx.Users().Update(ctx, u)
				}))
				record(e.svc.Read(ctx, func(tx store.Tx) error {
					_, err := tx.Users().Get(ctx, "r1", "u2")
					return err
				}))
			}
		}()
		for _, args := range [][]string{
			{"user", "update", "main", "u1", "--name", "Annie"},
			{"user", "disable", "main", "u1"},
			{"user", "enable", "main", "u1"},
			{"user", "link", "main", "u1", "github", "h1"},
			{"user", "unlink", "main", "u1", "github", "h1"},
			{"user", "delete", "main", "u1", "--skip-revocation"},
		} {
			if r := e.run(t, args...); r.code != 0 {
				t.Errorf("%v: %+v", args, r)
			}
		}
		// A snapshot is taken on SQLite only; the other drivers refuse it (pg_dump).
		if r := e.run(t, "backup"); d.snapshots != (r.code == 0) || (!d.snapshots && !strings.Contains(r.stderr, "pg_dump")) {
			t.Errorf("backup: %+v", r)
		}
		close(stop)
		wg.Wait()
		if first != nil {
			t.Fatal(first)
		}
	})
}

// `featherauth backup` while logins write, then a restore on a clean host: the
// snapshot opens, with the users and the refresh tokens in it.
//
// Covers: FR-20 (part), FR-24 (part)
// Acceptance: CLI commands (part)
// Acceptance: Backup
func TestBackupWritesASnapshotThatOpens(t *testing.T) {
	e := newAdminEnv(t, sqliteDriver)
	ctx := context.Background()
	err := e.svc.Write(ctx, func(tx store.Tx) error {
		return tx.RefreshTokens().Insert(ctx, store.RefreshToken{
			ID: "rt1", RealmID: "r1", UserID: "u1", ClientID: "app", TokenHash: secure.HashOf("tok1"), SessionID: "s1",
			SessionStartedAt: t0, AuthTime: t0, ExpiresAt: t0.Add(time.Hour), CreatedAt: t0,
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	// Logins keep writing while the snapshot is taken.
	stop := make(chan struct{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	var werr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			err := e.svc.Write(ctx, func(tx store.Tx) error {
				u, err := tx.Users().Get(ctx, "r1", "u2")
				if err != nil {
					return err
				}
				u.UpdatedAt = t0.Add(time.Duration(i) * time.Second)
				return tx.Users().Update(ctx, u)
			})
			if err != nil {
				mu.Lock()
				werr = err
				mu.Unlock()
				return
			}
		}
	}()
	r := e.run(t, "backup")
	close(stop)
	wg.Wait()
	if werr != nil {
		t.Fatal(werr)
	}
	if r.code != 0 {
		t.Fatalf("%+v", r)
	}
	path := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(r.stdout), "wrote "))
	if filepath.Dir(path) != e.backups || !strings.HasPrefix(filepath.Base(path), "featherauth-") || !strings.HasSuffix(path, ".db") {
		t.Fatalf("stdout %q", r.stdout)
	}
	// Restore on a clean host: the snapshot becomes the database file.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	restored := filepath.Join(t.TempDir(), "featherauth.db")
	if err := os.WriteFile(restored, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	snap, err := store.Open(ctx, testutil.DatabaseConfig(restored), config.DatabaseSecrets{})
	if err != nil {
		t.Fatalf("the snapshot does not open: %v", err)
	}
	defer snap.Close()
	err = snap.Read(ctx, func(tx store.Tx) error {
		u, err := tx.Users().Get(ctx, "r1", "u1")
		if err != nil || u.Name != "Ann" {
			t.Errorf("snapshot user %+v, %v", u, err)
		}
		if _, err := tx.RefreshTokens().FindByHash(ctx, "r1", secure.HashOf("tok1")); err != nil {
			t.Errorf("snapshot refresh token: %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// A second snapshot in the same minute is refused: exit 1, the first is kept.
	if r := e.run(t, "backup"); r.code != 1 {
		t.Fatalf("same minute: %+v", r)
	}
	// An empty directory disables backups.
	writeConfig(t, e.dir, "database.yaml", "driver: sqlite\nsqlite:\n  path: "+e.db+"\nbackup:\n  directory: \"\"\n")
	if r := e.run(t, "backup"); r.code != 1 || r.stderr == "" {
		t.Fatalf("disabled: %+v", r)
	}
	if r := e.run(t, "backup", "extra"); r.code != 2 {
		t.Fatalf("extra argument: %+v", r)
	}
}

func mkdirWrite(p, content string) error {
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	return os.WriteFile(p, []byte(content), 0o600)
}

// Covers: FR-20 (part), FR-23 (part)
// Acceptance: CLI commands (part)
func TestUserUpdateNoticeWhenTheEmailChangeClearsVerification(t *testing.T) {
	forEachDB(t, func(t *testing.T, d dbDriver) {
		notice := "--email-verified true"
		for _, tc := range []struct {
			name   string
			args   []string
			notice bool
			verify bool // the user is verified afterwards
		}{
			{"new address", []string{"--email", "new@example.org"}, true, false},
			{"new address, verified kept", []string{"--email", "new@example.org", "--email-verified", "true"}, false, true},
			{"only the case differs", []string{"--email", "ANN@example.org"}, false, true},
			{"name only", []string{"--name", "Anna"}, false, true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				e := newAdminEnv(t, d) // u1 has a verified email
				r := e.run(t, append([]string{"user", "update", "main", "u1"}, tc.args...)...)
				if r.code != 0 {
					t.Fatalf("%+v", r)
				}
				if got := strings.Contains(r.stderr, notice); got != tc.notice {
					t.Fatalf("notice %v, want %v: %q", got, tc.notice, r.stderr)
				}
				if tc.notice && !strings.Contains(r.stderr, "email_verified") {
					t.Fatalf("the notice does not say what was cleared: %q", r.stderr)
				}
				if e.user(t, "u1").EmailVerified != tc.verify {
					t.Fatalf("verified = %v", !tc.verify)
				}
			})
		}
	})
}

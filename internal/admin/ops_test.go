package admin_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/yyudhistira/featherauth/internal/admin"
	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/logx"
	"github.com/yyudhistira/featherauth/internal/secure"
	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/store/audit"
	"github.com/yyudhistira/featherauth/internal/testutil"
	"github.com/yyudhistira/featherauth/internal/user"
)

var start = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

type env struct {
	st    store.Store
	clock *clock.Fake
	log   *bytes.Buffer
	ops   *admin.Ops
	realm store.RealmID
}

func newEnv(t *testing.T) *env {
	t.Helper()
	st := testutil.NewStore(t)
	return wire(t, st)
}

func wire(t *testing.T, st store.Store) *env {
	t.Helper()
	c := clock.NewFake(start)
	var buf bytes.Buffer
	l := logx.New(&buf, 0, c)
	w := audit.NewWriter(st, l, c, secure.Default)
	mgr := user.NewManager(st, w, nil, nil, l, c, secure.Default, func(n config.RealmName) (*config.Realm, bool) {
		return &config.Realm{Name: n}, true // no clients: the sessions queue no logout
	})
	e := &env{st: st, clock: c, log: &buf, ops: admin.NewOps(st, mgr, c, l), realm: "r1"}
	ctx := context.Background()
	err := st.Write(ctx, func(tx store.Tx) error {
		_, err := tx.Realms().Ensure(ctx, "main", e.realm, start)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *env) addUser(t *testing.T, id, email string, verified bool) {
	t.Helper()
	ctx := context.Background()
	err := e.st.Write(ctx, func(tx store.Tx) error {
		return tx.Users().Create(ctx, store.User{
			ID: store.UserID(id), RealmID: e.realm, Email: email, EmailKey: strings.ToLower(email),
			EmailVerified: verified, Name: "Name " + id, CreatedAt: start, UpdatedAt: start,
		})
	})
	if err != nil {
		t.Fatal(err)
	}
}

func (e *env) user(t *testing.T, id string) store.User {
	t.Helper()
	var u store.User
	err := e.st.Read(context.Background(), func(tx store.Tx) (err error) {
		u, err = tx.Users().Get(context.Background(), e.realm, store.UserID(id))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func (e *env) events(t *testing.T) []store.AuditEvent {
	t.Helper()
	var evs []store.AuditEvent
	err := e.st.Read(context.Background(), func(tx store.Tx) (err error) {
		evs, err = tx.Audit().List(context.Background(), e.realm, time.Unix(0, 0))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return evs
}

func (e *env) lastEvent(t *testing.T) store.AuditEvent {
	t.Helper()
	evs := e.events(t)
	if len(evs) == 0 {
		t.Fatal("no audit event")
	}
	return evs[len(evs)-1]
}

func ptr[T any](v T) *T { return &v }

// Covers: FR-23 (part)
// Acceptance: User admin (part)
func TestGetAndListByEmail(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.addUser(t, "u1", "Ann@Example.org", true)
	e.addUser(t, "u2", "ann@example.org", false)
	if err := e.ops.Link(ctx, "main", "u1", "google", "g1"); err != nil {
		t.Fatal(err)
	}

	got, err := e.ops.Get(ctx, "main", "u1")
	if err != nil {
		t.Fatal(err)
	}
	if got.User.ID != "u1" || len(got.Identities) != 1 || got.Identities[0].ProviderSub != "g1" {
		t.Fatalf("Get = %+v", got)
	}
	if _, err := e.ops.Get(ctx, "main", "nope"); !errors.Is(err, admin.ErrNotFound) {
		t.Fatalf("unknown user: %v", err)
	}
	if _, err := e.ops.Get(ctx, "other", "u1"); !errors.Is(err, admin.ErrNotFound) {
		t.Fatalf("unknown realm: %v", err)
	}

	list, err := e.ops.ListByEmail(ctx, "main", "  ANN@example.ORG ")
	if err != nil || len(list) != 2 {
		t.Fatalf("ListByEmail = %v, %v", list, err)
	}
	if _, err := e.ops.ListByEmail(ctx, "main", " "); !errors.Is(err, admin.ErrInvalid) {
		t.Fatalf("empty email: %v", err)
	}
	if _, err := e.ops.ListByEmail(ctx, "other", "a@b"); !errors.Is(err, admin.ErrNotFound) {
		t.Fatalf("unknown realm: %v", err)
	}
}

// Covers: FR-23 (part)
// Acceptance: User admin (part)
func TestUpdateChangesNameAndAudits(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.addUser(t, "u1", "ann@example.org", true)
	e.clock.Advance(time.Hour)

	if _, err := e.ops.Update(ctx, "main", "u1", admin.Fields{Name: ptr("Ann B")}); err != nil {
		t.Fatal(err)
	}
	u := e.user(t, "u1")
	if u.Name != "Ann B" || u.Email != "ann@example.org" || !u.UpdatedAt.Equal(e.clock.Now()) {
		t.Fatalf("user = %+v", u)
	}
	ev := e.lastEvent(t)
	if ev.Actor != "admin" || ev.Action != admin.ActionUpdate || ev.UserID != "u1" {
		t.Fatalf("event = %+v", ev)
	}
	if f, _ := ev.Details["fields"].([]any); len(f) != 1 || f[0] != "name" {
		t.Fatalf("details = %v", ev.Details)
	}
	line := e.log.String()
	if !strings.Contains(line, `"audit":true`) || !strings.Contains(line, admin.ActionUpdate) || strings.Contains(line, "Ann B") {
		t.Fatalf("log = %s", line)
	}
}

// Covers: FR-23 (part)
// Acceptance: User admin (part)
func TestUpdateEmailFields(t *testing.T) {
	ctx := context.Background()
	t.Run("email and verified", func(t *testing.T) {
		e := newEnv(t)
		e.addUser(t, "u1", "ann@example.org", false)
		_, err := e.ops.Update(ctx, "main", "u1", admin.Fields{Email: ptr("  New@Example.org "), EmailVerified: ptr(true)})
		if err != nil {
			t.Fatal(err)
		}
		u := e.user(t, "u1")
		if u.Email != "New@Example.org" || u.EmailKey != "new@example.org" || !u.EmailVerified {
			t.Fatalf("user = %+v", u)
		}
		ev := e.lastEvent(t)
		if strings.Contains(string(mustJSON(t, ev.Details)), "example.org") {
			t.Fatalf("audit details hold an email: %v", ev.Details)
		}
	})
	t.Run("email change of a verified user clears verified", func(t *testing.T) {
		e := newEnv(t)
		e.addUser(t, "u1", "ann@example.org", true)
		if _, err := e.ops.Update(ctx, "main", "u1", admin.Fields{Email: ptr("other@example.org")}); err != nil {
			t.Fatal(err)
		}
		if u := e.user(t, "u1"); u.Email != "other@example.org" || u.EmailVerified {
			t.Fatalf("user = %+v", u)
		}
		ev := e.lastEvent(t)
		if f, _ := ev.Details["fields"].([]any); len(f) != 2 || f[0] != "email" || f[1] != "email_verified" {
			t.Fatalf("details = %v", ev.Details)
		}
	})
	t.Run("a different case of the same email keeps verified", func(t *testing.T) {
		e := newEnv(t)
		e.addUser(t, "u1", "ann@example.org", true)
		if _, err := e.ops.Update(ctx, "main", "u1", admin.Fields{Email: ptr("Ann@Example.org")}); err != nil {
			t.Fatal(err)
		}
		if u := e.user(t, "u1"); u.Email != "Ann@Example.org" || !u.EmailVerified {
			t.Fatalf("user = %+v", u)
		}
	})
	t.Run("email cleared", func(t *testing.T) {
		e := newEnv(t)
		e.addUser(t, "u1", "ann@example.org", true)
		if _, err := e.ops.Update(ctx, "main", "u1", admin.Fields{Email: ptr(" ")}); err != nil {
			t.Fatal(err)
		}
		if u := e.user(t, "u1"); u.Email != "" || u.EmailKey != "" || u.EmailVerified {
			t.Fatalf("user = %+v", u)
		}
	})
	t.Run("second verified holder", func(t *testing.T) {
		e := newEnv(t)
		e.addUser(t, "u1", "ann@example.org", true)
		e.addUser(t, "u2", "bob@example.org", true)
		_, err := e.ops.Update(ctx, "main", "u2", admin.Fields{Email: ptr("ANN@example.org"), EmailVerified: ptr(true)})
		if !errors.Is(err, admin.ErrConflict) {
			t.Fatalf("err = %v", err)
		}
		if e.user(t, "u2").Email != "bob@example.org" || len(e.events(t)) != 0 {
			t.Fatal("conflict changed something")
		}
	})
	t.Run("verified without email", func(t *testing.T) {
		e := newEnv(t)
		e.addUser(t, "u1", "", false)
		_, err := e.ops.Update(ctx, "main", "u1", admin.Fields{EmailVerified: ptr(true)})
		if !errors.Is(err, admin.ErrInvalid) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("no fields", func(t *testing.T) {
		e := newEnv(t)
		e.addUser(t, "u1", "ann@example.org", true)
		if _, err := e.ops.Update(ctx, "main", "u1", admin.Fields{}); !errors.Is(err, admin.ErrInvalid) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("same values change nothing", func(t *testing.T) {
		e := newEnv(t)
		e.addUser(t, "u1", "ann@example.org", true)
		e.clock.Advance(time.Hour)
		if _, err := e.ops.Update(ctx, "main", "u1", admin.Fields{Name: ptr("Name u1")}); err != nil {
			t.Fatal(err)
		}
		if !e.user(t, "u1").UpdatedAt.Equal(start) || len(e.events(t)) != 0 {
			t.Fatal("no-op update changed or audited something")
		}
	})
	t.Run("unknown user", func(t *testing.T) {
		e := newEnv(t)
		if _, err := e.ops.Update(ctx, "main", "x", admin.Fields{Name: ptr("a")}); !errors.Is(err, admin.ErrNotFound) {
			t.Fatalf("err = %v", err)
		}
	})
}

// Covers: FR-23 (part)
// Acceptance: User admin (part)
func TestSubAndRealmCannotChange(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.addUser(t, "u1", "ann@example.org", true)
	if _, err := e.ops.Update(ctx, "main", "u1", admin.Fields{Name: ptr("x"), Email: ptr("z@example.org"), EmailVerified: ptr(false)}); err != nil {
		t.Fatal(err)
	}
	u := e.user(t, "u1")
	if u.ID != "u1" || u.RealmID != e.realm {
		t.Fatalf("id or realm changed: %+v", u)
	}
	// A user of one realm cannot be reached through another realm.
	err := e.st.Write(ctx, func(tx store.Tx) error {
		_, err := tx.Realms().Ensure(ctx, "second", "r2", start)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.ops.Update(ctx, "second", "u1", admin.Fields{Name: ptr("y")}); !errors.Is(err, admin.ErrNotFound) {
		t.Fatalf("other realm: %v", err)
	}
	if e.user(t, "u1").Name != "x" {
		t.Fatal("other realm changed the user")
	}
}

// Covers: FR-23 (part)
// Acceptance: User admin (part)
func TestDisableEnableDeleteLinkUnlinkAudit(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.addUser(t, "u1", "ann@example.org", true)

	steps := []struct {
		name   string
		action string
		run    func() error
	}{
		{"disable", user.ActionDisable, func() error { return e.ops.Disable(ctx, "main", "u1") }},
		{"enable", user.ActionEnable, func() error { return e.ops.Enable(ctx, "main", "u1") }},
		{"link", user.ActionLink, func() error { return e.ops.Link(ctx, "main", "u1", "google", "g1") }},
		{"unlink", user.ActionUnlink, func() error { return e.ops.Unlink(ctx, "main", "u1", "google", "g1") }},
		{"delete", user.ActionDelete, func() error { return e.ops.Delete(ctx, "main", "u1") }},
	}
	for i, s := range steps {
		e.clock.Advance(time.Second) // audit rows sort by time
		if err := s.run(); err != nil {
			t.Fatalf("%s: %v", s.name, err)
		}
		evs := e.events(t)
		if len(evs) != i+1 || evs[i].Action != s.action || evs[i].Actor != "admin" {
			t.Fatalf("%s: events = %+v", s.name, evs)
		}
	}
	if _, err := e.ops.Get(ctx, "main", "u1"); !errors.Is(err, admin.ErrNotFound) {
		t.Fatalf("deleted user: %v", err)
	}
	if n := strings.Count(e.log.String(), `"audit":true`); n != len(steps) {
		t.Fatalf("%d audit lines, want %d", n, len(steps))
	}
}

// Covers: FR-23 (part)
// Acceptance: User admin (part)
func TestLinkErrors(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.addUser(t, "u1", "a@example.org", true)
	e.addUser(t, "u2", "b@example.org", true)
	if err := e.ops.Link(ctx, "main", "u1", "google", "g1"); err != nil {
		t.Fatal(err)
	}
	if err := e.ops.Link(ctx, "main", "u2", "google", "g1"); !errors.Is(err, admin.ErrConflict) {
		t.Fatalf("linked identity: %v", err)
	}
	if err := e.ops.Link(ctx, "main", "u1", "", "g1"); !errors.Is(err, admin.ErrInvalid) {
		t.Fatalf("empty provider: %v", err)
	}
	if err := e.ops.Link(ctx, "main", "u1", "google", ""); !errors.Is(err, admin.ErrInvalid) {
		t.Fatalf("empty subject: %v", err)
	}
	if err := e.ops.Unlink(ctx, "main", "u2", "google", "g1"); !errors.Is(err, admin.ErrNotFound) {
		t.Fatalf("other user's identity: %v", err)
	}
	if err := e.ops.Link(ctx, "main", "nope", "google", "g9"); !errors.Is(err, admin.ErrNotFound) {
		t.Fatalf("unknown user: %v", err)
	}
	if err := e.ops.Disable(ctx, "other", "u1"); !errors.Is(err, admin.ErrNotFound) {
		t.Fatalf("unknown realm: %v", err)
	}
}

// Covers: FR-24 (part)
// Acceptance: Backup (part)
func TestBackupWritesSnapshotAndRotates(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	dir := t.TempDir()
	e.addUser(t, "u1", "a@example.org", true)
	p1, err := e.ops.Backup(ctx, dir, 1)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(p1) != dir || !strings.HasPrefix(filepath.Base(p1), "featherauth-"+e.clock.Now().Local().Format("20060102-1504")) {
		t.Fatalf("path = %s", p1)
	}
	e.clock.Advance(time.Minute)
	if _, err := e.ops.Backup(ctx, dir, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := e.ops.Backup(ctx, dir, 0); !errors.Is(err, admin.ErrInvalid) {
		t.Fatalf("keep 0: %v", err)
	}
}

const importFile = `[
 {"id":"imp1","email":"Ann@Example.org","email_verified":true,"name":"Ann","identities":[{"provider":"google","subject":"g1"}]},
 {"email":"bob@example.org","email_verified":false,"name":"Bob","disabled":true,"identities":[{"provider":"github","subject":"h1"}]},
 {"email":"cy@example.org","email_verified":true,"name":"Cy","identities":[]}
]`

// Covers: FR-27 (part)
// Acceptance: Import (part)
func TestImport(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	rep, err := e.ops.Import(ctx, "main", strings.NewReader(importFile), admin.ImportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Created != 2 || rep.Existing != 0 || len(rep.Skipped) != 1 || rep.Skipped[0] != 3 {
		t.Fatalf("report = %+v", rep)
	}
	u := e.user(t, "imp1")
	if u.Email != "Ann@Example.org" || u.EmailKey != "ann@example.org" || !u.EmailVerified || u.Name != "Ann" {
		t.Fatalf("user = %+v", u)
	}
	evs := e.events(t)
	if len(evs) != 2 || evs[0].Action != admin.ActionImport || evs[0].Actor != "admin" {
		t.Fatalf("events = %+v", evs)
	}
	got, err := e.ops.Get(ctx, "main", "imp1")
	if err != nil || len(got.Identities) != 1 || got.Identities[0].Provider != "google" {
		t.Fatalf("identities = %+v, %v", got, err)
	}

	// Again: same ids, nothing new.
	rep, err = e.ops.Import(ctx, "main", strings.NewReader(importFile), admin.ImportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Created != 0 || rep.Existing != 2 || len(rep.Skipped) != 1 || len(e.events(t)) != 2 {
		t.Fatalf("second report = %+v", rep)
	}
	var n int
	_ = e.st.Read(ctx, func(tx store.Tx) error {
		l, err := tx.Users().ListByEmailKey(ctx, e.realm, "bob@example.org")
		n = len(l)
		return err
	})
	if n != 1 {
		t.Fatalf("bob imported %d times", n)
	}
}

// Covers: FR-27 (part)
// Acceptance: Import without identity (part)
func TestImportWithoutIdentity(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	opts := admin.ImportOptions{IncludeWithoutIdentity: true}
	rep, err := e.ops.Import(ctx, "main", strings.NewReader(importFile), opts)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Created != 3 || len(rep.Skipped) != 0 {
		t.Fatalf("report = %+v", rep)
	}
	rep, err = e.ops.Import(ctx, "main", strings.NewReader(importFile), opts)
	if err != nil || rep.Created != 0 || rep.Existing != 3 {
		t.Fatalf("second report = %+v, %v", rep, err)
	}
}

// Covers: FR-27 (part)
// Acceptance: Import (part)
func TestImportWritesNothingOnFailure(t *testing.T) {
	good := `{"email":"ok@example.org","email_verified":true,"identities":[{"provider":"google","subject":"g1"}]}`
	tests := []struct {
		name string
		file string
		want error
	}{
		{"not json", `{`, admin.ErrInvalid},
		{"not a list", `{"email":"a@b"}`, admin.ErrInvalid},
		{"empty provider", `[` + good + `,{"email":"a@b","identities":[{"provider":"","subject":"x"}]}]`, admin.ErrInvalid},
		{"empty subject", `[` + good + `,{"email":"a@b","identities":[{"provider":"github","subject":""}]}]`, admin.ErrInvalid},
		{"duplicate id", `[{"id":"d","email":"a@b","identities":[{"provider":"github","subject":"1"}]},{"id":"d","email":"c@d","identities":[{"provider":"github","subject":"2"}]}]`, admin.ErrInvalid},
		{"duplicate identity", `[` + good + `,{"email":"c@d","identities":[{"provider":"google","subject":"g1"}]}]`, admin.ErrInvalid},
		{"two verified holders in file", `[` + good + `,{"email":"OK@example.org","email_verified":true,"identities":[{"provider":"github","subject":"2"}]}]`, admin.ErrInvalid},
		{"verified without email", `[` + good + `,{"email_verified":true,"identities":[{"provider":"github","subject":"2"}]}]`, admin.ErrInvalid},
		{"verified holder in database", `[` + good + `,{"email":"HELD@example.org","email_verified":true,"identities":[{"provider":"github","subject":"2"}]}]`, admin.ErrConflict},
		{"identity of another user", `[` + good + `,{"id":"newid","email":"q@example.org","identities":[{"provider":"apple","subject":"taken"}]}]`, admin.ErrConflict},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			ctx := context.Background()
			e.addUser(t, "held", "held@example.org", true)
			e.addUser(t, "owner", "owner@example.org", false)
			if err := e.ops.Link(ctx, "main", "owner", "apple", "taken"); err != nil {
				t.Fatal(err)
			}
			before := len(e.events(t))
			_, err := e.ops.Import(ctx, "main", strings.NewReader(tc.file), admin.ImportOptions{})
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			var n int
			_ = e.st.Read(ctx, func(tx store.Tx) error {
				l, err := tx.Users().ListByEmailKey(ctx, e.realm, "ok@example.org")
				n = len(l)
				return err
			})
			if n != 0 || len(e.events(t)) != before {
				t.Fatalf("failed import wrote %d users, %d events", n, len(e.events(t))-before)
			}
		})
	}
}

// Covers: FR-27 (part)
// Acceptance: Import (part)
func TestImportCreatesTheRealmRow(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	_, err := e.ops.Import(ctx, "fresh", strings.NewReader(`[{"email":"a@b","identities":[{"provider":"g","subject":"1"}]}]`), admin.ImportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	_ = e.st.Read(ctx, func(tx store.Tx) error {
		_, err := tx.Realms().Find(ctx, "fresh")
		found = err == nil
		return nil
	})
	if !found {
		t.Fatal("realm row not created")
	}
}

// Covers: FR-23 (part), FR-24 (part)
// Acceptance: User admin (part)
func TestSecondStoreOnTheSameFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "featherauth.db")
	ctx := context.Background()
	service, err := store.Open(ctx, testutil.DatabaseConfig(path), config.DatabaseSecrets{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })
	cli, err := store.Open(ctx, testutil.DatabaseConfig(path), config.DatabaseSecrets{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cli.Close() })

	srv, cmd := wire(t, service), wire(t, cli)
	for i := 0; i < 20; i++ {
		srv.addUser(t, "s"+string(rune('a'+i)), "", false)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 100)
	wg.Add(2)
	go func() { // the service: reads and writes
		defer wg.Done()
		for i := 0; i < 20; i++ {
			id := "s" + string(rune('a'+i))
			errs <- srv.st.Write(ctx, func(tx store.Tx) error {
				u, err := tx.Users().Get(ctx, srv.realm, store.UserID(id))
				if err != nil {
					return err
				}
				u.Name = "svc"
				return tx.Users().Update(ctx, u)
			})
			errs <- srv.st.Read(ctx, func(tx store.Tx) error {
				_, err := tx.Users().Get(ctx, srv.realm, store.UserID(id))
				return err
			})
		}
	}()
	go func() { // the CLI: the admin operations through the second store
		defer wg.Done()
		for i := 0; i < 20; i++ {
			id := store.UserID("s" + string(rune('a'+i)))
			_, err := cmd.ops.Update(ctx, "main", id, admin.Fields{Email: ptr("x@example.org")})
			errs <- err
			errs <- cmd.ops.Disable(ctx, "main", id)
		}
	}()
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Covers: FR-27 (part)
// Acceptance: Import (part)
func TestImportValidationRows(t *testing.T) {
	id := `"identities":[{"provider":"google","subject":"g1"}]`
	tests := []struct {
		name string
		file string
	}{
		{"id with spaces", `[{"id":" x","email":"a@b",` + id + `}]`},
		{"trailing data", `[{"email":"a@b",` + id + `}] []`},
		{"no identity and no email", `[{"name":"x","identities":[]}]`},
		{"no identities field and no email", `[{"name":"x"}]`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			_, err := e.ops.Import(context.Background(), "main", strings.NewReader(tc.file), admin.ImportOptions{IncludeWithoutIdentity: true})
			if !errors.Is(err, admin.ErrInvalid) {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

// Covers: FR-27 (part)
// Acceptance: Import (part)
func TestImportReportsEverySkippedRow(t *testing.T) {
	e := newEnv(t)
	file := `[
 {"email":"a@example.org"},
 {"email":"b@example.org","identities":[{"provider":"google","subject":"1"}]},
 {"email":"c@example.org","identities":[]},
 {"email":"d@example.org","identities":[{"provider":"google","subject":"2"}]},
 {"email":"e@example.org"}
]`
	rep, err := e.ops.Import(context.Background(), "main", strings.NewReader(file), admin.ImportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Created != 2 || len(rep.Skipped) != 3 || rep.Skipped[0] != 1 || rep.Skipped[1] != 3 || rep.Skipped[2] != 5 {
		t.Fatalf("report = %+v", rep)
	}
}

// Covers: FR-27 (part)
// Acceptance: Import (part)
func TestImportMatchesExistingUsers(t *testing.T) {
	ctx := context.Background()
	t.Run("by id, whatever its identities", func(t *testing.T) {
		e := newEnv(t)
		e.addUser(t, "keep", "keep@example.org", true)
		file := `[{"id":"keep","email":"changed@example.org","name":"Changed","identities":[{"provider":"github","subject":"new"}]}]`
		rep, err := e.ops.Import(ctx, "main", strings.NewReader(file), admin.ImportOptions{})
		if err != nil || rep.Existing != 1 || rep.Created != 0 {
			t.Fatalf("report = %+v, %v", rep, err)
		}
		rec, err := e.ops.Get(ctx, "main", "keep")
		if err != nil || rec.User.Email != "keep@example.org" || rec.User.Name != "Name keep" || len(rec.Identities) != 0 {
			t.Fatalf("user changed: %+v, %v", rec, err)
		}
	})
	t.Run("no identities, by email held by a user with identities", func(t *testing.T) {
		e := newEnv(t)
		e.addUser(t, "holder", "Held@Example.org", false)
		if err := e.ops.Link(ctx, "main", "holder", "google", "g1"); err != nil {
			t.Fatal(err)
		}
		file := `[{"email":"held@example.org"}]`
		rep, err := e.ops.Import(ctx, "main", strings.NewReader(file), admin.ImportOptions{IncludeWithoutIdentity: true})
		if err != nil || rep.Existing != 1 || rep.Created != 0 {
			t.Fatalf("report = %+v, %v", rep, err)
		}
	})
	t.Run("by identity without id", func(t *testing.T) {
		e := newEnv(t)
		e.addUser(t, "u1", "a@example.org", false)
		if err := e.ops.Link(ctx, "main", "u1", "google", "g1"); err != nil {
			t.Fatal(err)
		}
		file := `[{"email":"z@example.org","identities":[{"provider":"google","subject":"g1"}]}]`
		rep, err := e.ops.Import(ctx, "main", strings.NewReader(file), admin.ImportOptions{})
		if err != nil || rep.Existing != 1 {
			t.Fatalf("report = %+v, %v", rep, err)
		}
	})
}

// Covers: FR-27 (part)
// Acceptance: Import (part)
func TestImportTrimsEmailAndNeedsRealmName(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	file := `[{"id":"t1","email":"  Pad@Example.org ","identities":[{"provider":"google","subject":"g1"}]}]`
	if _, err := e.ops.Import(ctx, "main", strings.NewReader(file), admin.ImportOptions{}); err != nil {
		t.Fatal(err)
	}
	if u := e.user(t, "t1"); u.Email != "Pad@Example.org" || u.EmailKey != "pad@example.org" {
		t.Fatalf("user = %+v", u)
	}
	// The caller checks the realm against the configuration; an empty name
	// is refused here so no nameless realm row can be made.
	if _, err := e.ops.Import(ctx, "", strings.NewReader(`[]`), admin.ImportOptions{}); !errors.Is(err, admin.ErrInvalid) {
		t.Fatalf("empty realm: %v", err)
	}
}

// Covers: SEC-13 (part)
func TestRecordAndFieldsLogNoEmail(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.addUser(t, "u1", "secret.person@example.org", true)
	if err := e.ops.Link(ctx, "main", "u1", "google", "g1"); err != nil {
		t.Fatal(err)
	}
	rec, err := e.ops.Get(ctx, "main", "u1")
	if err != nil {
		t.Fatal(err)
	}
	f := admin.Fields{Name: ptr("Secret Name"), Email: ptr("secret.person@example.org"), EmailVerified: ptr(true)}
	var buf bytes.Buffer
	l := logx.New(&buf, 0, e.clock)
	l.Info("direct", "record", rec, "fields", f)
	l.Info("nested", "details", map[string]any{"record": rec, "fields": f})
	out := buf.String()
	for _, bad := range []string{"secret.person", "Secret Name", "example.org"} {
		if strings.Contains(out, bad) {
			t.Fatalf("log holds %q: %s", bad, out)
		}
	}
	if !strings.Contains(out, "u1") || !strings.Contains(out, "email_verified") {
		t.Fatalf("log lacks ids or field names: %s", out)
	}
}

// A conflict found while writing, in a realm the import creates, leaves
// neither the realm row nor any user, not even those of earlier rows.
//
// Covers: FR-27 (part)
// Acceptance: Import (part)
func TestImportConflictInANewRealmLeavesNothing(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.addUser(t, "taken", "taken@example.org", true) // an id of realm "main"
	file := `[
 {"id":"first","email":"first@example.org","identities":[{"provider":"google","subject":"g1"}]},
 {"id":"taken","email":"other@example.org","identities":[{"provider":"google","subject":"g2"}]}
]`
	_, err := e.ops.Import(ctx, "fresh", strings.NewReader(file), admin.ImportOptions{})
	if !errors.Is(err, admin.ErrConflict) {
		t.Fatalf("err = %v", err)
	}
	err = e.st.Read(ctx, func(tx store.Tx) error {
		if _, err := tx.Realms().Find(ctx, "fresh"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("realm row left behind: %v", err)
		}
		for _, id := range []string{"first"} {
			if _, err := tx.Users().Get(ctx, e.realm, store.UserID(id)); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("user %s left behind: %v", id, err)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(e.events(t)) != 0 || strings.Contains(e.log.String(), `"audit":true`) {
		t.Fatal("a failed import wrote or logged an audit row")
	}
	// The id of the first row is free again: a user left behind would conflict.
	rep, err := e.ops.Import(ctx, "fresh", strings.NewReader(`[{"id":"first","email":"first@example.org","identities":[{"provider":"google","subject":"g1"}]}]`), admin.ImportOptions{})
	if err != nil || rep.Created != 1 {
		t.Fatalf("retry: %+v, %v", rep, err)
	}
}

func (e *env) addToken(t *testing.T, id, userID string) {
	t.Helper()
	ctx := context.Background()
	err := e.st.Write(ctx, func(tx store.Tx) error {
		return tx.RefreshTokens().Insert(ctx, store.RefreshToken{
			ID: store.RefreshTokenID(id), RealmID: e.realm, UserID: store.UserID(userID), ClientID: "app",
			TokenHash: secure.HashOf(id), SessionID: store.SessionID("s-" + id),
			SessionStartedAt: start, AuthTime: start, ExpiresAt: start.Add(time.Hour), CreatedAt: start,
		})
	})
	if err != nil {
		t.Fatal(err)
	}
}

func (e *env) tokenRevoked(t *testing.T, id string) bool {
	t.Helper()
	var revoked bool
	err := e.st.Read(context.Background(), func(tx store.Tx) error {
		rt, err := tx.RefreshTokens().FindByID(context.Background(), e.realm, store.RefreshTokenID(id))
		revoked = !rt.RevokedAt.IsZero()
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return revoked
}

// Update with Disabled changes the fields and disables or enables in one
// transaction, with an audit row for each.
//
// Covers: FR-23 (part)
// Acceptance: User admin (part)
func TestUpdateWithDisabledIsOneTransaction(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.addUser(t, "u1", "ann@example.org", true)
	e.addToken(t, "rt1", "u1")

	e.clock.Advance(time.Hour)
	if _, err := e.ops.Update(ctx, "main", "u1", admin.Fields{Name: ptr("Anna"), Disabled: ptr(true)}); err != nil {
		t.Fatal(err)
	}
	u := e.user(t, "u1")
	if u.Name != "Anna" || u.DisabledAt.IsZero() || !e.tokenRevoked(t, "rt1") {
		t.Fatalf("user %+v, token revoked %v", u, e.tokenRevoked(t, "rt1"))
	}
	var acts []string
	for _, ev := range e.events(t) {
		if ev.Actor != "admin" || ev.UserID != "u1" {
			t.Fatalf("event %+v", ev)
		}
		acts = append(acts, ev.Action)
	}
	sort.Strings(acts)
	if strings.Join(acts, ",") != "user.disable,user.update" {
		t.Fatalf("actions %v", acts)
	}

	// Disabled alone is a valid update; already disabled changes and audits nothing.
	e.clock.Advance(time.Hour)
	if _, err := e.ops.Update(ctx, "main", "u1", admin.Fields{Disabled: ptr(true)}); err != nil || len(e.events(t)) != 2 {
		t.Fatalf("second disable: %v, %d events", err, len(e.events(t)))
	}
	if _, err := e.ops.Update(ctx, "main", "u1", admin.Fields{Disabled: ptr(false)}); err != nil {
		t.Fatal(err)
	}
	if !e.user(t, "u1").DisabledAt.IsZero() || e.lastEvent(t).Action != "user.enable" {
		t.Fatal("not enabled and audited")
	}
	// Enabling does not bring the revoked session back.
	if !e.tokenRevoked(t, "rt1") {
		t.Fatal("the session came back")
	}
}

// A failure in an update with Disabled leaves nothing changed.
//
// Covers: FR-23 (part)
// Acceptance: User admin (part)
func TestUpdateWithDisabledFailureChangesNothing(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.addUser(t, "u1", "ann@example.org", true)
	e.addUser(t, "u2", "bob@example.org", true)
	e.addToken(t, "rt2", "u2")
	_, err := e.ops.Update(ctx, "main", "u2", admin.Fields{Name: ptr("Robert"), Email: ptr("ann@example.org"), EmailVerified: ptr(true), Disabled: ptr(true)})
	if !errors.Is(err, admin.ErrConflict) {
		t.Fatalf("err = %v", err)
	}
	u := e.user(t, "u2")
	if u.Name != "Name u2" || u.Email != "bob@example.org" || !u.DisabledAt.IsZero() || e.tokenRevoked(t, "rt2") || len(e.events(t)) != 0 {
		t.Fatalf("a failed update changed something: %+v, %d events", u, len(e.events(t)))
	}
	if strings.Contains(e.log.String(), `"audit":true`) {
		t.Fatal("a failed update logged an audit line")
	}
}

// Covers: FR-27 (part)
// Acceptance: Import (part)
func TestImportIgnoresALeadingByteOrderMark(t *testing.T) {
	e := newEnv(t)
	file := "\xef\xbb\xbf" + `[{"id":"bom1","email":"a@example.org","identities":[{"provider":"google","subject":"g1"}]}]`
	rep, err := e.ops.Import(context.Background(), "main", strings.NewReader(file), admin.ImportOptions{})
	if err != nil || rep.Created != 1 {
		t.Fatalf("%+v, %v", rep, err)
	}
}

// Update says when a changed email cleared the verification, so a caller does
// not have to read the user again.
//
// Covers: FR-23 (part)
// Acceptance: User admin (part)
func TestUpdateReportsAClearedVerification(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name    string
		fields  admin.Fields
		cleared bool
	}{
		{"new address", admin.Fields{Email: ptr("new@example.org")}, true},
		{"new address, verified given", admin.Fields{Email: ptr("new@example.org"), EmailVerified: ptr(true)}, false},
		{"new address, unverified given", admin.Fields{Email: ptr("new@example.org"), EmailVerified: ptr(false)}, false},
		{"only the case differs", admin.Fields{Email: ptr("ANN@example.org")}, false},
		{"name only", admin.Fields{Name: ptr("Anna")}, false},
		{"nothing changes", admin.Fields{Name: ptr("Name u1")}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			e.addUser(t, "u1", "ann@example.org", true)
			res, err := e.ops.Update(ctx, "main", "u1", tc.fields)
			if err != nil || res.VerificationCleared != tc.cleared {
				t.Fatalf("result %+v, %v; want cleared %v", res, err, tc.cleared)
			}
		})
	}
	// A user that was not verified has nothing to clear.
	e := newEnv(t)
	e.addUser(t, "u1", "ann@example.org", false)
	if res, err := e.ops.Update(ctx, "main", "u1", admin.Fields{Email: ptr("new@example.org")}); err != nil || res.VerificationCleared {
		t.Fatalf("result %+v, %v", res, err)
	}
}

// A deadlock aborts the first run of Update after it has changed the user and
// audited it. The result and the audit rows are those of the run that commits:
// one update, one audit row, and the cleared verification reported once.
// Covers: FR-35 (part)
func TestUpdateCountsTheRunThatCommits(t *testing.T) {
	ctx := context.Background()
	f := testutil.NewFaultStore(testutil.NewStore(t))
	e := wire(t, f)
	e.addUser(t, "u1", "ann@example.org", true)
	f.AbortRuns(1, &pgconn.PgError{Code: "40P01"})
	res, err := e.ops.Update(ctx, "main", "u1", admin.Fields{Email: ptr("new@example.org")})
	if err != nil {
		t.Fatalf("Update = %v, want success on the second run", err)
	}
	if !res.VerificationCleared {
		t.Fatalf("result %+v, want the cleared verification of the run that commits", res)
	}
	if n := len(e.events(t)); n != 1 {
		t.Fatalf("%d audit rows, want 1 (the first run's row is not kept)", n)
	}
}

package store_test

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/logx"
	"github.com/yyudhistira/featherauth/internal/secure"
	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/testutil"
)

// localNoon is 12:00 on 1 March 2026 in the local time zone, as a clock value.
func localNoon() time.Time { return time.Date(2026, 3, 1, 12, 0, 0, 0, time.Local).UTC() }

type schedEnv struct {
	st    store.Store
	clock *clock.Fake
	log   *bytes.Buffer
	dir   string
}

func newSchedEnv(t *testing.T) *schedEnv {
	t.Helper()
	c := clock.NewFake(localNoon())
	var buf bytes.Buffer
	return &schedEnv{st: testutil.NewStore(t), clock: c, log: &buf, dir: filepath.Join(t.TempDir(), "backups")}
}

func (e *schedEnv) start(t *testing.T, at string, keep int) *store.BackupSchedule {
	t.Helper()
	b, err := store.StartBackups(e.st, config.BackupConfig{Directory: e.dir, At: at, Keep: keep}, e.clock, logx.New(e.log, slog.LevelInfo, e.clock))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Stop)
	return b
}

func (e *schedEnv) files(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(e.dir)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	var names []string
	for _, f := range entries {
		names = append(names, f.Name())
	}
	return names
}

func want(names ...string) string { return strings.Join(names, ",") }

// Covers: FR-24 (part)
func TestBackupScheduleWritesOneSnapshotPerDayAtTheSetMinute(t *testing.T) {
	e := newSchedEnv(t)
	e.start(t, "03:00", 7)

	e.clock.Advance(14*time.Hour + 59*time.Minute) // 02:59 the next day
	if got := e.files(t); len(got) != 0 {
		t.Fatalf("a snapshot before the set minute: %v", got)
	}
	e.clock.Advance(time.Minute) // 03:00
	if got := want(e.files(t)...); got != want("featherauth-20260302-0300.db") {
		t.Fatalf("files %s", got)
	}
	e.clock.Advance(23 * time.Hour) // later the same day: nothing more
	if got := e.files(t); len(got) != 1 {
		t.Fatalf("files %v", got)
	}
	e.clock.Advance(48 * time.Hour) // two more days
	if got := want(e.files(t)...); got != want("featherauth-20260302-0300.db", "featherauth-20260303-0300.db", "featherauth-20260304-0300.db") {
		t.Fatalf("files %s", got)
	}
	// One audit-free information line for each snapshot, naming the file.
	if n := strings.Count(e.log.String(), "backup written"); n != 3 {
		t.Fatalf("%d log lines: %s", n, e.log.String())
	}
}

// Covers: FR-24 (part)
func TestBackupScheduleOnTheSameDayWhenTheMinuteIsStillAhead(t *testing.T) {
	e := newSchedEnv(t)
	e.start(t, "18:30", 7)
	e.clock.Advance(6*time.Hour + 30*time.Minute)
	if got := want(e.files(t)...); got != want("featherauth-20260301-1830.db") {
		t.Fatalf("files %s", got)
	}
}

// Covers: FR-24 (part)
func TestBackupScheduleKeepsTheNewestSnapshots(t *testing.T) {
	e := newSchedEnv(t)
	e.start(t, "03:00", 2)
	e.clock.Advance(5 * 24 * time.Hour)
	if got := want(e.files(t)...); got != want("featherauth-20260305-0300.db", "featherauth-20260306-0300.db") {
		t.Fatalf("files %s", got)
	}
}

// Covers: FR-24 (part)
func TestBackupScheduleIsOffWithoutADirectoryOrATime(t *testing.T) {
	for _, cfg := range []config.BackupConfig{
		{Directory: "", At: "03:00", Keep: 7},
		{Directory: "x", At: "", Keep: 7},
	} {
		e := newSchedEnv(t)
		cfg.Directory = strings.Replace(cfg.Directory, "x", e.dir, 1)
		b, err := store.StartBackups(e.st, cfg, e.clock, logx.New(e.log, slog.LevelInfo, e.clock))
		if err != nil {
			t.Fatal(err)
		}
		e.clock.Advance(72 * time.Hour)
		b.Stop()
		if got := e.files(t); len(got) != 0 || e.log.Len() != 0 {
			t.Fatalf("%+v wrote %v, logged %q", cfg, got, e.log.String())
		}
	}
}

// Covers: FR-24 (part)
func TestBackupScheduleRejectsABadTime(t *testing.T) {
	e := newSchedEnv(t)
	for _, at := range []string{"3:00", "24:00", "03:60", "noon", "03:00 "} {
		if _, err := store.StartBackups(e.st, config.BackupConfig{Directory: e.dir, At: at, Keep: 7}, e.clock, nil); err == nil {
			t.Errorf("at %q accepted", at)
		}
	}
	if _, err := store.StartBackups(e.st, config.BackupConfig{Directory: e.dir, At: "03:00", Keep: 0}, e.clock, nil); err == nil {
		t.Error("keep 0 accepted")
	}
}

// A failed snapshot is logged and never stops the schedule or the process.
//
// Covers: FR-24 (part)
func TestBackupScheduleSurvivesAFailedSnapshot(t *testing.T) {
	e := newSchedEnv(t)
	// The directory is a file, so the first snapshot cannot be written.
	if err := os.WriteFile(e.dir, []byte("in the way"), 0o600); err != nil {
		t.Fatal(err)
	}
	e.start(t, "03:00", 7)
	e.clock.Advance(15 * time.Hour)
	if !strings.Contains(e.log.String(), `"level":"ERROR"`) || !strings.Contains(e.log.String(), "backup failed") || !strings.Contains(e.log.String(), `"error"`) {
		t.Fatalf("log %q", e.log.String())
	}
	// Once the obstacle is gone the next day's snapshot is written.
	if err := os.Remove(e.dir); err != nil {
		t.Fatal(err)
	}
	e.clock.Advance(24 * time.Hour)
	if got := want(e.files(t)...); got != want("featherauth-20260303-0300.db") {
		t.Fatalf("files %s", got)
	}
}

// A snapshot of the same minute that exists already (a manual backup, a
// restart) is a logged failure that leaves the old file alone.
//
// Covers: FR-24 (part)
func TestBackupScheduleKeepsAnExistingSnapshotOfTheSameMinute(t *testing.T) {
	e := newSchedEnv(t)
	if err := os.MkdirAll(e.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	old := filepath.Join(e.dir, "featherauth-20260302-0300.db")
	if err := os.WriteFile(old, []byte("earlier"), 0o600); err != nil {
		t.Fatal(err)
	}
	e.start(t, "03:00", 7)
	e.clock.Advance(15 * time.Hour)
	if b, _ := os.ReadFile(old); string(b) != "earlier" {
		t.Fatal("the existing snapshot was replaced")
	}
	if !strings.Contains(e.log.String(), "backup failed") {
		t.Fatalf("log %q", e.log.String())
	}
	e.clock.Advance(24 * time.Hour)
	if got := e.files(t); len(got) != 2 {
		t.Fatalf("files %v", got)
	}
}

// Three days of the fake clock with backup.keep 2, and the snapshot of the
// second day failing, once because one of that minute exists already and once
// because the snapshot writer fails (a store test hook makes VACUUM INTO fail, as
// a full disk would): the two newest are kept and the older deleted, the failure
// is logged at error with the reason, the older snapshot is unchanged during it,
// the store keeps serving and the next day's snapshot is written.
//
// Covers: FR-59
// Acceptance: Snapshot retention
func TestBackupScheduleRetentionWithAFailedDay(t *testing.T) {
	if d, diags := config.DecodeDatabase("database.yaml", []byte("driver: sqlite\n")); len(diags) != 0 || d.Backup.Keep != 7 {
		t.Fatalf("the default backup.keep is %v (%v), want 7", d.Backup.Keep, diags)
	}
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		// fail makes the second day's snapshot fail; restore undoes it.
		fail    func(t *testing.T, e *schedEnv, second string)
		restore func(t *testing.T, e *schedEnv)
		after   func(t *testing.T, second string)
	}{
		{
			name: "a snapshot of that minute exists",
			fail: func(t *testing.T, _ *schedEnv, second string) {
				if err := os.WriteFile(second, []byte("earlier"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			restore: func(*testing.T, *schedEnv) {},
			after: func(t *testing.T, second string) {
				if b, _ := os.ReadFile(second); string(b) != "earlier" {
					t.Fatal("the existing file of the failed minute was replaced")
				}
			},
		},
		{
			name: "the snapshot writer fails",
			fail: func(t *testing.T, e *schedEnv, _ string) {
				if err := store.SetQueryOnlyForTest(ctx, e.st, true); err != nil {
					t.Fatal(err)
				}
			},
			restore: func(t *testing.T, e *schedEnv) {
				if err := store.SetQueryOnlyForTest(ctx, e.st, false); err != nil {
					t.Fatal(err)
				}
			},
			after: func(t *testing.T, second string) {
				if _, err := os.Stat(second); err == nil {
					t.Error("a failed snapshot left a file")
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newSchedEnv(t)
			e.start(t, "03:00", 2)
			first := filepath.Join(e.dir, "featherauth-20260302-0300.db")
			second := filepath.Join(e.dir, "featherauth-20260303-0300.db")
			third := filepath.Join(e.dir, "featherauth-20260304-0300.db")

			e.clock.Advance(15 * time.Hour) // 03:00 of the first day
			if got := want(e.files(t)...); got != want("featherauth-20260302-0300.db") {
				t.Fatalf("files %s", got)
			}
			before, err := os.ReadFile(first)
			if err != nil {
				t.Fatal(err)
			}

			tc.fail(t, e, second)
			e.log.Reset()
			e.clock.Advance(24 * time.Hour)
			logged := e.log.String()
			if !strings.Contains(logged, `"level":"ERROR"`) || !strings.Contains(logged, "backup failed") || !strings.Contains(logged, `"error":"`) {
				t.Fatalf("the failure is not logged at error with its reason: %q", logged)
			}
			if after, err := os.ReadFile(first); err != nil || !bytes.Equal(after, before) {
				t.Fatalf("the older snapshot changed during the failure: %v", err)
			}
			tc.after(t, second)
			if err := e.st.Ping(ctx); err != nil {
				t.Fatalf("the store does not serve after the failure: %v", err)
			}
			tc.restore(t, e)

			// The next day's snapshot is written and only the two newest stay.
			e.clock.Advance(24 * time.Hour)
			got := want(e.files(t)...)
			if tc.name == "the snapshot writer fails" {
				// The second day has no snapshot: the first and the third remain.
				if got != want("featherauth-20260302-0300.db", "featherauth-20260304-0300.db") {
					t.Fatalf("files %s, want the first and the third day's", got)
				}
				return
			}
			if got != want("featherauth-20260303-0300.db", "featherauth-20260304-0300.db") {
				t.Fatalf("files %s, want the two newest", got)
			}
			if _, err := os.Stat(first); !os.IsNotExist(err) {
				t.Errorf("the oldest snapshot was not deleted: %v", err)
			}
			if _, err := os.Stat(third); err != nil {
				t.Errorf("the third day's snapshot is missing: %v", err)
			}
		})
	}
}

// Covers: FR-24 (part)
func TestBackupScheduleStops(t *testing.T) {
	e := newSchedEnv(t)
	b := e.start(t, "03:00", 7)
	b.Stop()
	b.Stop() // twice is fine
	e.clock.Advance(72 * time.Hour)
	if got := e.files(t); len(got) != 0 {
		t.Fatalf("a stopped schedule wrote %v", got)
	}
}

// A scheduled snapshot taken while logins write opens on a clean host, with
// the users and the refresh tokens in it.
//
// Covers: FR-24 (part)
// Acceptance: Backup (part)
func TestScheduledSnapshotRestoresOnACleanHost(t *testing.T) {
	e := newSchedEnv(t)
	ctx := context.Background()
	now := e.clock.Now()
	seed := func(i int) error {
		id := string(rune('a' + i))
		return e.st.Write(ctx, func(tx store.Tx) error {
			if i == 0 {
				if _, err := tx.Realms().Ensure(ctx, "main", "r1", now); err != nil {
					return err
				}
			}
			if err := tx.Users().Create(ctx, store.User{ID: store.UserID("u" + id), RealmID: "r1", Name: id, CreatedAt: now, UpdatedAt: now}); err != nil {
				return err
			}
			return tx.RefreshTokens().Insert(ctx, store.RefreshToken{
				ID: store.RefreshTokenID("rt" + id), RealmID: "r1", UserID: store.UserID("u" + id), ClientID: "app",
				TokenHash: secure.HashOf("tok" + id), SessionID: store.SessionID("s" + id),
				SessionStartedAt: now, AuthTime: now, ExpiresAt: now.Add(time.Hour), CreatedAt: now,
			})
		})
	}
	for i := 0; i < 3; i++ {
		if err := seed(i); err != nil {
			t.Fatal(err)
		}
	}
	e.start(t, "03:00", 7)

	// Logins keep writing while the snapshot is taken.
	stop := make(chan struct{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	var first error
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 3; i < 200; i++ {
			select {
			case <-stop:
				return
			default:
			}
			if err := seed(i % 26); err != nil && !strings.Contains(err.Error(), "conflict") {
				mu.Lock()
				if first == nil {
					first = err
				}
				mu.Unlock()
			}
		}
	}()
	e.clock.Advance(15 * time.Hour)
	close(stop)
	wg.Wait()
	if first != nil {
		t.Fatal(first)
	}

	files := e.files(t)
	if len(files) != 1 {
		t.Fatalf("files %v", files)
	}
	// "Restore": copy the snapshot to the path of a clean host and open it.
	raw, err := os.ReadFile(filepath.Join(e.dir, files[0]))
	if err != nil {
		t.Fatal(err)
	}
	restored := filepath.Join(t.TempDir(), "featherauth.db")
	if err := os.WriteFile(restored, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(ctx, testutil.DatabaseConfig(restored), config.DatabaseSecrets{})
	if err != nil {
		t.Fatalf("the snapshot does not open: %v", err)
	}
	defer st.Close()
	err = st.Read(ctx, func(tx store.Tx) error {
		for _, id := range []string{"a", "b", "c"} {
			u, err := tx.Users().Get(ctx, "r1", store.UserID("u"+id))
			if err != nil || u.Name != id {
				t.Errorf("user %s: %+v, %v", id, u, err)
			}
			if _, err := tx.RefreshTokens().FindByHash(ctx, "r1", secure.HashOf("tok"+id)); err != nil {
				t.Errorf("refresh token %s: %v", id, err)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

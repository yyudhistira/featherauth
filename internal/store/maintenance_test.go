package store_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/secure"
	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/testutil"
)

func TestCleanupRemovesExpiredAndKeepsLiveRows(t *testing.T) {
	s := testutil.NewStore(t)
	ctx := context.Background()
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	past, future := now.Add(-time.Second), now.Add(time.Second)

	err := s.Write(ctx, func(tx store.Tx) error {
		for id, exp := range map[string]time.Time{"req-old": past, "req-edge": now, "req-live": future} {
			if err := tx.AuthRequests().Create(ctx, store.AuthRequest{ID: store.AuthRequestID(id), RealmID: "r", ExpiresAt: exp}); err != nil {
				return err
			}
		}
		for id, exp := range map[string]time.Time{"code-old": past, "code-edge": now, "code-live": future} {
			if err := tx.AuthCodes().Create(ctx, store.AuthCode{CodeHash: secure.HashOf(id), RealmID: "r", ExpiresAt: exp}); err != nil {
				return err
			}
		}
		for id, exp := range map[string]time.Time{"h-old": past, "h-edge": now, "h-live": future} {
			if err := tx.Handoffs().Create(ctx, store.Handoff{IDHash: secure.HashOf(id), AuthRequestID: store.AuthRequestID(id), Payload: "p", ExpiresAt: exp}); err != nil {
				return err
			}
		}
		for id, exp := range map[string]time.Time{"t-old": past, "t-edge": now, "t-live": future} {
			if err := tx.RefreshTokens().Insert(ctx, store.RefreshToken{ID: store.RefreshTokenID(id), RealmID: "r", UserID: "u",
				ClientID: "c", TokenHash: secure.HashOf(id), SessionID: "s", ExpiresAt: exp}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	got, err := store.Cleanup(ctx, s, now)
	if err != nil {
		t.Fatal(err)
	}
	if want := (store.Removed{AuthRequests: 2, AuthCodes: 2, Handoffs: 2, RefreshTokens: 2}); got != want {
		t.Fatalf("Cleanup = %+v, want %+v", got, want)
	}
	for _, c := range []struct{ table, col, want string }{
		{"auth_requests", "id", "req-live"},
		{"auth_codes", "code_hash", string(secure.HashOf("code-live"))},
		{"callback_handoffs", "id_hash", string(secure.HashOf("h-live"))},
		{"refresh_tokens", "id", "t-live"},
	} {
		var ids []string
		err := s.Read(ctx, func(tx store.Tx) error {
			rows, err := store.RawTx(tx).QueryContext(ctx, "SELECT "+c.col+" FROM "+c.table)
			if err != nil {
				return err
			}
			defer func() { _ = rows.Close() }()
			for rows.Next() {
				var id string
				if err := rows.Scan(&id); err != nil {
					return err
				}
				ids = append(ids, id)
			}
			return rows.Err()
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(ids) != 1 || ids[0] != c.want {
			t.Fatalf("%s rows = %v, want only %s", c.table, ids, c.want)
		}
	}

	again, err := store.Cleanup(ctx, s, now)
	if err != nil || again != (store.Removed{}) {
		t.Fatalf("second Cleanup = %+v, %v, want nothing", again, err)
	}
}

func TestCleanupKeepsAuditEvents(t *testing.T) {
	s := testutil.NewStore(t)
	ctx := context.Background()
	old := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := s.Write(ctx, func(tx store.Tx) error {
		return tx.Audit().Insert(ctx, store.AuditEvent{ID: "a", RealmID: "r", Actor: "system", Action: "x", CreatedAt: old})
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Cleanup(ctx, s, old.AddDate(10, 0, 0)); err != nil {
		t.Fatal(err)
	}
	var n int
	_ = s.Read(ctx, func(tx store.Tx) error {
		ev, err := tx.Audit().List(ctx, "r", old)
		n = len(ev)
		return err
	})
	if n != 1 {
		t.Fatalf("audit events after Cleanup = %d, want 1 (kept, not pruned)", n)
	}
}

func TestSnapshotNamesFileAndKeepsNewest(t *testing.T) {
	s := testutil.NewStore(t)
	ctx := context.Background()
	dir := t.TempDir()
	// Files that are not snapshots stay.
	other := filepath.Join(dir, "notes.txt")
	if err := os.WriteFile(other, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 3, 1, 3, 0, 0, 0, time.UTC)
	var last string
	for i := range 5 {
		var err error
		last, err = store.Snapshot(ctx, s, dir, start.Add(time.Duration(i)*24*time.Hour), 3)
		if err != nil {
			t.Fatal(err)
		}
	}
	if want := filepath.Join(dir, "featherauth-20260305-0300.db"); last != want {
		t.Fatalf("Snapshot returned %q, want %q", last, want)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	want := []string{"featherauth-20260303-0300.db", "featherauth-20260304-0300.db", "featherauth-20260305-0300.db", "notes.txt"}
	if fmt.Sprint(names) != fmt.Sprint(want) {
		t.Fatalf("directory = %v, want %v", names, want)
	}
}

func TestSnapshotNeverRemovesTheFileItWrote(t *testing.T) {
	// A clock that steps back (or a DST change) gives the new file an older
	// name than the ones kept.
	s := testutil.NewStore(t)
	ctx := context.Background()
	dir := t.TempDir()
	late := time.Date(2026, 3, 2, 3, 0, 0, 0, time.UTC)
	if _, err := store.Snapshot(ctx, s, dir, late, 1); err != nil {
		t.Fatal(err)
	}
	path, err := store.Snapshot(ctx, s, dir, late.Add(-24*time.Hour), 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the snapshot just written was removed: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("directory has %d files, %v, want 1 (keep is 1)", len(entries), err)
	}
}

func TestSnapshotErrors(t *testing.T) {
	s := testutil.NewStore(t)
	ctx := context.Background()
	now := time.Date(2026, 3, 1, 3, 0, 0, 0, time.UTC)
	if _, err := store.Snapshot(ctx, s, t.TempDir(), now, 0); err == nil {
		t.Fatal("keep 0 must fail")
	}
	if _, err := store.Snapshot(ctx, s, filepath.Join(t.TempDir(), "missing"), now, 1); err == nil {
		t.Fatal("a missing directory must fail")
	}
	dir := t.TempDir()
	if _, err := store.Snapshot(ctx, s, dir, now, 2); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Snapshot(ctx, s, dir, now, 2); err == nil {
		t.Fatal("a second snapshot in the same minute must fail, not overwrite")
	}
}

func TestSnapshotWhileWritesRunIsConsistent(t *testing.T) {
	// Covers: FR-24 (part)
	// Acceptance: Backup (part)
	s := testutil.NewStore(t)
	ctx := context.Background()
	started, stop := make(chan struct{}), make(chan struct{})
	var wg sync.WaitGroup
	var once sync.Once
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer once.Do(func() { close(started) }) // never leave the test waiting
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			// One transaction inserts one realm and one audit row: a consistent
			// snapshot sees equal counts.
			err := s.Write(ctx, func(tx store.Tx) error {
				id := fmt.Sprintf("%06d", i)
				if _, err := tx.Realms().Ensure(ctx, config.RealmName("realm-"+id), store.RealmID(id), time.Unix(1, 0)); err != nil {
					return err
				}
				return tx.Audit().Insert(ctx, store.AuditEvent{ID: id, RealmID: store.RealmID(id), Actor: "system", Action: "x", CreatedAt: time.Unix(1, 0)})
			})
			if err != nil {
				t.Errorf("write %d: %v", i, err)
				return
			}
			if i == 0 {
				once.Do(func() { close(started) })
			}
		}
	}()
	<-started

	dir := t.TempDir()
	base := time.Date(2026, 3, 1, 3, 0, 0, 0, time.UTC)
	var paths []string
	for i := range 5 {
		p, err := store.Snapshot(ctx, s, dir, base.Add(time.Duration(i)*time.Minute), 10)
		if err != nil {
			close(stop)
			wg.Wait()
			t.Fatal(err)
		}
		paths = append(paths, p)
	}
	close(stop)
	wg.Wait()

	for _, p := range paths {
		db := rawDB(t, p)
		var realms, events int
		if err := db.QueryRow(`SELECT COUNT(*) FROM realms`).Scan(&realms); err != nil {
			t.Fatal(err)
		}
		if err := db.QueryRow(`SELECT COUNT(*) FROM audit_events`).Scan(&events); err != nil {
			t.Fatal(err)
		}
		if realms == 0 || realms != events {
			t.Fatalf("%s: realms = %d, audit events = %d, want equal and above 0", filepath.Base(p), realms, events)
		}
		var check string
		if err := db.QueryRow(`PRAGMA integrity_check`).Scan(&check); err != nil || check != "ok" {
			t.Fatalf("%s: integrity_check = %q, %v", filepath.Base(p), check, err)
		}
	}
}

// Covers: SEC-27 (part)
// The hourly cleanup removes the provider event ids that expired at or before
// now, and keeps the live ones.
func TestCleanupRemovesExpiredProviderEventIDs(t *testing.T) {
	s := testutil.NewStore(t)
	ctx := context.Background()
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	err := s.Write(ctx, func(tx store.Tx) error {
		for id, exp := range map[string]time.Time{"old": now.Add(-time.Second), "edge": now, "live": now.Add(time.Second)} {
			if _, err := tx.ProviderEvents().Remember(ctx, "r", "apple", secure.HashOf(id), exp); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := store.Cleanup(ctx, s, now)
	if err != nil {
		t.Fatal(err)
	}
	if got.ProviderEvents != 1 {
		t.Fatalf("Cleanup removed %d provider event ids, want 1 (the one strictly past its expiry)", got.ProviderEvents)
	}
	err = s.Write(ctx, func(tx store.Tx) error {
		for id, wantNew := range map[string]bool{"old": true, "edge": false, "live": false} {
			first, err := tx.ProviderEvents().Remember(ctx, "r", "apple", secure.HashOf(id), now.Add(time.Hour))
			if err != nil {
				return err
			}
			if first != wantNew {
				t.Errorf("Remember(%s) = %v, want %v", id, first, wantNew)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// A deadlock aborts the first run of Cleanup after it has counted what it removed.
// The counts returned are those of the run that commits: each count is set by
// that run, and the rows it removed are back after the rollback, so the second
// run removes and counts them again. Nothing of the first run is carried over.
func TestCleanupCountsTheRunThatCommits(t *testing.T) {
	s := testutil.NewStore(t)
	ctx := context.Background()
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	past := now.Add(-time.Second)
	err := s.Write(ctx, func(tx store.Tx) error {
		if err := tx.AuthRequests().Create(ctx, store.AuthRequest{ID: "req-old", RealmID: "r", ExpiresAt: past}); err != nil {
			return err
		}
		if err := tx.Handoffs().Create(ctx, store.Handoff{IDHash: secure.HashOf("h"), AuthRequestID: "h", Payload: "p", ExpiresAt: past}); err != nil {
			return err
		}
		for _, id := range []string{"t-old-1", "t-old-2"} {
			if err := tx.RefreshTokens().Insert(ctx, store.RefreshToken{ID: store.RefreshTokenID(id), RealmID: "r", UserID: "u",
				ClientID: "c", TokenHash: secure.HashOf(id), SessionID: "s", ExpiresAt: past}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	f := testutil.NewFaultStore(s)
	f.AbortRuns(1, &pgconn.PgError{Code: "40P01"})
	got, err := store.Cleanup(ctx, f, now)
	if err != nil {
		t.Fatalf("Cleanup = %v, want success on the second run", err)
	}
	if want := (store.Removed{AuthRequests: 1, Handoffs: 1, RefreshTokens: 2}); got != want {
		t.Fatalf("Cleanup = %+v, want %+v", got, want)
	}
}

// Covers: SEC-36 (part)
// Acceptance: DPoP proof (part)
// The hourly cleanup removes the DPoP proofs strictly past their expiry, keeps
// the one at its expiry and the live one, and reports how many it removed.
func TestCleanupRemovesExpiredDPoPProofs(t *testing.T) {
	s := testutil.NewStore(t)
	ctx := context.Background()
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	err := s.Write(ctx, func(tx store.Tx) error {
		for id, exp := range map[string]time.Time{"old": now.Add(-time.Second), "edge": now, "live": now.Add(time.Second)} {
			if _, err := tx.DPoPProofs().Use(ctx, secure.HashOf(id), exp); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := store.Cleanup(ctx, s, now)
	if err != nil {
		t.Fatal(err)
	}
	if got.DPoPProofs != 1 {
		t.Fatalf("Cleanup removed %d DPoP proofs, want 1 (the one strictly past its expiry)", got.DPoPProofs)
	}
	err = s.Write(ctx, func(tx store.Tx) error {
		for id, wantNew := range map[string]bool{"old": true, "edge": false, "live": false} {
			first, err := tx.DPoPProofs().Use(ctx, secure.HashOf(id), now.Add(time.Hour))
			if err != nil {
				return err
			}
			if first != wantNew {
				return fmt.Errorf("Use(%s) = %v, want %v", id, first, wantNew)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// Covers: FR-45 (part), SEC-37 (part)
// Acceptance: Single sign-on start (part)
// The hourly cleanup deletes the browser sessions at or past their expiry and keeps
// the one a second before its expiry; the count is reported in SSOSessions.
func TestCleanupRemovesExpiredBrowserSessions(t *testing.T) {
	s := testutil.NewStore(t)
	ctx := context.Background()
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	err := s.Write(ctx, func(tx store.Tx) error {
		if _, err := tx.Realms().Ensure(ctx, "main", "r1", now); err != nil {
			return err
		}
		if err := tx.Users().Create(ctx, store.User{ID: "u1", RealmID: "r1", CreatedAt: now, UpdatedAt: now}); err != nil {
			return err
		}
		for id, exp := range map[string]time.Time{"old": now.Add(-time.Second), "edge": now, "live": now.Add(time.Second)} {
			if err := tx.SSOSessions().Create(ctx, store.SSOSession{
				IDHash: secure.HashOf(id), RealmID: "r1", UserID: "u1", IdentityID: "i1", Provider: "google",
				AuthTime: now, CreatedAt: now, LastUsedAt: now, ExpiresAt: exp,
			}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := store.Cleanup(ctx, s, now)
	if err != nil {
		t.Fatal(err)
	}
	if got.SSOSessions != 2 {
		t.Fatalf("Cleanup removed %d browser sessions, want 2 (the one at its expiry and the one past it)", got.SSOSessions)
	}
	err = s.Read(ctx, func(tx store.Tx) error {
		if _, err := tx.SSOSessions().Find(ctx, "r1", secure.HashOf("live")); err != nil {
			return fmt.Errorf("the live session: %w", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// The hourly job deletes every rate limit window that starts before the current
// minute, and keeps the current one with its count.
//
// Covers: FR-53 (part)
// Acceptance: Shared rate limit (part)
func TestCleanupDeletesTheRateLimitWindowsBeforeTheCurrentMinute(t *testing.T) {
	s := testutil.NewStore(t)
	ctx := context.Background()
	now := time.Date(2026, 3, 1, 12, 0, 30, 0, time.UTC)
	cur := now.Truncate(time.Minute)
	old := cur.Add(-time.Minute)
	for _, w := range []time.Time{old, cur} {
		if err := s.Write(ctx, func(tx store.Tx) error {
			_, err := tx.RateLimits().Hit(ctx, "203.0.113.7", w)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := store.Cleanup(ctx, s, now)
	if err != nil || got.RateLimits != 1 {
		t.Fatalf("Cleanup removed %+v, %v; want one rate limit window", got, err)
	}
	var n int64
	if err := s.Write(ctx, func(tx store.Tx) (err error) {
		n, err = tx.RateLimits().Hit(ctx, "203.0.113.7", cur)
		return err
	}); err != nil || n != 2 {
		t.Fatalf("the current window counts %d, %v after the job; want 2", n, err)
	}
}

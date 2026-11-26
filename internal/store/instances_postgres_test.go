//go:build postgres

package store_test

import (
	"context"
	"database/sql"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/testutil"
)

// secondPool opens another pool on the schema of db, as a second instance does.
func secondPool(t *testing.T, db *sql.DB) *sql.DB {
	t.Helper()
	var schema string
	if err := db.QueryRowContext(t.Context(), `SELECT current_schema()`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	dsn := os.Getenv(testutil.PostgresEnv)
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.RuntimeParams["search_path"] = schema
	second := stdlib.OpenDB(*cfg)
	t.Cleanup(func() { _ = second.Close() })
	return second
}

// Two instances that start at the same moment on an empty database both come up,
// and the migrations apply once: the second waits for the advisory lock of the
// first and then finds the schema current.
//
// Covers: FR-54 (part)
// Acceptance: Several instances (part)
func TestPostgresMigrationsRunOnceForTwoStartingInstances(t *testing.T) {
	first := testutil.NewPostgresDB(t)
	second := secondPool(t, first)
	var (
		wg   sync.WaitGroup
		errs [2]error
		out  [2]store.Store
	)
	for i, db := range []*sql.DB{first, second} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out[i], errs[i] = store.NewPostgres(t.Context(), db)
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("instance %d did not start: %v", i+1, err)
		}
	}
	for _, s := range out {
		_ = s.Close()
	}
}

// Two workers that claim at the same time take different notifications: the row
// one worker locks is skipped by the other, whose claim does not wait for it.
//
// Covers: FR-54 (part)
// Acceptance: Several instances (part)
func TestPostgresTwoWorkersClaimDifferentNotifications(t *testing.T) {
	ctx := t.Context()
	first := testutil.NewPostgresDB(t)
	s1, err := store.NewPostgres(ctx, first)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s1.Close() })
	s2, err := store.NewPostgres(ctx, secondPool(t, first))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s2.Close() })

	epoch := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	for _, id := range []string{"n1", "n2", "n3", "n4"} {
		if err := s1.Write(ctx, func(tx store.Tx) error {
			return tx.LogoutNotifications().Enqueue(ctx, store.LogoutNotification{
				ID: store.LogoutNotificationID(id), RealmID: "r1", ClientID: "app", UserID: "u1",
				SessionID: store.SessionID("s-" + id), NextAttemptAt: epoch, CreatedAt: epoch,
			})
		}); err != nil {
			t.Fatal(err)
		}
	}

	// Worker one claims two rows and holds their locks until worker two has claimed.
	taken := make(chan []store.LogoutNotification, 1)
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- s1.Write(ctx, func(tx store.Tx) error {
			rows, err := tx.LogoutNotifications().Claim(ctx, epoch, 2)
			taken <- rows
			<-release
			return err
		})
	}()
	firstRows := <-taken

	// Worker two must not wait for worker one's locks. Without SKIP LOCKED its claim
	// blocks on the first row, so a deadline turns the hang into a failure; the
	// release of worker one is then sent first, so that its transaction ends.
	var secondRows []store.LogoutNotification
	claimCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	err = s2.Write(claimCtx, func(tx store.Tx) (err error) {
		secondRows, err = tx.LogoutNotifications().Claim(claimCtx, epoch, 4)
		return err
	})
	close(release)
	if werr := <-done; werr != nil {
		t.Fatal(werr)
	}
	if err != nil {
		t.Fatalf("worker two's claim did not finish while worker one holds two rows (%v): the claim must skip locked rows (FOR UPDATE SKIP LOCKED)", err)
	}

	seen := map[store.LogoutNotificationID]bool{}
	for _, n := range append(firstRows, secondRows...) {
		if seen[n.ID] {
			t.Fatalf("notification %s was claimed by both workers", n.ID)
		}
		seen[n.ID] = true
	}
	if len(firstRows) != 2 || len(secondRows) != 2 {
		t.Fatalf("workers took %d and %d rows, want 2 and 2", len(firstRows), len(secondRows))
	}
}

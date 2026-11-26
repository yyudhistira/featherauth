//go:build postgres

package store_test

import (
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/testutil"
)

// Covers: FR-43 (part)
// Acceptance: Back-channel logout (part)
// On Postgres a claim skips a row that another transaction holds locked, so two
// workers never take the same notification.
func TestPostgresLogoutClaimSkipsLockedRows(t *testing.T) {
	ctx := t.Context()
	db := testutil.NewPostgresDB(t)
	s, err := store.NewPostgres(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	epoch := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	for _, id := range []string{"n1", "n2"} {
		if err := s.Write(ctx, func(tx store.Tx) error {
			return tx.LogoutNotifications().Enqueue(ctx, store.LogoutNotification{
				ID: store.LogoutNotificationID(id), RealmID: "r1", ClientID: "app", UserID: "u1",
				SessionID: store.SessionID("s-" + id), NextAttemptAt: epoch, CreatedAt: epoch,
			})
		}); err != nil {
			t.Fatal(err)
		}
	}
	// Another worker's transaction holds n1 (the first row in order).
	other, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = other.Rollback() }()
	var held string
	if err := other.QueryRowContext(ctx, `SELECT id FROM logout_notifications WHERE id = $1 FOR UPDATE`, "n1").Scan(&held); err != nil {
		t.Fatal(err)
	}
	var rows []store.LogoutNotification
	if err := s.Write(ctx, func(tx store.Tx) (err error) {
		rows, err = tx.LogoutNotifications().Claim(ctx, epoch, 10)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].ID != "n2" {
		t.Fatalf("the claim took %+v, want only n2 (n1 is locked elsewhere)", rows)
	}
	if err := other.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err := s.Write(ctx, func(tx store.Tx) (err error) {
		rows, err = tx.LogoutNotifications().Claim(ctx, epoch, 10)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].ID != "n1" {
		t.Fatalf("after the release the claim took %+v, want n1", rows)
	}
}

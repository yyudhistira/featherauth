package audit_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/logx"
	"github.com/yyudhistira/featherauth/internal/secure"
	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/store/audit"
	"github.com/yyudhistira/featherauth/internal/testutil"
)

var start = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

func setup(t *testing.T) (*audit.Writer, store.Store, *bytes.Buffer) {
	t.Helper()
	s := testutil.NewStore(t)
	var buf bytes.Buffer
	c := clock.NewFake(start)
	w := audit.NewWriter(s, logx.New(&buf, 0, c), c, secure.Default)
	return w, s, &buf
}

func list(t *testing.T, s store.Store, realm store.RealmID) []store.AuditEvent {
	t.Helper()
	var got []store.AuditEvent
	err := s.Read(context.Background(), func(tx store.Tx) (err error) {
		got, err = tx.Audit().List(context.Background(), realm, time.Unix(0, 0))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestWriteStoresRowAndLogsLine(t *testing.T) {
	w, s, buf := setup(t)
	ctx := context.Background()
	err := w.Write(ctx, audit.Event{
		Realm: "r1", Actor: "provider:apple", Action: "account.delete", User: "u1",
		Details: map[string]any{"event": "consent-revoked"},
	})
	if err != nil {
		t.Fatal(err)
	}
	rows := list(t, s, "r1")
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	r := rows[0]
	if len(r.ID) != 26 || r.RealmID != "r1" || r.Actor != "provider:apple" || r.Action != "account.delete" ||
		r.UserID != "u1" || !r.CreatedAt.Equal(start) || r.Details["event"] != "consent-revoked" {
		t.Fatalf("row = %+v", r)
	}

	var line map[string]any
	if err := json.Unmarshal(buf.Bytes(), &line); err != nil {
		t.Fatalf("log output %q: %v", buf.String(), err)
	}
	details, _ := line["details"].(map[string]any)
	if line["audit"] != true || line["id"] != r.ID || line["realm_id"] != "r1" || line["actor"] != "provider:apple" ||
		line["action"] != "account.delete" || line["user_id"] != "u1" || details["event"] != "consent-revoked" {
		t.Fatalf("log line = %v", line)
	}
}

func TestWriteIDsAreUniqueAndOrdered(t *testing.T) {
	w, s, _ := setup(t)
	for range 3 {
		if err := w.Write(context.Background(), audit.Event{Realm: "r1", Actor: "system", Action: "x"}); err != nil {
			t.Fatal(err)
		}
	}
	seen := map[string]bool{}
	for _, r := range list(t, s, "r1") {
		seen[r.ID] = true
	}
	if len(seen) != 3 {
		t.Fatalf("distinct ids = %d, want 3", len(seen))
	}
}

func TestAuditByUserIDHoldsNoEmail(t *testing.T) {
	// Covers: SEC-13 (part)
	w, s, buf := setup(t)
	ctx := context.Background()
	const email = "alice@example.com"
	// The user has an email; the audit event names the user by id only.
	err := s.Write(ctx, func(tx store.Tx) error {
		if _, err := tx.Realms().Ensure(ctx, "main", "r1", start); err != nil {
			return err
		}
		return tx.Users().Create(ctx, store.User{ID: "u1", RealmID: "r1", Email: email, EmailKey: email,
			EmailVerified: true, CreatedAt: start, UpdatedAt: start})
	})
	if err != nil {
		t.Fatal(err)
	}
	// The event names the user by id and carries ids in its details, as the
	// callers must; the stored JSON and the log line then hold no email.
	if err := w.Write(ctx, audit.Event{Realm: "r1", Actor: "admin", Action: "user.link", User: "u1",
		Details: map[string]any{"provider": "google", "identity": "i1"}}); err != nil {
		t.Fatal(err)
	}

	// Read the stored JSON from a snapshot with a plain connection.
	snap, err := store.Snapshot(ctx, s, t.TempDir(), start, 1)
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", snap)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	var stored string
	if err := db.QueryRow(`SELECT details FROM audit_events`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stored, "@") || strings.Contains(stored, email) {
		t.Fatalf("stored details %q hold an email", stored)
	}
	if strings.Contains(buf.String(), "@") || strings.Contains(buf.String(), email) {
		t.Fatalf("log line %q holds an email", buf.String())
	}
	if !strings.Contains(buf.String(), `"user_id":"u1"`) {
		t.Fatalf("log line %q lacks the user id", buf.String())
	}
}

func TestWriteFailureReturnsErrorAndLogsNothing(t *testing.T) {
	w, s, buf := setup(t)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := w.Write(context.Background(), audit.Event{Realm: "r1", Actor: "system", Action: "x"}); err == nil {
		t.Fatal("expected an error from a closed store")
	}
	if buf.Len() != 0 {
		t.Fatalf("log line written for an event that was not stored: %s", buf.String())
	}
}

func TestLogHidesAnEmailKeyInDetails(t *testing.T) {
	// Covers: SEC-13 (part)
	// Keeping emails out of the stored details is the caller's job; Write
	// does not inspect them. The log line is protected anyway by logx, which
	// hides the value of an email key.
	w, _, buf := setup(t)
	const email = "alice@example.com"
	err := w.Write(context.Background(), audit.Event{Realm: "r1", Actor: "admin", Action: "user.update", User: "u1",
		Details: map[string]any{"email": email, "nested": map[string]any{"user_email": email}}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), email) || strings.Contains(buf.String(), "@") {
		t.Fatalf("log line %q holds the email", buf.String())
	}
}

func TestWriteTxStoresInCallerTransactionAndLogsOnPublish(t *testing.T) {
	w, s, buf := setup(t)
	ctx := context.Background()
	var publish func()
	err := s.Write(ctx, func(tx store.Tx) error {
		var err error
		publish, err = w.WriteTx(ctx, tx, audit.Event{
			Realm: "r1", Actor: "provider:google", Action: "identity.link", User: "u1",
			Details: map[string]any{"provider": "google"},
		})
		if err != nil {
			return err
		}
		if buf.Len() != 0 {
			t.Error("logged before the commit")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 0 {
		t.Fatal("logged by the commit itself; the caller publishes")
	}
	if rows := list(t, s, "r1"); len(rows) != 1 || rows[0].Action != "identity.link" || rows[0].UserID != "u1" {
		t.Fatalf("rows = %+v", rows)
	}
	publish()
	var line map[string]any
	if err := json.Unmarshal(buf.Bytes(), &line); err != nil {
		t.Fatalf("log output %q: %v", buf.String(), err)
	}
	if line["audit"] != true || line["action"] != "identity.link" || line["user_id"] != "u1" {
		t.Fatalf("log line = %v", line)
	}
}

func TestWriteTxRolledBackLeavesNoRowAndNoLine(t *testing.T) {
	w, s, buf := setup(t)
	ctx := context.Background()
	err := s.Write(ctx, func(tx store.Tx) error {
		if _, err := w.WriteTx(ctx, tx, audit.Event{Realm: "r1", Actor: "system", Action: "x"}); err != nil {
			return err
		}
		return errors.New("later failure")
	})
	if err == nil {
		t.Fatal("transaction did not fail")
	}
	if rows := list(t, s, "r1"); len(rows) != 0 || buf.Len() != 0 {
		t.Fatalf("rows = %d, log = %q", len(rows), buf.String())
	}
}

func TestWriteTxReturnsStoreError(t *testing.T) {
	w, s, _ := setup(t)
	ctx := context.Background()
	err := s.Write(ctx, func(tx store.Tx) error {
		ev := audit.Event{Realm: "r1", Actor: "system", Action: "x"}
		if _, err := w.WriteTx(ctx, tx, ev); err != nil {
			return err
		}
		// Same random source, so a distinct id, but a closed context fails.
		cctx, cancel := context.WithCancel(ctx)
		cancel()
		publish, err := w.WriteTx(cctx, tx, ev)
		if err == nil || publish != nil {
			t.Errorf("WriteTx on a cancelled context returned publish %t, err %v", publish != nil, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

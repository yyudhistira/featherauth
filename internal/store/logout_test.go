package store_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/secure"
	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/testutil"
)

// Covers: FR-43 (part)
// Acceptance: Back-channel logout (part)
func TestQueueLogoutsNotifiesOnlyClientsWithAURI(t *testing.T) {
	ctx := context.Background()
	s := testutil.NewStore(t)
	epoch := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	clk := clock.NewFake(epoch)
	realm := &config.Realm{Clients: map[config.ClientID]*config.Client{
		"app":  {BackchannelLogoutURI: "https://app.example.com/logout"},
		"frag": {}, // no URI: no row
	}}
	ended := []store.EndedSession{
		{SessionID: "s1", ClientID: "app", UserID: "u1"},
		{SessionID: "s2", ClientID: "frag", UserID: "u1"},
		{SessionID: "s3", ClientID: "removed", UserID: "u1"}, // a client no longer in the realm
		{SessionID: "s4", ClientID: "app", UserID: "u2"},
	}
	if err := s.Write(ctx, func(tx store.Tx) error {
		return store.QueueLogouts(ctx, tx, realm, "r1", ended, clk, secure.Default)
	}); err != nil {
		t.Fatal(err)
	}
	var rows []store.LogoutNotification
	if err := s.Write(ctx, func(tx store.Tx) (err error) {
		rows, err = tx.LogoutNotifications().Claim(ctx, epoch, 10)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	// Rows due at one instant come back in id order, so the check sorts by session.
	if len(rows) != 2 {
		t.Fatalf("rows = %+v, want one for s1 and one for s4 of the client with a URI", rows)
	}
	bySession := map[store.SessionID]store.LogoutNotification{rows[0].SessionID: rows[0], rows[1].SessionID: rows[1]}
	s1, s4 := bySession["s1"], bySession["s4"]
	if s1.ID == "" || s4.ID == "" || s1.ID == s4.ID || s1.ClientID != "app" || s1.UserID != "u1" || s4.UserID != "u2" ||
		s1.RealmID != "r1" || s1.Attempts != 0 || !s1.NextAttemptAt.Equal(epoch) || !s1.CreatedAt.Equal(epoch) {
		t.Fatalf("rows = %+v, want one for s1 and one for s4 of the client with a URI", rows)
	}
}

// Covers: FR-43 (part)
// Acceptance: Back-channel logout (part)
func TestQueueLogoutsWithoutSessionsOrRealmConfig(t *testing.T) {
	ctx := context.Background()
	s := testutil.NewStore(t)
	clk := clock.NewFake(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC))
	if err := s.Write(ctx, func(tx store.Tx) error {
		return store.QueueLogouts(ctx, tx, nil, "r1", nil, clk, secure.Default)
	}); err != nil {
		t.Fatalf("no sessions need no configuration: %v", err)
	}
	// Without the realm's configuration the clients' URIs are unknown: no row, no error.
	if err := s.Write(ctx, func(tx store.Tx) error {
		return store.QueueLogouts(ctx, tx, nil, "r1", []store.EndedSession{{SessionID: "s1", ClientID: "app", UserID: "u1"}}, clk, secure.Default)
	}); err != nil {
		t.Fatalf("sessions without the realm's configuration: %v, want no error", err)
	}
	var rows []store.LogoutNotification
	if err := s.Write(ctx, func(tx store.Tx) (err error) {
		rows, err = tx.LogoutNotifications().Claim(ctx, clk.Now(), 10)
		return err
	}); err != nil || len(rows) != 0 {
		t.Fatalf("rows %+v, %v, want none", rows, err)
	}
}

// Covers: FR-43 (part)
// Acceptance: Back-channel logout (part)
// A failing random source or a failing insert stops the helper with its error,
// so the revocation that asked for the rows is rolled back with them.
func TestQueueLogoutsFailures(t *testing.T) {
	ctx := context.Background()
	s := testutil.NewStore(t)
	clk := clock.NewFake(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC))
	realm := &config.Realm{Clients: map[config.ClientID]*config.Client{"app": {BackchannelLogoutURI: "https://app.example.com/logout"}}}
	ended := []store.EndedSession{{SessionID: "s1", ClientID: "app", UserID: "u1"}}
	t.Run("no random bytes for the id", func(t *testing.T) {
		err := s.Write(ctx, func(tx store.Tx) error {
			return store.QueueLogouts(ctx, tx, realm, "r1", ended, clk, bytes.NewReader(nil))
		})
		if err == nil {
			t.Fatal("a row was queued without an id")
		}
	})
	t.Run("a cancelled insert", func(t *testing.T) {
		cancelled, cancel := context.WithCancel(ctx)
		cancel()
		err := s.Write(ctx, func(tx store.Tx) error {
			return store.QueueLogouts(cancelled, tx, realm, "r1", ended, clk, secure.Default)
		})
		if err == nil {
			t.Fatal("the insert ignored a cancelled context")
		}
	})
}

// Covers: FR-45 (part), SEC-37 (part)
// Acceptance: Single sign-on end (part)
// QueueLogouts ends the browser session of each ended session even when the
// realm's configuration is not available (a nil realm): a browser session is not a
// logout notification, so no configuration decides it.
func TestQueueLogoutsEndsBrowserSessionsWithoutConfiguration(t *testing.T) {
	s := testutil.NewStore(t)
	ctx := context.Background()
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	hash := secure.HashOf("cookie-of-a-session")
	err := s.Write(ctx, func(tx store.Tx) error {
		if _, err := tx.Realms().Ensure(ctx, "main", "r1", now); err != nil {
			return err
		}
		if err := tx.Users().Create(ctx, store.User{ID: "u1", RealmID: "r1", CreatedAt: now, UpdatedAt: now}); err != nil {
			return err
		}
		return tx.SSOSessions().Create(ctx, store.SSOSession{IDHash: hash, RealmID: "r1", UserID: "u1",
			IdentityID: "i1", Provider: "google", AuthTime: now, CreatedAt: now, LastUsedAt: now, ExpiresAt: now.Add(time.Hour)})
	})
	if err != nil {
		t.Fatal(err)
	}
	err = s.Write(ctx, func(tx store.Tx) error {
		return store.QueueLogouts(ctx, tx, nil, "r1",
			[]store.EndedSession{{SessionID: "s1", ClientID: "app", UserID: "u1", SSOIDHash: hash}, {SessionID: "s2", UserID: "u1"}},
			clock.NewFake(now), secure.Default)
	})
	if err != nil {
		t.Fatalf("QueueLogouts with a nil realm: %v", err)
	}
	err = s.Read(ctx, func(tx store.Tx) error {
		if _, err := tx.SSOSessions().Find(ctx, "r1", hash); !errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("the browser session of the ended session is still there: %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

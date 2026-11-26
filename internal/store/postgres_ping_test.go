//go:build postgres

package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/testutil"
)

// The readiness ping of Postgres does not wait for the pool: with the only
// connection of the pool held by a write, Ping still answers, as on SQLite
// (FR-16 asks /readyz to ping the read side, not the queue of the writes).
// Covers: FR-16
// Acceptance: Health (part)
func TestPostgresPingDoesNotWaitForThePool(t *testing.T) {
	srv := testutil.NewPostgresServer(t)
	pg := srv.NewDatabase(t)
	pg.Host, pg.Port = srv.Host, srv.Port
	pg.MaxOpenConns = 1
	s, err := openPostgres(t, pg, srv.Password, nil)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	held, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- s.Write(context.Background(), func(store.Tx) error {
			close(held)
			<-release
			return nil
		})
	}()
	<-held
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err = s.Ping(ctx)
	close(release)
	if werr := <-done; werr != nil {
		t.Fatal(werr)
	}
	if err != nil {
		t.Fatalf("ping while the only pool connection is busy: %v", err)
	}
}

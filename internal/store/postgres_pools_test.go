package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// countConnector is a stub driver whose connections are counted when they are
// opened and closed, so a test can see which pool a call used and whether
// Close closed every connection.
type countConnector struct{ opened, closed *atomic.Int32 }

func (c countConnector) Connect(context.Context) (driver.Conn, error) {
	c.opened.Add(1)
	return countConn{c.closed}, nil
}

func (c countConnector) Driver() driver.Driver { return nil }

type countConn struct{ closed *atomic.Int32 }

func (c countConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("not supported") }
func (c countConn) Close() error                        { c.closed.Add(1); return nil }
func (c countConn) Begin() (driver.Tx, error)           { return nil, errors.New("not supported") }

// newCountPool returns a pool of one connection over the stub, with its
// connection counters.
func newCountPool() (db *sql.DB, opened, closed *atomic.Int32) {
	opened, closed = new(atomic.Int32), new(atomic.Int32)
	db = sql.OpenDB(countConnector{opened, closed})
	db.SetMaxOpenConns(1)
	return db, opened, closed
}

// Covers: FR-16
func TestPostgresPingUsesItsOwnPoolAndCloseClosesBoth(t *testing.T) {
	ctx := context.Background()
	db, dbOpened, dbClosed := newCountPool()
	ping, pingOpened, pingClosed := newCountPool()
	s := &postgresStore{db: db, ping: ping}

	// The only connection of the main pool is held, as a busy write holds it.
	held, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	pctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := s.Ping(pctx); err != nil {
		t.Fatalf("ping with the main pool busy: %v", err)
	}
	if pingOpened.Load() != 1 || dbOpened.Load() != 1 {
		t.Errorf("ping opened %d connections on the ping pool and %d on the main pool, want 1 and 1 (the held one)",
			pingOpened.Load(), dbOpened.Load())
	}

	// Without a ping pool, the ping goes through the main pool and waits for it.
	fallback := &postgresStore{db: db}
	fctx, fcancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer fcancel()
	if err := fallback.Ping(fctx); err == nil {
		t.Error("a store without a ping pool answered while its only connection was held")
	}

	if err := held.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if pingClosed.Load() != pingOpened.Load() {
		t.Errorf("close left the ping pool open: %d of %d connections closed", pingClosed.Load(), pingOpened.Load())
	}
	if dbClosed.Load() != dbOpened.Load() {
		t.Errorf("close left the main pool open: %d of %d connections closed", dbClosed.Load(), dbOpened.Load())
	}
	if err := ping.PingContext(ctx); err == nil {
		t.Error("the ping pool still answers after Close")
	}
	if err := db.PingContext(ctx); err == nil {
		t.Error("the main pool still answers after Close")
	}
}

// Covers: FR-16
func TestPostgresCloseWithoutPingPool(t *testing.T) {
	db, opened, closed := newCountPool()
	s := &postgresStore{db: db}
	if err := s.Ping(context.Background()); err != nil {
		t.Fatalf("ping: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if closed.Load() != opened.Load() {
		t.Errorf("close left the main pool open: %d of %d connections closed", closed.Load(), opened.Load())
	}
}

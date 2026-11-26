package store_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/testutil"
)

func countRealms(t *testing.T, s store.Store, write bool) int {
	t.Helper()
	var n int
	fn := func(tx store.Tx) error {
		return store.RawTx(tx).QueryRow(`SELECT COUNT(*) FROM realms`).Scan(&n)
	}
	var err error
	if write {
		err = s.Write(context.Background(), fn)
	} else {
		err = s.Read(context.Background(), fn)
	}
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestPragmas(t *testing.T) {
	s, err := store.Open(context.Background(), dbConfig(filepath.Join(t.TempDir(), "f.db")), config.DatabaseSecrets{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	want := map[string]string{"journal_mode": "wal", "synchronous": "1", "foreign_keys": "1", "busy_timeout": "5000"}
	for _, run := range []struct {
		name string
		do   func(context.Context, func(store.Tx) error) error
	}{{"write", s.Write}, {"read", s.Read}} {
		err := run.do(context.Background(), func(tx store.Tx) error {
			for p, w := range want {
				var got string
				if err := store.RawTx(tx).QueryRow(`PRAGMA ` + p).Scan(&got); err != nil {
					return err
				}
				if got != w {
					t.Errorf("%s connection: %s = %q, want %q", run.name, p, got, w)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestReadConnectionsLimit(t *testing.T) {
	cfg := dbConfig(filepath.Join(t.TempDir(), "f.db"))
	cfg.SQLite.ReadConnections = 2
	s, err := store.Open(context.Background(), cfg, config.DatabaseSecrets{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if got := store.ReadPoolSize(s); got != 2 {
		t.Fatalf("read pool size = %d, want 2", got)
	}
}

func TestReadTxCannotWrite(t *testing.T) {
	s := testutil.NewStore(t)
	err := s.Read(context.Background(), func(tx store.Tx) error {
		_, err := store.RawTx(tx).Exec(`INSERT INTO realms (id, name, created_at) VALUES ('r', 'n', 1)`)
		return err
	})
	if err == nil {
		t.Fatal("write in a read transaction succeeded")
	}
}

func TestWriteCommitsAndRollsBackOnError(t *testing.T) {
	s := testutil.NewStore(t)
	ctx := context.Background()
	boom := errors.New("boom")
	err := s.Write(ctx, func(tx store.Tx) error {
		if _, err := store.RawTx(tx).Exec(`INSERT INTO realms (id, name, created_at) VALUES ('r', 'n', 1)`); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want boom", err)
	}
	if n := countRealms(t, s, false); n != 0 {
		t.Fatalf("rows after rollback = %d", n)
	}
	if err := store.ExecForTest(ctx, s, `INSERT INTO realms (id, name, created_at) VALUES ('r', 'n', 1)`); err != nil {
		t.Fatal(err)
	}
	if n := countRealms(t, s, false); n != 1 {
		t.Fatalf("rows after commit = %d", n)
	}
}

func TestWriteRollsBackOnPanic(t *testing.T) {
	s := testutil.NewStore(t)
	func() {
		defer func() {
			if recover() == nil {
				t.Error("panic was swallowed")
			}
		}()
		_ = s.Write(context.Background(), func(tx store.Tx) error {
			_, _ = store.RawTx(tx).Exec(`INSERT INTO realms (id, name, created_at) VALUES ('r', 'n', 1)`)
			panic("x")
		})
	}()
	// The write connection is free again and the row is gone.
	if n := countRealms(t, s, true); n != 0 {
		t.Fatalf("rows after panic = %d", n)
	}
}

func TestConcurrentWritesQueue(t *testing.T) {
	s := testutil.NewStore(t)
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id := fmt.Sprintf("r%d", i)
			errs <- store.ExecForTest(context.Background(), s, `INSERT INTO realms (id, name, created_at) VALUES (?, ?, 1)`, id, id)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if n := countRealms(t, s, false); n != 20 {
		t.Fatalf("rows = %d, want 20", n)
	}
}

func TestBusyMapsToUnavailable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f.db")
	cfg := dbConfig(path)
	cfg.SQLite.BusyTimeout = config.Duration(50 * time.Millisecond)
	s, err := store.Open(context.Background(), cfg, config.DatabaseSecrets{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	// Another process holds the write lock.
	other, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	conn, err := other.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(context.Background(), `BEGIN IMMEDIATE`); err != nil {
		t.Fatal(err)
	}

	err = store.ExecForTest(context.Background(), s, `INSERT INTO realms (id, name, created_at) VALUES ('r', 'n', 1)`)
	if !errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
}

func TestOpenRejectsBadOptions(t *testing.T) {
	for _, tc := range []struct {
		name string
		mod  func(*config.DatabaseFile)
	}{
		{"journal mode", func(c *config.DatabaseFile) { c.SQLite.JournalMode = "wal);drop" }},
		{"read connections", func(c *config.DatabaseFile) { c.SQLite.ReadConnections = 0 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := dbConfig(filepath.Join(t.TempDir(), "f.db"))
			tc.mod(&cfg)
			if _, err := store.Open(context.Background(), cfg, config.DatabaseSecrets{}); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestOpenFailsOnUnwritablePath(t *testing.T) {
	cfg := dbConfig(filepath.Join(t.TempDir(), "missing-dir", "f.db"))
	if _, err := store.Open(context.Background(), cfg, config.DatabaseSecrets{}); err == nil {
		t.Fatal("expected an error")
	}
}

func TestTxRepositoryAccessors(t *testing.T) {
	s := testutil.NewStore(t)
	_ = s.Read(context.Background(), func(tx store.Tx) error {
		_, _, _, _ = tx.Realms(), tx.Users(), tx.Identities(), tx.AuthRequests()
		_, _, _, _ = tx.AuthCodes(), tx.Handoffs(), tx.RefreshTokens(), tx.Audit()
		return nil
	})
}

func TestOpenFailsOnNotADatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f.db")
	if err := os.WriteFile(path, []byte(strings.Repeat("not a database ", 200)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Open(context.Background(), dbConfig(path), config.DatabaseSecrets{}); err == nil {
		t.Fatal("expected an error")
	}
}

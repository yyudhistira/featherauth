//go:build postgres

package testutil

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib" // registers the "pgx" driver of database/sql

	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/secure"
	"github.com/yyudhistira/featherauth/internal/store"
)

// PostgresEnv names the environment variable with the connection string of the
// Postgres of the postgres suites. make postgres sets it.
const PostgresEnv = "FEATHERAUTH_TEST_POSTGRES"

// postgresDSN returns the connection string that lookup finds. An unset or
// empty variable is an error: the postgres suites never skip.
func postgresDSN(lookup func(string) (string, bool)) (string, error) {
	dsn, ok := lookup(PostgresEnv)
	if !ok || dsn == "" {
		return "", fmt.Errorf("%s is not set; run make postgres", PostgresEnv)
	}
	return dsn, nil
}

// NewPostgresDB returns a connection pool to the Postgres named by
// FEATHERAUTH_TEST_POSTGRES whose search_path is a schema of its own. The schema
// is created for the test and dropped when it ends, so the tests share one
// server without seeing each other's rows. It fails the test when the variable
// is not set or the server does not answer.
func NewPostgresDB(t testing.TB) *sql.DB {
	t.Helper()
	dsn, err := postgresDSN(os.LookupEnv)
	if err != nil {
		t.Fatal(err)
	}
	// Cleanups run last in, first out: the schema is dropped before the
	// bootstrap connection that dropped it closes.
	boot, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = boot.Close() })
	id, err := secure.NewUUID(secure.Default)
	if err != nil {
		t.Fatal(err)
	}
	schema := "ft_" + strings.ReplaceAll(id, "-", "_")
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err := boot.ExecContext(t.Context(), "CREATE SCHEMA "+quoted); err != nil {
		t.Fatalf("create the test schema: %v", err)
	}
	t.Cleanup(func() {
		_, _ = boot.ExecContext(context.Background(), "DROP SCHEMA "+quoted+" CASCADE")
	})

	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse %s: %v", PostgresEnv, err)
	}
	cfg.RuntimeParams["search_path"] = schema
	db := stdlib.OpenDB(*cfg)
	t.Cleanup(func() { _ = db.Close() })
	if err := db.PingContext(t.Context()); err != nil {
		t.Fatalf("connect to the test Postgres: %v", err)
	}
	return db
}

// NewPostgresStore returns a migrated store on a fresh Postgres schema (see
// NewPostgresDB) and closes it when the test ends.
func NewPostgresStore(t testing.TB) store.Store {
	t.Helper()
	s, err := store.NewPostgres(t.Context(), NewPostgresDB(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// PostgresServer is the server named by FEATHERAUTH_TEST_POSTGRES: where the
// postgres suites connect, and as which user.
type PostgresServer struct {
	Host     string
	Port     int
	User     string
	Password string
	dsn      string
}

// NewPostgresServer parses FEATHERAUTH_TEST_POSTGRES. It fails the test when the
// variable is unset, or when it is not a postgres:// URL with a host, a port, a
// user and a password.
func NewPostgresServer(t testing.TB) PostgresServer {
	t.Helper()
	dsn, err := postgresDSN(os.LookupEnv)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(dsn)
	if err != nil || u.Scheme != "postgres" || u.User == nil {
		t.Fatalf("%s is not a postgres:// URL with a user", PostgresEnv)
	}
	pw, ok := u.User.Password()
	port, err := strconv.Atoi(u.Port())
	if !ok || err != nil || u.Hostname() == "" {
		t.Fatalf("%s needs a host, a port and a password", PostgresEnv)
	}
	return PostgresServer{Host: u.Hostname(), Port: port, User: u.User.Username(), Password: pw, dsn: dsn}
}

// Addr is the host and port of the server, for a proxy to forward to.
func (s PostgresServer) Addr() string { return net.JoinHostPort(s.Host, strconv.Itoa(s.Port)) }

// NewDatabase creates a database of its own on the server and returns the
// postgres block of database.yaml that connects to it, with sslmode disable.
// The database is dropped, with any connection still open to it, when the test
// ends. The password is not in the block: a test writes it to a password file.
func (s PostgresServer) NewDatabase(t testing.TB) config.PostgresConfig {
	t.Helper()
	boot, err := sql.Open("pgx", s.dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = boot.Close() })
	id, err := secure.NewUUID(secure.Default)
	if err != nil {
		t.Fatal(err)
	}
	name := "ft_" + strings.ReplaceAll(id, "-", "_")
	quoted := pgx.Identifier{name}.Sanitize()
	if _, err := boot.ExecContext(t.Context(), "CREATE DATABASE "+quoted); err != nil {
		t.Fatalf("create the test database: %v", err)
	}
	t.Cleanup(func() {
		_, _ = boot.ExecContext(context.Background(), "DROP DATABASE IF EXISTS "+quoted+" WITH (FORCE)")
	})
	return config.PostgresConfig{
		Host:            s.Host,
		Port:            s.Port,
		Database:        name,
		User:            s.User,
		SSLMode:         "disable",
		MaxOpenConns:    5,
		MaxIdleConns:    2,
		ConnectTimeout:  config.Duration(5 * time.Second),
		ConnMaxLifetime: config.Duration(30 * time.Minute),
	}
}

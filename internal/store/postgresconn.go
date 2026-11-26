package store

import (
	"context"
	"crypto/tls"
	"database/sql"
	"fmt"
	"net"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/yyudhistira/featherauth/internal/config"
)

// openPostgres connects to the Postgres database of cfg with the secrets of the
// same database.yaml, sets up the pool of the postgres block and applies the
// migrations. The pool serves reads and writes; the readiness ping uses a
// connection of its own.
func openPostgres(ctx context.Context, cfg config.PostgresConfig, secrets config.DatabaseSecrets) (Store, error) {
	db, err := openPostgresDB(cfg, secrets)
	if err != nil {
		return nil, err
	}
	// The readiness ping has a connection of its own (FR-16): one connection,
	// with the same server and secrets as the pool.
	pingCfg := cfg
	pingCfg.MaxOpenConns, pingCfg.MaxIdleConns = 1, 1
	ping, err := openPostgresDB(pingCfg, secrets)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return newPostgres(ctx, db, ping)
}

// openPostgresDB returns the pool of the postgres block of cfg, with its pool
// settings, without connecting or migrating: a connection is made by the first
// query.
func openPostgresDB(cfg config.PostgresConfig, secrets config.DatabaseSecrets) (*sql.DB, error) {
	cc, err := postgresConnConfig(cfg, secrets)
	if err != nil {
		return nil, err
	}
	db := stdlib.OpenDB(*cc)
	db.SetMaxOpenConns(cfg.MaxOpenConns)
	db.SetMaxIdleConns(cfg.MaxIdleConns)
	db.SetConnMaxLifetime(cfg.ConnMaxLifetime.Std())
	return db, nil
}

// postgresConnConfig returns the connection configuration of the postgres block
// with the password and the certificate authority of secrets.
//
// pgx.ParseConfig also reads the PG* environment variables (libpq's names) into
// the connection configuration, and it reads PGSERVICEFILE and PGPASSFILE. The
// address, user, database, password and TLS settings are set here from
// database.yaml and the secret files, so those variables have no effect on them.
// Every other setting that pgx takes from the environment is reset to the value
// pgx gives when none of the variables is set (the test of this function checks
// each one against that baseline), so that no variable changes the connection.
// A variable with a value pgx cannot parse makes ParseConfig fail, and the start
// fails with its error, which holds no password.
func postgresConnConfig(cfg config.PostgresConfig, secrets config.DatabaseSecrets) (*pgx.ConnConfig, error) {
	if cfg.Port < 1 || cfg.Port > 65535 {
		return nil, fmt.Errorf("postgres.port must be between 1 and 65535, got %d", cfg.Port)
	}
	cc, err := pgx.ParseConfig("")
	if err != nil {
		return nil, err
	}
	cc.Host = cfg.Host
	cc.Port = uint16(cfg.Port)
	cc.Database = cfg.Database
	cc.User = cfg.User
	cc.Password = secrets.Password()

	// Reset to pgx's values without the environment.
	cc.Fallbacks = nil                     // no plain-connection fallback from sslmode prefer
	cc.RuntimeParams = map[string]string{} // PGOPTIONS, PGAPPNAME, PGTZ
	// postgres.connect_timeout (OPS-22) bounds one connection, TCP connect, TLS
	// and login together, for the pool and for /readyz; PGCONNECT_TIMEOUT has no
	// effect. Its dialer is replaced as well.
	cc.ConnectTimeout = cfg.ConnectTimeout.Std()
	cc.DialFunc = (&net.Dialer{}).DialContext
	cc.ValidateConnect = nil // PGTARGETSESSIONATTRS
	cc.SSLNegotiation = ""   // PGSSLNEGOTIATION: direct TLS would skip the SSLRequest
	cc.SSLCertMode = "allow" // PGSSLCERTMODE; the TLS settings below replace the client certificates
	cc.MinProtocolVersion = "3.0"
	cc.MaxProtocolVersion = "3.0"
	cc.ChannelBinding = "prefer" // PGCHANNELBINDING
	cc.RequireAuth = ""          // PGREQUIREAUTH

	switch cfg.SSLMode {
	case "disable":
		cc.TLSConfig = nil
	case "require":
		// Encrypted, and the server's certificate is not checked: the mode is
		// for a server whose identity the network already guarantees.
		cc.TLSConfig = &tls.Config{InsecureSkipVerify: true}
	case "verify-full":
		// The certificate must be signed by the root certificate file (or the
		// system's store) and name the host.
		cc.TLSConfig = &tls.Config{ServerName: cfg.Host, RootCAs: secrets.RootCAs()}
	default:
		return nil, fmt.Errorf("postgres.sslmode must be disable, require or verify-full, got %q", cfg.SSLMode)
	}
	return cc, nil
}

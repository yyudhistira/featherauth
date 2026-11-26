package store_test

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/yyudhistira/featherauth/internal/store"
)

// pgEnvNames are the PG* variables pgx reads when it parses a connection
// configuration (libpq's names).
var pgEnvNames = []string{
	"PGHOST", "PGPORT", "PGDATABASE", "PGUSER", "PGPASSWORD", "PGPASSFILE",
	"PGAPPNAME", "PGCONNECT_TIMEOUT", "PGSSLMODE", "PGSSLKEY", "PGSSLCERT",
	"PGSSLCERTMODE", "PGSSLSNI", "PGSSLROOTCERT", "PGSSLPASSWORD",
	"PGSSLNEGOTIATION", "PGTARGETSESSIONATTRS", "PGSERVICE", "PGSERVICEFILE",
	"PGTZ", "PGOPTIONS", "PGMINPROTOCOLVERSION", "PGMAXPROTOCOLVERSION",
	"PGCHANNELBINDING", "PGREQUIREAUTH",
}

// unsetEnv removes a variable for the test and puts it back afterwards.
func unsetEnv(t *testing.T, name string) {
	t.Helper()
	v, ok := os.LookupEnv(name)
	if err := os.Unsetenv(name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if ok {
			_ = os.Setenv(name, v)
		}
	})
}

// Covers: FR-35 (part), FR-25 (part)
// Acceptance: Postgres service (part)
func TestPostgresConnConfigIgnoresThePGEnvironment(t *testing.T) {
	// The baseline is pgx's own configuration with none of the variables set.
	for _, n := range pgEnvNames {
		unsetEnv(t, n)
	}
	base, err := pgx.ParseConfig("")
	if err != nil {
		t.Fatal(err)
	}
	pg, secrets := connFixture(t, "disable", "")

	// Every variable is set to a value that would change the connection if it
	// were honoured: another host, user, database and password, a service file
	// with settings of its own, options, a time zone, a protocol version, TLS
	// and authentication requirements.
	svc := filepath.Join(t.TempDir(), "pg_service.conf")
	if err := os.WriteFile(svc, []byte("[evil]\nhost=evil.example\noptions=-c search_path=evil\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{
		"PGHOST": "evil.example", "PGPORT": "1", "PGDATABASE": "evil", "PGUSER": "evil",
		"PGPASSWORD": "evil-password", "PGAPPNAME": "evil-app", "PGOPTIONS": "-c search_path=evil",
		"PGTZ": "Asia/Jakarta", "PGCONNECT_TIMEOUT": "7", "PGTARGETSESSIONATTRS": "read-only",
		"PGSSLNEGOTIATION": "direct", "PGSSLMODE": "require", "PGSSLCERTMODE": "allow",
		"PGMINPROTOCOLVERSION": "3.2", "PGCHANNELBINDING": "require", "PGREQUIREAUTH": "password",
		"PGSERVICE": "evil", "PGSERVICEFILE": svc,
	} {
		t.Setenv(name, value)
	}

	got, err := store.PostgresConnConfig(pg, secrets)
	if err != nil {
		t.Fatalf("with the variables set: %v", err)
	}
	// database.yaml decides the address, the user and the password.
	if got.Host != pg.Host || got.Port != uint16(pg.Port) || got.Database != pg.Database || got.User != pg.User || got.Password != connPassword {
		t.Errorf("connection = host %q port %d database %q user %q; the database.yaml values are %q %d %q %q",
			got.Host, got.Port, got.Database, got.User, pg.Host, pg.Port, pg.Database, pg.User)
	}
	if got.TLSConfig != nil || len(got.Fallbacks) != 0 {
		t.Errorf("sslmode disable: TLS = %v, fallbacks = %d", got.TLSConfig != nil, len(got.Fallbacks))
	}
	// The settings pgx takes from the environment are the ones it has with
	// none of the variables set.
	if !reflect.DeepEqual(got.RuntimeParams, base.RuntimeParams) {
		t.Errorf("RuntimeParams = %v, want %v", got.RuntimeParams, base.RuntimeParams)
	}
	// The connect timeout is postgres.connect_timeout (OPS-22), not the 7 seconds
	// of PGCONNECT_TIMEOUT.
	if got.ConnectTimeout != pg.ConnectTimeout.Std() || pg.ConnectTimeout.Std() != 5*time.Second {
		t.Errorf("ConnectTimeout = %v, want the 5s of postgres.connect_timeout (%v)", got.ConnectTimeout, pg.ConnectTimeout.Std())
	}
	if got.ValidateConnect != nil {
		t.Error("ValidateConnect is set: target_session_attrs came from the environment")
	}
	checks := []struct {
		name      string
		got, want string
	}{
		{"SSLNegotiation", got.SSLNegotiation, base.SSLNegotiation},
		{"SSLCertMode", got.SSLCertMode, base.SSLCertMode},
		{"MinProtocolVersion", got.MinProtocolVersion, base.MinProtocolVersion},
		{"MaxProtocolVersion", got.MaxProtocolVersion, base.MaxProtocolVersion},
		{"ChannelBinding", got.ChannelBinding, base.ChannelBinding},
		{"RequireAuth", got.RequireAuth, base.RequireAuth},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", c.name, c.got, c.want)
		}
	}
}

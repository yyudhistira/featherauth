package config

import (
	"crypto/x509"
	"log/slog"
	"os"
)

// DatabaseSecrets are the secrets of database.yaml: the password of the
// postgres block, and the certificate authority that sslmode verify-full checks
// the server against. ReadDatabaseSecrets reads them at startup, and a change
// to the files needs a restart. A DatabaseSecrets logs no secret.
type DatabaseSecrets struct {
	password string
	rootCAs  *x509.CertPool
}

var _ slog.LogValuer = DatabaseSecrets{}

// Password returns the password of the postgres user, with one trailing newline
// dropped, or "" when none is read (sqlite, or the file is not used).
func (d DatabaseSecrets) Password() string { return d.password }

// RootCAs returns the certificate pool of postgres.root_cert_file, or nil for
// the system's certificate store.
func (d DatabaseSecrets) RootCAs() *x509.CertPool { return d.rootCAs }

// LogValue logs whether each secret is set and nothing else (implements
// slog.LogValuer).
func (d DatabaseSecrets) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Bool("password_set", d.password != ""),
		slog.Bool("root_cert_set", d.rootCAs != nil),
	)
}

// ReadDatabaseSecrets reads the secrets that database.yaml names, the file
// file in dir, which db is the decoded content of. The checks are those of the
// loader: a secret file readable by others is an error when strict is true and a
// warning otherwise, and a missing or empty secret is an error. The secrets are
// valid when no diagnostic is an error. Diagnostics never contain a secret.
func ReadDatabaseSecrets(dir, file string, db *DatabaseFile, strict bool) (DatabaseSecrets, []Diagnostic) {
	l := &loader{dir: dir, strict: strict}
	s := l.database(file, db)
	if l.failed {
		return DatabaseSecrets{}, l.ds
	}
	return s, l.ds
}

// database reads the secrets of database.yaml that the configuration uses: the
// password file with driver postgres, and the root certificate file with
// sslmode verify-full. A secret the configuration does not use is not read.
func (l *loader) database(file string, db *DatabaseFile) DatabaseSecrets {
	var s DatabaseSecrets
	if db == nil || db.Driver != "postgres" {
		return s
	}
	if name := db.Postgres.PasswordFile; name != "" {
		at := where{file, db.Line("postgres.password_file"), "postgres.password_file"}
		if text, ok := l.readSecretText(name, at); ok {
			s.password = text
		}
	}
	if db.Postgres.SSLMode == "verify-full" && db.Postgres.RootCertFile != "" {
		at := where{file, db.Line("postgres.root_cert_file"), "postgres.root_cert_file"}
		s.rootCAs = l.rootCerts(db.Postgres.RootCertFile, at)
	}
	return s
}

// rootCerts reads the PEM file of the certificate authority. A certificate is
// public, so no permission check applies; the file must hold at least one
// certificate.
func (l *loader) rootCerts(name string, at where) *x509.CertPool {
	b, err := os.ReadFile(l.path(name))
	if err != nil {
		l.errorf(at, "cannot read certificate file %s", name)
		return nil
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		l.errorf(at, "%s holds no PEM certificate; it must be the certificate authority of the server", name)
		return nil
	}
	return pool
}

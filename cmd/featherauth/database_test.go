package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yyudhistira/featherauth/internal/config"
)

// With driver postgres the built-in snapshot does not exist: no schedule runs,
// whatever backup.directory and backup.at say.
// Covers: FR-25 (part)
// Acceptance: Postgres service (part)
func TestBackupScheduleIsOffOnPostgres(t *testing.T) {
	backup := config.BackupConfig{Directory: "/var/backups/featherauth", At: "03:00", Keep: 3}
	pg := &config.DatabaseFile{Driver: "postgres", Backup: backup}
	if got := backupOf(pg); got != (config.BackupConfig{}) {
		t.Fatalf("backupOf(postgres) = %+v, want no schedule", got)
	}
	sq := &config.DatabaseFile{Driver: "sqlite", Backup: backup}
	if got := backupOf(sq); got != backup {
		t.Fatalf("backupOf(sqlite) = %+v, want %+v", got, backup)
	}
}

// featherauth backup takes SQLite snapshots only. With driver postgres it exits
// 1 before anything is written, and the message names pg_dump.
// Covers: FR-25 (part)
// Acceptance: Postgres service (part)
func TestBackupOnPostgresNamesPgDump(t *testing.T) {
	dir := t.TempDir()
	backups := filepath.Join(dir, "backups")
	writeConfig(t, dir, "database.yaml", "driver: postgres\npostgres:\n  host: db.example.com\n  password_file: secrets/pg\nbackup:\n  directory: "+backups+"\n")
	r := exec(t, map[string]string{"FEATHERAUTH_CONFIG_DIR": dir}, "backup")
	if r.code != 1 || !strings.Contains(r.stderr, "pg_dump") {
		t.Fatalf("backup on postgres: %+v", r)
	}
	if _, err := os.Stat(backups); err == nil {
		t.Fatal("backup created the snapshot directory on postgres")
	}
}

// The password file is read before the service or a command connects, so an
// unreadable one, an empty one and one readable by others (with strict
// permissions, the default) stop the command with the file named; the password
// itself is never printed.
// Covers: FR-25 (part), SEC-09 (part)
// Acceptance: Postgres service (part)
func TestPostgresPasswordFileIsCheckedBeforeConnecting(t *testing.T) {
	const pw = "cli-sentinel-password"
	for _, tc := range []struct {
		name    string
		write   bool
		mode    os.FileMode
		content string
		want    string
	}{
		{name: "missing", want: "postgres.password_file"},
		{name: "empty", write: true, mode: 0o600, content: "\n", want: "postgres.password_file"},
		{name: "readable by others", write: true, mode: 0o644, content: pw, want: "postgres.password_file"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeConfig(t, dir, "database.yaml", "driver: postgres\npostgres:\n  host: db.example.com\n  password_file: secrets/pg\n")
			if tc.write {
				writeConfig(t, dir, "secrets/pg", tc.content)
				if err := os.Chmod(filepath.Join(dir, "secrets", "pg"), tc.mode); err != nil {
					t.Fatal(err)
				}
			}
			r := exec(t, map[string]string{"FEATHERAUTH_CONFIG_DIR": dir}, "user", "get", "main", "u1")
			if r.code != 1 || !strings.Contains(r.stderr, tc.want) || strings.Contains(r.stderr+r.stdout, pw) {
				t.Fatalf("%+v", r)
			}
		})
	}
}

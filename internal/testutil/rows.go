package testutil

import (
	"database/sql"
	"testing"
)

// SQLiteRowCounts returns the number of rows of every table of the SQLite file
// at path, except goose's version table. The file is read on its own connection.
func SQLiteRowCounts(t testing.TB, path string) map[string]int64 {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	out := map[string]int64{}
	for _, name := range SQLiteTables(t, path) {
		if name == "goose_db_version" {
			continue
		}
		var n int64
		if err := db.QueryRow(`SELECT COUNT(*) FROM "` + name + `"`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		out[name] = n
	}
	return out
}

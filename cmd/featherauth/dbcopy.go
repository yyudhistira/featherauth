package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/store"
)

// db runs a database subcommand. copy is the only one.
func (a *app) db(ctx context.Context, args []string) int {
	if len(args) == 0 {
		return a.usageError("db needs a subcommand: copy")
	}
	if args[0] != "copy" {
		return a.usageError(fmt.Sprintf("unknown db subcommand %q", args[0]))
	}
	return a.dbCopy(ctx, args[1:])
}

// dbCopy copies the SQLite database named by the database.yaml of --from to the
// Postgres database named by the database.yaml of --to. The files are read, checked
// and reported as the service reads them; the copy itself is in the store.
func (a *app) dbCopy(ctx context.Context, args []string) int {
	fl := flag.NewFlagSet("db copy", flag.ContinueOnError)
	fl.SetOutput(io.Discard)
	var from, to string
	seen := map[string]bool{}
	once := func(name string, dst *string) func(string) error {
		return func(v string) error {
			if seen[name] {
				return fmt.Errorf("-%s is given twice", name)
			}
			seen[name] = true
			*dst = v
			return nil
		}
	}
	fl.Func("from", "", once("from", &from))
	fl.Func("to", "", once("to", &to))
	if err := fl.Parse(args); err != nil {
		return a.usageError(fmt.Sprintf("db copy: %v", err))
	}
	if fl.NArg() != 0 {
		return a.usageError(fmt.Sprintf("db copy takes no argument %q", fl.Arg(0)))
	}
	if from == "" || to == "" {
		return a.usageError("db copy needs --from <file> and --to <file>")
	}

	srcDB, srcDs, err := readCopyFile(from)
	if err != nil {
		return a.fail(err)
	}
	dstDB, dstDs, err := readCopyFile(to)
	if err != nil {
		return a.fail(err)
	}
	if srcDB == nil {
		return a.failDiagnostics(srcDs)
	}
	if dstDB == nil {
		return a.failDiagnostics(dstDs)
	}
	if srcDB.Driver != "sqlite" || dstDB.Driver != "postgres" {
		return a.usageError(fmt.Sprintf("db copy copies a sqlite database to a postgres database: --from names driver %s and --to names driver %s", srcDB.Driver, dstDB.Driver))
	}
	if code := a.checkCopyFile(from, srcDB, srcDs); code != 0 {
		return code
	}
	if code := a.checkCopyFile(to, dstDB, dstDs); code != 0 {
		return code
	}
	secrets, sds := config.ReadDatabaseSecrets(filepath.Dir(to), filepath.Base(to), dstDB, a.strictPermissions())
	if failed := errorDiagnostics(sds); len(failed) > 0 {
		return a.failDiagnostics(failed)
	}

	tables, err := store.CopySQLiteToPostgres(ctx, *srcDB, *dstDB, secrets)
	for _, t := range tables {
		if t.Match {
			fmt.Fprintf(a.stdout, "%s %d ok\n", t.Table, t.Rows)
		} else {
			fmt.Fprintf(a.stdout, "%s %d %d differs\n", t.Table, t.Rows, t.TargetRows)
		}
	}
	if err != nil {
		return a.fail(err)
	}
	fmt.Fprintln(a.stdout, "copied")
	return 0
}

// readCopyFile reads and decodes the database.yaml at path. The decoded file is nil
// when the file is not valid YAML; the diagnostics come back with it.
func readCopyFile(path string) (*config.DatabaseFile, []config.Diagnostic, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	db, ds := config.DecodeDatabase(path, b)
	return db, ds, nil
}

// checkCopyFile validates the decoded database.yaml at path, as config check does,
// and returns the exit code: 0 when it has no error, 1 when it has one.
func (a *app) checkCopyFile(path string, db *config.DatabaseFile, decoded []config.Diagnostic) int {
	ds := append(decoded, config.ValidateDatabase(path, db)...)
	if failed := errorDiagnostics(ds); len(failed) > 0 {
		return a.failDiagnostics(failed)
	}
	return 0
}

// errorDiagnostics returns the diagnostics that are errors.
func errorDiagnostics(ds []config.Diagnostic) []config.Diagnostic {
	var out []config.Diagnostic
	for _, d := range ds {
		if d.Severity == config.Error {
			out = append(out, d)
		}
	}
	return out
}

// failDiagnostics prints the diagnostics, one per line, and returns the failure
// exit code.
func (a *app) failDiagnostics(ds []config.Diagnostic) int {
	for _, d := range ds {
		fmt.Fprintln(a.stderr, d.String())
	}
	return 1
}

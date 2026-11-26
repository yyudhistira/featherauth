package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/yyudhistira/featherauth/internal/admin"
	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/logx"
	"github.com/yyudhistira/featherauth/internal/provider"
	"github.com/yyudhistira/featherauth/internal/secure"
	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/store/audit"
	"github.com/yyudhistira/featherauth/internal/user"
)

// usageErr marks a mistake in the command line (exit code 2).
type usageErr string

func (e usageErr) Error() string { return string(e) }

// configDir returns FEATHERAUTH_CONFIG_DIR, default /etc/featherauth (FR-17).
func (a *app) configDir() string {
	if d := a.getenv(envConfigDir); d != "" {
		return d
	}
	return defaultConfigDir
}

// openDatabase reads database.yaml in the configuration directory and opens the
// database it names, with the secrets of that file (missing means the defaults,
// as for the service).
func (a *app) openDatabase(ctx context.Context) (store.Store, *config.DatabaseFile, error) {
	db, err := a.readDatabase()
	if err != nil {
		return nil, nil, err
	}
	secrets, ds := config.ReadDatabaseSecrets(a.configDir(), "database.yaml", db, a.strictPermissions())
	for _, d := range ds {
		if d.Severity == config.Error {
			return nil, nil, errors.New(d.String())
		}
	}
	st, err := store.Open(ctx, *db, secrets)
	if err != nil {
		return nil, nil, err
	}
	return st, db, nil
}

// readDatabase decodes and validates database.yaml in the configuration
// directory. A missing file gives the defaults; any error diagnostic fails it.
func (a *app) readDatabase() (*config.DatabaseFile, error) {
	b, err := os.ReadFile(filepath.Join(a.configDir(), "database.yaml"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	db, ds := config.DecodeDatabase("database.yaml", b)
	if db != nil {
		ds = append(ds, config.ValidateDatabase("database.yaml", db)...)
	}
	for _, d := range ds {
		if d.Severity == config.Error {
			return nil, errors.New(d.String())
		}
	}
	return db, nil
}

// strictPermissions returns strict_permissions of server.yaml in the
// configuration directory. The database opens before the configuration loads
// (the Restart specification), so its secrets take the option from here. A
// missing or unreadable server.yaml gives the default; the loader reports the
// file's own errors.
func (a *app) strictPermissions() bool {
	b, err := os.ReadFile(filepath.Join(a.configDir(), "server.yaml"))
	if err != nil {
		return true
	}
	srv, _ := config.DecodeServer("server.yaml", b)
	if srv == nil {
		return true
	}
	return srv.StrictPermissions
}

// revocation says how a deletion treats the stored provider tokens.
type revocation int

const (
	noRevocation   revocation = iota // not a deletion
	revokeProvider                   // load the configuration; refuse when it is unusable
	skipRevocation                   // --skip-revocation: delete, tokens stay unrevoked
)

// ops opens the database and returns the administration operations; the audit
// line of each change goes to standard error. For a deletion with revokeProvider
// the configuration is loaded, so the stored provider tokens can be revoked at
// their providers; when the configuration cannot be loaded or its encryption
// key cannot be used, ops fails and nothing is deleted. skipRevocation deletes
// without revoking and says so.
func (a *app) ops(ctx context.Context, rev revocation) (*admin.Ops, store.Store, *config.DatabaseFile, error) {
	log := logx.New(a.stderr, slog.LevelInfo, a.clock)
	var box *secure.Box
	var revokers user.RevokerFor
	switch rev {
	case revokeProvider:
		var err error
		if box, revokers, err = a.revokers(); err != nil {
			return nil, nil, nil, fmt.Errorf("%w; fix the configuration, or use --skip-revocation to delete without revoking the provider tokens", err)
		}
	case skipRevocation:
		log.LogAttrs(ctx, slog.LevelWarn, "provider tokens are not revoked at their providers (--skip-revocation)")
	}
	st, db, err := a.openDatabase(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	if a.wrapStore != nil {
		st = a.wrapStore(st)
	}
	mgr := user.NewManager(st, audit.NewWriter(st, log, a.clock, secure.Default), box, revokers, log, a.clock, secure.Default, a.realmsOf())
	return admin.NewOps(st, mgr, a.clock, log), st, db, nil
}

// realmsOf returns the configuration of the realms for a command's revocations.
// The configuration is loaded at the first call, which is the first revocation
// (the manager asks only when it revokes), not when the command opens its
// operations: most commands never read it. When it cannot be loaded, the lookup
// reports it unavailable: the revocation goes on as without this lookup, queues no logout
// notification and logs one warning.
func (a *app) realmsOf() user.RealmOf {
	var (
		once   sync.Once
		loaded config.Source
	)
	return func(name config.RealmName) (*config.Realm, bool) {
		once.Do(func() {
			if loader, err := config.NewLoader(a.configDir(), a.clock, nil); err == nil { // its own log lines are not the command's output
				loaded = loader
			}
		})
		if loaded == nil {
			return nil, false
		}
		return sourceRealms(loaded)(name)
	}
}

// revokers loads the configuration for the encryption keys and the provider
// adapters.
func (a *app) revokers() (*secure.Box, user.RevokerFor, error) {
	loader, err := config.NewLoader(a.configDir(), a.clock, nil) // its own log lines are not the command's output
	if err != nil {
		return nil, nil, err
	}
	box, err := openBox(loader.Current().Secrets().EncryptionKeys())
	if err != nil {
		return nil, nil, err
	}
	factory := a.revokerFactory
	if factory == nil {
		factory = poolRevokers
	}
	return box, factory(loader, a.clock, a.logger()), nil
}

// logger is the command's logger: standard error.
func (a *app) logger() *slog.Logger { return logx.New(a.stderr, slog.LevelInfo, a.clock) }

// openBox returns the box of the encryption keys, nil when there is none. A
// key the box cannot use is an error.
func openBox(keys [][]byte) (*secure.Box, error) {
	if len(keys) == 0 {
		return nil, nil
	}
	box, err := secure.NewBox(keys)
	if err != nil {
		return nil, fmt.Errorf("the encryption key cannot be used: %w", err)
	}
	return box, nil
}

// poolRevokers returns the revokers of the providers of the configuration.
func poolRevokers(src config.Source, c clock.Clock, log *slog.Logger) user.RevokerFor {
	pool := provider.NewPool(src, c, log)
	return func(realm, key string) provider.Revoker {
		p, ok := pool.Get(config.RealmName(realm), config.ProviderKey(key))
		if !ok {
			return nil
		}
		rv, _ := p.(provider.Revoker)
		return rv
	}
}

func (a *app) user(ctx context.Context, args []string) int {
	err := a.userCommand(ctx, args)
	var ue usageErr
	switch {
	case err == nil:
		return 0
	case errors.As(err, &ue):
		return a.usageError(ue.Error())
	}
	return a.fail(err)
}

func (a *app) userCommand(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return usageErr("user needs a subcommand: get, list, update, disable, enable, delete, link or unlink")
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "delete":
		if len(rest) < 2 {
			return usageErr("user delete needs <realm> <id> [--skip-revocation]")
		}
	case "get", "disable", "enable":
		if len(rest) != 2 {
			return usageErr(fmt.Sprintf("user %s needs <realm> <id>", cmd))
		}
	case "link", "unlink":
		if len(rest) != 4 {
			return usageErr(fmt.Sprintf("user %s needs <realm> <id> <provider> <subject>", cmd))
		}
	case "list", "update":
		if len(rest) < 1 || (cmd == "update" && len(rest) < 2) {
			return usageErr(fmt.Sprintf("user %s needs %s", cmd, map[string]string{"list": "<realm> --email <address>", "update": "<realm> <id> and at least one flag"}[cmd]))
		}
	default:
		return usageErr(fmt.Sprintf("unknown user subcommand %q", cmd))
	}
	realm := config.RealmName(rest[0])
	var upd updateFlags
	var email string
	rev := noRevocation
	switch cmd {
	case "delete":
		var skip bool
		fs := newFlags("user delete")
		fs.BoolVar(&skip, "skip-revocation", false, "delete without revoking the provider tokens")
		if err := parseFlags(fs, rest[2:], 0); err != nil {
			return err
		}
		rev = revokeProvider
		if skip {
			rev = skipRevocation
		}
	case "list":
		fs := newFlags("user list")
		fs.StringVar(&email, "email", "", "email address to look for")
		if err := parseFlags(fs, rest[1:], 0); err != nil {
			return err
		}
		if strings.TrimSpace(email) == "" {
			return usageErr("user list needs --email <address>")
		}
	case "update":
		var err error
		if upd, err = parseUpdate(rest[2:]); err != nil {
			return err
		}
	}

	ops, st, _, err := a.ops(ctx, rev)
	if err != nil {
		return err
	}
	defer st.Close()
	id := store.UserID("")
	if len(rest) > 1 {
		id = store.UserID(rest[1])
	}
	switch cmd {
	case "get":
		rec, err := ops.Get(ctx, realm, id)
		if err != nil {
			return err
		}
		return a.printJSON(view(rec.User, rec.Identities))
	case "list":
		users, err := ops.ListByEmail(ctx, realm, email)
		if err != nil {
			return err
		}
		out := make([]userView, 0, len(users))
		for _, u := range users {
			out = append(out, view(u, nil))
		}
		return a.printJSON(out)
	case "update":
		return a.applyUpdate(ctx, ops, realm, id, upd)
	case "disable":
		return ops.Disable(ctx, realm, id)
	case "enable":
		return ops.Enable(ctx, realm, id)
	case "delete":
		return ops.Delete(ctx, realm, id)
	case "link":
		return ops.Link(ctx, realm, id, config.ProviderKey(rest[2]), rest[3])
	default: // unlink
		return ops.Unlink(ctx, realm, id, config.ProviderKey(rest[2]), rest[3])
	}
}

func newFlags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

// parseFlags parses args, which must hold flags only (positional arguments
// come before the flags), and wants nPositional of them after the flags.
func parseFlags(fs *flag.FlagSet, args []string, nPositional int) error {
	if err := fs.Parse(args); err != nil {
		return usageErr(err.Error())
	}
	if fs.NArg() != nPositional {
		return usageErr(fmt.Sprintf("unexpected argument %q", strings.Join(fs.Args(), " ")))
	}
	return nil
}

// updateFlags are the fields of `user update`; a nil pointer means not given.
type updateFlags struct{ fields admin.Fields }

func parseUpdate(args []string) (updateFlags, error) {
	var name, email, verified, disabled string
	fs := newFlags("user update")
	fs.StringVar(&name, "name", "", "new name")
	fs.StringVar(&email, "email", "", "new email")
	fs.StringVar(&verified, "email-verified", "", "true or false")
	fs.StringVar(&disabled, "disabled", "", "true or false")
	if err := parseFlags(fs, args, 0); err != nil {
		return updateFlags{}, err
	}
	var u updateFlags
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "name":
			u.fields.Name = &name
		case "email":
			u.fields.Email = &email
		}
	})
	for _, f := range []struct {
		flag, val string
		dst       **bool
	}{{"email-verified", verified, &u.fields.EmailVerified}, {"disabled", disabled, &u.fields.Disabled}} {
		set := false
		fs.Visit(func(x *flag.Flag) { set = set || x.Name == f.flag })
		if !set {
			continue
		}
		switch f.val {
		case "true", "false":
			b := f.val == "true"
			*f.dst = &b
		default:
			return updateFlags{}, usageErr(fmt.Sprintf("--%s must be true or false, not %q", f.flag, f.val))
		}
	}
	if u.fields == (admin.Fields{}) {
		return updateFlags{}, usageErr("user update needs at least one of --name, --email, --email-verified, --disabled")
	}
	return u, nil
}

// applyUpdate runs the update; --disabled is part of it, so the field changes and
// the disabling or enabling happen in one transaction. When a new email makes
// the user unverified it says so on standard error.
func (a *app) applyUpdate(ctx context.Context, ops *admin.Ops, realm config.RealmName, id store.UserID, u updateFlags) error {
	res, err := ops.Update(ctx, realm, id, u.fields)
	if err != nil {
		return err
	}
	if res.VerificationCleared {
		fmt.Fprintln(a.stderr, "notice: the address changed, so email_verified was cleared; give --email-verified true with the new email to keep it verified (set it now with: user update <realm> <id> --email-verified true)")
	}
	return nil
}

// userView is what `user get` and `user list` print.
type userView struct {
	ID            string         `json:"id"`
	Email         string         `json:"email"`
	EmailVerified bool           `json:"email_verified"`
	Name          string         `json:"name"`
	Disabled      bool           `json:"disabled"`
	CreatedAt     time.Time      `json:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
	Identities    []identityView `json:"identities,omitempty"`
}

type identityView struct {
	Provider string `json:"provider"`
	Subject  string `json:"subject"`
}

func view(u store.User, ids []store.Identity) userView {
	v := userView{
		ID: string(u.ID), Email: u.Email, EmailVerified: u.EmailVerified, Name: u.Name,
		Disabled: !u.DisabledAt.IsZero(), CreatedAt: u.CreatedAt.UTC(), UpdatedAt: u.UpdatedAt.UTC(),
	}
	for _, i := range ids {
		v.Identities = append(v.Identities, identityView{string(i.Provider), i.ProviderSub})
	}
	return v
}

func (a *app) printJSON(v any) error {
	enc := json.NewEncoder(a.stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// backup writes one snapshot to backup.directory of database.yaml and keeps
// the newest backup.keep, as the daily schedule does.
func (a *app) backup(ctx context.Context, args []string) int {
	if len(args) != 0 {
		return a.usageError("backup takes no arguments")
	}
	// The built-in snapshot is SQLite's; a Postgres database is backed up with
	// pg_dump. This is checked before the database is opened.
	db, err := a.readDatabase()
	if err != nil {
		return a.fail(err)
	}
	if db.Driver == "postgres" {
		return a.fail(errors.New("backup takes SQLite snapshots only; back up postgres with pg_dump"))
	}
	ops, st, _, err := a.ops(ctx, noRevocation)
	if err != nil {
		return a.fail(err)
	}
	defer st.Close()
	if db.Backup.Directory == "" {
		return a.fail(errors.New("backup.directory is empty in database.yaml: backups are disabled"))
	}
	if err := os.MkdirAll(db.Backup.Directory, 0o700); err != nil {
		return a.fail(err)
	}
	path, err := ops.Backup(ctx, db.Backup.Directory, db.Backup.Keep)
	if err != nil {
		return a.fail(err)
	}
	fmt.Fprintf(a.stdout, "wrote %s\n", path)
	return 0
}

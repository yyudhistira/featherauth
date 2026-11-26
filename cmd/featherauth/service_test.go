package main

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/provider"
	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/testutil/server"
	"github.com/yyudhistira/featherauth/internal/user"
)

// The CLI changes users while the service runs and serves logins on the same
// database; the service sees each change at once.
//
// Covers: FR-20 (part), FR-23
// Acceptance: CLI commands (part)
// Acceptance: User admin
func TestUserAdminWhileTheServiceServesLogins(t *testing.T) {
	e := server.New(t)
	app := server.ClientQuery
	env := serviceConfigDir(t, e) // the service's own configuration, so a deletion can revoke
	clk := clock.NewFake(time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC))
	cli := func(args ...string) result {
		clk.Advance(time.Second)
		return execAt(t, clk, env, args...)
	}
	ctx := context.Background()

	tk := e.Exchange(t, app, e.Login(t, app))
	var uid string
	err := e.Store.Read(ctx, func(tx store.Tx) error {
		rid, err := tx.Realms().Find(ctx, "main")
		if err != nil {
			return err
		}
		ident, err := tx.Identities().Find(ctx, rid, "google", "1001")
		uid = string(ident.UserID)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	refresh := func(token string) string {
		return e.NewClient().PostToken(t, server.RefreshForm(app, token), nil).Tokens(t).Error
	}
	loginError := func() string {
		return e.Login(t, app).Values.Get("error")
	}

	// Disabled: no login (access_denied), no refresh (invalid_grant).
	if r := cli("user", "disable", "main", uid); r.code != 0 {
		t.Fatalf("%+v", r)
	}
	if got := loginError(); got != "access_denied" {
		t.Fatalf("login of a disabled user: %q", got)
	}
	if got := refresh(tk.RefreshToken); got != "invalid_grant" {
		t.Fatalf("refresh of a disabled user: %q", got)
	}
	// Enabled again: the old refresh tokens still fail, a new login works.
	if r := cli("user", "enable", "main", uid); r.code != 0 {
		t.Fatalf("%+v", r)
	}
	if got := refresh(tk.RefreshToken); got != "invalid_grant" {
		t.Fatalf("old refresh token after enabling: %q", got)
	}
	if got := loginError(); got != "" {
		t.Fatalf("login after enabling: %q", got)
	}

	// Name changed, identity linked and unlinked.
	if r := cli("user", "update", "main", uid, "--name", "Ann Changed"); r.code != 0 {
		t.Fatalf("%+v", r)
	}
	if r := cli("user", "get", "main", uid); r.code != 0 || !strings.Contains(r.stdout, `"name": "Ann Changed"`) {
		t.Fatalf("%+v", r)
	}
	for _, args := range [][]string{
		{"user", "link", "main", uid, "github", "gh-1"},
		{"user", "unlink", "main", uid, "github", "gh-1"},
	} {
		if r := cli(args...); r.code != 0 {
			t.Fatalf("%v: %+v", args, r)
		}
	}

	// Deleted: gone, and an audit entry for each change.
	if r := cli("user", "delete", "main", uid); r.code != 0 {
		t.Fatalf("%+v", r)
	}
	if r := cli("user", "get", "main", uid); r.code != 1 {
		t.Fatalf("deleted user: %+v", r)
	}
	want := map[string]bool{"user.disable": true, "user.enable": true, "user.update": true, "identity.link": true, "identity.unlink": true, "user.delete": true}
	err = e.Store.Read(ctx, func(tx store.Tx) error {
		rid, err := tx.Realms().Find(ctx, "main")
		if err != nil {
			return err
		}
		evs, err := tx.Audit().List(ctx, rid, time.Unix(0, 0))
		for _, ev := range evs {
			if ev.Actor == "admin" && ev.UserID == store.UserID(uid) {
				delete(want, ev.Action)
			}
		}
		return err
	})
	if err != nil || len(want) != 0 {
		t.Fatalf("missing audit entries %v, %v", want, err)
	}
}

type recordingRevoker struct{ tokens []string }

func (r *recordingRevoker) Revoke(_ context.Context, tok string) error {
	r.tokens = append(r.tokens, tok)
	return nil
}

// seedAppleToken gives the user of the Google login an Apple identity that
// holds a sealed provider refresh token, and returns the user id.
func seedAppleToken(t *testing.T, e *server.Env, plain string) string {
	t.Helper()
	ctx := context.Background()
	sealed, err := e.Box.Seal([]byte(plain))
	if err != nil {
		t.Fatal(err)
	}
	var uid string
	err = e.Store.Write(ctx, func(tx store.Tx) error {
		rid, err := tx.Realms().Find(ctx, "main")
		if err != nil {
			return err
		}
		ident, err := tx.Identities().Find(ctx, rid, "google", "1001")
		if err != nil {
			return err
		}
		uid = string(ident.UserID)
		return tx.Identities().Create(ctx, store.Identity{
			ID: "apple-ident", RealmID: rid, UserID: ident.UserID, Provider: "apple", ProviderSub: "a1",
			ProviderRefreshTokenEnc: sealed, CreatedAt: e.Clock.Now(),
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	return uid
}

// serviceConfigDir is the service's configuration directory with a
// database.yaml that names the service's database.
func serviceConfigDir(t *testing.T, e *server.Env) map[string]string {
	t.Helper()
	writeConfig(t, e.ConfigDir(), "database.yaml", "driver: sqlite\nsqlite:\n  path: "+e.DatabasePath+"\n")
	return map[string]string{"FEATHERAUTH_CONFIG_DIR": e.ConfigDir()}
}

// A deletion with a loadable configuration opens the stored provider token
// with the configuration's encryption key and revokes it once at the provider.
//
// Covers: SEC-10 (part), FR-23 (part)
// Acceptance: Encryption key rotation (part)
func TestUserDeleteRevokesTheStoredProviderToken(t *testing.T) {
	e := server.New(t)
	e.Login(t, server.ClientQuery)
	uid := seedAppleToken(t, e, "apple-refresh-token")
	env := serviceConfigDir(t, e)
	rv := &recordingRevoker{}
	r := execApp(t, e.Clock, env, func(a *app) {
		a.revokerFactory = func(config.Source, clock.Clock, *slog.Logger) user.RevokerFor {
			return func(realm, key string) provider.Revoker {
				if realm == "main" && key == "apple" {
					return rv
				}
				return nil
			}
		}
	}, "user", "delete", "main", uid)
	if r.code != 0 {
		t.Fatalf("%+v", r)
	}
	if len(rv.tokens) != 1 || rv.tokens[0] != "apple-refresh-token" {
		t.Fatalf("revoked %v", rv.tokens)
	}
	if strings.Contains(r.stderr, "apple-refresh-token") || strings.Contains(r.stderr, `"level":"WARN"`) {
		t.Fatalf("stderr %q", r.stderr)
	}
	if got := execAt(t, e.Clock, env, "user", "get", "main", uid); got.code != 1 {
		t.Fatalf("the user is still there: %+v", got)
	}
}

// The default revokers come from the provider pool of the loaded
// configuration; a provider without a revoker is a warning, never a failure.
//
// Covers: SEC-10 (part), FR-23 (part)
// Acceptance: Encryption key rotation (part)
func TestUserDeleteWithTheConfigurationsProviderPool(t *testing.T) {
	e := server.New(t)
	e.Login(t, server.ClientQuery)
	ctx := context.Background()
	sealed, err := e.Box.Seal([]byte("gh-token"))
	if err != nil {
		t.Fatal(err)
	}
	var uid string
	err = e.Store.Write(ctx, func(tx store.Tx) error {
		rid, err := tx.Realms().Find(ctx, "main")
		if err != nil {
			return err
		}
		ident, err := tx.Identities().Find(ctx, rid, "google", "1001")
		if err != nil {
			return err
		}
		uid = string(ident.UserID)
		return tx.Identities().Create(ctx, store.Identity{
			ID: "gh-ident", RealmID: rid, UserID: ident.UserID, Provider: "github", ProviderSub: "h1",
			ProviderRefreshTokenEnc: sealed, CreatedAt: e.Clock.Now(),
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	r := execAt(t, e.Clock, serviceConfigDir(t, e), "user", "delete", "main", uid)
	if r.code != 0 || !strings.Contains(r.stderr, "provider has no revoker") || strings.Contains(r.stderr, "gh-token") {
		t.Fatalf("%+v", r)
	}
}

// When the configuration cannot be loaded, the deletion is refused with the
// reason and deletes nothing; --skip-revocation deletes anyway and warns that
// the provider tokens are not revoked.
//
// Covers: SEC-10 (part), FR-23 (part)
// Acceptance: Encryption key rotation (part)
func TestUserDeleteFailsClosedWithoutAConfiguration(t *testing.T) {
	forEachDB(t, func(t *testing.T, d dbDriver) {
		e := newAdminEnvWith(t, d, false) // a directory with database.yaml only
		r := e.run(t, "user", "delete", "main", "u2")
		if r.code != 1 || r.stdout != "" {
			t.Fatalf("%+v", r)
		}
		if !strings.Contains(r.stderr, "configuration is not valid") || !strings.Contains(r.stderr, "--skip-revocation") {
			t.Fatalf("stderr %q", r.stderr)
		}
		if e.user(t, "u2").ID != "u2" || len(e.audit(t)) != 0 {
			t.Fatal("a refused deletion changed something")
		}

		r = e.run(t, "user", "delete", "main", "u2", "--skip-revocation")
		if r.code != 0 || !strings.Contains(r.stderr, "not revoked") || !strings.Contains(r.stderr, `"level":"WARN"`) {
			t.Fatalf("%+v", r)
		}
		if g := e.run(t, "user", "get", "main", "u2"); g.code != 1 {
			t.Fatalf("the user is still there: %+v", g)
		}
	})
}

// A box that cannot be built refuses the deletion as well.
//
// Covers: SEC-10 (part)
// Acceptance: Encryption key rotation (part)
func TestOpenBoxFailsWhenTheKeysAreUnusable(t *testing.T) {
	if _, err := openBox([][]byte{[]byte("short")}); err == nil {
		t.Fatal("a box from an unusable key")
	}
	if box, err := openBox(nil); err != nil || box != nil {
		t.Fatalf("no keys: %v, %v", box, err)
	}
}

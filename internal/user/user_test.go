package user_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/logx"
	"github.com/yyudhistira/featherauth/internal/provider"
	"github.com/yyudhistira/featherauth/internal/secure"
	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/store/audit"
	"github.com/yyudhistira/featherauth/internal/testutil"
	"github.com/yyudhistira/featherauth/internal/user"
)

var start = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

type env struct {
	t      *testing.T
	st     store.Store
	clock  *clock.Fake
	log    *bytes.Buffer
	logger *slog.Logger
	svc    *user.Service
	realm  *config.Realm
}

func defaultRealm() *config.Realm {
	return &config.Realm{
		Name: "main", Enabled: true,
		UserData: config.UserData{
			Attributes:        []string{"email", "name"},
			KeepNameIfMissing: true,
			AutoLinkDomains:   []string{"gmail.com", "googlemail.com", "icloud.com", "me.com", "mac.com"},
		},
	}
}

func newEnv(t *testing.T) *env {
	t.Helper()
	return newEnvWith(t, testutil.NewStore(t))
}

func newEnvWith(t *testing.T, st store.Store) *env {
	t.Helper()
	var buf bytes.Buffer
	c := clock.NewFake(start)
	log := logx.New(&buf, slog.LevelDebug, c)
	w := audit.NewWriter(st, log, c, secure.Default)
	return &env{t, st, c, &buf, log, user.NewService(st, w, log, c, secure.Default), defaultRealm()}
}

// trusted is a provider like Google: it vouches for emails and may link.
func trusted() *config.Provider {
	return &config.Provider{TrustEmail: true, AutoLink: true, SyncMode: "import"}
}

// untrusted is a provider like Facebook or a default generic oidc.
func untrusted() *config.Provider {
	return &config.Provider{TrustEmail: false, AutoLink: false, SyncMode: "import"}
}

func (e *env) resolve(key string, p *config.Provider, id provider.Identity) (*store.User, error) {
	e.t.Helper()
	return e.svc.Resolve(context.Background(), user.ResolveInput{
		Realm: e.realm, ProviderKey: config.ProviderKey(key), Provider: p, Identity: id,
	})
}

func (e *env) must(key string, p *config.Provider, id provider.Identity) *store.User {
	e.t.Helper()
	u, err := e.resolve(key, p, id)
	if err != nil {
		e.t.Fatalf("Resolve(%s, %s): %v", key, id.Subject, err)
	}
	return u
}

func ident(sub, email string, verified bool) provider.Identity {
	return provider.Identity{Subject: sub, Email: email, EmailVerified: verified, Name: "Ann"}
}

// svcLog returns the logger the services of this environment share.
func (e *env) svcLog() *slog.Logger { return e.logger }

func (e *env) realmID() store.RealmID {
	e.t.Helper()
	var id store.RealmID
	err := e.st.Read(context.Background(), func(tx store.Tx) (err error) {
		id, err = tx.Realms().Find(context.Background(), e.realm.Name)
		return err
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return id
}

func (e *env) identities(u *store.User) []store.Identity {
	e.t.Helper()
	var got []store.Identity
	err := e.st.Read(context.Background(), func(tx store.Tx) (err error) {
		got, err = tx.Identities().ListByUser(context.Background(), u.RealmID, u.ID)
		return err
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return got
}

func (e *env) stored(u *store.User) store.User {
	e.t.Helper()
	var got store.User
	err := e.st.Read(context.Background(), func(tx store.Tx) (err error) {
		got, err = tx.Users().Get(context.Background(), u.RealmID, u.ID)
		return err
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return got
}

func (e *env) audits() []store.AuditEvent {
	e.t.Helper()
	var got []store.AuditEvent
	err := e.st.Read(context.Background(), func(tx store.Tx) (err error) {
		got, err = tx.Audit().List(context.Background(), e.realmID(), time.Unix(0, 0))
		return err
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return got
}

func (e *env) setDisabled(u *store.User) {
	e.t.Helper()
	err := e.st.Write(context.Background(), func(tx store.Tx) error {
		cur, err := tx.Users().Get(context.Background(), u.RealmID, u.ID)
		if err != nil {
			return err
		}
		cur.DisabledAt = e.clock.Now()
		return tx.Users().Update(context.Background(), cur)
	})
	if err != nil {
		e.t.Fatal(err)
	}
}

func notFoundIdentity(t *testing.T, e *env, provKey, sub string) bool {
	t.Helper()
	var missing bool
	err := e.st.Read(context.Background(), func(tx store.Tx) error {
		_, err := tx.Identities().Find(context.Background(), e.realmID(), config.ProviderKey(provKey), sub)
		missing = errors.Is(err, store.ErrNotFound)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return missing
}

func (e *env) usersWithKey(key string) int {
	e.t.Helper()
	var n int
	err := e.st.Read(context.Background(), func(tx store.Tx) error {
		us, err := tx.Users().ListByEmailKey(context.Background(), e.realmID(), key)
		n = len(us)
		return err
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return n
}

// Covers: FR-12 (part)
// Acceptance: Identity match
func TestSameProviderAccountReturnsSameUser(t *testing.T) {
	e := newEnv(t)
	a := e.must("google", trusted(), ident("g1", "ann@example.org", true))
	b := e.must("google", trusted(), ident("g1", "ann@example.org", true))
	if a.ID != b.ID || a.ID == "" {
		t.Fatalf("ids %q and %q", a.ID, b.ID)
	}
	if n := len(e.identities(a)); n != 1 {
		t.Fatalf("identities = %d", n)
	}
	if n := e.usersWithKey("ann@example.org"); n != 1 {
		t.Fatalf("users in the realm = %d, want no new user", n)
	}
	if a.RealmID != e.realmID() || a.Email != "ann@example.org" || a.Name != "Ann" || !a.EmailVerified {
		t.Fatalf("user = %+v", a)
	}
	t.Run("a changed email finds the same user", func(t *testing.T) {
		c := e.must("google", trusted(), ident("g1", "changed@example.org", true))
		if c.ID != a.ID || e.usersWithKey("changed@example.org") != 0 {
			t.Fatalf("user %q, want %q and no new user", c.ID, a.ID)
		}
	})
	t.Run("the same subject under another provider is another user", func(t *testing.T) {
		d := e.must("github", untrusted(), ident("g1", "ann@example.org", true))
		if d.ID == a.ID {
			t.Fatal("matched across providers")
		}
		if e.usersWithKey("ann@example.org") != 2 {
			t.Fatal("expected a second user")
		}
	})
}

// Covers: FR-12 (part), SEC-04 (part)
func TestConcurrentFirstLogins(t *testing.T) {
	const n = 8
	run := func(e *env, calls []func() (*store.User, error)) []*store.User {
		t.Helper()
		var wg sync.WaitGroup
		users := make([]*store.User, len(calls))
		errs := make([]error, len(calls))
		for i := range calls {
			wg.Add(1)
			go func() {
				defer wg.Done()
				users[i], errs[i] = calls[i]()
			}()
		}
		wg.Wait()
		for i, err := range errs {
			if err != nil {
				t.Fatalf("login %d: %v", i, err)
			}
		}
		return users
	}
	t.Run("one new identity", func(t *testing.T) {
		e := newEnv(t)
		calls := make([]func() (*store.User, error), n)
		for i := range calls {
			calls[i] = func() (*store.User, error) {
				return e.resolve("google", trusted(), ident("g1", "ann@example.org", true))
			}
		}
		users := run(e, calls)
		for _, u := range users {
			if u.ID != users[0].ID {
				t.Fatalf("users %q and %q", u.ID, users[0].ID)
			}
		}
		if got := e.usersWithKey("ann@example.org"); got != 1 {
			t.Fatalf("users = %d, want 1", got)
		}
		if got := len(e.identities(users[0])); got != 1 {
			t.Fatalf("identities = %d", got)
		}
	})
	t.Run("two identities with one verified email", func(t *testing.T) {
		e := newEnv(t)
		calls := make([]func() (*store.User, error), n)
		for i := range calls {
			sub := fmt.Sprintf("s%d", i%2)
			key := []string{"google", "github"}[i%2]
			calls[i] = func() (*store.User, error) {
				return e.resolve(key, trusted(), ident(sub, "ann@example.org", true))
			}
		}
		users := run(e, calls)
		ids := map[store.UserID]bool{}
		for _, u := range users {
			ids[u.ID] = true
		}
		if len(ids) != 2 {
			t.Fatalf("distinct users = %d, want 2", len(ids))
		}
		verified := 0
		for id := range ids {
			if e.stored(&store.User{ID: id, RealmID: e.realmID()}).EmailVerified {
				verified++
			}
		}
		if verified != 1 {
			t.Fatalf("verified holders = %d, want 1", verified)
		}
	})
}

// Covers: FR-21 (part)
func TestSameAccountInAnotherRealmIsAnotherUser(t *testing.T) {
	e := newEnv(t)
	a := e.must("google", trusted(), ident("g1", "ann@gmail.com", true))
	other := *e.realm
	other.Name = "other"
	e.realm = &other
	b := e.must("google", trusted(), ident("g1", "ann@gmail.com", true))
	if a.ID == b.ID || a.RealmID == b.RealmID {
		t.Fatalf("users %+v and %+v", a, b)
	}
}

// Covers: FR-12 (part), SEC-04 (part)
// Acceptance: Auto-link (part)
func TestAutoLinkGoogleThenApple(t *testing.T) {
	e := newEnv(t)
	g := e.must("google", trusted(), ident("g1", "ann@gmail.com", true))
	a := e.must("apple", trusted(), ident("a1", "ann@gmail.com", true))
	if g.ID != a.ID {
		t.Fatalf("users %q and %q, want one", g.ID, a.ID)
	}
	if n := len(e.identities(g)); n != 2 {
		t.Fatalf("identities = %d, want 2", n)
	}
	rows := e.audits()
	if len(rows) != 1 || rows[0].Action != "identity.auto_link" || rows[0].Actor != "provider:apple" || rows[0].UserID != g.ID {
		t.Fatalf("audit rows = %+v", rows)
	}
	if rows[0].Details["provider"] != "apple" {
		t.Errorf("details = %v", rows[0].Details)
	}
	out := e.log.String()
	if strings.Count(out, `"audit":true`) != 1 {
		t.Errorf("want one audit log line: %s", out)
	}
	if strings.Contains(out, "ann@gmail.com") {
		t.Errorf("the log holds the email: %s", out)
	}
	// A third login with the linked identity is a plain match.
	if again := e.must("apple", trusted(), ident("a1", "ann@gmail.com", true)); again.ID != g.ID || len(e.audits()) != 1 {
		t.Fatal("a second login linked again")
	}
}

// Covers: SEC-04 (part)
// Acceptance: Auto-link domains (part)
func TestAutoLinkOnlyOnListedDomains(t *testing.T) {
	e := newEnv(t)
	g := e.must("google", trusted(), ident("g1", "ann@example.com", true))
	h := e.must("github", trusted(), ident("h1", "ann@example.com", true))
	if g.ID == h.ID {
		t.Fatal("linked on a domain that is not listed")
	}
	if h.EmailVerified {
		t.Error("the second holder of a verified email was created verified")
	}
	if len(e.audits()) != 0 {
		t.Error("audit rows without a link")
	}

	e.realm.UserData.AutoLinkDomains = append(e.realm.UserData.AutoLinkDomains, "Example.COM")
	g2 := e.must("google", trusted(), ident("g2", "bob@example.com", true))
	h2 := e.must("github", trusted(), ident("h2", "bob@example.com", true))
	if g2.ID != h2.ID {
		t.Fatal("not linked after the domain was listed")
	}
}

// Covers: FR-12 (part)
// Acceptance: Email case (part)
func TestEmailsAreNormalized(t *testing.T) {
	e := newEnv(t)
	g := e.must("google", trusted(), ident("g1", "Foo@gmail.com", true))
	a := e.must("apple", trusted(), ident("a1", " foo@gmail.com ", true))
	if g.ID != a.ID {
		t.Fatal("case and spaces made two users")
	}
	if g.EmailKey != "foo@gmail.com" || g.Email != "Foo@gmail.com" {
		t.Fatalf("email %q key %q", g.Email, g.EmailKey)
	}
}

// Covers: FR-12 (part)
// Acceptance: One verified email (part)
func TestSecondVerifiedHolderIsCreatedUnverified(t *testing.T) {
	e := newEnv(t)
	first := e.must("google", trusted(), ident("g1", "ann@gmail.com", true))
	noLink := trusted()
	noLink.AutoLink = false
	second := e.must("apple", noLink, ident("a1", "ann@gmail.com", true))
	if first.ID == second.ID || second.EmailVerified || !first.EmailVerified {
		t.Fatalf("first %+v second %+v", first, second)
	}
	if second.EmailKey != "ann@gmail.com" {
		t.Errorf("key = %q", second.EmailKey)
	}
}

// Covers: FR-12 (part)
// Acceptance: Email change (part)
func TestEmailChangeBySyncMode(t *testing.T) {
	t.Run("import updates the identity only", func(t *testing.T) {
		e := newEnv(t)
		u := e.must("google", trusted(), ident("g1", "ann@gmail.com", true))
		again := e.must("google", trusted(), ident("g1", "new@gmail.com", true))
		if again.Email != "ann@gmail.com" {
			t.Errorf("user email = %q", again.Email)
		}
		if ids := e.identities(u); len(ids) != 1 || ids[0].Email != "new@gmail.com" {
			t.Errorf("identities = %+v", ids)
		}
	})
	t.Run("force updates the user", func(t *testing.T) {
		e := newEnv(t)
		p := trusted()
		p.SyncMode = "force"
		u := e.must("google", p, ident("g1", "ann@gmail.com", true))
		again := e.must("google", p, ident("g1", "New@gmail.com", true))
		if again.ID != u.ID || again.Email != "New@gmail.com" || again.EmailKey != "new@gmail.com" || !again.EmailVerified {
			t.Errorf("user = %+v", again)
		}
		if got := e.stored(u); got.EmailKey != "new@gmail.com" {
			t.Errorf("stored = %+v", got)
		}
	})
	t.Run("force to an unverified email", func(t *testing.T) {
		e := newEnv(t)
		p := trusted()
		p.SyncMode = "force"
		e.must("google", p, ident("g1", "ann@gmail.com", true))
		again := e.must("google", p, ident("g1", "ann@gmail.com", false))
		if again.EmailVerified {
			t.Error("still verified")
		}
	})
	t.Run("force to an email another verified user holds", func(t *testing.T) {
		e := newEnv(t)
		p := trusted()
		p.SyncMode = "force"
		e.must("github", trusted(), ident("h1", "bob@gmail.com", true))
		u := e.must("google", p, ident("g1", "ann@gmail.com", true))
		again := e.must("google", p, ident("g1", "bob@gmail.com", true))
		if again.ID != u.ID || again.Email != "ann@gmail.com" || again.EmailKey != "ann@gmail.com" {
			t.Errorf("user = %+v, want the old email kept", again)
		}
		out := e.log.String()
		if !strings.Contains(out, "email conflict") || strings.Contains(out, "bob@gmail.com") || strings.Contains(out, "ann@gmail.com") {
			t.Errorf("log = %s", out)
		}
		if ids := e.identities(u); ids[0].Email != "bob@gmail.com" {
			t.Errorf("identity email = %q, the identity is updated at every login", ids[0].Email)
		}
	})
}

// Covers: SEC-04 (part)
// Acceptance: No unsafe link (part)
func TestNoUnsafeLink(t *testing.T) {
	e := newEnv(t)
	g := e.must("google", trusted(), ident("g1", "ann@gmail.com", true))
	cases := []struct {
		name string
		key  string
		p    *config.Provider
		id   provider.Identity
	}{
		{"unverified email", "github", trusted(), ident("h1", "ann@gmail.com", false)},
		{"facebook", "facebook", untrusted(), ident("f1", "ann@gmail.com", true)},
		{"default generic oidc", "corp", untrusted(), ident("o1", "ann@gmail.com", true)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u := e.must(tc.key, tc.p, tc.id)
			if u.ID == g.ID {
				t.Fatal("linked")
			}
			if u.EmailVerified {
				t.Error("created verified")
			}
		})
	}
	if len(e.audits()) != 0 {
		t.Error("audit rows without a link")
	}
}

// Covers: FR-12 (part)
// Acceptance: Apple private relay (part)
func TestApplePrivateRelay(t *testing.T) {
	e := newEnv(t)
	a := e.must("apple", trusted(), ident("a1", "xyz@privaterelay.appleid.com", true))
	g := e.must("google", trusted(), ident("g1", "ann@gmail.com", true))
	again := e.must("apple", trusted(), ident("a1", "xyz@privaterelay.appleid.com", true))
	if a.ID == g.ID || again.ID != a.ID {
		t.Fatalf("a %q g %q again %q", a.ID, g.ID, again.ID)
	}
}

// Covers: FR-22 (part)
// Acceptance: Apple name (part)
func TestNameIsNeverBlanked(t *testing.T) {
	e := newEnv(t)
	first := provider.Identity{Subject: "a1", Email: "x@privaterelay.appleid.com", EmailVerified: true, Name: "Ann Apple"}
	e.must("apple", trusted(), first)
	second := first
	second.Name = ""
	if u := e.must("apple", trusted(), second); u.Name != "Ann Apple" {
		t.Fatalf("name = %q", u.Name)
	}
	// Also under force.
	p := trusted()
	p.SyncMode = "force"
	if u := e.must("apple", p, second); u.Name != "Ann Apple" {
		t.Fatalf("name under force = %q", u.Name)
	}
	// A later name replaces it under force only.
	third := first
	third.Name = "Ann B"
	if u := e.must("apple", trusted(), third); u.Name != "Ann Apple" {
		t.Fatalf("import changed the name to %q", u.Name)
	}
	if u := e.must("apple", p, third); u.Name != "Ann B" {
		t.Fatalf("force left the name %q", u.Name)
	}
	// With keep_name_if_missing off an empty name overwrites under force.
	e.realm.UserData.KeepNameIfMissing = false
	if u := e.must("apple", p, second); u.Name != "" {
		t.Fatalf("name = %q, want blank when keep_name_if_missing is false", u.Name)
	}
}

// Covers: FR-22 (part)
// Acceptance: User data (part)
func TestAttributesDecideWhatIsStored(t *testing.T) {
	t.Run("email only", func(t *testing.T) {
		e := newEnv(t)
		e.realm.UserData.Attributes = []string{"email"}
		p := trusted()
		p.SyncMode = "force"
		u := e.must("google", p, ident("g1", "ann@gmail.com", true))
		if u.Name != "" || u.Email != "ann@gmail.com" {
			t.Fatalf("user = %+v", u)
		}
		if again := e.must("google", p, ident("g1", "ann@gmail.com", true)); again.Name != "" {
			t.Fatalf("name stored on a later login: %q", again.Name)
		}
	})
	t.Run("name only", func(t *testing.T) {
		e := newEnv(t)
		e.realm.UserData.Attributes = []string{"name"}
		g := e.must("google", trusted(), ident("g1", "ann@gmail.com", true))
		a := e.must("apple", trusted(), ident("a1", "ann@gmail.com", true))
		if g.Email != "" || g.EmailKey != "" || g.EmailVerified || g.Name != "Ann" {
			t.Fatalf("user = %+v", g)
		}
		if g.ID == a.ID {
			t.Error("linked on an email that is not stored")
		}
		if ids := e.identities(g); ids[0].Email != "" {
			t.Errorf("identity email = %q", ids[0].Email)
		}
	})
	t.Run("none", func(t *testing.T) {
		e := newEnv(t)
		e.realm.UserData.Attributes = nil
		u := e.must("google", trusted(), ident("g1", "ann@gmail.com", true))
		if u.Email != "" || u.Name != "" || u.ID == "" {
			t.Fatalf("user = %+v", u)
		}
	})
}

// Covers: FR-12 (part)
func TestUserWithoutEmail(t *testing.T) {
	e := newEnv(t)
	a := e.must("github", trusted(), provider.Identity{Subject: "h1", Name: "Ann"})
	b := e.must("github", trusted(), provider.Identity{Subject: "h2", Name: "Bob"})
	if a.ID == b.ID || a.Email != "" || a.EmailVerified {
		t.Fatalf("users %+v %+v", a, b)
	}
}

// Covers: FR-12 (part)
func TestDisabledAndRefused(t *testing.T) {
	t.Run("disabled user by identity", func(t *testing.T) {
		e := newEnv(t)
		u := e.must("google", trusted(), ident("g1", "ann@gmail.com", true))
		e.setDisabled(u)
		_, err := e.resolve("google", trusted(), ident("g1", "ann@gmail.com", true))
		if !errors.Is(err, user.ErrDisabled) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("disabled auto-link target", func(t *testing.T) {
		e := newEnv(t)
		u := e.must("google", trusted(), ident("g1", "ann@gmail.com", true))
		e.setDisabled(u)
		_, err := e.resolve("apple", trusted(), ident("a1", "ann@gmail.com", true))
		if !errors.Is(err, user.ErrDisabled) {
			t.Fatalf("err = %v", err)
		}
		if !notFoundIdentity(t, e, "apple", "a1") || len(e.audits()) != 0 {
			t.Error("a refused login left an identity or an audit row")
		}
	})
	t.Run("no subject", func(t *testing.T) {
		e := newEnv(t)
		_, err := e.resolve("google", trusted(), ident("", "ann@gmail.com", true))
		if !errors.Is(err, user.ErrRefused) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("realm disabled", func(t *testing.T) {
		e := newEnv(t)
		e.realm.Enabled = false
		_, err := e.resolve("google", trusted(), ident("g1", "ann@gmail.com", true))
		if !errors.Is(err, user.ErrRefused) {
			t.Fatalf("err = %v", err)
		}
	})
}

// Covers: SEC-13 (part)
func TestResolveInputLogsNoEmail(t *testing.T) {
	in := user.ResolveInput{
		Realm: defaultRealm(), ProviderKey: "google", Provider: trusted(),
		Identity:            provider.Identity{Subject: "sub-1", Email: "ann@example.com", Name: "Ann Secret", RefreshToken: "REFRESH-SECRET"},
		SealedProviderToken: "SEALED-SECRET",
	}
	var buf bytes.Buffer
	log := logx.New(&buf, slog.LevelDebug, clock.NewFake(start))
	log.Info("direct", "input", in)
	log.Info("pointer", "input", &in)
	log.Info("nested", "details", map[string]any{"input": in})
	out := buf.String()
	for _, s := range []string{"ann@example.com", "Ann Secret", "REFRESH-SECRET", "SEALED-SECRET"} {
		if strings.Contains(out, s) {
			t.Errorf("log holds %q: %s", s, out)
		}
	}
	if !strings.Contains(out, "sub-1") {
		t.Errorf("subject not logged: %s", out)
	}
}

func TestErrorsText(t *testing.T) {
	if user.ErrDisabled.Error() == "" || user.ErrRefused.Error() == "" || errors.Is(user.ErrDisabled, user.ErrRefused) {
		t.Fatal("sentinel errors")
	}
}

func TestStoreFailures(t *testing.T) {
	scenarios := []struct {
		name string
		ops  []string
		run  func(e *env) error
	}{
		{"new user", []string{"Realms.Ensure", "Identities.Find", "Users.FindVerifiedByEmailKey", "Users.Create", "Identities.Create"},
			func(e *env) error {
				_, err := e.resolve("google", trusted(), ident("g9", "new@gmail.com", true))
				return err
			}},
		{"auto-link", []string{"Users.FindVerifiedByEmailKey", "Identities.Create", "Audit.Insert"},
			func(e *env) error {
				_, err := e.resolve("apple", trusted(), ident("a1", "ann@gmail.com", true))
				return err
			}},
		{"known identity", []string{"Users.Get", "Identities.Update", "Users.Update", "Users.FindVerifiedByEmailKey"},
			func(e *env) error {
				p := trusted()
				p.SyncMode = "force"
				_, err := e.resolve("google", p, ident("g1", "other@gmail.com", true))
				return err
			}},
	}
	for _, sc := range scenarios {
		for _, op := range sc.ops {
			t.Run(sc.name+" "+op, func(t *testing.T) {
				base := testutil.NewStore(t)
				seed := newEnvWith(t, base)
				seed.must("google", trusted(), ident("g1", "ann@gmail.com", true))
				seed.log.Reset()
				f := testutil.NewFaultStore(base)
				f.Fail(op, errInjected)
				e := newEnvWith(t, f)
				err := sc.run(e)
				if !errors.Is(err, errInjected) || errors.Is(err, user.ErrDisabled) || errors.Is(err, user.ErrRefused) {
					t.Fatalf("err = %v, want the store failure", err)
				}
				if strings.Contains(e.log.String(), `"audit":true`) {
					t.Errorf("audit line logged for a failed login: %s", e.log.String())
				}
				if sc.name == "auto-link" {
					if !notFoundIdentity(t, seed, "apple", "a1") || len(seed.audits()) != 0 {
						t.Error("a failed link left an identity or an audit row")
					}
				}
			})
		}
	}
}

var errInjected = errors.New("injected failure")

func TestUnavailableStoreIsReturned(t *testing.T) {
	f := testutil.NewFaultStore(testutil.NewStore(t))
	f.FailWrite = store.ErrUnavailable
	e := newEnvWith(t, f)
	_, err := e.resolve("google", trusted(), ident("g1", "ann@gmail.com", true))
	if !errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("err = %v", err)
	}
}

// tokenOf returns the sealed provider token stored on the user's identity of
// the provider.
func (e *env) tokenOf(u *store.User, key string) string {
	e.t.Helper()
	for _, i := range e.identities(u) {
		if string(i.Provider) == key {
			return i.ProviderRefreshTokenEnc
		}
	}
	e.t.Fatalf("no %s identity", key)
	return ""
}

func (e *env) resolveSealed(key string, p *config.Provider, id provider.Identity, sealed string) *store.User {
	e.t.Helper()
	u, err := e.svc.Resolve(context.Background(), user.ResolveInput{
		Realm: e.realm, ProviderKey: config.ProviderKey(key), Provider: p, Identity: id, SealedProviderToken: sealed,
	})
	if err != nil {
		e.t.Fatalf("Resolve(%s): %v", key, err)
	}
	return u
}

// Covers: SEC-10 (part)
func TestResolveStoresTheSealedProviderToken(t *testing.T) {
	t.Run("a new identity", func(t *testing.T) {
		e := newEnv(t)
		u := e.resolveSealed("apple", trusted(), ident("a1", "ann@gmail.com", true), "sealed-1")
		if got := e.tokenOf(u, "apple"); got != "sealed-1" {
			t.Errorf("stored %q", got)
		}
	})
	t.Run("an identity linked to an existing user", func(t *testing.T) {
		e := newEnv(t)
		e.must("google", trusted(), ident("g1", "ann@gmail.com", true))
		u := e.resolveSealed("apple", trusted(), ident("a1", "ann@gmail.com", true), "sealed-1")
		if n := len(e.identities(u)); n != 2 {
			t.Fatalf("%d identities, want a link", n)
		}
		if got := e.tokenOf(u, "apple"); got != "sealed-1" {
			t.Errorf("stored %q", got)
		}
		if got := e.tokenOf(u, "google"); got != "" {
			t.Errorf("the other identity holds %q", got)
		}
	})
	t.Run("a known identity: replaced by a new token, kept without one", func(t *testing.T) {
		e := newEnv(t)
		id := ident("a1", "ann@gmail.com", true)
		u := e.resolveSealed("apple", trusted(), id, "sealed-1")
		e.resolveSealed("apple", trusted(), id, "sealed-2")
		if got := e.tokenOf(u, "apple"); got != "sealed-2" {
			t.Errorf("after a new token: %q", got)
		}
		e.resolveSealed("apple", trusted(), id, "")
		if got := e.tokenOf(u, "apple"); got != "sealed-2" {
			t.Errorf("after a login without one: %q", got)
		}
	})
	t.Run("nothing to store", func(t *testing.T) {
		e := newEnv(t)
		u := e.must("apple", trusted(), ident("a1", "ann@gmail.com", true))
		if got := e.tokenOf(u, "apple"); got != "" {
			t.Errorf("stored %q", got)
		}
	})
}

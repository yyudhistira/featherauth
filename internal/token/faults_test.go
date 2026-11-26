package token_test

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/secure"
	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/testutil"
	"github.com/yyudhistira/featherauth/internal/token"
)

var errInjected = errors.New("injected failure")

// failingSource gives n good reads, then fails every read.
type failingSource struct{ n int }

func (f *failingSource) Read(p []byte) (int, error) {
	if f.n <= 0 {
		return 0, errInjected
	}
	f.n--
	return secure.Default.Read(p)
}

var _ io.Reader = (*failingSource)(nil)

// Covers: FR-07 (part), FR-08 (part)
func TestRandomnessFailuresAreNotGrantErrors(t *testing.T) {
	ctx := context.Background()
	t.Run("issue", func(t *testing.T) {
		e := newRefreshEnv(t)
		for n := 0; ; n++ {
			c := token.NewCodes(e.st, e.issuer, e.clock, &failingSource{n})
			_, err := c.Issue(ctx, token.IssueInput{Realm: e.realm, Client: e.client("web"), User: "u1", RedirectURI: cb})
			if err == nil {
				if n == 0 {
					t.Fatal("Issue needs no randomness")
				}
				return
			}
			notGrantErr(t, err)
		}
	})
	for _, format := range []string{"opaque", "jwt"} {
		t.Run("exchange "+format, func(t *testing.T) {
			e := newRefreshEnv(t)
			e.realm.Tokens.RefreshTokenFormat = format
			code := e.issue(t, "web", "")
			for n := 0; ; n++ {
				c := token.NewCodes(e.st, e.issuer, e.clock, &failingSource{n})
				_, err := c.Exchange(ctx, e.in("web", code, cb, ""))
				if err == nil {
					return
				}
				notGrantErr(t, err)
			}
		})
		t.Run("refresh "+format, func(t *testing.T) {
			e := newRefreshEnv(t)
			e.realm.Tokens.RefreshTokenFormat = format
			g := e.login(t, "web")
			for n := 0; ; n++ {
				r := token.NewRefresher(e.st, e.issuer, e.clock, &failingSource{n})
				_, err := r.Refresh(ctx, token.RefreshInput{Realm: e.realm, Client: e.client("web"), Token: g.RefreshToken})
				if err == nil {
					return
				}
				notGrantErr(t, err)
			}
		})
	}
}

// Covers: FR-07 (part), FR-08 (part)
func TestSigningFailuresAreNotGrantErrors(t *testing.T) {
	ctx := context.Background()
	t.Run("no key for the access token", func(t *testing.T) {
		e := newRefreshEnv(t)
		g := e.login(t, "web")
		broken := *e.realm
		broken.Tokens.Algorithm = "ES256" // the realm has no EC key
		_, err := e.ref.Refresh(ctx, token.RefreshInput{Realm: &broken, Client: e.client("web"), Token: g.RefreshToken})
		notGrantErr(t, err)
		code := e.issue(t, "web", "")
		in := e.in("web", code, cb, "")
		in.Realm = &broken
		_, err = e.codes.Exchange(ctx, in)
		notGrantErr(t, err)
	})
	t.Run("no RSA key for the ID token", func(t *testing.T) {
		e := newRefreshEnv(t)
		g := e.login(t, "web")
		broken := *e.realm
		broken.Keys = nil
		_, err := e.ref.Refresh(ctx, token.RefreshInput{Realm: &broken, Client: e.client("web"), Token: g.RefreshToken})
		notGrantErr(t, err)
	})
}

// Covers: FR-07 (part), FR-08 (part)
func TestStoreOperationFailures(t *testing.T) {
	ctx := context.Background()
	fault := func(e *refreshEnv, op string) *testutil.FaultStore {
		f := testutil.NewFaultStore(e.st)
		f.Fail(op, errInjected)
		return f
	}
	refreshVia := func(e *refreshEnv, f store.Store, tok string) error {
		_, err := token.NewRefresher(f, e.issuer, e.clock, secure.Default).Refresh(ctx,
			token.RefreshInput{Realm: e.realm, Client: e.client("web"), Token: tok})
		return err
	}
	exchangeVia := func(e *refreshEnv, f store.Store, code string) error {
		_, err := token.NewCodes(f, e.issuer, e.clock, secure.Default).Exchange(ctx, e.in("web", code, cb, ""))
		return err
	}

	for _, op := range []string{"Realms.Find", "Users.Get", "AuthCodes.Consume", "Refresh.Insert"} {
		t.Run("exchange "+op, func(t *testing.T) {
			e := newRefreshEnv(t)
			code := e.issue(t, "web", "")
			notGrantErr(t, exchangeVia(e, fault(e, op), code))
			if _, err := e.codes.Exchange(ctx, e.in("web", code, cb, "")); err != nil {
				t.Fatalf("code not usable after the failure: %v", err)
			}
		})
	}
	t.Run("exchange Refresh.RevokeSession", func(t *testing.T) {
		e := newRefreshEnv(t)
		code := e.issue(t, "web", "")
		e.mustExchange(t, code)
		notGrantErr(t, exchangeVia(e, fault(e, "Refresh.RevokeSession"), code))
	})
	for _, op := range []string{"Realms.Ensure", "AuthCodes.Create"} {
		t.Run("issue "+op, func(t *testing.T) {
			e := newRefreshEnv(t)
			_, err := token.NewCodes(fault(e, op), e.issuer, e.clock, secure.Default).Issue(ctx,
				token.IssueInput{Realm: e.realm, Client: e.client("web"), User: "u1", RedirectURI: cb})
			notGrantErr(t, err)
		})
	}

	for _, op := range []string{
		"Realms.Find", "Users.Get", "Refresh.FindByHash", "Refresh.RevokeOthers",
		"Refresh.Insert", "Refresh.MarkReplaced",
	} {
		t.Run("refresh "+op, func(t *testing.T) {
			e := newRefreshEnv(t)
			g := e.login(t, "web")
			notGrantErr(t, refreshVia(e, fault(e, op), g.RefreshToken))
			if row := e.refreshRow(t, g.RefreshToken); row.ReplacedBy != "" || !row.RevokedAt.IsZero() {
				t.Fatalf("a failed refresh changed the row: %+v", row)
			}
			e.mustRefresh(t, "web", g.RefreshToken)
		})
	}
	t.Run("refresh Refresh.FindByID", func(t *testing.T) {
		e := newRefreshEnv(t)
		g := e.login(t, "web")
		e.mustRefresh(t, "web", g.RefreshToken)
		notGrantErr(t, refreshVia(e, fault(e, "Refresh.FindByID"), g.RefreshToken))
	})
	t.Run("refresh Insert in grace", func(t *testing.T) {
		e := newRefreshEnv(t)
		g := e.login(t, "web")
		e.mustRefresh(t, "web", g.RefreshToken)
		notGrantErr(t, refreshVia(e, fault(e, "Refresh.Insert"), g.RefreshToken))
	})
	t.Run("refresh RevokeSession of a revoked token", func(t *testing.T) {
		e := newRefreshEnv(t)
		g := e.login(t, "web")
		e.mustRefresh(t, "web", g.RefreshToken)
		e.clock.Advance(grace)
		notGrantErr(t, refreshVia(e, fault(e, "Refresh.RevokeSession"), g.RefreshToken))
	})
	t.Run("refresh Extend", func(t *testing.T) {
		e := newRefreshEnv(t)
		e.confidential(false)
		g := e.login(t, "conf")
		r := token.NewRefresher(fault(e, "Refresh.Extend"), e.issuer, e.clock, secure.Default)
		_, err := r.Refresh(ctx, token.RefreshInput{Realm: e.realm, Client: e.client("conf"), Token: g.RefreshToken})
		notGrantErr(t, err)
	})
}

func (e *refreshEnv) mustExchange(t *testing.T, code string) {
	t.Helper()
	if _, err := e.codes.Exchange(context.Background(), e.in("web", code, cb, "")); err != nil {
		t.Fatal(err)
	}
}

// Covers: FR-08 (part)
func TestRefreshRotationOffExpiredSession(t *testing.T) {
	e := newRefreshEnv(t)
	e.confidential(false)
	g := e.login(t, "conf")
	// A cap in the past: the idle lifetime is 1h, the session maximum is
	// lowered after login so that the extended expiry is already over.
	d := config.Duration(time.Minute)
	e.client("conf").SessionMaxLifetime = &d
	e.clock.Advance(10 * time.Minute)
	_, err := e.refresh("conf", g.RefreshToken)
	wantGrantErr(t, err, token.CodeInvalidGrant)
}

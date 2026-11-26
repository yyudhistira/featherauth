package token_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/logx"
	"github.com/yyudhistira/featherauth/internal/secure"
	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/testutil"
	"github.com/yyudhistira/featherauth/internal/token"
)

const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

func s256(v string) string {
	sum := sha256.Sum256([]byte(v))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

type codesEnv struct {
	*env
	st    store.Store
	codes *token.Codes
	rid   store.RealmID
}

func newCodesEnv(t *testing.T) *codesEnv {
	t.Helper()
	return newCodesEnvOn(t, testutil.NewStore(t))
}

// newCodesEnvOn is newCodesEnv on the store st.
func newCodesEnvOn(t *testing.T, st store.Store) *codesEnv {
	t.Helper()
	e := newEnv(t, "RS256", "")
	ctx := context.Background()
	var rid store.RealmID
	err := st.Write(ctx, func(tx store.Tx) error {
		var err error
		rid, err = tx.Realms().Ensure(ctx, e.realm.Name, "realm-1", e.clock.Now())
		if err != nil {
			return err
		}
		return tx.Users().Create(ctx, store.User{
			ID: "u1", RealmID: rid, Email: "ann@example.com", EmailKey: "ann@example.com",
			EmailVerified: true, Name: "Ann", CreatedAt: e.clock.Now(), UpdatedAt: e.clock.Now(),
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	return &codesEnv{e, st, token.NewCodes(st, e.issuer, e.clock, secure.Default), rid}
}

func (e *codesEnv) issue(t *testing.T, client, challenge string) string {
	t.Helper()
	code, err := e.codes.Issue(context.Background(), token.IssueInput{
		Realm: e.realm, Client: e.client(client), User: "u1",
		RedirectURI: "https://app.example.com/callback", CodeChallenge: challenge,
		Nonce: "n-1", AuthTime: e.clock.Now().Add(-time.Minute),
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return code
}

func (e *codesEnv) in(client, code, redirect, v string) token.ExchangeInput {
	return token.ExchangeInput{
		Realm: e.realm, Client: e.client(client), Code: code, RedirectURI: redirect, Verifier: v,
	}
}

const cb = "https://app.example.com/callback"

func wantGrantErr(t *testing.T, err error, code string) {
	t.Helper()
	var ge *token.GrantError
	if !errors.As(err, &ge) || ge.Code != code {
		t.Fatalf("err = %v, want grant error %s", err, code)
	}
}

func (e *codesEnv) refreshRow(t *testing.T, raw string) store.RefreshToken {
	t.Helper()
	var rt store.RefreshToken
	err := e.st.Read(context.Background(), func(tx store.Tx) error {
		var err error
		rt, err = tx.RefreshTokens().FindByHash(context.Background(), e.rid, secure.HashOf(raw))
		return err
	})
	if err != nil {
		t.Fatalf("FindByHash: %v", err)
	}
	return rt
}

// Covers: FR-07 (part), SEC-01 (part)
func TestCodeGrantHappyPath(t *testing.T) {
	e := newCodesEnv(t)
	code := e.issue(t, "web", s256(verifier))
	g, err := e.codes.Exchange(context.Background(), e.in("web", code, cb, verifier))
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if g.AccessToken == "" || g.IDToken == "" || g.RefreshToken == "" || g.Scope != "openid" {
		t.Fatalf("grant = %+v", g)
	}
	if g.ExpiresIn != 900 {
		t.Errorf("ExpiresIn = %d", g.ExpiresIn)
	}
	rt := e.refreshRow(t, g.RefreshToken)
	if rt.UserID != "u1" || rt.ClientID != "web" || rt.Nonce != "n-1" || rt.SessionID == "" {
		t.Errorf("row = %+v", rt)
	}
	if !rt.AuthTime.Equal(e.clock.Now().Add(-time.Minute)) || !rt.SessionStartedAt.Equal(e.clock.Now()) {
		t.Errorf("times = %v %v", rt.AuthTime, rt.SessionStartedAt)
	}
	idle := e.client("web").Lifetimes().RefreshIdle
	if want := e.clock.Now().Add(idle); !rt.ExpiresAt.Equal(want) || g.RefreshExpiresIn != int(idle.Seconds()) {
		t.Errorf("refresh expiry %v / %d, want %v", rt.ExpiresAt, g.RefreshExpiresIn, want)
	}
	d := decode(t, e.env, g.AccessToken)
	if d.claims["sid"] != string(rt.SessionID) || d.claims["sub"] != "u1" {
		t.Errorf("claims = %v", d.claims)
	}
	if id := decode(t, e.env, g.IDToken); id.claims["sid"] != string(rt.SessionID) || id.claims["nonce"] != "n-1" {
		t.Errorf("id claims = %v", id.claims)
	}
}

func TestCodeGrantWithoutChallenge(t *testing.T) {
	e := newCodesEnv(t)
	code := e.issue(t, "web", "")
	if _, err := e.codes.Exchange(context.Background(), e.in("web", code, cb, "")); err != nil {
		t.Fatalf("Exchange: %v", err)
	}
}

func TestCodeGrantJWTRefreshAndSessionMax(t *testing.T) {
	e := newCodesEnv(t)
	e.realm.Tokens.RefreshTokenFormat = "jwt"
	e.realm.Tokens.SessionMaxLifetime = config.Duration(time.Hour)
	e.realm.Tokens.RefreshIdleLifetime = config.Duration(24 * time.Hour)
	code := e.issue(t, "web", "")
	g, err := e.codes.Exchange(context.Background(), e.in("web", code, cb, ""))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(g.RefreshToken, ".") != 2 {
		t.Fatalf("refresh token is not a JWT: %q", g.RefreshToken)
	}
	rt := e.refreshRow(t, g.RefreshToken)
	if want := e.clock.Now().Add(time.Hour); !rt.ExpiresAt.Equal(want) || g.RefreshExpiresIn != 3600 {
		t.Errorf("expiry = %v / %d, want %v", rt.ExpiresAt, g.RefreshExpiresIn, want)
	}
}

// Covers: FR-07 (part), SEC-01 (part)
// Acceptance: PKCE (part)
func TestCodeGrantMalformedVerifier(t *testing.T) {
	for _, tc := range []struct{ name, v string }{
		{"too short", strings.Repeat("a", 42)},
		{"too long", strings.Repeat("a", 129)},
		{"bad character", strings.Repeat("a", 42) + "+"},
		{"space", strings.Repeat("a", 42) + " "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newCodesEnv(t)
			code := e.issue(t, "web", s256(verifier))
			_, err := e.codes.Exchange(context.Background(), e.in("web", code, cb, tc.v))
			wantGrantErr(t, err, token.CodeInvalidRequest)
			// The code was not used up by the malformed request.
			if _, err := e.codes.Exchange(context.Background(), e.in("web", code, cb, verifier)); err != nil {
				t.Fatalf("code was burnt: %v", err)
			}
		})
	}
}

// Covers: FR-07 (part), SEC-01 (part)
// Acceptance: PKCE (part)
// Acceptance: PKCE downgrade (part)
// Acceptance: Code binding (part)
func TestCodeGrantInvalidGrant(t *testing.T) {
	other := strings.Repeat("b", 43)
	tests := []struct {
		name      string
		challenge string
		client    string
		redirect  string
		verifier  string
		advance   time.Duration
	}{
		{"wrong verifier", s256(verifier), "web", cb, other, 0},
		{"missing verifier", s256(verifier), "web", cb, "", 0},
		{"verifier for a code without challenge", "", "web", cb, verifier, 0},
		{"expired code", s256(verifier), "web", cb, verifier, 60 * time.Second},
		{"another client", s256(verifier), "plain", cb, verifier, 0},
		{"another redirect uri", s256(verifier), "web", "https://app.example.com/other", verifier, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newCodesEnv(t)
			code := e.issue(t, "web", tc.challenge)
			e.clock.Advance(tc.advance)
			_, err := e.codes.Exchange(context.Background(), e.in(tc.client, code, tc.redirect, tc.verifier))
			wantGrantErr(t, err, token.CodeInvalidGrant)
		})
	}
	t.Run("unknown code", func(t *testing.T) {
		e := newCodesEnv(t)
		_, err := e.codes.Exchange(context.Background(), e.in("web", "nope", cb, verifier))
		wantGrantErr(t, err, token.CodeInvalidGrant)
	})
}

// Covers: SEC-06 (part)
// Acceptance: Code lifetime and reuse (part)
func TestCodeReuseRevokesSession(t *testing.T) {
	e := newCodesEnv(t)
	code := e.issue(t, "web", s256(verifier))
	g, err := e.codes.Exchange(context.Background(), e.in("web", code, cb, verifier))
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.codes.Exchange(context.Background(), e.in("web", code, cb, verifier))
	wantGrantErr(t, err, token.CodeInvalidGrant)
	if rt := e.refreshRow(t, g.RefreshToken); rt.RevokedAt.IsZero() {
		t.Fatal("refresh token of the session still works after code reuse")
	}
}

// Covers: FR-07 (part)
// Acceptance: Code lifetime and reuse (part)
func TestCodeLifetimeFollowsConfig(t *testing.T) {
	e := newCodesEnv(t)
	e.realm.Tokens.CodeLifetime = config.Duration(10 * time.Second)
	code := e.issue(t, "web", "")
	e.clock.Advance(10 * time.Second)
	_, err := e.codes.Exchange(context.Background(), e.in("web", code, cb, ""))
	wantGrantErr(t, err, token.CodeInvalidGrant)
}

// Covers: FR-07 (part)
// Acceptance: Code binding (part)
func TestCodeGrantStateChangedAfterIssue(t *testing.T) {
	t.Run("user disabled", func(t *testing.T) {
		e := newCodesEnv(t)
		code := e.issue(t, "web", "")
		err := e.st.Write(context.Background(), func(tx store.Tx) error {
			u, err := tx.Users().Get(context.Background(), e.rid, "u1")
			if err != nil {
				return err
			}
			u.DisabledAt = e.clock.Now()
			return tx.Users().Update(context.Background(), u)
		})
		if err != nil {
			t.Fatal(err)
		}
		_, err = e.codes.Exchange(context.Background(), e.in("web", code, cb, ""))
		wantGrantErr(t, err, token.CodeInvalidGrant)
	})
	t.Run("user deleted", func(t *testing.T) {
		e := newCodesEnv(t)
		code := e.issue(t, "web", "")
		err := e.st.Write(context.Background(), func(tx store.Tx) error {
			return tx.Users().Delete(context.Background(), e.rid, "u1")
		})
		if err != nil {
			t.Fatal(err)
		}
		_, err = e.codes.Exchange(context.Background(), e.in("web", code, cb, ""))
		wantGrantErr(t, err, token.CodeInvalidGrant)
	})
	t.Run("client removed", func(t *testing.T) {
		e := newCodesEnv(t)
		code := e.issue(t, "web", "")
		in := e.in("web", code, cb, "")
		stripped := *e.realm
		stripped.Clients = map[config.ClientID]*config.Client{"plain": e.client("plain")}
		in.Realm = &stripped
		_, err := e.codes.Exchange(context.Background(), in)
		wantGrantErr(t, err, token.CodeInvalidGrant)
	})
	t.Run("realm disabled", func(t *testing.T) {
		e := newCodesEnv(t)
		code := e.issue(t, "web", "")
		e.realm.Enabled = false
		_, err := e.codes.Exchange(context.Background(), e.in("web", code, cb, ""))
		wantGrantErr(t, err, token.CodeInvalidGrant)
	})
}

func TestCodeIssueStoresOnlyTheHash(t *testing.T) {
	e := newCodesEnv(t)
	code := e.issue(t, "web", s256(verifier))
	err := e.st.Write(context.Background(), func(tx store.Tx) error {
		c, err := tx.AuthCodes().Consume(context.Background(), secure.HashOf(code), e.clock.Now())
		if err != nil {
			return err
		}
		if c.CodeHash == secure.Hash(code) || c.SessionID == "" || c.UserID != "u1" || c.ClientID != "web" {
			t.Errorf("row = %+v", c)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestCodeIssueErrors(t *testing.T) {
	e := newCodesEnv(t)
	_, err := e.codes.Issue(context.Background(), token.IssueInput{
		Realm: e.realm, Client: &config.Client{}, User: "u1", RedirectURI: cb,
	})
	if err == nil {
		t.Fatal("Issue with a client outside the realm succeeded")
	}
}

// Covers: SEC-13 (part)
func TestGrantLogsNoToken(t *testing.T) {
	g := &token.Grant{
		AccessToken: "ACCESS-SECRET", IDToken: "ID-SECRET", RefreshToken: "REFRESH-SECRET",
		ExpiresIn: 900, RefreshExpiresIn: 3600, Scope: "openid",
	}
	var buf bytes.Buffer
	log := logx.New(&buf, slog.LevelDebug, clock.NewFake(time.Unix(0, 0)))
	log.Info("grant", "grant", g, "nested", map[string]any{"grant": g}, "value", *g)
	out := buf.String()
	for _, s := range []string{"ACCESS-SECRET", "ID-SECRET", "REFRESH-SECRET"} {
		if strings.Contains(out, s) {
			t.Errorf("log holds %s: %s", s, out)
		}
	}
}

func notGrantErr(t *testing.T, err error) {
	t.Helper()
	var ge *token.GrantError
	if err == nil || errors.As(err, &ge) {
		t.Fatalf("err = %v, want a store failure that is not a GrantError", err)
	}
}

// Covers: FR-07 (part)
func TestCodesStoreFailures(t *testing.T) {
	ctx := context.Background()
	busy := fmt.Errorf("%w: database is locked", store.ErrUnavailable)

	t.Run("unavailable store on exchange", func(t *testing.T) {
		e := newCodesEnv(t)
		code := e.issue(t, "web", "")
		fs := faultWrite(e.st, busy)
		_, err := token.NewCodes(fs, e.issuer, e.clock, secure.Default).Exchange(ctx, e.in("web", code, cb, ""))
		notGrantErr(t, err)
		if !errors.Is(err, store.ErrUnavailable) {
			t.Fatalf("err = %v, want ErrUnavailable", err)
		}
	})
	t.Run("unavailable store on issue", func(t *testing.T) {
		e := newCodesEnv(t)
		fs := faultWrite(e.st, busy)
		_, err := token.NewCodes(fs, e.issuer, e.clock, secure.Default).Issue(ctx, token.IssueInput{
			Realm: e.realm, Client: e.client("web"), User: "u1", RedirectURI: cb,
		})
		notGrantErr(t, err)
		if !errors.Is(err, store.ErrUnavailable) {
			t.Fatalf("err = %v, want ErrUnavailable", err)
		}
	})
	t.Run("cancelled context", func(t *testing.T) {
		e := newCodesEnv(t)
		code := e.issue(t, "web", "")
		cctx, cancel := context.WithCancel(ctx)
		cancel()
		_, err := e.codes.Exchange(cctx, e.in("web", code, cb, ""))
		notGrantErr(t, err)
		if _, err := e.codes.Exchange(ctx, e.in("web", code, cb, "")); err != nil {
			t.Fatalf("code unusable after a cancelled request: %v", err)
		}
	})
	t.Run("closed store", func(t *testing.T) {
		e := newCodesEnv(t)
		code := e.issue(t, "web", "")
		if err := e.st.Close(); err != nil {
			t.Fatal(err)
		}
		_, err := e.codes.Exchange(ctx, e.in("web", code, cb, ""))
		notGrantErr(t, err)
	})
	t.Run("failure in the middle of the transaction rolls back", func(t *testing.T) {
		e := newCodesEnv(t)
		code := e.issue(t, "web", "")
		fs := faultInsert(e.st, errors.New("disk full"))
		_, err := token.NewCodes(fs, e.issuer, e.clock, secure.Default).Exchange(ctx, e.in("web", code, cb, ""))
		notGrantErr(t, err)
		// The code is still unused, so the retry succeeds.
		if _, err := e.codes.Exchange(ctx, e.in("web", code, cb, "")); err != nil {
			t.Fatalf("code was used up by a failed exchange: %v", err)
		}
	})
}

// Covers: FR-07 (part), SEC-01 (part)
// Acceptance: Code binding (part)
func TestCodeUsedUpByFirstRequest(t *testing.T) {
	other := strings.Repeat("b", 43)
	for _, tc := range []struct {
		name, client, redirect, verifier string
	}{
		{"wrong verifier", "web", cb, other},
		{"missing verifier", "web", cb, ""},
		{"wrong client", "plain", cb, verifier},
		{"wrong redirect uri", "web", "https://app.example.com/other", verifier},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newCodesEnv(t)
			code := e.issue(t, "web", s256(verifier))
			_, err := e.codes.Exchange(context.Background(), e.in(tc.client, code, tc.redirect, tc.verifier))
			wantGrantErr(t, err, token.CodeInvalidGrant)
			_, err = e.codes.Exchange(context.Background(), e.in("web", code, cb, verifier))
			wantGrantErr(t, err, token.CodeInvalidGrant)
		})
	}
}

// Covers: SEC-06 (part)
// Acceptance: Code lifetime and reuse (part)
func TestCodeReuseByAnotherClientRevokesSession(t *testing.T) {
	e := newCodesEnv(t)
	code := e.issue(t, "web", "")
	g, err := e.codes.Exchange(context.Background(), e.in("web", code, cb, ""))
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.codes.Exchange(context.Background(), e.in("plain", code, cb, ""))
	wantGrantErr(t, err, token.CodeInvalidGrant)
	if rt := e.refreshRow(t, g.RefreshToken); rt.RevokedAt.IsZero() {
		t.Fatal("session survived reuse of its code by another client")
	}
}

// Covers: FR-07 (part)
func TestExchangeWithoutRealmRowWritesNothing(t *testing.T) {
	e := newCodesEnv(t)
	code := e.issue(t, "web", "")
	ghost := *e.realm
	ghost.Name = "ghost"
	in := e.in("web", code, cb, "")
	in.Realm = &ghost
	_, err := e.codes.Exchange(context.Background(), in)
	wantGrantErr(t, err, token.CodeInvalidGrant)
	err = e.st.Read(context.Background(), func(tx store.Tx) error {
		if _, err := tx.Realms().Find(context.Background(), "ghost"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("realm row created by a refused exchange: %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// The code of the real realm is untouched.
	if _, err := e.codes.Exchange(context.Background(), e.in("web", code, cb, "")); err != nil {
		t.Fatalf("code used up: %v", err)
	}
}

// Covers: FR-07 (part), SEC-06 (part)
// Acceptance: Code lifetime and reuse (part)
func TestConcurrentExchangeHasOneWinner(t *testing.T) {
	e := newCodesEnv(t)
	code := e.issue(t, "web", s256(verifier))
	const n = 8
	var wg sync.WaitGroup
	var ok, refused atomic.Int32
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := e.codes.Exchange(context.Background(), e.in("web", code, cb, verifier))
			var ge *token.GrantError
			switch {
			case err == nil:
				ok.Add(1)
			case errors.As(err, &ge) && ge.Code == token.CodeInvalidGrant:
				refused.Add(1)
			default:
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	wg.Wait()
	if ok.Load() != 1 || refused.Load() != n-1 {
		t.Fatalf("successes = %d, refusals = %d", ok.Load(), refused.Load())
	}
}

func TestGrantErrorText(t *testing.T) {
	err := &token.GrantError{Code: token.CodeInvalidGrant, Description: "invalid code"}
	if got := err.Error(); got != "token: invalid_grant: invalid code" {
		t.Fatalf("Error() = %q", got)
	}
}

func faultWrite(s store.Store, err error) *testutil.FaultStore {
	f := testutil.NewFaultStore(s)
	f.FailWrite = err
	return f
}

func faultInsert(s store.Store, err error) *testutil.FaultStore {
	f := testutil.NewFaultStore(s)
	f.Fail("Refresh.Insert", err)
	return f
}

// loginRow stores an auth request of the realm, as the callback reads it.
func (e *codesEnv) loginRow(t *testing.T, id store.AuthRequestID) {
	t.Helper()
	err := e.st.Write(context.Background(), func(tx store.Tx) error {
		return tx.AuthRequests().Create(context.Background(), store.AuthRequest{
			ID: id, RealmID: e.rid, ClientID: "web", RedirectURI: cb, Provider: "github",
			ExpiresAt: e.clock.Now().Add(time.Minute),
		})
	})
	if err != nil {
		t.Fatal(err)
	}
}

// loginExists reports whether the auth request is still stored.
func (e *codesEnv) loginExists(t *testing.T, id store.AuthRequestID) bool {
	t.Helper()
	var found bool
	err := e.st.Read(context.Background(), func(tx store.Tx) error {
		_, err := tx.AuthRequests().Get(context.Background(), id)
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		found = err == nil
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return found
}

// codeRows counts the login codes in the store. DeleteExpired with a time after
// every code's expiry counts them all, and the write is rolled back so the
// count changes nothing.
func (e *codesEnv) codeRows(t *testing.T) int64 {
	t.Helper()
	errCount := errors.New("count only")
	var n int64
	err := e.st.Write(context.Background(), func(tx store.Tx) error {
		var err error
		n, err = tx.AuthCodes().DeleteExpired(context.Background(), e.clock.Now().Add(time.Hour))
		if err != nil {
			return err
		}
		return errCount
	})
	if !errors.Is(err, errCount) {
		t.Fatalf("counting the codes: %v", err)
	}
	return n
}

// issueFor issues the login code of the login row id.
func (e *codesEnv) issueFor(codes *token.Codes, id store.AuthRequestID) (string, error) {
	return codes.Issue(context.Background(), token.IssueInput{
		Realm: e.realm, Client: e.client("web"), User: "u1", RedirectURI: cb,
		Nonce: "n-1", AuthTime: e.clock.Now().Add(-time.Minute), Login: id,
	})
}

// Covers: SEC-28 (part)
// Acceptance: Login single use (part)
func TestIssueCompletesTheLoginOnce(t *testing.T) {
	t.Run("the login is deleted with the code", func(t *testing.T) {
		e := newCodesEnv(t)
		e.loginRow(t, "login-1")
		if _, err := e.issueFor(e.codes, "login-1"); err != nil {
			t.Fatalf("Issue: %v", err)
		}
		if e.loginExists(t, "login-1") {
			t.Fatal("the login is still stored after its code was issued")
		}
		if n := e.codeRows(t); n != 1 {
			t.Fatalf("%d codes, want 1", n)
		}
	})
	t.Run("a login that is gone issues no code", func(t *testing.T) {
		e := newCodesEnv(t)
		e.loginRow(t, "login-1")
		if _, err := e.issueFor(e.codes, "login-1"); err != nil {
			t.Fatalf("Issue: %v", err)
		}
		_, err := e.issueFor(e.codes, "login-1")
		if !errors.Is(err, token.ErrLoginGone) {
			t.Fatalf("second Issue = %v, want ErrLoginGone", err)
		}
		if n := e.codeRows(t); n != 1 {
			t.Fatalf("%d codes after the refused Issue, want 1", n)
		}
	})
	t.Run("an unknown login issues no code", func(t *testing.T) {
		e := newCodesEnv(t)
		_, err := e.issueFor(e.codes, "never-started")
		if !errors.Is(err, token.ErrLoginGone) {
			t.Fatalf("Issue = %v, want ErrLoginGone", err)
		}
		if n := e.codeRows(t); n != 0 {
			t.Fatalf("%d codes, want 0", n)
		}
	})
	t.Run("a failed delete keeps the login and issues no code", func(t *testing.T) {
		e := newCodesEnv(t)
		e.loginRow(t, "login-1")
		busy := fmt.Errorf("%w: database is locked", store.ErrUnavailable)
		fs := faultWrite(e.st, nil)
		fs.Fail("AuthRequests.Delete", busy)
		_, err := e.issueFor(token.NewCodes(fs, e.issuer, e.clock, secure.Default), "login-1")
		if !errors.Is(err, store.ErrUnavailable) || errors.Is(err, token.ErrLoginGone) {
			t.Fatalf("Issue = %v, want the store failure", err)
		}
		if !e.loginExists(t, "login-1") {
			t.Fatal("the login was deleted by a failed Issue")
		}
		if n := e.codeRows(t); n != 0 {
			t.Fatalf("%d codes, want 0", n)
		}
	})
}

// Covers: SEC-28 (part)
// Acceptance: Login single use (part)
func TestConcurrentIssueHasOneWinner(t *testing.T) {
	e := newCodesEnv(t)
	e.loginRow(t, "login-1")
	const n = 8
	var wg sync.WaitGroup
	var ok, gone atomic.Int32
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := e.issueFor(e.codes, "login-1")
			switch {
			case err == nil:
				ok.Add(1)
			case errors.Is(err, token.ErrLoginGone):
				gone.Add(1)
			default:
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	wg.Wait()
	if ok.Load() != 1 || gone.Load() != n-1 {
		t.Fatalf("codes issued = %d, refused = %d", ok.Load(), gone.Load())
	}
	if c := e.codeRows(t); c != 1 {
		t.Fatalf("%d codes stored, want 1", c)
	}
}

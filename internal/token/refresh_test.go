package token_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/secure"
	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/testutil"
	"github.com/yyudhistira/featherauth/internal/token"
)

type refreshEnv struct {
	*codesEnv
	ref *token.Refresher
}

func newRefreshEnv(t *testing.T) *refreshEnv {
	t.Helper()
	return newRefreshEnvOn(t, testutil.NewStore(t))
}

// newRefreshEnvOn is newRefreshEnv on the store st.
func newRefreshEnvOn(t *testing.T, st store.Store) *refreshEnv {
	t.Helper()
	e := newCodesEnvOn(t, st)
	return &refreshEnv{e, token.NewRefresher(e.st, e.issuer, e.clock, secure.Default)}
}

// login runs a login and returns the first grant.
func (e *refreshEnv) login(t *testing.T, client string) *token.Grant {
	t.Helper()
	code := e.issue(t, client, "")
	g, err := e.codes.Exchange(context.Background(), e.in(client, code, cb, ""))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	return g
}

func (e *refreshEnv) refresh(client, tok string) (*token.Grant, error) {
	return e.ref.Refresh(context.Background(), token.RefreshInput{
		Realm: e.realm, Client: e.client(client), Token: tok,
	})
}

func (e *refreshEnv) mustRefresh(t *testing.T, client, tok string) *token.Grant {
	t.Helper()
	g, err := e.refresh(client, tok)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	return g
}

func (e *refreshEnv) revoked(t *testing.T, tok string) bool {
	t.Helper()
	return !e.refreshRow(t, tok).RevokedAt.IsZero()
}

// confidential adds a confidential client with rotation off to the realm.
func (e *refreshEnv) confidential(rotate bool) {
	d := func(v time.Duration) *config.Duration { c := config.Duration(v); return &c }
	e.realm.Clients["conf"] = &config.Client{
		Type: config.Confidential, RedirectURIs: []string{cb}, RefreshTokenRotation: &rotate,
		AccessTokenLifetime: d(15 * time.Minute), RefreshIdleLifetime: d(time.Hour),
		SessionMaxLifetime: d(0),
	}
}

const grace = 30 * time.Second

// Covers: FR-08 (part)
// Acceptance: Refresh rotation (part)
func TestRefreshRotates(t *testing.T) {
	for _, format := range []string{"opaque", "jwt"} {
		t.Run(format, func(t *testing.T) {
			e := newRefreshEnv(t)
			e.realm.Tokens.RefreshTokenFormat = format
			g0 := e.login(t, "web")
			e.clock.Advance(5 * time.Minute)
			g1 := e.mustRefresh(t, "web", g0.RefreshToken)
			if g1.RefreshToken == g0.RefreshToken || g1.AccessToken == "" || g1.IDToken == "" || g1.Scope != "openid" {
				t.Fatalf("grant = %+v", g1)
			}
			if (format == "jwt") != (strings.Count(g1.RefreshToken, ".") == 2) {
				t.Fatalf("refresh token %q does not match format %s", g1.RefreshToken, format)
			}
			old, row := e.refreshRow(t, g0.RefreshToken), e.refreshRow(t, g1.RefreshToken)
			if old.ReplacedBy != row.ID {
				t.Errorf("replaced_by = %q, want %q", old.ReplacedBy, row.ID)
			}
			if row.SessionID != old.SessionID || !row.SessionStartedAt.Equal(old.SessionStartedAt) ||
				!row.AuthTime.Equal(old.AuthTime) || row.Nonce != "n-1" || row.UserID != "u1" || row.ClientID != "web" {
				t.Errorf("successor row = %+v, old = %+v", row, old)
			}
			// The new refresh token works.
			e.mustRefresh(t, "web", g1.RefreshToken)
		})
	}
}

// Covers: FR-22 (part)
// Acceptance: Token timing (part)
func TestRefreshedTokensKeepSessionClaims(t *testing.T) {
	e := newRefreshEnv(t)
	g0 := e.login(t, "web")
	e.clock.Advance(5 * time.Minute)
	g1 := e.mustRefresh(t, "web", g0.RefreshToken)
	for name, pair := range map[string][2]string{
		"access": {g0.AccessToken, g1.AccessToken}, "id": {g0.IDToken, g1.IDToken},
	} {
		a, b := decode(t, e.env, pair[0]), decode(t, e.env, pair[1])
		for _, k := range []string{"sid", "auth_time", "nonce", "sub"} {
			if a.claims[k] != b.claims[k] {
				t.Errorf("%s token: %s changed from %v to %v", name, k, a.claims[k], b.claims[k])
			}
		}
		if a.claims["iat"] == b.claims["iat"] {
			t.Errorf("%s token: iat did not change", name)
		}
		if got := b.claims["iat"].(float64); int64(got) != e.clock.Now().Unix() {
			t.Errorf("%s token: iat = %v, want now", name, got)
		}
	}
}

// Covers: FR-08 (part), SEC-06 (part)
// Acceptance: Refresh rotation (part)
func TestRefreshReuseAfterGraceRevokesSession(t *testing.T) {
	e := newRefreshEnv(t)
	g0 := e.login(t, "web")
	g1 := e.mustRefresh(t, "web", g0.RefreshToken)
	e.clock.Advance(grace)
	_, err := e.refresh("web", g0.RefreshToken)
	wantGrantErr(t, err, token.CodeInvalidGrant)
	if !e.revoked(t, g1.RefreshToken) {
		t.Fatal("successor still works after reuse of the old token past the grace window")
	}
	_, err = e.refresh("web", g1.RefreshToken)
	wantGrantErr(t, err, token.CodeInvalidGrant)
}

// Covers: FR-08 (part)
// Acceptance: Refresh within grace (part)
func TestRefreshWithinGraceTwiceSucceeds(t *testing.T) {
	e := newRefreshEnv(t)
	g0 := e.login(t, "web")
	g1 := e.mustRefresh(t, "web", g0.RefreshToken)
	e.clock.Advance(grace - time.Second)
	g2 := e.mustRefresh(t, "web", g0.RefreshToken)
	if g1.RefreshToken == g2.RefreshToken {
		t.Fatal("the retry got the same token")
	}
}

// Covers: FR-08 (part), SEC-06 (part)
// Acceptance: Refresh within grace (part)
func TestConcurrentRefreshesBothSucceed(t *testing.T) {
	e := newRefreshEnv(t)
	g0 := e.login(t, "web")
	var wg sync.WaitGroup
	errs := make([]error, 3)
	grants := make([]*token.Grant, 3)
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			grants[i], errs[i] = e.refresh("web", g0.RefreshToken)
		}()
	}
	wg.Wait()
	seen := map[string]bool{}
	for i, err := range errs {
		if err != nil {
			t.Fatalf("refresh %d: %v", i, err)
		}
		seen[grants[i].RefreshToken] = true
	}
	if len(seen) != 3 {
		t.Fatalf("got %d distinct successors, want 3", len(seen))
	}
}

// Covers: FR-08 (part), SEC-06 (part)
// Acceptance: Refresh within grace (part)
func TestRefreshSuccessorsInsideGrace(t *testing.T) {
	setup := func(t *testing.T) (*refreshEnv, [4]string) {
		e := newRefreshEnv(t)
		g0 := e.login(t, "web")
		var toks [4]string
		toks[0] = g0.RefreshToken
		for i := 1; i < 4; i++ {
			toks[i] = e.mustRefresh(t, "web", g0.RefreshToken).RefreshToken
		}
		// All four work until one is used.
		for i, tok := range toks {
			if e.revoked(t, tok) {
				t.Fatalf("token %d revoked before any successor was used", i)
			}
		}
		return e, toks
	}
	t.Run("using one revokes the others", func(t *testing.T) {
		e, toks := setup(t)
		next := e.mustRefresh(t, "web", toks[2]).RefreshToken
		for _, i := range []int{0, 1, 3} {
			if !e.revoked(t, toks[i]) {
				t.Errorf("token %d still active after a successor was used", i)
			}
		}
		if e.revoked(t, next) {
			t.Error("the new token is revoked")
		}
	})
	for _, i := range []int{0, 1, 3} {
		t.Run("presenting another one revokes the session", func(t *testing.T) {
			e, toks := setup(t)
			next := e.mustRefresh(t, "web", toks[2]).RefreshToken
			_, err := e.refresh("web", toks[i])
			wantGrantErr(t, err, token.CodeInvalidGrant)
			if !e.revoked(t, next) {
				t.Error("session still active")
			}
		})
	}
}

// Covers: FR-08 (part), SEC-06 (part)
// Acceptance: Refresh within grace (part)
func TestRefreshOldTokenAfterSuccessorUsedRevokesSession(t *testing.T) {
	e := newRefreshEnv(t)
	g0 := e.login(t, "web")
	g1 := e.mustRefresh(t, "web", g0.RefreshToken)
	g2 := e.mustRefresh(t, "web", g1.RefreshToken)
	// g0 is inside its grace window, but its successor was used.
	_, err := e.refresh("web", g0.RefreshToken)
	wantGrantErr(t, err, token.CodeInvalidGrant)
	if !e.revoked(t, g2.RefreshToken) {
		t.Fatal("session still active")
	}
}

// Covers: FR-08 (part), SEC-06 (part)
// Acceptance: Refresh binding (part)
func TestRefreshBinding(t *testing.T) {
	e := newRefreshEnv(t)
	g := e.login(t, "web")
	_, err := e.refresh("plain", g.RefreshToken)
	wantGrantErr(t, err, token.CodeInvalidGrant)
	// The other client's attempt changes nothing.
	if row := e.refreshRow(t, g.RefreshToken); !row.RevokedAt.IsZero() || row.ReplacedBy != "" {
		t.Fatalf("row changed: %+v", row)
	}
	e.mustRefresh(t, "web", g.RefreshToken)
}

// Covers: FR-08 (part)
// Acceptance: Rotation off (part)
func TestRefreshRotationOff(t *testing.T) {
	e := newRefreshEnv(t)
	e.confidential(false)
	g0 := e.login(t, "conf")
	before := e.refreshRow(t, g0.RefreshToken).ExpiresAt
	e.clock.Advance(20 * time.Minute)
	g1 := e.mustRefresh(t, "conf", g0.RefreshToken)
	if g1.RefreshToken != g0.RefreshToken {
		t.Fatal("rotation off returned another token")
	}
	row := e.refreshRow(t, g0.RefreshToken)
	if !row.ExpiresAt.After(before) || !row.ExpiresAt.Equal(e.clock.Now().Add(time.Hour)) || row.ReplacedBy != "" {
		t.Fatalf("row = %+v, before %v", row, before)
	}
	if g1.RefreshExpiresIn != 3600 {
		t.Errorf("RefreshExpiresIn = %d", g1.RefreshExpiresIn)
	}
	e.mustRefresh(t, "conf", g0.RefreshToken)
}

func TestRefreshRotationOnConfidentialRotates(t *testing.T) {
	e := newRefreshEnv(t)
	e.confidential(true)
	g0 := e.login(t, "conf")
	if g1 := e.mustRefresh(t, "conf", g0.RefreshToken); g1.RefreshToken == g0.RefreshToken {
		t.Fatal("rotation on returned the same token")
	}
}

// Covers: FR-08 (part)
// Acceptance: Long-lived session (part)
func TestRefreshLongIdleLifetime(t *testing.T) {
	const day = 24 * time.Hour
	t.Run("two years idle works", func(t *testing.T) {
		e := newRefreshEnv(t)
		e.realm.Tokens.RefreshIdleLifetime = config.Duration(2 * 365 * day)
		e.realm.Tokens.SessionMaxLifetime = config.Duration(0)
		g := e.login(t, "web")
		e.clock.Advance(400 * day)
		e.mustRefresh(t, "web", g.RefreshToken)
	})
	t.Run("the short default does not", func(t *testing.T) {
		e := newRefreshEnv(t)
		g := e.login(t, "web")
		e.clock.Advance(400 * day)
		_, err := e.refresh("web", g.RefreshToken)
		wantGrantErr(t, err, token.CodeInvalidGrant)
	})
}

// Covers: FR-08 (part)
// Acceptance: Sliding expiry (part)
func TestRefreshSlidingExpiry(t *testing.T) {
	const day = 24 * time.Hour
	t.Run("never passes the session maximum", func(t *testing.T) {
		e := newRefreshEnv(t)
		e.realm.Tokens.RefreshIdleLifetime = config.Duration(10 * day)
		e.realm.Tokens.SessionMaxLifetime = config.Duration(12 * day)
		g := e.login(t, "web")
		start := e.refreshRow(t, g.RefreshToken).SessionStartedAt
		e.clock.Advance(8 * day)
		g = e.mustRefresh(t, "web", g.RefreshToken)
		row := e.refreshRow(t, g.RefreshToken)
		if want := start.Add(12 * day); !row.ExpiresAt.Equal(want) {
			t.Fatalf("expiry = %v, want %v", row.ExpiresAt, want)
		}
		if g.RefreshExpiresIn != int((4 * day).Seconds()) {
			t.Errorf("RefreshExpiresIn = %d", g.RefreshExpiresIn)
		}
		e.clock.Advance(4 * day)
		_, err := e.refresh("web", g.RefreshToken)
		wantGrantErr(t, err, token.CodeInvalidGrant)
	})
	t.Run("zero means idle only", func(t *testing.T) {
		e := newRefreshEnv(t)
		e.realm.Tokens.RefreshIdleLifetime = config.Duration(10 * day)
		e.realm.Tokens.SessionMaxLifetime = config.Duration(0)
		g := e.login(t, "web")
		for i := 0; i < 3; i++ {
			e.clock.Advance(9 * day)
			g = e.mustRefresh(t, "web", g.RefreshToken)
		}
		if row := e.refreshRow(t, g.RefreshToken); !row.ExpiresAt.Equal(e.clock.Now().Add(10 * day)) {
			t.Fatalf("expiry = %v", row.ExpiresAt)
		}
	})
	t.Run("a maximum lowered by config refuses", func(t *testing.T) {
		e := newRefreshEnv(t)
		g := e.login(t, "web")
		e.clock.Advance(time.Hour)
		e.realm.Tokens.SessionMaxLifetime = config.Duration(time.Minute)
		_, err := e.refresh("web", g.RefreshToken)
		wantGrantErr(t, err, token.CodeInvalidGrant)
	})
}

func TestRefreshRevokedTokenChangesNothing(t *testing.T) {
	e := newRefreshEnv(t)
	g := e.login(t, "web")
	other := e.login(t, "web")
	rid := e.rid
	row := e.refreshRow(t, g.RefreshToken)
	err := e.st.Write(context.Background(), func(tx store.Tx) error {
		_, err := tx.RefreshTokens().RevokeSession(context.Background(), rid, row.SessionID, e.clock.Now())
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	row = e.refreshRow(t, g.RefreshToken)
	e.clock.Advance(time.Minute)
	_, err = e.refresh("web", g.RefreshToken)
	wantGrantErr(t, err, token.CodeInvalidGrant)
	if after := e.refreshRow(t, g.RefreshToken); !after.RevokedAt.Equal(row.RevokedAt) || row.RevokedAt.IsZero() {
		t.Fatalf("revoked_at moved: %v, was %v", after.RevokedAt, row.RevokedAt)
	}
	if e.revoked(t, other.RefreshToken) {
		t.Fatal("another session was revoked")
	}
}

// Covers: FR-08 (part)
// Acceptance: Refresh binding (part)
func TestRefreshRefusals(t *testing.T) {
	t.Run("unknown token", func(t *testing.T) {
		e := newRefreshEnv(t)
		_, err := e.refresh("web", "nope")
		wantGrantErr(t, err, token.CodeInvalidGrant)
	})
	t.Run("user disabled", func(t *testing.T) {
		e := newRefreshEnv(t)
		g := e.login(t, "web")
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
		_, err = e.refresh("web", g.RefreshToken)
		wantGrantErr(t, err, token.CodeInvalidGrant)
	})
	t.Run("user deleted", func(t *testing.T) {
		e := newRefreshEnv(t)
		g := e.login(t, "web")
		err := e.st.Write(context.Background(), func(tx store.Tx) error {
			return tx.Users().Delete(context.Background(), e.rid, "u1")
		})
		if err != nil {
			t.Fatal(err)
		}
		_, err = e.refresh("web", g.RefreshToken)
		wantGrantErr(t, err, token.CodeInvalidGrant)
	})
	t.Run("client removed", func(t *testing.T) {
		e := newRefreshEnv(t)
		g := e.login(t, "web")
		stripped := *e.realm
		stripped.Clients = map[config.ClientID]*config.Client{"plain": e.client("plain")}
		_, err := e.ref.Refresh(context.Background(), token.RefreshInput{Realm: &stripped, Client: e.client("web"), Token: g.RefreshToken})
		wantGrantErr(t, err, token.CodeInvalidGrant)
	})
	t.Run("realm disabled", func(t *testing.T) {
		e := newRefreshEnv(t)
		g := e.login(t, "web")
		e.realm.Enabled = false
		_, err := e.refresh("web", g.RefreshToken)
		wantGrantErr(t, err, token.CodeInvalidGrant)
	})
	t.Run("realm without a row", func(t *testing.T) {
		e := newRefreshEnv(t)
		g := e.login(t, "web")
		ghost := *e.realm
		ghost.Name = "ghost"
		_, err := e.ref.Refresh(context.Background(), token.RefreshInput{Realm: &ghost, Client: e.client("web"), Token: g.RefreshToken})
		wantGrantErr(t, err, token.CodeInvalidGrant)
	})
}

func TestRefreshStoreFailures(t *testing.T) {
	ctx := context.Background()
	t.Run("unavailable", func(t *testing.T) {
		e := newRefreshEnv(t)
		g := e.login(t, "web")
		r := token.NewRefresher(faultWrite(e.st, store.ErrUnavailable), e.issuer, e.clock, secure.Default)
		_, err := r.Refresh(ctx, token.RefreshInput{Realm: e.realm, Client: e.client("web"), Token: g.RefreshToken})
		notGrantErr(t, err)
		if !errors.Is(err, store.ErrUnavailable) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("failure in the middle rolls back", func(t *testing.T) {
		e := newRefreshEnv(t)
		g := e.login(t, "web")
		r := token.NewRefresher(faultInsert(e.st, errors.New("disk full")), e.issuer, e.clock, secure.Default)
		_, err := r.Refresh(ctx, token.RefreshInput{Realm: e.realm, Client: e.client("web"), Token: g.RefreshToken})
		notGrantErr(t, err)
		if row := e.refreshRow(t, g.RefreshToken); row.ReplacedBy != "" || !row.RevokedAt.IsZero() {
			t.Fatalf("row changed: %+v", row)
		}
		e.mustRefresh(t, "web", g.RefreshToken)
	})
}

// Covers: FR-08 (part)
// Acceptance: Refresh within grace (part)
func TestRefreshGraceDoesNotDependOnExpiry(t *testing.T) {
	e := newRefreshEnv(t)
	// The idle lifetime is shorter than the grace window, so by the time of
	// the retry the rotated token and its first successor have both expired.
	e.realm.Tokens.RefreshIdleLifetime = config.Duration(10 * time.Second)
	e.realm.Tokens.SessionMaxLifetime = config.Duration(0)
	g0 := e.login(t, "web")
	g1 := e.mustRefresh(t, "web", g0.RefreshToken)
	e.clock.Advance(20 * time.Second)
	if !e.refreshRow(t, g0.RefreshToken).ExpiresAt.Before(e.clock.Now()) ||
		!e.refreshRow(t, g1.RefreshToken).ExpiresAt.Before(e.clock.Now()) {
		t.Fatal("setup: the tokens should have expired")
	}
	// An expired rotated token still inside the window gets a successor.
	g2 := e.mustRefresh(t, "web", g0.RefreshToken)
	if g2.RefreshToken == g1.RefreshToken {
		t.Fatal("the retry got the same token")
	}
	if row := e.refreshRow(t, g2.RefreshToken); !row.ExpiresAt.Equal(e.clock.Now().Add(10 * time.Second)) {
		t.Fatalf("successor expiry = %v", row.ExpiresAt)
	}
	// The window runs from the first rotation: past it the session is revoked.
	e.clock.Advance(10 * time.Second)
	_, err := e.refresh("web", g0.RefreshToken)
	wantGrantErr(t, err, token.CodeInvalidGrant)
	if !e.revoked(t, g2.RefreshToken) {
		t.Fatal("session still active after reuse past the window")
	}
}

// Covers: FR-08 (part)
// Acceptance: Rotation off (part)
func TestRefreshRotationOffJWTKeepsItsExpClaim(t *testing.T) {
	e := newRefreshEnv(t)
	e.realm.Tokens.RefreshTokenFormat = "jwt"
	e.confidential(false)
	g0 := e.login(t, "conf")
	exp0 := decode(t, e.env, g0.RefreshToken).claims["exp"]
	e.clock.Advance(20 * time.Minute)
	g1 := e.mustRefresh(t, "conf", g0.RefreshToken)
	if g1.RefreshToken != g0.RefreshToken {
		t.Fatal("rotation off returned another token")
	}
	// The JWT is handed back unchanged, so its exp claim is the original
	// one; validity comes from the stored expiry, which moved forward.
	if exp := decode(t, e.env, g1.RefreshToken).claims["exp"]; exp != exp0 {
		t.Errorf("exp claim = %v, want the original %v", exp, exp0)
	}
	if row := e.refreshRow(t, g1.RefreshToken); !row.ExpiresAt.Equal(e.clock.Now().Add(time.Hour)) {
		t.Errorf("stored expiry = %v", row.ExpiresAt)
	}
	// Past the JWT's own exp the token still works.
	e.clock.Advance(50 * time.Minute)
	e.mustRefresh(t, "conf", g0.RefreshToken)
}

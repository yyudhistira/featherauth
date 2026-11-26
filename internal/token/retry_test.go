package token_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/yyudhistira/featherauth/internal/secure"
	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/testutil"
	"github.com/yyudhistira/featherauth/internal/token"
)

// deadlock is the failure of a Postgres transaction chosen as the victim of a
// deadlock (SQLSTATE 40P01).
func deadlock() error { return &pgconn.PgError{Code: "40P01"} }

// runAtOnce makes n calls at the same moment and returns their results in order.
func runAtOnce[T any](n int, call func(i int) (T, error)) ([]T, []error) {
	vals := make([]T, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			vals[i], errs[i] = call(i)
		}()
	}
	close(start)
	wg.Wait()
	return vals, errs
}

// runDriverCases runs the concurrency and retry cases of the token service on
// the stores newStore makes. The same cases run on every driver.
func runDriverCases(t *testing.T, newStore func(testing.TB) store.Store) {
	t.Run("exchange one code from 20 requests", func(t *testing.T) { exchangeOneCodeAtOnce(t, newStore(t)) })
	t.Run("refresh one token from 20 requests in grace", func(t *testing.T) { refreshOneTokenAtOnce(t, newStore(t)) })
	t.Run("exchange with a deadlock once", func(t *testing.T) { exchangeDeadlockOnce(t, newStore(t)) })
	t.Run("refresh with a deadlock once", func(t *testing.T) { refreshDeadlockOnce(t, newStore(t)) })
	t.Run("exchange with a deadlock three times", func(t *testing.T) { exchangeDeadlockThrice(t, newStore(t)) })
	t.Run("refresh with a deadlock three times", func(t *testing.T) { refreshDeadlockThrice(t, newStore(t)) })
	t.Run("exchange: a refused first run leaves no refusal", func(t *testing.T) { exchangeRefusedFirstRun(t, newStore(t)) })
	t.Run("refresh: a refused first run leaves no refusal", func(t *testing.T) { refreshRefusedFirstRun(t, newStore(t)) })
}

// exactly one of 20 exchanges of one code succeeds; the others are refused as
// used (invalid_grant).
func exchangeOneCodeAtOnce(t *testing.T, st store.Store) {
	e := newCodesEnvOn(t, st)
	code := e.issue(t, "web", "")
	grants, errs := runAtOnce(20, func(int) (*token.Grant, error) {
		return e.codes.Exchange(context.Background(), e.in("web", code, cb, ""))
	})
	won := 0
	for i, err := range errs {
		if err == nil {
			won++
			if grants[i].AccessToken == "" || grants[i].RefreshToken == "" {
				t.Fatalf("the winning grant is empty: %+v", grants[i])
			}
			continue
		}
		wantGrantErr(t, err, token.CodeInvalidGrant)
	}
	if won != 1 {
		t.Fatalf("%d exchanges succeeded, want 1", won)
	}
}

// 20 refreshes with one token at once: the first rotates it and the others,
// inside the grace window, each get their own successor. No session is revoked.
func refreshOneTokenAtOnce(t *testing.T, st store.Store) {
	e := newRefreshEnvOn(t, st)
	g0 := e.login(t, "web")
	grants, errs := runAtOnce(20, func(int) (*token.Grant, error) {
		return e.refresh("web", g0.RefreshToken)
	})
	seen := map[string]bool{}
	for i, err := range errs {
		if err != nil {
			t.Fatalf("refresh %d: %v", i, err)
		}
		seen[grants[i].RefreshToken] = true
	}
	if len(seen) != 20 {
		t.Fatalf("%d distinct successors, want 20", len(seen))
	}
	for tok := range seen {
		if e.revoked(t, tok) {
			t.Fatal("a successor of the grace window is revoked")
		}
	}
}

// A deadlock once: the second run exchanges the code, and the first run's
// consumption is not left behind, so the code is used exactly once.
func exchangeDeadlockOnce(t *testing.T, st store.Store) {
	e := newCodesEnvOn(t, st)
	code := e.issue(t, "web", "")
	f := testutil.NewFaultStore(e.st)
	f.AbortRuns(1, deadlock())
	g, err := token.NewCodes(f, e.issuer, e.clock, secure.Default).Exchange(context.Background(), e.in("web", code, cb, ""))
	if err != nil {
		t.Fatalf("Exchange = %v, want success on the second run", err)
	}
	if g.AccessToken == "" || g.RefreshToken == "" {
		t.Fatalf("grant = %+v", g)
	}
	// Only the second run used the code: a second use finds it used and ends
	// the session of the grant.
	_, err = e.codes.Exchange(context.Background(), e.in("web", code, cb, ""))
	wantGrantErr(t, err, token.CodeInvalidGrant)
	if row := e.refreshRow(t, g.RefreshToken); row.RevokedAt.IsZero() {
		t.Fatal("the second use did not end the session of the grant")
	}
}

// A deadlock once: the presented token points at the successor of the second
// run, and that successor is live.
func refreshDeadlockOnce(t *testing.T, st store.Store) {
	e := newRefreshEnvOn(t, st)
	g0 := e.login(t, "web")
	f := testutil.NewFaultStore(e.st)
	f.AbortRuns(1, deadlock())
	r := token.NewRefresher(f, e.issuer, e.clock, secure.Default)
	g1, err := r.Refresh(context.Background(), token.RefreshInput{Realm: e.realm, Client: e.client("web"), Token: g0.RefreshToken})
	if err != nil {
		t.Fatalf("Refresh = %v, want success on the second run", err)
	}
	old := e.refreshRow(t, g0.RefreshToken)
	next := e.refreshRow(t, g1.RefreshToken)
	if old.ReplacedBy != next.ID {
		t.Fatalf("the presented token is replaced by %q, want the successor %q", old.ReplacedBy, next.ID)
	}
	if e.revoked(t, g1.RefreshToken) {
		t.Fatal("the successor is revoked")
	}
}

// A deadlock three times: a store failure (ErrUnavailable, not a grant error),
// and the code is still usable.
func exchangeDeadlockThrice(t *testing.T, st store.Store) {
	e := newCodesEnvOn(t, st)
	code := e.issue(t, "web", "")
	f := testutil.NewFaultStore(e.st)
	f.AbortRuns(3, deadlock())
	_, err := token.NewCodes(f, e.issuer, e.clock, secure.Default).Exchange(context.Background(), e.in("web", code, cb, ""))
	if !errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("Exchange = %v, want ErrUnavailable", err)
	}
	var ge *token.GrantError
	if errors.As(err, &ge) {
		t.Fatalf("a store failure is a grant error: %v", err)
	}
	if _, err := e.codes.Exchange(context.Background(), e.in("web", code, cb, "")); err != nil {
		t.Fatalf("the code is not usable after the failed runs: %v", err)
	}
}

// A deadlock three times: ErrUnavailable, and the presented token is untouched.
func refreshDeadlockThrice(t *testing.T, st store.Store) {
	e := newRefreshEnvOn(t, st)
	g0 := e.login(t, "web")
	f := testutil.NewFaultStore(e.st)
	f.AbortRuns(3, deadlock())
	r := token.NewRefresher(f, e.issuer, e.clock, secure.Default)
	_, err := r.Refresh(context.Background(), token.RefreshInput{Realm: e.realm, Client: e.client("web"), Token: g0.RefreshToken})
	if !errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("Refresh = %v, want ErrUnavailable", err)
	}
	var ge *token.GrantError
	if errors.As(err, &ge) {
		t.Fatalf("a store failure is a grant error: %v", err)
	}
	if row := e.refreshRow(t, g0.RefreshToken); row.ReplacedBy != "" || !row.RevokedAt.IsZero() {
		t.Fatalf("a failed refresh changed the row: %+v", row)
	}
	e.mustRefresh(t, "web", g0.RefreshToken)
}

// Regression: the first run refuses (Realms.Find finds no realm) and then its
// transaction is run again. The refusal of the first run must not survive into
// the second run, which succeeds.
func exchangeRefusedFirstRun(t *testing.T, st store.Store) {
	e := newCodesEnvOn(t, st)
	code := e.issue(t, "web", "")
	f := testutil.NewFaultStore(e.st)
	f.FailOnce("Realms.Find", store.ErrNotFound)
	f.AbortRuns(1, deadlock())
	g, err := token.NewCodes(f, e.issuer, e.clock, secure.Default).Exchange(context.Background(), e.in("web", code, cb, ""))
	if err != nil {
		t.Fatalf("Exchange = %v: the refusal of the first run was kept", err)
	}
	if g.AccessToken == "" {
		t.Fatalf("grant = %+v", g)
	}
}

// Regression: as exchangeRefusedFirstRun, for a refresh.
func refreshRefusedFirstRun(t *testing.T, st store.Store) {
	e := newRefreshEnvOn(t, st)
	g0 := e.login(t, "web")
	f := testutil.NewFaultStore(e.st)
	f.FailOnce("Realms.Find", store.ErrNotFound)
	f.AbortRuns(1, deadlock())
	r := token.NewRefresher(f, e.issuer, e.clock, secure.Default)
	g1, err := r.Refresh(context.Background(), token.RefreshInput{Realm: e.realm, Client: e.client("web"), Token: g0.RefreshToken})
	if err != nil {
		t.Fatalf("Refresh = %v: the refusal of the first run was kept", err)
	}
	if g1.RefreshToken == "" {
		t.Fatalf("grant = %+v", g1)
	}
}

// Covers: FR-07 (part), FR-08 (part), FR-35 (part)
func TestDriverCasesSQLite(t *testing.T) {
	runDriverCases(t, testutil.NewStore)
}

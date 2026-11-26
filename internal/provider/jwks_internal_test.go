package provider

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"

	"github.com/yyudhistira/featherauth/internal/secure"
)

// signingKey returns a key of the provider and the JWKS that publishes it.
func signingKey(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), secure.Default)
	if err != nil {
		t.Fatal(err)
	}
	k, err := jwk.Import(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := k.Set(jwk.KeyIDKey, "k1"); err != nil {
		t.Fatal(err)
	}
	set := jwk.NewSet()
	if err := set.AddKey(k); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	return priv, b
}

// signed returns a compact JWT signed with priv under kid.
func signed(t *testing.T, priv *ecdsa.PrivateKey, kid string) string {
	t.Helper()
	h := jws.NewHeaders()
	if err := h.Set(jws.KeyIDKey, kid); err != nil {
		t.Fatal(err)
	}
	out, err := jws.Sign([]byte(`{"sub":"u1"}`), jws.WithKey(jwa.ES256(), priv, jws.WithProtectedHeaders(h)))
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

// Covers: FR-31, SEC-22
// Acceptance: Apple event formats (part)
// A key fetch that fails is recorded for the call that made it, and the call that
// starts right after it fetches again: it never gets the earlier call's failure
// (go-oidc's RemoteKeySet could hand it over while the earlier fetch was still
// being released).
func TestKeyFetchFailureBelongsToItsCall(t *testing.T) {
	priv, jwks := signingKey(t)
	var fetches atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fetches.Add(1) == 1 {
			http.Error(w, "down", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwks)
	}))
	defer srv.Close()
	ks := &jwksKeys{url: srv.URL, client: &http.Client{Timeout: 5 * time.Second}}
	tok := signed(t, priv, "k1")

	ctxA, failedA := withKeyFetch(context.Background())
	if _, err := ks.VerifySignature(ctxA, tok); err == nil || !failedA.failed {
		t.Fatalf("the first call: err %v, failed %v; want its own fetch failure", err, failedA.failed)
	}
	ctxB, failedB := withKeyFetch(context.Background())
	if _, err := ks.VerifySignature(ctxB, tok); err != nil {
		t.Fatalf("the call right after: %v; want the keys fetched again", err)
	}
	if failedB.failed {
		t.Fatal("the second call is blamed for the first call's fetch")
	}
	if n := fetches.Load(); n != 2 {
		t.Fatalf("%d fetches, want 2 (one each)", n)
	}
}

// Covers: FR-31, SEC-22
// Acceptance: Apple event formats (part)
// A token that no published key verifies is a bad token, not a fetch failure.
func TestTokenNoKeyVerifiesIsNotAFetchFailure(t *testing.T) {
	_, jwks := signingKey(t)
	other, _ := signingKey(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwks)
	}))
	defer srv.Close()
	ks := &jwksKeys{url: srv.URL, client: &http.Client{Timeout: 5 * time.Second}}
	ctx, kf := withKeyFetch(context.Background())
	if _, err := ks.VerifySignature(ctx, signed(t, other, "k1")); err == nil {
		t.Fatal("a token of another key verified")
	}
	if kf.failed {
		t.Fatal("a bad token is recorded as a key fetch failure")
	}
}

// gatedKeys serves a key set. Fetches numbered gateFrom and later report their
// arrival on entered and wait until release is closed; the earlier ones are
// answered at once.
type gatedKeys struct {
	jwks     []byte
	gateFrom int64
	fetches  atomic.Int64
	entered  chan struct{}
	release  chan struct{}
}

func newGatedKeys(t *testing.T, jwks []byte, gateFrom int64) (*gatedKeys, *httptest.Server) {
	t.Helper()
	g := &gatedKeys{jwks: jwks, gateFrom: gateFrom, entered: make(chan struct{}, 64), release: make(chan struct{})}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if g.fetches.Add(1) >= g.gateFrom {
			g.entered <- struct{}{}
			select {
			case <-g.release:
			case <-r.Context().Done():
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(g.jwks)
	}))
	t.Cleanup(srv.Close)
	return g, srv
}

// Covers: FR-31, SEC-22
// Acceptance: Apple event formats (part)
// Keys already cached verify a token at once, while a fetch of the keys hangs: a
// key outage must not stall the logins and events that the cached keys serve.
func TestCachedKeysVerifyWhileAFetchHangs(t *testing.T) {
	priv, jwks := signingKey(t)
	other, _ := signingKey(t)
	g, srv := newGatedKeys(t, jwks, 2)
	ks := &jwksKeys{url: srv.URL, client: &http.Client{Timeout: 30 * time.Second}}
	valid := signed(t, priv, "k1")
	if _, err := ks.VerifySignature(context.Background(), valid); err != nil {
		t.Fatal(err)
	}
	// A token of an unknown key starts a fetch that hangs.
	hung := make(chan error, 1)
	go func() {
		_, err := ks.VerifySignature(context.Background(), signed(t, other, "k2"))
		hung <- err
	}()
	<-g.entered
	verified := make(chan error, 1)
	go func() {
		_, err := ks.VerifySignature(context.Background(), valid)
		verified <- err
	}()
	if err := <-verified; err != nil {
		t.Fatalf("a cached key did not verify while a fetch hangs: %v", err)
	}
	close(g.release)
	if err := <-hung; err == nil {
		t.Fatal("a token of an unpublished key verified")
	}
}

// Covers: FR-31, SEC-22
// Acceptance: Apple event formats (part)
// Callers that need the keys at once share one fetch of them.
func TestConcurrentCallersShareOneFetch(t *testing.T) {
	priv, jwks := signingKey(t)
	g, srv := newGatedKeys(t, jwks, 1)
	ks := &jwksKeys{url: srv.URL, client: &http.Client{Timeout: 30 * time.Second}}
	const n = 16
	results := make(chan error, n)
	for i := 0; i < n; i++ {
		go func() {
			_, err := ks.VerifySignature(context.Background(), signed(t, priv, "k1"))
			results <- err
		}()
	}
	<-g.entered
	close(g.release)
	for i := 0; i < n; i++ {
		if err := <-results; err != nil {
			t.Fatalf("a caller failed: %v", err)
		}
	}
	if got := g.fetches.Load(); got != 1 {
		t.Fatalf("%d fetches for %d callers, want 1 shared by them", got, n)
	}
}

// Covers: FR-31, SEC-22
// Acceptance: Apple event formats (part)
// A caller that waits for a fetch honours its context: a cancelled waiter returns
// at once, marked as unavailable, and the fetch goes on for the others.
func TestCancelledWaiterReturnsAtOnce(t *testing.T) {
	priv, jwks := signingKey(t)
	g, srv := newGatedKeys(t, jwks, 1)
	ks := &jwksKeys{url: srv.URL, client: &http.Client{Timeout: 30 * time.Second}}
	started := make(chan error, 1)
	go func() {
		_, err := ks.VerifySignature(context.Background(), signed(t, priv, "k1"))
		started <- err
	}()
	<-g.entered // the fetch is in flight and hangs
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	ctx, kf := withKeyFetch(cancelled)
	waited := make(chan error, 1)
	go func() {
		_, err := ks.VerifySignature(ctx, signed(t, priv, "k1"))
		waited <- err
	}()
	if err := <-waited; err == nil || !kf.failed {
		t.Fatalf("the cancelled waiter: err %v, failed %v; want an error marked unavailable", err, kf.failed)
	}
	close(g.release)
	if err := <-started; err != nil {
		t.Fatalf("the initiator: %v", err)
	}
}

// Covers: FR-31, SEC-22
// Acceptance: Apple event formats (part)
// A caller that read the keys at generation gen, after which newer keys were
// fetched, gets those newer keys and starts no fetch of its own.
func TestJoinOrStartReturnsNewerKeysWithoutFetching(t *testing.T) {
	_, jwks := signingKey(t)
	set, err := jwk.Parse(jwks)
	if err != nil {
		t.Fatal(err)
	}
	var fetches atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetches.Add(1)
		_, _ = w.Write(jwks)
	}))
	defer srv.Close()
	k := &jwksKeys{url: srv.URL, client: &http.Client{Timeout: 5 * time.Second}}
	k.mu.Lock()
	oldGen := k.gen
	k.cur = set // a fetch completed after the caller read generation oldGen
	k.gen++
	k.mu.Unlock()

	keys, call := k.joinOrStart(oldGen)
	if call != nil {
		t.Fatal("a caller whose keys are stale started or joined a fetch; want the newer keys")
	}
	if keys != set {
		t.Fatalf("keys %v, want the newer keys", keys)
	}
	if n := fetches.Load(); n != 0 {
		t.Fatalf("%d fetches, want none", n)
	}
	k.mu.Lock()
	inflight := k.inflight
	k.mu.Unlock()
	if inflight != nil {
		t.Fatal("a fetch is in flight")
	}
}

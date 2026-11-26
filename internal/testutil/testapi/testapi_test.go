package testapi_test

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/secure"
	"github.com/yyudhistira/featherauth/internal/testutil/configdir"
	"github.com/yyudhistira/featherauth/internal/testutil/testapi"
	"github.com/yyudhistira/featherauth/internal/token"
)

var start = time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)

// world is the real service side: a config directory, the loader, and a JWKS
// endpoint built from the current snapshot.
type world struct {
	t      *testing.T
	dir    *configdir.Dir
	clock  *clock.Fake
	loader *config.Loader
	srv    *httptest.Server
	hits   atomic.Int32
}

func pemKey(t *testing.T) string {
	t.Helper()
	b, err := token.GenerateRSA(2048)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// realmYAML lists keys as "kid:state" pairs.
func realmYAML(keys ...string) string {
	y := "name: main\nkeys:\n"
	for _, k := range keys {
		kid, state, _ := strings.Cut(k, ":")
		y += "  - { kid: " + kid + ", file: secrets/" + kid + ".pem, state: " + state + " }\n"
	}
	return y + `providers:
  google:
    enabled: true
    client_id: 1234.apps.googleusercontent.com
    client_secret_file: secrets/google_secret
clients:
  web:
    redirect_uris: [https://app.example.com/callback]
    audience: https://api.example.com
`
}

func newWorld(t *testing.T, kids []string, keys ...string) *world {
	t.Helper()
	w := &world{t: t, dir: configdir.New(t), clock: clock.NewFake(start)}
	w.dir.Server(t, "public_url: https://auth.example.com\n")
	w.dir.Secret(t, "secrets/google_secret")
	for _, kid := range kids {
		w.dir.Write(t, "secrets/"+kid+".pem", pemKey(t))
	}
	w.dir.Realm(t, "main", realmYAML(keys...))
	l, err := config.NewLoader(w.dir.Root, w.clock, nil)
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}
	w.loader = l
	w.srv = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		w.hits.Add(1)
		snap := w.loader.Current()
		r, _ := snap.Realm("main")
		ks, err := token.NewKeySet(r, snap.Secrets())
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}
		rw.Header().Set("Content-Type", "application/json")
		rw.Header().Set("Cache-Control", "public, max-age=300")
		_, _ = rw.Write(ks.JWKS())
	}))
	t.Cleanup(w.srv.Close)
	return w
}

// setKeys rewrites the realm file and reloads the configuration.
func (w *world) setKeys(keys ...string) {
	w.t.Helper()
	w.dir.Realm(w.t, "main", realmYAML(keys...))
	if res := w.loader.Reload(context.Background()); !res.Applied {
		w.t.Fatalf("reload not applied: %+v", res)
	}
}

func (w *world) realm() (*config.Realm, *config.Client, config.Secrets) {
	snap := w.loader.Current()
	r, _ := snap.Realm("main")
	return r, r.Clients["web"], snap.Secrets()
}

func (w *world) issuer() *token.Issuer {
	_, _, s := w.realm()
	return token.NewIssuer(w.clock, secure.Default, s)
}

var (
	subject = token.Subject{ID: "u1", Email: "ann@example.com", EmailVerified: true, Name: "Ann"}
	session = token.Session{ID: "s1", StartedAt: start, AuthTime: start, Nonce: "n-1"}
)

func (w *world) access() string {
	w.t.Helper()
	r, cl, _ := w.realm()
	raw, _, err := w.issuer().Access(r, cl, subject, session)
	if err != nil {
		w.t.Fatal(err)
	}
	return raw
}

func (w *world) api() *testapi.API {
	r, cl, _ := w.realm()
	return testapi.New(w.clock, w.srv.URL, r.Issuer(), cl.Audience)
}

func verify(a *testapi.API, raw string) error {
	_, err := a.Verify(context.Background(), raw)
	return err
}

// Covers: FR-10 (part)
// Acceptance: Offline verification
func TestAPIAcceptsIssuedAccessTokenAndRejectsTamperedOne(t *testing.T) {
	w := newWorld(t, []string{"k1"}, "k1:active")
	a := w.api()
	raw := w.access()
	c, err := a.Verify(context.Background(), raw)
	if err != nil {
		t.Fatalf("issued access token rejected: %v", err)
	}
	if c.Sub != "u1" {
		t.Errorf("sub = %q", c.Sub)
	}
	if !c.Exp.Equal(start.Add(15 * time.Minute)) {
		t.Errorf("exp = %v", c.Exp)
	}

	parts := strings.Split(raw, ".")
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	forged := strings.Replace(string(payload), `"u1"`, `"u2"`, 1)
	if forged == string(payload) {
		t.Fatal("tamper did not change the payload")
	}
	parts[1] = base64.RawURLEncoding.EncodeToString([]byte(forged))
	if err := verify(a, strings.Join(parts, ".")); err == nil {
		t.Error("tampered token accepted")
	}
	sig := []byte(parts[2])
	sig[0] ^= 1
	parts[1] = strings.Split(raw, ".")[1]
	parts[2] = string(sig)
	if err := verify(a, strings.Join(parts, ".")); err == nil {
		t.Error("token with a damaged signature accepted")
	}
}

func TestAPIChecksIssuerAudienceAndExpiry(t *testing.T) {
	w := newWorld(t, []string{"k1"}, "k1:active")
	r, cl, _ := w.realm()
	raw := w.access()
	for _, tc := range []struct{ name, iss, aud string }{
		{"wrong issuer", "https://other.example.com/main", cl.Audience},
		{"wrong audience", r.Issuer(), "https://other-api.example.com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := verify(testapi.New(w.clock, w.srv.URL, tc.iss, tc.aud), raw); err == nil {
				t.Error("accepted")
			}
		})
	}
	a := w.api()
	w.clock.Advance(15*time.Minute - time.Second)
	if err := verify(a, raw); err != nil {
		t.Errorf("one second before exp: %v", err)
	}
	w.clock.Advance(time.Second)
	if err := verify(a, raw); err == nil {
		t.Error("expired token accepted")
	}
}

// Covers: FR-10 (part)
// Acceptance: Offline verification
func TestAPIRejectsIDTokenAndJWTRefreshToken(t *testing.T) {
	w := newWorld(t, []string{"k1"}, "k1:active")
	r, cl, _ := w.realm()
	access := w.access()
	id, err := w.issuer().ID(r, cl, subject, session, access)
	if err != nil {
		t.Fatal(err)
	}
	refresh, err := w.issuer().RefreshJWT(r, cl, subject, session, start.Add(time.Hour), "j1")
	if err != nil {
		t.Fatal(err)
	}
	a := w.api()
	if err := verify(a, access); err != nil {
		t.Fatalf("access token: %v", err)
	}
	if err := verify(a, id); err == nil {
		t.Error("ID token accepted as an access token")
	}
	if err := verify(a, refresh); err == nil {
		t.Error("JWT refresh token accepted as an access token")
	}
}

func TestAPICachesJWKSFor300Seconds(t *testing.T) {
	w := newWorld(t, []string{"k1"}, "k1:active")
	a := w.api()
	raw := w.access()
	for range 3 {
		if err := verify(a, raw); err != nil {
			t.Fatal(err)
		}
	}
	if n := w.hits.Load(); n != 1 {
		t.Fatalf("fetches = %d, want 1", n)
	}
	w.clock.Advance(testapi.JWKSCacheTTL - time.Second)
	_ = verify(a, raw)
	if n := w.hits.Load(); n != 1 {
		t.Fatalf("fetches at 299 s = %d, want 1", n)
	}
	w.clock.Advance(time.Second)
	_ = verify(a, raw)
	if n := w.hits.Load(); n != 2 {
		t.Fatalf("fetches at 300 s = %d, want 2", n)
	}
}

func TestAPIFetchFailureIsAnError(t *testing.T) {
	w := newWorld(t, []string{"k1"}, "k1:active")
	a := w.api()
	raw := w.access()
	w.srv.Close()
	if err := verify(a, raw); err == nil {
		t.Error("accepted without a reachable JWKS")
	}
	if err := verify(testapi.New(w.clock, "http://127.0.0.1:1/%zz", "x", "y"), raw); err == nil {
		t.Error("accepted with a bad URL")
	}
}

// Covers: SEC-07
// Acceptance: Key rotation
func TestTwoStepRotationCausesNoFailure(t *testing.T) {
	w := newWorld(t, []string{"old", "new"}, "old:active")
	a := w.api()
	ctx := context.Background()
	mustOK := func(step, raw string) {
		t.Helper()
		if _, err := a.Verify(ctx, raw); err != nil {
			t.Fatalf("%s: %v", step, err)
		}
	}

	// Before: the API caches the JWKS with the old key only.
	tokOld := w.access()
	mustOK("before rotation", tokOld)

	// Step 1: the new key is added as verify_only. Nothing signs with it yet.
	w.setKeys("old:active", "new:verify_only")
	mustOK("step 1, cached JWKS", tokOld)
	mustOK("step 1, new token", w.access())

	// Wait at least 5 minutes, the JWKS max-age: the API refetches and now
	// knows the new key.
	w.clock.Advance(5 * time.Minute)
	tokOld2 := w.access() // signed by old, issued in the overlap
	mustOK("after the wait", tokOld)
	mustOK("after the wait, token signed by old", tokOld2)

	// Step 2: the new key becomes active, the old one verify_only.
	w.setKeys("old:verify_only", "new:active")
	tokNew := w.access()
	mustOK("step 2, token signed by new", tokNew)
	mustOK("step 2, token signed by old", tokOld2)

	// The API's cache expires inside this loop; no step fails at any time.
	for range 12 {
		w.clock.Advance(time.Minute)
		mustOK("overlap, old token", tokOld2)
		mustOK("overlap, new token", tokNew)
		mustOK("overlap, fresh token", w.access())
	}
	if w.hits.Load() < 3 {
		t.Fatalf("the API never refetched the JWKS: %d fetches", w.hits.Load())
	}

	// The old key is removed after the longest token it signed has expired.
	w.clock.Advance(15 * time.Minute)
	w.setKeys("new:active")
	tokLate := w.access()
	w.clock.Advance(5 * time.Minute)
	mustOK("after removal", tokLate)
	if err := verify(a, tokOld2); err == nil {
		t.Error("an expired token signed by the removed key was accepted")
	}
}

// Covers: SEC-07
// Acceptance: Key rotation
func TestOneStepRotationFailsForUpTo300Seconds(t *testing.T) {
	w := newWorld(t, []string{"old", "new"}, "old:active")
	a := w.api()
	mustOldOK := w.access()
	if err := verify(a, mustOldOK); err != nil {
		t.Fatal(err)
	} // the JWKS is fetched and cached here, at start

	// One step: the new key is active at once and the old one is verify_only.
	w.setKeys("old:verify_only", "new:active")
	tokNew := w.access()

	for _, at := range []time.Duration{0, time.Second, 150 * time.Second, 299 * time.Second} {
		w.clock.Set(start.Add(at))
		if err := verify(a, tokNew); err == nil {
			t.Fatalf("%v after the cache fill: a token of the new key was accepted from a stale JWKS", at)
		}
		if err := verify(a, mustOldOK); err != nil {
			t.Fatalf("%v: the old token must still verify: %v", at, err)
		}
	}
	if n := w.hits.Load(); n != 1 {
		t.Fatalf("fetches = %d, the API must not refetch inside 300 s", n)
	}

	w.clock.Set(start.Add(300 * time.Second))
	if err := verify(a, tokNew); err != nil {
		t.Fatalf("after 300 s the API refetches and accepts the new key: %v", err)
	}
	if err := verify(a, mustOldOK); err != nil {
		t.Fatalf("old token after the refetch: %v", err)
	}
}

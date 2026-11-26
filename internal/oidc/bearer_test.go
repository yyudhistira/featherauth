package oidc_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/oidc"
	"github.com/yyudhistira/featherauth/internal/secure"
	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/testutil"
	"github.com/yyudhistira/featherauth/internal/testutil/configdir"
	"github.com/yyudhistira/featherauth/internal/token"
)

type bearerEnv struct {
	clock       *clock.Fake
	main, other *config.Realm
	issuer      *token.Issuer
	auth        *oidc.BearerAuth
	store       store.Store
	rid         store.RealmID
}

func newBearerEnv(t *testing.T) *bearerEnv {
	t.Helper()
	realm := func(name string) string {
		return "name: " + name + "\nkeys:\n  - { kid: " + name + "-1, file: secrets/" + name + ".pem, state: active }\n" +
			"providers:\n  google:\n    enabled: true\n    client_id: 1234.apps.googleusercontent.com\n    client_secret_file: secrets/google_secret\n" +
			"clients:\n  web:\n    redirect_uris: [https://app.example.com/callback]\n"
	}
	d := configdir.New(t)
	d.Server(t, "public_url: https://auth.example.com\n")
	d.Realm(t, "main", realm("main"))
	d.Realm(t, "other", realm("other"))
	d.RSAKey(t, "secrets/main.pem")
	d.RSAKey(t, "secrets/other.pem")
	d.Secret(t, "secrets/google_secret")
	fc := clock.NewFake(time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC))
	l, err := config.NewLoader(d.Root, fc, nil)
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}
	snap := l.Current()
	e := &bearerEnv{clock: fc, store: testutil.NewStore(t)}
	e.main, _ = snap.Realm("main")
	e.other, _ = snap.Realm("other")
	e.issuer = token.NewIssuer(fc, secure.Default, snap.Secrets())
	e.auth = oidc.NewBearerAuth(token.NewVerifier(fc, snap.Secrets()), e.store, fc)
	err = e.store.Write(context.Background(), func(tx store.Tx) error {
		rid, err := tx.Realms().Ensure(context.Background(), "main", "realm-main", fc.Now())
		e.rid = rid
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *bearerEnv) addUser(t *testing.T, disabled bool) {
	t.Helper()
	u := store.User{ID: "u1", RealmID: e.rid, Email: "ann@example.com", Name: "Ann", CreatedAt: e.clock.Now(), UpdatedAt: e.clock.Now()}
	if disabled {
		u.DisabledAt = e.clock.Now()
	}
	err := e.store.Write(context.Background(), func(tx store.Tx) error { return tx.Users().Create(context.Background(), u) })
	if err != nil {
		t.Fatal(err)
	}
}

func (e *bearerEnv) tokens(t *testing.T, realm *config.Realm) (access, id string) {
	t.Helper()
	sub := token.Subject{ID: "u1", Email: "ann@example.com", EmailVerified: true, Name: "Ann"}
	ss := token.Session{ID: "s1", StartedAt: e.clock.Now(), AuthTime: e.clock.Now()}
	access, _, err := e.issuer.Access(realm, realm.Clients["web"], sub, ss)
	if err != nil {
		t.Fatal(err)
	}
	id, err = e.issuer.ID(realm, realm.Clients["web"], sub, ss, access)
	if err != nil {
		t.Fatal(err)
	}
	return access, id
}

func bearerRequest(authorization ...string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/main/userinfo", nil)
	for _, a := range authorization {
		r.Header.Add("Authorization", a)
	}
	return r
}

// Covers: SEC-20 (part)
func TestBearerAcceptsAnAccessToken(t *testing.T) {
	e := newBearerEnv(t)
	e.addUser(t, false)
	access, _ := e.tokens(t, e.main)
	claims, u, err := e.auth.Bearer(bearerRequest("Bearer "+access), e.main, config.EndpointUserinfo)
	if err != nil {
		t.Fatalf("Bearer: %+v", err)
	}
	if claims.Sub != "u1" || claims.Azp != "web" || claims.Sid != "s1" || u == nil || u.ID != "u1" || u.Email != "ann@example.com" {
		t.Fatalf("claims %+v user %+v", claims, u)
	}
}

// Covers: SEC-20 (part)
func TestBearerRefusals(t *testing.T) {
	e := newBearerEnv(t)
	e.addUser(t, false)
	access, id := e.tokens(t, e.main)
	otherAccess, _ := e.tokens(t, e.other)
	rows := []struct {
		name string
		hdr  []string
	}{
		{"missing header", nil},
		{"empty header", []string{""}},
		{"wrong scheme", []string{"Basic " + access}},
		{"scheme without token", []string{"Bearer"}},
		{"empty token", []string{"Bearer "}},
		{"garbage token", []string{"Bearer not-a-jwt"}},
		{"id token", []string{"Bearer " + id}},
		{"other realm", []string{"Bearer " + otherAccess}},
		{"two headers", []string{"Bearer " + access, "Bearer " + access}},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			_, u, err := e.auth.Bearer(bearerRequest(row.hdr...), e.main, config.EndpointUserinfo)
			wantInvalidToken(t, u, err)
		})
	}
	t.Run("scheme is case-insensitive", func(t *testing.T) {
		if _, _, err := e.auth.Bearer(bearerRequest("bearer "+access), e.main, config.EndpointUserinfo); err != nil {
			t.Fatalf("err %+v", err)
		}
	})
	t.Run("expired", func(t *testing.T) {
		e.clock.Advance(2 * time.Hour)
		_, u, err := e.auth.Bearer(bearerRequest("Bearer "+access), e.main, config.EndpointUserinfo)
		wantInvalidToken(t, u, err)
	})
}

// Covers: SEC-20 (part)
func TestBearerRefusesAMissingOrDisabledUser(t *testing.T) {
	t.Run("missing user", func(t *testing.T) {
		e := newBearerEnv(t)
		access, _ := e.tokens(t, e.main)
		_, u, err := e.auth.Bearer(bearerRequest("Bearer "+access), e.main, config.EndpointUserinfo)
		wantInvalidToken(t, u, err)
	})
	t.Run("disabled user", func(t *testing.T) {
		e := newBearerEnv(t)
		e.addUser(t, true)
		access, _ := e.tokens(t, e.main)
		_, u, err := e.auth.Bearer(bearerRequest("Bearer "+access), e.main, config.EndpointUserinfo)
		wantInvalidToken(t, u, err)
	})
}

// Covers: SEC-20 (part)
func TestBearerStoreFailureIsNotAnAuthenticationFailure(t *testing.T) {
	e := newBearerEnv(t)
	e.addUser(t, false)
	access, _ := e.tokens(t, e.main)
	if err := e.store.Close(); err != nil {
		t.Fatal(err)
	}
	_, u, err := e.auth.Bearer(bearerRequest("Bearer "+access), e.main, config.EndpointUserinfo)
	if u != nil || err == nil || err.Code == "invalid_token" || err.Status < 500 {
		t.Fatalf("user %v err %+v, want a 5xx that is not invalid_token", u, err)
	}
}

func wantInvalidToken(t *testing.T, u *store.User, err *oidc.Error) {
	t.Helper()
	if u != nil {
		t.Fatalf("user %+v returned with a refusal", u)
	}
	if err == nil {
		t.Fatal("no error, want invalid_token")
	}
	if err.Code != "invalid_token" || (err.Status != 0 && err.Status != http.StatusUnauthorized) {
		t.Fatalf("error %+v, want invalid_token 401", *err)
	}
	w := httptest.NewRecorder()
	oidc.WriteBearerError(w, *err, nil)
	if w.Code != http.StatusUnauthorized || w.Header().Get("WWW-Authenticate") != `Bearer error="invalid_token"` {
		t.Fatalf("response %d %q", w.Code, w.Header().Get("WWW-Authenticate"))
	}
}

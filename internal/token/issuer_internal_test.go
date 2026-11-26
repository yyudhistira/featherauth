package token

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jws"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/secure"
)

type signers map[string]crypto.Signer

type fakeSecrets struct {
	config.Secrets
	keys signers
}

func (f fakeSecrets) Signing(kid string) crypto.Signer { return f.keys[kid] }

type issuerFixture struct {
	realm  *config.Realm
	client *config.Client
	issuer *Issuer
}

func newFixture(t *testing.T, alg string, keys []config.Key, ks signers) issuerFixture {
	t.Helper()
	cl := &config.Client{Audience: "web"}
	r := &config.Realm{
		Name:    "main",
		Tokens:  config.Tokens{Algorithm: alg},
		Keys:    keys,
		Clients: map[config.ClientID]*config.Client{"web": cl},
	}
	iss := NewIssuer(clock.NewFake(time.Unix(1_700_000_000, 0)), bytes.NewReader(bytes.Repeat([]byte{1}, 256)), fakeSecrets{keys: ks})
	return issuerFixture{r, cl, iss}
}

func (f issuerFixture) all(t *testing.T) map[string]error {
	t.Helper()
	s, ss := Subject{ID: "u"}, Session{ID: "s"}
	_, _, errA := f.issuer.Access(f.realm, f.client, s, ss)
	_, errI := f.issuer.ID(f.realm, f.client, s, ss, "at")
	_, errR := f.issuer.RefreshJWT(f.realm, f.client, s, ss, time.Unix(1_700_001_000, 0), "j")
	return map[string]error{"access": errA, "id": errI, "refresh": errR}
}

func mustFail(t *testing.T, errs map[string]error) {
	t.Helper()
	for name, err := range errs {
		if err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

func rsaKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(secure.Default, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// Covers: SEC-05 (part)
func TestIssuerRejectsMissingRealmOrClient(t *testing.T) {
	f := newFixture(t, "RS256", nil, nil)
	if _, _, err := f.issuer.Access(nil, f.client, Subject{}, Session{}); err == nil {
		t.Error("nil realm accepted")
	}
	if _, err := f.issuer.ID(f.realm, nil, Subject{}, Session{}, ""); err == nil {
		t.Error("nil client accepted")
	}
	other := &config.Client{}
	if _, err := f.issuer.RefreshJWT(f.realm, other, Subject{}, Session{}, time.Time{}, ""); err == nil {
		t.Error("client of another realm accepted")
	}
}

// Covers: SEC-05 (part)
func TestIssuerNeedsAnActiveKeyOfTheRightType(t *testing.T) {
	rk := rsaKey(t)
	ek, err := ecdsa.GenerateKey(elliptic.P256(), secure.Default)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		f    issuerFixture
		fail []string // the tokens that cannot be issued
	}{
		{"no keys", newFixture(t, "RS256", nil, nil), []string{"access", "id", "refresh"}},
		{"verify-only key", newFixture(t, "RS256", []config.Key{{Kid: "a", State: "verify_only"}}, signers{"a": rk}), []string{"access", "id", "refresh"}},
		{"key not loaded", newFixture(t, "RS256", []config.Key{{Kid: "a", State: "active"}}, signers{}), []string{"access", "id", "refresh"}},
		{"EC key only", newFixture(t, "ES256", []config.Key{{Kid: "e", State: "active"}}, signers{"e": ek}), []string{"id"}},
		{"RSA key only in an ES256 realm", newFixture(t, "ES256", []config.Key{{Kid: "a", State: "active"}}, signers{"a": rk}), []string{"access", "refresh"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for name, err := range tc.f.all(t) {
				if failing := slices.Contains(tc.fail, name); failing != (err != nil) {
					t.Errorf("%s: error %v, want failure %v", name, err, failing)
				}
			}
		})
	}
}

// Covers: SEC-05 (part)
func TestIssuerFailsWhenRandomSourceFails(t *testing.T) {
	f := newFixture(t, "RS256", nil, nil)
	f.issuer.src = bytes.NewReader(nil)
	if _, _, err := f.issuer.Access(f.realm, f.client, Subject{}, Session{}); err == nil {
		t.Error("no error")
	}
}

// Covers: SEC-05 (part)
func TestIssuerReportsLibraryFailures(t *testing.T) {
	rk := rsaKey(t)
	f := newFixture(t, "RS256", []config.Key{{Kid: "a", State: "active"}}, signers{"a": rk})
	boom := errors.New("boom")
	t.Run("encode", func(t *testing.T) {
		old := encodeJSON
		defer func() { encodeJSON = old }()
		encodeJSON = func(map[string]any) ([]byte, error) { return nil, boom }
		mustFail(t, f.all(t))
	})
	t.Run("header", func(t *testing.T) {
		old := setHeader
		defer func() { setHeader = old }()
		setHeader = func(jws.Headers, string, any) error { return boom }
		mustFail(t, f.all(t))
	})
	t.Run("sign", func(t *testing.T) {
		old := signJWS
		defer func() { signJWS = old }()
		signJWS = func([]byte, ...jws.SignOption) ([]byte, error) { return nil, boom }
		mustFail(t, f.all(t))
	})
	// and without a seam it works
	for name, err := range f.all(t) {
		if err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

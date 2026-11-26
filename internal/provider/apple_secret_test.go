package provider_test

import (
	"bytes"
	"crypto/elliptic"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/logx"
	"github.com/yyudhistira/featherauth/internal/provider"
	"github.com/yyudhistira/featherauth/internal/testutil"
)

var appleStart = time.Date(2030, 3, 4, 5, 6, 7, 0, time.UTC)

func appleOpts(pemKey []byte, clk clock.Clock) provider.AppleSecretOptions {
	return provider.AppleSecretOptions{
		TeamID: "TEAM123456", KeyID: "KEY1234567", ServicesID: "com.example.web",
		PrivateKeyPEM: pemKey, Lifetime: 5 * time.Minute, Clock: clk,
	}
}

// Covers: SEC-03 (part)
// Acceptance: Provider adapters (part)
func TestAppleSecretClaimsHeaderAndSignature(t *testing.T) {
	key, pemKey := testutil.ECKey(t)
	clk := clock.NewFake(appleStart)
	a, err := provider.NewAppleSecret(appleOpts(pemKey, clk))
	if err != nil {
		t.Fatal(err)
	}
	tok, err := a.Secret()
	if err != nil {
		t.Fatal(err)
	}
	msg, err := jws.Parse([]byte(tok))
	if err != nil {
		t.Fatal(err)
	}
	sigs := msg.Signatures()
	if len(sigs) != 1 {
		t.Fatalf("%d signatures", len(sigs))
	}
	h := sigs[0].ProtectedHeaders()
	if kid, _ := h.KeyID(); kid != "KEY1234567" {
		t.Errorf("kid = %q", kid)
	}
	if alg, _ := h.Algorithm(); alg.String() != "ES256" {
		t.Errorf("alg = %v", alg)
	}
	var claims map[string]any
	if err := json.Unmarshal(msg.Payload(), &claims); err != nil {
		t.Fatal(err)
	}
	iat := float64(appleStart.Unix())
	want := map[string]any{
		"iss": "TEAM123456", "sub": "com.example.web", "aud": "https://appleid.apple.com",
		"iat": iat, "exp": iat + 300,
	}
	if len(claims) != len(want) {
		t.Errorf("claims = %v, want exactly %v", claims, want)
	}
	for k, v := range want {
		if claims[k] != v {
			t.Errorf("claim %s = %v, want %v", k, claims[k], v)
		}
	}
	if _, err := jws.Verify([]byte(tok), jws.WithKey(jwa.ES256(), &key.PublicKey)); err != nil {
		t.Errorf("the signature does not verify with the public key: %v", err)
	}

	// generated on demand: a later call uses the clock again
	clk.Advance(time.Hour)
	tok2, err := a.Secret()
	if err != nil {
		t.Fatal(err)
	}
	m2, _ := jws.Parse([]byte(tok2))
	var c2 map[string]any
	_ = json.Unmarshal(m2.Payload(), &c2)
	if c2["iat"] != iat+3600 || c2["exp"] != iat+3600+300 {
		t.Errorf("second secret claims = %v", c2)
	}
}

// Covers: SEC-03 (part)
// Acceptance: Provider adapters (part)
func TestAppleSecretLifetimeBound(t *testing.T) {
	_, pemKey := testutil.ECKey(t)
	clk := clock.NewFake(appleStart)
	const sixMonths = config.MaxAppleSecretLifetime
	for _, c := range []struct {
		name string
		d    time.Duration
		ok   bool
	}{
		{"zero", 0, false}, {"negative", -time.Second, false}, {"one second", time.Second, true},
		{"six months", sixMonths, true}, {"over six months", sixMonths + time.Second, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			o := appleOpts(pemKey, clk)
			o.Lifetime = c.d
			_, err := provider.NewAppleSecret(o)
			if (err == nil) != c.ok {
				t.Errorf("error = %v, want ok=%v", err, c.ok)
			}
		})
	}
}

// Covers: SEC-03 (part)
func TestAppleSecretRejectsBadOptions(t *testing.T) {
	_, pemKey := testutil.ECKey(t)
	clk := clock.NewFake(appleStart)

	rsaPEM := testutil.RSAKeyPEM(t)
	_, p384 := testutil.ECKeyOn(t, elliptic.P384())

	cases := map[string]func(o *provider.AppleSecretOptions){
		"no team id":     func(o *provider.AppleSecretOptions) { o.TeamID = "" },
		"no key id":      func(o *provider.AppleSecretOptions) { o.KeyID = "" },
		"no services id": func(o *provider.AppleSecretOptions) { o.ServicesID = "" },
		"no clock":       func(o *provider.AppleSecretOptions) { o.Clock = nil },
		"not a PEM":      func(o *provider.AppleSecretOptions) { o.PrivateKeyPEM = []byte("not a key") },
		"an RSA key":     func(o *provider.AppleSecretOptions) { o.PrivateKeyPEM = rsaPEM },
		"a P-384 key":    func(o *provider.AppleSecretOptions) { o.PrivateKeyPEM = p384 },
	}
	for name, mod := range cases {
		t.Run(name, func(t *testing.T) {
			o := appleOpts(pemKey, clk)
			mod(&o)
			if _, err := provider.NewAppleSecret(o); err == nil {
				t.Error("NewAppleSecret accepted the options")
			}
		})
	}
}

// Covers: SEC-13 (part)
func TestAppleSecretLogsNoKey(t *testing.T) {
	_, pemKey := testutil.ECKey(t)
	a, err := provider.NewAppleSecret(appleOpts(pemKey, clock.NewFake(appleStart)))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	log := logx.New(&buf, slog.LevelDebug, clock.NewFake(appleStart))
	log.Info("direct", "secret_source", a)
	log.Info("pointer", "secret_source", *a)
	log.Info("nested", "details", map[string]any{"apple": a})
	out := buf.String()
	body := strings.ReplaceAll(strings.TrimSpace(strings.TrimPrefix(strings.TrimSuffix(strings.TrimSpace(string(pemKey)), "-----END PRIVATE KEY-----"), "-----BEGIN PRIVATE KEY-----")), "\n", "")
	for _, s := range []string{body[:40], "PRIVATE KEY"} {
		if strings.Contains(out, s) {
			t.Errorf("log holds %q: %s", s, out)
		}
	}
	if !strings.Contains(out, "KEY1234567") {
		t.Errorf("the key id is not logged: %s", out)
	}
}

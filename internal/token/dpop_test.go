package token_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"log/slog"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/logx"
	"github.com/yyudhistira/featherauth/internal/secure"
	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/testutil"
	"github.com/yyudhistira/featherauth/internal/token"
)

// dpopURL is the endpoint URL a proof is checked against.
const dpopURL = "https://id.example.com/t"

var dpopNow = time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)

// dpopClaimsAt returns the claims of a proof that passes every rule at now.
func dpopClaimsAt(now time.Time) map[string]any {
	return map[string]any{"htm": "POST", "htu": dpopURL, "iat": now.Unix(), "jti": "jti-1"}
}

// dpopOne returns a builder of one proof signed with key, with the default
// claims and header changed by mut.
func dpopOne(key any, mut func(h, c map[string]any)) func(*testing.T) []string {
	return func(t *testing.T) []string {
		h, c := map[string]any{}, dpopClaimsAt(dpopNow)
		if mut != nil {
			mut(h, c)
		}
		return []string{testutil.DPoPProof(t, key, h, c)}
	}
}

// dpopForged returns a token of a header and claims with the signature sig,
// for the faults that a signature cannot make.
func dpopForged(t *testing.T, header map[string]any, claims any, sig string) []string {
	return []string{testutil.DPoPSigningInput(t, header, claims) + "." + sig}
}

// rsaJWK is the public jwk of an RSA key written out by hand: jwx refuses to
// import a key under 2048 bits, and the 1024-bit row needs one in its header.
func rsaJWK(pub *rsa.PublicKey) map[string]any {
	enc := base64.RawURLEncoding.EncodeToString
	return map[string]any{"kty": "RSA", "n": enc(pub.N.Bytes()), "e": enc(big.NewInt(int64(pub.E)).Bytes())}
}

// dpopSignedRSA returns a proof signed by hand with key: RS256 (PKCS 1 v1.5)
// or, when pss is set, PS256. jwx refuses to sign or import some of these keys
// (a key under 2048 bits), so the signature is made here.
func dpopSignedRSA(t *testing.T, key *rsa.PrivateKey, pss bool, header map[string]any, claims any) []string {
	t.Helper()
	input := testutil.DPoPSigningInput(t, header, claims)
	sum := sha256.Sum256([]byte(input))
	var sig []byte
	var err error
	if pss {
		sig, err = rsa.SignPSS(secure.Default, key, crypto.SHA256, sum[:], &rsa.PSSOptions{SaltLength: sha256.Size})
	} else {
		sig, err = rsa.SignPKCS1v15(secure.Default, key, crypto.SHA256, sum[:])
	}
	if err != nil {
		t.Fatal(err)
	}
	return []string{input + "." + base64.RawURLEncoding.EncodeToString(sig)}
}

// dpopHash returns the base64url SHA-256 of s, as an ath claim holds it.
func dpopHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// dpopThumbprint is the RFC 7638 thumbprint of a public key, computed here
// without the JWT library so that the tests do not check the library against itself.
func dpopThumbprint(t testing.TB, pub any) string {
	enc := base64.RawURLEncoding.EncodeToString
	var members string
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		// The uncompressed encoding is 0x04, then X and Y at 32 bytes each.
		point, err := k.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		members = `{"crv":"P-256","kty":"EC","x":"` + enc(point[1:33]) + `","y":"` + enc(point[33:65]) + `"}`
	case *rsa.PublicKey:
		members = `{"e":"` + enc(big.NewInt(int64(k.E)).Bytes()) + `","kty":"RSA","n":"` + enc(k.N.Bytes()) + `"}`
	}
	sum := sha256.Sum256([]byte(members))
	return enc(sum[:])
}

// Covers: SEC-36 (part)
// Acceptance: DPoP proof (part)
// Every fault of the token endpoint's DPoP proof list is refused with
// ErrDPoPProof, and the accepted variants pass.
func TestDPoPProofRules(t *testing.T) {
	ec, _ := testutil.ECKey(t)
	rs2048 := testutil.RSAKey(t, 2048)
	rs1024 := testutil.RSAKey(t, 1024)
	ecPub := testutil.DPoPJWK(t, ec, false)
	rsPub := testutil.DPoPJWK(t, rs2048, false)
	valid := dpopClaimsAt(dpopNow)
	withClaim := func(name string, v any) func(h, c map[string]any) {
		return func(_, c map[string]any) { c[name] = v }
	}
	without := func(name string) func(h, c map[string]any) {
		return func(_, c map[string]any) { delete(c, name) }
	}
	twoHeaders := func(t *testing.T) []string {
		p := testutil.DPoPProof(t, ec, nil, valid)
		return []string{p, p}
	}
	tampered := func(t *testing.T) []string {
		p := strings.Split(testutil.DPoPProof(t, ec, nil, valid), ".")
		changed := dpopClaimsAt(dpopNow)
		changed["jti"] = "tampered"
		q := strings.Split(testutil.DPoPSigningInput(t, map[string]any{"alg": "ES256"}, changed), ".")
		return []string{p[0] + "." + q[1] + "." + p[2]}
	}
	ath := func(token string) func(h, c map[string]any) {
		return func(_, c map[string]any) { c["ath"] = dpopHash(token) }
	}
	rows := []struct {
		name    string
		build   func(t *testing.T) []string
		token   string
		wantErr bool
	}{
		{"valid ES256 proof", dpopOne(ec, nil), "", false},
		{"valid RS256 proof with a 2048-bit key", dpopOne(rs2048, nil), "", false},
		{"RSA key of 1024 bits with a valid signature", func(t *testing.T) []string {
			return dpopSignedRSA(t, rs1024, false, map[string]any{"alg": "RS256", "typ": "dpop+jwt", "jwk": rsaJWK(&rs1024.PublicKey)}, valid)
		}, "", true},
		{"PS256 with a 2048-bit key", func(t *testing.T) []string {
			return dpopSignedRSA(t, rs2048, true, map[string]any{"alg": "PS256", "typ": "dpop+jwt", "jwk": rsPub}, valid)
		}, "", true},
		{"ES256 proof with a P-384 key", func(t *testing.T) []string {
			p384, _ := testutil.ECKeyOn(t, elliptic.P384())
			return dpopOne(p384, nil)(t)
		}, "", true},
		{"RSA key of 1024 bits", func(t *testing.T) []string {
			return dpopForged(t, map[string]any{"alg": "RS256", "typ": "dpop+jwt", "jwk": rsaJWK(&rs1024.PublicKey)}, valid, "c2ln")
		}, "", true},
		{"no DPoP header", func(*testing.T) []string { return nil }, "", true},
		{"two DPoP headers", twoHeaders, "", true},
		{"not a compact JWS", func(*testing.T) []string { return []string{"not-a-jws"} }, "", true},
		{"typ JWT", dpopOne(ec, func(h, _ map[string]any) { h["typ"] = "JWT" }), "", true},
		{"typ in another case", dpopOne(ec, func(h, _ map[string]any) { h["typ"] = "DPOP+JWT" }), "", true},
		{"alg HS256", func(t *testing.T) []string {
			return dpopForged(t, map[string]any{"alg": "HS256", "typ": "dpop+jwt", "jwk": ecPub}, valid, "c2ln")
		}, "", true},
		{"alg none", func(t *testing.T) []string {
			return dpopForged(t, map[string]any{"alg": "none", "typ": "dpop+jwt", "jwk": ecPub}, valid, "")
		}, "", true},
		{"alg missing", func(t *testing.T) []string {
			return dpopForged(t, map[string]any{"typ": "dpop+jwt", "jwk": ecPub}, valid, "c2ln")
		}, "", true},
		{"alg RS256 with an EC key", func(t *testing.T) []string {
			return dpopForged(t, map[string]any{"alg": "RS256", "typ": "dpop+jwt", "jwk": ecPub}, valid, "c2ln")
		}, "", true},
		{"alg ES256 with an RSA key", func(t *testing.T) []string {
			return dpopForged(t, map[string]any{"alg": "ES256", "typ": "dpop+jwt", "jwk": rsPub}, valid, "c2ln")
		}, "", true},
		{"jwk with private parts", func(t *testing.T) []string {
			return []string{testutil.DPoPProof(t, ec, map[string]any{"jwk": testutil.DPoPJWK(t, ec, true)}, valid)}
		}, "", true},
		{"symmetric jwk", dpopOne(ec, func(h, _ map[string]any) {
			h["jwk"] = map[string]any{"kty": "oct", "k": "c2VjcmV0"}
		}), "", true},
		{"bad signature", tampered, "", true},
		{"wrong htm", dpopOne(ec, withClaim("htm", "GET")), "", true},
		{"htm in lower case", dpopOne(ec, withClaim("htm", "post")), "", true},
		{"htm missing", dpopOne(ec, without("htm")), "", true},
		{"wrong htu", dpopOne(ec, withClaim("htu", "https://id.example.com/other")), "", true},
		{"htu with a trailing slash", dpopOne(ec, withClaim("htu", dpopURL+"/")), "", true},
		{"htu on another port", dpopOne(ec, withClaim("htu", "https://id.example.com:8443/t")), "", true},
		{"htu with user information", dpopOne(ec, withClaim("htu", "https://user@id.example.com/t")), "", true},
		{"htu that is not a URL", dpopOne(ec, withClaim("htu", "%zz")), "", true},
		{"htu missing", dpopOne(ec, without("htu")), "", true},
		{"htu with another query", dpopOne(ec, withClaim("htu", dpopURL+"?page=2")), "", false},
		{"htu with a fragment", dpopOne(ec, withClaim("htu", dpopURL+"#part")), "", false},
		{"htu with scheme and host in capitals and the default port", dpopOne(ec, withClaim("htu", "HTTPS://ID.Example.Com:443/t")), "", false},
		{"iat with a fraction of a second", dpopOne(ec, withClaim("iat", float64(dpopNow.Unix())+0.5)), "", false},
		{"iat 6 minutes old", dpopOne(ec, withClaim("iat", dpopNow.Add(-6*time.Minute).Unix())), "", true},
		{"iat 5 minutes old", dpopOne(ec, withClaim("iat", dpopNow.Add(-5*time.Minute).Unix())), "", false},
		{"iat 2 minutes ahead", dpopOne(ec, withClaim("iat", dpopNow.Add(2*time.Minute).Unix())), "", true},
		{"iat 1 minute ahead", dpopOne(ec, withClaim("iat", dpopNow.Add(time.Minute).Unix())), "", false},
		{"iat before 1970", dpopOne(ec, withClaim("iat", -1)), "", true},
		{"iat beyond year 9999", dpopOne(ec, withClaim("iat", 300000000000)), "", true},
		{"iat missing", dpopOne(ec, without("iat")), "", true},
		{"iat not a number", dpopOne(ec, withClaim("iat", "soon")), "", true},
		{"jti missing", dpopOne(ec, without("jti")), "", true},
		{"jti empty", dpopOne(ec, withClaim("jti", "")), "", true},
		{"jti of 255 characters", dpopOne(ec, withClaim("jti", strings.Repeat("j", 255))), "", false},
		{"jti of 256 characters", dpopOne(ec, withClaim("jti", strings.Repeat("j", 256))), "", true},
		{"payload that is not an object", func(t *testing.T) []string {
			return []string{testutil.DPoPProof(t, ec, nil, []int{1})}
		}, "", true},
		{"ath missing with an access token", dpopOne(ec, nil), "at-1", true},
		{"ath of another access token", dpopOne(ec, ath("at-2")), "at-1", true},
		{"ath of the presented access token", dpopOne(ec, ath("at-1")), "at-1", false},
		{"ath ignored without an access token", dpopOne(ec, withClaim("ath", "anything")), "", false},
	}
	for _, c := range rows {
		t.Run(c.name, func(t *testing.T) {
			_, err := token.VerifyDPoP(c.build(t), "POST", dpopURL, c.token, dpopNow)
			switch {
			case c.wantErr && !errors.Is(err, token.ErrDPoPProof):
				t.Fatalf("VerifyDPoP err = %v, want ErrDPoPProof", err)
			case !c.wantErr && err != nil:
				t.Fatalf("VerifyDPoP rejected a valid proof: %v", err)
			}
		})
	}
}

// Covers: SEC-36 (part)
// Acceptance: DPoP proof (part)
// The thumbprint is the RFC 7638 thumbprint of the proof's own key, for an EC
// and an RSA key; a proof that is not the thumbprint of its key is refused by
// its signature, not here.
func TestDPoPThumbprintIsRFC7638(t *testing.T) {
	ec, _ := testutil.ECKey(t)
	rs := testutil.RSAKey(t, 2048)
	for _, c := range []struct {
		name string
		key  any
		pub  any
	}{
		{"EC P-256", ec, &ec.PublicKey},
		{"RSA 2048", rs, &rs.PublicKey},
	} {
		t.Run(c.name, func(t *testing.T) {
			p, err := token.VerifyDPoP([]string{testutil.DPoPProof(t, c.key, nil, dpopClaimsAt(dpopNow))}, "POST", dpopURL, "", dpopNow)
			if err != nil {
				t.Fatal(err)
			}
			if want := dpopThumbprint(t, c.pub); p.Thumbprint != want {
				t.Fatalf("Thumbprint = %q, want %q", p.Thumbprint, want)
			}
		})
	}
}

// Covers: SEC-36 (part)
// Acceptance: DPoP proof (part)
// The hash that a jti is remembered under depends on the key and the jti: the
// same jti with another key is another hash, and the same key with the same
// jti is the same one, whatever the rest of the proof says.
func TestDPoPHashIsPerKeyAndJTI(t *testing.T) {
	first, _ := testutil.ECKey(t)
	other, _ := testutil.ECKey(t)
	verify := func(key any, iat time.Time) token.DPoPProof {
		t.Helper()
		c := dpopClaimsAt(iat)
		c["jti"] = "same"
		p, err := token.VerifyDPoP([]string{testutil.DPoPProof(t, key, nil, c)}, "POST", dpopURL, "", dpopNow)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	a := verify(first, dpopNow)
	if b := verify(other, dpopNow); b.Hash == a.Hash {
		t.Fatal("the same jti with another key has the same hash")
	}
	if b := verify(first, dpopNow.Add(-time.Minute)); b.Hash != a.Hash {
		t.Fatal("the same key and jti have different hashes")
	}
	c := dpopClaimsAt(dpopNow)
	c["jti"] = "another"
	p, err := token.VerifyDPoP([]string{testutil.DPoPProof(t, first, nil, c)}, "POST", dpopURL, "", dpopNow)
	if err != nil {
		t.Fatal(err)
	}
	if p.Hash == a.Hash {
		t.Fatal("the same key with another jti has the same hash")
	}
}

// Covers: SEC-36 (part)
// The retention is seven minutes, as the design says.
func TestDPoPProofRetentionIsSevenMinutes(t *testing.T) {
	if token.DPoPProofRetention != 7*time.Minute {
		t.Fatalf("DPoPProofRetention = %v, want 7m", token.DPoPProofRetention)
	}
}

// Covers: SEC-36 (part)
// Acceptance: DPoP proof (part)
// A proof dated one minute ahead is accepted, and again six minutes later
// (its iat is then five minutes old); the store refuses the repeat, because the
// jti is remembered for seven minutes.
func TestDPoPRepeatSixMinutesLaterIsRefused(t *testing.T) {
	ec, _ := testutil.ECKey(t)
	s := testutil.NewStore(t)
	ctx := t.Context()
	c := map[string]any{"htm": "POST", "htu": dpopURL, "iat": dpopNow.Add(time.Minute).Unix(), "jti": "repeat-me"}
	proof := testutil.DPoPProof(t, ec, nil, c)
	first, err := token.VerifyDPoP([]string{proof}, "POST", dpopURL, "", dpopNow)
	if err != nil {
		t.Fatal(err)
	}
	again, err := token.VerifyDPoP([]string{proof}, "POST", dpopURL, "", dpopNow.Add(6*time.Minute))
	if err != nil {
		t.Fatalf("the repeat six minutes later is refused by its iat: %v", err)
	}
	use := func(p token.DPoPProof, at time.Time) bool {
		t.Helper()
		var first bool
		if err := s.Write(ctx, func(tx store.Tx) (err error) {
			first, err = tx.DPoPProofs().Use(ctx, p.Hash, at.Add(token.DPoPProofRetention))
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return first
	}
	if !use(first, dpopNow) {
		t.Fatal("the first use of the jti was refused")
	}
	if use(again, dpopNow.Add(6*time.Minute)) {
		t.Fatal("the repeat of the jti six minutes later was accepted")
	}
}

// Covers: SEC-13 (part)
// Acceptance: DPoP proof (part)
// A proof logs only its thumbprint, directly and nested in a map: neither its
// jti nor its hash reaches a log line.
func TestDPoPProofLogsOnlyItsThumbprint(t *testing.T) {
	ec, _ := testutil.ECKey(t)
	c := dpopClaimsAt(dpopNow)
	c["jti"] = "jti-logged"
	p, err := token.VerifyDPoP([]string{testutil.DPoPProof(t, ec, nil, c)}, "POST", dpopURL, "", dpopNow)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	log := logx.New(&buf, slog.LevelDebug, clock.NewFake(dpopNow))
	log.Info("proof", "proof", p)
	log.Info("nested", "details", map[string]any{"proof": p})
	out := buf.String()
	if strings.Count(out, p.Thumbprint) != 2 {
		t.Fatalf("the thumbprint is not logged once per line:\n%s", out)
	}
	for _, hidden := range []string{"jti-logged", string(p.Hash)} {
		if strings.Contains(out, hidden) {
			t.Fatalf("a log line holds %q:\n%s", hidden, out)
		}
	}
}

// Covers: SEC-36 (part)
// The endpoint URL the proof is checked against must parse; a broken one is a
// configuration error, not a proof that fails.
func TestDPoPEndpointURLMustParse(t *testing.T) {
	ec, _ := testutil.ECKey(t)
	p := testutil.DPoPProof(t, ec, nil, dpopClaimsAt(dpopNow))
	_, err := token.VerifyDPoP([]string{p}, "POST", "https://[::1/t", "", dpopNow)
	if err == nil || errors.Is(err, token.ErrDPoPProof) {
		t.Fatalf("err = %v, want a configuration error", err)
	}
}

func FuzzVerifyDPoP(f *testing.F) {
	ec, _ := testutil.ECKey(f)
	valid := testutil.DPoPProof(f, ec, nil, dpopClaimsAt(dpopNow))
	parts := strings.Split(valid, ".")
	forged := testutil.DPoPSigningInput(f, map[string]any{"alg": "none", "typ": "dpop+jwt"}, dpopClaimsAt(dpopNow))
	for _, seed := range []string{
		valid, "", ".", "..", "a.b.c", parts[0] + "." + parts[1], valid + ".x",
		forged + ".", forged + ".c2ln", strings.Repeat("a", 4096), "e30.e30.",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		_, err := token.VerifyDPoP([]string{raw}, "POST", dpopURL, "", dpopNow)
		if err != nil && !errors.Is(err, token.ErrDPoPProof) {
			t.Fatalf("error %v is not ErrDPoPProof", err)
		}
		if raw == valid && err != nil {
			t.Fatalf("the valid proof was refused: %v", err)
		}
	})
}

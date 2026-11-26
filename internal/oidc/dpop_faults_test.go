package oidc_test

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/secure"
	"github.com/yyudhistira/featherauth/internal/testutil"
	"github.com/yyudhistira/featherauth/internal/testutil/server"
)

// tokenClaims returns the claims of a proof for the token endpoint of e, with mut
// applied.
func tokenClaims(e *server.Env, mut func(c map[string]any)) map[string]any {
	c := map[string]any{
		"htm": "POST", "htu": e.Realm.EndpointURL(config.EndpointToken, ""),
		"iat": e.Clock.Now().Unix(), "jti": "jti-" + strconv.FormatInt(dpopJTI.Add(1), 10),
	}
	if mut != nil {
		mut(c)
	}
	return c
}

// rsaJWKOf is the public jwk of an RSA key as a JSON object.
func rsaJWKOf(pub *rsa.PublicKey) map[string]any {
	enc := base64.RawURLEncoding.EncodeToString
	return map[string]any{"kty": "RSA", "n": enc(pub.N.Bytes()), "e": enc([]byte{byte(pub.E >> 16), byte(pub.E >> 8), byte(pub.E)})}
}

// rsa1024Proof is a proof signed with RS256 by a 1024-bit key. jwx refuses to
// import such a key, so the signature is made here.
func rsa1024Proof(t *testing.T, e *server.Env) string {
	t.Helper()
	k := testutil.RSAKey(t, 1024)
	input := testutil.DPoPSigningInput(t, map[string]any{"alg": "RS256", "typ": "dpop+jwt", "jwk": rsaJWKOf(&k.PublicKey)}, tokenClaims(e, nil))
	sum := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(secure.Default, k, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// Covers: FR-44, SEC-36
// Acceptance: DPoP proof
// Every token-endpoint fault of the DPoP proof row is refused with
// invalid_dpop_proof, and the code it came with still exchanges after them; the
// accepted variants pass: an htu with another query, the same jti with another
// key, and a proof dated a minute ahead repeated six minutes later is refused.
func TestDPoPProofRowAtTheTokenEndpoint(t *testing.T) {
	key, _ := testutil.ECKey(t)
	other, _ := testutil.ECKey(t)
	e := server.New(t)
	setDPoP(t, e, server.ClientQuery.ID, "allowed")
	code := e.Login(t, server.ClientQuery)
	form := server.CodeForm(server.ClientQuery, code)
	faults := []struct {
		name string
		h    http.Header
	}{
		{"two DPoP headers", http.Header{http.CanonicalHeaderKey("DPoP"): {dpopProof(t, e, key, nil), dpopProof(t, e, key, nil)}}},
		{"typ JWT", dpopHeader(testutil.DPoPProof(t, key, map[string]any{"typ": "JWT"}, tokenClaims(e, nil)))},
		{"alg HS256", dpopHeader(testutil.DPoPSigningInput(t, map[string]any{"alg": "HS256", "typ": "dpop+jwt", "jwk": testutil.DPoPJWK(t, key, false)}, tokenClaims(e, nil)) + ".c2ln")},
		{"alg none", dpopHeader(testutil.DPoPSigningInput(t, map[string]any{"alg": "none", "typ": "dpop+jwt", "jwk": testutil.DPoPJWK(t, key, false)}, tokenClaims(e, nil)) + ".")},
		{"a jwk with private parts", dpopHeader(testutil.DPoPProof(t, key, map[string]any{"jwk": testutil.DPoPJWK(t, key, true)}, tokenClaims(e, nil)))},
		{"an RSA key of 1024 bits", dpopHeader(rsa1024Proof(t, e))},
		{"a bad signature", dpopHeader(tamperedPayload(t, e, key))},
		{"iat 2 minutes ahead", dpopHeader(dpopProof(t, e, key, func(c map[string]any) { c["iat"] = e.Clock.Now().Add(2 * time.Minute).Unix() }))},
		{"htm GET", dpopHeader(dpopProof(t, e, key, func(c map[string]any) { c["htm"] = "GET" }))},
		{"htu of another path", dpopHeader(dpopProof(t, e, key, func(c map[string]any) { c["htu"] = "https://auth.example.com/main/other" }))},
		{"iat 6 minutes old", dpopHeader(dpopProof(t, e, key, func(c map[string]any) { c["iat"] = e.Clock.Now().Add(-6 * time.Minute).Unix() }))},
		{"an empty jti", dpopHeader(dpopProof(t, e, key, func(c map[string]any) { c["jti"] = "" }))},
		{"not a compact JWS", dpopHeader("not-a-proof")},
	}
	for _, f := range faults {
		t.Run(f.name, func(t *testing.T) {
			wantDPoPRefusal(t, post(t, e, form, f.h), "invalid_dpop_proof")
		})
	}
	t.Run("the code still exchanges after the faults", func(t *testing.T) {
		p := dpopProof(t, e, key, nil)
		wantDPoPTokens(t, post(t, e, form, dpopHeader(p)), dpopThumb(t, e, p))
	})

	t.Run("a repeated jti is refused, and its code still exchanges with a new proof", func(t *testing.T) {
		p := dpopProof(t, e, key, nil)
		wantDPoPTokens(t, codeExchange(t, e, server.ClientQuery, dpopHeader(p)), dpopThumb(t, e, p))
		wantDPoPRefusal(t, codeExchange(t, e, server.ClientQuery, dpopHeader(p)), "invalid_dpop_proof")
		wantDPoPTokens(t, codeExchange(t, e, server.ClientQuery, dpopHeader(dpopProof(t, e, key, nil))), dpopThumb(t, e, p))
	})
	t.Run("a made-up code with a valid proof writes nothing", func(t *testing.T) {
		before := rowCounts(t, e)
		made := server.CodeForm(server.ClientQuery, server.Result{Values: url.Values{"code": {"made-up-code"}}})
		wantDPoPRefusal(t, post(t, e, made, dpopHeader(dpopProof(t, e, key, nil))), "invalid_grant")
		if got := rowCounts(t, e); got["dpop_proofs"] != before["dpop_proofs"] || got["refresh_tokens"] != before["refresh_tokens"] {
			t.Fatalf("a made-up code wrote rows: before %v, after %v", before, got)
		}
	})
	t.Run("a wrong secret with a valid proof writes nothing", func(t *testing.T) {
		setDPoP(t, e, server.ClientConfidential.ID, "allowed")
		before := rowCounts(t, e)
		f := server.CodeForm(server.ClientConfidential, e.Login(t, server.ClientConfidential))
		f.Set("client_secret", "wrong-secret")
		wantError(t, post(t, e, f, dpopHeader(dpopProof(t, e, key, nil))), http.StatusBadRequest, "invalid_client")
		if got := rowCounts(t, e); got["dpop_proofs"] != before["dpop_proofs"] || got["refresh_tokens"] != before["refresh_tokens"] {
			t.Fatalf("a wrong secret wrote rows: before %v, after %v", before, got)
		}
	})
	t.Run("an htu with another query is accepted", func(t *testing.T) {
		p := dpopProof(t, e, key, func(c map[string]any) { c["htu"] = e.Realm.EndpointURL(config.EndpointToken, "") + "?page=2" })
		wantDPoPTokens(t, codeExchange(t, e, server.ClientQuery, dpopHeader(p)), dpopThumb(t, e, dpopProof(t, e, key, nil)))
	})
	t.Run("the same jti with another key is accepted", func(t *testing.T) {
		a := dpopProof(t, e, key, func(c map[string]any) { c["jti"] = "shared-jti" })
		b := dpopProof(t, e, other, func(c map[string]any) { c["jti"] = "shared-jti" })
		wantDPoPTokens(t, codeExchange(t, e, server.ClientQuery, dpopHeader(a)), dpopThumb(t, e, a))
		wantDPoPTokens(t, codeExchange(t, e, server.ClientQuery, dpopHeader(b)), dpopThumb(t, e, b))
	})
	t.Run("a proof dated a minute ahead is accepted, and refused six minutes later", func(t *testing.T) {
		late := dpopProof(t, e, key, func(c map[string]any) {
			c["iat"] = e.Clock.Now().Add(time.Minute).Unix()
			c["jti"] = "late-jti"
		})
		wantDPoPTokens(t, codeExchange(t, e, server.ClientQuery, dpopHeader(late)), dpopThumb(t, e, late))
		e.Clock.Advance(6 * time.Minute)
		wantDPoPRefusal(t, codeExchange(t, e, server.ClientQuery, dpopHeader(late)), "invalid_dpop_proof")
	})
}

// tamperedPayload is a valid proof whose claims were changed after signing: its
// signature no longer matches.
func tamperedPayload(t *testing.T, e *server.Env, key any) string {
	t.Helper()
	p := strings.Split(testutil.DPoPProof(t, key, nil, tokenClaims(e, nil)), ".")
	changed := tokenClaims(e, func(c map[string]any) { c["jti"] = "tampered" })
	q := strings.Split(testutil.DPoPSigningInput(t, map[string]any{"alg": "ES256"}, changed), ".")
	return p[0] + "." + q[1] + "." + p[2]
}

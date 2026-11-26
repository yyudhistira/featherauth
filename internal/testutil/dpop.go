package testutil

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"

	"github.com/yyudhistira/featherauth/internal/secure"
)

// RSAKey generates an RSA private key of bits bits. It is a fresh test key.
func RSAKey(t testing.TB, bits int) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(secure.Default, bits)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// DPoPProof returns a compact DPoP proof (RFC 9449) signed with key, an EC or
// an RSA private key. The header gets typ dpop+jwt and the public jwk of key;
// the values of header replace them and add to them. The algorithm is ES256
// for an EC key and RS256 for an RSA key. claims is marshalled as the payload.
func DPoPProof(t testing.TB, key any, header map[string]any, claims any) string {
	t.Helper()
	var alg jwa.SignatureAlgorithm
	var pub any
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		alg, pub = jwa.ES256(), &k.PublicKey
	case *rsa.PrivateKey:
		alg, pub = jwa.RS256(), &k.PublicKey
	default:
		t.Fatalf("DPoPProof: unsupported key %T", key)
	}
	publicKey, err := jwk.Import(pub)
	if err != nil {
		t.Fatal(err)
	}
	fields := map[string]any{"typ": "dpop+jwt", "jwk": publicKey}
	for name, v := range header {
		fields[name] = v
	}
	h := jws.NewHeaders()
	for name, v := range fields {
		if m, ok := v.(map[string]any); ok && name == "jwk" {
			v = dpopJWKOf(t, m)
		}
		if err := h.Set(name, v); err != nil {
			t.Fatal(err)
		}
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := jws.Sign(payload, jws.WithKey(alg, key, jws.WithProtectedHeaders(h)))
	if err != nil {
		t.Fatal(err)
	}
	return string(signed)
}

// DPoPSigningInput returns the first two parts of a compact JWS, the base64url
// of header and of claims joined by a dot, with nothing signed. A test adds the
// signature part itself, to forge a token.
func DPoPSigningInput(t testing.TB, header map[string]any, claims any) string {
	t.Helper()
	h, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	c, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(c)
}

// DPoPJWK returns the public jwk of key as a JSON object, or the private one
// when private is set. key is an EC or an RSA private key.
func DPoPJWK(t testing.TB, key any, private bool) map[string]any {
	t.Helper()
	var src any = key
	if !private {
		switch k := key.(type) {
		case *ecdsa.PrivateKey:
			src = &k.PublicKey
		case *rsa.PrivateKey:
			src = &k.PublicKey
		}
	}
	k, err := jwk.Import(src)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(k)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// dpopJWKOf parses a jwk given as a JSON object, public or private.
func dpopJWKOf(t testing.TB, m map[string]any) jwk.Key {
	t.Helper()
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	k, err := jwk.ParseKey(data)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

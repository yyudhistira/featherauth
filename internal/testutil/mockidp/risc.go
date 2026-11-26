package mockidp

import (
	"crypto/rsa"
	"encoding/json"
	"net/http"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"

	"github.com/yyudhistira/featherauth/internal/secure"
)

// RISCIssuer is the issuer the mock names in its RISC configuration document
// and in its security event tokens: Google's documented issuer. The mock's ID
// tokens carry the mock's own URL, so a security event token with that issuer
// is the wrong-issuer case of the Google events.
const RISCIssuer = "https://accounts.google.com"

// RISCConfigPath is the path of the mock's RISC configuration document. Its
// keys are at /risc-jwks, RS256 like the security event tokens the mock signs.
const RISCConfigPath = "/risc-configuration"

const riscKID = "risc-1"

// FailRISC makes the next n requests to the RISC configuration document and to
// its key set answer 500.
func (s *Server) FailRISC(n int) { s.mu.Lock(); defer s.mu.Unlock(); s.failRISC = n }

// SetRISCIssuer sets the issuer the RISC configuration document names, which is
// RISCIssuer until it is called (an empty issuer is kept as empty), for the test of
// a document whose issuer is empty or ends in a slash. The security event tokens keep the claims the test gives them.
func (s *Server) SetRISCIssuer(issuer string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.riscIssuer, s.riscIssuerSet = issuer, true
}

// riscDocumentIssuer is the issuer the RISC configuration document names.
func (s *Server) riscDocumentIssuer() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.riscIssuerSet {
		return RISCIssuer
	}
	return s.riscIssuer
}

// riscFails reports whether the next RISC request must answer 500, and counts it.
func (s *Server) riscFails() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failRISC > 0 {
		s.failRISC--
		return true
	}
	return false
}

// riscPrivate returns the RSA key of the security event tokens, made on first use.
func (s *Server) riscPrivate() *rsa.PrivateKey {
	s.riscOnce.Do(func() {
		k, err := rsa.GenerateKey(secure.Default, 2048)
		if err != nil {
			panic(err)
		}
		s.riscKey = k
	})
	return s.riscKey
}

// riscConfig serves the RISC configuration document: the issuer of the security
// event tokens and the URL of their keys.
func (s *Server) riscConfig(w http.ResponseWriter, _ *http.Request) {
	if s.redirected(w, "risc") {
		return
	}
	if s.riscFails() {
		oauthError(w, http.StatusInternalServerError, "server_error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"issuer": s.riscDocumentIssuer(), "jwks_uri": s.URL() + "/risc-jwks"})
}

// riscJWKS serves the key set of the security event tokens.
func (s *Server) riscJWKS(w http.ResponseWriter, _ *http.Request) {
	if s.redirected(w, "risc-jwks") {
		return
	}
	if s.riscFails() {
		oauthError(w, http.StatusInternalServerError, "server_error")
		return
	}
	pub, err := jwk.Import(&s.riscPrivate().PublicKey)
	if err != nil {
		panic(err)
	}
	for name, v := range map[string]any{jwk.KeyIDKey: riscKID, jwk.AlgorithmKey: "RS256", jwk.KeyUsageKey: "sig"} {
		if err := pub.Set(name, v); err != nil {
			panic(err)
		}
	}
	set := jwk.NewSet()
	if err := set.AddKey(pub); err != nil {
		panic(err)
	}
	writeJSON(w, http.StatusOK, set)
}

// RISCToken returns a security event token with exactly these claims, signed
// with the RISC key, for a test of a token that is wrong in one claim.
func (s *Server) RISCToken(claims map[string]any) string {
	payload, err := json.Marshal(claims)
	if err != nil {
		panic(err) // a test passes a plain map
	}
	h := jws.NewHeaders()
	if err := h.Set(jws.KeyIDKey, riscKID); err != nil {
		panic(err)
	}
	out, err := jws.Sign(payload, jws.WithKey(jwa.RS256(), s.riscPrivate(), jws.WithProtectedHeaders(h)))
	if err != nil {
		panic(err)
	}
	return string(out)
}

// SecurityEvent returns a security event token from the RISC issuer for aud,
// with the given events (the events claim), a fresh jti and the current iat.
func (s *Server) SecurityEvent(aud string, events map[string]any) string {
	s.mu.Lock()
	claims := map[string]any{
		"iss": RISCIssuer, "aud": aud, "iat": s.clock.Now().Unix(), "jti": s.next("set"), "events": events,
	}
	s.mu.Unlock()
	return s.RISCToken(claims)
}

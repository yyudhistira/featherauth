package token

import (
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"

	"github.com/yyudhistira/featherauth/internal/secure"
)

// ErrDPoPProof is returned for a DPoP proof that fails a rule of SEC-36; test it
// with errors.Is. The text says which rule.
var ErrDPoPProof = errors.New("token: invalid DPoP proof")

const (
	dpopType     = "dpop+jwt"
	dpopMaxAge   = 5 * time.Minute
	dpopMaxAhead = time.Minute
	dpopMaxJTI   = 255
	// dpopMaxUnix is 9999-12-31T23:59:59Z, the last instant a proof's iat can name.
	dpopMaxUnix = 253402300799
)

// DPoPProofRetention is how long the hash of a proof's jti is remembered: a
// proof is valid for at most dpopMaxAge after its iat and dpopMaxAhead before
// it, so the window is their sum, and one minute more keeps a repeat refused
// for any proof that could still be accepted.
const DPoPProofRetention = dpopMaxAge + dpopMaxAhead + time.Minute

// DPoPProof is a DPoP proof (RFC 9449) that passed the rules of VerifyDPoP.
type DPoPProof struct {
	// Thumbprint is the RFC 7638 thumbprint of the proof's key, base64url without padding.
	Thumbprint string
	// Hash is the SHA-256 of the thumbprint and the jti. The caller remembers
	// it (DPoPProofs.Use) to refuse a repeated jti.
	Hash secure.Hash
}

var _ slog.LogValuer = DPoPProof{}

// LogValue logs only the thumbprint: neither the jti nor the hash reaches a log line.
func (p DPoPProof) LogValue() slog.Value {
	return slog.GroupValue(slog.String("thumbprint", p.Thumbprint))
}

// dpopClaims are the claims a proof carries. Pointers tell a missing member
// from an empty one.
type dpopClaims struct {
	HTM *string  `json:"htm"`
	HTU *string  `json:"htu"`
	IAT *float64 `json:"iat"`
	JTI *string  `json:"jti"`
	ATH *string  `json:"ath"`
}

// VerifyDPoP checks the DPoP proof of a request with method to the endpoint at
// url, the endpoint's full URL (public_url and its configured path). header
// holds the values of the DPoP header, which must be exactly one. accessToken
// is the access token the request presents, or "": a proof of such a request
// carries ath, and the hash of the token is checked against it. now is the
// time of the check. VerifyDPoP does not remember the jti: the caller does, with
// the returned Hash, in its write transaction (SEC-36). A url that does not
// parse is a configuration error, returned unwrapped and not as ErrDPoPProof:
// the proof is not at fault.
func VerifyDPoP(header []string, method, url, accessToken string, now time.Time) (DPoPProof, error) {
	want, err := normalizeHTU(url)
	if err != nil {
		return DPoPProof{}, fmt.Errorf("token: endpoint URL: %w", err)
	}
	if len(header) != 1 {
		return DPoPProof{}, dpopErr(fmt.Sprintf("want exactly one DPoP header, got %d", len(header)))
	}
	msg, err := jws.Parse([]byte(header[0]), jws.WithCompact())
	if err != nil || len(msg.Signatures()) != 1 {
		return DPoPProof{}, dpopErr("not a compact JWS")
	}
	h := msg.Signatures()[0].ProtectedHeaders()
	if typ, _ := h.Type(); typ != dpopType {
		return DPoPProof{}, dpopErr("typ is not dpop+jwt")
	}
	alg, ok := h.Algorithm()
	if !ok || (alg.String() != "ES256" && alg.String() != "RS256") {
		return DPoPProof{}, dpopErr("alg is not ES256 or RS256")
	}
	key, ok := h.JWK()
	if !ok {
		return DPoPProof{}, dpopErr("no jwk in the header")
	}
	if private, err := jwk.IsPrivateKey(key); err != nil || private {
		return DPoPProof{}, dpopErr("jwk is not a public asymmetric key")
	}
	if err := dpopCheckKey(key, alg.String()); err != nil {
		return DPoPProof{}, err
	}
	if _, err := jws.Verify([]byte(header[0]), jws.WithKey(alg, key)); err != nil {
		return DPoPProof{}, dpopErr("invalid signature")
	}
	var c dpopClaims
	if err := json.Unmarshal(msg.Payload(), &c); err != nil {
		return DPoPProof{}, dpopErr("payload is not a JSON object of the right claims")
	}
	if c.HTM == nil || *c.HTM != method {
		return DPoPProof{}, dpopErr("htm does not match the method")
	}
	if c.HTU == nil {
		return DPoPProof{}, dpopErr("htu missing")
	}
	got, err := normalizeHTU(*c.HTU)
	if err != nil || got != want {
		return DPoPProof{}, dpopErr("htu does not match the endpoint")
	}
	if c.IAT == nil {
		return DPoPProof{}, dpopErr("iat missing")
	}
	iat, ok := unixTime(*c.IAT)
	if !ok {
		return DPoPProof{}, dpopErr("iat is not a time")
	}
	if now.Sub(iat) > dpopMaxAge {
		return DPoPProof{}, dpopErr("iat is more than 5 minutes old")
	}
	if iat.Sub(now) > dpopMaxAhead {
		return DPoPProof{}, dpopErr("iat is more than 1 minute ahead")
	}
	if c.JTI == nil || *c.JTI == "" || utf8.RuneCountInString(*c.JTI) > dpopMaxJTI {
		return DPoPProof{}, dpopErr("jti missing or longer than 255 characters")
	}
	if accessToken != "" && (c.ATH == nil || !secure.Equal(*c.ATH, accessHash(accessToken))) {
		return DPoPProof{}, dpopErr("ath does not match the access token")
	}
	thumb, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return DPoPProof{}, dpopErr("jwk has no thumbprint")
	}
	jkt := base64.RawURLEncoding.EncodeToString(thumb)
	// The thumbprint has no dot, so the dot separates it from the jti exactly.
	return DPoPProof{Thumbprint: jkt, Hash: secure.HashOf(jkt + "." + *c.JTI)}, nil
}

// dpopErr is a proof that fails a rule, with the rule in its text.
func dpopErr(reason string) error {
	return fmt.Errorf("%w: %s", ErrDPoPProof, reason)
}

// dpopCheckKey checks that an ES256 proof's public jwk is a P-256 key. For RS256
// nothing is checked here: jwx refuses an RSA key under 2048 bits when it reads
// the jwk (jws.Parse), and the signature check refuses any other key type.
func dpopCheckKey(key jwk.Key, alg string) error {
	if alg != "ES256" {
		return nil
	}
	ek, ok := key.(jwk.ECDSAPublicKey)
	if !ok {
		return dpopErr("the jwk is not a P-256 key for ES256")
	}
	if crv, has := ek.Crv(); !has || crv != jwa.P256() {
		return dpopErr("the jwk is not a P-256 key for ES256")
	}
	return nil
}

// unixTime returns the instant of an iat, a number of seconds, and false when
// the value is past dpopMaxUnix: a float beyond the int64 range has no defined
// integer, so it is not converted.
func unixTime(sec float64) (time.Time, bool) {
	if sec > dpopMaxUnix {
		return time.Time{}, false
	}
	whole, frac := math.Modf(sec)
	return time.Unix(int64(whole), int64(frac*1e9)).UTC(), true
}

// accessHash is the ath claim of an access token: its SHA-256, base64url without padding.
func accessHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// normalizeHTU returns a URL as RFC 9449 section 4.3 compares it: the query and
// the fragment are dropped, the scheme and host are in lower case, and a default
// port is dropped. A URL with user information is not comparable, so it is an error.
func normalizeHTU(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if u.User != nil {
		return "", errors.New("user information in the URL")
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	switch {
	case port != "" && !((scheme == "https" && port == "443") || (scheme == "http" && port == "80")):
		host = net.JoinHostPort(host, port)
	case strings.Contains(host, ":"):
		host = "[" + host + "]"
	}
	return scheme + "://" + host + u.EscapedPath(), nil
}

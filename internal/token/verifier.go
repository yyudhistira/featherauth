package token

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/config"
)

// Errors returned by the Verifier; test them with errors.Is.
var (
	ErrWrongType  = errors.New("token: wrong token type")
	ErrWrongRealm = errors.New("token: token of another realm")
	ErrExpired    = errors.New("token: token expired")
	ErrSignature  = errors.New("token: invalid signature")
)

// AccessClaims are the claims of a verified access token.
type AccessClaims struct {
	Sub      UserID
	Aud      string
	ClientID string
	Azp      string
	Sid      SessionID
	Scope    string
	Exp      time.Time
	Iat      time.Time
	// AuthTime is the login time behind the token; zero when the claim is missing.
	AuthTime time.Time
	Jti      string
	// Jkt is the JWK thumbprint the token is bound to (its cnf.jkt claim, FR-44);
	// empty for an unbound token.
	Jkt string
}

// HintClaims are the claims of a verified ID token hint.
type HintClaims struct {
	Sub UserID
	Sid SessionID
	Aud string
	Exp time.Time
}

// Verifier checks tokens issued by an Issuer.
type Verifier struct {
	clock   clock.Clock
	secrets config.Secrets
	mu      sync.Mutex
	sets    map[config.RealmName]cachedKeySet
}

// cachedKeySet is the key set built for one realm snapshot.
type cachedKeySet struct {
	realm *config.Realm
	set   *KeySet
}

// NewVerifier returns a Verifier.
func NewVerifier(c clock.Clock, secrets config.Secrets) *Verifier {
	return &Verifier{clock: c, secrets: secrets, sets: map[config.RealmName]cachedKeySet{}}
}

// Access verifies an access token of realm r: header typ at+jwt, iss equal to
// the realm's issuer, a signature by one of the realm's keys (verify-only
// keys included) made with tokens.algorithm, and exp in the future. There is no
// clock leeway: a token is expired from the second of its exp. The audience is
// not checked.
func (v *Verifier) Access(r *config.Realm, raw string) (AccessClaims, error) {
	if r == nil {
		return AccessClaims{}, errors.New("token: a realm is required")
	}
	m, err := v.verify(r, raw, "at+jwt", r.Tokens.Algorithm)
	if err != nil {
		return AccessClaims{}, err
	}
	exp, ok := unixClaim(m, "exp")
	if !ok || !v.clock.Now().Before(exp) {
		return AccessClaims{}, ErrExpired
	}
	iat, _ := unixClaim(m, "iat")
	authTime, _ := unixClaim(m, "auth_time")
	jkt := ""
	if cnf, ok := m["cnf"].(map[string]any); ok {
		jkt = str(cnf, "jkt")
	}
	return AccessClaims{
		Sub: UserID(str(m, "sub")), Aud: str(m, "aud"), ClientID: str(m, "client_id"),
		Azp: str(m, "azp"), Sid: SessionID(str(m, "sid")), Scope: str(m, "scope"),
		Exp: exp, Iat: iat, AuthTime: authTime, Jti: str(m, "jti"), Jkt: jkt,
	}, nil
}

// IDTokenHint verifies an ID token used as id_token_hint: header typ JWT, RS256,
// iss equal to the realm's issuer and a valid signature. Its expiry is ignored.
func (v *Verifier) IDTokenHint(r *config.Realm, raw string) (HintClaims, error) {
	if r == nil {
		return HintClaims{}, errors.New("token: a realm is required")
	}
	m, err := v.verify(r, raw, "JWT", "RS256")
	if err != nil {
		return HintClaims{}, err
	}
	exp, _ := unixClaim(m, "exp")
	return HintClaims{Sub: UserID(str(m, "sub")), Sid: SessionID(str(m, "sid")), Aud: str(m, "aud"), Exp: exp}, nil
}

// verify checks the header, the issuer and the signature, in that order, and
// returns the claims. Expiry is left to the caller.
func (v *Verifier) verify(r *config.Realm, raw, typ, alg string) (map[string]any, error) {
	msg, err := jws.Parse([]byte(raw), jws.WithCompact())
	if err != nil || len(msg.Signatures()) != 1 {
		return nil, fmt.Errorf("%w: not a compact JWS", ErrSignature)
	}
	h := msg.Signatures()[0].ProtectedHeaders()
	if got, _ := h.Type(); got != typ {
		return nil, ErrWrongType
	}
	var m map[string]any
	if err := json.Unmarshal(msg.Payload(), &m); err != nil {
		return nil, fmt.Errorf("%w: payload is not a JSON object", ErrSignature)
	}
	if str(m, "iss") != r.Issuer() {
		return nil, ErrWrongRealm
	}
	ks, err := v.keySet(r)
	if err != nil {
		return nil, err
	}
	kid, _ := h.KeyID()
	pub, keyAlg, ok := ks.Lookup(kid)
	if !ok {
		return nil, fmt.Errorf("%w: unknown or missing kid", ErrSignature)
	}
	if got, _ := h.Algorithm(); got.String() != alg || keyAlg != alg {
		return nil, fmt.Errorf("%w: algorithm not accepted here", ErrSignature)
	}
	a, _ := jwa.LookupSignatureAlgorithm(alg)
	if _, err := jws.Verify([]byte(raw), jws.WithKey(a, pub)); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSignature, err)
	}
	return m, nil
}

func str(m map[string]any, name string) string {
	s, _ := m[name].(string)
	return s
}

// maxUnixClaim bounds a time claim (2^53 seconds), so that converting it to an
// integer cannot overflow; a larger number is clamped to the bound.
const maxUnixClaim = 1 << 53

func unixClaim(m map[string]any, name string) (time.Time, bool) {
	f, ok := m[name].(float64)
	if !ok {
		return time.Time{}, false
	}
	f = max(-maxUnixClaim, min(maxUnixClaim, f))
	return time.Unix(int64(f), 0).UTC(), true
}

// keySet returns the key set of a realm. It is built once per *config.Realm: a
// snapshot is immutable, so a reload yields new pointers. The cache holds one
// entry per realm name, so a reload replaces the entry instead of adding one.
func (v *Verifier) keySet(r *config.Realm) (*KeySet, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if c, ok := v.sets[r.Name]; ok && c.realm == r {
		return c.set, nil
	}
	ks, err := NewKeySet(r, v.secrets)
	if err != nil {
		return nil, err
	}
	v.sets[r.Name] = cachedKeySet{realm: r, set: ks}
	return ks, nil
}

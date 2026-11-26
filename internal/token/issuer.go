package token

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/secure"
)

// jtiBytes is the size of the random jti of an access token (128 bits).
const jtiBytes = 16

// Seams for library calls whose errors cannot be provoked with real input;
// tests replace them (and restore them) to reach those branches.
var (
	signJWS    = func(payload []byte, opts ...jws.SignOption) ([]byte, error) { return jws.Sign(payload, opts...) }
	setHeader  = func(h jws.Headers, name string, v any) error { return h.Set(name, v) }
	encodeJSON = EncodeClaims
)

// UserID is the stable internal id of a user (the sub claim).
type UserID string

// SessionID identifies a login session (the sid claim).
type SessionID string

// Session is what tokens copy from the login: the same values on every
// refresh.
type Session struct {
	ID        SessionID
	StartedAt time.Time
	AuthTime  time.Time
	Nonce     string
	// Jkt is the key the access token is bound to (its cnf.jkt claim); empty
	// for an unbound access token.
	Jkt string
	// SSOIDHash is the hash of the browser session the session started from
	// (FR-45), kept by its refresh tokens; empty when it started from none.
	SSOIDHash secure.Hash
}

// LogValue implements slog.LogValuer. The nonce is a secret (SEC-13) and is
// not logged.
func (s Session) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("id", string(s.ID)),
		slog.Time("started_at", s.StartedAt),
		slog.Time("auth_time", s.AuthTime),
	)
}

// Subject is the stored profile of a user, as far as tokens use it.
type Subject struct {
	ID            UserID
	Email         string
	EmailVerified bool
	Name          string
}

// LogValue implements slog.LogValuer. Only the user id is logged: emails are
// never logged and the name is personal data (SEC-13).
func (s Subject) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("id", string(s.ID)),
		slog.Bool("email_verified", s.EmailVerified),
	)
}

// Issuer signs access tokens, ID tokens and JWT refresh tokens with the
// active keys of a realm. It holds no state and is safe for concurrent use.
type Issuer struct {
	clock   clock.Clock
	src     secure.Source
	secrets config.Secrets
}

// NewIssuer returns an Issuer that reads time from c, random jti values from
// src and private keys from secrets.
func NewIssuer(c clock.Clock, src secure.Source, secrets config.Secrets) *Issuer {
	return &Issuer{clock: c, src: src, secrets: secrets}
}

// Access issues an access token (RFC 9068, typ at+jwt) signed with the realm's
// tokens.algorithm, and returns it with its expiry. Its user claims are those
// of user_data.access_token_claims when set, else of user_data.claims.
func (i *Issuer) Access(r *config.Realm, cl *config.Client, s Subject, ss Session) (string, time.Time, error) {
	id, err := clientID(r, cl)
	if err != nil {
		return "", time.Time{}, err
	}
	jti, err := secure.Token(i.src, jtiBytes)
	if err != nil {
		return "", time.Time{}, err
	}
	now := i.clock.Now()
	exp := now.Add(cl.Lifetimes().AccessToken)
	m := map[string]any{
		"iss": r.Issuer(), "sub": string(s.ID), "aud": cl.Audience,
		"client_id": string(id), "azp": string(id),
		"exp": exp, "iat": now, "jti": jti,
		"auth_time": ss.AuthTime, "sid": string(ss.ID), "scope": "openid",
	}
	addNonce(m, ss)
	if ss.Jkt != "" {
		m["cnf"] = map[string]any{"jkt": ss.Jkt}
	}
	userClaims(m, r.UserData.AccessClaims(), cl, s)
	raw, err := i.sign(r, r.Tokens.Algorithm, "at+jwt", m)
	if err != nil {
		return "", time.Time{}, err
	}
	return raw, exp, nil
}

// ID issues an ID token, always RS256, with at_hash of accessToken.
func (i *Issuer) ID(r *config.Realm, cl *config.Client, s Subject, ss Session, accessToken string) (string, error) {
	id, err := clientID(r, cl)
	if err != nil {
		return "", err
	}
	now := i.clock.Now()
	sum := sha256.Sum256([]byte(accessToken))
	m := map[string]any{
		"iss": r.Issuer(), "sub": string(s.ID), "aud": string(id),
		"exp": now.Add(cl.Lifetimes().AccessToken), "iat": now,
		"auth_time": ss.AuthTime, "sid": string(ss.ID),
		"at_hash": base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2]),
	}
	addNonce(m, ss)
	userClaims(m, r.UserData.Claims, cl, s)
	return i.sign(r, "RS256", "JWT", m)
}

// backchannelEvent is the event member of a back-channel logout token (SEC-35).
const backchannelEvent = "http://schemas.openid.net/event/backchannel-logout"

// Logout issues a back-channel logout token (OpenID Connect Back-Channel Logout
// 1.0, SEC-35) for the session sid of sub, for the client cl, with the jti given.
// It has typ logout+jwt, is signed RS256 with the realm's active RSA key whatever
// tokens.algorithm is, expires two minutes after the time of the call, and has no
// nonce.
func (i *Issuer) Logout(r *config.Realm, cl *config.Client, sub UserID, sid SessionID, jti string) (string, error) {
	id, err := clientID(r, cl)
	if err != nil {
		return "", err
	}
	now := i.clock.Now()
	m := map[string]any{
		"iss": r.Issuer(), "aud": string(id), "iat": now, "exp": now.Add(2 * time.Minute), "jti": jti,
		"sub": string(sub), "sid": string(sid),
		"events": map[string]any{backchannelEvent: map[string]any{}},
	}
	return i.sign(r, "RS256", "logout+jwt", m)
}

// RefreshJWT issues a JWT refresh token (typ refresh+jwt) whose audience is
// the realm's issuer, so that no API accepts it as an access token.
func (i *Issuer) RefreshJWT(r *config.Realm, cl *config.Client, s Subject, ss Session, exp time.Time, jti string) (string, error) {
	id, err := clientID(r, cl)
	if err != nil {
		return "", err
	}
	m := map[string]any{
		"iss": r.Issuer(), "aud": r.Issuer(), "sub": string(s.ID), "azp": string(id),
		"exp": exp, "iat": i.clock.Now(), "jti": jti, "sid": string(ss.ID), "typ": "Refresh",
	}
	addNonce(m, ss)
	return i.sign(r, r.Tokens.Algorithm, "refresh+jwt", m)
}

func addNonce(m map[string]any, ss Session) {
	if ss.Nonce != "" {
		m["nonce"] = ss.Nonce
	}
}

// clientID finds the id of cl in r; a client does not know its own id.
func clientID(r *config.Realm, cl *config.Client) (config.ClientID, error) {
	if r == nil || cl == nil {
		return "", errors.New("token: a realm and a client are required")
	}
	for id, c := range r.Clients {
		if c == cl {
			return id, nil
		}
	}
	return "", fmt.Errorf("token: client is not in realm %s", r.Name)
}

// ProfileClaims returns the claims chosen by user_data.claims for a stored
// profile and the client that called, for /userinfo; the user id is not in it.
func ProfileClaims(r *config.Realm, cl *config.Client, s Subject) map[string]any {
	m := map[string]any{}
	userClaims(m, r.UserData.Claims, cl, s)
	return m
}

// userClaims adds the user claims named in names; a claim with no value is
// left out. preferred_username is the email when stored, else the user id.
func userClaims(m map[string]any, names []string, cl *config.Client, s Subject) {
	for _, name := range names {
		switch name {
		case "name":
			if s.Name != "" {
				m["name"] = s.Name
			}
		case "email":
			if s.Email != "" {
				m["email"] = s.Email
			}
		case "email_verified":
			if s.Email != "" {
				m["email_verified"] = s.EmailVerified
			}
		case "preferred_username":
			if s.Email != "" {
				m["preferred_username"] = s.Email
			} else {
				m["preferred_username"] = string(s.ID)
			}
		case "allowed-origins":
			if cl != nil && len(cl.WebOrigins) > 0 {
				m["allowed-origins"] = slices.Clone(cl.WebOrigins)
			}
		}
	}
}

// activeKey returns the realm's active key of an algorithm: RS256 needs an
// RSA key, ES256 an EC key.
func (i *Issuer) activeKey(r *config.Realm, alg string) (string, crypto.Signer, error) {
	for _, k := range r.Keys {
		if k.State != "active" {
			continue
		}
		signer := i.secrets.Signing(k.Kid)
		switch signer.(type) {
		case *rsa.PrivateKey:
			if alg == "RS256" {
				return k.Kid, signer, nil
			}
		case *ecdsa.PrivateKey:
			if alg == "ES256" {
				return k.Kid, signer, nil
			}
		}
	}
	return "", nil, fmt.Errorf("token: realm %s has no active %s key", r.Name, alg)
}

// sign encodes the claims with EncodeClaims and signs those exact bytes, so
// the escaping of the payload survives.
func (i *Issuer) sign(r *config.Realm, alg, typ string, claims map[string]any) (string, error) {
	kid, key, err := i.activeKey(r, alg)
	if err != nil {
		return "", err
	}
	payload, err := encodeJSON(claims)
	if err != nil {
		return "", err
	}
	h := jws.NewHeaders()
	for name, v := range map[string]any{jws.TypeKey: typ, jws.KeyIDKey: kid} {
		if err := setHeader(h, name, v); err != nil {
			return "", fmt.Errorf("token: set header %s: %w", name, err)
		}
	}
	a, _ := jwa.LookupSignatureAlgorithm(alg)
	out, err := signJWS(payload, jws.WithKey(a, key, jws.WithProtectedHeaders(h)))
	if err != nil {
		return "", fmt.Errorf("token: sign: %w", err)
	}
	return string(out), nil
}

var (
	_ slog.LogValuer = Subject{}
	_ slog.LogValuer = Session{}
)

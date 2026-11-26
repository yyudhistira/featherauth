package oidc

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/secure"
	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/token"
)

// accessVerifier is what bearer authentication needs of the token verifier.
type accessVerifier interface {
	Access(r *config.Realm, raw string) (token.AccessClaims, error)
}

var _ accessVerifier = (*token.Verifier)(nil)

// BearerAuth authenticates the bearer endpoints (/userinfo, DELETE /account,
// bearer POST /logout, /sessions). A request uses the scheme Bearer for an
// unbound token, or the scheme DPoP with a proof for a bound one (FR-44).
type BearerAuth struct {
	verifier accessVerifier
	store    store.Store
	clock    clock.Clock
}

// NewBearerAuth returns the authenticator of the bearer endpoints. c gives the
// time of the proof checks.
func NewBearerAuth(v *token.Verifier, s store.Store, c clock.Clock) *BearerAuth {
	return &BearerAuth{verifier: v, store: s, clock: c}
}

// schemeBearer and schemeDPoP are the authentication schemes of a bearer request.
const (
	schemeBearer = "Bearer"
	schemeDPoP   = "DPoP"
)

func invalidToken() *Error {
	return &Error{Code: "invalid_token", Description: "the access token is missing, invalid or expired", Status: http.StatusUnauthorized}
}

// challenged answers e with the challenge of scheme: DPoP for a DPoP request,
// Bearer otherwise.
func challenged(scheme string, e *Error) *Error {
	if scheme == schemeDPoP {
		e.Scheme = schemeDPoP
	}
	return e
}

// Bearer authenticates a bearer request to endpoint ep: its token and proof
// (Claims), then its user (User), then the proof's jti is remembered (Remember).
// A failure of any step is the error of that step: invalid_token or
// invalid_dpop_proof with status 401, which the handler answers with
// WriteBearerError. A store failure gives temporarily_unavailable (503) or
// server_error (500), never invalid_token.
func (b *BearerAuth) Bearer(r *http.Request, realm *config.Realm, ep config.Endpoint) (token.AccessClaims, *store.User, *Error) {
	claims, proof, berr := b.Claims(r, realm, ep)
	if berr != nil {
		return token.AccessClaims{}, nil, berr
	}
	u, berr := b.User(r, realm, claims)
	if berr != nil {
		e := withScheme(r, *berr)
		return token.AccessClaims{}, nil, &e
	}
	if berr := b.Remember(r.Context(), proof); berr != nil {
		return token.AccessClaims{}, nil, berr
	}
	return claims, u, nil
}

// Claims reads the Authorization header of r and verifies the access token (typ
// at+jwt, issued by realm, not expired), without looking the user up. A missing
// or malformed header and an invalid token give invalid_token with status 401.
//
// The scheme Bearer takes an unbound token; a bound one is refused as invalid_token
// with the DPoP challenge. The scheme DPoP takes a bound token with a proof
// (its jti in the header, its ath the token, its htu the endpoint ep of realm)
// whose key is the token's cnf.jkt; a missing proof or a bad one is
// invalid_dpop_proof, a proof of another key is invalid_token, and an unbound
// token is invalid_token. The proof is returned for Remember; it is nil for a
// Bearer request.
func (b *BearerAuth) Claims(r *http.Request, realm *config.Realm, ep config.Endpoint) (token.AccessClaims, *token.DPoPProof, *Error) {
	scheme, raw, ok := bearerCredentials(r)
	if !ok {
		return token.AccessClaims{}, nil, invalidToken()
	}
	claims, err := b.verifier.Access(realm, raw)
	if err != nil {
		return token.AccessClaims{}, nil, challenged(scheme, invalidToken())
	}
	bound := claims.Jkt != ""
	if scheme == schemeBearer {
		if bound {
			return token.AccessClaims{}, nil, challenged(schemeDPoP, invalidToken())
		}
		return claims, nil, nil
	}
	if !bound {
		return token.AccessClaims{}, nil, challenged(schemeDPoP, invalidToken())
	}
	// A missing DPoP header is a proof that fails (VerifyDPoP wants exactly one).
	p, err := token.VerifyDPoP(r.Header.Values("DPoP"), r.Method, realm.EndpointURL(ep, ""), raw, b.clock.Now())
	if errors.Is(err, token.ErrDPoPProof) {
		return token.AccessClaims{}, nil, challenged(schemeDPoP, dpopProofError())
	}
	if err != nil {
		// A malformed endpoint URL is a configuration error, not a proof's fault.
		return token.AccessClaims{}, nil, storeError(err)
	}
	if !secure.Equal(p.Thumbprint, claims.Jkt) {
		return token.AccessClaims{}, nil, challenged(schemeDPoP, invalidToken())
	}
	return claims, &p, nil
}

// withScheme gives e the DPoP challenge when r is a DPoP request, so that an
// answer after the request's authentication names the scheme it was made with.
func withScheme(r *http.Request, e Error) Error {
	if scheme, _, ok := bearerCredentials(r); ok && scheme == schemeDPoP {
		e.Scheme = schemeDPoP
	}
	return e
}

// dpopProofError is the answer to a DPoP request whose proof fails (FR-44).
func dpopProofError() *Error {
	return &Error{Code: token.CodeInvalidDPoPProof, Description: "the DPoP proof is not valid", Status: http.StatusUnauthorized, Scheme: schemeDPoP}
}

// Remember records the jti of a proof whose request has passed: a repeat is
// invalid_dpop_proof, and a Bearer request (no proof) remembers nothing.
func (b *BearerAuth) Remember(ctx context.Context, p *token.DPoPProof) *Error {
	if p == nil {
		return nil
	}
	var first bool
	err := b.store.Write(ctx, func(tx store.Tx) (err error) {
		first, err = tx.DPoPProofs().Use(ctx, p.Hash, b.clock.Now().Add(token.DPoPProofRetention))
		return err
	})
	if err != nil {
		return storeError(err)
	}
	if !first {
		return &Error{Code: token.CodeInvalidDPoPProof, Description: "the DPoP proof was used before", Status: http.StatusUnauthorized, Scheme: schemeDPoP}
	}
	return nil
}

// User looks up the user of verified claims. A user that is missing or
// disabled gives invalid_token with status 401; a store failure gives
// temporarily_unavailable (503) or server_error (500).
func (b *BearerAuth) User(r *http.Request, realm *config.Realm, claims token.AccessClaims) (*store.User, *Error) {
	var u store.User
	err := b.store.Read(r.Context(), func(tx store.Tx) error {
		rid, err := tx.Realms().Find(r.Context(), realm.Name)
		if err != nil {
			return err
		}
		u, err = tx.Users().Get(r.Context(), rid, store.UserID(claims.Sub))
		return err
	})
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil, invalidToken()
	case err != nil:
		return nil, storeError(err)
	}
	if !u.DisabledAt.IsZero() {
		return nil, invalidToken()
	}
	return &u, nil
}

// storeError maps a store failure of a bearer endpoint: temporarily_unavailable
// (503) when the store is unavailable, server_error (500) otherwise.
func storeError(err error) *Error {
	if errors.Is(err, store.ErrUnavailable) {
		return &Error{Code: "temporarily_unavailable", Description: "the service is temporarily unavailable", Status: http.StatusServiceUnavailable}
	}
	return &Error{Code: "server_error", Description: "the request could not be completed", Status: http.StatusInternalServerError}
}

// writeBearerFailure answers an error of BearerAuth on a bearer endpoint: a
// store failure (503 or 500) as a JSON error, logged as what; anything else
// with the WWW-Authenticate header.
func writeBearerFailure(w http.ResponseWriter, r *http.Request, log *slog.Logger, berr *Error, what string) {
	switch berr.Status {
	case http.StatusServiceUnavailable:
		log.WarnContext(r.Context(), what+": the store is unavailable")
		WriteJSONError(w, *berr)
	case http.StatusInternalServerError:
		log.ErrorContext(r.Context(), what+" failed")
		WriteJSONError(w, *berr)
	default:
		WriteBearerError(w, *berr, nil)
	}
}

// bearerCredentials returns the scheme (Bearer or DPoP, case-insensitive, RFC
// 7235) and the token of the single Authorization header of r.
func bearerCredentials(r *http.Request) (scheme, tok string, ok bool) {
	h := r.Header.Values("Authorization")
	if len(h) != 1 {
		return "", "", false
	}
	name, tok, found := strings.Cut(h[0], " ")
	if !found || tok == "" || strings.ContainsAny(tok, " \t") {
		return "", "", false
	}
	switch {
	case strings.EqualFold(name, schemeBearer):
		return schemeBearer, tok, true
	case strings.EqualFold(name, schemeDPoP):
		return schemeDPoP, tok, true
	}
	return "", "", false
}

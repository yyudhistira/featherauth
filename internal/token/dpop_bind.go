package token

import (
	"context"
	"errors"
	"time"

	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/secure"
	"github.com/yyudhistira/featherauth/internal/store"
)

// CodeInvalidDPoPProof is the OAuth error of a DPoP proof of a token request
// that fails a rule of SEC-36, or whose jti was used before (FR-44).
const CodeInvalidDPoPProof = "invalid_dpop_proof"

// DPoPRequest is the DPoP header of a token request with what its proof is
// checked against: the request method and the token endpoint's full URL.
// Header holds the values of the DPoP header; none means no proof was sent.
type DPoPRequest struct {
	Header []string
	Method string
	URL    string
}

// binding is the binding a grant answers with. access is the key the answer's
// access token is bound to (cnf.jkt, token_type DPoP); empty means a Bearer
// answer. refresh is the key the session's refresh tokens are bound to; empty
// means they are not bound.
type binding struct {
	access, refresh string
}

// bindNew decides the binding of a code grant for a client, with its proof. It
// runs in the grant's write transaction: a refusal makes the caller roll the
// transaction back, so a refused code is not used up. A proof that passes
// remembers its jti in the same transaction.
func bindNew(ctx context.Context, tx store.Tx, cl *config.Client, req DPoPRequest, now time.Time) (binding, error) {
	if cl.DPoP == config.DPoPOff {
		return binding{}, nil
	}
	if len(req.Header) == 0 {
		if cl.DPoP == config.DPoPRequired {
			return binding{}, grantErr(CodeInvalidRequest, "a DPoP proof is required")
		}
		return binding{}, nil
	}
	p, err := verifyProof(req, now)
	if err != nil {
		return binding{}, err
	}
	if err := remember(ctx, tx, p, now); err != nil {
		return binding{}, err
	}
	if cl.Type == config.Public {
		// A public client's session is bound: its refresh tokens and the
		// access token carry the key.
		return binding{access: p.Thumbprint, refresh: p.Thumbprint}, nil
	}
	// A confidential client's refresh token is never bound (RFC 9449 section 5);
	// its access token carries the key of this request's proof.
	return binding{access: p.Thumbprint}, nil
}

// bindRefresh decides the binding of a refresh of the valid token rt for a
// client, with its proof. The checks are in the order of the design: a bound
// token needs a proof (invalid_request without one), a proof must verify
// (invalid_dpop_proof), its key must be the token's (invalid_grant), and only
// then its jti is remembered in the write transaction.
func bindRefresh(ctx context.Context, tx store.Tx, cl *config.Client, rt store.RefreshToken, req DPoPRequest, now time.Time) (binding, error) {
	bound := rt.DPoPJKT != ""
	if !bound && cl.DPoP == config.DPoPOff {
		return binding{}, nil
	}
	if len(req.Header) == 0 {
		if bound {
			return binding{}, grantErr(CodeInvalidRequest, "a DPoP proof is required: the token is bound to a key")
		}
		if cl.DPoP == config.DPoPRequired {
			return binding{}, grantErr(CodeInvalidRequest, "a DPoP proof is required")
		}
		return binding{}, nil
	}
	p, err := verifyProof(req, now)
	if err != nil {
		return binding{}, err
	}
	if bound && !secure.Equal(p.Thumbprint, rt.DPoPJKT) {
		return binding{}, grantErr(CodeInvalidGrant, "the DPoP key is not the one the token is bound to")
	}
	if err := remember(ctx, tx, p, now); err != nil {
		return binding{}, err
	}
	switch {
	case bound:
		// The session stays bound to its key, and so does the access token.
		return binding{access: p.Thumbprint, refresh: rt.DPoPJKT}, nil
	case cl.Type == config.Confidential:
		return binding{access: p.Thumbprint}, nil
	default:
		// An unbound public session answers with Bearer tokens.
		return binding{}, nil
	}
}

// verifyProof checks the proof of a request. A proof that fails a rule is a
// grant refusal; a malformed endpoint URL is a configuration error and is
// returned as it is, so that it is not taken for a fault of the proof.
func verifyProof(req DPoPRequest, now time.Time) (DPoPProof, error) {
	p, err := VerifyDPoP(req.Header, req.Method, req.URL, "", now)
	if errors.Is(err, ErrDPoPProof) {
		return DPoPProof{}, grantErr(CodeInvalidDPoPProof, "the DPoP proof is not valid")
	}
	return p, err
}

// remember records the jti of a proof that passed. A jti that was used before
// is a refusal, not an error.
func remember(ctx context.Context, tx store.Tx, p DPoPProof, now time.Time) error {
	first, err := tx.DPoPProofs().Use(ctx, p.Hash, now.Add(DPoPProofRetention))
	if err != nil {
		return err
	}
	if !first {
		return grantErr(CodeInvalidDPoPProof, "the DPoP proof was used before")
	}
	return nil
}

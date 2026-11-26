package token_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/secure"
	"github.com/yyudhistira/featherauth/internal/testutil"
	"github.com/yyudhistira/featherauth/internal/token"
)

// dpopGrantEnv is a code and refresh environment whose client web has dpop
// allowed, with its proofs for the realm's token endpoint.
func dpopGrantEnv(t *testing.T) *codesEnv {
	t.Helper()
	e := newCodesEnv(t)
	e.client("web").DPoP = config.DPoPAllowed
	return e
}

// proofOf returns a proof of key for the token endpoint of e, with jti.
func (e *codesEnv) proofOf(t *testing.T, key any, jti string) []string {
	t.Helper()
	return []string{testutil.DPoPProof(t, key, nil, map[string]any{
		"htm": "POST", "htu": e.realm.EndpointURL(config.EndpointToken, ""),
		"iat": e.clock.Now().Unix(), "jti": jti,
	})}
}

// dpopReq is the DPoP request of a token request of e with header h.
func (e *codesEnv) dpopReq(h []string) token.DPoPRequest {
	return token.DPoPRequest{Header: h, Method: "POST", URL: e.realm.EndpointURL(config.EndpointToken, "")}
}

// accessJKT returns the cnf.jkt of an access token, or "".
func accessJKT(t *testing.T, access string) string {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(strings.Split(access, ".")[1])
	if err != nil {
		t.Fatal(err)
	}
	var c struct {
		Cnf *struct {
			JKT string `json:"jkt"`
		} `json:"cnf"`
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	if c.Cnf == nil {
		return ""
	}
	return c.Cnf.JKT
}

// refresher returns the refresh service on the environment's store.
func (e *codesEnv) refresher() *token.Refresher {
	return token.NewRefresher(e.st, e.issuer, e.clock, secure.Default)
}

// Covers: FR-44 (part), SEC-36 (part)
// Acceptance: DPoP binding (part)
// The code grant binds the session with a proof, and a refused proof leaves the
// code usable; the refresh grant needs the key of a bound token.
func TestDPoPGrantsBindAndRefuse(t *testing.T) {
	ctx := context.Background()
	k, _ := testutil.ECKey(t)
	e := dpopGrantEnv(t)
	code := e.issue(t, "web", s256(verifier))

	in := e.in("web", code, cb, verifier)
	in.DPoP = e.dpopReq([]string{"not-a-proof"})
	_, err := e.codes.Exchange(ctx, in)
	wantGrantErr(t, err, token.CodeInvalidDPoPProof)

	in.DPoP = e.dpopReq(e.proofOf(t, k, "code-1"))
	grant, err := e.codes.Exchange(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if grant.TokenType != "DPoP" || accessJKT(t, grant.AccessToken) == "" {
		t.Fatalf("grant %+v is not bound", grant)
	}
	rt := e.refreshRow(t, grant.RefreshToken)
	if rt.DPoPJKT != accessJKT(t, grant.AccessToken) {
		t.Fatalf("refresh row key %q, access key %q", rt.DPoPJKT, accessJKT(t, grant.AccessToken))
	}

	ref := token.RefreshInput{Realm: e.realm, Client: e.client("web"), Token: grant.RefreshToken}
	ref.DPoP = e.dpopReq(nil)
	_, err = e.refresher().Refresh(ctx, ref)
	wantGrantErr(t, err, token.CodeInvalidRequest)
	ref.DPoP = e.dpopReq(e.proofOf(t, k, "refresh-1"))
	next, err := e.refresher().Refresh(ctx, ref)
	if err != nil {
		t.Fatal(err)
	}
	if next.TokenType != "DPoP" || accessJKT(t, next.AccessToken) != rt.DPoPJKT {
		t.Fatalf("refresh %+v does not keep the binding", next)
	}
}

// Covers: FR-44 (part)
// Acceptance: DPoP binding (part)
// The access token of a Bearer answer carries no cnf claim, and one bound to a
// key carries it.
func TestIssuerCarriesTheKeyOnlyWhenBound(t *testing.T) {
	e := newEnv(t, "RS256", "")
	access, _, err := e.issuer.Access(e.realm, e.client("web"), testSubject(), token.Session{ID: "s-1", StartedAt: e.clock.Now(), Jkt: "thumb-1"})
	if err != nil {
		t.Fatal(err)
	}
	if got := accessJKT(t, access); got != "thumb-1" {
		t.Fatalf("cnf.jkt = %q", got)
	}
	plain, _, err := e.issuer.Access(e.realm, e.client("web"), testSubject(), testSession())
	if err != nil {
		t.Fatal(err)
	}
	if got := accessJKT(t, plain); got != "" {
		t.Fatalf("an unbound access token has cnf.jkt %q", got)
	}
}

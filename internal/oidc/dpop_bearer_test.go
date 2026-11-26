package oidc_test

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
	"strconv"
	"testing"

	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/testutil"
	"github.com/yyudhistira/featherauth/internal/testutil/server"
)

// challengeInvalidToken is the WWW-Authenticate of a DPoP answer for an access
// token that is not usable with the scheme DPoP (FR-44).
const challengeInvalidToken = `DPoP error="invalid_token", algs="ES256 RS256"`

// challengeInvalidProof is the WWW-Authenticate of a DPoP answer for a proof that
// fails (FR-44).
const challengeInvalidProof = `DPoP error="invalid_dpop_proof", algs="ES256 RS256"`

// athOf is the ath claim of an access token: its base64url SHA-256.
func athOf(access string) string {
	sum := sha256.Sum256([]byte(access))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// resourceProof returns a proof of key for a request with method to the endpoint
// ep of e, bound to access by ath; mut changes its claims.
func resourceProof(t *testing.T, e *server.Env, key *ecdsa.PrivateKey, method string, ep config.Endpoint, access string, mut func(c map[string]any)) string {
	t.Helper()
	c := map[string]any{
		"htm": method, "htu": e.Realm.EndpointURL(ep, ""), "iat": e.Clock.Now().Unix(),
		"jti": "jti-" + strconv.FormatInt(dpopJTI.Add(1), 10), "ath": athOf(access),
	}
	if mut != nil {
		mut(c)
	}
	return testutil.DPoPProof(t, key, nil, c)
}

// bearerCall sends a request to path with the Authorization header of scheme and
// access, and the DPoP header of proof when it is not empty.
func bearerCall(t *testing.T, e *server.Env, method, path, scheme, access, proof string, form url.Values) server.Response {
	t.Helper()
	h := http.Header{"Authorization": {scheme + " " + access}}
	if proof != "" {
		h[http.CanonicalHeaderKey("DPoP")] = []string{proof}
	}
	body := ""
	if form != nil {
		body = form.Encode()
		h.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	return e.NewClient().Request(t, method, server.Issuer+path, body, h)
}

// wantBearerChallenge checks a 401 with the WWW-Authenticate header and that it
// is not cached.
func wantBearerChallenge(t *testing.T, r server.Response, challenge string) {
	t.Helper()
	if r.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401 (%s)", r.Code, r.Body)
	}
	if got := r.Header.Get("WWW-Authenticate"); got != challenge {
		t.Fatalf("WWW-Authenticate %q, want %q", got, challenge)
	}
	wantNoStoreHeaders(t, r)
}

// boundToken logs in as the public client web with dpop allowed and a proof of
// key, and returns its tokens, bound to that key.
func boundToken(t *testing.T, e *server.Env, key *ecdsa.PrivateKey) server.Tokens {
	t.Helper()
	setDPoP(t, e, server.ClientQuery.ID, "allowed")
	p := dpopProof(t, e, key, nil)
	return wantDPoPTokens(t, codeExchange(t, e, server.ClientQuery, dpopHeader(p)), dpopThumb(t, e, p))
}

// Covers: FR-44, SEC-36
// Acceptance: DPoP proof
// Acceptance: DPoP binding
// /userinfo with a bound access token: the scheme DPoP with a valid proof is
// answered; the scheme Bearer, an unbound token as DPoP, a missing proof, a
// proof without ath or with the ath of another token, a proof of another key and
// a proof with an invalid token are refused with the challenge of the design, and
// nothing is remembered.
func TestDPoPUserinfoAndTheChallenges(t *testing.T) {
	key, _ := testutil.ECKey(t)
	other, _ := testutil.ECKey(t)
	e := server.New(t)
	bound := boundToken(t, e, key)
	setDPoP(t, e, server.ClientQuery.ID, "off")
	unbound := wantBearerTokens(t, codeExchange(t, e, server.ClientQuery, nil))
	setDPoP(t, e, server.ClientQuery.ID, "allowed")
	ok := func(access, p string) server.Response {
		return bearerCall(t, e, http.MethodGet, "/userinfo", "DPoP", access, p, nil)
	}

	t.Run("a valid proof answers 200", func(t *testing.T) {
		p := resourceProof(t, e, key, http.MethodGet, config.EndpointUserinfo, bound.AccessToken, nil)
		r := ok(bound.AccessToken, p)
		if r.Code != http.StatusOK {
			t.Fatalf("status %d (%s)", r.Code, r.Body)
		}
	})
	t.Run("the scheme Bearer is refused for a bound token", func(t *testing.T) {
		r := bearerCall(t, e, http.MethodGet, "/userinfo", "Bearer", bound.AccessToken, "", nil)
		wantBearerChallenge(t, r, challengeInvalidToken)
	})
	t.Run("an unbound token as DPoP is refused", func(t *testing.T) {
		p := resourceProof(t, e, key, http.MethodGet, config.EndpointUserinfo, unbound.AccessToken, nil)
		r := bearerCall(t, e, http.MethodGet, "/userinfo", "DPoP", unbound.AccessToken, p, nil)
		wantBearerChallenge(t, r, challengeInvalidToken)
	})
	t.Run("an unbound token as DPoP is refused with no proof either", func(t *testing.T) {
		wantBearerChallenge(t, bearerCall(t, e, http.MethodGet, "/userinfo", "DPoP", unbound.AccessToken, "", nil), challengeInvalidToken)
	})
	refusals := []struct {
		name      string
		access    string
		proof     func() string
		challenge string
	}{
		{"no proof", bound.AccessToken, func() string { return "" }, challengeInvalidProof},
		{"a proof without ath", bound.AccessToken, func() string {
			return resourceProof(t, e, key, http.MethodGet, config.EndpointUserinfo, bound.AccessToken, func(c map[string]any) { delete(c, "ath") })
		}, challengeInvalidProof},
		{"a proof with the ath of another token", bound.AccessToken, func() string {
			return resourceProof(t, e, key, http.MethodGet, config.EndpointUserinfo, unbound.AccessToken, nil)
		}, challengeInvalidProof},
		{"a proof with a wrong htm", bound.AccessToken, func() string {
			return resourceProof(t, e, key, http.MethodPost, config.EndpointUserinfo, bound.AccessToken, nil)
		}, challengeInvalidProof},
		{"a proof of another key", bound.AccessToken, func() string {
			return resourceProof(t, e, other, http.MethodGet, config.EndpointUserinfo, bound.AccessToken, nil)
		}, challengeInvalidToken},
		{"a valid proof with an invalid token", "not-a-token", func() string {
			return resourceProof(t, e, key, http.MethodGet, config.EndpointUserinfo, "not-a-token", nil)
		}, challengeInvalidToken},
	}
	for _, c := range refusals {
		t.Run(c.name+" is refused and remembers nothing", func(t *testing.T) {
			before := rowCounts(t, e)
			wantBearerChallenge(t, ok(c.access, c.proof()), c.challenge)
			if got := rowCounts(t, e)["dpop_proofs"]; got != before["dpop_proofs"] {
				t.Fatalf("a refused request remembered a jti: %d rows, want %d", got, before["dpop_proofs"])
			}
		})
	}
	t.Run("a proof is remembered once: its repeat is refused", func(t *testing.T) {
		p := resourceProof(t, e, key, http.MethodGet, config.EndpointUserinfo, bound.AccessToken, nil)
		before := rowCounts(t, e)["dpop_proofs"]
		if r := ok(bound.AccessToken, p); r.Code != http.StatusOK {
			t.Fatalf("first use: %d (%s)", r.Code, r.Body)
		}
		if got := rowCounts(t, e)["dpop_proofs"]; got != before+1 {
			t.Fatalf("first use remembered %d rows, want one more than %d", got, before)
		}
		wantBearerChallenge(t, ok(bound.AccessToken, p), challengeInvalidProof)
	})
}

// Covers: FR-44, SEC-36
// Acceptance: DPoP proof
// A valid proof of a token whose user is disabled is refused as invalid_token,
// and its jti is not remembered: the user check comes before the remembering.
func TestDPoPDisabledUserRemembersNothing(t *testing.T) {
	key, _ := testutil.ECKey(t)
	e := server.New(t)
	tk := boundToken(t, e, key)
	e.DisableUser(t, store.UserID(accessPayload(t, tk.AccessToken)["sub"].(string)), true)
	p := resourceProof(t, e, key, http.MethodGet, config.EndpointUserinfo, tk.AccessToken, nil)
	before := rowCounts(t, e)["dpop_proofs"]
	wantBearerChallenge(t, bearerCall(t, e, http.MethodGet, "/userinfo", "DPoP", tk.AccessToken, p, nil), challengeInvalidToken)
	if got := rowCounts(t, e)["dpop_proofs"]; got != before {
		t.Fatalf("a disabled user's proof remembered a jti: %d rows, want %d", got, before)
	}
	// The same at DELETE /account, where the client here may not delete accounts:
	// the user check comes first for a DPoP request, so the answer is invalid_token.
	pd := resourceProof(t, e, key, http.MethodDelete, config.EndpointAccountDelete, tk.AccessToken, nil)
	before = rowCounts(t, e)["dpop_proofs"]
	wantBearerChallenge(t, bearerCall(t, e, http.MethodDelete, "/account", "DPoP", tk.AccessToken, pd, nil), challengeInvalidToken)
	if got := rowCounts(t, e)["dpop_proofs"]; got != before {
		t.Fatalf("a disabled user's deletion remembered a jti: %d rows, want %d", got, before)
	}
}

// Covers: FR-44, SEC-36
// Acceptance: DPoP proof
// Acceptance: DPoP binding
// The bearer logout and the sessions path take the scheme DPoP as they take
// Bearer, and refuse a bound token presented as Bearer.
func TestDPoPLogoutAndSessionsUseTheSameChecks(t *testing.T) {
	key, _ := testutil.ECKey(t)
	e := signOutEnv(t)
	bound := boundToken(t, e, key)
	p := resourceProof(t, e, key, http.MethodPost, config.EndpointLogout, bound.AccessToken, nil)

	t.Run("a bearer logout with a valid proof signs the user out", func(t *testing.T) {
		r := bearerCall(t, e, http.MethodPost, "/logout", "DPoP", bound.AccessToken, p, url.Values{"all_sessions": {"true"}})
		if r.Code != http.StatusNoContent {
			t.Fatalf("status %d (%s)", r.Code, r.Body)
		}
	})
	t.Run("the bearer logout revokes the session", func(t *testing.T) {
		wantDPoPRefusal(t, refreshWith(t, e, server.ClientQuery, bound.RefreshToken, dpopHeader(dpopProof(t, e, key, nil))), "invalid_grant")
	})
	t.Run("a logout by the bound refresh token needs no proof", func(t *testing.T) {
		e2 := server.New(t)
		tk := boundToken(t, e2, key)
		r := logout(t, e2, http.MethodPost, url.Values{"refresh_token": {tk.RefreshToken}, "client_id": {server.ClientQuery.ID}}, nil)
		if r.Code != http.StatusNoContent {
			t.Fatalf("status %d (%s)", r.Code, r.Body)
		}
	})
	t.Run("a bound token as Bearer on logout is refused", func(t *testing.T) {
		r := bearerCall(t, e, http.MethodPost, "/logout", "Bearer", bound.AccessToken, "", url.Values{"all_sessions": {"true"}})
		wantBearerChallenge(t, r, challengeInvalidToken)
	})
	t.Run("a logout without a proof is refused", func(t *testing.T) {
		r := bearerCall(t, e, http.MethodPost, "/logout", "DPoP", bound.AccessToken, "", url.Values{"all_sessions": {"true"}})
		wantBearerChallenge(t, r, challengeInvalidProof)
	})
	t.Run("sessions with a valid proof answers 200, and as Bearer 401", func(t *testing.T) {
		e2 := signOutEnv(t)
		tk := boundToken(t, e2, key)
		ps := resourceProof(t, e2, key, http.MethodGet, config.EndpointSessions, tk.AccessToken, nil)
		if r := bearerCall(t, e2, http.MethodGet, "/sessions", "DPoP", tk.AccessToken, ps, nil); r.Code != http.StatusOK {
			t.Fatalf("sessions: %d (%s)", r.Code, r.Body)
		}
		wantBearerChallenge(t, bearerCall(t, e2, http.MethodGet, "/sessions", "Bearer", tk.AccessToken, "", nil), challengeInvalidToken)
	})
}

// Covers: FR-44, SEC-36
// Acceptance: DPoP binding
// DELETE /account takes the scheme DPoP: a bound token with a valid proof of its
// key is accepted for the account of a client that may delete accounts, and the
// same token as Bearer is refused.
func TestDPoPAccountDeletionTakesTheScheme(t *testing.T) {
	key, _ := testutil.ECKey(t)
	e := server.New(t)
	setDPoP(t, e, server.ClientDelete.ID, "allowed")
	p := dpopProof(t, e, key, nil)
	tk := wantDPoPTokens(t, codeExchangeSecret(t, e, server.ClientDelete, dpopHeader(p)), dpopThumb(t, e, p))
	wantBearerChallenge(t, bearerCall(t, e, http.MethodDelete, "/account", "Bearer", tk.AccessToken, "", nil), challengeInvalidToken)
	wantBearerChallenge(t, bearerCall(t, e, http.MethodDelete, "/account", "DPoP", tk.AccessToken, "", nil), challengeInvalidProof)
	ok := resourceProof(t, e, key, http.MethodDelete, config.EndpointAccountDelete, tk.AccessToken, nil)
	before := rowCounts(t, e)["dpop_proofs"]
	if r := bearerCall(t, e, http.MethodDelete, "/account", "DPoP", tk.AccessToken, ok, nil); r.Code != http.StatusNoContent {
		t.Fatalf("deletion with a valid proof: %d (%s)", r.Code, r.Body)
	}
	if got := rowCounts(t, e)["dpop_proofs"]; got != before+1 {
		t.Fatalf("the deletion remembered %d jtis, want one more than %d", got, before)
	}
}

// Covers: FR-44
// Acceptance: DPoP binding
// A DPoP request refused after its authentication names the DPoP scheme in its
// challenge: a client without the option, on account deletion, sessions and
// the bearer logout.
func TestDPoPRefusalsAfterAuthenticationNameTheScheme(t *testing.T) {
	key, _ := testutil.ECKey(t)
	const forbidden = `DPoP error="insufficient_scope", algs="ES256 RS256"`
	// A refusal after the authentication has passed keeps the proof's jti: the
	// proof passed, so exactly one row is remembered.
	refused := func(t *testing.T, r server.Response) {
		t.Helper()
		if r.Code != http.StatusForbidden || r.Header.Get("WWW-Authenticate") != forbidden {
			t.Fatalf("status %d, WWW-Authenticate %q (%s)", r.Code, r.Header.Get("WWW-Authenticate"), r.Body)
		}
	}
	t.Run("account deletion", func(t *testing.T) {
		e := server.New(t)
		tk := boundToken(t, e, key)
		p := resourceProof(t, e, key, http.MethodDelete, config.EndpointAccountDelete, tk.AccessToken, nil)
		before := rowCounts(t, e)["dpop_proofs"]
		refused(t, bearerCall(t, e, http.MethodDelete, "/account", "DPoP", tk.AccessToken, p, nil))
		if got := rowCounts(t, e)["dpop_proofs"]; got != before+1 {
			t.Fatalf("the refused deletion remembered %d jtis, want one more than %d", got, before)
		}
	})
	t.Run("sessions", func(t *testing.T) {
		e := server.New(t)
		tk := boundToken(t, e, key)
		p := resourceProof(t, e, key, http.MethodGet, config.EndpointSessions, tk.AccessToken, nil)
		before := rowCounts(t, e)["dpop_proofs"]
		refused(t, bearerCall(t, e, http.MethodGet, "/sessions", "DPoP", tk.AccessToken, p, nil))
		if got := rowCounts(t, e)["dpop_proofs"]; got != before+1 {
			t.Fatalf("the refused sessions request remembered %d jtis, want one more than %d", got, before)
		}
	})
	t.Run("bearer logout with all sessions", func(t *testing.T) {
		e := server.New(t)
		tk := boundToken(t, e, key)
		p := resourceProof(t, e, key, http.MethodPost, config.EndpointLogout, tk.AccessToken, nil)
		before := rowCounts(t, e)["dpop_proofs"]
		refused(t, bearerCall(t, e, http.MethodPost, "/logout", "DPoP", tk.AccessToken, p, url.Values{"all_sessions": {"true"}}))
		if got := rowCounts(t, e)["dpop_proofs"]; got != before+1 {
			t.Fatalf("the refused logout remembered %d jtis, want one more than %d", got, before)
		}
	})
}

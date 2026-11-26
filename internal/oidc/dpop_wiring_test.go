package oidc_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/testutil"
	"github.com/yyudhistira/featherauth/internal/testutil/server"
)

// accessPayload returns the claims of an access token.
func accessPayload(t *testing.T, access string) map[string]any {
	t.Helper()
	return accessPayloadOf(t, access)
}

// accessPayloadOf returns the claims of a compact JWT.
func accessPayloadOf(t *testing.T, raw string) map[string]any {
	t.Helper()
	_, payload := claims(t, raw)
	return payload
}

// Covers: FR-44, SEC-36
// Acceptance: DPoP binding
// Acceptance: DPoP proof
// Wiring: a public client with dpop required and a back-channel logout
// URI logs in with a key, refreshes, lists its sessions, calls /userinfo and logs
// out; the receiver gets the logout token, the access token carries only the
// claims of access_token_claims, and no token, proof or jti reaches a log line.
func TestDPoPWiringPhase28(t *testing.T) {
	key, _ := testutil.ECKey(t)
	e := server.New(t)
	e.Reload(t, func(y string) string {
		y = strings.Replace(y, "name: main\n", "name: main\nuser_data:\n  access_token_claims: [email]\n", 1)
		return strings.Replace(y, "  web:\n    redirect_uris: [https://app.example.com/callback]\n",
			"  web:\n    dpop: required\n    backchannel_logout_uri: https://app.example.com/backchannel\n    allow_session_management: true\n    redirect_uris: [https://app.example.com/callback]\n", 1)
	})
	rig := newBackchannelRig(t, e)
	proof := func() string {
		return dpopProof(t, e, key, nil)
	}

	p := proof()
	tk := wantDPoPTokens(t, codeExchange(t, e, server.ClientQuery, dpopHeader(p)), dpopThumb(t, e, p))
	pr := proof()
	tk2 := wantDPoPTokens(t, refreshWith(t, e, server.ClientQuery, tk.RefreshToken, dpopHeader(pr)), dpopThumb(t, e, pr))

	sid, _ := accessPayload(t, tk2.AccessToken)["sid"].(string)
	ps := resourceProof(t, e, key, http.MethodGet, config.EndpointSessions, tk2.AccessToken, nil)
	if r := bearerCall(t, e, http.MethodGet, "/sessions", "DPoP", tk2.AccessToken, ps, nil); r.Code != http.StatusOK || !strings.Contains(r.Body, sid) {
		t.Fatalf("sessions: %d (%s)", r.Code, r.Body)
	}
	pu := resourceProof(t, e, key, http.MethodGet, config.EndpointUserinfo, tk2.AccessToken, nil)
	if r := bearerCall(t, e, http.MethodGet, "/userinfo", "DPoP", tk2.AccessToken, pu, nil); r.Code != http.StatusOK {
		t.Fatalf("userinfo: %d (%s)", r.Code, r.Body)
	}

	pl := resourceProof(t, e, key, http.MethodPost, config.EndpointLogout, tk2.AccessToken, nil)
	if r := bearerCall(t, e, http.MethodPost, "/logout", "DPoP", tk2.AccessToken, pl, map[string][]string{"all_sessions": {"true"}}); r.Code != http.StatusNoContent {
		t.Fatalf("logout: %d (%s)", r.Code, r.Body)
	}
	rig.deliveredSessions(t, []string{sid})

	payload := accessPayload(t, tk2.AccessToken)
	if _, ok := payload["email"]; !ok {
		t.Fatalf("the access token lacks the email claim: %v", payload)
	}
	for _, name := range []string{"name", "preferred_username", "email_verified"} {
		if _, ok := payload[name]; ok {
			t.Fatalf("the access token carries %s, which access_token_claims leaves out", name)
		}
	}
	// The secrets: the tokens, each proof, and the jti of each proof. The
	// thumbprint of a key may appear in a log line; nothing else of these may.
	secrets := []string{tk.AccessToken, tk.RefreshToken, tk2.AccessToken, tk2.RefreshToken, p, pr, ps, pu, pl}
	for _, proof := range []string{p, pr, ps, pu, pl} {
		jti, _ := accessPayloadOf(t, proof)["jti"].(string)
		secrets = append(secrets, jti)
	}
	logs := e.Logs.String()
	for _, secret := range secrets {
		if secret == "" || strings.Contains(logs, secret) {
			t.Fatalf("a log line holds a token, a proof or a jti")
		}
	}
}

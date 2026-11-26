package oidc_test

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/testutil"
	"github.com/yyudhistira/featherauth/internal/testutil/server"
	"github.com/yyudhistira/featherauth/internal/token"
)

var dpopJTI atomic.Int64

// dpopProof returns a proof for the token endpoint of e, signed with key, for a
// POST at the current fake time; mut changes its claims.
func dpopProof(t *testing.T, e *server.Env, key *ecdsa.PrivateKey, mut func(c map[string]any)) string {
	t.Helper()
	c := map[string]any{
		"htm": "POST", "htu": e.Realm.EndpointURL(config.EndpointToken, ""),
		"iat": e.Clock.Now().Unix(), "jti": "jti-" + strconv.FormatInt(dpopJTI.Add(1), 10),
	}
	if mut != nil {
		mut(c)
	}
	return testutil.DPoPProof(t, key, nil, c)
}

// dpopHeader is the DPoP header of a request carrying the proofs.
func dpopHeader(proofs ...string) http.Header {
	return http.Header{http.CanonicalHeaderKey("DPoP"): proofs}
}

// dpopThumb is the thumbprint of the key of a proof, as the token endpoint
// computes it.
func dpopThumb(t *testing.T, e *server.Env, proof string) string {
	t.Helper()
	p, err := token.VerifyDPoP([]string{proof}, "POST", e.Realm.EndpointURL(config.EndpointToken, ""), "", e.Clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	return p.Thumbprint
}

// accessCNF returns the cnf.jkt claim of an access token, or "" when it has none.
func accessCNF(t *testing.T, access string) string {
	t.Helper()
	parts := strings.Split(access, ".")
	if len(parts) != 3 {
		t.Fatalf("access token has %d parts", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims struct {
		Cnf *struct {
			JKT string `json:"jkt"`
		} `json:"cnf"`
	}
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatal(err)
	}
	if claims.Cnf == nil {
		return ""
	}
	return claims.Cnf.JKT
}

// wantDPoPTokens checks a DPoP answer bound to thumb and returns its tokens.
func wantDPoPTokens(t *testing.T, r server.Response, thumb string) server.Tokens {
	t.Helper()
	if r.Code != http.StatusOK {
		t.Fatalf("status %d, want 200 (%s)", r.Code, r.Body)
	}
	tk := r.Tokens(t)
	if tk.TokenType != "DPoP" || tk.AccessToken == "" || tk.RefreshToken == "" {
		t.Fatalf("answer %+v, want DPoP tokens", tk)
	}
	if got := accessCNF(t, tk.AccessToken); got != thumb {
		t.Fatalf("cnf.jkt = %q, want %q", got, thumb)
	}
	return tk
}

// wantBearerTokens checks a Bearer answer whose access token has no cnf.
func wantBearerTokens(t *testing.T, r server.Response) server.Tokens {
	t.Helper()
	tk := wantTokens(t, r)
	if got := accessCNF(t, tk.AccessToken); got != "" {
		t.Fatalf("a Bearer access token has cnf.jkt %q", got)
	}
	return tk
}

// wantDPoPRefusal checks an OAuth refusal with its status and that it is not cached.
func wantDPoPRefusal(t *testing.T, r server.Response, code string) {
	t.Helper()
	wantError(t, r, http.StatusBadRequest, code)
	if got := r.Header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q on the refusal", got)
	}
}

// setDPoP sets the dpop option of client id in the realm file of e: a new
// line for the client, or the value of its existing one replaced.
func setDPoP(t *testing.T, e *server.Env, id, mode string) {
	t.Helper()
	e.Reload(t, func(y string) string {
		head := "  " + id + ":\n"
		i := strings.Index(y, head)
		if i < 0 {
			t.Fatalf("client %s not in the realm file", id)
		}
		rest := y[i+len(head):]
		if strings.HasPrefix(rest, "    dpop: ") {
			end := strings.Index(rest, "\n")
			return y[:i+len(head)] + "    dpop: " + mode + rest[end:]
		}
		return y[:i+len(head)] + "    dpop: " + mode + "\n" + rest
	})
}

// confidentialApp reports whether app authenticates with a secret in the
// test realm.
func confidentialApp(app server.App) bool {
	return app.ID == server.ClientConfidential.ID || app.ID == server.ClientFixed.ID
}

// codeExchange exchanges a fresh login code of app with headers and the
// client secret of a confidential client.
func codeExchange(t *testing.T, e *server.Env, app server.App, h http.Header) server.Response {
	t.Helper()
	return codeExchangeSecret(t, e, app, h)
}

// codeExchangeSecret is codeExchange for any client; the secret is sent for a
// confidential one.
func codeExchangeSecret(t *testing.T, e *server.Env, app server.App, h http.Header) server.Response {
	t.Helper()
	f := server.CodeForm(app, e.Login(t, app))
	if confidentialApp(app) {
		f.Set("client_secret", e.Secret(app.ID))
	}
	return post(t, e, f, h)
}

// refreshWith refreshes rt for app with headers, and the client secret of a
// confidential client.
func refreshWith(t *testing.T, e *server.Env, app server.App, rt string, h http.Header) server.Response {
	t.Helper()
	f := server.RefreshForm(app, rt)
	if confidentialApp(app) {
		f.Set("client_secret", e.Secret(app.ID))
	}
	return post(t, e, f, h)
}

// rowCounts returns the rows of the tables the binding writes.
func rowCounts(t *testing.T, e *server.Env) map[string]int64 {
	t.Helper()
	return testutil.SQLiteRowCounts(t, e.DatabasePath)
}

// Covers: FR-44 (part), SEC-36 (part)
// Acceptance: DPoP binding
// The code grant answers by the client's dpop option: off ignores the header;
// allowed binds the answer when a proof is sent and gives Bearer otherwise;
// required refuses a request without a proof.
func TestDPoPCodeGrantByMode(t *testing.T) {
	key, _ := testutil.ECKey(t)
	for _, c := range []struct {
		mode  string
		proof bool
		want  string // "bearer", "dpop", or the refused error code
	}{
		{"off", false, "bearer"},
		{"off", true, "bearer"},
		{"allowed", false, "bearer"},
		{"allowed", true, "dpop"},
		{"required", false, "invalid_request"},
		{"required", true, "dpop"},
	} {
		t.Run(c.mode+" proof "+strconv.FormatBool(c.proof), func(t *testing.T) {
			e := server.New(t)
			setDPoP(t, e, server.ClientQuery.ID, c.mode)
			var h http.Header
			var thumb string
			if c.proof {
				p := dpopProof(t, e, key, nil)
				h, thumb = dpopHeader(p), dpopThumb(t, e, p)
			}
			r := codeExchange(t, e, server.ClientQuery, h)
			switch c.want {
			case "bearer":
				wantBearerTokens(t, r)
			case "dpop":
				wantDPoPTokens(t, r, thumb)
			default:
				wantDPoPRefusal(t, r, c.want)
			}
		})
	}
}

// Covers: FR-44 (part), SEC-36 (part)
// Acceptance: DPoP proof (part)
// A refused code request is not a use of the code: the same code exchanges
// once a valid proof is sent, and no proof is remembered for the refusal.
func TestDPoPInvalidProofKeepsTheCode(t *testing.T) {
	key, _ := testutil.ECKey(t)
	e := server.New(t)
	setDPoP(t, e, server.ClientQuery.ID, "allowed")
	code := e.Login(t, server.ClientQuery)
	form := server.CodeForm(server.ClientQuery, code)
	before := rowCounts(t, e)
	for _, c := range []struct {
		name string
		h    http.Header
	}{
		{"two headers", dpopHeader(dpopProof(t, e, key, nil), dpopProof(t, e, key, nil))},
		{"wrong htu", dpopHeader(dpopProof(t, e, key, func(c map[string]any) { c["htu"] = "https://auth.example.com/main/other" }))},
		{"wrong htm", dpopHeader(dpopProof(t, e, key, func(c map[string]any) { c["htm"] = "GET" }))},
		{"iat 6 minutes old", dpopHeader(dpopProof(t, e, key, func(c map[string]any) { c["iat"] = e.Clock.Now().Add(-6 * time.Minute).Unix() }))},
		{"empty jti", dpopHeader(dpopProof(t, e, key, func(c map[string]any) { c["jti"] = "" }))},
		{"not a proof", dpopHeader("not-a-proof")},
	} {
		t.Run(c.name, func(t *testing.T) {
			wantDPoPRefusal(t, post(t, e, form, c.h), "invalid_dpop_proof")
			if got := rowCounts(t, e); got["refresh_tokens"] != before["refresh_tokens"] || got["dpop_proofs"] != before["dpop_proofs"] {
				t.Fatalf("a refused proof wrote rows: before %v, after %v", before, got)
			}
		})
	}
	p := dpopProof(t, e, key, nil)
	wantDPoPTokens(t, post(t, e, form, dpopHeader(p)), dpopThumb(t, e, p))
}

// Covers: FR-44 (part), SEC-36 (part)
// Acceptance: DPoP binding
// A bound refresh token needs its key at every refresh: no proof and another
// key are refused without using the token up, and the successors stay bound.
func TestDPoPBoundRefreshNeedsItsKey(t *testing.T) {
	a, _ := testutil.ECKey(t)
	b, _ := testutil.ECKey(t)
	e := server.New(t)
	setDPoP(t, e, server.ClientQuery.ID, "allowed")
	pa := dpopProof(t, e, a, nil)
	tk := wantDPoPTokens(t, codeExchange(t, e, server.ClientQuery, dpopHeader(pa)), dpopThumb(t, e, pa))
	before := rowCounts(t, e)

	wantDPoPRefusal(t, refreshWith(t, e, server.ClientQuery, tk.RefreshToken, nil), "invalid_request")
	wantDPoPRefusal(t, refreshWith(t, e, server.ClientQuery, tk.RefreshToken, dpopHeader(dpopProof(t, e, b, nil))), "invalid_grant")
	if got := rowCounts(t, e); got["refresh_tokens"] != before["refresh_tokens"] || got["dpop_proofs"] != before["dpop_proofs"] {
		t.Fatalf("a refused refresh wrote rows: before %v, after %v", before, got)
	}

	pa2 := dpopProof(t, e, a, nil)
	tk2 := wantDPoPTokens(t, refreshWith(t, e, server.ClientQuery, tk.RefreshToken, dpopHeader(pa2)), dpopThumb(t, e, pa2))
	wantDPoPRefusal(t, refreshWith(t, e, server.ClientQuery, tk2.RefreshToken, nil), "invalid_request")
	wantDPoPTokens(t, refreshWith(t, e, server.ClientQuery, tk2.RefreshToken, dpopHeader(dpopProof(t, e, a, nil))), dpopThumb(t, e, pa2))
}

// Covers: FR-44 (part), SEC-36 (part)
// Acceptance: DPoP binding
// An unbound refresh token answers with Bearer tokens when a proof is sent with
// it; the proof is still checked and its jti remembered.
func TestDPoPUnboundRefreshWithProof(t *testing.T) {
	key, _ := testutil.ECKey(t)
	e := server.New(t)
	setDPoP(t, e, server.ClientQuery.ID, "allowed")
	tk := wantBearerTokens(t, codeExchange(t, e, server.ClientQuery, nil))
	before := rowCounts(t, e)
	wantBearerTokens(t, refreshWith(t, e, server.ClientQuery, tk.RefreshToken, dpopHeader(dpopProof(t, e, key, nil))))
	if got := rowCounts(t, e)["dpop_proofs"]; got != before["dpop_proofs"]+1 {
		t.Fatalf("dpop_proofs rows %d, want one more than %d", got, before["dpop_proofs"])
	}
}

// Covers: FR-44 (part)
// Acceptance: DPoP binding
// A required client refreshes only with a proof, bound or not.
func TestDPoPRequiredRefresh(t *testing.T) {
	key, _ := testutil.ECKey(t)
	e := server.New(t)
	setDPoP(t, e, server.ClientQuery.ID, "required")
	p := dpopProof(t, e, key, nil)
	tk := wantDPoPTokens(t, codeExchange(t, e, server.ClientQuery, dpopHeader(p)), dpopThumb(t, e, p))
	wantDPoPRefusal(t, refreshWith(t, e, server.ClientQuery, tk.RefreshToken, nil), "invalid_request")
	wantDPoPTokens(t, refreshWith(t, e, server.ClientQuery, tk.RefreshToken, dpopHeader(dpopProof(t, e, key, nil))), dpopThumb(t, e, p))
}

// Covers: FR-44 (part)
// Acceptance: DPoP binding
// A client set back to dpop off still needs the key of a bound token, and the
// answer stays bound; an unbound token ignores the header.
func TestDPoPOffClientKeepsTheBinding(t *testing.T) {
	a, _ := testutil.ECKey(t)
	b, _ := testutil.ECKey(t)
	e := server.New(t)
	setDPoP(t, e, server.ClientQuery.ID, "allowed")
	pa := dpopProof(t, e, a, nil)
	tk := wantDPoPTokens(t, codeExchange(t, e, server.ClientQuery, dpopHeader(pa)), dpopThumb(t, e, pa))
	setDPoP(t, e, server.ClientQuery.ID, "off")
	wantDPoPRefusal(t, refreshWith(t, e, server.ClientQuery, tk.RefreshToken, nil), "invalid_request")
	wantDPoPRefusal(t, refreshWith(t, e, server.ClientQuery, tk.RefreshToken, dpopHeader(dpopProof(t, e, b, nil))), "invalid_grant")
	wantDPoPTokens(t, refreshWith(t, e, server.ClientQuery, tk.RefreshToken, dpopHeader(dpopProof(t, e, a, nil))), dpopThumb(t, e, pa))

	before := rowCounts(t, e)
	wantBearerTokens(t, codeExchange(t, e, server.ClientQuery, dpopHeader(dpopProof(t, e, a, nil))))
	if got := rowCounts(t, e)["dpop_proofs"]; got != before["dpop_proofs"] {
		t.Fatalf("an off client remembered a proof: %d rows, want %d", got, before["dpop_proofs"])
	}
}

// Covers: FR-44 (part), SEC-36 (part)
// Acceptance: DPoP binding (part)
// A client with refresh_token_rotation off keeps its refresh token: the same
// token answers again, bound to the key of the proof sent with the refresh.
func TestDPoPNonRotatingRefresh(t *testing.T) {
	key, _ := testutil.ECKey(t)
	e := server.New(t)
	setDPoP(t, e, server.ClientFixed.ID, "allowed")
	p := dpopProof(t, e, key, nil)
	first := wantDPoPTokens(t, codeExchangeSecret(t, e, server.ClientFixed, dpopHeader(p)), dpopThumb(t, e, p))
	p2 := dpopProof(t, e, key, nil)
	again := wantDPoPTokens(t, refreshWith(t, e, server.ClientFixed, first.RefreshToken, dpopHeader(p2)), dpopThumb(t, e, p2))
	if again.RefreshToken != first.RefreshToken {
		t.Fatal("a non-rotating client returned another refresh token")
	}
}

// Covers: FR-44 (part)
// Acceptance: DPoP binding
// A confidential client's refresh token is never bound: each answer's access
// token carries the key of the proof sent with that request, and a refresh
// without a proof answers with Bearer tokens.
func TestDPoPConfidentialClientBindsOnlyTheAccessToken(t *testing.T) {
	a, _ := testutil.ECKey(t)
	b, _ := testutil.ECKey(t)
	e := server.New(t)
	setDPoP(t, e, server.ClientConfidential.ID, "allowed")
	pa := dpopProof(t, e, a, nil)
	tk := wantDPoPTokens(t, codeExchange(t, e, server.ClientConfidential, dpopHeader(pa)), dpopThumb(t, e, pa))
	pb := dpopProof(t, e, b, nil)
	tk2 := wantDPoPTokens(t, refreshWith(t, e, server.ClientConfidential, tk.RefreshToken, dpopHeader(pb)), dpopThumb(t, e, pb))
	wantBearerTokens(t, refreshWith(t, e, server.ClientConfidential, tk2.RefreshToken, nil))
}

// Covers: FR-44 (part), SEC-36 (part)
// Acceptance: DPoP proof
// A proof's jti is remembered once: a repeat is refused with
// invalid_dpop_proof, and the code it came with is still usable.
func TestDPoPRepeatedJTIIsRefused(t *testing.T) {
	key, _ := testutil.ECKey(t)
	e := server.New(t)
	setDPoP(t, e, server.ClientQuery.ID, "allowed")
	p := dpopProof(t, e, key, nil)
	wantDPoPTokens(t, codeExchange(t, e, server.ClientQuery, dpopHeader(p)), dpopThumb(t, e, p))
	wantDPoPRefusal(t, codeExchange(t, e, server.ClientQuery, dpopHeader(p)), "invalid_dpop_proof")
	wantDPoPTokens(t, codeExchange(t, e, server.ClientQuery, dpopHeader(dpopProof(t, e, key, nil))), dpopThumb(t, e, p))
}

// Covers: FR-44 (part), SEC-36 (part)
// Acceptance: DPoP binding (part)
// A made-up code with a valid proof, and a wrong secret with a valid proof,
// are refused as without DPoP and write nothing.
func TestDPoPRefusalsWriteNothing(t *testing.T) {
	key, _ := testutil.ECKey(t)
	e := server.New(t)
	setDPoP(t, e, server.ClientQuery.ID, "allowed")
	setDPoP(t, e, server.ClientConfidential.ID, "allowed")
	before := rowCounts(t, e)
	made := server.CodeForm(server.ClientQuery, server.Result{Values: url.Values{"code": {"made-up-code"}}})
	wantDPoPRefusal(t, post(t, e, made, dpopHeader(dpopProof(t, e, key, nil))), "invalid_grant")

	f := server.CodeForm(server.ClientConfidential, e.Login(t, server.ClientConfidential))
	f.Set("client_secret", "wrong-secret")
	wantError(t, post(t, e, f, dpopHeader(dpopProof(t, e, key, nil))), http.StatusBadRequest, "invalid_client")

	if got := rowCounts(t, e); got["dpop_proofs"] != before["dpop_proofs"] || got["refresh_tokens"] != before["refresh_tokens"] {
		t.Fatalf("a refusal wrote rows: before %v, after %v", before, got)
	}
}

// Covers: FR-44 (part), SEC-36 (part)
// Acceptance: DPoP binding
// A reused code with a valid proof is refused as without DPoP: the session is revoked,
// and no proof is remembered.
func TestDPoPReusedCodeRemembersNoProof(t *testing.T) {
	key, _ := testutil.ECKey(t)
	e := server.New(t)
	setDPoP(t, e, server.ClientQuery.ID, "allowed")
	code := e.Login(t, server.ClientQuery)
	tk := wantBearerTokens(t, post(t, e, server.CodeForm(server.ClientQuery, code), nil))
	before := rowCounts(t, e)
	wantDPoPRefusal(t, post(t, e, server.CodeForm(server.ClientQuery, code), dpopHeader(dpopProof(t, e, key, nil))), "invalid_grant")
	if got := rowCounts(t, e)["dpop_proofs"]; got != before["dpop_proofs"] {
		t.Fatalf("a reused code remembered a proof: %d rows, want %d", got, before["dpop_proofs"])
	}
	wantDPoPRefusal(t, refreshWith(t, e, server.ClientQuery, tk.RefreshToken, nil), "invalid_grant")
}

// Covers: FR-44 (part), SEC-36 (part)
// Acceptance: DPoP binding
// A rotated token presented after the grace window is refused as without DPoP and
// remembers no proof.
func TestDPoPRotatedTokenRemembersNoProof(t *testing.T) {
	a, _ := testutil.ECKey(t)
	b, _ := testutil.ECKey(t)
	e := server.New(t)
	setDPoP(t, e, server.ClientQuery.ID, "allowed")
	pa := dpopProof(t, e, a, nil)
	tk := wantDPoPTokens(t, codeExchange(t, e, server.ClientQuery, dpopHeader(pa)), dpopThumb(t, e, pa))
	wantDPoPTokens(t, refreshWith(t, e, server.ClientQuery, tk.RefreshToken, dpopHeader(dpopProof(t, e, a, nil))), dpopThumb(t, e, pa))
	e.Clock.Advance(31 * time.Second) // past refresh_reuse_grace
	before := rowCounts(t, e)
	wantDPoPRefusal(t, refreshWith(t, e, server.ClientQuery, tk.RefreshToken, dpopHeader(dpopProof(t, e, b, nil))), "invalid_grant")
	if got := rowCounts(t, e)["dpop_proofs"]; got != before["dpop_proofs"] {
		t.Fatalf("a rotated token remembered a proof: %d rows, want %d", got, before["dpop_proofs"])
	}
}

// Covers: FR-44 (part)
// Acceptance: DPoP binding
// The preflight of the token and userinfo endpoints allows the header DPoP; the
// others keep their headers.
func TestDPoPPreflightAllowsTheHeader(t *testing.T) {
	e := server.New(t)
	preflight := func(path string) string {
		r := e.NewClient().Request(t, http.MethodOptions, server.Issuer+path, "", http.Header{
			"Origin": {"https://app.example.com"}, "Access-Control-Request-Method": {"POST"},
		})
		return r.Header.Get("Access-Control-Allow-Headers")
	}
	if got := preflight("/token"); got != "Authorization, Content-Type, DPoP" {
		t.Fatalf("token preflight allows %q", got)
	}
	if got := preflight("/userinfo"); got != "Authorization, Content-Type, DPoP" {
		t.Fatalf("userinfo preflight allows %q", got)
	}
	if got := preflight("/sessions"); got != "Authorization, Content-Type, DPoP" {
		t.Fatalf("sessions preflight allows %q", got)
	}
	if got := preflight("/jwks.json"); got != "Authorization, Content-Type" {
		t.Fatalf("jwks preflight allows %q", got)
	}
}

// Covers: FR-44 (part)
// Acceptance: DPoP binding
// Discovery lists the proof algorithms for a realm with a dpop client, and not otherwise.
func TestDPoPDiscoveryListsTheAlgorithms(t *testing.T) {
	get := func(e *server.Env) map[string]any {
		r := e.NewClient().Request(t, http.MethodGet, server.Issuer+"/.well-known/openid-configuration", "", nil)
		var doc map[string]any
		if err := json.Unmarshal([]byte(r.Body), &doc); err != nil {
			t.Fatal(err)
		}
		return doc
	}
	e := server.New(t)
	if _, ok := get(e)["dpop_signing_alg_values_supported"]; ok {
		t.Fatal("discovery lists DPoP algorithms with no dpop client")
	}
	setDPoP(t, e, server.ClientQuery.ID, "allowed")
	algs, _ := get(e)["dpop_signing_alg_values_supported"].([]any)
	if len(algs) != 2 || algs[0] != "ES256" || algs[1] != "RS256" {
		t.Fatalf("dpop_signing_alg_values_supported = %v", algs)
	}
}

// Covers: FR-44 (part), SEC-36 (part)
// Acceptance: DPoP binding (part)
// Inside the grace window a just-rotated bound token needs a proof of its own
// key before its successor is returned: without one, or with another key, it is
// refused and uses nothing up; with its key the successor is returned, keeps the
// key, and the proof's jti is remembered.
func TestDPoPRefreshWithinGraceKeepsTheKey(t *testing.T) {
	a, _ := testutil.ECKey(t)
	b, _ := testutil.ECKey(t)
	e := server.New(t)
	setDPoP(t, e, server.ClientQuery.ID, "allowed")
	pa := dpopProof(t, e, a, nil)
	tk := wantDPoPTokens(t, codeExchange(t, e, server.ClientQuery, dpopHeader(pa)), dpopThumb(t, e, pa))
	// tk is rotated by this refresh; the grace window is open.
	pa2 := dpopProof(t, e, a, nil)
	wantDPoPTokens(t, refreshWith(t, e, server.ClientQuery, tk.RefreshToken, dpopHeader(pa2)), dpopThumb(t, e, pa2))

	before := rowCounts(t, e)
	wantDPoPRefusal(t, refreshWith(t, e, server.ClientQuery, tk.RefreshToken, nil), "invalid_request")
	wantDPoPRefusal(t, refreshWith(t, e, server.ClientQuery, tk.RefreshToken, dpopHeader(dpopProof(t, e, b, nil))), "invalid_grant")
	if got := rowCounts(t, e); got["refresh_tokens"] != before["refresh_tokens"] || got["dpop_proofs"] != before["dpop_proofs"] {
		t.Fatalf("a refused grace refresh wrote rows: before %v, after %v", before, got)
	}

	pa3 := dpopProof(t, e, a, nil)
	graced := wantDPoPTokens(t, refreshWith(t, e, server.ClientQuery, tk.RefreshToken, dpopHeader(pa3)), dpopThumb(t, e, pa3))
	if got := rowCounts(t, e)["dpop_proofs"]; got != before["dpop_proofs"]+1 {
		t.Fatalf("the grace proof's jti was not remembered: %d rows, want %d", got, before["dpop_proofs"]+1)
	}
	// The successor keeps the key.
	wantDPoPRefusal(t, refreshWith(t, e, server.ClientQuery, graced.RefreshToken, nil), "invalid_request")
	wantDPoPTokens(t, refreshWith(t, e, server.ClientQuery, graced.RefreshToken, dpopHeader(dpopProof(t, e, a, nil))), dpopThumb(t, e, pa3))
}

// Covers: FR-44 (part), SEC-36 (part)
// Acceptance: DPoP binding (part)
// An unbound session on an allowed client whose token was just rotated answers
// inside the grace window exactly as without DPoP: Bearer tokens, whether the request
// has no proof, an invalid one or a valid one, and no jti is remembered.
func TestDPoPUnboundGraceIsV1(t *testing.T) {
	key, _ := testutil.ECKey(t)
	for _, made := range []string{"off", "allowed without a proof"} {
		for _, probe := range []string{"no proof", "invalid proof", "valid proof"} {
			t.Run(made+", "+probe, func(t *testing.T) {
				e := server.New(t)
				if made == "allowed without a proof" {
					setDPoP(t, e, server.ClientQuery.ID, "allowed")
				}
				tk := wantBearerTokens(t, codeExchange(t, e, server.ClientQuery, nil))
				setDPoP(t, e, server.ClientQuery.ID, "allowed")
				wantBearerTokens(t, refreshWith(t, e, server.ClientQuery, tk.RefreshToken, nil)) // tk is rotated now

				var h http.Header
				switch probe {
				case "invalid proof":
					h = dpopHeader(dpopProof(t, e, key, func(c map[string]any) { c["htu"] = "https://auth.example.com/main/other" }))
				case "valid proof":
					h = dpopHeader(dpopProof(t, e, key, nil))
				}
				before := rowCounts(t, e)
				wantBearerTokens(t, refreshWith(t, e, server.ClientQuery, tk.RefreshToken, h))
				if got := rowCounts(t, e)["dpop_proofs"]; got != before["dpop_proofs"] {
					t.Fatalf("the grace refresh remembered a jti: %d rows, want %d", got, before["dpop_proofs"])
				}
			})
		}
	}
}

// Covers: FR-44 (part), SEC-36 (part)
// Acceptance: DPoP binding (part)
// An unbound just-rotated token inside the grace window on a required client is
// checked as a normal unbound refresh of a required client (the user's decision:
// required wins): no proof is invalid_request, an invalid proof invalid_dpop_proof,
// and a valid proof is accepted as Bearer with its jti remembered.
func TestDPoPUnboundGraceRequiredProofs(t *testing.T) {
	key, _ := testutil.ECKey(t)
	for _, probe := range []string{"no proof", "invalid proof", "valid proof"} {
		t.Run(probe, func(t *testing.T) {
			e := server.New(t)
			tk := wantBearerTokens(t, codeExchange(t, e, server.ClientQuery, nil))
			wantBearerTokens(t, refreshWith(t, e, server.ClientQuery, tk.RefreshToken, nil)) // tk is rotated, unbound
			setDPoP(t, e, server.ClientQuery.ID, "required")

			var h http.Header
			switch probe {
			case "invalid proof":
				h = dpopHeader(dpopProof(t, e, key, func(c map[string]any) { c["htu"] = "https://auth.example.com/main/other" }))
			case "valid proof":
				h = dpopHeader(dpopProof(t, e, key, nil))
			}
			before := rowCounts(t, e)
			r := refreshWith(t, e, server.ClientQuery, tk.RefreshToken, h)
			switch probe {
			case "no proof":
				wantDPoPRefusal(t, r, "invalid_request")
			case "invalid proof":
				wantDPoPRefusal(t, r, "invalid_dpop_proof")
			case "valid proof":
				wantBearerTokens(t, r)
			}
			wantRows := before["dpop_proofs"]
			if probe == "valid proof" {
				wantRows++
			}
			if got := rowCounts(t, e)["dpop_proofs"]; got != wantRows {
				t.Fatalf("dpop_proofs rows %d, want %d", got, wantRows)
			}
		})
	}
}

package token_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/logx"
	"github.com/yyudhistira/featherauth/internal/testutil/configdir"
	"github.com/yyudhistira/featherauth/internal/token"
)

var issueTime = time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)

// jtiOf is the jti an issuer makes from the fixed source below.
var jtiOf = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 16))

func fixedSource() *bytes.Reader { return bytes.NewReader(bytes.Repeat([]byte{7}, 1024)) }

type env struct {
	realm   *config.Realm
	secrets config.Secrets
	keys    *token.KeySet
	clock   *clock.Fake
	issuer  *token.Issuer
}

const realmHead = `name: main
`

// newEnv loads a realm with the given algorithm and an extra user_data block.
func newEnv(t testing.TB, alg, userData string) *env {
	t.Helper()
	y := realmHead + "tokens:\n  algorithm: " + alg + "\nkeys:\n" +
		"  - { kid: rsa-new, file: secrets/rsa-new.pem, state: active }\n" +
		"  - { kid: rsa-old, file: secrets/rsa-old.pem, state: verify_only }\n"
	if alg == "ES256" {
		y += "  - { kid: ec-new, file: secrets/ec-new.pem, state: active }\n"
	}
	y += userData + `providers:
  google:
    enabled: true
    client_id: 1234.apps.googleusercontent.com
    client_secret_file: secrets/google_secret
clients:
  web:
    redirect_uris: [https://app.example.com/callback]
    web_origins: [https://app.example.com, https://admin.example.com]
  plain:
    redirect_uris: [https://plain.example.com/callback]
    access_token_lifetime: 5m
    audience: https://api.example.com
`
	d := configdir.New(t)
	d.Server(t, "public_url: https://auth.example.com\n")
	d.Realm(t, "main", y)
	d.RSAKey(t, "secrets/rsa-new.pem")
	d.RSAKey(t, "secrets/rsa-old.pem")
	d.AppleKey(t, "secrets/ec-new.pem")
	d.Secret(t, "secrets/google_secret")
	fc := clock.NewFake(issueTime)
	l, err := config.NewLoader(d.Root, fc, nil)
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}
	snap := l.Current()
	r, ok := snap.Realm("main")
	if !ok {
		t.Fatal("no realm main")
	}
	ks, err := token.NewKeySet(r, snap.Secrets())
	if err != nil {
		t.Fatal(err)
	}
	return &env{r, snap.Secrets(), ks, fc, token.NewIssuer(fc, fixedSource(), snap.Secrets())}
}

func (e *env) client(id string) *config.Client { return e.realm.Clients[config.ClientID(id)] }

func testSubject() token.Subject {
	return token.Subject{ID: "u1", Email: "ann@example.com", EmailVerified: true, Name: "Ann"}
}

func testSession() token.Session {
	return token.Session{ID: "s1", StartedAt: issueTime.Add(-5 * time.Minute), AuthTime: issueTime.Add(-time.Minute), Nonce: "n-1"}
}

// decoded is a token split into its parts; the signature is verified.
type decoded struct {
	header, claims map[string]any
	payloadB64     string
}

func decode(t *testing.T, e *env, raw string) decoded {
	t.Helper()
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d parts: %q", len(parts), raw)
	}
	var d decoded
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(hb, &d.header); err != nil {
		t.Fatal(err)
	}
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(pb, &d.claims); err != nil {
		t.Fatal(err)
	}
	d.payloadB64 = parts[1]
	kid, _ := d.header["kid"].(string)
	pub, alg, ok := e.keys.Lookup(kid)
	if !ok {
		t.Fatalf("kid %q not in the key set", kid)
	}
	if d.header["alg"] != alg {
		t.Fatalf("header alg %v, key alg %s", d.header["alg"], alg)
	}
	if _, err := jws.Verify([]byte(raw), jws.WithKey(mustAlg(t, alg), pub)); err != nil {
		t.Fatalf("signature does not verify: %v", err)
	}
	return d
}

func unix(tm time.Time) float64 { return float64(tm.Unix()) }

func mustAccess(t *testing.T, e *env, client string, s token.Subject, ss token.Session) (string, time.Time) {
	t.Helper()
	raw, exp, err := e.issuer.Access(e.realm, e.client(client), s, ss)
	if err != nil {
		t.Fatal(err)
	}
	return raw, exp
}

// Covers: FR-22 (part)
// Acceptance: Claims selection (part)
// Acceptance: User data (part)
func TestAccessTokenClaims(t *testing.T) {
	iss := "https://auth.example.com/main"
	base := func() map[string]any {
		return map[string]any{
			"iss": iss, "sub": "u1", "aud": "web", "client_id": "web", "azp": "web",
			"exp": unix(issueTime.Add(15 * time.Minute)), "iat": unix(issueTime),
			"jti": jtiOf, "auth_time": unix(issueTime.Add(-time.Minute)), "sid": "s1",
			"scope": "openid", "nonce": "n-1",
			"name": "Ann", "email": "ann@example.com", "email_verified": true,
			"preferred_username": "ann@example.com",
		}
	}
	allowed := "user_data:\n  claims: [name, email, email_verified, preferred_username, allowed-origins]\n"
	cases := []struct {
		name     string
		userData string
		client   string
		subject  token.Subject
		nonce    string
		edit     func(m map[string]any)
	}{
		{name: "default claims", client: "web", subject: testSubject(), nonce: "n-1", edit: func(m map[string]any) {}},
		{name: "allowed-origins with web origins", userData: allowed, client: "web", subject: testSubject(), nonce: "n-1",
			edit: func(m map[string]any) {
				m["allowed-origins"] = []any{"https://app.example.com", "https://admin.example.com"}
			}},
		{name: "allowed-origins omitted without web origins", userData: allowed, client: "plain", subject: testSubject(), nonce: "n-1",
			edit: func(m map[string]any) {
				m["aud"], m["client_id"], m["azp"] = "https://api.example.com", "plain", "plain"
				m["exp"] = unix(issueTime.Add(5 * time.Minute))
			}},
		{name: "no name", client: "web", subject: token.Subject{ID: "u1", Email: "ann@example.com", EmailVerified: true}, nonce: "n-1",
			edit: func(m map[string]any) { delete(m, "name") }},
		{name: "no email uses the user id", client: "web", subject: token.Subject{ID: "u1", Name: "Ann"}, nonce: "n-1",
			edit: func(m map[string]any) {
				delete(m, "email")
				delete(m, "email_verified")
				m["preferred_username"] = "u1"
			}},
		{name: "unverified email", client: "web", subject: token.Subject{ID: "u1", Email: "ann@example.com", Name: "Ann"}, nonce: "n-1",
			edit: func(m map[string]any) { m["email_verified"] = false }},
		{name: "no nonce", client: "web", subject: testSubject(), nonce: "",
			edit: func(m map[string]any) { delete(m, "nonce") }},
		{name: "only selected claims", userData: "user_data:\n  claims: [email]\n", client: "web", subject: testSubject(), nonce: "n-1",
			edit: func(m map[string]any) {
				delete(m, "name")
				delete(m, "email_verified")
				delete(m, "preferred_username")
			}},
		{name: "no user claims", userData: "user_data:\n  claims: []\n", client: "web", subject: testSubject(), nonce: "n-1",
			edit: func(m map[string]any) {
				delete(m, "name")
				delete(m, "email")
				delete(m, "email_verified")
				delete(m, "preferred_username")
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, "RS256", tc.userData)
			ss := testSession()
			ss.Nonce = tc.nonce
			raw, exp := mustAccess(t, e, tc.client, tc.subject, ss)
			d := decode(t, e, raw)
			want := base()
			tc.edit(want)
			if !reflect.DeepEqual(d.claims, want) {
				t.Errorf("claims\n got %v\nwant %v", d.claims, want)
			}
			if wantExp := time.Unix(int64(want["exp"].(float64)), 0).UTC(); !exp.Equal(wantExp) {
				t.Errorf("returned exp %v, want %v", exp, wantExp)
			}
		})
	}
}

// Covers: FR-22 (part)
func TestIATIsTheIssueTimeAndAuthTimeIsKept(t *testing.T) {
	e := newEnv(t, "RS256", "")
	e.clock.Advance(7 * time.Minute)
	raw, exp := mustAccess(t, e, "web", testSubject(), testSession())
	d := decode(t, e, raw)
	if d.claims["iat"] != unix(issueTime.Add(7*time.Minute)) {
		t.Errorf("iat = %v", d.claims["iat"])
	}
	if d.claims["auth_time"] != unix(issueTime.Add(-time.Minute)) {
		t.Errorf("auth_time = %v", d.claims["auth_time"])
	}
	if !exp.Equal(issueTime.Add(22 * time.Minute)) {
		t.Errorf("exp = %v", exp)
	}
}

// Covers: FR-22 (part)
// Acceptance: Claims selection (part)
func TestIDTokenClaims(t *testing.T) {
	e := newEnv(t, "RS256", "user_data:\n  claims: [name, email, email_verified, preferred_username, allowed-origins]\n")
	raw, err := e.issuer.ID(e.realm, e.client("web"), testSubject(), testSession(), "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y")
	if err != nil {
		t.Fatal(err)
	}
	d := decode(t, e, raw)
	want := map[string]any{
		"iss": "https://auth.example.com/main", "sub": "u1", "aud": "web",
		"exp": unix(issueTime.Add(15 * time.Minute)), "iat": unix(issueTime),
		"auth_time": unix(issueTime.Add(-time.Minute)), "sid": "s1", "nonce": "n-1",
		"at_hash": "77QmUPtjPfzWtF2AnpK9RQ",
		"name":    "Ann", "email": "ann@example.com", "email_verified": true,
		"preferred_username": "ann@example.com",
		"allowed-origins":    []any{"https://app.example.com", "https://admin.example.com"},
	}
	if !reflect.DeepEqual(d.claims, want) {
		t.Errorf("claims\n got %v\nwant %v", d.claims, want)
	}
}

// Covers: FR-22 (part)
func TestIDTokenWithoutNonceAndUsesClientLifetimeAndClientIDAsAudience(t *testing.T) {
	e := newEnv(t, "RS256", "")
	ss := testSession()
	ss.Nonce = ""
	raw, err := e.issuer.ID(e.realm, e.client("plain"), testSubject(), ss, "at")
	if err != nil {
		t.Fatal(err)
	}
	d := decode(t, e, raw)
	if _, ok := d.claims["nonce"]; ok {
		t.Error("nonce present without a request nonce")
	}
	// the audience override applies to access tokens only
	if d.claims["aud"] != "plain" {
		t.Errorf("aud = %v, want the client id", d.claims["aud"])
	}
	if d.claims["exp"] != unix(issueTime.Add(5*time.Minute)) {
		t.Errorf("exp = %v, want the client's 5m lifetime", d.claims["exp"])
	}
}

// Covers: FR-22 (part)
func TestAtHashKnownVector(t *testing.T) {
	// OpenID Connect Core, A.3 style vector: SHA-256, left half, base64url.
	e := newEnv(t, "RS256", "")
	raw, err := e.issuer.ID(e.realm, e.client("web"), testSubject(), testSession(), "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y")
	if err != nil {
		t.Fatal(err)
	}
	if got := decode(t, e, raw).claims["at_hash"]; got != "77QmUPtjPfzWtF2AnpK9RQ" {
		t.Errorf("at_hash = %v", got)
	}
}

// Covers: SEC-05
// Covers: SEC-06 (part)
// Acceptance: Token types (part)
func TestHeadersAndAlgorithmPerRealm(t *testing.T) {
	for _, tc := range []struct {
		alg, accessKid string
	}{{"RS256", "rsa-new"}, {"ES256", "ec-new"}} {
		t.Run(tc.alg, func(t *testing.T) {
			e := newEnv(t, tc.alg, "")
			access, _ := mustAccess(t, e, "web", testSubject(), testSession())
			id, err := e.issuer.ID(e.realm, e.client("web"), testSubject(), testSession(), access)
			if err != nil {
				t.Fatal(err)
			}
			refresh, err := e.issuer.RefreshJWT(e.realm, e.client("web"), testSubject(), testSession(), issueTime.Add(time.Hour), "r1")
			if err != nil {
				t.Fatal(err)
			}
			for _, c := range []struct {
				name, raw, typ, alg, kid string
			}{
				{"access", access, "at+jwt", tc.alg, tc.accessKid},
				{"id", id, "JWT", "RS256", "rsa-new"},
				{"refresh", refresh, "refresh+jwt", tc.alg, tc.accessKid},
			} {
				d := decode(t, e, c.raw)
				if d.header["typ"] != c.typ || d.header["alg"] != c.alg || d.header["kid"] != c.kid {
					t.Errorf("%s header = %v, want typ %s alg %s kid %s", c.name, d.header, c.typ, c.alg, c.kid)
				}
			}
			ad := decode(t, e, access)
			if ad.claims["client_id"] != ad.claims["azp"] {
				t.Errorf("client_id %v and azp %v differ", ad.claims["client_id"], ad.claims["azp"])
			}
		})
	}
}

// Covers: SEC-06 (part)
// Acceptance: Token types (part)
func TestRefreshJWTClaims(t *testing.T) {
	e := newEnv(t, "RS256", "")
	exp := issueTime.Add(30 * 24 * time.Hour)
	raw, err := e.issuer.RefreshJWT(e.realm, e.client("web"), testSubject(), testSession(), exp, "jti-9")
	if err != nil {
		t.Fatal(err)
	}
	d := decode(t, e, raw)
	iss := "https://auth.example.com/main"
	want := map[string]any{
		"iss": iss, "aud": iss, "sub": "u1", "azp": "web", "exp": unix(exp), "iat": unix(issueTime),
		"jti": "jti-9", "sid": "s1", "nonce": "n-1", "typ": "Refresh",
	}
	if !reflect.DeepEqual(d.claims, want) {
		t.Errorf("claims\n got %v\nwant %v", d.claims, want)
	}
	ss := testSession()
	ss.Nonce = ""
	raw, err = e.issuer.RefreshJWT(e.realm, e.client("web"), testSubject(), ss, exp, "jti-9")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := decode(t, e, raw).claims["nonce"]; ok {
		t.Error("nonce present without a request nonce")
	}
}

// Covers: FR-22 (part), SEC-05
func TestAccessExpiryFromClientLifetimeOverride(t *testing.T) {
	e := newEnv(t, "RS256", "")
	_, exp := mustAccess(t, e, "plain", testSubject(), testSession())
	if !exp.Equal(issueTime.Add(5 * time.Minute)) {
		t.Errorf("exp = %v, want now+5m", exp)
	}
	_, exp = mustAccess(t, e, "web", testSubject(), testSession())
	if !exp.Equal(issueTime.Add(15 * time.Minute)) {
		t.Errorf("exp = %v, want now+15m", exp)
	}
}

// Signs tokens with random non-ASCII text and the four special characters
// (the generator is the one the claim-encoding property test uses).
// Covers: FR-22 (part)
// Acceptance: ASCII payload
func TestSignedPayloadsDecodeWithPlainBase64(t *testing.T) {
	e := newEnv(t, "ES256", "user_data:\n  claims: [name, email, email_verified, preferred_username, allowed-origins]\n")
	x := xorshift(0x2545f4914f6cdd1d)
	e.issuer = token.NewIssuer(e.clock, bytes.NewReader(bytes.Repeat([]byte{7}, 16*400)), e.secrets)
	for i := 0; i < 300; i++ {
		// the padding in front moves the special characters through every
		// position of a 3-byte group
		s := token.Subject{
			ID:    token.UserID(strings.Repeat("a", x.intn(3)) + x.randomString()),
			Email: strings.Repeat("e", x.intn(3)) + x.randomString() + ">?~\x7f",
			Name:  strings.Repeat("n", x.intn(3)) + x.randomString() + "?>\x7f~",
		}
		ss := testSession()
		ss.Nonce = x.randomString()
		access, _, err := e.issuer.Access(e.realm, e.client("web"), s, ss)
		if err != nil {
			t.Fatal(err)
		}
		id, err := e.issuer.ID(e.realm, e.client("web"), s, ss, access)
		if err != nil {
			t.Fatal(err)
		}
		refresh, err := e.issuer.RefreshJWT(e.realm, e.client("web"), s, ss, issueTime.Add(time.Hour), "j"+x.randomString())
		if err != nil {
			t.Fatal(err)
		}
		for _, raw := range []string{access, id, refresh} {
			p := strings.Split(raw, ".")[1]
			if strings.ContainsAny(p, "-_") {
				t.Fatalf("payload %q has - or _", p)
			}
			std := p
			for len(std)%4 != 0 {
				std += "="
			}
			viaStd, err := base64.StdEncoding.DecodeString(std)
			if err != nil {
				t.Fatalf("plain base64 rejects %q: %v", p, err)
			}
			viaURL, err := base64.RawURLEncoding.DecodeString(p)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(viaStd, viaURL) {
				t.Fatalf("payload decodes differently: %q vs %q", viaStd, viaURL)
			}
			for _, b := range viaURL {
				if b >= 0x80 || b == '>' || b == '?' || b == '~' || b == 0x7f {
					t.Fatalf("payload holds byte %#x: %q", b, viaURL)
				}
			}
			var m map[string]any
			if err := json.Unmarshal(viaStd, &m); err != nil {
				t.Fatal(err)
			}
			if m["sub"] != string(s.ID) {
				t.Fatalf("sub = %q, want %q", m["sub"], s.ID)
			}
		}
	}
}

// Covers: SEC-13 (part)
func TestSubjectAndSessionLogNeitherEmailNorNonce(t *testing.T) {
	s := token.Subject{ID: "u-77", Email: "secret.person@example.com", EmailVerified: true, Name: "Secret Person"}
	ss := token.Session{ID: "s-88", StartedAt: issueTime, AuthTime: issueTime, Nonce: "nonce-sentinel-123"}
	var _ slog.LogValuer = s
	var _ slog.LogValuer = ss
	cases := map[string]func(l *slog.Logger){
		"direct": func(l *slog.Logger) { l.Info("m", "subject", s, "session", ss) },
		"nested map": func(l *slog.Logger) {
			l.Info("m", "details", map[string]any{"s": s, "inner": map[string]any{"ss": ss}})
		},
		"slice": func(l *slog.Logger) { l.Info("m", "list", []any{s, ss}) },
	}
	for name, log := range cases {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			log(logx.New(&buf, slog.LevelDebug, clock.NewFake(time.Unix(0, 0))))
			out := buf.String()
			for _, f := range []string{"secret.person", "example.com", "nonce-sentinel-123", "Secret Person"} {
				if strings.Contains(out, f) {
					t.Errorf("log holds %q: %s", f, out)
				}
			}
			for _, want := range []string{"u-77", "s-88"} {
				if !strings.Contains(out, want) {
					t.Errorf("log lacks %q: %s", want, out)
				}
			}
		})
	}
}

func mustAlg(t testing.TB, alg string) jwa.SignatureAlgorithm {
	t.Helper()
	a, ok := jwa.LookupSignatureAlgorithm(alg)
	if !ok {
		t.Fatalf("unknown algorithm %s", alg)
	}
	return a
}

// Covers: FR-22 (part)
func TestProfileClaims(t *testing.T) {
	r := &config.Realm{}
	r.UserData.Claims = []string{"name", "preferred_username", "allowed-origins"}
	got := token.ProfileClaims(r, nil, token.Subject{ID: "u1", Name: "Ann"})
	want := map[string]any{"name": "Ann", "preferred_username": "u1"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("claims %v, want %v (no client: no allowed-origins, no sub)", got, want)
	}
}

// assertUserClaims checks that m holds exactly the named user claims, each with
// its value from values, and none of the other user claims of values.
func assertUserClaims(t *testing.T, m map[string]any, want []string, values map[string]any) {
	t.Helper()
	for name, v := range values {
		got, ok := m[name]
		if slices.Contains(want, name) {
			if !ok || !reflect.DeepEqual(got, v) {
				t.Errorf("%s = %v (present %v), want %v", name, got, ok, v)
			}
		} else if ok {
			t.Errorf("%s is present, want it absent", name)
		}
	}
}

// Covers: FR-41
// Acceptance: Access token claims
func TestAccessTokenClaimsOption(t *testing.T) {
	userValues := map[string]any{
		"name": "Ann", "email": "ann@example.com", "email_verified": true, "preferred_username": "ann@example.com",
	}
	all := []string{"name", "email", "email_verified", "preferred_username"}
	cases := []struct {
		name      string
		userData  string
		access    []string // user claims of the access token
		idAndInfo []string // user claims of the ID token and of /userinfo
	}{
		{name: "not set: the claims of user_data.claims", access: all, idAndInfo: all},
		{name: "not set with user_data.claims narrowed", userData: "user_data:\n  claims: [email]\n",
			access: []string{"email"}, idAndInfo: []string{"email"}},
		{name: "one claim", userData: "user_data:\n  access_token_claims: [preferred_username]\n",
			access: []string{"preferred_username"}, idAndInfo: all},
		{name: "empty list", userData: "user_data:\n  access_token_claims: []\n",
			access: nil, idAndInfo: all},
		{name: "empty value is not set", userData: "user_data:\n  access_token_claims:\n",
			access: all, idAndInfo: all},
	}
	subject := testSubject()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, "RS256", tc.userData)
			raw, _ := mustAccess(t, e, "web", subject, testSession())
			assertUserClaims(t, decode(t, e, raw).claims, tc.access, userValues)

			idRaw, err := e.issuer.ID(e.realm, e.client("web"), subject, testSession(), "accessTokenValue")
			if err != nil {
				t.Fatal(err)
			}
			assertUserClaims(t, decode(t, e, idRaw).claims, tc.idAndInfo, userValues)
			assertUserClaims(t, token.ProfileClaims(e.realm, e.client("web"), subject), tc.idAndInfo, userValues)
		})
	}
}

// Covers: FR-43 (part)
// Acceptance: Logout token is not a credential (part)
// A logout token (SEC-35) has typ logout+jwt, is signed RS256 whatever the
// realm's algorithm, lives 2 minutes and carries the back-channel event and no
// nonce. Every token check of FeatherAuth refuses it.
func TestLogoutTokenClaimsAndRefusal(t *testing.T) {
	e := newEnv(t, "ES256", "")
	raw, err := e.issuer.Logout(e.realm, e.client("web"), "u1", "s1", "jti-1")
	if err != nil {
		t.Fatal(err)
	}
	d := decode(t, e, raw)
	if d.header["typ"] != "logout+jwt" || d.header["alg"] != "RS256" {
		t.Errorf("header %v, want typ logout+jwt and alg RS256", d.header)
	}
	want := map[string]any{
		"iss": "https://auth.example.com/main", "aud": "web", "sub": "u1", "sid": "s1", "jti": "jti-1",
		"iat": unix(issueTime), "exp": unix(issueTime.Add(2 * time.Minute)),
		"events": map[string]any{"http://schemas.openid.net/event/backchannel-logout": map[string]any{}},
	}
	if !reflect.DeepEqual(d.claims, want) {
		t.Errorf("claims\n got %v\nwant %v", d.claims, want)
	}
	v := token.NewVerifier(e.clock, e.secrets)
	if _, err := v.Access(e.realm, raw); err == nil {
		t.Error("a logout token verified as an access token")
	}
	if _, err := v.IDTokenHint(e.realm, raw); err == nil {
		t.Error("a logout token verified as an id_token_hint")
	}
}

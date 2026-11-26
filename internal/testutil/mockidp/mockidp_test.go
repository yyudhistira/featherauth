package mockidp_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/testutil/mockidp"
)

const redirect = "https://app.example/cb"

func newServer(t *testing.T, p mockidp.Profile) (*mockidp.Server, *clock.Fake) {
	t.Helper()
	clk := clock.NewFake(time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC))
	s := mockidp.New(t, clk, p)
	s.SetUser(mockidp.User{Sub: "42", Email: "ann@example.com", EmailVerified: true, Name: "Ann"})
	return s, clk
}

// client does not follow redirects, so tests read the Location.
var client = &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

func do(t *testing.T, req *http.Request) (*http.Response, []byte) {
	t.Helper()
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

func get(t *testing.T, u string, hdr map[string]string) (*http.Response, []byte) {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, u, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	return do(t, req)
}

func post(t *testing.T, u string, form url.Values, hdr map[string]string) (*http.Response, []byte) {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, u, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	return do(t, req)
}

func challenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// authorize runs the authorize step and returns the code from the redirect.
func authorize(t *testing.T, s *mockidp.Server, path string, extra url.Values) string {
	t.Helper()
	q := url.Values{"client_id": {s.ClientID()}, "redirect_uri": {redirect}, "state": {"st"}, "response_type": {"code"}}
	for k, v := range extra {
		q[k] = v
	}
	resp, _ := get(t, s.URL()+path+"?"+q.Encode(), nil)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize status = %d", resp.StatusCode)
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if loc.Query().Get("state") != "st" {
		t.Fatalf("state not echoed: %s", loc)
	}
	return loc.Query().Get("code")
}

func tokenForm(s *mockidp.Server, code, verifier string) url.Values {
	f := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirect},
		"client_id": {s.ClientID()}, "client_secret": {s.ClientSecret()}}
	if verifier != "" {
		f.Set("code_verifier", verifier)
	}
	return f
}

func decode(t *testing.T, b []byte) map[string]any {
	t.Helper()
	m := map[string]any{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("body %q: %v", b, err)
	}
	return m
}

func claimsOf(t *testing.T, tok string) (map[string]any, jws.Headers) {
	t.Helper()
	msg, err := jws.Parse([]byte(tok), jws.WithCompact())
	if err != nil {
		t.Fatal(err)
	}
	return decode(t, msg.Payload()), msg.Signatures()[0].ProtectedHeaders()
}

func TestDiscoveryAndAuthorizeRecording(t *testing.T) {
	s, _ := newServer(t, mockidp.Generic)
	resp, body := get(t, s.URL()+"/.well-known/openid-configuration", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	d := decode(t, body)
	for k, want := range map[string]string{"issuer": s.URL(), "authorization_endpoint": s.URL() + "/authorize",
		"token_endpoint": s.URL() + "/token", "jwks_uri": s.URL() + "/jwks", "userinfo_endpoint": s.URL() + "/userinfo"} {
		if d[k] != want {
			t.Errorf("%s = %v, want %s", k, d[k], want)
		}
	}
	authorize(t, s, "/authorize", url.Values{"nonce": {"n1"}, "prompt": {"login"}, "code_challenge": {"c"}})
	a := s.Authorizations()
	if len(a) != 1 || a[0].Params.Get("nonce") != "n1" || a[0].Params.Get("prompt") != "login" || a[0].Params.Get("code_challenge") != "c" {
		t.Fatalf("authorizations = %+v", a)
	}
}

func TestAuthorizeError(t *testing.T) {
	s, _ := newServer(t, mockidp.Generic)
	s.SetAuthorizeError("access_denied")
	q := url.Values{"client_id": {s.ClientID()}, "redirect_uri": {redirect}, "state": {"st"}}
	resp, _ := get(t, s.URL()+"/authorize?"+q.Encode(), nil)
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != http.StatusFound || loc.Query().Get("error") != "access_denied" || loc.Query().Get("state") != "st" || loc.Query().Get("code") != "" {
		t.Fatalf("status %d location %s", resp.StatusCode, loc)
	}
}

func TestTokenExchangeIDTokenAndPKCE(t *testing.T) {
	s, clk := newServer(t, mockidp.Google)
	s.SetUser(mockidp.User{Sub: "42", Email: "ann@example.com", EmailVerified: "true", HD: "example.com", AuthTime: clk.Now().Add(-time.Minute)})
	verifier := strings.Repeat("v", 43)
	code := authorize(t, s, "/authorize", url.Values{"nonce": {"n1"}, "code_challenge": {challenge(verifier)}, "code_challenge_method": {"S256"}})
	resp, body := post(t, s.URL()+"/token", tokenForm(s, code, verifier), nil)
	if resp.StatusCode != 200 {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	tok := decode(t, body)
	claims, hdr := claimsOf(t, tok["id_token"].(string))
	if claims["iss"] != s.URL() || claims["aud"] != s.ClientID() || claims["sub"] != "42" || claims["nonce"] != "n1" ||
		claims["email_verified"] != "true" || claims["hd"] != "example.com" {
		t.Errorf("claims = %v", claims)
	}
	if int64(claims["auth_time"].(float64)) != clk.Now().Add(-time.Minute).Unix() || int64(claims["exp"].(float64)) <= clk.Now().Unix() {
		t.Errorf("times = %v", claims)
	}
	if kid, _ := hdr.KeyID(); kid == "" {
		t.Error("no kid")
	}
	if s.TokenCalls() != 1 {
		t.Errorf("token calls = %d", s.TokenCalls())
	}
	// the code is single use
	resp, body = post(t, s.URL()+"/token", tokenForm(s, code, verifier), nil)
	if resp.StatusCode != 400 || decode(t, body)["error"] != "invalid_grant" {
		t.Errorf("reuse: %d %s", resp.StatusCode, body)
	}
	if s.TokenCalls() != 2 {
		t.Errorf("token calls = %d", s.TokenCalls())
	}
}

func TestTokenRejections(t *testing.T) {
	verifier := strings.Repeat("v", 43)
	cases := []struct {
		name     string
		extra    url.Values // authorize params
		mutate   func(f url.Values)
		basic    bool
		wantCode string
	}{
		{"wrong verifier", url.Values{"code_challenge": {challenge(verifier)}}, func(f url.Values) { f.Set("code_verifier", "wrong") }, false, "invalid_grant"},
		{"missing verifier", url.Values{"code_challenge": {challenge(verifier)}}, func(f url.Values) { f.Del("code_verifier") }, false, "invalid_grant"},
		{"verifier without challenge", nil, func(f url.Values) { f.Set("code_verifier", verifier) }, false, "invalid_grant"},
		{"wrong secret", nil, func(f url.Values) { f.Set("client_secret", "nope") }, false, "invalid_client"},
		{"wrong redirect", nil, func(f url.Values) { f.Set("redirect_uri", "https://evil/cb") }, false, "invalid_grant"},
		{"unknown code", nil, func(f url.Values) { f.Set("code", "nope") }, false, "invalid_grant"},
		{"bad grant type", nil, func(f url.Values) { f.Set("grant_type", "password") }, false, "unsupported_grant_type"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, _ := newServer(t, mockidp.Generic)
			code := authorize(t, s, "/authorize", c.extra)
			f := tokenForm(s, code, "")
			c.mutate(f)
			resp, body := post(t, s.URL()+"/token", f, nil)
			if resp.StatusCode != 400 && resp.StatusCode != 401 {
				t.Fatalf("status %d", resp.StatusCode)
			}
			if got := decode(t, body)["error"]; got != c.wantCode {
				t.Errorf("error = %v, want %s", got, c.wantCode)
			}
		})
	}
}

func TestTokenBasicAuthAndSecretCheck(t *testing.T) {
	s, _ := newServer(t, mockidp.Apple)
	var seen string
	s.SetSecretCheck(func(secret string) error { seen = secret; return nil })
	code := authorize(t, s, "/authorize", nil)
	f := tokenForm(s, code, "")
	f.Set("client_secret", "generated-jwt")
	resp, body := post(t, s.URL()+"/token", f, nil)
	if resp.StatusCode != 200 || seen != "generated-jwt" {
		t.Fatalf("status %d seen %q %s", resp.StatusCode, seen, body)
	}

	s2, _ := newServer(t, mockidp.Generic)
	code = authorize(t, s2, "/authorize", nil)
	f = tokenForm(s2, code, "")
	f.Del("client_id")
	f.Del("client_secret")
	basic := base64.StdEncoding.EncodeToString([]byte(s2.ClientID() + ":" + s2.ClientSecret()))
	resp, body = post(t, s2.URL()+"/token", f, map[string]string{"Authorization": "Basic " + basic})
	if resp.StatusCode != 200 {
		t.Fatalf("basic status %d %s", resp.StatusCode, body)
	}
}

func TestUserinfo(t *testing.T) {
	s, _ := newServer(t, mockidp.Generic)
	code := authorize(t, s, "/authorize", nil)
	_, body := post(t, s.URL()+"/token", tokenForm(s, code, ""), nil)
	at := decode(t, body)["access_token"].(string)
	resp, body := get(t, s.URL()+"/userinfo", map[string]string{"Authorization": "Bearer " + at})
	if resp.StatusCode != 200 || decode(t, body)["sub"] != "42" || decode(t, body)["email"] != "ann@example.com" {
		t.Fatalf("status %d %s", resp.StatusCode, body)
	}
	resp, _ = get(t, s.URL()+"/userinfo", map[string]string{"Authorization": "Bearer bad"})
	if resp.StatusCode != 401 {
		t.Errorf("bad token status %d", resp.StatusCode)
	}
}

func TestJWKSRotation(t *testing.T) {
	s, _ := newServer(t, mockidp.Generic)
	kids := func() []string {
		_, body := get(t, s.URL()+"/jwks", nil)
		set, err := jwk.Parse(body)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for i := 0; i < set.Len(); i++ {
			k, _ := set.Key(i)
			kid, _ := k.KeyID()
			out = append(out, kid)
		}
		return out
	}
	before := kids()
	if len(before) != 1 {
		t.Fatalf("kids = %v", before)
	}
	s.RotateKey()
	after := kids()
	if len(after) != 2 {
		t.Fatalf("kids after rotate = %v", after)
	}
	_, hdr := claimsOf(t, s.IDToken("n"))
	if kid, _ := hdr.KeyID(); kid != after[1] {
		t.Errorf("signed with %q, want the new key %q", kid, after[1])
	}
	s.RetireOldKeys()
	if got := kids(); len(got) != 1 || got[0] != after[1] {
		t.Errorf("kids after retire = %v", got)
	}
	if s.JWKSCalls() != 3 {
		t.Errorf("jwks calls = %d", s.JWKSCalls())
	}
}

func TestFailJWKSAndBlock(t *testing.T) {
	s, _ := newServer(t, mockidp.Generic)
	s.FailJWKS(1)
	if resp, _ := get(t, s.URL()+"/jwks", nil); resp.StatusCode != 500 {
		t.Errorf("first status %d", resp.StatusCode)
	}
	if resp, _ := get(t, s.URL()+"/jwks", nil); resp.StatusCode != 200 {
		t.Errorf("second status %d", resp.StatusCode)
	}

	// a blocked endpoint answers nothing until the caller gives up
	s.Block()
	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, s.URL()+"/token", strings.NewReader(""))
	done := make(chan error, 1)
	go func() {
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
		}
		done <- err
	}()
	<-s.Blocked() // a handler is waiting
	cancel()
	if err := <-done; err == nil {
		t.Error("blocked request succeeded")
	}
	s.Unblock()
	if resp, _ := get(t, s.URL()+"/jwks", nil); resp.StatusCode != 200 {
		t.Errorf("after unblock status %d", resp.StatusCode)
	}
}

func TestIDTokenMutator(t *testing.T) {
	s, _ := newServer(t, mockidp.Generic)
	s.SetIDTokenClaims(func(c map[string]any) { c["aud"] = "other"; delete(c, "email_verified") })
	claims, _ := claimsOf(t, s.IDToken("n"))
	if claims["aud"] != "other" {
		t.Errorf("aud = %v", claims["aud"])
	}
	if _, ok := claims["email_verified"]; ok {
		t.Error("email_verified still present")
	}
}

func TestAppleFormPostRevokeAndEvents(t *testing.T) {
	s, _ := newServer(t, mockidp.Apple)
	q := url.Values{"client_id": {s.ClientID()}, "redirect_uri": {redirect}, "state": {"st"}, "response_mode": {"form_post"}, "nonce": {"n1"}}
	resp, body := get(t, s.URL()+"/authorize?"+q.Encode(), nil)
	if resp.StatusCode != 200 || !strings.Contains(string(body), `action="`+redirect+`"`) {
		t.Fatalf("status %d body %s", resp.StatusCode, body)
	}
	a := s.Authorizations()
	p := a[0].Posted
	if p.Get("state") != "st" || p.Get("code") == "" || p.Get("id_token") == "" || !strings.Contains(p.Get("user"), "ann@example.com") {
		t.Fatalf("posted = %v", p)
	}
	claims, _ := claimsOf(t, p.Get("id_token"))
	if claims["nonce"] != "n1" {
		t.Errorf("posted id_token nonce = %v", claims["nonce"])
	}
	resp, body = post(t, s.URL()+"/token", tokenForm(s, p.Get("code"), ""), nil)
	tok := decode(t, body)
	if resp.StatusCode != 200 || tok["refresh_token"] == "" || tok["refresh_token"] == nil {
		t.Fatalf("token %d %s", resp.StatusCode, body)
	}
	if s.RefreshToken() != tok["refresh_token"] {
		t.Errorf("RefreshToken() = %q, want the token given", s.RefreshToken())
	}
	s.OmitRefreshToken(true)
	_, body = post(t, s.URL()+"/token", tokenForm(s, p.Get("code"), ""), nil)
	if _, has := decode(t, body)["refresh_token"]; has {
		t.Errorf("a refresh token was given after OmitRefreshToken: %s", body)
	}
	s.OmitRefreshToken(false)

	f := url.Values{"client_id": {s.ClientID()}, "client_secret": {s.ClientSecret()}, "token": {tok["refresh_token"].(string)}, "token_type_hint": {"refresh_token"}}
	if resp, _ = post(t, s.URL()+"/revoke", f, nil); resp.StatusCode != 200 {
		t.Fatalf("revoke status %d", resp.StatusCode)
	}
	r := s.Revocations()
	if len(r) != 1 || r[0].Token != tok["refresh_token"] || r[0].Secret != s.ClientSecret() {
		t.Errorf("revocations = %+v", r)
	}

	ev := s.SignedEvent(s.ClientID(), "consent-revoked", "42")
	var env struct{ Payload string }
	if err := json.Unmarshal([]byte(ev), &env); err != nil {
		t.Fatal(err)
	}
	ec, _ := claimsOf(t, env.Payload)
	if ec["iss"] != "https://appleid.apple.com" || ec["aud"] != s.ClientID() {
		t.Errorf("event claims = %v", ec)
	}
	var inner map[string]any
	if err := json.Unmarshal([]byte(ec["events"].(string)), &inner); err != nil || inner["type"] != "consent-revoked" || inner["sub"] != "42" {
		t.Errorf("events = %v %v", ec["events"], err)
	}
	custom := s.SignedClaims(map[string]any{"iss": "x", "aud": "y"})
	var cenv struct{ Payload string }
	if err := json.Unmarshal([]byte(custom), &cenv); err != nil {
		t.Fatal(err)
	}
	if cc, _ := claimsOf(t, cenv.Payload); len(cc) != 2 || cc["iss"] != "x" || cc["aud"] != "y" {
		t.Errorf("custom claims = %v", cc)
	}
	// verifies with the JWKS
	_, jb := get(t, s.URL()+"/jwks", nil)
	set, _ := jwk.Parse(jb)
	if _, err := jws.Verify([]byte(env.Payload), jws.WithKeySet(set)); err != nil {
		t.Errorf("event signature: %v", err)
	}
}

func TestGitHubProfile(t *testing.T) {
	s, _ := newServer(t, mockidp.GitHub)
	s.SetUser(mockidp.User{Sub: "1234", Name: "Ann", Emails: []mockidp.Email{
		{Email: "old@example.com", Verified: false}, {Email: "ann@example.com", Primary: true, Verified: true}}})
	code := authorize(t, s, "/login/oauth/authorize", nil)
	// without Accept: application/json the answer is form encoded
	_, body := post(t, s.URL()+"/login/oauth/access_token", tokenForm(s, code, ""), nil)
	if v, _ := url.ParseQuery(string(body)); v.Get("access_token") == "" {
		t.Fatalf("form body %s", body)
	}
	code = authorize(t, s, "/login/oauth/authorize", nil)
	_, body = post(t, s.URL()+"/login/oauth/access_token", tokenForm(s, code, ""), map[string]string{"Accept": "application/json"})
	at, _ := decode(t, body)["access_token"].(string)
	if at == "" {
		t.Fatalf("json body %s", body)
	}
	auth := map[string]string{"Authorization": "Bearer " + at}
	if resp, _ := get(t, s.URL()+"/user", auth); resp.StatusCode != 403 {
		t.Errorf("without User-Agent status %d", resp.StatusCode)
	}
	auth["User-Agent"] = "featherauth"
	_, body = get(t, s.URL()+"/user", auth)
	if u := decode(t, body); u["id"] != float64(1234) || u["name"] != "Ann" {
		t.Errorf("user = %v", u)
	}
	_, body = get(t, s.URL()+"/user/emails", auth)
	var emails []map[string]any
	if err := json.Unmarshal(body, &emails); err != nil || len(emails) != 2 || emails[1]["primary"] != true || emails[1]["verified"] != true {
		t.Errorf("emails = %s %v", body, err)
	}
}

func TestFacebookProfile(t *testing.T) {
	s, _ := newServer(t, mockidp.Facebook)
	code := authorize(t, s, "/dialog/oauth", nil)
	resp, body := get(t, s.URL()+"/oauth/access_token?"+tokenForm(s, code, "").Encode(), nil)
	at, _ := decode(t, body)["access_token"].(string)
	if resp.StatusCode != 200 || at == "" {
		t.Fatalf("status %d %s", resp.StatusCode, body)
	}
	mac := hmac.New(sha256.New, []byte(s.ClientSecret()))
	mac.Write([]byte(at))
	proof := hex.EncodeToString(mac.Sum(nil))
	q := url.Values{"access_token": {at}, "fields": {"id,name,email"}, "appsecret_proof": {proof}}
	resp, body = get(t, s.URL()+"/me?"+q.Encode(), nil)
	if u := decode(t, body); resp.StatusCode != 200 || u["id"] != "42" || u["email"] != "ann@example.com" {
		t.Fatalf("me %d %s", resp.StatusCode, body)
	}
	q.Set("appsecret_proof", "bad")
	if resp, _ = get(t, s.URL()+"/me?"+q.Encode(), nil); resp.StatusCode != 400 {
		t.Errorf("bad proof status %d", resp.StatusCode)
	}
	q.Del("appsecret_proof")
	if resp, _ = get(t, s.URL()+"/me?"+q.Encode(), nil); resp.StatusCode != 400 {
		t.Errorf("no proof status %d", resp.StatusCode)
	}
	// Bearer is accepted too, with the proof
	q = url.Values{"fields": {"id"}, "appsecret_proof": {proof}}
	if resp, _ = get(t, s.URL()+"/me?"+q.Encode(), map[string]string{"Authorization": "Bearer " + at}); resp.StatusCode != 200 {
		t.Errorf("bearer status %d", resp.StatusCode)
	}
}

func TestRecordsRequests(t *testing.T) {
	s, _ := newServer(t, mockidp.GitHub)
	get(t, s.URL()+"/user?x=1", map[string]string{"User-Agent": "ua-1"})
	r := s.Requests()
	if len(r) != 1 || r[0].Method != "GET" || r[0].Path != "/user" || r[0].Query.Get("x") != "1" || r[0].Header.Get("User-Agent") != "ua-1" {
		t.Errorf("requests = %+v", r)
	}
}

func TestFailToken(t *testing.T) {
	s, _ := newServer(t, mockidp.Generic)
	s.FailToken(1)
	if resp, _ := post(t, s.URL()+"/token", url.Values{"grant_type": {"authorization_code"}}, nil); resp.StatusCode != 500 {
		t.Errorf("first status %d, want 500", resp.StatusCode)
	}
	if resp, _ := post(t, s.URL()+"/token", url.Values{"grant_type": {"authorization_code"}}, nil); resp.StatusCode == 500 {
		t.Errorf("second status %d, want the normal answer", resp.StatusCode)
	}
	if s.TokenCalls() != 2 {
		t.Errorf("token calls = %d, want 2", s.TokenCalls())
	}
}

func TestFacebookTokenNeedsNoGrantType(t *testing.T) {
	s, _ := newServer(t, mockidp.Facebook)
	code := authorize(t, s, "/dialog/oauth", nil)
	f := tokenForm(s, code, "")
	f.Del("grant_type") // Facebook's token endpoint takes none
	resp, body := get(t, s.URL()+"/oauth/access_token?"+f.Encode(), nil)
	if resp.StatusCode != 200 || decode(t, body)["access_token"] == "" {
		t.Errorf("status %d %s", resp.StatusCode, body)
	}
	// the other profiles still require it
	g, _ := newServer(t, mockidp.Generic)
	gcode := authorize(t, g, "/authorize", nil)
	gf := tokenForm(g, gcode, "")
	gf.Del("grant_type")
	if resp, _ := post(t, g.URL()+"/token", gf, nil); resp.StatusCode != 400 {
		t.Errorf("generic without grant_type: status %d", resp.StatusCode)
	}
}

// ListenAt serves on the given address, and SetPublicURL names it
// (the conformance setup reaches it from containers by another name).
func TestListenAtPublicURL(t *testing.T) {
	s := mockidp.ListenAt(t, clock.Real(), mockidp.Generic, "127.0.0.1:0", "")
	s.SetPublicURL("http://mock.test:9999")
	if s.URL() != "http://mock.test:9999" {
		t.Fatalf("URL = %q", s.URL())
	}
	resp, body := get(t, "http://"+s.Addr()+"/.well-known/openid-configuration", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["issuer"] != "http://mock.test:9999" || doc["token_endpoint"] != "http://mock.test:9999/token" {
		t.Fatalf("discovery = %v", doc)
	}
}

// With a session, the server behaves like a provider that remembers its user:
// auth_time stays the same across sign-ins until prompt=login or an exceeded
// max_age starts a new session, whose auth_time is strictly later.
func TestSessionAuthTime(t *testing.T) {
	s, clk := newServer(t, mockidp.Generic)
	s.SetSession(true)
	authTime := func(extra url.Values) float64 {
		t.Helper()
		code := authorize(t, s, "/authorize", extra)
		_, body := post(t, s.URL()+"/token", tokenForm(s, code, ""), nil)
		claims, _ := claimsOf(t, decode(t, body)["id_token"].(string))
		return claims["auth_time"].(float64)
	}
	first := authTime(nil)
	if first != float64(clk.Now().Unix()) {
		t.Fatalf("first auth_time = %v, want now", first)
	}
	clk.Advance(5 * time.Second)
	if got := authTime(url.Values{"max_age": {"10000"}}); got != first {
		t.Errorf("max_age not exceeded: auth_time = %v, want %v", got, first)
	}
	if got := authTime(url.Values{"max_age": {"1"}}); got != first+5 {
		t.Errorf("max_age exceeded: auth_time = %v, want %v", got, first+5)
	}
	if got := authTime(url.Values{"prompt": {"login"}}); got != first+6 {
		t.Errorf("prompt=login in the same second: auth_time = %v, want strictly later %v", got, first+6)
	}
	if got := authTime(nil); got != first+6 {
		t.Errorf("no prompt: auth_time = %v, want %v", got, first+6)
	}
}

// The default public URL of a server started on port 0 is its real address.
func TestListenAtDefaultURLIsReachable(t *testing.T) {
	s := mockidp.ListenAt(t, clock.Real(), mockidp.Generic, "127.0.0.1:0", "")
	if s.URL() != "http://"+s.Addr() || strings.HasSuffix(s.URL(), ":0") {
		t.Fatalf("URL = %q, Addr = %q", s.URL(), s.Addr())
	}
	resp, body := get(t, s.URL()+"/.well-known/openid-configuration", nil)
	if resp.StatusCode != 200 || decode(t, body)["issuer"] != s.URL() {
		t.Fatalf("status %d body %s", resp.StatusCode, body)
	}
}

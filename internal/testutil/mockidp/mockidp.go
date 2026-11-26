// Package mockidp is a mock identity provider for tests: an httptest server
// that speaks enough of Google, Apple, GitHub, Facebook and generic OpenID
// Connect for the adapters, the handlers and the conformance setup to sign in
// against it. It is test support and only tests may import it.
//
// All routes exist on every server; the Profile decides the shape of the
// token response and the ID token:
//
//	GET  /.well-known/openid-configuration   discovery
//	GET  /authorize, /login/oauth/authorize, /dialog/oauth   authorize
//	POST /token, /login/oauth/access_token; GET/POST /oauth/access_token   token
//	GET  /userinfo                           OIDC user info
//	GET  /jwks                               signing keys
//	POST /revoke                             Apple's revoke
//	GET  /user, /user/emails                 GitHub API
//	GET  /me                                 Facebook Graph
//	GET  /risc-configuration, /risc-jwks     Google's RISC configuration and its keys (see RISCToken)
package mockidp

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/secure"
)

// Profile selects the provider the server imitates.
type Profile string

// The profiles.
const (
	Generic  Profile = "oidc"
	Google   Profile = "google"
	Apple    Profile = "apple"
	GitHub   Profile = "github"
	Facebook Profile = "facebook"
)

// AppleIssuer is the issuer of Apple's signed events and ID tokens; the mock
// signs events with it whatever its own URL is.
const AppleIssuer = "https://appleid.apple.com"

// Email is an entry of GitHub's /user/emails.
type Email struct {
	Email    string
	Primary  bool
	Verified bool
}

// User is the account the mock signs in.
type User struct {
	Sub  string
	Name string
	// Email is the address in the ID token, user info and Graph answer.
	Email string
	// EmailVerified is put in the ID token and user info as given, so a test
	// can pass a bool or the string "true"; nil leaves the claim out.
	EmailVerified any
	// IsPrivateEmail is Apple's claim, as given; nil leaves it out.
	IsPrivateEmail any
	// HD is Google's hosted domain claim; empty leaves it out.
	HD string
	// AuthTime is the auth_time claim; the zero time leaves it out.
	AuthTime time.Time
	// Emails is GitHub's /user/emails list.
	Emails []Email
}

// Request is a request the server received.
type Request struct {
	Method string
	Path   string
	Query  url.Values
	Header http.Header
	Form   url.Values // the form body, when it has one
}

// Authorization is one request to an authorize endpoint.
type Authorization struct {
	Params url.Values
	// Posted holds the values of the form POST answer (response_mode=form_post);
	// nil for a redirect answer.
	Posted url.Values
}

// Revocation is one call to /revoke.
type Revocation struct {
	Token  string
	Secret string
	Hint   string
}

type grant struct {
	challenge string
	redirect  string
	nonce     string
	user      User
}

type keyEntry struct {
	kid  string
	priv *ecdsa.PrivateKey
}

// Server is the mock identity provider.
type Server struct {
	srv   *httptest.Server
	base  string // the URL the server names itself with
	clock clock.Clock
	prof  Profile

	mu            sync.Mutex
	clientID      string
	secret        string
	secretCheck   func(string) error
	user          User
	authErr       string
	claimsFn      func(map[string]any)
	keys          []keyEntry
	keySeq        int
	failJWKS      int
	failToken     int
	jwksCalls     int
	tokenCalls    int
	seq           int
	grants        map[string]grant
	accessTok     map[string]User
	requests      []Request
	auths         []Authorization
	revokes       []Revocation
	lastRefresh   string
	noRefresh     bool
	session       bool
	sessionAt     time.Time
	release       chan struct{}
	blocked       chan struct{}
	redirects     map[string]string
	failRISC      int       // the next n RISC requests answer 500
	riscIssuer    string    // the issuer of the RISC document, when riscIssuerSet
	riscIssuerSet bool      // false means RISCIssuer
	riscOnce      sync.Once // makes riscKey on first use
	riscKey       *rsa.PrivateKey
}

// New starts a server for the profile and stops it when the test ends. The
// client id is "client-id" and the secret "client-secret"; the user is empty
// until SetUser.
func New(t testing.TB, clk clock.Clock, p Profile) *Server {
	t.Helper()
	return start(t, clk, p, "", "")
}

// ListenAt is New on the given listen address (such as "0.0.0.0:0"), naming
// itself with publicURL (such as "http://host.docker.internal:9000") instead
// of the loopback address, for a client that reaches it from another network
// namespace.
func ListenAt(t testing.TB, clk clock.Clock, p Profile, addr, publicURL string) *Server {
	t.Helper()
	return start(t, clk, p, addr, publicURL)
}

func start(t testing.TB, clk clock.Clock, p Profile, addr, publicURL string) *Server {
	t.Helper()
	s := &Server{
		clock: clk, prof: p, clientID: "client-id", secret: "client-secret",
		grants: map[string]grant{}, accessTok: map[string]User{}, blocked: make(chan struct{}, 64),
	}
	s.RotateKey()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", s.discovery)
	for _, p := range []string{"/authorize", "/login/oauth/authorize", "/dialog/oauth"} {
		mux.HandleFunc("GET "+p, s.authorize)
	}
	for _, p := range []string{"/token", "/login/oauth/access_token", "/oauth/access_token"} {
		mux.HandleFunc(p, s.token)
	}
	mux.HandleFunc("GET /userinfo", s.userinfo)
	mux.HandleFunc("GET /jwks", s.jwks)
	mux.HandleFunc("POST /revoke", s.revoke)
	mux.HandleFunc("GET /user", s.githubUser)
	mux.HandleFunc("GET /user/emails", s.githubEmails)
	mux.HandleFunc("GET /me", s.graphMe)
	mux.HandleFunc("GET "+RISCConfigPath, s.riscConfig)
	mux.HandleFunc("GET /risc-jwks", s.riscJWKS)
	if addr == "" {
		s.srv = httptest.NewServer(s.record(mux))
		s.base = s.srv.URL
	} else {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			t.Fatalf("mockidp: listen %s: %v", addr, err)
		}
		s.srv = httptest.NewUnstartedServer(s.record(mux))
		_ = s.srv.Listener.Close()
		s.srv.Listener = ln
		s.base = publicURL
		if s.base == "" {
			s.base = "http://" + ln.Addr().String()
		}
		s.srv.Start()
	}
	t.Cleanup(func() { s.Unblock(); s.srv.Close() })
	return s
}

// URL is the server's base URL and, for the OIDC profiles, its issuer.
func (s *Server) URL() string { s.mu.Lock(); defer s.mu.Unlock(); return s.base }

// SetPublicURL changes the URL the server names itself with, for a server
// started on port 0 whose public URL names the port.
func (s *Server) SetPublicURL(u string) { s.mu.Lock(); defer s.mu.Unlock(); s.base = u }

// Addr is the address the server listens on.
func (s *Server) Addr() string { return s.srv.Listener.Addr().String() }

// ClientID is the client id the server accepts.
func (s *Server) ClientID() string { s.mu.Lock(); defer s.mu.Unlock(); return s.clientID }

// ClientSecret is the client secret the server accepts.
func (s *Server) ClientSecret() string { s.mu.Lock(); defer s.mu.Unlock(); return s.secret }

// SetCredentials changes the client id and secret the server accepts.
func (s *Server) SetCredentials(id, secret string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clientID, s.secret = id, secret
}

// SetSecretCheck replaces the comparison with the configured secret, for
// Apple's generated client secret: fn gets the secret the client sent and
// returns an error to refuse it.
func (s *Server) SetSecretCheck(fn func(secret string) error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.secretCheck = fn
}

// SetUser sets the account that later authorizations sign in.
func (s *Server) SetUser(u User) { s.mu.Lock(); defer s.mu.Unlock(); s.user = u }

// SetSession makes the server remember its user like a provider with its own
// browser session: the ID token's auth_time is the start of the session, which
// a request with prompt=login, or with a max_age the session has outlived,
// replaces with a start strictly later than the last one.
func (s *Server) SetSession(on bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.session, s.sessionAt = on, time.Time{}
}

// SetAuthorizeError makes the authorize endpoint answer with this error code
// (such as "access_denied") instead of a code; "" restores the normal answer.
func (s *Server) SetAuthorizeError(code string) { s.mu.Lock(); defer s.mu.Unlock(); s.authErr = code }

// SetIDTokenClaims lets fn change the claims of every ID token before it is
// signed (a wrong aud, iss, exp or nonce, a missing claim).
func (s *Server) SetIDTokenClaims(fn func(claims map[string]any)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.claimsFn = fn
}

// RotateKey adds a new signing key. New tokens use it; the old keys stay in
// the JWKS until RetireOldKeys.
func (s *Server) RotateKey() {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), secure.Default)
	if err != nil {
		panic(err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keySeq++
	s.keys = append(s.keys, keyEntry{kid: fmt.Sprintf("key-%d", s.keySeq), priv: priv})
}

// RetireOldKeys removes every key but the newest from the JWKS.
func (s *Server) RetireOldKeys() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys = s.keys[len(s.keys)-1:]
}

// FailJWKS makes the next n JWKS requests answer 500.
func (s *Server) FailJWKS(n int) { s.mu.Lock(); defer s.mu.Unlock(); s.failJWKS = n }

// FailToken makes the next n token requests answer 500.
func (s *Server) FailToken(n int) { s.mu.Lock(); defer s.mu.Unlock(); s.failToken = n }

// Block makes the token, JWKS, user-info, revoke and API endpoints hold every
// request until Unblock or until the caller gives up, which is how a test
// makes a provider time out without sleeping.
func (s *Server) Block() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.release == nil {
		s.release = make(chan struct{})
	}
}

// Unblock releases the held requests and stops holding new ones.
func (s *Server) Unblock() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.release != nil {
		close(s.release)
		s.release = nil
	}
}

// RedirectTo makes an endpoint answer 302 with target as its Location, as a
// provider that redirects would, and "" restores the normal answer. The
// endpoints are "discovery", "token", "jwks", "userinfo", "revoke" and "api"
// (the GitHub user and email APIs and the Graph profile call). The request is
// recorded, and nothing else happens at the mock.
func (s *Server) RedirectTo(endpoint, target string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.redirects == nil {
		s.redirects = map[string]string{}
	}
	if target == "" {
		delete(s.redirects, endpoint)
		return
	}
	s.redirects[endpoint] = target
}

// redirected answers 302 to the target set for endpoint and reports whether it
// did, so a handler returns at once.
func (s *Server) redirected(w http.ResponseWriter, endpoint string) bool {
	s.mu.Lock()
	target := s.redirects[endpoint]
	s.mu.Unlock()
	if target == "" {
		return false
	}
	w.Header().Set("Location", target)
	w.WriteHeader(http.StatusFound)
	return true
}

// Blocked receives once for each request that has reached a blocked endpoint.
func (s *Server) Blocked() <-chan struct{} { return s.blocked }

// TokenCalls is the number of requests the token endpoints received.
func (s *Server) TokenCalls() int { s.mu.Lock(); defer s.mu.Unlock(); return s.tokenCalls }

// JWKSCalls is the number of requests the JWKS endpoint received.
func (s *Server) JWKSCalls() int { s.mu.Lock(); defer s.mu.Unlock(); return s.jwksCalls }

// Requests returns every request received, oldest first.
func (s *Server) Requests() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Request(nil), s.requests...)
}

// Authorizations returns every authorize request received, oldest first.
func (s *Server) Authorizations() []Authorization {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Authorization(nil), s.auths...)
}

// RefreshToken returns the refresh token the Apple token endpoint gave last;
// empty before the first.
func (s *Server) RefreshToken() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastRefresh
}

// OmitRefreshToken makes the Apple token endpoint answer without a refresh
// token (or with one again).
func (s *Server) OmitRefreshToken(omit bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.noRefresh = omit
}

// Revocations returns every call to /revoke, oldest first.
func (s *Server) Revocations() []Revocation {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Revocation(nil), s.revokes...)
}

// IDToken returns an ID token for the current user, audience and nonce, as
// the token endpoint would issue it.
func (s *Server) IDToken(nonce string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.idToken(s.user, nonce)
}

// SignedEvent returns the body Apple would post for an account event: a JSON
// object whose payload is a JWT signed with the server's key.
func (s *Server) SignedEvent(aud, eventType, sub string) string {
	s.mu.Lock()
	now := s.clock.Now()
	inner, _ := json.Marshal(map[string]any{"type": eventType, "sub": sub, "event_time": now.UnixMilli()})
	claims := map[string]any{
		"iss": AppleIssuer, "aud": aud, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
		"jti": s.next("evt"), "events": string(inner),
	}
	s.mu.Unlock()
	return s.SignedClaims(claims)
}

// SignedClaims returns the body of an event post whose payload is a JWT with
// exactly these claims, signed with the server's key, for tests of a payload
// that is wrong in one claim.
func (s *Server) SignedClaims(claims map[string]any) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	body, _ := json.Marshal(map[string]string{"payload": s.sign(claims)})
	return string(body)
}

// next returns a fresh opaque value; the caller holds s.mu.
func (s *Server) next(prefix string) string {
	s.seq++
	tok, err := secure.Token(secure.Default, 16)
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf("%s-%d-%s", prefix, s.seq, tok)
}

// sign signs claims with the newest key; the caller holds s.mu.
func (s *Server) sign(claims map[string]any) string {
	k := s.keys[len(s.keys)-1]
	payload, err := json.Marshal(claims)
	if err != nil {
		panic(err)
	}
	h := jws.NewHeaders()
	if err := h.Set(jws.KeyIDKey, k.kid); err != nil {
		panic(err)
	}
	out, err := jws.Sign(payload, jws.WithKey(jwa.ES256(), k.priv, jws.WithProtectedHeaders(h)))
	if err != nil {
		panic(err)
	}
	return string(out)
}

// idToken builds and signs an ID token; the caller holds s.mu.
func (s *Server) idToken(u User, nonce string) string {
	now := s.clock.Now()
	c := map[string]any{
		"iss": s.base, "sub": u.Sub, "aud": s.clientID,
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
	}
	if s.prof == Apple {
		c["iss"] = AppleIssuer
	}
	set := func(k string, v any) {
		if v != nil {
			c[k] = v
		}
	}
	if nonce != "" {
		c["nonce"] = nonce
	}
	if u.Email != "" {
		c["email"] = u.Email
	}
	set("email_verified", u.EmailVerified)
	set("is_private_email", u.IsPrivateEmail)
	if u.Name != "" {
		c["name"] = u.Name
	}
	if u.HD != "" {
		c["hd"] = u.HD
	}
	if !u.AuthTime.IsZero() {
		c["auth_time"] = u.AuthTime.Unix()
	}
	if s.claimsFn != nil {
		s.claimsFn(c)
	}
	return s.sign(c)
}

// record logs each request and keeps its form body readable for the handler.
func (s *Server) record(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
		r.Body = io.NopCloser(bytes.NewReader(body))
		req := Request{Method: r.Method, Path: r.URL.Path, Query: r.URL.Query(), Header: r.Header.Clone()}
		if strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
			req.Form, _ = url.ParseQuery(string(body))
		}
		s.mu.Lock()
		s.requests = append(s.requests, req)
		s.mu.Unlock()
		next.ServeHTTP(w, r)
	})
}

// hold waits while the server is blocked; it reports false when the caller
// gave up first.
func (s *Server) hold(r *http.Request) bool {
	s.mu.Lock()
	rel := s.release
	s.mu.Unlock()
	if rel == nil {
		return true
	}
	select {
	case s.blocked <- struct{}{}:
	default:
	}
	select {
	case <-rel:
		return true
	case <-r.Context().Done():
		return false
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func oauthError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}

func (s *Server) discovery(w http.ResponseWriter, _ *http.Request) {
	if s.redirected(w, "discovery") {
		return
	}
	u := s.URL()
	writeJSON(w, 200, map[string]any{
		"issuer": u, "authorization_endpoint": u + "/authorize", "token_endpoint": u + "/token",
		"jwks_uri": u + "/jwks", "userinfo_endpoint": u + "/userinfo",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"ES256"},
		"code_challenge_methods_supported":      []string{"S256"},
	})
}

func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	s.mu.Lock()
	rec := Authorization{Params: q}
	redirect := q.Get("redirect_uri")
	if q.Get("client_id") != s.clientID || redirect == "" {
		s.auths = append(s.auths, rec)
		s.mu.Unlock()
		http.Error(w, "bad client_id or redirect_uri", http.StatusBadRequest)
		return
	}
	out := url.Values{}
	if q.Get("state") != "" {
		out.Set("state", q.Get("state"))
	}
	if s.authErr != "" {
		out.Set("error", s.authErr)
	} else {
		code := s.next("code")
		u := s.user
		if s.session {
			u.AuthTime = s.sessionFor(q)
		}
		s.grants[code] = grant{challenge: q.Get("code_challenge"), redirect: redirect, nonce: q.Get("nonce"), user: u}
		out.Set("code", code)
		if s.prof == Apple && q.Get("response_mode") == "form_post" {
			out.Set("id_token", s.idToken(u, q.Get("nonce")))
			if s.user.Email != "" || s.user.Name != "" {
				first, last, _ := strings.Cut(s.user.Name, " ")
				u, _ := json.Marshal(map[string]any{"name": map[string]string{"firstName": first, "lastName": last}, "email": s.user.Email})
				out.Set("user", string(u))
			}
		}
	}
	formPost := s.prof == Apple && q.Get("response_mode") == "form_post"
	if formPost {
		rec.Posted = out
	}
	s.auths = append(s.auths, rec)
	s.mu.Unlock()

	if formPost {
		var b strings.Builder
		fmt.Fprintf(&b, `<html><body onload="document.forms[0].submit()"><form method="post" action="%s">`, html.EscapeString(redirect))
		for k, v := range out {
			fmt.Fprintf(&b, `<input type="hidden" name="%s" value="%s">`, html.EscapeString(k), html.EscapeString(v[0]))
		}
		b.WriteString(`</form></body></html>`)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, b.String())
		return
	}
	loc, err := url.Parse(redirect)
	if err != nil {
		http.Error(w, "bad redirect_uri", http.StatusBadRequest)
		return
	}
	lq := loc.Query()
	for k, v := range out {
		lq.Set(k, v[0])
	}
	loc.RawQuery = lq.Encode()
	http.Redirect(w, r, loc.String(), http.StatusFound)
}

// sessionFor returns the start of the session this request signs in with; the
// caller holds s.mu.
func (s *Server) sessionFor(q url.Values) time.Time {
	now := s.clock.Now().Truncate(time.Second)
	maxAge, err := strconv.Atoi(q.Get("max_age"))
	expired := err == nil && s.clock.Now().Sub(s.sessionAt) > time.Duration(maxAge)*time.Second
	if s.sessionAt.IsZero() || q.Get("prompt") == "login" || expired {
		if !now.After(s.sessionAt) {
			now = s.sessionAt.Add(time.Second)
		}
		s.sessionAt = now
	}
	return s.sessionAt
}

// clientAuth returns the client id and secret of the request, from the Basic
// header or the form; the caller holds s.mu.
func clientAuth(r *http.Request) (id, secret string) {
	if u, p, ok := r.BasicAuth(); ok {
		return u, p
	}
	return r.Form.Get("client_id"), r.Form.Get("client_secret")
}

// secretOK reports whether the client credentials are right; the caller holds s.mu.
func (s *Server) secretOK(id, secret string) bool {
	if id != s.clientID {
		return false
	}
	if s.secretCheck != nil {
		return s.secretCheck(secret) == nil
	}
	return secure.Equal(secret, s.secret)
}

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	if s.redirected(w, "token") {
		return
	}
	_ = r.ParseForm()
	s.mu.Lock()
	s.tokenCalls++
	s.mu.Unlock()
	if !s.hold(r) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failToken > 0 {
		s.failToken--
		oauthError(w, 500, "server_error")
		return
	}
	id, secret := clientAuth(r)
	if !s.secretOK(id, secret) {
		oauthError(w, http.StatusUnauthorized, "invalid_client")
		return
	}
	if r.Form.Get("grant_type") != "authorization_code" && s.prof != Facebook { // Facebook takes no grant_type
		oauthError(w, 400, "unsupported_grant_type")
		return
	}
	code := r.Form.Get("code")
	g, ok := s.grants[code]
	if !ok {
		oauthError(w, 400, "invalid_grant")
		return
	}
	delete(s.grants, code) // single use, whether or not the rest checks out
	verifier := r.Form.Get("code_verifier")
	if r.Form.Get("redirect_uri") != g.redirect {
		oauthError(w, 400, "invalid_grant")
		return
	}
	if g.challenge == "" && verifier != "" {
		oauthError(w, 400, "invalid_grant") // a verifier without a challenge is a downgrade
		return
	}
	if g.challenge != "" {
		sum := sha256.Sum256([]byte(verifier))
		if verifier == "" || !secure.Equal(base64.RawURLEncoding.EncodeToString(sum[:]), g.challenge) {
			oauthError(w, 400, "invalid_grant")
			return
		}
	}
	at := s.next("at")
	s.accessTok[at] = g.user
	resp := map[string]any{"access_token": at, "token_type": "Bearer", "expires_in": 3600}
	switch s.prof {
	case GitHub:
		resp["token_type"] = "bearer"
		resp["scope"] = "user:email"
		if !strings.Contains(r.Header.Get("Accept"), "application/json") {
			w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
			_, _ = io.WriteString(w, url.Values{"access_token": {at}, "token_type": {"bearer"}, "scope": {"user:email"}}.Encode())
			return
		}
	case Facebook:
	case Apple:
		if !s.noRefresh {
			s.lastRefresh = s.next("rt")
			resp["refresh_token"] = s.lastRefresh
		}
		resp["id_token"] = s.idToken(g.user, g.nonce)
	default:
		resp["id_token"] = s.idToken(g.user, g.nonce)
	}
	writeJSON(w, 200, resp)
}

// bearer returns the access token of the request, from the Authorization
// header or the access_token query parameter.
func bearer(r *http.Request) string {
	if h := r.Header.Get("Authorization"); h != "" {
		_, tok, _ := strings.Cut(h, " ")
		return tok
	}
	return r.URL.Query().Get("access_token")
}

// userFor returns the user an access token belongs to, after the blocking
// check; ok is false when the response was already written.
func (s *Server) userFor(w http.ResponseWriter, r *http.Request) (User, string, bool) {
	if !s.hold(r) {
		return User{}, "", false
	}
	tok := bearer(r)
	s.mu.Lock()
	u, ok := s.accessTok[tok]
	s.mu.Unlock()
	if !ok {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		oauthError(w, 401, "invalid_token")
		return User{}, "", false
	}
	return u, tok, true
}

func (s *Server) userinfo(w http.ResponseWriter, r *http.Request) {
	if s.redirected(w, "userinfo") {
		return
	}
	u, _, ok := s.userFor(w, r)
	if !ok {
		return
	}
	c := map[string]any{"sub": u.Sub}
	if u.Email != "" {
		c["email"] = u.Email
	}
	if u.EmailVerified != nil {
		c["email_verified"] = u.EmailVerified
	}
	if u.Name != "" {
		c["name"] = u.Name
	}
	writeJSON(w, 200, c)
}

func (s *Server) jwks(w http.ResponseWriter, r *http.Request) {
	if s.redirected(w, "jwks") {
		return
	}
	if !s.hold(r) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.jwksCalls++
	if s.failJWKS > 0 {
		s.failJWKS--
		oauthError(w, 500, "server_error")
		return
	}
	set := jwk.NewSet()
	for _, k := range s.keys {
		pub, err := jwk.Import(&k.priv.PublicKey)
		if err != nil {
			panic(err)
		}
		for name, v := range map[string]any{jwk.KeyIDKey: k.kid, jwk.AlgorithmKey: "ES256", jwk.KeyUsageKey: "sig"} {
			if err := pub.Set(name, v); err != nil {
				panic(err)
			}
		}
		if err := set.AddKey(pub); err != nil {
			panic(err)
		}
	}
	writeJSON(w, 200, set)
}

func (s *Server) revoke(w http.ResponseWriter, r *http.Request) {
	if s.redirected(w, "revoke") {
		return
	}
	_ = r.ParseForm()
	if !s.hold(r) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	id, secret := clientAuth(r)
	if !s.secretOK(id, secret) {
		oauthError(w, 401, "invalid_client")
		return
	}
	s.revokes = append(s.revokes, Revocation{Token: r.Form.Get("token"), Secret: secret, Hint: r.Form.Get("token_type_hint")})
	w.WriteHeader(200)
}

func (s *Server) githubUser(w http.ResponseWriter, r *http.Request) {
	if s.redirected(w, "api") {
		return
	}
	if r.Header.Get("User-Agent") == "" || strings.HasPrefix(r.Header.Get("User-Agent"), "Go-http-client") {
		http.Error(w, "a User-Agent header is required", http.StatusForbidden)
		return
	}
	u, _, ok := s.userFor(w, r)
	if !ok {
		return
	}
	var id any = u.Sub
	if n, err := strconv.ParseInt(u.Sub, 10, 64); err == nil {
		id = n
	}
	body := map[string]any{"id": id, "login": "user-" + u.Sub, "name": u.Name}
	for _, e := range u.Emails {
		if e.Primary {
			body["email"] = e.Email
		}
	}
	writeJSON(w, 200, body)
}

func (s *Server) githubEmails(w http.ResponseWriter, r *http.Request) {
	if s.redirected(w, "api") {
		return
	}
	if r.Header.Get("User-Agent") == "" || strings.HasPrefix(r.Header.Get("User-Agent"), "Go-http-client") {
		http.Error(w, "a User-Agent header is required", http.StatusForbidden)
		return
	}
	u, _, ok := s.userFor(w, r)
	if !ok {
		return
	}
	out := make([]map[string]any, 0, len(u.Emails))
	for _, e := range u.Emails {
		out = append(out, map[string]any{"email": e.Email, "primary": e.Primary, "verified": e.Verified, "visibility": nil})
	}
	writeJSON(w, 200, out)
}

func (s *Server) graphMe(w http.ResponseWriter, r *http.Request) {
	if s.redirected(w, "api") {
		return
	}
	if !s.hold(r) {
		return
	}
	tok := bearer(r)
	s.mu.Lock()
	u, known := s.accessTok[tok]
	secret := s.secret
	s.mu.Unlock()
	graphErr := func(msg string) {
		writeJSON(w, 400, map[string]any{"error": map[string]any{"message": msg, "type": "OAuthException", "code": 100}})
	}
	if !known {
		graphErr("Invalid OAuth access token.")
		return
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(tok))
	if !hmac.Equal([]byte(hex.EncodeToString(mac.Sum(nil))), []byte(r.URL.Query().Get("appsecret_proof"))) {
		graphErr("Invalid appsecret_proof provided in the API argument")
		return
	}
	fields := map[string]bool{}
	for _, f := range strings.Split(r.URL.Query().Get("fields"), ",") {
		fields[f] = true
	}
	body := map[string]any{"id": u.Sub}
	if fields["name"] && u.Name != "" {
		body["name"] = u.Name
	}
	if fields["email"] && u.Email != "" {
		body["email"] = u.Email
	}
	writeJSON(w, 200, body)
}

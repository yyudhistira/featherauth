package oidc

import (
	"maps"
	"math"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/yyudhistira/featherauth/internal/config"
)

// AuthRequest is a checked authorization request. The optional fields are
// empty (nil for MaxAge) when the client sent nothing.
type AuthRequest struct {
	Realm    *config.Realm
	ClientID config.ClientID
	Client   *config.Client
	// RedirectURI is the URI the request named, which matched the client's
	// registered URIs (a loopback URI of a public client may differ in port).
	RedirectURI string
	// State is the client's state, echoed in every answer; empty when the
	// client sent none.
	State         string
	Nonce         string
	CodeChallenge string
	// ResponseMode is the request's, else the client's setting.
	ResponseMode ResponseMode
	// Prompt is the first of "login", "select_account" and "consent" the
	// request names; "none" is answered by ParseAuthorization itself.
	Prompt string
	// PromptNone is set when the request names prompt=none, which the endpoint
	// answers from a browser session or with login_required (FR-45).
	PromptNone bool
	MaxAge     *time.Duration
	LoginHint  string
	// Hint is the provider hint: the value of the first name in
	// login.provider_hint_params the request carries.
	Hint string
}

// PageError is a request that cannot be answered by redirecting: the client,
// the redirect URI or the response mode is not known to be valid, so the
// answer is the HTML error page (Errors in the authorization request).
type PageError struct {
	// Status is the HTTP status of the page.
	Status int
	// MessageID is the id of the explanation (web.English).
	MessageID string
	// Reason says what was wrong, for the log; it is never shown.
	Reason string
}

// Error implements error.
func (e *PageError) Error() string { return "oidc: authorization request: " + e.Reason }

var _ error = (*PageError)(nil)

// RedirectError is a request error that is delivered to the client's redirect
// URI in the request's response mode, with the realm's iss and State when the
// client sent one.
type RedirectError struct {
	Err         Error
	Mode        ResponseMode
	RedirectURI string
	State       string
}

// Error implements error.
func (e *RedirectError) Error() string { return e.Err.Error() }

var _ error = (*RedirectError)(nil)

// Values is the result to deliver: error, error_description, state when the
// request sent one, and iss.
func (e *RedirectError) Values(iss string) url.Values {
	v := url.Values{"error": {e.Err.Code}, "iss": {iss}}
	if e.Err.Description != "" {
		v.Set("error_description", e.Err.Description)
	}
	if e.State != "" {
		v.Set("state", e.State)
	}
	return v
}

func pageError(reason string) *PageError {
	return &PageError{Status: 400, MessageID: "error.invalid_request", Reason: reason}
}

// maxAgeLimit is the largest max_age, in seconds, that fits a time.Duration.
const maxAgeLimit = int64(math.MaxInt64 / int64(time.Second))

// ParseAuthorization checks an authorization request, from the query of a GET
// or the form of a POST, in the order of "Errors in the authorization
// request". It returns the request, or the page error (no redirect is safe) or
// the redirect error to answer with; exactly one of the three results is set.
// prompt=none is answered login_required here: the endpoint itself uses
// checkAuthorization, which leaves prompt=none to the browser session (FR-45).
func ParseAuthorization(r *config.Realm, v url.Values) (AuthRequest, *PageError, *RedirectError) {
	return checkAuthorization(r, v, false)
}

// checkAuthorization is ParseAuthorization. With silent set, prompt=none is not
// an error: the request is returned with PromptNone set, and the endpoint decides
// it from the browser session.
func checkAuthorization(r *config.Realm, v url.Values, silent bool) (AuthRequest, *PageError, *RedirectError) {
	// Until the client, the redirect URI and the response mode are valid there
	// is nobody safe to redirect to.
	id, ok := single(v, "client_id")
	if !ok || id == "" {
		return AuthRequest{}, pageError("client_id is missing or repeated"), nil
	}
	client, ok := r.Clients[config.ClientID(id)]
	if !ok {
		return AuthRequest{}, pageError("client_id is unknown"), nil
	}
	uri, ok := single(v, "redirect_uri")
	if !ok || !redirectURIAllowed(client, uri) {
		return AuthRequest{}, pageError("redirect_uri is missing, repeated or not registered"), nil
	}

	mode, _ := ParseResponseMode(client.ResponseMode)
	if mode == "" {
		mode = ModeQuery
	}
	// A repeated response_mode names none that can be trusted: it is an
	// invalid_request below, delivered the way the client asks for by default.
	if modes := v["response_mode"]; len(modes) == 1 {
		m, ok := ParseResponseMode(modes[0])
		if !ok {
			return AuthRequest{}, pageError("response_mode is not supported"), nil
		}
		mode = m
	}

	state := ""
	if s := v["state"]; len(s) == 1 {
		state = s[0]
	}
	fail := func(code, description string) (AuthRequest, *PageError, *RedirectError) {
		return AuthRequest{}, nil, &RedirectError{
			Err: Error{Code: code, Description: description}, Mode: mode, RedirectURI: uri, State: state,
		}
	}

	for _, k := range slices.Sorted(maps.Keys(v)) {
		if len(v[k]) > 1 {
			return fail("invalid_request", "the parameter "+k+" is repeated")
		}
	}
	rt, present := v["response_type"]
	if !present {
		return fail("invalid_request", "response_type is missing")
	}
	if rt[0] != "code" {
		return fail("unsupported_response_type", "only response_type=code is supported")
	}
	if !slices.Contains(strings.Fields(v.Get("scope")), "openid") {
		return fail("invalid_scope", "the scope must contain openid")
	}
	if v.Has("request") {
		return fail("request_not_supported", "the request parameter is not supported")
	}
	if v.Has("request_uri") {
		return fail("request_uri_not_supported", "the request_uri parameter is not supported")
	}

	prompts := strings.Fields(v.Get("prompt"))
	if slices.Contains(prompts, "none") && len(slices.DeleteFunc(slices.Clone(prompts), func(p string) bool { return p == "none" })) > 0 {
		return fail("invalid_request", "prompt=none cannot be combined with another prompt value")
	}
	var maxAge *time.Duration
	if v.Has("max_age") {
		d, ok := parseMaxAge(v.Get("max_age"))
		if !ok {
			return fail("invalid_request", "max_age must be a whole number of seconds, 0 or more")
		}
		maxAge = &d
	}

	challenge := v.Get("code_challenge")
	if v.Has("code_challenge_method") && v.Get("code_challenge_method") != "S256" {
		return fail("invalid_request", "code_challenge_method must be S256")
	}
	if v.Has("code_challenge") {
		if !v.Has("code_challenge_method") {
			return fail("invalid_request", "code_challenge needs code_challenge_method=S256")
		}
		if !validChallenge(challenge) {
			return fail("invalid_request", "code_challenge must be 43 base64url characters")
		}
	} else if client.RequirePKCE {
		return fail("invalid_request", "code_challenge is required")
	}
	promptNone := slices.Contains(prompts, "none")
	if promptNone && !silent {
		return fail("login_required", "there is no session to reuse")
	}

	req := AuthRequest{
		Realm: r, ClientID: config.ClientID(id), Client: client, RedirectURI: uri, State: state,
		Nonce: v.Get("nonce"), CodeChallenge: challenge, ResponseMode: mode, MaxAge: maxAge,
		LoginHint: v.Get("login_hint"), PromptNone: promptNone,
	}
	for _, p := range prompts {
		if p == "login" || p == "select_account" || p == "consent" {
			req.Prompt = p
			break
		}
	}
	for _, name := range r.ProviderHintParams() {
		if h := v.Get(name); h != "" {
			req.Hint = h
			break
		}
	}
	return req, nil, nil
}

// single returns the value of a parameter that is present exactly once.
func single(v url.Values, k string) (string, bool) {
	vs := v[k]
	if len(vs) != 1 {
		return "", false
	}
	return vs[0], true
}

// parseMaxAge reads digits only: a whole number of seconds, 0 or more.
func parseMaxAge(s string) (time.Duration, bool) {
	if s == "" {
		return 0, false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n > maxAgeLimit {
		return 0, false
	}
	return time.Duration(n) * time.Second, true
}

// validChallenge reports whether s is 43 unpadded base64url characters, the
// size of a SHA-256 digest.
func validChallenge(s string) bool {
	if len(s) != 43 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

// redirectURIAllowed matches uri against the client's registered URIs:
// exactly, or for a public client a loopback URI that differs from a
// registered one only in its port (SEC-02, RFC 8252 section 7.3).
func redirectURIAllowed(c *config.Client, uri string) bool {
	if uri == "" {
		return false
	}
	if slices.Contains(c.RedirectURIs, uri) {
		return true
	}
	if c.Type != config.Public {
		return false
	}
	u, ok := loopbackURL(uri)
	if !ok {
		return false
	}
	for _, reg := range c.RedirectURIs {
		if r, ok := loopbackURL(reg); ok && r.Hostname() == u.Hostname() && r.EscapedPath() == u.EscapedPath() && r.RawQuery == u.RawQuery {
			return true
		}
	}
	return false
}

// loopbackURL parses an http URI on 127.0.0.1 or [::1] that has no user info,
// fragment or invalid port.
func loopbackURL(s string) (*url.URL, bool) {
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "http" || u.User != nil || u.Fragment != "" || strings.Contains(s, "#") {
		return nil, false
	}
	if h := u.Hostname(); h != "127.0.0.1" && h != "::1" {
		return nil, false
	}
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return nil, false
		}
	}
	return u, true
}

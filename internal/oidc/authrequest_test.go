package oidc_test

import (
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/oidc"
)

// Covers: FR-02 (part), FR-03 (part)
// Acceptance: Request errors (part)
// Acceptance: Redirect URI (part)
func TestParseAuthorizationPageErrors(t *testing.T) {
	realm := authzRealm(t)
	tests := []struct {
		name string
		v    url.Values
	}{
		{"client_id missing", goodRequest("client_id", "-")},
		{"client_id empty", goodRequest("client_id", "")},
		{"client_id unknown", goodRequest("client_id", "nobody")},
		{"client_id repeated", withExtra(goodRequest(), "client_id", "web")},
		{"redirect_uri missing", goodRequest("redirect_uri", "-")},
		{"redirect_uri empty", goodRequest("redirect_uri", "")},
		{"redirect_uri repeated", withExtra(goodRequest(), "redirect_uri", "https://app.example.com/callback")},
		{"redirect_uri other path", goodRequest("redirect_uri", "https://app.example.com/other")},
		{"redirect_uri trailing slash", goodRequest("redirect_uri", "https://app.example.com/callback/")},
		{"redirect_uri other host", goodRequest("redirect_uri", "https://evil.example.com/callback")},
		{"redirect_uri other scheme", goodRequest("redirect_uri", "http://app.example.com/callback")},
		{"redirect_uri with a query", goodRequest("redirect_uri", "https://app.example.com/callback?x=1")},
		{"redirect_uri of another client", goodRequest("redirect_uri", "https://srv.example.com/callback")},
		{"redirect_uri upper case", goodRequest("redirect_uri", "https://app.example.com/CALLBACK")},
		{"response_mode unknown", goodRequest("response_mode", "web_message")},
		{"response_mode empty", goodRequest("response_mode", "")},
		{"response_mode upper case", goodRequest("response_mode", "QUERY")},
		// The page errors come first: later problems do not turn them into redirects.
		{"unknown client and no response_type", goodRequest("client_id", "nobody", "response_type", "-")},
		{"bad redirect_uri and unsupported response_type", goodRequest("redirect_uri", "https://x.example.com/", "response_type", "token")},
		{"bad response_mode and no scope", goodRequest("response_mode", "nope", "scope", "-")},
		{"bad response_mode and prompt=none", goodRequest("response_mode", "nope", "prompt", "none")},
	}
	for _, mode := range []string{"", "fragment"} {
		for _, tt := range tests {
			t.Run(tt.name+"/"+mode, func(t *testing.T) {
				v := tt.v
				if mode != "" && v.Get("response_mode") == "" && !v.Has("response_mode") {
					v = cloneValues(v)
					v.Set("response_mode", mode)
				}
				_, page, redir := oidc.ParseAuthorization(realm, v)
				if page == nil || redir != nil {
					t.Fatalf("page %v, redirect %v; want a page error only", page, redir)
				}
				if page.Status != 400 || page.MessageID != "error.invalid_request" {
					t.Errorf("page error %+v", page)
				}
			})
		}
	}
}

func withExtra(v url.Values, k, val string) url.Values {
	v = cloneValues(v)
	v.Add(k, val)
	return v
}

func cloneValues(v url.Values) url.Values {
	out := url.Values{}
	for k, vs := range v {
		out[k] = append([]string(nil), vs...)
	}
	return out
}

// Covers: FR-02 (part), SEC-01 (part)
// Acceptance: Request errors (part)
// Acceptance: Scope handling (part)
// Acceptance: prompt=none (part)
// Acceptance: PKCE for every client (part)
func TestParseAuthorizationRedirectErrors(t *testing.T) {
	realm := authzRealm(t)
	long := challenge + "A"
	tests := []struct {
		name string
		v    url.Values
		code string
	}{
		{"response_type missing", goodRequest("response_type", "-"), "invalid_request"},
		{"response_type repeated", withExtra(goodRequest(), "response_type", "code"), "invalid_request"},
		{"state repeated", withExtra(goodRequest(), "state", "again"), "invalid_request"},
		{"nonce repeated", withExtra(goodRequest(), "nonce", "again"), "invalid_request"},
		{"scope repeated", withExtra(goodRequest(), "scope", "openid"), "invalid_request"},
		{"an unknown parameter repeated", withExtra(goodRequest("ui_locales", "nl"), "ui_locales", "en"), "invalid_request"},
		{"provider hint repeated", withExtra(goodRequest("provider", "google"), "provider", "github"), "invalid_request"},
		{"repeated parameter comes before response_type", withExtra(goodRequest("response_type", "token"), "nonce", "x"), "invalid_request"},
		{"response_type token", goodRequest("response_type", "token"), "unsupported_response_type"},
		{"response_type code token", goodRequest("response_type", "code token"), "unsupported_response_type"},
		{"response_type empty", goodRequest("response_type", ""), "unsupported_response_type"},
		{"scope missing", goodRequest("scope", "-"), "invalid_scope"},
		{"scope empty", goodRequest("scope", ""), "invalid_scope"},
		{"scope without openid", goodRequest("scope", "profile email"), "invalid_scope"},
		{"scope openid as a prefix", goodRequest("scope", "openidx"), "invalid_scope"},
		{"scope openid in another case", goodRequest("scope", "OpenID"), "invalid_scope"},
		{"scope before request", goodRequest("scope", "-", "request", "eyJ"), "invalid_scope"},
		{"request present", goodRequest("request", "eyJhbGciOiJub25lIn0"), "request_not_supported"},
		{"request empty", goodRequest("request", ""), "request_not_supported"},
		{"request_uri present", goodRequest("request_uri", "https://x.example.com/r"), "request_uri_not_supported"},
		{"request before request_uri", goodRequest("request", "a", "request_uri", "b"), "request_not_supported"},
		{"request before prompt", goodRequest("request", "a", "prompt", "none login"), "request_not_supported"},
		{"prompt none with login", goodRequest("prompt", "none login"), "invalid_request"},
		{"prompt login with none", goodRequest("prompt", "login none"), "invalid_request"},
		{"prompt none with consent and select_account", goodRequest("prompt", "select_account none consent"), "invalid_request"},
		{"max_age text", goodRequest("max_age", "soon"), "invalid_request"},
		{"max_age negative", goodRequest("max_age", "-1"), "invalid_request"},
		{"max_age fraction", goodRequest("max_age", "1.5"), "invalid_request"},
		{"max_age empty", goodRequest("max_age", ""), "invalid_request"},
		{"max_age with a plus", goodRequest("max_age", "+5"), "invalid_request"},
		{"max_age with a space", goodRequest("max_age", "5 "), "invalid_request"},
		{"max_age before prompt=none", goodRequest("max_age", "x", "prompt", "none"), "invalid_request"},
		{"challenge method plain", goodRequest("code_challenge_method", "plain"), "invalid_request"},
		{"challenge method lower case", goodRequest("code_challenge_method", "s256"), "invalid_request"},
		{"challenge method without a challenge", goodRequest("code_challenge", "-", "code_challenge_method", "plain"), "invalid_request"},
		{"challenge without a method", goodRequest("code_challenge_method", "-"), "invalid_request"},
		{"challenge with an empty method", goodRequest("code_challenge_method", ""), "invalid_request"},
		{"challenge too short", goodRequest("code_challenge", challenge[:42]), "invalid_request"},
		{"challenge too long", goodRequest("code_challenge", long), "invalid_request"},
		{"challenge with a plus", goodRequest("code_challenge", challenge[:42]+"+"), "invalid_request"},
		{"challenge with padding", goodRequest("code_challenge", challenge[:42]+"="), "invalid_request"},
		{"challenge with a space", goodRequest("code_challenge", challenge[:42]+" "), "invalid_request"},
		{"no challenge for a default public client", goodRequest("code_challenge", "-", "code_challenge_method", "-"), "invalid_request"},
		{"no challenge for a default confidential client", goodRequest("client_id", "srv", "redirect_uri", "https://srv.example.com/callback",
			"code_challenge", "-", "code_challenge_method", "-"), "invalid_request"},
		{"challenge without a method for a confidential client", goodRequest("client_id", "srv", "redirect_uri", "https://srv.example.com/callback",
			"code_challenge_method", "-"), "invalid_request"},
		{"challenge without a method for a client that does not require PKCE", goodRequest("client_id", "legacy",
			"redirect_uri", "https://legacy.example.com/callback", "code_challenge_method", "-"), "invalid_request"},
		{"bad challenge before prompt=none", goodRequest("prompt", "none", "code_challenge", challenge[:5]), "invalid_request"},
		{"missing challenge before prompt=none", goodRequest("prompt", "none", "code_challenge", "-", "code_challenge_method", "-"), "invalid_request"},
		{"prompt=none", goodRequest("prompt", "none"), "login_required"},
		{"prompt=none for a client that needs no PKCE", goodRequest("client_id", "legacy", "redirect_uri", "https://legacy.example.com/callback",
			"prompt", "none", "code_challenge", "-", "code_challenge_method", "-"), "login_required"},
	}
	for _, withState := range []bool{true, false} {
		for _, tt := range tests {
			if tt.name == "state repeated" && !withState {
				continue // the row is about a repeated state
			}
			name := tt.name + "/state"
			if !withState {
				name = tt.name + "/no state"
			}
			t.Run(name, func(t *testing.T) {
				v := cloneValues(tt.v)
				if !withState {
					v.Del("state")
				}
				_, page, redir := oidc.ParseAuthorization(realm, v)
				if page != nil || redir == nil {
					t.Fatalf("page %v, redirect %v; want a redirect error only", page, redir)
				}
				if redir.Err.Code != tt.code {
					t.Errorf("error %q (%s), want %q", redir.Err.Code, redir.Err.Description, tt.code)
				}
				if redir.Err.Description == "" {
					t.Error("no error_description")
				}
				wantState := ""
				if withState && tt.name != "state repeated" { // two values: none can be echoed
					wantState = "st-1"
				}
				if redir.State != wantState {
					t.Errorf("state %q, want %q", redir.State, wantState)
				}
				// Every redirect error also carries where and how to deliver it.
				if redir.RedirectURI == "" {
					t.Error("no redirect URI")
				}
				if redir.Mode != oidc.ModeQuery && v.Get("client_id") != "frag" && v.Get("client_id") != "posting" {
					t.Errorf("mode %q", redir.Mode)
				}
			})
		}
	}
}

// Covers: FR-02 (part)
// Acceptance: Request errors (part)
func TestParseAuthorizationErrorModes(t *testing.T) {
	realm := authzRealm(t)
	tests := []struct {
		name string
		v    url.Values
		mode oidc.ResponseMode
	}{
		{"default query", goodRequest("scope", "-"), oidc.ModeQuery},
		{"request fragment", goodRequest("scope", "-", "response_mode", "fragment"), oidc.ModeFragment},
		{"request form_post", goodRequest("scope", "-", "response_mode", "form_post"), oidc.ModeFormPost},
		{"request query", goodRequest("scope", "-", "response_mode", "query"), oidc.ModeQuery},
		{"client fragment", goodRequest("client_id", "frag", "redirect_uri", "https://frag.example.com/callback", "scope", "-"), oidc.ModeFragment},
		{"client form_post", goodRequest("client_id", "posting", "redirect_uri", "https://post.example.com/callback", "scope", "-"), oidc.ModeFormPost},
		{"the request wins over the client", goodRequest("client_id", "frag", "redirect_uri", "https://frag.example.com/callback",
			"scope", "-", "response_mode", "query"), oidc.ModeQuery},
		{"a repeated response_mode uses the client's", goodRequest("client_id", "frag", "redirect_uri", "https://frag.example.com/callback",
			"response_mode", "query"), oidc.ModeFragment},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := tt.v
			if tt.name == "a repeated response_mode uses the client's" {
				v = withExtra(v, "response_mode", "query")
			}
			_, page, redir := oidc.ParseAuthorization(realm, v)
			if page != nil || redir == nil {
				t.Fatalf("page %v, redirect %v", page, redir)
			}
			if redir.Mode != tt.mode {
				t.Errorf("mode %q, want %q", redir.Mode, tt.mode)
			}
			if want := v.Get("redirect_uri"); redir.RedirectURI != want {
				t.Errorf("redirect URI %q, want %q", redir.RedirectURI, want)
			}
		})
	}
}

// Covers: FR-02 (part), SEC-01 (part)
// Acceptance: Scope handling (part)
func TestParseAuthorizationAcceptsValidRequests(t *testing.T) {
	realm := authzRealm(t)
	ten := 10 * time.Second
	zero := time.Duration(0)
	tests := []struct {
		name string
		v    url.Values
		want oidc.AuthRequest
	}{
		{"plain request", goodRequest(), oidc.AuthRequest{
			ClientID: "web", RedirectURI: "https://app.example.com/callback", State: "st-1", Nonce: "n-1",
			CodeChallenge: challenge, ResponseMode: oidc.ModeQuery,
		}},
		{"other scopes are ignored", goodRequest("scope", "profile openid  foo"), oidc.AuthRequest{
			ClientID: "web", RedirectURI: "https://app.example.com/callback", State: "st-1", Nonce: "n-1",
			CodeChallenge: challenge, ResponseMode: oidc.ModeQuery,
		}},
		{"no state and no nonce", goodRequest("state", "-", "nonce", "-"), oidc.AuthRequest{
			ClientID: "web", RedirectURI: "https://app.example.com/callback",
			CodeChallenge: challenge, ResponseMode: oidc.ModeQuery,
		}},
		{"unsupported optional parameters are ignored", goodRequest("display", "popup", "ui_locales", "nl", "claims", "{}",
			"id_token_hint", "x", "acr_values", "1"), oidc.AuthRequest{
			ClientID: "web", RedirectURI: "https://app.example.com/callback", State: "st-1", Nonce: "n-1",
			CodeChallenge: challenge, ResponseMode: oidc.ModeQuery,
		}},
		{"response mode of the request", goodRequest("response_mode", "form_post"), oidc.AuthRequest{
			ClientID: "web", RedirectURI: "https://app.example.com/callback", State: "st-1", Nonce: "n-1",
			CodeChallenge: challenge, ResponseMode: oidc.ModeFormPost,
		}},
		{"response mode of the client", goodRequest("client_id", "frag", "redirect_uri", "https://frag.example.com/callback"), oidc.AuthRequest{
			ClientID: "frag", RedirectURI: "https://frag.example.com/callback", State: "st-1", Nonce: "n-1",
			CodeChallenge: challenge, ResponseMode: oidc.ModeFragment,
		}},
		{"prompt login", goodRequest("prompt", "login"), oidc.AuthRequest{
			ClientID: "web", RedirectURI: "https://app.example.com/callback", State: "st-1", Nonce: "n-1",
			CodeChallenge: challenge, ResponseMode: oidc.ModeQuery, Prompt: "login",
		}},
		{"prompt select_account", goodRequest("prompt", "select_account"), oidc.AuthRequest{
			ClientID: "web", RedirectURI: "https://app.example.com/callback", State: "st-1", Nonce: "n-1",
			CodeChallenge: challenge, ResponseMode: oidc.ModeQuery, Prompt: "select_account",
		}},
		{"prompt consent", goodRequest("prompt", "consent"), oidc.AuthRequest{
			ClientID: "web", RedirectURI: "https://app.example.com/callback", State: "st-1", Nonce: "n-1",
			CodeChallenge: challenge, ResponseMode: oidc.ModeQuery, Prompt: "consent",
		}},
		{"several prompt values", goodRequest("prompt", "consent  login"), oidc.AuthRequest{
			ClientID: "web", RedirectURI: "https://app.example.com/callback", State: "st-1", Nonce: "n-1",
			CodeChallenge: challenge, ResponseMode: oidc.ModeQuery, Prompt: "consent",
		}},
		{"an unknown prompt value is ignored", goodRequest("prompt", "create"), oidc.AuthRequest{
			ClientID: "web", RedirectURI: "https://app.example.com/callback", State: "st-1", Nonce: "n-1",
			CodeChallenge: challenge, ResponseMode: oidc.ModeQuery,
		}},
		{"max_age", goodRequest("max_age", "10"), oidc.AuthRequest{
			ClientID: "web", RedirectURI: "https://app.example.com/callback", State: "st-1", Nonce: "n-1",
			CodeChallenge: challenge, ResponseMode: oidc.ModeQuery, MaxAge: &ten,
		}},
		{"max_age zero", goodRequest("max_age", "0"), oidc.AuthRequest{
			ClientID: "web", RedirectURI: "https://app.example.com/callback", State: "st-1", Nonce: "n-1",
			CodeChallenge: challenge, ResponseMode: oidc.ModeQuery, MaxAge: &zero,
		}},
		{"login_hint", goodRequest("login_hint", "ann@example.com"), oidc.AuthRequest{
			ClientID: "web", RedirectURI: "https://app.example.com/callback", State: "st-1", Nonce: "n-1",
			CodeChallenge: challenge, ResponseMode: oidc.ModeQuery, LoginHint: "ann@example.com",
		}},
		{"provider hint", goodRequest("provider", "github"), oidc.AuthRequest{
			ClientID: "web", RedirectURI: "https://app.example.com/callback", State: "st-1", Nonce: "n-1",
			CodeChallenge: challenge, ResponseMode: oidc.ModeQuery, Hint: "github",
		}},
		{"the second hint name", goodRequest("idp", "apple"), oidc.AuthRequest{
			ClientID: "web", RedirectURI: "https://app.example.com/callback", State: "st-1", Nonce: "n-1",
			CodeChallenge: challenge, ResponseMode: oidc.ModeQuery, Hint: "apple",
		}},
		{"the first hint name wins", goodRequest("idp", "apple", "provider", "github"), oidc.AuthRequest{
			ClientID: "web", RedirectURI: "https://app.example.com/callback", State: "st-1", Nonce: "n-1",
			CodeChallenge: challenge, ResponseMode: oidc.ModeQuery, Hint: "github",
		}},
		{"an empty first hint name falls to the second", goodRequest("provider", "", "idp", "apple"), oidc.AuthRequest{
			ClientID: "web", RedirectURI: "https://app.example.com/callback", State: "st-1", Nonce: "n-1",
			CodeChallenge: challenge, ResponseMode: oidc.ModeQuery, Hint: "apple",
		}},
		{"no challenge for a client that does not require PKCE", goodRequest("client_id", "legacy",
			"redirect_uri", "https://legacy.example.com/callback", "code_challenge", "-", "code_challenge_method", "-"), oidc.AuthRequest{
			ClientID: "legacy", RedirectURI: "https://legacy.example.com/callback", State: "st-1", Nonce: "n-1", ResponseMode: oidc.ModeQuery,
		}},
		{"a challenge that is sent is accepted for a client that does not require PKCE", goodRequest("client_id", "legacy",
			"redirect_uri", "https://legacy.example.com/callback"), oidc.AuthRequest{
			ClientID: "legacy", RedirectURI: "https://legacy.example.com/callback", State: "st-1", Nonce: "n-1",
			CodeChallenge: challenge, ResponseMode: oidc.ModeQuery,
		}},
		{"confidential client", goodRequest("client_id", "srv", "redirect_uri", "https://srv.example.com/callback"), oidc.AuthRequest{
			ClientID: "srv", RedirectURI: "https://srv.example.com/callback", State: "st-1", Nonce: "n-1",
			CodeChallenge: challenge, ResponseMode: oidc.ModeQuery,
		}},
		{"custom scheme", goodRequest("client_id", "native", "redirect_uri", "com.example.app:/callback"), oidc.AuthRequest{
			ClientID: "native", RedirectURI: "com.example.app:/callback", State: "st-1", Nonce: "n-1",
			CodeChallenge: challenge, ResponseMode: oidc.ModeQuery,
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, page, redir := oidc.ParseAuthorization(realm, tt.v)
			if page != nil || redir != nil {
				t.Fatalf("page %v, redirect %v", page, redir)
			}
			if got.Realm != realm || got.Client == nil || got.Client != realm.Clients[got.ClientID] {
				t.Errorf("realm or client not set: %+v", got)
			}
			got.Realm, got.Client = nil, nil
			if got.MaxAge != nil && tt.want.MaxAge != nil {
				if *got.MaxAge != *tt.want.MaxAge {
					t.Errorf("MaxAge %v, want %v", *got.MaxAge, *tt.want.MaxAge)
				}
				got.MaxAge, tt.want.MaxAge = nil, nil
			}
			if got != tt.want {
				t.Errorf("got  %+v\nwant %+v", got, tt.want)
			}
		})
	}
}

// Covers: FR-02 (part)
func TestParseAuthorizationMaxAgeRange(t *testing.T) {
	realm := authzRealm(t)
	for _, tt := range []struct {
		value string
		ok    bool
		want  time.Duration
	}{
		{"007", true, 7 * time.Second},
		{"9223372036", true, 9223372036 * time.Second},
		{"9223372037", false, 0},
		{strings.Repeat("9", 30), false, 0},
	} {
		got, page, redir := oidc.ParseAuthorization(realm, goodRequest("max_age", tt.value))
		if tt.ok {
			if page != nil || redir != nil || got.MaxAge == nil || *got.MaxAge != tt.want {
				t.Errorf("max_age=%s: page %v, redirect %v, max age %v", tt.value, page, redir, got.MaxAge)
			}
			continue
		}
		if page != nil || redir == nil || redir.Err.Code != "invalid_request" {
			t.Errorf("max_age=%s: page %v, redirect %v; want invalid_request", tt.value, page, redir)
		}
	}
}

// Covers: FR-03 (part), SEC-02 (part)
// Acceptance: Redirect URI (part)
func TestParseAuthorizationLoopbackRedirects(t *testing.T) {
	realm := authzRealm(t)
	tests := []struct {
		name, client, uri string
		ok                bool
	}{
		{"registered as it is", "native", "http://127.0.0.1:8080/cb", true},
		{"another port", "native", "http://127.0.0.1:54321/cb", true},
		{"no port", "native", "http://127.0.0.1/cb", true},
		{"IPv6 on another port", "native", "http://[::1]:1234/cb", true},
		{"IPv6 as registered", "native", "http://[::1]:9090/cb", true},
		{"another path", "native", "http://127.0.0.1:54321/other", false},
		{"a query", "native", "http://127.0.0.1:54321/cb?x=1", false},
		{"a fragment", "native", "http://127.0.0.1:54321/cb#x", false},
		{"user info", "native", "http://user@127.0.0.1:54321/cb", false},
		{"localhost", "native", "http://localhost:8080/cb", false},
		{"another loopback address", "native", "http://127.0.0.2:8080/cb", false},
		{"https", "native", "https://127.0.0.1:8080/cb", false},
		{"a port that is not a number", "native", "http://127.0.0.1:abc/cb", false},
		{"a port out of range", "native", "http://127.0.0.1:99999/cb", false},
		{"a trailing slash", "native", "http://127.0.0.1:54321/cb/", false},
		{"a custom scheme with a port", "native", "com.example.app://x:1/callback", false},
		{"a public client without a loopback URI", "web", "http://127.0.0.1:54321/callback", false},
		{"a confidential client as it would be registered", "srv", "http://127.0.0.1:8080/cb", false},
		{"a confidential client on another port", "srv", "http://127.0.0.1:54321/cb", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, page, redir := oidc.ParseAuthorization(realm, goodRequest("client_id", tt.client, "redirect_uri", tt.uri))
			if tt.ok {
				if page != nil || redir != nil {
					t.Fatalf("page %v, redirect %v", page, redir)
				}
				if got.RedirectURI != tt.uri {
					t.Errorf("RedirectURI %q, want the requested %q", got.RedirectURI, tt.uri)
				}
				return
			}
			if page == nil || redir != nil {
				t.Errorf("page %v, redirect %v; want a page error", page, redir)
			}
		})
	}
}

// FuzzParseAuthorization checks what every outcome promises, for any query.
func FuzzParseAuthorization(f *testing.F) {
	realm := authzRealm(f)
	for _, seed := range []url.Values{
		goodRequest(),
		goodRequest("response_mode", "form_post", "prompt", "login consent", "max_age", "5", "login_hint", "a@b.c", "provider", "google"),
		goodRequest("client_id", "native", "redirect_uri", "http://127.0.0.1:5555/cb"),
		goodRequest("client_id", "srv", "redirect_uri", "https://srv.example.com/callback", "code_challenge", "-"),
		goodRequest("prompt", "none"),
		goodRequest("request", "x"),
		goodRequest("scope", "-"),
		withExtra(goodRequest(), "state", "again"),
		goodRequest("redirect_uri", "http://[::1]:99999/cb"),
	} {
		f.Add(seed.Encode())
	}
	f.Add("")
	f.Add("client_id=web&client_id=web")
	f.Fuzz(func(t *testing.T, query string) {
		v, err := url.ParseQuery(query)
		if err != nil {
			t.Skip()
		}
		req, page, redir := oidc.ParseAuthorization(realm, v)
		switch {
		case page != nil && redir != nil:
			t.Fatal("both a page and a redirect error")
		case page != nil:
			if page.Status != 400 || page.MessageID == "" {
				t.Errorf("page error %+v", page)
			}
		case redir != nil:
			if _, ok := oidc.ParseResponseMode(string(redir.Mode)); !ok {
				t.Errorf("redirect error mode %q", redir.Mode)
			}
			if redir.Err.Code == "" || redir.RedirectURI == "" || redir.RedirectURI != v.Get("redirect_uri") {
				t.Errorf("redirect error %+v for %q", redir, v.Get("redirect_uri"))
			}
			if redir.State != "" && redir.State != v.Get("state") {
				t.Errorf("state %q is not the request's %q", redir.State, v.Get("state"))
			}
		default:
			if req.Realm != realm || req.Client == nil || realm.Clients[req.ClientID] != req.Client {
				t.Fatalf("accepted request without its client: %+v", req)
			}
			if req.RedirectURI != v.Get("redirect_uri") {
				t.Errorf("redirect URI %q is not the request's", req.RedirectURI)
			}
			if _, ok := oidc.ParseResponseMode(string(req.ResponseMode)); !ok {
				t.Errorf("mode %q", req.ResponseMode)
			}
			if req.CodeChallenge == "" && req.Client.RequirePKCE {
				t.Error("accepted without a challenge for a client that requires one")
			}
			if req.CodeChallenge != "" && len(req.CodeChallenge) != 43 {
				t.Errorf("challenge %q", req.CodeChallenge)
			}
			if req.MaxAge != nil && *req.MaxAge < 0 {
				t.Errorf("max_age %v", *req.MaxAge)
			}
			if !slices.Contains(strings.Fields(v.Get("scope")), "openid") {
				t.Error("accepted without the openid scope")
			}
		}
	})
}

// Covers: FR-02 (part)
// Acceptance: Request errors (part)
func TestAuthorizationErrorValues(t *testing.T) {
	e := &oidc.RedirectError{Err: oidc.Error{Code: "invalid_scope", Description: "no openid"}, Mode: oidc.ModeQuery, RedirectURI: "https://a.example/cb", State: "st"}
	want := url.Values{"error": {"invalid_scope"}, "error_description": {"no openid"}, "state": {"st"}, "iss": {"https://auth.example.com/main"}}
	if got := e.Values("https://auth.example.com/main"); got.Encode() != want.Encode() {
		t.Errorf("values %v, want %v", got, want)
	}
	e.State, e.Err.Description = "", ""
	if got := e.Values("https://auth.example.com/main"); got.Has("state") || got.Has("error_description") || got.Get("iss") == "" {
		t.Errorf("values without state or description: %v", got)
	}
	if e.Error() == "" || (&oidc.PageError{Reason: "x"}).Error() == "" {
		t.Error("an error has no text")
	}
}

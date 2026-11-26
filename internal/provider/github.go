package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"golang.org/x/oauth2"
)

// GitHub's fixed endpoints and the fixed User-Agent its API requires.
const (
	githubAuthorizeURL = "https://github.com/login/oauth/authorize"
	githubTokenURL     = "https://github.com/login/oauth/access_token"
	githubUserURL      = "https://api.github.com/user"
	githubEmailsURL    = "https://api.github.com/user/emails"
	githubUserAgent    = "FeatherAuth"
)

// GitHubOptions configures the GitHub adapter. Empty URLs default to GitHub's.
type GitHubOptions struct {
	ClientID             string
	ClientSecret         string
	RedirectURI          string // the callback URL
	Scopes               []string
	PKCE                 bool // send an S256 challenge
	AllowSignup          bool // false sends allow_signup=false
	RequireVerifiedEmail bool // refuse a login without a verified email
	AuthorizeURL         string
	TokenURL             string
	UserURL              string
	EmailsURL            string
	Timeout              time.Duration // for every call to GitHub
}

// GitHub is the adapter for GitHub, which is plain OAuth2: the identity comes
// from the API, not from an ID token.
type GitHub struct {
	oauth       oauth2.Config
	client      *http.Client
	pkce        bool
	allowSignup bool
	requireMail bool
	userURL     string
	emailsURL   string
}

var (
	_ Provider       = (*GitHub)(nil)
	_ slog.LogValuer = GitHub{}
)

// LogValue implements slog.LogValuer. The adapter holds the client secret, so
// only its name is logged.
func (GitHub) LogValue() slog.Value {
	return slog.GroupValue(slog.String("provider", "github"))
}

// headerTransport adds the headers every call to GitHub needs: the User-Agent
// its API requires, and Accept: application/json so that the token endpoint
// answers JSON.
type headerTransport struct{ next http.RoundTripper }

func (h headerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Header.Set("User-Agent", githubUserAgent)
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "application/json")
	}
	return h.next.RoundTrip(req)
}

// CloseIdleConnections passes the call on to the wrapped transport.
func (h headerTransport) CloseIdleConnections() {
	if c, ok := h.next.(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
	}
}

// CloseIdleConnections closes the adapter's idle connections to GitHub.
func (g *GitHub) CloseIdleConnections() { g.client.CloseIdleConnections() }

// NewGitHub checks the options and builds the adapter. It makes no network call.
func NewGitHub(o GitHubOptions) (*GitHub, error) {
	switch {
	case o.ClientID == "" || o.RedirectURI == "":
		return nil, errors.New("provider: github: the client id and the redirect URI are required")
	case o.Timeout <= 0:
		return nil, errors.New("provider: github: the timeout must be positive")
	}
	def := func(v *string, d string) {
		if *v == "" {
			*v = d
		}
	}
	def(&o.AuthorizeURL, githubAuthorizeURL)
	def(&o.TokenURL, githubTokenURL)
	def(&o.UserURL, githubUserURL)
	def(&o.EmailsURL, githubEmailsURL)
	return &GitHub{
		oauth: oauth2.Config{
			ClientID: o.ClientID, ClientSecret: o.ClientSecret, RedirectURL: o.RedirectURI, Scopes: o.Scopes,
			// Fixed, so the library never repeats the single-use exchange with
			// the other style.
			Endpoint: oauth2.Endpoint{AuthURL: o.AuthorizeURL, TokenURL: o.TokenURL, AuthStyle: oauth2.AuthStyleInParams},
		},
		client:      &http.Client{Timeout: o.Timeout, Transport: headerTransport{&http.Transport{}}, CheckRedirect: noRedirect},
		pkce:        o.PKCE,
		allowSignup: o.AllowSignup,
		requireMail: o.RequireVerifiedEmail,
		userURL:     o.UserURL,
		emailsURL:   o.EmailsURL,
	}, nil
}

// Name implements Provider.
func (*GitHub) Name() string { return "github" }

// AuthURL implements Provider. There is no nonce (GitHub has no ID token).
// prompt=login and max_age become prompt=select_account, as does
// prompt=select_account; prompt=consent and login_hint are not passed.
func (g *GitHub) AuthURL(state, _, pkceChallenge string, opts AuthOptions) string {
	var args []oauth2.AuthCodeOption
	if g.pkce {
		args = append(args,
			oauth2.SetAuthURLParam("code_challenge", pkceChallenge),
			oauth2.SetAuthURLParam("code_challenge_method", "S256"))
	}
	if !g.allowSignup {
		args = append(args, oauth2.SetAuthURLParam("allow_signup", "false"))
	}
	if opts.Prompt == "login" || opts.Prompt == "select_account" || opts.MaxAge != nil {
		args = append(args, oauth2.SetAuthURLParam("prompt", "select_account"))
	}
	return g.oauth.AuthCodeURL(state, args...)
}

// Exchange implements Provider. The code exchange is made once and never
// retried. A timeout, a transport failure or a 5xx answer from any call is
// ErrUnavailable; a 4xx answer or a malformed one is a plain error.
func (g *GitHub) Exchange(ctx context.Context, cb Callback, pkceVerifier, _ string) (Identity, error) {
	if cb.Error != "" {
		if cb.Error == "access_denied" {
			return Identity{}, ErrCancelled
		}
		return Identity{}, errors.New("provider: github: the provider returned an error")
	}
	if cb.Code == "" {
		return Identity{}, errors.New("provider: github: the callback has no code")
	}
	// Without the client in the context, x/oauth2 falls back to http.DefaultClient.
	ctx = context.WithValue(ctx, oauth2.HTTPClient, g.client)
	var opts []oauth2.AuthCodeOption
	if g.pkce && pkceVerifier != "" {
		opts = append(opts, oauth2.VerifierOption(pkceVerifier))
	}
	tok, err := g.oauth.Exchange(ctx, cb.Code, opts...)
	if err != nil {
		return Identity{}, tokenError(err)
	}
	if tok.AccessToken == "" {
		return Identity{}, errors.New("provider: github: no access token in the token response")
	}

	var u struct {
		ID   json.RawMessage `json:"id"`
		Name string          `json:"name"`
	}
	if err := g.getJSON(ctx, g.userURL, tok.AccessToken, &u); err != nil {
		return Identity{}, err
	}
	subject := string(u.ID)
	if !githubID(subject) {
		return Identity{}, errors.New("provider: github: the user id is not a positive integer")
	}
	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := g.getJSON(ctx, g.emailsURL, tok.AccessToken, &emails); err != nil {
		return Identity{}, err
	}

	id := Identity{Subject: subject, Name: u.Name}
	for _, e := range emails {
		if e.Primary && e.Verified {
			id.Email, id.EmailVerified = e.Email, true
			return id, nil
		}
	}
	if g.requireMail {
		return Identity{}, fmt.Errorf("%w: GitHub has no verified primary email", ErrRefused)
	}
	// Not required: the primary address is still reported, never as verified.
	for _, e := range emails {
		if e.Primary {
			id.Email = e.Email
		}
	}
	return id, nil
}

// getJSON makes an authenticated GET with the adapter's own client and decodes
// the answer into v. The answer's body is never put into an error.
func (g *GitHub) getJSON(ctx context.Context, u, accessToken string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return errors.New("provider: github: the API URL is not valid")
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := g.client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: the GitHub API could not be reached", ErrUnavailable)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode >= 500:
		return fmt.Errorf("%w: the GitHub API answered %d", ErrUnavailable, resp.StatusCode)
	case resp.StatusCode != http.StatusOK:
		return fmt.Errorf("provider: github: the GitHub API answered %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("%w: the GitHub API answer could not be read", ErrUnavailable)
	}
	if err := json.Unmarshal(body, v); err != nil {
		return errors.New("provider: github: the GitHub API answer is not valid")
	}
	return nil
}

// githubID reports whether raw, the id as it is in the JSON, is a positive
// decimal integer written with digits only: no sign, fraction, exponent or
// quotes. It is kept as text, so a large id keeps every digit.
func githubID(raw string) bool {
	if raw == "" || raw[0] == '0' {
		return false
	}
	for _, c := range raw {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/secure"
)

// OIDCEndpoints override the URLs of the provider's discovery document. Empty
// fields keep the discovered value.
type OIDCEndpoints struct {
	Authorize string
	Token     string
	JWKS      string
	// Userinfo is the provider's user-info endpoint. It is called only when
	// set: a discovered user-info endpoint is never used.
	Userinfo string
}

// OIDCOptions configures the generic OpenID Connect adapter.
type OIDCOptions struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURI  string // the callback URL
	Scopes       []string
	Endpoints    OIDCEndpoints
	// Algorithms are the ID token signing algorithms to accept; empty takes the
	// discovered ones, or RS256 when no discovery is made.
	Algorithms []string
	Timeout    time.Duration // for every call to the provider
	Clock      clock.Clock
}

// OIDC is the adapter for any OpenID Connect provider with a single issuer,
// using the authorization code flow with PKCE.
type OIDC struct {
	oauth    oauth2.Config
	verifier *gooidc.IDTokenVerifier
	// anyAudience verifies the signature and the issuer, but neither the audience
	// nor the expiry: the caller checks both (provider account events).
	anyAudience *gooidc.IDTokenVerifier
	client      *http.Client
	// The fields below are how the adapters built on OIDC differ.
	name string
	// hints maps the request's options to authorize parameters; nil passes
	// prompt, max_age and login_hint on as they are.
	hints func(AuthOptions) url.Values
	// extra is added to every authorize URL.
	extra url.Values
	// check looks at the ID token's claims after they are verified; its error
	// is returned by Exchange.
	check func(claims map[string]any) error
	// noPKCE leaves the challenge and the verifier out (Apple has no PKCE).
	noPKCE bool
	// secret gives the client secret of each token call; nil uses the
	// configured one.
	secret func() (string, error)
	// userinfoURL is the user-info endpoint to call, or empty for no call.
	userinfoURL string
	// verified reads email_verified; nil accepts only the boolean true.
	verified func(v any) bool
}

var (
	_ Provider       = (*OIDC)(nil)
	_ slog.LogValuer = OIDC{}
)

// LogValue implements slog.LogValuer. The adapter holds the client secret, so
// only its name is logged.
func (p OIDC) LogValue() slog.Value {
	return slog.GroupValue(slog.String("provider", p.name))
}

// retryKeys wraps a transport and repeats a failed GET of the key set once
// (Provider calls); every other request goes through once.
type retryKeys struct {
	next    http.RoundTripper
	jwksURL string
}

// CloseIdleConnections passes the call on to the wrapped transport.
func (r *retryKeys) CloseIdleConnections() {
	if c, ok := r.next.(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
	}
}

func (r *retryKeys) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.String() != r.jwksURL {
		return r.next.RoundTrip(req)
	}
	var resp *http.Response
	var err error
	for attempt := 0; attempt < 2; attempt++ {
		resp, err = r.next.RoundTrip(req)
		if err == nil && resp.StatusCode == http.StatusOK {
			return resp, nil
		}
		if attempt == 0 && resp != nil {
			resp.Body.Close()
		}
	}
	return resp, err
}

// noRedirect is the CheckRedirect of every client of a provider call. The 3xx
// answer is then the answer, so a redirect is a failure of the call and the
// server it names is never called (SEC-26).
func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// NewOIDC builds the adapter. It fetches the discovery document from the
// issuer unless every endpoint the adapter needs is overridden.
func NewOIDC(ctx context.Context, o OIDCOptions) (*OIDC, error) {
	if o.Timeout <= 0 {
		return nil, errors.New("provider: oidc: the timeout must be positive")
	}
	if o.Clock == nil {
		return nil, errors.New("provider: oidc: no clock")
	}
	cfg := gooidc.ProviderConfig{
		IssuerURL: o.Issuer, Algorithms: o.Algorithms, AuthURL: o.Endpoints.Authorize, TokenURL: o.Endpoints.Token, JWKSURL: o.Endpoints.JWKS,
	}
	// One client for every call, with the provider's timeout. The transport
	// retries a failed key fetch once.
	tr := &retryKeys{next: &http.Transport{}, jwksURL: cfg.JWKSURL}
	client := &http.Client{Timeout: o.Timeout, Transport: tr, CheckRedirect: noRedirect}
	ctx = gooidc.ClientContext(ctx, client)

	if cfg.AuthURL == "" || cfg.TokenURL == "" || cfg.JWKSURL == "" {
		disc, err := gooidc.NewProvider(ctx, o.Issuer)
		if err != nil {
			return nil, fmt.Errorf("provider: oidc discovery: %w", err)
		}
		var d struct {
			Authorize  string   `json:"authorization_endpoint"`
			Token      string   `json:"token_endpoint"`
			JWKS       string   `json:"jwks_uri"`
			Algorithms []string `json:"id_token_signing_alg_values_supported"`
		}
		if err := disc.Claims(&d); err != nil {
			return nil, fmt.Errorf("provider: oidc discovery: %w", err)
		}
		if len(cfg.Algorithms) == 0 {
			cfg.Algorithms = d.Algorithms
		}
		for _, f := range []struct {
			dst  *string
			from string
		}{{&cfg.AuthURL, d.Authorize}, {&cfg.TokenURL, d.Token}, {&cfg.JWKSURL, d.JWKS}} {
			if *f.dst == "" {
				*f.dst = f.from
			}
		}
		tr.jwksURL = cfg.JWKSURL
	}
	keys := &jwksKeys{url: cfg.JWKSURL, client: client}
	return &OIDC{
		oauth: oauth2.Config{
			ClientID: o.ClientID, ClientSecret: o.ClientSecret, RedirectURL: o.RedirectURI, Scopes: o.Scopes,
			// Fixed, so the library never repeats the single-use exchange with
			// the other style.
			Endpoint: oauth2.Endpoint{AuthURL: cfg.AuthURL, TokenURL: cfg.TokenURL, AuthStyle: oauth2.AuthStyleInHeader},
		},
		verifier:    gooidc.NewVerifier(o.Issuer, keys, &gooidc.Config{ClientID: o.ClientID, SupportedSigningAlgs: cfg.Algorithms, Now: o.Clock.Now}),
		anyAudience: gooidc.NewVerifier(o.Issuer, keys, &gooidc.Config{SkipClientIDCheck: true, SkipExpiryCheck: true, SupportedSigningAlgs: cfg.Algorithms, Now: o.Clock.Now}),
		client:      client,
		name:        "oidc",
		userinfoURL: o.Endpoints.Userinfo,
	}, nil
}

// CloseIdleConnections closes the adapter's idle connections to the provider.
// A call that is running is not touched. The registry calls it on an adapter
// that a reload replaced.
func (p *OIDC) CloseIdleConnections() { p.client.CloseIdleConnections() }

// Name implements Provider.
func (p *OIDC) Name() string { return p.name }

// AuthURL implements Provider. The prompt, max_age and login_hint of the
// request are passed on as they are.
func (p *OIDC) AuthURL(state, nonce, pkceChallenge string, opts AuthOptions) string {
	args := []oauth2.AuthCodeOption{oauth2.SetAuthURLParam("nonce", nonce)}
	if !p.noPKCE {
		args = append(args,
			oauth2.SetAuthURLParam("code_challenge", pkceChallenge),
			oauth2.SetAuthURLParam("code_challenge_method", "S256"))
	}
	params := url.Values{}
	if p.hints != nil {
		params = p.hints(opts)
	} else {
		if opts.Prompt != "" {
			params.Set("prompt", opts.Prompt)
		}
		if opts.MaxAge != nil {
			params.Set("max_age", strconv.Itoa(*opts.MaxAge))
		}
		if opts.LoginHint != "" {
			params.Set("login_hint", opts.LoginHint)
		}
	}
	for k, v := range p.extra {
		params[k] = v
	}
	for k, v := range params {
		args = append(args, oauth2.SetAuthURLParam(k, v[0]))
	}
	return p.oauth.AuthCodeURL(state, args...)
}

// Exchange implements Provider. The code exchange is made once and never
// retried. A timeout, a transport failure, a failed key fetch and a 5xx answer
// are ErrUnavailable.
func (p *OIDC) Exchange(ctx context.Context, cb Callback, pkceVerifier, nonce string) (Identity, error) {
	id, _, err := p.exchange(ctx, cb, pkceVerifier, nonce)
	return id, err
}

// withClient puts the adapter's own client in the context for go-oidc and
// oauth2, which would otherwise fall back to http.DefaultClient.
func (p *OIDC) withClient(ctx context.Context) context.Context {
	ctx = gooidc.ClientContext(ctx, p.client)
	return context.WithValue(ctx, oauth2.HTTPClient, p.client)
}

// verifyIDToken checks the signature, iss, aud and exp of a raw ID token and
// its nonce.
func (p *OIDC) verifyIDToken(ctx context.Context, raw, nonce string) (*gooidc.IDToken, error) {
	ctx, kf := withKeyFetch(ctx)
	idt, err := p.verifier.Verify(ctx, raw)
	if err != nil {
		if kf.failed {
			return nil, fmt.Errorf("%w: the provider's keys could not be fetched", ErrUnavailable)
		}
		return nil, errors.New("provider: oidc: the ID token is not valid")
	}
	if err := p.checkAuthorizedParty(idt); err != nil {
		return nil, err
	}
	// secure.Equal, not !=: a nonce is a secret, so it is compared in constant time.
	if idt.Nonce == "" || nonce == "" || !secure.Equal(idt.Nonce, nonce) {
		return nil, errors.New("provider: oidc: the ID token nonce does not match")
	}
	if idt.Subject == "" {
		return nil, errors.New("provider: oidc: the ID token has no subject")
	}
	return idt, nil
}

// checkAuthorizedParty applies OIDC Core 3.1.3.7 rules 3 to 5 to a verified ID
// token: an azp claim that is present must be our client id, and a token with
// more than one audience must have one (SEC-26).
func (p *OIDC) checkAuthorizedParty(idt *gooidc.IDToken) error {
	var claims map[string]any
	if err := idt.Claims(&claims); err != nil {
		return errors.New("provider: oidc: the ID token claims are not valid")
	}
	aud, _ := claims["aud"].([]any)
	azp, has := claims["azp"]
	if !has {
		if len(aud) > 1 {
			return errors.New("provider: oidc: the ID token has several audiences and no azp")
		}
		return nil
	}
	if s, ok := azp.(string); !ok || s != p.oauth.ClientID {
		return errors.New("provider: oidc: the ID token azp is not our client id")
	}
	return nil
}

// exchange is Exchange that also returns the token response.
func (p *OIDC) exchange(ctx context.Context, cb Callback, pkceVerifier, nonce string) (Identity, *oauth2.Token, error) {
	if cb.Error != "" {
		if cb.Error == "access_denied" {
			return Identity{}, nil, ErrCancelled
		}
		return Identity{}, nil, errors.New("provider: oidc: the provider returned an error")
	}
	if cb.Code == "" {
		return Identity{}, nil, errors.New("provider: oidc: the callback has no code")
	}
	ctx = p.withClient(ctx)

	cfg := p.oauth
	if p.secret != nil {
		s, err := p.secret()
		if err != nil {
			return Identity{}, nil, fmt.Errorf("provider: oidc: the client secret: %w", err)
		}
		cfg.ClientSecret = s
	}
	var opts []oauth2.AuthCodeOption
	if pkceVerifier != "" && !p.noPKCE {
		opts = append(opts, oauth2.VerifierOption(pkceVerifier))
	}
	tok, err := cfg.Exchange(ctx, cb.Code, opts...)
	if err != nil {
		return Identity{}, nil, tokenError(err)
	}
	raw, _ := tok.Extra("id_token").(string)
	if raw == "" {
		return Identity{}, nil, errors.New("provider: oidc: no ID token in the token response")
	}
	idt, err := p.verifyIDToken(ctx, raw, nonce)
	if err != nil {
		return Identity{}, nil, err
	}
	var claims map[string]any
	if err := idt.Claims(&claims); err != nil {
		return Identity{}, nil, errors.New("provider: oidc: the ID token claims are not valid")
	}
	if p.check != nil {
		if err := p.check(claims); err != nil {
			return Identity{}, nil, err
		}
	}
	id := Identity{Subject: idt.Subject}
	id.Email, _ = claims["email"].(string)
	id.Name, _ = claims["name"].(string)
	// A missing claim, or one that is not the boolean true, is unverified.
	if p.verified != nil {
		id.EmailVerified = p.verified(claims["email_verified"])
	} else {
		id.EmailVerified, _ = claims["email_verified"].(bool)
	}
	if v, ok := claims["auth_time"]; ok && v != nil {
		// A number of seconds in a range that fits an int64 exactly (2^53); anything
		// else (a string, NaN, a huge or negative value) fails the exchange.
		at, isNum := v.(float64)
		if !isNum || math.IsNaN(at) || at < 0 || at > 1<<53 {
			return Identity{}, nil, errors.New("provider: oidc: the ID token auth_time is not valid")
		}
		if at != 0 {
			id.AuthTime = time.Unix(int64(at), 0).UTC()
		}
	}
	if p.userinfoURL != "" {
		if err := p.fillFromUserinfo(ctx, tok.AccessToken, claims, &id); err != nil {
			return Identity{}, nil, err
		}
	}
	return id, tok, nil
}

// fillFromUserinfo calls the configured user-info endpoint with the access
// token and fills the identity's email, email_verified and name where the ID
// token (claims) has none. It never replaces what the ID token gave. The
// user-info sub must be the ID token's. The answer's body is never put into
// an error.
func (p *OIDC) fillFromUserinfo(ctx context.Context, accessToken string, claims map[string]any, id *Identity) error {
	if accessToken == "" {
		return errors.New("provider: oidc: the token response has no access token for the user-info call")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.userinfoURL, nil)
	if err != nil {
		return errors.New("provider: oidc: the user-info URL is not valid")
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: the user-info endpoint could not be reached", ErrUnavailable)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode >= 500:
		return fmt.Errorf("%w: the user-info endpoint answered %d", ErrUnavailable, resp.StatusCode)
	case resp.StatusCode != http.StatusOK:
		return fmt.Errorf("provider: oidc: the user-info endpoint answered %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("%w: the user-info answer could not be read", ErrUnavailable)
	}
	var info map[string]any
	if err := json.Unmarshal(body, &info); err != nil {
		return errors.New("provider: oidc: the user-info answer is not valid")
	}
	sub, _ := info["sub"].(string)
	if sub == "" || !secure.Equal(sub, id.Subject) {
		if sub == "" {
			return errors.New("provider: oidc: the user-info answer has no subject")
		}
		return fmt.Errorf("%w: the user-info subject is not the ID token's", ErrRefused)
	}
	if email, _ := info["email"].(string); id.Email == "" {
		id.Email = email
	}
	if name, _ := info["name"].(string); id.Name == "" {
		id.Name = name
	}
	// email_verified is taken only when the ID token has no such claim, only
	// for the address user info itself gave (or the same one), and only as
	// the boolean true, like the ID token's.
	if _, has := claims["email_verified"]; !has {
		infoEmail, _ := info["email"].(string)
		if v, _ := info["email_verified"].(bool); v && infoEmail != "" && infoEmail == id.Email {
			id.EmailVerified = true
		}
	}
	return nil
}

// tokenError maps an error of the code exchange. The provider's answer is not
// put into the error.
func tokenError(err error) error {
	var re *oauth2.RetrieveError
	if errors.As(err, &re) {
		if re.Response != nil && re.Response.StatusCode >= 500 {
			return fmt.Errorf("%w: the token endpoint answered %d", ErrUnavailable, re.Response.StatusCode)
		}
		return errors.New("provider: oidc: the token endpoint refused the code")
	}
	var ue *url.Error
	if errors.As(err, &ue) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return fmt.Errorf("%w: the token endpoint could not be reached", ErrUnavailable)
	}
	return errors.New("provider: oidc: the token response is not valid")
}

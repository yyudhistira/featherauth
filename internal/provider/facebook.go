package provider

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/yyudhistira/featherauth/internal/clock"
)

// FacebookOptions configures the Facebook adapter (the oauth flow). Empty
// URLs default to Meta's, built from GraphVersion.
type FacebookOptions struct {
	ClientID     string
	ClientSecret string // the app secret: it also keys the appsecret_proof
	RedirectURI  string // the callback URL
	GraphVersion string // such as "v26.0"
	Scopes       []string
	Fields       []string // fields requested from /me; id is always requested
	RequireEmail bool     // refuse a login when Facebook returns no email
	AuthorizeURL string
	TokenURL     string
	GraphURL     string // the Graph base, such as https://graph.facebook.com/v26.0
	MeURL        string // the URL of the identity call; empty means GraphURL + "/me"
	Timeout      time.Duration
	// Clock dates the issued_at of Meta's signed_request; required.
	Clock clock.Clock
}

// Facebook is the adapter for Facebook Login with the oauth flow: the code is
// exchanged with a GET and the identity comes from the Graph API. Facebook
// reports no email verification, so an email is never verified.
type Facebook struct {
	clientID     string
	clientSecret string
	redirectURI  string
	scopes       []string
	fields       []string
	requireEmail bool
	authorizeURL string
	tokenURL     string
	graphURL     string
	meURL        string
	client       *http.Client
	clock        clock.Clock
}

var (
	_ Provider       = (*Facebook)(nil)
	_ slog.LogValuer = Facebook{}
)

// LogValue implements slog.LogValuer. The adapter holds the app secret, so
// only its name is logged.
func (Facebook) LogValue() slog.Value {
	return slog.GroupValue(slog.String("provider", "facebook"))
}

// NewFacebook checks the options and builds the adapter. It makes no network call.
func NewFacebook(o FacebookOptions) (*Facebook, error) {
	switch {
	case o.ClientID == "" || o.ClientSecret == "" || o.RedirectURI == "":
		return nil, errors.New("provider: facebook: the client id, the app secret and the redirect URI are required")
	case o.GraphVersion == "":
		return nil, errors.New("provider: facebook: the graph version is required")
	case o.Timeout <= 0:
		return nil, errors.New("provider: facebook: the timeout must be positive")
	case o.Clock == nil:
		return nil, errors.New("provider: facebook: a clock is required")
	}
	if o.AuthorizeURL == "" {
		o.AuthorizeURL = "https://www.facebook.com/" + o.GraphVersion + "/dialog/oauth"
	}
	if o.GraphURL == "" {
		o.GraphURL = "https://graph.facebook.com/" + o.GraphVersion
	}
	if o.TokenURL == "" {
		o.TokenURL = o.GraphURL + "/oauth/access_token"
	}
	if o.MeURL == "" {
		o.MeURL = o.GraphURL + "/me"
	}
	fields := slices.Clone(o.Fields)
	if len(fields) == 0 {
		fields = []string{"id", "name", "email"}
	}
	if !slices.Contains(fields, "id") {
		fields = append([]string{"id"}, fields...)
	}
	return &Facebook{
		clientID: o.ClientID, clientSecret: o.ClientSecret, redirectURI: o.RedirectURI,
		scopes: slices.Clone(o.Scopes), fields: fields, requireEmail: o.RequireEmail,
		authorizeURL: o.AuthorizeURL, tokenURL: o.TokenURL, graphURL: o.GraphURL, meURL: o.MeURL,
		client: &http.Client{Timeout: o.Timeout, Transport: &http.Transport{}, CheckRedirect: noRedirect},
		clock:  o.Clock,
	}, nil
}

// CloseIdleConnections closes the adapter's idle connections to Meta.
func (f *Facebook) CloseIdleConnections() { f.client.CloseIdleConnections() }

// Name implements Provider.
func (*Facebook) Name() string { return "facebook" }

// AuthURL implements Provider. There is no nonce and no PKCE in the oauth
// flow. prompt=login and max_age become auth_type=reauthenticate; the other
// hints are not passed.
func (f *Facebook) AuthURL(state, _, _ string, opts AuthOptions) string {
	q := url.Values{
		"client_id": {f.clientID}, "redirect_uri": {f.redirectURI}, "response_type": {"code"}, "state": {state},
	}
	if len(f.scopes) > 0 {
		q.Set("scope", strings.Join(f.scopes, ","))
	}
	if opts.Prompt == "login" || opts.MaxAge != nil {
		q.Set("auth_type", "reauthenticate")
	}
	return f.authorizeURL + querySep(f.authorizeURL) + q.Encode()
}

// Exchange implements Provider. The code exchange is a GET, made once and
// never retried. A timeout, a transport failure or a 5xx answer from any call
// is ErrUnavailable; a 4xx answer or a malformed one is a plain error. No
// answer body, token or proof is put into an error.
func (f *Facebook) Exchange(ctx context.Context, cb Callback, _, _ string) (Identity, error) {
	if cb.Error != "" {
		if cb.Error == "access_denied" {
			return Identity{}, ErrCancelled
		}
		return Identity{}, errors.New("provider: facebook: the provider returned an error")
	}
	if cb.Code == "" {
		return Identity{}, errors.New("provider: facebook: the callback has no code")
	}

	var tok struct {
		AccessToken string `json:"access_token"`
	}
	tq := url.Values{
		"client_id": {f.clientID}, "client_secret": {f.clientSecret}, "redirect_uri": {f.redirectURI}, "code": {cb.Code},
	}
	if err := f.get(ctx, f.tokenURL+"?"+tq.Encode(), "", &tok); err != nil {
		return Identity{}, err
	}
	if tok.AccessToken == "" {
		return Identity{}, errors.New("provider: facebook: no access token in the token response")
	}

	// Every Graph call carries appsecret_proof, the HMAC-SHA256 of the access
	// token keyed with the app secret, and sends the token in a header, not in
	// the URL.
	mac := hmac.New(sha256.New, []byte(f.clientSecret))
	mac.Write([]byte(tok.AccessToken))
	mq := url.Values{"fields": {strings.Join(f.fields, ",")}, "appsecret_proof": {hex.EncodeToString(mac.Sum(nil))}}
	// Only id, name and email are read from the answer, whatever else
	// the configured fields ask for.
	var me struct {
		ID    any    `json:"id"`
		Name  string `json:"name"`
		Email string `json:"email"`
	}
	if err := f.get(ctx, f.meURL+querySep(f.meURL)+mq.Encode(), tok.AccessToken, &me); err != nil {
		return Identity{}, err
	}
	subject, _ := me.ID.(string)
	if subject == "" {
		return Identity{}, errors.New("provider: facebook: the user has no id")
	}
	if f.requireEmail && me.Email == "" {
		return Identity{}, fmt.Errorf("%w: Facebook returned no email", ErrRefused)
	}
	// Facebook reports no verification, so EmailVerified stays false.
	return Identity{Subject: subject, Email: me.Email, Name: me.Name}, nil
}

// get makes a GET with the adapter's own client, with a bearer token when
// there is one, and decodes the JSON answer into v.
func (f *Facebook) get(ctx context.Context, u, accessToken string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return errors.New("provider: facebook: the request URL is not valid")
	}
	req.Header.Set("Accept", "application/json")
	if accessToken != "" {
		req.Header.Set("Authorization", "Bearer "+accessToken)
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: Facebook could not be reached", ErrUnavailable)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode >= 500:
		return fmt.Errorf("%w: Facebook answered %d", ErrUnavailable, resp.StatusCode)
	case resp.StatusCode != http.StatusOK:
		return fmt.Errorf("provider: facebook: Facebook answered %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("%w: the Facebook answer could not be read", ErrUnavailable)
	}
	if err := json.Unmarshal(body, v); err != nil {
		return errors.New("provider: facebook: the Facebook answer is not valid")
	}
	return nil
}

// querySep is the separator that appends parameters to a URL: "&" when it
// already has a query, else "?".
func querySep(u string) string {
	if strings.Contains(u, "?") {
		return "&"
	}
	return "?"
}

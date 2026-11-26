package server

import (
	"bytes"
	"context"
	"encoding/json"
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/admin"
	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/logx"
	"github.com/yyudhistira/featherauth/internal/oidc"
	"github.com/yyudhistira/featherauth/internal/provider"
	"github.com/yyudhistira/featherauth/internal/secure"
	isrv "github.com/yyudhistira/featherauth/internal/server"
	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/store/audit"
	"github.com/yyudhistira/featherauth/internal/testutil"
	"github.com/yyudhistira/featherauth/internal/testutil/configdir"
	"github.com/yyudhistira/featherauth/internal/testutil/mockidp"
	"github.com/yyudhistira/featherauth/internal/token"
	"github.com/yyudhistira/featherauth/internal/user"
	"github.com/yyudhistira/featherauth/internal/web"
)

// The service of the tests: one realm, "main", on a public URL that no
// network serves; the test client reaches it in process.
const (
	PublicURL = "https://auth.example.com"
	Issuer    = PublicURL + "/main"
)

// Providers are the provider keys of the realm; each has a mock identity
// provider in Env.Mocks.
var Providers = []string{"google", "apple", "github", "facebook", "corp"}

// A client of each response mode (the client's own setting), with its
// redirect URI.
var (
	ClientQuery    = App{ID: "web", RedirectURI: "https://app.example.com/callback", Mode: "query"}
	ClientFragment = App{ID: "frag", RedirectURI: "https://frag.example.com/callback", Mode: "fragment"}
	ClientFormPost = App{ID: "posting", RedirectURI: "https://post.example.com/callback", Mode: "form_post"}
	Clients        = []App{ClientQuery, ClientFragment, ClientFormPost}

	// ClientConfidential authenticates with its secret; ClientFixed is
	// confidential with refresh_token_rotation off; ClientLegacy is public
	// with require_pkce off; ClientLong has a 17520h idle lifetime and no
	// session limit; ClientCapped has a session limit of 2 hours.
	ClientConfidential = App{ID: "srv", RedirectURI: "https://srv.example.com/callback", Mode: "query"}
	ClientFixed        = App{ID: "fixed", RedirectURI: "https://fixed.example.com/callback", Mode: "query"}
	ClientLegacy       = App{ID: "legacy", RedirectURI: "https://legacy.example.com/callback", Mode: "query"}
	ClientLong         = App{ID: "long", RedirectURI: "https://long.example.com/callback", Mode: "query"}
	ClientCapped       = App{ID: "capped", RedirectURI: "https://capped.example.com/callback", Mode: "query"}

	// ClientDelete has allow_account_delete: true.
	ClientDelete = App{ID: "deleter", RedirectURI: "https://deleter.example.com/callback", Mode: "query"}
)

// App is a client application of the realm.
type App struct{ ID, RedirectURI, Mode string }

// Challenge is the S256 challenge of Verifier (RFC 7636's example).
const (
	Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	Verifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
)

// Option changes the service New starts.
type Option func(*options)

type options struct {
	// store opens the store of the service and returns it with the database
	// file, or "" when the store is not a file; nil means SQLite.
	store     func(testing.TB) (store.Store, string)
	algorithm string
	tokens    []string
	serverYML string
	login     []string
	google    []func(*provider.GoogleOptions)
	github    []func(*provider.GitHubOptions)
	facebook  []func(*provider.FacebookOptions)
}

// WithStore opens the service's store with open, for example the Postgres
// store of WithPostgres. The default is a SQLite file.
func WithStore(open func(testing.TB) (store.Store, string)) Option {
	return func(o *options) { o.store = open }
}

// WithGoogleOptions changes the options of the Google adapter the service uses.
func WithGoogleOptions(f func(*provider.GoogleOptions)) Option {
	return func(o *options) { o.google = append(o.google, f) }
}

// WithGitHubOptions changes the options of the GitHub adapter.
func WithGitHubOptions(f func(*provider.GitHubOptions)) Option {
	return func(o *options) { o.github = append(o.github, f) }
}

// WithFacebookOptions changes the options of the Facebook adapter.
func WithFacebookOptions(f func(*provider.FacebookOptions)) Option {
	return func(o *options) { o.facebook = append(o.facebook, f) }
}

// WithLoginSetting adds one line of the realm's login_page block, such as
// "accent_color: \"#aa3300\"".
func WithLoginSetting(line string) Option {
	return func(o *options) { o.login = append(o.login, line) }
}

// WithServerSetting appends YAML to server.yaml, such as "urls:\n  path_prefix: /auth\n".
func WithServerSetting(yaml string) Option {
	return func(o *options) { o.serverYML += yaml }
}

// WithAlgorithm sets tokens.algorithm of the realm ("RS256" or "ES256"; an
// ES256 realm also gets an active EC key).
func WithAlgorithm(alg string) Option {
	return func(o *options) {
		o.algorithm = alg
		o.tokens = append(o.tokens, "algorithm: "+alg)
	}
}

// WithRefreshFormat sets tokens.refresh_token_format of the realm.
func WithRefreshFormat(f string) Option {
	return func(o *options) { o.tokens = append(o.tokens, "refresh_token_format: "+f) }
}

// WithTokenSetting adds one line of the realm's tokens block, such as
// "code_lifetime: 2m".
func WithTokenSetting(line string) Option {
	return func(o *options) { o.tokens = append(o.tokens, line) }
}

const serverYAML = "public_url: " + PublicURL + "\n"

const realmYAML = `name: main
keys:
  - { kid: main-1, file: secrets/main/signing.pem, state: active }
login_page:
  contact: help@example.com
providers:
  google:
    enabled: true
    client_id: client-id
    client_secret_file: secrets/main/google_secret
  apple:
    enabled: true
    client_id: client-id
    team_id: TEAM123456
    key_id: KEY1234567
    private_key_file: secrets/main/apple.p8
  github:
    enabled: true
    client_id: client-id
    client_secret_file: secrets/main/github_secret
  facebook:
    enabled: true
    client_id: client-id
    client_secret_file: secrets/main/facebook_secret
  corp:
    type: oidc
    enabled: true
    display_name: Corp
    client_id: client-id
    client_secret_file: secrets/main/corp_secret
    issuer: "%CORP%"
clients:
  web:
    redirect_uris: [https://app.example.com/callback]
    web_origins: [https://app.example.com]
  frag:
    response_mode: fragment
    redirect_uris: [https://frag.example.com/callback]
    web_origins: [https://frag.example.com]
  posting:
    response_mode: form_post
    redirect_uris: [https://post.example.com/callback]
  srv:
    type: confidential
    client_secret_file: secrets/main/srv_secret
    redirect_uris: [https://srv.example.com/callback]
  fixed:
    type: confidential
    client_secret_file: secrets/main/fixed_secret
    refresh_token_rotation: false
    redirect_uris: [https://fixed.example.com/callback]
  legacy:
    require_pkce: false
    refresh_idle_lifetime: 24h
    session_max_lifetime: 720h
    redirect_uris: [https://legacy.example.com/callback]
  long:
    refresh_idle_lifetime: 17520h
    session_max_lifetime: 0
    redirect_uris: [https://long.example.com/callback]
  capped:
    session_max_lifetime: 2h
    redirect_uris: [https://capped.example.com/callback]
  deleter:
    allow_account_delete: true
    redirect_uris: [https://deleter.example.com/callback]
`

// Env is the whole HTTP service in process: the router with the real
// endpoints, a temporary store, a mock identity provider for each provider key
// and a fake clock.
type Env struct {
	Clock *clock.Fake
	Store store.Store
	// Faults is the store with failures injected; Store is the same store.
	Faults *testutil.FaultStore
	Router *isrv.Router
	Codes  *token.Codes
	// Snapshot is the configuration the service started with.
	Snapshot *config.Snapshot
	// Box opens and seals the stored provider tokens (the encryption key of
	// the configuration).
	Box *secure.Box
	// Issuer signs tokens with the realm's keys; tests use it for tokens the
	// service would not issue, such as a logout token.
	Issuer *token.Issuer
	// Users is the user manager the service uses; tests use it for changes that
	// the service makes through it.
	Users *user.Manager

	loader     *config.Loader
	dir        *configdir.Dir
	realmYAML  string
	serverYAML string
	Realm      *config.Realm
	// DatabasePath is the SQLite file of Store.
	DatabasePath string
	Mocks        map[string]*mockidp.Server
	Logs         *bytes.Buffer
}

// DisableUser disables (disabled true) or enables a user of the test realm
// through the user manager, as the administration commands do.
func (e *Env) DisableUser(t testing.TB, id store.UserID, disabled bool) {
	t.Helper()
	ctx := context.Background()
	var err error
	if disabled {
		err = e.Users.Disable(ctx, "admin", "main", id)
	} else {
		err = e.Users.Enable(ctx, "admin", "main", id)
	}
	if err != nil {
		t.Fatal(err)
	}
}

// realmsOf returns the configuration of the realms of a source, for the user
// manager's back-channel logouts.
func realmsOf(src config.Source) user.RealmOf {
	return func(name config.RealmName) (*config.Realm, bool) {
		snap := src.Current()
		if snap == nil {
			return nil, false
		}
		r, _ := snap.Realm(name)
		return r, true
	}
}

// ConfigDir is the configuration directory the service loaded.
func (e *Env) ConfigDir() string { return e.dir.Root }

// New starts the service. The mock identity providers stop with the test.
func New(t testing.TB, opts ...Option) *Env {
	t.Helper()
	var o options
	for _, f := range opts {
		f(&o)
	}
	clk := clock.NewFake(time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC))
	e := &Env{Clock: clk, Logs: &bytes.Buffer{}, Mocks: map[string]*mockidp.Server{
		"google":   mockidp.New(t, clk, mockidp.Google),
		"apple":    mockidp.New(t, clk, mockidp.Apple),
		"github":   mockidp.New(t, clk, mockidp.GitHub),
		"facebook": mockidp.New(t, clk, mockidp.Facebook),
		"corp":     mockidp.New(t, clk, mockidp.Generic),
	}}
	for _, m := range e.Mocks {
		m.SetSecretCheck(func(string) error { return nil }) // the secrets of the files are random
	}
	realm := strings.ReplaceAll(realmYAML, "%CORP%", e.Mocks["corp"].URL())
	if len(o.tokens) > 0 {
		realm = strings.Replace(realm, "keys:\n", "tokens:\n  "+strings.Join(o.tokens, "\n  ")+"\nkeys:\n", 1)
	}
	if len(o.login) > 0 {
		realm = strings.Replace(realm, "login_page:\n", "login_page:\n  "+strings.Join(o.login, "\n  ")+"\n", 1)
	}
	if o.algorithm == "ES256" {
		realm = strings.Replace(realm, "state: active }\n", "state: active }\n  - { kid: main-ec, file: secrets/main/signing-ec.pem, state: active }\n", 1)
	}
	d := configdir.New(t)
	for _, f := range []string{"google_secret", "github_secret", "facebook_secret", "corp_secret", "srv_secret", "fixed_secret"} {
		d.Secret(t, "secrets/main/"+f)
	}
	d.AppleKey(t, "secrets/main/apple.p8")
	d.RSAKey(t, "secrets/main/signing.pem")
	if o.algorithm == "ES256" {
		_, ec := testutil.ECKey(t)
		d.Write(t, "secrets/main/signing-ec.pem", string(ec))
	}
	d.EncryptionKey(t, "secrets/encryption_key")
	d.Server(t, serverYAML+o.serverYML)
	e.serverYAML = serverYAML + o.serverYML
	d.Realm(t, "main", realm)
	src, err := config.NewLoader(d.Root, clk, nil)
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}
	snap := src.Current()
	e.Snapshot, e.loader, e.dir, e.realmYAML = snap, src, d, realm
	e.Realm, _ = snap.Realm("main")
	open := o.store
	if open == nil {
		open = testutil.NewStoreFile
	}
	st, dbPath := open(t)
	e.DatabasePath = dbPath
	e.Faults = testutil.NewFaultStore(st)
	e.Store = e.Faults

	log := logx.New(e.Logs, slog.LevelDebug, clk)
	callback := func(p string) string { return e.Realm.EndpointURL(config.EndpointCallback, config.ProviderKey(p)) }
	reg := Registry{Registry: provider.NewPool(src, clk, log), Adapters: map[config.ProviderKey]provider.Provider{
		"google":   Google(t, clk, e.Mocks["google"], callback("google"), o.google...),
		"apple":    Apple(t, clk, e.Mocks["apple"], callback("apple")),
		"github":   GitHub(t, e.Mocks["github"], callback("github"), o.github...),
		"facebook": Facebook(t, clk, e.Mocks["facebook"], callback("facebook"), o.facebook...),
	}}
	secrets := config.LiveSecrets{Source: src}
	e.Issuer = token.NewIssuer(clk, secure.Default, secrets)
	e.Codes = token.NewCodes(e.Store, e.Issuer, clk, secure.Default)
	users := user.NewService(e.Store, audit.NewWriter(e.Store, log, clk, secure.Default), log, clk, secure.Default)
	refresher := token.NewRefresher(e.Store, token.NewIssuer(clk, secure.Default, secrets), clk, secure.Default)
	verifier := token.NewVerifier(clk, secrets)
	box, err := secure.NewBox(secrets.EncryptionKeys())
	if err != nil {
		t.Fatalf("NewBox: %v", err)
	}
	e.Box = box
	revokers := func(realm, key string) provider.Revoker {
		p, _ := reg.Get(config.RealmName(realm), config.ProviderKey(key))
		rv, _ := p.(provider.Revoker)
		return rv
	}
	manager := user.NewManager(e.Store, audit.NewWriter(e.Store, log, clk, secure.Default), box, revokers, log, clk, secure.Default, realmsOf(src))
	e.Users = manager
	bearer := oidc.NewBearerAuth(verifier, e.Store, clk)
	ops := admin.NewOps(e.Store, manager, clk, log)
	h := handlers{
		discovery: oidc.NewDiscovery(),
		jwks:      oidc.NewJWKS(),
		userinfo:  oidc.NewUserinfo(oidc.UserinfoConfig{Bearer: bearer, Log: log}),
		logout:    oidc.NewLogout(oidc.LogoutConfig{Verifier: verifier, Bearer: bearer, Store: e.Store, Users: manager, Clock: clk, Rand: secure.Default, Log: log}),
		revoke:    oidc.NewRevoke(oidc.RevokeConfig{Verifier: verifier, Store: e.Store, Clock: clk, Rand: secure.Default, Log: log}),
		sessions:  oidc.NewSessions(oidc.SessionsConfig{Bearer: bearer, Lister: ops, Log: log}),
		account:   oidc.NewAccount(oidc.AccountConfig{Bearer: bearer, Users: manager, Clock: clk, Log: log}),
		token:     oidc.NewToken(oidc.TokenConfig{Codes: e.Codes, Refresher: refresher, Audit: audit.NewWriter(e.Store, log, clk, secure.Default), Log: log}),
		authorize: oidc.NewAuthorize(oidc.AuthorizeConfig{Registry: reg, Store: e.Store, Clock: clk, Log: log, Verifier: verifier, Codes: e.Codes}),
		deletion:  oidc.NewDataDeletion(),
		events:    oidc.NewEvents(oidc.EventsConfig{Registry: reg, Users: manager, Rand: secure.Default, Log: log}),
		callback:  oidc.NewCallback(oidc.CallbackConfig{Registry: reg, Store: e.Store, Clock: clk, Log: log, Users: users, Codes: e.Codes, Box: box}),
	}
	e.Router = isrv.NewHandler(src, h, isrv.Middleware{Logger: log, Clock: clk, CORS: isrv.CORS()})
	return e
}

// handlers is the endpoints the service has so far; the others answer 404.
type handlers struct {
	discovery *oidc.Discovery
	authorize *oidc.Authorize
	callback  *oidc.Callback
	token     *oidc.Token
	jwks      *oidc.JWKS
	userinfo  *oidc.Userinfo
	logout    *oidc.Logout
	revoke    *oidc.Revoke
	sessions  *oidc.Sessions
	account   *oidc.Account
	events    *oidc.Events
	deletion  oidc.DataDeletion
}

var _ isrv.Handlers = handlers{}

func (h handlers) Authorize(w http.ResponseWriter, r *http.Request) { h.authorize.ServeHTTP(w, r) }
func (h handlers) Callback(w http.ResponseWriter, r *http.Request)  { h.callback.ServeCallback(w, r) }
func (h handlers) CallbackContinue(w http.ResponseWriter, r *http.Request) {
	h.callback.ServeContinue(w, r)
}
func (h handlers) Discovery(w http.ResponseWriter, r *http.Request)     { h.discovery.ServeHTTP(w, r) }
func (h handlers) Token(w http.ResponseWriter, r *http.Request)         { h.token.ServeHTTP(w, r) }
func (h handlers) Userinfo(w http.ResponseWriter, r *http.Request)      { h.userinfo.ServeHTTP(w, r) }
func (h handlers) JWKS(w http.ResponseWriter, r *http.Request)          { h.jwks.ServeHTTP(w, r) }
func (h handlers) Logout(w http.ResponseWriter, r *http.Request)        { h.logout.ServeHTTP(w, r) }
func (h handlers) Revoke(w http.ResponseWriter, r *http.Request)        { h.revoke.ServeHTTP(w, r) }
func (h handlers) Sessions(w http.ResponseWriter, r *http.Request)      { h.sessions.ServeHTTP(w, r) }
func (h handlers) AccountDelete(w http.ResponseWriter, r *http.Request) { h.account.ServeHTTP(w, r) }
func (handlers) Assets(w http.ResponseWriter, r *http.Request) {
	info, ok := isrv.FromContext(r.Context())
	if !ok || info.Realm == nil {
		http.NotFound(w, r)
		return
	}
	if !isrv.AllowMethods(w, r, http.MethodGet) {
		return
	}
	web.Assets(w, r, info.Realm)
}
func (h handlers) ProviderEvents(w http.ResponseWriter, r *http.Request) { h.events.ServeHTTP(w, r) }
func (h handlers) DataDeletion(w http.ResponseWriter, r *http.Request)   { h.deletion.ServeHTTP(w, r) }

// Authorize returns the parameters of a valid authorization request of the
// client at the provider; kv pairs replace or ("-") remove parameters.
func Authorize(c App, providerKey string, kv ...string) url.Values {
	v := url.Values{
		"client_id": {c.ID}, "redirect_uri": {c.RedirectURI}, "response_type": {"code"}, "scope": {"openid"},
		"state": {"st-1"}, "nonce": {"n-1"}, "code_challenge": {Challenge}, "code_challenge_method": {"S256"},
	}
	if providerKey != "" {
		v.Set("provider", providerKey)
	}
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] == "-" {
			v.Del(kv[i])
		} else {
			v.Set(kv[i], kv[i+1])
		}
	}
	return v
}

// Result is what the client receives at the end of a login.
type Result struct {
	// Mode is where the values came: "query", "fragment" or "form_post".
	Mode   string
	Values url.Values
	// URL is the redirect URI it was delivered to, without the values.
	URL string
}

// Client is a test browser with its own cookies. It reaches the service in
// process and the mock identity providers over loopback HTTP.
type Client struct {
	env  *Env
	jar  *cookiejar.Jar
	http *http.Client
}

// NewClient returns a browser with no cookies.
func (e *Env) NewClient() *Client {
	jar, _ := cookiejar.New(nil) // nil options cannot fail
	return &Client{env: e, jar: jar, http: &http.Client{
		Timeout:       10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

// Cookies are the cookies the browser would send to the service now.
func (b *Client) Cookies() []*http.Cookie {
	u, _ := url.Parse(PublicURL + "/main/callback/x")
	return b.jar.Cookies(u)
}

// Response is an answer, from the service or a mock.
type Response struct {
	Code   int
	Header http.Header
	Body   string
}

// Do sends one request without following redirects. The service's host is
// answered in process, with the cookies of the jar and recording the ones it
// sets; any other host over HTTP.
func (b *Client) Do(t testing.TB, method, rawURL string, form url.Values) Response {
	t.Helper()
	var body string
	var h http.Header
	if form != nil {
		body = form.Encode()
		h = http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}
	}
	return b.Request(t, method, rawURL, body, h)
}

// Request is Do with a raw body and request headers.
func (b *Client) Request(t testing.TB, method, rawURL, rawBody string, header http.Header) Response {
	t.Helper()

	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	var body io.Reader
	if rawBody != "" {
		body = strings.NewReader(rawBody)
	}
	if u.Scheme+"://"+u.Host != PublicURL {
		req, err := http.NewRequestWithContext(context.Background(), method, rawURL, body)
		if err != nil {
			t.Fatal(err)
		}
		for k, v := range header {
			req.Header[k] = v
		}
		resp, err := b.http.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, rawURL, err)
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(resp.Body)
		return Response{Code: resp.StatusCode, Header: resp.Header, Body: string(data)}
	}
	req := httptest.NewRequest(method, rawURL, body)
	req.RemoteAddr = "192.0.2.10:4000"
	for k, v := range header {
		req.Header[k] = v
	}
	for _, c := range b.jar.Cookies(u) {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	b.env.Router.ServeHTTP(rec, req)
	b.jar.SetCookies(u, rec.Result().Cookies())
	return Response{Code: rec.Code, Header: rec.Header(), Body: rec.Body.String()}
}

var (
	formAction  = regexp.MustCompile(`<form[^>]*action="([^"]*)"`)
	hiddenField = regexp.MustCompile(`<input type="hidden" name="([^"]*)" value="([^"]*)">`)
)

// Login runs a login the way a browser does, from the authorization request
// until the result reaches a URL that is neither the service nor a mock
// provider: it follows redirects and submits the forms of the pages
// (Apple's form POST and the service's form_post page).
func (b *Client) Login(t testing.TB, authorize url.Values) Result {
	t.Helper()
	return b.LoginAt(t, b.env.Realm.EndpointURL(config.EndpointAuthorize, ""), authorize)
}

// LoginAt is Login at the authorize URL of another realm.
func (b *Client) LoginAt(t testing.TB, authorizeURL string, authorize url.Values) Result {
	t.Helper()
	method, cur, form := "GET", authorizeURL+"?"+authorize.Encode(), url.Values(nil)
	own := func(u *url.URL) bool {
		return u.Scheme+"://"+u.Host == PublicURL || strings.HasPrefix(u.Host, "127.0.0.1:")
	}
	for range 12 {
		resp := b.Do(t, method, cur, form)
		base, _ := url.Parse(cur)
		switch {
		case resp.Code >= 300 && resp.Code < 400:
			next, err := base.Parse(resp.Header.Get("Location"))
			if err != nil {
				t.Fatal(err)
			}
			if !own(next) {
				return resultOf(t, next)
			}
			method, cur, form = "GET", next.String(), nil
		case resp.Code == http.StatusOK && formAction.MatchString(resp.Body):
			action, err := base.Parse(html.UnescapeString(formAction.FindStringSubmatch(resp.Body)[1]))
			if err != nil {
				t.Fatal(err)
			}
			fields := url.Values{}
			for _, m := range hiddenField.FindAllStringSubmatch(resp.Body, -1) {
				fields.Add(html.UnescapeString(m[1]), html.UnescapeString(m[2]))
			}
			if !own(action) {
				return Result{Mode: "form_post", Values: fields, URL: action.String()}
			}
			method, cur, form = "POST", action.String(), fields
		default:
			t.Fatalf("%s %s: status %d, body %s", method, cur, resp.Code, resp.Body)
		}
	}
	t.Fatal("too many redirects")
	return Result{}
}

// resultOf reads the values of a redirect to the client.
func resultOf(t testing.TB, u *url.URL) Result {
	t.Helper()
	bare := *u
	bare.RawQuery, bare.Fragment = "", ""
	if u.Fragment != "" {
		v, err := url.ParseQuery(u.Fragment)
		if err != nil {
			t.Fatal(err)
		}
		return Result{Mode: "fragment", Values: v, URL: bare.String()}
	}
	return Result{Mode: "query", Values: u.Query(), URL: bare.String()}
}

// Exchange trades the code of a result at the token service as the client
// would, with Verifier, and fails the test when it does not work.
func (e *Env) Exchange(t testing.TB, c App, r Result) *token.Grant {
	t.Helper()
	g, err := e.Codes.Exchange(context.Background(), token.ExchangeInput{
		Realm: e.Realm, Client: e.Realm.Clients[config.ClientID(c.ID)], Code: r.Values.Get("code"),
		RedirectURI: c.RedirectURI, Verifier: Verifier,
	})
	if err != nil {
		t.Fatalf("the delivered code does not work: %v", err)
	}
	return g
}

// Reload rewrites the realm file with change applied to its YAML and reloads
// the configuration; it fails the test when the reload is not applied. Env.Realm
// is replaced by the new realm.
func (e *Env) Reload(t testing.TB, change func(yaml string) string) {
	t.Helper()
	e.realmYAML = change(e.realmYAML)
	e.dir.Realm(t, "main", e.realmYAML)
	res := e.loader.Reload(context.Background())
	if !res.Applied {
		t.Fatalf("reload not applied: %v", res.Diagnostics)
	}
	for _, d := range res.Diagnostics {
		if d.Severity == config.Error {
			t.Fatalf("reload reported an error: %+v", d)
		}
	}
	e.Snapshot = e.loader.Current()
	e.Realm, _ = e.Snapshot.Realm("main")
}

// ReloadDiagnostics rewrites the realm file with change applied, reloads, and
// returns the error diagnostics of the reload. The change is not kept: the
// original file is written back and reloaded, so the Env stays valid.
func (e *Env) ReloadDiagnostics(t testing.TB, change func(yaml string) string) []config.Diagnostic {
	t.Helper()
	orig := e.realmYAML
	e.dir.Realm(t, "main", change(orig))
	res := e.loader.Reload(context.Background())
	var errs []config.Diagnostic
	for _, d := range res.Diagnostics {
		if d.Severity == config.Error {
			errs = append(errs, d)
		}
	}
	e.dir.Realm(t, "main", orig)
	e.loader.Reload(context.Background())
	e.Snapshot = e.loader.Current()
	e.Realm, _ = e.Snapshot.Realm("main")
	return errs
}

// ReloadServer is Reload for server.yaml.
func (e *Env) ReloadServer(t testing.TB, change func(yaml string) string) {
	t.Helper()
	e.serverYAML = change(e.serverYAML)
	e.dir.Server(t, e.serverYAML)
	res := e.loader.Reload(context.Background())
	if !res.Applied {
		t.Fatalf("reload not applied: %v", res.Diagnostics)
	}
	for _, d := range res.Diagnostics {
		if d.Severity == config.Error {
			t.Fatalf("reload reported an error: %+v", d)
		}
	}
	e.Snapshot = e.loader.Current()
	e.Realm, _ = e.Snapshot.Realm("main")
}

// AddRealm adds a realm of this name to the configuration directory and
// reloads: a copy of "main" with a signing key of its own, the same clients,
// providers and mock identity providers. Env.Realm stays "main".
func (e *Env) AddRealm(t testing.TB, name string) *config.Realm {
	t.Helper()
	e.dir.RSAKey(t, "secrets/"+name+"/signing.pem")
	y := strings.Replace(e.realmYAML, "name: main\n", "name: "+name+"\n", 1)
	y = strings.Replace(y, "kid: main-1, file: secrets/main/signing.pem", "kid: "+name+"-1, file: secrets/"+name+"/signing.pem", 1)
	e.dir.Realm(t, name, y)
	res := e.loader.Reload(context.Background())
	if !res.Applied {
		t.Fatalf("reload not applied: %v", res.Diagnostics)
	}
	for _, d := range res.Diagnostics {
		if d.Severity == config.Error {
			t.Fatalf("reload reported an error: %+v", d)
		}
	}
	e.Snapshot = e.loader.Current()
	e.Realm, _ = e.Snapshot.Realm("main")
	r, _ := e.Snapshot.Realm(config.RealmName(name))
	return r
}

// RefreshForm is the body of a refresh request of the app, with its secret
// when the app is the confidential client that authenticates with one in the
// body.
func (e *Env) RefreshForm(app App, refreshToken string) url.Values {
	f := RefreshForm(app, refreshToken)
	if _, ok := e.Realm.Clients[config.ClientID(app.ID)]; ok && e.Realm.Clients[config.ClientID(app.ID)].Type == config.Confidential {
		f.Set("client_secret", e.Secret(app.ID))
	}
	return f
}

// Secret returns the secret of a confidential client.
func (e *Env) Secret(clientID string) string {
	return e.Snapshot.Secrets().ClientSecret("main", config.ClientSecretOf, clientID)
}

// Login logs a user in through Google as the client, with a new browser, and
// returns the result; kv replaces or removes authorization parameters (see
// Authorize). The user is the same on every call.
func (e *Env) Login(t testing.TB, app App, kv ...string) Result {
	t.Helper()
	e.Mocks["google"].SetUser(mockidp.User{
		Sub: "1001", Name: "Ann Lee", Email: "ann@example.com", EmailVerified: true,
	})
	return e.NewClient().Login(t, Authorize(app, "google", kv...))
}

// SetDisabled disables or enables the user the Google login of Login creates.
func (e *Env) SetDisabled(t testing.TB, disabled bool) {
	t.Helper()
	ctx := context.Background()
	err := e.Store.Write(ctx, func(tx store.Tx) error {
		rid, err := tx.Realms().Find(ctx, "main")
		if err != nil {
			return err
		}
		ident, err := tx.Identities().Find(ctx, rid, "google", "1001")
		if err != nil {
			return err
		}
		u, err := tx.Users().Get(ctx, rid, ident.UserID)
		if err != nil {
			return err
		}
		u.DisabledAt = time.Time{}
		if disabled {
			u.DisabledAt = e.Clock.Now()
		}
		return tx.Users().Update(ctx, u)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// CodeForm is the body of a code exchange with Verifier; kv replaces or ("-")
// removes parameters.
func CodeForm(app App, r Result, kv ...string) url.Values {
	return formWith(url.Values{
		"grant_type": {"authorization_code"}, "client_id": {app.ID}, "code": {r.Values.Get("code")},
		"redirect_uri": {app.RedirectURI}, "code_verifier": {Verifier},
	}, kv)
}

// RefreshForm is the body of a refresh request.
func RefreshForm(app App, refreshToken string, kv ...string) url.Values {
	return formWith(url.Values{"grant_type": {"refresh_token"}, "client_id": {app.ID}, "refresh_token": {refreshToken}}, kv)
}

func formWith(v url.Values, kv []string) url.Values {
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] == "-" {
			v.Del(kv[i])
		} else {
			v.Set(kv[i], kv[i+1])
		}
	}
	return v
}

// PostToken sends a form to the token endpoint; header adds request headers.
func (b *Client) PostToken(t testing.TB, form url.Values, header http.Header) Response {
	t.Helper()
	h := http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}
	for k, v := range header {
		h[k] = v
	}
	return b.Request(t, http.MethodPost, b.env.Realm.EndpointURL(config.EndpointToken, ""), form.Encode(), h)
}

// Tokens are the fields of a token response.
type Tokens struct {
	AccessToken      string `json:"access_token"`
	IDToken          string `json:"id_token"`
	RefreshToken     string `json:"refresh_token"`
	TokenType        string `json:"token_type"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
	Scope            string `json:"scope"`
	Error            string `json:"error"`
	Description      string `json:"error_description"`
}

// Tokens decodes the JSON body of a token response.
func (r Response) Tokens(t testing.TB) Tokens {
	t.Helper()
	var tk Tokens
	if err := json.Unmarshal([]byte(r.Body), &tk); err != nil {
		t.Fatalf("body %q is not JSON: %v", r.Body, err)
	}
	return tk
}

package config

import (
	"log/slog"
	"maps"
	"path"
	"slices"
	"strings"
	"time"
)

// RealmName, ClientID and ProviderKey are distinct types so that arguments
// cannot be swapped silently.
type (
	RealmName   string
	ClientID    string
	ProviderKey string
)

// Endpoint names one of the endpoints configured under urls.endpoints.
type Endpoint string

// The endpoints of urls.endpoints.
const (
	EndpointAuthorize      Endpoint = "authorize"
	EndpointToken          Endpoint = "token"
	EndpointUserinfo       Endpoint = "userinfo"
	EndpointJWKS           Endpoint = "jwks"
	EndpointLogout         Endpoint = "logout"
	EndpointRevoke         Endpoint = "revoke"
	EndpointSessions       Endpoint = "sessions"
	EndpointCallback       Endpoint = "callback"
	EndpointAccountDelete  Endpoint = "account_delete"
	EndpointAssets         Endpoint = "assets"
	EndpointProviderEvents Endpoint = "provider_events"
	EndpointDataDeletion   Endpoint = "data_deletion"
)

// Lifetimes are the effective lifetimes of a client: its own value, else the
// realm's.
type Lifetimes struct {
	AccessToken time.Duration
	RefreshIdle time.Duration
	// SessionMax is the longest a session lasts; 0 means no cap.
	SessionMax time.Duration
}

// Source gives the current configuration. Callers take one snapshot per
// request and use it throughout.
type Source interface{ Current() *Snapshot }

type static struct{ s *Snapshot }

var _ Source = static{}

// Static returns a Source that always returns s.
func Static(s *Snapshot) Source { return static{s} }

// Current implements Source.
func (s static) Current() *Snapshot { return s.s }

// Snapshot is a validated view of the whole configuration. It copies its
// inputs, and Server, Database and Realms return fresh copies. The realms,
// clients and providers it exposes are shared: callers MUST NOT modify them
// or the maps and slices inside them.
type Snapshot struct {
	server   ServerFile
	database DatabaseFile
	realms   map[RealmName]*Realm
	order    []RealmName // sorted
	secrets  Secrets
}

var _ slog.LogValuer = (*Snapshot)(nil)

// NewSnapshot resolves already validated files into a snapshot. db and
// secrets may be nil. The realm names must be unique.
func NewSnapshot(srv *ServerFile, db *DatabaseFile, realms []*RealmFile, secrets Secrets) *Snapshot {
	s := &Snapshot{server: cloneServer(srv), realms: map[RealmName]*Realm{}, secrets: secrets}
	if db != nil {
		s.database = cloneDatabase(db)
	}
	for _, rf := range realms {
		r := newRealm(s.server, rf)
		s.realms[r.Name] = r
	}
	s.order = slices.Sorted(maps.Keys(s.realms))
	return s
}

// Server returns a copy of the server options.
func (s *Snapshot) Server() ServerFile { return cloneServer(&s.server) }

// Database returns a copy of the database options.
func (s *Snapshot) Database() DatabaseFile { return cloneDatabase(&s.database) }

// Secrets returns the loaded secrets, or nil.
func (s *Snapshot) Secrets() Secrets { return s.secrets }

// Realm returns the realm with the given name.
func (s *Snapshot) Realm(name RealmName) (*Realm, bool) {
	r, ok := s.realms[name]
	return r, ok
}

// Realms returns every realm sorted by name, in a new slice.
func (s *Snapshot) Realms() []*Realm {
	out := make([]*Realm, len(s.order))
	for i, n := range s.order {
		out[i] = s.realms[n]
	}
	return out
}

// LogValue logs only the number of realms and what the secrets log.
func (s *Snapshot) LogValue() slog.Value {
	attrs := []slog.Attr{slog.Int("realm_count", len(s.realms))}
	if s.secrets != nil {
		attrs = append(attrs, slog.Any("loaded", s.secrets))
	}
	return slog.GroupValue(attrs...)
}

// Realm is a resolved realm. It is shared between callers: its exported
// fields, including the Clients and Providers maps and slices such as Keys,
// are not copied on access and MUST NOT be modified.
type Realm struct {
	Name            RealmName
	DisplayName     string
	Enabled         bool
	Tokens          Tokens
	SSO             SSO
	Keys            []Key
	UserData        UserData
	LoginPage       LoginPage
	SecurityHeaders SecurityHeaders
	Providers       map[ProviderKey]*Provider
	Clients         map[ClientID]*Client

	publicURL  string
	urls       URLs
	hintParams []string
	messages   map[string]map[string]string
}

// Messages returns a copy of the translation of a supported locale, which
// maps message ids to text, or nil when the realm has no translation file for
// code. "en" is built in and has none.
func (r *Realm) Messages(code string) map[string]string {
	m, ok := r.messages[code]
	if !ok {
		return nil
	}
	return maps.Clone(m)
}

func newRealm(srv ServerFile, rf *RealmFile) *Realm {
	var accessClaims *[]string
	if rf.UserData.AccessTokenClaims != nil {
		list := slices.Clone(*rf.UserData.AccessTokenClaims)
		accessClaims = &list
	}
	r := &Realm{
		Name:        RealmName(rf.Name),
		DisplayName: rf.DisplayName,
		Enabled:     rf.Enabled,
		Tokens:      rf.Tokens,
		SSO:         rf.SSO,
		Keys:        slices.Clone(rf.Keys),
		UserData: UserData{
			Attributes:        slices.Clone(rf.UserData.Attributes),
			Claims:            slices.Clone(rf.UserData.Claims),
			KeepNameIfMissing: rf.UserData.KeepNameIfMissing,
			IDFormat:          rf.UserData.IDFormat,
			AutoLinkDomains:   slices.Clone(rf.UserData.AutoLinkDomains),
			AccessTokenClaims: accessClaims,
		},
		LoginPage:       rf.LoginPage,
		SecurityHeaders: rf.SecurityHeaders,
		Providers:       make(map[ProviderKey]*Provider, len(rf.Providers)),
		Clients:         make(map[ClientID]*Client, len(rf.Clients)),
		publicURL:       srv.PublicURL,
		urls:            srv.URLs,
		hintParams:      slices.Clone(srv.Login.ProviderHintParams),
	}
	if rf.locales != nil {
		r.messages = make(map[string]map[string]string, len(rf.locales))
		for code, m := range rf.locales {
			r.messages[code] = maps.Clone(m)
		}
	}
	r.LoginPage.ProviderOrder = slices.Clone(rf.LoginPage.ProviderOrder)
	r.LoginPage.SupportedLocales = slices.Clone(rf.LoginPage.SupportedLocales)
	for k, p := range rf.Providers {
		r.Providers[ProviderKey(k)] = cloneProvider(p)
	}
	for id, c := range rf.Clients {
		cc := cloneClient(c)
		cc.realm = r
		r.Clients[ClientID(id)] = cc
	}
	return r
}

// expand fills the placeholders of a path template.
func (r *Realm) expand(tmpl, provider string) string {
	return strings.NewReplacer("{prefix}", r.urls.PathPrefix, "{realm}", string(r.Name), "{provider}", provider).Replace(tmpl)
}

func (r *Realm) template(e Endpoint) string {
	ep := r.urls.Endpoints
	switch e {
	case EndpointAuthorize:
		return ep.Authorize
	case EndpointToken:
		return ep.Token
	case EndpointUserinfo:
		return ep.Userinfo
	case EndpointJWKS:
		return ep.JWKS
	case EndpointLogout:
		return ep.Logout
	case EndpointRevoke:
		return ep.Revoke
	case EndpointSessions:
		return ep.Sessions
	case EndpointCallback:
		return ep.Callback
	case EndpointAccountDelete:
		return ep.AccountDelete
	case EndpointAssets:
		return ep.Assets
	case EndpointProviderEvents:
		return ep.ProviderEvents
	case EndpointDataDeletion:
		return ep.DataDeletion
	}
	return ""
}

// Issuer is public_url followed by the urls.issuer path.
func (r *Realm) Issuer() string { return r.publicURL + r.expand(r.urls.Issuer, "") }

// EndpointPath is the path of e; p is used only by the callback and the
// provider events endpoints.
func (r *Realm) EndpointPath(e Endpoint, p ProviderKey) string {
	return r.expand(r.template(e), string(p))
}

// EndpointURL is the full URL of e under public_url.
func (r *Realm) EndpointURL(e Endpoint, p ProviderKey) string {
	return r.publicURL + r.EndpointPath(e, p)
}

// ProviderHintParams returns the names of the authorize parameters that pick a
// provider (login.provider_hint_params), in order of precedence.
func (r *Realm) ProviderHintParams() []string { return slices.Clone(r.hintParams) }

// SSOCookiePath is the path of the browser session cookie (FR-45, SEC-37): the
// longest common directory of the authorize and logout paths, so that the cookie
// reaches both and nothing wider; "/" when they share none.
func (r *Realm) SSOCookiePath() string {
	a := strings.Split(path.Dir(r.EndpointPath(EndpointAuthorize, "")), "/")
	l := strings.Split(path.Dir(r.EndpointPath(EndpointLogout, "")), "/")
	var common []string
	for i := 0; i < len(a) && i < len(l) && a[i] == l[i]; i++ {
		common = append(common, a[i])
	}
	if p := strings.Join(common, "/"); p != "" {
		return p
	}
	return "/"
}

// StateCookiePath is the callback path up to {provider}, with its trailing
// slash, such as /main/callback/.
func (r *Realm) StateCookiePath() string {
	t, _, _ := strings.Cut(r.urls.Endpoints.Callback, "{provider}")
	return r.expand(t, "")
}

// PostLogoutURIRegistered reports whether uri is a post-logout URI of any
// client of the realm, and which one (the first by client id).
func (r *Realm) PostLogoutURIRegistered(uri string) (ClientID, bool) {
	for _, id := range slices.Sorted(maps.Keys(r.Clients)) {
		if slices.Contains(r.Clients[id].PostLogoutURIs(), uri) {
			return id, true
		}
	}
	return "", false
}

// Rotates reports whether the client's refresh tokens rotate: always for a
// public client, else the client's setting, else the realm's. A client that
// NewSnapshot did not build has no realm and rotates unless it sets false.
func (c *Client) Rotates() bool {
	if c.Type == Public {
		return true
	}
	if c.RefreshTokenRotation != nil {
		return *c.RefreshTokenRotation
	}
	if c.realm == nil {
		return true
	}
	return c.realm.Tokens.RefreshTokenRotation
}

// Lifetimes returns the effective lifetimes. A client that NewSnapshot did
// not build has no realm value to fall back to, so an option it does not set
// is 0.
func (c *Client) Lifetimes() Lifetimes {
	pick := func(own *Duration, realm Duration) time.Duration {
		if own != nil {
			return own.Std()
		}
		return realm.Std()
	}
	var t Tokens
	if c.realm != nil {
		t = c.realm.Tokens
	}
	return Lifetimes{
		AccessToken: pick(c.AccessTokenLifetime, t.AccessTokenLifetime),
		RefreshIdle: pick(c.RefreshIdleLifetime, t.RefreshIdleLifetime),
		SessionMax:  pick(c.SessionMaxLifetime, t.SessionMaxLifetime),
	}
}

// PostLogoutURIs returns a copy of the registered post-logout URIs; a client
// that lists none uses its redirect URIs.
func (c *Client) PostLogoutURIs() []string {
	if len(c.PostLogoutRedirectURIs) > 0 {
		return slices.Clone(c.PostLogoutRedirectURIs)
	}
	return slices.Clone(c.RedirectURIs)
}

func cloneServer(s *ServerFile) ServerFile {
	c := *s
	c.Secrets.EncryptionKeyFiles = slices.Clone(s.Secrets.EncryptionKeyFiles)
	c.TrustedProxies = slices.Clone(s.TrustedProxies)
	c.Login.ProviderHintParams = slices.Clone(s.Login.ProviderHintParams)
	c.Logout.RedirectParams = slices.Clone(s.Logout.RedirectParams)
	return c
}

func cloneDatabase(d *DatabaseFile) DatabaseFile { return *d }

func cloneProvider(p *Provider) *Provider {
	c := *p
	c.Scopes = slices.Clone(p.Scopes)
	c.NotificationAudiences = slices.Clone(p.NotificationAudiences)
	c.Fields = slices.Clone(p.Fields)
	return &c
}

func cloneClient(cl *Client) *Client {
	c := *cl
	c.RedirectURIs = slices.Clone(cl.RedirectURIs)
	c.PostLogoutRedirectURIs = slices.Clone(cl.PostLogoutRedirectURIs)
	c.WebOrigins = slices.Clone(cl.WebOrigins)
	c.AccessTokenLifetime = clonePtr(cl.AccessTokenLifetime)
	c.RefreshIdleLifetime = clonePtr(cl.RefreshIdleLifetime)
	c.SessionMaxLifetime = clonePtr(cl.SessionMaxLifetime)
	c.RefreshTokenRotation = clonePtr(cl.RefreshTokenRotation)
	return &c
}

func clonePtr[T any](p *T) *T {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

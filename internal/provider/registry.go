package provider

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"reflect"
	"slices"
	"sync"
	"time"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/config"
)

// Registry gives the login adapters of each realm.
type Registry interface {
	// Get returns the adapter of an enabled provider (a hidden one too), or
	// false when there is none or it cannot be built now.
	Get(realm config.RealmName, key config.ProviderKey) (Provider, bool)
	// Visible lists the enabled providers that are not hidden, in the order of
	// login_page.provider_order, the others following by key.
	Visible(realm config.RealmName) []config.ProviderKey
}

// discoveryRetry is how long a provider that could not be built waits before
// the next attempt. It is fixed, not an option (Provider calls).
const discoveryRetry = 30 * time.Second

// spec is everything needed to build one adapter, resolved from the
// configuration with no Go zero values left where the design has a default.
type spec struct {
	kind     string // "oidc", "google", "apple", "github" or "facebook"
	oidc     OIDCOptions
	google   GoogleOptions
	apple    AppleOptions
	github   GitHubOptions
	facebook FacebookOptions
}

// newSpec resolves one provider of a realm. Every type needs a loaded client
// secret (Apple: its key).
func newSpec(clk clock.Clock, r *config.Realm, key config.ProviderKey, p *config.Provider, secrets config.Secrets) (spec, error) {
	redirect := r.EndpointURL(config.EndpointCallback, key)
	timeout := p.Timeout.Std()
	endpoints := OIDCEndpoints{Authorize: p.Endpoints.Authorize, Token: p.Endpoints.Token, JWKS: p.Endpoints.JWKS, Userinfo: p.Endpoints.Userinfo}
	oidcBase := func(issuer, secret string) OIDCOptions {
		return OIDCOptions{
			Issuer: issuer, ClientID: p.ClientID, ClientSecret: secret, RedirectURI: redirect, Scopes: openIDScopes(p.Scopes),
			Endpoints: endpoints, Timeout: timeout, Clock: clk,
		}
	}

	if p.Type == "apple" {
		var k []byte
		if secrets != nil {
			if ec := secrets.AppleKey(string(r.Name), string(key)); ec != nil {
				der, err := x509.MarshalPKCS8PrivateKey(ec)
				if err != nil {
					return spec{}, errors.New("the Apple key cannot be encoded")
				}
				k = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
			}
		}
		if k == nil {
			return spec{}, errors.New("the Apple key is not loaded")
		}
		o := oidcBase(AppleIssuer, "")
		o.Scopes = slices.Clone(p.Scopes) // validated: name and email, each once; empty asks for none
		o.Endpoints.Userinfo = ""         // Apple has no user-info endpoint
		// RevokeURL stays empty: the design has no revoke endpoint override.
		return spec{kind: "apple", apple: AppleOptions{
			OIDCOptions: o, TeamID: p.TeamID, KeyID: p.KeyID, PrivateKeyPEM: k,
			Lifetime: p.ClientSecretLifetime.Std(), StoreRefreshToken: p.StoreRefreshToken, NotificationAudiences: slices.Clone(p.NotificationAudiences),
		}}, nil
	}

	var secret string
	if secrets != nil {
		secret = secrets.ClientSecret(string(r.Name), config.ProviderSecret, string(key))
	}
	if secret == "" {
		return spec{}, errors.New("the client secret is not loaded")
	}
	switch p.Type {
	case "oidc":
		return spec{kind: "oidc", oidc: oidcBase(p.Issuer, secret)}, nil
	case "google":
		return spec{kind: "google", google: GoogleOptions{
			OIDCOptions: oidcBase(GoogleIssuer, secret), HostedDomain: p.HostedDomain, RISCConfigurationURL: p.Endpoints.RISCConfiguration,
		}}, nil
	case "github":
		// endpoints.userinfo replaces the URL of GET /user; /user/emails keeps
		// its fixed URL.
		return spec{kind: "github", github: GitHubOptions{
			ClientID: p.ClientID, ClientSecret: secret, RedirectURI: redirect, Scopes: slices.Clone(p.Scopes),
			PKCE: p.PKCE, AllowSignup: p.AllowSignup, RequireVerifiedEmail: p.RequireVerifiedEmail,
			AuthorizeURL: p.Endpoints.Authorize, TokenURL: p.Endpoints.Token, UserURL: p.Endpoints.Userinfo, Timeout: timeout,
		}}, nil
	case "facebook":
		if p.Flow != "oauth" { // config validation rejects any other value
			return spec{}, fmt.Errorf("facebook flow %q is not supported", p.Flow)
		}
		return spec{kind: "facebook", facebook: FacebookOptions{
			ClientID: p.ClientID, ClientSecret: secret, RedirectURI: redirect, GraphVersion: p.GraphVersion,
			Scopes: slices.Clone(p.Scopes), Fields: slices.Clone(p.Fields), RequireEmail: p.RequireEmail,
			AuthorizeURL: p.Endpoints.Authorize, TokenURL: p.Endpoints.Token, MeURL: p.Endpoints.Userinfo, Timeout: timeout,
			Clock: clk,
		}}, nil
	}
	return spec{}, fmt.Errorf("unknown provider type %q", p.Type)
}

// openIDScopes gives the scopes of an OpenID Connect login: an OpenID Connect
// request must have openid, so it is added when missing, and a provider with
// no scopes configured (the generic type has no design default) asks for
// openid, email and profile like Google's default.
func openIDScopes(scopes []string) []string {
	if len(scopes) == 0 {
		return []string{"openid", "email", "profile"}
	}
	if !slices.Contains(scopes, "openid") {
		return append([]string{"openid"}, scopes...)
	}
	return slices.Clone(scopes)
}

// build makes the adapter. For the generic and Google adapters this fetches
// the provider's discovery document.
func (s spec) build(ctx context.Context) (Provider, error) {
	switch s.kind {
	case "oidc":
		p, err := NewOIDC(ctx, s.oidc)
		if err != nil {
			return nil, err
		}
		return p, nil
	case "google":
		p, err := NewGoogle(ctx, s.google)
		if err != nil {
			return nil, err
		}
		return p, nil
	case "apple":
		p, err := NewApple(ctx, s.apple)
		if err != nil {
			return nil, err
		}
		return p, nil
	case "github":
		p, err := NewGitHub(s.github)
		if err != nil {
			return nil, err
		}
		return p, nil
	case "facebook":
		p, err := NewFacebook(s.facebook)
		if err != nil {
			return nil, err
		}
		return p, nil
	}
	return nil, fmt.Errorf("unknown provider kind %q", s.kind)
}

// idleCloser is implemented by every adapter.
type idleCloser interface{ CloseIdleConnections() }

var (
	_ idleCloser = (*OIDC)(nil)
	_ idleCloser = (*Apple)(nil)
	_ idleCloser = (*GitHub)(nil)
	_ idleCloser = (*Facebook)(nil)
)

// flight is one discovery in progress; waiting callers share its result.
type flight struct {
	done    chan struct{}
	adapter Provider // set before done is closed; nil when it failed
}

// entry is one provider of one realm. It is shared by the snapshots in which
// the provider's resolved spec is unchanged, so a reload keeps the adapter
// and its key cache.
type entry struct {
	realm config.RealmName
	key   config.ProviderKey
	spec  spec

	mu      sync.Mutex
	adapter Provider
	failed  bool
	retryAt time.Time
	flight  *flight
	retired bool // a reload replaced it
}

// retire marks the entry replaced and closes its adapter's idle connections.
// A call in progress is not disturbed.
func (e *entry) retire() {
	e.mu.Lock()
	e.retired = true
	a := e.adapter
	e.mu.Unlock()
	closeIdle(a)
}

func closeIdle(a Provider) {
	if c, ok := a.(idleCloser); ok {
		c.CloseIdleConnections()
	}
}

type realmSet struct {
	visible []config.ProviderKey
	entries map[config.ProviderKey]*entry
}

// Pool is the Registry: it builds the adapters of every realm of the current
// configuration snapshot, on first use, and swaps them when a reload gives a
// new snapshot.
type Pool struct {
	src config.Source
	clk clock.Clock
	log *slog.Logger

	mu     sync.Mutex
	snap   *config.Snapshot
	realms map[config.RealmName]*realmSet
}

var (
	_ Registry       = (*Pool)(nil)
	_ slog.LogValuer = (*Pool)(nil)
)

// NewPool returns a registry that follows src. Adapters are built when first
// asked for; a provider whose discovery fails is retried at most every 30
// seconds by the clock clk.
func NewPool(src config.Source, clk clock.Clock, log *slog.Logger) *Pool {
	return &Pool{src: src, clk: clk, log: log}
}

// LogValue implements slog.LogValuer. The registry holds client secrets, so
// only the number of realms is logged.
func (p *Pool) LogValue() slog.Value {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slog.GroupValue(slog.Int("realm_count", len(p.realms)))
}

// current returns the sets of the current snapshot, rebuilding them when a
// reload swapped the snapshot. Unchanged providers keep their entry; the
// others are retired.
func (p *Pool) current() map[config.RealmName]*realmSet {
	p.mu.Lock()
	defer p.mu.Unlock()
	// Read under the lock: a caller that read an older snapshot before taking
	// it could otherwise flip the registry back to it.
	snap := p.src.Current()
	if snap == p.snap && p.realms != nil {
		return p.realms
	}
	old := p.realms
	next := map[config.RealmName]*realmSet{}
	kept := map[*entry]bool{}
	if snap != nil {
		for _, r := range snap.Realms() {
			next[r.Name] = p.newRealmSet(snap, r, old[r.Name], kept)
		}
	}
	p.snap, p.realms = snap, next
	for _, rs := range old {
		for _, e := range rs.entries {
			if !kept[e] {
				e.retire()
			}
		}
	}
	return next
}

func (p *Pool) newRealmSet(snap *config.Snapshot, r *config.Realm, old *realmSet, kept map[*entry]bool) *realmSet {
	rs := &realmSet{entries: map[config.ProviderKey]*entry{}}
	for _, key := range slices.Sorted(maps.Keys(r.Providers)) {
		cfg := r.Providers[key]
		if !cfg.Enabled {
			continue
		}
		sp, err := newSpec(p.clk, r, key, cfg, snap.Secrets())
		if err != nil {
			p.log.Warn("provider not usable", "realm", string(r.Name), "provider", string(key), "err", err)
			continue // no entry: Get finds none
		}
		if old != nil {
			if oe := old.entries[key]; oe != nil && reflect.DeepEqual(oe.spec, sp) {
				rs.entries[key] = oe
				kept[oe] = true
				continue
			}
		}
		rs.entries[key] = &entry{realm: r.Name, key: key, spec: sp}
	}
	// Visible: enabled and not hidden, in login_page.provider_order, then the rest by key.
	var shown []config.ProviderKey
	for key := range rs.entries {
		if !r.Providers[key].Hidden {
			shown = append(shown, key)
		}
	}
	slices.Sort(shown)
	for _, name := range slices.Backward(r.LoginPage.ProviderOrder) {
		k := config.ProviderKey(name)
		if i := slices.Index(shown, k); i >= 0 {
			shown = slices.Insert(slices.Delete(shown, i, i+1), 0, k)
		}
	}
	rs.visible = shown
	return rs
}

// Get implements Registry.
func (p *Pool) Get(realm config.RealmName, key config.ProviderKey) (Provider, bool) {
	rs := p.current()[realm]
	if rs == nil {
		return nil, false
	}
	e := rs.entries[key]
	if e == nil {
		return nil, false
	}
	a := e.provider(p)
	return a, a != nil
}

// Visible implements Registry.
func (p *Pool) Visible(realm config.RealmName) []config.ProviderKey {
	rs := p.current()[realm]
	if rs == nil {
		return nil
	}
	return slices.Clone(rs.visible)
}

// provider returns the adapter, building it when it does not exist yet. One
// build is shared by concurrent callers; after a failure no new build is made
// for 30 seconds. The build uses the adapter's own client and timeout.
func (e *entry) provider(p *Pool) Provider {
	e.mu.Lock()
	if e.adapter != nil {
		a := e.adapter
		e.mu.Unlock()
		return a
	}
	if f := e.flight; f != nil {
		e.mu.Unlock()
		<-f.done
		return f.adapter
	}
	if e.failed && p.clk.Now().Before(e.retryAt) {
		e.mu.Unlock()
		return nil
	}
	f := &flight{done: make(chan struct{})}
	e.flight = f
	e.mu.Unlock()

	a, err := e.spec.build(context.Background())

	e.mu.Lock()
	e.flight = nil
	if err != nil {
		e.failed, e.retryAt = true, p.clk.Now().Add(discoveryRetry)
		a = nil
	} else {
		e.adapter, e.failed = a, false
	}
	retired := e.retired
	f.adapter = a
	e.mu.Unlock()
	close(f.done)

	if err != nil {
		p.log.Warn("provider not available", "realm", string(e.realm), "provider", string(e.key), "err", err)
	} else if retired {
		closeIdle(a) // a reload replaced the entry while it was being built
	}
	return a
}

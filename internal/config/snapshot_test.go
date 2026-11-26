package config_test

import (
	"bytes"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/config/configtest"
	"github.com/yyudhistira/featherauth/internal/logx"
)

const realmYAML = `
name: main
display_name: EQ
tokens:
  access_token_lifetime: 10m
  refresh_idle_lifetime: 100h
  session_max_lifetime: 200h
  refresh_token_rotation: false
clients:
  web:
    type: confidential
    client_secret_file: secrets/web
    redirect_uris: ["https://app.example.com/cb"]
  web-over:
    type: confidential
    client_secret_file: secrets/web2
    redirect_uris: ["https://app2.example.com/cb"]
    post_logout_redirect_uris: ["https://app2.example.com/bye"]
    access_token_lifetime: 5m
    refresh_idle_lifetime: 1h
    session_max_lifetime: 2h
    refresh_token_rotation: true
  no-cap:
    type: confidential
    client_secret_file: secrets/nocap
    redirect_uris: ["https://nocap.example.com/cb"]
    session_max_lifetime: 0
  shared-a:
    type: public
    redirect_uris: ["https://shared.example.com/cb"]
  shared-b:
    type: public
    redirect_uris: ["https://shared.example.com/cb"]
  mobile:
    type: public
    redirect_uris: ["com.example.app:/callback", "http://127.0.0.1/cb"]
`

func decodeServer(t *testing.T, extra string) *config.ServerFile {
	t.Helper()
	s, ds := config.DecodeServer("server.yaml", []byte("public_url: https://auth.example.com\n"+extra))
	if len(ds) != 0 {
		t.Fatalf("server diagnostics: %v", ds)
	}
	return s
}

func decodeRealm(t *testing.T, text string) *config.RealmFile {
	t.Helper()
	r, ds := config.DecodeRealm("main.yaml", []byte(text))
	if len(ds) != 0 {
		t.Fatalf("realm diagnostics: %v", ds)
	}
	return r
}

func snapshot(t *testing.T, serverExtra string) *config.Snapshot {
	t.Helper()
	return config.NewSnapshot(decodeServer(t, serverExtra), nil, []*config.RealmFile{decodeRealm(t, realmYAML)}, nil)
}

const keycloakURLs = `urls:
  path_prefix: /auth
  issuer: "{prefix}/realms/{realm}"
  endpoints:
    authorize: "{prefix}/realms/{realm}/protocol/openid-connect/auth"
    token: "{prefix}/realms/{realm}/protocol/openid-connect/token"
    userinfo: "{prefix}/realms/{realm}/protocol/openid-connect/userinfo"
    jwks: "{prefix}/realms/{realm}/protocol/openid-connect/certs"
    logout: "{prefix}/realms/{realm}/protocol/openid-connect/logout"
    callback: "{prefix}/realms/{realm}/broker/{provider}/endpoint"
`

// Covers: FR-28 (part), FR-29 (part)
// Acceptance: Issuer with prefix (part)
// Acceptance: Non-default URLs and token format (part)
func TestURLBuilderLayouts(t *testing.T) {
	type paths struct {
		issuer, cookie                                                                       string
		authorize, token, userinfo, jwks, logout, callback, account, assets, events, deleted string
	}
	tests := []struct {
		name, server string
		want         paths
	}{
		{"default", "", paths{
			issuer: "https://auth.example.com/main", cookie: "/main/callback/",
			authorize: "/main/authorize", token: "/main/token", userinfo: "/main/userinfo", jwks: "/main/jwks.json",
			logout: "/main/logout", callback: "/main/callback/google", account: "/main/account", assets: "/main/assets",
			events: "/main/events/google", deleted: "/main/data-deletion",
		}},
		{"auth prefix", "urls:\n  path_prefix: /auth\n", paths{
			issuer: "https://auth.example.com/auth/main", cookie: "/auth/main/callback/",
			authorize: "/auth/main/authorize", token: "/auth/main/token", userinfo: "/auth/main/userinfo", jwks: "/auth/main/jwks.json",
			logout: "/auth/main/logout", callback: "/auth/main/callback/google", account: "/auth/main/account", assets: "/auth/main/assets",
			events: "/auth/main/events/google", deleted: "/auth/main/data-deletion",
		}},
		{"keycloak layout", keycloakURLs, paths{
			issuer: "https://auth.example.com/auth/realms/main", cookie: "/auth/realms/main/broker/",
			authorize: "/auth/realms/main/protocol/openid-connect/auth", token: "/auth/realms/main/protocol/openid-connect/token",
			userinfo: "/auth/realms/main/protocol/openid-connect/userinfo", jwks: "/auth/realms/main/protocol/openid-connect/certs",
			logout: "/auth/realms/main/protocol/openid-connect/logout", callback: "/auth/realms/main/broker/google/endpoint",
			account: "/auth/main/account", assets: "/auth/main/assets", events: "/auth/main/events/google", deleted: "/auth/main/data-deletion",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, ok := snapshot(t, tt.server).Realm("main")
			if !ok {
				t.Fatal("realm main missing")
			}
			if got := r.Issuer(); got != tt.want.issuer {
				t.Errorf("Issuer = %q, want %q", got, tt.want.issuer)
			}
			if got := r.StateCookiePath(); got != tt.want.cookie {
				t.Errorf("StateCookiePath = %q, want %q", got, tt.want.cookie)
			}
			for _, e := range []struct {
				e    config.Endpoint
				want string
			}{
				{config.EndpointAuthorize, tt.want.authorize}, {config.EndpointToken, tt.want.token},
				{config.EndpointUserinfo, tt.want.userinfo}, {config.EndpointJWKS, tt.want.jwks},
				{config.EndpointLogout, tt.want.logout}, {config.EndpointCallback, tt.want.callback},
				{config.EndpointAccountDelete, tt.want.account}, {config.EndpointAssets, tt.want.assets},
				{config.EndpointProviderEvents, tt.want.events}, {config.EndpointDataDeletion, tt.want.deleted},
			} {
				if got := r.EndpointPath(e.e, "google"); got != e.want {
					t.Errorf("EndpointPath(%s) = %q, want %q", e.e, got, e.want)
				}
				if got := r.EndpointURL(e.e, "google"); got != "https://auth.example.com"+e.want {
					t.Errorf("EndpointURL(%s) = %q", e.e, got)
				}
			}
		})
	}
}

// Covers: FR-28 (part), FR-29 (part)
// Acceptance: Non-default URLs and token format (part)
func TestKeycloakLayoutAppleEventsURL(t *testing.T) {
	r, _ := snapshot(t, keycloakURLs).Realm("main")
	if got, want := r.EndpointPath(config.EndpointProviderEvents, "apple"), "/auth/main/events/apple"; got != want {
		t.Errorf("path = %q, want %q", got, want)
	}
	if got, want := r.EndpointURL(config.EndpointProviderEvents, "apple"), "https://auth.example.com/auth/main/events/apple"; got != want {
		t.Errorf("URL = %q, want %q", got, want)
	}
}

// Covers: FR-29 (part)
func TestProviderIgnoredByEndpointsWithoutProvider(t *testing.T) {
	r, _ := snapshot(t, "").Realm("main")
	if a, b := r.EndpointPath(config.EndpointToken, "google"), r.EndpointPath(config.EndpointToken, ""); a != b {
		t.Errorf("token path depends on the provider: %q vs %q", a, b)
	}
}

// Covers: FR-28 (part)
func TestRealmProviderHintParams(t *testing.T) {
	r, _ := snapshot(t, "").Realm("main")
	if got := r.ProviderHintParams(); !slices.Equal(got, []string{"provider"}) {
		t.Errorf("default = %v", got)
	}
	r, _ = snapshot(t, "login:\n  provider_hint_params: [idp, kc_idp_hint]\n").Realm("main")
	got := r.ProviderHintParams()
	if !slices.Equal(got, []string{"idp", "kc_idp_hint"}) {
		t.Errorf("configured = %v", got)
	}
	got[0] = "changed"
	if again := r.ProviderHintParams(); again[0] != "idp" {
		t.Error("ProviderHintParams returns the realm's own slice")
	}
}

func TestClientEffectiveValues(t *testing.T) {
	r, _ := snapshot(t, "").Realm("main")
	get := func(id config.ClientID) *config.Client {
		c, ok := r.Clients[id]
		if !ok {
			t.Fatalf("client %s missing", id)
		}
		return c
	}
	h := time.Hour
	tests := []struct {
		id      config.ClientID
		rotates bool
		life    config.Lifetimes
	}{
		{"web", false, config.Lifetimes{AccessToken: 10 * time.Minute, RefreshIdle: 100 * h, SessionMax: 200 * h}},
		{"web-over", true, config.Lifetimes{AccessToken: 5 * time.Minute, RefreshIdle: h, SessionMax: 2 * h}},
		{"mobile", true, config.Lifetimes{AccessToken: 10 * time.Minute, RefreshIdle: 100 * h, SessionMax: 200 * h}},
		{"no-cap", false, config.Lifetimes{AccessToken: 10 * time.Minute, RefreshIdle: 100 * h, SessionMax: 0}},
	}
	for _, tt := range tests {
		t.Run(string(tt.id), func(t *testing.T) {
			c := get(tt.id)
			if got := c.Rotates(); got != tt.rotates {
				t.Errorf("Rotates = %v, want %v", got, tt.rotates)
			}
			if got := c.Lifetimes(); got != tt.life {
				t.Errorf("Lifetimes = %+v, want %+v", got, tt.life)
			}
		})
	}
}

func TestPublicClientRotatesEvenWhenRealmDoesNot(t *testing.T) {
	r, _ := snapshot(t, "").Realm("main")
	if r.Tokens.RefreshTokenRotation {
		t.Fatal("fixture realm should have rotation off")
	}
	if !r.Clients["mobile"].Rotates() {
		t.Error("public client must always rotate")
	}
}

func TestPostLogoutURIs(t *testing.T) {
	r, _ := snapshot(t, "").Realm("main")
	if got, want := r.Clients["web"].PostLogoutURIs(), []string{"https://app.example.com/cb"}; !slices.Equal(got, want) {
		t.Errorf("default = %v, want the redirect URIs %v", got, want)
	}
	if got, want := r.Clients["web-over"].PostLogoutURIs(), []string{"https://app2.example.com/bye"}; !slices.Equal(got, want) {
		t.Errorf("explicit = %v, want %v", got, want)
	}
	tests := []struct {
		uri  string
		id   config.ClientID
		want bool
	}{
		{"https://app.example.com/cb", "web", true},
		{"https://app2.example.com/bye", "web-over", true},
		{"com.example.app:/callback", "mobile", true},
		{"https://app2.example.com/cb", "", false}, // redirect URI of a client with its own post-logout list
		{"https://app.example.com/cb/", "", false},
		{"", "", false},
		{"https://shared.example.com/cb", "shared-a", true}, // two clients: first by sorted id
	}
	for _, tt := range tests {
		id, ok := r.PostLogoutURIRegistered(tt.uri)
		if ok != tt.want || id != tt.id {
			t.Errorf("PostLogoutURIRegistered(%q) = %q, %v; want %q, %v", tt.uri, id, ok, tt.id, tt.want)
		}
	}
}

func TestSnapshotIsImmutable(t *testing.T) {
	srv := decodeServer(t, "trusted_proxies: [\"10.0.0.0/8\"]\n")
	rf := decodeRealm(t, realmYAML)
	s := config.NewSnapshot(srv, nil, []*config.RealmFile{rf}, nil)
	r, _ := s.Realm("main")

	r.Clients["web"].PostLogoutURIs()[0] = "https://evil.example/"
	r.Clients["web-over"].PostLogoutURIs()[0] = "https://evil.example/"
	if got := r.Clients["web"].PostLogoutURIs()[0]; got != "https://app.example.com/cb" {
		t.Errorf("mutating a returned slice changed the snapshot: %q", got)
	}
	if got := r.Clients["web-over"].PostLogoutURIs()[0]; got != "https://app2.example.com/bye" {
		t.Errorf("mutating a returned slice changed the snapshot: %q", got)
	}

	// Changing the inputs after the snapshot is built does not reach it.
	rf.Clients["web"].RedirectURIs[0] = "https://changed.example/"
	rf.Tokens.AccessTokenLifetime = config.Duration(time.Second)
	srv.URLs.PathPrefix = "/changed"
	srv.TrustedProxies[0] = "1.2.3.4/32"
	if got := r.Clients["web"].PostLogoutURIs()[0]; got != "https://app.example.com/cb" {
		t.Errorf("input mutation reached the snapshot: %q", got)
	}
	if got := r.Clients["web"].Lifetimes().AccessToken; got != 10*time.Minute {
		t.Errorf("input mutation reached the snapshot: %v", got)
	}
	if got := r.Issuer(); got != "https://auth.example.com/main" {
		t.Errorf("input mutation reached the issuer: %q", got)
	}

	got := s.Server()
	got.TrustedProxies[0] = "9.9.9.9/32"
	if s.Server().TrustedProxies[0] != "10.0.0.0/8" {
		t.Error("mutating Server() slices changed the snapshot")
	}
	names := s.Realms()
	names[0] = nil
	if s.Realms()[0] == nil {
		t.Error("mutating the Realms() slice changed the snapshot")
	}
}

func TestRealmsAreSortedByName(t *testing.T) {
	a := decodeRealm(t, strings.Replace(realmYAML, "name: main", "name: zeta", 1))
	b := decodeRealm(t, realmYAML)
	s := config.NewSnapshot(decodeServer(t, ""), nil, []*config.RealmFile{a, b}, nil)
	var got []config.RealmName
	for _, r := range s.Realms() {
		got = append(got, r.Name)
	}
	if want := []config.RealmName{"main", "zeta"}; !slices.Equal(got, want) {
		t.Errorf("Realms order = %v, want %v", got, want)
	}
	if _, ok := s.Realm("nope"); ok {
		t.Error("unknown realm found")
	}
}

type loudSecrets struct{ config.Secrets }

func (loudSecrets) LogValue() slog.Value { return slog.GroupValue(slog.Int("secret_count", 1)) }

func TestSnapshotLogsNoSecrets(t *testing.T) {
	rf := decodeRealm(t, realmYAML)
	s := config.NewSnapshot(decodeServer(t, ""), nil, []*config.RealmFile{rf}, loudSecrets{})
	cases := map[string]func(l *slog.Logger){
		"direct": func(l *slog.Logger) { l.Info("m", "config", s) },
		"nested map": func(l *slog.Logger) {
			l.Info("m", "details", map[string]any{"config": s, "inner": map[string]any{"x": s}})
		},
	}
	for name, log := range cases {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			log(logx.New(&buf, slog.LevelDebug, clock.NewFake(time.Unix(0, 0))))
			out := buf.String()
			if !strings.Contains(out, `"realm_count":1`) {
				t.Errorf("log lacks the realm count: %s", out)
			}
			for _, bad := range []string{"secrets/web", "app.example.com", "client_secret_file"} {
				if strings.Contains(out, bad) {
					t.Errorf("log holds %q: %s", bad, out)
				}
			}
		})
	}
	var _ slog.LogValuer = s
}

func TestStaticSource(t *testing.T) {
	configtest.RunSource(t, func(t *testing.T) config.Source {
		return config.Static(snapshot(t, "urls:\n  path_prefix: /auth\n"))
	})
}

// A client straight from DecodeRealm has no realm: the methods must not panic.
func TestClientWithoutRealmDoesNotPanic(t *testing.T) {
	rf := decodeRealm(t, realmYAML)
	conf, pub, over := rf.Clients["web"], rf.Clients["mobile"], rf.Clients["web-over"]
	if !conf.Rotates() || !pub.Rotates() || !over.Rotates() {
		t.Error("a client without a realm should rotate")
	}
	off := false
	conf.RefreshTokenRotation = &off
	if conf.Rotates() {
		t.Error("an explicit false must still turn rotation off")
	}
	if got := conf.Lifetimes(); got != (config.Lifetimes{}) {
		t.Errorf("Lifetimes without realm or override = %+v, want zero", got)
	}
	if got, want := over.Lifetimes(), (config.Lifetimes{AccessToken: 5 * time.Minute, RefreshIdle: time.Hour, SessionMax: 2 * time.Hour}); got != want {
		t.Errorf("own overrides = %+v, want %+v", got, want)
	}
}

func TestRealmSessionMaxZeroIsInherited(t *testing.T) {
	text := strings.Replace(realmYAML, "session_max_lifetime: 200h", "session_max_lifetime: 0", 1)
	s := config.NewSnapshot(decodeServer(t, ""), nil, []*config.RealmFile{decodeRealm(t, text)}, nil)
	r, _ := s.Realm("main")
	if got := r.Clients["web"].Lifetimes().SessionMax; got != 0 {
		t.Errorf("inherited SessionMax = %v, want 0", got)
	}
	if got := r.Clients["web-over"].Lifetimes().SessionMax; got != 2*time.Hour {
		t.Errorf("override SessionMax = %v, want 2h", got)
	}
}

func TestSnapshotCopiesProviders(t *testing.T) {
	text := realmYAML + "providers:\n  google:\n    client_id: abc\n    client_secret_file: secrets/g\n"
	rf := decodeRealm(t, text)
	s := config.NewSnapshot(decodeServer(t, ""), nil, []*config.RealmFile{rf}, nil)
	r, _ := s.Realm("main")
	rf.Providers["google"].Scopes[0] = "changed"
	rf.Providers["google"].ClientID = "changed"
	if p := r.Providers["google"]; p.Scopes[0] == "changed" || p.ClientID != "abc" {
		t.Errorf("input mutation reached the snapshot provider: %+v", p)
	}
}

// Covers: FR-22 (part)
func TestSnapshotCarriesTheIDFormat(t *testing.T) {
	for _, tc := range []struct{ name, extra, want string }{
		{"default", "", config.IDFormatUUID},
		{"uuid", "user_data:\n  id_format: uuid\n", config.IDFormatUUID},
		{"ulid", "user_data:\n  id_format: ulid\n", config.IDFormatULID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := config.NewSnapshot(decodeServer(t, ""), nil, []*config.RealmFile{decodeRealm(t, realmYAML+tc.extra)}, nil)
			r, ok := s.Realm("main")
			if !ok || r.UserData.IDFormat != tc.want {
				t.Fatalf("IDFormat = %q (found %v), want %q", r.UserData.IDFormat, ok, tc.want)
			}
		})
	}
}

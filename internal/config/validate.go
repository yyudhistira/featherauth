package config

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"net"
	"net/mail"
	"net/netip"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// RealmCheck is what ValidateRealm needs besides the realm file.
type RealmCheck struct {
	// Server is the validated server.yaml; nil skips the rule that needs it
	// (store_refresh_token needs an encryption key file).
	Server *ServerFile
	// Secrets holds the loaded key material; nil skips the key rules that
	// depend on the key type. LoadSecrets has already reported a key it could
	// not load.
	Secrets Secrets
	// Locales says whether locales/<code>.yaml exists; nil means none does.
	// "en" is built in.
	Locales func(code string) bool
}

// MaxAppleSecretLifetime is Apple's own limit for a client secret, six months
// (15777000 seconds). The Apple adapter uses it too.
const MaxAppleSecretLifetime = 15777000 * time.Second

const (
	maxProviderTimeout     = 30 * time.Second
	minAccessTokenLifetime = time.Minute
	minCodeLifetime        = 10 * time.Second
	maxCodeLifetime        = 300 * time.Second
)

var (
	reRealmName     = regexp.MustCompile(`^[a-z0-9-]+$`)
	reBackupAt      = regexp.MustCompile(`^([01][0-9]|2[0-3]):[0-5][0-9]$`)
	reAccentColor   = regexp.MustCompile(`^#([0-9a-fA-F]{3,4}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})$`)
	reGraphVersion  = regexp.MustCompile(`^v[0-9]+\.[0-9]+$`)
	reservedRealms  = []string{"admin", "healthz", "readyz"}
	endpointOrder   = []string{"authorize", "token", "userinfo", "jwks", "logout", "revoke", "sessions", "callback", "account_delete", "assets", "provider_events", "data_deletion"}
	allUserClaims   = []string{"name", "email", "email_verified", "preferred_username", "allowed-origins"}
	allUserAttrs    = []string{"email", "name"}
	providerTypeSet = []string{"google", "apple", "github", "facebook", "oidc"}
)

// checker collects the diagnostics of one file.
type checker struct {
	file string
	line func(string) int
	ds   []Diagnostic
}

// lineOf returns the line of field, else the line of the nearest option
// above it that the file sets, else 0.
func (c *checker) lineOf(field string) int {
	for field != "" {
		if l := c.line(field); l > 0 {
			return l
		}
		i := strings.LastIndexAny(field, ".[")
		if i < 0 {
			return 0
		}
		field = field[:i]
	}
	return 0
}

func (c *checker) errorf(field, format string, args ...any) {
	c.errorAt(c.lineOf(field), field, format, args...)
}

func (c *checker) errorAt(line int, field, format string, args ...any) {
	c.ds = append(c.ds, Diagnostic{File: c.file, Line: line, Field: field, Severity: Error, Message: fmt.Sprintf(format, args...)})
}

func (c *checker) warnf(field, format string, args ...any) {
	c.warnAt(c.lineOf(field), field, format, args...)
}

func (c *checker) warnAt(line int, field, format string, args ...any) {
	c.ds = append(c.ds, Diagnostic{File: c.file, Line: line, Field: field, Severity: Warning, Message: fmt.Sprintf(format, args...)})
}

// place puts a diagnostic of a Validate function at field.
func (c *checker) place(field string, d *Diagnostic) {
	if d == nil {
		return
	}
	d.File, d.Field, d.Line = c.file, field, c.lineOf(field)
	c.ds = append(c.ds, *d)
}

func (c *checker) oneOf(field, v string, allowed ...string) {
	for _, a := range allowed {
		if v == a {
			return
		}
	}
	c.errorf(field, "%q is not valid; use one of: %s", v, strings.Join(allowed, ", "))
}

// requiredAt reports a missing option at its own line, else at the nearest
// option above it, else at the line of fallback.
func (c *checker) requiredAt(field, fallback, format string, args ...any) {
	line := c.lineOf(field)
	if line == 0 {
		line = c.line(fallback)
	}
	c.errorAt(line, field, format, args...)
}

func (c *checker) positive(field string, d Duration) {
	if d <= 0 {
		c.errorf(field, "must be greater than zero, got %s", d)
	}
}

func (c *checker) nonNegative(field string, d Duration) {
	if d < 0 {
		c.errorf(field, "must not be negative, got %s", d)
	}
}

// ValidateServer checks server.yaml (Configuration reference, `server.yaml`).
func ValidateServer(file string, s *ServerFile) []Diagnostic {
	c := &checker{file: file, line: s.Line}

	switch u, err := url.Parse(s.PublicURL); {
	case s.PublicURL == "":
		c.errorf("public_url", "required: the external base URL, such as https://auth.example.com")
	case err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http"):
		c.errorf("public_url", "must be a URL such as https://host")
	case strings.HasSuffix(s.PublicURL, "/"):
		c.errorf("public_url", "must not end with /")
	case u.Scheme == "http" && s.RequireHTTPS:
		c.errorf("public_url", "must be https while require_https is true")
	case s.TLS.Mode == "files" && u.Scheme != "https":
		c.errorf("public_url", "must be https while tls.mode is files")
	}

	if !validListen(s.Listen) {
		c.errorf("listen", "%q must be host:port or :port", s.Listen)
	}
	c.tls(s)
	c.oneOf("log_level", s.LogLevel, "debug", "info", "warn", "error")
	for i, p := range s.TrustedProxies {
		if pf, err := netip.ParsePrefix(p); err != nil || pf.Bits() < 0 {
			c.errorf(fmt.Sprintf("trusted_proxies[%d]", i), "%q is not a CIDR such as 127.0.0.1/32", p)
		}
	}
	c.oneOf("rate_limit.store", s.RateLimit.Store, "memory", "database")
	if s.RateLimit.PerIPPerMinute < 0 {
		c.errorf("rate_limit.per_ip_per_minute", "must be 0 or more, got %d", s.RateLimit.PerIPPerMinute)
	}

	if p := s.URLs.PathPrefix; p != "" && !strings.HasPrefix(p, "/") {
		c.errorf("urls.path_prefix", "must be empty or start with /, got %q", p)
	}
	expand := func(t string) string { return strings.ReplaceAll(t, "{prefix}", s.URLs.PathPrefix) }
	// A bad prefix is reported once, at the option; it would otherwise make
	// every template that uses it fail the leading-slash rule.
	prefixOK := s.URLs.PathPrefix == "" || strings.HasPrefix(s.URLs.PathPrefix, "/")
	startsWithSlash := func(t string) bool {
		return strings.HasPrefix(expand(t), "/") || (!prefixOK && strings.HasPrefix(t, "{prefix}"))
	}

	{ // the issuer path
		t := s.URLs.Issuer
		field := "urls.issuer"
		c.placeholders(field, t, false)
		if !strings.Contains(t, "{realm}") {
			c.errorf(field, "%q must contain {realm}", t)
		}
		if !startsWithSlash(t) {
			c.errorf(field, "%q must start with /", t)
		}
		if strings.HasSuffix(t, "/") {
			c.errorf(field, "%q must not end with a trailing slash", t)
		}
	}

	templates := map[string]string{}
	e := s.URLs.Endpoints
	for name, t := range map[string]string{
		"authorize": e.Authorize, "token": e.Token, "userinfo": e.Userinfo, "jwks": e.JWKS, "logout": e.Logout,
		"revoke": e.Revoke, "sessions": e.Sessions,
		"callback": e.Callback, "account_delete": e.AccountDelete, "assets": e.Assets,
		"provider_events": e.ProviderEvents, "data_deletion": e.DataDeletion,
	} {
		templates[name] = t
	}
	owner := map[string]string{} // expanded path -> first endpoint option
	for _, name := range endpointOrder {
		t := templates[name]
		field := "urls.endpoints." + name
		c.placeholders(field, t, name == "callback" || name == "provider_events")
		if !strings.Contains(t, "{realm}") {
			c.errorf(field, "%q must contain {realm}", t)
		}
		if (name == "callback" || name == "provider_events") && !strings.Contains(t, "{provider}") {
			c.errorf(field, "%q must contain {provider}", t)
		}
		x := expand(t)
		if !startsWithSlash(t) {
			c.errorf(field, "%q must start with /", t)
		}
		if first, dup := owner[x]; dup {
			c.errorf(field, "%q resolves to the same path as %s", t, first)
		} else {
			owner[x] = field
		}
	}
	return c.ds
}

// tls checks the tls block of server.yaml (Configuration reference,
// `server.yaml`). With tls.mode files the pair is required, the listen address
// is a loopback address and no proxy may be in front (trusted_proxies).
func (c *checker) tls(s *ServerFile) {
	t := s.TLS
	c.oneOf("tls.mode", t.Mode, "none", "files")
	if !validListen(t.Listen) {
		c.errorf("tls.listen", "%q must be host:port or :port", t.Listen)
	}
	if t.HTTPListen != "" && !validListen(t.HTTPListen) {
		c.errorf("tls.http_listen", "%q must be host:port or :port, or empty", t.HTTPListen)
	}
	if t.Mode != "files" {
		return
	}
	if t.CertFile == "" {
		c.requiredAt("tls.cert_file", "tls", "required with tls.mode files: the PEM certificate chain")
	}
	if t.KeyFile == "" {
		c.requiredAt("tls.key_file", "tls", "required with tls.mode files: the PEM private key")
	}
	if validListen(s.Listen) && !loopbackListen(s.Listen) {
		c.errorf("listen", "%q must be a loopback address (127.0.0.1 or ::1) with tls.mode files, which serves the health endpoints only", s.Listen)
	}
	if len(s.TrustedProxies) > 0 {
		c.errorf("trusted_proxies", "must be empty with tls.mode files: no proxy is in front of the service")
	}
}

// loopbackListen reports whether v is host:port with an IP address host in the
// loopback range.
func loopbackListen(v string) bool {
	host, _, err := net.SplitHostPort(v)
	if err != nil {
		return false
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}

var rePlaceholder = regexp.MustCompile(`\{[^{}]*\}`)

// placeholders rejects every placeholder but {prefix} and {realm}, and
// {provider} where the endpoint has a provider.
func (c *checker) placeholders(field, tmpl string, providerOK bool) {
	for _, ph := range rePlaceholder.FindAllString(tmpl, -1) {
		switch {
		case ph == "{prefix}" || ph == "{realm}" || (ph == "{provider}" && providerOK):
		case ph == "{provider}":
			c.errorf(field, "%q: {provider} is allowed only in callback and provider_events", tmpl)
		default:
			c.errorf(field, "%q has the unknown placeholder %s; use {prefix}, {realm} or {provider}", tmpl, ph)
		}
	}
}

// validURL reports whether v is an absolute URL with a scheme and a host.
func validURL(v string) bool {
	u, err := url.Parse(v)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

// validListen accepts host:port and :port with a port of 0 to 65535.
func validListen(v string) bool {
	_, port, err := net.SplitHostPort(v)
	if err != nil {
		return false
	}
	_, err = strconv.ParseUint(port, 10, 16)
	return err == nil
}

// ValidateDatabase checks database.yaml (Configuration reference,
// `database.yaml`).
func ValidateDatabase(file string, d *DatabaseFile) []Diagnostic {
	c := &checker{file: file, line: d.Line}
	c.oneOf("driver", d.Driver, "sqlite", "postgres")
	c.positive("sqlite.busy_timeout", d.SQLite.BusyTimeout)
	if d.SQLite.ReadConnections < 1 {
		c.errorf("sqlite.read_connections", "must be 1 or more, got %d", d.SQLite.ReadConnections)
	}
	if d.Driver == "postgres" {
		for _, o := range []struct{ name, v string }{{"host", d.Postgres.Host}, {"password_file", d.Postgres.PasswordFile}} {
			if o.v == "" {
				c.requiredAt("postgres."+o.name, "driver", "required when driver is postgres")
			}
		}
	}
	c.oneOf("postgres.sslmode", d.Postgres.SSLMode, "disable", "require", "verify-full")
	c.positive("postgres.connect_timeout", d.Postgres.ConnectTimeout)
	c.positive("postgres.conn_max_lifetime", d.Postgres.ConnMaxLifetime)
	// The pool sizes are integers (Configuration reference); 0 is what database/sql
	// reads as no limit (max_open_conns) or no idle connections (max_idle_conns).
	if d.Postgres.MaxOpenConns < 0 {
		c.errorf("postgres.max_open_conns", "must not be negative, got %d", d.Postgres.MaxOpenConns)
	}
	if d.Postgres.MaxIdleConns < 0 {
		c.errorf("postgres.max_idle_conns", "must not be negative, got %d", d.Postgres.MaxIdleConns)
	}
	if d.Backup.At != "" && !reBackupAt.MatchString(d.Backup.At) {
		c.errorf("backup.at", "%q must be HH:MM (00:00 to 23:59) or empty", d.Backup.At)
	}
	if d.Backup.Keep < 1 {
		c.errorf("backup.keep", "must be 1 or more, got %d", d.Backup.Keep)
	}
	return c.ds
}

// ValidateRealm checks one realm file. The kid rule across realms is
// ValidateKeyIDs.
func ValidateRealm(file string, r *RealmFile, chk RealmCheck) []Diagnostic {
	c := &checker{file: file, line: r.Line}
	c.name(r)
	if strings.ContainsAny(r.DisplayName, "<>") {
		c.errorf("display_name", "must be plain text without markup")
	}
	c.tokens(r.Tokens)
	c.sso(r.SSO)
	c.keys(r, chk.Secrets)
	for i, a := range r.UserData.Attributes {
		c.oneOf(fmt.Sprintf("user_data.attributes[%d]", i), a, allUserAttrs...)
	}
	for i, a := range r.UserData.Claims {
		c.oneOf(fmt.Sprintf("user_data.claims[%d]", i), a, allUserClaims...)
	}
	if set := r.UserData.AccessTokenClaims; set != nil {
		for i, a := range *set {
			if !slices.Contains(r.UserData.Claims, a) {
				c.errorf(fmt.Sprintf("user_data.access_token_claims[%d]", i), "%q is not in user_data.claims", a)
			}
		}
	}
	c.oneOf("user_data.id_format", r.UserData.IDFormat, IDFormatUUID, IDFormatULID)
	c.loginPage(r.LoginPage, chk.Locales)
	for _, name := range sortedKeys(r.Providers) {
		c.provider(r, name, r.Providers[name], chk.Server)
	}
	// http is allowed for a back-channel logout URI only with require_https: false.
	httpOK := chk.Server != nil && !chk.Server.RequireHTTPS
	for _, id := range sortedKeys(r.Clients) {
		c.client("clients."+id, id, r.Clients[id], r.Tokens, httpOK)
	}
	c.iosLoginRule(r)
	return c.ds
}

func (c *checker) name(r *RealmFile) {
	switch {
	case r.Name == "":
		c.errorf("name", "required")
		return
	case !reRealmName.MatchString(r.Name):
		c.errorf("name", "%q must use lowercase letters, digits and dashes only", r.Name)
	}
	for _, w := range reservedRealms {
		if r.Name == w {
			c.errorf("name", "%q is reserved and cannot name a realm", w)
		}
	}
	if base := strings.TrimSuffix(filepath.Base(c.file), filepath.Ext(c.file)); base != r.Name {
		c.errorf("name", "%q must equal the file name %q", r.Name, base)
	}
}

func (c *checker) tokens(t Tokens) {
	if t.AccessTokenLifetime.Std() < minAccessTokenLifetime {
		c.errorf("tokens.access_token_lifetime", "must be 1 minute or more, got %s", t.AccessTokenLifetime)
	}
	c.positive("tokens.refresh_idle_lifetime", t.RefreshIdleLifetime)
	c.nonNegative("tokens.session_max_lifetime", t.SessionMaxLifetime)
	if d := t.CodeLifetime.Std(); d < minCodeLifetime || d > maxCodeLifetime {
		c.errorf("tokens.code_lifetime", "must be 10 to 300 seconds, got %s", t.CodeLifetime)
	}
	c.positive("tokens.login_timeout", t.LoginTimeout)
	c.nonNegative("tokens.refresh_reuse_grace", t.RefreshReuseGrace)
	c.positive("tokens.account_delete_max_auth_age", t.AccountDeleteMaxAuthAge)
	c.oneOf("tokens.algorithm", t.Algorithm, "RS256", "ES256")
	c.oneOf("tokens.refresh_token_format", t.RefreshTokenFormat, "opaque", "jwt")
}

// sso checks the single sign-on lifetimes (FR-45); enabled is a boolean and
// needs no check.
func (c *checker) sso(s SSO) {
	c.positive("sso.idle_lifetime", s.IdleLifetime)
	c.positive("sso.max_lifetime", s.MaxLifetime)
}

func (c *checker) keys(r *RealmFile, secrets Secrets) {
	if len(r.Keys) == 0 {
		c.errorf("keys", "at least one signing key is required")
		return
	}
	complete := true
	for i, k := range r.Keys {
		f := fmt.Sprintf("keys[%d].", i)
		if k.Kid == "" {
			c.errorf(f+"kid", "required")
		}
		if k.File == "" {
			c.errorf(f+"file", "required")
		}
		switch k.State {
		case "":
			c.errorf(f+"state", "required: active or verify_only")
		case "active", "verify_only":
		default:
			c.errorf(f+"state", "%q is not valid; use one of: active, verify_only", k.State)
		}
		// The key rules below need every key to be understood; the problems
		// above and in LoadSecrets are reported on their own.
		if k.Kid == "" || k.File == "" || (k.State != "active" && k.State != "verify_only") ||
			secrets == nil || secrets.Signing(k.Kid) == nil {
			complete = false
		}
	}
	if !complete {
		return
	}

	var rsaKeys, ecKeys []int
	for i, k := range r.Keys {
		if k.State != "active" {
			continue
		}
		switch secrets.Signing(k.Kid).(type) {
		case *rsa.PrivateKey:
			rsaKeys = append(rsaKeys, i)
		case *ecdsa.PrivateKey:
			ecKeys = append(ecKeys, i)
		}
	}
	if len(rsaKeys) != 1 {
		c.errorf("keys", "a realm needs exactly one active RSA key (it signs ID tokens), found %d", len(rsaKeys))
	}
	switch r.Tokens.Algorithm {
	case "ES256":
		if len(ecKeys) != 1 {
			c.errorf("keys", "with tokens.algorithm ES256 a realm needs exactly one active EC key, found %d", len(ecKeys))
		}
	case "RS256":
		for _, i := range ecKeys {
			c.errorf(fmt.Sprintf("keys[%d].state", i), "an active EC key is an error while tokens.algorithm is RS256; make it verify_only or set ES256")
		}
	}
}

func (c *checker) loginPage(p LoginPage, locales func(string) bool) {
	if p.LogoURL != "" {
		if u, err := url.Parse(p.LogoURL); err != nil || u.Scheme != "https" || u.Host == "" {
			c.errorf("login_page.logo_url", "must be empty or an https URL, got %q", p.LogoURL)
		}
	}
	if !reAccentColor.MatchString(p.AccentColor) {
		c.errorf("login_page.accent_color", "%q is not a CSS hex color such as #2563eb", p.AccentColor)
	}
	if p.Contact != "" && !validContact(p.Contact) {
		c.errorf("login_page.contact", "%q must be empty, an email address or an https URL", p.Contact)
	}
	supported := false
	for i, code := range p.SupportedLocales {
		if code == p.DefaultLocale {
			supported = true
		}
		if !BuiltinLocale(code) && (locales == nil || !locales(code)) {
			c.errorf(fmt.Sprintf("login_page.supported_locales[%d]", i), "no translation file locales/%s.yaml", code)
		}
	}
	if !supported {
		c.errorf("login_page.default_locale", "%q must be one of supported_locales", p.DefaultLocale)
	}
}

func validContact(v string) bool {
	if strings.HasPrefix(v, "https://") {
		u, err := url.Parse(v)
		return err == nil && u.Host != ""
	}
	a, err := mail.ParseAddress(v)
	return err == nil && a.Address == v
}

func (c *checker) provider(r *RealmFile, key string, p *Provider, srv *ServerFile) {
	f := "providers." + key + "."
	c.oneOf(f+"type", p.Type, providerTypeSet...)
	c.oneOf(f+"sync_mode", p.SyncMode, "import", "force")
	switch {
	case p.Timeout <= 0:
		c.errorf(f+"timeout", "must be greater than zero, got %s (zero would mean no timeout)", p.Timeout)
	case p.Timeout.Std() > maxProviderTimeout:
		c.errorf(f+"timeout", "must be at most 30s, got %s", p.Timeout)
	}
	for _, o := range []struct{ name, v string }{
		{"endpoints.authorize", p.Endpoints.Authorize}, {"endpoints.token", p.Endpoints.Token},
		{"endpoints.userinfo", p.Endpoints.Userinfo}, {"endpoints.jwks", p.Endpoints.JWKS}, {"issuer", p.Issuer},
		{"endpoints.risc_configuration", p.Endpoints.RISCConfiguration},
	} {
		if o.v != "" && !validURL(o.v) {
			c.errorf(f+o.name, "%q must be an absolute URL with scheme and host, such as https://idp.example.com/auth", o.v)
		}
	}
	c.requiredProviderOptions(f, p)
	switch p.Type {
	case "apple":
		c.appleScopes(f, p.Scopes)
		switch d := p.ClientSecretLifetime; {
		case d <= 0:
			c.errorf(f+"client_secret_lifetime", "must be greater than zero, got %s", d)
		case d.Std() > MaxAppleSecretLifetime:
			c.errorf(f+"client_secret_lifetime", "must be at most 6 months, got %s", d)
		}
		if p.Enabled && p.StoreRefreshToken && srv != nil && len(srv.Secrets.EncryptionKeyFiles) == 0 {
			c.errorf(f+"store_refresh_token", "store_refresh_token needs an encryption key: list a file in secrets.encryption_key_files in server.yaml")
		}
	case "facebook":
		if !reGraphVersion.MatchString(p.GraphVersion) {
			c.errorf(f+"graph_version", "%q must be a version such as v26.0", p.GraphVersion)
		}
		if p.Flow == "oidc" {
			c.errorf(f+"flow", "%q is not supported (pending confirmation against Meta's documentation); use oauth", p.Flow)
		} else {
			c.oneOf(f+"flow", p.Flow, "oauth")
		}
		if p.Enabled && p.TrustEmail {
			c.warnf(f+"trust_email", "Facebook gives no verified-email flag, so its emails are never trusted or auto-linked")
		}
		if p.Enabled && r.LoginPage.Contact == "" {
			line := c.line("login_page.contact")
			if line == 0 {
				line = c.lineOf(strings.TrimSuffix(f, "."))
			}
			c.errorAt(line, "login_page.contact", "required when Facebook is enabled (provider %s): it is shown on the data-deletion page", key)
		}
	}
}

// appleScopes checks the scopes of an Apple provider: each value is name or
// email, at most once. A diagnostic names the option and sits on the line of
// the offending value.
func (c *checker) appleScopes(f string, scopes []string) {
	seen := map[string]bool{}
	for i, v := range scopes {
		line := c.lineOf(fmt.Sprintf("%sscopes[%d]", f, i))
		switch {
		case v != "name" && v != "email":
			c.errorAt(line, f+"scopes", "Apple supports only the scopes name and email")
		case seen[v]:
			c.errorAt(line, f+"scopes", "%s is listed twice", v)
		}
		seen[v] = true
	}
}

// requiredProviderOptions reports the options an enabled provider needs.
func (c *checker) requiredProviderOptions(f string, p *Provider) {
	if !p.Enabled {
		return
	}
	type opt struct{ name, v string }
	opts := []opt{{"client_id", p.ClientID}}
	switch p.Type {
	case "apple":
		opts = append(opts, opt{"team_id", p.TeamID}, opt{"key_id", p.KeyID}, opt{"private_key_file", p.PrivateKeyFile})
	default:
		opts = append(opts, opt{"client_secret_file", p.ClientSecretFile})
		if p.Type == "oidc" {
			opts = append(opts, opt{"issuer", p.Issuer})
		}
	}
	for _, o := range opts {
		if o.v == "" {
			c.errorf(f+o.name, "required when the provider is enabled")
		}
	}
}

// client checks one client of a realm; id is its key and realm the realm's
// token lifetimes, which the client inherits where it sets none.
// backchannelLogoutURI checks a client's backchannel_logout_uri: empty, or an
// absolute URL with a host and no fragment. It must be https unless http is
// allowed (require_https: false).
func (c *checker) backchannelLogoutURI(field, v string, httpOK bool) {
	if v == "" {
		return
	}
	u, err := url.Parse(v)
	switch {
	case err != nil || u.Host == "" || strings.Contains(v, "#") || (u.Scheme != "https" && u.Scheme != "http"):
		c.errorf(field, "%q must be empty or an https URL with a host and no fragment", v)
	case u.Scheme == "http" && !httpOK:
		c.errorf(field, "%q must be https while require_https is true", v)
	}
}

func (c *checker) client(path, id string, cl *Client, realm Tokens, httpOK bool) {
	f := path + "."
	c.backchannelLogoutURI(f+"backchannel_logout_uri", cl.BackchannelLogoutURI, httpOK)
	c.oneOf(f+"type", string(cl.Type), string(Public), string(Confidential))
	c.oneOf(f+"response_mode", cl.ResponseMode, "query", "fragment", "form_post")
	c.oneOf(f+"dpop", string(cl.DPoP), "off", "allowed", "required")
	if cl.AccessTokenLifetime != nil {
		c.positive(f+"access_token_lifetime", *cl.AccessTokenLifetime)
	}
	if cl.RefreshIdleLifetime != nil {
		c.positive(f+"refresh_idle_lifetime", *cl.RefreshIdleLifetime)
	}
	if cl.SessionMaxLifetime != nil {
		c.nonNegative(f+"session_max_lifetime", *cl.SessionMaxLifetime)
	}
	if cl.Type == Confidential && cl.ClientSecretFile == "" {
		c.errorf(f+"client_secret_file", "required for a confidential client")
	}
	if len(cl.RedirectURIs) == 0 {
		c.errorf(f+"redirect_uris", "required: list at least one redirect URI")
	}
	for i, u := range cl.RedirectURIs {
		field := fmt.Sprintf("%sredirect_uris[%d]", f, i)
		c.place(field, ValidateRedirectURI(u, cl.Type))
	}
	for i, u := range cl.PostLogoutRedirectURIs {
		field := fmt.Sprintf("%spost_logout_redirect_uris[%d]", f, i)
		c.place(field, ValidateRedirectURI(u, cl.Type))
	}
	for i, o := range cl.WebOrigins {
		field := fmt.Sprintf("%sweb_origins[%d]", f, i)
		c.place(field, ValidateWebOrigin(o))
	}
	if !cl.RequirePKCE {
		if cl.Type == Public {
			c.warnf(f+"require_pkce", "require_pkce: false on a public client does not meet RFC 9700 section 2.1.1, which requires PKCE for public clients; the code is protected only by the exact redirect URI match, so use it only as a temporary exception")
			c.pkceExceptionLimits(f, id, cl, realm)
		} else {
			c.warnf(f+"require_pkce", "require_pkce: false is an explicit exception for a client that cannot send a challenge; a challenge that is sent is still verified")
		}
	}
	if cl.Type == Public && cl.RefreshTokenRotation != nil && !*cl.RefreshTokenRotation {
		c.errorf(f+"refresh_token_rotation", "false is not allowed for a public client, which always rotates; only a confidential client may turn rotation off")
	}
}

// The limits of the PKCE exception for a public client (FR-32, SEC-01): its
// effective refresh idle lifetime is at most 24 hours, and its effective session
// lifetime is above 0 and at most 720 hours, so that a code intercepted through
// a custom scheme never becomes a long session (RFC 8252 section 8.1).
const (
	pkceExceptionMaxIdle    = 24 * time.Hour
	pkceExceptionMaxSession = 720 * time.Hour
)

// pkceExceptionLimits reports a public client with require_pkce: false whose
// effective lifetimes are outside the limits. The client's own value is used
// where it sets one, else the realm's. The error is on the require_pkce line.
func (c *checker) pkceExceptionLimits(f, id string, cl *Client, realm Tokens) {
	idle := realm.RefreshIdleLifetime.Std()
	if cl.RefreshIdleLifetime != nil {
		idle = cl.RefreshIdleLifetime.Std()
	}
	if idle > pkceExceptionMaxIdle {
		c.errorf(f+"require_pkce", "client %s: a public client with require_pkce: false needs refresh_idle_lifetime of at most 24h", id)
	}
	session := realm.SessionMaxLifetime.Std()
	if cl.SessionMaxLifetime != nil {
		session = cl.SessionMaxLifetime.Std()
	}
	if session == 0 || session > pkceExceptionMaxSession {
		c.errorf(f+"require_pkce", "client %s: a public client with require_pkce: false needs session_max_lifetime above 0 and at most 720h", id)
	}
}

// iosLoginRule warns once when a public client has a custom-scheme redirect
// URI and Google, Facebook or GitHub is enabled while Apple is not offered:
// App Store Review Guideline 4.8.
func (c *checker) iosLoginRule(r *RealmFile) {
	thirdParty, apple := false, false
	for _, p := range r.Providers {
		switch {
		case !p.Enabled:
		case p.Type == "apple" && !p.Hidden:
			apple = true
		case p.Type == "google" || p.Type == "facebook" || p.Type == "github":
			thirdParty = true
		}
	}
	if !thirdParty || apple {
		return
	}
	for _, id := range sortedKeys(r.Clients) {
		cl := r.Clients[id]
		if cl.Type != Public {
			continue
		}
		for i, raw := range cl.RedirectURIs {
			if u, err := url.Parse(raw); err == nil && u.Scheme != "" && u.Scheme != "http" && u.Scheme != "https" {
				c.warnf(fmt.Sprintf("clients.%s.redirect_uris[%d]", id, i), "public client with a custom-scheme redirect URI while a third-party login (Google, Facebook or GitHub) is enabled and Sign in with Apple is disabled or hidden: App Store Review Guideline 4.8 requires an iOS app that offers one to offer Sign in with Apple or an equivalent")
				return
			}
		}
	}
}

// ValidateKeyIDs checks that every kid is unique across the realms (SEC-07).
// A later use of a kid is reported at its own file and line.
func ValidateKeyIDs(realms []RealmSource) []Diagnostic {
	var ds []Diagnostic
	first := map[string]string{}
	for _, rs := range realms {
		c := &checker{file: rs.File, line: rs.Realm.Line}
		for i, k := range rs.Realm.Keys {
			if k.Kid == "" {
				continue
			}
			if at, dup := first[k.Kid]; dup {
				c.errorf(fmt.Sprintf("keys[%d].kid", i), "kid %q is already used in %s; a kid must be unique across realms", k.Kid, at)
				continue
			}
			first[k.Kid] = rs.File
		}
		ds = append(ds, c.ds...)
	}
	return ds
}

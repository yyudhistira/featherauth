package config

import (
	"context"
	"crypto"
	"crypto/elliptic"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/clock"
)

// vrow is one failing case of the validation table: a file that breaks exactly
// one rule and the one diagnostic that rule must produce.
type vrow struct {
	name  string
	kind  string // "server", "database" or "realm"
	file  string // diagnostic file; a default per kind when empty
	yaml  string // the whole file, or the extra lines when extra is set
	noEnc bool   // realm: the server file lists no encryption key file
	extra bool   // realm and server: yaml is added after the name (or public_url) line
	line  int
	field string
	msg   string   // a part of the reason
	sev   Severity // Error when zero
}

const (
	srvBase   = "public_url: https://auth.example.com\n"
	realmHead = "name: main\n"
	realmKeys = "keys:\n  - kid: rsa1\n    file: keys/rsa.pem\n    state: active\n"
)

func endpointNames() []string {
	return []string{"authorize", "token", "userinfo", "jwks", "logout", "revoke", "sessions", "callback", "account_delete", "assets", "provider_events", "data_deletion"}
}

func withoutEncKeys(r vrow) vrow { r.noEnc = true; return r }

func srvRow(name, extra string, line int, field, msg string) vrow {
	return vrow{name: name, kind: "server", yaml: extra, extra: true, line: line, field: field, msg: msg}
}

func dbRow(name, y string, line int, field, msg string) vrow {
	return vrow{name: name, kind: "database", yaml: y, line: line, field: field, msg: msg}
}

// realmRow breaks a rule with lines placed after "name: main" (line 1) and
// before the RSA key block.
func realmRow(name, extra string, line int, field, msg string) vrow {
	return vrow{name: name, kind: "realm", yaml: extra, extra: true, line: line, field: field, msg: msg}
}

func fullRealm(name, y string, line int, field, msg string) vrow {
	return vrow{name: name, kind: "realm", yaml: y, line: line, field: field, msg: msg}
}

func providerRow(name, body string, line int, field, msg string) vrow {
	return realmRow(name, "providers:\n"+body, line, field, msg)
}

// clientRow adds a valid redirect_uris after body so that the row breaks one rule.
func clientRow(name, body string, line int, field, msg string) vrow {
	return clientURIRow(name, body+"    redirect_uris: [https://app.example.com/cb]\n", line, field, msg)
}

// clientURIRow takes the whole body of the client, redirect_uris included.
func clientURIRow(name, body string, line int, field, msg string) vrow {
	return realmRow(name, "clients:\n  web:\n"+body, line, field, msg)
}

func warnRow(r vrow) vrow { r.sev = Warning; return r }

// The enabled provider options each type needs, one per line, so a row can
// leave one out.
const (
	googleOpts   = "    enabled: true\n    client_id: id\n    client_secret_file: secrets/g\n"
	appleOpts    = "    enabled: true\n    client_id: id\n    team_id: T\n    key_id: K\n    private_key_file: secrets/a.p8\n"
	facebookOpts = "    enabled: true\n    client_id: id\n    client_secret_file: secrets/f\n"
	contactLine  = "login_page:\n  contact: help@example.com\n"
)

// without removes the line that starts with option from opts.
func without(opts, option string) string {
	var out []string
	for _, l := range strings.SplitAfter(opts, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(l), option+":") {
			out = append(out, l)
		}
	}
	return strings.Join(out, "")
}

func validationRows() []vrow {
	rows := []vrow{
		// server.yaml
		{name: "public_url missing", kind: "server", yaml: "listen: \":8080\"\n", line: 0, field: "public_url", msg: "required"},
	}
	rows = append(rows,
		vrow{name: "public_url trailing slash", kind: "server", yaml: "public_url: https://auth.example.com/\n", line: 1, field: "public_url", msg: "must not end with /"},
		vrow{name: "public_url without scheme", kind: "server", yaml: "public_url: auth.example.com\n", line: 1, field: "public_url", msg: "https://host"},
		vrow{name: "public_url other scheme", kind: "server", yaml: "public_url: ftp://auth.example.com\n", line: 1, field: "public_url", msg: "https://host"},
		vrow{name: "public_url without host", kind: "server", yaml: "public_url: https://\n", line: 1, field: "public_url", msg: "https://host"},
		vrow{name: "require_https with http", kind: "server", yaml: "public_url: http://localhost:8080\n", line: 1, field: "public_url", msg: "require_https"},
		srvRow("listen without port", "listen: auth\n", 2, "listen", "host:port"),
		srvRow("listen with bad port", "listen: \"host:abc\"\n", 2, "listen", "host:port"),
		srvRow("listen with port too large", "listen: \":70000\"\n", 2, "listen", "host:port"),
		srvRow("log_level unknown", "log_level: trace\n", 2, "log_level", "debug, info, warn, error"),
		srvRow("trusted_proxies address without mask", "trusted_proxies: [10.0.0.1]\n", 2, "trusted_proxies[0]", "CIDR"),
		srvRow("trusted_proxies second item bad", "trusted_proxies:\n  - 127.0.0.1/32\n  - nope\n", 4, "trusted_proxies[1]", "CIDR"),
		srvRow("rate limit negative", "rate_limit:\n  per_ip_per_minute: -1\n", 3, "rate_limit.per_ip_per_minute", "0 or more"),
		srvRow("path_prefix without slash", "urls:\n  path_prefix: auth\n", 3, "urls.path_prefix", "start with /"),
		srvRow("issuer without realm", "urls:\n  issuer: \"{prefix}/main\"\n", 3, "urls.issuer", "{realm}"),
		srvRow("issuer trailing slash", "urls:\n  issuer: \"{prefix}/{realm}/\"\n", 3, "urls.issuer", "trailing slash"),
		srvRow("issuer without leading slash", "urls:\n  issuer: \"{realm}\"\n", 3, "urls.issuer", "start with /"),
		srvRow("rate_limit.store unknown", "rate_limit:\n  store: redis\n", 3, "rate_limit.store", "memory, database"),
		srvRow("tls.mode unknown", "tls:\n  mode: maybe\n", 3, "tls.mode", "none, files"),
		srvRow("tls.listen without port", "tls:\n  listen: \"8443\"\n", 3, "tls.listen", "host:port"),
		srvRow("tls.http_listen without port", "tls:\n  http_listen: port\n", 3, "tls.http_listen", "host:port"),
		srvRow("files without tls.cert_file", "listen: \"127.0.0.1:8080\"\ntls:\n  mode: files\n  key_file: secrets/tls_key.pem\n", 3, "tls.cert_file", "required with tls.mode files"),
		srvRow("files without tls.key_file", "listen: \"127.0.0.1:8080\"\ntls:\n  mode: files\n  cert_file: secrets/tls_cert.pem\n", 3, "tls.key_file", "required with tls.mode files"),
	)
	for _, n := range endpointNames() {
		tmpl := "/fixed"
		if n == "callback" || n == "provider_events" {
			tmpl = "/fixed/{provider}"
		}
		rows = append(rows, srvRow("endpoint "+n+" without realm", fmt.Sprintf("urls:\n  endpoints:\n    %s: %q\n", n, tmpl), 4, "urls.endpoints."+n, "{realm}"))
	}
	rows = append(rows,
		srvRow("callback without provider", "urls:\n  endpoints:\n    callback: \"{prefix}/{realm}/callback\"\n", 4, "urls.endpoints.callback", "{provider}"),
		srvRow("provider_events without provider", "urls:\n  endpoints:\n    provider_events: \"{prefix}/{realm}/events\"\n", 4, "urls.endpoints.provider_events", "{provider}"),
		srvRow("authorize with an unknown placeholder", "urls:\n  endpoints:\n    authorize: \"{prefix}/{realm}/{foo}\"\n", 4, "urls.endpoints.authorize", "unknown placeholder {foo}"),
		srvRow("callback with an unknown placeholder", "urls:\n  endpoints:\n    callback: \"{prefix}/{realm}/{provider}/{foo}\"\n", 4, "urls.endpoints.callback", "unknown placeholder {foo}"),
		srvRow("issuer with an unknown placeholder", "urls:\n  issuer: \"{prefix}/{realm}/{foo}\"\n", 3, "urls.issuer", "unknown placeholder {foo}"),
		srvRow("token with {provider}", "urls:\n  endpoints:\n    token: \"{prefix}/{realm}/token/{provider}\"\n", 4, "urls.endpoints.token", "{provider} is allowed only in callback and provider_events"),
		srvRow("issuer with {provider}", "urls:\n  issuer: \"{prefix}/{realm}/{provider}\"\n", 3, "urls.issuer", "{provider} is allowed only in callback and provider_events"),
		srvRow("endpoint path without leading slash", "urls:\n  endpoints:\n    authorize: \"{realm}/authorize\"\n", 4, "urls.endpoints.authorize", "start with /"),
		srvRow("two endpoints on one path", "urls:\n  endpoints:\n    authorize: \"{prefix}/{realm}/x\"\n    token: \"{prefix}/{realm}/x\"\n", 5, "urls.endpoints.token", "urls.endpoints.authorize"),
		srvRow("two endpoints on one path after the prefix", "urls:\n  path_prefix: /a\n  endpoints:\n    authorize: \"{prefix}/{realm}/x\"\n    token: \"/a/{realm}/x\"\n", 6, "urls.endpoints.token", "urls.endpoints.authorize"),

		// database.yaml
		dbRow("driver unknown", "driver: mysql\n", 1, "driver", "sqlite, postgres"),
		dbRow("busy_timeout zero", "sqlite:\n  busy_timeout: 0s\n", 2, "sqlite.busy_timeout", "greater than zero"),
		dbRow("busy_timeout negative", "sqlite:\n  busy_timeout: -1s\n", 2, "sqlite.busy_timeout", "greater than zero"),
		dbRow("read_connections zero", "sqlite:\n  read_connections: 0\n", 2, "sqlite.read_connections", "1 or more"),
		dbRow("sslmode unknown", "postgres:\n  sslmode: prefer\n", 2, "postgres.sslmode", "disable, require, verify-full"),
		dbRow("conn_max_lifetime zero", "postgres:\n  conn_max_lifetime: 0s\n", 2, "postgres.conn_max_lifetime", "greater than zero"),
		dbRow("connect_timeout zero", "postgres:\n  connect_timeout: 0s\n", 2, "postgres.connect_timeout", "greater than zero"),
		dbRow("connect_timeout negative", "postgres:\n  connect_timeout: -1s\n", 2, "postgres.connect_timeout", "greater than zero"),
		dbRow("max_open_conns negative", "postgres:\n  max_open_conns: -1\n", 2, "postgres.max_open_conns", "must not be negative"),
		dbRow("max_idle_conns negative", "postgres:\n  max_idle_conns: -1\n", 2, "postgres.max_idle_conns", "must not be negative"),
		dbRow("backup.at not a time", "backup:\n  at: 3am\n", 2, "backup.at", "HH:MM"),
		dbRow("backup.at hour 24", "backup:\n  at: \"24:00\"\n", 2, "backup.at", "HH:MM"),
		dbRow("postgres without host", "driver: postgres\npostgres:\n  password_file: secrets/pg\n", 2, "postgres.host", "required"),
		dbRow("postgres without password_file", "driver: postgres\npostgres:\n  host: db.example.com\n", 2, "postgres.password_file", "required"),
		dbRow("backup.keep zero", "backup:\n  keep: 0\n", 2, "backup.keep", "1 or more"),

		// realm name
		vrow{name: "name pattern", kind: "realm", file: "realms/Main.yaml", yaml: "name: Main\n" + realmKeys, line: 1, field: "name", msg: "lowercase letters, digits and dashes"},
		vrow{name: "name differs from the file", kind: "realm", file: "realms/other.yaml", yaml: realmHead + realmKeys, line: 1, field: "name", msg: "file name"},
		vrow{name: "name admin", kind: "realm", file: "realms/admin.yaml", yaml: "name: admin\n" + realmKeys, line: 1, field: "name", msg: `"admin" is reserved`},
		vrow{name: "name healthz", kind: "realm", file: "realms/healthz.yaml", yaml: "name: healthz\n" + realmKeys, line: 1, field: "name", msg: `"healthz" is reserved`},
		vrow{name: "name readyz", kind: "realm", file: "realms/readyz.yaml", yaml: "name: readyz\n" + realmKeys, line: 1, field: "name", msg: `"readyz" is reserved`},
		fullRealm("name missing", realmKeys, 0, "name", "required"),
		realmRow("display_name with markup", "display_name: <b>Main</b>\n", 2, "display_name", "markup"),

		// tokens
		realmRow("access_token_lifetime below a minute", "tokens:\n  access_token_lifetime: 30s\n", 3, "tokens.access_token_lifetime", "1 minute or more"),
		realmRow("access_token_lifetime zero", "tokens:\n  access_token_lifetime: 0s\n", 3, "tokens.access_token_lifetime", "1 minute or more"),
		realmRow("refresh_idle_lifetime zero", "tokens:\n  refresh_idle_lifetime: 0s\n", 3, "tokens.refresh_idle_lifetime", "greater than zero"),
		realmRow("refresh_idle_lifetime negative", "tokens:\n  refresh_idle_lifetime: -1h\n", 3, "tokens.refresh_idle_lifetime", "greater than zero"),
		realmRow("session_max_lifetime negative", "tokens:\n  session_max_lifetime: -1s\n", 3, "tokens.session_max_lifetime", "negative"),
		realmRow("code_lifetime below 10s", "tokens:\n  code_lifetime: 9s\n", 3, "tokens.code_lifetime", "10 to 300 seconds"),
		realmRow("code_lifetime above 300s", "tokens:\n  code_lifetime: 301s\n", 3, "tokens.code_lifetime", "10 to 300 seconds"),
		realmRow("login_timeout zero", "tokens:\n  login_timeout: 0s\n", 3, "tokens.login_timeout", "greater than zero"),
		realmRow("refresh_reuse_grace negative", "tokens:\n  refresh_reuse_grace: -1s\n", 3, "tokens.refresh_reuse_grace", "negative"),
		realmRow("account_delete_max_auth_age zero", "tokens:\n  account_delete_max_auth_age: 0s\n", 3, "tokens.account_delete_max_auth_age", "greater than zero"),
		realmRow("algorithm unknown", "tokens:\n  algorithm: HS256\n", 3, "tokens.algorithm", "RS256, ES256"),
		realmRow("refresh_token_format unknown", "tokens:\n  refresh_token_format: cookie\n", 3, "tokens.refresh_token_format", "opaque, jwt"),
		realmRow("sso idle_lifetime zero", "sso:\n  idle_lifetime: 0s\n", 3, "sso.idle_lifetime", "greater than zero"),
		realmRow("sso idle_lifetime negative", "sso:\n  idle_lifetime: -1s\n", 3, "sso.idle_lifetime", "greater than zero"),
		realmRow("sso max_lifetime zero", "sso:\n  max_lifetime: 0s\n", 3, "sso.max_lifetime", "greater than zero"),
		realmRow("sso max_lifetime negative", "sso:\n  max_lifetime: -5m\n", 3, "sso.max_lifetime", "greater than zero"),

		// keys
		fullRealm("no keys", realmHead+"keys: []\n", 2, "keys", "at least one"),
		fullRealm("kid missing", realmHead+"keys:\n  - file: keys/rsa.pem\n    state: active\n", 3, "keys[0].kid", "required"),
		fullRealm("key file missing", realmHead+"keys:\n  - kid: rsa1\n    state: active\n", 3, "keys[0].file", "required"),
		fullRealm("key state missing", realmHead+"keys:\n  - kid: rsa1\n    file: keys/rsa.pem\n", 3, "keys[0].state", "required"),
		fullRealm("key state unknown", realmHead+"keys:\n  - kid: rsa1\n    file: keys/rsa.pem\n    state: retired\n", 5, "keys[0].state", "active, verify_only"),
		fullRealm("two active RSA keys", realmHead+realmKeys+"  - kid: rsa2\n    file: keys/rsa2.pem\n    state: active\n", 2, "keys", "exactly one active RSA key"),
		fullRealm("no active RSA key", realmHead+"keys:\n  - kid: rsa1\n    file: keys/rsa.pem\n    state: verify_only\n", 2, "keys", "exactly one active RSA key"),
		fullRealm("ES256 without EC key", realmHead+"tokens:\n  algorithm: ES256\n"+realmKeys, 4, "keys", "exactly one active EC key"),
		fullRealm("ES256 with two EC keys", realmHead+"tokens:\n  algorithm: ES256\n"+realmKeys+"  - kid: ec1\n    file: keys/ec.pem\n    state: active\n  - kid: ec2\n    file: keys/ec2.pem\n    state: active\n", 4, "keys", "exactly one active EC key"),
		fullRealm("ES256 without RSA key", realmHead+"tokens:\n  algorithm: ES256\nkeys:\n  - kid: ec1\n    file: keys/ec.pem\n    state: active\n", 4, "keys", "exactly one active RSA key"),
		fullRealm("active EC key in an RS256 realm", realmHead+realmKeys+"  - kid: ec1\n    file: keys/ec.pem\n    state: active\n", 8, "keys[1].state", "RS256"),

		// providers
		providerRow("provider type unknown", "  mystery: {}\n", 3, "providers.mystery.type", "google, apple, github, facebook, oidc"),
		providerRow("provider type oauth2 is unknown", "  other:\n    type: oauth2\n", 4, "providers.other.type", "google, apple, github, facebook, oidc"),
		providerRow("provider sync_mode unknown", "  google:\n    sync_mode: merge\n", 4, "providers.google.sync_mode", "import, force"),
		providerRow("provider timeout zero", "  google:\n    timeout: 0s\n", 4, "providers.google.timeout", "greater than zero"),
		providerRow("provider timeout negative", "  google:\n    timeout: -1s\n", 4, "providers.google.timeout", "greater than zero"),
		providerRow("provider timeout 31s", "  google:\n    timeout: 31s\n", 4, "providers.google.timeout", "at most 30s"),
		providerRow("apple secret lifetime zero", "  apple:\n    client_secret_lifetime: 0s\n", 4, "providers.apple.client_secret_lifetime", "greater than zero"),
		providerRow("apple secret lifetime above 6 months", "  apple:\n    client_secret_lifetime: 15777001s\n", 4, "providers.apple.client_secret_lifetime", "6 months"),
		providerRow("apple scopes with openid", "  apple:\n    scopes: [openid]\n", 4, "providers.apple.scopes", "Apple supports only the scopes name and email"),
		providerRow("apple scopes with a third value", "  apple:\n    scopes: [name, email, phone]\n", 4, "providers.apple.scopes", "Apple supports only the scopes name and email"),
		providerRow("apple scopes with a bad value on its own line", "  apple:\n    scopes:\n      - email\n      - profile\n", 6, "providers.apple.scopes", "Apple supports only the scopes name and email"),
		providerRow("apple scopes name twice", "  apple:\n    scopes: [name, name]\n", 4, "providers.apple.scopes", "name is listed twice"),
		providerRow("apple scopes email twice on its own line", "  apple:\n    scopes:\n      - email\n      - name\n      - email\n", 7, "providers.apple.scopes", "email is listed twice"),
		providerRow("facebook graph_version", "  facebook:\n    graph_version: \"26\"\n", 4, "providers.facebook.graph_version", "v26.0"),
		providerRow("facebook flow", "  facebook:\n    flow: token\n", 4, "providers.facebook.flow", "use one of: oauth"),
		providerRow("facebook flow oidc is not supported", "  facebook:\n    flow: oidc\n", 4, "providers.facebook.flow", "is not supported (pending confirmation against Meta's documentation); use oauth"),
		withoutEncKeys(providerRow("encryption key missing", "  apple:\n    enabled: true\n    store_refresh_token: true\n    client_id: id\n    team_id: T\n    key_id: K\n    private_key_file: secrets/a.p8\n", 5, "providers.apple.store_refresh_token", "needs an encryption key")),
		providerRow("provider authorize endpoint not a URL", "  google:\n    endpoints:\n      authorize: idp.example.com/auth\n", 5, "providers.google.endpoints.authorize", "absolute URL"),
		providerRow("provider token endpoint wrong scheme", "  google:\n    endpoints:\n      token: ftp://idp.example.com/token\n", 5, "providers.google.endpoints.token", "absolute URL"),
		providerRow("provider userinfo endpoint without host", "  google:\n    endpoints:\n      userinfo: \"https://\"\n", 5, "providers.google.endpoints.userinfo", "absolute URL"),
		providerRow("provider jwks endpoint not a URL", "  google:\n    endpoints:\n      jwks: /keys\n", 5, "providers.google.endpoints.jwks", "absolute URL"),
		providerRow("google RISC configuration not a URL", "  google:\n    endpoints:\n      risc_configuration: /risc\n", 5, "providers.google.endpoints.risc_configuration", "absolute URL"),
		providerRow("oidc issuer not a URL", "  oidc:\n    issuer: idp.example.com\n", 4, "providers.oidc.issuer", "absolute URL"),
		providerRow("facebook without contact", "  facebook:\n"+facebookOpts, 3, "login_page.contact", "Facebook"),

		// required provider options
		providerRow("google without client_id", "  google:\n"+without(googleOpts, "client_id"), 3, "providers.google.client_id", "required"),
		providerRow("google without client_secret_file", "  google:\n"+without(googleOpts, "client_secret_file"), 3, "providers.google.client_secret_file", "required"),
		providerRow("github without client_id", "  github:\n"+without(googleOpts, "client_id"), 3, "providers.github.client_id", "required"),
		providerRow("github without client_secret_file", "  github:\n"+without(googleOpts, "client_secret_file"), 3, "providers.github.client_secret_file", "required"),
		withContact(providerRow("facebook without client_id", "  facebook:\n"+without(facebookOpts, "client_id"), 3, "providers.facebook.client_id", "required")),
		withContact(providerRow("facebook without client_secret_file", "  facebook:\n"+without(facebookOpts, "client_secret_file"), 3, "providers.facebook.client_secret_file", "required")),
		providerRow("apple without client_id", "  apple:\n"+without(appleOpts, "client_id"), 3, "providers.apple.client_id", "required"),
		providerRow("apple without team_id", "  apple:\n"+without(appleOpts, "team_id"), 3, "providers.apple.team_id", "required"),
		providerRow("apple without key_id", "  apple:\n"+without(appleOpts, "key_id"), 3, "providers.apple.key_id", "required"),
		providerRow("apple without private_key_file", "  apple:\n"+without(appleOpts, "private_key_file"), 3, "providers.apple.private_key_file", "required"),
		providerRow("oidc without issuer", "  oidc:\n"+googleOpts, 3, "providers.oidc.issuer", "required"),
		providerRow("oidc without client_id", "  oidc:\n    issuer: https://idp.example.com\n"+without(googleOpts, "client_id"), 3, "providers.oidc.client_id", "required"),
		providerRow("oidc without client_secret_file", "  oidc:\n    issuer: https://idp.example.com\n"+without(googleOpts, "client_secret_file"), 3, "providers.oidc.client_secret_file", "required"),
		warnRow(withContact(providerRow("facebook trust_email true", "  facebook:\n"+facebookOpts+"    trust_email: true\n", 7, "providers.facebook.trust_email", "never trusted"))),

		// user data
		realmRow("attribute unknown", "user_data:\n  attributes: [email, phone]\n", 3, "user_data.attributes[1]", "email, name"),
		realmRow("id_format unknown", "user_data:\n  id_format: snowflake\n", 3, "user_data.id_format", "uuid, ulid"),
		realmRow("claim unknown", "user_data:\n  claims: [name, nickname]\n", 3, "user_data.claims[1]", "name, email, email_verified, preferred_username, allowed-origins"),
		realmRow("access token claim not in user_data.claims", "user_data:\n  access_token_claims: [nickname]\n", 3, "user_data.access_token_claims[0]", "not in user_data.claims"),

		// login page
		realmRow("logo_url http", "login_page:\n  logo_url: http://example.com/logo.png\n", 3, "login_page.logo_url", "https URL"),
		realmRow("logo_url without host", "login_page:\n  logo_url: https://\n", 3, "login_page.logo_url", "https URL"),
		realmRow("accent_color name", "login_page:\n  accent_color: blue\n", 3, "login_page.accent_color", "hex color"),
		realmRow("accent_color digits", "login_page:\n  accent_color: \"#12345\"\n", 3, "login_page.accent_color", "hex color"),
		realmRow("contact neither email nor URL", "login_page:\n  contact: call us\n", 3, "login_page.contact", "email address or an https URL"),
		realmRow("contact http URL", "login_page:\n  contact: http://example.com/help\n", 3, "login_page.contact", "email address or an https URL"),
		realmRow("contact with a display name", "login_page:\n  contact: \"Help <help@example.com>\"\n", 3, "login_page.contact", "email address or an https URL"),
		realmRow("locale without file", "login_page:\n  supported_locales: [en, de]\n", 3, "login_page.supported_locales[1]", "locales/de.yaml"),
		realmRow("default locale not supported", "login_page:\n  default_locale: fr\n", 3, "login_page.default_locale", "supported_locales"),

		// clients
		// required client options
		clientURIRow("client without redirect_uris", "    name: Web\n", 3, "clients.web.redirect_uris", "required"),
		clientURIRow("client with empty redirect_uris", "    redirect_uris: []\n", 4, "clients.web.redirect_uris", "required"),
		clientURIRow("confidential client without client_secret_file", "    type: confidential\n    redirect_uris: [https://app.example.com/cb]\n", 3, "clients.web.client_secret_file", "required"),

		// redirect_uris (FR-32)
		clientURIRow("redirect URI with a fragment", uriList("redirect_uris", "https://app.example.com/cb#frag"), 5, "clients.web.redirect_uris[0]", "fragment"),
		clientURIRow("redirect URI with a wildcard", uriList("redirect_uris", "https://*.example.com/cb"), 5, "clients.web.redirect_uris[0]", "wildcard"),
		clientURIRow("redirect URI javascript", uriList("redirect_uris", "javascript:alert(1)"), 5, "clients.web.redirect_uris[0]", "javascript"),
		clientURIRow("redirect URI data", uriList("redirect_uris", "data:text/html,x"), 5, "clients.web.redirect_uris[0]", "data"),
		clientURIRow("redirect URI file", uriList("redirect_uris", "file:///etc/passwd"), 5, "clients.web.redirect_uris[0]", "file"),
		clientURIRow("redirect URI http on a public host", uriList("redirect_uris", "http://app.example.com/cb"), 5, "clients.web.redirect_uris[0]", "127.0.0.1"),
		clientURIRow("redirect URI http localhost", uriList("redirect_uris", "http://localhost:3000/cb"), 5, "clients.web.redirect_uris[0]", "use http://127.0.0.1"),
		clientURIRow("redirect URI not absolute", uriList("redirect_uris", "/cb"), 5, "clients.web.redirect_uris[0]", "absolute"),
		clientURIRow("second redirect URI bad", uriList("redirect_uris", "https://app.example.com/cb", "https://app.example.com/x#f"), 6, "clients.web.redirect_uris[1]", "fragment"),
		clientURIRow("loopback IPv4 on a confidential client", confidential+uriList("redirect_uris", "http://127.0.0.1:8080/cb"), 7, "clients.web.redirect_uris[0]", "loopback"),
		clientURIRow("loopback IPv6 on a confidential client", confidential+uriList("redirect_uris", "http://[::1]:8080/cb"), 7, "clients.web.redirect_uris[0]", "loopback"),

		// post_logout_redirect_uris (FR-32)
		clientURIRow("backchannel logout URI with a fragment", "    redirect_uris: [https://app.example.com/callback]\n    backchannel_logout_uri: https://app.example.com/logout#x\n", 5, "clients.web.backchannel_logout_uri", "no fragment"),
		clientRow("post-logout URI with a fragment", uriList("post_logout_redirect_uris", "https://app.example.com/bye#x"), 5, "clients.web.post_logout_redirect_uris[0]", "fragment"),
		clientRow("post-logout URI with a wildcard", uriList("post_logout_redirect_uris", "https://app.example.com/*"), 5, "clients.web.post_logout_redirect_uris[0]", "wildcard"),
		clientRow("post-logout URI javascript", uriList("post_logout_redirect_uris", "javascript:alert(1)"), 5, "clients.web.post_logout_redirect_uris[0]", "javascript"),
		clientRow("post-logout URI http on a public host", uriList("post_logout_redirect_uris", "http://app.example.com/bye"), 5, "clients.web.post_logout_redirect_uris[0]", "127.0.0.1"),
		clientRow("post-logout URI http localhost", uriList("post_logout_redirect_uris", "http://localhost/bye"), 5, "clients.web.post_logout_redirect_uris[0]", "use http://127.0.0.1"),
		clientURIRow("post-logout loopback on a confidential client", confidential+"    redirect_uris: [https://app.example.com/cb]\n"+uriList("post_logout_redirect_uris", "http://127.0.0.1:8080/bye"), 8, "clients.web.post_logout_redirect_uris[0]", "loopback"),

		// web_origins
		clientRow("web origin with a path", "    web_origins: [\"https://app.example.com/app\"]\n", 4, "clients.web.web_origins[0]", "origin"),
		clientRow("web origin with a trailing slash", "    web_origins: [\"https://app.example.com/\"]\n", 4, "clients.web.web_origins[0]", "origin"),
		clientRow("web origin with a query", "    web_origins: [\"https://app.example.com?x=1\"]\n", 4, "clients.web.web_origins[0]", "origin"),
		clientRow("web origin with a fragment", "    web_origins: [\"https://app.example.com#x\"]\n", 4, "clients.web.web_origins[0]", "origin"),
		clientRow("web origin with a wildcard", "    web_origins: [\"https://*.example.com\"]\n", 4, "clients.web.web_origins[0]", "wildcard"),
		clientRow("web origin with user info", "    web_origins: [\"https://u@app.example.com\"]\n", 4, "clients.web.web_origins[0]", "origin"),
		clientRow("web origin without scheme", "    web_origins: [app.example.com]\n", 4, "clients.web.web_origins[0]", "origin"),
		clientRow("web origin star", "    web_origins: [\"*\"]\n", 4, "clients.web.web_origins[0]", "wildcard"),
		clientRow("second web origin bad", "    web_origins:\n      - https://a.example.com\n      - https://b.example.com/x\n", 6, "clients.web.web_origins[1]", "origin"),

		// refresh_token_rotation, require_pkce, App Store 4.8
		clientRow("rotation off on a default public client", "    refresh_token_rotation: false\n", 4, "clients.web.refresh_token_rotation", "public client"),
		clientRow("rotation off on an explicit public client", "    type: public\n    refresh_token_rotation: false\n", 5, "clients.web.refresh_token_rotation", "public client"),
		warnRow(clientRow("require_pkce false on a public client", "    require_pkce: false\n    refresh_idle_lifetime: 24h\n    session_max_lifetime: 720h\n", 4, "clients.web.require_pkce", "RFC 9700 section 2.1.1")),
		warnRow(clientURIRow("require_pkce false on a confidential client", confidential+"    redirect_uris: [https://app.example.com/cb]\n    require_pkce: false\n", 7, "clients.web.require_pkce", "require_pkce: false")),
		warnRow(realmRow("custom-scheme public client with Google and no Apple", "providers:\n  google:\n"+googleOpts+"clients:\n  web:\n    redirect_uris: [\"com.example.app:/cb\"]\n", 9, "clients.web.redirect_uris[0]", "Guideline 4.8")),
		warnRow(realmRow("custom-scheme public client with GitHub and a hidden Apple", "providers:\n  github:\n"+googleOpts+"  apple:\n"+appleOpts+"    hidden: true\n"+"clients:\n  web:\n    redirect_uris: [\"com.example.app:/cb\"]\n", 16, "clients.web.redirect_uris[0]", "Guideline 4.8")),

		// other client options
		clientRow("client type unknown", "    type: secret\n", 4, "clients.web.type", "public, confidential"),
		clientRow("client response_mode unknown", "    response_mode: body\n", 4, "clients.web.response_mode", "query, fragment, form_post"),
		clientRow("client dpop unknown", "    dpop: maybe\n", 4, "clients.web.dpop", "off, allowed, required"),
		clientRow("client access_token_lifetime zero", "    access_token_lifetime: 0s\n", 4, "clients.web.access_token_lifetime", "greater than zero"),
		clientRow("client refresh_idle_lifetime negative", "    refresh_idle_lifetime: -1h\n", 4, "clients.web.refresh_idle_lifetime", "greater than zero"),
		clientRow("client session_max_lifetime negative", "    session_max_lifetime: -1s\n", 4, "clients.web.session_max_lifetime", "negative"),
	)
	return rows
}

const confidential = "    type: confidential\n    client_secret_file: secrets/web\n"

// uriList is a block list of URIs, one per line, quoted.
func uriList(option string, uris ...string) string {
	out := "    " + option + ":\n"
	for _, u := range uris {
		out += "      - " + fmt.Sprintf("%q", u) + "\n"
	}
	return out
}

// withContact adds the login_page.contact Facebook needs.
func withContact(r vrow) vrow { r.yaml += contactLine; return r }

// keyDir writes the signing keys the rows name.
func keyDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, dir, "keys/rsa.pem", rsaPEM(t, 2048), 0o600)
	writeFile(t, dir, "keys/rsa2.pem", rsaPEM(t, 2048), 0o600)
	writeFile(t, dir, "keys/ec.pem", ecPEM(t, elliptic.P256(), false), 0o600)
	writeFile(t, dir, "keys/ec2.pem", ecPEM(t, elliptic.P256(), true), 0o600)
	return dir
}

func hasFile(code string) bool { return code == "fr" }

// validateText decodes text as a file of the given kind and validates it. It
// fails the test on a decoding diagnostic.
func validateText(t *testing.T, dir, kind, file, text string, noEnc bool) []Diagnostic {
	t.Helper()
	switch kind {
	case "server":
		s, ds := DecodeServer(file, []byte(text))
		if len(ds) != 0 {
			t.Fatal(ds)
		}
		return ValidateServer(file, s)
	case "database":
		d, ds := DecodeDatabase(file, []byte(text))
		if len(ds) != 0 {
			t.Fatal(ds)
		}
		return ValidateDatabase(file, d)
	}
	r, ds := DecodeRealm(file, []byte(text))
	if len(ds) != 0 {
		t.Fatal(ds)
	}
	srv := defaultServer()
	if noEnc {
		srv.Secrets.EncryptionKeyFiles = nil
	}
	chk := RealmCheck{Server: &srv, Locales: hasFile}
	// Key files that do not load are reported by LoadSecrets, not here.
	if s, _ := LoadSecrets(dir, SecretSources{Realms: []RealmSource{{File: file, Realm: r}}}); s != nil {
		chk.Secrets = s
	}
	return ValidateRealm(file, r, chk)
}

func (r vrow) text() string {
	if !r.extra {
		return r.yaml
	}
	if r.kind == "server" {
		return srvBase + r.yaml
	}
	return realmHead + r.yaml + realmKeys
}

func (r vrow) fileName() string {
	switch {
	case r.file != "":
		return r.file
	case r.kind == "server":
		return "server.yaml"
	case r.kind == "database":
		return "database.yaml"
	}
	return "realms/main.yaml"
}

// Covers: FR-30
// Covers: FR-29 (part), FR-32 (part), SEC-02 (part), SEC-07 (part), SEC-10 (part), FR-19 (part)
// Acceptance: Reserved realm names (part)
// Acceptance: Config validation (part)
// Acceptance: Encryption key rotation (part)
// Acceptance: Rotation off (part)
// Covers: FR-56 (part)
// Acceptance: Apple scopes rejected
func TestValidationRulesReportFileLineFieldAndReason(t *testing.T) {
	dir := keyDir(t)
	for _, row := range validationRows() {
		t.Run(row.name, func(t *testing.T) {
			ds := validateText(t, dir, row.kind, row.fileName(), row.text(), row.noEnc)
			if len(ds) != 1 {
				t.Fatalf("want exactly one diagnostic, got %v", ds)
			}
			d := ds[0]
			want := row.sev
			if want == 0 {
				want = Error
			}
			if d.Severity != want || d.File != row.fileName() || d.Line != row.line || d.Field != row.field || !strings.Contains(d.Message, row.msg) {
				t.Fatalf("got  %+v\nwant error in %s line %d field %s containing %q", d, row.fileName(), row.line, row.field, row.msg)
			}
		})
	}
}

// The failing row is in the table; here are the cases that need no key.
func TestStoreRefreshTokenNeedsEncryptionKeyFiles(t *testing.T) {
	dir := keyDir(t)
	// Not storing, or not enabled: no key is needed.
	for _, extra := range []string{appleOpts + "    store_refresh_token: false\n", "    store_refresh_token: true\n"} {
		y := realmHead + "providers:\n  apple:\n" + extra + realmKeys
		noErrors(t, validateText(t, dir, "realm", "realms/main.yaml", y, true))
	}
}

// Covers: FR-30, FR-29 (part), FR-32 (part)
// Acceptance: Config validation (part)
func TestDefaultsAndDocumentedValuesAreValid(t *testing.T) {
	dir := keyDir(t)
	noErrors(t, validateText(t, dir, "server", "server.yaml", srvBase, false))
	noErrors(t, validateText(t, dir, "database", "database.yaml", "", false))
	noErrors(t, validateText(t, dir, "realm", "realms/main.yaml", realmHead+realmKeys, false))

	noErrors(t, validateText(t, dir, "server", "server.yaml", `public_url: http://localhost:8080
require_https: false
listen: 127.0.0.1:0
log_level: debug
trusted_proxies: ["127.0.0.1/32", "::1/128"]
rate_limit:
  per_ip_per_minute: 0
urls:
  path_prefix: /auth
  issuer: "{prefix}/{realm}"
  endpoints:
    authorize: "{prefix}/{realm}/protocol/openid-connect/auth"
    token: "{prefix}/{realm}/protocol/openid-connect/token"
    provider_events: "{prefix}/{realm}/app/events/{provider}"
`, false))
	noErrors(t, validateText(t, dir, "server", "server.yaml", "public_url: https://a.example\nlisten: \":8080\"\nlog_level: error\n", false))

	noErrors(t, validateText(t, dir, "database", "database.yaml", `driver: postgres
sqlite:
  busy_timeout: 1ms
postgres:
  host: db.example.com
  password_file: secrets/pg
  sslmode: verify-full
backup:
  at: ""
  keep: 1
`, false))
	noErrors(t, validateText(t, dir, "database", "database.yaml", "backup:\n  at: \"23:59\"\npostgres:\n  sslmode: disable\n", false))

	noErrors(t, validateText(t, dir, "realm", "realms/main.yaml", `name: main
display_name: Main & Co
tokens:
  access_token_lifetime: 1m
  refresh_idle_lifetime: 1s
  session_max_lifetime: 0
  code_lifetime: 300s
  refresh_reuse_grace: 0
  algorithm: ES256
  refresh_token_format: jwt
user_data:
  attributes: [email, name]
  claims: [name, email, email_verified, preferred_username, allowed-origins]
login_page:
  logo_url: https://example.com/logo.png
  accent_color: "#FFF"
  contact: help@example.com
  default_locale: fr
  supported_locales: [en, fr]
providers:
  google: {sync_mode: force, timeout: 30s, endpoints: {authorize: "http://127.0.0.1:9/auth", token: "https://idp.example.com/token", userinfo: "http://localhost/ui", jwks: "https://idp.example.com/jwks"}}
  oidc: {issuer: "http://127.0.0.1:9"}
  apple: {client_secret_lifetime: 15777000s}
  facebook: {flow: oauth, graph_version: v26.0}
clients:
  web: {type: confidential, client_secret_file: secrets/web, redirect_uris: ["https://app.example.com/cb", "com.example.app:/cb"], post_logout_redirect_uris: ["https://app.example.com/bye"], web_origins: ["https://app.example.com", "http://localhost:3000"], refresh_token_rotation: false, response_mode: form_post, session_max_lifetime: 0, access_token_lifetime: 1s}
  app: {redirect_uris: ["http://127.0.0.1:8080/cb", "http://[::1]/cb", "com.example.app:/cb"], refresh_token_rotation: true}
keys:
  - { kid: rsa1, file: keys/rsa.pem, state: active }
  - { kid: ec1, file: keys/ec.pem, state: active }
  - { kid: rsa0, file: keys/rsa2.pem, state: verify_only }
  - { kid: ec0, file: keys/ec2.pem, state: verify_only }
`, false))
	// The lower code_lifetime bound is accepted.
	noErrors(t, validateText(t, dir, "realm", "realms/main.yaml", realmHead+"tokens:\n  code_lifetime: 10s\n"+realmKeys, false))
	noErrors(t, validateText(t, dir, "realm", "realms/main.yaml", realmHead+"login_page:\n  contact: https://example.com/help\n  accent_color: \"#11223344\"\n"+realmKeys, false))
	// A verify-only EC key is fine in an RS256 realm; Facebook needs a contact only when enabled.
	noErrors(t, validateText(t, dir, "realm", "realms/main.yaml", realmHead+"providers:\n  facebook:\n"+facebookOpts+"login_page:\n  contact: help@example.com\n"+realmKeys+"  - kid: ec1\n    file: keys/ec.pem\n    state: verify_only\n", false))
}

// Covers: SEC-07 (part), FR-32 (part)
// Acceptance: Config validation (part)
func TestKeyRulesAreSkippedWithoutKeyMaterial(t *testing.T) {
	r, ds := DecodeRealm("realms/main.yaml", []byte(realmHead+realmKeys))
	if len(ds) != 0 {
		t.Fatal(ds)
	}
	srv := defaultServer()
	// The key file failed to load, which LoadSecrets reported; no second diagnostic.
	noErrors(t, ValidateRealm("realms/main.yaml", r, RealmCheck{Server: &srv}))
	empty := &FileSecrets{signing: map[string]crypto.Signer{}}
	noErrors(t, ValidateRealm("realms/main.yaml", r, RealmCheck{Server: &srv, Secrets: empty}))
}

// kid uniqueness spans realms, so it cannot be a one-file row of the table and
// has this dedicated test.
//
// Covers: SEC-07 (part)
// Acceptance: Config validation (part)
func TestKidIsUniqueAcrossRealms(t *testing.T) {
	mk := func(file, name string, kids ...string) RealmSource {
		y := "name: " + name + "\nkeys:\n"
		for _, k := range kids {
			y += "  - { kid: " + k + ", file: keys/rsa.pem, state: active }\n"
		}
		r, ds := DecodeRealm(file, []byte(y))
		if len(ds) != 0 {
			t.Fatal(ds)
		}
		return RealmSource{File: file, Realm: r}
	}
	a := mk("realms/a.yaml", "a", "k1", "k2")
	b := mk("realms/b.yaml", "b", "k3", "k2")
	ds := ValidateKeyIDs([]RealmSource{a, b})
	if len(ds) != 1 {
		t.Fatalf("got %v", ds)
	}
	d := ds[0]
	if d.Severity != Error || d.File != "realms/b.yaml" || d.Line != 4 || d.Field != "keys[1].kid" ||
		!strings.Contains(d.Message, "k2") || !strings.Contains(d.Message, "realms/a.yaml") {
		t.Fatalf("got %+v", d)
	}
	// The same kid twice in one realm is a duplicate too.
	c := mk("realms/c.yaml", "c", "k9", "k9")
	ds = ValidateKeyIDs([]RealmSource{c})
	if len(ds) != 1 || ds[0].Field != "keys[1].kid" || ds[0].File != "realms/c.yaml" {
		t.Fatalf("got %v", ds)
	}
	noErrors(t, ValidateKeyIDs([]RealmSource{a, mk("realms/d.yaml", "d", "k7")}))
	noErrors(t, ValidateKeyIDs(nil))
}

// deferredOptions have a "Possible values" cell whose constraint the
// validator cannot check, with the reason. TestEveryPossibleValueHasARule
// fails when one of them gets a rule, so the list cannot go stale.
var deferredOptions = map[string]string{
	"login.provider_hint_params":               "parameter names: the design gives no syntax",
	"logout.redirect_params":                   "parameter names: the design gives no syntax",
	"sqlite.journal_mode":                      "`wal`, others only for filesystems that cannot support it: the design lists no others",
	"backup.directory":                         "directory path",
	"user_data.auto_link_domains":              "list of domains: the design gives no syntax",
	"login_page.provider_order":                "list of provider keys that may name providers not configured (the default does)",
	"security_headers.content_security_policy": "header value, empty omits it",
	"security_headers.hsts":                    "header value, empty omits it",
	"providers.*.hosted_domain":                "empty or a domain: the design gives no syntax",
}

// freeCells are "Possible values" cells that name no constraint.
var freeCells = map[string]bool{"text": true, "list": true, "file path": true, "list of files": true}

var (
	boolCell   = regexp.MustCompile("^`(true|false)`")
	arrayIndex = regexp.MustCompile(`\[\d+\]`)
)

// normalize turns a diagnostic field such as providers.google.timeout or
// keys[0].kid into the option path of the Configuration reference's tables.
func normalizeField(f string) string {
	f = strings.TrimSuffix(arrayIndex.ReplaceAllString(f, "[]"), "[]") // an item rule belongs to its list option
	parts := strings.Split(f, ".")
	if len(parts) > 2 && (parts[0] == "providers" || parts[0] == "clients") {
		parts[1] = "*"
	}
	return strings.Join(parts, ".")
}

// Covers: FR-30
// Acceptance: Config validation (part)
func TestEveryPossibleValueHasARule(t *testing.T) {
	covered := map[string]bool{}
	for _, row := range validationRows() {
		covered[normalizeField(row.field)] = true
	}
	tables := designTables(t)
	roots := map[string]reflect.Type{
		"server": reflect.TypeOf(ServerFile{}), "database": reflect.TypeOf(DatabaseFile{}),
		"realm": reflect.TypeOf(RealmFile{}), "common": reflect.TypeOf(Provider{}),
		"per-provider": reflect.TypeOf(Provider{}), "client": reflect.TypeOf(Client{}),
	}
	seen := map[string]bool{}
	constrained := 0
	for section, typ := range roots {
		for _, row := range tables[section] {
			if row.possible == "" {
				t.Errorf("%s %v: no Possible values cell parsed", section, row.options)
			}
			for _, opt := range row.options {
				path := opt
				switch section {
				case "common", "per-provider":
					path = "providers.*." + opt
				case "client":
					path = "clients.*." + opt
				}
				seen[path] = true
				cell := strings.TrimSpace(row.possible)
				switch {
				case freeCells[cell]:
					continue
				case deferredOptions[path] != "":
					if covered[path] {
						t.Errorf("%s has a rule row now: remove it from deferredOptions", path)
					}
					continue
				}
				constrained++
				sf, _, ok := field(typ, opt)
				if !ok {
					t.Errorf("%s: option not found in %s", path, typ)
					continue
				}
				kind := deref(sf.Type).Kind()
				switch {
				case boolCell.MatchString(cell):
					// Decoding rejects anything but a boolean; the Facebook
					// trust_email warning has its own row.
					if kind != reflect.Bool {
						t.Errorf("%s: cell %q says boolean, field is %s", path, cell, kind)
					}
				case cell == "integer":
					if kind != reflect.Int {
						t.Errorf("%s: cell %q says integer, field is %s", path, cell, kind)
					}
				case !covered[path]:
					t.Errorf("%s: %q has no failing row in the validation table", path, cell)
				}
			}
		}
	}
	for path := range deferredOptions {
		if !seen[path] {
			t.Errorf("deferredOptions names %s, which is not in the reference", path)
		}
	}
	for path := range covered {
		if !seen[path] {
			t.Errorf("table row for %s, which is not an option of the reference", path)
		}
	}
	if constrained < 60 {
		t.Errorf("only %d constrained cells found; the parser may have lost rows", constrained)
	}
}

func TestDiagnosticFileIsAsGiven(t *testing.T) {
	s, _ := DecodeServer("conf/server.yaml", []byte("public_url: nope\n"))
	ds := ValidateServer("conf/server.yaml", s)
	if len(ds) == 0 || ds[0].File != filepath.ToSlash("conf/server.yaml") {
		t.Fatalf("got %v", ds)
	}
}

// Covers: FR-32 (part)
// Acceptance: Config validation (part)
func TestDiagnosticOrderIsStable(t *testing.T) {
	dir := keyDir(t)
	y := realmHead + `providers:
  google:
    endpoints: {authorize: a, token: b, userinfo: c, jwks: d}
  oidc: {issuer: i}
  github: {sync_mode: merge, timeout: 0s}
  apple: {client_secret_lifetime: 0s}
  facebook: {flow: token, graph_version: "26"}
` + realmKeys
	first := fmt.Sprint(validateText(t, dir, "realm", "realms/main.yaml", y, false))
	if n := strings.Count(first, "\n") + strings.Count(first, "error:") - 1; n < 8 {
		t.Fatalf("expected many diagnostics, got %s", first)
	}
	for i := 0; i < 50; i++ {
		if got := fmt.Sprint(validateText(t, dir, "realm", "realms/main.yaml", y, false)); got != first {
			t.Fatalf("order changed:\n%s\n%s", first, got)
		}
	}
	// And the server file with several broken endpoints.
	sy := srvBase + "urls:\n  endpoints: {authorize: x, token: x, userinfo: x, jwks: x, logout: x, assets: x}\n"
	s, _ := DecodeServer("server.yaml", []byte(sy))
	want := fmt.Sprint(ValidateServer("server.yaml", s))
	for i := 0; i < 50; i++ {
		if got := fmt.Sprint(ValidateServer("server.yaml", s)); got != want {
			t.Fatalf("server order changed:\n%s\n%s", want, got)
		}
	}
}

var (
	rowKeys     sync.Once
	rowKeyFiles map[string][]byte // generated once: RSA keys are slow
)

// writeRowDir writes a configuration directory around a validation row: the
// row's file as it is, and a valid file for everything else.
func writeRowDir(t *testing.T, row vrow) string {
	t.Helper()
	dir := t.TempDir()
	rowKeys.Do(func() {
		rowKeyFiles = map[string][]byte{
			"keys/rsa.pem": rsaPEM(t, 2048), "keys/rsa2.pem": rsaPEM(t, 2048),
			"keys/ec.pem": ecPEM(t, elliptic.P256(), false), "keys/ec2.pem": ecPEM(t, elliptic.P256(), true),
		}
	})
	for name, b := range rowKeyFiles {
		writeFile(t, dir, name, b, 0o600)
	}
	server, database, realm := srvBase, "", realmHead+realmKeys
	realmFile := "realms/main.yaml"
	switch row.kind {
	case "server":
		server = row.text()
	case "database":
		database = row.text()
	default:
		realm, realmFile = row.text(), row.fileName()
	}
	if row.noEnc {
		server += "secrets:\n  encryption_key_files: []\n"
	}
	writeFile(t, dir, "server.yaml", []byte(server), 0o600)
	if database != "" {
		writeFile(t, dir, "database.yaml", []byte(database), 0o600)
	}
	writeFile(t, dir, realmFile, []byte(realm), 0o600)
	writeFile(t, dir, "locales/fr.yaml", []byte("chooser.title: \"Connexion\"\n"), 0o600)
	return dir
}

// Every row of the validation table is reported with the same file, line,
// field and reason when the whole directory is checked, which is what
// `featherauth config check` prints.
//
// Covers: FR-32, FR-19 (part)
// Acceptance: Config validation
func TestCheckReportsEveryValidationRow(t *testing.T) {
	for _, row := range validationRows() {
		t.Run(row.name, func(t *testing.T) {
			ds := Check(context.Background(), writeRowDir(t, row), clock.NewFake(time.Unix(0, 0)))
			want := row.sev
			if want == 0 {
				want = Error
			}
			for _, d := range ds {
				if d.Severity == want && d.File == row.fileName() && d.Line == row.line && d.Field == row.field && strings.Contains(d.Message, row.msg) {
					return
				}
			}
			t.Fatalf("no diagnostic in %s line %d field %s containing %q among %v", row.fileName(), row.line, row.field, row.msg, ds)
		})
	}
	// Rejections that depend on the content of a secret file.
	secretRows := []struct {
		name, file, field, msg string
		server, realm          string
		files                  map[string]string
	}{
		{name: "encryption key too short", file: "server.yaml", field: "secrets.encryption_key_files[0]", msg: "32 bytes",
			server: "secrets:\n  encryption_key_files: [secrets/enc]\n", files: map[string]string{"secrets/enc": "c2hvcnQ=\n"}},
		{name: "encryption key not base64", file: "server.yaml", field: "secrets.encryption_key_files[0]", msg: "32 bytes",
			server: "secrets:\n  encryption_key_files: [secrets/enc]\n", files: map[string]string{"secrets/enc": strings.Repeat("!", 44) + "\n"}},
		{name: "provider secret empty", file: "realms/main.yaml", field: "providers.google.client_secret_file", msg: "empty",
			realm: "providers:\n  google:\n" + googleOpts, files: map[string]string{"secrets/g": ""}},
		{name: "provider secret whitespace only", file: "realms/main.yaml", field: "providers.google.client_secret_file", msg: "empty",
			realm: "providers:\n  google:\n" + googleOpts, files: map[string]string{"secrets/g": " \t\n"}},
		{name: "client secret empty", file: "realms/main.yaml", field: "clients.web.client_secret_file", msg: "empty",
			realm: "clients:\n  web:\n    type: confidential\n    client_secret_file: secrets/c\n    redirect_uris: [https://app.example.com/cb]\n", files: map[string]string{"secrets/c": ""}},
		{name: "client secret whitespace only", file: "realms/main.yaml", field: "clients.web.client_secret_file", msg: "empty",
			realm: "clients:\n  web:\n    type: confidential\n    client_secret_file: secrets/c\n    redirect_uris: [https://app.example.com/cb]\n", files: map[string]string{"secrets/c": "\n\n"}},
	}
	for _, row := range secretRows {
		t.Run(row.name, func(t *testing.T) {
			dir := keyDir(t)
			writeFile(t, dir, "server.yaml", []byte(srvBase+row.server), 0o600)
			writeFile(t, dir, "realms/main.yaml", []byte(realmHead+row.realm+realmKeys), 0o600)
			for name, content := range row.files {
				writeFile(t, dir, name, []byte(content), 0o600)
			}
			ds := Check(context.Background(), dir, clock.NewFake(time.Unix(0, 0)))
			for _, d := range ds {
				if d.Severity == Error && d.File == row.file && d.Line > 0 && d.Field == row.field && strings.Contains(d.Message, row.msg) {
					return
				}
			}
			t.Fatalf("no error in %s for %s containing %q among %v", row.file, row.field, row.msg, ds)
		})
	}

	// The cases that are accepted: the two zeros with a meaning, a missing
	// secret file of a disabled provider, and a missing encryption key file
	// when no enabled provider stores a refresh token.
	accepted := map[string]string{
		"the two zeros": "tokens:\n  session_max_lifetime: 0\n  refresh_reuse_grace: 0\n",
		"missing secret file of a disabled provider": "providers:\n  google:\n    enabled: false\n    client_id: id\n    client_secret_file: secrets/missing\n",
		"missing encryption key file":                "providers:\n  google:\n    enabled: false\n",
	}
	for name, extra := range accepted {
		t.Run("accepted: "+name, func(t *testing.T) {
			dir := keyDir(t)
			writeFile(t, dir, "server.yaml", []byte(srvBase), 0o600)
			writeFile(t, dir, "realms/main.yaml", []byte(realmHead+extra+realmKeys), 0o600)
			if ds := Check(context.Background(), dir, clock.NewFake(time.Unix(0, 0))); len(ds) != 0 {
				t.Fatalf("diagnostics %v", ds)
			}
		})
	}
}

// Covers: FR-32 (part)
// Acceptance: Config validation (part)
func TestCheckAcceptsTheTwoZeroLifetimes(t *testing.T) {
	dir := keyDir(t)
	writeFile(t, dir, "server.yaml", []byte(srvBase), 0o600)
	writeFile(t, dir, "realms/main.yaml", []byte(realmHead+"tokens:\n  session_max_lifetime: 0\n  refresh_reuse_grace: 0\n"+realmKeys), 0o600)
	if ds := Check(context.Background(), dir, clock.NewFake(time.Unix(0, 0))); len(ds) != 0 {
		t.Fatalf("diagnostics %v", ds)
	}
}

func TestCheckReportsAnEmptyDirectoryAsAnError(t *testing.T) {
	ds := Check(context.Background(), t.TempDir(), clock.NewFake(time.Unix(0, 0)))
	if !hasError(ds) {
		t.Fatalf("diagnostics %v", ds)
	}
}

// The Postgres password file is read, and its permissions checked, only with
// driver: postgres.
//
// Covers: SEC-09 (part)
func TestPostgresPasswordFileIsReadOnlyWithThePostgresDriver(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mode   int // -1: the file does not exist; -2: a directory, which no user can read as a file
		driver string
		want   string // part of an error; empty for a clean load
	}{
		{"sqlite, file missing", -1, "sqlite", ""},
		{"sqlite, path is a directory", -2, "sqlite", ""},
		{"sqlite, file world readable", 0o644, "sqlite", ""},
		{"postgres, file missing", -1, "postgres", "postgres.password_file"},
		{"postgres, path is a directory", -2, "postgres", "postgres.password_file"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := keyDir(t)
			writeFile(t, dir, "server.yaml", []byte(srvBase), 0o600)
			writeFile(t, dir, "realms/main.yaml", []byte(realmHead+realmKeys), 0o600)
			writeFile(t, dir, "database.yaml", []byte("driver: "+tc.driver+"\npostgres:\n  host: db.example.com\n  password_file: secrets/pg\n"), 0o600)
			switch {
			case tc.mode >= 0:
				writeFile(t, dir, "secrets/pg", []byte("pw\n"), os.FileMode(tc.mode))
			case tc.mode == -2:
				if err := os.MkdirAll(filepath.Join(dir, "secrets/pg"), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			ds := Check(context.Background(), dir, clock.NewFake(time.Unix(0, 0)))
			if tc.want == "" {
				if len(ds) != 0 {
					t.Fatalf("diagnostics %v", ds)
				}
				return
			}
			if !hasError(ds) || !strings.Contains(ds[0].Field, tc.want) {
				t.Fatalf("diagnostics %v", ds)
			}
		})
	}
}

// Covers: FR-35 (part)
// Acceptance: Config validation (part)
// Zero pool sizes are accepted (0 is no limit, or no idle connections), and an
// idle count above the open count is accepted too: database/sql caps the idle
// count at the open count (the Configuration reference).
func TestPoolSizesZeroIsAccepted(t *testing.T) {
	dir := keyDir(t)
	for _, pool := range []string{
		"max_open_conns: 0\n  max_idle_conns: 0\n",
		"max_open_conns: 2\n  max_idle_conns: 5\n",
	} {
		noErrors(t, validateText(t, dir, "database", "database.yaml", "driver: postgres\npostgres:\n  host: db\n  password_file: secrets/pg\n  "+pool, false))
	}
}

// Apple's scopes (FR-56): the default, an empty list and either order are
// accepted, and decoding keeps an empty list empty instead of restoring the
// default.
//
// Covers: FR-56 (part)
// Acceptance: Apple scopes accepted
func TestAppleScopesAcceptedValues(t *testing.T) {
	for _, tc := range []struct {
		name, scopes string
		want         []string
	}{
		{"unset", "", []string{"name", "email"}},
		{"email alone", "    scopes: [email]\n", []string{"email"}},
		{"reversed", "    scopes: [email, name]\n", []string{"email", "name"}},
		{"empty", "    scopes: []\n", []string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := keyDir(t)
			writeFile(t, dir, "server.yaml", []byte(srvBase), 0o600)
			writeFile(t, dir, "realms/main.yaml", []byte(realmHead+"providers:\n  apple:\n"+tc.scopes+realmKeys), 0o600)
			if ds := Check(context.Background(), dir, clock.NewFake(time.Unix(0, 0))); len(ds) != 0 {
				t.Fatalf("diagnostics %v", ds)
			}
			r, ds := DecodeRealm("realms/main.yaml", []byte(realmHead+"providers:\n  apple:\n"+tc.scopes+realmKeys))
			if len(ds) != 0 {
				t.Fatal(ds)
			}
			got := r.Providers["apple"].Scopes
			if got == nil || !slices.Equal(got, tc.want) {
				t.Fatalf("scopes %#v, want %#v", got, tc.want)
			}
		})
	}
}

// postgres.connect_timeout: 0s and -1s are errors that name database.yaml, the
// line and the reason, as `config check` prints them; unset means 5s and 2s is
// accepted.
//
// Covers: FR-25
// Acceptance: Postgres connect timeout
func TestConfigCheckRejectsAPostgresConnectTimeoutThatIsNotPositive(t *testing.T) {
	for _, tc := range []struct{ name, value string }{{"zero", "0s"}, {"negative", "-1s"}} {
		t.Run(tc.name, func(t *testing.T) {
			row := dbRow(tc.name, "postgres:\n  connect_timeout: "+tc.value+"\n", 2, "postgres.connect_timeout", "greater than zero")
			ds := Check(context.Background(), writeRowDir(t, row), clock.NewFake(time.Unix(0, 0)))
			for _, d := range ds {
				if d.Severity == Error && d.File == "database.yaml" && d.Line == 2 && d.Field == "postgres.connect_timeout" &&
					strings.Contains(d.Message, "greater than zero") {
					return
				}
			}
			t.Fatalf("no error in database.yaml line 2 for postgres.connect_timeout among %v", ds)
		})
	}
	for _, tc := range []struct {
		name, yaml string
		want       time.Duration
	}{
		{"unset", "postgres:\n  host: db\n", 5 * time.Second},
		{"2s", "postgres:\n  connect_timeout: 2s\n", 2 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, ds := DecodeDatabase("database.yaml", []byte(tc.yaml))
			if len(ds) != 0 {
				t.Fatal(ds)
			}
			for _, e := range ValidateDatabase("database.yaml", d) {
				if e.Field == "postgres.connect_timeout" {
					t.Errorf("unexpected diagnostic %+v", e)
				}
			}
			if got := d.Postgres.ConnectTimeout.Std(); got != tc.want {
				t.Errorf("connect_timeout = %v, want %v", got, tc.want)
			}
		})
	}
}

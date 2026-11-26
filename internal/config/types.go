package config

import (
	"slices"

	"go.yaml.in/yaml/v3"
)

// ClientType is "public" or "confidential".
type ClientType string

const (
	Public       ClientType = "public"
	Confidential ClientType = "confidential"
)

// ServerFile is server.yaml.
type ServerFile struct {
	PublicURL         string        `yaml:"public_url"`
	Listen            string        `yaml:"listen"`
	TLS               TLSFile       `yaml:"tls"`
	Secrets           ServerSecrets `yaml:"secrets"`
	RequireHTTPS      bool          `yaml:"require_https"`
	StrictPermissions bool          `yaml:"strict_permissions"`
	LogLevel          string        `yaml:"log_level"`
	TrustedProxies    []string      `yaml:"trusted_proxies"`
	RateLimit         RateLimit     `yaml:"rate_limit"`
	URLs              URLs          `yaml:"urls"`
	Login             ServerLogin   `yaml:"login"`
	Logout            ServerLogout  `yaml:"logout"`

	lines map[string]int // option path -> line in the file
}

// Line returns the line of an option path such as
// "secrets.encryption_key_files[0]", or 0 when the file does not set it.
func (s *ServerFile) Line(field string) int { return s.lines[field] }

// TLSFile is the tls section of server.yaml: built-in TLS (tls.mode files).
type TLSFile struct {
	Mode       string `yaml:"mode"`
	Listen     string `yaml:"listen"`
	HTTPListen string `yaml:"http_listen"`
	CertFile   string `yaml:"cert_file"`
	KeyFile    string `yaml:"key_file"`
}

// ServerSecrets is the secrets section of server.yaml.
type ServerSecrets struct {
	EncryptionKeyFiles []string `yaml:"encryption_key_files"`
}

// RateLimit is the rate_limit section of server.yaml.
type RateLimit struct {
	PerIPPerMinute int    `yaml:"per_ip_per_minute"`
	Store          string `yaml:"store"`
}

// URLs holds the path templates of server.yaml.
type URLs struct {
	PathPrefix string    `yaml:"path_prefix"`
	Issuer     string    `yaml:"issuer"`
	Endpoints  Endpoints `yaml:"endpoints"`
}

// Endpoints are the path templates of the endpoints.
type Endpoints struct {
	Authorize      string `yaml:"authorize"`
	Token          string `yaml:"token"`
	Userinfo       string `yaml:"userinfo"`
	JWKS           string `yaml:"jwks"`
	Logout         string `yaml:"logout"`
	Revoke         string `yaml:"revoke"`
	Sessions       string `yaml:"sessions"`
	Callback       string `yaml:"callback"`
	AccountDelete  string `yaml:"account_delete"`
	Assets         string `yaml:"assets"`
	ProviderEvents string `yaml:"provider_events"`
	DataDeletion   string `yaml:"data_deletion"`
}

// ServerLogin is the login section of server.yaml.
type ServerLogin struct {
	ProviderHintParams []string `yaml:"provider_hint_params"`
}

// ServerLogout is the logout section of server.yaml.
type ServerLogout struct {
	RedirectParams []string `yaml:"redirect_params"`
}

// DatabaseFile is database.yaml.
type DatabaseFile struct {
	Driver   string         `yaml:"driver"`
	SQLite   SQLiteConfig   `yaml:"sqlite"`
	Postgres PostgresConfig `yaml:"postgres"`
	Backup   BackupConfig   `yaml:"backup"`

	lines map[string]int // option path -> line in the file
}

// Line returns the line of an option path such as "postgres.password_file",
// or 0 when the file does not set it.
func (d *DatabaseFile) Line(field string) int { return d.lines[field] }

// SQLiteConfig is the sqlite section of database.yaml.
type SQLiteConfig struct {
	Path            string   `yaml:"path"`
	BusyTimeout     Duration `yaml:"busy_timeout"`
	JournalMode     string   `yaml:"journal_mode"`
	ReadConnections int      `yaml:"read_connections"`
}

// PostgresConfig is the postgres section of database.yaml.
type PostgresConfig struct {
	Host            string   `yaml:"host"`
	Port            int      `yaml:"port"`
	Database        string   `yaml:"database"`
	User            string   `yaml:"user"`
	PasswordFile    string   `yaml:"password_file"`
	SSLMode         string   `yaml:"sslmode"`
	RootCertFile    string   `yaml:"root_cert_file"`
	MaxOpenConns    int      `yaml:"max_open_conns"`
	MaxIdleConns    int      `yaml:"max_idle_conns"`
	ConnectTimeout  Duration `yaml:"connect_timeout"`
	ConnMaxLifetime Duration `yaml:"conn_max_lifetime"`
}

// BackupConfig is the backup section of database.yaml.
type BackupConfig struct {
	Directory string `yaml:"directory"`
	At        string `yaml:"at"`
	Keep      int    `yaml:"keep"`
}

// RealmFile is realms/<name>.yaml.
type RealmFile struct {
	Name            string          `yaml:"name"`
	DisplayName     string          `yaml:"display_name"`
	Enabled         bool            `yaml:"enabled"`
	Tokens          Tokens          `yaml:"tokens"`
	SSO             SSO             `yaml:"sso"`
	Keys            []Key           `yaml:"keys"`
	UserData        UserData        `yaml:"user_data"`
	LoginPage       LoginPage       `yaml:"login_page"`
	SecurityHeaders SecurityHeaders `yaml:"security_headers"`
	Providers       Providers       `yaml:"providers"`
	Clients         Clients         `yaml:"clients"`

	lines   map[string]int               // option path -> line in the file
	locales map[string]map[string]string // locale code -> message id -> text; set by the Loader
}

// Line returns the line of an option path such as "tokens.code_lifetime" or
// "keys[0].kid", or 0 when the file does not set it.
func (r *RealmFile) Line(field string) int { return r.lines[field] }

// SSO is the realm's single sign-on session (FR-45): whether it is on, and the
// idle and maximum lifetimes of a browser session.
type SSO struct {
	Enabled      bool     `yaml:"enabled"`
	IdleLifetime Duration `yaml:"idle_lifetime"`
	MaxLifetime  Duration `yaml:"max_lifetime"`
}

// Tokens are the token lifetimes and formats of a realm.
type Tokens struct {
	AccessTokenLifetime     Duration `yaml:"access_token_lifetime"`
	RefreshIdleLifetime     Duration `yaml:"refresh_idle_lifetime"`
	SessionMaxLifetime      Duration `yaml:"session_max_lifetime"`
	CodeLifetime            Duration `yaml:"code_lifetime"`
	LoginTimeout            Duration `yaml:"login_timeout"`
	RefreshReuseGrace       Duration `yaml:"refresh_reuse_grace"`
	RefreshTokenRotation    bool     `yaml:"refresh_token_rotation"`
	AccountDeleteMaxAuthAge Duration `yaml:"account_delete_max_auth_age"`
	Algorithm               string   `yaml:"algorithm"`
	RefreshTokenFormat      string   `yaml:"refresh_token_format"`
}

// Key is one signing key of a realm.
type Key struct {
	Kid   string `yaml:"kid"`
	File  string `yaml:"file"`
	State string `yaml:"state"`
}

// The values of user_data.id_format: the format of the id of every user the
// realm creates.
const (
	IDFormatUUID = "uuid"
	IDFormatULID = "ulid"
)

// UserData says what is stored and emitted about a user.
type UserData struct {
	Attributes        []string `yaml:"attributes"`
	Claims            []string `yaml:"claims"`
	KeepNameIfMissing bool     `yaml:"keep_name_if_missing"`
	IDFormat          string   `yaml:"id_format"`
	AutoLinkDomains   []string `yaml:"auto_link_domains"`
	// AccessTokenClaims is nil when user_data.access_token_claims is not set.
	// A set empty list is not nil and puts no user claim in access tokens.
	AccessTokenClaims *[]string `yaml:"access_token_claims"`
}

// AccessClaims returns the user claims that go into access tokens: the names
// of AccessTokenClaims when the option is set, else those of Claims. The
// result is a copy.
func (u UserData) AccessClaims() []string {
	if u.AccessTokenClaims != nil {
		return slices.Clone(*u.AccessTokenClaims)
	}
	return slices.Clone(u.Claims)
}

// LoginPage configures the chooser and the error pages.
type LoginPage struct {
	LogoURL          string   `yaml:"logo_url"`
	AccentColor      string   `yaml:"accent_color"`
	Contact          string   `yaml:"contact"`
	ProviderOrder    []string `yaml:"provider_order"`
	DefaultLocale    string   `yaml:"default_locale"`
	SupportedLocales []string `yaml:"supported_locales"`
}

// SecurityHeaders are the headers of browser pages.
type SecurityHeaders struct {
	ContentSecurityPolicy string `yaml:"content_security_policy"`
	HSTS                  string `yaml:"hsts"`
}

// Provider holds the options of one provider: the common ones and those of
// every adapter type. A field with an `only` tag is accepted only for the
// listed types; for a type the design does not know, every field is accepted
// and validation reports the type.
type Provider struct {
	Type                  string            `yaml:"type"`
	Enabled               bool              `yaml:"enabled"`
	DisplayName           string            `yaml:"display_name"`
	Hidden                bool              `yaml:"hidden"`
	ClientID              string            `yaml:"client_id"`
	ClientSecretFile      string            `yaml:"client_secret_file"`
	Scopes                []string          `yaml:"scopes"`
	TrustEmail            bool              `yaml:"trust_email"`
	AutoLink              bool              `yaml:"auto_link"`
	SyncMode              string            `yaml:"sync_mode"`
	Timeout               Duration          `yaml:"timeout"`
	Endpoints             ProviderEndpoints `yaml:"endpoints"`
	HostedDomain          string            `yaml:"hosted_domain" only:"google"`
	TeamID                string            `yaml:"team_id" only:"apple"`
	KeyID                 string            `yaml:"key_id" only:"apple"`
	PrivateKeyFile        string            `yaml:"private_key_file" only:"apple"`
	ClientSecretLifetime  Duration          `yaml:"client_secret_lifetime" only:"apple"`
	StoreRefreshToken     bool              `yaml:"store_refresh_token" only:"apple"`
	NotificationAudiences []string          `yaml:"notification_audiences" only:"apple"`
	PKCE                  bool              `yaml:"pkce" only:"github"`
	AllowSignup           bool              `yaml:"allow_signup" only:"github"`
	RequireVerifiedEmail  bool              `yaml:"require_verified_email" only:"github"`
	GraphVersion          string            `yaml:"graph_version" only:"facebook"`
	Flow                  string            `yaml:"flow" only:"facebook"`
	Fields                []string          `yaml:"fields" only:"facebook"`
	RequireEmail          bool              `yaml:"require_email" only:"facebook"`
	Issuer                string            `yaml:"issuer" only:"oidc"`
}

// ProviderEndpoints override a provider's own URLs.
type ProviderEndpoints struct {
	Authorize string `yaml:"authorize"`
	Token     string `yaml:"token"`
	Userinfo  string `yaml:"userinfo"`
	JWKS      string `yaml:"jwks"`
	// RISCConfiguration is Google's RISC configuration document (Google only).
	RISCConfiguration string `yaml:"risc_configuration" only:"google"`
}

// Client is one client of a realm. A nil lifetime or rotation means the realm
// value.
type Client struct {
	Name                   string     `yaml:"name"`
	Description            string     `yaml:"description"`
	Type                   ClientType `yaml:"type"`
	ClientSecretFile       string     `yaml:"client_secret_file"`
	RedirectURIs           []string   `yaml:"redirect_uris"`
	PostLogoutRedirectURIs []string   `yaml:"post_logout_redirect_uris"`
	WebOrigins             []string   `yaml:"web_origins"`
	RequirePKCE            bool       `yaml:"require_pkce"`
	ResponseMode           string     `yaml:"response_mode"`
	Audience               string     `yaml:"audience"`
	AccessTokenLifetime    *Duration  `yaml:"access_token_lifetime"`
	RefreshIdleLifetime    *Duration  `yaml:"refresh_idle_lifetime"`
	SessionMaxLifetime     *Duration  `yaml:"session_max_lifetime"`
	RefreshTokenRotation   *bool      `yaml:"refresh_token_rotation"`
	AllowAccountDelete     bool       `yaml:"allow_account_delete"`
	AllowSessionManagement bool       `yaml:"allow_session_management"`
	SSO                    bool       `yaml:"sso"`
	BackchannelLogoutURI   string     `yaml:"backchannel_logout_uri"`
	DPoP                   DPoPMode   `yaml:"dpop"`

	// Set by NewSnapshot; zero on a client straight from DecodeRealm.
	realm *Realm
}

// DPoPMode is a client's dpop option (FR-44): whether its tokens are bound to
// the key of a DPoP proof.
type DPoPMode string

// The values of the dpop option.
const (
	DPoPOff      DPoPMode = "off"
	DPoPAllowed  DPoPMode = "allowed"
	DPoPRequired DPoPMode = "required"
)

// Providers maps provider keys to their options. Decoding applies the
// defaults of the provider's type.
type Providers map[string]*Provider

// Clients maps client ids to their options.
type Clients map[string]*Client

var (
	_ yaml.Unmarshaler = (*Duration)(nil)
	_ yaml.Unmarshaler = (*Providers)(nil)
	_ yaml.Unmarshaler = (*Client)(nil)
)

package config

import "time"

func defaultServer() ServerFile {
	return ServerFile{
		Listen:            ":8080",
		TLS:               TLSFile{Mode: "none", Listen: ":443", HTTPListen: ":80"},
		Secrets:           ServerSecrets{EncryptionKeyFiles: []string{"secrets/encryption_key"}},
		RequireHTTPS:      true,
		StrictPermissions: true,
		LogLevel:          "info",
		TrustedProxies:    []string{},
		RateLimit:         RateLimit{PerIPPerMinute: 30, Store: "memory"},
		URLs: URLs{
			Issuer: "{prefix}/{realm}",
			Endpoints: Endpoints{
				Authorize:      "{prefix}/{realm}/authorize",
				Token:          "{prefix}/{realm}/token",
				Userinfo:       "{prefix}/{realm}/userinfo",
				JWKS:           "{prefix}/{realm}/jwks.json",
				Logout:         "{prefix}/{realm}/logout",
				Revoke:         "{prefix}/{realm}/revoke",
				Sessions:       "{prefix}/{realm}/sessions",
				Callback:       "{prefix}/{realm}/callback/{provider}",
				AccountDelete:  "{prefix}/{realm}/account",
				Assets:         "{prefix}/{realm}/assets",
				ProviderEvents: "{prefix}/{realm}/events/{provider}",
				DataDeletion:   "{prefix}/{realm}/data-deletion",
			},
		},
		Login:  ServerLogin{ProviderHintParams: []string{"provider"}},
		Logout: ServerLogout{RedirectParams: []string{"post_logout_redirect_uri"}},
	}
}

func defaultDatabase() DatabaseFile {
	return DatabaseFile{
		Driver: "sqlite",
		SQLite: SQLiteConfig{
			Path:            "/var/lib/featherauth/featherauth.db",
			BusyTimeout:     Duration(5 * time.Second),
			JournalMode:     "wal",
			ReadConnections: 4,
		},
		Postgres: PostgresConfig{
			Port:            5432,
			Database:        "featherauth",
			User:            "featherauth",
			SSLMode:         "require",
			MaxOpenConns:    20,
			MaxIdleConns:    5,
			ConnectTimeout:  Duration(5 * time.Second),
			ConnMaxLifetime: Duration(30 * time.Minute),
		},
		Backup: BackupConfig{Directory: "/var/backups/featherauth", At: "03:00", Keep: 7},
	}
}

func defaultRealm() RealmFile {
	return RealmFile{
		Enabled: true,
		Tokens: Tokens{
			AccessTokenLifetime:     Duration(15 * time.Minute),
			RefreshIdleLifetime:     Duration(720 * time.Hour),
			SessionMaxLifetime:      Duration(2160 * time.Hour),
			CodeLifetime:            Duration(60 * time.Second),
			LoginTimeout:            Duration(10 * time.Minute),
			RefreshReuseGrace:       Duration(30 * time.Second),
			RefreshTokenRotation:    true,
			AccountDeleteMaxAuthAge: Duration(10 * time.Minute),
			Algorithm:               "RS256",
			RefreshTokenFormat:      "opaque",
		},
		SSO: SSO{IdleLifetime: Duration(8 * time.Hour), MaxLifetime: Duration(720 * time.Hour)},
		UserData: UserData{
			Attributes:        []string{"email", "name"},
			Claims:            []string{"name", "email", "email_verified", "preferred_username"},
			KeepNameIfMissing: true,
			IDFormat:          IDFormatUUID,
			AutoLinkDomains:   []string{"gmail.com", "googlemail.com", "icloud.com", "me.com", "mac.com"},
		},
		LoginPage: LoginPage{
			AccentColor:      "#2563eb",
			ProviderOrder:    []string{"google", "apple", "github", "facebook"},
			DefaultLocale:    "en",
			SupportedLocales: []string{"en"},
		},
		SecurityHeaders: SecurityHeaders{
			ContentSecurityPolicy: "default-src 'none'; style-src 'self'; img-src 'self' https:; frame-ancestors 'none'; form-action 'self'",
			HSTS:                  "max-age=31536000; includeSubDomains",
		},
	}
}

func defaultClient(id string) Client {
	return Client{
		Name:         id,
		Type:         Public,
		RequirePKCE:  true,
		ResponseMode: "query",
		Audience:     id,
		DPoP:         DPoPOff,
		SSO:          true,
	}
}

// providerTypes are the adapter types of the design.
var providerTypes = map[string]bool{
	"google": true, "apple": true, "github": true, "facebook": true, "oidc": true,
}

// brandNames are the names the vendors write for their built-in providers; the
// button text of those providers uses them unless display_name says otherwise.
var brandNames = map[string]string{"google": "Google", "apple": "Apple", "github": "GitHub", "facebook": "Facebook"}

// defaultDisplayName is the default button text of a provider: the vendor's
// name for a built-in adapter, the key for a generic oidc provider.
func defaultDisplayName(typ, key string) string {
	if n, ok := brandNames[typ]; ok {
		return n
	}
	return key
}

// defaultProvider returns the defaults of a provider of the given type under
// the given key.
func defaultProvider(typ, key string) Provider {
	p := Provider{
		Type:        typ,
		DisplayName: defaultDisplayName(typ, key),
		AutoLink:    true,
		SyncMode:    "import",
		Timeout:     Duration(10 * time.Second),
	}
	switch typ {
	case "google":
		p.Scopes = []string{"openid", "email", "profile"}
		p.TrustEmail = true
	case "oidc":
		p.Scopes = []string{"openid", "email", "profile"}
	case "apple":
		p.ClientSecretLifetime = Duration(5 * time.Minute)
		p.StoreRefreshToken = true
		p.Scopes = []string{"name", "email"}
		p.TrustEmail = true
		p.NotificationAudiences = []string{}
	case "github":
		p.Scopes = []string{"read:user", "user:email"}
		p.PKCE = true
		p.AllowSignup = true
		p.RequireVerifiedEmail = true
		p.TrustEmail = true
	case "facebook":
		p.GraphVersion = "v26.0"
		p.Flow = "oauth"
		p.Scopes = []string{"public_profile", "email"}
		p.Fields = []string{"id", "name", "email"}
	}
	return p
}

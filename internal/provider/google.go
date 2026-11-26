package provider

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/yyudhistira/featherauth/internal/clock"
)

// GoogleIssuer is Google's issuer. It is fixed and not configurable.
const GoogleIssuer = "https://accounts.google.com"

// GoogleRISCConfigurationURL is Google's RISC configuration document, which
// names the issuer and the keys of its security event tokens. It is the default
// of endpoints.risc_configuration.
const GoogleRISCConfigurationURL = "https://accounts.google.com/.well-known/risc-configuration"

// GoogleOptions configures the Google adapter: the generic OpenID Connect
// options, the hosted domain and the RISC configuration. The registry must pass
// GoogleIssuer as the Issuer of the embedded OIDCOptions; tests point it at a
// mock instead.
type GoogleOptions struct {
	OIDCOptions
	// HostedDomain restricts sign-in to one Workspace domain; empty allows any.
	HostedDomain string
	// RISCConfigurationURL is the RISC configuration document; empty means
	// GoogleRISCConfigurationURL.
	RISCConfigurationURL string
}

// Google is the Google adapter: the OpenID Connect adapter with Google's login
// hints and hosted domain, and the receiver of Google's security event tokens
// (Google Cross-Account Protection, FR-48).
type Google struct {
	*OIDC
	risc  *riscConfig
	clock clock.Clock
}

var (
	_ Provider       = (*Google)(nil)
	_ EventReceiver  = (*Google)(nil)
	_ EventAnswerer  = (*Google)(nil)
	_ slog.LogValuer = Google{}
)

// NewGoogle builds the Google adapter on the generic OIDC adapter. It differs
// in the login hints (Google has no forced re-login) and in the hosted domain:
// sent as the hd parameter, which only steers Google's screen, and enforced by
// checking the ID token's hd claim.
func NewGoogle(ctx context.Context, o GoogleOptions) (*Google, error) {
	p, err := NewOIDC(ctx, o.OIDCOptions)
	if err != nil {
		return nil, err
	}
	p.name = "google"
	p.hints = googleHints
	if o.HostedDomain != "" {
		p.extra = url.Values{"hd": {o.HostedDomain}}
		want := o.HostedDomain
		p.check = func(claims map[string]any) error {
			if hd, _ := claims["hd"].(string); !strings.EqualFold(hd, want) {
				return fmt.Errorf("%w: the ID token is not for the hosted domain", ErrRefused)
			}
			return nil
		}
	}
	riscURL := o.RISCConfigurationURL
	if riscURL == "" {
		riscURL = GoogleRISCConfigurationURL
	}
	return &Google{OIDC: p, risc: &riscConfig{url: riscURL, client: p.client}, clock: o.Clock}, nil
}

// EventStatus implements EventAnswerer: a verified security event token is
// answered 202.
func (*Google) EventStatus() int { return http.StatusAccepted }

// googleHints is the Google column of Login hints passed to the provider:
// prompt=login and max_age become select_account, select_account and consent
// pass (both together as "select_account consent"), and login_hint passes.
func googleHints(opts AuthOptions) url.Values {
	v := url.Values{}
	selectAccount := opts.Prompt == "login" || opts.Prompt == "select_account" || opts.MaxAge != nil
	switch {
	case opts.Prompt == "consent" && selectAccount:
		v.Set("prompt", "select_account consent")
	case opts.Prompt == "consent":
		v.Set("prompt", "consent")
	case selectAccount:
		v.Set("prompt", "select_account")
	}
	if opts.LoginHint != "" {
		v.Set("login_hint", opts.LoginHint)
	}
	return v
}

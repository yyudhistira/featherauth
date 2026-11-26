// Package provider holds the types shared by the login providers and the
// code that uses their results. The adapters and the registry come in later
// steps.
package provider

import (
	"context"
	"errors"
	"log/slog"
	"time"
)

// LogValue implements slog.LogValuer. An event's ID is the signed payload when
// it has no jti, so only the type is logged.
func (e Event) LogValue() slog.Value {
	return slog.GroupValue(slog.String("type", e.Type))
}

var _ slog.LogValuer = Event{}

// Identity is a provider account as an adapter normalizes it.
type Identity struct {
	Subject       string
	Email         string
	EmailVerified bool
	Name          string
	// AuthTime is from the provider's ID token when it has one, otherwise zero.
	AuthTime time.Time
	// RefreshToken is Apple only, kept for revocation on account deletion.
	RefreshToken string
}

// LogValue implements slog.LogValuer. Only the subject and flags are logged:
// the email and name are personal data and the refresh token is a secret
// (SEC-13).
func (i Identity) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("subject", i.Subject),
		slog.Bool("email_present", i.Email != ""),
		slog.Bool("email_verified", i.EmailVerified),
		slog.Bool("name_present", i.Name != ""),
		slog.Bool("refresh_present", i.RefreshToken != ""),
	)
}

var _ slog.LogValuer = Identity{}

// Revoker is implemented by adapters that can revoke a stored provider
// refresh token at account deletion (Apple).
type Revoker interface {
	Revoke(ctx context.Context, refreshToken string) error
}

// AuthOptions is what the client asked for; each adapter maps it to its
// provider's parameters (Login hints passed to the provider).
type AuthOptions struct {
	Prompt    string // "login", "select_account", "consent" or empty
	MaxAge    *int
	LoginHint string
}

// Callback holds what the provider sent back to the callback path.
type Callback struct {
	Code    string
	IDToken string // Apple's form POST only; checked against the token endpoint's ID token
	User    string // Apple's form POST only; unsigned JSON, used for the name only
	// Error is the error parameter the provider sent, empty on success; the
	// adapter maps it (Errors during login).
	Error string
}

// LogValue implements slog.LogValuer. The code and ID token are secrets and
// the user JSON holds an email (SEC-13), and the provider's error text is not
// ours to log, so only their presence is logged.
func (c Callback) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Bool("code_present", c.Code != ""),
		slog.Bool("id_token_present", c.IDToken != ""),
		slog.Bool("user_present", c.User != ""),
		slog.Bool("error_present", c.Error != ""),
	)
}

var _ slog.LogValuer = Callback{}

// Provider is one login provider adapter.
type Provider interface {
	Name() string
	AuthURL(state, nonce, pkceChallenge string, opts AuthOptions) string
	Exchange(ctx context.Context, cb Callback, pkceVerifier, nonce string) (Identity, error)
}

// FormPoster is implemented by adapters whose provider returns the login's
// result by a cross-site form POST (Apple). Only such a callback may be
// stored as a handoff (SEC-23).
type FormPoster interface {
	FormPost() bool
}

// EventReceiver is implemented by adapters whose provider sends account
// events (Apple, Meta and Google). ParseEvent verifies a posted body and returns
// its events: one for Apple and Meta, every event of a token for Google.
// ErrInvalidEvent for a body that is not a valid, signed event, and an error
// that wraps ErrUnavailable when the provider's keys cannot be fetched.
type EventReceiver interface {
	ParseEvent(ctx context.Context, body []byte) ([]Event, error)
}

// EventAnswerer is implemented by adapters whose provider wants another status
// than 200 for a verified event (Google's security event tokens get 202).
type EventAnswerer interface {
	EventStatus() int
}

// EventConfirmer is implemented by adapters whose provider wants an answer to
// an event with a confirmation code and the URL of a status page (Meta's
// data-deletion callback). The events endpoint then answers 200 with that
// JSON instead of an empty body.
type EventConfirmer interface {
	ConfirmsEvents() bool
}

// EventSet names the vocabulary of a provider's account events. The adapter sets
// it on each event, and the user manager applies only the actions of that set,
// so a type that one provider sends never acts as another provider's type.
type EventSet string

// The event sets of the adapters.
const (
	EventSetApple  EventSet = "apple"
	EventSetMeta   EventSet = "meta"
	EventSetGoogle EventSet = "google"
)

// Event is a provider account event.
type Event struct {
	// Set is the vocabulary the type comes from (see EventSet).
	Set     EventSet
	Type    string // "consent-revoked", "account-delete", "email-disabled", "email-enabled"
	Subject string // the provider's user id
	// ID is what a repeat of the event carries: the payload's jti, or without
	// one the signed payload itself. The store keeps its SHA-256 (SEC-27).
	ID string
	// Expires is the time until which ID is remembered.
	Expires time.Time
	// State is the state of a verification event (Google), which is logged.
	State string
}

// ErrInvalidEvent is what ParseEvent returns for a body that is not a valid,
// signed event for this provider: the endpoint answers it with 400.
var ErrInvalidEvent = errors.New("provider: invalid event")

// Errors an adapter returns from Exchange; MapError turns them into the
// OAuth error of the redirect to the client.
var (
	// ErrCancelled means the user cancelled or denied access at the provider.
	ErrCancelled = errors.New("provider: the user cancelled")
	// ErrUnavailable means the provider could not be reached, timed out or
	// failed temporarily.
	ErrUnavailable = errors.New("provider: unavailable")
	// ErrRefused means FeatherAuth refuses the identity under a provider rule
	// (hosted_domain, require_verified_email, require_email).
	ErrRefused = errors.New("provider: identity refused")
)

// MapError returns the OAuth error code and description for an error from an
// adapter (Errors during login). Any error that is not one of the sentinels
// is a server_error.
func MapError(err error) (code, description string) {
	switch {
	case errors.Is(err, ErrCancelled):
		return "access_denied", "the user cancelled the login"
	case errors.Is(err, ErrRefused):
		return "access_denied", "the login was refused"
	case errors.Is(err, ErrUnavailable):
		return "temporarily_unavailable", "the provider is unavailable"
	default:
		return "server_error", "the login failed"
	}
}

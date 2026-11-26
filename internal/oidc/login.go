package oidc

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/provider"
	"github.com/yyudhistira/featherauth/internal/secure"
	"github.com/yyudhistira/featherauth/internal/store"
)

// The sizes of the random values of a login: state and nonce are 128 bits
// (SEC-08), the provider's PKCE verifier 256 bits.
const (
	stateBytes    = 16
	nonceBytes    = 16
	verifierBytes = 32
)

// StateCookieName is the name of the state cookie of a login: fa_state_ and the
// first 8 hex characters of SHA-256 of the state, so parallel logins in one
// browser do not overwrite each other (SEC-08).
func StateCookieName(state string) string {
	return "fa_state_" + string(secure.HashOf(state))[:8]
}

// stateCookieSecure says whether the state cookie is Secure: it is when
// public_url is https (SEC-08).
func stateCookieSecure(r *config.Realm) bool { return strings.HasPrefix(r.Issuer(), "https://") }

// loginStarted is what to answer when a login has been started: the cookie to
// set and the provider's URL to redirect to.
type loginStarted struct {
	state    string
	cookie   *http.Cookie
	location string
}

// startLogin stores the login in progress and builds the redirect to the
// provider: the request row with the state as its id, a nonce and a PKCE
// verifier of its own for the provider, the client's values and the resolved
// response mode, expiring after login_timeout. The request's prompt, max_age
// and login_hint go to the adapter, which maps them (Login hints passed to the
// provider).
func (a *Authorize) startLogin(ctx context.Context, req AuthRequest, key config.ProviderKey, p provider.Provider) (loginStarted, error) {
	state, err := secure.Token(a.rand, stateBytes)
	if err != nil {
		return loginStarted{}, err
	}
	nonce, err := secure.Token(a.rand, nonceBytes)
	if err != nil {
		return loginStarted{}, err
	}
	verifier, err := secure.Token(a.rand, verifierBytes)
	if err != nil {
		return loginStarted{}, err
	}
	rid, err := secure.NewID(a.rand, a.clock)
	if err != nil {
		return loginStarted{}, err
	}
	timeout := req.Realm.Tokens.LoginTimeout.Std()
	row := store.AuthRequest{
		ID: store.AuthRequestID(state), ClientID: req.ClientID, RedirectURI: req.RedirectURI,
		ClientState: req.State, Nonce: req.Nonce, ProviderNonce: nonce, CodeChallenge: req.CodeChallenge,
		ResponseMode: string(req.ResponseMode), MaxAge: req.MaxAge, Provider: key,
		ProviderPKCEVerifier: verifier, ExpiresAt: a.clock.Now().Add(timeout),
	}
	err = a.store.Write(ctx, func(tx store.Tx) error {
		realmID, err := tx.Realms().Ensure(ctx, req.Realm.Name, store.RealmID(rid), a.clock.Now())
		if err != nil {
			return err
		}
		row.RealmID = realmID
		return tx.AuthRequests().Create(ctx, row)
	})
	if err != nil {
		return loginStarted{}, fmt.Errorf("storing the login: %w", err)
	}

	opts := provider.AuthOptions{Prompt: req.Prompt, LoginHint: req.LoginHint}
	if req.MaxAge != nil {
		secs := int(*req.MaxAge / time.Second)
		opts.MaxAge = &secs
	}
	sum := sha256.Sum256([]byte(verifier))
	location := p.AuthURL(state, nonce, base64.RawURLEncoding.EncodeToString(sum[:]), opts)

	return loginStarted{
		state: state,
		cookie: &http.Cookie{
			Name:     StateCookieName(state),
			Value:    state,
			Path:     req.Realm.StateCookiePath(),
			MaxAge:   int(timeout / time.Second),
			HttpOnly: true,
			Secure:   stateCookieSecure(req.Realm),
			SameSite: http.SameSiteLaxMode,
		},
		location: location,
	}, nil
}

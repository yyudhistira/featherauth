package oidc

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/secure"
	"github.com/yyudhistira/featherauth/internal/store"
)

// ssoCookiePrefix starts the name of the browser session cookie; the realm name
// follows it (FR-45).
const ssoCookiePrefix = "fa_sso_"

// ssoValueBytes is the size of the random value of a browser session: 256 bits
// (SEC-37).
const ssoValueBytes = 32

// ssoCookieName is the name of the browser session cookie of the realm.
func ssoCookieName(realm *config.Realm) string { return ssoCookiePrefix + string(realm.Name) }

// ssoStart is the browser session that a login starts: the value the cookie
// carries and its hash, the only form the store keeps (SEC-37).
type ssoStart struct {
	value string
	hash  secure.Hash
}

// newSSOStart returns the browser session of a login of client, or nil when the
// login starts none: sso.enabled is false, or the client has sso: false.
func (c *Callback) newSSOStart(realm *config.Realm, client config.ClientID) (*ssoStart, error) {
	cl, ok := realm.Clients[client]
	if !realm.SSO.Enabled || !ok || !cl.SSO {
		return nil, nil
	}
	v, err := secure.Token(c.rand, ssoValueBytes)
	if err != nil {
		return nil, err
	}
	return &ssoStart{value: v, hash: secure.HashOf(v)}, nil
}

// ssoExpiry is when a browser session last used at now expires: the earlier of
// now plus the idle lifetime and created plus the maximum lifetime (FR-45).
func ssoExpiry(s config.SSO, created, now time.Time) time.Time {
	exp := now.Add(s.IdleLifetime.Std())
	if limit := created.Add(s.MaxLifetime.Std()); limit.Before(exp) {
		return limit
	}
	return exp
}

// ssoCookie is the browser session cookie of a login: HttpOnly, Secure as the
// state cookie is, SameSite=Lax, Max-Age the idle lifetime and the path of the
// realm's SSO cookie path (FR-45, SEC-37).
func ssoCookie(realm *config.Realm, value string) *http.Cookie {
	return &http.Cookie{
		Name: ssoCookieName(realm), Value: value, Path: realm.SSOCookiePath(),
		MaxAge:   int(realm.SSO.IdleLifetime.Std() / time.Second),
		HttpOnly: true, Secure: stateCookieSecure(realm), SameSite: http.SameSiteLaxMode,
	}
}

// ssoValueOf returns the value of the browser session cookie of the realm in the
// request, or "" when the request carries none.
func ssoValueOf(r *http.Request, realm *config.Realm) string {
	if ck, err := r.Cookie(ssoCookieName(realm)); err == nil {
		return ck.Value
	}
	return ""
}

// errSSOUserMismatch means the identity of the login belongs to another user than
// the code was issued for; no browser session is made for it.
var errSSOUserMismatch = errors.New("oidc: the login's identity belongs to another user")

// storeSession stores the browser session of a login, made with the identity
// the login used, and deletes the browser session of the request's cookie (prev,
// when not empty): a new login replaces the browser's earlier session. The
// identity must belong to uid, the user the code was issued for.
func (c *Callback) storeSession(ctx context.Context, realm *config.Realm, s *ssoStart, prev string, key config.ProviderKey, sub string, uid store.UserID, authTime time.Time) error {
	now := c.clock.Now()
	return c.store.Write(ctx, func(tx store.Tx) error {
		rid, err := tx.Realms().Find(ctx, realm.Name)
		if err != nil {
			return err
		}
		ident, err := tx.Identities().Find(ctx, rid, key, sub)
		if err != nil {
			return err
		}
		if ident.UserID != uid {
			return errSSOUserMismatch
		}
		if prev != "" {
			if err := tx.SSOSessions().Delete(ctx, rid, secure.HashOf(prev)); err != nil {
				return err
			}
		}
		return tx.SSOSessions().Create(ctx, store.SSOSession{
			IDHash: s.hash, RealmID: rid, UserID: uid, IdentityID: ident.ID, Provider: key,
			AuthTime: authTime, CreatedAt: now, LastUsedAt: now, ExpiresAt: ssoExpiry(realm.SSO, now, now),
		})
	})
}

// deletedSSOCookie ends the browser session cookie of the realm: the same name and
// path and the same attributes, with no value and an end of life now. The cookie
// is cleared when a logout ends the browser session, and when a request names no
// usable session (FR-45).
func deletedSSOCookie(realm *config.Realm) *http.Cookie {
	return &http.Cookie{
		Name: ssoCookieName(realm), Path: realm.SSOCookiePath(), MaxAge: -1,
		HttpOnly: true, Secure: stateCookieSecure(realm), SameSite: http.SameSiteLaxMode,
	}
}

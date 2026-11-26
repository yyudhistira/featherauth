package token

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/secure"
	"github.com/yyudhistira/featherauth/internal/store"
)

// CodeInvalidGrant is the OAuth error code of a code or refresh token that is
// not accepted. CodeInvalidRequest is declared with client authentication.
const CodeInvalidGrant = "invalid_grant"

// GrantError is a request the token endpoint refuses with an OAuth error
// code. Failures of the store are returned as they are (wrapped), so the
// caller can answer 503 for store.ErrUnavailable. Reuse is set when the
// refusal is of a reused token that revoked its session.
type GrantError struct {
	Code        string
	Description string
	Reuse       *Reuse
}

// Error implements error.
func (e *GrantError) Error() string { return "token: " + e.Code + ": " + e.Description }

var _ error = (*GrantError)(nil)

func grantErr(code, desc string) *GrantError { return &GrantError{Code: code, Description: desc} }

const (
	codeBytes    = 32
	refreshBytes = 32
	jtiLen       = 16
	verifierMin  = 43
	verifierMax  = 128
)

// Grant is the result of a successful token request.
type Grant struct {
	AccessToken      string
	IDToken          string
	RefreshToken     string
	ExpiresIn        int
	RefreshExpiresIn int
	Scope            string
	// TokenType is "DPoP" for an answer bound to a key and "Bearer" otherwise;
	// empty means Bearer.
	TokenType string
}

// LogValue implements slog.LogValuer. No token is logged (SEC-13).
func (g Grant) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Int("expires_in", g.ExpiresIn),
		slog.Int("refresh_expires_in", g.RefreshExpiresIn),
		slog.String("scope", g.Scope),
	)
}

var _ slog.LogValuer = Grant{}

// IssueInput is what a login code is issued for. AuthTime is when the user
// authenticated with the provider.
type IssueInput struct {
	Realm         *config.Realm
	Client        *config.Client
	User          UserID
	RedirectURI   string
	CodeChallenge string
	Nonce         string
	AuthTime      time.Time
	// Login is the login in progress that the code completes (its auth
	// request id). Issue deletes that row in the transaction that creates the
	// code, so a login completes once (SEC-28). Empty means no login row.
	Login store.AuthRequestID
	// SSOIDHash is the hash of the browser session the login started (FR-45),
	// carried to the token session; empty when it started none.
	SSOIDHash secure.Hash
}

// ErrLoginGone is returned by Issue when the login it completes has no row any
// more: another callback completed it first, or the hourly job removed it after
// it expired. No code is issued then.
var ErrLoginGone = errors.New("token: the login is no longer in progress")

// ExchangeInput is a code grant request after client authentication.
type ExchangeInput struct {
	Realm       *config.Realm
	Client      *config.Client
	Code        string
	RedirectURI string
	Verifier    string
	// DPoP is the DPoP header of the request (FR-44); no header means no proof.
	DPoP DPoPRequest
}

// Codes issues login codes and exchanges them for tokens. It is safe for
// concurrent use.
type Codes struct {
	store store.Store
	clock clock.Clock
	src   secure.Source
	minter
}

// NewCodes returns a Codes that keeps its rows in st, signs with issuer, reads
// time from c and random values from src.
func NewCodes(st store.Store, issuer *Issuer, c clock.Clock, src secure.Source) *Codes {
	return &Codes{store: st, clock: c, src: src, minter: minter{issuer, c, src}}
}

// ensureRealm finds the store id of r, creating the realm row when it has none.
func ensureRealm(ctx context.Context, tx store.Tx, src secure.Source, c clock.Clock, r *config.Realm) (store.RealmID, error) {
	id, err := secure.NewID(src, c)
	if err != nil {
		return "", err
	}
	return tx.Realms().Ensure(ctx, r.Name, store.RealmID(id), c.Now())
}

// Issue stores a login code for a new session and returns the code. Only its
// hash is stored. When in.Login is set, the login's row is deleted in the same
// transaction; if it is not there, Issue returns ErrLoginGone and stores no code.
func (c *Codes) Issue(ctx context.Context, in IssueInput) (string, error) {
	cid, err := clientID(in.Realm, in.Client)
	if err != nil {
		return "", err
	}
	code, err := secure.Token(c.src, codeBytes)
	if err != nil {
		return "", err
	}
	sid, err := secure.NewID(c.src, c.clock)
	if err != nil {
		return "", err
	}
	now := c.clock.Now()
	err = c.store.Write(ctx, func(tx store.Tx) error {
		rid, err := ensureRealm(ctx, tx, c.src, c.clock, in.Realm)
		if err != nil {
			return err
		}
		if in.Login != "" {
			err := tx.AuthRequests().Delete(ctx, in.Login)
			if errors.Is(err, store.ErrNotFound) {
				return ErrLoginGone
			}
			if err != nil {
				return err
			}
		}
		return tx.AuthCodes().Create(ctx, store.AuthCode{
			CodeHash: secure.HashOf(code), RealmID: rid, UserID: store.UserID(in.User),
			SessionID: store.SessionID(sid), SessionStartedAt: now, ClientID: cid,
			RedirectURI: in.RedirectURI, CodeChallenge: in.CodeChallenge, Nonce: in.Nonce,
			AuthTime: in.AuthTime, ExpiresAt: now.Add(in.Realm.Tokens.CodeLifetime.Std()),
			SSOIDHash: in.SSOIDHash,
		})
	})
	if errors.Is(err, ErrLoginGone) {
		return "", ErrLoginGone
	}
	if err != nil {
		return "", fmt.Errorf("token: issue code: %w", err)
	}
	return code, nil
}

// Exchange checks a login code and returns the tokens of its session. A code
// is used up by the first request that names it, whether or not that request
// passes the other checks; a second use also revokes the session.
func (c *Codes) Exchange(ctx context.Context, in ExchangeInput) (*Grant, error) {
	if in.Verifier != "" && !validVerifier(in.Verifier) {
		return nil, grantErr(CodeInvalidRequest, "code_verifier must be 43 to 128 characters of A-Z a-z 0-9 - . _ ~")
	}
	if !in.Realm.Enabled {
		return nil, grantErr(CodeInvalidGrant, "invalid code")
	}
	cid, err := clientID(in.Realm, in.Client)
	if err != nil {
		return nil, grantErr(CodeInvalidGrant, "invalid code")
	}

	var grant *Grant
	var refused *GrantError
	err = c.store.Write(ctx, func(tx store.Tx) error {
		// The store runs this again after a deadlock, so a run starts with no
		// result of an earlier one.
		grant, refused = nil, nil
		// A realm with no row has issued no code: refuse without writing.
		rid, err := tx.Realms().Find(ctx, in.Realm.Name)
		if errors.Is(err, store.ErrNotFound) {
			refused = grantErr(CodeInvalidGrant, "invalid code")
			return nil
		}
		if err != nil {
			return err
		}
		now := c.clock.Now()
		ac, err := tx.AuthCodes().Consume(ctx, secure.HashOf(in.Code), now)
		var used *store.UsedError
		switch {
		case errors.As(err, &used):
			// The revocation is committed, so the refusal is recorded, and the
			// refusal names the reuse for the caller.
			ended, err := tx.RefreshTokens().RevokeSession(ctx, rid, used.SessionID, now)
			if err != nil {
				return err
			}
			if err := store.QueueLogouts(ctx, tx, in.Realm, rid, ended.Sessions, c.clock, c.src); err != nil {
				return err
			}
			refused = grantErr(CodeInvalidGrant, "invalid code")
			refused.Reuse = &Reuse{
				Realm: rid, User: UserID(used.UserID), Client: used.ClientID,
				Session: SessionID(used.SessionID), Kind: ReuseCode, Ended: ended.Tokens > 0,
			}
			return nil
		case errors.Is(err, store.ErrNotFound), errors.Is(err, store.ErrExpired):
			refused = grantErr(CodeInvalidGrant, "invalid code")
			return nil
		case err != nil:
			return err
		}
		if ac.RealmID != rid || ac.ClientID != cid ||
			!secure.Equal(ac.RedirectURI, in.RedirectURI) || !pkceOK(ac.CodeChallenge, in.Verifier) {
			refused = grantErr(CodeInvalidGrant, "invalid code")
			return nil
		}
		u, err := tx.Users().Get(ctx, rid, ac.UserID)
		if errors.Is(err, store.ErrNotFound) || (err == nil && !u.DisabledAt.IsZero()) {
			refused = grantErr(CodeInvalidGrant, "invalid code")
			return nil
		}
		if err != nil {
			return err
		}
		sub := Subject{ID: UserID(u.ID), Email: u.Email, EmailVerified: u.EmailVerified, Name: u.Name}
		sess := Session{
			ID: SessionID(ac.SessionID), StartedAt: ac.SessionStartedAt,
			AuthTime: ac.AuthTime, Nonce: ac.Nonce, SSOIDHash: ac.SSOIDHash,
		}
		b, err := bindNew(ctx, tx, in.Client, in.DPoP, now)
		if err != nil {
			return err
		}
		sess.Jkt = b.access
		grant, err = c.minter.grant(ctx, tx, rid, in.Realm, in.Client, sub, sess, b.refresh)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("token: exchange code: %w", err)
	}
	if refused != nil {
		return nil, refused
	}
	return grant, nil
}

// minter signs the tokens of a session and makes its refresh tokens; the code
// grant and the refresh grant share it.
type minter struct {
	issuer *Issuer
	clock  clock.Clock
	src    secure.Source
}

// signed holds the signed tokens of one grant.
type signed struct {
	access, id string
	expiresIn  int
}

// sign signs an access token and an ID token for the session.
func (m minter) sign(r *config.Realm, cl *config.Client, sub Subject, sess Session) (signed, error) {
	access, exp, err := m.issuer.Access(r, cl, sub, sess)
	if err != nil {
		return signed{}, err
	}
	idTok, err := m.issuer.ID(r, cl, sub, sess, access)
	if err != nil {
		return signed{}, err
	}
	return signed{access, idTok, int(exp.Sub(m.clock.Now()) / time.Second)}, nil
}

// newRefresh makes a refresh token of the session and its row.
func (m minter) newRefresh(rid store.RealmID, r *config.Realm, cl *config.Client, sub Subject, sess Session, refreshJKT string) (string, store.RefreshToken, error) {
	now := m.clock.Now()
	cid, err := clientID(r, cl)
	if err != nil {
		return "", store.RefreshToken{}, err
	}
	exp := refreshExpiry(cl.Lifetimes(), now, sess.StartedAt)
	if !exp.After(now) {
		return "", store.RefreshToken{}, grantErr(CodeInvalidGrant, "session expired")
	}
	raw, err := m.newRefreshToken(r, cl, sub, sess, exp)
	if err != nil {
		return "", store.RefreshToken{}, err
	}
	rowID, err := secure.NewID(m.src, m.clock)
	if err != nil {
		return "", store.RefreshToken{}, err
	}
	return raw, store.RefreshToken{
		ID: store.RefreshTokenID(rowID), RealmID: rid, UserID: store.UserID(sub.ID), ClientID: cid,
		TokenHash: secure.HashOf(raw), SessionID: store.SessionID(sess.ID),
		SessionStartedAt: sess.StartedAt, AuthTime: sess.AuthTime, Nonce: sess.Nonce,
		ExpiresAt: exp, CreatedAt: now, DPoPJKT: refreshJKT, SSOIDHash: sess.SSOIDHash,
	}, nil
}

// grant signs the tokens of a session and stores a new refresh token.
func (m minter) grant(ctx context.Context, tx store.Tx, rid store.RealmID, r *config.Realm, cl *config.Client, sub Subject, sess Session, refreshJKT string) (*Grant, error) {
	tk, err := m.sign(r, cl, sub, sess)
	if err != nil {
		return nil, err
	}
	raw, row, err := m.newRefresh(rid, r, cl, sub, sess, refreshJKT)
	if err != nil {
		return nil, err
	}
	if err := tx.RefreshTokens().Insert(ctx, row); err != nil {
		return nil, err
	}
	return m.result(tk, raw, row.ExpiresAt, sess.Jkt != ""), nil
}

func (m minter) result(tk signed, refresh string, refreshExp time.Time, dpop bool) *Grant {
	g := &Grant{
		AccessToken: tk.access, IDToken: tk.id, RefreshToken: refresh, ExpiresIn: tk.expiresIn,
		RefreshExpiresIn: int(refreshExp.Sub(m.clock.Now()) / time.Second), Scope: "openid", TokenType: "Bearer",
	}
	if dpop {
		g.TokenType = "DPoP"
	}
	return g
}

// newRefreshToken makes the value handed to the client, in the realm's
// refresh_token_format: the random secret itself, or a JWT.
func (m minter) newRefreshToken(r *config.Realm, cl *config.Client, sub Subject, sess Session, exp time.Time) (string, error) {
	if r.Tokens.RefreshTokenFormat == "jwt" {
		jti, err := secure.Token(m.src, jtiLen)
		if err != nil {
			return "", err
		}
		return m.issuer.RefreshJWT(r, cl, sub, sess, exp, jti)
	}
	return secure.Token(m.src, refreshBytes)
}

// refreshExpiry is the earlier of now plus the idle lifetime and the session
// start plus the maximum lifetime; a maximum of 0 means no cap.
func refreshExpiry(l config.Lifetimes, now, started time.Time) time.Time {
	exp := now.Add(l.RefreshIdle)
	if l.SessionMax > 0 {
		if limit := started.Add(l.SessionMax); limit.Before(exp) {
			return limit
		}
	}
	return exp
}

// validVerifier reports whether v is 43 to 128 characters of the PKCE
// unreserved set (RFC 7636 section 4.1).
func validVerifier(v string) bool {
	if len(v) < verifierMin || len(v) > verifierMax {
		return false
	}
	for i := 0; i < len(v); i++ {
		b := v[i]
		switch {
		case b >= 'A' && b <= 'Z', b >= 'a' && b <= 'z', b >= '0' && b <= '9',
			b == '-', b == '.', b == '_', b == '~':
		default:
			return false
		}
	}
	return true
}

// pkceOK checks the verifier against the stored S256 challenge. A code issued
// without a challenge accepts no verifier (RFC 9700 section 2.1.1), and a
// code with one requires it.
func pkceOK(challenge, verifier string) bool {
	if challenge == "" {
		return verifier == ""
	}
	if verifier == "" {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	return secure.Equal(base64.RawURLEncoding.EncodeToString(sum[:]), challenge)
}

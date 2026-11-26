// Package store holds the repository interfaces and the SQLite and Postgres
// implementations. All access to the database goes through Store.
package store

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/secure"
)

// Open opens the database that cfg names, with the implementation of its
// driver, and applies the migrations. secrets are the secrets of the same
// database.yaml (config.ReadDatabaseSecrets); sqlite takes none, so its callers
// pass the zero value.
func Open(ctx context.Context, cfg config.DatabaseFile, secrets config.DatabaseSecrets) (Store, error) {
	switch cfg.Driver {
	case "sqlite":
		return openSQLite(ctx, cfg)
	case "postgres":
		return openPostgres(ctx, cfg.Postgres, secrets)
	default:
		return nil, fmt.Errorf("unknown database driver %q", cfg.Driver)
	}
}

// Errors every implementation returns, to be tested with errors.Is.
var (
	ErrNotFound = errors.New("store: not found")
	ErrConflict = errors.New("store: conflict")
	ErrUsed     = errors.New("store: already used")
	ErrExpired  = errors.New("store: expired")
	// ErrUnavailable is transient (for example the database is busy) and is
	// answered with 503.
	ErrUnavailable = errors.New("store: temporarily unavailable")
)

// Store runs transactions on the database. Read uses the read connections;
// Write uses the one write connection, so writers queue in the service.
type Store interface {
	Read(ctx context.Context, fn func(Tx) error) error
	Write(ctx context.Context, fn func(Tx) error) error
	Ping(ctx context.Context) error
	// Backup writes a consistent snapshot to path, which must not exist. Only
	// SQLite has one; Postgres returns an error that names pg_dump.
	Backup(ctx context.Context, path string) error
	Close() error
}

// Tx gives the repositories of one transaction. The repository interfaces below
// get their methods in the steps that implement them.
type Tx interface {
	Realms() Realms
	Users() Users
	Identities() Identities
	AuthRequests() AuthRequests
	AuthCodes() AuthCodes
	Handoffs() Handoffs
	ProviderEvents() ProviderEvents
	RefreshTokens() RefreshTokens
	LogoutNotifications() LogoutNotifications
	DPoPProofs() DPoPProofs
	RateLimits() RateLimits
	SSOSessions() SSOSessions
	Audit() Audit
}

// EndedSession is a session that a revoking call ended: it had at least one
// refresh token that the call revoked or deleted.
type EndedSession struct {
	SessionID SessionID
	ClientID  config.ClientID
	UserID    UserID
	// SSOIDHash is the hash of the browser session the session came from (FR-45),
	// empty when it came from none; the revoking helper ends that browser session.
	SSOIDHash secure.Hash
}

// Ended is what a revoking call ended: Tokens counts the refresh tokens it
// revoked or deleted, and Sessions lists each session that had one of them.
type Ended struct {
	Tokens   int64
	Sessions []EndedSession
}

// LogoutNotificationID is the id of a row of logout_notifications.
type LogoutNotificationID string

// LogoutNotification is a back-channel logout token still to be sent: to
// ClientID, for the session SessionID of UserID. Attempts counts the tries made.
type LogoutNotification struct {
	ID            LogoutNotificationID
	RealmID       RealmID
	ClientID      config.ClientID
	UserID        UserID
	SessionID     SessionID
	Attempts      int
	NextAttemptAt time.Time
	CreatedAt     time.Time
}

// LogoutNotifications holds the back-channel logout notifications (FR-43).
type LogoutNotifications interface {
	// Enqueue returns ErrConflict when the id exists.
	Enqueue(ctx context.Context, n LogoutNotification) error
	// Claim returns up to limit rows due at now (NextAttemptAt not after now),
	// oldest first. Each row is returned with the Attempts and NextAttemptAt it
	// had before the claim; the claim adds one to Attempts and moves
	// NextAttemptAt to the next try (1, 5, 30 and 120 minutes after the first
	// four tries, and at once after the fifth).
	Claim(ctx context.Context, now time.Time, limit int) ([]LogoutNotification, error)
	// Done deletes a row once its logout token was delivered. Drop deletes a
	// row that is not sent. A missing id is not an error for either.
	Done(ctx context.Context, id LogoutNotificationID) error
	Drop(ctx context.Context, id LogoutNotificationID) error
}

// RateLimits holds the windows of the shared rate limit (FR-53): one row for
// each client key and minute of the service clock.
type RateLimits interface {
	// Hit counts one request for key in window (a minute of the service clock)
	// and returns the count of that window, the request included.
	Hit(ctx context.Context, key string, window time.Time) (int64, error)
	// DeleteBefore removes the windows that start before window and returns how
	// many it removed.
	DeleteBefore(ctx context.Context, window time.Time) (int64, error)
}

// DPoPProofs holds the DPoP proofs already used (SEC-36): the hash of the key
// thumbprint and the jti of each proof that passed, remembered until the hourly
// job deletes it after its expiry.
type DPoPProofs interface {
	// Use remembers proofHash until expiresAt and reports whether it was new;
	// false is a repeat, not an error.
	Use(ctx context.Context, proofHash secure.Hash, expiresAt time.Time) (bool, error)
	// DeleteExpired removes the proofs strictly past their expiry at now and
	// returns how many it removed.
	DeleteExpired(ctx context.Context, now time.Time) (int64, error)
}

// AuditEvent is a row of the audit_events table. Actor is "admin", "system"
// or "provider:<name>". An empty UserID is stored as NULL and nil Details as an
// empty JSON object. Details never hold secrets or emails; the caller sees to
// that. CreatedAt is kept as UTC Unix seconds.
type AuditEvent struct {
	ID        string
	RealmID   RealmID
	Actor     string
	Action    string
	UserID    UserID
	Details   map[string]any
	CreatedAt time.Time
}

// Audit holds the audit log. Rows are kept and never pruned.
type Audit interface {
	// Insert returns ErrConflict when the id exists.
	Insert(ctx context.Context, e AuditEvent) error
	// List returns the realm's events created at or after since, oldest
	// first (ties by id).
	List(ctx context.Context, realm RealmID, since time.Time) ([]AuditEvent, error)
}

// Distinct id types, so arguments cannot be swapped silently.
type (
	RealmID    string
	UserID     string
	IdentityID string
	SessionID  string
)

// AuthRequestID is the id of an authorization request; it is also the state
// sent to the provider, so it is a secret.
type AuthRequestID string

// Realms holds the realm rows. A realm's settings stay in files.
type Realms interface {
	// Ensure returns the id of the realm called name. When the realm has no
	// row yet it is created with id and createdAt; otherwise the existing id
	// is returned and id is ignored.
	Ensure(ctx context.Context, name config.RealmName, id RealmID, createdAt time.Time) (RealmID, error)
	// Find returns the id of the realm called name, or ErrNotFound when it has
	// no row. It never creates one.
	Find(ctx context.Context, name config.RealmName) (RealmID, error)
}

// User is a row of the users table. An empty Email, EmailKey or Name and a
// zero DisabledAt are stored as NULL. EmailKey is the trimmed, lowercased
// Email, set by the caller. Times are kept as UTC Unix seconds.
type User struct {
	ID            UserID
	RealmID       RealmID
	Email         string
	EmailKey      string
	EmailVerified bool
	Name          string
	DisabledAt    time.Time
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// Users holds the users of every realm; each method is scoped to one realm.
type Users interface {
	// Create returns ErrConflict when the id exists or another user of the
	// realm already holds the same verified email_key.
	Create(ctx context.Context, u User) error
	// Get returns ErrNotFound when the realm has no such user.
	Get(ctx context.Context, realm RealmID, id UserID) (User, error)
	// Update replaces every column but id, realm and created_at. It returns
	// ErrNotFound for an unknown user and ErrConflict like Create.
	Update(ctx context.Context, u User) error
	// Delete removes the user and, by cascade, its identities.
	Delete(ctx context.Context, realm RealmID, id UserID) error
	// FindVerifiedByEmailKey returns the one user with that verified
	// email_key, or ErrNotFound.
	FindVerifiedByEmailKey(ctx context.Context, realm RealmID, key string) (User, error)
	// ListByEmailKey returns every user, verified or not, with that
	// email_key, oldest first.
	ListByEmailKey(ctx context.Context, realm RealmID, key string) ([]User, error)
}

// Identity is a row of the identities table. An empty ProviderRefreshTokenEnc
// is stored as NULL; otherwise it is the sealed token and never logged.
type Identity struct {
	ID                      IdentityID
	RealmID                 RealmID
	UserID                  UserID
	Provider                config.ProviderKey
	ProviderSub             string
	Email                   string
	EmailVerified           bool
	ProviderRefreshTokenEnc string
	CreatedAt               time.Time
}

// SealedIdentity is an identity with a stored provider token, as the key
// commands list it. Value is the sealed token: it is never logged, so the type
// implements slog.LogValuer and leaves it out.
type SealedIdentity struct {
	ID       IdentityID
	RealmID  RealmID
	UserID   UserID
	Provider config.ProviderKey
	Subject  string
	Value    string
}

// LogValue implements slog.LogValuer: the ids and the provider, never the
// stored value or the subject.
func (s SealedIdentity) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("identity_id", string(s.ID)),
		slog.String("user_id", string(s.UserID)),
		slog.String("provider", string(s.Provider)),
	)
}

var _ slog.LogValuer = SealedIdentity{}

// Identities holds the provider identities; each method is scoped to one realm.
type Identities interface {
	// Find returns ErrNotFound when no identity has that provider and subject.
	Find(ctx context.Context, realm RealmID, provider config.ProviderKey, sub string) (Identity, error)
	// Create returns ErrConflict when the id or (realm, provider, sub) exists.
	Create(ctx context.Context, i Identity) error
	// Update replaces email and email_verified; ErrNotFound for an unknown id.
	Update(ctx context.Context, i Identity) error
	// ListByUser returns the identities of one user, oldest first.
	ListByUser(ctx context.Context, realm RealmID, user UserID) ([]Identity, error)
	Delete(ctx context.Context, realm RealmID, id IdentityID) error
	// SetProviderToken stores the sealed provider refresh token; an empty
	// string clears it.
	SetProviderToken(ctx context.Context, realm RealmID, id IdentityID, sealed string) error
	// SealedBy returns the identities of the realm whose stored token starts
	// with keyID and a dot, ordered by user id, provider and subject (by
	// bytes). It scans the realm's identities; no index serves it.
	SealedBy(ctx context.Context, realm RealmID, keyID string) ([]SealedIdentity, error)
	// ReplaceProviderToken sets the stored token to next (empty clears it) only
	// when it is still old, and reports whether it did. An identity that is
	// gone, or has another token, or none, is not an error: it reports false.
	ReplaceProviderToken(ctx context.Context, realm RealmID, id IdentityID, old, next string) (bool, error)
}

// UsedError is the error of AuthCodes.Consume for a code that was already
// used. It matches ErrUsed with errors.Is and carries the session created from
// the code, which the caller revokes, and the user and the client the code was
// issued to, so the caller can record the reuse.
type UsedError struct {
	SessionID SessionID
	UserID    UserID
	ClientID  config.ClientID
}

func (e *UsedError) Error() string { return ErrUsed.Error() }

// Is reports whether target is ErrUsed.
func (e *UsedError) Is(target error) bool { return target == ErrUsed }

// AuthRequest is a row of the auth_requests table: a login in progress. An
// empty ClientState, Nonce or CodeChallenge means the client sent none; a nil
// MaxAge means no max_age. Times are kept as UTC Unix seconds, MaxAge as whole
// seconds.
type AuthRequest struct {
	ID            AuthRequestID
	RealmID       RealmID
	ClientID      config.ClientID
	RedirectURI   string
	ClientState   string
	Nonce         string
	ProviderNonce string
	CodeChallenge string
	ResponseMode  string
	MaxAge        *time.Duration
	Provider      config.ProviderKey
	// ProviderPKCEVerifier is the PKCE verifier sent to the provider.
	ProviderPKCEVerifier string
	ExpiresAt            time.Time
}

// AuthRequests holds the logins in progress. Get does not check ExpiresAt and
// does not scope by realm; the caller checks both.
type AuthRequests interface {
	// Create returns ErrConflict when the id exists.
	Create(ctx context.Context, r AuthRequest) error
	// Get returns ErrNotFound for an unknown id.
	Get(ctx context.Context, id AuthRequestID) (AuthRequest, error)
	// Delete removes the row. It returns ErrNotFound when it removed none
	// (an unknown id, or one already deleted), so a caller can tell a login it
	// took from one another transaction already took.
	Delete(ctx context.Context, id AuthRequestID) error
	// DeleteExpired removes every row whose ExpiresAt is at or before now and
	// returns how many it removed.
	DeleteExpired(ctx context.Context, now time.Time) (int64, error)
}

// AuthCode is a row of the auth_codes table, keyed by the hash of the code.
// An empty CodeChallenge or Nonce means none; a zero UsedAt means unused.
type AuthCode struct {
	CodeHash         secure.Hash
	RealmID          RealmID
	UserID           UserID
	SessionID        SessionID
	SessionStartedAt time.Time
	ClientID         config.ClientID
	RedirectURI      string
	CodeChallenge    string
	Nonce            string
	AuthTime         time.Time
	ExpiresAt        time.Time
	UsedAt           time.Time
	// SSOIDHash is the hash of the browser session the login started (FR-45),
	// carried to the token session; empty when the login started none.
	SSOIDHash secure.Hash
}

// AuthCodes holds the login codes. Consume must run in a write transaction.
type AuthCodes interface {
	// Create returns ErrConflict when the hash exists.
	Create(ctx context.Context, c AuthCode) error
	// Consume checks the code and marks it used at now in one step. It returns
	// the code with UsedAt set; a *UsedError (matching ErrUsed) for a code that
	// was used before, even if it has expired since; ErrExpired when now is at
	// or after ExpiresAt (the code stays unused); and ErrNotFound for an
	// unknown hash.
	Consume(ctx context.Context, hash secure.Hash, now time.Time) (AuthCode, error)
	// DeleteExpired removes every row whose ExpiresAt is at or before now,
	// used or not, and returns how many it removed.
	DeleteExpired(ctx context.Context, now time.Time) (int64, error)
}

// Handoff is a row of the callback_handoffs table, keyed by the hash of the id.
type Handoff struct {
	IDHash        secure.Hash
	AuthRequestID AuthRequestID
	Payload       string
	ExpiresAt     time.Time
}

// Handoffs holds the one-time handoffs of a callback to the browser.
type Handoffs interface {
	// Create returns ErrConflict when the hash exists.
	Create(ctx context.Context, h Handoff) error
	// Take returns and deletes the handoff. An unknown or already taken id is
	// ErrNotFound; when now is at or after ExpiresAt it is ErrExpired and the
	// row stays for the hourly job.
	Take(ctx context.Context, hash secure.Hash, now time.Time) (Handoff, error)
	// DeleteExpired removes every row whose ExpiresAt is at or before now and
	// returns how many it removed.
	DeleteExpired(ctx context.Context, now time.Time) (int64, error)
}

// ProviderEvents holds the provider events already acted on (SEC-27). Each
// method is scoped by realm and provider where it takes them.
type ProviderEvents interface {
	// Remember records idHash, the hash of an event id, until expiresAt. It
	// reports whether the id was new: false means the event was acted on
	// before, and the caller skips its action. Remember does not look at
	// expiresAt; DeleteExpired removes an expired row.
	Remember(ctx context.Context, realm RealmID, provider config.ProviderKey, idHash secure.Hash, expiresAt time.Time) (bool, error)
	// DeleteExpired removes every row whose ExpiresAt is strictly before now, in
	// every realm, and returns how many. A row at exactly ExpiresAt stays.
	DeleteExpired(ctx context.Context, now time.Time) (int64, error)
}

// SSOSession is a row of the sso_sessions table: a browser session of single
// sign-on (FR-45). IDHash is the SHA-256 of the cookie value, which is never
// stored. Times are kept as UTC Unix seconds.
type SSOSession struct {
	IDHash     secure.Hash
	RealmID    RealmID
	UserID     UserID
	IdentityID IdentityID
	Provider   config.ProviderKey
	AuthTime   time.Time
	CreatedAt  time.Time
	LastUsedAt time.Time
	ExpiresAt  time.Time
}

// SSOSessions holds the browser sessions of single sign-on (FR-45, SEC-37). Each
// method is scoped to one realm.
type SSOSessions interface {
	// Create returns ErrConflict when the hash exists.
	Create(ctx context.Context, s SSOSession) error
	// Find returns the row of the realm with that hash whatever its expiry (the
	// caller checks the expiry). ErrNotFound when the realm has no such row.
	Find(ctx context.Context, realm RealmID, idHash secure.Hash) (SSOSession, error)
	// Touch sets the last use and the expiry of the row. ErrNotFound when the
	// realm has no such row.
	Touch(ctx context.Context, realm RealmID, idHash secure.Hash, usedAt, expiresAt time.Time) error
	// Delete removes the row. A missing row is not an error.
	Delete(ctx context.Context, realm RealmID, idHash secure.Hash) error
	// DeleteByUser removes the rows of the user, DeleteByIdentity the rows made
	// with the identity and DeleteByRealm every row of the realm. None is an error
	// when no row matches.
	DeleteByUser(ctx context.Context, realm RealmID, user UserID) error
	DeleteByIdentity(ctx context.Context, realm RealmID, identity IdentityID) error
	DeleteByRealm(ctx context.Context, realm RealmID) error
	// DeleteExpired removes every row whose ExpiresAt is at or before now, in every
	// realm, and returns how many.
	DeleteExpired(ctx context.Context, now time.Time) (int64, error)
}

// RefreshTokenID is the id of a refresh token row. It is not the token.
type RefreshTokenID string

// RefreshToken is a row of the refresh_tokens table, keyed by the hash of the
// token (for the jwt format, of the whole JWT string). An empty Nonce or
// ReplacedBy and a zero RevokedAt are stored as NULL.
type RefreshToken struct {
	ID               RefreshTokenID
	RealmID          RealmID
	UserID           UserID
	ClientID         config.ClientID
	TokenHash        secure.Hash
	SessionID        SessionID
	SessionStartedAt time.Time
	AuthTime         time.Time
	Nonce            string
	// DPoPJKT is the JWK thumbprint of the key the session is bound to (FR-44);
	// empty when the token is not bound.
	DPoPJKT string
	// SSOIDHash is the hash of the browser session the token's session came
	// from (FR-45); empty when it came from none.
	SSOIDHash secure.Hash
	// ReplacedBy is the id of the successor made when this token was rotated.
	ReplacedBy RefreshTokenID
	ExpiresAt  time.Time
	RevokedAt  time.Time
	CreatedAt  time.Time
}

// LiveSession describes a session that has an active refresh token: one that is
// neither revoked nor expired at the time of the query. ClientID, StartedAt and
// AuthTime are those of the session's newest active token, and LastUsedAt and
// ExpiresAt are that token's creation and expiry times.
type LiveSession struct {
	SessionID  SessionID
	ClientID   config.ClientID
	StartedAt  time.Time
	AuthTime   time.Time
	LastUsedAt time.Time
	ExpiresAt  time.Time
}

// RefreshTokens holds the refresh tokens; each method is scoped to one realm
// except MarkReplaced, which names a row by its id, and DeleteExpired.
type RefreshTokens interface {
	// Insert returns ErrConflict when the id or the hash exists.
	Insert(ctx context.Context, t RefreshToken) error
	// FindByHash returns the row whatever its state (expired, replaced or
	// revoked); the caller decides. ErrNotFound when the realm has no such hash.
	FindByHash(ctx context.Context, realm RealmID, hash secure.Hash) (RefreshToken, error)
	// MarkReplaced sets replaced_by when it is still empty, in one atomic
	// step. It returns ErrConflict when the token already has a successor
	// (the caller reads the row to see which) and ErrNotFound for an unknown id.
	MarkReplaced(ctx context.Context, id, successor RefreshTokenID) error
	// FindByID returns the row with that id whatever its state, including
	// expired. ErrNotFound when the realm has no such id.
	FindByID(ctx context.Context, realm RealmID, id RefreshTokenID) (RefreshToken, error)
	// Extend sets the expiry of the token with that id, for a confidential
	// client with rotation off. ErrNotFound when the realm has no such id.
	Extend(ctx context.Context, realm RealmID, id RefreshTokenID, expiresAt time.Time) error
	// RevokeSession sets revoked_at to now on every row of the session that is
	// not revoked yet (expired rows that are not revoked count). It returns what
	// it ended (Ended). It is not an error when there is none.
	RevokeSession(ctx context.Context, realm RealmID, session SessionID, now time.Time) (Ended, error)
	// SessionLive reports whether the session has a refresh token that is not
	// revoked (expired and rotated rows count when they are not revoked).
	SessionLive(ctx context.Context, realm RealmID, session SessionID) (bool, error)
	// RevokeOthers is RevokeSession for every row of the session except keep. It
	// ends no session (the rotation's cleanup of stale siblings), so it reports
	// nothing.
	RevokeOthers(ctx context.Context, realm RealmID, session SessionID, keep RefreshTokenID, now time.Time) error
	// RevokeUser is RevokeSession for every row of the user.
	RevokeUser(ctx context.Context, realm RealmID, user UserID, now time.Time) (Ended, error)
	// DeleteUser removes every row of the user (account deletion) and returns
	// what it ended: the sessions with a row that was not revoked yet. It is not
	// an error when there is none.
	DeleteUser(ctx context.Context, realm RealmID, user UserID) (Ended, error)
	// DeleteExpired removes every row whose ExpiresAt is at or before now, in
	// every realm, and returns how many.
	DeleteExpired(ctx context.Context, now time.Time) (int64, error)
	// UserLiveSessions returns the live sessions of the user at now, ordered by
	// StartedAt, then by SessionID. A session with no active token is not listed.
	UserLiveSessions(ctx context.Context, realm RealmID, user UserID, now time.Time) ([]LiveSession, error)
	// RealmLiveSessions is UserLiveSessions for every user of the realm.
	RealmLiveSessions(ctx context.Context, realm RealmID, now time.Time) ([]LiveSession, error)
	// HasSession reports whether the session has a refresh token of the user in
	// any state, expired and revoked included. It is false for another user's
	// session and for an unknown one.
	HasSession(ctx context.Context, realm RealmID, user UserID, session SessionID) (bool, error)
}

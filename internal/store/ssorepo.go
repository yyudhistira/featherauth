package store

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"time"

	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/secure"
)

var (
	_ SSOSessions    = ssoRepo{}
	_ slog.LogValuer = SSOSession{}
)

// LogValue logs ids, the provider and the expiry only: never the id hash, which
// is the key of a browser session (SEC-37).
func (s SSOSession) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("realm_id", string(s.RealmID)),
		slog.String("user_id", string(s.UserID)),
		slog.String("identity_id", string(s.IdentityID)),
		slog.String("provider", string(s.Provider)),
		slog.Time("expires_at", s.ExpiresAt),
	)
}

// ssoRepo is the sso_sessions table.
type ssoRepo struct{ q dbtx }

const ssoColumns = `id_hash, realm_id, user_id, identity_id, provider, auth_time, created_at, last_used_at, expires_at`

func (r ssoRepo) Create(ctx context.Context, s SSOSession) error {
	_, err := r.q.ExecContext(ctx,
		`INSERT INTO sso_sessions (`+ssoColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		string(s.IDHash), string(s.RealmID), string(s.UserID), string(s.IdentityID), string(s.Provider),
		unix(s.AuthTime), unix(s.CreatedAt), unix(s.LastUsedAt), unix(s.ExpiresAt))
	return mapWriteErr(err)
}

func (r ssoRepo) Find(ctx context.Context, realm RealmID, idHash secure.Hash) (SSOSession, error) {
	var (
		hash, rid, user, identity, provider string
		authTime, created, used, expires    int64
	)
	err := r.q.QueryRowContext(ctx,
		`SELECT `+ssoColumns+` FROM sso_sessions WHERE realm_id = ? AND id_hash = ?`,
		string(realm), string(idHash)).
		Scan(&hash, &rid, &user, &identity, &provider, &authTime, &created, &used, &expires)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return SSOSession{}, ErrNotFound
		}
		return SSOSession{}, err
	}
	return SSOSession{
		IDHash: secure.Hash(hash), RealmID: RealmID(rid), UserID: UserID(user), IdentityID: IdentityID(identity),
		Provider: config.ProviderKey(provider), AuthTime: fromUnix(authTime), CreatedAt: fromUnix(created),
		LastUsedAt: fromUnix(used), ExpiresAt: fromUnix(expires),
	}, nil
}

func (r ssoRepo) Touch(ctx context.Context, realm RealmID, idHash secure.Hash, usedAt, expiresAt time.Time) error {
	return expectOne(r.q.ExecContext(ctx,
		`UPDATE sso_sessions SET last_used_at = ?, expires_at = ? WHERE realm_id = ? AND id_hash = ?`,
		unix(usedAt), unix(expiresAt), string(realm), string(idHash)))
}

func (r ssoRepo) Delete(ctx context.Context, realm RealmID, idHash secure.Hash) error {
	_, err := r.q.ExecContext(ctx, `DELETE FROM sso_sessions WHERE realm_id = ? AND id_hash = ?`, string(realm), string(idHash))
	return err
}

func (r ssoRepo) DeleteByUser(ctx context.Context, realm RealmID, user UserID) error {
	_, err := r.q.ExecContext(ctx, `DELETE FROM sso_sessions WHERE realm_id = ? AND user_id = ?`, string(realm), string(user))
	return err
}

func (r ssoRepo) DeleteByIdentity(ctx context.Context, realm RealmID, identity IdentityID) error {
	_, err := r.q.ExecContext(ctx, `DELETE FROM sso_sessions WHERE realm_id = ? AND identity_id = ?`, string(realm), string(identity))
	return err
}

func (r ssoRepo) DeleteByRealm(ctx context.Context, realm RealmID) error {
	_, err := r.q.ExecContext(ctx, `DELETE FROM sso_sessions WHERE realm_id = ?`, string(realm))
	return err
}

func (r ssoRepo) DeleteExpired(ctx context.Context, now time.Time) (int64, error) {
	return rowsAffected(r.q.ExecContext(ctx, `DELETE FROM sso_sessions WHERE expires_at <= ?`, unix(now)))
}

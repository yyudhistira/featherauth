package store

import (
	"cmp"
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5/pgconn"
	"modernc.org/sqlite"

	"github.com/yyudhistira/featherauth/internal/config"
)

var (
	_ Realms     = realmRepo{}
	_ Users      = userRepo{}
	_ Identities = identityRepo{}

	_ slog.LogValuer = User{}
	_ slog.LogValuer = Identity{}
)

// LogValue logs ids and flags only: never the email, the email key or the name.
func (u User) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("id", string(u.ID)),
		slog.String("realm_id", string(u.RealmID)),
		slog.Bool("email_verified", u.EmailVerified),
		slog.Bool("disabled", !u.DisabledAt.IsZero()),
	)
}

// LogValue logs ids and the provider only: never the email, the subject or
// the sealed provider token.
func (i Identity) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("id", string(i.ID)),
		slog.String("realm_id", string(i.RealmID)),
		slog.String("user_id", string(i.UserID)),
		slog.String("provider", string(i.Provider)),
		slog.Bool("email_verified", i.EmailVerified),
	)
}

// dbtx is what *sql.Tx offers the repositories.
type dbtx interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

type (
	realmRepo    struct{ tx dbtx }
	userRepo     struct{ tx dbtx }
	identityRepo struct{ tx dbtx }
)

// uniqueError is a unique or primary key violation of Postgres. It is ErrConflict
// to errors.Is. Its text names the key only: Postgres' own text holds the key's
// values, and an email is one of them. Write reads the key name (retry.go).
type uniqueError struct{ constraint string }

var _ error = (*uniqueError)(nil)

func (e *uniqueError) Error() string {
	if e.constraint == "" {
		return ErrConflict.Error()
	}
	return ErrConflict.Error() + " on " + e.constraint
}

// Is makes errors.Is(err, ErrConflict) true.
func (e *uniqueError) Is(target error) bool { return target == ErrConflict }

// mapWriteErr turns a unique or primary key violation into ErrConflict, on
// SQLite and on Postgres (SQLSTATE 23505).
func mapWriteErr(err error) error {
	var se *sqlite.Error
	if errors.As(err, &se) {
		switch se.Code() {
		case 1555, 2067: // SQLITE_CONSTRAINT_PRIMARYKEY, SQLITE_CONSTRAINT_UNIQUE
			return ErrConflict
		}
	}
	var pe *pgconn.PgError
	if errors.As(err, &pe) && pe.Code == "23505" { // unique_violation
		return &uniqueError{constraint: pe.ConstraintName}
	}
	return err
}

// expectOne returns ErrNotFound when a statement changed no row.
func expectOne(res sql.Result, err error) error {
	if err != nil {
		return mapWriteErr(err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func unix(t time.Time) int64 { return t.UTC().Unix() }

func fromUnix(n int64) time.Time { return time.Unix(n, 0).UTC() }

func nullStr(s string) sql.NullString { return sql.NullString{String: s, Valid: s != ""} }

func nullTime(t time.Time) sql.NullInt64 {
	return sql.NullInt64{Int64: unix(t), Valid: !t.IsZero()}
}

func (r realmRepo) Ensure(ctx context.Context, name config.RealmName, id RealmID, createdAt time.Time) (RealmID, error) {
	if _, err := r.tx.ExecContext(ctx,
		`INSERT INTO realms (id, name, created_at) VALUES (?, ?, ?) ON CONFLICT (name) DO NOTHING`,
		string(id), string(name), unix(createdAt)); err != nil {
		return "", mapWriteErr(err)
	}
	var got string
	if err := r.tx.QueryRowContext(ctx, `SELECT id FROM realms WHERE name = ?`, string(name)).Scan(&got); err != nil {
		return "", err
	}
	return RealmID(got), nil
}

func (r realmRepo) Find(ctx context.Context, name config.RealmName) (RealmID, error) {
	var got string
	err := r.tx.QueryRowContext(ctx, `SELECT id FROM realms WHERE name = ?`, string(name)).Scan(&got)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	return RealmID(got), nil
}

const userColumns = `id, realm_id, email, email_key, email_verified, name, disabled_at, created_at, updated_at`

type scanner interface{ Scan(dest ...any) error }

func scanUser(s scanner) (User, error) {
	var (
		u                  User
		id, realm          string
		email, key, name   sql.NullString
		verified           bool
		disabled           sql.NullInt64
		created, updatedAt int64
	)
	if err := s.Scan(&id, &realm, &email, &key, &verified, &name, &disabled, &created, &updatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, ErrNotFound
		}
		return User{}, err
	}
	u = User{
		ID: UserID(id), RealmID: RealmID(realm), Email: email.String, EmailKey: key.String,
		EmailVerified: verified, Name: name.String,
		CreatedAt: fromUnix(created), UpdatedAt: fromUnix(updatedAt),
	}
	if disabled.Valid {
		u.DisabledAt = fromUnix(disabled.Int64)
	}
	return u, nil
}

func (r userRepo) Create(ctx context.Context, u User) error {
	_, err := r.tx.ExecContext(ctx,
		`INSERT INTO users (`+userColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		string(u.ID), string(u.RealmID), nullStr(u.Email), nullStr(u.EmailKey), u.EmailVerified,
		nullStr(u.Name), nullTime(u.DisabledAt), unix(u.CreatedAt), unix(u.UpdatedAt))
	return mapWriteErr(err)
}

func (r userRepo) Get(ctx context.Context, realm RealmID, id UserID) (User, error) {
	return scanUser(r.tx.QueryRowContext(ctx,
		`SELECT `+userColumns+` FROM users WHERE realm_id = ? AND id = ?`+rowLock(r.tx), string(realm), string(id)))
}

func (r userRepo) Update(ctx context.Context, u User) error {
	return expectOne(r.tx.ExecContext(ctx,
		`UPDATE users SET email = ?, email_key = ?, email_verified = ?, name = ?, disabled_at = ?, updated_at = ?
		 WHERE realm_id = ? AND id = ?`,
		nullStr(u.Email), nullStr(u.EmailKey), u.EmailVerified, nullStr(u.Name), nullTime(u.DisabledAt),
		unix(u.UpdatedAt), string(u.RealmID), string(u.ID)))
}

func (r userRepo) Delete(ctx context.Context, realm RealmID, id UserID) error {
	return expectOne(r.tx.ExecContext(ctx,
		`DELETE FROM users WHERE realm_id = ? AND id = ?`, string(realm), string(id)))
}

func (r userRepo) FindVerifiedByEmailKey(ctx context.Context, realm RealmID, key string) (User, error) {
	return scanUser(r.tx.QueryRowContext(ctx,
		`SELECT `+userColumns+` FROM users WHERE realm_id = ? AND email_key = ? AND email_verified = TRUE`,
		string(realm), key))
}

func (r userRepo) ListByEmailKey(ctx context.Context, realm RealmID, key string) ([]User, error) {
	rows, err := r.tx.QueryContext(ctx,
		`SELECT `+userColumns+` FROM users WHERE realm_id = ? AND email_key = ? ORDER BY created_at, id`,
		string(realm), key)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

const identityColumns = `id, realm_id, user_id, provider, provider_sub, email, email_verified, provider_refresh_token_enc, created_at`

func scanIdentity(s scanner) (Identity, error) {
	var (
		id, realm, user, provider, sub, email string
		verified                              bool
		enc                                   sql.NullString
		created                               int64
	)
	if err := s.Scan(&id, &realm, &user, &provider, &sub, &email, &verified, &enc, &created); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Identity{}, ErrNotFound
		}
		return Identity{}, err
	}
	return Identity{
		ID: IdentityID(id), RealmID: RealmID(realm), UserID: UserID(user),
		Provider: config.ProviderKey(provider), ProviderSub: sub, Email: email,
		EmailVerified: verified, ProviderRefreshTokenEnc: enc.String, CreatedAt: fromUnix(created),
	}, nil
}

func (r identityRepo) Find(ctx context.Context, realm RealmID, provider config.ProviderKey, sub string) (Identity, error) {
	return scanIdentity(r.tx.QueryRowContext(ctx,
		`SELECT `+identityColumns+` FROM identities WHERE realm_id = ? AND provider = ? AND provider_sub = ?`,
		string(realm), string(provider), sub))
}

// Create requires i.RealmID to equal the realm of the user i.UserID; the caller
// guarantees it, the store does not check.
func (r identityRepo) Create(ctx context.Context, i Identity) error {
	_, err := r.tx.ExecContext(ctx,
		`INSERT INTO identities (`+identityColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		string(i.ID), string(i.RealmID), string(i.UserID), string(i.Provider), i.ProviderSub,
		i.Email, i.EmailVerified, nullStr(i.ProviderRefreshTokenEnc), unix(i.CreatedAt))
	return mapWriteErr(err)
}

func (r identityRepo) Update(ctx context.Context, i Identity) error {
	return expectOne(r.tx.ExecContext(ctx,
		`UPDATE identities SET email = ?, email_verified = ? WHERE realm_id = ? AND id = ?`,
		i.Email, i.EmailVerified, string(i.RealmID), string(i.ID)))
}

func (r identityRepo) ListByUser(ctx context.Context, realm RealmID, user UserID) ([]Identity, error) {
	rows, err := r.tx.QueryContext(ctx,
		`SELECT `+identityColumns+` FROM identities WHERE realm_id = ? AND user_id = ? ORDER BY created_at, id`,
		string(realm), string(user))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Identity
	for rows.Next() {
		i, err := scanIdentity(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

func (r identityRepo) Delete(ctx context.Context, realm RealmID, id IdentityID) error {
	return expectOne(r.tx.ExecContext(ctx,
		`DELETE FROM identities WHERE realm_id = ? AND id = ?`, string(realm), string(id)))
}

func (r identityRepo) SetProviderToken(ctx context.Context, realm RealmID, id IdentityID, sealed string) error {
	return expectOne(r.tx.ExecContext(ctx,
		`UPDATE identities SET provider_refresh_token_enc = ? WHERE realm_id = ? AND id = ?`,
		nullStr(sealed), string(realm), string(id)))
}

func (r identityRepo) SealedBy(ctx context.Context, realm RealmID, keyID string) ([]SealedIdentity, error) {
	prefix := keyID + "."
	rows, err := r.tx.QueryContext(ctx,
		`SELECT id, realm_id, user_id, provider, provider_sub, provider_refresh_token_enc FROM identities
		 WHERE realm_id = ? AND substr(provider_refresh_token_enc, 1, ?) = ?`,
		string(realm), utf8.RuneCountInString(prefix), prefix)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SealedIdentity
	for rows.Next() {
		var id, rid, user, provider, sub, enc string
		if err := rows.Scan(&id, &rid, &user, &provider, &sub, &enc); err != nil {
			return nil, err
		}
		out = append(out, SealedIdentity{
			ID: IdentityID(id), RealmID: RealmID(rid), UserID: UserID(user),
			Provider: config.ProviderKey(provider), Subject: sub, Value: enc,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// The order is by bytes, whatever the database's collation.
	slices.SortFunc(out, func(a, b SealedIdentity) int {
		return cmp.Or(strings.Compare(string(a.UserID), string(b.UserID)),
			strings.Compare(string(a.Provider), string(b.Provider)), strings.Compare(a.Subject, b.Subject))
	})
	return out, nil
}

func (r identityRepo) ReplaceProviderToken(ctx context.Context, realm RealmID, id IdentityID, old, next string) (bool, error) {
	res, err := r.tx.ExecContext(ctx,
		`UPDATE identities SET provider_refresh_token_enc = ? WHERE realm_id = ? AND id = ? AND provider_refresh_token_enc = ?`,
		nullStr(next), string(realm), string(id), old)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

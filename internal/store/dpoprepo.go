package store

import (
	"context"
	"time"

	"github.com/yyudhistira/featherauth/internal/secure"
)

// dpopRepo is the dpop_proofs table.
type dpopRepo struct{ q dbtx }

var _ DPoPProofs = dpopRepo{}

// Use inserts the row unless the hash has one already, in the same statement:
// the insert does nothing on a conflict and reports whether it wrote, so a
// repeat is a refusal and not a database error.
func (r dpopRepo) Use(ctx context.Context, proofHash secure.Hash, expiresAt time.Time) (bool, error) {
	res, err := r.q.ExecContext(ctx,
		`INSERT INTO dpop_proofs (proof_hash, expires_at) VALUES (?, ?) ON CONFLICT (proof_hash) DO NOTHING`,
		string(proofHash), unix(expiresAt))
	if err != nil {
		return false, mapWriteErr(err)
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// DeleteExpired removes the proofs strictly past their expiry at now. A proof
// at exactly its expiry is kept, as for provider event ids.
func (r dpopRepo) DeleteExpired(ctx context.Context, now time.Time) (int64, error) {
	return rowsAffected(r.q.ExecContext(ctx, `DELETE FROM dpop_proofs WHERE expires_at < ?`, unix(now)))
}

package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgconn"
)

// maxRuns is how many times Write runs its function at most: the first run and
// two more.
const maxRuns = 3

// onceOnly names the unique keys of the rows that may exist only once: a verified
// email, a provider identity, a remembered provider event and the one handoff of
// a login. A violation of one of them is run again (retryWrite).
var onceOnly = map[string]bool{
	"users_verified_email_key":          true,
	"identities_provider_sub":           true,
	"provider_event_ids_pkey":           true,
	"callback_handoffs_auth_request_id": true,
}

// sqlState returns the SQLSTATE of the Postgres failure in err's chain and, for a
// unique violation, the name of its key. Any other error gives "".
func sqlState(err error) (code, constraint string) {
	var ue *uniqueError
	if errors.As(err, &ue) {
		return "23505", ue.constraint
	}
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe.Code, pe.ConstraintName
	}
	return "", ""
}

// retryWrite runs attempt, which is one write transaction and its function, until
// it succeeds or fails in a way that a run again can change. A deadlock or a
// serialization failure (40P01, 40001) is run again. A violation of a once-only
// key (23505) is run again too: the other transaction committed the row, so the
// next run finds it. A second violation of such a key is the conflict itself, and
// is returned as it is. Any other failure is returned as it is. A failure that is
// still retryable after the last run is ErrUnavailable.
func retryWrite(ctx context.Context, attempt func(context.Context) error) error {
	conflict := false
	for run := 1; ; run++ {
		err := attempt(ctx)
		if err == nil {
			return nil
		}
		code, constraint := sqlState(err)
		switch {
		case code == "23505" && onceOnly[constraint]:
			if conflict {
				return err
			}
			conflict = true
		case code == "40P01" || code == "40001":
		default:
			return err
		}
		if run == maxRuns {
			return fmt.Errorf("%w: the transaction failed %d times (SQLSTATE %s)", ErrUnavailable, run, code)
		}
	}
}

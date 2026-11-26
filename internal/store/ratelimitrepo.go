package store

import (
	"context"
	"time"
)

// rateLimitRepo is the rate_limits table (FR-53).
type rateLimitRepo struct{ q dbtx }

var _ RateLimits = rateLimitRepo{}

// Hit adds one request to the count of key in window and returns the count of
// that window, the request included, in one statement: the insert creates the
// row with a count of one, and a conflict on (key, window_start) raises it.
func (r rateLimitRepo) Hit(ctx context.Context, key string, window time.Time) (int64, error) {
	var n int64
	err := r.q.QueryRowContext(ctx,
		`INSERT INTO rate_limits (key, window_start, count) VALUES (?, ?, 1)
		 ON CONFLICT (key, window_start) DO UPDATE SET count = rate_limits.count + 1
		 RETURNING count`,
		key, unix(window)).Scan(&n)
	return n, mapWriteErr(err)
}

// DeleteBefore removes the windows that start before window.
func (r rateLimitRepo) DeleteBefore(ctx context.Context, window time.Time) (int64, error) {
	return rowsAffected(r.q.ExecContext(ctx, `DELETE FROM rate_limits WHERE window_start < ?`, unix(window)))
}

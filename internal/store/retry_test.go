package store

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

// Covers: FR-35 (part)
// retryWrite runs a transaction again only for the failures the design names:
// 40P01 and 40001 use all three runs and end in ErrUnavailable; a violation of a
// once-only key is run again once, and a second one is returned as it is.
func TestRetryWrite(t *testing.T) {
	once := &pgconn.PgError{Code: "23505", ConstraintName: "users_verified_email_key"}
	other := &pgconn.PgError{Code: "23505", ConstraintName: "users_pkey"}
	deadlock := &pgconn.PgError{Code: "40P01"}
	serial := &pgconn.PgError{Code: "40001"}
	boom := errors.New("boom")
	onceMapped := &uniqueError{constraint: "identities_provider_sub"}
	otherMapped := &uniqueError{constraint: "users_pkey"}
	tests := []struct {
		name     string
		errs     []error // the error of each run in turn; a run past the list succeeds
		wantRuns int
		wantErr  error // errors.Is target of the result; nil for success
	}{
		{name: "no failure", wantRuns: 1},
		{name: "deadlock once", errs: []error{deadlock}, wantRuns: 2},
		{name: "deadlock three times", errs: []error{deadlock, deadlock, deadlock}, wantRuns: 3, wantErr: ErrUnavailable},
		{name: "serialization failure twice", errs: []error{serial, serial}, wantRuns: 3},
		{name: "once-only violation once", errs: []error{once}, wantRuns: 2},
		{name: "once-only violation twice is the conflict", errs: []error{once, once}, wantRuns: 2, wantErr: once},
		{name: "once-only, deadlock, once-only", errs: []error{once, deadlock, once}, wantRuns: 3, wantErr: once},
		{name: "other unique key is not run again", errs: []error{other}, wantRuns: 1, wantErr: other},
		{name: "other error is not run again", errs: []error{boom}, wantRuns: 1, wantErr: boom},
		{name: "mapped once-only conflict is run again", errs: []error{onceMapped}, wantRuns: 2},
		{name: "mapped other conflict is not run again", errs: []error{otherMapped}, wantRuns: 1, wantErr: otherMapped},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runs := 0
			err := retryWrite(context.Background(), func(context.Context) error {
				i := runs
				runs++
				if i < len(tc.errs) {
					return tc.errs[i]
				}
				return nil
			})
			if runs != tc.wantRuns {
				t.Fatalf("runs = %d, want %d", runs, tc.wantRuns)
			}
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("err = %v, want success", err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"time"
)

// Removed counts the rows Cleanup deleted from each table.
type Removed struct {
	AuthRequests   int64
	AuthCodes      int64
	Handoffs       int64
	ProviderEvents int64
	DPoPProofs     int64
	RateLimits     int64
	RefreshTokens  int64
	SSOSessions    int64
}

// Cleanup deletes, in one transaction, the authorization requests, codes,
// handoffs, provider event ids, DPoP proofs, refresh tokens and browser sessions
// that expired at or before now, and the rate limit windows that start before
// the minute of now.
// Audit events are kept. The hourly job calls it.
func Cleanup(ctx context.Context, s Store, now time.Time) (Removed, error) {
	var out Removed
	err := s.Write(ctx, func(tx Tx) (err error) {
		out = Removed{} // a run that is run again starts with no count
		if out.AuthRequests, err = tx.AuthRequests().DeleteExpired(ctx, now); err != nil {
			return err
		}
		if out.AuthCodes, err = tx.AuthCodes().DeleteExpired(ctx, now); err != nil {
			return err
		}
		if out.Handoffs, err = tx.Handoffs().DeleteExpired(ctx, now); err != nil {
			return err
		}
		if out.ProviderEvents, err = tx.ProviderEvents().DeleteExpired(ctx, now); err != nil {
			return err
		}
		if out.DPoPProofs, err = tx.DPoPProofs().DeleteExpired(ctx, now); err != nil {
			return err
		}
		if out.RefreshTokens, err = tx.RefreshTokens().DeleteExpired(ctx, now); err != nil {
			return err
		}
		if out.RateLimits, err = tx.RateLimits().DeleteBefore(ctx, now.UTC().Truncate(time.Minute)); err != nil {
			return err
		}
		out.SSOSessions, err = tx.SSOSessions().DeleteExpired(ctx, now)
		return err
	})
	if err != nil {
		return Removed{}, err
	}
	return out, nil
}

var snapshotName = regexp.MustCompile(`^featherauth-\d{8}-\d{4}\.db$`)

// Snapshot writes a consistent copy of the database to dir as
// featherauth-YYYYMMDD-HHMM.db, named from now as given (callers pass server
// local time), then deletes all but the newest keep snapshots in dir; the one just written always stays. Other
// files stay. dir must exist and keep must be at least 1. It fails, leaving
// the old file, when a snapshot of that minute already exists. It returns the
// path written.
func Snapshot(ctx context.Context, s Store, dir string, now time.Time, keep int) (string, error) {
	if keep < 1 {
		return "", errors.New("store: snapshots to keep must be at least 1")
	}
	path := filepath.Join(dir, "featherauth-"+now.Format("20060102-1504")+".db")
	if err := s.Backup(ctx, path); err != nil {
		return "", err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return path, fmt.Errorf("store: listing snapshots: %w", err)
	}
	var names []string
	for _, e := range entries {
		if e.Type().IsRegular() && e.Name() != filepath.Base(path) && snapshotName.MatchString(e.Name()) {
			names = append(names, e.Name())
		}
	}
	// The names sort by time, oldest first. The new file is never removed,
	// even when a clock step gave it an older name than the others; it
	// counts as one of the files kept.
	sort.Strings(names)
	for len(names) > keep-1 {
		if err := os.Remove(filepath.Join(dir, names[0])); err != nil {
			return path, fmt.Errorf("store: removing old snapshot: %w", err)
		}
		names = names[1:]
	}
	return path, nil
}

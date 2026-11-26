package store

import "context"

// Ended is what a revoking call ended.
type Ended struct{ Sessions []string }

// RefreshTokens is the fixture's revoking interface.
type RefreshTokens interface {
	RevokeSession(ctx context.Context, session string) (Ended, error)
	DeleteUser(ctx context.Context, user string) (Ended, error)
	RevokeOthers(ctx context.Context, session string) error
}

// Tx is the fixture's transaction.
type Tx interface{ RefreshTokens() RefreshTokens }

// QueueLogouts is the fixture's helper.
func QueueLogouts(ctx context.Context, tx Tx, ended Ended) error { return nil }

package user

import (
	"context"

	"example.com/fixture/internal/store"
)

func revokeWithoutQueue(ctx context.Context, tx store.Tx) error {
	_, err := tx.RefreshTokens().RevokeSession(ctx, "s")
	return err
}

func revokeQueued(ctx context.Context, tx store.Tx) error {
	ended, err := tx.RefreshTokens().RevokeSession(ctx, "s")
	if err != nil {
		return err
	}
	return store.QueueLogouts(ctx, tx, ended)
}

func deleteWithoutQueue(ctx context.Context, tx store.Tx) error {
	_, err := tx.RefreshTokens().DeleteUser(ctx, "u")
	return err
}

// rotateCleanup ends no session, so it needs no queue.
func rotateCleanup(ctx context.Context, tx store.Tx) error {
	return tx.RefreshTokens().RevokeOthers(ctx, "s")
}

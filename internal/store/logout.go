package store

import (
	"context"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/secure"
)

// QueueLogouts writes a logout notification, in tx, for each session in
// sessions whose client of realm has a backchannel_logout_uri. It is the one
// helper that writes logout_notifications rows: every call that ends sessions
// (RevokeSession, RevokeUser, DeleteUser) passes what it reported to it. A nil
// realm (its configuration is not available) has no client with a URI, so it
// queues nothing and is not an error.
//
// It also ends the browser session that each ended session came from (FR-45):
// that happens whatever the configuration says, since a browser session is not a
// logout notification.
func QueueLogouts(ctx context.Context, tx Tx, realm *config.Realm, rid RealmID, sessions []EndedSession, clk clock.Clock, src secure.Source) error {
	for _, ss := range sessions {
		if ss.SSOIDHash == "" {
			continue
		}
		if err := tx.SSOSessions().Delete(ctx, rid, ss.SSOIDHash); err != nil {
			return err
		}
	}
	if realm == nil {
		return nil
	}
	for _, ss := range sessions {
		cl := realm.Clients[ss.ClientID]
		if cl == nil || cl.BackchannelLogoutURI == "" {
			continue
		}
		id, err := secure.NewID(src, clk)
		if err != nil {
			return err
		}
		now := clk.Now()
		if err := tx.LogoutNotifications().Enqueue(ctx, LogoutNotification{
			ID: LogoutNotificationID(id), RealmID: rid, ClientID: ss.ClientID, UserID: ss.UserID,
			SessionID: ss.SessionID, NextAttemptAt: now, CreatedAt: now,
		}); err != nil {
			return err
		}
	}
	return nil
}

// Package audit writes audit events to the audit_events table and, for each
// stored event, to the log as a line marked audit: true. It lives under
// internal/store, so it has the store's rank in the import order.
package audit

import (
	"context"
	"log/slog"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/logx"
	"github.com/yyudhistira/featherauth/internal/secure"
	"github.com/yyudhistira/featherauth/internal/store"
)

// Event is what a caller reports. Details hold no secrets and no emails; the
// user is named by id only.
type Event struct {
	Realm   store.RealmID
	Actor   string // "admin", "system" or "provider:<name>"
	Action  string
	User    store.UserID // empty when the event concerns no user
	Details map[string]any
}

// Writer stores audit events. The id and the time come from the random source
// and the clock it was made with.
type Writer struct {
	store store.Store
	log   *slog.Logger
	clock clock.Clock
	rand  secure.Source
}

// NewWriter returns a Writer. log should be made by logx.New.
func NewWriter(s store.Store, log *slog.Logger, c clock.Clock, src secure.Source) *Writer {
	return &Writer{store: s, log: log, clock: c, rand: src}
}

// Write stores the event in its own transaction and, once that has committed,
// logs it. A failure to store is returned and nothing is logged. Do not call
// it inside a Store.Write callback: the store has one write connection, so it
// would wait for itself forever.
func (w *Writer) Write(ctx context.Context, e Event) error {
	var publish func()
	err := w.store.Write(ctx, func(tx store.Tx) error {
		var err error
		publish, err = w.WriteTx(ctx, tx, e)
		return err
	})
	if err != nil {
		return err
	}
	publish()
	return nil
}

// WriteTx stores the event in the caller's transaction, so that it commits or
// rolls back with the change it records, and returns a function that logs the
// line. The caller calls it only after the transaction has committed; if the
// transaction fails, it never calls it and nothing is logged.
func (w *Writer) WriteTx(ctx context.Context, tx store.Tx, e Event) (func(), error) {
	id, err := secure.NewID(w.rand, w.clock)
	if err != nil {
		return nil, err
	}
	row := store.AuditEvent{
		ID: id, RealmID: e.Realm, Actor: e.Actor, Action: e.Action, UserID: e.User,
		Details: e.Details, CreatedAt: w.clock.Now(),
	}
	if err := tx.Audit().Insert(ctx, row); err != nil {
		return nil, err
	}
	return func() {
		logx.Audit(ctx, w.log, logx.AuditEvent{
			ID: row.ID, RealmID: string(row.RealmID), Actor: row.Actor, Action: row.Action,
			UserID: string(row.UserID), Details: row.Details, CreatedAt: row.CreatedAt,
		})
	}, nil
}

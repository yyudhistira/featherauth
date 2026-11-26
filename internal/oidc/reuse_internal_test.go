package oidc

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/logx"
	"github.com/yyudhistira/featherauth/internal/secure"
	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/store/audit"
	"github.com/yyudhistira/featherauth/internal/testutil"
	"github.com/yyudhistira/featherauth/internal/token"
)

// Covers: SEC-25
// Acceptance: Reuse records (part)
func TestReuseRowSurvivesCancelledRequest(t *testing.T) {
	st := testutil.NewStore(t)
	clk := clock.NewFake(time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC))
	log := logx.New(io.Discard, slog.LevelDebug, clk)
	tok := &Token{audit: audit.NewWriter(st, log, clk, secure.Default), log: log}

	ctx := context.Background()
	if err := st.Write(ctx, func(tx store.Tx) error {
		_, err := tx.Realms().Ensure(ctx, "main", "realm-1", clk.Now())
		return err
	}); err != nil {
		t.Fatal(err)
	}

	// The request hangs up after the revocation committed and before the row
	// is written: the row must still be written.
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	tok.recordReuse(cancelled, &token.Reuse{
		Realm: "realm-1", User: "u1", Client: "web", Session: "sess-1",
		Kind: token.ReuseRefreshToken, Ended: true,
	})

	var rows []store.AuditEvent
	if err := st.Read(ctx, func(tx store.Tx) error {
		var err error
		rows, err = tx.Audit().List(ctx, "realm-1", time.Time{})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Action != "session.reuse_detected" || rows[0].Details["kind"] != "refresh_token" {
		t.Fatalf("rows = %+v, want one session.reuse_detected row", rows)
	}
}

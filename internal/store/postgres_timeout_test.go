//go:build postgres

package store_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/testutil"
)

// A server that accepts the connection and never answers fails the start within
// postgres.connect_timeout, not after the operating system's TCP timeout or the
// caller's context, and the error holds no password (OPS-22, row "Postgres
// connect timeout").
func TestOpenPostgresStopsWithinTheConnectTimeout(t *testing.T) {
	hole := testutil.NewBlackhole(t, "127.0.0.1:0")
	host, port := hole.HostPort(t)
	pg := config.PostgresConfig{
		Host: host, Port: port, Database: "d", User: "u", SSLMode: "disable",
		MaxOpenConns: 2, MaxIdleConns: 1,
		ConnMaxLifetime: config.Duration(time.Minute),
		ConnectTimeout:  config.Duration(500 * time.Millisecond),
	}
	// The context is far above the limit: only the connect timeout can end the
	// attempt in time.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	clk := clock.Real()
	begin := clk.Now()
	_, err := openPostgresCtx(ctx, t, pg, connPassword, nil)
	took := clk.Now().Sub(begin)
	if err == nil {
		t.Fatal("open succeeded against a server that never answers")
	}
	if ctx.Err() != nil {
		t.Fatalf("the context ended the attempt, not the connect timeout: %v", err)
	}
	if took < 400*time.Millisecond || took > 3*time.Second {
		t.Errorf("open failed after %v, want about the 500ms connect timeout", took)
	}
	if strings.Contains(err.Error(), connPassword) {
		t.Errorf("the error holds the password: %v", err)
	}
}

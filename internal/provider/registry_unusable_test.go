package provider_test

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/logx"
	"github.com/yyudhistira/featherauth/internal/provider"
)

// A provider the registry cannot use is warned about with its error under err,
// so the logger sees the error the way it sees the others (SR-12).
//
// Covers: SEC-13 (part)
func TestRegistryWarnsWithTheErrorUnderErr(t *testing.T) {
	clk := clock.NewFake(time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC))
	var buf bytes.Buffer
	log := logx.New(&buf, slog.LevelDebug, clk)
	rf := &config.RealmFile{Name: "main", Enabled: true, Providers: config.Providers{
		"corp": {Enabled: true, Type: "saml", Timeout: config.Duration(time.Second)},
	}}
	snap := config.NewSnapshot(&config.ServerFile{}, nil, []*config.RealmFile{rf}, nil)
	pool := provider.NewPool(config.Static(snap), clk, log)
	if _, ok := pool.Get("main", "corp"); ok {
		t.Fatal("a provider of an unknown type was found")
	}
	logs := buf.String()
	if !strings.Contains(logs, `"msg":"provider not usable"`) {
		t.Fatalf("no warning in the log:\n%s", logs)
	}
	if !strings.Contains(logs, `"err":`) || strings.Contains(logs, `"reason":`) {
		t.Errorf("the warning must pass the error under err, not reason:\n%s", logs)
	}
}

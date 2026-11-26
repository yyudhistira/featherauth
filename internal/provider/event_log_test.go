package provider_test

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/logx"
	"github.com/yyudhistira/featherauth/internal/provider"
)

// Covers: FR-31, SEC-27
// Acceptance: Event replay (part)
func TestEventLogsOnlyItsType(t *testing.T) {
	clk := clock.NewFake(time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC))
	ev := provider.Event{
		Type:    "account-delete",
		Subject: "001.subjectvalue",
		ID:      "eyJhbGciOiJSUzI1NiJ9.signedpayloadvalue.signaturevalue",
		Expires: clk.Now().Add(time.Hour),
	}
	var buf bytes.Buffer
	log := logx.New(&buf, slog.LevelDebug, clk)
	log.Info("direct", "event", ev)
	log.Info("nested", "details", map[string]any{"event": ev})
	out := buf.String()
	for _, secret := range []string{ev.ID, "signedpayloadvalue", "signaturevalue", ev.Subject} {
		if strings.Contains(out, secret) {
			t.Errorf("log holds %q: %s", secret, out)
		}
	}
	if !strings.Contains(out, "account-delete") {
		t.Errorf("log does not name the event type: %s", out)
	}
}

package oidc

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/logx"
)

// Covers: SEC-13 (part)
func TestHandoffPayloadLogValue(t *testing.T) {
	p := handoffPayload{
		Code: "code-value-xyz", IDToken: "id-token-value-xyz", State: "state-value-xyz",
		User: `{"email":"person@example.com"}`, Error: "error-value-xyz",
	}
	var buf bytes.Buffer
	log := logx.New(&buf, slog.LevelInfo, clock.NewFake(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)))
	log.Info("direct", "payload", p)
	log.Info("nested", "details", map[string]any{"payload": p, "ptr": &p, "list": []handoffPayload{p}})
	out := buf.String()
	for _, secret := range []string{"code-value-xyz", "id-token-value-xyz", "state-value-xyz", "person@example.com", "error-value-xyz"} {
		if strings.Contains(out, secret) {
			t.Errorf("%q reached the log:\n%s", secret, out)
		}
	}
	if !strings.Contains(out, "code_present") {
		t.Errorf("the payload is not logged at all:\n%s", out)
	}
}

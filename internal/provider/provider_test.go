package provider_test

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/logx"
	"github.com/yyudhistira/featherauth/internal/provider"
)

// Covers: SEC-13 (part)
func TestIdentityLogsNoEmailOrToken(t *testing.T) {
	id := provider.Identity{
		Subject: "sub-1", Email: "ann@example.com", EmailVerified: true, Name: "Ann Secret",
		AuthTime: time.Unix(100, 0), RefreshToken: "REFRESH-SECRET",
	}
	var buf bytes.Buffer
	log := logx.New(&buf, slog.LevelDebug, clock.NewFake(time.Unix(0, 0)))
	log.Info("direct", "identity", id)
	log.Info("pointer", "identity", &id)
	log.Info("nested", "details", map[string]any{"identity": id})
	out := buf.String()
	for _, s := range []string{"ann@example.com", "REFRESH-SECRET", "Ann Secret"} {
		if strings.Contains(out, s) {
			t.Errorf("log holds %q: %s", s, out)
		}
	}
	if !strings.Contains(out, "sub-1") {
		t.Errorf("the subject is not logged: %s", out)
	}
}

// Covers: SEC-13 (part)
func TestCallbackLogsOnlyFlags(t *testing.T) {
	cb := provider.Callback{Code: "CODE-SECRET", IDToken: "IDTOKEN-SECRET", User: `{"email":"ann@example.com"}`, Error: "ERROR-DESCRIPTION"}
	var buf bytes.Buffer
	log := logx.New(&buf, slog.LevelDebug, clock.NewFake(time.Unix(0, 0)))
	log.Info("direct", "callback", cb)
	log.Info("pointer", "callback", &cb)
	log.Info("nested", "details", map[string]any{"callback": cb})
	out := buf.String()
	for _, s := range []string{"CODE-SECRET", "IDTOKEN-SECRET", "ann@example.com", "ERROR-DESCRIPTION"} {
		if strings.Contains(out, s) {
			t.Errorf("log holds %q: %s", s, out)
		}
	}
	if !strings.Contains(out, "code_present") || !strings.Contains(out, "error_present") {
		t.Errorf("flags are not logged: %s", out)
	}
}

// Covers: FR-05 (part)
func TestMapError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		code string
	}{
		{"cancelled", provider.ErrCancelled, "access_denied"},
		{"refused", provider.ErrRefused, "access_denied"},
		{"unavailable", provider.ErrUnavailable, "temporarily_unavailable"},
		{"wrapped cancelled", fmt.Errorf("x: %w", provider.ErrCancelled), "access_denied"},
		{"wrapped unavailable", fmt.Errorf("x: %w", provider.ErrUnavailable), "temporarily_unavailable"},
		{"other", errors.New("boom"), "server_error"},
		{"nil", nil, "server_error"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, desc := provider.MapError(c.err)
			if code != c.code {
				t.Errorf("code = %q, want %q", code, c.code)
			}
			if desc == "" {
				t.Error("empty description")
			}
		})
	}
}

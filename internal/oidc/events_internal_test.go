package oidc

import (
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/logx"
	"github.com/yyudhistira/featherauth/internal/server"
)

type failingSource struct{}

func (failingSource) Read([]byte) (int, error) { return 0, errors.New("no randomness") }

// Covers: FR-40
// Acceptance: Meta deletion callback (part)
func TestConfirmWithoutRandomnessIsAServerError(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC))
	ev := &Events{rand: failingSource{}, log: logx.New(io.Discard, slog.LevelDebug, clk)}
	w := httptest.NewRecorder()
	ev.confirm(w, httptest.NewRequest(http.MethodPost, "/main/events/facebook", nil), server.Info{})
	if w.Code != http.StatusInternalServerError || w.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("status %d headers %v, want 500 with no-store", w.Code, w.Header())
	}
	if got := w.Body.String(); got == "" || !strings.Contains(got, `"server_error"`) || strings.Contains(got, "no randomness") {
		t.Errorf("body %q", got)
	}
}

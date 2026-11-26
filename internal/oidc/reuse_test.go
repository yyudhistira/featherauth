package oidc_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/testutil/server"
)

// logLine is one parsed line of the service log.
type logLine map[string]any

// logLines returns every line of the service log. A line that is not JSON
// fails the test.
func logLines(t *testing.T, e *server.Env) []logLine {
	t.Helper()
	var out []logLine
	for _, s := range strings.Split(e.Logs.String(), "\n") {
		if s == "" {
			continue
		}
		var m logLine
		if err := json.Unmarshal([]byte(s), &m); err != nil {
			t.Fatalf("line is not JSON: %s", s)
		}
		out = append(out, m)
	}
	return out
}

// reuseLines returns the lines at level that name the kind of a reuse.
func reuseLines(t *testing.T, e *server.Env, level string) []logLine {
	t.Helper()
	var out []logLine
	for _, m := range logLines(t, e) {
		if m["level"] == level {
			if _, ok := m["kind"]; ok {
				out = append(out, m)
			}
		}
	}
	return out
}

// warnings returns every warning line of the service log.
func warnings(t *testing.T, e *server.Env) []logLine {
	t.Helper()
	var out []logLine
	for _, m := range logLines(t, e) {
		if m["level"] == "WARN" {
			out = append(out, m)
		}
	}
	return out
}

// realmAudit returns every audit row of the realm. A realm with no row yet
// (no login has run) has none.
func realmAudit(t *testing.T, e *server.Env) []store.AuditEvent {
	t.Helper()
	ctx := context.Background()
	var rows []store.AuditEvent
	err := e.Store.Read(ctx, func(tx store.Tx) error {
		rid, err := tx.Realms().Find(ctx, "main")
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		rows, err = tx.Audit().List(ctx, rid, time.Time{})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

// reuseRows returns the session.reuse_detected rows of the realm.
func reuseRows(t *testing.T, e *server.Env) []store.AuditEvent {
	t.Helper()
	var out []store.AuditEvent
	for _, row := range realmAudit(t, e) {
		if row.Action == "session.reuse_detected" {
			out = append(out, row)
		}
	}
	return out
}

// wantNoSecretsRecorded fails when the logs or the audit rows hold any of the
// secrets, or the SEC-13 values the log scan rejects.
func wantNoSecretsRecorded(t *testing.T, e *server.Env, secrets ...string) {
	t.Helper()
	logs := e.Logs.String()
	if !strings.Contains(logs, `"msg":"request"`) {
		t.Fatal("no request line, the scan would prove little")
	}
	for _, p := range logProblems(logs, secrets) {
		t.Error(p)
	}
	rows, err := json.Marshal(realmAudit(t, e))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range secrets {
		if s != "" && strings.Contains(string(rows), s) {
			t.Error("an audit row holds a secret")
		}
	}
}

// wantReuse checks the warning and the row of one reuse of the session of the
// ID token tk.
func wantReuse(t *testing.T, e *server.Env, tk server.Tokens, app server.App, kind string, warned, rows int) {
	t.Helper()
	sub := subOf(t, tk)
	sid, _ := decodeJWT(t, tk.IDToken).claims["sid"].(string)
	if got := reuseLines(t, e, "WARN"); len(got) != warned {
		t.Fatalf("%d reuse warnings, want %d: %v", len(got), warned, got)
	}
	if got := reuseRows(t, e); len(got) != rows {
		t.Fatalf("%d reuse rows, want %d", len(got), rows)
	}
	if warned == 0 {
		return
	}
	w := reuseLines(t, e, "WARN")[0]
	if w["user_id"] != sub || w["client"] != app.ID || w["session"] != sid || w["kind"] != kind {
		t.Fatalf("warning %v, want user %s, client %s, session %s, kind %s", w, sub, app.ID, sid, kind)
	}
	row := reuseRows(t, e)[0]
	if row.Actor != "system" || string(row.UserID) != sub || row.Details["client"] != app.ID ||
		row.Details["session"] != sid || row.Details["kind"] != kind {
		t.Fatalf("row %+v, want actor system, user %s, client %s, session %s, kind %s", row, sub, app.ID, sid, kind)
	}
}

// Covers: SEC-25
// Acceptance: Reuse records
func TestReuseRecords(t *testing.T) {
	t.Run("refresh token reused after the grace window twice", func(t *testing.T) {
		e := server.New(t)
		app := server.ClientQuery
		flowUser(e, "google", "301", "ann@example.com", true)
		tk := flowSignIn(t, e, app, "google")
		next := wantTokens(t, post(t, e, e.RefreshForm(app, tk.RefreshToken), nil))
		e.Clock.Advance(31 * time.Second) // the default refresh_reuse_grace is 30s

		wantError(t, post(t, e, e.RefreshForm(app, tk.RefreshToken), nil), 400, "invalid_grant")
		wantReuse(t, e, tk, app, "refresh_token", 1, 1)

		wantError(t, post(t, e, e.RefreshForm(app, tk.RefreshToken), nil), 400, "invalid_grant")
		wantReuse(t, e, tk, app, "refresh_token", 1, 1)
		if got := reuseLines(t, e, "INFO"); len(got) != 1 {
			t.Fatalf("%d information lines for the second reuse, want 1: %v", len(got), got)
		}
		wantNoSecretsRecorded(t, e, tk.RefreshToken, next.RefreshToken, tk.AccessToken, tk.IDToken)
	})

	t.Run("login code used twice", func(t *testing.T) {
		e := server.New(t)
		app := server.ClientQuery
		flowUser(e, "google", "302", "bob@example.com", true)
		res := e.NewClient().Login(t, server.Authorize(app, "google"))
		f := server.CodeForm(app, res)
		tk := wantTokens(t, post(t, e, f, nil))
		wantError(t, post(t, e, f, nil), 400, "invalid_grant")
		wantReuse(t, e, tk, app, "code", 1, 1)
		wantNoSecretsRecorded(t, e, res.Values.Get("code"), tk.RefreshToken, tk.AccessToken, tk.IDToken)
	})

	t.Run("refresh after logout", func(t *testing.T) {
		e := server.New(t)
		app := server.ClientQuery
		flowUser(e, "google", "303", "cy@example.com", true)
		tk := flowSignIn(t, e, app, "google")
		if r := logout(t, e, http.MethodPost, url.Values{"refresh_token": {tk.RefreshToken}, "client_id": {app.ID}}, nil); r.Code != http.StatusNoContent {
			t.Fatalf("logout: %d %s", r.Code, r.Body)
		}
		warned, rows := len(warnings(t, e)), len(reuseRows(t, e))
		wantError(t, post(t, e, e.RefreshForm(app, tk.RefreshToken), nil), 400, "invalid_grant")
		if got := len(warnings(t, e)); got != warned {
			t.Fatalf("%d warnings after the refresh, want none new", got-warned)
		}
		if got := len(reuseRows(t, e)); got != rows {
			t.Fatalf("%d reuse rows after the refresh, want none new", got-rows)
		}
		if got := reuseLines(t, e, "INFO"); len(got) != 1 {
			t.Fatalf("%d information lines, want 1: %v", len(got), got)
		}
		wantNoSecretsRecorded(t, e, tk.RefreshToken, tk.AccessToken, tk.IDToken)
	})

	for _, tc := range []struct {
		name   string
		form   url.Values
		h      http.Header
		status int // 401 for the Basic header, 400 for a secret in the body or none
	}{
		{"wrong secret", nil, basic(server.ClientConfidential.ID, "not-the-secret-7f3a"), http.StatusUnauthorized},
		{"missing secret", url.Values{"client_id": {server.ClientConfidential.ID}}, nil, http.StatusBadRequest},
	} {
		t.Run("confidential client, "+tc.name, func(t *testing.T) {
			e := server.New(t)
			app := server.ClientConfidential
			form := tc.form
			if form == nil {
				form = url.Values{}
			}
			form.Set("grant_type", "authorization_code")
			wantError(t, post(t, e, form, tc.h), tc.status, "invalid_client")
			if got := warnings(t, e); len(got) != 1 || got[0]["client"] != app.ID || got[0]["kind"] != nil {
				t.Fatalf("warnings %v, want one naming client %s", got, app.ID)
			}
			if got := reuseRows(t, e); len(got) != 0 {
				t.Fatalf("%d reuse rows for a failed authentication, want none", len(got))
			}
			wantNoSecretsRecorded(t, e, "not-the-secret-7f3a", e.Secret(app.ID))
		})
	}

	t.Run("logout with a wrong secret of a confidential client", func(t *testing.T) {
		e := server.New(t)
		app := server.ClientConfidential
		form := url.Values{"refresh_token": {"made-up"}, "client_id": {app.ID}, "client_secret": {"not-the-secret-7f3a"}}
		if r := logout(t, e, http.MethodPost, form, nil); r.Code != http.StatusBadRequest {
			t.Fatalf("logout: %d %s", r.Code, r.Body)
		}
		if got := warnings(t, e); len(got) != 1 || got[0]["client"] != app.ID {
			t.Fatalf("warnings %v, want one naming client %s", got, app.ID)
		}
		wantNoSecretsRecorded(t, e, "not-the-secret-7f3a", e.Secret(app.ID))
	})

	t.Run("the row fails to write: the refusal stays and the failure is logged", func(t *testing.T) {
		e := server.New(t)
		app := server.ClientQuery
		flowUser(e, "google", "304", "dee@example.com", true)
		tk := flowSignIn(t, e, app, "google")
		next := wantTokens(t, post(t, e, e.RefreshForm(app, tk.RefreshToken), nil))
		e.Clock.Advance(31 * time.Second)
		e.Faults.Fail("Audit.Insert", errors.New("disk full"))
		wantError(t, post(t, e, e.RefreshForm(app, tk.RefreshToken), nil), 400, "invalid_grant")
		if got := reuseLines(t, e, "WARN"); len(got) != 1 {
			t.Fatalf("%d warnings, want 1", len(got))
		}
		if got := logLines(t, e); !hasLevel(got, "ERROR") {
			t.Fatal("no error line for the row that could not be written")
		}
		// The revocation was committed before the row failed.
		wantRevoked(t, e, app, next.RefreshToken)
		wantNoSecretsRecorded(t, e, tk.RefreshToken, next.RefreshToken, tk.AccessToken, tk.IDToken)
	})
}

// hasLevel reports whether one of the lines is at level.
func hasLevel(lines []logLine, level string) bool {
	for _, m := range lines {
		if m["level"] == level {
			return true
		}
	}
	return false
}

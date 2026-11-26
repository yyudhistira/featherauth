package provider

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/logx"
)

// A URL with a query in the error of a warning must not reach the log: the
// warning passes the error under err, so logx cleans the URL (SR-12).
//
// Covers: SEC-13 (part), SEC-26 (part)
func TestRegistryWarningHidesURLQueries(t *testing.T) {
	clk := clock.NewFake(time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC))
	var buf bytes.Buffer
	pool := &Pool{clk: clk, log: logx.New(&buf, slog.LevelDebug, clk)}
	// The discovery URL is this issuer with the path appended, so the marker
	// sits in the query of the URL the connection error names.
	e := &entry{realm: "main", key: "corp", spec: spec{kind: "oidc", oidc: OIDCOptions{
		Issuer: "http://127.0.0.1:1/?token=query-marker", ClientID: "client", ClientSecret: "secret",
		RedirectURI: "https://featherauth.example/cb", Timeout: time.Second, Clock: clk,
	}}}
	if a := e.provider(pool); a != nil {
		t.Fatal("an adapter was built from an unreachable issuer")
	}
	logs := buf.String()
	if !strings.Contains(logs, `"msg":"provider not available"`) {
		t.Fatalf("no warning in the log:\n%s", logs)
	}
	if !strings.Contains(logs, `"err":`) || strings.Contains(logs, `"reason":`) {
		t.Errorf("the warning must pass the error under err, not reason:\n%s", logs)
	}
	if strings.Contains(logs, "query-marker") {
		t.Errorf("the query of a URL in the error reached the log:\n%s", logs)
	}
}

package oidc

import (
	"encoding/json"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/store"
)

// Covers: FR-42 (part)
// Acceptance: Sessions endpoint (part)
func TestSessionEntryIsTheCLISessionPlusCurrent(t *testing.T) {
	at := time.Date(2026, 3, 1, 10, 0, 0, 0, time.FixedZone("UTC+1", 3600))
	live := store.LiveSession{
		SessionID: "s1", ClientID: config.ClientID("app"),
		StartedAt: at, AuthTime: at, LastUsedAt: at, ExpiresAt: at.Add(time.Hour),
	}
	fields, err := json.Marshal(SessionFieldsOf(live))
	if err != nil {
		t.Fatal(err)
	}
	entry, err := json.Marshal(sessionView{SessionFields: SessionFieldsOf(live), Current: true})
	if err != nil {
		t.Fatal(err)
	}
	var f, e map[string]any
	if err := json.Unmarshal(fields, &f); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(entry, &e); err != nil {
		t.Fatal(err)
	}
	keys := func(m map[string]any) []string {
		var out []string
		for k := range m {
			out = append(out, k)
		}
		slices.Sort(out)
		return out
	}
	want := append(keys(f), "current")
	slices.Sort(want)
	if got := keys(e); !reflect.DeepEqual(got, want) {
		t.Fatalf("entry keys %v, want the CLI keys plus current: %v", got, want)
	}
	for k, v := range f {
		if e[k] != v {
			t.Errorf("%s: entry %v, CLI %v", k, e[k], v)
		}
	}
	if e["started_at"] != "2026-03-01T09:00:00Z" {
		t.Errorf("times are not UTC: %v", e["started_at"])
	}
}

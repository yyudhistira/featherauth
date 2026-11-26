package store_test

import (
	"strings"
	"testing"
	"time"
	_ "time/tzdata" // the zone database, so the test runs on every machine

	"github.com/yyudhistira/featherauth/internal/clock"
)

// setLocal makes zone the server's local time for the test. These tests change
// the global time.Local, so they must not run in parallel with others.
func setLocal(t *testing.T, zone string) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation(zone)
	if err != nil {
		t.Fatal(err)
	}
	old := time.Local
	time.Local = loc
	t.Cleanup(func() { time.Local = old })
	return loc
}

// Across a spring-forward day (02:30 does not exist) and a fall-back day
// (02:30 happens twice) the schedule writes exactly one snapshot a day.
//
// Covers: FR-24 (part)
func TestBackupScheduleAcrossDaylightSavingChanges(t *testing.T) {
	loc := setLocal(t, "Europe/Amsterdam")
	for _, tc := range []struct {
		name  string
		start time.Time // noon local, the day before the change
		days  []string  // the local dates that must each have one snapshot
		names string    // the file names: the skipped 02:30 runs at 03:30, the repeated one once
	}{
		{"spring forward", time.Date(2026, 3, 28, 12, 0, 0, 0, loc), []string{"20260329", "20260330", "20260331"},
			want("featherauth-20260329-0330.db", "featherauth-20260330-0230.db", "featherauth-20260331-0230.db")},
		{"fall back", time.Date(2026, 10, 24, 12, 0, 0, 0, loc), []string{"20261025", "20261026", "20261027"},
			want("featherauth-20261025-0230.db", "featherauth-20261026-0230.db", "featherauth-20261027-0230.db")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newSchedEnv(t)
			e.clock = clock.NewFake(tc.start.UTC())
			e.start(t, "02:30", 30)
			for range 3 * 48 { // three days in half-hour steps, so no instant is jumped over
				e.clock.Advance(30 * time.Minute)
			}
			byDay := map[string][]string{}
			for _, f := range e.files(t) {
				// featherauth-YYYYMMDD-HHMM.db
				byDay[f[len("featherauth-"):len("featherauth-")+8]] = append(byDay[f[len("featherauth-"):len("featherauth-")+8]], f)
			}
			for _, d := range tc.days {
				if len(byDay[d]) != 1 {
					t.Errorf("day %s: snapshots %v (all: %v)", d, byDay[d], e.files(t))
				}
			}
			if got := want(e.files(t)...); got != tc.names {
				t.Errorf("files %s, want %s", got, tc.names)
			}
			if strings.Contains(e.log.String(), "backup failed") {
				t.Errorf("a snapshot failed: %s", e.log.String())
			}
		})
	}
}

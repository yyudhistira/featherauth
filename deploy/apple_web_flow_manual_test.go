//go:build manual

package deploy_test

import (
	"os"
	"strings"
	"testing"
)

// The table of the subsection "Apple web flow" in the browser section of
// docs/RESULTS.md records the manual runs of the check M4 (docs/RELEASING.md). Until the owner
// has run every row, the test fails: each row needs a date, a device or browser
// with its version, and a result, and "not yet recorded" is not a result. Notes
// may stay empty. The test is behind the build tag manual, so make check does
// not run it (no make target runs it either; the owner runs it after the runs
// with go test -tags manual ./deploy/ -run TestAppleWebFlowResultsRecorded).
//
// The table is complete, so this test has the full tag and the row is not in
// pending.txt.
//
// Covers: FR-05, SEC-08
// Acceptance: Apple web flow on devices
func TestAppleWebFlowResultsRecorded(t *testing.T) {
	b, err := os.ReadFile("../docs/RESULTS.md")
	if err != nil {
		t.Fatal(err)
	}
	browser := section(string(b), "Browser")
	if browser == "" {
		t.Fatal("docs/RESULTS.md has no section \"## Browser\"")
	}
	body := subsection(browser, "Apple web flow")
	if body == "" {
		t.Fatal("the browser section of docs/RESULTS.md has no subsection \"### Apple web flow\"")
	}
	rows := 0
	for _, line := range strings.Split(body, "\n") {
		if !strings.HasPrefix(line, "|") || strings.HasPrefix(line, "| Run ") || strings.HasPrefix(line, "| ---") {
			continue
		}
		cells := strings.Split(strings.Trim(line, "|"), "|")
		if len(cells) != 5 {
			t.Errorf("row has %d cells, want 5 (Run, Device, Date, Result, Notes): %s", len(cells), line)
			continue
		}
		rows++
		run := strings.TrimSpace(cells[0])
		if strings.TrimSpace(cells[1]) == "" {
			t.Errorf("%s: the Device, OS or browser cell is empty", run)
		}
		if strings.TrimSpace(cells[2]) == "" {
			t.Errorf("%s: the Date cell is empty", run)
		}
		if res := strings.TrimSpace(cells[3]); res == "" || res == "not yet recorded" {
			t.Errorf("%s: the Result cell is not recorded (%q)", run, res)
		}
	}
	if rows == 0 {
		t.Error("the table of \"Apple web flow on devices\" has no rows")
	}
}

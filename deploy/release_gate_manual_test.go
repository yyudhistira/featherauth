//go:build manual

package deploy_test

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The release gate section of docs/RESULTS.md records the checks of one release:
// the items 1 to 13 of `make release-check` and the manual checks M1 to M6
// (docs/RELEASING.md), each with its result, and the table of the release tags
// with their commits and image digests. Until every check has a result, this
// test fails: each of the nineteen rows needs a result of one of the five forms
// docs/RELEASING.md defines and a detail (the rules are in gateTableProblems, which
// release_gate_values_test.go tests under make check). The test is behind the build
// tag manual, so make check does not run it (the same precedent as
// TestAppleWebFlowResultsRecorded); the maintainer runs it after the checks with
// go test -tags manual ./deploy/ -run TestReleaseGateResultsRecorded.
//
// The signing and attestation results are in the rows 11 and 12 and are the manual
// pass conditions of the row "Signed images"; the other conditions are asserted by
// the workflow and compose tests of deploy/signing_test.go and by TestOpsCheckImage.
//
// Covers: SEC-42
// Acceptance: Signed images
func TestReleaseGateResultsRecorded(t *testing.T) {
	b, err := os.ReadFile("../docs/RESULTS.md")
	if err != nil {
		t.Fatal(err)
	}
	gate := section(string(b), "Release gate")
	if gate == "" {
		t.Fatal("docs/RESULTS.md has no section \"## Release gate\"")
	}
	if !regexp.MustCompile(`(?m)^- Release: v\d+\.\d+\.\d+$`).MatchString(gate) {
		t.Error("no line '- Release: vX.Y.Z'")
	}
	if !regexp.MustCompile(`(?m)^- Commit: [0-9a-f]{40}$`).MatchString(gate) {
		t.Error("no line '- Commit: <40-character hash of the release commit>'")
	}
	if !regexp.MustCompile(`(?m)^- Date: \d{4}-\d{2}-\d{2}$`).MatchString(gate) {
		t.Error("no line '- Date: YYYY-MM-DD'")
	}
	tags := subsection(gate, "Release tags")
	table := strings.TrimSuffix(gate, tags)
	if tags == "" {
		t.Error("no subsection \"### Release tags\"")
		table = gate
	}

	for _, p := range gateTableProblems(table) {
		t.Error(p)
	}

	digest := regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	hash := regexp.MustCompile(`^[0-9a-f]{40}$`)
	rows := 0
	for _, line := range strings.Split(tags, "\n") {
		if !strings.HasPrefix(line, "|") || strings.HasPrefix(line, "| Tag ") || strings.HasPrefix(line, "| ---") {
			continue
		}
		cells := strings.Split(strings.Trim(line, "|"), "|")
		if len(cells) != 3 {
			t.Errorf("tag row has %d cells, want 3 (Tag, Commit, Image digest): %s", len(cells), line)
			continue
		}
		rows++
		if !regexp.MustCompile(`^v\d+\.\d+\.\d+$`).MatchString(strings.TrimSpace(cells[0])) {
			t.Errorf("tag %q is not vMAJOR.MINOR.PATCH", strings.TrimSpace(cells[0]))
		}
		if !hash.MatchString(strings.TrimSpace(cells[1])) {
			t.Errorf("tag %s: the commit is not a 40-character hash", strings.TrimSpace(cells[0]))
		}
		if !digest.MatchString(strings.TrimSpace(cells[2])) {
			t.Errorf("tag %s: the image digest is not sha256:<64 hex digits>", strings.TrimSpace(cells[0]))
		}
	}
	if rows == 0 {
		t.Error("the table of release tags has no rows")
	}
}

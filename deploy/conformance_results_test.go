package deploy_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The conformance section of docs/RESULTS.md records the date, the commit and
// the suite version of the run, and a reason for every failure, warning and
// skipped test that the conformance setup lists as expected. It is a mapped condition of
// TestConformanceSuite (build tag conformance), which runs the plans.
func TestConformanceResultsRecordSuiteVersion(t *testing.T) {
	b, err := os.ReadFile("../docs/RESULTS.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := section(string(b), "Conformance")
	if doc == "" {
		t.Fatal("docs/RESULTS.md has no section \"## Conformance\"")
	}
	if !regexp.MustCompile(`(?m)^- Date: \d{4}-\d{2}-\d{2}$`).MatchString(doc) {
		t.Error("no line '- Date: YYYY-MM-DD'")
	}
	if !regexp.MustCompile(`(?m)^- Commit: [0-9a-f]{40}$`).MatchString(doc) {
		t.Error("no line '- Commit: <40-character hash>'")
	}
	if !strings.Contains(doc, "release-v5.3.4") {
		t.Error("the suite version release-v5.3.4 is not recorded")
	}
	compose, err := os.ReadFile("conformance/compose.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(compose), "conformance-suite:release-v5.3.4@sha256:") {
		t.Error("compose.yaml does not pin the suite release by digest")
	}
	var entries []struct {
		Test    string `json:"test-name"`
		Comment string `json:"comment"`
	}
	files, err := filepath.Glob("conformance/expected/*.json")
	if err != nil || len(files) == 0 {
		t.Fatalf("no expected files: %v", err)
	}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var part []struct {
			Test    string `json:"test-name"`
			Comment string `json:"comment"`
		}
		if err := json.Unmarshal(raw, &part); err != nil {
			t.Fatal(err)
		}
		entries = append(entries, part...)
	}
	if len(entries) == 0 {
		t.Fatal("no expected entries")
	}
	for _, e := range entries {
		if !strings.Contains(doc, "`"+e.Test+"`") {
			t.Errorf("%s is expected but has no entry in the conformance section of RESULTS.md", e.Test)
		}
		if e.Comment == "" {
			t.Errorf("%s has no comment", e.Test)
		}
	}
}

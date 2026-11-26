package deploy_test

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The load section of docs/RESULTS.md records the date, the commit, the machine
// and the tools of the load run, and, for each driver, a subsection for every
// scenario of the Load verification. It is a mapped condition of
// TestLoadScenarios (build tag load), which runs them.
func TestLoadResultsRecorded(t *testing.T) {
	b, err := os.ReadFile("../docs/RESULTS.md")
	if err != nil {
		t.Fatal(err)
	}
	load := section(string(b), "Load")
	if load == "" {
		t.Fatal("docs/RESULTS.md has no section \"## Load\"")
	}
	if !regexp.MustCompile(`(?m)^- Date: \d{4}-\d{2}-\d{2}$`).MatchString(load) {
		t.Error("no line '- Date: YYYY-MM-DD'")
	}
	if !regexp.MustCompile(`(?m)^- Commit: [0-9a-f]{40}$`).MatchString(load) {
		t.Error("no line '- Commit: <40-character hash>'")
	}
	if !regexp.MustCompile(`(?m)^- Machine: .+`).MatchString(load) {
		t.Error("no line '- Machine: <description>'")
	}
	compose, err := os.ReadFile("load/compose.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(compose), "grafana/k6:1.4.2@sha256:") || !regexp.MustCompile(`(?m)^- Tools: .*k6 1\.4\.2`).MatchString(load) {
		t.Error("k6 is not pinned by version and digest in compose.yaml, or its version is not on the Tools line")
	}
	// Each driver has its own subsection, with a subsection for every scenario
	// of the Load verification.
	for _, driver := range []string{"SQLite", "Postgres"} {
		d := subsection(load, driver)
		if d == "" {
			t.Errorf("no subsection \"### %s\"", driver)
			continue
		}
		for _, h := range []string{"Targets", "Idle", "Steady", "Peak", "Burst", "Restart under load", "Soak", "Rate limiter", "Restart loops"} {
			if !strings.Contains(d, "\n#### "+h+"\n") {
				t.Errorf("%s: no subsection %q", driver, "#### "+h)
			}
		}
	}
}

// section returns the text of the level-two section named name of doc, from its
// heading to the next level-two heading or the end, or "" when there is none.
func section(doc, name string) string {
	return headed(doc, "\n## "+name+"\n", "\n## ")
}

// subsection returns the text of the level-three subsection named name of a
// section, from its heading to the next level-three heading or the end, or ""
// when there is none.
func subsection(sec, name string) string {
	return headed(sec, "\n### "+name+"\n", "\n### ")
}

func headed(doc, heading, next string) string {
	start := strings.Index(doc, heading)
	if start < 0 {
		return ""
	}
	body := doc[start+1:]
	if end := strings.Index(body[len(heading)-1:], next); end >= 0 {
		return body[:len(heading)-1+end]
	}
	return body
}

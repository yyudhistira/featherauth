package deploy_test

import (
	"regexp"
	"slices"
	"testing"
)

// The postgres job of ci.yml runs make postgres once for each matrix version:
// 15, the oldest supported, and 18, the newest stable major. Its if is the one
// of the browser and ops jobs (documentation-only and pending.txt skips).
//
// Covers: FR-35 (part)
// Acceptance: Postgres store (part)
func TestCIPostgresJob(t *testing.T) {
	w, _ := readWorkflow(t, "ci.yml")
	j, ok := w.Jobs["postgres"]
	if !ok {
		t.Fatal("ci.yml has no postgres job")
	}
	if !j.needs("changes") {
		t.Error("postgres does not need changes")
	}
	if j.RunsOn != runnerExpr {
		t.Errorf("runs-on = %q", j.RunsOn)
	}
	for _, name := range []string{"browser", "ops"} {
		if got, want := j.If, w.Jobs[name].If; got != want {
			t.Errorf("postgres if = %q, want the if of %s: %q", got, name, want)
		}
	}
	if len(j.Strategy.Matrix) != 1 {
		t.Fatalf("matrix = %v, want exactly one key", j.Strategy.Matrix)
	}
	if got, want := j.Strategy.Matrix["postgres"], []string{"15", "18"}; !slices.Equal(got, want) {
		t.Errorf("matrix postgres = %v, want %v", got, want)
	}

	const cmd = `make postgres POSTGRES_VERSION="$POSTGRES_VERSION"`
	if !j.runs(cmd) {
		t.Fatalf("postgres does not run %q", cmd)
	}
	i := stepIndex(j, func(s workflowStep) bool { return s.Env["POSTGRES_VERSION"] == "${{ matrix.postgres }}" })
	if i < 0 || j.Steps[i].Run != cmd {
		t.Errorf("the step that runs make postgres does not take POSTGRES_VERSION from the matrix: %+v", j.Steps)
	}

	mk := readFile(t, "../Makefile")
	if !regexp.MustCompile(`(?m)^postgres:\n`).MatchString(mk) {
		t.Error("the Makefile has no postgres target")
	}
	if !regexp.MustCompile(`(?m)^POSTGRES_VERSION \?= 18$`).MatchString(mk) {
		t.Error("the Makefile default POSTGRES_VERSION is not 18")
	}
}

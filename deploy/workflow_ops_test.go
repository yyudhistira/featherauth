//go:build ops

package deploy_test

import (
	"os/exec"
	"path/filepath"
	"regexp"
	"testing"
)

// actionlint 1.7.12 (pinned by digest) checks the workflow files for errors.
//
// Acceptance: Deploy (part)
func TestOpsActionlint(t *testing.T) {
	dir, err := filepath.Abs(filepath.Join("..", ".github", "workflows"))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), "docker", "run", "--rm", "-v", dir+":/wf:ro",
		"-w", "/wf", "rhysd/actionlint@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667", "-no-color", "ci.yml", "deploy.yml")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("actionlint: %v\n%s", err, out)
	}
}

// govulncheck is clean, and CI runs it: the ci.yml check job runs make check,
// which depends on make vuln, which runs govulncheck over every package.
//
// Covers: SEC-15
// Acceptance: Dependencies
func TestOpsGovulncheckCleanAndRunByCI(t *testing.T) {
	cmd := exec.CommandContext(t.Context(), "go", "tool", "govulncheck", "./...")
	cmd.Dir = ".."
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("govulncheck: %v\n%s", err, out)
	}
	mk := readFile(t, "../Makefile")
	if !regexp.MustCompile(`(?m)^check:.*\bvuln\b`).MatchString(mk) {
		t.Error("make check does not depend on vuln")
	}
	if !regexp.MustCompile(`(?m)^vuln:\n\t.*tool govulncheck \$\(PKGS\)`).MatchString(mk) {
		t.Error("make vuln does not run govulncheck over $(PKGS)")
	}
	w, _ := readWorkflow(t, "ci.yml")
	if !w.Jobs["check"].runs("make check") {
		t.Error("the ci.yml check job does not run make check")
	}
	if _, ok := w.On["pull_request"]; !ok {
		t.Error("ci.yml does not run on pull requests")
	}
	d, _ := readWorkflow(t, "deploy.yml")
	if d.Jobs["checks"].Uses != "./.github/workflows/ci.yml" {
		t.Error("deploy.yml does not run the ci.yml checks")
	}
}

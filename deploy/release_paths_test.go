package deploy_test

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// gateCheckPaths maps the rows of the release gate that can be recorded as
// `no change since <hash>` to the check name in deploy/release-paths.txt.
var gateCheckPaths = map[string]string{
	"7": "conformance", "8": "load", "M3": "browser", "M4": "apple", "M5": "tls", "M6": "workflow",
}

var (
	gateCommitLine = regexp.MustCompile(`^- Commit: ([0-9a-f]{40})\s*$`)
	gateRowNoCh    = regexp.MustCompile(`^\|\s*([^|\s]+)\s*\|\s*no change since ([0-9a-f]{40})\s*\|`)
)

// readReleasePaths reads deploy/release-paths.txt: check name -> paths.
func readReleasePaths(t *testing.T, file string) map[string][]string {
	t.Helper()
	f, err := os.Open(file)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	out := map[string][]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			t.Fatalf("%s: the line %q has no paths", file, line)
		}
		out[fields[0]] = fields[1:]
	}
	return out
}

func gitOut(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// noChangeProblems checks every `no change since <hash>` cell of the release
// gate section of results (the text of docs/RESULTS.md) against the git history
// in repo: the paths of that check must not differ between the hash and the
// release commit the section names. A cell for a row without a path list, a
// hash git does not know, or a missing release commit is a problem too.
func noChangeProblems(t *testing.T, repo string, paths map[string][]string, results string) []string {
	t.Helper()
	var problems []string
	in := false
	release := ""
	for _, line := range strings.Split(results, "\n") {
		if strings.HasPrefix(line, "## ") {
			in = strings.TrimSpace(strings.TrimPrefix(line, "## ")) == "Release gate"
			continue
		}
		if !in {
			continue
		}
		if m := gateCommitLine.FindStringSubmatch(line); m != nil && release == "" {
			release = m[1]
		}
		m := gateRowNoCh.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		row, hash := m[1], m[2]
		name, ok := gateCheckPaths[row]
		if !ok {
			problems = append(problems, fmt.Sprintf("check %s is recorded as no change since %s, but it has no path list in deploy/release-paths.txt", row, hash))
			continue
		}
		pl, ok := paths[name]
		if !ok {
			problems = append(problems, fmt.Sprintf("check %s (%s) has no line in deploy/release-paths.txt", row, name))
			continue
		}
		if release == "" {
			problems = append(problems, fmt.Sprintf("check %s: the release gate section names no release commit", row))
			continue
		}
		known := true
		for _, h := range []string{hash, release} {
			if _, err := gitOut(repo, "cat-file", "-e", h+"^{commit}"); err != nil {
				known = false
				problems = append(problems, fmt.Sprintf("check %s: the commit %s is not in the repository history (a shallow clone? CI checks out with fetch-depth: 0)", row, h))
			}
		}
		if !known {
			continue
		}
		out, err := gitOut(repo, append([]string{"diff", "--name-only", hash, release, "--"}, pl...)...)
		if err != nil {
			problems = append(problems, fmt.Sprintf("check %s: git diff failed: %v: %s", row, err, strings.TrimSpace(out)))
			continue
		}
		if changed := strings.Fields(out); len(changed) > 0 {
			problems = append(problems, fmt.Sprintf("check %s (%s) is recorded as no change since %s, but these paths changed up to %s: %s", row, name, hash, release, strings.Join(changed, " ")))
		}
	}
	return problems
}

// fixtureRepo makes a git repository with three commits and returns their
// hashes: base, a change outside every path list (docs), and a change of
// internal/provider (the apple and the conformance and load paths).
func fixtureRepo(t *testing.T) (dir, base, docs, code string) {
	t.Helper()
	dir = t.TempDir()
	run := func(args ...string) string {
		t.Helper()
		out, err := gitOut(dir, append([]string{"-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false"}, args...)...)
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(out)
	}
	write := func(name, body string) {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	run("init", "-q")
	write("internal/provider/a.go", "package a\n")
	write("internal/web/w.go", "package w\n")
	write("notes.txt", "one\n")
	run("add", ".")
	run("commit", "-qm", "base")
	base = run("rev-parse", "HEAD")
	write("notes.txt", "two\n")
	run("commit", "-qam", "docs")
	docs = run("rev-parse", "HEAD")
	write("internal/provider/a.go", "package a // changed\n")
	run("commit", "-qam", "code")
	code = run("rev-parse", "HEAD")
	return dir, base, docs, code
}

func gateSection(release string, rows ...string) string {
	return "# Results\n\n## Release gate\n\n- Release: v1.0.0\n- Commit: " + release + "\n- Date: 2026-11-24\n\n| Check | Result | Detail |\n| --- | --- | --- |\n" +
		strings.Join(rows, "\n") + "\n\n### Release tags\n"
}

// Acceptance: No-change claims
// Also proves NFR-13 (not traced).
func TestNoChangeClaims(t *testing.T) {
	repo, base, docs, code := fixtureRepo(t)
	paths := readReleasePaths(t, "release-paths.txt")
	for _, name := range []string{"conformance", "load", "browser", "apple", "tls", "workflow"} {
		if len(paths[name]) == 0 {
			t.Fatalf("deploy/release-paths.txt has no paths for %s", name)
		}
	}
	unknown := strings.Repeat("0", 40)
	for _, c := range []struct {
		name, results string
		want          string // substring of a problem; "" means none
	}{
		{"unchanged paths pass", gateSection(docs, "| M3 | no change since "+base+" | x |", "| M4 | no change since "+base+" | x |"), ""},
		{"a section with no claim passes", gateSection(code, "| M4 | pass | x |", "| 7 | pass | x |"), ""},
		{"a changed path fails and names the check and the path", gateSection(code, "| M4 | no change since "+base+" | x |"), "check M4 (apple) is recorded as no change since " + base + ", but these paths changed up to " + code + ": internal/provider/a.go"},
		{"the conformance paths changed", gateSection(code, "| 7 | no change since "+docs+" | x |"), "internal/provider/a.go"},
		{"a later commit does not matter", gateSection(docs, "| M4 | no change since "+base+" | x |"), ""},
		{"the claim after the change passes", gateSection(code, "| M4 | no change since "+code+" | x |"), ""},
		{"a cell of a check with no path list fails", gateSection(code, "| 3 | no change since "+base+" | x |"), "check 3 is recorded as no change"},
		{"an unknown commit fails", gateSection(code, "| M3 | no change since "+unknown+" | x |"), "not in the repository history"},
		{"an unknown release commit fails", gateSection(unknown, "| M3 | no change since "+base+" | x |"), "not in the repository history"},
		{"other sections are not read", "## Load\n\n| M4 | no change since " + base + " | x |\n" + gateSection(code), ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := noChangeProblems(t, repo, paths, c.results)
			joined := strings.Join(p, "\n")
			if c.want == "" && len(p) != 0 {
				t.Fatalf("unexpected problems: %s", joined)
			}
			if c.want != "" && !strings.Contains(joined, c.want) {
				t.Fatalf("problems %q do not contain %q", joined, c.want)
			}
		})
	}
}

// The release gate section of docs/RESULTS.md as it is: every `no change since`
// claim holds against the git history of this repository. A claimed commit that
// is not in the history (a shallow clone) fails the test; it is never skipped.
//
// Acceptance: No-change claims hold
// Also proves NFR-13 (not traced).
func TestReleaseGateNoChangeClaimsHold(t *testing.T) {
	b, err := os.ReadFile("../docs/RESULTS.md")
	if err != nil {
		t.Fatal(err)
	}
	if p := noChangeProblems(t, "..", readReleasePaths(t, "release-paths.txt"), string(b)); len(p) != 0 {
		t.Fatal(strings.Join(p, "\n"))
	}
}

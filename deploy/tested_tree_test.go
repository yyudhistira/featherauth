package deploy_test

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The tested-tree script is run against a fake gh. The fake answers by
// endpoint from canned JSON files and applies the --jq expression with jq, so
// the expressions of the script are tested too (jq must be installed; the
// GitHub runners have it). The fake logs every call.

const (
	ttRepo  = "owner/name"
	ttSHA   = "0123456789abcdef0123456789abcdef01234567"
	ttHead  = "89abcdef0123456789abcdef0123456789abcdef"
	ttTree  = "fedcba9876543210fedcba9876543210fedcba98"
	ttOther = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	ttBot   = "github-actions[bot]"
	// A title that must never reach the output of the script.
	ttTitle = "TITLE-MUST-NOT-LEAK"
)

type ttCase struct {
	files map[string]string // pulls, statuses, commit, runs -> JSON
	fail  []string          // answers for which gh exits 1
}

func ttPulls(prs ...string) string { return "[" + strings.Join(prs, ",") + "]" }

func ttPR(merged bool, mergeSHA, head string) string {
	m := "null"
	if merged {
		m = `"2026-11-01T10:00:00Z"`
	}
	ms := "null"
	if mergeSHA != "" {
		ms = `"` + mergeSHA + `"`
	}
	return `{"number":1,"title":"` + ttTitle + `","merged_at":` + m + `,"merge_commit_sha":` + ms + `,"head":{"sha":"` + head + `"}}`
}

func ttStatus(id int, ctx, state, login, desc string) string {
	return `{"id":` + itoa(id) + `,"context":"` + ctx + `","state":"` + state + `","description":"` + desc +
		`","created_at":"2026-11-01T10:00:00Z","creator":{"login":"` + login + `"}}`
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	for ; n > 0; n /= 10 {
		s = string(rune('0'+n%10)) + s
	}
	return s
}

func ttCommit(tree string) string { return `{"sha":"` + ttSHA + `","tree":{"sha":"` + tree + `"}}` }

func ttRun(branch, conclusion, sha string) string {
	return `{"head_branch":"` + branch + `","conclusion":"` + conclusion + `","head_sha":"` + sha + `","event":"push"}`
}

func ttRuns(runs ...string) string {
	return `{"total_count":` + itoa(len(runs)) + `,"workflow_runs":[` + strings.Join(runs, ",") + `]}`
}

func goodBranch() ttCase {
	return ttCase{files: map[string]string{
		"pulls":    ttPulls(ttPR(true, ttSHA, ttHead)),
		"statuses": "[" + ttStatus(2, "ci/tested-tree", "success", ttBot, ttTree) + "]",
		"commit":   ttCommit(ttTree),
	}}
}

func (c ttCase) with(key, body string) ttCase {
	m := map[string]string{}
	for k, v := range c.files {
		m[k] = v
	}
	m[key] = body
	return ttCase{files: m, fail: c.fail}
}

func (c ttCase) failing(keys ...string) ttCase { return ttCase{files: c.files, fail: keys} }

func fakeGH(t *testing.T, c ttCase) (path, dir string) {
	t.Helper()
	if _, err := exec.LookPath("jq"); err != nil {
		t.Fatalf("jq is needed by the fake gh of these tests: %v", err)
	}
	dir = t.TempDir()
	for k, v := range c.files {
		if err := os.WriteFile(filepath.Join(dir, k+".json"), []byte(v), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, k := range c.fail {
		if err := os.WriteFile(filepath.Join(dir, k+".fail"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	script := `#!/bin/sh
d="` + dir + `"
[ "$1" = api ] || { echo "fake gh: only api" >&2; exit 64; }
ep=$2
echo "$ep" >> "$d/calls.log"
jq_expr=
if [ "${3:-}" = --jq ]; then jq_expr=$4; elif [ "$#" -ne 2 ]; then echo "fake gh: bad arguments" >&2; exit 64; fi
case "$ep" in
  repos/*/commits/*/pulls*) k=pulls ;;
  repos/*/commits/*/statuses*) k=statuses ;;
  repos/*/git/commits/*) k=commit ;;
  repos/*/actions/workflows/deploy.yml/runs\?*) k=runs ;;
  *) echo "fake gh: unknown endpoint $ep" >&2; exit 64 ;;
esac
[ ! -e "$d/$k.fail" ] || { echo "fake gh: HTTP 500" >&2; exit 1; }
[ -e "$d/$k.json" ] || { echo "fake gh: no answer" >&2; exit 1; }
if [ -n "$jq_expr" ]; then jq -r "$jq_expr" "$d/$k.json"; else cat "$d/$k.json"; fi
`
	if err := os.WriteFile(filepath.Join(bin, "gh"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin + ":" + os.Getenv("PATH"), dir
}

type ttResult struct {
	stdout, stderr string
	code           int
	calls          string
	output         string // content of the GITHUB_OUTPUT file ("" when unset)
	outputSet      bool
}

func runTT(t *testing.T, c ttCase, withOutput bool, args ...string) ttResult {
	t.Helper()
	path, dir := fakeGH(t, c)
	cmd := exec.CommandContext(t.Context(), "sh", append([]string{"ops/tested-tree.sh"}, args...)...)
	env := append(os.Environ(), "PATH="+path, "GITHUB_OUTPUT=")
	outFile := filepath.Join(dir, "github_output")
	if withOutput {
		env = append(env, "GITHUB_OUTPUT="+outFile)
	}
	cmd.Env = env
	var so, se strings.Builder
	cmd.Stdout, cmd.Stderr = &so, &se
	err := cmd.Run()
	r := ttResult{stdout: so.String(), stderr: se.String()}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		r.code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	calls, _ := os.ReadFile(filepath.Join(dir, "calls.log"))
	r.calls = string(calls)
	if b, err := os.ReadFile(outFile); err == nil {
		r.output, r.outputSet = string(b), true
	}
	return r
}

func wantSkip(t *testing.T, r ttResult, skip bool) {
	t.Helper()
	want := "skip=false\n"
	if skip {
		want = "skip=true\n"
	}
	if r.code != 0 {
		t.Errorf("exit code %d, want 0\n%s", r.code, r.stderr)
	}
	if r.stdout != want {
		t.Errorf("stdout = %q, want %q", r.stdout, want)
	}
	if strings.Contains(r.stdout+r.stderr, ttTitle) {
		t.Errorf("API data reached the output: %q %q", r.stdout, r.stderr)
	}
}

// Proves OPS-02 (repeated checks): see the pass conditions of the row; OPS ids are not traced.
// Acceptance: Repeated checks (part)
func TestTestedTreeBranchEqualTreeSkips(t *testing.T) {
	r := runTT(t, goodBranch(), true, ttRepo, ttSHA, "branch")
	wantSkip(t, r, true)
	if r.output != "skip=true\n" {
		t.Errorf("GITHUB_OUTPUT = %q, want exactly skip=true", r.output)
	}
	// The status is read on the head commit of the pull request, the tree on the pushed commit.
	for _, want := range []string{
		"repos/" + ttRepo + "/commits/" + ttSHA + "/pulls",
		"repos/" + ttRepo + "/commits/" + ttHead + "/statuses",
		"repos/" + ttRepo + "/git/commits/" + ttSHA + "\n",
	} {
		if !strings.Contains(r.calls, want) {
			t.Errorf("gh was not called for %q:\n%s", want, r.calls)
		}
	}
}

// Proves OPS-02 (repeated checks): see the pass conditions of the row; OPS ids are not traced.
// Acceptance: Repeated checks (part)
func TestTestedTreeBranchRunsTheChecks(t *testing.T) {
	good := goodBranch()
	st := func(statuses ...string) string { return "[" + strings.Join(statuses, ",") + "]" }
	ok := ttStatus(2, "ci/tested-tree", "success", ttBot, ttTree)
	for _, tc := range []struct {
		name string
		c    ttCase
	}{
		{"no pull request (direct push)", good.with("pulls", "[]")},
		{"pull request not merged", good.with("pulls", ttPulls(ttPR(false, "", ttHead)))},
		{"unmerged with the same merge sha", good.with("pulls", ttPulls(ttPR(false, ttSHA, ttHead)))},
		{"merge commit differs", good.with("pulls", ttPulls(ttPR(true, ttOther, ttHead)))},
		{"two pull requests that disagree", good.with("pulls", ttPulls(ttPR(true, ttSHA, ttHead), ttPR(true, ttSHA, ttOther)))},
		{"merged one and an unmerged one", good.with("pulls", ttPulls(ttPR(true, ttOther, ttHead), ttPR(false, ttSHA, ttOther)))},
		{"no status", good.with("statuses", "[]")},
		{"status context other", good.with("statuses", st(ttStatus(2, "ci/other", "success", ttBot, ttTree)))},
		{"state failure", good.with("statuses", st(ttStatus(2, "ci/tested-tree", "failure", ttBot, ttTree)))},
		{"state pending", good.with("statuses", st(ttStatus(2, "ci/tested-tree", "pending", ttBot, ttTree)))},
		{"state error", good.with("statuses", st(ttStatus(2, "ci/tested-tree", "error", ttBot, ttTree)))},
		{"creator another login", good.with("statuses", st(ttStatus(2, "ci/tested-tree", "success", "someone", ttTree)))},
		{"creator login prefix", good.with("statuses", st(ttStatus(2, "ci/tested-tree", "success", "github-actions", ttTree)))},
		{"creator missing", good.with("statuses", `[{"id":2,"context":"ci/tested-tree","state":"success","description":"`+ttTree+`"}]`)},
		{"description uppercase", good.with("statuses", st(ttStatus(2, "ci/tested-tree", "success", ttBot, strings.ToUpper(ttTree)))).with("commit", ttCommit(strings.ToUpper(ttTree)))},
		{"description 39 characters", good.with("statuses", st(ttStatus(2, "ci/tested-tree", "success", ttBot, ttTree[:39]))).with("commit", ttCommit(ttTree[:39]))},
		{"description with extra text", good.with("statuses", st(ttStatus(2, "ci/tested-tree", "success", ttBot, ttTree+" x")))},
		{"description not hex", good.with("statuses", st(ttStatus(2, "ci/tested-tree", "success", ttBot, strings.Repeat("z", 40)))).with("commit", ttCommit(strings.Repeat("z", 40)))},
		{"description empty", good.with("statuses", st(ttStatus(2, "ci/tested-tree", "success", ttBot, ""))).with("commit", ttCommit(""))},
		{"description null", good.with("statuses", `[{"id":2,"context":"ci/tested-tree","state":"success","description":null,"creator":{"login":"`+ttBot+`"}}]`)},
		{"different tree", good.with("commit", ttCommit(ttOther))},
		{"tree missing", good.with("commit", `{"sha":"x"}`)},
		{"newest is failure, older success", good.with("statuses", st(
			ttStatus(3, "ci/tested-tree", "failure", ttBot, ttTree), ok))},
		{"newest is failure, listed last", good.with("statuses", st(
			ok, ttStatus(3, "ci/tested-tree", "failure", ttBot, ttTree)))},
		{"newest is by another creator", good.with("statuses", st(
			ttStatus(3, "ci/tested-tree", "success", "someone", ttTree), ok))},
		{"gh fails for the pull requests", good.failing("pulls")},
		{"gh fails for the statuses", good.failing("statuses")},
		{"gh fails for the commit", good.failing("commit")},
		{"pulls empty output", good.with("pulls", "")},
		{"statuses empty output", good.with("statuses", "")},
		{"commit empty output", good.with("commit", "")},
		{"pulls garbage", good.with("pulls", "<html>not json")},
		{"statuses garbage", good.with("statuses", "not json at all")},
		{"commit garbage", good.with("commit", "}{")},
		{"pulls is an object", good.with("pulls", `{"message":"Not Found"}`)},
		{"statuses is an object", good.with("statuses", `{"message":"Not Found"}`)},
		{"pulls hold null", good.with("pulls", "[null]")},
		{"pull request without head", good.with("pulls", `[{"merged_at":"2026-11-01T10:00:00Z","merge_commit_sha":"`+ttSHA+`"}]`)},
		{"head sha not hex", good.with("pulls", ttPulls(ttPR(true, ttSHA, "../../x")))},
		{"head sha with extra text", good.with("pulls", ttPulls(ttPR(true, ttSHA, ttHead+"\\nskip=true")))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := runTT(t, tc.c, true, ttRepo, ttSHA, "branch")
			wantSkip(t, r, false)
			if r.output != "skip=false\n" {
				t.Errorf("GITHUB_OUTPUT = %q, want exactly skip=false", r.output)
			}
		})
	}
}

// Two pull requests with the same head agree: still one candidate.
//
// Proves OPS-02 (repeated checks): see the pass conditions of the row; OPS ids are not traced.
// Acceptance: Repeated checks (part)
func TestTestedTreeBranchPullRequestsThatAgreeSkip(t *testing.T) {
	c := goodBranch().with("pulls", ttPulls(ttPR(true, ttSHA, ttHead), ttPR(true, ttSHA, ttHead), ttPR(true, ttOther, ttOther)))
	wantSkip(t, runTT(t, c, false, ttRepo, ttSHA, "branch"), true)
}

func goodTag() ttCase {
	return ttCase{files: map[string]string{"runs": ttRuns(ttRun("main", "success", ttSHA))}}
}

// Proves OPS-02 (repeated checks): see the pass conditions of the row; OPS ids are not traced.
// Acceptance: Repeated checks (part)
func TestTestedTreeTag(t *testing.T) {
	good := goodTag()
	r := runTT(t, good, true, ttRepo, ttSHA, "tag")
	wantSkip(t, r, true)
	if r.output != "skip=true\n" {
		t.Errorf("GITHUB_OUTPUT = %q", r.output)
	}
	want := "repos/" + ttRepo + "/actions/workflows/deploy.yml/runs?head_sha=" + ttSHA + "&event=push&status=success&per_page=100\n"
	if r.calls != want {
		t.Errorf("gh calls = %q, want only %q", r.calls, want)
	}
	for _, tc := range []struct {
		name string
		c    ttCase
	}{
		{"no run", good.with("runs", ttRuns())},
		{"run failed", good.with("runs", ttRuns(ttRun("main", "failure", ttSHA)))},
		{"run cancelled", good.with("runs", ttRuns(ttRun("main", "cancelled", ttSHA)))},
		{"run skipped", good.with("runs", ttRuns(ttRun("main", "skipped", ttSHA)))},
		{"conclusion null", good.with("runs", `{"workflow_runs":[{"head_branch":"main","conclusion":null,"head_sha":"`+ttSHA+`","event":"push"}]}`)},
		{"another branch", good.with("runs", ttRuns(ttRun("feature", "success", ttSHA)))},
		{"branch main-like", good.with("runs", ttRuns(ttRun("main2", "success", ttSHA)))},
		{"another commit", good.with("runs", ttRuns(ttRun("main", "success", ttOther)))},
		{"another event", good.with("runs", `{"workflow_runs":[{"head_branch":"main","conclusion":"success","head_sha":"`+ttSHA+`","event":"workflow_dispatch"}]}`)},
		{"failed then another branch", good.with("runs", ttRuns(ttRun("main", "failure", ttSHA), ttRun("x", "success", ttSHA)))},
		{"gh fails", good.failing("runs")},
		{"empty output", good.with("runs", "")},
		{"garbage", good.with("runs", "not json")},
		{"no workflow_runs", good.with("runs", `{"message":"Not Found"}`)},
		{"workflow_runs is a string", good.with("runs", `{"workflow_runs":"x"}`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := runTT(t, tc.c, true, ttRepo, ttSHA, "tag")
			wantSkip(t, r, false)
			if r.output != "skip=false\n" {
				t.Errorf("GITHUB_OUTPUT = %q", r.output)
			}
		})
	}
	// One matching run among others is enough.
	c := good.with("runs", ttRuns(ttRun("main", "failure", ttSHA), ttRun("main", "success", ttSHA)))
	wantSkip(t, runTT(t, c, false, ttRepo, ttSHA, "tag"), true)
}

// The script never looks at pull requests for a tag, nor at runs for a branch.
//
// Proves OPS-02 (repeated checks): see the pass conditions of the row; OPS ids are not traced.
// Acceptance: Repeated checks (part)
func TestTestedTreeModesUseTheirOwnEndpoints(t *testing.T) {
	both := goodBranch().with("runs", ttRuns(ttRun("main", "success", ttSHA)))
	if r := runTT(t, both, false, ttRepo, ttSHA, "tag"); strings.Contains(r.calls, "/pulls") || strings.Contains(r.calls, "/statuses") {
		t.Errorf("tag mode asked for pull requests or statuses:\n%s", r.calls)
	}
	if r := runTT(t, both, false, ttRepo, ttSHA, "branch"); strings.Contains(r.calls, "actions/") {
		t.Errorf("branch mode asked for workflow runs:\n%s", r.calls)
	}
}

// Proves OPS-02 (repeated checks): see the pass conditions of the row; OPS ids are not traced.
// Acceptance: Repeated checks (part)
func TestTestedTreeWritesNothingWithoutGitHubOutput(t *testing.T) {
	r := runTT(t, goodBranch(), false, ttRepo, ttSHA, "branch")
	wantSkip(t, r, true)
	if r.outputSet {
		t.Error("an output file was written without GITHUB_OUTPUT")
	}
	// An existing output file is appended to, not replaced.
	path, dir := fakeGH(t, goodBranch())
	out := filepath.Join(dir, "out")
	if err := os.WriteFile(out, []byte("a=b\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), "sh", "ops/tested-tree.sh", ttRepo, ttSHA, "branch")
	cmd.Env = append(os.Environ(), "PATH="+path, "GITHUB_OUTPUT="+out)
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(out); string(b) != "a=b\nskip=true\n" {
		t.Errorf("output file = %q", b)
	}
}

// Proves OPS-02 (repeated checks): see the pass conditions of the row; OPS ids are not traced.
// Acceptance: Repeated checks (part)
func TestTestedTreeRejectsBadArguments(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"no arguments", nil},
		{"two arguments", []string{ttRepo, ttSHA}},
		{"four arguments", []string{ttRepo, ttSHA, "branch", "x"}},
		{"empty repository", []string{"", ttSHA, "branch"}},
		{"repository without owner", []string{"name", ttSHA, "branch"}},
		{"repository with two slashes", []string{"a/b/c", ttSHA, "branch"}},
		{"repository with space", []string{"a/b c", ttSHA, "branch"}},
		{"repository with semicolon", []string{"a/b;id", ttSHA, "branch"}},
		{"repository with substitution", []string{"a/$(id)", ttSHA, "branch"}},
		{"repository with query", []string{"a/b?x=1", ttSHA, "branch"}},
		{"repository with dotdot", []string{"../b", ttSHA, "branch"}},
		{"repository name dotdot", []string{"a/..", ttSHA, "branch"}},
		{"repository option-like", []string{"-a/b", ttSHA, "branch"}},
		{"repository with newline", []string{"a/b\nc", ttSHA, "branch"}},
		{"repository empty owner", []string{"/b", ttSHA, "branch"}},
		{"repository empty name", []string{"a/", ttSHA, "branch"}},
		{"sha 39 characters", []string{ttRepo, ttSHA[:39], "branch"}},
		{"sha 41 characters", []string{ttRepo, ttSHA + "a", "branch"}},
		{"sha not hex", []string{ttRepo, strings.Repeat("g", 40), "branch"}},
		{"sha empty", []string{ttRepo, "", "branch"}},
		{"sha with newline", []string{ttRepo, ttSHA[:39] + "\n", "branch"}},
		{"mode empty", []string{ttRepo, ttSHA, ""}},
		{"mode other", []string{ttRepo, ttSHA, "pull_request"}},
		{"mode upper case", []string{ttRepo, ttSHA, "Branch"}},
		{"mode with suffix", []string{ttRepo, ttSHA, "branch "}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := runTT(t, goodBranch(), true, tc.args...)
			if r.code != 2 {
				t.Errorf("exit code %d, want 2\n%s", r.code, r.stderr)
			}
			if r.stdout != "" || r.outputSet || r.calls != "" {
				t.Errorf("a bad call printed %q, wrote %q or called gh: %q", r.stdout, r.output, r.calls)
			}
		})
	}
}

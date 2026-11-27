package deploy_test

import (
	"fmt"
	"go/ast"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// Documentation-only changes. The tests of the script are in
// changed_files_test.go; these are the workflow tests, run on the parsed files
// and on the real text of the steps (executed with sh and a fake gh).

var results4 = []string{"success", "failure", "cancelled", "skipped"}

// stepByID returns the step with the id.
func stepByID(t *testing.T, j workflowJob, id string) workflowStep {
	t.Helper()
	for _, s := range j.Steps {
		if s.ID == id {
			return s
		}
	}
	t.Fatalf("no step with id %q", id)
	return workflowStep{}
}

// runStep executes the run text of a step the way the runner does (sh -e),
// from dir, with env added and GITHUB_OUTPUT pointing to a file.
func runStep(t *testing.T, run, dir, path string, env ...string) (stdout, stderr, output string, err error) {
	t.Helper()
	out := filepath.Join(t.TempDir(), "github_output")
	if err := os.WriteFile(out, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), "sh", "-e", "-c", run)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "PATH="+path, "GITHUB_OUTPUT="+out)
	cmd.Env = append(cmd.Env, env...)
	var so, se strings.Builder
	cmd.Stdout, cmd.Stderr = &so, &se
	err = cmd.Run()
	b, _ := os.ReadFile(out)
	return so.String(), se.String(), string(b), err
}

// Proves OPS-02 (documentation-only changes): see the pass conditions of the row; OPS ids are not traced.
// Acceptance: Documentation-only changes (part)
func TestCIChangesJob(t *testing.T) {
	w, _ := readWorkflow(t, "ci.yml")
	// deploy.yml calls ci.yml with the boolean input docs_only, false by default.
	call, _ := w.On["workflow_call"].(map[string]any)
	inputs, _ := call["inputs"].(map[string]any)
	in, _ := inputs["docs_only"].(map[string]any)
	if len(inputs) != 1 || in["type"] != "boolean" || in["default"] != false || in["required"] == true {
		t.Errorf("workflow_call inputs = %v, want only docs_only: boolean, default false, not required", call["inputs"])
	}
	j, ok := w.Jobs["changes"]
	if !ok {
		t.Fatal("ci.yml has no changes job")
	}
	if len(j.Permissions) != 2 || j.Permissions["contents"] != "read" || j.Permissions["pull-requests"] != "read" {
		t.Errorf("changes permissions = %v, want exactly contents: read and pull-requests: read", j.Permissions)
	}
	if j.Needs != nil || j.If != "" {
		t.Errorf("changes has needs %v or if %q; it runs first, always", j.Needs, j.If)
	}
	if j.RunsOn != runnerExpr {
		t.Errorf("runs-on = %q", j.RunsOn)
	}
	if len(j.Steps) != 2 || !strings.HasPrefix(j.Steps[0].Uses, "actions/checkout@") ||
		j.Steps[0].With["persist-credentials"] != "false" {
		t.Fatalf("want a checkout without persisted credentials (the script must exist) and one more step: %+v", j.Steps)
	}
	s := j.Steps[1]
	if s.ID == "" || s.If != "" || s.ContinueOnError {
		t.Errorf("the script step needs an id, no if and no continue-on-error: %+v", s)
	}
	for k, v := range map[string]string{
		"EVENT": "${{ github.event_name }}", "REPO": "${{ github.repository }}",
		"BASE": "${{ github.event.pull_request.base.sha }}", "HEAD": "${{ github.event.pull_request.head.sha }}",
		"GH_TOKEN": "${{ github.token }}", "DOCS_ONLY": "${{ inputs.docs_only }}",
	} {
		if s.Env[k] != v {
			t.Errorf("env %s = %q, want %q", k, s.Env[k], v)
		}
	}
	if strings.Contains(s.Run, "${{") {
		t.Error("an expression is interpolated inside run:")
	}
	if got, want := j.Outputs["docs_only"], "${{ steps."+s.ID+".outputs.docs_only }}"; got != want {
		t.Errorf("output docs_only = %q, want %q", got, want)
	}
	if len(j.Outputs) != 1 {
		t.Errorf("outputs = %v, want docs_only only (slow_skip is removed)", j.Outputs)
	}

	// Run the real text. A pull request reads the files in compare mode and
	// ignores the input; any other event says what the input says and never
	// calls gh.
	compare := "1 repos/owner/name/compare/" + cfBase + "..." + cfHead + "?per_page=100\n"
	pr := func(names ...string) cfCase { return cfCompare(cfJSON(cfNames(names...)...)) }
	docs := pr("README.md")
	comment := cfCompare(cfJSON(goFile(h, "+// a")))
	contents := "0 repos/owner/name/contents/internal/x/x.go?ref=" + cfHead + "\n"
	covers := cfCompare(cfJSON(goFile(h, "+// Covers: FR-16")))
	for _, tc := range []struct {
		name, event, input string
		c                  cfCase
		want               bool
		calls              string
	}{
		{"pull request, docs", "pull_request", "", docs, true, compare},
		{"pull request, code", "pull_request", "", pr("README.md", "main.go"), false, compare},
		{"pull request, the design", "pull_request", "", pr("docs/DESIGN.md"), true, compare},
		{"pull request, only a Go comment", "pull_request", "", comment, true, compare + contents},
		{"pull request, a Covers line", "pull_request", "", covers, false, compare},
		{"pull request, only pending.txt", "pull_request", "", pr("tools/trace/pending.txt"), true, compare},
		{"pull request, only the results", "pull_request", "", pr("docs/RESULTS.md"), true, compare},
		{"pull request, the example readme and the user guide", "pull_request", "", pr("examples/web-app/README.md", "docs/USER_GUIDE.md"), true, compare},
		{"pull request, an audit", "pull_request", "", pr("docs/audits/2026-11-27.md"), true, compare},
		{"pull request, an image under docs/audits", "pull_request", "", pr("docs/audits/x.png"), false, compare},
		{"pull request, the input is not read", "pull_request", "true", pr("main.go"), false, compare},
		{"push, called without the input", "push", "", docs, false, ""},
		{"push, called with docs_only false", "push", "false", docs, false, ""},
		{"push, called with docs_only true", "push", "true", pr("main.go"), true, ""},
		{"push, an unexpected input", "push", "yes", docs, false, ""},
		{"workflow_dispatch", "workflow_dispatch", "", docs, false, ""},
		{"empty event", "", "", docs, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path, dir := cfFakeGH(t, tc.c)
			_, se, out, err := runStep(t, s.Run, "..", path, "EVENT="+tc.event, "REPO=owner/name", "BASE="+cfBase, "HEAD="+cfHead, "GH_TOKEN=x", "DOCS_ONLY="+tc.input)
			if err != nil {
				t.Fatalf("%v\n%s", err, se)
			}
			if want := cfLines(tc.want); out != want {
				t.Errorf("GITHUB_OUTPUT = %q, want %q", out, want)
			}
			calls, _ := os.ReadFile(filepath.Join(dir, "calls.log"))
			if string(calls) != tc.calls {
				t.Errorf("gh calls = %q, want %q", calls, tc.calls)
			}
		})
	}
}

// check, browser, ops and postgres need changes and run unless docs_only is
// exactly 'true'; docs runs only when it is. A changes job that failed or was
// cancelled must not skip the tests: their condition has !cancelled(), so
// success() is not added implicitly, and an empty docs_only runs them and
// skips docs.
//
// Proves OPS-02 (documentation-only changes): see the pass conditions of the row; OPS ids are not traced.
// Acceptance: Documentation-only changes (part)
func TestCIJobsSkipOnDocsOnly(t *testing.T) {
	w, _ := readWorkflow(t, "ci.yml")
	for _, name := range []string{"check", "browser", "ops", "postgres", "docs"} {
		j := w.Jobs[name]
		if !j.needs("changes") {
			t.Errorf("%s does not need changes", name)
		}
		for _, changesRes := range results4 {
			for _, docs := range []string{"true", "false", "TRUE", "yes", ""} {
				for _, cancelled := range []bool{false, true} {
					ctx := exprCtx{
						runCancelled: cancelled,
						results:      map[string]string{"changes": changesRes},
						outputs:      map[string]string{"changes.docs_only": docs},
					}
					got := jobRuns(t, j, []string{"changes"}, ctx)
					// GitHub compares strings without case, so 'TRUE' is true too.
					want := !cancelled && !strings.EqualFold(docs, "true")
					if name == "docs" {
						want = !cancelled && changesRes == "success" && strings.EqualFold(docs, "true")
					}
					if got != want {
						t.Errorf("%s runs = %v with changes %s, docs_only %q, cancelled %v; want %v",
							name, got, changesRes, docs, cancelled, want)
					}
				}
			}
		}
	}
	// The named case of the design: a failed changes job gives an empty
	// docs_only, which runs every test job and skips docs.
	ctx := exprCtx{results: map[string]string{"changes": "failure"}, outputs: map[string]string{"changes.docs_only": ""}}
	for _, name := range []string{"check", "browser", "ops", "postgres"} {
		if !jobRuns(t, w.Jobs[name], []string{"changes"}, ctx) {
			t.Errorf("%s does not run after a failed changes job", name)
		}
	}
	if jobRuns(t, w.Jobs["docs"], []string{"changes"}, ctx) {
		t.Error("docs runs after a failed changes job")
	}
}

// Proves OPS-02 (documentation-only changes): see the pass conditions of the row; OPS ids are not traced.
// Acceptance: Documentation-only changes (part)
func TestCIScanJob(t *testing.T) {
	w, _ := readWorkflow(t, "ci.yml")
	j, ok := w.Jobs["scan"]
	if !ok {
		t.Fatal("ci.yml has no scan job")
	}
	// It runs on every run: no needs, no condition.
	if j.Needs != nil || j.If != "" {
		t.Errorf("scan has needs %v or if %q; it runs on every run", j.Needs, j.If)
	}
	if len(j.Permissions) != 1 || j.Permissions["contents"] != "read" {
		t.Errorf("scan permissions = %v, want contents: read only", j.Permissions)
	}
	if len(j.Steps) != 2 || !strings.HasPrefix(j.Steps[0].Uses, "actions/checkout@") ||
		j.Steps[0].With["persist-credentials"] != "false" {
		t.Fatalf("want a checkout without persisted credentials and one script step (no Go setup): %+v", j.Steps)
	}
	for _, s := range j.Steps {
		if strings.Contains(s.Uses, "setup-go") || strings.Contains(s.Run, "make ") || strings.Contains(s.Run, "go ") {
			t.Errorf("scan sets up or runs Go: %+v", s)
		}
	}
	run := j.Steps[1].Run
	// The same pattern as TestRepositoryHoldsNoSecretFiles.
	const pattern = `^-----BEGIN [ABCDEFGHIJKLMNOPQRSTUVWXYZ ]*PRIVATE KEY-----$`
	if !strings.Contains(run, "git grep -lE '"+pattern+"'") || !strings.Contains(readFile(t, "deploy_test.go"), "`"+pattern+"`") {
		t.Errorf("scan does not use the pattern of TestRepositoryHoldsNoSecretFiles:\n%s", run)
	}
	if strings.Contains(run, "${{") {
		t.Error("an expression is interpolated inside run:")
	}

	// Run the real text in a throwaway repository.
	for _, tc := range []struct {
		name, file, content string
		fails               bool
	}{
		{"clean", "README.md", "# Title\nhello\n", false},
		{"private key in README.md", "README.md", "-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----\n", true},
		{"rsa key in a nested file", "docs/x.md", "text\n-----BEGIN RSA PRIVATE KEY-----\nx\n", true},
		{"ec key", "a.txt", "-----BEGIN EC PRIVATE KEY-----\n", true},
		{"public key only", "a.txt", "-----BEGIN PUBLIC KEY-----\n", false},
		{"key header inside a line", "a.txt", "see -----BEGIN PRIVATE KEY----- here\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := t.TempDir()
			if err := os.MkdirAll(filepath.Dir(filepath.Join(repo, tc.file)), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(repo, tc.file), []byte(tc.content), 0o600); err != nil {
				t.Fatal(err)
			}
			for _, args := range [][]string{{"init", "-q"}, {"add", "-A"}} {
				cmd := exec.CommandContext(t.Context(), "git", args...)
				cmd.Dir = repo
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("git %v: %v\n%s", args, err, out)
				}
			}
			_, se, _, err := runStep(t, run, repo, os.Getenv("PATH"))
			if tc.fails && err == nil {
				t.Error("the scan passed a repository with a private key")
			}
			if !tc.fails && err != nil {
				t.Errorf("the scan failed a clean repository: %v\n%s", err, se)
			}
		})
	}
}

// record-tested-tree runs only when every job before it ran and succeeded: a
// skipped need (documentation-only) skips it.
//
// Proves OPS-02 (documentation-only changes): see the pass conditions of the row; OPS ids are not traced.
// Acceptance: Documentation-only changes (part)
func TestCIRecordsOnlyAfterEveryJobRan(t *testing.T) {
	w, _ := readWorkflow(t, "ci.yml")
	j := w.Jobs["record-tested-tree"]
	needs := []string{"changes", "scan", "check", "browser", "ops", "postgres"}
	if strings.Contains(j.If, "cancelled()") || strings.Contains(j.If, "always()") {
		t.Fatalf("record-tested-tree if %q has a status function: a skipped need would not skip it", j.If)
	}
	for _, event := range []string{"pull_request", "push"} {
		for _, skipOne := range append([]string{""}, needs...) {
			for _, res := range []string{"success", "failure", "cancelled", "skipped"} {
				results := map[string]string{}
				for _, n := range needs {
					results[n] = "success"
				}
				if skipOne != "" {
					results[skipOne] = res
				}
				ctx := exprCtx{results: results, vals: map[string]string{"github.event_name": event}}
				want := event == "pull_request" && (skipOne == "" || res == "success")
				if got := jobRuns(t, j, needs, ctx); got != want {
					t.Errorf("record-tested-tree runs = %v on %s with %s %s; want %v", got, event, skipOne, res, want)
				}
			}
		}
	}
}

// A fake gh for the steps of the tested job of deploy.yml. One commit answer
// serves both the files and the parents; the runs answer serves tested-tree.sh
// in tag mode.
type dtCase struct {
	files       []cfFile
	parent      string // the first parent, "" for none
	parentsRaw  string // replaces the parents array when set
	runs        string // answer of the workflow runs list
	failKeys    []string
	noCommitRaw string // replaces the whole commit answer when set
}

func dtFakeGH(t *testing.T, c dtCase) (path, dir string) {
	t.Helper()
	if _, err := exec.LookPath("jq"); err != nil {
		t.Fatalf("jq is needed by the fake gh of these tests: %v", err)
	}
	dir = t.TempDir()
	parents := "[]"
	if c.parent != "" {
		parents = `[{"sha":"` + c.parent + `"}]`
	}
	if c.parentsRaw != "" {
		parents = c.parentsRaw
	}
	commit := `{"sha":"` + cfSHA + `","parents":` + parents + `,"files":` + cfJSON(c.files...) + `}`
	if c.noCommitRaw != "" {
		commit = c.noCommitRaw
	}
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("commit.json", commit)
	write("runs.json", c.runs)
	write("contents.json", cfContent("package x\n"))
	for _, k := range c.failKeys {
		write(k+".fail", "")
	}
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	script := `#!/bin/sh
d="` + dir + `"
[ "$1" = api ] || { echo "fake gh: only api" >&2; exit 64; }
shift
ep=; jq_expr=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --paginate) ;;
    --jq) shift; jq_expr=$1 ;;
    -*) echo "fake gh: unknown flag $1" >&2; exit 64 ;;
    *) [ -z "$ep" ] || { echo "fake gh: two endpoints" >&2; exit 64; }; ep=$1 ;;
  esac
  shift
done
echo "$ep" >> "$d/calls.log"
case "$ep" in
  repos/*/commits/*)
    case "$jq_expr" in
      *parents*) k=parents; f=commit ;;
      *) k=commit; f=commit ;;
    esac ;;
  repos/*/contents/*) k=contents; f=contents ;;
  repos/*/actions/workflows/deploy.yml/runs\?*) k=runs; f=runs ;;
  *) echo "fake gh: unknown endpoint $ep" >&2; exit 64 ;;
esac
[ ! -e "$d/$k.fail" ] || { echo "fake gh: HTTP 500" >&2; exit 1; }
jq -r "$jq_expr" "$d/$f.json"
`
	if err := os.WriteFile(filepath.Join(bin, "gh"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin + ":" + os.Getenv("PATH"), dir
}

const dtParent = "89abcdef0123456789abcdef0123456789abcdef"

func dtRuns(branch, conclusion, sha string) string {
	return ttRuns(ttRun(branch, conclusion, sha))
}

// Proves OPS-02 (documentation-only changes): see the pass conditions of the row; OPS ids are not traced.
// Acceptance: Documentation-only changes (part)
func TestDeployDocsStep(t *testing.T) {
	w, _ := readWorkflow(t, "deploy.yml")
	j := w.Jobs["tested"]
	s := stepByID(t, j, "docs")
	if s.If != "" || s.ContinueOnError {
		t.Errorf("the docs step has if %q or continue-on-error; it must always run and write docs_only", s.If)
	}
	for k, v := range map[string]string{
		"REPO": "${{ github.repository }}", "SHA": "${{ github.sha }}",
		"REF_TYPE": "${{ github.ref_type }}", "GH_TOKEN": "${{ github.token }}",
	} {
		if s.Env[k] != v {
			t.Errorf("env %s = %q, want %q", k, s.Env[k], v)
		}
	}
	if strings.Contains(s.Run, "${{") {
		t.Error("an expression is interpolated inside run:")
	}
	// It reuses the two scripts; the lookup is not copied.
	for _, want := range []string{
		`deploy/ops/changed-files.sh "$REPO" commit "$SHA"`,
		`deploy/ops/tested-tree.sh "$REPO" "$parent" tag`,
	} {
		if !strings.Contains(s.Run, want) {
			t.Errorf("the docs step does not run %q", want)
		}
	}
	if strings.Contains(s.Run, "actions/workflows") {
		t.Error("the docs step looks at workflow runs itself; it must reuse tested-tree.sh")
	}
	// The tested-tree step is still before it and is not given the docs result.
	if i, k := stepIndex(j, func(x workflowStep) bool { return x.ID == "tested" }), stepIndex(j, func(x workflowStep) bool { return x.ID == "docs" }); i < 0 || k < i {
		t.Error("the docs step must come after the tested-tree step")
	}

	docs := cfNames("README.md", "docs/RELEASING.md")
	good := dtCase{files: docs, parent: dtParent, runs: dtRuns("main", "success", dtParent)}
	with := func(f func(c *dtCase)) dtCase { c := good; f(&c); return c }
	for _, tc := range []struct {
		name    string
		refType string
		c       dtCase
		want    string
		parent  bool // whether the parent was looked up
	}{
		{"docs-only, parent passed on main", "branch", good, "true", true},
		{"parent has no run", "branch", with(func(c *dtCase) { c.runs = ttRuns() }), "false", true},
		{"parent run failed", "branch", with(func(c *dtCase) { c.runs = dtRuns("main", "failure", dtParent) }), "false", true},
		{"parent run on another branch", "branch", with(func(c *dtCase) { c.runs = dtRuns("feature", "success", dtParent) }), "false", true},
		{"parent run is for another commit", "branch", with(func(c *dtCase) { c.runs = dtRuns("main", "success", ttOther) }), "false", true},
		{"runs not available", "branch", with(func(c *dtCase) { c.failKeys = []string{"runs"} }), "false", true},
		{"runs garbage", "branch", with(func(c *dtCase) { c.runs = "not json" }), "false", true},
		{"code among docs", "branch", with(func(c *dtCase) { c.files = cfNames("README.md", "main.go") }), "false", false},
		{"only a Go comment, parent passed on main", "branch", with(func(c *dtCase) { c.files = []cfFile{goFile(h, "+// a")} }), "true", true},
		{"only a Go comment, parent has no run", "branch", with(func(c *dtCase) { c.files = []cfFile{goFile(h, "+// a")}; c.runs = ttRuns() }), "false", true},
		{"a Covers line", "branch", with(func(c *dtCase) { c.files = []cfFile{goFile(h, "+// Covers: FR-16")} }), "false", false},
		{"Go code", "branch", with(func(c *dtCase) { c.files = []cfFile{goFile(h, "+x := 1")} }), "false", false},
		// pending.txt and every .md file under docs/ are documentation files.
		{"only pending.txt", "branch", with(func(c *dtCase) { c.files = cfNames("tools/trace/pending.txt") }), "true", true},
		{"design", "branch", with(func(c *dtCase) { c.files = cfNames("docs/DESIGN.md") }), "true", true},
		{"the results of a release gate", "branch", with(func(c *dtCase) { c.files = cfNames("docs/RESULTS.md") }), "true", true},
		{"the results, parent has no run", "branch", with(func(c *dtCase) { c.files = cfNames("docs/RESULTS.md"); c.runs = ttRuns() }), "false", true},
		{"an image under docs", "branch", with(func(c *dtCase) { c.files = cfNames("docs/audits/x.png") }), "false", false},
		{"no files", "branch", with(func(c *dtCase) { c.files = nil }), "false", false},
		{"files not available", "branch", with(func(c *dtCase) { c.failKeys = []string{"commit"} }), "false", false},
		{"commit garbage", "branch", with(func(c *dtCase) { c.noCommitRaw = "garbage" }), "false", false},
		{"parent lookup fails", "branch", with(func(c *dtCase) { c.failKeys = []string{"parents"} }), "false", false},
		{"no parent", "branch", with(func(c *dtCase) { c.parent = "" }), "false", false},
		{"parent is null", "branch", with(func(c *dtCase) { c.parent = ""; c.parentsRaw = `[{"sha":null}]` }), "false", false},
		{"parent is not hex", "branch", with(func(c *dtCase) { c.parent = ""; c.parentsRaw = `[{"sha":"../../x"}]` }), "false", false},
		{"parent too short", "branch", with(func(c *dtCase) { c.parent = dtParent[:39]; c.runs = dtRuns("main", "success", dtParent[:39]) }), "false", false},
		{"parent upper case", "branch", with(func(c *dtCase) { c.parent = strings.ToUpper(dtParent) }), "false", false},
		{"parent with extra text", "branch", with(func(c *dtCase) { c.parent = dtParent + "\\nx" }), "false", false},
		// The first parent decides, not the last one (a merge commit has two).
		{"two parents, only the first passed", "branch", with(func(c *dtCase) {
			c.parent = ""
			c.parentsRaw = `[{"sha":"` + dtParent + `"},{"sha":"` + ttOther + `"}]`
		}), "true", true},
		{"two parents, only the second passed", "branch", with(func(c *dtCase) {
			c.parent = ""
			c.parentsRaw = `[{"sha":"` + dtParent + `"},{"sha":"` + ttOther + `"}]`
			c.runs = dtRuns("main", "success", ttOther)
		}), "false", true},
		{"tag push", "tag", good, "false", false},
		{"empty ref type", "", good, "false", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path, dir := dtFakeGH(t, tc.c)
			_, se, out, err := runStep(t, s.Run, "..", path, "REPO=owner/name", "SHA="+cfSHA, "REF_TYPE="+tc.refType, "GH_TOKEN=x")
			if err != nil {
				t.Fatalf("%v\n%s", err, se)
			}
			if want := "docs_only=" + tc.want + "\n"; out != want {
				t.Errorf("GITHUB_OUTPUT = %q, want exactly %q\n%s", out, want, se)
			}
			calls, _ := os.ReadFile(filepath.Join(dir, "calls.log"))
			if tc.refType != "branch" && len(calls) != 0 {
				t.Errorf("gh was called for a %q push: %s", tc.refType, calls)
			}
			wantRuns := "repos/owner/name/actions/workflows/deploy.yml/runs?head_sha=" + dtParent
			if tc.parent && !strings.Contains(string(calls), wantRuns) {
				t.Errorf("the lookup of the tag mode of tested-tree.sh was not made for the parent:\n%s", calls)
			}
			if !tc.parent && strings.Contains(string(calls), "/actions/") {
				t.Errorf("the runs were looked up although the answer was already false:\n%s", calls)
			}
			// The tree lookup of the branch mode is never made for the parent.
			if strings.Contains(string(calls), "/pulls") || strings.Contains(string(calls), "/statuses") {
				t.Errorf("the branch mode of tested-tree.sh was used:\n%s", calls)
			}
		})
	}
}

// The job output skip is true for a tree match only; docs_only comes from the
// docs step only, and a documentation-only commit keeps skip false so that the
// checks job runs ci.yml with docs_only: true.
//
// Proves OPS-02 (documentation-only changes): see the pass conditions of the row; OPS ids are not traced.
// Acceptance: Documentation-only changes (part)
func TestDeployTestedOutputs(t *testing.T) {
	w, _ := readWorkflow(t, "deploy.yml")
	j := w.Jobs["tested"]
	if got, want := j.Outputs["docs_only"], "${{ steps.docs.outputs.docs_only }}"; got != want {
		t.Errorf("output docs_only = %q, want %q", got, want)
	}
	if len(j.Outputs) != 2 {
		t.Errorf("outputs = %v, want skip and docs_only", j.Outputs)
	}
	for _, tree := range []string{"true", "false", ""} {
		for _, docs := range []string{"true", "false", ""} {
			ctx := exprCtx{vals: map[string]string{"steps.tested.outputs.skip": tree, "steps.docs.outputs.docs_only": docs}}
			got, err := evalExpr(j.Outputs["skip"], ctx)
			if err != nil {
				t.Fatal(err)
			}
			if want := tree == "true"; got != want {
				t.Errorf("skip = %v with tree %q, docs %q; want %v", got, tree, docs, want)
			}
		}
	}
	// The job summary names each reason.
	var tree, docs bool
	for _, s := range j.Steps {
		if !strings.Contains(s.Run, "GITHUB_STEP_SUMMARY") {
			continue
		}
		switch s.If {
		case "${{ steps.tested.outputs.skip == 'true' }}":
			tree = strings.Contains(s.Run, "same git tree") && strings.Contains(s.Run, "tagged commit")
		case "${{ steps.docs.outputs.docs_only == 'true' }}":
			docs = strings.Contains(s.Run, "documentation-only") && strings.Contains(s.Run, "docs job") &&
				strings.Contains(s.Run, "deploy was skipped") && strings.Contains(s.Run, "image is still built")
		default:
			t.Errorf("summary step with if %q", s.If)
		}
	}
	if !tree || !docs {
		t.Errorf("job summary reasons: tree match %v, documentation-only %v; want both named", tree, docs)
	}
}

// checks, build and deploy for every combination of what tested says. A
// documentation-only commit runs the checks job, which calls ci.yml with
// docs_only: true (the key scan and the docs job), builds the image when they
// pass and skips the deploy.
//
// Proves OPS-02 (documentation-only changes): see the pass conditions of the row; OPS ids are not traced.
// Acceptance: Documentation-only changes
func TestDeployJobConditionTable(t *testing.T) {
	w, _ := readWorkflow(t, "deploy.yml")
	checks, build, deploy := w.Jobs["checks"], w.Jobs["build"], w.Jobs["deploy"]
	if len(checks.With) != 1 {
		t.Errorf("checks with = %v, want docs_only only", checks.With)
	}
	// GitHub's implicit success() looks at every ancestor in the needs chain, not
	// only the direct needs: deploy needs build, build needs checks, so a skipped
	// checks job skips deploy unless its if: names a status function.
	deployAncestors := []string{"tested", "build", "checks"}
	for _, testedRes := range results4 {
		for _, skip := range []string{"true", "false", ""} {
			for _, docs := range []string{"true", "false", "", "TRUE"} {
				// The input given to ci.yml.
				ctx := exprCtx{outputs: map[string]string{"tested.skip": skip, "tested.docs_only": docs}}
				if got, err := evalExpr(checks.With["docs_only"], ctx); err != nil || got != strings.EqualFold(docs, "true") {
					t.Errorf("checks with docs_only = %v, %v with tested docs_only %q; want %v", got, err, docs, strings.EqualFold(docs, "true"))
				}
				for _, checksRes := range results4 {
					for _, buildRes := range results4 {
						for _, cancelled := range []bool{false, true} {
							for _, deployPath := range []string{"/srv/x", ""} {
								for _, ref := range []string{"branch", "tag"} {
									ctx := exprCtx{
										runCancelled: cancelled,
										results:      map[string]string{"tested": testedRes, "checks": checksRes, "build": buildRes},
										outputs:      map[string]string{"tested.skip": skip, "tested.docs_only": docs},
										vals:         map[string]string{"vars.DEPLOY_PATH": deployPath, "github.ref_type": ref},
									}
									if got, want := jobRuns(t, checks, []string{"tested"}, ctx), testedRes == "success" && !cancelled && skip != "true"; got != want {
										t.Errorf("checks runs = %v with tested %s, skip %s, docs %s; want %v", got, testedRes, skip, docs, want)
									}
									wantBuild := !cancelled && testedRes == "success" &&
										(checksRes == "success" || (checksRes == "skipped" && skip == "true"))
									if got := jobRuns(t, build, []string{"tested", "checks"}, ctx); got != wantBuild {
										t.Errorf("build runs = %v with tested %s, skip %s, docs %s, checks %s, cancelled %v; want %v",
											got, testedRes, skip, docs, checksRes, cancelled, wantBuild)
									}
									wantDeploy := !cancelled && testedRes == "success" && buildRes == "success" &&
										deployPath != "" && ref == "branch" && !strings.EqualFold(docs, "true")
									if got := jobRuns(t, deploy, deployAncestors, ctx); got != wantDeploy {
										t.Errorf("deploy runs = %v with tested %s, docs %s, build %s, DEPLOY_PATH %q, %s, cancelled %v; want %v",
											got, testedRes, docs, buildRes, deployPath, ref, cancelled, wantDeploy)
									}
								}
							}
						}
					}
				}
			}
		}
	}
	// The named case of the design: a documentation-only commit runs the
	// checks job with docs_only: true, still builds and skips the deploy.
	ctx := exprCtx{
		results: map[string]string{"tested": "success", "checks": "success", "build": "success"},
		outputs: map[string]string{"tested.skip": "false", "tested.docs_only": "true"},
		vals:    map[string]string{"vars.DEPLOY_PATH": "/srv/x", "github.ref_type": "branch"},
	}
	if !jobRuns(t, checks, []string{"tested"}, ctx) {
		t.Error("checks do not run for a documentation-only commit")
	}
	if v, err := evalExpr(checks.With["docs_only"], ctx); err != nil || !v {
		t.Errorf("checks call ci.yml with docs_only %v, %v for a documentation-only commit; want true", v, err)
	}
	if !jobRuns(t, build, []string{"tested", "checks"}, ctx) {
		t.Error("build does not run for a documentation-only commit")
	}
	if jobRuns(t, deploy, deployAncestors, ctx) {
		t.Error("deploy runs for a documentation-only commit")
	}
	// A red docs job (the checks job fails) builds nothing.
	ctx.results["checks"] = "failure"
	if jobRuns(t, build, []string{"tested", "checks"}, ctx) {
		t.Error("build runs although the documentation checks failed")
	}
	// A code commit calls ci.yml with docs_only false.
	ctx.outputs["tested.docs_only"] = "false"
	if v, err := evalExpr(checks.With["docs_only"], ctx); err != nil || v {
		t.Errorf("checks call ci.yml with docs_only %v, %v for a code commit; want false", v, err)
	}
	// Regression (run 44802697696): the tree was already tested, so checks were
	// skipped; the deploy must still run.
	ctx = exprCtx{
		results: map[string]string{"tested": "success", "checks": "skipped", "build": "success"},
		outputs: map[string]string{"tested.skip": "true", "tested.docs_only": "false"},
		vals:    map[string]string{"vars.DEPLOY_PATH": "/srv/x", "github.ref_type": "branch"},
	}
	if !jobRuns(t, deploy, deployAncestors, ctx) {
		t.Error("deploy does not run when the checks were skipped because the tree was already tested")
	}
}

// Proves OPS-02 (documentation-only changes): see the pass conditions of the row; OPS ids are not traced.
// Acceptance: Documentation-only changes (part)
func TestExprEvaluatorValues(t *testing.T) {
	ctx := exprCtx{vals: map[string]string{"vars.X": "", "github.ref_type": "branch"}}
	for expr, want := range map[string]bool{
		"${{ vars.X != '' }}":                                false,
		"${{ github.ref_type == 'branch' }}":                 true,
		"${{ vars.X == '' && github.ref_type == 'branch' }}": true,
		"${{ github.ref_type == 'tag' || vars.X != '' }}":    false,
	} {
		if got, err := evalExpr(expr, ctx); err != nil || got != want {
			t.Errorf("%s = %v, %v; want %v", expr, got, err, want)
		}
	}
	if _, err := evalExpr("${{ vars.Y == '' }}", ctx); err == nil {
		t.Error("an unset value is not an error")
	}
}

// The reader set (DESIGN.md, CI/CD, Reader set), written out here on purpose:
// the docs job of ci.yml must run exactly this.
const (
	readerPattern  = "^(TestConformanceResultsRecordSuiteVersion|TestLoadResultsRecorded|TestReleaseGateNoChangeClaimsHold|TestReleaseCheckBeforeTheTag|TestReleaseCheckAfterTheTag|TestRepositoryHoldsNoSecretFiles|TestConfigReferenceMatchesDesign|TestEveryDocumentedOptionIsReachableFromSnapshot|TestEveryPossibleValueHasARule|TestServerOptionClassesMatchTheDesign|TestProviderOptionsEveryOptionHasAProof|TestSchemaMatchesDesign|TestRunbookCommandsExist|TestRunbookFlagsExistInUsage|TestEmergencyKeyRotationRunbook)$"
	readerPackages = "./cmd/featherauth/ ./deploy/ ./internal/config/ ./internal/provider/ ./internal/store/"
)

// The two postgres tests that read docs/DESIGN.md; they need docker and do not
// run for a documentation change (an accepted risk of the design).
var acceptedPostgresReaders = map[string]bool{"TestPostgresSchemaMatchesDesign": true, "TestCopyCoversEveryTableOfTheSchema": true}

// The list of documentation files of the design (Documentation-only changes),
// as the # BEGIN list block of changed-files.sh holds it: files by path, every
// file under the directories, and every .md file under the md directories.
var docListWant = map[string]string{
	"doc_files":   "README.md CLAUDE.md deploy/ASSETS.md examples/web-app/README.md tools/trace/pending.txt",
	"doc_dirs":    ".claude/",
	"doc_md_dirs": "docs/",
}

// Files that name the documentation files only as data for changed-files.sh
// and the workflows; they are not scanned.
var readerScanExcluded = map[string]bool{
	"deploy/changed_files_test.go":    true,
	"deploy/changed_files_go_test.go": true,
	"deploy/docs_only_test.go":        true,
}

// The files outside tests that may name a documentation file: the trace tool
// (make trace), the script that holds the list, and the release check (make
// release-check, and in make check only through the release-check tests of
// the pattern).
var readerNameAllowed = map[string]bool{
	"tools/trace/main.go":         true,
	"deploy/ops/changed-files.sh": true,
	"deploy/ops/release-check.sh": true,
}

// docNamer tells whether a text names a documentation file: its path, its base
// name, or a .md path under docs/.
type docNamer struct{ names []string }

var docPathRE = regexp.MustCompile(`(^|[^A-Za-z0-9_.-])docs/[^\s"'` + "`" + `]*\.md`)

func newDocNamer(root string) docNamer {
	n := docNamer{names: []string{"README.md", "CLAUDE.md", "ASSETS.md", "pending.txt", ".claude"}}
	_ = filepath.WalkDir(filepath.Join(root, "docs"), func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(d.Name(), ".md") {
			n.names = append(n.names, d.Name())
		}
		return nil
	})
	return n
}

func (n docNamer) hit(s string) string {
	for _, name := range n.names {
		if strings.Contains(s, name) {
			return name
		}
	}
	if m := docPathRE.FindString(s); m != "" {
		return strings.TrimLeft(m, "/\\.\"'")
	}
	return ""
}

// readerNode is a top-level function, method, variable or constant of a
// directory's Go files.
type readerNode struct {
	file    string // relative path
	name    string
	isTest  bool   // a top-level Test function
	literal string // the documentation name it holds, "" for none
	edges   []string
}

type readerFile struct {
	rel    string
	tagged bool // a tagged file; false for a make check file
}

// The classes of a Go file by its //go:build expression (DESIGN.md, Reader set).
const (
	classSkip   = iota // runs only at a release: not scanned
	classCheck         // a make check file
	classTagged        // a tagged file (postgres, browser, conformance || load || ops)
)

// buildClass is the class of a file: a make check file when it has no
// constraint, or when the expression is true with browser, ops, postgres,
// manual, conformance and load off and every other tag on (operating system,
// architecture and Go version tags count as on); otherwise a tagged file when
// it is true with only manual, conformance and load off; otherwise not scanned.
func buildClass(f *ast.File) int {
	for _, cg := range f.Comments {
		if cg.Pos() > f.Package {
			break
		}
		for _, c := range cg.List {
			if !constraint.IsGoBuild(c.Text) {
				continue
			}
			expr, err := constraint.Parse(c.Text)
			if err != nil {
				return classTagged
			}
			off := func(tags ...string) func(string) bool {
				return func(tag string) bool { return !slices.Contains(tags, tag) }
			}
			switch {
			case expr.Eval(off("browser", "ops", "postgres", "manual", "conformance", "load")):
				return classCheck
			case expr.Eval(off("manual", "conformance", "load")):
				return classTagged
			}
			return classSkip
		}
	}
	return classCheck
}

// readerSetProblems applies the rules of TestOnlyTheReaderSetReadsDocumentation
// to the tree at root. It returns the problems, the readers it found (file:Test)
// and the number of files it scanned.
func readerSetProblems(t *testing.T, root string) (problems, readers []string, scanned int) {
	t.Helper()
	namer := newDocNamer(root)

	// (1) The list in changed-files.sh is the list of the design.
	script, err := os.ReadFile(filepath.Join(root, "deploy/ops/changed-files.sh"))
	if err != nil {
		problems = append(problems, "deploy/ops/changed-files.sh: "+err.Error())
	} else {
		m := regexp.MustCompile(`(?s)\n# BEGIN list\n(.*?)\n# END list\n`).FindStringSubmatch(string(script))
		got := map[string]string{}
		if m != nil {
			for _, l := range strings.Split(m[1], "\n") {
				if strings.HasPrefix(strings.TrimSpace(l), "#") {
					continue
				}
				kv := regexp.MustCompile(`^([a-z_]+)='([^']*)'$`).FindStringSubmatch(l)
				if kv == nil {
					got["?"] = l
					continue
				}
				got[kv[1]] = strings.Join(strings.Fields(kv[2]), " ")
			}
		}
		if !maps.Equal(got, docListWant) {
			problems = append(problems, fmt.Sprintf("deploy/ops/changed-files.sh: the # BEGIN list block is %v, want the list of docs/DESIGN.md (Documentation-only changes): %v", got, docListWant))
		}
	}

	// The pattern and the packages of the docs job of ci.yml.
	var names map[string]bool
	pkgs := map[string]bool{}
	var w workflow
	if b, err := os.ReadFile(filepath.Join(root, ".github/workflows/ci.yml")); err != nil {
		problems = append(problems, ".github/workflows/ci.yml: "+err.Error())
	} else if err := yaml.Unmarshal(b, &w); err != nil {
		problems = append(problems, ".github/workflows/ci.yml: "+err.Error())
	}
	runRE := regexp.MustCompile(`^go test -count=1 -run '\^\(([A-Za-z0-9_|]*)\)\$' (.+)$`)
	for _, s := range w.Jobs["docs"].Steps {
		if m := runRE.FindStringSubmatch(strings.TrimSpace(s.Run)); m != nil {
			names = map[string]bool{}
			for _, n := range strings.Split(m[1], "|") {
				names[n] = true
			}
			for _, p := range strings.Fields(m[2]) {
				pkgs[strings.TrimSuffix(strings.TrimPrefix(p, "./"), "/")] = true
			}
		}
	}
	if names == nil {
		problems = append(problems, ".github/workflows/ci.yml: the docs job has no step go test -count=1 -run '^(...)$' <packages>")
	}

	// Walk the tree: Go files by directory, and the other files of rule (4).
	type dirFiles struct {
		files []*ast.File
		info  []readerFile
	}
	dirs := map[string]*dirFiles{}
	fset := token.NewFileSet()
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if d.Name() == ".git" || d.Name() == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		inTestdata := strings.Contains("/"+rel, "/testdata/")
		switch {
		case strings.HasSuffix(rel, ".go"):
			if inTestdata || readerScanExcluded[rel] {
				return nil
			}
			f, err := parser.ParseFile(fset, p, nil, parser.ParseComments|parser.SkipObjectResolution)
			if err != nil {
				problems = append(problems, rel+": "+err.Error())
				return nil
			}
			class := buildClass(f)
			if class == classSkip {
				return nil
			}
			tagged := class == classTagged
			scanned++
			dir := filepath.ToSlash(filepath.Dir(rel))
			if dirs[dir] == nil {
				dirs[dir] = &dirFiles{}
			}
			dirs[dir].files = append(dirs[dir].files, f)
			dirs[dir].info = append(dirs[dir].info, readerFile{rel: rel, tagged: tagged})
			// (4) A Go file that is not a test names no documentation file.
			if !strings.HasSuffix(rel, "_test.go") && !readerNameAllowed[rel] {
				for _, decl := range f.Decls {
					where := "at package level"
					if fd, ok := decl.(*ast.FuncDecl); ok {
						where = "in " + fd.Name.Name
					}
					ast.Inspect(decl, func(n ast.Node) bool {
						if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
							if v := literalValue(lit); namer.hit(v) != "" {
								problems = append(problems, fmt.Sprintf("%s:%d: %s names %q: only tests of the reader set and the tools allowed by docs/DESIGN.md (Reader set) may", rel, fset.Position(lit.Pos()).Line, where, v))
							}
						}
						return true
					})
				}
			}
		case rel == "Makefile" || strings.HasPrefix(d.Name(), "Dockerfile") ||
			(strings.HasPrefix(rel, ".github/workflows/") && (strings.HasSuffix(rel, ".yml") || strings.HasSuffix(rel, ".yaml"))) ||
			((strings.HasPrefix(rel, "deploy/") || strings.HasPrefix(rel, "tools/")) && strings.HasSuffix(rel, ".sh")) ||
			(strings.HasPrefix(rel, "tools/") && d.Name() != ".DS_Store"):
			if readerNameAllowed[rel] {
				return nil
			}
			scanned++
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			for i, line := range strings.Split(string(b), "\n") {
				if strings.HasPrefix(strings.TrimSpace(line), "#") {
					continue
				}
				code, _, _ := strings.Cut(line, " #")
				if h := namer.hit(code); h != "" {
					problems = append(problems, fmt.Sprintf("%s:%d names %q: only the tests and tools of the reader set may read a documentation file (docs/DESIGN.md, Reader set)", rel, i+1, h))
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// (2) and (3), per directory.
	tests := map[string]bool{} // "dir Name" of every Test in an untagged file
	for _, dir := range slices.Sorted(maps.Keys(dirs)) {
		df := dirs[dir]
		pkgNames := map[string]bool{}
		for _, f := range df.files {
			pkgNames[strings.TrimSuffix(f.Name.Name, "_test")] = true
		}
		nodes := map[string]*readerNode{}
		add := func(key string, n *readerNode) {
			if old, ok := nodes[key]; ok { // the same name in two files or two receivers: merge
				old.edges = append(old.edges, n.edges...)
				if old.literal == "" {
					old.literal = n.literal
				}
				return
			}
			nodes[key] = n
		}
		var testNodes []*readerNode
		var testFiles []readerFile
		for i, f := range df.files {
			info := df.info[i]
			collect := func(root ast.Node, n *readerNode) {
				sels := map[*ast.Ident]bool{}
				ast.Inspect(root, func(x ast.Node) bool {
					switch v := x.(type) {
					case *ast.BasicLit:
						if v.Kind == token.STRING && n.literal == "" && namer.hit(literalValue(v)) != "" {
							n.literal = literalValue(v)
						}
					case *ast.SelectorExpr:
						sels[v.Sel] = true
						n.edges = append(n.edges, "m:"+v.Sel.Name)
						if id, ok := v.X.(*ast.Ident); ok && pkgNames[id.Name] {
							n.edges = append(n.edges, "f:"+v.Sel.Name)
						}
					case *ast.Ident:
						if !sels[v] {
							n.edges = append(n.edges, "f:"+v.Name)
						}
					}
					return true
				})
			}
			for _, decl := range f.Decls {
				switch d := decl.(type) {
				case *ast.FuncDecl:
					n := &readerNode{file: info.rel, name: d.Name.Name}
					if d.Body != nil {
						collect(d.Body, n)
					}
					if d.Recv != nil {
						add("m:"+d.Name.Name, n)
						continue
					}
					n.isTest = strings.HasPrefix(d.Name.Name, "Test")
					if n.isTest {
						// A Test function is a node of its own: two files never share one.
						testNodes = append(testNodes, n)
						testFiles = append(testFiles, info)
						if !info.tagged {
							tests[dir+" "+d.Name.Name] = true
						}
						nodes["t:"+info.rel+":"+d.Name.Name] = n
						continue
					}
					add("f:"+d.Name.Name, n)
				case *ast.GenDecl:
					for _, spec := range d.Specs {
						vs, ok := spec.(*ast.ValueSpec)
						if !ok {
							continue
						}
						for _, id := range vs.Names {
							n := &readerNode{file: info.rel, name: id.Name}
							for _, v := range vs.Values {
								collect(v, n)
							}
							add("f:"+id.Name, n)
						}
					}
				}
			}
		}
		for i, tn := range testNodes {
			// Breadth-first through the functions, methods, variables and
			// constants it uses.
			seen := map[*readerNode]bool{tn: true}
			queue := []*readerNode{tn}
			var holder *readerNode
			for len(queue) > 0 && holder == nil {
				n := queue[0]
				queue = queue[1:]
				if n.literal != "" {
					holder = n
					break
				}
				for _, e := range n.edges {
					if m, ok := nodes[e]; ok && !seen[m] {
						seen[m] = true
						queue = append(queue, m)
					}
				}
			}
			if holder == nil {
				continue
			}
			info := testFiles[i]
			readers = append(readers, info.rel+":"+tn.name)
			via := ""
			if holder != tn {
				via = " through " + holder.name + " (" + holder.file + ")"
			}
			switch {
			case info.tagged:
				if !acceptedPostgresReaders[tn.name] {
					problems = append(problems, fmt.Sprintf("%s: %s names %q%s in a tagged file: only %s may (docs/DESIGN.md, Reader set)",
						info.rel, tn.name, holder.literal, via, strings.Join(slices.Sorted(maps.Keys(acceptedPostgresReaders)), " and ")))
				}
			case dir == "tools/trace":
			case names[tn.name] && pkgs[dir]:
			default:
				problems = append(problems, fmt.Sprintf("%s: %s names %q%s but is not in the reader set: add it to the -run pattern of the docs job of ci.yml and to docs/DESIGN.md (Reader set), or do not read the file",
					info.rel, tn.name, holder.literal, via))
			}
		}
	}
	for _, n := range slices.Sorted(maps.Keys(names)) {
		found := false
		for p := range pkgs {
			found = found || tests[p+" "+n]
		}
		if !found {
			problems = append(problems, fmt.Sprintf(".github/workflows/ci.yml: the -run pattern of the docs job names %s, which is not a Test function in a make check file in one of its packages", n))
		}
	}
	return problems, readers, scanned
}

func literalValue(lit *ast.BasicLit) string {
	if v, err := strconv.Unquote(lit.Value); err == nil {
		return v
	}
	return lit.Value
}

// writeTree writes the files under root.
func writeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for name, body := range files {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// readerFixture is a small tree that passes the guard: a reader in the pattern
// in each of two packages (one through a helper, one through a constant), the
// two accepted postgres readers, the trace tool and its test, and comment lines
// that name documentation files.
func readerFixture(t *testing.T, script string) map[string]string {
	t.Helper()
	return map[string]string{
		"deploy/ops/changed-files.sh": script,
		"deploy/ops/release-check.sh": "#!/bin/sh\nawk 1 docs/DESIGN.md\n",
		".github/workflows/ci.yml": `name: ci
on:
  pull_request:
jobs:
  docs:
    runs-on: x
    steps:
      - uses: actions/checkout@x
        with:
          fetch-depth: 0
      # make trace reads docs/DESIGN.md
      - run: make trace
      - run: go test -count=1 ./tools/trace/
      - run: go test -count=1 -run '^(TestReadsDesign|TestReadsGuide)$' ./a/ ./b/
`,
		"Makefile":                  "# make trace reads docs/DESIGN.md and tools/trace/pending.txt\ntrace:\n\tgo run ./tools/trace # reads README.md\n",
		"README.md":                 "# Fixture\n",
		"docs/DESIGN.md":            "# Design\n",
		"docs/USER_GUIDE.md":        "# Guide\n",
		"a/a.go":                    "package a\n\n// A is named in README.md.\nfunc A() string { return \"a\" }\n",
		"a/a_test.go":               "package a\n\nimport \"testing\"\n\nfunc design() string { return \"../docs/DESIGN.md\" }\n\nfunc TestReadsDesign(t *testing.T) { _ = design() }\n\nfunc TestPure(t *testing.T) {}\n",
		"b/b_test.go":               "package b_test\n\nimport \"testing\"\n\nconst guide = \"../docs/USER_GUIDE.md\"\n\nfunc TestReadsGuide(t *testing.T) { _ = guide }\n",
		"b/pg_test.go":              "//go:build postgres\n\npackage b_test\n\nimport \"testing\"\n\nfunc TestPostgresSchemaMatchesDesign(t *testing.T) { _ = \"../docs/DESIGN.md\" }\n\nfunc TestCopyCoversEveryTableOfTheSchema(t *testing.T) { _ = design2() }\n\nfunc design2() string { return \"DESIGN.md\" }\n",
		"tools/trace/main.go":       "package main\n\nvar design = \"docs/DESIGN.md\"\n\nfunc main() { _ = design }\n",
		"tools/trace/trace_test.go": "package main\n\nimport \"testing\"\n\nfunc TestRealDesign(t *testing.T) { _ = \"../../docs/DESIGN.md\"; _ = \"pending.txt\" }\n",
		"tools/trace/pending.txt":   "# Entries not yet covered (docs/DESIGN.md).\n",
	}
}

// Proves OPS-02 (documentation-only changes): see the pass conditions of the row; OPS ids are not traced.
// Acceptance: Documentation reader set
func TestOnlyTheReaderSetReadsDocumentation(t *testing.T) {
	t.Run("the docs job of ci.yml runs the reader set", func(t *testing.T) {
		w, _ := readWorkflow(t, "ci.yml")
		j, ok := w.Jobs["docs"]
		if !ok {
			t.Fatal("ci.yml has no docs job")
		}
		if !j.needs("changes") || j.RunsOn != runnerExpr {
			t.Errorf("docs needs %v, runs on %q; want changes and the runner", j.Needs, j.RunsOn)
		}
		if len(j.Steps) == 0 || !strings.HasPrefix(j.Steps[0].Uses, "actions/checkout@") ||
			j.Steps[0].With["fetch-depth"] != "0" || j.Steps[0].With["persist-credentials"] != "false" {
			t.Fatalf("docs must start with a checkout with fetch-depth: 0 and no persisted credentials: %+v", j.Steps)
		}
		var runs []string
		for _, s := range j.Steps[1:] {
			switch {
			case s.Run != "":
				runs = append(runs, strings.TrimSpace(s.Run))
			case strings.HasPrefix(s.Uses, "actions/setup-go@") && s.With["go-version-file"] == "go.mod":
			default:
				t.Errorf("docs has an unexpected step %+v", s)
			}
		}
		want := []string{"make trace", "go test -count=1 ./tools/trace/", "go test -count=1 -run '" + readerPattern + "' " + readerPackages}
		if !slices.Equal(runs, want) {
			t.Errorf("docs runs\n%q\nwant, in order,\n%q", runs, want)
		}
	})

	t.Run("this repository", func(t *testing.T) {
		problems, readers, scanned := readerSetProblems(t, "..")
		for _, p := range problems {
			t.Error(p)
		}
		if scanned < 100 {
			t.Errorf("only %d files scanned; the walk is wrong", scanned)
		}
		// The scan must see the readers the design names, or it proves nothing.
		for _, r := range []string{
			"deploy/conformance_results_test.go:TestConformanceResultsRecordSuiteVersion",
			"deploy/release_check_test.go:TestReleaseCheckBeforeTheTag",
			"internal/store/store_test.go:TestSchemaMatchesDesign",
			"internal/config/validate_test.go:TestEveryPossibleValueHasARule",
			"cmd/featherauth/runbook_wiring_test.go:TestRunbookCommandsExist",
			"internal/store/postgres_test.go:TestPostgresSchemaMatchesDesign",
			"tools/trace/trace_test.go:TestRealDesign",
		} {
			if !slices.Contains(readers, r) {
				t.Errorf("the scan does not see the reader %s; found %v", r, readers)
			}
		}
	})

	script := readFile(t, "ops/changed-files.sh")
	t.Run("the fixture passes", func(t *testing.T) {
		root := t.TempDir()
		writeTree(t, root, readerFixture(t, script))
		problems, readers, _ := readerSetProblems(t, root)
		if len(problems) != 0 {
			t.Errorf("problems on the clean fixture: %q", problems)
		}
		want := []string{"a/a_test.go:TestReadsDesign", "b/b_test.go:TestReadsGuide", "b/pg_test.go:TestCopyCoversEveryTableOfTheSchema", "b/pg_test.go:TestPostgresSchemaMatchesDesign", "tools/trace/trace_test.go:TestRealDesign"}
		slices.Sort(readers)
		if !slices.Equal(readers, want) {
			t.Errorf("readers = %q, want %q", readers, want)
		}
	})

	for _, tc := range []struct {
		name   string
		change func(files map[string]string)
		want   []string // substrings of the one problem; nil for none
	}{
		{"a new untagged test reading the user guide", func(f map[string]string) {
			f["a/new_test.go"] = "package a\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\nfunc TestNewReader(t *testing.T) { _, _ = os.ReadFile(\"../docs/USER_GUIDE.md\") }\n"
		}, []string{"a/new_test.go", "TestNewReader", "docs/USER_GUIDE.md"}},
		{"an untagged helper called by a test outside the pattern", func(f map[string]string) {
			f["a/helper_test.go"] = "package a\n\nfunc loadDesign() string { return helperPath() }\n\nfunc helperPath() string { return \"docs/DESIGN.md\" }\n"
			f["a/uses_test.go"] = "package a\n\nimport \"testing\"\n\nfunc TestUsesHelper(t *testing.T) { _ = loadDesign() }\n"
		}, []string{"a/uses_test.go", "TestUsesHelper", "helperPath"}},
		{"a method that reads, called by a test outside the pattern", func(f map[string]string) {
			f["a/env_test.go"] = "package a\n\nimport \"testing\"\n\ntype env struct{}\n\nfunc (env) results() string { return \"../docs/RESULTS.md\" }\n\nfunc TestEnv(t *testing.T) { var e env; _ = e.results() }\n"
			f["docs/RESULTS.md"] = "# Results\n"
		}, []string{"a/env_test.go", "TestEnv", "RESULTS.md"}},
		{"a browser-tagged reader", func(f map[string]string) {
			f["a/b_browser_test.go"] = "//go:build browser\n\npackage a\n\nimport \"testing\"\n\nfunc TestBrowserReads(t *testing.T) { _ = \"../README.md\" }\n"
		}, []string{"a/b_browser_test.go", "TestBrowserReads", "tagged file"}},
		{"an ops-tagged reader", func(f map[string]string) {
			f["a/o_test.go"] = "//go:build ops\n\npackage a\n\nimport \"testing\"\n\nfunc TestOpsReads(t *testing.T) { _ = \".claude/settings.json\" }\n"
		}, []string{"a/o_test.go", "TestOpsReads"}},
		{"a third postgres-tagged reader", func(f map[string]string) {
			f["b/pg2_test.go"] = "//go:build postgres\n\npackage b_test\n\nimport \"testing\"\n\nfunc TestPostgresThird(t *testing.T) { _ = design2() }\n"
		}, []string{"b/pg2_test.go", "TestPostgresThird", "design2"}},
		{"a package-level constant used by a test outside the pattern", func(f map[string]string) {
			f["b/const_test.go"] = "package b_test\n\nimport \"testing\"\n\nconst resultsPath = \"../docs/RESULTS.md\"\n\nfunc TestUsesConst(t *testing.T) { _ = resultsPath }\n"
		}, []string{"b/const_test.go", "TestUsesConst", "resultsPath", "docs/RESULTS.md"}},
		{"a reader outside the pattern in a !postgres file", func(f map[string]string) {
			f["a/np_test.go"] = "//go:build !postgres\n\npackage a\n\nimport \"testing\"\n\nfunc TestNoPostgresReads(t *testing.T) { _ = \"../docs/DESIGN.md\" }\n"
		}, []string{"a/np_test.go", "TestNoPostgresReads", "not in the reader set"}},
		{"a reader outside the pattern in a file limited to operating systems", func(f map[string]string) {
			f["a/os_test.go"] = "//go:build darwin || linux\n\npackage a\n\nimport \"testing\"\n\nfunc TestOSReads(t *testing.T) { _ = \"../docs/DESIGN.md\" }\n"
		}, []string{"a/os_test.go", "TestOSReads", "not in the reader set"}},
		{"a reader in a conformance, load or ops file", func(f map[string]string) {
			f["a/clo_test.go"] = "//go:build conformance || load || ops\n\npackage a\n\nimport \"testing\"\n\nfunc TestCLOReads(t *testing.T) { _ = \"../docs/RESULTS.md\" }\n"
		}, []string{"a/clo_test.go", "TestCLOReads", "tagged file"}},
		{"a Dockerfile naming README.md", func(f map[string]string) {
			f["deploy/Dockerfile"] = "# the image\nFROM scratch\nCOPY README.md /README.md\n"
		}, []string{"deploy/Dockerfile:3", "README.md"}},
		{"a Dockerfile variant naming CLAUDE.md", func(f map[string]string) {
			f["Dockerfile.dev"] = "FROM scratch\nCOPY CLAUDE.md /x\n"
		}, []string{"Dockerfile.dev:2", "CLAUDE.md"}},
		{"a load-tagged reader is not scanned", func(f map[string]string) {
			f["a/l_test.go"] = "//go:build load\n\npackage a\n\nimport \"testing\"\n\nfunc TestLoadReads(t *testing.T) { _ = \"../docs/RESULTS.md\" }\n"
		}, nil},
		{"a reader in a package outside the step", func(f map[string]string) {
			f["c/c_test.go"] = "package c\n\nimport \"testing\"\n\nfunc TestReadsDesign(t *testing.T) { _ = \"../docs/DESIGN.md\" }\n"
		}, []string{"c/c_test.go", "TestReadsDesign"}},
		{"a pattern naming a test that does not exist", func(f map[string]string) {
			f[".github/workflows/ci.yml"] = strings.Replace(f[".github/workflows/ci.yml"], "TestReadsGuide)", "TestReadsGuide|TestMissing)", 1)
		}, []string{"ci.yml", "TestMissing"}},
		{"a pattern naming a tagged test", func(f map[string]string) {
			f[".github/workflows/ci.yml"] = strings.Replace(f[".github/workflows/ci.yml"], "TestReadsGuide)", "TestReadsGuide|TestPostgresSchemaMatchesDesign)", 1)
		}, []string{"ci.yml", "TestPostgresSchemaMatchesDesign"}},
		{"a list in changed-files.sh that differs", func(f map[string]string) {
			f["deploy/ops/changed-files.sh"] = strings.Replace(f["deploy/ops/changed-files.sh"], "CLAUDE.md ", "", 1)
		}, []string{"deploy/ops/changed-files.sh", "# BEGIN list"}},
		{"a Makefile recipe naming README.md", func(f map[string]string) {
			f["Makefile"] += "readme:\n\tcat README.md\n"
		}, []string{"Makefile:5", "README.md"}},
		{"a workflow step naming README.md", func(f map[string]string) {
			f[".github/workflows/other.yml"] = "jobs:\n  x:\n    steps:\n      - run: cat README.md\n"
		}, []string{".github/workflows/other.yml:4", "README.md"}},
		{"a script under deploy naming pending.txt", func(f map[string]string) {
			f["deploy/ops/x.sh"] = "#!/bin/sh\n# reads nothing\ncat tools/trace/pending.txt\n"
		}, []string{"deploy/ops/x.sh:3", "pending.txt"}},
		{"a non-test Go file naming README.md", func(f map[string]string) {
			f["a/a.go"] = "package a\n\n// A is named in README.md.\nfunc A() string { return \"../README.md\" }\n"
		}, []string{"a/a.go:4", "in A", "README.md"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files := readerFixture(t, script)
			tc.change(files)
			root := t.TempDir()
			writeTree(t, root, files)
			problems, _, _ := readerSetProblems(t, root)
			if tc.want == nil {
				if len(problems) != 0 {
					t.Errorf("problems = %q, want none", problems)
				}
				return
			}
			if len(problems) != 1 {
				t.Fatalf("problems = %q, want exactly one naming %q", problems, tc.want)
			}
			for _, w := range tc.want {
				if !strings.Contains(problems[0], w) {
					t.Errorf("the problem %q does not name %q", problems[0], w)
				}
			}
		})
	}
}

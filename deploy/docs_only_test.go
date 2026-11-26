package deploy_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
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
		"GH_TOKEN": "${{ github.token }}",
	} {
		if s.Env[k] != v {
			t.Errorf("env %s = %q, want %q", k, s.Env[k], v)
		}
	}
	if strings.Contains(s.Run, "${{") {
		t.Error("an expression is interpolated inside run:")
	}
	for _, o := range []string{"docs_only", "slow_skip"} {
		if got, want := j.Outputs[o], "${{ steps."+s.ID+".outputs."+o+" }}"; got != want {
			t.Errorf("output %s = %q, want %q", o, got, want)
		}
	}
	if len(j.Outputs) != 2 {
		t.Errorf("outputs = %v, want docs_only and slow_skip", j.Outputs)
	}

	// Run the real text. A pull request reads the files in compare mode; any other
	// event says false and never calls gh.
	docs := cfCompare(cfJSON(cfNames("README.md")...))
	code := cfCompare(cfJSON(cfNames("README.md", "main.go")...))
	pending := cfCompare(cfJSON(cfNames("tools/trace/pending.txt")...))
	comment := cfCompare(cfJSON(goFile(h, "+// a")))
	contents := "0 repos/owner/name/contents/internal/x/x.go?ref=" + cfHead + "\n"
	covers := cfCompare(cfJSON(goFile(h, "+// Covers: FR-16")))
	for _, tc := range []struct {
		name, event string
		c           cfCase
		want        string
		calls       string
	}{
		{"pull request, docs", "pull_request", docs, cfLines(true, true), "1 repos/owner/name/compare/" + cfBase + "..." + cfHead + "?per_page=100\n"},
		{"pull request, code", "pull_request", code, cfLines(false, false), "1 repos/owner/name/compare/" + cfBase + "..." + cfHead + "?per_page=100\n"},
		{"pull request, only a Go comment", "pull_request", comment, cfLines(true, true), "1 repos/owner/name/compare/" + cfBase + "..." + cfHead + "?per_page=100\n" + contents},
		{"pull request, a Covers line", "pull_request", covers, cfLines(false, false), "1 repos/owner/name/compare/" + cfBase + "..." + cfHead + "?per_page=100\n"},
		{"pull request, only pending.txt", "pull_request", pending, cfLines(false, true), "1 repos/owner/name/compare/" + cfBase + "..." + cfHead + "?per_page=100\n"},
		{"push", "push", docs, cfLines(false, false), ""},
		{"called from deploy.yml (push)", "push", docs, cfLines(false, false), ""},
		{"workflow_dispatch", "workflow_dispatch", docs, cfLines(false, false), ""},
		{"empty event", "", docs, cfLines(false, false), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path, dir := cfFakeGH(t, tc.c)
			_, se, out, err := runStep(t, s.Run, "..", path, "EVENT="+tc.event, "REPO=owner/name", "BASE="+cfBase, "HEAD="+cfHead, "GH_TOKEN=x")
			if err != nil {
				t.Fatalf("%v\n%s", err, se)
			}
			if out != tc.want {
				t.Errorf("GITHUB_OUTPUT = %q, want %q", out, tc.want)
			}
			calls, _ := os.ReadFile(filepath.Join(dir, "calls.log"))
			if string(calls) != tc.calls {
				t.Errorf("gh calls = %q, want %q", calls, tc.calls)
			}
		})
	}
}

// check, browser, ops and postgres need changes. check runs unless docs_only is
// exactly 'true'; browser, ops and postgres run unless docs_only or slow_skip is
// exactly 'true'
// (a change of tools/trace/pending.txt alone skips the slow jobs, never check,
// which runs make trace). A changes job that failed or was cancelled must not
// skip them: the condition has !cancelled(), so success() is not added
// implicitly.
//
// Proves OPS-02 (documentation-only changes): see the pass conditions of the row; OPS ids are not traced.
// Acceptance: Documentation-only changes (part)
func TestCIJobsSkipOnDocsOnly(t *testing.T) {
	w, _ := readWorkflow(t, "ci.yml")
	for _, name := range []string{"check", "browser", "ops", "postgres"} {
		j := w.Jobs[name]
		if !j.needs("changes") {
			t.Errorf("%s does not need changes", name)
		}
		for _, changesRes := range results4 {
			for _, docs := range []string{"true", "false", "TRUE", "yes", ""} {
				for _, slow := range []string{"true", "false", "TRUE", "yes", ""} {
					for _, cancelled := range []bool{false, true} {
						ctx := exprCtx{
							runCancelled: cancelled,
							results:      map[string]string{"changes": changesRes},
							outputs:      map[string]string{"changes.docs_only": docs, "changes.slow_skip": slow},
						}
						got := jobRuns(t, j, []string{"changes"}, ctx)
						// Skipped only when the flag is 'true' (GitHub compares strings
						// without case, so 'TRUE' is true too) or the run was cancelled;
						// a failed, cancelled or skipped changes job runs the tests.
						want := !cancelled && !strings.EqualFold(docs, "true")
						if name != "check" {
							want = want && !strings.EqualFold(slow, "true")
						}
						if got != want {
							t.Errorf("%s runs = %v with changes %s, docs_only %q, slow_skip %q, cancelled %v; want %v",
								name, got, changesRes, docs, slow, cancelled, want)
						}
					}
				}
			}
		}
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
		// pending.txt alone skips only the slow jobs of a pull request; on a push
		// the checks run.
		{"only pending.txt", "branch", with(func(c *dtCase) { c.files = cfNames("tools/trace/pending.txt") }), "false", false},
		{"design", "branch", with(func(c *dtCase) { c.files = cfNames("docs/DESIGN.md") }), "false", false},
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

// The job output skip is true for a tree match or for a documentation-only
// commit; docs_only comes from the docs step only.
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
			if want := tree == "true" || docs == "true"; got != want {
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
			docs = strings.Contains(s.Run, "documentation-only") && strings.Contains(s.Run, "image")
		default:
			t.Errorf("summary step with if %q", s.If)
		}
	}
	if !tree || !docs {
		t.Errorf("job summary reasons: tree match %v, documentation-only %v; want both named", tree, docs)
	}
}

// checks, build and deploy for every combination of what tested says.
//
// Proves OPS-02 (documentation-only changes): see the pass conditions of the row; OPS ids are not traced.
// Acceptance: Documentation-only changes
func TestDeployJobConditionTable(t *testing.T) {
	w, _ := readWorkflow(t, "deploy.yml")
	checks, build, deploy := w.Jobs["checks"], w.Jobs["build"], w.Jobs["deploy"]
	// GitHub's implicit success() looks at every ancestor in the needs chain, not
	// only the direct needs: deploy needs build, build needs checks, so a skipped
	// checks job skips deploy unless its if: names a status function.
	deployAncestors := []string{"tested", "build", "checks"}
	for _, testedRes := range results4 {
		for _, tree := range []string{"true", "false"} {
			for _, docs := range []string{"true", "false"} {
				// What the tested job outputs: skip is true for either reason.
				skip := "false"
				if tree == "true" || docs == "true" {
					skip = "true"
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
										t.Errorf("checks runs = %v with tested %s, skip %s; want %v", got, testedRes, skip, want)
									}
									wantBuild := !cancelled && testedRes == "success" &&
										(checksRes == "success" || (checksRes == "skipped" && skip == "true"))
									if got := jobRuns(t, build, []string{"tested", "checks"}, ctx); got != wantBuild {
										t.Errorf("build runs = %v with tested %s, skip %s (tree %s, docs %s), checks %s, cancelled %v; want %v",
											got, testedRes, skip, tree, docs, checksRes, cancelled, wantBuild)
									}
									wantDeploy := !cancelled && testedRes == "success" && buildRes == "success" &&
										deployPath != "" && ref == "branch" && docs != "true"
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
	// The named case of the design: a documentation-only commit skips the
	// checks and the deploy and still builds.
	ctx := exprCtx{
		results: map[string]string{"tested": "success", "checks": "skipped", "build": "success"},
		outputs: map[string]string{"tested.skip": "true", "tested.docs_only": "true"},
		vals:    map[string]string{"vars.DEPLOY_PATH": "/srv/x", "github.ref_type": "branch"},
	}
	if jobRuns(t, checks, []string{"tested"}, ctx) {
		t.Error("checks run for a documentation-only commit")
	}
	if !jobRuns(t, build, []string{"tested", "checks"}, ctx) {
		t.Error("build does not run for a documentation-only commit")
	}
	if jobRuns(t, deploy, deployAncestors, ctx) {
		t.Error("deploy runs for a documentation-only commit")
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

// The list of documentation-only files lives only in changed-files.sh. No Go
// source (string literals only; comments may name the files), no Makefile and
// no workflow, Dockerfile, .dockerignore, shell script under deploy/ or tools/ and
// no non-Go file under tools/ (comment lines and trailing comments ignored) may
// read one of them: a test that reads README.md would not run on a documentation-only
// change. The files that define or test the list are excluded.
//
// Proves OPS-02 (documentation-only changes): see the pass conditions of the row; OPS ids are not traced.
// Acceptance: Documentation-only changes (part)
func TestNoCodeReadsADocumentationOnlyFile(t *testing.T) {
	script := readFile(t, "ops/changed-files.sh")
	m := regexp.MustCompile(`(?m)^doc_files='([^']*)'\ndoc_dirs='([^']*)'$`).FindStringSubmatch(script)
	if m == nil {
		t.Fatal("changed-files.sh has no doc_files and doc_dirs lines")
	}
	files, dirs := strings.Fields(m[1]), strings.Fields(m[2])
	wantFiles := []string{"README.md", "CLAUDE.md", "docs/RELEASING.md", "deploy/ASSETS.md"}
	if strings.Join(files, " ") != strings.Join(wantFiles, " ") || strings.Join(dirs, " ") != ".claude/" {
		t.Errorf("the list in changed-files.sh is %v and %v, want the list of docs/DESIGN.md: %v and .claude/", files, dirs, wantFiles)
	}
	names := append([]string{}, files...)
	names = append(names, ".claude")
	hint := "the list in deploy/ops/changed-files.sh and in docs/DESIGN.md (CI/CD, Documentation-only changes) must change, or the file must not be read"
	hit := func(s string) string {
		for _, n := range names {
			if strings.Contains(s, n) {
				return n
			}
		}
		return ""
	}
	root := ".."
	excluded := map[string]bool{
		"deploy/changed_files_test.go":    true, // names the list to test the script
		"deploy/changed_files_go_test.go": true, // the same, for the Go comment and pending.txt cases
		"deploy/docs_only_test.go":        true, // this test
		"deploy/ops/changed-files.sh":     true, // holds the list
	}
	var scanned int
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
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
		if excluded[rel] {
			return nil
		}
		switch {
		case strings.HasSuffix(rel, ".go"):
			scanned++
			f, err := parser.ParseFile(token.NewFileSet(), p, nil, parser.SkipObjectResolution)
			if err != nil {
				t.Errorf("%s: %v", rel, err)
				return nil
			}
			ast.Inspect(f, func(n ast.Node) bool {
				if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
					v, err := strconv.Unquote(lit.Value)
					if err != nil {
						v = lit.Value
					}
					if h := hit(v); h != "" {
						t.Errorf("%s reads %q in a string: %s", rel, h, hint)
					}
				}
				return true
			})
		case rel == "Makefile" || rel == "deploy/Dockerfile" || rel == ".dockerignore" ||
			(strings.HasPrefix(rel, ".github/workflows/") && (strings.HasSuffix(rel, ".yml") || strings.HasSuffix(rel, ".yaml"))) ||
			((strings.HasPrefix(rel, "deploy/") || strings.HasPrefix(rel, "tools/")) && strings.HasSuffix(rel, ".sh")) ||
			(strings.HasPrefix(rel, "tools/") && !strings.HasSuffix(rel, ".go") && d.Name() != ".DS_Store"):
			scanned++
			for i, line := range strings.Split(readFile(t, p), "\n") {
				if strings.HasPrefix(strings.TrimSpace(line), "#") {
					continue
				}
				code, _, _ := strings.Cut(line, " #")
				if h := hit(code); h != "" {
					t.Errorf("%s:%d reads %q: %s", rel, i+1, h, hint)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if scanned < 20 {
		t.Errorf("only %d files scanned; the walk is wrong", scanned)
	}
	// The check itself must see a read: a fabricated source with a literal.
	f, err := parser.ParseFile(token.NewFileSet(), "x.go", "package x\nvar _ = \"../README.md\"\n", 0)
	if err != nil {
		t.Fatal(err)
	}
	var seen bool
	ast.Inspect(f, func(n ast.Node) bool {
		if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING && hit(lit.Value) != "" {
			seen = true
		}
		return true
	})
	if !seen {
		t.Error("the scan does not recognise a string literal naming README.md")
	}
}

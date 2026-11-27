package deploy_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// changed-files.sh is run against a fake gh. Like the fake of the tested-tree
// tests it answers by endpoint from canned JSON files and applies the --jq
// expression with jq, so the expressions of the script are tested too (jq must
// be installed). The fake mimics gh: without --paginate only the first page is
// returned, with it every page is filtered on its own and the outputs are
// joined, and the endpoint must carry per_page=100 for the lists.

const (
	cfRepo  = "owner/name"
	cfSHA   = "0123456789abcdef0123456789abcdef01234567"
	cfBase  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	cfHead  = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	cfTitle = "TITLE-MUST-NOT-LEAK"
)

// The list of the design (CI/CD, "Documentation-only changes"), written out
// here on purpose: the script must agree with it. Every .md file under docs/
// is in it (today DESIGN.md, REQUIREMENTS.md, USER_GUIDE.md, RELEASING.md,
// RESULTS.md and the files under docs/audits/).
var cfDocs = []string{
	"README.md", "CLAUDE.md", "docs/DESIGN.md", "docs/REQUIREMENTS.md", "docs/USER_GUIDE.md",
	"docs/RELEASING.md", "docs/RESULTS.md", "docs/audits/2026-11-27-audit.md", "docs/PLAN.md",
	"deploy/ASSETS.md", "examples/web-app/README.md", "tools/trace/pending.txt",
	".claude/settings.json", ".claude/agents/x.md",
}

type cfFile struct {
	name, prev string
	raw        string // extra JSON members (status, patch, counts); a "status" in it replaces the default
}

func cfJSON(files ...cfFile) string {
	var parts []string
	for _, f := range files {
		s := fmt.Sprintf(`{"sha":"x","filename":%q`, f.name)
		if !strings.Contains(f.raw, `"status"`) {
			s += `,"status":"modified"`
		}
		if f.prev != "" {
			s += fmt.Sprintf(`,"previous_filename":%q`, f.prev)
		}
		if f.raw != "" {
			s += "," + f.raw
		}
		parts = append(parts, s+"}")
	}
	return "[" + strings.Join(parts, ",") + "]"
}

// cfPatchFile is a modified file with a patch (the lines joined with newlines)
// and the additions and deletions counts GitHub gives.
func cfPatchFile(name string, lines ...string) cfFile {
	var add, del int
	for _, l := range lines {
		switch {
		case strings.HasPrefix(l, "+"):
			add++
		case strings.HasPrefix(l, "-"):
			del++
		}
	}
	patch, _ := json.Marshal(strings.Join(lines, "\n"))
	return cfFile{name: name, raw: fmt.Sprintf(`"patch":%s,"additions":%d,"deletions":%d`, patch, add, del)}
}

func cfNames(names ...string) []cfFile {
	var fs []cfFile
	for _, n := range names {
		fs = append(fs, cfFile{name: n})
	}
	return fs
}

// cfContent is the answer of the contents API for a file with this text.
func cfContent(text string) string {
	b := base64.StdEncoding.EncodeToString([]byte(text))
	var lines []string
	for len(b) > 60 {
		lines = append(lines, b[:60])
		b = b[60:]
	}
	lines = append(lines, b)
	enc, _ := json.Marshal(strings.Join(lines, "\n") + "\n")
	return fmt.Sprintf(`{"type":"file","encoding":"base64","size":%d,"content":%s}`, len(text), enc)
}

func cfN(name string, n int) []cfFile {
	var fs []cfFile
	for range n {
		fs = append(fs, cfFile{name: name})
	}
	return fs
}

type cfCase struct {
	mode  string   // compare or commit
	pages []string // answers, one per page
	fail  []int    // 1-based pages for which gh exits 1
	// contents maps a path to the answer of the contents API for it. When nil,
	// every path gets a clean file (no backquote); otherwise a path that is not
	// in the map is a 404.
	contents     map[string]string
	contentsFail []string // paths for which gh exits 1
}

// cfWrap puts a JSON list into the object GitHub answers with (one page of a
// compare or of a commit); anything else is kept as it is.
func cfWrap(pages []string) []string {
	var out []string
	for _, p := range pages {
		if strings.HasPrefix(p, "[") {
			p = `{"files":` + p + `}`
		}
		out = append(out, p)
	}
	return out
}

func cfCompare(pages ...string) cfCase { return cfCase{mode: "compare", pages: cfWrap(pages)} }
func cfCommit(pages ...string) cfCase  { return cfCase{mode: "commit", pages: cfWrap(pages)} }

func (c cfCase) args() []string {
	if c.mode == "compare" {
		return []string{cfRepo, "compare", cfBase, cfHead}
	}
	return []string{cfRepo, "commit", cfSHA}
}

func (c cfCase) endpoint() string {
	if c.mode == "compare" {
		return "repos/" + cfRepo + "/compare/" + cfBase + "..." + cfHead + "?per_page=100"
	}
	return "repos/" + cfRepo + "/commits/" + cfSHA + "?per_page=100"
}

func cfFakeGH(t *testing.T, c cfCase) (path, dir string) {
	t.Helper()
	if _, err := exec.LookPath("jq"); err != nil {
		t.Fatalf("jq is needed by the fake gh of these tests: %v", err)
	}
	dir = t.TempDir()
	k := "compare"
	if c.mode == "commit" {
		k = "commit"
	}
	for i, p := range c.pages {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("%s-%d.json", k, i+1)), []byte(p), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, i := range c.fail {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("%s-%d.fail", k, i)), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if c.contents == nil {
		if err := os.WriteFile(filepath.Join(dir, "contents-default.json"), []byte(cfContent("package x\n")), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for path, body := range c.contents {
		if err := os.WriteFile(filepath.Join(dir, "contents-"+strings.ReplaceAll(path, "/", "__")+".json"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range c.contentsFail {
		if err := os.WriteFile(filepath.Join(dir, "contents-"+strings.ReplaceAll(path, "/", "__")+".fail"), nil, 0o600); err != nil {
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
shift
pag=0; ep=; jq_expr=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --paginate) pag=1 ;;
    --jq) shift; jq_expr=$1 ;;
    -*) echo "fake gh: unknown flag $1" >&2; exit 64 ;;
    *) [ -z "$ep" ] || { echo "fake gh: two endpoints" >&2; exit 64; }; ep=$1 ;;
  esac
  shift
done
[ -n "$jq_expr" ] || { echo "fake gh: no --jq" >&2; exit 64; }
echo "$pag $ep" >> "$d/calls.log"
case "$ep" in
  repos/*/contents/*\?ref=*)
    f=$(printf '%s' "$ep" | sed 's|^repos/[^/]*/[^/]*/contents/||; s|?ref=.*$||; s|/|__|g')
    [ ! -e "$d/contents-$f.fail" ] || { echo "fake gh: HTTP 500" >&2; exit 1; }
    if [ -e "$d/contents-$f.json" ]; then src="$d/contents-$f.json"
    elif [ -e "$d/contents-default.json" ]; then src="$d/contents-default.json"
    else echo "fake gh: HTTP 404" >&2; exit 1; fi
    [ "$pag" = 0 ] || { echo "fake gh: contents must not be paginated" >&2; exit 64; }
    jq -r "$jq_expr" "$src" || exit 1
    exit 0 ;;
  repos/*/compare/*...*\?per_page=100) k=compare ;;
  repos/*/commits/*\?per_page=100) k=commit ;;
  *) echo "fake gh: unknown endpoint $ep" >&2; exit 64 ;;
esac
i=1
while [ -e "$d/$k-$i.json" ]; do
  [ ! -e "$d/$k-$i.fail" ] || { echo "fake gh: HTTP 500" >&2; exit 1; }
  jq -r "$jq_expr" "$d/$k-$i.json" || exit 1
  [ "$pag" = 1 ] || break
  i=$((i + 1))
done
[ "$i" -gt 1 ] || [ -e "$d/$k-1.json" ] || { echo "fake gh: no answer" >&2; exit 1; }
`
	if err := os.WriteFile(filepath.Join(bin, "gh"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin + ":" + os.Getenv("PATH"), dir
}

type cfResult struct {
	stdout, stderr string
	code           int
	calls          string
	output         string
	outputSet      bool
}

func runCF(t *testing.T, c cfCase, withOutput bool, args ...string) cfResult {
	t.Helper()
	path, dir := cfFakeGH(t, c)
	cmd := exec.CommandContext(t.Context(), "sh", append([]string{"ops/changed-files.sh"}, args...)...)
	env := append(os.Environ(), "PATH="+path, "GITHUB_OUTPUT=")
	outFile := filepath.Join(dir, "github_output")
	if withOutput {
		env = append(env, "GITHUB_OUTPUT="+outFile)
	}
	cmd.Env = env
	var so, se strings.Builder
	cmd.Stdout, cmd.Stderr = &so, &se
	err := cmd.Run()
	r := cfResult{stdout: so.String(), stderr: se.String()}
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

// cfLines is the output of the script: one line, docs_only.
func cfLines(docsOnly bool) string {
	return fmt.Sprintf("docs_only=%v\n", docsOnly)
}

func cfWant(t *testing.T, r cfResult, docsOnly bool) {
	t.Helper()
	want := cfLines(docsOnly)
	if r.code != 0 {
		t.Errorf("exit code %d, want 0\n%s", r.code, r.stderr)
	}
	if r.stdout != want {
		t.Errorf("stdout = %q, want %q", r.stdout, want)
	}
	if strings.Contains(r.stdout+r.stderr, cfTitle) {
		t.Errorf("API data reached the output: %q %q", r.stdout, r.stderr)
	}
}

// cfRun expects exactly the line docs_only=want on stdout and in GITHUB_OUTPUT.
func cfRun(t *testing.T, c cfCase, want bool) {
	t.Helper()
	r := runCF(t, c, true, c.args()...)
	cfWant(t, r, want)
	if exp := cfLines(want); r.output != exp {
		t.Errorf("GITHUB_OUTPUT = %q, want exactly %q", r.output, exp)
	}
}

func cfBoth(files []cfFile) map[string]cfCase {
	return map[string]cfCase{"compare": cfCompare(cfJSON(files...)), "commit": cfCommit(cfJSON(files...))}
}

// Proves OPS-02 (documentation-only changes): see the pass conditions of the row; OPS ids are not traced.
// Acceptance: Documentation-only changes (part)
func TestChangedFilesEveryListedFileAlone(t *testing.T) {
	for _, name := range cfDocs {
		for mode, c := range cfBoth(cfNames(name)) {
			t.Run(mode+" "+name, func(t *testing.T) { t.Parallel(); cfRun(t, c, true) })
		}
	}
	// All of them together, in one page.
	for mode, c := range cfBoth(cfNames(cfDocs...)) {
		t.Run(mode+" all", func(t *testing.T) { t.Parallel(); cfRun(t, c, true) })
	}
}

// Proves OPS-02 (documentation-only changes): see the pass conditions of the row; OPS ids are not traced.
// Acceptance: Documentation-only changes (part)
func TestChangedFilesCodeChanges(t *testing.T) {
	for _, tc := range []struct {
		name  string
		files []cfFile
	}{
		{"go file", cfNames("main.go")},
		{"one code file among docs", cfNames("README.md", "internal/x/x.go", "CLAUDE.md")},
		{"code file first", cfNames("main.go", "README.md")},
		{"plan file is not a documentation file", cfNames("PLAN.md")},
		{"plan file among docs", cfNames("README.md", "PLAN.md")},
		{"rename from a code file into docs", []cfFile{{name: "docs/DESIGN.md", prev: "internal/x/x.go"}}},
		{"readme in a subdirectory", cfNames("sub/README.md")},
		{"readme with a suffix", cfNames("README.md.bak")},
		{"readme lower case", cfNames("readme.md")},
		{"releasing in the root", cfNames("RELEASING.md")},
		{"design in the root", cfNames("DESIGN.md")},
		{"assets elsewhere", cfNames("ASSETS.md")},
		{"assets in a longer path", cfNames("deploy/ASSETS.md/x")},
		{"an image under docs/audits", cfNames("docs/audits/x.png")},
		{"an image under docs", cfNames("docs/assets/icon.png")},
		{"a non-md file under docs among docs", cfNames("docs/DESIGN.md", "docs/audits/x.png")},
		{"md upper case under docs", cfNames("docs/x.MD")},
		{"md with a suffix under docs", cfNames("docs/x.md.bak")},
		{"md suffix only under docs", cfNames("docs/.md")},
		{"md file named like the directory", cfNames("docs.md")},
		{"docs look-alike directory", cfNames("xdocs/a.md")},
		{"docs nested in another directory", cfNames("sub/docs/a.md")},
		{"docs upper case", cfNames("DOCS/a.md")},
		{"md file under deploy", cfNames("deploy/x.md")},
		{"another file of the example", cfNames("examples/web-app/package.json")},
		{"the example readme with code of the example", cfNames("examples/web-app/README.md", "examples/web-app/src/main.ts")},
		{"another readme under examples", cfNames("examples/README.md")},
		{"a readme deeper in the example", cfNames("examples/web-app/src/README.md")},
		{"pending with a suffix", cfNames("tools/trace/pending.txt.bak")},
		{"the trace tool", cfNames("tools/trace/main.go")},
		{"claude look-alike", cfNames(".claudeX/x")},
		{"claude file look-alike", cfNames(".claude")},
		{"claude nested in another directory", cfNames("x/.claude/y")},
		{"claude without the dot", cfNames("claude/x")},
		{"claude upper case", cfNames(".CLAUDE/x")},
		{"newline joins two listed names", cfNames("README.md\nCLAUDE.md")},
		{"newline hides a code name", cfNames("README.md\nmain.go")},
		{"newline hides a code name after a docs path", cfNames("docs/a.md\nmain.go")},
		{"title in a name", cfNames(cfTitle + "/x.go")},
		{"makefile", cfNames("Makefile")},
		{"workflow", cfNames(".github/workflows/ci.yml")},
		{"script", cfNames("deploy/ops/changed-files.sh")},
	} {
		for mode, c := range cfBoth(tc.files) {
			t.Run(mode+" "+tc.name, func(t *testing.T) { t.Parallel(); cfRun(t, c, false) })
		}
	}
}

// Proves OPS-02 (documentation-only changes): see the pass conditions of the row; OPS ids are not traced.
// Acceptance: Documentation-only changes (part)
func TestChangedFilesPreviousNames(t *testing.T) {
	for _, tc := range []struct {
		name  string
		files []cfFile
		want  bool
	}{
		{"rename inside the list", []cfFile{{name: "README.md", prev: "CLAUDE.md"}}, true},
		{"rename into the list from a code file", []cfFile{{name: "README.md", prev: "main.go"}}, false},
		{"rename out of the list into code", []cfFile{{name: "main.go", prev: "README.md"}}, false},
		{"rename from the design", []cfFile{{name: "docs/RELEASING.md", prev: "docs/DESIGN.md"}}, true},
		{"rename from the requirements into the list", []cfFile{{name: "README.md", prev: "docs/REQUIREMENTS.md"}}, true},
		{"rename into docs/audits", []cfFile{{name: "docs/audits/a.md", prev: "docs/RESULTS.md"}}, true},
		{"rename of an image into an md file", []cfFile{{name: "docs/audits/a.md", prev: "docs/audits/a.png"}}, false},
		{"rename of an md file into an image", []cfFile{{name: "docs/audits/a.png", prev: "docs/audits/a.md"}}, false},
		{"rename of pending.txt", []cfFile{{name: "tools/trace/pending.txt", prev: "tools/trace/old.txt"}}, false},
		{"rename inside .claude", []cfFile{{name: ".claude/a.md", prev: ".claude/b.md"}}, true},
		{"rename from a claude look-alike", []cfFile{{name: ".claude/a.md", prev: ".claudeX/a.md"}}, false},
		{"previous name null", []cfFile{{name: "README.md", prev: ""}}, true},
	} {
		for mode, c := range cfBoth(tc.files) {
			t.Run(mode+" "+tc.name, func(t *testing.T) { t.Parallel(); cfRun(t, c, tc.want) })
		}
	}
	// An explicit null previous name counts as none; a non-string one does not.
	for body, want := range map[string]bool{
		`[{"filename":"README.md","previous_filename":null}]`: true,
		`[{"filename":"README.md","previous_filename":5}]`:    false,
		`[{"filename":"README.md","previous_filename":""}]`:   false,
	} {
		t.Run("previous "+body, func(t *testing.T) {
			cfRun(t, cfCompare(body), want)
			cfRun(t, cfCommit(body), want)
		})
	}
}

// Proves OPS-02 (documentation-only changes): see the pass conditions of the row; OPS ids are not traced.
// Acceptance: Documentation-only changes (part)
func TestChangedFilesAnswersThatAreNotDocsOnly(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"empty list", "[]"},
		{"empty output", ""},
		{"garbage", "<html>not json"},
		{"truncated", `[{"filename":"README.md"`},
		{"error object", `{"message":"Not Found"}`},
		{"null", "null"},
		{"holds null", "[null]"},
		{"holds a number", "[1]"},
		{"holds a string", `["README.md"]`},
		{"file without a name", `[{"status":"modified"}]`},
		{"name is a number", `[{"filename":5}]`},
		{"name is null", `[{"filename":null}]`},
		{"name is a list", `[{"filename":["README.md"]}]`},
		{"name is empty", `[{"filename":""}]`},
		{"one good file and one without a name", `[{"filename":"README.md"},{}]`},
	} {
		t.Run("compare "+tc.name, func(t *testing.T) { t.Parallel(); cfRun(t, cfCompare(tc.body), false) })
	}
	for _, tc := range []struct{ name, body string }{
		{"no files key", `{"sha":"x"}`},
		{"files null", `{"files":null}`},
		{"files empty", `{"files":[]}`},
		{"files an object", `{"files":{"filename":"README.md"}}`},
		{"files a string", `{"files":"README.md"}`},
		{"empty output", ""},
		{"garbage", "}{"},
		{"error object", `{"message":"Not Found"}`},
		{"a list instead of an object", `[{"filename":"README.md"}]`},
	} {
		t.Run("commit "+tc.name, func(t *testing.T) {
			cfRun(t, cfCase{mode: "commit", pages: []string{tc.body}}, false)
		})
	}
}

// Proves OPS-02 (documentation-only changes): see the pass conditions of the row; OPS ids are not traced.
// Acceptance: Documentation-only changes (part)
func TestChangedFilesGhFailures(t *testing.T) {
	good := cfNames("README.md")
	c := cfCompare(cfJSON(good...))
	c.fail = []int{1}
	cfRun(t, c, false)
	c = cfCommit(cfJSON(good...))
	c.fail = []int{1}
	cfRun(t, c, false)
	// Pages 1 and 2 are documentation, page 3 fails: the list is not complete.
	c = cfCompare(cfJSON(good...), cfJSON(good...), cfJSON(good...))
	c.fail = []int{3}
	cfRun(t, c, false)
	c.fail = []int{2}
	cfRun(t, c, false)
	// The fake without any page at all (gh has nothing to answer).
	cfRun(t, cfCase{mode: "compare"}, false)
	cfRun(t, cfCase{mode: "commit"}, false)
}

// Proves OPS-02 (documentation-only changes): see the pass conditions of the row; OPS ids are not traced.
// Acceptance: Documentation-only changes (part)
func TestChangedFilesPagination(t *testing.T) {
	docs := cfJSON(cfNames("README.md", "CLAUDE.md")...)
	code := cfJSON(cfNames("README.md", "main.go")...)
	cfRun(t, cfCompare(docs, docs, docs), true)
	cfRun(t, cfCompare(docs, docs, code), false)
	cfRun(t, cfCompare(code, docs, docs), false)
	cfRun(t, cfCompare(docs, "[]", docs), true)
	cfRun(t, cfCompare(docs, docs, "garbage"), false)
	c := cfCompare(docs, docs)
	r := runCF(t, c, false, c.args()...)
	if want := "1 " + c.endpoint() + "\n"; r.calls != want {
		t.Errorf("gh calls = %q, want exactly %q (paginated, 100 per page)", r.calls, want)
	}
	c = cfCommit(docs, docs)
	r = runCF(t, c, false, c.args()...)
	if want := "1 " + c.endpoint() + "\n"; r.calls != want {
		t.Errorf("gh calls = %q, want exactly %q (paginated, 100 per page)", r.calls, want)
	}
	// A commit with 30+ documentation files on the first page and code on the
	// second (GitHub paginates the file list of a commit).
	first := cfJSON(cfN("README.md", 30)...)
	cfRun(t, cfCommit(first, docs), true)
	cfRun(t, cfCommit(first, code), false)
	cfRun(t, cfCommit(first, "garbage"), false)
	cfRun(t, cfCompare(first, code), false)
	// A first page with files only and a failing second page.
	f := cfCommit(first, docs)
	f.fail = []int{2}
	cfRun(t, f, false)
	f = cfCompare(first, docs)
	f.fail = []int{2}
	cfRun(t, f, false)
}

// Proves OPS-02 (documentation-only changes): see the pass conditions of the row; OPS ids are not traced.
// Acceptance: Documentation-only changes (part)
func TestChangedFilesSizeLimits(t *testing.T) {
	pages := func(n int) []string {
		var ps []string
		for n > 0 {
			k := min(n, 100)
			ps = append(ps, cfJSON(cfN("README.md", k)...))
			n -= k
		}
		return ps
	}
	cfRun(t, cfCompare(pages(2999)...), true)
	cfRun(t, cfCompare(pages(3000)...), false)
	cfRun(t, cfCompare(pages(3001)...), false)
	// The count is summed over the pages of a commit as well.
	cfRun(t, cfCommit(pages(299)...), true)
	cfRun(t, cfCommit(pages(300)...), false)
	cfRun(t, cfCommit(pages(301)...), false)
	cfRun(t, cfCommit(cfJSON(cfN("README.md", 150)...), cfJSON(cfN("README.md", 150)...)), false)
}

// Proves OPS-02 (documentation-only changes): see the pass conditions of the row; OPS ids are not traced.
// Acceptance: Documentation-only changes (part)
func TestChangedFilesWritesNothingWithoutGitHubOutput(t *testing.T) {
	c := cfCompare(cfJSON(cfNames("README.md")...))
	r := runCF(t, c, false, c.args()...)
	cfWant(t, r, true)
	if r.outputSet {
		t.Error("an output file was written without GITHUB_OUTPUT")
	}
	path, dir := cfFakeGH(t, c)
	out := filepath.Join(dir, "out")
	if err := os.WriteFile(out, []byte("a=b\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), "sh", append([]string{"ops/changed-files.sh"}, c.args()...)...)
	cmd.Env = append(os.Environ(), "PATH="+path, "GITHUB_OUTPUT="+out)
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(out); string(b) != "a=b\n"+cfLines(true) {
		t.Errorf("output file = %q", b)
	}
}

// Proves OPS-02 (documentation-only changes): see the pass conditions of the row; OPS ids are not traced.
// Acceptance: Documentation-only changes (part)
func TestChangedFilesRejectsBadArguments(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"no arguments", nil},
		{"two arguments", []string{cfRepo, "compare"}},
		{"compare with one sha", []string{cfRepo, "compare", cfBase}},
		{"compare with three shas", []string{cfRepo, "compare", cfBase, cfHead, cfHead}},
		{"commit with two shas", []string{cfRepo, "commit", cfSHA, cfSHA}},
		{"old pull mode", []string{cfRepo, "pull", "7"}},
		{"old pull mode with two more", []string{cfRepo, "pull", cfBase, cfHead}},
		{"mode empty", []string{cfRepo, "", cfSHA}},
		{"mode branch", []string{cfRepo, "branch", cfSHA}},
		{"mode upper case", []string{cfRepo, "Compare", cfBase, cfHead}},
		{"mode with suffix", []string{cfRepo, "commit ", cfSHA}},
		{"empty repository", []string{"", "compare", cfBase, cfHead}},
		{"empty repository (commit)", []string{"", "commit", cfSHA}},
		{"repository without owner", []string{"name", "compare", cfBase, cfHead}},
		{"repository without owner (commit)", []string{"name", "commit", cfSHA}},
		{"repository with two slashes", []string{"a/b/c", "compare", cfBase, cfHead}},
		{"repository with two slashes (commit)", []string{"a/b/c", "commit", cfSHA}},
		{"repository with space", []string{"a/b c", "compare", cfBase, cfHead}},
		{"repository with space (commit)", []string{"a/b c", "commit", cfSHA}},
		{"repository with semicolon", []string{"a/b;id", "compare", cfBase, cfHead}},
		{"repository with semicolon (commit)", []string{"a/b;id", "commit", cfSHA}},
		{"repository with substitution", []string{"a/$(id)", "compare", cfBase, cfHead}},
		{"repository with substitution (commit)", []string{"a/$(id)", "commit", cfSHA}},
		{"repository with query", []string{"a/b?x=1", "compare", cfBase, cfHead}},
		{"repository with query (commit)", []string{"a/b?x=1", "commit", cfSHA}},
		{"repository with dotdot", []string{"../b", "compare", cfBase, cfHead}},
		{"repository with dotdot (commit)", []string{"../b", "commit", cfSHA}},
		{"repository option-like", []string{"-a/b", "compare", cfBase, cfHead}},
		{"repository option-like (commit)", []string{"-a/b", "commit", cfSHA}},
		{"repository with newline", []string{"a/b\nc", "compare", cfBase, cfHead}},
		{"repository with newline (commit)", []string{"a/b\nc", "commit", cfSHA}},
		{"base sha 39 characters", []string{cfRepo, "compare", cfBase[:39], cfHead}},
		{"head sha 39 characters", []string{cfRepo, "compare", cfBase, cfBase[:39]}},
		{"commit sha 39 characters", []string{cfRepo, "commit", cfBase[:39]}},
		{"base sha 41 characters", []string{cfRepo, "compare", cfBase + "a", cfHead}},
		{"head sha 41 characters", []string{cfRepo, "compare", cfBase, cfBase + "a"}},
		{"commit sha 41 characters", []string{cfRepo, "commit", cfBase + "a"}},
		{"base sha not hex", []string{cfRepo, "compare", strings.Repeat("g", 40), cfHead}},
		{"head sha not hex", []string{cfRepo, "compare", cfBase, strings.Repeat("g", 40)}},
		{"commit sha not hex", []string{cfRepo, "commit", strings.Repeat("g", 40)}},
		{"base sha upper case", []string{cfRepo, "compare", strings.ToUpper(cfBase), cfHead}},
		{"head sha upper case", []string{cfRepo, "compare", cfBase, strings.ToUpper(cfBase)}},
		{"commit sha upper case", []string{cfRepo, "commit", strings.ToUpper(cfBase)}},
		{"base sha empty", []string{cfRepo, "compare", "", cfHead}},
		{"head sha empty", []string{cfRepo, "compare", cfBase, ""}},
		{"commit sha empty", []string{cfRepo, "commit", ""}},
		{"base sha with newline", []string{cfRepo, "compare", cfBase[:39] + "\n", cfHead}},
		{"head sha with newline", []string{cfRepo, "compare", cfBase, cfBase[:39] + "\n"}},
		{"commit sha with newline", []string{cfRepo, "commit", cfBase[:39] + "\n"}},
		{"base sha a number", []string{cfRepo, "compare", "7", cfHead}},
		{"head sha a number", []string{cfRepo, "compare", cfBase, "7"}},
		{"commit sha a number", []string{cfRepo, "commit", "7"}},
		{"base sha with range", []string{cfRepo, "compare", cfBase + "..." + cfHead, cfHead}},
		{"head sha with range", []string{cfRepo, "compare", cfBase, cfBase + "..." + cfHead}},
		{"commit sha with range", []string{cfRepo, "commit", cfBase + "..." + cfHead}},
		{"base sha with slash", []string{cfRepo, "compare", "../" + cfBase[:37], cfHead}},
		{"head sha with slash", []string{cfRepo, "compare", cfBase, "../" + cfBase[:37]}},
		{"commit sha with slash", []string{cfRepo, "commit", "../" + cfBase[:37]}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := runCF(t, cfCompare(cfJSON(cfNames("README.md")...)), true, tc.args...)
			if r.code != 2 {
				t.Errorf("exit code %d, want 2\n%s", r.code, r.stderr)
			}
			if r.stdout != "" || r.outputSet || r.calls != "" {
				t.Errorf("a bad call printed %q, wrote %q or called gh: %q", r.stdout, r.output, r.calls)
			}
		})
	}
}

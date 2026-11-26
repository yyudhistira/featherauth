package main

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const fixtureRequirements = `# Requirements

## Product requirements (FR)

| ID | Requirement |
| --- | --- |
| FR-01 | First. |
| FR-02 | Second, with a ` + "`a|b`" + ` pipe in code. |

## Operations requirements (OPS)

| ID | Requirement |
| --- | --- |
| OPS-01 | Not traced. |

## Security requirements (SEC)

| ID | Requirement |
| --- | --- |
| SEC-01 | Third. |

## Performance and size requirements (NFR)

| ID | Requirement |
| --- | --- |
| NFR-01 | Not traced. |

## Open requirements

- FR-90 is only mentioned here.

## Unused ids

These ids are never reused: FR-37, SEC-32.
`

// legacyDesign is a design from before the requirements moved: it holds the
// requirement tables itself.
const legacyDesign = `# Design

## Functional requirements

| ID | Requirement |
| --- | --- |
| FR-01 | First. |
| FR-02 | Second. |

## Security requirements

| ID | Requirement |
| --- | --- |
| SEC-01 | Third. |

` + fixtureDesign

const fixtureDesign = `# Design

## Acceptance criteria and test plan

| Area | Test | Pass condition | Covers |
| --- | --- | --- | --- |
| **Group** | | | |
| Alpha | Do a | A happens | FR-01, SEC-01 |
| Beta | Do ` + "`b|c`" + ` | B happens | FR-02 |

## Roadmap

| Stage | Items |
| --- | --- |
| Gamma | Not an acceptance row |
`

// writeRepo creates a repository in a temporary directory with the given
// files (path relative to the root -> content) and returns its root.
func writeRepo(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, content := range files {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func testFile(funcs ...string) string {
	return "package x\n\nimport \"testing\"\n\n" + strings.Join(funcs, "\n")
}

func testFunc(name string, comments ...string) string {
	var b strings.Builder
	for _, c := range comments {
		b.WriteString("// " + c + "\n")
	}
	b.WriteString("func " + name + "(t *testing.T) {}\n")
	return b.String()
}

func runCheck(t *testing.T, files map[string]string) []string {
	t.Helper()
	return runCheckWithBase(t, files, nil)
}

// runCheckWithBase runs the check with a base revision whose files are
// baseFiles (nil means no base comparison).
func runCheckWithBase(t *testing.T, files, baseFiles map[string]string) []string {
	t.Helper()
	root := writeRepo(t, files)
	cfg := config{
		design:       filepath.Join(root, "docs/DESIGN.md"),
		requirements: filepath.Join(root, "docs/REQUIREMENTS.md"),
		root:         root,
		pending:      filepath.Join(root, "tools/trace/pending.txt"),
	}
	if baseFiles != nil {
		cfg.bases = []base{{ref: "origin/main", r: fakeBase(baseFiles)}}
	}
	problems, err := check(cfg)
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	return problems
}

func fullyCovered() string {
	return testFile(
		testFunc("TestA", "Covers: FR-01, SEC-01", "Acceptance: Alpha"),
		testFunc("TestB", "Covers: FR-02", "Acceptance: Beta"),
	)
}

func TestParseDesign(t *testing.T) {
	d, problems := parseDesign(fixtureRequirements, fixtureDesign)
	if len(problems) != 0 {
		t.Fatalf("problems = %v", problems)
	}
	if got, want := strings.Join(d.ids, ","), "FR-01,FR-02,SEC-01"; got != want {
		t.Errorf("ids = %s, want %s", got, want)
	}
	if got, want := strings.Join(d.areas, ","), "Alpha,Beta"; got != want {
		t.Errorf("areas = %s, want %s (group and roadmap rows excluded)", got, want)
	}
	if got := strings.Join(d.covers["Alpha"], ","); got != "FR-01,SEC-01" {
		t.Errorf("covers[Alpha] = %s", got)
	}
}

func TestParseDesignRejectsDuplicates(t *testing.T) {
	reqs := strings.Replace(fixtureRequirements, "| SEC-01 | Third. |", "| SEC-01 | Third. |\n| SEC-01 | Again. |", 1)
	text := strings.Replace(fixtureDesign, "| Beta |", "| Alpha |", 1)
	_, problems := parseDesign(reqs, text)
	assertProblems(t, problems, "duplicate requirement SEC-01", "duplicate acceptance row \"Alpha\"")
}

func TestDesignSelfCheck(t *testing.T) {
	text := strings.Replace(fixtureDesign, "| FR-02 |\n", "| Non-functional |\n", 1)
	problems := runCheck(t, map[string]string{
		"docs/REQUIREMENTS.md":    fixtureRequirements,
		"docs/DESIGN.md":          text,
		"tools/trace/pending.txt": "",
		"x/x_test.go":             fullyCovered(),
	})
	assertProblems(t, problems, "design: FR-02 is not in the Covers column of any acceptance row")
}

func TestAllCoveredPasses(t *testing.T) {
	problems := runCheck(t, map[string]string{
		"docs/REQUIREMENTS.md":    fixtureRequirements,
		"docs/DESIGN.md":          fixtureDesign,
		"tools/trace/pending.txt": "# nothing pending\n",
		"x/x_test.go":             fullyCovered(),
	})
	if len(problems) != 0 {
		t.Fatalf("problems = %v", problems)
	}
}

func TestUncoveredNotPendingFails(t *testing.T) {
	problems := runCheck(t, map[string]string{
		"docs/REQUIREMENTS.md":    fixtureRequirements,
		"docs/DESIGN.md":          fixtureDesign,
		"tools/trace/pending.txt": "",
		"x/x_test.go":             testFile(testFunc("TestA", "Covers: FR-01, SEC-01", "Acceptance: Alpha")),
	})
	assertProblems(t, problems, "FR-02 has no test and is not in pending.txt", "\"Beta\" has no test and is not in pending.txt")
}

func TestUncoveredPendingPasses(t *testing.T) {
	problems := runCheck(t, map[string]string{
		"docs/REQUIREMENTS.md":    fixtureRequirements,
		"docs/DESIGN.md":          fixtureDesign,
		"tools/trace/pending.txt": "FR-02\nBeta\n",
		"x/x_test.go":             testFile(testFunc("TestA", "Covers: FR-01, SEC-01", "Acceptance: Alpha")),
	})
	if len(problems) != 0 {
		t.Fatalf("problems = %v", problems)
	}
}

func TestCoveredButPendingFails(t *testing.T) {
	problems := runCheck(t, map[string]string{
		"docs/REQUIREMENTS.md":    fixtureRequirements,
		"docs/DESIGN.md":          fixtureDesign,
		"tools/trace/pending.txt": "FR-02\nBeta\n",
		"x/x_test.go":             fullyCovered(),
	})
	assertProblems(t, problems,
		"FR-02 has a full test, TestB (x/x_test.go:11): remove it from pending.txt, or add (part) to that tag if the test proves only part of it",
		"\"Beta\" has a full test, TestB (x/x_test.go:11): remove it from pending.txt, or add (part) to that tag if the test proves only part of it")
}

func TestPartialMustStayPending(t *testing.T) {
	files := map[string]string{
		"docs/REQUIREMENTS.md":    fixtureRequirements,
		"docs/DESIGN.md":          fixtureDesign,
		"tools/trace/pending.txt": "",
		"x/x_test.go": testFile(
			testFunc("TestA", "Covers: FR-01, SEC-01", "Acceptance: Alpha"),
			testFunc("TestB", "Covers: FR-02 (part)", "Acceptance: Beta (part)"),
		),
	}
	assertProblems(t, runCheck(t, files),
		"FR-02 has only partial tests and is not in pending.txt",
		"\"Beta\" has only partial tests and is not in pending.txt")

	files["tools/trace/pending.txt"] = "FR-02\nBeta\n"
	if problems := runCheck(t, files); len(problems) != 0 {
		t.Fatalf("with pending entries: problems = %v", problems)
	}
}

func TestUnknownTagsFail(t *testing.T) {
	problems := runCheck(t, map[string]string{
		"docs/REQUIREMENTS.md":    fixtureRequirements,
		"docs/DESIGN.md":          fixtureDesign,
		"tools/trace/pending.txt": "",
		"x/x_test.go": fullyCovered() + "\n" +
			testFunc("TestC", "Covers: FR-99, nonsense", "Acceptance: Delta"),
	})
	assertProblems(t, problems,
		"x/x_test.go:13: TestC: unknown requirement FR-99",
		"x/x_test.go:13: TestC: malformed requirement id \"nonsense\"",
		"x/x_test.go:14: TestC: unknown acceptance row \"Delta\"")
}

func TestUnknownPendingEntryFails(t *testing.T) {
	problems := runCheck(t, map[string]string{
		"docs/REQUIREMENTS.md":    fixtureRequirements,
		"docs/DESIGN.md":          fixtureDesign,
		"tools/trace/pending.txt": "FR-77\nNo such row\n",
		"x/x_test.go":             fullyCovered(),
	})
	assertProblems(t, problems,
		"pending.txt:1: unknown entry \"FR-77\"",
		"pending.txt:2: unknown entry \"No such row\"")
}

func TestScanSkipsTestdataAndNonTests(t *testing.T) {
	problems := runCheck(t, map[string]string{
		"docs/REQUIREMENTS.md":    fixtureRequirements,
		"docs/DESIGN.md":          fixtureDesign,
		"tools/trace/pending.txt": "",
		"x/x_test.go":             fullyCovered(),
		// Tags outside test functions or in skipped places are ignored.
		"x/testdata/y_test.go": testFile(testFunc("TestFixture", "Covers: FR-99")),
		"x/helper_test.go":     "package x\n\n// Covers: FR-99\nfunc helper() {}\n",
		"x/plain.go":           "package x\n\n// Covers: FR-99\nfunc TestNotATestFile() {}\n",
	})
	if len(problems) != 0 {
		t.Fatalf("problems = %v", problems)
	}
}

// An installed Node project (the example web app) is never read.
func TestScanSkipsNodeModules(t *testing.T) {
	problems := runCheck(t, map[string]string{
		"docs/REQUIREMENTS.md":                      fixtureRequirements,
		"docs/DESIGN.md":                            fixtureDesign,
		"tools/trace/pending.txt":                   "",
		"x/x_test.go":                               fullyCovered(),
		"examples/web-app/node_modules/p/y_test.go": testFile(testFunc("TestFixture", "Covers: FR-99")),
	})
	if len(problems) != 0 {
		t.Fatalf("problems = %v", problems)
	}
}

// Tests behind a build tag (browser, conformance, load, ops) count: the scan
// reads every _test.go file and ignores build constraints.
func TestScanCountsBuildTaggedTests(t *testing.T) {
	tagged := "//go:build ops\n\n" + fullyCovered()
	problems := runCheck(t, map[string]string{
		"docs/REQUIREMENTS.md":    fixtureRequirements,
		"docs/DESIGN.md":          fixtureDesign,
		"tools/trace/pending.txt": "# nothing pending\n",
		"x/ops_test.go":           tagged,
	})
	if len(problems) != 0 {
		t.Fatalf("problems = %v", problems)
	}
}

func TestFuzzTargetsCount(t *testing.T) {
	problems := runCheck(t, map[string]string{
		"docs/REQUIREMENTS.md":    fixtureRequirements,
		"docs/DESIGN.md":          fixtureDesign,
		"tools/trace/pending.txt": "",
		"x/x_test.go": testFile(
			testFunc("TestA", "Covers: FR-01, SEC-01", "Acceptance: Alpha"),
			"// Covers: FR-02\n// Acceptance: Beta\nfunc FuzzB(f *testing.F) {}\n",
		),
	})
	if len(problems) != 0 {
		t.Fatalf("problems = %v", problems)
	}
}

// The real design must parse cleanly and pass its own self-check.
func TestRealDesign(t *testing.T) {
	b, err := os.ReadFile("../../docs/DESIGN.md")
	if err != nil {
		t.Fatal(err)
	}
	r, err := os.ReadFile("../../docs/REQUIREMENTS.md")
	if err != nil {
		t.Fatal(err)
	}
	d, problems := parseDesign(string(r), string(b))
	pending, err := readPending("pending.txt")
	if err != nil {
		t.Fatal(err)
	}
	problems = append(problems, d.selfCheck(pending)...)
	if len(problems) != 0 {
		t.Fatalf("problems = %v", problems)
	}
	if len(d.ids) == 0 || len(d.areas) == 0 {
		t.Fatalf("parsed %d ids and %d areas, want both > 0", len(d.ids), len(d.areas))
	}
}

func assertProblems(t *testing.T, got []string, want ...string) {
	t.Helper()
	sort.Strings(want)
	g := append([]string(nil), got...)
	sort.Strings(g)
	if strings.Join(g, "\n") != strings.Join(want, "\n") {
		t.Fatalf("problems:\n  %s\nwant:\n  %s", strings.Join(g, "\n  "), strings.Join(want, "\n  "))
	}
}

type fakeBase map[string]string

func (f fakeBase) show(path string) ([]byte, bool, error) {
	content, ok := f[path]
	return []byte(content), ok, nil
}

func TestPendingOnlyShrinks(t *testing.T) {
	// At the base, FR-02 and Beta existed and were covered (not pending).
	// Now they are pending again: refused. FR-03 and Gamma are new in the
	// design since the base, so they may be pending.
	reqs := strings.Replace(fixtureRequirements, "| SEC-01 | Third. |", "| SEC-01 | Third. |\n| FR-03 | New. |", 1)
	design := strings.Replace(fixtureDesign, "| Beta | Do", "| Gamma | Do g | G happens | FR-03 |\n| Beta | Do", 1)
	problems := runCheckWithBase(t, map[string]string{
		"docs/REQUIREMENTS.md":    reqs,
		"docs/DESIGN.md":          design,
		"tools/trace/pending.txt": "FR-02\nBeta\nFR-03\nGamma\n",
		"x/x_test.go":             testFile(testFunc("TestA", "Covers: FR-01, SEC-01", "Acceptance: Alpha")),
	}, map[string]string{
		"docs/REQUIREMENTS.md":    fixtureRequirements,
		"docs/DESIGN.md":          fixtureDesign,
		"tools/trace/pending.txt": "# nothing pending\n",
	})
	assertProblems(t, problems,
		"pending.txt:1: FR-02 was not pending at origin/main; pending.txt only shrinks",
		"pending.txt:2: \"Beta\" was not pending at origin/main; pending.txt only shrinks")
}

func TestPendingAllowedWhenBaseHasNoPendingFile(t *testing.T) {
	problems := runCheckWithBase(t, map[string]string{
		"docs/REQUIREMENTS.md":    fixtureRequirements,
		"docs/DESIGN.md":          fixtureDesign,
		"tools/trace/pending.txt": "FR-02\nBeta\n",
		"x/x_test.go":             testFile(testFunc("TestA", "Covers: FR-01, SEC-01", "Acceptance: Alpha")),
	}, map[string]string{"docs/DESIGN.md": fixtureDesign})
	if len(problems) != 0 {
		t.Fatalf("problems = %v", problems)
	}
}

func TestDesignCoversUnknownID(t *testing.T) {
	text := strings.Replace(fixtureDesign, "| FR-01, SEC-01 |", "| FR-01, SEC-01, SEC-31 |", 1)
	_, problems := parseDesign(fixtureRequirements, text)
	assertProblems(t, problems, `design line 8: acceptance row "Alpha" names unknown requirement SEC-31`)
}

func TestParserScope(t *testing.T) {
	reqs := fixtureRequirements + `
## Notes

| ID | Elsewhere |
| --- | --- |
| FR-99 | Not a requirement: outside the requirement sections. |
`
	text := fixtureDesign
	// A second table under the acceptance heading is not read.
	text = strings.Replace(text, "## Roadmap", "Another table:\n\n| Area | Test | Pass condition | Covers |\n| --- | --- | --- | --- |\n| Delta | x | y | FR-01 |\n\n## Roadmap", 1)
	d, problems := parseDesign(reqs, text)
	if len(problems) != 0 {
		t.Fatalf("problems = %v", problems)
	}
	if got := strings.Join(d.ids, ","); got != "FR-01,FR-02,SEC-01" {
		t.Errorf("ids = %s", got)
	}
	if got := strings.Join(d.areas, ","); got != "Alpha,Beta" {
		t.Errorf("areas = %s", got)
	}
}

func TestParserRowProblems(t *testing.T) {
	cases := map[string]struct{ from, to, want string }{
		"unbalanced backtick": {"| Alpha | Do a |", "| Alpha | Do `a |", "design line 8: unbalanced backtick in table row"},
		"cell count":          {"| Alpha | Do a | A happens |", "| Alpha | Do a | A | happens |", "design line 8: row has 5 cells, the header has 4"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, problems := parseDesign(fixtureRequirements, strings.Replace(fixtureDesign, c.from, c.to, 1))
			assertProblems(t, problems, c.want)
		})
	}
}

func TestEscapedPipeIsLiteral(t *testing.T) {
	text := strings.Replace(fixtureDesign, "| Alpha | Do a |", `| Alpha | Do a \| b |`, 1)
	d, problems := parseDesign(fixtureRequirements, text)
	if len(problems) != 0 {
		t.Fatalf("problems = %v", problems)
	}
	if got := strings.Join(d.covers["Alpha"], ","); got != "FR-01,SEC-01" {
		t.Fatalf("covers[Alpha] = %s", got)
	}
}

// The git reader against this repository's HEAD.
func TestGitBase(t *testing.T) {
	if err := refExists("../..", "HEAD"); err != nil {
		t.Fatal(err)
	}
	if err := refExists("../..", "no-such-revision-xyz"); err == nil {
		t.Fatal("refExists accepted an unknown revision")
	}
	g := gitBase{root: "../..", ref: "HEAD"}
	if data, ok, err := g.show("docs/DESIGN.md"); err != nil || !ok || len(data) == 0 {
		t.Fatalf("show(docs/DESIGN.md) = %d bytes, %v, %v", len(data), ok, err)
	}
	if _, ok, err := g.show("no/such/file.txt"); err != nil || ok {
		t.Fatalf("show(missing) = %v, %v; want not found and no error", ok, err)
	}
}

// git runs git in dir with a fixed identity and fails the test on error.
func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	out, err := gitOutput(dir, append([]string{"-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false"}, args...)...)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(out)
}

// commitRepo writes files into a git repository in dir and commits them.
func commitRepo(t *testing.T, dir string, files map[string]string) string {
	t.Helper()
	for name, content := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	git(t, dir, "add", "-A")
	git(t, dir, "commit", "-q", "-m", "step")
	return git(t, dir, "rev-parse", "HEAD")
}

// Within one branch: S-a closes FR-02, S-b reopens it while the branch's
// base still lists it as pending.
func TestHistoryCatchesReopenedEntry(t *testing.T) {
	dir := t.TempDir()
	git(t, dir, "init", "-q")
	tests := testFile(testFunc("TestA", "Covers: FR-01, SEC-01", "Acceptance: Alpha"))
	baseRev := commitRepo(t, dir, map[string]string{
		"docs/REQUIREMENTS.md": fixtureRequirements, "docs/DESIGN.md": fixtureDesign, "tools/trace/pending.txt": "FR-02\nBeta\n", "x/x_test.go": tests,
	})
	commitRepo(t, dir, map[string]string{"tools/trace/pending.txt": "Beta\n"})
	reopened := commitRepo(t, dir, map[string]string{"tools/trace/pending.txt": "FR-02\nBeta\n"})

	problems, err := historyProblems(dir, baseRev+"..HEAD", relFiles{pending: "tools/trace/pending.txt", design: "docs/DESIGN.md", requirements: "docs/REQUIREMENTS.md"})
	if err != nil {
		t.Fatal(err)
	}
	assertProblems(t, problems, "commit "+reopened[:7]+": pending.txt:1: FR-02 was not pending at its parent; pending.txt only shrinks")

	// The comparison with the branch base alone does not see it.
	cfg := config{
		design: filepath.Join(dir, "docs/DESIGN.md"), requirements: filepath.Join(dir, "docs/REQUIREMENTS.md"), root: dir, pending: filepath.Join(dir, "tools/trace/pending.txt"),
		bases: []base{{ref: baseRev, r: gitBase{root: dir, ref: baseRev}}},
	}
	if p, err := check(cfg); err != nil || len(p) != 0 {
		t.Fatalf("base-only check: problems = %v, err = %v", p, err)
	}
}

// Before a commit: the working tree reopens an entry closed at HEAD.
func TestWorkingTreeAgainstHEAD(t *testing.T) {
	dir := t.TempDir()
	git(t, dir, "init", "-q")
	commitRepo(t, dir, map[string]string{
		"docs/REQUIREMENTS.md": fixtureRequirements, "docs/DESIGN.md": fixtureDesign, "tools/trace/pending.txt": "Beta\n",
		"x/x_test.go": testFile(testFunc("TestA", "Covers: FR-01, FR-02, SEC-01", "Acceptance: Alpha")),
	})
	if err := os.WriteFile(filepath.Join(dir, "tools/trace/pending.txt"), []byte("FR-02\nBeta\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "x/x_test.go"), []byte(testFile(testFunc("TestA", "Covers: FR-01, SEC-01", "Acceptance: Alpha"))), 0o644); err != nil {
		t.Fatal(err)
	}
	problems, err := check(config{
		design: filepath.Join(dir, "docs/DESIGN.md"), requirements: filepath.Join(dir, "docs/REQUIREMENTS.md"), root: dir, pending: filepath.Join(dir, "tools/trace/pending.txt"),
		bases: []base{{ref: "HEAD", r: gitBase{root: dir, ref: "HEAD"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	assertProblems(t, problems, "pending.txt:1: FR-02 was not pending at HEAD; pending.txt only shrinks")
}

// Word boundary: NFR-03, OPS-01 and UC-02 in a Covers cell are not read as
// FR or SEC ids.
func TestCoversWordBoundary(t *testing.T) {
	text := strings.Replace(fixtureDesign, "| FR-01, SEC-01 |", "| FR-01, NFR-03, OPS-01, UC-02, SEC-01, XFR-05 |", 1)
	d, problems := parseDesign(fixtureRequirements, text)
	if len(problems) != 0 {
		t.Fatalf("problems = %v", problems)
	}
	if got := strings.Join(d.covers["Alpha"], ","); got != "FR-01,SEC-01" {
		t.Fatalf("covers[Alpha] = %s, want FR-01,SEC-01", got)
	}
}

// Ids of OPS, NFR and UC, the Open requirements bullets and Unused ids are
// not requirements for the tool.
func TestRequirementsIgnoreOtherSections(t *testing.T) {
	ids, problems, found := parseRequirements(fixtureRequirements, productHeading, securityHeading)
	if len(problems) != 0 || !found {
		t.Fatalf("problems = %v, found = %v", problems, found)
	}
	if got := strings.Join(ids, ","); got != "FR-01,FR-02,SEC-01" {
		t.Fatalf("ids = %s", got)
	}
}

// At a revision without docs/REQUIREMENTS.md the requirements come from the
// legacy sections of the design, so entries that were covered there cannot
// become pending, and a missing file is not an error.
func TestShrinkFallsBackToLegacyDesign(t *testing.T) {
	problems := runCheckWithBase(t, map[string]string{
		"docs/REQUIREMENTS.md":    fixtureRequirements,
		"docs/DESIGN.md":          fixtureDesign,
		"tools/trace/pending.txt": "FR-02\nBeta\n",
		"x/x_test.go":             testFile(testFunc("TestA", "Covers: FR-01, SEC-01", "Acceptance: Alpha")),
	}, map[string]string{
		"docs/DESIGN.md":          legacyDesign,
		"tools/trace/pending.txt": "# nothing pending\n",
	})
	assertProblems(t, problems,
		"pending.txt:1: FR-02 was not pending at origin/main; pending.txt only shrinks",
		"pending.txt:2: \"Beta\" was not pending at origin/main; pending.txt only shrinks")
}

// A base whose REQUIREMENTS.md has no requirement headings falls back too.
func TestShrinkFallsBackWhenRequirementsLackHeadings(t *testing.T) {
	problems := runCheckWithBase(t, map[string]string{
		"docs/REQUIREMENTS.md":    fixtureRequirements,
		"docs/DESIGN.md":          fixtureDesign,
		"tools/trace/pending.txt": "FR-02\nBeta\n",
		"x/x_test.go":             testFile(testFunc("TestA", "Covers: FR-01, SEC-01", "Acceptance: Alpha")),
	}, map[string]string{
		"docs/REQUIREMENTS.md":    "# Requirements\n\nNothing yet.\n",
		"docs/DESIGN.md":          legacyDesign,
		"tools/trace/pending.txt": "# nothing pending\n",
	})
	assertProblems(t, problems,
		"pending.txt:1: FR-02 was not pending at origin/main; pending.txt only shrinks",
		"pending.txt:2: \"Beta\" was not pending at origin/main; pending.txt only shrinks")
}

// The history check uses the fallback for a commit whose parent predates
// docs/REQUIREMENTS.md.
func TestHistoryFallsBackForOldParent(t *testing.T) {
	dir := t.TempDir()
	git(t, dir, "init", "-q")
	tests := testFile(testFunc("TestA", "Covers: FR-01, SEC-01", "Acceptance: Alpha"))
	baseRev := commitRepo(t, dir, map[string]string{
		"docs/DESIGN.md": legacyDesign, "tools/trace/pending.txt": "# none\n", "x/x_test.go": tests,
	})
	moved := commitRepo(t, dir, map[string]string{
		"docs/REQUIREMENTS.md": fixtureRequirements, "docs/DESIGN.md": fixtureDesign, "tools/trace/pending.txt": "FR-02\nBeta\n",
	})
	problems, err := historyProblems(dir, baseRev+"..HEAD", relFiles{pending: "tools/trace/pending.txt", design: "docs/DESIGN.md", requirements: "docs/REQUIREMENTS.md"})
	if err != nil {
		t.Fatal(err)
	}
	assertProblems(t, problems,
		"commit "+moved[:7]+": pending.txt:1: FR-02 was not pending at its parent; pending.txt only shrinks",
		"commit "+moved[:7]+": pending.txt:2: \"Beta\" was not pending at its parent; pending.txt only shrinks")
}

// A requirement without a covering row may be pending: it waits for its row
// and its test; once it is not pending the self-check fails again.
func TestSelfCheckAllowsPendingWithoutRow(t *testing.T) {
	text := strings.Replace(fixtureDesign, "| FR-02 |\n", "| Non-functional |\n", 1)
	files := map[string]string{
		"docs/REQUIREMENTS.md":    fixtureRequirements,
		"docs/DESIGN.md":          text,
		"tools/trace/pending.txt": "FR-02\nBeta\n",
		"x/x_test.go":             testFile(testFunc("TestA", "Covers: FR-01, SEC-01", "Acceptance: Alpha")),
	}
	if problems := runCheck(t, files); len(problems) != 0 {
		t.Fatalf("problems = %v", problems)
	}
}

// A requirements file without its two headings is an error, not an empty id
// list.
func TestParseDesignRequiresRequirementHeadings(t *testing.T) {
	_, problems := parseDesign("# Requirements\n\n| ID | Text |\n| --- | --- |\n| FR-01 | x |\n", fixtureDesign)
	if len(problems) == 0 || !strings.Contains(strings.Join(problems, "\n"), "## Product requirements (FR)") {
		t.Fatalf("problems = %v; want one naming the missing heading", problems)
	}
}

// At a revision where neither the requirements file nor the legacy design
// sections list requirements, reading the base is an error.
func TestReadBaseDesignRequiresRequirementHeadings(t *testing.T) {
	rel := relFiles{design: "docs/DESIGN.md", requirements: "docs/REQUIREMENTS.md"}
	_, _, err := readBaseDesign(fakeBase{"docs/DESIGN.md": fixtureDesign, "docs/REQUIREMENTS.md": "# nothing\n"}, rel)
	if err == nil {
		t.Fatal("readBaseDesign accepted a revision with no requirement headings")
	}
	if _, ok, err := readBaseDesign(fakeBase{"docs/DESIGN.md": fixtureDesign, "docs/REQUIREMENTS.md": fixtureRequirements}, rel); err != nil || !ok {
		t.Fatalf("readBaseDesign(valid) = %v, %v", ok, err)
	}
}

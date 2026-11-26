// Command trace checks that tests cover every requirement and acceptance row,
// except the entries listed in tools/trace/pending.txt. Requirement ids (FR
// and SEC) come from the tables under "## Product requirements (FR)" and "##
// Security requirements (SEC)" of docs/REQUIREMENTS.md (-requirements);
// acceptance rows and their Covers columns come from docs/DESIGN.md
// (-design). Other ids (OPS, NFR, UC) are not traced.
//
// A test names what it proves with comment lines directly above it:
//
//	// Covers: FR-07, SEC-01
//	// Acceptance: PKCE downgrade
//	func TestExchangeRejectsVerifierWithoutChallenge(t *testing.T) {
//
// A tag ending in "(part)" proves only part of a requirement or row; such an
// entry must stay in pending.txt until a test tags it without "(part)".
//
// pending.txt only shrinks: an entry that existed in the design at a -base
// revision (origin/main and HEAD by default) but was not pending there
// cannot become pending again, and with -history every commit of a range is
// checked against its parent the same way. At a revision where
// docs/REQUIREMENTS.md does not exist yet, the requirements are read from the
// "## Functional requirements" and "## Security requirements" sections of
// docs/DESIGN.md at that revision.
//
// Tests behind build tags (browser, conformance, load) count as coverage
// like any other; those suites run before each release, not in make check.
package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

func main() {
	var cfg config
	flag.StringVar(&cfg.design, "design", "docs/DESIGN.md", "design document (acceptance rows)")
	flag.StringVar(&cfg.requirements, "requirements", "docs/REQUIREMENTS.md", "requirements document (FR and SEC ids)")
	flag.StringVar(&cfg.root, "root", ".", "repository root to scan for tests")
	flag.StringVar(&cfg.pending, "pending", "tools/trace/pending.txt", "entries not yet covered")
	refs := []string{"origin/main", "HEAD"}
	refsSet := false
	flag.Func("base", "git revision pending.txt may only shrink from; repeat for several; an empty value turns the rule off (default origin/main and HEAD)", func(v string) error {
		if !refsSet {
			refs, refsSet = nil, true
		}
		if v != "" {
			refs = append(refs, v)
		}
		return nil
	})
	flag.StringVar(&cfg.history, "history", "origin/main..HEAD", "commit range whose commits must each only shrink pending.txt from their parent; empty skips it")
	flag.Parse()
	for _, ref := range refs {
		if err := refExists(cfg.root, ref); err != nil {
			fmt.Fprintln(os.Stderr, "trace:", err)
			os.Exit(2)
		}
		cfg.bases = append(cfg.bases, base{ref: ref, r: gitBase{root: cfg.root, ref: ref}})
	}

	problems, err := check(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "trace:", err)
		os.Exit(2)
	}
	for _, p := range problems {
		fmt.Fprintln(os.Stderr, "trace:", p)
	}
	if len(problems) > 0 {
		os.Exit(1)
	}
}

type config struct {
	design, requirements string
	root, pending        string
	bases                []base // revisions pending.txt may only shrink from
	history              string // commit range checked commit by commit; empty skips it
}

// base is one revision for the only-shrinks rule.
type base struct {
	ref string
	r   baseReader
}

// baseReader reads a file, by path relative to the root, at the base
// revision; ok is false when the file does not exist there.
type baseReader interface {
	show(path string) (data []byte, ok bool, err error)
}

type gitBase struct{ root, ref string }

func (g gitBase) show(path string) ([]byte, bool, error) {
	cmd := exec.Command("git", "show", g.ref+":"+path)
	cmd.Dir = g.root
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		msg := stderr.String()
		if strings.Contains(msg, "does not exist") || strings.Contains(msg, "but not in") {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("git show %s:%s: %v: %s", g.ref, path, err, msg)
	}
	return out, true, nil
}

func refExists(root, ref string) error {
	cmd := exec.Command("git", "rev-parse", "--verify", "--quiet", ref+"^{commit}")
	cmd.Dir = root
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("base revision %s not found: fetch it (git fetch origin main), or run with -base \"\" -history \"\" (TRACE_BASE= in make) to skip the only-shrinks rule", ref)
	}
	return nil
}

var (
	requirementRow = regexp.MustCompile(`^\| ((?:FR|SEC)-\d+) \|`)
	requirementID  = regexp.MustCompile(`^(?:FR|SEC)-\d+$`)
	// The word boundary keeps NFR-03 from being read as FR-03.
	anyID = regexp.MustCompile(`\b(?:FR|SEC)-\d+\b`)
)

const (
	productHeading    = "## Product requirements (FR)"
	securityHeading   = "## Security requirements (SEC)"
	acceptanceHeading = "## Acceptance criteria and test plan"

	// Headings of the requirement sections of DESIGN.md before the
	// requirements moved to docs/REQUIREMENTS.md.
	legacyFunctionalHeading = "## Functional requirements"
	legacySecurityHeading   = "## Security requirements"
)

type design struct {
	ids    []string            // requirement ids in document order
	areas  []string            // acceptance rows in document order
	covers map[string][]string // acceptance row -> ids in its Covers cell
}

func (d *design) knownID(id string) bool     { return contains(d.ids, id) }
func (d *design) knownArea(area string) bool { return contains(d.areas, area) }

// parseRequirements reads the FR and SEC ids from the rows of the tables
// under the two given headings. found is false when neither heading is in the
// text.
func parseRequirements(text string, headings ...string) (ids, problems []string, found bool) {
	section := ""
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "## ") {
			section = strings.TrimSpace(line)
			if contains(headings, section) {
				found = true
			}
			continue
		}
		if !contains(headings, section) {
			continue
		}
		if m := requirementRow.FindStringSubmatch(line); m != nil {
			if contains(ids, m[1]) {
				problems = append(problems, "duplicate requirement "+m[1])
				continue
			}
			ids = append(ids, m[1])
		}
	}
	return ids, problems, found
}

// parseDesign combines the requirement ids of the requirements document with
// the acceptance rows of the design: rows come from the first table under
// the acceptance heading whose header starts with Area and ends with Covers.
func parseDesign(requirements, designText string) (*design, []string) {
	ids, problems, found := parseRequirements(requirements, productHeading, securityHeading)
	if !found {
		problems = append(problems, fmt.Sprintf("requirements file has neither %q nor %q", productHeading, securityHeading))
	}
	return parseAcceptance(ids, designText, problems)
}

// parseAcceptance reads the acceptance table of designText and checks its
// Covers cells against ids.
func parseAcceptance(ids []string, text string, problems []string) (*design, []string) {
	d := &design{ids: ids, covers: map[string][]string{}}
	areaLine := map[string]int{}
	section := ""
	const (
		beforeTable = iota
		inTable
		afterTable
	)
	state, headerCells := beforeTable, 0
	for i, line := range strings.Split(text, "\n") {
		n := i + 1
		if strings.HasPrefix(line, "## ") {
			section = strings.TrimSpace(line)
			continue
		}
		switch section {
		case acceptanceHeading:
			if state == afterTable {
				continue
			}
			if !strings.HasPrefix(line, "|") {
				if state == inTable {
					state = afterTable
				}
				continue
			}
			cells, ok := splitCells(line)
			if !ok {
				problems = append(problems, fmt.Sprintf("design line %d: unbalanced backtick in table row", n))
				continue
			}
			if state == beforeTable {
				if cells[0] == "Area" && cells[len(cells)-1] == "Covers" {
					state, headerCells = inTable, len(cells)
				}
				continue
			}
			if strings.Trim(strings.Join(cells, ""), "-: ") == "" {
				continue // separator row
			}
			if len(cells) != headerCells {
				problems = append(problems, fmt.Sprintf("design line %d: row has %d cells, the header has %d", n, len(cells), headerCells))
				continue
			}
			area := cells[0]
			if strings.HasPrefix(area, "**") {
				continue // group row
			}
			if d.knownArea(area) {
				problems = append(problems, fmt.Sprintf("duplicate acceptance row %q", area))
				continue
			}
			d.areas = append(d.areas, area)
			areaLine[area] = n
			d.covers[area] = anyID.FindAllString(cells[len(cells)-1], -1)
		}
	}
	for _, area := range d.areas {
		for _, id := range d.covers[area] {
			if !d.knownID(id) {
				problems = append(problems, fmt.Sprintf("design line %d: acceptance row %q names unknown requirement %s", areaLine[area], area, id))
			}
		}
	}
	return d, problems
}

// selfCheck reports requirements that no acceptance row names in its Covers
// column, except those listed in pending.txt: a requirement new to the
// requirements may wait for its row, like it waits for its test.
func (d *design) selfCheck(pending map[string]int) []string {
	named := map[string]bool{}
	for _, ids := range d.covers {
		for _, id := range ids {
			named[id] = true
		}
	}
	var problems []string
	for _, id := range d.ids {
		if _, wait := pending[id]; !named[id] && !wait {
			problems = append(problems, fmt.Sprintf("design: %s is not in the Covers column of any acceptance row", id))
		}
	}
	return problems
}

// splitCells splits a Markdown table row. Pipes inside code spans and
// escaped pipes (\|) are literal. ok is false when a code span is not closed.
func splitCells(line string) (cells []string, ok bool) {
	line = strings.TrimSpace(line)
	line = strings.TrimPrefix(line, "|")
	if strings.HasSuffix(line, "|") && !strings.HasSuffix(line, `\|`) {
		line = strings.TrimSuffix(line, "|")
	}
	var cur strings.Builder
	inCode, escaped := false, false
	for _, r := range line {
		switch {
		case escaped:
			escaped = false
			if r != '|' {
				cur.WriteRune('\\')
			}
			cur.WriteRune(r)
		case r == '\\':
			escaped = true
		case r == '`':
			inCode = !inCode
			cur.WriteRune(r)
		case r == '|' && !inCode:
			cells = append(cells, strings.TrimSpace(cur.String()))
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	return append(cells, strings.TrimSpace(cur.String())), !inCode
}

// tag is one Covers or Acceptance entry on a test function.
type tag struct {
	fn      string // test function name
	file    string // path relative to the root
	fnLine  int    // line of the function declaration
	tagLine int    // line of the comment
	part    bool
}

type tags struct {
	ids   map[string][]tag
	areas map[string][]tag
}

// scanTests collects the tags on Test and Fuzz functions in _test.go files,
// skipping testdata, vendor, node_modules and hidden directories.
func scanTests(root string) (*tags, []string, error) {
	found := &tags{ids: map[string][]tag{}, areas: map[string][]tag{}}
	var malformed []string
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if e.IsDir() {
			name := e.Name()
			if path != root && (name == "testdata" || name == "vendor" || name == "node_modules" || strings.HasPrefix(name, ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || fn.Doc == nil || !isTestName(fn.Name.Name) {
				continue
			}
			base := tag{fn: fn.Name.Name, file: rel, fnLine: fset.Position(fn.Pos()).Line}
			for _, c := range fn.Doc.List {
				text := strings.TrimSpace(strings.TrimPrefix(c.Text, "//"))
				t := base
				t.tagLine = fset.Position(c.Pos()).Line
				switch {
				case strings.HasPrefix(text, "Covers:"):
					for _, item := range strings.Split(strings.TrimPrefix(text, "Covers:"), ",") {
						id, part := splitPart(item)
						if id == "" {
							continue
						}
						if !requirementID.MatchString(id) {
							malformed = append(malformed, fmt.Sprintf("%s:%d: %s: malformed requirement id %q", rel, t.tagLine, t.fn, id))
							continue
						}
						t.part = part
						found.ids[id] = append(found.ids[id], t)
					}
				case strings.HasPrefix(text, "Acceptance:"):
					area, part := splitPart(strings.TrimPrefix(text, "Acceptance:"))
					if area == "" {
						continue
					}
					t.part = part
					found.areas[area] = append(found.areas[area], t)
				}
			}
		}
		return nil
	})
	return found, malformed, err
}

func isTestName(name string) bool {
	return strings.HasPrefix(name, "Test") || strings.HasPrefix(name, "Fuzz")
}

func splitPart(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if strings.HasSuffix(s, "(part)") {
		return strings.TrimSpace(strings.TrimSuffix(s, "(part)")), true
	}
	return s, false
}

// readPending returns the entries of pending.txt with their line numbers.
// Blank lines and lines starting with # are ignored.
func readPending(path string) (map[string]int, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parsePending(f)
}

func parsePending(r io.Reader) (map[string]int, error) {
	entries := map[string]int{}
	s := bufio.NewScanner(r)
	for n := 1; s.Scan(); n++ {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		entries[line] = n
	}
	return entries, s.Err()
}

// shrinkAgainst reports pending entries that existed in the design at a base
// revision but were not pending there. label names the base in messages.
func shrinkAgainst(r baseReader, label string, pending map[string]int, rel relFiles) ([]string, error) {
	basePendingText, ok, err := r.show(rel.pending)
	if err != nil || !ok {
		return nil, err // no pending.txt at the base: nothing to shrink from
	}
	basePending, err := parsePending(bytes.NewReader(basePendingText))
	if err != nil {
		return nil, err
	}
	baseDesign, ok, err := readBaseDesign(r, rel)
	if err != nil || !ok {
		return nil, err
	}

	var problems []string
	for entry, line := range pending {
		if _, was := basePending[entry]; was {
			continue
		}
		switch {
		case baseDesign.knownID(entry):
			problems = append(problems, fmt.Sprintf("pending.txt:%d: %s was not pending at %s; pending.txt only shrinks", line, entry, label))
		case baseDesign.knownArea(entry):
			problems = append(problems, fmt.Sprintf("pending.txt:%d: %q was not pending at %s; pending.txt only shrinks", line, entry, label))
		}
	}
	return problems, nil
}

// readBaseDesign reads the requirements and acceptance rows at a revision.
// Requirements come from docs/REQUIREMENTS.md when it exists there with the
// requirement headings, otherwise from the legacy sections of the design.
func readBaseDesign(r baseReader, rel relFiles) (*design, bool, error) {
	designText, ok, err := r.show(rel.design)
	if err != nil || !ok {
		return nil, false, err
	}
	var ids []string
	reqText, ok, err := r.show(rel.requirements)
	if err != nil {
		return nil, false, err
	}
	found := false
	if ok {
		ids, _, found = parseRequirements(string(reqText), productHeading, securityHeading)
	}
	if !found {
		ids, _, found = parseRequirements(string(designText), legacyFunctionalHeading, legacySecurityHeading)
	}
	if !found {
		return nil, false, fmt.Errorf("no requirement headings (%q, %q) in %s or the legacy sections of %s", productHeading, securityHeading, rel.requirements, rel.design)
	}
	d, _ := parseAcceptance(ids, string(designText), nil)
	return d, true, nil
}

// historyProblems applies the only-shrinks rule to every commit of a range
// against its first parent, so an entry closed in one step of a branch
// cannot be reopened in a later step even while the base still lists it.
func historyProblems(root, rng string, rel relFiles) ([]string, error) {
	out, err := gitOutput(root, "rev-list", "--reverse", rng)
	if err != nil {
		return nil, err
	}
	var problems []string
	for _, c := range strings.Fields(out) {
		text, ok, err := gitBase{root: root, ref: c}.show(rel.pending)
		if err != nil {
			return nil, err
		}
		if !ok || refExists(root, c+"^") != nil {
			continue
		}
		pending, err := parsePending(bytes.NewReader(text))
		if err != nil {
			return nil, err
		}
		ps, err := shrinkAgainst(gitBase{root: root, ref: c + "^"}, "its parent", pending, rel)
		if err != nil {
			return nil, err
		}
		for _, p := range ps {
			problems = append(problems, "commit "+c[:7]+": "+p)
		}
	}
	return problems, nil
}

func gitOutput(root string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = root
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("git %s: %v: %s", strings.Join(args, " "), err, stderr.String())
	}
	return string(out), nil
}

// relFiles holds the paths of the three input files relative to the root,
// with forward slashes, as git expects them.
type relFiles struct{ pending, design, requirements string }

func relPaths(cfg config) (relFiles, error) {
	var out relFiles
	for _, f := range []struct {
		dst  *string
		path string
	}{{&out.pending, cfg.pending}, {&out.design, cfg.design}, {&out.requirements, cfg.requirements}} {
		p, err := filepath.Rel(cfg.root, f.path)
		if err != nil {
			return relFiles{}, err
		}
		*f.dst = filepath.ToSlash(p)
	}
	return out, nil
}

func check(cfg config) ([]string, error) {
	text, err := os.ReadFile(cfg.design)
	if err != nil {
		return nil, err
	}
	reqText, err := os.ReadFile(cfg.requirements)
	if err != nil {
		return nil, err
	}
	d, problems := parseDesign(string(reqText), string(text))

	found, malformed, err := scanTests(cfg.root)
	if err != nil {
		return nil, err
	}
	problems = append(problems, malformed...)

	pending, err := readPending(cfg.pending)
	if err != nil {
		return nil, err
	}
	problems = append(problems, d.selfCheck(pending)...)
	rel, err := relPaths(cfg)
	if err != nil {
		return nil, err
	}
	for _, b := range cfg.bases {
		shrink, err := shrinkAgainst(b.r, b.ref, pending, rel)
		if err != nil {
			return nil, err
		}
		problems = append(problems, shrink...)
	}
	if cfg.history != "" {
		hist, err := historyProblems(cfg.root, cfg.history, rel)
		if err != nil {
			return nil, err
		}
		problems = append(problems, hist...)
	}

	for id, ts := range found.ids {
		if !d.knownID(id) {
			for _, t := range ts {
				problems = append(problems, fmt.Sprintf("%s:%d: %s: unknown requirement %s", t.file, t.tagLine, t.fn, id))
			}
		}
	}
	for area, ts := range found.areas {
		if !d.knownArea(area) {
			for _, t := range ts {
				problems = append(problems, fmt.Sprintf("%s:%d: %s: unknown acceptance row %q", t.file, t.tagLine, t.fn, area))
			}
		}
	}
	for entry, line := range pending {
		if !d.knownID(entry) && !d.knownArea(entry) {
			problems = append(problems, fmt.Sprintf("pending.txt:%d: unknown entry %q", line, entry))
		}
	}

	report := func(name, label string, ts []tag) {
		_, isPending := pending[name]
		full := firstFull(ts)
		switch {
		case full != nil && isPending:
			problems = append(problems, fmt.Sprintf("%s has a full test, %s (%s:%d): remove it from pending.txt, or add (part) to that tag if the test proves only part of it", label, full.fn, full.file, full.fnLine))
		case full == nil && len(ts) > 0 && !isPending:
			problems = append(problems, label+" has only partial tests and is not in pending.txt")
		case len(ts) == 0 && !isPending:
			problems = append(problems, label+" has no test and is not in pending.txt")
		}
	}
	for _, id := range d.ids {
		report(id, id, found.ids[id])
	}
	for _, area := range d.areas {
		report(area, fmt.Sprintf("%q", area), found.areas[area])
	}

	sort.Strings(problems)
	return problems, nil
}

func firstFull(ts []tag) *tag {
	for i := range ts {
		if !ts[i].part {
			return &ts[i]
		}
	}
	return nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

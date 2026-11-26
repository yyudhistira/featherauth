package deploy_test

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The value forms of the release gate's Result column, as docs/RELEASING.md
// defines them ("Values of the release gate's Result column").
var (
	gateNotApplicable = regexp.MustCompile(`^not applicable: \S.*$`)
	gateNotRun        = regexp.MustCompile(`^not run: (\S.*); accepted by (\S.*)$`)
	gateNoChange      = regexp.MustCompile(`^no change since [0-9a-f]{40}$`)
)

// gateValue returns the kind of a Result cell (pass, fail, not applicable,
// not run, no change) or an error when it is none of the five forms.
func gateValue(result string) (string, error) {
	switch {
	case result == "pass":
		return "pass", nil
	case result == "fail":
		return "fail", nil
	case gateNotApplicable.MatchString(result):
		return "not applicable", nil
	case gateNotRun.MatchString(result):
		return "not run", nil
	case gateNoChange.MatchString(result):
		return "no change", nil
	}
	return "", fmt.Errorf("the result %q is not pass, fail, not applicable: <reason>, not run: <reason>; accepted by <name>, or no change since <40-character hash>", result)
}

// gateWantChecks lists the checks that have a row: items 1 to 13 and M1 to M6.
func gateWantChecks() []string {
	var want []string
	for i := 1; i <= 13; i++ {
		want = append(want, strconv.Itoa(i))
	}
	return append(want, "M1", "M2", "M3", "M4", "M5", "M6")
}

// gateBlocksTag reports whether a failed check stops the tag: items 1 to 10
// and M1 to M6.
func gateBlocksTag(check string) bool {
	n, err := strconv.Atoi(check)
	return err != nil || n <= 10
}

// gateTableProblems checks the rows of the release gate table against the
// rules of docs/RELEASING.md: every check has exactly one row, a result of one
// of the five forms and a non-empty detail; no check that blocks the tag is
// `fail`; items 1 and 2 are never `not run`.
func gateTableProblems(table string) []string {
	var problems []string
	seen := map[string]bool{}
	for _, line := range strings.Split(table, "\n") {
		if !strings.HasPrefix(line, "|") || strings.HasPrefix(line, "| Check ") || strings.HasPrefix(line, "| ---") {
			continue
		}
		cells := strings.Split(strings.Trim(line, "|"), "|")
		if len(cells) != 3 {
			problems = append(problems, fmt.Sprintf("row has %d cells, want 3 (Check, Result, Detail): %s", len(cells), line))
			continue
		}
		check, result, detail := strings.TrimSpace(cells[0]), strings.TrimSpace(cells[1]), strings.TrimSpace(cells[2])
		if seen[check] {
			problems = append(problems, fmt.Sprintf("check %s has two rows", check))
		}
		seen[check] = true
		kind, err := gateValue(result)
		if err != nil {
			problems = append(problems, fmt.Sprintf("check %s: %v", check, err))
		}
		if kind == "fail" && gateBlocksTag(check) {
			problems = append(problems, fmt.Sprintf("check %s is fail: it blocks the tag", check))
		}
		if kind == "not run" && (check == "1" || check == "2") {
			problems = append(problems, fmt.Sprintf("check %s is not run: items 1 and 2 are never not run", check))
		}
		if detail == "" {
			problems = append(problems, fmt.Sprintf("check %s: the detail is empty", check))
		}
	}
	want := gateWantChecks()
	for _, c := range want {
		if !seen[c] {
			problems = append(problems, fmt.Sprintf("no row for check %s", c))
		}
	}
	if len(seen) != len(want) {
		problems = append(problems, fmt.Sprintf("the table has %d checks, want %d", len(seen), len(want)))
	}
	return problems
}

// Parser of the release gate values (docs/RELEASING.md); the file check is TestReleaseGateResultsRecorded.
func TestGateValueForms(t *testing.T) {
	hash := strings.Repeat("a", 40)
	for _, c := range []struct {
		name, in, kind string
		ok             bool
	}{
		{"pass", "pass", "pass", true},
		{"fail", "fail", "fail", true},
		{"not applicable", "not applicable: first release", "not applicable", true},
		{"not applicable without reason", "not applicable", "", false},
		{"not applicable empty reason", "not applicable: ", "", false},
		{"not run", "not run: no device; accepted by Ana", "not run", true},
		{"not run without acceptance", "not run: no device", "", false},
		{"not run without reason", "not run; accepted by Ana", "", false},
		{"not run empty name", "not run: no device; accepted by ", "", false},
		{"no change", "no change since " + hash, "no change", true},
		{"no change short hash", "no change since abc1234", "", false},
		{"no change upper case", "no change since " + strings.Repeat("A", 40), "", false},
		{"old skipped form", "skipped: no change since " + hash, "", false},
		{"empty", "", "", false},
		{"not yet recorded", "not yet recorded", "", false},
		{"pass with text", "pass (mostly)", "", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			kind, err := gateValue(c.in)
			if (err == nil) != c.ok || kind != c.kind {
				t.Fatalf("gateValue(%q) = %q, %v; want %q, ok=%v", c.in, kind, err, c.kind, c.ok)
			}
		})
	}
}

func gateTable(rows map[string]string) string {
	var b strings.Builder
	b.WriteString("| Check | Result | Detail |\n| --- | --- | --- |\n")
	for _, c := range gateWantChecks() {
		result, ok := rows[c]
		if !ok {
			result = "pass"
		}
		fmt.Fprintf(&b, "| %s | %s | detail |\n", c, result)
	}
	return b.String()
}

// Parser of the release gate values (docs/RELEASING.md); the file check is TestReleaseGateResultsRecorded.
func TestGateTableRules(t *testing.T) {
	if p := gateTableProblems(gateTable(nil)); len(p) != 0 {
		t.Fatalf("a complete table has problems: %v", p)
	}
	for _, c := range []struct {
		name  string
		rows  map[string]string
		table string
		want  string
	}{
		{"empty result", map[string]string{"5": ""}, "", "check 5"},
		{"fail in item 3", map[string]string{"3": "fail"}, "", "blocks the tag"},
		{"fail in M2", map[string]string{"M2": "fail"}, "", "blocks the tag"},
		{"item 1 not run", map[string]string{"1": "not run: x; accepted by Ana"}, "", "never not run"},
		{"item 2 not run", map[string]string{"2": "not run: x; accepted by Ana"}, "", "never not run"},
		{"empty detail", nil, strings.Replace(gateTable(nil), "| 4 | pass | detail |", "| 4 | pass |  |", 1), "detail is empty"},
		{"missing row", nil, strings.Replace(gateTable(nil), "| M6 | pass | detail |\n", "", 1), "no row for check M6"},
		{"two rows", nil, gateTable(nil) + "| 7 | pass | again |\n", "two rows"},
	} {
		t.Run(c.name, func(t *testing.T) {
			table := c.table
			if table == "" {
				table = gateTable(c.rows)
			}
			if p := strings.Join(gateTableProblems(table), "\n"); !strings.Contains(p, c.want) {
				t.Fatalf("problems = %q, want one containing %q", p, c.want)
			}
		})
	}
	// Allowed: fail after the tag, not run with acceptance among the other items.
	if p := gateTableProblems(gateTable(map[string]string{"12": "fail", "5": "not run: x; accepted by Ana"})); len(p) != 0 {
		t.Fatalf("fail in item 12 and not run in item 5 are allowed, got %v", p)
	}
}

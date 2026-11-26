package main

import (
	"strconv"
	"strings"
	"testing"
)

const module = "example.com/m"

// profile builds a cover profile; each block is "file:stmts:count".
func profile(blocks ...string) string {
	var b strings.Builder
	b.WriteString("mode: atomic\n")
	for i, blk := range blocks {
		parts := strings.Split(blk, ":")
		b.WriteString(module + "/" + parts[0] + ":" + itoa(i+1) + ".1," + itoa(i+1) + ".9 " + parts[1] + " " + parts[2] + "\n")
	}
	return b.String()
}

func itoa(i int) string { return strconv.Itoa(i) }

var defaultThresholds = `
# comment
internal/... 90
internal/token/... 95
internal/skipme skip
`

func run(t *testing.T, prof string, pkgs ...string) []string {
	t.Helper()
	th, err := parseThresholds(strings.NewReader(defaultThresholds))
	if err != nil {
		t.Fatal(err)
	}
	cov, err := parseProfile(strings.NewReader(prof))
	if err != nil {
		t.Fatal(err)
	}
	return evaluate(module, cov, th, pkgs)
}

func TestAboveAndAtThresholdPass(t *testing.T) {
	// internal/store: 9 of 10 statements = 90% (at threshold).
	// internal/token: 19 of 20 = 95% (at its stricter threshold).
	prof := profile(
		"internal/store/a.go:9:1", "internal/store/a.go:1:0",
		"internal/token/t.go:19:3", "internal/token/t.go:1:0",
	)
	if p := run(t, prof, module+"/internal/store", module+"/internal/token"); len(p) != 0 {
		t.Fatalf("problems = %v", p)
	}
}

func TestBelowThresholdFails(t *testing.T) {
	prof := profile(
		"internal/store/a.go:8:1", "internal/store/a.go:2:0", // 80%
		"internal/token/t.go:18:1", "internal/token/t.go:2:0", // 90% < 95%
	)
	got := run(t, prof, module+"/internal/store", module+"/internal/token")
	want := []string{
		"internal/store: 80.0% of statements covered, below 90%",
		"internal/token: 90.0% of statements covered, below 95%",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestMostSpecificThresholdWins(t *testing.T) {
	// internal/token/sub is under internal/token/... (95), not just internal/... (90).
	prof := profile("internal/token/sub/s.go:92:1", "internal/token/sub/s.go:8:0") // 92%
	got := run(t, prof, module+"/internal/token/sub")
	if len(got) != 1 || !strings.Contains(got[0], "below 95%") {
		t.Fatalf("got %v, want one problem against 95%%", got)
	}
}

func TestPackageWithoutCoverageDataFails(t *testing.T) {
	got := run(t, profile(), module+"/internal/store")
	if len(got) != 1 || got[0] != "internal/store: no coverage data; does it have tests?" {
		t.Fatalf("got %v", got)
	}
}

func TestDuplicateBlocksCountOnce(t *testing.T) {
	// The same block reported twice (once uncovered, once covered) counts
	// once, as covered.
	prof := "mode: atomic\n" +
		module + "/internal/store/a.go:1.1,1.9 10 0\n" +
		module + "/internal/store/a.go:1.1,1.9 10 4\n"
	if p := run(t, prof, module+"/internal/store"); len(p) != 0 {
		t.Fatalf("problems = %v", p)
	}
}

func TestExcludedPackages(t *testing.T) {
	prof := profile(
		"cmd/app/main.go:1:0",
		"tools/x/x.go:1:0",
		"internal/testutil/h.go:1:0",
		"internal/store/storetest/s.go:1:0",
		"internal/skipme/s.go:1:0",
	)
	pkgs := []string{
		module + "/cmd/app", module + "/tools/x", module + "/internal/testutil",
		module + "/internal/store/storetest", module + "/internal/skipme",
	}
	if p := run(t, prof, pkgs...); len(p) != 0 {
		t.Fatalf("problems = %v", p)
	}
}

func TestZeroStatementPackageIsSkipped(t *testing.T) {
	prof := "mode: atomic\n" + module + "/internal/store/types.go:1.1,1.2 0 0\n"
	if p := run(t, prof, module+"/internal/store"); len(p) != 0 {
		t.Fatalf("problems = %v", p)
	}
}

func TestParseErrors(t *testing.T) {
	if _, err := parseProfile(strings.NewReader("mode: atomic\nnot a block\n")); err == nil {
		t.Error("parseProfile accepted a bad line")
	}
	if _, err := parseThresholds(strings.NewReader("internal/... ninety\n")); err == nil {
		t.Error("parseThresholds accepted a bad percentage")
	}
	if _, err := parseThresholds(strings.NewReader("internal/...\n")); err == nil {
		t.Error("parseThresholds accepted a line without a value")
	}
}

// The thresholds shipped in the repository parse and match CLAUDE.md.
func TestRepositoryThresholds(t *testing.T) {
	th, err := readThresholds("thresholds.txt")
	if err != nil {
		t.Fatal(err)
	}
	for rel, want := range map[string]float64{
		"internal/token": 95, "internal/oidc": 95, "internal/config": 95, "internal/user": 95, "internal/secure": 95,
		"internal/store": 90, "internal/web": 90, "internal/clock": 90,
	} {
		got, skip, ok := th.lookup(rel)
		if !ok || skip || got != want {
			t.Errorf("threshold for %s = %v (skip %v, found %v), want %v", rel, got, skip, ok, want)
		}
	}
}

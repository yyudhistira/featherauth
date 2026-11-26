// Command cover checks per-package statement coverage against
// tools/cover/thresholds.txt. Packages outside internal/ and test-support
// packages (internal/testutil/..., <component>test) are not checked.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"sort"
	"strconv"
	"strings"
)

func main() {
	profilePath := flag.String("profile", "cover.out", "cover profile from go test -coverprofile")
	thresholdsPath := flag.String("thresholds", "tools/cover/thresholds.txt", "per-package thresholds")
	flag.Parse()

	if err := runMain(*profilePath, *thresholdsPath); err != nil {
		fmt.Fprintln(os.Stderr, "cover:", err)
		os.Exit(2)
	}
}

func runMain(profilePath, thresholdsPath string) error {
	th, err := readThresholds(thresholdsPath)
	if err != nil {
		return err
	}
	f, err := os.Open(profilePath)
	if err != nil {
		return err
	}
	defer f.Close()
	cov, err := parseProfile(f)
	if err != nil {
		return err
	}
	module, err := goOutput("list", "-m")
	if err != nil {
		return err
	}
	list, err := goOutput("list", "./...")
	if err != nil {
		return err
	}
	problems := evaluate(strings.TrimSpace(module), cov, th, strings.Fields(list))
	for _, p := range problems {
		fmt.Fprintln(os.Stderr, "cover:", p)
	}
	if len(problems) > 0 {
		os.Exit(1)
	}
	return nil
}

// coverage holds, per package import path, the statements of each block
// and whether the block ran.
type coverage map[string]map[string]block

type block struct {
	stmts   int
	covered bool
}

// parseProfile reads a profile written by go test -coverprofile. A block
// reported more than once counts once, as covered if any report ran it.
func parseProfile(r io.Reader) (coverage, error) {
	cov := coverage{}
	s := bufio.NewScanner(r)
	for n := 1; s.Scan(); n++ {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "mode:") {
			continue
		}
		// file.go:start.col,end.col numStmts count
		fields := strings.Fields(line)
		colon := strings.LastIndex(fields[0], ":")
		if len(fields) != 3 || colon < 0 {
			return nil, fmt.Errorf("profile line %d: malformed %q", n, line)
		}
		stmts, err1 := strconv.Atoi(fields[1])
		count, err2 := strconv.Atoi(fields[2])
		if err1 != nil || err2 != nil {
			return nil, fmt.Errorf("profile line %d: malformed %q", n, line)
		}
		pkg := path.Dir(fields[0][:colon])
		if cov[pkg] == nil {
			cov[pkg] = map[string]block{}
		}
		b := cov[pkg][fields[0]]
		b.stmts = stmts
		b.covered = b.covered || count > 0
		cov[pkg][fields[0]] = b
	}
	return cov, s.Err()
}

type threshold struct {
	pattern string // a package path, or a prefix ending in "/..."
	percent float64
	skip    bool
}

type thresholds []threshold

// lookup returns the most specific threshold for a package path relative to
// the module root.
func (ts thresholds) lookup(rel string) (percent float64, skip, ok bool) {
	best := -1
	for i, t := range ts {
		if !matches(t.pattern, rel) {
			continue
		}
		if best < 0 || len(t.pattern) > len(ts[best].pattern) {
			best = i
		}
	}
	if best < 0 {
		return 0, false, false
	}
	return ts[best].percent, ts[best].skip, true
}

func matches(pattern, rel string) bool {
	if prefix, ok := strings.CutSuffix(pattern, "/..."); ok {
		return rel == prefix || strings.HasPrefix(rel, prefix+"/")
	}
	return rel == pattern
}

func readThresholds(p string) (thresholds, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseThresholds(f)
}

// parseThresholds reads lines of "<pattern> <percent>" or "<pattern> skip".
func parseThresholds(r io.Reader) (thresholds, error) {
	var ts thresholds
	s := bufio.NewScanner(r)
	for n := 1; s.Scan(); n++ {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return nil, fmt.Errorf("thresholds line %d: want \"<pattern> <percent|skip>\", got %q", n, line)
		}
		if fields[1] == "skip" {
			ts = append(ts, threshold{pattern: fields[0], skip: true})
			continue
		}
		pct, err := strconv.ParseFloat(fields[1], 64)
		if err != nil || pct < 0 || pct > 100 {
			return nil, fmt.Errorf("thresholds line %d: bad percentage %q", n, fields[1])
		}
		ts = append(ts, threshold{pattern: fields[0], percent: pct})
	}
	return ts, s.Err()
}

// evaluate returns one problem per checked package below its threshold or
// without coverage data.
func evaluate(module string, cov coverage, ts thresholds, pkgs []string) []string {
	var problems []string
	for _, pkg := range pkgs {
		rel := strings.TrimPrefix(strings.TrimPrefix(pkg, module), "/")
		if !checked(rel) {
			continue
		}
		want, skip, ok := ts.lookup(rel)
		if skip {
			continue
		}
		if !ok {
			problems = append(problems, rel+": no threshold in thresholds.txt")
			continue
		}
		blocks, ok := cov[pkg]
		if !ok {
			problems = append(problems, rel+": no coverage data; does it have tests?")
			continue
		}
		total, covered := 0, 0
		for _, b := range blocks {
			total += b.stmts
			if b.covered {
				covered += b.stmts
			}
		}
		if total == 0 {
			continue
		}
		got := 100 * float64(covered) / float64(total)
		if got < want {
			problems = append(problems, fmt.Sprintf("%s: %.1f%% of statements covered, below %s%%", rel, got, strconv.FormatFloat(want, 'f', -1, 64)))
		}
	}
	sort.Strings(problems)
	return problems
}

// checked reports whether a package is subject to the coverage gate.
func checked(rel string) bool {
	parts := strings.Split(rel, "/")
	if len(parts) < 2 || parts[0] != "internal" {
		return false
	}
	comp := parts[1]
	return comp != "testutil" && path.Base(rel) != comp+"test"
}

func goOutput(args ...string) (string, error) {
	out, err := exec.Command("go", args...).Output()
	if err != nil {
		return "", fmt.Errorf("go %s: %v", strings.Join(args, " "), err)
	}
	return string(out), nil
}

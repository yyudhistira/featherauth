package deploy_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// In a locale such as en_US.UTF-8 a bracket range like [a-f] can match upper
// case letters, so validation written with ranges accepts bad input there
// (CI runs under LC_ALL=C and would not notice). The scripts of the
// repository must list the characters instead: [0123456789abcdef].

var rangeInBracket = regexp.MustCompile(`\[[^][\"$=]*[A-Za-z0-9]-[A-Za-z0-9][^][\"$=]*\]`)

// Lines whose expression is not read by a shell, grep, awk or sed: jq
// programs (the regular expressions of jq do not depend on the locale) and
// the tag filter of the workflow, a GitHub glob.
func rangeLineExempt(line string) bool {
	return strings.Contains(line, "test(\"") ||
		strings.Contains(line, "tags: [") ||
		strings.Contains(line, "[server_metadata=") ||
		strings.Contains(line, "[response_type=")
}

func localeRangeFindings(name, text string) []string {
	var out []string
	for i, line := range strings.Split(text, "\n") {
		if rangeInBracket.MatchString(line) && !rangeLineExempt(line) {
			out = append(out, name+":"+itoa(i+1)+": "+strings.TrimSpace(line))
		}
	}
	return out
}

func TestLocaleRangeScanFlagsBadLines(t *testing.T) {
	bad := []string{
		`  *[!0-9a-f]*) exit 2 ;;`,
		`awk '/^[0-9a-f]{40}$/'`,
		`case $x in *[!a-f]*) ;; esac`,
		`x=*[!A-Za-z0-9_./-]*`,
	}
	for _, l := range bad {
		if len(localeRangeFindings("fixture", l)) != 1 {
			t.Errorf("not flagged: %s", l)
		}
	}
	good := []string{
		`  *[!0123456789abcdef]*) exit 2 ;;`,
		`awk '/^[0123456789abcdef]{40}$/'`,
		`case $x in *[!._/-]*) ;; esac`,
		`select(test("^[0-9]+$"))`,
	}
	for _, l := range good {
		if f := localeRangeFindings("fixture", l); len(f) != 0 {
			t.Errorf("flagged: %v", f)
		}
	}
}

func TestScriptsUseNoLocaleRanges(t *testing.T) {
	var files []string
	for _, pat := range []string{"ops/*.sh", "*.sh", "conformance/*.sh", "load/*.sh", "../.github/workflows/*.yml", "../Makefile"} {
		m, err := filepath.Glob(pat)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, m...)
	}
	if len(files) < 10 {
		t.Fatalf("only %d files found: %v", len(files), files)
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, fd := range localeRangeFindings(f, string(b)) {
			t.Errorf("locale-dependent range: %s", fd)
		}
	}
}

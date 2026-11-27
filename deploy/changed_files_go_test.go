package deploy_test

import (
	"fmt"
	"strings"
	"testing"
)

// Comment-only Go changes, and a change of tools/trace/pending.txt, which is a
// documentation file like the others.
// The script reads the patch field of the file list. cfPatchFile builds it.

const (
	h  = "@@ -10,3 +10,4 @@ func f() {"
	cx = " \tx := 1" // a context line of code
)

func goFile(lines ...string) cfFile { return cfPatchFile("internal/x/x.go", lines...) }

// Proves OPS-02 (documentation-only changes): see the pass conditions of the row; OPS ids are not traced.
// Acceptance: Documentation-only changes (part)
func TestChangedFilesCommentOnlyGo(t *testing.T) {
	for _, tc := range []struct {
		name  string
		files []cfFile
		want  bool
	}{
		// Comment-only changes.
		{"line comment added", []cfFile{goFile(h, cx, "+\t// a note", cx)}, true},
		{"line comment removed", []cfFile{goFile(h, cx, "-\t// a note", cx)}, true},
		{"line comment changed", []cfFile{goFile(h, cx, "-\t// old", "+\t// new", cx)}, true},
		{"blank lines", []cfFile{goFile(h, cx, "+", "+\t", "-", cx)}, true},
		{"doc comment with a tab and CRLF", []cfFile{goFile(h, "+// a\r", "+\r", cx)}, true},
		{"one-line block comment", []cfFile{goFile(h, cx, "+\t/* a note */", cx)}, true},
		{"block comment then line comment", []cfFile{goFile(h, cx, "+\t/* a */ // b", cx)}, true},
		{"block comment over several changed lines", []cfFile{goFile(h, cx, "+/*", "+ * text // not code", "+ * more", "+ */", cx)}, true},
		{"block comment replaced", []cfFile{goFile(h, cx, "-/*", "- old", "- */", "+/* new */", cx)}, true},
		{"empty block opener", []cfFile{goFile(h, cx, "+/*/", "+ */", cx)}, true},
		{"two hunks", []cfFile{goFile(h, "+// a", cx, "@@ -50,3 +51,4 @@", "+// b", cx)}, true},
		{"no newline marker", []cfFile{goFile(h, cx, "-// a", `\ No newline at end of file`, "+// a", `\ No newline at end of file`)}, true},
		{"test file", []cfFile{cfPatchFile("internal/x/x_test.go", h, "+// a")}, true},
		{"two go files", []cfFile{goFile(h, "+// a"), cfPatchFile("cmd/y/main.go", h, "-// b")}, true},
		{"go comment among docs", []cfFile{goFile(h, "+// a"), {name: "README.md"}, {name: ".claude/x.md"}}, true},
		{"empty context line", []cfFile{goFile(h, "+// a", "")}, true},

		// Not comment-only: code.
		{"code added", []cfFile{goFile(h, cx, "+\ty := 2", cx)}, false},
		{"code removed", []cfFile{goFile(h, cx, "-\ty := 2", cx)}, false},
		{"comment and code", []cfFile{goFile(h, "+// a", "+\ty := 2")}, false},
		{"comment changed into code", []cfFile{goFile(h, "-// y := 2", "+y := 2")}, false},
		{"trailing comment after code", []cfFile{goFile(h, "-\tx := 1", "+\tx := 1 // note")}, false},
		{"code before a block comment", []cfFile{goFile(h, "+\tx := 1 /* a */")}, false},
		{"code after a block comment", []cfFile{goFile(h, "+\t/* a */ x := 1")}, false},
		{"code after a block closing", []cfFile{goFile(h, "+/*", "+ */ x := 1")}, false},
		{"block closing then another opener", []cfFile{goFile(h, "+/* a */ /* b */")}, false},
		{"block comment inside a line of code", []cfFile{goFile(h, "+\tf(/* a */)")}, false},
		{"star line without an opener", []cfFile{goFile(h, cx, "+ * text", cx)}, false},
		{"closing without an opener", []cfFile{goFile(h, cx, "+ */", cx)}, false},
		{"opener never closed", []cfFile{goFile(h, cx, "+/* a", cx)}, false},
		{"opener closed after context code", []cfFile{goFile(h, "+/*", cx, "+*/")}, false},
		{"opener closed in another hunk", []cfFile{goFile(h, "+/*", "@@ -50,3 +51,4 @@", "+*/")}, false},
		{"opener at the end of the patch", []cfFile{goFile(h, "+// a", "+/*")}, false},
		{"removed opener without its closing", []cfFile{goFile(h, "-/*", cx)}, false},
		{"removed closing only", []cfFile{goFile(h, "- */", cx)}, false},
		{"block comment replaced by a block comment", []cfFile{goFile(h, "-/*", "+/* a", "- */", "+ */")}, true},
		{"code among comment files", []cfFile{goFile(h, "+// a"), cfPatchFile("b.go", h, "+x := 1")}, false},
		{"comment-only go file and a code file", []cfFile{goFile(h, "+// a"), {name: "main.sh"}}, false},
		{"comment-only go file and the design", []cfFile{goFile(h, "+// a"), {name: "docs/DESIGN.md"}}, true},
		{"comment-only go file and an image under docs", []cfFile{goFile(h, "+// a"), {name: "docs/audits/x.png"}}, false},
		{"raw string line", []cfFile{goFile(h, "+// `a")}, false},
		{"slash slash star is a line comment", []cfFile{goFile(h, "+//* a")}, true},

		// Not comment-only: lines the tools or the compiler read.
		{"covers added", []cfFile{goFile(h, "+// Covers: FR-16")}, false},
		{"covers removed", []cfFile{goFile(h, "-// Covers: FR-16")}, false},
		{"covers changed", []cfFile{goFile(h, "-// Covers: FR-16", "+// Covers: FR-17")}, false},
		{"acceptance changed", []cfFile{goFile(h, "-// Acceptance: A", "+// Acceptance: B")}, false},
		{"acceptance partial", []cfFile{goFile(h, "+// Acceptance: A (part)")}, false},
		{"covers in a block comment", []cfFile{goFile(h, "+/* Covers: FR-1 */")}, false},
		{"covers inside a longer comment", []cfFile{goFile(h, "+// the line Covers: is read by tools/trace")}, false},
		{"covers in the context", []cfFile{goFile(h, " // Covers: FR-16", "+", " func TestX(t *testing.T) {")}, false},
		{"acceptance in the context", []cfFile{goFile(h, " // Acceptance: A", "-", " func TestX(t *testing.T) {")}, false},
		{"go build constraint", []cfFile{goFile(h, "+//go:build linux")}, false},
		{"plus build constraint", []cfFile{goFile(h, "+// +build linux")}, false},
		{"build constraint in the context", []cfFile{goFile(h, " //go:build linux", "-", " package x")}, false},
		{"go generate", []cfFile{goFile(h, "+//go:generate stringer")}, false},
		{"go embed", []cfFile{goFile(h, "-//go:embed a.txt")}, false},
		{"go embed in the context", []cfFile{goFile(h, " //go:embed a.txt", "+// a")}, false},
		{"go linkname", []cfFile{goFile(h, "+//go:linkname a b")}, false},
		{"export", []cfFile{goFile(h, "+//export F")}, false},
		{"line directive", []cfFile{goFile(h, "+//line a.go:1")}, false},
		{"cgo preamble", []cfFile{goFile(h, "+// #include <stdio.h>")}, false},
		{"cgo define", []cfFile{goFile(h, "+/* #define X 1 */")}, false},
		{"cgo flags", []cfFile{goFile(h, "+// #cgo LDFLAGS: -lm")}, false},
		{"block line directive", []cfFile{goFile(h, "+/*line a.go:10:1*/")}, false},
		{"block line directive removed", []cfFile{goFile(h, "-\t/*line :10*/")}, false},
		{"block line directive in the context", []cfFile{goFile(h, " /*line a.go:1*/", "+// a")}, false},
		{"example output", []cfFile{goFile(h, "+\t// Output: 1")}, false},
		{"example unordered output", []cfFile{goFile(h, "-\t// Unordered output: 1")}, false},
		{"example output in the context", []cfFile{goFile(h, " \t// Output:", "+\t// 1")}, false},
		{"lint directive", []cfFile{goFile(h, "+//lint:ignore SA1019 reason")}, false},
		{"nolint directive", []cfFile{goFile(h, "+// nolint:gosec")}, false},
		{"nolint without a space", []cfFile{goFile(h, "-//nolint")}, false},
		{"deprecated", []cfFile{goFile(h, "+// Deprecated: use y.")}, false},
		{"deprecated in the context", []cfFile{goFile(h, " // Deprecated: use y.", "+//")}, false},
		{"import C in the context", []cfFile{goFile(h, "+// a", ` import "C"`)}, false},

		// Not comment-only: the patch cannot be trusted or the file is not changed in place.
		{"no patch", []cfFile{{name: "a.go"}}, false},
		{"empty patch", []cfFile{{name: "a.go", raw: `"patch":"","additions":0,"deletions":0`}}, false},
		{"patch is null", []cfFile{{name: "a.go", raw: `"patch":null,"additions":1,"deletions":0`}}, false},
		{"patch is not a string", []cfFile{{name: "a.go", raw: `"patch":["+// a"],"additions":1,"deletions":0`}}, false},
		{"no counts", []cfFile{{name: "a.go", raw: `"patch":"@@ -1 +1 @@\n+// a"`}}, false},
		{"truncated patch (more additions than shown)", []cfFile{{name: "a.go", raw: `"patch":"@@ -1 +1 @@\n+// a","additions":2,"deletions":0`}}, false},
		{"truncated patch (more deletions than shown)", []cfFile{{name: "a.go", raw: `"patch":"@@ -1 +1 @@\n+// a","additions":1,"deletions":1`}}, false},
		{"counts as strings", []cfFile{{name: "a.go", raw: `"patch":"@@ -1 +1 @@\n+// a","additions":"1","deletions":"0"`}}, false},
		{"added file", []cfFile{{name: "a.go", raw: `"status":"added","patch":"@@ -0,0 +1 @@\n+// a","additions":1,"deletions":0`}}, false},
		{"removed file", []cfFile{{name: "a.go", raw: `"status":"removed","patch":"@@ -1 +0,0 @@\n-// a","additions":0,"deletions":1`}}, false},
		{"renamed with a change", []cfFile{{name: "b.go", prev: "a.go", raw: `"status":"renamed","patch":"@@ -1 +1 @@\n+// a","additions":1,"deletions":0`}}, false},
		{"renamed without a change", []cfFile{{name: "b.go", prev: "a.go", raw: `"status":"renamed","additions":0,"deletions":0,"changes":0`}}, false},
		{"renamed from a non-go file", []cfFile{{name: "b.go", prev: "a.txt", raw: `"status":"renamed","patch":"@@ -1 +1 @@\n+// a","additions":1,"deletions":0`}}, false},
		{"no status", []cfFile{{name: "a.go", raw: `"status":null,"patch":"@@ -1 +1 @@\n+// a","additions":1,"deletions":0`}}, false},

		// Not comment-only: the file is not Go source of the module.
		{"a comment in a non-go file", []cfFile{cfPatchFile("Makefile", h, "+# a")}, false},
		{"a go comment in a text file", []cfFile{cfPatchFile("a.go.txt", h, "+// a")}, false},
		{"upper case suffix", []cfFile{cfPatchFile("a.GO", h, "+// a")}, false},
		{"go.mod", []cfFile{cfPatchFile("go.mod", h, "+// a")}, false},
		{"testdata", []cfFile{cfPatchFile("internal/x/testdata/a.go", h, "+// a")}, false},
		{"testdata at the root", []cfFile{cfPatchFile("testdata/a.go", h, "+// a")}, false},
		{"name with a newline", []cfFile{cfPatchFile("a.go\nREADME.md", h, "+// a")}, false},
	} {
		for mode, c := range map[string]cfCase{
			"compare": cfCompare(cfJSON(tc.files...)),
			"commit":  cfCommit(cfJSON(tc.files...)),
		} {
			t.Run(mode+" "+tc.name, func(t *testing.T) { t.Parallel(); cfRun(t, c, tc.want) })
		}
	}
}

// Nothing from the patch reaches the output: a comment-only patch and a code
// patch that both hold a marker text print only the two fixed lines.
//
// Proves OPS-02 (documentation-only changes): see the pass conditions of the row; OPS ids are not traced.
// Acceptance: Documentation-only changes (part)
func TestChangedFilesGoPatchIsNotPrinted(t *testing.T) {
	c := cfCompare(cfJSON(goFile(h, "+// "+cfTitle)))
	r := runCF(t, c, true, c.args()...)
	cfWant(t, r, true)
	c = cfCompare(cfJSON(goFile(h, "+x := \""+cfTitle+"\"")))
	r = runCF(t, c, true, c.args()...)
	cfWant(t, r, false)
}

// A comment-only Go file on a later page of the list decides too.
//
// Proves OPS-02 (documentation-only changes): see the pass conditions of the row; OPS ids are not traced.
// Acceptance: Documentation-only changes (part)
func TestChangedFilesGoPagination(t *testing.T) {
	docs := cfJSON(cfNames("README.md")...)
	ok := cfJSON(goFile(h, "+// a"))
	bad := cfJSON(goFile(h, "+x := 1"))
	cfRun(t, cfCompare(docs, ok, docs), true)
	cfRun(t, cfCommit(docs, ok), true)
	cfRun(t, cfCompare(docs, ok, bad), false)
	cfRun(t, cfCommit(ok, bad), false)
	// The size limit counts these files too.
	var pages []string
	for range 29 {
		pages = append(pages, cfJSON(append(cfN("README.md", 99), goFile(h, "+// a"))...))
	}
	pages = append(pages, cfJSON(cfN("README.md", 99)...))
	cfRun(t, cfCompare(pages...), true)
	cfRun(t, cfCompare(append(pages, cfJSON(cfN("README.md", 1)...))...), false)
}

// tools/trace/pending.txt is a documentation file: alone, with other
// documentation files or with a comment-only Go file, the change is
// documentation-only; with any other file it is not. There is no separate rule
// for it any more.
//
// Proves OPS-02 (documentation-only changes): see the pass conditions of the row; OPS ids are not traced.
// Acceptance: Documentation-only changes (part)
func TestChangedFilesPendingIsDocumentation(t *testing.T) {
	const pending = "tools/trace/pending.txt"
	pend := cfPatchFile(pending, "@@ -1 +1 @@", "-Release tag", "+Deploy")
	for _, tc := range []struct {
		name  string
		files []cfFile
		docs  bool
	}{
		{"alone", []cfFile{pend}, true},
		{"alone without a patch", cfNames(pending), true},
		{"with a documentation file", []cfFile{{name: "README.md"}, pend}, true},
		{"with every kind of documentation file", append(cfNames(cfDocs...), pend), true},
		{"with the design", []cfFile{pend, {name: "docs/DESIGN.md"}}, true},
		{"with the results", []cfFile{pend, {name: "docs/RESULTS.md"}}, true},
		{"with a comment-only go file", []cfFile{pend, goFile(h, "+// a")}, true},
		{"with a code file", []cfFile{pend, {name: "main.go"}}, false},
		{"with a Go code change", []cfFile{pend, goFile(h, "+x := 1")}, false},
		{"with a trace tool file", []cfFile{pend, {name: "tools/trace/main.go"}}, false},
		{"a trace tool file alone", cfNames("tools/trace/main.go"), false},
		{"renamed from another file", []cfFile{{name: pending, prev: "tools/trace/old.txt", raw: `"status":"renamed"`}}, false},
		{"renamed to another file", []cfFile{{name: "tools/trace/old.txt", prev: pending, raw: `"status":"renamed"`}}, false},
		{"in a subdirectory", cfNames("sub/" + pending), false},
		{"with a suffix", cfNames(pending + ".bak"), false},
		{"upper case", cfNames("tools/trace/PENDING.txt"), false},
		{"next to it", cfNames("tools/trace/pending2.txt"), false},
		{"a newline hides a code file", cfNames(pending + "\nmain.go"), false},
		{"empty list", nil, false},
	} {
		for mode, c := range cfBoth(tc.files) {
			t.Run(mode+" "+tc.name, func(t *testing.T) { t.Parallel(); cfRun(t, c, tc.docs) })
		}
	}
	// A list that cannot be read or may be incomplete gives false.
	for _, body := range []string{"", "garbage", `{"files":null}`, `{"message":"Not Found"}`} {
		cfRun(t, cfCase{mode: "commit", pages: []string{body}}, false)
	}
	c := cfCompare(cfJSON(pend))
	c.fail = []int{1}
	cfRun(t, c, false)
	var pages []string
	for n := 3000; n > 0; n -= 100 {
		pages = append(pages, cfJSON(cfN(pending, 100)...))
	}
	cfRun(t, cfCompare(pages...), false)
	cfRun(t, cfCompare(pages[1:]...), true)
}

// The script prints one line, docs_only, and writes the same line to
// GITHUB_OUTPUT: the output slow_skip is gone.
//
// Proves OPS-02 (documentation-only changes): see the pass conditions of the row; OPS ids are not traced.
// Acceptance: Documentation-only changes (part)
func TestChangedFilesPrintsOneOutput(t *testing.T) {
	for _, files := range [][]cfFile{cfNames("tools/trace/pending.txt"), cfNames("main.go")} {
		c := cfCommit(cfJSON(files...))
		r := runCF(t, c, true, c.args()...)
		want := cfLines(files[0].name != "main.go")
		if r.stdout != want || r.output != want {
			t.Errorf("stdout %q, output %q, want both %q", r.stdout, r.output, want)
		}
		if strings.Count(r.stdout, "\n") != 1 || strings.Contains(r.stdout+r.output, "slow_skip") {
			t.Errorf("stdout = %q, want exactly one line and no slow_skip", r.stdout)
		}
	}
}

// A Go file that is otherwise comment-only is fetched at the head commit and
// counts as comment-only only when the whole file holds no backquote (a raw
// string or a struct tag): the patch cannot show that a changed blank or //
// line is inside a raw string opened outside its window.
//
// Proves OPS-02 (documentation-only changes): see the pass conditions of the row; OPS ids are not traced.
// Acceptance: Documentation-only changes (part)
func TestChangedFilesGoFileContents(t *testing.T) {
	const path = "internal/x/x.go"
	file := []cfFile{goFile(h, "+// a")}
	rawString := "package x\n\nvar t = `\nline\n\n// not a comment\nline\n`\n"
	tag := "package x\n\ntype T struct {\n\tA int `json:\"a\"`\n}\n"
	body := func(text string) map[string]string { return map[string]string{path: cfContent(text)} }
	for _, tc := range []struct {
		name     string
		contents map[string]string
		fail     []string
		want     bool
	}{
		{"clean file", body("package x\n\n// a\nfunc f() {}\n"), nil, true},
		{"default clean file", nil, nil, true},
		{"raw string, backquotes out of the window", body(rawString), nil, false},
		{"struct tag", body(tag), nil, false},
		{"backquote only in a comment", body("package x\n// a `b`\n"), nil, false},
		{"backquote on the last line", body("package x\nvar _ = `"), nil, false},
		{"fetch fails", body("package x\n"), []string{path}, false},
		{"not found", map[string]string{}, nil, false},
		{"empty answer", map[string]string{path: ""}, nil, false},
		{"empty content", map[string]string{path: `{"type":"file","encoding":"base64","size":9,"content":""}`}, nil, false},
		{"content too large (encoding none)", map[string]string{path: `{"type":"file","encoding":"none","size":2000000,"content":""}`}, nil, false},
		{"encoding is not base64", map[string]string{path: `{"type":"file","encoding":"utf-8","content":"package x"}`}, nil, false},
		{"a directory listing", map[string]string{path: `[{"type":"file","name":"x.go"}]`}, nil, false},
		{"type is not file", map[string]string{path: `{"type":"symlink","encoding":"base64","content":"cGFja2FnZSB4Cg=="}`}, nil, false},
		{"content is not a string", map[string]string{path: `{"type":"file","encoding":"base64","content":5}`}, nil, false},
		{"garbage", map[string]string{path: "<html>"}, nil, false},
		{"error object", map[string]string{path: `{"message":"Not Found"}`}, nil, false},
		{"content is not base64", map[string]string{path: `{"type":"file","encoding":"base64","content":"!!!"}`}, nil, false},
	} {
		for _, mode := range []string{"compare", "commit"} {
			t.Run(mode+" "+tc.name, func(t *testing.T) {
				t.Parallel()
				c := cfCompare(cfJSON(file...))
				ref := cfHead
				if mode == "commit" {
					c = cfCommit(cfJSON(file...))
					ref = cfSHA
				}
				c.contents, c.contentsFail = tc.contents, tc.fail
				r := runCF(t, c, true, c.args()...)
				cfWant(t, r, tc.want)
				want := "1 " + c.endpoint() + "\n0 repos/" + cfRepo + "/contents/" + path + "?ref=" + ref + "\n"
				if r.calls != want {
					t.Errorf("gh calls = %q, want %q", r.calls, want)
				}
			})
		}
	}
}

// Only a file that passed every patch check is fetched, and the fetch stops at
// the first file that is not clean. A file with a backquote makes the whole
// change a code change, also next to clean Go files and documentation.
//
// Proves OPS-02 (documentation-only changes): see the pass conditions of the row; OPS ids are not traced.
// Acceptance: Documentation-only changes (part)
func TestChangedFilesGoContentsAreFetchedOnlyWhenNeeded(t *testing.T) {
	a, b := cfPatchFile("a/a.go", h, "+// a"), cfPatchFile("b/b.go", h, "+// b")
	clean, dirty := cfContent("package x\n"), cfContent("package x\nvar _ = `a`\n")
	for _, tc := range []struct {
		name     string
		files    []cfFile
		contents map[string]string
		want     bool
		fetched  []string
	}{
		{"documentation only", cfNames("README.md"), nil, true, nil},
		{"code file", []cfFile{a, cfPatchFile("c.go", h, "+x := 1")}, map[string]string{"a/a.go": clean}, false, nil},
		{"two clean files", []cfFile{a, b}, map[string]string{"a/a.go": clean, "b/b.go": clean}, true, []string{"a/a.go", "b/b.go"}},
		{"second file has a backquote", []cfFile{a, b}, map[string]string{"a/a.go": clean, "b/b.go": dirty}, false, []string{"a/a.go", "b/b.go"}},
		{"first file has a backquote, no more fetches", []cfFile{a, b}, map[string]string{"a/a.go": dirty, "b/b.go": clean}, false, []string{"a/a.go"}},
		{"with documentation", []cfFile{{name: "README.md"}, a}, map[string]string{"a/a.go": clean}, true, []string{"a/a.go"}},
		{"a patch check failed, no fetch", []cfFile{cfPatchFile("a/a.go", h, "+// Covers: FR-16")}, map[string]string{}, false, nil},
		{"pending.txt and a clean comment-only file", []cfFile{{name: "tools/trace/pending.txt"}, a}, map[string]string{"a/a.go": clean}, true, []string{"a/a.go"}},
		{"the design and a Go file with a backquote", []cfFile{{name: "docs/DESIGN.md"}, a}, map[string]string{"a/a.go": dirty}, false, []string{"a/a.go"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := cfCompare(cfJSON(tc.files...))
			c.contents = tc.contents
			r := runCF(t, c, true, c.args()...)
			cfWant(t, r, tc.want)
			var want string
			for _, f := range tc.fetched {
				want += "0 repos/" + cfRepo + "/contents/" + f + "?ref=" + cfHead + "\n"
			}
			if got := strings.TrimPrefix(r.calls, "1 "+c.endpoint()+"\n"); got != want {
				t.Errorf("fetches = %q, want %q", got, want)
			}
		})
	}
}

// At most 50 Go files are fetched: more than 50 comment-only Go files make the
// change a code change before any fetch (the token's rate limit).
//
// Proves OPS-02 (documentation-only changes): see the pass conditions of the row; OPS ids are not traced.
// Acceptance: Documentation-only changes (part)
func TestChangedFilesGoFileCap(t *testing.T) {
	files := func(n int) []cfFile {
		var fs []cfFile
		for i := range n {
			fs = append(fs, cfPatchFile(fmt.Sprintf("p/f%d.go", i), h, "+// a"))
		}
		return fs
	}
	for _, n := range []int{50, 51} {
		for _, mode := range []string{"compare", "commit"} {
			t.Run(fmt.Sprintf("%s %d files", mode, n), func(t *testing.T) {
				t.Parallel()
				c := cfCompare(cfJSON(files(n)...))
				if mode == "commit" {
					c = cfCommit(cfJSON(files(n)...))
				}
				r := runCF(t, c, true, c.args()...)
				cfWant(t, r, n == 50)
				fetches := strings.Count(r.calls, "/contents/")
				if want := map[int]int{50: 50, 51: 0}[n]; fetches != want {
					t.Errorf("%d fetches, want %d", fetches, want)
				}
			})
		}
	}
	// Documentation files do not count toward the cap, and a file that is not
	// comment-only does not either (it already makes the change a code change).
	fs := append(files(50), cfN("README.md", 100)...)
	cfRun(t, cfCompare(cfJSON(fs...)), true)
}

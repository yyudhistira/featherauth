// Command archcheck enforces the package rules in CLAUDE.md: the import
// direction between components, test-support packages used only by tests,
// no dot imports, and calls that must go through internal/clock (time and
// timers), internal/secure (randomness), internal/logx (logging), or an
// HTTP client and server with timeouts and requests with a context.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

func main() {
	root := flag.String("root", ".", "module root")
	flag.Parse()
	problems, err := check(*root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "archcheck:", err)
		os.Exit(2)
	}
	for _, p := range problems {
		fmt.Fprintln(os.Stderr, "archcheck:", p)
	}
	if len(problems) > 0 {
		os.Exit(1)
	}
}

// ranks orders the components: a package may import its own component or a
// component with a lower rank. Same-rank imports between components are not
// allowed. internal/testutil and <component>test packages are test support
// and have no rank.
var ranks = map[string]int{
	"clock":    0,
	"secure":   1,
	"logx":     1,
	"config":   2,
	"store":    3,
	"token":    4,
	"provider": 4,
	"user":     5,
	"web":      5,
	"server":   6,
	"oidc":     7,
	"admin":    7,
	"cmd":      8,
}

// Only clock reads the system clock and timers, and only secure reads
// crypto/rand; math/rand is allowed nowhere.
const (
	timeComponent   = "clock"
	cryptoComponent = "secure"
)

// randomImportAllowedIn maps each random-source import to the one component
// that may use it ("" means none).
var randomImportAllowedIn = map[string]string{
	"crypto/rand":  cryptoComponent,
	"math/rand":    "",
	"math/rand/v2": "",
}

// forbiddenTimeCalls read the system clock or real timers; tests advance a
// fake clock instead of sleeping.
var forbiddenTimeCalls = map[string]bool{
	"Now": true, "Since": true, "Until": true,
	"Sleep": true, "After": true, "Tick": true, "NewTimer": true, "NewTicker": true, "AfterFunc": true,
}

var forbiddenHTTP = map[string]string{
	"DefaultClient":     "use a client with a timeout",
	"Get":               "use a client with a timeout",
	"Post":              "use a client with a timeout",
	"Head":              "use a client with a timeout",
	"PostForm":          "use a client with a timeout",
	"NewRequest":        "use http.NewRequestWithContext",
	"ListenAndServe":    "use an http.Server with read, write and idle timeouts",
	"ListenAndServeTLS": "use an http.Server with read, write and idle timeouts",
	"Serve":             "use an http.Server with read, write and idle timeouts",
	"ServeTLS":          "use an http.Server with read, write and idle timeouts",
}

// forbiddenSlog are the slog functions that log or build a logger without
// going through internal/logx and its redaction (SEC-13). Attribute and value
// constructors and types stay allowed.
var forbiddenSlog = map[string]bool{
	"Debug": true, "DebugContext": true, "Info": true, "InfoContext": true,
	"Warn": true, "WarnContext": true, "Error": true, "ErrorContext": true,
	"Log": true, "LogAttrs": true, "Default": true, "SetDefault": true,
	"SetLogLoggerLevel": true, "New": true, "NewJSONHandler": true,
	"NewTextHandler": true, "NewLogLogger": true,
}

var htmlComponents = map[string]bool{"web": true, "oidc": true}

// componentOf returns the component of a package path relative to the
// module root: the first element below internal/, "cmd" for commands, or ""
// for packages the rules do not apply to (such as tools).
func componentOf(rel string) string {
	parts := strings.Split(rel, "/")
	switch {
	case len(parts) >= 2 && parts[0] == "internal":
		return parts[1]
	case parts[0] == "cmd":
		return "cmd"
	}
	return ""
}

// isTestSupport reports whether a package exists only for tests:
// internal/testutil/... or a <component>test package inside its component.
func isTestSupport(rel string) bool {
	comp := componentOf(rel)
	return comp == "testutil" || (comp != "" && path.Base(rel) == comp+"test")
}

func check(root string) ([]string, error) {
	mod, err := goCmd(root, "list", "-m")
	if err != nil {
		return nil, err
	}
	module := strings.TrimSpace(string(mod))
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	dirs, err := goFilesByDir(absRoot)
	if err != nil {
		return nil, err
	}

	seen := map[string]bool{}
	var problems []string
	report := func(file string, line int, format string, args ...any) {
		p := fmt.Sprintf("%s:%d: %s", file, line, fmt.Sprintf(format, args...))
		if !seen[p] {
			seen[p] = true
			problems = append(problems, p)
		}
	}

	for _, dir := range sortedKeys(dirs) {
		files := dirs[dir]
		rel, err := filepath.Rel(absRoot, dir)
		if err != nil {
			return nil, err
		}
		rel = filepath.ToSlash(rel)
		comp := componentOf(rel)
		if comp == "" {
			continue
		}
		if _, ok := ranks[comp]; !ok && comp != "testutil" {
			report(relFile(absRoot, dir, files[0]), 1, "unknown component %q; add it to the rank table in tools/archcheck", comp)
			continue
		}
		for _, name := range files {
			if err := checkFile(absRoot, module, rel, comp, dir, name, report); err != nil {
				return nil, err
			}
		}
	}
	if err := typedChecks(absRoot, report); err != nil {
		return nil, err
	}
	sort.Strings(problems)
	return problems, nil
}

// goFilesByDir walks the module and returns its .go files by directory,
// whatever their build tags, so tests behind the browser, conformance and
// load tags are checked as well. It skips testdata, vendor, hidden
// directories and nested modules.
func goFilesByDir(absRoot string) (map[string][]string, error) {
	dirs := map[string][]string{}
	err := filepath.WalkDir(absRoot, func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if e.IsDir() {
			if p == absRoot {
				return nil
			}
			name := e.Name()
			if name == "testdata" || name == "vendor" || strings.HasPrefix(name, ".") {
				return filepath.SkipDir
			}
			if _, err := os.Stat(filepath.Join(p, "go.mod")); err == nil {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(p, ".go") {
			dirs[filepath.Dir(p)] = append(dirs[filepath.Dir(p)], e.Name())
		}
		return nil
	})
	for _, files := range dirs {
		sort.Strings(files)
	}
	return dirs, err
}

func sortedKeys(m map[string][]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

type reporter func(file string, line int, format string, args ...any)

func checkFile(absRoot, module, rel, comp, dir, name string, report reporter) error {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
	if err != nil {
		return err
	}
	file := relFile(absRoot, dir, name)
	isTest := strings.HasSuffix(name, "_test.go")
	line := func(n ast.Node) int { return fset.Position(n.Pos()).Line }

	names := map[string]string{} // local import name -> import path
	for _, spec := range f.Imports {
		imp, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			return err
		}
		local := path.Base(imp)
		if strings.HasPrefix(local, "v") && strings.Contains(imp, "/") {
			if _, err := strconv.Atoi(local[1:]); err == nil {
				local = path.Base(path.Dir(imp)) // math/rand/v2 -> rand
			}
		}
		if spec.Name != nil {
			local = spec.Name.Name
		}
		if local == "." {
			report(file, line(spec), "dot import of %q is forbidden; import it by name", imp)
			continue
		}
		names[local] = imp

		switch {
		case isRandomImport(imp) && randomImportAllowedIn[imp] != comp:
			report(file, line(spec), "import %q is forbidden here; use internal/secure", imp)
		case imp == "log":
			report(file, line(spec), "import \"log\" is forbidden; use internal/logx")
		case imp == "text/template" && htmlComponents[comp]:
			report(file, line(spec), "import \"text/template\" is forbidden in %s; use html/template", comp)
		case strings.HasPrefix(imp, module+"/"):
			checkInternalImport(rel, comp, strings.TrimPrefix(imp, module+"/"), isTest, func(format string, args ...any) {
				report(file, line(spec), format, args...)
			})
		}
	}

	// pkgSel returns the import path and name of a selector like http.Client.
	pkgSel := func(e ast.Expr) (string, string, bool) {
		sel, ok := e.(*ast.SelectorExpr)
		if !ok {
			return "", "", false
		}
		x, ok := sel.X.(*ast.Ident)
		if !ok {
			return "", "", false
		}
		return names[x.Name], sel.Sel.Name, true
	}

	ast.Inspect(f, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.SelectorExpr:
			imp, name, ok := pkgSel(n)
			if !ok {
				return true
			}
			switch imp {
			case "time":
				if forbiddenTimeCalls[name] && comp != timeComponent {
					report(file, line(n), "time.%s is forbidden here; use internal/clock", name)
				}
			case "net/http":
				if hint, bad := forbiddenHTTP[name]; bad {
					report(file, line(n), "http.%s is forbidden; %s", name, hint)
				}
			case "log/slog":
				if forbiddenSlog[name] && comp != "logx" {
					report(file, line(n), "slog.%s is forbidden outside internal/logx; use a logger from logx.New", name)
				}
			}
		case *ast.CompositeLit:
			imp, name, ok := pkgSel(n.Type)
			if !ok || imp != "net/http" || (name != "Client" && name != "Server") {
				return true
			}
			// set holds the fields given a value other than the literal 0;
			// a literal 0 means no timeout and is reported as such.
			set := map[string]bool{}
			checkRedirectNil := false // CheckRedirect: nil, which refuses nothing
			for _, el := range n.Elts {
				kv, ok := el.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				k, ok := kv.Key.(*ast.Ident)
				if !ok {
					continue
				}
				if id, isIdent := kv.Value.(*ast.Ident); isIdent && k.Name == "CheckRedirect" && id.Name == "nil" {
					checkRedirectNil = true
				}
				if lit, ok := kv.Value.(*ast.BasicLit); ok && lit.Value == "0" && strings.HasSuffix(k.Name, "Timeout") {
					report(file, line(n), "http.%s with %s 0 (no timeout)", name, k.Name)
					set[k.Name+"=0"] = true
					continue
				}
				set[k.Name] = true
			}
			given := func(k string) bool { return set[k] || set[k+"=0"] }
			switch name {
			case "Client":
				if !given("Timeout") {
					report(file, line(n), "http.Client without Timeout")
				}
				// A client of a provider call answers a redirect as the answer,
				// so a 3xx is a failure and never a second request (SEC-26). The
				// rule checks that the literal has a CheckRedirect value that is
				// not the literal nil; what the function does is not inspected.
				if comp == "provider" && !isTest && (!given("CheckRedirect") || checkRedirectNil) {
					report(file, line(n), "http.Client in provider needs a CheckRedirect func that refuses redirects (SEC-26)")
				}
			case "Server":
				var missing []string
				if !given("ReadTimeout") && !given("ReadHeaderTimeout") {
					missing = append(missing, "ReadTimeout")
				}
				for _, k := range []string{"WriteTimeout", "IdleTimeout"} {
					if !given(k) {
						missing = append(missing, k)
					}
				}
				if len(missing) > 0 {
					report(file, line(n), "http.Server without %s", strings.Join(missing, ", "))
				}
			}
		case *ast.StructType:
			// A value field (embedded or named) starts as the zero value: a
			// client without Timeout or a server without timeouts.
			for _, field := range n.Fields.List {
				if imp, name, ok := pkgSel(field.Type); ok && imp == "net/http" {
					switch name {
					case "Client":
						report(file, line(field), "struct field of type http.Client; hold a *http.Client built with a literal that sets Timeout")
					case "Server":
						report(file, line(field), "struct field of type http.Server; hold a *http.Server built with a literal that sets its timeouts")
					}
				}
			}
		case *ast.ValueSpec:
			if len(n.Values) > 0 || n.Type == nil {
				return true
			}
			if imp, name, ok := pkgSel(n.Type); ok && imp == "net/http" {
				switch name {
				case "Client":
					report(file, line(n), "var of type http.Client has no Timeout; build it with a literal that sets Timeout")
				case "Server":
					report(file, line(n), "var of type http.Server has no timeouts; build it with a literal that sets them")
				}
			}
		case *ast.CallExpr:
			if fn, ok := n.Fun.(*ast.Ident); ok && fn.Name == "new" && len(n.Args) == 1 {
				if imp, name, ok := pkgSel(n.Args[0]); ok && imp == "net/http" {
					switch name {
					case "Client":
						report(file, line(n), "new(http.Client) has no Timeout; use a literal that sets it")
					case "Server":
						report(file, line(n), "new(http.Server) has no timeouts; use a literal that sets them")
					}
				}
			}
		}
		return true
	})
	return nil
}

func isRandomImport(imp string) bool {
	_, ok := randomImportAllowedIn[imp]
	return ok
}

func checkInternalImport(rel, comp, target string, isTest bool, report func(format string, args ...any)) {
	if isTest {
		return // tests may import anything, including test support
	}
	if isTestSupport(target) {
		if !isTestSupport(rel) {
			report("non-test code imports test-support package %s", strings.TrimPrefix(target, "internal/"))
		}
		return
	}
	targetComp := componentOf(target)
	if targetComp == comp || comp == "testutil" {
		return
	}
	targetRank, ok := ranks[targetComp]
	if !ok {
		return // reported as an unknown component on its own package
	}
	if ranks[comp] <= targetRank {
		report("%s imports %s, which is not below it (ranks: %s %d, %s %d)", comp, targetComp, comp, ranks[comp], targetComp, targetRank)
	}
}

func relFile(absRoot, dir, name string) string {
	rel, err := filepath.Rel(absRoot, filepath.Join(dir, name))
	if err != nil {
		return filepath.Join(dir, name)
	}
	return filepath.ToSlash(rel)
}

func goCmd(dir string, args ...string) ([]byte, error) {
	cmd := exec.Command("go", args...)
	cmd.Dir = dir
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("go %s: %v: %s", strings.Join(args, " "), err, stderr.String())
	}
	return out, nil
}

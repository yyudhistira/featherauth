package deploy_test

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// directAllowed lists every direct dependency the design's Tech stack table
// approves (plus the test tools of CLAUDE.md, which are tools, not stack).
var directAllowed = map[string]bool{
	"golang.org/x/oauth2":           true, // provider code exchange
	"github.com/coreos/go-oidc/v3":  true, // ID token validation
	"github.com/lestrrat-go/jwx/v3": true, // JWT and JWKS
	"modernc.org/sqlite":            true, // database
	"github.com/pressly/goose/v3":   true, // migrations
	"go.yaml.in/yaml/v3":            true, // config
	"github.com/fsnotify/fsnotify":  true, // file watching
	"golang.org/x/time":             true, // rate limiting
	"golang.org/x/tools":            true, // go/packages in tools/archcheck; goimports
	"github.com/chromedp/chromedp":  true, // browser tests
	"github.com/jackc/pgx/v5":       true, // Postgres (later)
	"golang.org/x/vuln":             true,
	"honnef.co/go/tools":            true,
}

func goMod(t *testing.T) (requires []struct {
	Path     string
	Indirect bool
}) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "go", "mod", "edit", "-json")
	cmd.Dir = ".."
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Require []struct {
			Path     string
			Indirect bool
		}
	}
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatal(err)
	}
	return m.Require
}

// Covers: SEC-15
// Acceptance: Dependencies
func TestDirectDependenciesAreInTheTechStack(t *testing.T) {
	for _, r := range goMod(t) {
		if !r.Indirect && !directAllowed[r.Path] {
			t.Errorf("direct dependency %s is not in the design's Tech stack", r.Path)
		}
	}
}

// rawCrypto are the packages that sign, verify or authenticate on their own.
// Non-test code may import them only in the files listed in rawCryptoAllowed.
var rawCrypto = map[string]bool{
	"crypto/hmac":    true,
	"crypto/rsa":     true,
	"crypto/ecdsa":   true,
	"crypto/ed25519": true,
}

// rawCryptoAllowed lists, by path relative to the repository root, the files
// that may import a raw crypto package, with the reason. None of them signs or
// verifies a token: jwx does that (TestTokensAreSignedAndVerifiedByLibraries).
var rawCryptoAllowed = map[string][]string{
	// Key types: loading, validating and type-switching the keys given to jwx.
	"internal/token/issuer.go":          {"crypto/ecdsa", "crypto/rsa"},
	"internal/token/keys.go":            {"crypto/ecdsa", "crypto/rsa"},
	"internal/config/secrets.go":        {"crypto/ecdsa", "crypto/rsa"},
	"internal/config/loader.go":         {"crypto/ecdsa"},
	"internal/config/validate.go":       {"crypto/ecdsa", "crypto/rsa"},
	"internal/provider/apple_secret.go": {"crypto/ecdsa"}, // the Apple key's type; the client secret is signed by jwx
	// Key generation of `featherauth keys generate`.
	"cmd/featherauth/keys.go": {"crypto/ecdsa", "crypto/rsa"},
	// The Facebook appsecret_proof is an HMAC-SHA256, not a token.
	"internal/provider/facebook.go": {"crypto/hmac"},
	// Meta's signed_request is an HMAC-SHA256 over its payload under the app
	// secret (a Meta format, not a token), compared with secure.Equal.
	"internal/provider/facebook_event.go": {"crypto/hmac"},
}

// scanRawCrypto parses the non-test Go files under root/internal and
// root/cmd and reports every import of a raw crypto package outside allowed,
// and every call of a Sign or Verify function of rsa, ecdsa or ed25519.
func scanRawCrypto(t *testing.T, root string, allowed map[string][]string) []string {
	t.Helper()
	var bad []string
	for _, top := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, top), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "testdata" || d.Name() == "testutil" {
					return fs.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			rel, _ := filepath.Rel(root, path)
			rel = filepath.ToSlash(rel)
			f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
			if err != nil {
				return err
			}
			local := map[string]string{} // local name -> import path
			for _, im := range f.Imports {
				ip, _ := strconv.Unquote(im.Path.Value)
				if !rawCrypto[ip] {
					continue
				}
				name := ip[strings.LastIndex(ip, "/")+1:]
				if im.Name != nil {
					name = im.Name.Name
				}
				local[name] = ip
				if !slices.Contains(allowed[rel], ip) {
					bad = append(bad, rel+" imports "+ip)
				}
			}
			ast.Inspect(f, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				id, ok := sel.X.(*ast.Ident)
				if ok && local[id.Name] != "" && local[id.Name] != "crypto/hmac" &&
					(strings.HasPrefix(sel.Sel.Name, "Sign") || strings.HasPrefix(sel.Sel.Name, "Verify")) {
					bad = append(bad, rel+" calls "+id.Name+"."+sel.Sel.Name)
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return bad
}

// Covers: SEC-15
// Acceptance: Dependencies
func TestNoRawCryptoOutsideTheAllowList(t *testing.T) {
	if bad := scanRawCrypto(t, "..", rawCryptoAllowed); len(bad) > 0 {
		t.Errorf("raw crypto outside the allow-list:\n%s", strings.Join(bad, "\n"))
	}
	// Every allow-list entry is still needed, so the list cannot only grow.
	for file, pkgs := range rawCryptoAllowed {
		b, err := os.ReadFile(filepath.Join("..", file))
		if err != nil {
			t.Errorf("allow-list names %s: %v", file, err)
			continue
		}
		for _, p := range pkgs {
			if !strings.Contains(string(b), `"`+p+`"`) {
				t.Errorf("allow-list entry %s %s is unused", file, p)
			}
		}
	}
}

// The scan rejects a new raw crypto import and a raw Sign or Verify call, and
// accepts an allow-listed import.
//
// Covers: SEC-15
// Acceptance: Dependencies
func TestRawCryptoScanRejectsNewUse(t *testing.T) {
	root := t.TempDir()
	write := func(rel, src string) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("internal/ok/ok.go", "package ok\nimport \"crypto/hmac\"\nvar _ = hmac.New\n")
	write("internal/new/new.go", "package n\nimport \"crypto/rsa\"\nvar _ rsa.PublicKey\n")
	write("cmd/x/x.go", "package x\nimport e \"crypto/ecdsa\"\nvar _ = e.SignASN1\nfunc f() { e.VerifyASN1(nil, nil, nil) }\n")
	write("internal/new/new_test.go", "package n\nimport \"crypto/ed25519\"\nvar _ ed25519.PublicKey\n")
	got := strings.Join(scanRawCrypto(t, root, map[string][]string{"internal/ok/ok.go": {"crypto/hmac"}}), "\n")
	for _, want := range []string{"internal/new/new.go imports crypto/rsa", "cmd/x/x.go imports crypto/ecdsa", "cmd/x/x.go calls e.VerifyASN1"} {
		if !strings.Contains(got, want) {
			t.Errorf("scan did not report %q; got:\n%s", want, got)
		}
	}
	if strings.Contains(got, "internal/ok") || strings.Contains(got, "_test.go") || strings.Contains(got, "ed25519") {
		t.Errorf("scan reported an allowed or test file:\n%s", got)
	}
}

// Tokens are signed and verified by jwx; OAuth and OIDC by their libraries.
//
// Covers: SEC-15
// Acceptance: Dependencies
func TestTokensAreSignedAndVerifiedByLibraries(t *testing.T) {
	calls := func(dir string) (imports, called map[string]bool) {
		imports, called = map[string]bool{}, map[string]bool{}
		files, err := filepath.Glob(filepath.Join("..", dir, "*.go"))
		if err != nil || len(files) == 0 {
			t.Fatalf("no files in %s: %v", dir, err)
		}
		for _, p := range files {
			if strings.HasSuffix(p, "_test.go") {
				continue
			}
			f, err := parser.ParseFile(token.NewFileSet(), p, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			for _, im := range f.Imports {
				ip, _ := strconv.Unquote(im.Path.Value)
				imports[ip] = true
			}
			ast.Inspect(f, func(n ast.Node) bool {
				if sel, ok := n.(*ast.SelectorExpr); ok {
					if id, ok := sel.X.(*ast.Ident); ok {
						called[id.Name+"."+sel.Sel.Name] = true
					}
				}
				return true
			})
		}
		return imports, called
	}
	tokImports, tokCalls := calls("internal/token")
	for _, want := range []string{"github.com/lestrrat-go/jwx/v3/jws", "github.com/lestrrat-go/jwx/v3/jwk"} {
		if !tokImports[want] {
			t.Errorf("internal/token does not import %s", want)
		}
	}
	for _, want := range []string{"jws.Sign", "jws.Verify"} {
		if !tokCalls[want] {
			t.Errorf("internal/token does not use %s", want)
		}
	}
	provImports, _ := calls("internal/provider")
	for _, want := range []string{"golang.org/x/oauth2", "github.com/coreos/go-oidc/v3/oidc"} {
		if !provImports[want] {
			t.Errorf("internal/provider does not import %s", want)
		}
	}
}

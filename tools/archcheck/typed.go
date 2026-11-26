package main

import (
	"fmt"
	"go/ast"
	"go/types"
	"path/filepath"
	"strings"

	"golang.org/x/tools/go/packages"
)

// buildTags are the tags of the extra test suites; loading with all of them
// type-checks those files too.
const buildTags = "browser,conformance,load,ops,postgres"

// noContextMethods are the http.Client methods that build their request
// without a context.
var noContextMethods = map[string]bool{"Get": true, "Head": true, "Post": true, "PostForm": true}

// typedChecks runs the checks that need type information: a call to one of
// noContextMethods on an http.Client, also when the method is promoted from
// an embedded client or the client is held under another name.
func typedChecks(absRoot string, report reporter) error {
	cfg := &packages.Config{
		Mode:       packages.NeedName | packages.NeedFiles | packages.NeedSyntax | packages.NeedTypes | packages.NeedTypesInfo,
		Dir:        absRoot,
		Tests:      true,
		BuildFlags: []string{"-tags=" + buildTags},
	}
	pkgs, err := packages.Load(cfg, "./...")
	if err != nil {
		return err
	}
	var loadErrs []string
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		for _, e := range p.Errors {
			loadErrs = append(loadErrs, e.Error())
		}
	})
	if len(loadErrs) > 0 {
		return fmt.Errorf("type-checking failed:\n  %s", strings.Join(loadErrs, "\n  "))
	}

	for _, p := range pkgs {
		for _, f := range p.Syntax {
			ast.Inspect(f, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || !noContextMethods[sel.Sel.Name] {
					return true
				}
				if !isHTTPClientMethod(p.TypesInfo.Selections[sel]) {
					return true
				}
				pos := p.Fset.Position(sel.Pos())
				rel, err := filepath.Rel(absRoot, pos.Filename)
				if err != nil {
					rel = pos.Filename
				}
				report(filepath.ToSlash(rel), pos.Line, "http.Client.%s sends a request without a context; build it with http.NewRequestWithContext and call Do", sel.Sel.Name)
				return true
			})
		}
	}
	checkRevokingCalls(pkgs, absRoot, report)
	return nil
}

// revokingMethodsOf returns the methods of store.RefreshTokens whose result is a
// store.Ended: the calls that end sessions (FR-43). They are read from the
// interface itself, so a new revoking method is checked without a list here. A
// method that returns no Ended (the rotation's RevokeOthers) is not one.
func revokingMethodsOf(pkgs []*packages.Package) map[string]bool {
	for _, p := range pkgs {
		if p.Types == nil || !isStorePackage(p.PkgPath) {
			continue
		}
		obj := p.Types.Scope().Lookup("RefreshTokens")
		if obj == nil {
			continue
		}
		iface, ok := obj.Type().Underlying().(*types.Interface)
		if !ok {
			continue
		}
		out := map[string]bool{}
		for i := 0; i < iface.NumMethods(); i++ {
			m := iface.Method(i)
			res := m.Type().(*types.Signature).Results()
			for j := 0; j < res.Len(); j++ {
				if named, ok := res.At(j).Type().(*types.Named); ok && named.Obj().Name() == "Ended" {
					out[m.Name()] = true
				}
			}
		}
		return out
	}
	return nil
}

// checkRevokingCalls reports a function outside the store that calls a revoking
// RefreshTokens method without calling store.QueueLogouts: every revocation must
// queue the back-channel logouts of the sessions it ends, in its transaction.
// Test files, the store and its test support are not checked.
func checkRevokingCalls(pkgs []*packages.Package, absRoot string, report reporter) {
	revoking := revokingMethodsOf(pkgs)
	for _, p := range pkgs {
		for _, f := range p.Syntax {
			pos := p.Fset.Position(f.Pos())
			rel, err := filepath.Rel(absRoot, pos.Filename)
			if err != nil {
				rel = pos.Filename
			}
			rel = filepath.ToSlash(rel)
			if strings.HasSuffix(rel, "_test.go") || strings.HasPrefix(rel, "internal/store/") || strings.HasPrefix(rel, "internal/testutil/") {
				continue
			}
			for _, decl := range f.Decls {
				fd, ok := decl.(*ast.FuncDecl)
				if !ok || fd.Body == nil {
					continue
				}
				var calls []*ast.SelectorExpr
				queued := false
				ast.Inspect(fd.Body, func(n ast.Node) bool {
					sel, ok := n.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					fn, ok := p.TypesInfo.Uses[sel.Sel].(*types.Func)
					if !ok || fn.Pkg() == nil || !isStorePackage(fn.Pkg().Path()) {
						return true
					}
					switch {
					case fn.Name() == "QueueLogouts":
						queued = true
					case revoking[fn.Name()] && receiverNamed(fn) == "RefreshTokens":
						calls = append(calls, sel)
					}
					return true
				})
				if queued {
					continue
				}
				for _, sel := range calls {
					report(rel, p.Fset.Position(sel.Pos()).Line,
						"RefreshTokens.%s ends sessions in %s without store.QueueLogouts in the same function; the back-channel logouts would not be queued (FR-43)",
						sel.Sel.Name, fd.Name.Name)
				}
			}
		}
	}
}

// isStorePackage reports whether an import path is the store package.
func isStorePackage(path string) bool {
	return path == "internal/store" || strings.HasSuffix(path, "/internal/store")
}

// receiverNamed returns the name of the named type a method is declared on.
func receiverNamed(fn *types.Func) string {
	recv := fn.Type().(*types.Signature).Recv()
	if recv == nil {
		return ""
	}
	t := recv.Type()
	if ptr, ok := t.(*types.Pointer); ok {
		t = ptr.Elem()
	}
	named, ok := t.(*types.Named)
	if !ok {
		return ""
	}
	return named.Obj().Name()
}

// isHTTPClientMethod reports whether a selection is a method declared on
// net/http.Client, wherever the receiver came from.
func isHTTPClientMethod(s *types.Selection) bool {
	if s == nil || s.Kind() != types.MethodVal {
		return false
	}
	fn, ok := s.Obj().(*types.Func)
	if !ok {
		return false
	}
	recv := fn.Type().(*types.Signature).Recv()
	if recv == nil {
		return false
	}
	t := recv.Type()
	if ptr, ok := t.(*types.Pointer); ok {
		t = ptr.Elem()
	}
	named, ok := t.(*types.Named)
	if !ok {
		return false
	}
	obj := named.Obj()
	return obj.Pkg() != nil && obj.Pkg().Path() == "net/http" && obj.Name() == "Client"
}

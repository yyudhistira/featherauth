package main

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/yyudhistira/featherauth/deploy"
	"github.com/yyudhistira/featherauth/internal/config"
)

// exampleRoot is the directory of the embedded examples.
const exampleRoot = "config.example"

func (a *app) config(ctx context.Context, args []string) int {
	if len(args) == 0 {
		return a.usageError("config needs a subcommand: init or check")
	}
	switch args[0] {
	case "init":
		if len(args) != 2 {
			return a.usageError("config init needs exactly one directory")
		}
		return a.configInit(args[1])
	case "check":
		if len(args) != 2 {
			return a.usageError("config check needs exactly one directory")
		}
		return a.configCheck(ctx, args[1])
	}
	return a.usageError(fmt.Sprintf("unknown config subcommand %q", args[0]))
}

// configInit writes the annotated examples into dir. It writes nothing and
// fails when any of the files exists already.
func (a *app) configInit(dir string) int {
	var files []string
	err := fs.WalkDir(deploy.ConfigExample, exampleRoot, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			files = append(files, strings.TrimPrefix(p, exampleRoot+"/"))
		}
		return err
	})
	if err != nil {
		return a.fail(err)
	}
	for _, rel := range files {
		if _, err := os.Lstat(filepath.Join(dir, filepath.FromSlash(rel))); err == nil {
			return a.fail(fmt.Errorf("%s exists already; config init does not overwrite", filepath.Join(dir, filepath.FromSlash(rel))))
		}
	}
	for _, rel := range files {
		b, err := fs.ReadFile(deploy.ConfigExample, path.Join(exampleRoot, rel))
		if err != nil {
			return a.fail(err)
		}
		target := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return a.fail(err)
		}
		// O_EXCL: a file made since the check above is not overwritten either.
		f, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if err != nil {
			return a.fail(err)
		}
		_, werr := f.Write(b)
		if cerr := f.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			return a.fail(werr)
		}
		fmt.Fprintf(a.stdout, "wrote %s\n", target)
	}
	return 0
}

// configCheck prints every diagnostic of the configuration in dir, one per
// line, and "ok" when there is none. It fails when any is an error.
func (a *app) configCheck(ctx context.Context, dir string) int {
	ds := config.Check(ctx, dir, a.clock)
	failed := false
	for _, d := range ds {
		fmt.Fprintln(a.stdout, d.String())
		if d.Severity == config.Error {
			failed = true
		}
	}
	if failed {
		return 1
	}
	if len(ds) == 0 {
		fmt.Fprintln(a.stdout, "ok")
	}
	return 0
}

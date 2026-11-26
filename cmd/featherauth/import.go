package main

import (
	"context"
	"fmt"
	"os"

	"github.com/yyudhistira/featherauth/internal/admin"
	"github.com/yyudhistira/featherauth/internal/config"
)

// importReport is what `import` prints.
type importReport struct {
	Created  int   `json:"created"`
	Existing int   `json:"existing"`
	Skipped  []int `json:"skipped"`
}

// importCmd is `featherauth import <file> --realm <name>
// [--include-without-identity]`. The realm must be one of the loaded
// configuration. The file may come before or after the flags.
func (a *app) importCmd(ctx context.Context, args []string) int {
	var realm string
	var include bool
	var files []string
	for len(args) > 0 {
		fs := newFlags("import")
		fs.StringVar(&realm, "realm", "", "realm to import into")
		fs.BoolVar(&include, "include-without-identity", false, "import users that have no identities")
		if err := fs.Parse(args); err != nil {
			return a.usageError(err.Error())
		}
		if fs.NArg() == 0 {
			break
		}
		files = append(files, fs.Arg(0))
		args = fs.Args()[1:]
	}
	switch {
	case len(files) != 1:
		return a.usageError("import needs exactly one file")
	case realm == "":
		return a.usageError("import needs --realm <name>")
	}

	// The realm must be configured: reserved or misspelled names are refused
	// here, so no stray realm row is made.
	loader, err := config.NewLoader(a.configDir(), a.clock, nil)
	if err != nil {
		return a.fail(fmt.Errorf("the configuration must be valid before an import (run config check): %w", err))
	}
	rl, ok := loader.Current().Realm(config.RealmName(realm))
	if !ok {
		return a.fail(fmt.Errorf("realm %q is not in the configuration", realm))
	}
	f, err := os.Open(files[0])
	if err != nil {
		return a.fail(err)
	}
	defer f.Close()

	ops, st, _, err := a.ops(ctx, noRevocation)
	if err != nil {
		return a.fail(err)
	}
	defer st.Close()
	rep, err := ops.Import(ctx, config.RealmName(realm), f, admin.ImportOptions{IncludeWithoutIdentity: include, IDFormat: rl.UserData.IDFormat})
	if err != nil {
		return a.fail(err)
	}
	if rep.Skipped == nil {
		rep.Skipped = []int{}
	}
	if err := a.printJSON(importReport{rep.Created, rep.Existing, rep.Skipped}); err != nil {
		return a.fail(err)
	}
	return 0
}

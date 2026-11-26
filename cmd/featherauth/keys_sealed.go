package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/yyudhistira/featherauth/internal/admin"
	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/secure"
)

// sealedJSON is an identity as the key commands print it.
type sealedJSON struct {
	UserID   string `json:"user_id"`
	Provider string `json:"provider"`
	Subject  string `json:"subject"`
}

func sealedViews(refs []admin.SealedRef) []sealedJSON {
	out := make([]sealedJSON, len(refs)) // never nil: an empty list prints as []
	for i, r := range refs {
		out[i] = sealedJSON{string(r.UserID), string(r.Provider), r.Subject}
	}
	return out
}

// parseKeyArgs reads `<realm> --key-id <id>`: the realm first, then the flag,
// once, with a key id of exactly 8 lowercase hex characters.
func parseKeyArgs(cmd string, args []string) (config.RealmName, string, error) {
	pos, flags := splitAtFlag(args)
	var id string
	seen := false
	fs := newFlags("keys " + cmd)
	fs.Func("key-id", "the id of the key", func(v string) error {
		if seen {
			return errors.New("--key-id is given twice")
		}
		seen, id = true, v
		return nil
	})
	if err := parseFlags(fs, flags, 0); err != nil {
		return "", "", err
	}
	switch {
	case len(pos) != 1 || pos[0] == "":
		return "", "", usageErr(fmt.Sprintf("keys %s needs <realm> --key-id <id>", cmd))
	case !seen:
		return "", "", usageErr(fmt.Sprintf("keys %s needs --key-id <id>", cmd))
	case !secure.ValidKeyID(id):
		return "", "", usageErr("--key-id must be exactly 8 lowercase hex characters")
	}
	return config.RealmName(pos[0]), id, nil
}

// keysSealed runs keys sealed, keys reseal and keys clear-sealed.
func (a *app) keysSealed(ctx context.Context, cmd string, args []string) error {
	realm, id, err := parseKeyArgs(cmd, args)
	if err != nil {
		return err
	}
	var box *secure.Box
	if cmd == "reseal" { // the only one that reads a key
		if box, err = a.encryptionBox(); err != nil {
			return err
		}
	}
	ops, st, _, err := a.ops(ctx, noRevocation)
	if err != nil {
		return err
	}
	defer st.Close()
	switch cmd {
	case "sealed":
		refs, err := ops.SealedBy(ctx, realm, id)
		if err != nil {
			return err
		}
		return a.printJSON(sealedViews(refs))
	case "reseal":
		rep, err := ops.Reseal(ctx, realm, id, box)
		if err != nil {
			return err
		}
		if perr := a.printJSON(struct {
			Resealed int          `json:"resealed"`
			Skipped  int          `json:"skipped"`
			Failed   []sealedJSON `json:"failed"`
		}{rep.Resealed, rep.Skipped, sealedViews(rep.Failed)}); perr != nil {
			return perr
		}
		if len(rep.Failed) > 0 {
			return fmt.Errorf("%d stored token(s) did not decrypt with key %s and were left as they are", len(rep.Failed), id)
		}
		return nil
	default:
		rep, err := ops.ClearSealed(ctx, realm, id)
		if err != nil {
			return err
		}
		return a.printJSON(struct {
			Cleared int `json:"cleared"`
			Skipped int `json:"skipped"`
		}{rep.Cleared, rep.Skipped})
	}
}

// encryptionBox loads the configuration for its encryption keys, as user delete
// does, and returns the box of them; nil when none is configured.
func (a *app) encryptionBox() (*secure.Box, error) {
	loader, err := config.NewLoader(a.configDir(), a.clock, nil) // its own log lines are not the command's output
	if err != nil {
		return nil, err
	}
	return openBox(loader.Current().Secrets().EncryptionKeys())
}

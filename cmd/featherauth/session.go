package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"strings"

	"github.com/yyudhistira/featherauth/internal/admin"
	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/oidc"
	"github.com/yyudhistira/featherauth/internal/store"
)

// session runs the session subcommands and maps their errors to exit codes.
func (a *app) session(ctx context.Context, args []string) int {
	err := a.sessionCommand(ctx, args)
	var ue usageErr
	switch {
	case err == nil:
		return 0
	case errors.As(err, &ue):
		return a.usageError(ue.Error())
	}
	return a.fail(err)
}

// sessionCommand dispatches `session list` and `session revoke`.
func (a *app) sessionCommand(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return usageErr("session needs a subcommand: list or revoke")
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "list":
		return a.sessionList(ctx, rest)
	case "revoke":
		return a.sessionRevoke(ctx, rest)
	default:
		return usageErr(fmt.Sprintf("unknown session subcommand %q", cmd))
	}
}

// splitAtFlag splits args before the first flag: the positional arguments come
// first, the flags after them, as for the user commands.
func splitAtFlag(args []string) (positional, flags []string) {
	n := 0
	for n < len(args) && !strings.HasPrefix(args[n], "-") {
		n++
	}
	return args[:n], args[n:]
}

// sessionList prints the active sessions of a user as a JSON list.
func (a *app) sessionList(ctx context.Context, args []string) error {
	pos, flags := splitAtFlag(args)
	if err := parseFlags(newFlags("session list"), flags, 0); err != nil {
		return err
	}
	if len(pos) != 2 {
		return usageErr("session list needs <realm> <user id>")
	}
	ops, st, _, err := a.ops(ctx, noRevocation)
	if err != nil {
		return err
	}
	defer st.Close()
	live, err := ops.ListSessions(ctx, config.RealmName(pos[0]), store.UserID(pos[1]))
	if err != nil {
		return err
	}
	out := make([]oidc.SessionFields, 0, len(live))
	for _, s := range live {
		out = append(out, oidc.SessionFieldsOf(s))
	}
	return a.printJSON(out)
}

// sessionRevoke ends one session of a user, or all of them, or every session of
// the realm with --all. Its audit line goes to standard error; nothing else is
// printed.
func (a *app) sessionRevoke(ctx context.Context, args []string) error {
	var session string
	var all bool
	fs := newFlags("session revoke")
	fs.StringVar(&session, "session", "", "id of the session to revoke")
	fs.BoolVar(&all, "all", false, "revoke every session of the realm")
	pos, flags := splitAtFlag(args)
	if err := parseFlags(fs, flags, 0); err != nil {
		return err
	}
	given := false
	fs.Visit(func(f *flag.Flag) { given = given || f.Name == "session" })
	switch {
	case all && len(pos) != 1:
		return usageErr("session revoke <realm> --all takes no user id and no other argument")
	case all && given:
		return usageErr("session revoke: --all and --session cannot be used together")
	case !all && len(pos) != 2:
		return usageErr("session revoke needs <realm> <user id> [--session <id>], or <realm> --all")
	case given && session == "":
		return usageErr("session revoke: --session needs a session id")
	}
	ops, st, _, err := a.ops(ctx, noRevocation)
	if err != nil {
		return err
	}
	defer st.Close()
	realm := config.RealmName(pos[0])
	if all {
		_, err = ops.RevokeRealmSessions(ctx, admin.Actor, realm)
		return err
	}
	_, err = ops.RevokeSessions(ctx, admin.Actor, realm, store.UserID(pos[1]), store.SessionID(session))
	return err
}

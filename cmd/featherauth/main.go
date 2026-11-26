// Command featherauth is a small self-hosted OpenID Connect provider for
// social login. See docs/DESIGN.md.
package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/user"
)

// version is set at build time with -ldflags "-X main.version=<value>".
var version = "dev"

const usage = `usage: featherauth <command> [arguments]

commands:
  version                                        print the version
  config init <dir>                              write the annotated example configuration into <dir>
  config check <dir>                             validate the configuration in <dir>
  keys generate [--type rsa|ec|encryption] [--bits N] <file>
                                                 write a new key to <file> (mode 0600)
  keys sealed <realm> --key-id <id>              list the identities whose stored provider token that key sealed
  keys reseal <realm> --key-id <id>              seal those tokens again under the first key
  keys clear-sealed <realm> --key-id <id>        set those tokens to none
  user get|list|update|disable|enable|delete|link|unlink <realm> ...
                                                 administer users in the database named in database.yaml
  session list <realm> <user id>                 print the user's active sessions as JSON
  session revoke <realm> <user id> [--session <id>]
                                                 revoke one session, or every session of the user
  session revoke <realm> --all                   revoke every session of the realm
  import <file> --realm <name> [--include-without-identity]
                                                 import users from a JSON file
  db copy --from <file> --to <file>              copy the SQLite database of --from to the Postgres database of --to
  backup                                         write a database snapshot to backup.directory
  serve                                          run the service
  healthcheck                                    call /readyz of the running service

exit codes: 0 success, 1 failure, 2 usage error
`

// defaultHealthTimeout bounds the whole healthcheck request.
const defaultHealthTimeout = 3 * time.Second

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// app is the CLI with the things its commands depend on, so tests can replace
// them.
type app struct {
	stdout, stderr io.Writer
	getenv         func(string) string
	clock          clock.Clock
	healthTimeout  time.Duration
	// revokerFactory builds the provider revokers of a deletion from the
	// loaded configuration; nil means the provider pool. Tests replace it.
	revokerFactory func(config.Source, clock.Clock, *slog.Logger) user.RevokerFor
	// listen opens the service's listener; nil means TCP. Tests replace it.
	listen func(ctx context.Context, network, addr string) (net.Listener, error)
	// wrapStore wraps the store the admin commands open; nil means none. Tests
	// replace it.
	wrapStore func(store.Store) store.Store
	// wrap wraps the service's handler; nil means none. Tests replace it.
	wrap func(http.Handler) http.Handler
}

// run is the CLI entry point: it dispatches a subcommand and returns the
// process exit code. Every subcommand plugs in here.
func run(args []string, stdout, stderr io.Writer) int {
	a := &app{stdout: stdout, stderr: stderr, getenv: os.Getenv, clock: clock.Real(), healthTimeout: defaultHealthTimeout}
	return a.run(context.Background(), args)
}

func (a *app) run(ctx context.Context, args []string) int {
	if len(args) == 0 {
		fmt.Fprint(a.stderr, usage)
		return 2
	}
	rest := args[1:]
	switch args[0] {
	case "version":
		if len(rest) != 0 {
			return a.usageError("version takes no arguments")
		}
		fmt.Fprintln(a.stdout, version)
		return 0
	case "config":
		return a.config(ctx, rest)
	case "keys":
		return a.keys(ctx, rest)
	case "user":
		return a.user(ctx, rest)
	case "session":
		return a.session(ctx, rest)
	case "import":
		return a.importCmd(ctx, rest)
	case "db":
		return a.db(ctx, rest)
	case "backup":
		return a.backup(ctx, rest)
	case "serve":
		return a.serveCmd(ctx, rest)
	case "healthcheck":
		if len(rest) != 0 {
			return a.usageError("healthcheck takes no arguments")
		}
		return a.healthcheck(ctx)
	default:
		fmt.Fprintf(a.stderr, "featherauth: unknown command %q\n\n%s", args[0], usage)
		return 2
	}
}

// usageError reports a mistake in the command line and returns the usage exit code.
func (a *app) usageError(msg string) int {
	fmt.Fprintf(a.stderr, "featherauth: %s\n\n%s", msg, usage)
	return 2
}

// fail reports a failure of a command and returns the failure exit code.
func (a *app) fail(err error) int {
	fmt.Fprintf(a.stderr, "featherauth: %v\n", err)
	return 1
}

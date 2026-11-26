# CLAUDE.md: implementing FeatherAuth

FeatherAuth is a small self-hosted OpenID Connect provider in Go that signs users in through social providers. This file tells you how to build it. Read it fully before every work session.

## Sources of truth

| File | What it decides |
| --- | --- |
| `docs/REQUIREMENTS.md` | What FeatherAuth must do and how safe, fast and operable it must be: product (FR), operations (OPS), security (SEC) and performance (NFR) requirements, each with a stable id |
| `docs/DESIGN.md` | Every behaviour, option, default, endpoint, table and test that meets those requirements. It is the specification for the code |
| `docs/USER_GUIDE.md`, `README.md` | What adopters are told: how to set up, run, upgrade and scale it |
| `docs/RELEASING.md`, `docs/RESULTS.md` | How a release is cut and checked, and the latest recorded results |
| This file | How to work: rules, layout, testing, commands |

The work to do is given by the user or the software architect as a change: a short description of what to build, the requirement ids it serves and its done condition. A change has no file of its own; it lives in the conversation and in the pull request description.

## Roles and way of working

Work is split between four agents, defined in `.claude/agents/`. Each owns files and may not edit the others'. Feedback goes upstream as a written report, never as a silent edit.

| Agent | Owns | Cannot |
| --- | --- | --- |
| `product-security-architect` | `docs/REQUIREMENTS.md`, `README.md`, `docs/USER_GUIDE.md`, `docs/audits/`; reviews the design and `docs/RELEASING.md`; audits code and process | Change code or design. Settles requirement conflicts only through the human, who gets plain options with costs |
| `software-architect` | `docs/DESIGN.md`, `docs/RELEASING.md`; reviews implementers' code and the requirements | Change requirements or code. Sends requirement problems to the product and security architect |
| `go_implementer` | Code, tests and `deploy/` of one change; the data files tests read (`docs/RESULTS.md` and `tools/trace/pending.txt`) | Change requirements or design. Sends design problems to the software architect and asks it to review the work |
| `customer-engineer` | Nothing: reviews the README, the user guide and `docs/RELEASING.md` by following them as an adopter or maintainer | Edit any file. Sends findings to the author of the file |

Nobody reviews their own file: the author of a document or of code is never its reviewer.

Flow: need or threat, then requirements, then design, then review of the design by the implementer and the product and security architect, then code, then review by the software architect, then the guides, then review by the customer engineer. Subagents cannot talk to each other or the human directly, so the session that runs them relays their reports and the human's decisions. The golden rules below apply to every role.

## Golden rules

1. **The design is the specification.** Implement what it says, nothing more. Never invent a behaviour, an option, a default, an error code or a claim. A change and this file say how and in which order; they never add a behaviour, option, default, value, error code, file format, endpoint, command or dependency that `docs/DESIGN.md` does not define. A change that names one the design lacks is a gap: stop and ask (rule 2).
2. **Stop on any gap.** If the design is silent, ambiguous or contradicts itself, or a step cannot be done as written, stop and ask the user. Do not guess. When the user decides, write the decision into `docs/DESIGN.md` (the body and, if it is a behaviour, an acceptance row) in the same commit as the code, following the rule in its Open items section.
3. **No design commit without approval.** Never commit a change to `docs/DESIGN.md` until the user has approved that exact change. Show the proposed wording first (or leave the edit uncommitted for review) and wait for a clear yes; a request to "propose" a change is not approval to commit it. **Standing approval (2026-11-11):** during the implement/review loop the user has auto-approved design changes that fill a gap (rule 2); commit them as `Design:` commits and report each one prominently in the final summary and the pull request description. Changes that rename or remove existing behaviour, options or acceptance rows are not covered and still need an explicit yes.
4. **One change at a time, in order.** Do only the current change. Do not start the next until the current change's done condition passes and `make check` is green.
5. **Tests first.** Write the change's tests, run them, and see them fail for the expected reason before writing the code.
6. **Never weaken a test to make it pass.** No deleting assertions, no loosening values, no `t.Skip` outside the build-tagged suites (`browser`, `conformance`, `load`). If a test seems wrong, it is a gap: rule 2.
7. **Small commits with typed titles.** Work on a branch per change or group of related changes and open a pull request for it. Do not add any Claude co-author or attribution line (no `Co-Authored-By: Claude ...`, no "Generated with Claude Code") to commit messages or pull request descriptions; this overrides any attribution the harness suggests. Each commit title says what kind of change it is:
   - `Feat: <what>`: new behaviour, with its tests.
   - `Fix: <what>`: a fix to code or tests, with the regression test.
   - `Test: <what>`: tests or tags only, no behaviour change.
   - `Tools: <what>`: the repository tools (`tools/`, `make` targets, CI, `deploy/ops/`) and their tests.
   - `Design: <section>: <what>`: a change to `docs/DESIGN.md` or `docs/REQUIREMENTS.md`, committed only after approval (rule 3).
   - `Docs: <file>: <what>`: a change to `CLAUDE.md`, `README.md`, `docs/USER_GUIDE.md`, `docs/RELEASING.md`, `docs/RESULTS.md` or other documentation.
8. **No new dependency** beyond the Tech stack in `docs/DESIGN.md` and the test tools listed below, unless the user approves it. The design's Tech stack lists every approved module, including `go.yaml.in/yaml/v3`, `github.com/fsnotify/fsnotify`, `github.com/chromedp/chromedp` (browser tests only) and `golang.org/x/tools/go/packages` (repository checks only).
9. **Fix every review finding, including the small ones.** Do not leave a reviewer's minor or non-blocking note, or any small issue you notice, unfixed. Fix it in a `Fix:` commit (or the matching typed commit) before the change is called done. The only exception is a fix that needs a large rework (a redesign, a new interface, changes across many packages, or a change of behaviour the design does not cover): then do not do it silently and do not drop it; stop, describe the issue and the size of the rework, and ask the user whether to go ahead. Fix before the pull request is opened. A fix that is better made by a later change is recorded in the pull request description and as an item in the "Open items" section of `docs/DESIGN.md`. Never leave a finding only in a review message or a code comment.

## Commands

All of these are `make` targets. `make check` must pass before every commit.

| Target | Does |
| --- | --- |
| `make fmt` | `gofmt -s -w` and `goimports` |
| `make vet` | `go vet ./...` and `staticcheck ./...` |
| `make test` | `go test -race -count=1 ./...` (unit, contract and integration tests) |
| `make cover` | Tests with coverage, then `tools/cover` checks per-package thresholds |
| `make trace` | `tools/trace` checks that tests cover every FR, SEC and acceptance row (see Traceability) |
| `make arch` | `tools/archcheck` checks the import graph and forbidden calls |
| `make vuln` | `govulncheck ./...` |
| `make check` | All of the above except `fmt`, which must already be clean |
| `make browser` | Browser tests (build tag `browser`, needs Chrome) |
| `make ops` | Ops tests (build tag `ops`, needs docker): they run the scripts in `deploy/ops/` (image, proxy examples, off-server backup). CI runs it; `make check` does not |
| `make postgres` | Postgres tests (build tag `postgres`, needs docker): starts a Postgres container of the version in `POSTGRES_VERSION` (default: the newest stable major), runs `go test -tags postgres` against it through `FEATHERAUTH_TEST_POSTGRES` and removes it. CI runs it on Postgres 15 and on the newest stable major; `make check` does not |
| `make fuzz` | Each fuzz target for 30 seconds |
| `make example` | `npm ci --ignore-scripts` and the build of `examples/web-app` (needs Node, version in `examples/web-app/.node-version`); `make browser` depends on it |
| `make conformance`, `make load` | The OpenID conformance suite and the load test; run at a release when their area changed |
| `make release-check` | The automated release checks of `docs/RELEASING.md` (`TAG=vX.Y.Z` for the after-tag items); prints `ready to tag` or `not ready` |

## Releases

Rehearse a release before the real tag, and cut it, as `docs/RELEASING.md` describes ("Rehearsing a release" for the rehearsal). Record a rehearsal as a rehearsal, never as the result of the real release image.

## Layout

The layout follows "Tech stack and code structure" in `docs/DESIGN.md`, plus a few small packages so that every concern has one home.

```text
cmd/featherauth/            main, wiring, signals, subcommands
internal/clock/             Clock interface, real and fake clocks
internal/secure/            random tokens and ids, constant-time compare, SHA-256 hashing, AES-GCM box with key ids
internal/logx/              slog JSON handler with redaction, audit log lines
internal/config/            types, strict YAML, defaults, validation, snapshot, URL builder, loader, hot reload
internal/token/             key sets, JWKS, claim encoding, signing, verification, code and refresh services, client auth
internal/store/             repository interfaces, migrations, sqlite implementation
internal/store/storetest/   contract suite every store implementation must pass
internal/store/audit/       audit.Writer: audit rows in the table and audit log lines (store component, rank 3)
internal/user/              identity matching, linking, email rules, delete, disable, import
internal/provider/          Provider interface, registry, adapters: oidc, google, apple, github, facebook
internal/provider/providertest/  contract suite every adapter must pass
internal/web/               templates, assets, locales, security headers, page rendering, response modes
internal/server/            routing from path templates, middleware (client IP, rate limit, CORS, recover, request log)
internal/oidc/              handlers: discovery, JWKS, authorize, callback, token, userinfo, logout, account, events, data deletion
internal/admin/             user administration, import and backup operations the CLI calls (no HTTP API)
internal/testutil/          fake clock helpers, config builders, key fixtures, mock identity provider, test API, test server
tools/trace/, tools/archcheck/, tools/cover/   repository checks run by make
deploy/                     Dockerfile, compose files, proxy examples, config.example/, ops scripts
```

`deploy` also holds `embed.go`, a pure embed package (`config.example/` for `config init`) outside the rank table; `make arch` does not scan it, and only `cmd` imports it.

**Import direction** (enforced by `make arch`). Each component has a rank; a package may import its own component or a component of lower rank, never one of the same or a higher rank:

| Rank | Components |
| --- | --- |
| 8 | `cmd` |
| 7 | `oidc`, `admin` |
| 6 | `server` |
| 5 | `user`, `web` |
| 4 | `token`, `provider` |
| 3 | `store` |
| 2 | `config` |
| 1 | `secure`, `logx` |
| 0 | `clock` |

`internal/testutil/...` and `<component>test` packages (such as `storetest`) are test support: only tests and other test-support packages may import them. A new component needs a rank in `tools/archcheck` first.

## Boundaries and interfaces

The user asked for checks on every interface between parts, so every boundary follows these rules:

- **Small interfaces, defined by the consumer.** A package accepts interfaces and returns concrete types. Each interface lists only the methods its consumer calls.
- **Compile-time assertions.** Every implementation of an interface has `var _ Iface = (*Impl)(nil)` next to it.
- **Contract suites.** Every interface with more than one implementation (including test fakes) has a contract suite in a `<pkg>test` package: `storetest.Run`, `providertest.Run`, `clock` contract, `config.Source` contract. Every implementation and every fake runs the suite, so a fake cannot drift from the real thing.
- **No hand-written store fakes.** Tests that need storage use the real SQLite store on a temporary file (`testutil.NewStore(t)`); it is fast enough and cannot drift.
- **Wiring tests.** At the end of each change that connects parts, an integration test wires the real parts together (no fakes) and drives them through their public entry point.
- **Typed values.** Use distinct types for `RealmName`, `ClientID`, `UserID`, `SessionID`, `ProviderKey`, `IdentityID` and for hashes, so arguments cannot be swapped silently. Durations are `time.Duration`; instants are `time.Time` in UTC from the clock.
- **Errors.** Each package defines typed or sentinel errors (`errors.Is`/`errors.As`). The OAuth error type (`oidc.Error{Code, Description, Status}`) is mapped to HTTP in one place. Tests assert the error, not its text, except for config validation messages, whose file, line and reason are part of the specification.
- **Context.** Every function that does I/O takes `context.Context` first.

## Time, randomness and I/O

- Never call `time.Now`, `time.Since`, `time.Until` or the real timers (`time.Sleep`, `After`, `Tick`, `NewTimer`, `NewTicker`, `AfterFunc`) outside `internal/clock`; never import `crypto/rand` outside `internal/secure`; never use `math/rand`. Take a `clock.Clock` or a `secure.Source` instead. When a step needs a timer, add it to the `Clock` interface first, with a fake that fires on `Advance`. `make arch` fails otherwise.
- Tests never sleep. Advance the fake clock.
- Tests make no network calls except to `httptest` servers on loopback (the mock identity provider, the test API) and, under the `postgres` tag, to the Postgres container that `make postgres` starts on loopback (`FEATHERAUTH_TEST_POSTGRES`).
- Every outgoing HTTP call uses a client with the provider's `timeout` and a context: build requests with `http.NewRequestWithContext`; every `http.Client` literal sets a non-zero `Timeout`; never `http.DefaultClient`, `http.Get`, `http.Post`, the client methods `Get`, `Head`, `Post` and `PostForm` (they build requests without a context), `new(http.Client)`, a zero-value `var c http.Client`, or a struct field of type `http.Client` (hold a `*http.Client` instead); `make arch` rejects them all.
- `go-oidc` and `golang.org/x/oauth2` silently fall back to `http.DefaultClient` unless they get a client through the context. Always pass the provider's client (`oidc.ClientContext(ctx, c)`, `context.WithValue(ctx, oauth2.HTTPClient, c)`). The provider contract suite replaces `http.DefaultTransport` with one that fails the test, so a missed client shows up.

## Security rules for code

- Compare secrets, hashes and tokens with `secure.Equal` (constant time).
- Store and look up codes, refresh tokens and handoff ids only as SHA-256 hashes (`secure.Hash`).
- Never log the secrets SEC-13 lists or emails. Log only through `logx` (`make arch` rejects `slog.Info`, `slog.Default`, `slog.New`, `slog.NewJSONHandler` and the other package-level `slog` functions outside it), which redacts by key, strips URL queries and fragments, and cleans HTTP client errors. It recognises a secret only by its key, so pass a secret only as the value of a sensitive key (`"code", c`), never inside a message, a `fmt.Errorf` text or a struct field; the `logx` tests and the secret scan of the logs in the ops checks enforce it.
- Name log keys so useful values stay visible. Keys ending in `_code`, `_key`, `_hint`, `_token`, `_secret` and the other SEC-13 suffixes are always hidden, so log an HTTP status as `status` (not `status_code`), an OAuth error code such as `invalid_grant` as `error` (not `error_code`), and a provider as `provider` (not `provider_key`).
- HTML only through `html/template`. SQL only with parameters, never by concatenation.
- Limit request bodies (64 KB for forms and JSON). Every `http.Server` literal sets non-zero `ReadTimeout` or `ReadHeaderTimeout`, `WriteTimeout` and `IdleTimeout`; never `http.ListenAndServe` or `http.Serve`, a zero-value `var srv http.Server`, or a struct field of type `http.Server` (`make arch` rejects them).
- A panic in a handler is recovered, logged and answered `500`; it never kills the process.
- Use the libraries in the Tech stack for OAuth, OIDC and JWT; no hand-written cryptography (SEC-15).
- Validate every input where it enters (HTTP, config, provider responses, import files), then pass typed values inward.

## Testing

### Levels

| Level | Where | What |
| --- | --- | --- |
| Unit | next to the code | Pure functions, table-driven, one row per case in the design |
| Contract | `<pkg>test` packages | Behaviour every implementation of an interface must have |
| Handler | `internal/oidc` | `httptest` against handlers with real services on a temporary store |
| Integration | `internal/testutil/server` users | Whole service in process: temp config dir, temp SQLite, mock identity provider, fake clock |
| Browser | build tag `browser` | chromedp against the in-process server |
| Postgres | build tag `postgres` | Store, service and CLI suites on a real Postgres started with docker (`make postgres`); a missing docker or `FEATHERAUTH_TEST_POSTGRES` fails the test, it is not skipped |
| Ops | build tag `ops` | Go tests that run the `deploy/ops/check-*.sh` scripts against docker and fail on a non-zero exit; docker is required (a missing docker fails the test, it is not skipped); the one exception is `TestOpsUpgradeSQLite` and `TestOpsUpgradePostgres`, which skip with "no previous release to upgrade from" when there is neither `PREV_IMAGE` nor a release tag in a full checkout: see "Upgrades with no previous release" in `docs/DESIGN.md`) |
| Conformance, load | build tags | Run at a release when their area changed; results recorded in `docs/RESULTS.md` |

### Traceability

Every test that proves a requirement starts with comment lines naming what it proves:

```go
// Covers: FR-07, SEC-01
// Acceptance: PKCE downgrade
func TestExchangeRejectsVerifierWithoutChallenge(t *testing.T) {
```

- `Covers:` lists FR and SEC ids from `docs/REQUIREMENTS.md`. `Acceptance:` is the exact "Area" text of an acceptance row in `docs/DESIGN.md`. OPS and NFR ids are checked at each release by `docs/RELEASING.md`, not by `make trace`; a test that proves one names it in a plain comment (`// Proves OPS-03 (pinned references): ...`), never in a `Covers:` line.
- `make trace` reads the FR and SEC ids from `docs/REQUIREMENTS.md`, the acceptance table from `docs/DESIGN.md`, and all `_test.go` files. It fails on an unknown id or area, and on any requirement or row with no test, except those listed in `tools/trace/pending.txt`. A row of "Rows not yet traced" in the design has no test yet; it moves into the acceptance table in the same change that builds its test.
- A row is covered only when all of its pass conditions are asserted. A test that proves only part of a requirement or row adds `(part)` to the tag (`// Acceptance: PKCE (part)`); the entry stays in `pending.txt` while it has only partial tests, and the tool fails if it is missing there.
- `pending.txt` only shrinks. The test that completes an entry tags it without `(part)`, and the same commit removes the entry from `pending.txt`; the tool fails if a pending entry has a full tag. It also compares with `origin/main` (`TRACE_BASE`), with `HEAD`, and every commit on the branch with its parent: an entry that existed in the design at the earlier revision but was not pending there cannot be added back. Only requirements or rows new to the design may be added.
- Renaming an acceptance row makes it look new to the tool, so it could be made pending again. A design change that renames a row needs approval anyway (golden rule 3); the approval request says whether the old row was covered, and a covered row stays out of `pending.txt` under its new name. The release step requires the file to be empty.
- A full tag closes an entry, so add `(part)` whenever a test proves less than every pass condition; when the tool says an entry "has a full test", check the test before removing the entry.
- Tests behind build tags (`browser`, `conformance`, `load`, `ops`, `postgres`) count for traceability like any other test, but `make check` does not run them; their suites run before each release (`make release-check`, `docs/RELEASING.md`) and must pass there, and `make ops` and `make postgres` run in CI.

### Coverage

- `tools/cover` thresholds (statements): 95% for `internal/token`, `internal/oidc`, `internal/config`, `internal/user`, `internal/secure`; 90% for every other `internal` package. `cmd` is covered through CLI and integration tests.
- Coverage is a floor, not the goal. Every branch that returns an error in a security path (validation, verification, PKCE, client auth, logout, deletion, events) has a test that reaches it.
- Parsers get fuzz tests with a seed corpus: config decoding, redirect URI validation, authorization request parsing, claim encoding, the Apple event payload.

### Conventions

- Table-driven tests with a `name` per row; the rows mirror the design's tables (for example one row per line of "Errors in the authorization request").
- Golden files under `testdata/` for discovery JSON and HTML pages; update with `go test ./... -update`, and review the diff.
- Shared helpers live in `internal/testutil`; do not copy helpers between packages.
- Each bug gets a failing regression test before the fix.
- Run `make test` with `-race` always; integration tests run parallel where they do not share state.

## Definition of done for a change

- [ ] The change's tests were written first and failed for the expected reason.
- [ ] `make check` passes (format, vet, staticcheck, race tests, coverage, trace, arch, vuln).
- [ ] New interfaces have compile-time assertions and, where they have more than one implementation, a contract suite run by each.
- [ ] Every test that proves a requirement carries `Covers:`/`Acceptance:` lines; `pending.txt` updated.
- [ ] Every new type that holds a secret SEC-13 lists or an email, directly or through a field (a struct wrapping a type that has its own `LogValue` counts too, because plain struct fields are logged as they are), implements `slog.LogValuer`, logging only safe fields, with a test that logs it through `logx` both directly and nested in a map (as in audit details) and finds none of those values.
- [ ] New config fields are in `deploy/config.example/` with a comment (a test enforces it).
- [ ] No behaviour beyond the change; no stray TODO without an item in the "Open items" section of `docs/DESIGN.md`.
- [ ] The documents the change touches agree with the code: `docs/DESIGN.md` (and `docs/REQUIREMENTS.md` through its author), `docs/USER_GUIDE.md` and `README.md` through theirs.
- [ ] The change is committed with a typed title (rule 7).

## Things not to do

- No web framework, no ORM, no CGO, no global mutable state (configuration is an immutable snapshot passed around), no dot imports.
- Do not rename config options, endpoints, claims or error codes; they are part of the specification.
- Do not change `docs/DESIGN.md` decisions on your own; only record decisions the user made, and commit design changes only after the user approves them (golden rule 3).
- Do not read or print real secrets, tokens or keys in tests or logs; generate fixtures in `internal/testutil`.

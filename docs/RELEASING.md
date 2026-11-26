# Releasing FeatherAuth

For maintainers. A release is a git tag `vX.Y.Z` (`vMAJOR.MINOR.PATCH`, digits only) pushed to GitHub; the push makes the `deploy` workflow publish the container image `ghcr.io/yyudhistira/featherauth:vX.Y.Z`. The rules the workflow follows are in [DESIGN.md](DESIGN.md) (Deployment and operations). The requirements a release must meet are in [REQUIREMENTS.md](REQUIREMENTS.md); the OPS and NFR requirements are checked by the release check below.

In the commands, `vX.Y.Z` is the version you release and `vPREV` the release before it.

## Versions and release notes

Releases follow semantic versioning (OPS-20). A breaking change is an option, default, endpoint, claim or error code renamed or removed, a stricter validation, or a database migration that cannot be undone by running the previous image and restoring a backup. While the major version is `0`, a breaking change needs a new minor version; from `1.0.0` on, a new major version. A bug fix raises the last number. The workflow does not compare versions.

Release notes live only in GitHub Releases, one release per tag. They name every behaviour change, each with what the operator or the app developer must check, every breaking change, and every new option with its default.

## Two kinds of images

| Trigger | Image tag | Deploys? |
| --- | --- | --- |
| A push to `main` (a merged pull request) | The full 40-character commit hash | Only through the example pipeline, when `DEPLOY_PATH` is set |
| A pushed tag `vX.Y.Z` | The tag name only: no commit-hash tag, never `latest` | Never |

`featherauth version` prints the commit hash for a `main` image and the tag name for a release image. A tag run uses the workflow file of the tagged commit, so push the tag only after everything it releases is merged.

## Cutting a release

1. Merge what belongs in the release into `main` and wait for the `deploy` run of the merge to go green.
2. Run `make release-check` on that commit (below) and the manual checks it reports as required. Put their results into `docs/RESULTS.md` (release gate section, with the values defined at the end of this file; no row may be `fail`) and commit them; that commit runs all checks (tests read the file), so wait for its `deploy` run to go green. This commit is the release commit.
3. Draft the release notes as a GitHub Release for the tag `vX.Y.Z`, not yet published (Releases, Draft a new release).
4. Rehearse the tag path (below) when the workflow or these steps changed since the last rehearsal.
5. Tag the release commit and push the tag:
   ```bash
   git checkout main && git pull
   git tag vX.Y.Z
   git push origin vX.Y.Z
   ```
6. Wait for the tag's `deploy` run (it runs the checks unless the commit already passed them on `main`, then builds, signs and pushes; it never deploys). Then run `make release-check TAG=vX.Y.Z`, which checks the published image.
7. Publish the release notes. The post-tag run starts `release-out/results.md` afresh, so the lines of the pre-tag run are already in `docs/RESULTS.md` from step 2; copy the post-tag run's rows 11 to 13 and its table of release tags into the release gate section, and commit them as a follow-up commit (the tag stays on the release commit).

Operators move to the release with `FEATHERAUTH_TAG=vX.Y.Z`.

## Rehearsing a release

A release tag is never moved, overwritten or deleted (OPS-02), so a fault found on the release image costs a new version. Rehearse the tag path with a rehearsal tag first.

A **rehearsal tag** is a digits-only tag lower than every real release (for example `v0.0.1`) that is never announced, never named in release notes and never given to operators. Only such a tag counts as a rehearsal, and only it may be deleted with its package version; every other release-form tag is a release and falls under OPS-02.

```bash
git tag v0.0.1 <commit-of-main>
git push origin refs/tags/v0.0.1
# when its deploy run is green: make release-check TAG=v0.0.1
git push origin :refs/tags/v0.0.1 && git tag -d v0.0.1
```

Deleting the tag does not delete the image: delete the package version of `v0.0.1` on the repository's Packages page, or with `gh api -X DELETE /user/packages/container/featherauth/versions/<id>` (needs the `delete:packages` scope). A rehearsal is never recorded as the result of a real release.

## Verifying an image

Every pushed image is signed by digest with the workflow's own identity (keyless, through GitHub's OIDC token) and carries an SPDX software bill of materials (SEC-42). The build provenance exists only for a public repository; for a private one `gh attestation verify` has nothing to check.

Verify the digest, with the exact identity of the build that made it:

```bash
IMG=ghcr.io/yyudhistira/featherauth
DIGEST=$(docker buildx imagetools inspect "$IMG:vX.Y.Z" --format '{{json .Manifest}}' | jq -r .digest)
ISS=https://token.actions.githubusercontent.com
ID=https://github.com/yyudhistira/featherauth/.github/workflows/deploy.yml@refs/tags/vX.Y.Z   # a main image: @refs/heads/main
cosign verify --certificate-oidc-issuer "$ISS" --certificate-identity "$ID" "$IMG@$DIGEST"
cosign verify-attestation --type spdxjson --certificate-oidc-issuer "$ISS" --certificate-identity "$ID" "$IMG@$DIGEST"
gh attestation verify "oci://$IMG@$DIGEST" --repo yyudhistira/featherauth --signer-workflow yyudhistira/featherauth/.github/workflows/deploy.yml   # public repository only
```

A shared pattern (`--certificate-identity-regexp '...deploy\.yml@refs/(heads/main|tags/v[0-9]+\.[0-9]+\.[0-9]+)$'`) also accepts any build of `main`, so it does not prove that an image is a release. Use the exact tag identity and the digest.

## Finding the latest version

```bash
git ls-remote --tags --refs https://github.com/yyudhistira/featherauth.git 'v*' | sed 's#.*refs/tags/##' | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | sort -V | tail -1
```

## What the workflow checks, and what it refuses

- Only `v` + digits `.` digits `.` digits starts a release run; `v1.0`, `vX.Y.Z-rc1` or `X.Y.Z` start nothing.
- The tagged commit must be reachable from `main`, or the run fails before it builds or pushes anything.
- The checks are those of a pull request, skipped only when the tagged commit already passed them on `main`; a missing or failed GitHub answer runs them.

## Documentation-only changes

A change that touches only `README.md`, `CLAUDE.md`, `docs/RELEASING.md`, `deploy/ASSETS.md` or files under `.claude/`, or only comment and blank lines of Go files under the rules of DESIGN.md (Documentation-only changes), is documentation-only. `docs/DESIGN.md`, `docs/REQUIREMENTS.md` and `docs/RESULTS.md` are read by tests, so a change to them is never documentation-only, and neither is a change of `tools/trace/pending.txt`. On a pull request the test jobs are skipped and the private-key scan still runs; on a push to `main` the `checks` and `deploy` jobs are skipped and the image is still built, but only when the parent commit has a successful `deploy` run. The list lives in `deploy/ops/changed-files.sh` and DESIGN.md.

## What the skip trusts

- **Trust model.** The status `ci/tested-tree` proves that a workflow of this repository posted it. A pull request from the repository can change `ci.yml` or `changed-files.sh` and so decide its own skip; the decision for `main` is made again from the pushed commit. The skip is as trustworthy as the right to merge.
- **Staleness.** A tree that passed CI earlier is not tested again when merged later, so `govulncheck` does not see newer advisories; `make release-check` runs it on the release commit.

## Rules and cautions

- **Never move, overwrite or delete a release tag (OPS-02).** The workflow does not enforce it; `make release-check TAG=...` confirms at every release that the earlier tags and their digests are unchanged. A fix is a new tag.
- **Tag the release commit, which is the tip of `main`.** An older commit without a successful `main` run makes the tag run the checks, and `tools/trace` can fail on an older `pending.txt`.
- **Cancelled runs.** GitHub keeps one pending run per concurrency group, so a tag run queued behind a push to `main` can be cancelled silently. `make release-check TAG=...` fails when the image is missing; re-run the tag's workflow run then.
- **Stray tags.** A tag that cannot start the workflow (not `vMAJOR.MINOR.PATCH`) may be removed, and so may a rehearsal tag. A release-form tag above the rehearsal range is never deleted, even a mistyped one.

## Rolling back

Operators roll back by setting `FEATHERAUTH_TAG` to the previous release and, when the data must go back, by restoring the backup taken before the upgrade (USER_GUIDE.md, section 9.3).

## The release check

### One command

`make release-check` (the script `deploy/ops/release-check.sh`) runs every check that a program can do, in this order, prints one `pass`, `fail` or `skipped: no change since <commit>` line per item, and writes the result lines for the release gate section of `docs/RESULTS.md` to `release-out/results.md`. It stops at the first failure. Before the tag it runs items 1 to 10; with `TAG=vX.Y.Z` it runs items 11 to 13. It needs, on the machine that runs it: `git` with the repository's tags fetched (`git fetch --tags`), docker with compose and `buildx`, `gh` logged in to the repository, `cosign`, `jq`, Go (the version of `go.mod`, for `make vuln` and the ops tests), Node and `npm` (the version of `examples/web-app/.node-version`, for `npm audit`), and network access. Each run starts `release-out/results.md` afresh. What each item does exactly is in DESIGN.md (Test suites outside `make check`, Release check).

| # | Item | Requirements | When | Time |
| --- | --- | --- | --- | --- |
| 1 | CI of the release commit green (check, browser, ops, Postgres 15 and newest) | every FR and SEC with a test; OPS-03, OPS-07, OPS-09 to OPS-14, OPS-16 to OPS-18; NFR-12 | every release | 1 minute (reads CI) |
| 2 | `tools/trace/pending.txt` empty | every FR and SEC | every release | seconds |
| 3 | Module list against the Tech stack and `govulncheck`; for the example web app, `npm audit --omit=dev --audit-level=high` and exact versions in its `package.json` | NFR-14, SEC-15 | every release | 3 minutes |
| 4 | `config check` of the shipped examples and of `RELEASE_CONFIG_DIR`, in the signed commit image | OPS-20 (no unnoticed stricter validation) | every release | 2 minutes |
| 5 | Upgrade and rollback by image, SQLite and Postgres; the candidate's container start to `listening` timed on the 1,000-user seed (under 1 second) | OPS-04, OPS-05, OPS-06 | every release | 15 minutes |
| 6 | Postgres backup, encrypted copy and restore | OPS-07, OPS-08 | every release | 10 minutes |
| 7 | Conformance suite | FR-01, FR-02, FR-06 to FR-11 | when its paths changed | 10 minutes |
| 8 | Load verification, SQLite then Postgres | NFR-01 to NFR-11, NFR-13 | when its paths changed | 3 hours 30 minutes (1 h 45 min each) |
| 9 | Manual checks required: lists which of M3 to M6 the paths make necessary | | every release | seconds |
| 10 | Result lines for `docs/RESULTS.md` written | NFR-13 | every release | seconds |
| 11 | Tag run: image exists, prints `vX.Y.Z`, no `latest`, no new commit-hash tag | OPS-01, OPS-02 | after the tag | 2 minutes |
| 12 | Signature and SBOM (and provenance for a public repository) of the release and commit images, by digest with the exact identity | SEC-42 | after the tag | 3 minutes |
| 13 | Earlier release tags and digests unchanged against the release gate's table (the first release only records the table) | OPS-02 | after the tag | 1 minute |

"When its paths changed" uses the shared path list `deploy/release-paths.txt`; this file does not repeat it. A skipped item is recorded as `no change since <commit>`, and a test run by `make check` recomputes every such claim of the release gate and fails when the paths did change. The commit a check is compared with is that of its latest result: the `- Commit:` of the Load or Conformance section for items 7 and 8, of the Browser section for M3 and M4, and of the previous release gate for M5 and M6, but only when that gate's M5 or M6 row was `pass` or `no change since`; otherwise the manual check is required.

The first run of a release ends `not ready`: the rows M1 to M6 of the release gate count only when the section's `- Release:` names the version being prepared (not yet tagged), so the maintainer writes the section with the result lines of `release-out/results.md` and the manual rows, commits it, and runs `make release-check` again, which ends `ready to tag`. The post-tag run (`TAG=vX.Y.Z`) ends `post-tag checks passed`. With no previous release (the first release), item 5 is `not applicable: there is no previous release`, and the two upgrade ops tests of CI skip with `no previous release to upgrade from`; item 6 (the Postgres restore) still runs, with the candidate image only; for a private repository item 12 is `pass` with the detail `gh attestation verify: not applicable (private repository)`; at the first release item 13 is `not applicable` and writes the table of release tags. Set `RELEASE_CONFIG_DIR` to a real configuration directory the maintainers can read (a staging or production copy, no secrets printed); without it, item 4 checks the shipped examples only and the record says so.

### Manual checks

Only what needs a person, real accounts or a real device. M1 and M2 run at every release; M3 to M6 when item 9 says their paths changed. Record each in the release gate section of `docs/RESULTS.md`, without any code, token, `state`, provider payload, email or name.

**M1. Guides and release notes** (every release, 30 to 60 minutes). Read `docs/USER_GUIDE.md` and the draft release notes. Pass: the guide states which stored data is kept in clear (the database, the local snapshots, the Postgres volume) so that disks can be encrypted (OPS-19); it states the accepted risks of REQUIREMENTS.md and tells apps to confirm an account deletion with the user (SEC-21); its section 8 covers an exposed signing key, encryption key and client secret (OPS-11); the notes name every behaviour and breaking change of `git log vPREV..HEAD` with what to check, and the version follows Versions and release notes (OPS-20).

**M2. One real sign-in per enabled provider** (every release, 30 minutes). On the test deployment, for each of Google, Apple, GitHub, Facebook and one generic OIDC provider, run the commands of USER_GUIDE.md section 5 in a desktop browser. Pass: the token answer has `access_token`, `id_token` and `refresh_token`, userinfo answers, the refresh returns new tokens. For Apple, sign in a second time and check the name is kept without printing more than it:
```bash
sudo docker compose exec featherauth /featherauth user get <realm> <sub> | jq -r '.name | length'   # non-zero
```

**M3. Browser matrix** (when `browser` paths changed, 45 minutes). Start the local service with mock providers: `MANUAL_CERTS=$HOME/.featherauth-manual go test -tags manual -count=1 -timeout 0 -run TestManualServer -v ./internal/testutil/server/`. In Firefox, Safari on macOS and Safari in the iOS Simulator: a `form_post` login reaches `post.example.com` with `code`, `iss` and `state` without a click and the console shows no policy violation; with JavaScript off its button posts the form; "Apple direct" ends on `app.example.com/callback?code=…&state=st-1`; two tabs finished in reverse order both complete. In Chrome, Firefox and Safari at desktop width and at 360 by 640: the Google, Apple and Facebook buttons match each vendor's rules (links in `deploy/ASSETS.md`), all buttons have one size and fit without scrolling, logos are sharp. At the end remove the test authority's trust (One-time setup).

**M4. Apple on a real domain** (when `apple` paths changed, 1 to 1.5 hours). On the test deployment: compare Apple's pages "Request an authorization to the Sign in with Apple server" and "Processing changes for Sign in with Apple accounts" with DESIGN.md; cancel a first authorization at Apple's confirmation screen and read only the `error` field of the `POST` to `callback/apple` in the browser's network tab; sign in with Apple in Firefox and in Safari; remove the app at appleid.apple.com while watching `docker compose logs -f featherauth`. Pass: no difference from the design, or each reported; Apple posts `user_cancelled_authorize` and the client gets `error=access_denied` with `state=s1`; both logins complete; the notification is answered `200`, writes `identity.consent_revoked`, and a refresh of the earlier session then gets `invalid_grant`.

**M5. TLS examples on a test host** (when `tls` paths changed, 1 hour). With a public DNS name and ports 80 and 443 free, bring up `Caddyfile.example` with `compose.caddy.yaml`, and separately `nginx.example.conf` with Certbot (`sudo certbot certonly --webroot -w /var/www -d <host> --deploy-hook "nginx -s reload"`). Pass, for each: plain HTTP redirects to HTTPS; `curl -sS https://<host>/healthz` prints `ok` without `-k`; the certificate is from Let's Encrypt; Caddy keeps its certificate across `docker compose restart caddy`; `sudo certbot renew --dry-run` succeeds and the deploy hook ran; after `curl -sS 'https://<host>/<realm>/authorize?state=SECRETVALUE'` the command `sudo grep -c SECRETVALUE /var/log/nginx/*.log` prints `0` for every file (OPS-15, OPS-18, SEC-12).

**M6. Workflow rules on a throwaway repository** (when `workflow` paths changed, 1 to 2 hours). In the throwaway copy (One-time setup), run the cases of DESIGN.md's rows Repeated checks, Documentation-only changes and Release tag, and with `DEPLOY_PATH` set the example deploy and a forced readiness failure on its host. Pass: each case's jobs run or skip as the row says, the deploy logs `deployed <sha>`, the forced failure logs `rolled back to <previous tag>`, and no secret appears in a job log.

### One-time setup

Not part of a release; done once and kept.

- **Test deployment** for M2, M4 and M5: a host with a public HTTPS name, each provider's app registered with the redirect URI `https://<host>/<realm>/callback/<provider>`, Apple's notification endpoint `https://<host>/<realm>/events/apple`, and a public client of the realm. USER_GUIDE.md sections 3 and 4 describe the setup.
- **Throwaway repository** for M6: a private copy of this repository with the same workflows and a different image name (so it can never push to the real package), plus a disposable host with the four deploy secrets and `DEPLOY_PATH`.
- **Postgres restore** (item 6): the first run creates a test `age` key pair under `release-out/`; nothing else is needed.
- **Test authority for M3**, valid 30 days, constrained to `example.com`, with its key deleted after signing:
  ```bash
  echo "127.0.0.1 auth.example.com app.example.com post.example.com" | sudo tee -a /etc/hosts
  mkdir -p ~/.featherauth-manual && cd ~/.featherauth-manual
  openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -days 30 -subj "/CN=FeatherAuth manual test CA" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign" \
    -addext "nameConstraints=critical,permitted;DNS:example.com"
  openssl req -newkey rsa:2048 -nodes -keyout site.key -out site.csr -subj "/CN=auth.example.com"
  printf "subjectAltName=DNS:auth.example.com,DNS:app.example.com,DNS:post.example.com\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n" > ext.cnf
  openssl x509 -req -in site.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out site.pem -days 30 -extfile ext.cnf
  rm ca.key
  sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ca.pem
  ```
  Firefox: import `ca.pem` or set `security.enterprise_roots.enabled`. iOS Simulator: `xcrun simctl keychain <id> add-root-cert ~/.featherauth-manual/ca.pem`. Remove the trust at the end of each M3 session: `sudo security delete-certificate -c "FeatherAuth manual test CA" /Library/Keychains/System.keychain` (and the Simulator's, by erasing it).

### Time

A release with no conditional area changed: about 30 minutes of `make release-check` plus 1 to 1.5 hours of M1 and M2. With the load run: add 3.5 hours of machine time. Each conditional manual check adds its time above.

## `docs/RESULTS.md`

One file holds the latest result of each check, and only the latest: a new run replaces its section (git history keeps the earlier ones). Tests read it. The layout below lists the required parts; a section may add prose and tables between them (for example the Load section's description of the run after its four header lines).

**Figures from more than one run.** A section normally holds one run, named by its `- Date:` and `- Commit:` lines. When some of its figures come from an earlier run (for example a re-run measured only some scenarios), each subsection or figure taken from another run names that run's own date and commit next to it; a figure whose run is not named is not allowed. The next full run rewrites the whole section with its own figures only.

Layout:

```markdown
# Results

## Load
- Date: YYYY-MM-DD
- Commit: <40-character hash>
- Machine: <CPU, OS, docker version, the limits of the service container>
- Tools: k6 <version>, Caddy <version>, nginx <version>, Postgres <version>

### SQLite
#### Targets      (table: NFR id | figure | measured | result)
#### Idle
#### Steady       (table: endpoint | n | client p50/p95/p99/max | service p50/p95/p99)
#### Peak
#### Burst
#### Restart under load
#### Soak
#### Rate limiter
#### Restart loops

### Postgres
(the same subsections)

## Conformance
- Date: YYYY-MM-DD
- Commit: <40-character hash>
- Suite: release-vX.Y.Z

### Summary      (table: plan | passed | review | warning | failed | skipped)
### Differences  (from the expected lists, or "none")
### Expected warnings and skips  (table: test | condition or reason, one row per entry of deploy/conformance/expected/)

## Browser
- Date: YYYY-MM-DD
- Commit: <40-character hash>

### Manual matrix   (table: browser | version | form_post | without JavaScript | Apple cross-site | two tabs | buttons desktop | buttons phone | notes)
### Apple web flow  (table: run | browser and version | date | result | notes)

## Release gate
- Release: vX.Y.Z
- Commit: <40-character hash of the release commit>
- Date: YYYY-MM-DD

| Check | Result | Detail |
| --- | --- | --- |
| 1 ... 13, M1 ... M6 | one of the values below | run ids, versions, digests, exit codes |

### Release tags   (table: tag | commit | image digest)
```

**Values of the release gate's Result column.** Exactly one of:

- `pass`: the check ran as defined and passed.
- `fail`: the check ran and failed.
- `not applicable: <reason>`: the check cannot apply to this release, for example `gh attestation verify` for a private repository, or item 13 at the first release. A check that applies but was not run is never "not applicable".
- `not run: <reason>; accepted by <name>`: the check applies and was not run. The reason says why, and `<name>` is the person who owns the release and accepted cutting it without the check.
- `no change since <40-character hash>`: a conditional check skipped because its paths of `deploy/release-paths.txt` did not change since the commit of its latest result; a test run by `make check` recomputes the claim.

The detail is never empty. The record is always the truth, so a failed check is written `fail` even when the release was cut. The rules for cutting:

- Before the tag, no row among 1 to 10 and M1 to M6 may be `fail`, and items 1 and 2 may never be `not run` (they prove the release commit is the tested code). Any other `not run` needs the owner's acceptance written in the row itself; an agent or a script never writes "accepted by".
- After the tag, items 11 to 13 run on the published image. If one fails, the tag stays (OPS-02): the release notes say what failed, and a fixed release follows under a new version.

`TestReleaseGateResultsRecorded` (build tag `manual`) checks that every row's value has one of the forms above with a non-empty reason or hash and a non-empty detail, that every check 1 to 13 and M1 to M6 has exactly one row, and the release tags table. `make release-check` refuses to report the release ready while a rule for cutting is broken.

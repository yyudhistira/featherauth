package deploy_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The release check (deploy/ops/release-check.sh, make release-check) is run in a
// fixture repository against fake gh, cosign, docker, go, make and npm tools on
// PATH. The fakes answer from files, so each case changes one answer. Nothing
// here runs conformance, load, a registry or the network.

const (
	rcSlug    = "owner/name"
	rcDigestC = "sha256:" + "cc00000000000000000000000000000000000000000000000000000000000000" // the commit image
	rcDigestR = "sha256:" + "aa00000000000000000000000000000000000000000000000000000000000000" // the release image v0.2.0
	rcDigestO = "sha256:" + "bb00000000000000000000000000000000000000000000000000000000000000" // the earlier release v0.1.0
)

type rcEnv struct {
	t      *testing.T
	repo   string // the fixture repository
	remote string // its bare remote
	stub   string // the fakes and their answers
	out    string // RELEASE_OUT
	c1     string // first commit: v0.1.0, the commit of the recorded sections
	head   string // the release commit
}

func rcWrite(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
}

func rcGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	out, err := gitOut(dir, append([]string{"-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false"}, args...)...)
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(out)
}

func rcCopy(t *testing.T, from, to string) {
	t.Helper()
	b, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	rcWrite(t, to, string(b))
}

// rcResults builds docs/RESULTS.md: sections with their commits and the release
// gate with the given manual rows.
func rcResults(c1, c2 string, manual string, tags string) string {
	return "# Results\n\n## Conformance\n- Date: 2026-11-01\n- Commit: " + c1 + "\n\n## Load\n- Date: 2026-11-01\n- Commit: " + c1 +
		"\n\n## Browser\n- Date: 2026-11-01\n- Commit: " + c1 + "\n\n## Release gate\n- Release: v0.3.0\n- Commit: " + c2 + "\n- Date: 2026-11-02\n\n| Check | Result | Detail |\n| --- | --- | --- |\n" +
		manual + "\n### Release tags\n\n| Tag | Commit | Image digest |\n| --- | --- | --- |\n" + tags
}

const rcManualDone = "| M1 | pass | d |\n| M2 | pass | d |\n| M3 | pass | d |\n| M4 | pass | d |\n| M5 | pass | d |\n| M6 | pass | d |\n"

func newRCEnv(t *testing.T) *rcEnv {
	t.Helper()
	for _, tool := range []string{"jq", "git", "awk"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("%s is needed by the release check and its test: %v", tool, err)
		}
	}
	e := &rcEnv{t: t, repo: t.TempDir(), remote: t.TempDir(), stub: t.TempDir()}
	e.out = filepath.Join(t.TempDir(), "release-out")
	rcCopy(t, "ops/release-check.sh", filepath.Join(e.repo, "deploy/ops/release-check.sh"))
	rcCopy(t, "release-paths.txt", filepath.Join(e.repo, "deploy/release-paths.txt"))
	rcCopy(t, "../go.mod", filepath.Join(e.repo, "go.mod"))
	rcCopy(t, "../docs/DESIGN.md", filepath.Join(e.repo, "docs/DESIGN.md"))
	rcCopy(t, "../examples/web-app/package.json", filepath.Join(e.repo, "examples/web-app/package.json"))
	rcWrite(t, filepath.Join(e.repo, "tools/trace/pending.txt"), "# Entries not yet covered.\n")
	rcWrite(t, filepath.Join(e.repo, "internal/x/a.go"), "package x\n")
	rcGit(t, e.repo, "init", "-q", "-b", "main")
	rcGit(t, e.repo, "add", ".")
	rcGit(t, e.repo, "commit", "-qm", "c1")
	e.c1 = rcGit(t, e.repo, "rev-parse", "HEAD")
	rcGit(t, e.repo, "tag", "v0.1.0")
	rcWrite(t, filepath.Join(e.repo, "docs/RESULTS.md"), rcResults(e.c1, e.c1, rcManualDone, "| v0.1.0 | "+e.c1+" | "+rcDigestO+" |\n"))
	rcGit(t, e.repo, "add", ".")
	rcGit(t, e.repo, "commit", "-qm", "results")
	e.head = rcGit(t, e.repo, "rev-parse", "HEAD")
	rcGit(t, e.repo, "tag", "v0.2.0")
	rcGit(t, e.remote, "init", "-q", "--bare")
	rcGit(t, e.repo, "remote", "add", "origin", e.remote)
	rcGit(t, e.repo, "push", "-q", "origin", "main", "v0.1.0", "v0.2.0")
	e.fakes()
	e.defaults()
	return e
}

func (e *rcEnv) set(name, body string) {
	e.t.Helper()
	rcWrite(e.t, filepath.Join(e.stub, name), body)
}

func (e *rcEnv) unset(name string) { _ = os.Remove(filepath.Join(e.stub, name)) }

func (e *rcEnv) calls() string {
	b, _ := os.ReadFile(filepath.Join(e.stub, "calls.log"))
	return string(b)
}

func (e *rcEnv) fakes() {
	d := e.stub
	e.set("bin/gh", `#!/bin/sh
d="`+d+`"
echo "gh $*" >> "$d/calls.log"
if [ "$1" = attestation ]; then [ ! -e "$d/attest.fail" ]; exit $?; fi
[ "$1" = api ] || exit 64
ep=$2; shift 2
expr=
while [ $# -gt 0 ]; do case $1 in --jq) expr=$2; shift ;; esac; shift; done
case "$ep" in
  repos/*/actions/workflows/deploy.yml/runs\?head_sha=*) k=deploy_runs ;;
  repos/*/actions/workflows/deploy.yml/runs\?event=push*) k=tag_runs ;;
  repos/*/actions/workflows/ci.yml/runs*) k=ci_runs ;;
  repos/*/actions/runs/*/jobs*) id=${ep#repos/*/actions/runs/}; k=jobs-${id%%/*} ;;
  repos/*/commits/*/pulls*) k=pulls ;;
  users/*/packages/*) k=versions ;;
  repos/*/*) k=repo ;;
  *) echo "fake gh: unknown endpoint $ep" >&2; exit 64 ;;
esac
[ ! -e "$d/$k.fail" ] || { echo "fake gh: HTTP 500" >&2; exit 1; }
[ -e "$d/$k.json" ] || { echo "fake gh: no answer for $k" >&2; exit 1; }
if [ -n "$expr" ]; then jq -r "$expr" "$d/$k.json"; else cat "$d/$k.json"; fi
`)
	e.set("bin/cosign", `#!/bin/sh
d="`+d+`"
echo "cosign $*" >> "$d/calls.log"
id=; ref=
while [ $# -gt 0 ]; do case $1 in --certificate-identity) id=$2; shift ;; --certificate-oidc-issuer) [ "$2" = https://token.actions.githubusercontent.com ] || exit 1; shift ;; --type) shift ;; verify|verify-attestation) ;; *) ref=$1 ;; esac; shift; done
grep -qx "${ref#*@} $id" "$d/cosign.allow"
`)
	e.set("bin/docker", `#!/bin/sh
d="`+d+`"
echo "docker $*" >> "$d/calls.log"
case $1 in
  pull) for a; do last=$a; done; [ ! -e "$d/pull.fail" ] || exit 1; echo "$last" >> "$d/pulled"; exit 0 ;;
  volume) exit 0 ;;
  buildx)
    f="$d/digest_$(printf %s "$4" | tr -c 'A-Za-z0-9' _)"
    [ -e "$f" ] || { echo "no such image" >&2; exit 1; }
    printf '{"digest":"%s"}\n' "$(cat "$f")" ;;
  run)
    case " $* " in
      *" version "*) cat "$d/version.txt" ;;
      *" config check "*)
        p=check
        case " $* " in *realcfg*) p=real ;; esac
        [ ! -e "$d/platform.warn" ] || echo "WARNING: The requested image's platform (linux/amd64) does not match the detected host platform (linux/arm64/v8) and no specific platform was requested" >&2
        cat "$d/$p.out"
        [ ! -e "$d/$p.fail" ] ;;
      *) exit 0 ;;
    esac ;;
  *) exit 0 ;;
esac
`)
	e.set("bin/make", `#!/bin/sh
d="`+d+`"
echo "make $*" >> "$d/calls.log"
[ ! -e "$d/make_$(printf %s "$*" | tr -c 'A-Za-z0-9' _).fail" ]
`)
	e.set("bin/go", `#!/bin/sh
d="`+d+`"
echo "go $*" >> "$d/calls.log"
case " $* " in
  *TestOpsUpgrade*) echo "    upgrade_test.go:1: migration time sqlite 0.4s"; if [ -e "$d/go_upgrade.fail" ]; then echo "--- FAIL: TestOpsUpgradeSQLite"; exit 1; fi ;;
  *TestOpsPostgresRestore*)
    # The real test starts containers from NEW_IMAGE without pulling it.
    grep -qxF "$NEW_IMAGE" "$d/pulled" 2>/dev/null || { echo "Error response from daemon: No such image: $NEW_IMAGE"; echo "--- FAIL: TestOpsPostgresRestore"; exit 1; }
    if [ -e "$d/go_restore.fail" ]; then echo "--- FAIL: TestOpsPostgresRestore"; exit 1; fi ;;
esac
`)
	e.set("bin/npm", `#!/bin/sh
d="`+d+`"
echo "npm $*" >> "$d/calls.log"
if [ -e "$d/npm.fail" ]; then echo "found 1 high severity vulnerability"; exit 1; fi
`)
}

func (e *rcEnv) defaults() {
	h, img := e.head, "ghcr.io/"+rcSlug
	dig := func(ref, d string) { e.set("digest_"+rcSanitize(ref), d) }
	dig(img+":"+h, rcDigestC)
	dig(img+":v0.2.0", rcDigestR)
	dig(img+":v0.1.0", rcDigestO)
	e.set("version.txt", "v0.2.0\n")
	id := "https://github.com/" + rcSlug + "/.github/workflows/deploy.yml@"
	e.set("cosign.allow", rcDigestC+" "+id+"refs/heads/main\n"+rcDigestR+" "+id+"refs/tags/v0.2.0\n")
	e.set("check.out", "ok\n")
	e.set("real.out", "ok\n")
	e.set("deploy_runs.json", `{"workflow_runs":[{"id":100,"head_branch":"main","head_sha":"`+h+`","conclusion":"success"}]}`)
	e.set("jobs-100.json", rcJobs("tested", "success", "checks / check", "success", "checks / browser", "success", "checks / ops", "success",
		"checks / postgres (15)", "success", "checks / postgres (18)", "success", "build", "success", "deploy", "skipped"))
	e.set("tag_runs.json", `{"workflow_runs":[{"id":200,"head_branch":"v0.2.0","conclusion":"success","created_at":"2026-11-10T00:00:00Z"}]}`)
	e.set("jobs-200.json", rcJobs("tested", "success", "checks", "skipped", "build", "success", "deploy", "skipped"))
	e.set("repo.json", `{"private":false}`)
	e.set("versions.json", rcVersions("2026-11-05T00:00:00Z", h, "2026-11-10T00:01:00Z", "v0.2.0", "2026-10-01T00:00:00Z", "v0.1.0"))
}

func rcSanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}

func rcJobs(pairs ...string) string {
	var js []string
	for i := 0; i+1 < len(pairs); i += 2 {
		js = append(js, fmt.Sprintf(`{"name":%q,"conclusion":%q}`, pairs[i], pairs[i+1]))
	}
	return `{"jobs":[` + strings.Join(js, ",") + `]}`
}

func rcVersions(pairs ...string) string {
	var vs []string
	for i := 0; i+1 < len(pairs); i += 2 {
		vs = append(vs, fmt.Sprintf(`{"created_at":%q,"metadata":{"container":{"tags":[%q]}}}`, pairs[i], pairs[i+1]))
	}
	return "[" + strings.Join(vs, ",") + "]"
}

// run runs the script with the fakes first on PATH and returns its output
// lines, the results file and the exit code.
func (e *rcEnv) run(env ...string) (lines []string, results string, code int) {
	e.t.Helper()
	cmd := exec.Command("sh", "deploy/ops/release-check.sh")
	cmd.Dir = e.repo
	cmd.Env = append(os.Environ(), "PATH="+filepath.Join(e.stub, "bin")+":"+os.Getenv("PATH"),
		"RELEASE_REPO="+rcSlug, "RELEASE_OUT="+e.out, "RELEASE_REMOTE="+e.remote)
	cmd.Env = append(cmd.Env, env...)
	out, err := cmd.CombinedOutput()
	code = 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		e.t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(e.out, "results.md"))
	return strings.Split(strings.TrimRight(string(out), "\n"), "\n"), string(b), code
}

func rcHas(lines []string, want string) bool {
	for _, l := range lines {
		if strings.Contains(l, want) {
			return true
		}
	}
	return false
}

func rcLast(lines []string) string { return lines[len(lines)-1] }

// rcCommitChange adds a commit that changes internal/x/a.go and moves HEAD.
func (e *rcEnv) changeCode() {
	rcWrite(e.t, filepath.Join(e.repo, "internal/x/a.go"), "package x // changed\n")
	rcGit(e.t, e.repo, "commit", "-qam", "code")
	e.head = rcGit(e.t, e.repo, "rev-parse", "HEAD")
	e.defaults() // digests for the new commit
}

// Covers: SEC-42
// Acceptance: Release check before the tag
// Also proves OPS-01, OPS-02, OPS-20, NFR-13, NFR-14 (not traced).
func TestReleaseCheckBeforeTheTag(t *testing.T) {
	t.Run("a good commit passes every item in order and is ready to tag", func(t *testing.T) {
		e := newRCEnv(t)
		lines, results, code := e.run()
		if code != 0 || rcLast(lines) != "ready to tag" {
			t.Fatalf("exit %d, output:\n%s", code, strings.Join(lines, "\n"))
		}
		pos := -1
		for i, name := range []string{"item 1: CI of the commit: pass", "item 2: pending.txt: pass", "item 3: modules: pass", "item 4: config check: pass",
			"item 5: upgrade and rollback: pass", "item 6: Postgres restore: pass", "item 7: conformance: skipped: no change since " + e.c1,
			"item 8: load: skipped: no change since " + e.c1, "item 9: manual checks: pass", "item 10: result lines: pass"} {
			found := -1
			for j, l := range lines {
				if j > pos && l == name {
					found = j
					break
				}
			}
			if found < 0 {
				t.Fatalf("no line %q after line %d (item %d):\n%s", name, pos, i+1, strings.Join(lines, "\n"))
			}
			pos = found
		}
		for _, want := range []string{"| 1 | pass |", "| 2 | pass |", "| 3 | pass |", "| 4 | pass |", "| 5 | pass |", "| 6 | pass |",
			"| 7 | no change since " + e.c1 + " |", "| 8 | no change since " + e.c1 + " |", "| 9 | pass |", "| 10 | pass |",
			"| M3 | no change since " + e.c1 + " |", "| M4 | no change since " + e.c1 + " |"} {
			if !strings.Contains(results, want) {
				t.Errorf("results.md lacks %q:\n%s", want, results)
			}
		}
		if c := e.calls(); strings.Contains(c, "make conformance") || strings.Contains(c, "make load") {
			t.Fatalf("conformance or load ran with unchanged paths:\n%s", c)
		}
		// Item 4: the shipped examples are checked in the signed image with no network, as 65532, mounted read-only.
		if c := e.calls(); !strings.Contains(c, "--network none --user 65532:65532") || !strings.Contains(c, ":/etc/featherauth:ro "+"ghcr.io/"+rcSlug+"@"+rcDigestC+" config check /etc/featherauth") {
			t.Fatalf("config check was not run as designed:\n%s", c)
		}
		if !strings.Contains(e.calls(), "npm audit --omit=dev --audit-level=high") {
			t.Fatal("npm audit was not run")
		}
		if !strings.Contains(results, "RELEASE_CONFIG_DIR not set") {
			t.Fatalf("the record does not say the shipped examples only were checked:\n%s", results)
		}
	})

	for _, c := range []struct {
		name  string
		setup func(e *rcEnv)
		item  string // the line that must say fail, the last before the stop
		why   string
	}{
		{"a red deploy run", func(e *rcEnv) {
			e.set("deploy_runs.json", `{"workflow_runs":[{"id":100,"head_branch":"main","head_sha":"`+e.head+`","conclusion":"failure"}]}`)
		}, "item 1: CI of the commit: fail", "concluded failure"},
		{"no deploy run for the commit", func(e *rcEnv) { e.set("deploy_runs.json", `{"workflow_runs":[]}`) }, "item 1: CI of the commit: fail", "no deploy run"},
		{"a failed gh", func(e *rcEnv) { e.set("deploy_runs.fail", "") }, "item 1: CI of the commit: fail", "not available"},
		{"one job of the checks is red", func(e *rcEnv) {
			e.set("jobs-100.json", rcJobs("checks / check", "success", "checks / browser", "success", "checks / ops", "success", "checks / postgres (15)", "success", "checks / postgres (18)", "failure"))
		}, "item 1: CI of the commit: fail", "postgres (18)=failure"},
		{"the postgres job is missing", func(e *rcEnv) {
			e.set("jobs-100.json", rcJobs("checks / check", "success", "checks / browser", "success", "checks / ops", "success"))
		}, "item 1: CI of the commit: fail", "postgres=missing"},
		{"skipped checks and no merged pull request", func(e *rcEnv) {
			e.set("jobs-100.json", rcJobs("tested", "success", "checks", "skipped", "build", "success"))
			e.set("pulls.json", `[]`)
		}, "item 1: CI of the commit: fail", "pull request is not found"},
		{"skipped checks and a red ci run", func(e *rcEnv) {
			e.set("jobs-100.json", rcJobs("tested", "success", "checks", "skipped", "build", "success"))
			e.set("pulls.json", `[{"merged_at":"2026-11-01T00:00:00Z","merge_commit_sha":"`+e.head+`","head":{"sha":"`+strings.Repeat("1", 40)+`"}}]`)
			e.set("ci_runs.json", `{"workflow_runs":[{"id":300,"head_sha":"`+strings.Repeat("1", 40)+`","conclusion":"failure"}]}`)
		}, "item 1: CI of the commit: fail", "concluded failure"},
		{"skipped checks and a ci run with a skipped job", func(e *rcEnv) {
			e.set("jobs-100.json", rcJobs("tested", "success", "checks", "skipped", "build", "success"))
			e.set("pulls.json", `[{"merged_at":"2026-11-01T00:00:00Z","merge_commit_sha":"`+e.head+`","head":{"sha":"`+strings.Repeat("1", 40)+`"}}]`)
			e.set("ci_runs.json", `{"workflow_runs":[{"id":300,"head_sha":"`+strings.Repeat("1", 40)+`","conclusion":"success"}]}`)
			e.set("jobs-300.json", rcJobs("check", "success", "browser", "skipped", "ops", "success", "postgres (15)", "success", "postgres (18)", "success"))
		}, "item 1: CI of the commit: fail", "browser=skipped"},
		{"gh fails on the jobs of the deploy run", func(e *rcEnv) { e.set("jobs-100.fail", "") }, "item 1: CI of the commit: fail", "the jobs of deploy run 100 are not available"},
		{"gh fails on the jobs of the ci run", func(e *rcEnv) {
			e.set("jobs-100.json", rcJobs("tested", "success", "checks", "skipped", "build", "success"))
			e.set("pulls.json", `[{"merged_at":"2026-11-01T00:00:00Z","merge_commit_sha":"`+e.head+`","head":{"sha":"`+strings.Repeat("1", 40)+`"}}]`)
			e.set("ci_runs.json", `{"workflow_runs":[{"id":300,"head_sha":"`+strings.Repeat("1", 40)+`","conclusion":"success"}]}`)
			e.set("jobs-300.fail", "")
		}, "item 1: CI of the commit: fail", "the jobs of ci run 300 are not available"},
		{"an entry in pending.txt", func(e *rcEnv) {
			rcWrite(t, filepath.Join(e.repo, "tools/trace/pending.txt"), "# c\nSEC-99\n")
			rcGit(t, e.repo, "commit", "-qam", "pending")
			e.head = rcGit(t, e.repo, "rev-parse", "HEAD")
			e.defaults()
		}, "item 2: pending.txt: fail", "SEC-99"},
		{"a module outside the Tech stack", func(e *rcEnv) {
			b, _ := os.ReadFile(filepath.Join(e.repo, "go.mod"))
			rcWrite(t, filepath.Join(e.repo, "go.mod"), strings.Replace(string(b), "require (\n", "require (\n\texample.com/evil v1.0.0\n", 1))
		}, "item 3: modules: fail", "example.com/evil"},
		{"govulncheck finds something", func(e *rcEnv) { e.set("make_vuln.fail", "") }, "item 3: modules: fail", "govulncheck"},
		{"npm audit finds something", func(e *rcEnv) { e.set("npm.fail", "") }, "item 3: modules: fail", "npm audit"},
		{"the example web app has a version range", func(e *rcEnv) {
			b, _ := os.ReadFile(filepath.Join(e.repo, "examples/web-app/package.json"))
			rcWrite(t, filepath.Join(e.repo, "examples/web-app/package.json"), strings.Replace(string(b), `"6.2.18"`, `"^6.2.18"`, 1))
		}, "item 3: modules: fail", "jose@^6.2.18"},
		{"the example web app has a dependency the design does not name", func(e *rcEnv) {
			b, _ := os.ReadFile(filepath.Join(e.repo, "examples/web-app/package.json"))
			rcWrite(t, filepath.Join(e.repo, "examples/web-app/package.json"), strings.Replace(string(b), `"dependencies": {`, `"dependencies": {"left-pad-x1": "1.0.0",`, 1))
		}, "item 3: modules: fail", "left-pad-x1"},
		{"the example web app has a dependency the design names only outside its Example web app section", func(e *rcEnv) {
			b, _ := os.ReadFile(filepath.Join(e.repo, "examples/web-app/package.json"))
			rcWrite(t, filepath.Join(e.repo, "examples/web-app/package.json"), strings.Replace(string(b), `"dependencies": {`, `"dependencies": {"left-pad-x2": "1.0.0",`, 1))
			d, _ := os.ReadFile(filepath.Join(e.repo, "docs/DESIGN.md"))
			rcWrite(t, filepath.Join(e.repo, "docs/DESIGN.md"), string(d)+"\n## Elsewhere\n\nThe package left-pad-x2 is named here and not in the example's section.\n")
		}, "item 3: modules: fail", "left-pad-x2"},
		{"the commit image is missing", func(e *rcEnv) { e.unset("digest_" + rcSanitize("ghcr.io/"+rcSlug+":"+e.head)) }, "item 4: config check: fail", "does not exist"},
		{"the signer identity is wrong", func(e *rcEnv) {
			e.set("cosign.allow", rcDigestC+" https://github.com/"+rcSlug+"/.github/workflows/deploy.yml@refs/heads/other\n")
		}, "item 4: config check: fail", "cosign verify failed"},
		{"config check of the examples fails", func(e *rcEnv) { e.set("check.fail", ""); e.set("check.out", "realm.yaml:3: stricter rule\n") }, "item 4: config check: fail", "stricter rule"},
		{"config check of RELEASE_CONFIG_DIR fails", func(e *rcEnv) { e.set("real.fail", ""); e.set("real.out", "server.yaml:1: bad\n") }, "item 4: config check: fail", "RELEASE_CONFIG_DIR"},
		{"the upgrade ops test fails", func(e *rcEnv) { e.set("go_upgrade.fail", "") }, "item 5: upgrade and rollback: fail", "TestOpsUpgradeSQLite"},
		{"the Postgres restore ops test fails", func(e *rcEnv) { e.set("go_restore.fail", "") }, "item 6: Postgres restore: fail", "TestOpsPostgresRestore"},
	} {
		t.Run(c.name+" stops the run and names the item", func(t *testing.T) {
			e := newRCEnv(t)
			c.setup(e)
			lines, results, code := e.run("RELEASE_CONFIG_DIR=" + filepath.Join(e.repo, "realcfg"))
			if code == 0 || !rcHas(lines, c.item) {
				t.Fatalf("exit %d, want a failure with %q:\n%s", code, c.item, strings.Join(lines, "\n"))
			}
			last := rcLast(lines)
			if !strings.HasPrefix(last, "not ready: item "+strings.TrimPrefix(strings.SplitN(c.item, ":", 2)[0], "item ")) || !strings.Contains(last, c.why) {
				t.Fatalf("last line %q lacks the item and %q", last, c.why)
			}
			if strings.Contains(strings.Join(lines, "\n"), "ready to tag") && !strings.Contains(last, "not ready") {
				t.Fatal("reported ready")
			}
			if !strings.Contains(results, " fail |") {
				t.Fatalf("results.md has no fail line:\n%s", results)
			}
			// The run stopped: no later item has a line.
			n := 0
			fmt.Sscanf(strings.SplitN(c.item, ":", 2)[0], "item %d", &n)
			for _, l := range lines {
				var m int
				if _, err := fmt.Sscanf(l, "item %d:", &m); err == nil && m > n {
					t.Fatalf("item %d ran after the failure of item %d", m, n)
				}
			}
		})
	}

	t.Run("a skipped checks job is covered by the green ci run of the merged pull request", func(t *testing.T) {
		e := newRCEnv(t)
		head := strings.Repeat("1", 40)
		e.set("jobs-100.json", rcJobs("tested", "success", "checks", "skipped", "build", "success"))
		e.set("pulls.json", `[{"merged_at":"2026-11-01T00:00:00Z","merge_commit_sha":"`+e.head+`","head":{"sha":"`+head+`"}}]`)
		e.set("ci_runs.json", `{"workflow_runs":[{"id":300,"head_sha":"`+head+`","conclusion":"success"}]}`)
		e.set("jobs-300.json", rcJobs("changes", "success", "check", "success", "browser", "success", "ops", "success", "postgres (15)", "success", "postgres (18)", "success"))
		lines, results, _ := e.run()
		if !rcHas(lines, "item 1: CI of the commit: pass") || !strings.Contains(results, "ci run 300") {
			t.Fatalf("%s\n%s", strings.Join(lines, "\n"), results)
		}
	})

	t.Run("conformance and load run when their paths changed", func(t *testing.T) {
		e := newRCEnv(t)
		e.changeCode()
		lines, results, _ := e.run()
		c := e.calls()
		for _, want := range []string{"make conformance", "make load\n", "make load LOAD_DRIVER=postgres"} {
			if !strings.Contains(c, want) {
				t.Errorf("the calls lack %q:\n%s", want, c)
			}
		}
		if !rcHas(lines, "item 7: conformance: pass") || !rcHas(lines, "item 8: load: pass") || !strings.Contains(results, "| 7 | pass |") {
			t.Fatalf("%s", strings.Join(lines, "\n"))
		}
		// internal/ changed, not the browser paths of a file outside them: the
		// browser paths (internal/web, oidc, server, config) did not change.
		if !strings.Contains(results, "| M3 | no change since") {
			t.Fatalf("the browser check should be unchanged:\n%s", results)
		}
		// The apple paths include internal/provider, internal/oidc, internal/store: not internal/x.
		if strings.Contains(strings.Join(lines, "\n"), "required") {
			t.Fatalf("a manual check is required for a change outside its paths:\n%s", strings.Join(lines, "\n"))
		}
	})

	t.Run("a failed conformance or load run stops the release", func(t *testing.T) {
		e := newRCEnv(t)
		e.changeCode()
		e.set("make_conformance.fail", "")
		lines, _, code := e.run()
		if code == 0 || !rcHas(lines, "item 7: conformance: fail") || rcHas(lines, "item 8:") {
			t.Fatalf("%s", strings.Join(lines, "\n"))
		}
		e = newRCEnv(t)
		e.changeCode()
		e.set("make_load_LOAD_DRIVER_postgres.fail", "")
		lines, _, code = e.run()
		if code == 0 || !rcHas(lines, "item 8: load: fail") {
			t.Fatalf("%s", strings.Join(lines, "\n"))
		}
	})

	t.Run("a changed manual path makes the check required", func(t *testing.T) {
		e := newRCEnv(t)
		rcWrite(t, filepath.Join(e.repo, "internal/web/w.go"), "package w\n")
		rcGit(t, e.repo, "add", ".")
		rcGit(t, e.repo, "commit", "-qm", "web")
		e.head = rcGit(t, e.repo, "rev-parse", "HEAD")
		e.defaults()
		lines, _, _ := e.run()
		if !rcHas(lines, "item 9: manual check M3 (browser): required") || !rcHas(lines, "item 9: manual check M5 (tls): no change since") {
			t.Fatalf("%s", strings.Join(lines, "\n"))
		}
	})

	t.Run("a release with empty manual rows is not ready", func(t *testing.T) {
		e := newRCEnv(t)
		rcWrite(t, filepath.Join(e.repo, "docs/RESULTS.md"), rcResults(e.c1, e.c1, "| M1 | pass | d |\n| M2 |  |  |\n| M3 | pass | d |\n| M4 | pass | d |\n| M5 | pass | d |\n| M6 | fail | d |\n", ""))
		rcGit(t, e.repo, "commit", "-qam", "results")
		e.head = rcGit(t, e.repo, "rev-parse", "HEAD")
		e.defaults()
		lines, _, code := e.run()
		last := rcLast(lines)
		if code == 0 || !strings.HasPrefix(last, "not ready:") || !strings.Contains(last, "M2(empty)") || !strings.Contains(last, "M6(fail)") || rcHas(lines, "ready to tag") && !strings.HasPrefix(last, "not ready") {
			t.Fatalf("%s", strings.Join(lines, "\n"))
		}
	})

	t.Run("a gate section of an earlier, tagged release ends not ready", func(t *testing.T) {
		e := newRCEnv(t)
		// v0.2.0 is tagged: its rows, all filled and green, describe a release already made.
		b, _ := os.ReadFile(filepath.Join(e.repo, "docs/RESULTS.md"))
		rcWrite(t, filepath.Join(e.repo, "docs/RESULTS.md"), strings.Replace(string(b), "- Release: v0.3.0", "- Release: v0.2.0", 1))
		rcGit(t, e.repo, "commit", "-qam", "earlier gate")
		e.head = rcGit(t, e.repo, "rev-parse", "HEAD")
		e.defaults()
		lines, _, code := e.run()
		last := rcLast(lines)
		if code == 0 || !strings.HasPrefix(last, "not ready:") || !strings.Contains(last, "M1(empty)") || !strings.Contains(last, "v0.2.0") || rcHas(lines, "ready to tag") {
			t.Fatalf("%s", strings.Join(lines, "\n"))
		}
		// The manual check commits still come from the gate (item 9 is not stopped by it).
		if !rcHas(lines, "item 10: result lines: pass") {
			t.Fatalf("%s", strings.Join(lines, "\n"))
		}
	})

	t.Run("a gate section with no release version ends not ready", func(t *testing.T) {
		e := newRCEnv(t)
		b, _ := os.ReadFile(filepath.Join(e.repo, "docs/RESULTS.md"))
		rcWrite(t, filepath.Join(e.repo, "docs/RESULTS.md"), strings.Replace(string(b), "- Release: v0.3.0", "- Release:", 1))
		rcGit(t, e.repo, "commit", "-qam", "no release")
		e.head = rcGit(t, e.repo, "rev-parse", "HEAD")
		e.defaults()
		lines, _, code := e.run()
		if code == 0 || !strings.Contains(rcLast(lines), "M1(empty)") {
			t.Fatalf("%s", strings.Join(lines, "\n"))
		}
	})

	t.Run("the first release has no previous image", func(t *testing.T) {
		e := newRCEnv(t)
		rcGit(t, e.repo, "tag", "-d", "v0.1.0")
		rcGit(t, e.repo, "tag", "-d", "v0.2.0")
		lines, results, _ := e.run()
		if !rcHas(lines, "item 5: upgrade and rollback: not applicable: there is no previous release") || !strings.Contains(results, "| 5 | not applicable:") {
			t.Fatalf("%s", strings.Join(lines, "\n"))
		}
		if strings.Contains(e.calls(), "TestOpsUpgrade") {
			t.Fatal("the upgrade test ran without a previous release")
		}
		// Item 6 still runs and needs the commit image on the machine,
		// though item 5 did not pull anything.
		if !rcHas(lines, "item 6: Postgres restore: pass") || !strings.Contains(results, "| 6 | pass |") {
			t.Fatalf("%s", strings.Join(lines, "\n"))
		}
		if c := e.calls(); !strings.Contains(c, "docker pull ghcr.io/"+rcSlug+":"+e.head) {
			t.Fatalf("the commit image was not pulled before the restore test:\n%s", c)
		}
	})

	t.Run("the first release stops at item 6 when the commit image cannot be pulled", func(t *testing.T) {
		e := newRCEnv(t)
		rcGit(t, e.repo, "tag", "-d", "v0.1.0")
		rcGit(t, e.repo, "tag", "-d", "v0.2.0")
		e.set("pull.fail", "")
		lines, _, code := e.run()
		if code == 0 || !rcHas(lines, "item 6: Postgres restore: fail") || !strings.Contains(rcLast(lines), "cannot pull the commit image") || !strings.HasPrefix(rcLast(lines), "not ready") {
			t.Fatalf("exit %d:\n%s", code, strings.Join(lines, "\n"))
		}
	})

	t.Run("a docker notice on stderr is not a config check warning", func(t *testing.T) {
		e := newRCEnv(t)
		e.set("platform.warn", "")
		lines, results, _ := e.run()
		if !rcHas(lines, "item 4: config check: pass") {
			t.Fatalf("%s", strings.Join(lines, "\n"))
		}
		if strings.Contains(results, "warnings:") || strings.Contains(results, "platform") {
			t.Fatalf("the docker notice was recorded as a warning:\n%s", results)
		}
		e = newRCEnv(t)
		e.set("check.out", "warning: example.yaml:3: something to look at\n")
		_, results, _ = e.run()
		if !strings.Contains(results, "warnings: warning: example.yaml:3: something to look at") {
			t.Fatalf("a config check warning was not recorded:\n%s", results)
		}
	})

	t.Run("the previous image is the newest release tag, or PREV_IMAGE", func(t *testing.T) {
		e := newRCEnv(t)
		e.run()
		if c := e.calls(); !strings.Contains(c, "docker pull ghcr.io/"+rcSlug+":v0.2.0") {
			t.Fatalf("the newest tag was not the previous image:\n%s", c)
		}
		e = newRCEnv(t)
		e.run("PREV_IMAGE=registry.example/prev:1")
		if c := e.calls(); !strings.Contains(c, "docker pull registry.example/prev:1") {
			t.Fatalf("PREV_IMAGE was not used:\n%s", c)
		}
	})
}

// Covers: SEC-42
// Acceptance: Release check after the tag
// Also proves OPS-01, OPS-02 (not traced).
func TestReleaseCheckAfterTheTag(t *testing.T) {
	tagRun := func(e *rcEnv) ([]string, string, int) { return e.run("TAG=v0.2.0") }

	t.Run("a published release passes items 11 to 13", func(t *testing.T) {
		e := newRCEnv(t)
		lines, results, code := tagRun(e)
		if code != 0 || rcLast(lines) != "post-tag checks passed" {
			t.Fatalf("exit %d\n%s", code, strings.Join(lines, "\n"))
		}
		for _, want := range []string{"item 11: tag run: pass", "item 12: signatures: pass", "item 13: earlier tags: pass"} {
			if !rcHas(lines, want) {
				t.Errorf("no line %q", want)
			}
		}
		c := e.calls()
		id := "https://github.com/" + rcSlug + "/.github/workflows/deploy.yml@"
		for _, want := range []string{
			"cosign verify --certificate-oidc-issuer https://token.actions.githubusercontent.com --certificate-identity " + id + "refs/tags/v0.2.0 ghcr.io/" + rcSlug + "@" + rcDigestR,
			"cosign verify-attestation --type spdxjson --certificate-oidc-issuer https://token.actions.githubusercontent.com --certificate-identity " + id + "refs/heads/main ghcr.io/" + rcSlug + "@" + rcDigestC,
			"gh attestation verify oci://ghcr.io/" + rcSlug + "@" + rcDigestR + " --repo " + rcSlug + " --signer-workflow " + rcSlug + "/.github/workflows/deploy.yml",
		} {
			if !strings.Contains(c, want) {
				t.Errorf("the calls lack %q:\n%s", want, c)
			}
		}
		if !strings.Contains(results, "| v0.2.0 | "+e.head+" | "+rcDigestR+" |") || !strings.Contains(results, "| v0.1.0 | "+e.c1+" | "+rcDigestO+" |") {
			t.Fatalf("the release tags table was not written:\n%s", results)
		}
	})

	t.Run("a private repository has no provenance to verify", func(t *testing.T) {
		e := newRCEnv(t)
		e.set("repo.json", `{"private":true}`)
		lines, results, code := tagRun(e)
		if code != 0 || strings.Contains(e.calls(), "gh attestation") || !strings.Contains(results, "not applicable (private repository)") {
			t.Fatalf("exit %d\n%s\n%s", code, strings.Join(lines, "\n"), results)
		}
	})

	t.Run("the first release only writes the table", func(t *testing.T) {
		e := newRCEnv(t)
		rcWrite(t, filepath.Join(e.repo, "docs/RESULTS.md"), rcResults(e.c1, e.c1, rcManualDone, ""))
		lines, results, code := tagRun(e)
		if code != 0 || !rcHas(lines, "item 13: earlier tags: not applicable: first release") || !strings.Contains(results, "| v0.1.0 |") {
			t.Fatalf("exit %d\n%s\n%s", code, strings.Join(lines, "\n"), results)
		}
	})

	for _, c := range []struct {
		name  string
		setup func(e *rcEnv)
		item  string
		why   string
	}{
		{"the image is missing", func(e *rcEnv) { e.unset("digest_" + rcSanitize("ghcr.io/"+rcSlug+":v0.2.0")) }, "item 11: tag run: fail", "does not exist"},
		{"gh fails on the jobs of the tag run", func(e *rcEnv) { e.set("jobs-200.fail", "") }, "item 11: tag run: fail", "the jobs of the tag run 200 are not available"},
		{"the image prints another version", func(e *rcEnv) { e.set("version.txt", "v0.2.1\n") }, "item 11: tag run: fail", "prints 'v0.2.1'"},
		{"the tag run failed", func(e *rcEnv) {
			e.set("tag_runs.json", `{"workflow_runs":[{"id":200,"head_branch":"v0.2.0","conclusion":"failure","created_at":"2026-11-10T00:00:00Z"}]}`)
		}, "item 11: tag run: fail", "concluded failure"},
		{"the tag run deployed", func(e *rcEnv) {
			e.set("jobs-200.json", rcJobs("tested", "success", "build", "success", "deploy", "success"))
		}, "item 11: tag run: fail", "deploy job ran"},
		{"the package has a latest tag", func(e *rcEnv) {
			e.set("versions.json", rcVersions("2026-11-10T00:01:00Z", "v0.2.0", "2026-11-10T00:02:00Z", "latest"))
		}, "item 11: tag run: fail", "latest"},
		{"the tag run pushed a commit-hash tag", func(e *rcEnv) {
			e.set("versions.json", rcVersions("2026-11-10T00:01:00Z", "v0.2.0", "2026-11-10T00:02:00Z", strings.Repeat("d", 40)))
		}, "item 11: tag run: fail", "commit-hash tag"},
		{"the release image was signed by a main build", func(e *rcEnv) {
			id := "https://github.com/" + rcSlug + "/.github/workflows/deploy.yml@"
			e.set("cosign.allow", rcDigestC+" "+id+"refs/heads/main\n"+rcDigestR+" "+id+"refs/heads/main\n")
		}, "item 12: signatures: fail", "refs/tags/v0.2.0"},
		{"the commit image has no SBOM attestation", func(e *rcEnv) {
			e.set("bin/cosign", "#!/bin/sh\ncase \"$1\" in verify-attestation) case \"$*\" in *"+rcDigestC+"*) exit 1 ;; esac ;; esac\nexit 0\n")
		}, "item 12: signatures: fail", "SBOM"},
		{"gh attestation verify fails", func(e *rcEnv) { e.set("attest.fail", "") }, "item 12: signatures: fail", "gh attestation verify failed"},
		{"an earlier tag moved", func(e *rcEnv) {
			rcGit(t, e.remote, "update-ref", "refs/tags/v0.1.0", e.head)
		}, "item 13: earlier tags: fail", "the tag v0.1.0 moved"},
		{"an earlier image digest changed", func(e *rcEnv) {
			e.set("digest_"+rcSanitize("ghcr.io/"+rcSlug+":v0.1.0"), "sha256:"+strings.Repeat("9", 64))
		}, "item 13: earlier tags: fail", "image of v0.1.0 changed"},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newRCEnv(t)
			c.setup(e)
			lines, _, code := tagRun(e)
			last := rcLast(lines)
			if code == 0 || !rcHas(lines, c.item) || !strings.HasPrefix(last, "not ready: item ") || !strings.Contains(last, c.why) {
				t.Fatalf("exit %d, want %q and a last line with %q:\n%s", code, c.item, c.why, strings.Join(lines, "\n"))
			}
		})
	}

	t.Run("a TAG that is not a release version is refused", func(t *testing.T) {
		e := newRCEnv(t)
		for _, bad := range []string{"v1.0", "vX.Y.Z", "1.2.3", "v1.2.3-rc1"} {
			if _, _, code := e.run("TAG=" + bad); code != 2 {
				t.Errorf("TAG=%s exited %d, want 2", bad, code)
			}
		}
	})
}

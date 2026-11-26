package deploy_test

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

type workflowStep struct {
	ID              string            `yaml:"id"`
	ContinueOnError bool              `yaml:"continue-on-error"`
	Name            string            `yaml:"name"`
	If              string            `yaml:"if"`
	Uses            string            `yaml:"uses"`
	Run             string            `yaml:"run"`
	Env             map[string]string `yaml:"env"`
	With            map[string]string `yaml:"with"`
}

// Every job runs on the repository variable RUNNER, or on the pinned default
// when it is not set.
const (
	runnerDefault = "ubuntu-24.04"
	runnerExpr    = "${{ vars.RUNNER || '" + runnerDefault + "' }}"
)

type workflowJob struct {
	Uses        string            `yaml:"uses"`
	If          string            `yaml:"if"`
	Concurrency any               `yaml:"concurrency"`
	Needs       any               `yaml:"needs"`
	RunsOn      string            `yaml:"runs-on"`
	Permissions map[string]string `yaml:"permissions"`
	Outputs     map[string]string `yaml:"outputs"`
	Env         map[string]string `yaml:"env"`
	Strategy    struct {
		Matrix map[string][]string `yaml:"matrix"`
	} `yaml:"strategy"`
	Steps []workflowStep `yaml:"steps"`
}

type workflowConcurrency struct {
	Group            string `yaml:"group"`
	CancelInProgress any    `yaml:"cancel-in-progress"`
}

type workflow struct {
	On          map[string]any         `yaml:"on"`
	Concurrency workflowConcurrency    `yaml:"concurrency"`
	Permissions map[string]string      `yaml:"permissions"`
	Jobs        map[string]workflowJob `yaml:"jobs"`
}

func readWorkflow(t *testing.T, name string) (workflow, string) {
	t.Helper()
	text := readFile(t, filepath.Join("..", ".github", "workflows", name))
	var w workflow
	if err := yaml.Unmarshal([]byte(text), &w); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return w, text
}

func (j workflowJob) runs(cmd string) bool {
	for _, s := range j.Steps {
		for _, line := range strings.Split(s.Run, "\n") {
			if strings.TrimSpace(line) == cmd {
				return true
			}
		}
	}
	return false
}

func (j workflowJob) needs(name string) bool {
	switch n := j.Needs.(type) {
	case string:
		return n == name
	case []any:
		for _, v := range n {
			if v == name {
				return true
			}
		}
	}
	return false
}

func stepIndex(j workflowJob, match func(workflowStep) bool) int {
	for i, s := range j.Steps {
		if match(s) {
			return i
		}
	}
	return -1
}

// Covers: SEC-15 (part)
// Acceptance: Dependencies (part)
func TestCIRunsChecksBrowserAndOps(t *testing.T) {
	w, _ := readWorkflow(t, "ci.yml")
	if _, ok := w.On["pull_request"]; !ok {
		t.Error("ci.yml does not run on pull requests")
	}
	if _, ok := w.On["workflow_call"]; !ok {
		t.Error("ci.yml cannot be called by deploy.yml (workflow_call)")
	}
	for job, cmd := range map[string]string{
		"check":   "make check",
		"browser": "make browser",
		"ops":     "make ops",
	} {
		j, ok := w.Jobs[job]
		if !ok {
			t.Errorf("ci.yml has no job %q", job)
			continue
		}
		if j.RunsOn != runnerExpr {
			t.Errorf("job %s runs on %q, want %q", job, j.RunsOn, runnerExpr)
		}
		if !j.runs(cmd) {
			t.Errorf("job %s does not run %q", job, cmd)
		}
		if len(j.Steps) == 0 || !strings.HasPrefix(j.Steps[0].Uses, "actions/checkout@") {
			t.Errorf("job %s does not start with checkout", job)
		}
	}
	// tools/trace compares pending.txt with origin/main: it needs the history.
	if c := w.Jobs["check"].Steps[0].With["fetch-depth"]; c != "0" {
		t.Errorf("check job fetch-depth = %q, want 0", c)
	}
	// The upgrade ops tests build the newest release tag: the ops job needs the
	// full history and the tags, or they fail (they never pass for "no release").
	ops := w.Jobs["ops"].Steps[0].With
	if ops["fetch-depth"] != "0" || ops["fetch-tags"] != "true" {
		t.Errorf("ops job checkout fetch-depth, fetch-tags = %q, %q; want 0, true", ops["fetch-depth"], ops["fetch-tags"])
	}
}

// The check job gives govulncheck (make vuln) through make check.
//
// Covers: SEC-15 (part)
// Acceptance: Dependencies (part)
// A runner label that floats ("ubuntu-latest") moves to a new image on
// GitHub's schedule and can break a green pipeline without a commit; the
// default runner names an exact Ubuntu release, and it is changed on purpose.
// The repository variable RUNNER (for example "self-hosted") replaces it.
func TestWorkflowRunnersArePinned(t *testing.T) {
	pinned := regexp.MustCompile(`^ubuntu-\d{2}\.\d{2}$`)
	if !pinned.MatchString(runnerDefault) {
		t.Errorf("default runner %q is not an exact Ubuntu release", runnerDefault)
	}
	for _, name := range []string{"ci.yml", "deploy.yml"} {
		w, _ := readWorkflow(t, name)
		for job, j := range w.Jobs {
			if j.RunsOn == "" {
				continue // a job that calls a reusable workflow has no runner
			}
			if j.RunsOn != runnerExpr {
				t.Errorf("%s job %s runs on %q, want %q", name, job, j.RunsOn, runnerExpr)
			}
		}
	}
}

func TestMakeCheckRunsGovulncheck(t *testing.T) {
	mk := readFile(t, "../Makefile")
	if !regexp.MustCompile(`(?m)^check:.*\bvuln\b`).MatchString(mk) {
		t.Error("make check does not depend on vuln")
	}
	if !regexp.MustCompile(`(?m)^vuln:\n\t.*govulncheck`).MatchString(mk) {
		t.Error("make vuln does not run govulncheck")
	}
}

// Acceptance: Deploy (part)
// A repository that has not set DEPLOY_PATH has no host to deploy to (the first
// deploy on a fresh host is manual): the deploy job is skipped, so main stays
// green, while the image is still built and pushed. A repository that sets
// DEPLOY_PATH and misses a secret still fails, because the job runs.
func TestDeployJobIsSkippedWithoutADeployPath(t *testing.T) {
	w, _ := readWorkflow(t, "deploy.yml")
	// The condition was "${{ vars.DEPLOY_PATH != '' }}"; the deploy condition also has the branch
	// condition and the documentation-only one (tested by
	// TestDeployJobConditionTable). The meaning "skipped without
	// vars.DEPLOY_PATH" is kept.
	if got, want := w.Jobs["deploy"].If, "${{ !cancelled() && needs.tested.result == 'success' && needs.build.result == 'success' && vars.DEPLOY_PATH != '' && github.ref_type == 'branch' && needs.tested.outputs.docs_only != 'true' }}"; got != want {
		t.Errorf("deploy job if = %q, want %q", got, want)
	}
	if !strings.Contains(w.Jobs["deploy"].If, "vars.DEPLOY_PATH != ''") {
		t.Error("deploy job is no longer skipped without vars.DEPLOY_PATH")
	}
	// Checks and build depend on the "tested" job (TestDeployChecksAndBuildConditions);
	// neither may depend on DEPLOY_PATH, so a missing variable still builds and pushes the image.
	for _, job := range []string{"tested", "checks", "build"} {
		if strings.Contains(w.Jobs[job].If, "DEPLOY_PATH") {
			t.Errorf("job %s depends on DEPLOY_PATH (%q); only the deploy job may be skipped for it", job, w.Jobs[job].If)
		}
	}
	if w.Jobs["tested"].If != "" {
		t.Errorf("tested job is conditional (%q)", w.Jobs["tested"].If)
	}
}

// Acceptance: Deploy
func TestDeployWorkflowOrderAndImage(t *testing.T) {
	w, _ := readWorkflow(t, "deploy.yml")
	push, ok := w.On["push"].(map[string]any)
	if !ok {
		t.Fatal("deploy.yml does not run on push")
	}
	if b, _ := push["branches"].([]any); len(b) != 1 || b[0] != "main" {
		t.Errorf("deploy.yml push branches = %v, want [main]", push["branches"])
	}
	if len(w.On) != 1 {
		t.Errorf("deploy.yml has triggers beyond push: %v", w.On)
	}

	checks := w.Jobs["checks"]
	if checks.Uses != "./.github/workflows/ci.yml" {
		t.Errorf("checks job uses %q, want the same checks as ci.yml", checks.Uses)
	}
	build, deploy := w.Jobs["build"], w.Jobs["deploy"]
	if !build.needs("checks") {
		t.Error("build does not wait for the checks")
	}
	if !deploy.needs("build") {
		t.Error("deploy does not wait for the build")
	}

	// The image name is the one compose.yaml pulls, tagged with the commit SHA.
	c := readCompose(t, "compose.yaml")
	image := c.Services["featherauth"].Image
	image = regexp.MustCompile(`:\$\{FEATHERAUTH_TAG:\?[^}]*\}$`).ReplaceAllString(image, "")
	if image != "ghcr.io/yyudhistira/featherauth" {
		t.Fatalf("compose image = %q", image)
	}
	_, text := readWorkflow(t, "deploy.yml")
	if !strings.Contains(text, "IMAGE: "+image) {
		t.Errorf("deploy.yml does not use the image %s", image)
	}
	login := stepIndex(build, func(s workflowStep) bool { return strings.Contains(s.Run, "docker login ghcr.io") })
	bld := stepIndex(build, func(s workflowStep) bool { return strings.Contains(s.Run, "docker build") })
	push2 := stepIndex(build, func(s workflowStep) bool { return strings.Contains(s.Run, "docker push") })
	if login < 0 || bld < 0 || push2 < 0 || !(bld < push2 && login < push2) {
		t.Errorf("build steps: login %d, build %d, push %d; want login and build before push", login, bld, push2)
	}
	for _, s := range build.Steps {
		if s.If == tagOnly {
			continue // the tag build is checked in TestReleaseTagBuild
		}
		if strings.Contains(s.Run, "docker build") && !strings.Contains(s.Run, `"$IMAGE:${{ github.sha }}"`) &&
			!strings.Contains(s.Run, `"$IMAGE:$SHA"`) {
			t.Error("the image is not tagged with the commit SHA")
		}
	}

	_, wtext := readWorkflow(t, "deploy.yml")
	for _, want := range []string{"BatchMode=yes", "ConnectTimeout=15", "ServerAliveInterval=15", "StrictHostKeyChecking=yes",
		`""|-*|*[!ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_./-]*)`} {
		if !strings.Contains(wtext, want) {
			t.Errorf("deploy.yml lacks %q", want)
		}
	}
	if i, j := strings.Index(wtext, `*[!ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_./-]*)`), strings.Index(wtext, "ssh -i"); i < 0 || j < i {
		t.Error("DEPLOY_PATH is not validated before the ssh call")
	}
	ssh := stepIndex(deploy, func(s workflowStep) bool { return strings.Contains(s.Run, "deploy/ops/deploy-remote.sh") })
	if ssh < 0 {
		t.Error("deploy job does not run deploy/ops/deploy-remote.sh over ssh")
	}
}

// Acceptance: Deploy (part)
func TestWorkflowsPermissionsAndSecrets(t *testing.T) {
	for _, name := range []string{"ci.yml", "deploy.yml"} {
		w, text := readWorkflow(t, name)
		if len(w.Permissions) != 1 || w.Permissions["contents"] != "read" {
			t.Errorf("%s: top-level permissions = %v, want contents: read only", name, w.Permissions)
		}
		for jn, j := range w.Jobs {
			for k, v := range j.Permissions {
				if k == "packages" && v == "write" && !(name == "deploy.yml" && jn == "build") {
					t.Errorf("%s job %s has packages: write", name, jn)
				}
				// The last ci.yml job posts the commit status ci/tested-tree.
				if v == "write" && k != "packages" && !(name == "ci.yml" && jn == "record-tested-tree" && k == "statuses") &&
					!(name == "deploy.yml" && jn == "checks" && k == "statuses") &&
					!(name == "deploy.yml" && jn == "build" && (k == "id-token" || k == "attestations")) {
					t.Errorf("%s job %s has %s: write", name, jn, k)
				}
			}
		}
		if strings.Contains(text, "pull_request_target") {
			t.Errorf("%s uses pull_request_target", name)
		}
		// Every action is pinned by a full commit SHA.
		pin := regexp.MustCompile(`^[\w.-]+/[\w./-]+@[0-9a-f]{40}$`)
		for jn, j := range w.Jobs {
			for _, s := range j.Steps {
				if s.Uses != "" && !pin.MatchString(s.Uses) {
					t.Errorf("%s job %s: action %q is not pinned by SHA", name, jn, s.Uses)
				}
				// Secrets and the token reach a step only through env:, never inside a script,
				// and no step echoes them.
				if strings.Contains(s.Run, "${{ secrets.") || strings.Contains(s.Run, "${{ github.token") {
					t.Errorf("%s job %s: secret expanded inside a run script", name, jn)
				}
				if strings.Contains(s.Run, "set -x") || regexp.MustCompile(`echo[^\n]*\$\{?(SSH_KEY|DEPLOY_|TOKEN)`).MatchString(s.Run) {
					t.Errorf("%s job %s: a script may print a secret", name, jn)
				}
			}
		}
		for _, m := range regexp.MustCompile(`secrets\.(\w+)`).FindAllStringSubmatch(text, -1) {
			switch m[1] {
			case "GITHUB_TOKEN", "DEPLOY_HOST", "DEPLOY_USER", "DEPLOY_SSH_KEY", "DEPLOY_KNOWN_HOSTS":
			default:
				t.Errorf("%s uses secret %s: only SSH credentials are secrets", name, m[1])
			}
		}
	}
	w, _ := readWorkflow(t, "deploy.yml")
	if w.Jobs["build"].Permissions["packages"] != "write" {
		t.Error("build job cannot push to ghcr.io (packages: write)")
	}
	if len(w.Jobs["deploy"].Permissions) != 1 || w.Jobs["deploy"].Permissions["contents"] != "read" {
		t.Errorf("deploy job permissions = %v, want contents: read only", w.Jobs["deploy"].Permissions)
	}
}

// Acceptance: Deploy (part)
func TestDeployWorkflowDoesNotTouchConfig(t *testing.T) {
	_, text := readWorkflow(t, "deploy.yml")
	for _, bad := range []string{"scp ", "rsync", "config/", "FEATHERAUTH_CONFIG"} {
		if strings.Contains(text, bad) {
			t.Errorf("deploy.yml mentions %q: the deploy never touches the config directory", bad)
		}
	}
}

// fakeHost builds a PATH with a fake docker that records its calls, a fake date
// that advances one second per call and a fake sleep. The host's running tag is
// "old"; readiness succeeds only for the tags in okTags.
func fakeHost(t *testing.T, okTags string) (path, log string) {
	t.Helper()
	bin := t.TempDir()
	log = filepath.Join(bin, "calls.log")
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"+body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write("docker", `echo "tag=${FEATHERAUTH_TAG:-} $*" >> "`+log+`"
case "$*" in
  "compose ps -q featherauth") echo cid1 ;;
  "inspect --format {{.Config.Image}} cid1") echo "${FAKE_IMAGE-ghcr.io/yyudhistira/featherauth:old}" ;;
  "compose exec -T featherauth /featherauth healthcheck")
    for t in `+okTags+`; do [ "$t" = "$FEATHERAUTH_TAG" ] && exit 0; done
    exit 1 ;;
esac
exit 0
`)
	write("date", `f="`+bin+`/clock"; n=$(cat "$f" 2>/dev/null || echo 1000); echo $((n+1)) > "$f"; echo "$n"
`)
	write("sleep", "exit 0\n")
	return bin + ":" + os.Getenv("PATH"), log
}

func runRemote(t *testing.T, okTags string, env ...string) (string, string, error) {
	t.Helper()
	return runRemoteArgs(t, okTags, []string{"newsha", t.TempDir()}, env...)
}

func runRemoteArgs(t *testing.T, okTags string, args []string, env ...string) (string, string, error) {
	t.Helper()
	path, log := fakeHost(t, okTags)
	cmd := exec.CommandContext(t.Context(), "sh", append([]string{"ops/deploy-remote.sh"}, args...)...)
	cmd.Env = append(append(os.Environ(), "PATH="+path, "FEATHERAUTH_TAG="), env...)
	out, err := cmd.CombinedOutput()
	calls, _ := os.ReadFile(log)
	return string(out), string(calls), err
}

// Acceptance: Deploy (part)
func TestDeployRemoteSucceedsWhenReady(t *testing.T) {
	out, calls, err := runRemote(t, "newsha")
	if err != nil {
		t.Fatalf("deploy failed: %v\n%s", err, out)
	}
	for _, want := range []string{"tag=newsha compose pull", "tag=newsha compose up -d"} {
		if !strings.Contains(calls, want) {
			t.Errorf("missing call %q in\n%s", want, calls)
		}
	}
	if strings.Contains(calls, "tag=old compose up") {
		t.Errorf("rolled back although ready:\n%s", calls)
	}
}

// Acceptance: Deploy (part)
func TestDeployRemoteRollsBackToPreviousTagWhenNotReady(t *testing.T) {
	out, calls, err := runRemote(t, "old")
	if err == nil {
		t.Fatalf("deploy succeeded although the new tag never became ready\n%s", out)
	}
	up := strings.Index(calls, "tag=newsha compose up -d")
	back := strings.Index(calls, "tag=old compose up -d")
	if up < 0 || back < up {
		t.Errorf("want up with newsha then up with the previous tag old:\n%s", calls)
	}
	if !strings.Contains(out, "rolled back to old") {
		t.Errorf("output does not say the rollback worked:\n%s", out)
	}
}

// Acceptance: Deploy (part)
func TestDeployRemoteFailsWhenRollbackIsNotReadyEither(t *testing.T) {
	out, _, err := runRemote(t, "")
	if err == nil || !strings.Contains(out, "rollback to old is not ready") {
		t.Errorf("want failure naming the failed rollback, got %v\n%s", err, out)
	}
}

// The fake date advances one second per call, so the number of readiness
// polls before the rollback measures the wait in fake seconds.
//
// Acceptance: Deploy (part)
func TestDeployRemoteWaitsAbout30SecondsBeforeRollback(t *testing.T) {
	_, calls, err := runRemote(t, "old")
	if err == nil {
		t.Fatal("deploy succeeded")
	}
	before, _, ok := strings.Cut(calls, "tag=old compose up -d")
	if !ok {
		t.Fatalf("no rollback:\n%s", calls)
	}
	polls := strings.Count(before, "tag=newsha compose exec")
	if polls < 25 || polls > 35 {
		t.Errorf("the new tag was polled %d times before the rollback, want about 30 (one per second)", polls)
	}
}

// Acceptance: Deploy (part)
func TestDeployRemoteStopsPollingOnceReady(t *testing.T) {
	_, calls, err := runRemote(t, "newsha")
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(calls, "compose exec"); n != 1 {
		t.Errorf("polled %d times, want 1 when ready at once", n)
	}
}

// The deploy only pulls, starts, polls and reads the running tag; it never
// removes containers or volumes, and the script never names the config directory.
//
// Acceptance: Deploy (part)
func TestDeployRemoteTouchesNothingButTheStack(t *testing.T) {
	for _, tags := range []string{"newsha", "old", ""} {
		_, calls, _ := runRemote(t, tags)
		for _, line := range strings.Split(strings.TrimSpace(calls), "\n") {
			_, cmd, _ := strings.Cut(line, " ")
			switch {
			case cmd == "compose pull", cmd == "compose up -d", cmd == "compose ps -q featherauth",
				cmd == "compose exec -T featherauth /featherauth healthcheck",
				cmd == "inspect --format {{.Config.Image}} cid1":
			default:
				t.Errorf("tags %q: unexpected docker call %q", tags, cmd)
			}
		}
	}
	s := readFile(t, "ops/deploy-remote.sh")
	for _, bad := range []string{"compose down", " rm ", "volume", "prune", "FEATHERAUTH_CONFIG", "/etc/featherauth", "config/", "compose.yaml >"} {
		if strings.Contains(s, bad) {
			t.Errorf("deploy-remote.sh contains %q", bad)
		}
	}
}

// Acceptance: Deploy (part)
func TestDeployRemoteRejectsUnsafeArguments(t *testing.T) {
	good := t.TempDir()
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"space in directory", []string{"newsha", "/a b"}},
		{"semicolon", []string{"newsha", "/a;id"}},
		{"command substitution", []string{"newsha", "$(id)"}},
		{"backtick", []string{"newsha", "/a`id`"}},
		{"empty directory", []string{"newsha", ""}},
		{"option-like directory", []string{"newsha", "-x"}},
		{"newline", []string{"newsha", "/a\nb"}},
		{"tag with slash", []string{"a/b", good}},
		{"empty tag", []string{"", good}},
		{"tag with space", []string{"a b", good}},
		{"one argument", []string{"newsha"}},
		{"three arguments", []string{"newsha", good, "x"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, calls, err := runRemoteArgs(t, "newsha", tc.args)
			var ee *exec.ExitError
			if !errors.As(err, &ee) || ee.ExitCode() != 2 {
				t.Errorf("err = %v, want exit 2\n%s", err, out)
			}
			if calls != "" {
				t.Errorf("docker was called:\n%s", calls)
			}
		})
	}
}

// A previous image that is not a name:tag reference gives no rollback target.
//
// Acceptance: Deploy (part)
func TestDeployRemoteNeedsATagForRollback(t *testing.T) {
	for _, image := range []string{
		"ghcr.io/yyudhistira/featherauth@sha256:" + strings.Repeat("a", 64),
		"ghcr.io/yyudhistira/featherauth:v1@sha256:" + strings.Repeat("a", 64),
		"ghcr.io/yyudhistira/featherauth",
		"localhost:5000/featherauth",
		"sha256:" + strings.Repeat("b", 64),
		"",
	} {
		out, calls, err := runRemote(t, "old", "FAKE_IMAGE="+image)
		if err == nil || !strings.Contains(out, "no previous tag") {
			t.Errorf("image %q: err %v, output %q; want failure without a rollback", image, err, out)
		}
		if strings.Count(calls, "compose up -d") != 1 {
			t.Errorf("image %q: rolled back to something:\n%s", image, calls)
		}
	}
}

const (
	tagOnly    = "${{ github.ref_type == 'tag' }}"
	branchOnly = "${{ github.ref_type == 'branch' }}"
)

// githubFilterMatch reads a GitHub tag filter as GitHub does: the whole name
// must match; "[0-9]" is a character class, "+" means one or more of the item
// before it and "." is a literal dot.
func githubFilterMatch(filter, name string) bool {
	var re strings.Builder
	re.WriteString("^")
	for i := 0; i < len(filter); i++ {
		switch c := filter[i]; c {
		case '[':
			j := strings.IndexByte(filter[i:], ']')
			if j < 0 {
				return false
			}
			re.WriteString(filter[i : i+j+1])
			i += j
		case '+':
			re.WriteString("+")
		case '.':
			re.WriteString(`\.`)
		default:
			re.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	re.WriteString("$")
	return regexp.MustCompile(re.String()).MatchString(name)
}

func tagFilter(t *testing.T, w workflow) string {
	t.Helper()
	push, _ := w.On["push"].(map[string]any)
	tags, _ := push["tags"].([]any)
	if len(tags) != 1 {
		t.Fatalf("deploy.yml push tags = %v, want one filter", push["tags"])
	}
	f, _ := tags[0].(string)
	return f
}

// Proves OPS-01, OPS-02 (release tag): see the pass conditions of the row; OPS ids are not traced.
// Acceptance: Release tag
func TestReleaseTagTriggers(t *testing.T) {
	w, _ := readWorkflow(t, "deploy.yml")
	if len(w.On) != 1 {
		t.Errorf("deploy.yml has triggers beyond push: %v", w.On)
	}
	push, ok := w.On["push"].(map[string]any)
	if !ok {
		t.Fatal("deploy.yml does not run on push")
	}
	if b, _ := push["branches"].([]any); len(b) != 1 || b[0] != "main" {
		t.Errorf("push branches = %v, want [main]", push["branches"])
	}
	if len(push) != 2 {
		t.Errorf("push has keys beyond branches and tags: %v", push)
	}
	f := tagFilter(t, w)
	for _, n := range []string{"v0.2.0", "v10.20.30", "v0.0.0"} {
		if !githubFilterMatch(f, n) {
			t.Errorf("filter %q does not match %q", f, n)
		}
	}
	for _, n := range []string{"v1.0", "v0.2.0-rc1", "0.2.0", "v0.2.0.1", "v0.2", "v", "v0.2.x", "xv0.2.0"} {
		if githubFilterMatch(f, n) {
			t.Errorf("filter %q matches %q", f, n)
		}
	}
	if want := "v[0-9]+.[0-9]+.[0-9]+"; f != want {
		t.Errorf("filter = %q, want %q", f, want)
	}
}

// Proves OPS-01, OPS-02 (release tag): see the pass conditions of the row; OPS ids are not traced.
// Acceptance: Release tag (part)
func TestReleaseTagBuild(t *testing.T) {
	w, _ := readWorkflow(t, "deploy.yml")
	build := w.Jobs["build"]
	var tagBuilds, branchBuilds int
	for _, s := range build.Steps {
		if !strings.Contains(s.Run, "docker build") && !strings.Contains(s.Run, "docker push") {
			continue
		}
		switch s.If {
		case tagOnly:
			if strings.Contains(s.Run, "latest") || strings.Contains(s.Run, "$SHA") {
				t.Errorf("tag step %q uses latest or the SHA: %s", s.Name, s.Run)
			}
			if strings.Contains(s.Run, "docker build") {
				tagBuilds++
				if !strings.Contains(s.Run, `--build-arg "VERSION=$REF_NAME"`) || !strings.Contains(s.Run, `-t "$IMAGE:$REF_NAME"`) {
					t.Errorf("tag build must set VERSION and the image tag to the tag name: %s", s.Run)
				}
			} else if !strings.Contains(s.Run, `docker push "$IMAGE:$REF_NAME"`) {
				t.Errorf("tag push must push the tag name only: %s", s.Run)
			}
			if s.Env["REF_NAME"] != "${{ github.ref_name }}" {
				t.Errorf("tag step %q takes the tag name from %q", s.Name, s.Env["REF_NAME"])
			}
		case branchOnly:
			if strings.Contains(s.Run, "docker build") {
				branchBuilds++
				if !strings.Contains(s.Run, `--build-arg "VERSION=$SHA"`) || !strings.Contains(s.Run, `-t "$IMAGE:$SHA"`) {
					t.Errorf("main build must keep VERSION and the tag at the SHA: %s", s.Run)
				}
			}
			if strings.Contains(s.Run, "REF_NAME") || strings.Contains(s.Run, "latest") {
				t.Errorf("main step %q uses the tag name or latest: %s", s.Name, s.Run)
			}
		default:
			t.Errorf("step %q builds or pushes without a ref_type condition", s.Name)
		}
	}
	if tagBuilds != 1 || branchBuilds != 1 {
		t.Errorf("builds: tag %d, branch %d, want one each", tagBuilds, branchBuilds)
	}
}

// Proves OPS-01, OPS-02 (release tag): see the pass conditions of the row; OPS ids are not traced.
// Acceptance: Release tag (part)
func TestReleaseTagMustBeOnMain(t *testing.T) {
	w, _ := readWorkflow(t, "deploy.yml")
	build := w.Jobs["build"]
	if len(build.Steps) == 0 || !strings.HasPrefix(build.Steps[0].Uses, "actions/checkout@") {
		t.Fatal("build does not start with checkout")
	}
	if d := build.Steps[0].With["fetch-depth"]; d != "0" {
		t.Errorf("build checkout fetch-depth = %q, want 0 (the ancestor check needs history)", d)
	}
	if build.Steps[0].With["persist-credentials"] != "false" {
		t.Error("build checkout keeps credentials")
	}
	check := stepIndex(build, func(s workflowStep) bool {
		return strings.Contains(s.Run, `git merge-base --is-ancestor "$SHA" refs/remotes/origin/main`)
	})
	if check < 0 {
		t.Fatal("no ancestor check in the build job")
	}
	if build.Steps[check].If != tagOnly {
		t.Errorf("ancestor check runs with if %q, want tags only", build.Steps[check].If)
	}
	if build.Steps[check].Env["SHA"] == "" && w.Jobs["build"].Env["SHA"] == "" {
		t.Error("ancestor check has no SHA")
	}
	for i, s := range build.Steps {
		if (strings.Contains(s.Run, "docker build") || strings.Contains(s.Run, "docker push") ||
			strings.Contains(s.Run, "docker login")) && i < check {
			t.Errorf("step %d (%q) runs before the ancestor check (%d)", i, s.Name, check)
		}
	}
}

// Proves OPS-01, OPS-02 (release tag): see the pass conditions of the row; OPS ids are not traced.
// Acceptance: Release tag (part)
func TestReleaseTagNeverDeploys(t *testing.T) {
	w, _ := readWorkflow(t, "deploy.yml")
	if got := w.Jobs["deploy"].If; !strings.Contains(got, "github.ref_type == 'branch'") ||
		!strings.Contains(got, "vars.DEPLOY_PATH != ''") || !strings.Contains(got, "&&") || strings.Contains(got, "||") {
		t.Errorf("deploy job if = %q, want DEPLOY_PATH and a branch ref, joined by &&", got)
	}
}

// Proves OPS-01, OPS-02 (release tag): see the pass conditions of the row; OPS ids are not traced.
// Acceptance: Release tag (part)
// A tag name is chosen by whoever pushes it: it reaches a script only as an
// environment variable.
func TestWorkflowRefsNotInterpolatedInScripts(t *testing.T) {
	for _, name := range []string{"ci.yml", "deploy.yml"} {
		w, _ := readWorkflow(t, name)
		for jn, j := range w.Jobs {
			for _, s := range j.Steps {
				if strings.Contains(s.Run, "${{") {
					t.Errorf("%s job %s step %q interpolates ${{ }} inside run: %s", name, jn, s.Name, s.Run)
				}
			}
		}
	}
}

// A new push to a pull request cancels the older still-running ci run of that
// pull request; nothing else is cancelled. deploy.yml calls ci.yml, and there
// github.event_name is the caller's event (push), so the called run is never
// cancelled and its group is built from the event name and the unique run id,
// so it is not the "deploy" group of the caller and a run id cannot equal a
// pull request group. Observed on a real run on 2026-11-13
// (docs/DESIGN.md, the row Repeated checks).
func TestCIConcurrencyCancelsOnlySupersededPullRequestRuns(t *testing.T) {
	w, text := readWorkflow(t, "ci.yml")
	c := w.Concurrency
	const wantGroup = "ci-${{ github.event_name }}-${{ github.event.pull_request.number || github.run_id }}"
	if got := strings.Join(strings.Fields(c.Group), " "); got != wantGroup {
		t.Errorf("ci.yml concurrency group = %q, want %q", got, wantGroup)
	}
	for jn, j := range w.Jobs {
		if j.Concurrency != nil {
			t.Errorf("ci.yml job %s has its own concurrency: %v", jn, j.Concurrency)
		}
	}
	if !strings.Contains(c.Group, "github.event.pull_request.number") {
		t.Errorf("ci.yml concurrency group %q does not include the pull request number", c.Group)
	}
	if !strings.Contains(c.Group, "github.run_id") {
		t.Errorf("ci.yml concurrency group %q has no per-run fallback (github.run_id)", c.Group)
	}
	if c.Group == "deploy" || strings.HasPrefix(c.Group, "deploy") {
		t.Errorf("ci.yml concurrency group %q can collide with the deploy group", c.Group)
	}
	cancel, ok := c.CancelInProgress.(string)
	if !ok {
		t.Fatalf("ci.yml cancel-in-progress = %#v, want an expression on github.event_name", c.CancelInProgress)
	}
	if got, want := strings.Join(strings.Fields(cancel), " "), "${{ github.event_name == 'pull_request' }}"; got != want {
		t.Errorf("ci.yml cancel-in-progress = %q, want %q", got, want)
	}
	// Outside the record-tested-tree job only the pull request number, the run id
	// and the event name may be interpolated; the job itself (env: and if:) may
	// also use the five values below, nothing else.
	head, job, found := strings.Cut(text, "\n  record-tested-tree:")
	if !found {
		t.Fatal("ci.yml has no record-tested-tree job")
	}
	// The changes job (first in the file, before scan) passes more
	// values to its script through env: and reads one more in its output.
	pre, rest, found := strings.Cut(head, "\n  changes:")
	if !found {
		t.Fatal("ci.yml has no changes job")
	}
	changes, post, found := strings.Cut(rest, "\n  scan:")
	if !found {
		t.Fatal("ci.yml has no scan job after changes")
	}
	head = pre + post
	scan := func(part string, allowed ...string) {
		for _, m := range regexp.MustCompile(`\$\{\{(.*?)\}\}`).FindAllStringSubmatch(part, -1) {
			for _, ref := range regexp.MustCompile(`github\.[A-Za-z_.]+`).FindAllString(m[1], -1) {
				ok := false
				for _, a := range allowed {
					ok = ok || ref == a
				}
				if !ok {
					t.Errorf("ci.yml interpolates %q where it is not allowed", ref)
				}
			}
		}
	}
	scan(head, "github.event.pull_request.number", "github.run_id", "github.event_name")
	scan(changes, "github.event_name", "github.repository", "github.event.pull_request.base.sha", "github.event.pull_request.head.sha", "github.token")
	scan(job, "github.event_name", "github.sha", "github.repository", "github.token", "github.event.pull_request.head.sha")
}

func TestDeployConcurrencyAndChecksCallUnchanged(t *testing.T) {
	w, _ := readWorkflow(t, "deploy.yml")
	if w.Concurrency.Group != "deploy" || w.Concurrency.CancelInProgress != false {
		t.Errorf("deploy.yml concurrency = %#v, want group deploy and cancel-in-progress false", w.Concurrency)
	}
	if got := w.Jobs["checks"].Uses; got != "./.github/workflows/ci.yml" {
		t.Errorf("checks job uses %q", got)
	}
}

// A tiny evaluator for the subset of GitHub expressions the deploy build
// condition uses: !cancelled(), needs.<job>.result, needs.<job>.outputs.<name>,
// string literals, == != && || ! and parentheses. Anything else is an error, so
// a changed condition that uses more has to extend the evaluator on purpose.
type exprCtx struct {
	runCancelled bool
	results      map[string]string // needs.<job>.result
	outputs      map[string]string // needs.<job>.outputs.<name>, key "job.name"
	vals         map[string]string // other dotted names, such as vars.DEPLOY_PATH, github.ref_type, steps.<id>.outputs.<name>; unset ones are errors
}

type exprParser struct {
	toks []string
	pos  int
	ctx  exprCtx
	err  error
}

func evalExpr(expr string, ctx exprCtx) (bool, error) {
	expr = strings.TrimSpace(expr)
	expr = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(expr, "${{"), "}}"))
	var toks []string
	for rest := expr; strings.TrimSpace(rest) != ""; {
		m := regexp.MustCompile(`^\s*(&&|\|\||==|!=|!|\(|\)|'[^']*'|[A-Za-z_][A-Za-z0-9_.\-]*(?:\(\))?)`).FindStringSubmatch(rest)
		if m == nil {
			return false, errors.New("cannot parse near " + rest)
		}
		toks = append(toks, m[1])
		rest = rest[len(m[0]):]
	}
	p := &exprParser{toks: toks, ctx: ctx}
	v := p.or()
	if p.err == nil && p.pos != len(p.toks) {
		p.err = errors.New("trailing tokens")
	}
	if p.err != nil {
		return false, p.err
	}
	return v == "true", nil
}

func (p *exprParser) peek() string {
	if p.pos < len(p.toks) {
		return p.toks[p.pos]
	}
	return ""
}

func (p *exprParser) or() string {
	v := p.and()
	for p.peek() == "||" {
		p.pos++
		r := p.and()
		if v == "true" || r == "true" {
			v = "true"
		} else {
			v = "false"
		}
	}
	return v
}

func (p *exprParser) and() string {
	v := p.cmp()
	for p.peek() == "&&" {
		p.pos++
		r := p.cmp()
		if v == "true" && r == "true" {
			v = "true"
		} else {
			v = "false"
		}
	}
	return v
}

func (p *exprParser) cmp() string {
	l := p.unary()
	if op := p.peek(); op == "==" || op == "!=" {
		p.pos++
		r := p.unary()
		eq := strings.EqualFold(l, r) // GitHub compares strings case-insensitively
		if (op == "==") == eq {
			return "true"
		}
		return "false"
	}
	return l
}

func (p *exprParser) unary() string {
	tok := p.peek()
	p.pos++
	switch {
	case tok == "!":
		if p.unary() == "true" {
			return "false"
		}
		return "true"
	case tok == "(":
		v := p.or()
		if p.peek() != ")" {
			p.err = errors.New("missing )")
		}
		p.pos++
		return v
	case tok == "cancelled()":
		if p.ctx.runCancelled {
			return "true"
		}
		return "false"
	case strings.HasPrefix(tok, "'"):
		return tok[1 : len(tok)-1]
	case p.ctx.vals != nil && hasKey(p.ctx.vals, tok):
		return p.ctx.vals[tok]
	case strings.HasPrefix(tok, "needs."):
		parts := strings.Split(tok, ".")
		switch {
		case len(parts) == 3 && parts[2] == "result":
			if v, ok := p.ctx.results[parts[1]]; ok {
				return v
			}
		case len(parts) == 4 && parts[2] == "outputs":
			return p.ctx.outputs[parts[1]+"."+parts[3]] // an unset output is ""
		}
	}
	p.err = errors.New("unsupported token " + tok)
	return ""
}

func hasKey(m map[string]string, k string) bool { _, ok := m[k]; return ok }

// jobRuns is GitHub's rule for a job with needs: without a status function in its
// if, success() is added (all needed jobs must have succeeded); with one, the if
// alone decides.
func jobRuns(t *testing.T, j workflowJob, needs []string, ctx exprCtx) bool {
	t.Helper()
	hasStatus := strings.Contains(j.If, "cancelled()")
	if !hasStatus { // implicit success()
		if ctx.runCancelled {
			return false
		}
		for _, n := range needs {
			if ctx.results[n] != "success" {
				return false
			}
		}
	}
	if j.If == "" {
		return true
	}
	v, err := evalExpr(j.If, ctx)
	if err != nil {
		t.Fatalf("condition %q: %v", j.If, err)
	}
	return v
}

// Proves OPS-02 (repeated checks): see the pass conditions of the row; OPS ids are not traced.
// Acceptance: Repeated checks (part)
func TestDeployTestedJob(t *testing.T) {
	w, _ := readWorkflow(t, "deploy.yml")
	j, ok := w.Jobs["tested"]
	if !ok {
		t.Fatal("deploy.yml has no tested job")
	}
	if j.RunsOn != runnerExpr {
		t.Errorf("tested runs on %q", j.RunsOn)
	}
	want := map[string]string{"contents": "read", "pull-requests": "read", "statuses": "read", "actions": "read"}
	if len(j.Permissions) != len(want) {
		t.Errorf("tested permissions = %v, want exactly %v", j.Permissions, want)
	}
	for k, v := range want {
		if j.Permissions[k] != v {
			t.Errorf("tested permission %s = %q, want %q", k, j.Permissions[k], v)
		}
	}
	if j.Needs != nil {
		t.Errorf("tested has needs %v; it is the first job", j.Needs)
	}
	if len(j.Steps) == 0 || !strings.HasPrefix(j.Steps[0].Uses, "actions/checkout@") ||
		j.Steps[0].With["persist-credentials"] != "false" {
		t.Error("tested must start with a checkout that does not persist credentials")
	}
	i := stepIndex(j, func(s workflowStep) bool { return s.Run == `sh deploy/ops/tested-tree.sh "$REPO" "$SHA" "$MODE"` })
	if i < 0 {
		t.Fatal(`tested does not run sh deploy/ops/tested-tree.sh "$REPO" "$SHA" "$MODE"`)
	}
	s := j.Steps[i]
	for k, v := range map[string]string{
		"REPO": "${{ github.repository }}", "SHA": "${{ github.sha }}",
		"MODE": "${{ github.ref_type }}", "GH_TOKEN": "${{ github.token }}",
	} {
		if s.Env[k] != v {
			t.Errorf("tested env %s = %q, want %q", k, s.Env[k], v)
		}
	}
	if s.ID == "" || s.If != "" || s.ContinueOnError {
		t.Errorf("the script step needs an id, no if and no continue-on-error: %+v", s)
	}
	// Skip is true for the tree match (the tree check) or for a documentation-only
	// commit (the docs step); proved by TestDeployTestedOutputs.
	if got, want := j.Outputs["skip"], "${{ steps."+s.ID+".outputs.skip == 'true' || steps.docs.outputs.docs_only == 'true' }}"; got != want {
		t.Errorf("tested output skip = %q, want %q", got, want)
	}
	// The summary line is written only when skipping.
	sum := stepIndex(j, func(s workflowStep) bool { return strings.Contains(s.Run, "GITHUB_STEP_SUMMARY") })
	if sum < 0 {
		t.Fatal("tested writes no job summary")
	}
	if got, want := j.Steps[sum].If, "${{ steps."+s.ID+".outputs.skip == 'true' }}"; got != want {
		t.Errorf("summary step if = %q, want %q", got, want)
	}
	if !strings.Contains(j.Steps[sum].Run, "skipped") {
		t.Error("the summary does not say the checks were skipped")
	}
	if sum < i {
		t.Error("the summary is written before the decision")
	}
}

// Proves OPS-02 (repeated checks): see the pass conditions of the row; OPS ids are not traced.
// Acceptance: Repeated checks
func TestDeployChecksAndBuildConditions(t *testing.T) {
	w, _ := readWorkflow(t, "deploy.yml")
	checks, build, deploy := w.Jobs["checks"], w.Jobs["build"], w.Jobs["deploy"]
	if checks.Uses != "./.github/workflows/ci.yml" {
		t.Errorf("checks uses %q", checks.Uses)
	}
	if !checks.needs("tested") || !build.needs("tested") || !build.needs("checks") {
		t.Errorf("needs: checks %v, build %v", checks.Needs, build.Needs)
	}
	if got, want := checks.If, "${{ needs.tested.outputs.skip != 'true' }}"; got != want {
		t.Errorf("checks if = %q, want %q", got, want)
	}
	if !strings.Contains(build.If, "!cancelled()") {
		t.Errorf("build if %q has no !cancelled()", build.If)
	}
	// Deploy also needs tested (its docs_only output); the condition is
	// proved by TestDeployJobConditionTable.
	if !deploy.needs("build") || !deploy.needs("tested") || deploy.If != "${{ !cancelled() && needs.tested.result == 'success' && needs.build.result == 'success' && vars.DEPLOY_PATH != '' && github.ref_type == 'branch' && needs.tested.outputs.docs_only != 'true' }}" {
		t.Errorf("deploy changed: needs %v if %q", deploy.Needs, deploy.If)
	}

	// All combinations.
	results := []string{"success", "failure", "cancelled", "skipped"}
	for _, testedRes := range results {
		for _, skip := range []string{"true", "false", ""} {
			for _, checksRes := range results {
				for _, runCancelled := range []bool{false, true} {
					ctx := exprCtx{
						runCancelled: runCancelled,
						results:      map[string]string{"tested": testedRes, "checks": checksRes},
						outputs:      map[string]string{"tested.skip": skip},
					}
					// The checks job's own result is given; here the condition of
					// checks itself is checked against the tested job.
					checksRan := jobRuns(t, checks, []string{"tested"}, ctx)
					wantChecksRan := testedRes == "success" && !runCancelled && skip != "true"
					if checksRan != wantChecksRan {
						t.Errorf("checks runs = %v with tested %s, skip %q, cancelled %v; want %v",
							checksRan, testedRes, skip, runCancelled, wantChecksRan)
					}
					got := jobRuns(t, build, []string{"tested", "checks"}, ctx)
					want := !runCancelled && testedRes == "success" &&
						(checksRes == "success" || (checksRes == "skipped" && skip == "true"))
					if got != want {
						t.Errorf("build runs = %v with tested %s, skip %q, checks %s, cancelled %v; want %v",
							got, testedRes, skip, checksRes, runCancelled, want)
					}
				}
			}
		}
	}
	// The named cases of the design.
	for _, tc := range []struct {
		name         string
		tested, skip string
		checks       string
		want         bool
	}{
		{"checks passed", "success", "false", "success", true},
		{"checks failed", "success", "false", "failure", false},
		{"checks cancelled", "success", "false", "cancelled", false},
		{"skipped without skip=true", "success", "false", "skipped", false},
		{"skipped with an empty output", "success", "", "skipped", false},
		{"skipped with skip=true", "success", "true", "skipped", true},
		{"tested failed", "failure", "", "skipped", false},
		{"checks failed although skip=true", "success", "true", "failure", false},
	} {
		ctx := exprCtx{results: map[string]string{"tested": tc.tested, "checks": tc.checks}, outputs: map[string]string{"tested.skip": tc.skip}}
		if got := jobRuns(t, build, []string{"tested", "checks"}, ctx); got != tc.want {
			t.Errorf("%s: build runs = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// The evaluator itself must tell the truth, or the table above proves nothing.
func TestExprEvaluator(t *testing.T) {
	ctx := exprCtx{results: map[string]string{"a": "success"}, outputs: map[string]string{"a.x": "true"}}
	for expr, want := range map[string]bool{
		"${{ needs.a.result == 'success' }}":                                   true,
		"${{ needs.a.result != 'success' }}":                                   false,
		"${{ !cancelled() }}":                                                  true,
		"${{ !cancelled() && needs.a.outputs.x == 'true' }}":                   true,
		"${{ needs.a.result == 'x' || (needs.a.outputs.x == 'true') }}":        true,
		"${{ needs.a.result == 'x' || needs.a.outputs.x == 'false' }}":         false,
		"${{ needs.a.outputs.missing == '' }}":                                 true,
		"${{ needs.a.result == 'x' && (needs.a.result == 'success') }}":        false,
		"${{ !(needs.a.result == 'success') || needs.a.result == 'success' }}": true,
	} {
		got, err := evalExpr(expr, ctx)
		if err != nil || got != want {
			t.Errorf("%s = %v, %v; want %v", expr, got, err, want)
		}
	}
	for _, bad := range []string{"${{ github.ref == 'x' }}", "${{ needs.zz.result == 'x' }}", "${{ ( }}", "${{ a b }}"} {
		if _, err := evalExpr(bad, ctx); err == nil {
			t.Errorf("%s: no error", bad)
		}
	}
}

// Proves OPS-02 (repeated checks): see the pass conditions of the row; OPS ids are not traced.
// Acceptance: Repeated checks (part)
func TestCIRecordTestedTree(t *testing.T) {
	w, _ := readWorkflow(t, "ci.yml")
	j, ok := w.Jobs["record-tested-tree"]
	if !ok {
		t.Fatal("ci.yml has no record-tested-tree job")
	}
	// It also needs changes and scan, so that it cannot run when a test job
	// was skipped as documentation-only (TestCIRecordsOnlyAfterEveryJobRan).
	for _, n := range []string{"changes", "scan", "check", "browser", "ops", "postgres"} {
		if !j.needs(n) {
			t.Errorf("record-tested-tree does not need %s", n)
		}
	}
	if n, ok := j.Needs.([]any); !ok || len(n) != 6 {
		t.Errorf("needs = %v, want exactly the six jobs", j.Needs)
	}
	if got, want := j.If, "${{ github.event_name == 'pull_request' }}"; got != want {
		t.Errorf("if = %q, want %q", got, want)
	}
	if len(j.Permissions) != 2 || j.Permissions["contents"] != "read" || j.Permissions["statuses"] != "write" {
		t.Errorf("permissions = %v, want exactly contents: read and statuses: write", j.Permissions)
	}
	if j.RunsOn != runnerExpr {
		t.Errorf("runs-on = %q", j.RunsOn)
	}
	if j.Concurrency != nil {
		t.Error("the job has its own concurrency")
	}
	if len(j.Steps) != 2 || !strings.HasPrefix(j.Steps[0].Uses, "actions/checkout@") ||
		j.Steps[0].With["persist-credentials"] != "false" {
		t.Fatalf("want a checkout without persisted credentials and one more step: %+v", j.Steps)
	}
	if j.Steps[0].With["ref"] != "${{ github.sha }}" {
		t.Errorf("checkout ref = %q, want the commit of the run (${{ github.sha }})", j.Steps[0].With["ref"])
	}
	s := j.Steps[1]
	if !s.ContinueOnError {
		t.Error("the status step must have continue-on-error: true (an optimisation, it must not fail the run)")
	}
	if s.If != "" {
		t.Errorf("status step has if %q", s.If)
	}
	for k, v := range map[string]string{
		"REPO": "${{ github.repository }}", "HEAD_SHA": "${{ github.event.pull_request.head.sha }}",
		"GH_TOKEN": "${{ github.token }}", "SHA": "${{ github.sha }}",
	} {
		if s.Env[k] != v {
			t.Errorf("env %s = %q, want %q", k, s.Env[k], v)
		}
	}
	for _, want := range []string{
		"tree=$(git rev-parse \"HEAD^{tree}\")",
		`gh api "repos/$REPO/statuses/$HEAD_SHA" -f state=success -f context=ci/tested-tree -f description="$tree"`,
	} {
		if !strings.Contains(s.Run, want) {
			t.Errorf("status step lacks %q:\n%s", want, s.Run)
		}
	}
	if strings.Contains(s.Run, "${{") {
		t.Error("an expression is interpolated inside run:")
	}
	cmp := strings.Index(s.Run, `[ "$(git rev-parse HEAD)" != "$SHA" ]`)
	post := strings.Index(s.Run, "gh api")
	if cmp < 0 || post < 0 || cmp > post {
		t.Errorf("the step must compare HEAD with SHA before the gh api call:\n%s", s.Run)
	}
	if !strings.Contains(s.Run, "exit 0") || !strings.Contains(s.Run, ">&2") {
		t.Errorf("a mismatch must print a reason to stderr and exit 0:\n%s", s.Run)
	}
	// The job is last: nothing in ci.yml needs it.
	for jn, o := range w.Jobs {
		if o.needs("record-tested-tree") {
			t.Errorf("job %s needs record-tested-tree", jn)
		}
	}
}

// Only the checks job of deploy.yml (the caller of ci.yml) may have permissions
// of its own, and exactly contents: read, statuses: write and (for the
// changes job of ci.yml) pull-requests: read. The other jobs of
// deploy.yml are covered by their own tests.
//
// Proves OPS-02 (repeated checks): see the pass conditions of the row; OPS ids are not traced.
// Acceptance: Repeated checks (part)
func TestDeployChecksPermissionsAreNarrow(t *testing.T) {
	w, _ := readWorkflow(t, "deploy.yml")
	got := w.Jobs["checks"].Permissions
	if len(got) != 3 || got["contents"] != "read" || got["statuses"] != "write" || got["pull-requests"] != "read" {
		t.Errorf("checks permissions = %v, want exactly contents: read, statuses: write and pull-requests: read", got)
	}
	for jn, j := range w.Jobs {
		switch jn {
		case "checks", "build", "deploy", "tested": // build, deploy and tested are asserted by their own tests
		default:
			if len(j.Permissions) != 0 {
				t.Errorf("deploy.yml job %s has permissions %v", jn, j.Permissions)
			}
		}
	}
}

// A called workflow cannot request more than its caller grants, and GitHub
// checks this before the job's if: every permission of every ci.yml job must be
// within what the checks job of deploy.yml grants.
//
// Proves OPS-02 (repeated checks): see the pass conditions of the row; OPS ids are not traced.
// Acceptance: Repeated checks (part)
func TestCIPermissionsWithinWhatDeployChecksGrants(t *testing.T) {
	rank := map[string]int{"none": 0, "read": 1, "write": 2}
	ci, _ := readWorkflow(t, "ci.yml")
	dep, _ := readWorkflow(t, "deploy.yml")
	grant := dep.Jobs["checks"].Permissions
	if len(grant) == 0 {
		t.Fatal("the checks job of deploy.yml grants nothing of its own")
	}
	for jn, j := range ci.Jobs {
		perms := j.Permissions
		if len(perms) == 0 {
			perms = ci.Permissions // a job without permissions gets the workflow's
		}
		for k, v := range perms {
			if _, ok := rank[v]; !ok {
				t.Errorf("ci.yml job %s: unknown level %q for %s", jn, v, k)
			}
			if rank[v] > rank[grant[k]] {
				t.Errorf("ci.yml job %s requests %s: %s, but deploy.yml's checks job grants %q", jn, k, v, grant[k])
			}
		}
	}
	for k, v := range ci.Permissions {
		if rank[v] > rank[grant[k]] {
			t.Errorf("ci.yml requests %s: %s, deploy.yml's checks grants %q", k, v, grant[k])
		}
	}
}

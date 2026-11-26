//go:build ops

package deploy_test

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/testutil/mockidp"
)

// The images of the upgrade tests. NEW_IMAGE is the candidate: unset, the
// working tree is built. PREV_IMAGE is the previous release: unset, the newest
// release tag of the repository is built from a git worktree (a release image
// that was never published can still be tested; release-check.sh pulls the
// published one and sets PREV_IMAGE). The decision is previousRelease.
var (
	candidateOnce sync.Once
	candidateName string
	candidateErr  error
	previousOnce  sync.Once
	previousName  string
	previousErr   error
)

func dockerBuild(dir, tag string, args ...string) error {
	cmd := exec.Command("docker", append([]string{"build", "-q", "-f", "deploy/Dockerfile", "-t", tag}, append(args, ".")...)...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("docker build %s: %v\n%s", tag, err, out)
	}
	return nil
}

// candidateImage is NEW_IMAGE, or the image built from the working tree.
func candidateImage(t *testing.T) string {
	t.Helper()
	candidateOnce.Do(func() {
		candidateName = os.Getenv("NEW_IMAGE")
		if candidateName == "" {
			candidateName = "featherauth-ci-upgrade-new:local"
			candidateErr = dockerBuild("..", candidateName)
		}
	})
	if candidateErr != nil {
		t.Fatal(candidateErr)
	}
	return candidateName
}

// previousImage is PREV_IMAGE, or the image built from the newest release tag.
// With neither, and a full checkout, the test skips: there is nothing to upgrade
// from. A shallow checkout fails (previousRelease), and so does every other error.
func previousImage(t *testing.T) string {
	t.Helper()
	previousOnce.Do(func() {
		image, tag, err := previousRelease("..", os.Getenv("PREV_IMAGE"))
		if err != nil {
			previousErr = err
			return
		}
		if image != "" {
			previousName = image
			return
		}
		wt, err := os.MkdirTemp("", "featherauth-prev-")
		if err != nil {
			previousErr = err
			return
		}
		defer os.RemoveAll(wt)
		if out, err := exec.Command("git", "worktree", "add", "--detach", wt, tag).CombinedOutput(); err != nil {
			previousErr = fmt.Errorf("git worktree add %s: %v\n%s", tag, err, out)
			return
		}
		defer func() { _ = exec.Command("git", "worktree", "remove", "--force", wt).Run() }()
		previousName = "featherauth-ci-upgrade-prev:" + tag
		previousErr = dockerBuild(wt, previousName, "--build-arg", "VERSION="+tag)
	})
	if errors.Is(previousErr, errNoPreviousRelease) {
		t.Skip("no previous release to upgrade from")
	}
	if previousErr != nil {
		t.Fatal(previousErr)
	}
	return previousName
}

func upgradeIdp(t *testing.T) (idpPort, switchPort string) {
	t.Helper()
	idp := mockidp.ListenAt(t, clock.Real(), mockidp.Generic, "0.0.0.0:0", "")
	_, idpPort, err := net.SplitHostPort(idp.Addr())
	if err != nil {
		t.Fatal(err)
	}
	idp.SetPublicURL("http://host.docker.internal:" + idpPort)
	idp.SetCredentials("featherauth", "fixture-client-secret")
	idp.SetSession(true)
	idp.SetUser(mockidp.User{Sub: "u-none", Name: "None"})
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		sub := r.URL.Query().Get("sub")
		idp.SetUser(mockidp.User{Sub: sub, Name: "Upgrade " + sub, Email: sub + "@example.com", EmailVerified: true})
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: time.Minute}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	_, switchPort, _ = net.SplitHostPort(l.Addr().String())
	return idpPort, switchPort
}

var migrationTimestamps = regexp.MustCompile(`migration timestamps (\w+) started=(\S+) first=(\S+) listening=(\S+)`)

// runUpgrade runs check-upgrade.sh for a driver and checks the markers and the
// migration time of the candidate on the seeded database.
func runUpgrade(t *testing.T, driver string) {
	prev := previousImage(t)
	next := candidateImage(t)
	idpPort, switchPort := upgradeIdp(t)
	// CHECK_UPGRADE_USERS shortens the seed for trying the setup; the release uses 1000.
	users := os.Getenv("CHECK_UPGRADE_USERS")
	if users == "" {
		users = "1000"
	}
	env := []string{
		"CHECK_UPGRADE_USERS=" + users,
		"CHECK_UPGRADE_DRIVER=" + driver, "PREV_IMAGE=" + prev, "NEW_IMAGE=" + next,
		"CHECK_UPGRADE_IDP_PORT=" + idpPort, "CHECK_UPGRADE_SWITCH_PORT=" + switchPort,
	}
	out := runOpsEnvTimeout(t, "check-upgrade.sh", env, 40*time.Minute)
	for _, marker := range []string{
		"previous image started",
		"upgrade seed ok " + users,
		"upgrade backup ok",
		"upgrade new image ok",
		"rollback to previous image ok",
		"restore ok",
		"upgrade check passed",
	} {
		if !strings.Contains(out, marker) {
			t.Errorf("the upgrade check did not print %q:\n%s", marker, out)
		}
	}
	m := migrationTimestamps.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("the upgrade check printed no migration timestamps:\n%s", out)
	}
	ts := func(s string) time.Time {
		v, err := time.Parse(time.RFC3339Nano, s)
		if err != nil {
			t.Fatalf("timestamp %q: %v", s, err)
		}
		return v
	}
	started, first, listening := ts(m[2]), ts(m[3]), ts(m[4])
	// The service writes its first log line only after the database is opened and
	// migrated, so first log line to listening leaves the migrations out and proves
	// nothing about them: it is logged for information only. The design's measure
	// is the start of the container to its listening line, and that one is asserted.
	t.Logf("migration time %s: container start to listening %v, first log line to listening %v, on %s users with refresh tokens",
		driver, listening.Sub(started), listening.Sub(first), users)
	if d := listening.Sub(started); d >= time.Second {
		t.Errorf("container start to listening took %v, want under 1 second (OPS-05)", d)
	}
}

// The new release applies its migrations at startup, with no manual step, on a
// database the previous release seeded like the load test (1,000 users with their
// refresh tokens), timed; the previous image then starts on the migrated data and
// serves a sign-in and a refresh; a backup taken before the upgrade restores
// (the steps of the user guide) and the previous image serves it.
//
// Acceptance: Upgrade, rollback and migration time on SQLite
// Also proves OPS-04, OPS-05, OPS-06 (not traced).
func TestOpsUpgradeSQLite(t *testing.T) { runUpgrade(t, "sqlite") }

// The same on Postgres: the stack of compose.postgres.yaml, the backup a pg_dump
// and the restore the pg_restore of the user guide (10.4).
//
// Acceptance: Upgrade, rollback and migration time on Postgres
// Also proves OPS-04, OPS-05, OPS-06 (not traced).
func TestOpsUpgradePostgres(t *testing.T) { runUpgrade(t, "postgres") }

// The documented pg_dump and age job on the stack of compose.postgres.yaml, and
// the restore on a clean host from the encrypted copy: the copy holds no clear
// text and cannot be read without the private key; with it, pg_restore brings
// back users and sessions and the service serves an earlier refresh token and a
// new sign-in (OPS-07, OPS-08). The script installs age in a container
// (network needed for apk).
//
// Acceptance: Postgres restore
// Also proves OPS-07, OPS-08 (not traced).
func TestOpsPostgresRestore(t *testing.T) {
	next := candidateImage(t)
	idp := mockidp.ListenAt(t, clock.Real(), mockidp.Generic, "0.0.0.0:0", "")
	_, port, err := net.SplitHostPort(idp.Addr())
	if err != nil {
		t.Fatal(err)
	}
	idp.SetPublicURL("http://host.docker.internal:" + port)
	idp.SetCredentials("featherauth", "fixture-client-secret")
	idp.SetUser(mockidp.User{Sub: "restore-user", Name: "Restore User", Email: "restore-user@example.com", EmailVerified: true})
	idp.SetSession(true)
	out := runOpsEnv(t, "check-pg-restore.sh", []string{"RESTORE_IMAGE=" + next, "CHECK_PGR_IDP_PORT=" + port})
	for _, marker := range []string{
		"pg restore: user signed in",
		"pg restore: encrypted copy written",
		"pg restore: copy unreadable without the private key",
		"pg restore: restored and started",
		"pg restore: refresh and sign-in work",
		"pg restore check passed",
	} {
		if !strings.Contains(out, marker) {
			t.Errorf("the Postgres restore check did not print %q:\n%s", marker, out)
		}
	}
}

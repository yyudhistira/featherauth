//go:build ops

package deploy_test

import (
	"context"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/testutil/mockidp"
)

// runOps runs one of the CI check scripts from the repository root and fails
// on a non-zero exit. A missing docker fails too: the scripts need it. It
// returns the script's output.
func runOps(t *testing.T, script string) string {
	t.Helper()
	return runOpsEnv(t, script, nil)
}

// runOpsEnv is runOps with extra environment variables, each as KEY=value.
func runOpsEnv(t *testing.T, script string, extra []string) string {
	t.Helper()
	return runOpsEnvTimeout(t, script, extra, 10*time.Minute)
}

// runOpsEnvTimeout is runOpsEnv with its own limit, for the scripts that take longer.
func runOpsEnvTimeout(t *testing.T, script string, extra []string, limit time.Duration) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), limit)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sh", "deploy/ops/"+script)
	cmd.Dir = ".."
	cmd.Env = append(os.Environ(), extra...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s failed: %v\n%s", script, err, out)
	}
	return string(out)
}

// Covers: SEC-09, SEC-11, SEC-31
// Acceptance: Client IP
// Acceptance: Secrets and logs
// Acceptance: Container hardening
// Covers: FR-35 (part)
// Acceptance: Postgres service (part)
//
// This is the closing test of SEC-09 and of the "Secrets and logs" row, and the
// test of the "Container hardening" row (SEC-31). The script runs the login
// through the container against the mock identity provider, which this test
// starts on the host, as the load and conformance tests do: the container
// reaches it as host.docker.internal. The script prints one marker for each
// part of the container check, and this test asserts every marker. The tests
// that assert their conditions, one by one:
//
// SEC-09
//   - secrets never in the repo: TestRepositoryHoldsNoSecretFiles;
//   - never in the image, the database (and backup) and the logs of the
//     service: this test (image layers, metadata, data, container logs), and
//     TestFullFlowMatrix for the logs of every flow;
//   - the 0077 permission check, a warning or an error with
//     strict_permissions, at load and in config check: config
//     TestPermissionsWarnOrErrorByMode, TestPermissionsCheckEveryFileOption,
//     TestPermissionDiagnosticCarriesLine; cmd
//     TestConfigCheckSecretFilePermissionsAndKeySizes;
//   - keys generate, RSA 2048 for RS256, EC P-256 for ES256, --bits: token
//     TestGenerateRSA, TestGenerateECIsP256, TestGenerateEncryptionKeyIs32Bytes,
//     TestWriteKeyFileMode0600UnderPermissiveUmask; cmd
//     TestKeysGenerateRSAAndEC.
//
// "Secrets and logs" row
//   - service logs of every flow at debug: oidc TestFullFlowMatrix and
//     TestAuditLinesHoldUserIDsNotEmails (no secret, no email, no URL with a
//     query, user ids in audit lines);
//   - proxy access and error logs have no query strings: deploy
//     TestNginxExampleLogsPathNotQuery and TestOpsCheckProxy;
//   - the image layers: this test.
//
// The PostgreSQL stack (compose.postgres.yaml) is the second half of the script:
// its database publishes no port, its featherauth container keeps the four
// settings, a login, an import and the CLI commands work on it, backup is
// refused with pg_dump, the password file passes strict_permissions when it is
// 0600 and fails when it is 0644, and the password is in no log or database file.
//
// Proves OPS-12 (health check tolerance): see the pass conditions of the row; OPS ids are not traced.
// Acceptance: Health check tolerance
//
// The built-in TLS stack (compose.tls.yaml) is the last part of the
// script: the container serves HTTPS on the host's port 443 with the pair of a
// test certificate, the redirect listener on port 80 answers 301 to the URL
// under public_url, the loopback listener answers only the health endpoints,
// TLS 1.1 is refused, and the container keeps the settings of SEC-31 with no
// capability added. This test asserts the markers of that part. The other pass
// conditions of the row are proven by the (part) tests in cmd/featherauth/tls_test.go
// (HTTPS, the redirect, the loopback listener, the reload, the startup and listen
// checks) and internal/config/tls_test.go (the option rules, the key file and the
// pair). Together they cover the row; this test is the container case.
//
// The compose file refuses to render without FEATHERAUTH_TAG, and the TLS stack
// serves a login over HTTPS (the wiring of the stack; the rolling stack's
// login is in TestOpsRollingDeploy).
//
// Covers: FR-52, SEC-41, SEC-42 (part)
// Acceptance: Built-in TLS with files
// Acceptance: Signed images (part)
func TestOpsCheckImage(t *testing.T) {
	// The mock identity provider of the example realm's oidc provider. It signs
	// in at once (a session), with the client and secret the realm names.
	idp := mockidp.ListenAt(t, clock.Real(), mockidp.Generic, "0.0.0.0:0", "")
	_, port, err := net.SplitHostPort(idp.Addr())
	if err != nil {
		t.Fatal(err)
	}
	idp.SetPublicURL("http://host.docker.internal:" + port)
	idp.SetCredentials("featherauth", "fixture-client-secret")
	idp.SetUser(mockidp.User{Sub: "ci-user", Name: "CI User"})
	idp.SetSession(true)

	out := runOpsEnv(t, "check-image.sh", []string{"CHECK_IMAGE_IDP_PORT=" + port})
	// Container hardening (SEC-31): the four settings of the running container,
	// the writes the service makes where it must (a probe with the same settings
	// writes /tmp and not /), a login, an import, a backup and a reload with
	// SIGHUP in the read-only container.
	for _, marker := range []string{
		"container settings ok",
		"health check ok",
		"probe ok",
		"import ok",
		"login ok",
		"backup ok",
		"reload ok",
		"postgres container settings ok",
		"postgres port private ok",
		"postgres import ok",
		"postgres login ok",
		"postgres cli ok",
		"postgres backup refused",
		"postgres password file strict ok",
		"postgres password file layout ok",
		"postgres secret scan passed",
		"postgres stack checks passed",
		"tls container settings ok",
		"tls ports ok",
		"tls https ok",
		"tls redirect ok",
		"tls loopback ok",
		"tls version ok",
		"tls secret scan passed",
		"tls login ok",
		"tls stack checks passed",
		"compose refuses without the image tag",
	} {
		if !strings.Contains(out, marker) {
			t.Errorf("the container check did not print %q:\n%s", marker, out)
		}
	}
	// The scan of the image layers, metadata, database, backup and container
	// logs for the fixture secrets ran (and found a planted secret first).
	if !strings.Contains(out, "secret scan passed") {
		t.Fatalf("the secret scan did not run:\n%s", out)
	}
	// The probe from another network is skipped where the host is not reachable
	// through the network gateway (Docker Desktop). On Linux the "port is not
	// reachable from another host" condition must really be probed.
	if runtime.GOOS == "linux" && strings.Contains(out, "network probe skipped") {
		t.Fatalf("the network probe was skipped on Linux:\n%s", out)
	}
}

// Covers: SEC-12 (part), SEC-13 (part)
// Acceptance: TLS examples
// Acceptance: Secrets and logs (part)
func TestOpsCheckProxy(t *testing.T) {
	runOps(t, "check-proxy.sh")
}

// Covers: FR-24
// Acceptance: Encrypted copy
func TestOpsCheckOffsite(t *testing.T) {
	runOps(t, "check-offsite.sh")
}

// The rolling deploy of compose.ha.yaml: two instances on Postgres
// behind Caddy; a loop of logins and refreshes through Caddy runs while
// rolling-deploy.sh replaces both instances. Every request of the loop succeeds,
// the logins alternate between the instances, and both instances are replaced.
//
// This test is the container case of the row. The other pass conditions are
// proven by (part) tests: the migrations apply once when two instances start
// together (TestPostgresMigrationsRunOnceForTwoStartingInstances in
// internal/store/instances_postgres_test.go); no notification is claimed by two
// workers (TestPostgresTwoWorkersClaimDifferentNotifications, same file); a login
// started on one instance finishes on the other
// (TestLoginStartedOnOneInstanceFinishesOnTheOther in
// cmd/featherauth/instances_postgres_test.go). Together with this test they
// cover the row.
//
// Covers: FR-54
// Acceptance: Several instances
func TestOpsRollingDeploy(t *testing.T) {
	idp := mockidp.ListenAt(t, clock.Real(), mockidp.Generic, "0.0.0.0:0", "")
	_, port, err := net.SplitHostPort(idp.Addr())
	if err != nil {
		t.Fatal(err)
	}
	idp.SetPublicURL("http://host.docker.internal:" + port)
	idp.SetCredentials("featherauth", "fixture-client-secret")
	idp.SetUser(mockidp.User{Sub: "ci-user", Name: "CI User"})
	idp.SetSession(true)

	out := runOpsEnv(t, "check-rolling.sh", []string{"CHECK_ROLLING_IDP_PORT=" + port})
	for _, marker := range []string{
		"ha stack healthy",
		"rolling deploy ok",
		"no request failed",
		"both instances served",
		"ha login ok",
		"rolling check passed",
	} {
		if !strings.Contains(out, marker) {
			t.Errorf("the rolling check did not print %q:\n%s", marker, out)
		}
	}
}

// The image-only setup (OPS-21): the one-off containers of "Setup with the
// image alone" run with the candidate image on an empty directory owned by uid
// 65532, as the service's user with no network and a read-only root. The script
// asserts that each command exits 0, the files, the owner and mode of the three
// keys, their types, the refusal to overwrite and that config check has no
// permission diagnostic; this test asserts every marker it prints.
//
// Covers: FR-20
// Acceptance: Setup with the image alone
func TestOpsCheckSetup(t *testing.T) {
	out := runOps(t, "check-setup.sh")
	for _, marker := range []string{
		"setup commands ok",
		"config check ok",
		"config files ok",
		"key owner and mode ok",
		"key types ok",
		"keys generate refuses to overwrite ok",
		"permission diagnostic seen ok",
		"setup check passed",
	} {
		if !strings.Contains(out, marker) {
			t.Errorf("the setup check did not print %q:\n%s", marker, out)
		}
	}
}

// The hardened Postgres container (SEC-44): the postgres service of
// compose.postgres.yaml has a read-only root, every capability dropped with the
// add-backs the image needs, no-new-privileges and only the data volume and the
// tmpfs at /var/run/postgresql writable (no /tmp mount); it is healthy on an
// empty and on a filled volume; and the same start with any one add-back
// removed is not healthy, on either volume. The login and the refresh through the stack run in TestOpsCheckImage.
//
// The compose-file test of the hardening of compose.ha.yaml is
// TestComposeHAPostgresHardeningMatchesComposePostgres; the sign-in and the
// refresh are TestOpsCheckImage; the stack of compose.ha.yaml starts in
// TestOpsRollingDeploy. Together they cover the row.
//
// Covers: SEC-44
// Acceptance: Hardened Postgres container
func TestOpsCheckPostgres(t *testing.T) {
	out := runOps(t, "check-postgres.sh")
	for _, marker := range []string{
		"postgres hardening ok",
		"postgres healthy on an empty volume",
		"postgres healthy on a filled volume",
		"postgres add-back CHOWN needed",
		"postgres add-back DAC_OVERRIDE needed",
		"postgres add-back SETGID needed",
		"postgres add-back SETUID needed",
		"postgres hardening check passed",
	} {
		if !strings.Contains(out, marker) {
			t.Errorf("the Postgres check did not print %q:\n%s", marker, out)
		}
	}
}

// The example web app's compose file (FR-61): the image builds from the
// pinned Dockerfile, is healthy, and serves the page, the /callback route and
// config.json on 127.0.0.1:5173 only. docker and a free host port 5173 are
// needed.
//
// Covers: FR-61 (part)
// Acceptance: Example web app container
func TestOpsCheckExample(t *testing.T) {
	out := runOps(t, "check-example.sh")
	for _, marker := range []string{
		"example started",
		"example port loopback ok",
		"example headers ok",
		"example page ok",
		"example check passed",
	} {
		if !strings.Contains(out, marker) {
			t.Errorf("the example check did not print %q:\n%s", marker, out)
		}
	}
}

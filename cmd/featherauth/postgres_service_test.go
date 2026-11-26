//go:build postgres

package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/testutil"
	"github.com/yyudhistira/featherauth/internal/testutil/mockidp"
	"github.com/yyudhistira/featherauth/internal/testutil/server"
)

// startPostgresService starts the service on a database of its own on the test
// Postgres. The service reaches it through a proxy that the test can stop and
// start, so the database can go away for the service. Its database.yaml has a
// backup directory and a daily time, which driver postgres must not use; the
// directory is returned, so a test can check that nothing was written to it.
func startPostgresService(t *testing.T, opts ...server.Option) (*service, *testutil.PostgresProxy, *server.Env, string) {
	t.Helper()
	return startPostgresServiceWith(t, "", opts...)
}

// startPostgresServiceWith is startPostgresService with extra lines in the
// postgres block of database.yaml (each indented by two spaces and ended by a
// newline).
func startPostgresServiceWith(t *testing.T, extra string, opts ...server.Option) (*service, *testutil.PostgresProxy, *server.Env, string) {
	t.Helper()
	e := server.New(t, opts...)
	srv := testutil.NewPostgresServer(t)
	pg := srv.NewDatabase(t)
	proxy := testutil.NewPostgresProxy(t, srv.Addr(), nil)
	writeConfig(t, e.ConfigDir(), "secrets/postgres_password", srv.Password+"\n")
	backups := filepath.Join(t.TempDir(), "backups")
	writeConfig(t, e.ConfigDir(), "database.yaml", fmt.Sprintf(`driver: postgres
postgres:
  host: %s
  port: %d
  database: %s
  user: %s
  password_file: secrets/postgres_password
  sslmode: disable
%sbackup:
  directory: %s
  at: "03:00"
  keep: 3
`, srv.Host, proxy.Port(), pg.Database, pg.User, extra, backups))
	s := startServiceIn(t, e, e.ConfigDir(), e.Clock)
	return s, proxy, e, backups
}

// The service starts on Postgres, migrates it and answers its readiness.
// Covers: FR-35 (part), FR-25 (part)
// Acceptance: Postgres service (part)
func TestServiceStartsOnPostgres(t *testing.T) {
	s, _, _, _ := startPostgresService(t)
	if code, body := s.get("/readyz"); code != 200 {
		t.Fatalf("/readyz = %d %q", code, body)
	}
}

// /readyz pings the Postgres pool: 503 while the database is unreachable, and
// 200 again once it is back on the same address.
// Covers: FR-35 (part), FR-16 (part)
// Acceptance: Postgres service (part)
func TestReadyzFollowsPostgresAvailability(t *testing.T) {
	s, proxy, _, _ := startPostgresService(t)
	if code, _ := s.get("/readyz"); code != 200 {
		t.Fatalf("/readyz before the stop = %d", code)
	}
	proxy.Stop()
	if code, body := s.get("/readyz"); code != 503 {
		t.Fatalf("/readyz with Postgres stopped = %d %q", code, body)
	}
	proxy.Start(t)
	if code, body := s.get("/readyz"); code != 200 {
		t.Fatalf("/readyz with Postgres started again = %d %q", code, body)
	}
}

// featherauth backup on a live Postgres service exits 1, names pg_dump and writes
// nothing: the built-in snapshot is for SQLite only.
// Covers: FR-25 (part), FR-35 (part)
// Acceptance: Postgres service (part)
func TestBackupOnLivePostgresNamesPgDump(t *testing.T) {
	_, _, e, backups := startPostgresService(t)
	env := map[string]string{"FEATHERAUTH_CONFIG_DIR": e.ConfigDir()}
	r := execAt(t, e.Clock, env, "backup")
	if r.code != 1 || !strings.Contains(r.stderr, "pg_dump") {
		t.Fatalf("backup: %+v", r)
	}
	if _, err := os.Stat(backups); err == nil {
		t.Fatal("backup created the snapshot directory on postgres")
	}
}

// postgresLogin signs the mock user in at the provider "corp" through the
// running service, the way a browser does: the callback's host is the service's
// address, and the cookies of the authorize step go with it. It returns the
// login code, or the error of the client's redirect when there is none.
func postgresLogin(t *testing.T, s *service, e *server.Env) (code, errCode string) {
	t.Helper()
	e.Mocks["corp"].SetUser(mockidp.User{Sub: "77", Name: "Ann Lee", Email: "ann@example.com", EmailVerified: true})
	get := func(u string, cookies []*http.Cookie) *http.Response {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, u, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range cookies {
			req.AddCookie(c)
		}
		resp, err := s.http.Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", u, err)
		}
		_ = resp.Body.Close()
		return resp
	}
	start := get(s.url("/main/authorize?"+server.Authorize(server.ClientQuery, "corp").Encode()), nil)
	if start.StatusCode != http.StatusFound {
		t.Fatalf("authorize = %d", start.StatusCode)
	}
	atProvider := get(start.Header.Get("Location"), nil)
	back, err := url.Parse(atProvider.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	cb := get(s.url(back.RequestURI()), start.Cookies())
	loc, err := url.Parse(cb.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if loc.Query().Has("code") {
		return loc.Query().Get("code"), ""
	}
	return "", loc.Query().Get("error")
}

// postgresExchange redeems a login code at the token endpoint and returns the
// status and the JSON answer's error or refresh token.
func postgresExchange(t *testing.T, s *service, code string) (int, map[string]any) {
	t.Helper()
	form := server.CodeForm(server.ClientQuery, server.Result{Values: url.Values{"code": {code}}})
	status, _, body := s.do(http.MethodPost, "/main/token", form)
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatalf("token answer %q: %v", body, err)
	}
	return status, m
}

// The phase's wiring test: the service and the CLI share one Postgres database.
// A login through the running service creates the user; the CLI reads the user
// and its session; disabling the user from the CLI ends the session and refuses
// the next login and refresh, and enabling it lets the user in again; then 20
// requests redeem one login code at once, and exactly one gets the tokens. The
// service answers ready and the backup refuses at the end.
//
// Covers: FR-35 (part)
// Acceptance: Postgres service (part)
func TestPostgresServiceWiring(t *testing.T) {
	s, _, e, backups := startPostgresService(t, server.WithServerSetting("rate_limit:\n  per_ip_per_minute: 100\n"))
	env := map[string]string{"FEATHERAUTH_CONFIG_DIR": e.ConfigDir()}
	cli := func(args ...string) result {
		t.Helper()
		e.Clock.Advance(time.Second)
		return execAt(t, e.Clock, env, args...)
	}

	// The first login creates the user through the service on Postgres.
	code, _ := postgresLogin(t, s, e)
	if code == "" {
		t.Fatal("the login through the service gave no code")
	}
	status, tokens := postgresExchange(t, s, code)
	refresh, _ := tokens["refresh_token"].(string)
	if status != http.StatusOK || refresh == "" {
		t.Fatalf("the code exchange = %d %v", status, tokens)
	}

	// The CLI, on the same database, finds the user and the one session.
	list := cli("user", "list", "main", "--email", "ann@example.com")
	var users []map[string]any
	if list.code != 0 || json.Unmarshal([]byte(list.stdout), &users) != nil || len(users) != 1 {
		t.Fatalf("user list: %+v", list)
	}
	uid := fmt.Sprint(users[0]["id"])
	sessions := cli("session", "list", "main", uid)
	var rows []map[string]any
	if sessions.code != 0 || json.Unmarshal([]byte(sessions.stdout), &rows) != nil || len(rows) != 1 {
		t.Fatalf("session list: %+v", sessions)
	}

	// Disabled from the CLI: the login is refused and the refresh is invalid,
	// and the session is gone from the list.
	if r := cli("user", "disable", "main", uid); r.code != 0 {
		t.Fatalf("disable: %+v", r)
	}
	if _, errCode := postgresLogin(t, s, e); errCode != "access_denied" {
		t.Fatalf("login of a disabled user: %q", errCode)
	}
	if _, m := s.refresh(server.ClientQuery, refresh); m["error"] != "invalid_grant" {
		t.Fatalf("refresh of a disabled user: %v", m)
	}
	if r := cli("session", "list", "main", uid); r.code != 0 || strings.TrimSpace(r.stdout) != "[]" {
		t.Fatalf("session list after disable: %+v", r)
	}

	// Enabled again: a new login works.
	if r := cli("user", "enable", "main", uid); r.code != 0 {
		t.Fatalf("enable: %+v", r)
	}
	code, errCode := postgresLogin(t, s, e)
	if code == "" {
		t.Fatalf("login after enabling: %q", errCode)
	}

	// Twenty requests at once redeem the one code: exactly one gets tokens.
	statuses := make(chan int, 20)
	for range 20 {
		go func() {
			form := server.CodeForm(server.ClientQuery, server.Result{Values: url.Values{"code": {code}}})
			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, s.url("/main/token"), strings.NewReader(form.Encode()))
			if err != nil {
				statuses <- -1
				return
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			resp, err := s.http.Do(req)
			if err != nil {
				statuses <- -1
				return
			}
			_ = resp.Body.Close()
			statuses <- resp.StatusCode
		}()
	}
	ok := 0
	for range 20 {
		switch st := <-statuses; st {
		case http.StatusOK:
			ok++
		case http.StatusBadRequest:
		default:
			t.Fatalf("a concurrent exchange answered %d", st)
		}
	}
	if ok != 1 {
		t.Fatalf("%d of 20 concurrent exchanges of one code succeeded, want 1", ok)
	}

	// The service is ready, and the snapshot refusal names pg_dump and writes nothing.
	if code, body := s.get("/readyz"); code != http.StatusOK {
		t.Fatalf("/readyz = %d %q", code, body)
	}
	r := cli("backup")
	if r.code != 1 || !strings.Contains(r.stderr, "pg_dump") {
		t.Fatalf("backup: %+v", r)
	}
	if _, err := os.Stat(backups); err == nil {
		t.Fatal("backup created the snapshot directory on postgres")
	}
}

// The root certificate file decides verify-full: the right authority opens the
// database through the commands (the service opens it the same way at start),
// and a wrong one fails the open with an error that holds no password.
//
// Covers: FR-35 (part), FR-25 (part), SEC-13 (part)
// Acceptance: Postgres service (part)
func TestPostgresVerifyFullThroughTheCommands(t *testing.T) {
	srv := testutil.NewPostgresServer(t)
	pg := srv.NewDatabase(t)
	right := testutil.NewAuthority(t)
	proxy := testutil.NewPostgresProxy(t, srv.Addr(), &tls.Config{
		Certificates: []tls.Certificate{right.ServerCertificate(t, "127.0.0.1")},
	})
	dir := t.TempDir()
	writeConfig(t, dir, "secrets/postgres_password", srv.Password+"\n")
	writeConfig(t, dir, "database.yaml", fmt.Sprintf("driver: postgres\npostgres:\n  host: 127.0.0.1\n  port: %d\n  database: %s\n  user: %s\n  password_file: secrets/postgres_password\n  sslmode: verify-full\n  root_cert_file: ca.pem\n",
		proxy.Port(), pg.Database, pg.User))
	env := map[string]string{"FEATHERAUTH_CONFIG_DIR": dir}

	// The directory names no realm, so the command reaches the database and then
	// reports the realm as not found: that answer means the open succeeded.
	writeConfig(t, dir, "ca.pem", string(right.PEM))
	if r := exec(t, env, "user", "list", "main", "--email", "ann@example.com"); r.code != 1 || !strings.Contains(r.stderr, "not found") {
		t.Fatalf("the right authority did not open the database: %+v", r)
	}

	wrong := testutil.NewAuthority(t)
	writeConfig(t, dir, "ca.pem", string(wrong.PEM))
	r := exec(t, env, "user", "list", "main", "--email", "ann@example.com")
	if r.code != 1 || r.stderr == "" || strings.Contains(r.stderr, "not found") {
		t.Fatalf("the wrong authority did not fail the open: %+v", r)
	}
	if strings.Contains(r.stderr, srv.Password) || strings.Contains(r.stdout, srv.Password) {
		t.Fatalf("the error holds the password: %+v", r)
	}
}

// A wrong password fails the open with the server's login failure (SQLSTATE
// 28P01, "password authentication failed"), and the error holds neither the
// wrong password nor the right one. The right password, in the same test, opens
// the database: the command then reports the realm as not found, which is the
// contrast that makes the failure a password failure and not any other.
//
// Covers: FR-35 (part), FR-25 (part), SEC-13 (part)
// Acceptance: Postgres service (part)
func TestPostgresWrongPasswordThroughTheCommands(t *testing.T) {
	srv := testutil.NewPostgresServer(t)
	pg := srv.NewDatabase(t)
	dir := t.TempDir()
	writeConfig(t, dir, "database.yaml", fmt.Sprintf("driver: postgres\npostgres:\n  host: %s\n  port: %d\n  database: %s\n  user: %s\n  password_file: secrets/postgres_password\n  sslmode: disable\n",
		srv.Host, srv.Port, pg.Database, pg.User))
	env := map[string]string{"FEATHERAUTH_CONFIG_DIR": dir}
	open := func(password string) result {
		writeConfig(t, dir, "secrets/postgres_password", password+"\n")
		return exec(t, env, "user", "list", "main", "--email", "ann@example.com")
	}

	right := open(srv.Password)
	if right.code != 1 || !strings.Contains(right.stderr, "not found") || strings.Contains(right.stderr, "authentication") {
		t.Fatalf("the right password did not open the database: %+v", right)
	}
	const wrong = "wrong-password-sentinel"
	r := open(wrong)
	if r.code != 1 || !strings.Contains(r.stderr, "password authentication failed") {
		t.Fatalf("a wrong password is not refused as a login failure: %+v", r)
	}
	if strings.Contains(r.stderr, wrong) || strings.Contains(r.stderr, srv.Password) || strings.Contains(r.stdout, srv.Password) {
		t.Fatalf("the error holds a password: %+v", r)
	}
}

// The closing test of the row "Postgres service" and of FR-35. Its subtests
// assert each condition of the row: the start and the migrations, /readyz with
// the database down and up, backup, verify-full with the right and the wrong
// authority, the wrong password, and the service and the CLI on one database
// with 20 concurrent exchanges of one code (TestPostgresServiceWiring). The
// CLI suites (user, session, import) run here on both drivers, so under this tag
// on Postgres too. The full-flow matrix is the one exception: it lives in
// internal/oidc (package oidc_test), and its test TestFullFlowMatrix runs on
// Postgres under this tag and carries the matching (part) tags there.
//
// Covers: FR-35, FR-25
// Acceptance: Postgres service
func TestPostgresServiceRow(t *testing.T) {
	cases := []struct {
		name string
		fn   func(*testing.T)
	}{
		{"starts and migrates", TestServiceStartsOnPostgres},
		{"readyz follows the database", TestReadyzFollowsPostgresAvailability},
		{"backup names pg_dump", TestBackupOnLivePostgresNamesPgDump},
		{"verify-full through the commands", TestPostgresVerifyFullThroughTheCommands},
		{"wrong password through the commands", TestPostgresWrongPasswordThroughTheCommands},
		{"the service and the CLI on one database", TestPostgresServiceWiring},
		{"user admin", TestUserGetAndList},
		{"user update", TestUserUpdate},
		{"user disable and enable", TestUserUpdateDisabledRoutesToDisableAndEnable},
		{"user link and delete", TestUserDisableEnableDeleteLinkUnlink},
		{"user command errors", TestUserCommandErrors},
		{"user admin while a service serves", TestUserCommandsWhileAServiceUsesTheDatabase},
		{"email change notice", TestUserUpdateNoticeWhenTheEmailChangeClearsVerification},
		{"user delete without a configuration", TestUserDeleteFailsClosedWithoutAConfiguration},
		{"session commands", TestSessionCommandsAcceptanceRow},
		{"session revoke of another user", TestSessionRevokeOfAnotherUsersOrAnUnknownSessionExitsOne},
		{"session revoke of a revoked session", TestSessionRevokeOfARevokedOrExpiredSessionChangesNothing},
		{"session list of no session", TestSessionListOfAUserWithNoSessionIsAnEmptyList},
		{"session usage errors", TestSessionCommandUsageErrorsExitTwo},
		{"session output", TestSessionCommandsPrintNoEmailOrTokenHash},
		{"import twice", TestImportTwiceGivesTheSameIDs},
		{"import without identity", TestImportIncludeWithoutIdentity},
		{"import errors", TestImportErrors},
		{"import failure names the row", TestImportFailureNamesTheRow},
		{"every subcommand", TestEverySubcommandOfFR20},
		{"import refuses unusable files", TestImportRefusesUnusableFiles},
		{"import byte order mark", TestImportAcceptsAByteOrderMark},
		{"import configuration diagnostics", TestImportShowsTheConfigurationDiagnostics},
	}
	for _, c := range cases {
		t.Run(c.name, c.fn)
	}
}

// With a database that accepts the connection and never answers, /readyz answers
// 503 no later than postgres.connect_timeout (500ms here) after the request, not
// after the operating system's TCP timeout (OPS-22, row "Postgres connect
// timeout").
//
// The service runs through a TCP relay to the test Postgres. The relay then
// closes every open connection and accepts new ones without ever answering.
//
// Covers: FR-25
// Acceptance: Postgres connect timeout
func TestReadyzAnswers503WithinThePostgresConnectTimeout(t *testing.T) {
	s, proxy, _, _ := startPostgresServiceWith(t, "  connect_timeout: 500ms\n")
	if code, body := s.get("/readyz"); code != 200 {
		t.Fatalf("/readyz after a good start = %d %q", code, body)
	}
	// The database stops answering: its connections end, and the same address
	// accepts and never replies.
	port := proxy.Port()
	proxy.Stop()
	testutil.NewBlackhole(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	clk := clock.Real()
	begin := clk.Now()
	code, body := s.get("/readyz")
	took := clk.Now().Sub(begin)
	if code != 503 {
		t.Fatalf("/readyz with a database that never answers = %d %q", code, body)
	}
	// The limit is 500ms; the margin is for the test machine, and far below
	// the operating system's TCP timeout.
	if limit := 500*time.Millisecond + time.Second; took > limit {
		t.Errorf("/readyz took %v, want no more than the 500ms connect timeout plus a margin (%v)", took, limit)
	}
}

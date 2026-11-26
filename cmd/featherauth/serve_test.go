package main

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	osexec "os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/secure"
	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/testutil/mockidp"
	"github.com/yyudhistira/featherauth/internal/testutil/server"
)

// TestMain lets a test run the real process: the test binary starts main when
// FEATHERAUTH_TEST_MAIN is set.
func TestMain(m *testing.M) {
	if os.Getenv("FEATHERAUTH_TEST_MAIN") == "1" {
		main()
		return
	}
	os.Exit(m.Run())
}

// logBuffer is the service's standard output; tests wait for lines in it.
type logBuffer struct {
	mu      sync.Mutex
	buf     bytes.Buffer
	changed chan struct{}
}

func newLogBuffer() *logBuffer { return &logBuffer{changed: make(chan struct{})} }

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf.Write(p)
	close(b.changed)
	b.changed = make(chan struct{})
	return len(p), nil
}

func (b *logBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// count is the number of log lines that contain any of subs.
func (b *logBuffer) count(subs ...string) int {
	n := 0
	for _, l := range strings.Split(b.String(), "\n") {
		for _, s := range subs {
			if strings.Contains(l, s) {
				n++
				break
			}
		}
	}
	return n
}

// waitFor returns when at least n lines contain s.
func (b *logBuffer) waitFor(t testing.TB, s string, n int) {
	t.Helper()
	b.waitForAny(t, n, s)
}

// waitForAny returns when at least n lines contain one of subs.
func (b *logBuffer) waitForAny(t testing.TB, n int, subs ...string) {
	t.Helper()
	b.waitWithin(t, 10*time.Second, n, subs...)
}

// startupLimit is the time the design gives a start (Startup: ready in under
// 2 seconds); TestServeListensWhereTheEnvironmentSays holds the in-process
// service to it.
const startupLimit = 2 * time.Second

// waitWithin is waitForAny with its own limit.
func (b *logBuffer) waitWithin(t testing.TB, limit time.Duration, n int, subs ...string) {
	t.Helper()
	s := strings.Join(subs, "|")
	ctx, cancel := context.WithTimeout(t.Context(), limit)
	defer cancel()
	for {
		b.mu.Lock()
		ch := b.changed
		b.mu.Unlock()
		if b.count(subs...) >= n {
			return
		}
		select {
		case <-ch:
		case <-ctx.Done():
			t.Fatalf("no %d log lines with %q; log:\n%s", n, s, b.String())
		}
	}
}

// service is the whole process in the test, with its own clock and listener.
type service struct {
	t      *testing.T
	env    *server.Env
	app    *app
	logs   *logBuffer
	stderr *logBuffer
	hup    chan os.Signal
	// startLimit is how long startService waits for the listening line.
	startLimit time.Duration
	cancel     context.CancelFunc
	done       chan int
	http       *http.Client

	mu      sync.Mutex
	listens []string // the addresses asked for
	addr    string   // the address listened on
	bound   []string // every bound address, in the order of the listen calls
	stopped bool
}

// startService starts `featherauth serve` on the configuration directory of e
// (and its database), listening on 127.0.0.1 with a free port, on e's clock.
func startService(t *testing.T, e *server.Env, setup ...func(*app, *service)) *service {
	t.Helper()
	serviceConfigDir(t, e)
	return startServiceIn(t, e, e.ConfigDir(), e.Clock, setup...)
}

func startServiceIn(t *testing.T, e *server.Env, dir string, clk clock.Clock, setup ...func(*app, *service)) *service {
	t.Helper()
	s := &service{t: t, env: e, startLimit: 10 * time.Second, logs: newLogBuffer(), stderr: newLogBuffer(), hup: make(chan os.Signal, 4), done: make(chan int, 1)}
	s.http = &http.Client{
		Timeout:       10 * time.Second,
		Transport:     &http.Transport{DisableKeepAlives: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	env := map[string]string{"FEATHERAUTH_CONFIG_DIR": dir, "FEATHERAUTH_LISTEN": "127.0.0.1:0"}
	s.app = &app{
		stdout: s.logs, stderr: s.stderr, clock: clk, healthTimeout: 2 * time.Second,
		getenv: func(k string) string { return env[k] },
		listen: func(ctx context.Context, network, addr string) (net.Listener, error) {
			s.mu.Lock()
			s.listens = append(s.listens, addr)
			s.mu.Unlock()
			l, err := (&net.ListenConfig{}).Listen(ctx, network, addr)
			if err == nil {
				s.mu.Lock()
				if s.addr == "" { // the first listener is the one of the environment's address
					s.addr = l.Addr().String()
				}
				s.bound = append(s.bound, l.Addr().String())
				s.mu.Unlock()
			}
			return l, err
		},
	}
	for _, f := range setup {
		f(s.app, s)
	}
	ctx, cancel := context.WithCancel(t.Context())
	s.cancel = cancel
	go func() { s.done <- s.app.serve(ctx, s.hup) }()
	t.Cleanup(func() { s.stop() })
	s.logs.waitWithin(t, s.startLimit, 1, `"listening"`)
	s.logs.waitFor(t, `"watching the configuration directory"`, 1)
	return s
}

// stop ends the service as SIGTERM does and returns its exit code.
func (s *service) stop() int {
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return 0
	}
	s.stopped = true
	s.mu.Unlock()
	s.cancel()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	select {
	case code := <-s.done:
		return code
	case <-ctx.Done():
		s.t.Error("the service did not stop")
		return -1
	}
}

func (s *service) url(path string) string { return "http://" + s.address() + path }

// address is the address the service listens on.
func (s *service) address() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.addr
}

// boundAddrs is every address the service listened on, in the order of the
// listen calls: the environment's listener first.
func (s *service) boundAddrs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.bound)
}

// listened is the addresses the service asked to listen on.
func (s *service) listened() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.listens)
}

func (s *service) listenCount() int { return len(s.listened()) }

func (s *service) do(method, path string, form url.Values) (int, http.Header, string) {
	s.t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(s.t.Context(), method, s.url(path), body)
	if err != nil {
		s.t.Fatal(err)
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := s.http.Do(req)
	if err != nil {
		s.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, string(b)
}

func (s *service) get(path string) (int, string) {
	s.t.Helper()
	code, _, body := s.do(http.MethodGet, path, nil)
	return code, body
}

// sighup sends SIGHUP and waits until the reload it caused has been logged
// (n is the number of "configuration loaded" or error lines expected so far).
func (s *service) sighup(done string, n int) {
	s.t.Helper()
	s.hup <- syscall.SIGHUP
	s.logs.waitFor(s.t, done, n)
}

// refresh posts a refresh grant and returns the status and the JSON answer.
func (s *service) refresh(app server.App, token string) (int, map[string]any) {
	s.t.Helper()
	code, _, body := s.do(http.MethodPost, "/main/token", server.RefreshForm(app, token))
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		s.t.Fatalf("token answer %q: %v", body, err)
	}
	return code, m
}

func editFile(t *testing.T, path string, change func(string) string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(change(string(b))), 0o600); err != nil {
		t.Fatal(err)
	}
}

func realmFile(e *server.Env) string { return filepath.Join(e.ConfigDir(), "realms", "main.yaml") }

const (
	accentRule   = "login_page:\n  contact: help@example.com\n"
	cssPath      = "/main/assets/style.css"
	loaded       = `"configuration loaded"`
	notApplied   = `"configuration not applied`
	removeWebApp = "  web:\n    redirect_uris: [https://app.example.com/callback]\n    web_origins: [https://app.example.com]\n"
)

// recolour changes the accent colour a file already has.
func recolour(colour string) func(string) string {
	re := regexp.MustCompile(`accent_color: "#[0-9a-fA-F]+"`)
	return func(y string) string { return re.ReplaceAllString(y, `accent_color: "`+colour+`"`) }
}

func withAccent(colour string) func(string) string {
	return func(y string) string {
		return strings.Replace(y, accentRule, accentRule+"  accent_color: \""+colour+"\"\n", 1)
	}
}

// The service opens the database, loads the configuration and listens where
// the environment says, ready within startupLimit, having created the realm's row; with no
// valid configuration it fails and never listens.
//
// Covers: FR-17
// Acceptance: Startup
func TestServeListensWhereTheEnvironmentSays(t *testing.T) {
	var out, errb bytes.Buffer
	empty := t.TempDir()
	listens := 0
	failing := &app{
		stdout: &out, stderr: &errb, clock: clock.NewFake(time.Unix(0, 0)),
		getenv: func(k string) string {
			return map[string]string{"FEATHERAUTH_CONFIG_DIR": empty, "FEATHERAUTH_LISTEN": "127.0.0.1:0"}[k]
		},
		listen: func(context.Context, string, string) (net.Listener, error) { listens++; return nil, io.EOF },
	}
	writeConfig(t, empty, "database.yaml", "driver: sqlite\nsqlite:\n  path: "+filepath.Join(empty, "db.sqlite")+"\n")
	if code := failing.run(t.Context(), []string{"serve"}); code != 1 || listens != 0 || !strings.Contains(errb.String(), "server.yaml") {
		t.Fatalf("without a configuration: exit %d, listens %d, stderr %q", code, listens, errb.String())
	}

	e := server.New(t)
	s := startService(t, e, func(_ *app, s *service) { s.startLimit = startupLimit })
	if l := s.listened(); len(l) != 1 || l[0] != "127.0.0.1:0" {
		t.Fatalf("listened on %v", l)
	}
	if code, body := s.get("/readyz"); code != 200 || body != "ok\n" {
		t.Fatalf("readyz %d %q", code, body)
	}
	if code, _ := s.get("/main/.well-known/openid-configuration"); code != 200 {
		t.Fatalf("discovery %d", code)
	}
	if code, _ := s.get(cssPath); code != 200 {
		t.Fatalf("assets %d", code)
	}
	ctx := context.Background()
	err := e.Store.Read(ctx, func(tx store.Tx) error {
		_, err := tx.Realms().Find(ctx, "main")
		return err
	})
	if err != nil {
		t.Fatalf("the realm has no row: %v", err)
	}
}

// Without a valid configuration the service fails with the reason and never
// listens, for each kind of fault.
//
// Covers: FR-17 (part)
// Acceptance: Startup (part)
func TestServeFailsWithoutValidConfiguration(t *testing.T) {
	for _, tt := range []struct {
		name  string
		setup func(t *testing.T, dir string)
		want  string
	}{
		{"empty directory", func(*testing.T, string) {}, "server.yaml"},
		{"invalid database.yaml", func(t *testing.T, dir string) {
			writeConfig(t, dir, "database.yaml", "driver: nosuchdb\n")
		}, "database.yaml"},
		{"invalid server.yaml", func(t *testing.T, dir string) {
			writeConfig(t, dir, "server.yaml", "public_url: [\n")
		}, "server.yaml"},
		{"no realm", func(t *testing.T, dir string) {
			writeConfig(t, dir, "server.yaml", "public_url: https://auth.example.com\n")
		}, "realm"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			writeConfig(t, dir, "database.yaml", "driver: sqlite\nsqlite:\n  path: "+filepath.Join(dir, "db.sqlite")+"\n")
			tt.setup(t, dir)
			var listens int
			var out, errb bytes.Buffer
			a := &app{
				stdout: &out, stderr: &errb, clock: clock.NewFake(time.Unix(0, 0)),
				getenv: func(k string) string {
					return map[string]string{"FEATHERAUTH_CONFIG_DIR": dir, "FEATHERAUTH_LISTEN": "127.0.0.1:0"}[k]
				},
				listen: func(context.Context, string, string) (net.Listener, error) { listens++; return nil, io.EOF },
			}
			if code := a.run(t.Context(), []string{"serve"}); code != 1 {
				t.Fatalf("exit %d, stderr %q", code, errb.String())
			}
			if !strings.Contains(errb.String(), tt.want) || listens != 0 {
				t.Fatalf("stderr %q, listens %d", errb.String(), listens)
			}
		})
	}
}

// The service is for HTTPS only: with an http public_url and the default
// require_https it does not start and says why; with require_https false it
// starts (the TLS examples and the built-in TLS rows are tested elsewhere).
//
// Covers: SEC-12 (part)
// Acceptance: TLS front doors
func TestServeRequiresHTTPSUnlessTold(t *testing.T) {
	e := server.New(t)
	dir := e.ConfigDir()
	writeConfig(t, dir, "database.yaml", "driver: sqlite\nsqlite:\n  path: "+e.DatabasePath+"\n")

	writeConfig(t, dir, "server.yaml", "public_url: http://auth.example.com\n")
	var listens int
	var out, errb bytes.Buffer
	a := &app{
		stdout: &out, stderr: &errb, clock: clock.NewFake(time.Unix(0, 0)),
		getenv: func(k string) string {
			return map[string]string{"FEATHERAUTH_CONFIG_DIR": dir, "FEATHERAUTH_LISTEN": "127.0.0.1:0"}[k]
		},
		listen: func(context.Context, string, string) (net.Listener, error) { listens++; return nil, io.EOF },
	}
	if code := a.run(t.Context(), []string{"serve"}); code != 1 || listens != 0 {
		t.Fatalf("http public_url with the default require_https: exit %d, listens %d, stderr %q", code, listens, errb.String())
	}
	if !strings.Contains(errb.String(), "server.yaml") || !strings.Contains(errb.String(), "public_url") || !strings.Contains(errb.String(), "require_https") {
		t.Errorf("the refusal does not say why: %q", errb.String())
	}

	writeConfig(t, dir, "server.yaml", "public_url: http://auth.example.com\nrequire_https: false\n")
	s := startServiceIn(t, e, dir, e.Clock)
	if code, body := s.get("/readyz"); code != 200 || body != "ok\n" {
		t.Fatalf("with require_https false: readyz %d %q", code, body)
	}
}

// A key file readable by its group, in a configuration that does not set
// strict_permissions, is an error: config check exits 1 and serve fails
// without listening, naming the file.
//
// Covers: SEC-09
// Acceptance: Strict permissions default
func TestStrictPermissionsDefaultStopsTheService(t *testing.T) {
	dir := initDir(t)
	srv := filepath.Join(dir, "server.yaml")
	y := strings.Replace(read(t, srv), "strict_permissions: true\n", "", 1)
	if strings.Contains(y, "strict_permissions") {
		t.Fatal("the option is still set")
	}
	if err := os.WriteFile(srv, []byte(y), 0o600); err != nil {
		t.Fatal(err)
	}
	const key = "secrets/example/signing-2026-10.pem"
	if err := os.Chmod(filepath.Join(dir, key), 0o644); err != nil {
		t.Fatal(err)
	}
	if r := exec(t, nil, "config", "check", dir); r.code != 1 || !strings.Contains(r.stdout, "error") || !strings.Contains(r.stdout, key) {
		t.Fatalf("config check: %+v", r)
	}

	writeConfig(t, dir, "database.yaml", "driver: sqlite\nsqlite:\n  path: "+filepath.Join(t.TempDir(), "db.sqlite")+"\n")
	var out, errb bytes.Buffer
	listens := 0
	a := &app{
		stdout: &out, stderr: &errb, clock: clock.NewFake(time.Unix(0, 0)),
		getenv: func(k string) string {
			return map[string]string{"FEATHERAUTH_CONFIG_DIR": dir, "FEATHERAUTH_LISTEN": "127.0.0.1:0"}[k]
		},
		listen: func(context.Context, string, string) (net.Listener, error) { listens++; return nil, io.EOF },
	}
	if code := a.run(t.Context(), []string{"serve"}); code != 1 || listens != 0 || !strings.Contains(errb.String(), key) {
		t.Fatalf("serve: exit %d, listens %d, stderr %q", code, listens, errb.String())
	}

	// With strict_permissions: false the same file is a warning, and the
	// service gets as far as its listener.
	if err := os.WriteFile(srv, []byte(y+"strict_permissions: false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := exec(t, nil, "config", "check", dir); r.code != 0 || !strings.Contains(r.stdout, "warning") || strings.Contains(r.stdout, "error") {
		t.Fatalf("config check with false: %+v", r)
	}
	out.Reset()
	errb.Reset()
	if code := a.run(t.Context(), []string{"serve"}); listens != 1 {
		t.Fatalf("serve with false: exit %d, listens %d, stderr %q", code, listens, errb.String())
	}

	// With every file at 0600 and the default, there is no diagnostic.
	if err := os.Chmod(filepath.Join(dir, key), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(srv, []byte(y), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := exec(t, nil, "config", "check", dir); r.code != 0 || strings.TrimSpace(r.stdout) != "ok" {
		t.Fatalf("0600 with the default: %+v", r)
	}
}

// A usage error: serve takes no arguments.
func TestServeTakesNoArguments(t *testing.T) {
	if r := exec(t, nil, "serve", "now"); r.code != 2 {
		t.Fatalf("%+v", r)
	}
}

// loginInFlight starts a login through the corp provider up to the callback
// and holds it there: the provider's token endpoint does not answer until
// release is called. finish returns the redirect the callback answers.
func (s *service) loginInFlight(e *server.Env) (release func(), finish func() (int, *url.URL)) {
	s.t.Helper()
	e.Mocks["corp"].SetUser(mockidp.User{Sub: "77", Name: "Ann Lee", Email: "ann@example.com", EmailVerified: true})
	type answer struct {
		resp *http.Response
		err  error
	}
	get := func(u string, cookies []*http.Cookie) answer {
		req, err := http.NewRequestWithContext(s.t.Context(), http.MethodGet, u, nil)
		if err != nil {
			return answer{err: err}
		}
		for _, c := range cookies {
			req.AddCookie(c)
		}
		resp, err := s.http.Do(req)
		if err != nil {
			return answer{err: err}
		}
		_ = resp.Body.Close()
		return answer{resp: resp}
	}
	step := func(name, u string, cookies []*http.Cookie) *http.Response {
		s.t.Helper()
		a := get(u, cookies)
		if a.err != nil || a.resp.StatusCode != http.StatusFound {
			s.t.Fatalf("%s: %v %v", name, a.resp, a.err)
		}
		return a.resp
	}
	start := step("authorize", s.url("/main/authorize?"+server.Authorize(server.ClientQuery, "corp").Encode()), nil)
	atProvider := step("provider", start.Header.Get("Location"), nil)
	back, err := url.Parse(atProvider.Header.Get("Location"))
	if err != nil {
		s.t.Fatal(err)
	}
	e.Mocks["corp"].Block()
	done := make(chan answer, 1) // the goroutine only sends; the test goroutine judges
	go func() { done <- get(s.url(back.RequestURI()), start.Cookies()) }()
	select {
	case <-e.Mocks["corp"].Blocked():
	case <-s.t.Context().Done():
		s.t.Fatal("the callback did not reach the provider")
	}
	var once sync.Once
	release = func() { once.Do(e.Mocks["corp"].Unblock) }
	s.t.Cleanup(release)
	return release, func() (int, *url.URL) {
		a := <-done
		if a.err != nil {
			s.t.Fatalf("the callback: %v", a.err)
		}
		loc, _ := url.Parse(a.resp.Header.Get("Location"))
		return a.resp.StatusCode, loc
	}
}

// SIGHUP applies an edit to the next request, while a login in flight at the
// provider finishes; the service does not restart.
//
// Covers: FR-15
// Acceptance: Hot reload
func TestServeReloadsOnSIGHUP(t *testing.T) {
	e := server.New(t)
	s := startService(t, e)
	if _, body := s.get(cssPath); strings.Contains(body, "#123456") {
		t.Fatal("the accent is there before the edit")
	}
	release, finish := s.loginInFlight(e)

	editFile(t, realmFile(e), withAccent("#123456"))
	if _, body := s.get(cssPath); strings.Contains(body, "#123456") {
		t.Fatal("an edit applied without a reload")
	}
	s.sighup(loaded, 2)
	if _, body := s.get(cssPath); !strings.Contains(body, "--accent: #123456") {
		t.Fatalf("the next request does not see the edit: %q", body)
	}
	release()
	code, loc := finish()
	if code != http.StatusFound || loc.Query().Get("code") == "" || loc.Query().Get("error") != "" {
		t.Fatalf("the login in flight: %d %v", code, loc)
	}
	if s.logs.count(`"listening"`) != 1 || s.listenCount() != 1 {
		t.Fatal("the service listened again")
	}
}

// A change of a file in the directory reloads without a signal; this one runs
// on the real clock, whose timer is the debounce.
//
// Covers: FR-15
// Acceptance: Hot reload (part)
func TestServeReloadsOnFileChange(t *testing.T) {
	e := server.New(t)
	serviceConfigDir(t, e)
	s := startServiceIn(t, e, e.ConfigDir(), clock.Real())
	editFile(t, realmFile(e), withAccent("#654321"))
	s.logs.waitFor(t, loaded, 2)
	if _, body := s.get(cssPath); !strings.Contains(body, "--accent: #654321") {
		t.Fatalf("the edit is not applied: %q", body)
	}
}

// A reload creates the row of a realm seen for the first time.
//
// Covers: FR-15 (part)
func TestServeEnsuresTheRowOfANewRealm(t *testing.T) {
	e := server.New(t)
	s := startService(t, e)
	ctx := context.Background()
	exists := func(realm string) bool {
		err := e.Store.Read(ctx, func(tx store.Tx) error {
			_, err := tx.Realms().Find(ctx, config.RealmName(realm))
			return err
		})
		return err == nil
	}
	if !exists("main") || exists("second") {
		t.Fatal("rows before the reload")
	}
	b, err := os.ReadFile(realmFile(e))
	if err != nil {
		t.Fatal(err)
	}
	second := strings.Replace(strings.Replace(string(b), "name: main\n", "name: second\n", 1), "kid: main-1", "kid: second-1", 1)
	if err := os.WriteFile(filepath.Join(e.ConfigDir(), "realms", "second.yaml"), []byte(second), 0o600); err != nil {
		t.Fatal(err)
	}
	s.sighup(loaded, 2)
	if !exists("second") {
		t.Fatalf("the new realm has no row after the reload\n%s", s.logs.String())
	}
	if code, _ := s.get("/second/.well-known/openid-configuration"); code != 200 {
		t.Fatalf("discovery of the new realm %d", code)
	}
}

// ensureRealms is safe to repeat: after a failure (which the reload hook only
// logs) the next call creates the missing row.
//
// Covers: FR-15 (part)
func TestEnsureRealmsIsRetried(t *testing.T) {
	e := server.New(t)
	ctx := context.Background()
	boom := errors.New("boom")
	e.Faults.Fail("Realms.Ensure", boom)
	if err := ensureRealms(ctx, e.Faults, e.Snapshot, e.Clock); !errors.Is(err, boom) {
		t.Fatalf("got %v", err)
	}
	e.Faults.Fail("Realms.Ensure", nil)
	if err := ensureRealms(ctx, e.Faults, e.Snapshot, e.Clock); err != nil {
		t.Fatal(err)
	}
	err := e.Store.Read(ctx, func(tx store.Tx) error {
		_, err := tx.Realms().Find(ctx, "main")
		return err
	})
	if err != nil {
		t.Fatalf("no row after the retry: %v", err)
	}
}

// A client removed from the realm file fails new authorization requests at
// once and its refresh token on next use.
//
// Covers: FR-15
// Acceptance: Removed client
func TestServeRemovedClient(t *testing.T) {
	e := server.New(t)
	app := server.ClientQuery
	tk := e.Exchange(t, app, e.Login(t, app)) // a session in the shared database
	s := startService(t, e)

	q := server.Authorize(app, "corp").Encode()
	if code, _, _ := s.do(http.MethodGet, "/main/authorize?"+q, nil); code != http.StatusFound {
		t.Fatalf("authorization before the removal: %d", code)
	}
	code, m := s.refresh(app, tk.RefreshToken)
	if code != 200 {
		t.Fatalf("refresh before the removal: %d %v", code, m)
	}
	editFile(t, realmFile(e), func(y string) string { return strings.Replace(y, removeWebApp, "", 1) })
	s.sighup(loaded, 2)

	if code, _, _ := s.do(http.MethodGet, "/main/authorize?"+q, nil); code != http.StatusBadRequest {
		t.Fatalf("authorization after the removal: %d", code)
	}
	if code, m := s.refresh(app, m["refresh_token"].(string)); code != http.StatusBadRequest || m["error"] != "invalid_client" {
		t.Fatalf("refresh after the removal: %d %v", code, m)
	}
}

// Bad edits are logged and the last good configuration keeps serving; other
// realms are unaffected; a server secret that cannot be read does not stop the
// realms from reloading; the last realm file removed is not applied.
//
// Covers: FR-18
// Acceptance: Bad reload
func TestServeBadReloadKeepsServing(t *testing.T) {
	e := server.New(t)
	s := startService(t, e)
	editFile(t, realmFile(e), withAccent("#abcdef"))
	s.sighup(loaded, 2)
	goodMain, err := os.ReadFile(realmFile(e))
	if err != nil {
		t.Fatal(err)
	}
	css := func(realm string) string {
		t.Helper()
		code, body := s.get("/" + realm + "/assets/style.css")
		if code != 200 {
			t.Fatalf("%s stylesheet: %d", realm, code)
		}
		return body
	}
	good := func() {
		t.Helper()
		if !strings.Contains(css("main"), "#abcdef") {
			t.Fatal("main does not serve its last good configuration")
		}
		if code, _ := s.get("/readyz"); code != 200 {
			t.Fatalf("readyz %d", code)
		}
	}
	// reload sends SIGHUP, waits for the reload's own line and returns the
	// number of error lines it logged.
	reload := func() int {
		t.Helper()
		errs := s.logs.count(`"level":"ERROR"`)
		before := s.logs.count(loaded, notApplied)
		s.hup <- syscall.SIGHUP
		s.logs.waitForAny(t, before+1, loaded, notApplied)
		return s.logs.count(`"level":"ERROR"`) - errs
	}
	for _, tt := range []struct {
		name   string
		change func(t *testing.T)
	}{
		{"invalid yaml", func(t *testing.T) {
			editFile(t, realmFile(e), func(y string) string { return y + "\n  : [broken\n" })
		}},
		{"missing secret file", func(t *testing.T) {
			editFile(t, realmFile(e), func(y string) string { return strings.Replace(y, "secrets/main/google_secret", "secrets/main/gone", 1) })
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tt.change(t)
			if reload() == 0 {
				t.Fatal("the bad edit was not reported")
			}
			good()
		})
	}

	// main stays broken above; a new realm and its edits still load
	second := strings.Replace(strings.Replace(string(goodMain), "name: main\n", "name: second\n", 1), "kid: main-1", "kid: second-1", 1)
	secondFile := filepath.Join(e.ConfigDir(), "realms", "second.yaml")
	if err := os.WriteFile(secondFile, []byte(second), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Run("other realms are unaffected", func(t *testing.T) {
		reload()
		editFile(t, secondFile, recolour("#222222"))
		reload()
		if !strings.Contains(css("second"), "#222222") {
			t.Fatal("the other realm did not reload")
		}
		good()
	})

	t.Run("missing encryption key file", func(t *testing.T) {
		keyFile := filepath.Join(e.ConfigDir(), "secrets", "encryption_key")
		key, err := os.ReadFile(keyFile)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(keyFile); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := os.WriteFile(keyFile, key, 0o600); err != nil {
				t.Fatal(err)
			}
		}()
		editFile(t, secondFile, recolour("#333333"))
		if reload() == 0 {
			t.Fatal("the missing key file was not reported")
		}
		if !strings.Contains(css("second"), "#333333") {
			t.Fatal("the realms did not reload while a server secret is unreadable")
		}
		good()
	})

	t.Run("missing postgres.password_file", func(t *testing.T) {
		dbFile := filepath.Join(e.ConfigDir(), "database.yaml")
		orig, err := os.ReadFile(dbFile)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := os.WriteFile(dbFile, orig, 0o600); err != nil {
				t.Fatal(err)
			}
		}()
		writeConfig(t, e.ConfigDir(), "database.yaml", "driver: postgres\npostgres:\n  host: db\n  password_file: secrets/pg\n")
		editFile(t, secondFile, recolour("#444444"))
		if reload() == 0 {
			t.Fatal("the missing password file was not reported")
		}
		if !strings.Contains(css("second"), "#444444") {
			t.Fatal("the realms did not reload while a database secret is unreadable")
		}
		good()
		if code, _ := s.get("/readyz"); code != 200 {
			t.Fatalf("readyz %d", code)
		}
	})

	t.Run("last realm file removed", func(t *testing.T) {
		// removing the second realm is applied; removing main, now the only one, is not
		if err := os.Remove(secondFile); err != nil {
			t.Fatal(err)
		}
		reload()
		if code, _ := s.get("/second/assets/style.css"); code != 404 {
			t.Fatalf("the removed realm answers %d", code)
		}
		good()
		if err := os.Remove(realmFile(e)); err != nil {
			t.Fatal(err)
		}
		if reload() == 0 {
			t.Fatal("the removal of the last realm was not reported")
		}
		good()
	})
}

// A live option applies at once; a restart option and database.yaml report
// restart required and change nothing.
//
// Covers: FR-18 (part), FR-25
// Acceptance: Server config change
func TestServeServerConfigChange(t *testing.T) {
	e := server.New(t)
	s := startService(t, e)
	serverYAML := filepath.Join(e.ConfigDir(), "server.yaml")

	// live: the rate limit
	editFile(t, serverYAML, func(y string) string { return y + "rate_limit:\n  per_ip_per_minute: 1\n" })
	s.sighup(loaded, 2)
	var codes []int
	for range 2 {
		c, _, _ := s.do(http.MethodPost, "/main/token", server.RefreshForm(server.ClientQuery, "x"))
		codes = append(codes, c)
	}
	if codes[0] == http.StatusTooManyRequests || codes[1] != http.StatusTooManyRequests {
		t.Fatalf("the live rate limit is not applied: %v", codes)
	}
	if s.logs.count("restart required") != 0 {
		t.Fatal("a live option reported restart required")
	}

	// restart: the listen address; database.yaml
	editFile(t, serverYAML, func(y string) string { return y + "listen: \"127.0.0.1:1\"\n" })
	s.sighup(`restart required`, 1)
	editFile(t, filepath.Join(e.ConfigDir(), "database.yaml"), func(y string) string { return y + "backup:\n  keep: 9\n" })
	s.sighup(`restart required`, 2)
	log := s.logs.String()
	if !strings.Contains(log, "server.yaml:listen") || !strings.Contains(log, "database.yaml:backup") {
		t.Fatalf("restart required does not name the options:\n%s", log)
	}
	if code, _ := s.get("/readyz"); code != 200 || s.listenCount() != 1 {
		t.Fatalf("behaviour changed: readyz %d, listens %v", code, s.listened())
	}
}

// Requests to several endpoints each write one JSON line "request" with status
// and duration_ms; a valid reload writes "configuration loaded"; one realm file
// made invalid while another stays valid writes "configuration error" with its
// file, line, field and reason, "realm serves its last good configuration"
// naming the realm, and then "configuration loaded"; when the last valid realm
// file is removed the reload writes "configuration not applied; the last good
// configuration keeps serving"; a change of a restart option writes "restart
// required" naming it.
//
// Covers: FR-18 (part)
// Acceptance: Request and reload logs
func TestServeRequestAndReloadLogs(t *testing.T) {
	e := server.New(t)
	e.AddRealm(t, "other")
	s := startService(t, e)
	logLines := func() []map[string]any {
		var out []map[string]any
		for _, l := range strings.Split(s.logs.String(), "\n") {
			var m map[string]any
			if json.Unmarshal([]byte(l), &m) == nil {
				out = append(out, m)
			}
		}
		return out
	}

	before := len(logLines())
	paths := []struct {
		path   string
		status float64
	}{{"/healthz", 200}, {"/main/jwks.json", 200}, {"/main/.well-known/openid-configuration", 200}, {"/nowhere/jwks.json", 404}}
	for _, p := range paths {
		s.get(p.path)
	}
	var requests []map[string]any
	for _, m := range logLines()[before:] {
		if m["msg"] == "request" {
			requests = append(requests, m)
		}
	}
	if len(requests) != len(paths) {
		t.Fatalf("%d request lines for %d requests:\n%s", len(requests), len(paths), s.logs.String())
	}
	for i, p := range paths {
		m := requests[i]
		if m["path"] != p.path || m["status"] != p.status {
			t.Errorf("request line %d: %v, want path %s status %v", i, m, p.path, p.status)
		}
		if _, ok := m["duration_ms"]; !ok {
			t.Errorf("request line %d has no duration_ms: %v", i, m)
		}
	}

	// A valid reload, one realm file made invalid while the other stays valid
	// (the invalid realm keeps its last good configuration), the last valid
	// realm file removed (nothing is applied), then a restart option.
	serverYAML := filepath.Join(e.ConfigDir(), "server.yaml")
	otherFile := filepath.Join(e.ConfigDir(), "realms", "other.yaml")
	editFile(t, realmFile(e), withAccent("#112233"))
	s.sighup(loaded, 2)
	mark := len(s.logs.String())
	editFile(t, realmFile(e), func(y string) string { return y + "unknown_option_xyz: 1\n" })
	s.sighup(loaded, 3)
	var errLine, staleLine, loadedLine int
	for i, m := range logLines() {
		if i < before || m["msg"] == nil {
			continue
		}
		switch m["msg"] {
		case "configuration error":
			errLine = i
			if f, _ := m["file"].(string); !strings.HasSuffix(f, "main.yaml") || m["line"] == nil || m["line"] == float64(0) ||
				m["field"] != "unknown_option_xyz" || m["reason"] == "" || m["reason"] == nil || m["level"] != "ERROR" {
				t.Errorf("the configuration error line %v lacks its file, line, field, reason or level", m)
			}
		case "realm serves its last good configuration":
			staleLine = i
			if m["realm"] != "main" || m["level"] != "WARN" {
				t.Errorf("the stale realm line is %v, want a warning naming main", m)
			}
		case "configuration loaded":
			loadedLine = i
			if m["realm_count"] != float64(2) {
				t.Errorf("configuration loaded after the invalid realm file: %v, want realm_count 2", m)
			}
		}
	}
	if !(errLine > 0 && errLine < staleLine && staleLine < loadedLine) {
		t.Errorf("the lines are not an error, the stale realm, then loaded (%d, %d, %d):\n%s", errLine, staleLine, loadedLine, s.logs.String()[mark:])
	}
	if strings.Contains(s.logs.String()[mark:], "configuration not applied") {
		t.Errorf("a reload that kept one realm and applied another says it applied nothing:\n%s", s.logs.String()[mark:])
	}
	editFile(t, realmFile(e), func(y string) string { return strings.Replace(y, "unknown_option_xyz: 1\n", "", 1) })
	if err := os.Rename(realmFile(e), realmFile(e)+".off"); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(otherFile, otherFile+".off"); err != nil { // no valid realm file is left
		t.Fatal(err)
	}
	s.sighup(notApplied, 1)
	if !strings.Contains(s.logs.String(), "configuration not applied; the last good configuration keeps serving") {
		t.Errorf("the invalid reload does not say the last good configuration keeps serving:\n%s", s.logs.String())
	}
	if code, _ := s.get("/main/jwks.json"); code != 200 {
		t.Errorf("the service stopped serving after the invalid reload: %d", code)
	}
	if err := os.Rename(otherFile+".off", otherFile); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(realmFile(e)+".off", realmFile(e)); err != nil {
		t.Fatal(err)
	}
	editFile(t, serverYAML, func(y string) string { return y + "listen: \"127.0.0.1:1\"\n" })
	s.sighup(`restart required`, 1)
	if !strings.Contains(s.logs.String(), "server.yaml:listen") {
		t.Errorf("restart required does not name the option:\n%s", s.logs.String())
	}
}

// The unknown realm is 404 as JSON and as HTML; the disabled realm refuses
// logins and refreshes and still serves discovery and the JWKS.
//
// Covers: FR-21 (part)
// Acceptance: Unknown or disabled realm
func TestServeUnknownAndDisabledRealm(t *testing.T) {
	e := server.New(t)
	app := server.ClientQuery
	tk := e.Exchange(t, app, e.Login(t, app))
	s := startService(t, e)

	code, hdr, body := s.do(http.MethodPost, "/nowhere/token", server.RefreshForm(app, "x"))
	if code != 404 || !strings.HasPrefix(hdr.Get("Content-Type"), "application/json") || !strings.Contains(body, `"invalid_request"`) || !strings.Contains(body, "unknown realm") {
		t.Fatalf("API: %d %s %q", code, hdr.Get("Content-Type"), body)
	}
	code, hdr, _ = s.do(http.MethodGet, "/nowhere/authorize", nil)
	if code != 404 || !strings.HasPrefix(hdr.Get("Content-Type"), "text/html") {
		t.Fatalf("browser: %d %s", code, hdr.Get("Content-Type"))
	}

	editFile(t, realmFile(e), func(y string) string { return strings.Replace(y, "name: main\n", "name: main\nenabled: false\n", 1) })
	s.sighup(loaded, 2)
	q := server.Authorize(app, "corp").Encode()
	if code, hdr, body := s.do(http.MethodGet, "/main/authorize?"+q, nil); code != http.StatusForbidden ||
		!strings.HasPrefix(hdr.Get("Content-Type"), "text/html") || !strings.Contains(body, "<html") {
		t.Fatalf("login in a disabled realm: %d %s", code, hdr.Get("Content-Type"))
	}
	if code, m := s.refresh(app, tk.RefreshToken); code != 400 || m["error"] != "invalid_grant" {
		t.Fatalf("refresh in a disabled realm: %d %v", code, m)
	}
	for _, p := range []string{"/main/.well-known/openid-configuration", "/main/jwks.json"} {
		if code, _ := s.get(p); code != 200 {
			t.Fatalf("%s in a disabled realm: %d", p, code)
		}
	}
}

// There is no administration over HTTP and the service listens on one port.
//
// Covers: SEC-17
// Acceptance: Admin access
func TestServeHasNoAdminEndpointsAndOnePort(t *testing.T) {
	e := server.New(t)
	s := startService(t, e)
	for _, p := range []string{"/admin/reload", "/admin/main/users"} {
		for _, m := range []string{http.MethodGet, http.MethodPost} {
			if code, _, _ := s.do(m, p, nil); code != http.StatusNotFound {
				t.Fatalf("%s %s: %d", m, p, code)
			}
		}
	}
	if l := s.listened(); len(l) != 1 {
		t.Fatalf("the process listened on %v", l)
	}
}

// SIGTERM makes /readyz answer 503 at once, finishes the slow request, stops
// listening and exits 0.
//
// Covers: FR-16 (part)
// Acceptance: Restart (part)
func TestServeShutsDownGracefully(t *testing.T) {
	e := server.New(t)
	release := make(chan struct{})
	started := make(chan struct{})
	s := startService(t, e, func(a *app, _ *service) {
		a.wrap = func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/slow" {
					close(started)
					<-release
					// finishes as a readiness probe: it sees the state of the service now
					r2 := r.Clone(r.Context())
					r2.URL.Path = "/readyz"
					next.ServeHTTP(w, r2)
					return
				}
				next.ServeHTTP(w, r)
			})
		}
	})
	if code, _ := s.get("/readyz"); code != 200 {
		t.Fatalf("readyz before the signal: %d", code)
	}
	type answer struct {
		code int
		body string
	}
	slow := make(chan answer, 1)
	go func() { c, b := s.get("/slow"); slow <- answer{c, b} }()
	<-started

	s.cancel()
	s.logs.waitFor(t, "shutting down", 1)
	select {
	case code := <-s.done:
		t.Fatalf("the service exited (%d) with a request in flight", code)
	default:
	}
	close(release)
	if got := <-slow; got.code != http.StatusServiceUnavailable || got.body != "shutting down\n" {
		t.Fatalf("the slow request got %d %q", got.code, got.body)
	}
	if code := s.stop(); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if c, err := net.Dial("tcp", s.address()); err == nil {
		_ = c.Close()
		t.Fatal("still listening")
	}
}

// Expired rows are removed every hour.
//
// Covers: FR-24 (part)
func TestServeCleansUpHourly(t *testing.T) {
	e := server.New(t)
	s := startService(t, e)
	ctx := context.Background()
	var rid store.RealmID
	if err := e.Store.Read(ctx, func(tx store.Tx) (err error) { rid, err = tx.Realms().Find(ctx, "main"); return }); err != nil {
		t.Fatal(err)
	}
	row := store.AuthRequest{
		ID: "old", RealmID: rid, ClientID: "web", RedirectURI: "https://app.example.com/callback", Provider: "google",
		CodeChallenge: server.Challenge, ResponseMode: "query", ExpiresAt: e.Clock.Now().Add(10 * time.Minute),
	}
	if err := e.Store.Write(ctx, func(tx store.Tx) error { return tx.AuthRequests().Create(ctx, row) }); err != nil {
		t.Fatal(err)
	}
	e.Clock.Advance(30 * time.Minute) // expired, but the hour has not passed
	if n := s.logs.count("cleanup"); n != 0 {
		t.Fatalf("cleanup ran early: %d", n)
	}
	e.Clock.Advance(time.Hour)
	s.logs.waitFor(t, `"cleanup done"`, 1)
	err := e.Store.Read(ctx, func(tx store.Tx) error {
		_, err := tx.AuthRequests().Get(ctx, "old")
		return err
	})
	if err == nil {
		t.Fatal("the expired row is still there")
	}
}

// One expired and one live row of each kind that expires, and an old audit
// row, are in the database; when the fake clock passes the hour, every expired
// row is gone and every live row and the audit row stay (FR-60).
//
// Covers: FR-60
// Acceptance: Expired records
func TestServeCleansUpEveryKindOfExpiredRow(t *testing.T) {
	e := server.New(t)
	e.Login(t, server.ClientQuery) // makes the user and the identity that the session rows need
	s := startService(t, e)
	ctx := context.Background()
	var rid store.RealmID
	var uid store.UserID
	var iid store.IdentityID
	if err := e.Store.Read(ctx, func(tx store.Tx) (err error) {
		if rid, err = tx.Realms().Find(ctx, "main"); err != nil {
			return err
		}
		ident, err := tx.Identities().Find(ctx, rid, "google", "1001")
		uid, iid = ident.UserID, ident.ID
		return err
	}); err != nil {
		t.Fatal(err)
	}
	now := e.Clock.Now()
	expired, live := now.Add(10*time.Minute), now.Add(3*time.Hour) // the job runs after 1.5 hours
	hash := func(id string) secure.Hash { return secure.HashOf(id) }
	type kind struct {
		table, column       string
		expiredID, liveID   string
		insert              func(tx store.Tx, id string, exp time.Time) error
		expiredVal, liveVal string
	}
	kinds := []kind{
		{"auth_requests", "id", "ar-expired", "ar-live", func(tx store.Tx, id string, exp time.Time) error {
			return tx.AuthRequests().Create(ctx, store.AuthRequest{ID: store.AuthRequestID(id), RealmID: rid, ClientID: "web", RedirectURI: "https://app.example.com/callback",
				Provider: "google", CodeChallenge: server.Challenge, ResponseMode: "query", ExpiresAt: exp})
		}, "ar-expired", "ar-live"},
		{"auth_codes", "code_hash", "code-expired", "code-live", func(tx store.Tx, id string, exp time.Time) error {
			return tx.AuthCodes().Create(ctx, store.AuthCode{CodeHash: hash(id), RealmID: rid, ExpiresAt: exp})
		}, string(hash("code-expired")), string(hash("code-live"))},
		{"callback_handoffs", "id_hash", "h-expired", "h-live", func(tx store.Tx, id string, exp time.Time) error {
			return tx.Handoffs().Create(ctx, store.Handoff{IDHash: hash(id), AuthRequestID: store.AuthRequestID(id), Payload: "p", ExpiresAt: exp})
		}, string(hash("h-expired")), string(hash("h-live"))},
		{"refresh_tokens", "id", "rt-expired", "rt-live", func(tx store.Tx, id string, exp time.Time) error {
			return tx.RefreshTokens().Insert(ctx, store.RefreshToken{ID: store.RefreshTokenID(id), RealmID: rid, UserID: uid, ClientID: "web",
				TokenHash: hash(id), SessionID: "s-" + store.SessionID(id), ExpiresAt: exp})
		}, "rt-expired", "rt-live"},
		{"provider_event_ids", "id_hash", "ev-expired", "ev-live", func(tx store.Tx, id string, exp time.Time) error {
			_, err := tx.ProviderEvents().Remember(ctx, rid, "google", hash(id), exp)
			return err
		}, string(hash("ev-expired")), string(hash("ev-live"))},
		{"dpop_proofs", "proof_hash", "dp-expired", "dp-live", func(tx store.Tx, id string, exp time.Time) error {
			_, err := tx.DPoPProofs().Use(ctx, hash(id), exp)
			return err
		}, string(hash("dp-expired")), string(hash("dp-live"))},
		{"sso_sessions", "id_hash", "sso-expired", "sso-live", func(tx store.Tx, id string, exp time.Time) error {
			return tx.SSOSessions().Create(ctx, store.SSOSession{IDHash: hash(id), RealmID: rid, UserID: uid, IdentityID: iid, Provider: "google",
				AuthTime: now, CreatedAt: now, LastUsedAt: now, ExpiresAt: exp})
		}, string(hash("sso-expired")), string(hash("sso-live"))},
	}
	if err := e.Store.Write(ctx, func(tx store.Tx) error {
		for _, k := range kinds {
			if err := k.insert(tx, k.expiredID, expired); err != nil {
				return err
			}
			if err := k.insert(tx, k.liveID, live); err != nil {
				return err
			}
		}
		// A rate-limit window is live from the minute of the job on.
		if _, err := tx.RateLimits().Hit(ctx, "rl-expired", now); err != nil {
			return err
		}
		if _, err := tx.RateLimits().Hit(ctx, "rl-live", live); err != nil {
			return err
		}
		return tx.Audit().Insert(ctx, store.AuditEvent{ID: "audit-old", RealmID: rid, Actor: "system", Action: "x", CreatedAt: now.Add(-24 * 365 * time.Hour)})
	}); err != nil {
		t.Fatal(err)
	}
	kinds = append(kinds, kind{table: "rate_limits", column: "key", expiredVal: "rl-expired", liveVal: "rl-live"})

	db, err := sql.Open("sqlite", e.DatabasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	has := func(table, column, value string) bool {
		t.Helper()
		var n int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM "`+table+`" WHERE "`+column+`" = ?`, value).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n > 0
	}
	for _, k := range kinds {
		if !has(k.table, k.column, k.expiredVal) || !has(k.table, k.column, k.liveVal) {
			t.Fatalf("%s: the rows were not stored", k.table)
		}
	}

	e.Clock.Advance(30 * time.Minute)
	if n := s.logs.count("cleanup"); n != 0 {
		t.Fatalf("cleanup ran early: %d", n)
	}
	e.Clock.Advance(time.Hour)
	s.logs.waitFor(t, `"cleanup done"`, 1)
	for _, k := range kinds {
		if has(k.table, k.column, k.expiredVal) {
			t.Errorf("%s: the expired row is still there", k.table)
		}
		if !has(k.table, k.column, k.liveVal) {
			t.Errorf("%s: the live row was deleted", k.table)
		}
	}
	if !has("audit_events", "id", "audit-old") {
		t.Error("audit_events: the audit row was deleted")
	}
}

// The daily backup runs from database.yaml's backup block.
//
// Covers: FR-24 (part)
func TestServeRunsTheBackupSchedule(t *testing.T) {
	e := server.New(t)
	dir := filepath.Join(t.TempDir(), "backups")
	writeConfig(t, e.ConfigDir(), "database.yaml",
		"driver: sqlite\nsqlite:\n  path: "+e.DatabasePath+"\nbackup:\n  directory: "+dir+"\n  at: \"03:00\"\n  keep: 3\n")
	s := startServiceIn(t, e, e.ConfigDir(), e.Clock)
	e.Clock.Advance(25 * time.Hour)
	s.logs.waitFor(t, `"backup written"`, 1)
	files, _ := filepath.Glob(filepath.Join(dir, "featherauth-*.db"))
	if len(files) != 1 {
		t.Fatalf("backups: %v", files)
	}
}

// process is the real service in a subprocess of the test binary.
type process struct {
	cmd   *osexec.Cmd
	lines chan string
	addr  string
	errb  *bytes.Buffer
}

// startProcess starts `featherauth serve` on dir and listening on a port the
// system picks; the address is read from the "listening" line.
func startProcess(t *testing.T, dir string) *process {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := osexec.CommandContext(t.Context(), exe, "serve")
	cmd.Env = append(os.Environ(), "FEATHERAUTH_TEST_MAIN=1", "FEATHERAUTH_CONFIG_DIR="+dir, "FEATHERAUTH_LISTEN=127.0.0.1:0")
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	p := &process{cmd: cmd, lines: make(chan string, 256), errb: &bytes.Buffer{}}
	cmd.Stderr = p.errb
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	sc := bufio.NewScanner(out)
	go func() {
		for sc.Scan() {
			p.lines <- sc.Text()
		}
		close(p.lines)
	}()
	return p
}

// wait returns the first line that contains s, within limit.
func (p *process) wait(t *testing.T, limit time.Duration, s string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), limit)
	defer cancel()
	for {
		select {
		case l, ok := <-p.lines:
			if !ok {
				t.Fatalf("the process ended before %q; stderr %q", s, p.errb.String())
			}
			if strings.Contains(l, s) {
				return l
			}
		case <-ctx.Done():
			t.Fatalf("no %q line in time", s)
		}
	}
}

// listening waits for the "listening" line and returns the address in it.
func (p *process) listening(t *testing.T) string {
	t.Helper()
	line := p.wait(t, processLimit, `"listening"`)
	var m struct {
		Addr string `json:"addr"`
	}
	if err := json.Unmarshal([]byte(line), &m); err != nil || m.Addr == "" {
		t.Fatalf("listening line %q: %v", line, err)
	}
	p.addr = m.Addr
	return m.Addr
}

// exitCode waits for the process to end.
func (p *process) exitCode(t *testing.T) int {
	t.Helper()
	for range p.lines {
	}
	_ = p.cmd.Wait()
	return p.cmd.ProcessState.ExitCode()
}

// processLimit is the wall-clock margin for a subprocess, which also starts a
// race-instrumented binary; the 2-second limit of Startup is held in process
// (startupLimit).
const processLimit = 15 * time.Second

// The real process: it fails without a configuration, listens where the
// environment says, reloads on the real SIGHUP and exits 0 on the real SIGTERM.
//
// Covers: FR-17 (part), FR-16 (part), FR-18 (part)
// Acceptance: Startup (part)
// Acceptance: Restart (part)
func TestRealProcessLifecycle(t *testing.T) {
	e := server.New(t)
	serviceConfigDir(t, e)

	empty := t.TempDir()
	writeConfig(t, empty, "database.yaml", "driver: sqlite\nsqlite:\n  path: "+filepath.Join(empty, "db.sqlite")+"\n")
	bad := startProcess(t, empty)
	if code := bad.exitCode(t); code != 1 || !strings.Contains(bad.errb.String(), "server.yaml") {
		t.Fatalf("exit %d, stderr %q", code, bad.errb.String())
	}

	p := startProcess(t, e.ConfigDir())
	addr := p.listening(t)
	ctx, cancel := context.WithTimeout(t.Context(), processLimit)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/readyz", nil)
	resp, err := (&http.Client{Timeout: processLimit}).Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("readyz: %v %v", resp, err)
	}
	_ = resp.Body.Close()

	if err := p.cmd.Process.Signal(syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	p.wait(t, processLimit, loaded)
	if err := p.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if code := p.exitCode(t); code != 0 {
		t.Fatalf("exit after SIGTERM: %d", code)
	}
}

// SIGINT stops the real process like SIGTERM: readiness goes, the exit code
// is 0.
//
// Covers: FR-16 (part)
// Acceptance: Restart (part)
func TestRealProcessStopsOnSIGINT(t *testing.T) {
	e := server.New(t)
	serviceConfigDir(t, e)
	p := startProcess(t, e.ConfigDir())
	p.listening(t)
	if err := p.cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	p.wait(t, processLimit, `"shutting down"`)
	if code := p.exitCode(t); code != 0 {
		t.Fatalf("exit after SIGINT: %d", code)
	}
}

// Over the real process the 31st request in a minute from one address to
// authorize, token, revoke and the provider events path is answered 429; another
// address is unaffected.
//
// Covers: SEC-11 (part)
// Acceptance: Rate limit
func TestServeRateLimit(t *testing.T) {
	e := server.New(t)
	serviceConfigDir(t, e)
	editFile(t, filepath.Join(e.ConfigDir(), "server.yaml"), func(y string) string {
		return y + "trusted_proxies: [\"127.0.0.0/8\"]\n"
	})
	p := startProcess(t, e.ConfigDir())
	addr := p.listening(t)
	client := &http.Client{Timeout: processLimit, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	from := func(method, path, forwarded string) int {
		t.Helper()
		var body io.Reader
		if method == http.MethodPost {
			body = strings.NewReader("")
		}
		req, err := http.NewRequestWithContext(t.Context(), method, "http://"+addr+path, body)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-Forwarded-For", forwarded)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	for i, ep := range []struct{ method, path string }{
		{http.MethodGet, "/main/authorize"},
		{http.MethodPost, "/main/token"},
		{http.MethodPost, "/main/events/apple"},
		{http.MethodPost, "/main/revoke"},
	} {
		forwarded := "198.51.100." + string(rune('1'+i))
		for n := 1; n <= 30; n++ {
			if code := from(ep.method, ep.path, forwarded); code == http.StatusTooManyRequests {
				t.Fatalf("%s: request %d was limited", ep.path, n)
			}
		}
		if code := from(ep.method, ep.path, forwarded); code != http.StatusTooManyRequests {
			t.Fatalf("%s: the 31st request answered %d", ep.path, code)
		}
		if code := from(ep.method, ep.path, "203.0.113.9"); code == http.StatusTooManyRequests {
			t.Fatalf("%s: another address was limited", ep.path)
		}
	}
	_ = p.cmd.Process.Signal(syscall.SIGTERM)
	if code := p.exitCode(t); code != 0 {
		t.Fatalf("exit %d", code)
	}
}

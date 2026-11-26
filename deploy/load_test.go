//go:build load && (darwin || dragonfly || freebsd || illumos || linux || netbsd || openbsd)

package deploy_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/testutil/configdir"
	"github.com/yyudhistira/featherauth/internal/testutil/mockidp"
)

// The load verification (docs/DESIGN.md, Load verification): the real image
// limited to 1 CPU and 512 MB with a SQLite volume, the Caddy and nginx
// examples in front (deploy/load/compose.yaml), the mock identity provider on
// the host, and k6 (deploy/load/k6.js) in a container, so nothing but docker is
// needed on the host. Results go to LOAD_OUT (default load-out in the
// repository) and are recorded in docs/RESULTS.md.
//
// Durations: LOAD_IDLE (60s), LOAD_STEADY (10m), LOAD_PEAK (5m), LOAD_SOAK
// (1h), LOAD_RESTART (2m, the steady load around a restart); LOAD_USERS
// (1000) is the number of seeded users. A shorter value is for trying the
// setup; the recorded run uses the defaults.
const (
	loadHost    = "auth.example.com"
	loadRealm   = "load"
	loadApp     = "load-app"
	loadRedir   = "http://127.0.0.1:9/cb"
	loadVerif   = "load-verifier-0123456789-0123456789-0123456789-abcdefghij"
	loadCaddy   = "127.0.0.1:18543"
	loadNginx   = "127.0.0.1:18544"
	loadSvc     = "featherauth-load-featherauth-1"
	loadSubnet  = "172.28.77.0/24"
	loadProbe   = "nginx:1.28-alpine@sha256:a8b39bd9cf0f83869a2162827a0caf6137ddf759d50a171451b335cecc87d236"
	loadCompose = "deploy/load/compose.yaml"
)

const loadServerYAML = `public_url: https://` + loadHost + `
listen: ":8080"
strict_permissions: false
log_level: info
`

const loadRealmYAML = `name: ` + loadRealm + `
keys:
  - { kid: load-1, file: secrets/signing.pem, state: active }
providers:
  sso:
    type: oidc
    enabled: true
    display_name: Mock SSO
    client_id: mock-client
    client_secret_file: secrets/sso_secret
    issuer: "%MOCK%"
clients:
  ` + loadApp + `:
    type: public
    redirect_uris: [` + loadRedir + `]
`

func envDuration(t *testing.T, name string, def time.Duration) time.Duration {
	t.Helper()
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return d
}

type loadStack struct {
	t      *testing.T
	cfg    *configdir.Dir
	proxy  string
	out    string
	mock   *mockidp.Server
	mockHP string
	env    []string
	driver string // sqlite or postgres (LOAD_DRIVER)
}

// docker runs docker with args from the repository root and returns its output.
func (s *loadStack) docker(args ...string) (string, error) {
	return s.dockerEnv(nil, args...)
}

// dockerEnv is docker with more environment variables; it never changes s, so
// it is safe to call from several goroutines.
func (s *loadStack) dockerEnv(extra []string, args ...string) (string, error) {
	cmd := exec.CommandContext(context.Background(), "docker", args...)
	cmd.Dir = ".."
	cmd.Env = append(append(os.Environ(), s.env...), extra...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.String(), err
}

func (s *loadStack) must(args ...string) string {
	s.t.Helper()
	out, err := s.docker(args...)
	if err != nil {
		s.t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

func (s *loadStack) compose(args ...string) string {
	s.t.Helper()
	return s.must(append([]string{"compose", "-f", loadCompose}, args...)...)
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// The load lock of this process: taken by the first load stack, held until the
// process exits (loadLockRelease keeps the file open), so a second load run on
// this machine fails at once instead of removing this one's stack.
var (
	loadLockOnce    sync.Once
	loadLockRelease func() error
	loadLockErr     error
)

// holdLoadLock takes the load lock under the user's cache directory once per
// process, before anything touches docker, and fails the test when another
// run holds it (a failure, not a skip, so a refused run is never read as a
// passed one).
func holdLoadLock(t *testing.T) {
	t.Helper()
	loadLockOnce.Do(func() {
		dir, err := os.UserCacheDir()
		if err != nil {
			loadLockErr = err
			return
		}
		loadLockRelease, loadLockErr = takeLoadLock(filepath.Join(dir, "featherauth", "load.lock"))
	})
	if loadLockErr != nil {
		t.Fatal(loadLockErr)
	}
}

// newLoadStack starts the stack with a fresh database. The proxy files are
// derived from the examples the way deploy/ops/check-proxy.sh derives them, so
// the hold of the Caddy example and the plain proxying of the nginx example are
// what is measured.
func newLoadStack(t *testing.T) *loadStack {
	t.Helper()
	holdLoadLock(t)
	s := &loadStack{t: t}
	s.out = os.Getenv("LOAD_OUT")
	if s.out == "" {
		s.out = filepath.Join("..", "load-out")
	}
	var err error
	if s.out, err = filepath.Abs(s.out); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(s.out, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(s.out, 0o777); err != nil { // k6 runs as another user
		t.Fatal(err)
	}

	s.mock = mockidp.ListenAt(t, clock.Real(), mockidp.Generic, "0.0.0.0:0", "")
	_, port, err := net.SplitHostPort(s.mock.Addr())
	if err != nil {
		t.Fatal(err)
	}
	s.mockHP = "127.0.0.1:" + port
	s.mock.SetPublicURL("http://host.docker.internal:" + port)
	s.mock.SetSecretCheck(func(string) error { return nil })
	s.mock.SetCredentials("mock-client", "unused")

	s.cfg = configdir.New(t)
	s.WriteServer(loadServerYAML + "rate_limit:\n  per_ip_per_minute: 0\n")
	s.cfg.RSAKey(t, "secrets/signing.pem")
	s.cfg.Secret(t, "secrets/sso_secret")
	s.driver = loadDriver(t)
	// LOAD_READ_CONNECTIONS is a knob tried in the investigation of the peak memory;
	// LOAD_PG_MAX_CONNS is the Postgres pool size, tried in the investigation of
	// the peak /userinfo p95 (the recorded runs leave it unset: the design's 20).
	if y := loadDatabaseYAML(s.driver, os.Getenv("LOAD_READ_CONNECTIONS"), os.Getenv("LOAD_PG_MAX_CONNS")); y != "" {
		s.cfg.Write(t, "database.yaml", y)
	}
	if s.driver == "postgres" {
		s.cfg.Secret(t, "secrets/postgres_password") // the password of the postgres service
	}
	s.cfg.Realm(t, loadRealm, strings.ReplaceAll(loadRealmYAML, "%MOCK%", s.mock.URL()))
	openPermissions(t, s.cfg.Root)

	s.proxy = t.TempDir()
	certs := filepath.Join(s.proxy, "certs")
	if err := os.MkdirAll(certs, 0o755); err != nil {
		t.Fatal(err)
	}
	ssl := exec.CommandContext(context.Background(), "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
		"-subj", "/CN="+loadHost, "-keyout", filepath.Join(certs, "privkey.pem"), "-out", filepath.Join(certs, "fullchain.pem"))
	if out, err := ssl.CombinedOutput(); err != nil {
		t.Fatalf("openssl: %v\n%s", err, out)
	}
	openPermissions(t, s.proxy)

	caddy, err := os.ReadFile("Caddyfile.example")
	if err != nil {
		t.Fatal(err)
	}
	cf := strings.ReplaceAll(string(caddy), "    # tls ", "    tls ")
	cf = strings.ReplaceAll(cf, "/etc/ssl/auth/", "/certs/")
	cf = strings.ReplaceAll(cf, "127.0.0.1:8080", "featherauth:8080")
	if !strings.Contains(cf, "lb_try_duration 10s") || !strings.Contains(cf, "reverse_proxy featherauth:8080") ||
		!strings.Contains(cf, "keepalive off") {
		t.Fatal("the Caddyfile example changed: the load setup must be updated")
	}
	writeFile(t, filepath.Join(s.proxy, "Caddyfile"), cf)
	nginx, err := os.ReadFile("nginx.example.conf")
	if err != nil {
		t.Fatal(err)
	}
	nf := strings.ReplaceAll(string(nginx), "http://127.0.0.1:8080", "http://featherauth:8080")
	if !strings.Contains(nf, "proxy_pass http://featherauth:8080") {
		t.Fatal("the nginx example changed: the load setup must be updated")
	}
	writeFile(t, filepath.Join(s.proxy, "nginx.conf"), nf)

	s.env = []string{"LOAD_CONFIG=" + s.cfg.Root, "LOAD_PROXY=" + s.proxy, "LOAD_OUT=" + s.out}
	t.Cleanup(s.down)
	s.down()
	// With driver postgres, --profile postgres starts the postgres service of
	// deploy/load/compose.yaml; up does not start k6 (profile run).
	s.compose(append(composeProfiles(s.driver, false), "up", "--build", "--detach", "--wait")...)
	return s
}

// down removes the load stack, its containers and its volumes, with every
// profile of this driver (the Postgres container included).
func (s *loadStack) down() {
	args := append([]string{"compose", "-f", loadCompose}, composeProfiles(s.driver, true)...)
	_, _ = s.docker(append(args, "down", "--volumes", "--remove-orphans")...)
}

// WriteServer replaces server.yaml.
func (s *loadStack) WriteServer(yaml string) {
	s.t.Helper()
	s.cfg.Server(s.t, yaml)
	openPermissions(s.t, s.cfg.Root)
}

// client returns an HTTP client for the proxy listening at addr on the host. It
// reaches the mock identity provider, which the service names
// host.docker.internal, on the loopback.
func (s *loadStack) client(proxyAddr string) *http.Client {
	jar, _ := cookiejar.New(nil)
	d := &net.Dialer{Timeout: 5 * time.Second}
	return &http.Client{
		Timeout: 30 * time.Second,
		Jar:     jar,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: loadHost}, //nolint:gosec // the example's throwaway certificate
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				switch {
				case strings.HasPrefix(addr, loadHost+":"):
					addr = proxyAddr
				case strings.HasPrefix(addr, "host.docker.internal:"):
					addr = s.mockHP
				}
				return d.DialContext(ctx, network, addr)
			},
		},
		CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			if strings.HasPrefix(req.URL.String(), loadRedir) {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

type grant struct {
	Access  string `json:"access_token"`
	Refresh string `json:"refresh_token"`
}

func pkceChallenge() string {
	h := sha256.Sum256([]byte(loadVerif))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// login signs one user in through the mock identity provider and exchanges the
// code, as an app would.
func (s *loadStack) login(ctx context.Context, c *http.Client, sub string) (grant, error) {
	s.mock.SetUser(mockidp.User{Sub: sub, Name: "Load " + sub, Email: sub + "@example.com", EmailVerified: true})
	q := url.Values{
		"client_id": {loadApp}, "redirect_uri": {loadRedir}, "response_type": {"code"}, "scope": {"openid"},
		"state": {"st-" + sub}, "nonce": {"n-" + sub}, "code_challenge": {pkceChallenge()}, "code_challenge_method": {"S256"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+loadHost+"/"+loadRealm+"/authorize?"+q.Encode(), nil)
	if err != nil {
		return grant{}, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return grant{}, err
	}
	_ = resp.Body.Close()
	loc := resp.Header.Get("Location")
	if resp.StatusCode != http.StatusFound || !strings.HasPrefix(loc, loadRedir) {
		return grant{}, fmt.Errorf("login ended with %d at %q", resp.StatusCode, loc)
	}
	u, err := url.Parse(loc)
	if err != nil {
		return grant{}, err
	}
	return s.token(ctx, c, url.Values{
		"grant_type": {"authorization_code"}, "client_id": {loadApp}, "code": {u.Query().Get("code")},
		"redirect_uri": {loadRedir}, "code_verifier": {loadVerif},
	})
}

func (s *loadStack) token(ctx context.Context, c *http.Client, form url.Values) (grant, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+loadHost+"/"+loadRealm+"/token", strings.NewReader(form.Encode()))
	if err != nil {
		return grant{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.Do(req)
	if err != nil {
		return grant{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return grant{}, fmt.Errorf("token: status %d", resp.StatusCode)
	}
	var g grant
	if err := json.Unmarshal(body, &g); err != nil {
		return grant{}, err
	}
	return g, nil
}

// seed logs n users in and writes their tokens for k6.
func (s *loadStack) seed(n int) {
	s.t.Helper()
	ctx := context.Background()
	var all []grant
	for i := range n {
		g, err := s.login(ctx, s.client(loadCaddy), fmt.Sprintf("u%05d", i))
		if err != nil {
			s.t.Fatalf("seed user %d: %v", i, err)
		}
		all = append(all, g)
	}
	b, _ := json.Marshal(all)
	if err := os.WriteFile(filepath.Join(s.out, "tokens.json"), b, 0o644); err != nil {
		s.t.Fatal(err)
	}
	s.mock.SetUser(mockidp.User{Sub: "load-login", Name: "Load Login", Email: "load-login@example.com", EmailVerified: true})
}

// restart restarts the FeatherAuth container as docker compose restart does,
// and returns how long the command took.
func (s *loadStack) restart() time.Duration {
	s.t.Helper()
	t0 := clock.Real().Now()
	s.compose("restart", "--timeout", "30", "featherauth")
	return clock.Real().Now().Sub(t0)
}

// ready waits until the service answers /readyz through the proxy.
func (s *loadStack) ready(ctx context.Context, proxyAddr string) error {
	c := s.client(proxyAddr)
	for range 120 {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+loadHost+"/readyz", nil)
		if resp, err := c.Do(req); err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		pause(ctx, 250*time.Millisecond)
	}
	return fmt.Errorf("not ready")
}

type attempt struct {
	at     time.Time
	status int // 0 for a transport error
	took   time.Duration
}

// refreshLoop sends refreshes, one every 10 ms, while the service restarts
// after the third request: at least 20, and more until the restart is over and
// an answer came after it. It returns every attempt and the time the restart
// command took.
func (s *loadStack) refreshLoop(t *testing.T, proxyAddr, refresh string) ([]attempt, time.Duration) {
	t.Helper()
	ctx := context.Background()
	c := s.client(proxyAddr)
	var (
		res        []attempt
		restarted  = make(chan time.Duration, 1)
		restarting bool
		took       time.Duration
		over       bool
	)
	for i := 0; i < 120; i++ {
		start := clock.Real().Now()
		if i == 3 {
			restarting = true
			go func() { restarted <- s.restart() }()
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+loadHost+"/"+loadRealm+"/token",
			strings.NewReader(url.Values{"grant_type": {"refresh_token"}, "client_id": {loadApp}, "refresh_token": {refresh}}.Encode()))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		a := attempt{at: start}
		resp, err := c.Do(req)
		if err == nil {
			a.status = resp.StatusCode
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				var g grant
				if json.Unmarshal(body, &g) == nil && g.Refresh != "" {
					refresh = g.Refresh
				}
			}
		}
		a.took = clock.Real().Now().Sub(start)
		res = append(res, a)
		if restarting && !over {
			select {
			case took = <-restarted:
				over = true
			default:
			}
		}
		if i >= 19 && over && a.status == http.StatusOK {
			break
		}
		if wait := 10*time.Millisecond - a.took; wait > 0 {
			pause(ctx, wait)
		}
	}
	if !over {
		took = <-restarted
	}
	return res, took
}

// Covers: FR-16 (part)
// Acceptance: Restart
//
// The conditions of the row and the test that asserts each:
//   - Caddy: none of the refreshes of the loop fails and the slowest answer
//     takes under 10 seconds: this test, subtest caddy (it also requires that
//     an answer was held, so the loop did meet the restart);
//   - nginx: 502 answers occur only in the gap (a run of 502 answers with
//     answers 200 before and after) and the loop recovers within 5 seconds of
//     the first 502: this test, subtest nginx (it requires at least one 502,
//     so the gap was met);
//   - on SIGTERM /readyz turns 503 at once and the slow request completes:
//     server TestReadyzIs503OnceShutdownBegins and
//     TestShutdownLetsAnInFlightRequestComplete, cmd TestServeShutsDownGracefully
//     and TestRealProcessLifecycle (tagged "Acceptance: Restart (part)");
//   - with each shipped Caddyfile every POST answers 200 on its own upstream
//     connection, and a POST sent while the upstream refuses connections for
//     1 second answers 200 in under 10 seconds, having reached it once:
//     TestOpsCaddyOpensAConnectionPerRequest (build tag ops);
//   - every service that runs FeatherAuth in compose.yaml, compose.tls.yaml
//     and compose.ha.yaml has stop_grace_period: 35s, compose.postgres.yaml
//     sets no other value, and the deploy scripts neither stop the service
//     another way nor pass a timeout: TestComposeGivesTheDrainItsTime.
//
// One load run at a time: newLoadStack takes the lock that
// TestLoadLockRefusesASecondRun proves.
func TestLoadRestartLoop(t *testing.T) {
	s := newLoadStack(t)
	ctx := context.Background()
	for _, p := range []struct{ name, addr string }{{"caddy", loadCaddy}, {"nginx", loadNginx}} {
		t.Run(p.name, func(t *testing.T) {
			if err := s.ready(ctx, p.addr); err != nil {
				t.Fatal(err)
			}
			g, err := s.login(ctx, s.client(loadCaddy), "restart-"+p.name)
			if err != nil {
				t.Fatal(err)
			}
			res, restartTook := s.refreshLoop(t, p.addr, g.Refresh)

			var maxTook time.Duration
			var codes []string
			for _, a := range res {
				maxTook = max(maxTook, a.took)
				codes = append(codes, strconv.Itoa(a.status))
			}
			for i, a := range res {
				t.Logf("  %2d at +%v took %v status %d", i, a.at.Sub(res[0].at).Round(time.Millisecond), a.took.Round(time.Millisecond), a.status)
			}
			t.Logf("%s: %d refreshes, statuses %s, slowest %v, docker restart took %v", p.name, len(res), strings.Join(codes, " "), maxTook, restartTook)
			if len(res) < 20 {
				t.Fatalf("only %d refreshes", len(res))
			}
			switch p.name {
			case "caddy":
				for i, a := range res {
					if a.status != http.StatusOK {
						t.Errorf("refresh %d answered %d", i, a.status)
					}
				}
				if maxTook >= 10*time.Second {
					t.Errorf("slowest answer took %v, want under 10s", maxTook)
				}
				if maxTook < 100*time.Millisecond {
					t.Errorf("no request was held (slowest %v): the loop did not meet the restart", maxTook)
				}
			case "nginx":
				first, last := -1, -1
				for i, a := range res {
					switch a.status {
					case http.StatusOK:
					case http.StatusBadGateway:
						if first < 0 {
							first = i
						}
						last = i
					default:
						t.Errorf("refresh %d answered %d, want 200 or 502", i, a.status)
					}
				}
				if first < 0 {
					t.Fatal("no 502: the loop did not meet the restart")
				}
				for i := first; i <= last; i++ {
					if res[i].status != http.StatusBadGateway {
						t.Errorf("answer %d is %d inside the gap of 502 answers", i, res[i].status)
					}
				}
				if last+1 >= len(res) || res[last+1].status != http.StatusOK {
					t.Fatal("the loop did not recover")
				}
				recovery := res[last+1].at.Add(res[last+1].took).Sub(res[first].at)
				t.Logf("nginx: gap from refresh %d to %d, recovered %v after the first 502", first, last, recovery)
				if recovery > 5*time.Second {
					t.Errorf("recovered after %v, want within 5s", recovery)
				}
			}
		})
	}
}

// ---- scenarios

// sample is one reading of the service container.
type sample struct {
	at       time.Time
	rss, hwm int // kB
	cpu      float64
	pgKB     int     // the Postgres container's memory (kB) with driver postgres, else 0; -1 when docker fails
	pgCPU    float64 // the Postgres container's CPU, percent of one CPU
}

var gcRe = regexp.MustCompile(`^gc \d+ @.* (\d+)->\d+->(\d+) MB, \d+ MB goal, (\d+) MB stacks`)

var statusRe = regexp.MustCompile(`(VmRSS|VmHWM):\s+(\d+) kB`)

// memory reads VmRSS and VmHWM of the service process (pid 1 of its container)
// from /proc/1/status, by joining the container's process namespace.
func (s *loadStack) memory() (rss, hwm int) {
	s.t.Helper()
	out := s.must("run", "--rm", "--pid=container:"+loadSvc, loadProbe, "cat", "/proc/1/status")
	for _, m := range statusRe.FindAllStringSubmatch(out, -1) {
		n, _ := strconv.Atoi(m[2])
		if m[1] == "VmRSS" {
			rss = n
		} else {
			hwm = n
		}
	}
	if rss == 0 || hwm == 0 {
		s.t.Fatalf("no VmRSS or VmHWM in /proc/1/status:\n%s", out)
	}
	return rss, hwm
}

func (s *loadStack) cpu() float64 {
	out, err := s.docker("stats", "--no-stream", "--format", "{{.CPUPerc}}", loadSvc)
	if err != nil {
		return -1
	}
	v, _ := strconv.ParseFloat(strings.TrimSuffix(strings.TrimSpace(out), "%"), 64)
	return v
}

// sampler reads the container every interval until stop is called, and returns
// the readings.
func (s *loadStack) sampler(interval time.Duration) (stop func() []sample) {
	ctx, cancel := context.WithCancel(context.Background())
	var (
		mu  sync.Mutex
		got []sample
		wg  sync.WaitGroup
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for ctx.Err() == nil {
			pause(ctx, interval)
			if ctx.Err() != nil {
				return
			}
			rss, hwm := s.memoryQuiet()
			x := sample{at: clock.Real().Now(), rss: rss, hwm: hwm, cpu: s.cpu()}
			if s.driver == "postgres" {
				x.pgKB, x.pgCPU = s.pgStats()
			}
			mu.Lock()
			got = append(got, x)
			mu.Unlock()
		}
	}()
	return func() []sample {
		cancel()
		wg.Wait()
		mu.Lock()
		defer mu.Unlock()
		return got
	}
}

// memoryQuiet is memory for the sampler goroutine, which must not call t.Fatal.
func (s *loadStack) memoryQuiet() (rss, hwm int) {
	out, err := s.docker("run", "--rm", "--pid=container:"+loadSvc, loadProbe, "cat", "/proc/1/status")
	if err != nil {
		return 0, 0
	}
	for _, m := range statusRe.FindAllStringSubmatch(out, -1) {
		n, _ := strconv.Atoi(m[2])
		if m[1] == "VmRSS" {
			rss = n
		} else {
			hwm = n
		}
	}
	return rss, hwm
}

// k6 runs the k6 container and returns its summary. The public client rotates
// refresh tokens and a run keeps the new ones only in its own memory, so the
// caller seeds again before every run.
func (s *loadStack) k6(name, scenario, base, duration string, extra ...string) k6Summary {
	s.t.Helper()
	env := append([]string{
		"LOAD_NAME=" + name, "LOAD_SCENARIO=" + scenario, "LOAD_BASE=" + base, "LOAD_DURATION=" + duration,
	}, extra...)
	out, err := s.dockerEnv(env, "compose", "-f", loadCompose, "--profile", "run", "run", "--rm", "--no-deps", "k6")
	if err != nil {
		s.t.Fatalf("k6 %s: %v\n%s", name, err, out)
	}
	b, err := os.ReadFile(filepath.Join(s.out, "summary-"+name+".json"))
	if err != nil {
		s.t.Fatalf("k6 %s: no summary: %v\n%s", name, err, out)
	}
	var sum k6Summary
	if err := json.Unmarshal(b, &sum); err != nil {
		s.t.Fatal(err)
	}
	return sum
}

type k6Summary struct {
	Metrics map[string]struct {
		Values map[string]float64 `json:"values"`
	} `json:"metrics"`
}

func (k k6Summary) v(metric, stat string) float64 {
	m, ok := k.Metrics[metric]
	if !ok {
		return -1
	}
	if x, ok := m.Values[stat]; ok {
		return x
	}
	return -1
}

// ---- the service's own request log

type logStats struct {
	count      map[string]int
	p50, p95   map[string]float64
	p99        map[string]float64
	status5xx  int
	status4xx  int
	busy       int
	gcs        int            // garbage collections traced (GODEBUG=gctrace=1)
	gcStartMB  int            // largest heap at the start of a collection
	gcLiveMB   int            // largest heap live after a collection
	gcStacksMB int            // largest size of goroutine stacks
	by4xx      map[string]int // 4xx answers by status and endpoint
	ips        map[string]int // request lines by client_ip
	readyz5xx  int
	errLines   []string // the first request lines with a 5xx status
	totalLines int
}

var endpointOf = map[string]string{"token": "token", "userinfo": "userinfo", "jwks.json": "jwks", "authorize": "authorize"}

func classify(path string) string {
	if strings.Contains(path, "/callback/") {
		return "callback"
	}
	return endpointOf[path[strings.LastIndex(path, "/")+1:]]
}

func percentile(v []float64, p float64) float64 {
	if len(v) == 0 {
		return -1
	}
	sort.Float64s(v)
	i := int(float64(len(v))*p+0.999999) - 1
	return v[max(0, min(i, len(v)-1))]
}

// serviceLog reads the request lines of the service container between two
// instants.
func (s *loadStack) serviceLog(from, to time.Time) logStats {
	s.t.Helper()
	cmd := exec.CommandContext(context.Background(), "docker", "logs", "--since", from.Format(time.RFC3339Nano), "--until", to.Format(time.RFC3339Nano), loadSvc)
	cmd.Dir = ".."
	rd, err := cmd.StdoutPipe()
	if err != nil {
		s.t.Fatal(err)
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		s.t.Fatal(err)
	}
	durs := map[string][]float64{}
	st := logStats{ips: map[string]int{}, by4xx: map[string]int{}, count: map[string]int{}, p50: map[string]float64{}, p95: map[string]float64{}, p99: map[string]float64{}}
	sc := bufio.NewScanner(rd)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		st.totalLines++
		if strings.Contains(line, "SQLITE_BUSY") || strings.Contains(line, "database is locked") {
			st.busy++
		}
		if m := gcRe.FindStringSubmatch(line); m != nil {
			a, _ := strconv.Atoi(m[1])
			b, _ := strconv.Atoi(m[2])
			c, _ := strconv.Atoi(m[3])
			st.gcs++
			st.gcStacksMB = max(st.gcStacksMB, c)
			st.gcStartMB, st.gcLiveMB = max(st.gcStartMB, a), max(st.gcLiveMB, b)
			continue
		}
		var l struct {
			Msg    string  `json:"msg"`
			Path   string  `json:"path"`
			Status int     `json:"status"`
			Dur    float64 `json:"duration_ms"`
			IP     string  `json:"client_ip"`
		}
		if json.Unmarshal([]byte(line), &l) != nil || l.Msg != "request" {
			continue
		}
		st.ips[l.IP]++
		switch {
		case l.Status >= 500:
			st.status5xx++
			if l.Path == "/readyz" {
				st.readyz5xx++
			}
			if len(st.errLines) < 5 {
				st.errLines = append(st.errLines, line)
			}
		case l.Status >= 400:
			st.status4xx++
			st.by4xx[fmt.Sprintf("%d %s", l.Status, classify(l.Path))]++
		}
		if ep := classify(l.Path); ep != "" {
			durs[ep] = append(durs[ep], l.Dur)
		}
	}
	_ = cmd.Wait()
	for ep, v := range durs {
		st.count[ep] = len(v)
		st.p50[ep], st.p95[ep], st.p99[ep] = percentile(v, 0.50), percentile(v, 0.95), percentile(v, 0.99)
	}
	return st
}

// report collects the lines of the results file.
type report struct {
	t     *testing.T
	file  string // the file in LOAD_OUT that save writes
	lines []string
}

func (r *report) add(format string, args ...any) {
	line := fmt.Sprintf(format, args...)
	r.t.Log(line)
	r.lines = append(r.lines, line)
}

func (r *report) save(out string) {
	_ = os.WriteFile(filepath.Join(out, r.file), []byte(strings.Join(r.lines, "\n")+"\n"), 0o644)
}

func (r *report) endpoints(name string, k k6Summary, ls logStats) {
	for _, ep := range []string{"token", "userinfo", "jwks", "login_authorize", "login_idp", "login_callback", "login_token"} {
		m := "http_req_duration{ep:" + ep + "}"
		if _, ok := k.Metrics[m]; !ok {
			continue
		}
		r.add("%s client %s: n=%d p50=%.1f p95=%.1f p99=%.1f max=%.1f ms, failed rate %.4f, checks rate %.4f", name, ep,
			int(k.v("http_reqs{ep:"+ep+"}", "count")), k.v(m, "med"), k.v(m, "p(95)"), k.v(m, "p(99)"), k.v(m, "max"),
			k.v("http_req_failed{ep:"+ep+"}", "rate"), k.v("checks{ep:"+ep+"}", "rate"))
	}
	for _, ep := range []string{"token", "userinfo", "jwks", "authorize", "callback"} {
		if ls.count[ep] > 0 {
			r.add("%s service %s: n=%d p50=%.2f p95=%.2f p99=%.2f ms", name, ep, ls.count[ep], ls.p50[ep], ls.p95[ep], ls.p99[ep])
		}
	}
	for _, l := range ls.errLines {
		r.add("%s service 5xx line: %s", name, l)
	}
	if len(ls.ips) > 0 {
		top, topN := "", 0
		for ip, n := range ls.ips {
			if n > topN {
				top, topN = ip, n
			}
		}
		r.add("%s service: %d distinct client addresses in the request log, the busiest %s with %d requests", name, len(ls.ips), top, topN)
	}
	for k, n := range ls.by4xx {
		r.add("%s service 4xx answers: %s: %d", name, k, n)
	}
	if ls.gcs > 0 {
		r.add("%s service gctrace: %d collections, largest heap at the start of one %d MB, largest live heap %d MB, largest goroutine stacks %d MB", name, ls.gcs, ls.gcStartMB, ls.gcLiveMB, ls.gcStacksMB)
	}
	r.add("%s service: %d request log lines with status 5xx, %d with 4xx, %d SQLite busy lines, %d log lines", name, ls.status5xx, ls.status4xx, ls.busy, ls.totalLines)
}

func summarize(xs []sample) (minRSS, maxRSS, hwm int, meanCPU, maxCPU float64) {
	minRSS = 1 << 30
	for _, x := range xs {
		if x.rss == 0 {
			continue
		}
		minRSS, maxRSS, hwm = min(minRSS, x.rss), max(maxRSS, x.rss), max(hwm, x.hwm)
		meanCPU += x.cpu
		maxCPU = max(maxCPU, x.cpu)
	}
	if len(xs) > 0 {
		meanCPU /= float64(len(xs))
	}
	return
}

// Acceptance: Load
//
// The one condition of the row, "meets the non-functional targets, or the
// shortfall is recorded and the target revised with the measured numbers",
// is asserted here target by target, with the figures of NFR-01 to NFR-11
// (REQUIREMENTS.md): a measurement at or above its figure fails the run, with no
// recorded miss and no margin (DESIGN.md, Load verification, Decide).
//   - idle memory under 30 MB, image under 30 MB, startup under 2 seconds;
//   - steady p95 under 50 ms for /token, /userinfo and /jwks.json at 20 requests
//     a second, with no errors;
//   - peak: no errors at 1,000 concurrent connections; p95 for /userinfo and
//     /jwks.json under 3 and 2 ms (SQLite) or 5 s and 64 ms (Postgres); p99 for
//     /token under 15 s (SQLite) or 7 s (Postgres); memory under 120 MB;
//   - burst: p99 for /token under 3 seconds on both drivers;
//   - login overhead under 100 ms (the service's own durations of authorize,
//     callback and code exchange, which include the mock's round trips and so
//     are an upper bound);
//   - restart under load: no failure and the slowest answer under 10 seconds
//     through Caddy;
//   - soak: the resident memory does not grow;
//   - the results file with date, commit and machine: TestLoadResultsRecorded.
func TestLoadScenarios(t *testing.T) {
	if d := loadDriver(t); d != "sqlite" {
		t.Skipf("LOAD_DRIVER=%s: the SQLite scenarios do not run; see TestLoadScenariosPostgres", d)
	}
	runLoadScenarios(t)
}

// Acceptance: Load on Postgres
//
// The scenarios of Acceptance: Load with driver postgres (make load
// LOAD_DRIVER=postgres): the same assertions with the Postgres figures where they
// differ, and the results in the load section of docs/RESULTS.md under
// "### Postgres". The test skips with any other driver, so the Postgres run is
// the one with LOAD_DRIVER=postgres.
func TestLoadScenariosPostgres(t *testing.T) {
	if d := loadDriver(t); d != "postgres" {
		t.Skipf("LOAD_DRIVER=%s: the Postgres scenarios do not run; set LOAD_DRIVER=postgres", d)
	}
	runLoadScenarios(t)
}

// runLoadScenarios runs the scenarios of the Load verification on the driver of
// the load stack (LOAD_DRIVER).
func runLoadScenarios(t *testing.T) {
	users := 1000
	if v := os.Getenv("LOAD_USERS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			t.Fatalf("LOAD_USERS: %v", err)
		}
		users = n
	}
	idle := envDuration(t, "LOAD_IDLE", 60*time.Second)
	steady := envDuration(t, "LOAD_STEADY", 10*time.Minute)
	peak := envDuration(t, "LOAD_PEAK", 5*time.Minute)
	soak := envDuration(t, "LOAD_SOAK", time.Hour)
	restartRun := envDuration(t, "LOAD_RESTART", 2*time.Minute)

	s := newLoadStack(t)
	ctx := context.Background()
	rep := &report{t: t, file: resultsFile(s.driver)}
	defer rep.save(s.out)
	secs := func(d time.Duration) string { return strconv.Itoa(int(d.Seconds())) + "s" }
	caddyBase := "https://" + loadHost
	rep.add("driver %s, started %s, %d users, steady %v, peak %v, soak %v", s.driver, clock.Real().Now().Format(time.RFC3339), users, steady, peak, soak)

	s.seed(users)
	size, _ := strconv.Atoi(strings.TrimSpace(s.must("image", "inspect", "-f", "{{.Size}}", "featherauth-load:latest")))
	rep.add("image size: %d bytes", size)
	if size >= 30_000_000 {
		t.Errorf("image is %d bytes, target under 30 MB", size)
	}

	t.Run("idle", func(t *testing.T) {
		// A restart gives the idle process: started on the seeded database,
		// warmed by one discovery and one JWKS request, then 60 seconds alone.
		t0 := clock.Real().Now()
		s.must("stop", loadSvc)
		s.must("start", loadSvc)
		for {
			if _, err := s.docker("exec", loadSvc, "/featherauth", "healthcheck"); err == nil {
				break
			}
			if clock.Real().Now().Sub(t0) > 30*time.Second {
				t.Fatal("not ready")
			}
		}
		up := clock.Real().Now().Sub(t0)
		rep.add("startup: stop, start and ready (a docker exec healthcheck answered) in %v", up)
		if up >= 2*time.Second {
			t.Errorf("startup, with the docker stop, start and exec overhead, took %v, target under 2s", up)
		}
		if err := s.ready(ctx, loadCaddy); err != nil {
			t.Fatal(err)
		}
		c := s.client(loadCaddy)
		for _, p := range []string{"/" + loadRealm + "/.well-known/openid-configuration", "/" + loadRealm + "/jwks.json"} {
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+loadHost+p, nil)
			resp, err := c.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
		}
		pause(ctx, idle)
		rss, hwm := s.memory()
		rep.add("idle (%v after start and warm-up): VmRSS %d kB, VmHWM %d kB", idle, rss, hwm)
		if s.driver == "postgres" {
			pgKB, pgCPU := s.pgStats()
			rep.add("idle %s", pgLine([]sample{{pgKB: pgKB, pgCPU: pgCPU}}))
		}
		if rss >= 30*1000 {
			t.Errorf("idle memory %d kB, target under 30 MB", rss)
		}
	})

	checkSteady := func(t *testing.T, name string, k k6Summary) {
		for _, ep := range []string{"token", "userinfo", "jwks"} {
			if p95 := k.v("http_req_duration{ep:"+ep+"}", "p(95)"); p95 < 0 || p95 >= 50 {
				t.Errorf("%s: %s p95 %.1f ms, target under 50 ms", name, ep, p95)
			}
		}
		if f := k.v("http_req_failed", "rate"); f != 0 {
			t.Errorf("%s: failed request rate %v", name, f)
		}
		if c := k.v("checks", "rate"); c != 1 {
			t.Errorf("%s: checks rate %v", name, c)
		}
	}

	t.Run("steady", func(t *testing.T) {
		s.seed(users)
		stop := s.sampler(30 * time.Second)
		t0 := clock.Real().Now()
		k := s.k6("steady", "steady", caddyBase, secs(steady))
		t1 := clock.Real().Now()
		xs := stop()
		minRSS, maxRSS, hwm, cpu, cpuMax := summarize(xs)
		ls := s.serviceLog(t0, t1)
		rep.add("steady: %d requests in %v (%.1f/s), RSS %d..%d kB, VmHWM %d kB, CPU mean %.1f%% max %.1f%% of one CPU", int(k.v("http_reqs", "count")), steady, k.v("http_reqs", "rate"), minRSS, maxRSS, hwm, cpu, cpuMax)
		if line := pgLine(xs); line != "" {
			rep.add("steady %s", line)
		}
		rep.endpoints("steady", k, ls)
		checkSteady(t, "steady", k)
		// Login overhead: authorize, callback and the code exchange.
		sum := ls.p95["authorize"] + ls.p95["callback"] + ls.p95["token"]
		rep.add("steady login overhead upper bound: p95 authorize %.2f + callback %.2f + token %.2f = %.2f ms", ls.p95["authorize"], ls.p95["callback"], ls.p95["token"], sum)
		if sum >= 100 {
			t.Errorf("login overhead upper bound %.1f ms, target under 100 ms", sum)
		}
		if ls.busy != 0 {
			t.Errorf("%d SQLite busy lines", ls.busy)
		}
	})

	t.Run("peak", func(t *testing.T) {
		s.seed(users)
		stop := s.sampler(15 * time.Second)
		t0 := clock.Real().Now()
		k := s.k6("peak", "peak", caddyBase, secs(peak), "LOAD_VUS=1000")
		t1 := clock.Real().Now()
		xs := stop()
		pause(ctx, 30*time.Second)
		pauseRSS, pauseHWM := s.memory()
		minRSS, maxRSS, hwm, cpu, cpuMax := summarize(xs)
		ls := s.serviceLog(t0, t1)
		rep.add("peak: 1000 connections, %d requests in %v (%.0f/s), RSS %d..%d kB during, VmHWM %d kB, CPU mean %.1f%% max %.1f%%; settled 30 s after: VmRSS %d kB, VmHWM %d kB",
			int(k.v("http_reqs", "count")), peak, k.v("http_reqs", "rate"), minRSS, maxRSS, hwm, cpu, cpuMax, pauseRSS, pauseHWM)
		if s.driver == "postgres" {
			pgSettled, pgSettledCPU := s.pgStats()
			rep.add("peak %s; settled 30 s after: memory %d kB, CPU %.1f%% of one CPU", pgLine(xs), pgSettled, pgSettledCPU)
		}
		var series []string
		for _, x := range xs {
			series = append(series, strconv.Itoa(x.rss))
		}
		rep.add("peak VmRSS every 15 s from before the load starts to after it ends (kB): %s", strings.Join(series, " "))
		rep.add("peak: %d request log lines with status 5xx, %d of them /readyz", ls.status5xx, ls.readyz5xx)
		rep.endpoints("peak", k, ls)
		// NFR-03 and NFR-04: a measurement at or above its figure fails.
		lim := peakLimitsFor(s.driver)
		for ep, limit := range map[string]float64{"userinfo": lim.userinfoP95, "jwks": lim.jwksP95} {
			if p95 := k.v("http_req_duration{ep:"+ep+"}", "p(95)"); overLimit(p95, limit) {
				t.Errorf("peak: %s p95 %.1f ms, target under %.0f ms", ep, p95, limit)
			}
		}
		if p99 := k.v("http_req_duration{ep:token}", "p(99)"); overLimit(p99, lim.tokenP99) {
			t.Errorf("peak: token p99 %.1f ms, target under %.0f ms", p99, lim.tokenP99)
		}
		if f := k.v("http_req_failed", "rate"); f != 0 {
			t.Errorf("peak: failed request rate %v", f)
		}
		if c := k.v("checks", "rate"); c != 1 {
			t.Errorf("peak: checks rate %v", c)
		}
		if limit := peakMemoryLimitKB(s.driver); pauseHWM >= limit {
			t.Errorf("peak memory VmHWM %d kB, target under %d MB", pauseHWM, limit/1000)
		}
		if ls.busy != 0 {
			t.Errorf("%d SQLite busy lines", ls.busy)
		}
	})

	t.Run("burst", func(t *testing.T) {
		// The design's own picture of "1,000 simultaneous requests": 1,000
		// refreshes sent at the same instant, one per connection.
		s.seed(users)
		t0 := clock.Real().Now()
		k := s.k6("burst", "burst", caddyBase, "5m", "LOAD_VUS=1000")
		t1 := clock.Real().Now()
		rss, hwm := s.memory()
		ls := s.serviceLog(t0, t1)
		rep.add("burst: 1000 refreshes at once, VmRSS %d kB, VmHWM %d kB (the process has also served the steady and peak runs)", rss, hwm)
		rep.endpoints("burst", k, ls)
		if p99, limit := k.v("http_req_duration{ep:token}", "p(99)"), peakLimitsFor(s.driver).burstTokenP99; overLimit(p99, limit) {
			t.Errorf("burst: token p99 %.1f ms, target under %.0f ms", p99, limit)
		}
		if f := k.v("http_req_failed", "rate"); f != 0 {
			t.Errorf("burst: failed request rate %v", f)
		}
	})

	t.Run("restart under load", func(t *testing.T) {
		s.seed(users)
		done := make(chan time.Duration, 1)
		go func() {
			pause(ctx, restartRun/3)
			done <- s.restart()
		}()
		k := s.k6("restart", "steady", caddyBase, secs(restartRun))
		took := <-done
		rep.add("restart under load: steady 20/s through Caddy for %v, docker restart at one third took %v; %d requests, failed rate %.4f, checks rate %.4f, slowest %.0f ms",
			restartRun, took, int(k.v("http_reqs", "count")), k.v("http_req_failed", "rate"), k.v("checks", "rate"), k.v("http_req_duration", "max"))
		rep.endpoints("restart", k, logStats{})
		if f := k.v("http_req_failed", "rate"); f != 0 {
			t.Errorf("restart under load: failed request rate %v", f)
		}
		if c := k.v("checks", "rate"); c != 1 {
			t.Errorf("restart under load: checks rate %v", c)
		}
		if m := k.v("http_req_duration", "max"); m >= 10000 {
			t.Errorf("restart under load: slowest answer %.0f ms, want under 10 s", m)
		}
	})

	t.Run("soak", func(t *testing.T) {
		s.seed(users)
		rss0, _ := s.memory()
		stop := s.sampler(time.Minute)
		t0 := clock.Real().Now()
		k := s.k6("soak", "steady", caddyBase, secs(soak))
		t1 := clock.Real().Now()
		xs := stop()
		rss1, hwm1 := s.memory()
		minRSS, maxRSS, _, cpu, cpuMax := summarize(xs)
		ls := s.serviceLog(t0, t1)
		var series []string
		for _, x := range xs {
			series = append(series, strconv.Itoa(x.rss))
		}
		rep.add("soak: %d requests in %v, VmRSS at start %d kB, at end %d kB, minute samples min %d max %d kB, VmHWM %d kB, CPU mean %.1f%% max %.1f%%",
			int(k.v("http_reqs", "count")), soak, rss0, rss1, minRSS, maxRSS, hwm1, cpu, cpuMax)
		rep.add("soak VmRSS every minute (kB): %s", strings.Join(series, " "))
		if line := pgLine(xs); line != "" {
			rep.add("soak %s", line)
		}
		rep.endpoints("soak", k, ls)
		checkSteady(t, "soak", k)
		// "Does not grow": the last tenth of the samples is within 20% of the
		// first tenth (after the start-up, the heap settles).
		if n := len(xs); n >= 10 {
			avg := func(v []sample) float64 {
				var a float64
				for _, x := range v {
					a += float64(x.rss)
				}
				return a / float64(len(v))
			}
			first, last := avg(xs[n/10:n/5+1]), avg(xs[n-n/10:])
			rep.add("soak: mean VmRSS of the second tenth %.0f kB, of the last tenth %.0f kB", first, last)
			if last > first*1.2 {
				t.Errorf("soak: resident memory grew from %.0f to %.0f kB", first, last)
			}
		}
	})

	t.Run("rate limiter", func(t *testing.T) {
		// The default limit and the load spread over many source addresses: the
		// proxy is nginx, which appends the peer to the X-Forwarded-For header
		// the load sends, and the service trusts the network of the proxies.
		// The login steps need the host name of public_url to reach the proxy
		// under test, so nginx takes the name from Caddy.
		s.seed(users) // through Caddy and before the limit is on: the seeding comes from one address
		s.must("stop", "featherauth-load-caddy-1")
		s.must("network", "disconnect", "featherauth-load_default", "featherauth-load-nginx-1")
		s.must("network", "connect", "--alias", loadHost, "featherauth-load_default", "featherauth-load-nginx-1")
		s.WriteServer(loadServerYAML + "trusted_proxies: [\"" + loadSubnet + "\"]\n")
		s.restart()
		for range 120 {
			if _, err := s.docker("exec", loadSvc, "/featherauth", "healthcheck"); err == nil {
				break
			}
			pause(ctx, 250*time.Millisecond)
		}
		t0 := clock.Real().Now()
		k := s.k6("limiter", "steady", caddyBase, secs(steady), "LOAD_SPREAD=1")
		t1 := clock.Real().Now()
		ls := s.serviceLog(t0, t1)
		rep.add("rate limiter run: default limit, spread addresses through nginx, %d requests (%.1f/s), failed rate %.4f", int(k.v("http_reqs", "count")), k.v("http_reqs", "rate"), k.v("http_req_failed", "rate"))
		rep.endpoints("limiter", k, ls)
		if f := k.v("http_req_failed", "rate"); f != 0 {
			t.Errorf("limiter run: failed request rate %v (a 429 means the addresses were not told apart)", f)
		}
		if c := k.v("checks", "rate"); c != 1 {
			t.Errorf("limiter run: checks rate %v", c)
		}
	})
}

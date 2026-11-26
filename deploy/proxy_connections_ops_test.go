//go:build ops

package deploy_test

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/clock"
)

// connUpstream is the test's upstream for TestOpsCaddyOpensAConnectionPerRequest:
// a Go HTTP server on all interfaces with one listener per upstream address of
// a Caddyfile. It answers GET /readyz 200 on any connection, answers the first
// POST on a connection 200 with a fixed body, and closes a connection without
// answering when a POST arrives on a connection that already carried a
// request. It counts connections and POST requests.
type connUpstream struct {
	t       *testing.T
	ports   []string
	mu      sync.Mutex
	servers []*http.Server
	conns   int            // connections accepted
	posts   int            // POST requests received, answered or not
	answers []int          // connection id of each answered POST
	readyz  map[string]int // GET /readyz answered, by listener port
}

// upstreamConn is the state of one connection.
type upstreamConn struct {
	id       int
	requests int
}

type connKey struct{}

const upstreamBody = "upstream ok"

func newConnUpstream(t *testing.T, listeners int) *connUpstream {
	t.Helper()
	u := &connUpstream{t: t, readyz: map[string]int{}}
	for range listeners {
		port := u.serve("0.0.0.0:0")
		u.ports = append(u.ports, port)
	}
	t.Cleanup(u.close)
	return u
}

// serve listens on addr and serves on it; it returns the port.
func (u *connUpstream) serve(addr string) string {
	u.t.Helper()
	l, err := net.Listen("tcp", addr)
	if err != nil {
		u.t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(l.Addr().String())
	if err != nil {
		u.t.Fatal(err)
	}
	srv := &http.Server{
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       5 * time.Minute,
		Handler:           u.handler(port),
		ConnContext: func(ctx context.Context, _ net.Conn) context.Context {
			u.mu.Lock()
			defer u.mu.Unlock()
			u.conns++
			return context.WithValue(ctx, connKey{}, &upstreamConn{id: u.conns})
		},
	}
	u.mu.Lock()
	u.servers = append(u.servers, srv)
	u.mu.Unlock()
	go func() { _ = srv.Serve(l) }()
	return port
}

func (u *connUpstream) handler(port string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, _ := r.Context().Value(connKey{}).(*upstreamConn)
		u.mu.Lock()
		earlier := c.requests
		c.requests++
		if r.Method == http.MethodPost {
			u.posts++
		}
		u.mu.Unlock()
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/readyz":
			u.mu.Lock()
			u.readyz[port]++
			u.mu.Unlock()
			_, _ = io.WriteString(w, "ok")
		case r.Method == http.MethodPost && earlier > 0:
			// The race made certain: a POST on a connection that already
			// carried a request meets a connection the service is closing.
			hj, ok := w.(http.Hijacker)
			if !ok {
				panic("the upstream cannot hijack")
			}
			conn, _, err := hj.Hijack()
			if err == nil {
				_ = conn.Close()
			}
		case r.Method == http.MethodPost:
			_, _ = io.Copy(io.Discard, r.Body)
			u.mu.Lock()
			u.answers = append(u.answers, c.id)
			u.mu.Unlock()
			_, _ = io.WriteString(w, upstreamBody)
		default:
			http.NotFound(w, r)
		}
	})
}

// close closes every listener and every connection of the upstream.
func (u *connUpstream) close() {
	u.mu.Lock()
	servers := u.servers
	u.servers = nil
	u.mu.Unlock()
	for _, s := range servers {
		_ = s.Close()
	}
}

// reopen listens again on the same ports.
func (u *connUpstream) reopen() {
	for _, p := range u.ports {
		u.serve("0.0.0.0:" + p)
	}
}

func (u *connUpstream) counts() (posts int, answers []int, readyz map[string]int) {
	u.mu.Lock()
	defer u.mu.Unlock()
	r := map[string]int{}
	for k, v := range u.readyz {
		r[k] = v
	}
	return u.posts, append([]int(nil), u.answers...), r
}

// caddyImage is the Caddy image of compose.caddy.yaml.
func caddyImage(t *testing.T) string {
	t.Helper()
	img := readCompose(t, "compose.caddy.yaml").Services["caddy"].Image
	if !strings.HasPrefix(img, "caddy:") || !strings.Contains(img, "@sha256:") {
		t.Fatalf("compose.caddy.yaml: caddy image %q is not a pinned Caddy image", img)
	}
	return img
}

// deriveCaddyfile derives the test variant of a shipped Caddyfile the way
// deploy/ops/check-proxy.sh derives its variants: the site address becomes
// plain HTTP on the container port 80 (published on 127.0.0.1), and each
// upstream address becomes a listener of the test's upstream, reached as
// host.docker.internal. It fails when a replacement finds nothing, so a
// changed Caddyfile cannot silently test something else.
func deriveCaddyfile(t *testing.T, name string, ports []string) string {
	t.Helper()
	c := readFile(t, name)
	replace := func(old, repl string) {
		t.Helper()
		if !strings.Contains(c, old) {
			t.Fatalf("%s lacks %q: the derivation of this test must be updated", name, old)
		}
		c = strings.ReplaceAll(c, old, repl)
	}
	up := func(i int) string { return "host.docker.internal:" + ports[i] }
	switch name {
	case "Caddyfile.example":
		replace("\nauth.example.com {", "\n:80 {")
		replace("reverse_proxy 127.0.0.1:8080 {", "reverse_proxy "+up(0)+" {")
	case "Caddyfile.ha":
		replace("\n:8080 {", "\n:80 {")
		replace("reverse_proxy app1:8080 app2:8080 {", "reverse_proxy "+up(0)+" "+up(1)+" {")
	default:
		t.Fatalf("no derivation for %s", name)
	}
	return c
}

func dockerRun(t *testing.T, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", args...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, out.String())
	}
	return out.String()
}

// Acceptance: Restart (part)
//
// Proves OPS-13 (proxy connections): through Caddy with each shipped
// Caddyfile, every POST answers 200 from its own upstream connection, so a
// POST never meets a connection the service is closing, and a POST sent while
// the upstream refuses connections is held until it accepts again and reaches
// it once. With a Caddyfile that keeps idle upstream connections, the second
// POST to an upstream address meets a reused connection and answers 502.
func TestOpsCaddyOpensAConnectionPerRequest(t *testing.T) {
	img := caddyImage(t)
	for _, tc := range []struct {
		file      string
		listeners int
	}{
		{"Caddyfile.example", 1},
		{"Caddyfile.ha", 2},
	} {
		t.Run(tc.file, func(t *testing.T) {
			u := newConnUpstream(t, tc.listeners)
			dir := t.TempDir()
			cf := filepath.Join(dir, "Caddyfile")
			if err := os.WriteFile(cf, []byte(deriveCaddyfile(t, tc.file, u.ports)), 0o644); err != nil {
				t.Fatal(err)
			}
			openPermissions(t, dir) // readable by Caddy whatever the umask
			name := "featherauth-ci-caddy-conn-" + strings.ToLower(strings.ReplaceAll(tc.file, ".", "-"))
			_ = exec.CommandContext(context.Background(), "docker", "rm", "-f", name).Run()
			dockerRun(t, "run", "-d", "--name", name, "-p", "127.0.0.1::80",
				"--add-host", "host.docker.internal:host-gateway",
				"-v", cf+":/etc/caddy/Caddyfile:ro", img)
			t.Cleanup(func() {
				if t.Failed() {
					out, _ := exec.CommandContext(context.Background(), "docker", "logs", name).CombinedOutput()
					t.Logf("caddy logs:\n%s", out)
				}
				_ = exec.CommandContext(context.Background(), "docker", "rm", "-f", name).Run()
			})
			addr := strings.TrimSpace(strings.Split(dockerRun(t, "port", name, "80/tcp"), "\n")[0])
			base := "http://" + addr

			client := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
			do := func(method string) (int, string, error) {
				var body io.Reader
				if method == http.MethodPost {
					body = strings.NewReader("grant_type=refresh_token")
				}
				path := "/readyz"
				if method == http.MethodPost {
					path = "/token"
				}
				req, err := http.NewRequestWithContext(t.Context(), method, base+path, body)
				if err != nil {
					return 0, "", err
				}
				if body != nil {
					req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				}
				resp, err := client.Do(req)
				if err != nil {
					return 0, "", err
				}
				defer func() { _ = resp.Body.Close() }()
				b, err := io.ReadAll(resp.Body)
				return resp.StatusCode, string(b), err
			}

			// Caddy is ready when it proxies GET /readyz and, with active
			// health checks (Caddyfile.ha), when every listener has answered
			// one, so the round robin has both upstreams.
			ready := false
			for range 60 {
				st, _, err := do(http.MethodGet)
				_, _, rz := u.counts()
				if err == nil && st == http.StatusOK && len(rz) == tc.listeners {
					ready = true
					break
				}
				pause(t.Context(), 500*time.Millisecond)
			}
			if !ready {
				t.Fatal("caddy did not proxy GET /readyz to every upstream within 30 s")
			}

			// Two POST requests for each upstream address, one after the other.
			n := 2 * tc.listeners
			for i := range n {
				st, body, err := do(http.MethodPost)
				if err != nil {
					t.Fatalf("POST %d: %v", i, err)
				}
				if st != http.StatusOK || body != upstreamBody {
					t.Errorf("POST %d answered %d %q, want 200 %q", i, st, body, upstreamBody)
				}
			}
			posts, answers, _ := u.counts()
			if posts != n || len(answers) != n {
				t.Errorf("the upstream received %d POST requests and answered %d, want %d and %d", posts, len(answers), n, n)
			}
			seen := map[int]bool{}
			for _, id := range answers {
				if seen[id] {
					t.Errorf("two POST requests were answered on upstream connection %d", id)
				}
				seen[id] = true
			}
			if t.Failed() {
				return
			}

			// The hold: the listeners close, a POST is sent, and they open
			// again on the same ports 1 second later.
			u.close()
			reopened := make(chan struct{})
			start := clock.Real().Now()
			tm := clock.Real().AfterFunc(time.Second, func() {
				u.reopen()
				close(reopened)
			})
			defer tm.Stop()
			st, body, err := do(http.MethodPost)
			took := clock.Real().Now().Sub(start)
			<-reopened
			if err != nil {
				t.Fatalf("held POST: %v", err)
			}
			t.Logf("%s: held POST answered %d after %v", tc.file, st, took.Round(time.Millisecond))
			if st != http.StatusOK || body != upstreamBody {
				t.Errorf("held POST answered %d %q, want 200 %q", st, body, upstreamBody)
			}
			if took < time.Second || took >= 10*time.Second {
				t.Errorf("held POST took %v, want at least 1s and under 10s", took)
			}
			if after, _, _ := u.counts(); after != n+1 {
				t.Errorf("the upstream counted the held POST %d times, want once", after-n)
			}
		})
	}
}

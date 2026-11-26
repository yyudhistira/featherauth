package server_test

import (
	"context"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/server"
	"github.com/yyudhistira/featherauth/internal/testutil"
)

// Covers: FR-28 (part), FR-29 (part)
// Acceptance: Non-default URLs and token format (part)
func TestRoutingLayouts(t *testing.T) {
	type row struct {
		method, path string
		want         call
	}
	layouts := []struct {
		name   string
		server string
		rows   []row
	}{
		{"default", serverDefault, []row{
			{"GET", "/main/.well-known/openid-configuration", call{"discovery", "main", true, ""}},
			{"POST", "/main/authorize", call{"authorize", "main", true, ""}},
			{"GET", "/main/callback/google", call{"callback", "main", true, "google"}},
			{"GET", "/main/callback/google/continue", call{"continue", "main", true, "google"}},
			{"POST", "/main/token", call{"token", "main", true, ""}},
			{"GET", "/main/userinfo", call{"userinfo", "main", true, ""}},
			{"GET", "/main/jwks.json", call{"jwks", "main", true, ""}},
			{"GET", "/main/logout", call{"logout", "main", true, ""}},
			{"POST", "/main/revoke", call{"revoke", "main", true, ""}},
			{"DELETE", "/main/account", call{"account_delete", "main", true, ""}},
			{"GET", "/main/assets/style.css", call{"assets", "main", true, ""}},
			{"POST", "/main/events/apple", call{"provider_events", "main", true, "apple"}},
			{"GET", "/main/data-deletion", call{"data_deletion", "main", true, ""}},
			{"GET", "/other/token", call{"token", "other", true, ""}},
		}},
		{"/auth prefix", serverPrefix, []row{
			{"GET", "/auth/main/.well-known/openid-configuration", call{"discovery", "main", true, ""}},
			{"POST", "/auth/main/token", call{"token", "main", true, ""}},
			{"GET", "/auth/main/callback/github", call{"callback", "main", true, "github"}},
			{"GET", "/auth/main/assets/logos/google.svg", call{"assets", "main", true, ""}},
		}},
		{"keycloak", serverKeycloak, []row{
			{"GET", "/auth/realms/main/.well-known/openid-configuration", call{"discovery", "main", true, ""}},
			{"GET", "/auth/realms/main/protocol/openid-connect/auth", call{"authorize", "main", true, ""}},
			{"POST", "/auth/realms/main/protocol/openid-connect/token", call{"token", "main", true, ""}},
			{"GET", "/auth/realms/main/protocol/openid-connect/userinfo", call{"userinfo", "main", true, ""}},
			{"GET", "/auth/realms/main/protocol/openid-connect/certs", call{"jwks", "main", true, ""}},
			{"GET", "/auth/realms/main/protocol/openid-connect/logout", call{"logout", "main", true, ""}},
			{"GET", "/auth/realms/main/broker/google/endpoint", call{"callback", "main", true, "google"}},
			{"GET", "/auth/realms/main/broker/google/endpoint/continue", call{"continue", "main", true, "google"}},
			{"DELETE", "/auth/main/account", call{"account_delete", "main", true, ""}},
		}},
	}
	for _, l := range layouts {
		t.Run(l.name, func(t *testing.T) {
			e := newEnv(t, l.server, map[string]string{
				"main":  testutil.MinimalRealm("main"),
				"other": testutil.MinimalRealm("other"),
			}, nil)
			for _, r := range l.rows {
				before := e.h.count()
				rec := e.do(r.method, r.path, "")
				if rec.Code != http.StatusOK || e.h.count() != before+1 {
					t.Errorf("%s %s: status %d, handler called %v", r.method, r.path, rec.Code, e.h.count() == before+1)
					continue
				}
				if got := e.h.last(t); got != r.want {
					t.Errorf("%s %s: got %+v, want %+v", r.method, r.path, got, r.want)
				}
			}
		})
	}
}

// Covers: FR-28 (part), FR-29 (part)
// Acceptance: Non-default URLs and token format (part)
func TestDefaultPathsAre404WhenChanged(t *testing.T) {
	e := newEnv(t, serverKeycloak, map[string]string{"main": testutil.MinimalRealm("main")}, nil)
	for _, p := range []string{
		"/main/token", "/auth/main/token", "/auth/realms/main/token", "/main/authorize",
		"/main/callback/google", "/main/jwks.json", "/auth/main/jwks.json",
		"/auth/realms/main/protocol/openid-connect/token/", "/auth/realms/main/protocol/openid-connect",
		"/auth/realms/main/broker/google/endpoint/other", "/",
	} {
		if rec := e.do("GET", p, ""); rec.Code != http.StatusNotFound {
			t.Errorf("GET %s: status %d, want 404", p, rec.Code)
		}
	}
	if e.h.count() != 0 {
		t.Errorf("a handler was called %d times", e.h.count())
	}
}

// Covers: FR-21 (part)
// Acceptance: Unknown or disabled realm (part)
func TestUnknownRealm(t *testing.T) {
	e := newEnv(t, serverDefault, map[string]string{"main": testutil.MinimalRealm("main")}, nil)
	t.Run("API endpoints answer JSON", func(t *testing.T) {
		for _, p := range []string{"/nope/token", "/nope/userinfo", "/nope/jwks.json", "/nope/.well-known/openid-configuration", "/nope/account", "/nope/events/apple"} {
			rec := e.do("GET", p, "")
			if rec.Code != http.StatusNotFound {
				t.Errorf("%s: status %d", p, rec.Code)
			}
			if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
				t.Errorf("%s: content type %q", p, ct)
			}
			var body map[string]string
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("%s: %v", p, err)
			}
			if body["error"] != "invalid_request" || body["error_description"] != "unknown realm" {
				t.Errorf("%s: body %v", p, body)
			}
		}
	})
	t.Run("browser endpoints answer HTML", func(t *testing.T) {
		for _, p := range []string{"/nope/authorize", "/nope/callback/google", "/nope/callback/google/continue", "/nope/logout", "/nope/assets/style.css", "/nope/data-deletion"} {
			rec := e.do("GET", p, "")
			if rec.Code != http.StatusNotFound {
				t.Errorf("%s: status %d", p, rec.Code)
			}
			if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
				t.Errorf("%s: content type %q", p, ct)
			}
			if !strings.Contains(rec.Body.String(), "<html") {
				t.Errorf("%s: not an HTML page: %q", p, rec.Body.String())
			}
		}
	})
	if e.h.count() != 0 {
		t.Errorf("a handler was called %d times", e.h.count())
	}
}

// Covers: FR-21 (part)
// Acceptance: Unknown or disabled realm (part)
func TestDisabledRealmReachesHandlers(t *testing.T) {
	// A disabled realm refuses logins and refreshes in the handlers; discovery
	// and the JWKS stay available, so the router passes every request on and
	// tells the handler that the realm is disabled.
	e := newEnv(t, serverDefault, map[string]string{"off": testutil.RealmYAML("off", "enabled: false\n"+testutil.DefaultClients)}, nil)
	for _, p := range []string{"/off/.well-known/openid-configuration", "/off/jwks.json", "/off/authorize", "/off/token"} {
		before := e.h.count()
		if rec := e.do("GET", p, ""); rec.Code != http.StatusOK || e.h.count() != before+1 {
			t.Fatalf("%s: status %d", p, rec.Code)
		}
		if c := e.h.last(t); c.Realm != "off" || c.Enabled {
			t.Errorf("%s: handler saw %+v", p, c)
		}
	}
}

func TestRoutesFollowReload(t *testing.T) {
	src, dir := testutil.NewConfigDir(t, serverDefault, map[string]string{"main": testutil.MinimalRealm("main")})
	e := newEnvSrc(t, src, nil)
	if rec := e.do("GET", "/late/jwks.json", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("before the reload: status %d", rec.Code)
	}
	testutil.WriteRealm(t, dir, "late", testutil.MinimalRealm("late"))
	if res := src.Reload(context.Background()); !res.Applied {
		t.Fatalf("reload not applied: %+v", res)
	}
	if rec := e.do("GET", "/late/jwks.json", ""); rec.Code != http.StatusOK {
		t.Fatalf("after the reload: status %d", rec.Code)
	}
	if err := os.Remove(filepath.Join(dir.Root, "realms", "late.yaml")); err != nil {
		t.Fatal(err)
	}
	if res := src.Reload(context.Background()); !res.Applied {
		t.Fatalf("reload not applied: %+v", res)
	}
	if rec := e.do("GET", "/late/jwks.json", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("after removing the realm: status %d", rec.Code)
	}
}

func TestRouterUsesOneSnapshotPerRequest(t *testing.T) {
	src := testutil.NewConfig(t, serverDefault, map[string]string{"main": testutil.MinimalRealm("main")})
	e := newEnvSrc(t, src, nil)
	var seen *config.Snapshot
	e.h.run = func(w http.ResponseWriter, r *http.Request) {
		info, _ := server.FromContext(r.Context())
		seen = info.Snapshot
	}
	e.do("GET", "/main/jwks.json", "")
	if seen != src.Current() {
		t.Error("the request context does not carry the current snapshot")
	}
}

func TestPanicGives500AndALogLine(t *testing.T) {
	e := newEnv(t, serverDefault, map[string]string{"main": testutil.MinimalRealm("main")}, nil)
	e.h.run = func(http.ResponseWriter, *http.Request) { panic("boom: secret-value-123") }

	t.Run("API endpoint", func(t *testing.T) {
		rec := e.do("POST", "/main/token", "")
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status %d", rec.Code)
		}
		var body map[string]string
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body["error"] != "server_error" {
			t.Errorf("body %q", rec.Body.String())
		}
	})
	t.Run("browser endpoint", func(t *testing.T) {
		rec := e.do("GET", "/main/authorize", "")
		if rec.Code != http.StatusInternalServerError || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html") {
			t.Fatalf("status %d, type %q", rec.Code, rec.Header().Get("Content-Type"))
		}
	})
	lines := e.log.lines(t)
	var panics, requests int
	for _, l := range lines {
		switch l["msg"] {
		case "panic":
			panics++
			if strings.Contains(l["panic_type"].(string), "secret") || strings.Contains(mustJSON(l), "secret-value-123") {
				t.Errorf("the panic value was logged: %v", l)
			}
		case "request":
			requests++
			if l["status"] != float64(500) {
				t.Errorf("request line status %v", l["status"])
			}
		}
	}
	if panics != 2 || requests != 2 {
		t.Errorf("got %d panic and %d request lines in %v", panics, requests, lines)
	}
	// The router keeps serving.
	e.h.run = nil
	if rec := e.do("POST", "/main/token", ""); rec.Code != http.StatusOK {
		t.Errorf("after a panic: status %d", rec.Code)
	}
}

func TestPanicAfterTheAnswerStartedKeepsItsStatus(t *testing.T) {
	e := newEnv(t, serverDefault, map[string]string{"main": testutil.MinimalRealm("main")}, nil)
	e.h.run = func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		panic("late")
	}
	if rec := e.do("POST", "/main/token", ""); rec.Code != http.StatusAccepted {
		t.Errorf("status %d", rec.Code)
	}
}

func TestAbortHandlerPanicIsNotSwallowed(t *testing.T) {
	e := newEnv(t, serverDefault, map[string]string{"main": testutil.MinimalRealm("main")}, nil)
	e.h.run = func(http.ResponseWriter, *http.Request) { panic(http.ErrAbortHandler) }
	defer func() {
		if recover() != http.ErrAbortHandler {
			t.Error("http.ErrAbortHandler was swallowed")
		}
	}()
	e.do("POST", "/main/token", "")
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func TestLargeBodyGives413(t *testing.T) {
	e := newEnv(t, serverDefault, map[string]string{"main": testutil.MinimalRealm("main")}, nil)
	big := strings.Repeat("a", 64*1024+1)
	ok := strings.Repeat("a", 64*1024)

	t.Run("API endpoint with a length", func(t *testing.T) {
		rec := e.do("POST", "/main/token", big)
		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("status %d", rec.Code)
		}
		var body map[string]string
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body["error"] != "invalid_request" || body["error_description"] != "request body too large" {
			t.Errorf("body %q", rec.Body.String())
		}
	})
	t.Run("browser endpoint", func(t *testing.T) {
		rec := e.do("POST", "/main/authorize", big)
		if rec.Code != http.StatusRequestEntityTooLarge || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html") {
			t.Fatalf("status %d, type %q", rec.Code, rec.Header().Get("Content-Type"))
		}
	})
	t.Run("unknown length", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/main/token", strings.NewReader(big))
		req.ContentLength = -1
		rec := httptest.NewRecorder()
		e.rt.ServeHTTP(rec, req)
		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("status %d", rec.Code)
		}
	})
	t.Run("exactly 64 KB passes and the handler reads it all", func(t *testing.T) {
		var got int
		e.h.run = func(w http.ResponseWriter, r *http.Request) {
			buf := make([]byte, 4096)
			for {
				n, err := r.Body.Read(buf)
				got += n
				if err != nil {
					break
				}
			}
		}
		defer func() { e.h.run = nil }()
		if rec := e.do("POST", "/main/token", ok); rec.Code != http.StatusOK || got != len(ok) {
			t.Errorf("status %d, read %d bytes", rec.Code, got)
		}
	})
	t.Run("the handler is not called for the large body", func(t *testing.T) {
		before := e.h.count()
		e.do("POST", "/main/token", big)
		if e.h.count() != before {
			t.Error("the handler ran")
		}
	})
}

// Covers: FR-16 (part)
// Acceptance: Health (part)
func TestHealthz(t *testing.T) {
	e := newEnv(t, serverDefault, map[string]string{"main": testutil.MinimalRealm("main")}, nil)
	if rec := e.do("GET", "/healthz", ""); rec.Code != http.StatusOK {
		t.Errorf("status %d", rec.Code)
	}
	if e.h.count() != 0 {
		t.Error("a handler was called")
	}
}

// Covers: FR-16
// Acceptance: Health
func TestReadyzFollowsTheStore(t *testing.T) {
	st := testutil.NewStore(t)
	e := newEnv(t, serverDefault, map[string]string{"main": testutil.MinimalRealm("main")}, func(m *server.Middleware) { m.Ready = st })
	for _, p := range []string{"/healthz", "/readyz"} {
		if rec := e.do("GET", p, ""); rec.Code != http.StatusOK {
			t.Errorf("%s with the store up: status %d", p, rec.Code)
		}
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	if rec := e.do("GET", "/readyz", ""); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("/readyz with the store down: status %d", rec.Code)
	}
	if rec := e.do("GET", "/healthz", ""); rec.Code != http.StatusOK {
		t.Errorf("/healthz with the store down: status %d", rec.Code)
	}
}

// Covers: FR-16 (part)
// Acceptance: Health (part)
func TestReadyzWithAFailingPinger(t *testing.T) {
	fail := errors.New("down")
	var err error
	e := newEnv(t, serverDefault, map[string]string{"main": testutil.MinimalRealm("main")}, func(m *server.Middleware) {
		m.Ready = pinger(func() error { return err })
	})
	if rec := e.do("GET", "/readyz", ""); rec.Code != http.StatusOK {
		t.Errorf("status %d", rec.Code)
	}
	err = fail
	if rec := e.do("GET", "/readyz", ""); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status %d", rec.Code)
	}
}

// Covers: FR-16 (part)
// Acceptance: Restart (part)
func TestReadyzIs503OnceShutdownBegins(t *testing.T) {
	e := newEnv(t, serverDefault, map[string]string{"main": testutil.MinimalRealm("main")}, nil)
	if rec := e.do("GET", "/readyz", ""); rec.Code != http.StatusOK {
		t.Fatalf("before: status %d", rec.Code)
	}
	e.rt.BeginShutdown()
	if rec := e.do("GET", "/readyz", ""); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("/readyz during shutdown: status %d", rec.Code)
	}
	if rec := e.do("GET", "/healthz", ""); rec.Code != http.StatusOK {
		t.Errorf("/healthz during shutdown: status %d", rec.Code)
	}
}

// Covers: FR-16 (part)
// Acceptance: Restart (part)
func TestShutdownLetsAnInFlightRequestComplete(t *testing.T) {
	e := newEnv(t, serverDefault, map[string]string{"main": testutil.MinimalRealm("main")}, nil)
	started, release := make(chan struct{}), make(chan struct{})
	e.h.run = func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
		_, _ = w.Write([]byte("done"))
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := server.New(ln.Addr().String(), e.rt)
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ln) }()

	client := &http.Client{Timeout: 10 * time.Second}
	type result struct {
		body string
		err  error
	}
	res := make(chan result, 1)
	go func() {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://"+ln.Addr().String()+"/main/token", nil)
		if err != nil {
			res <- result{err: err}
			return
		}
		resp, err := client.Do(req)
		if err != nil {
			res <- result{err: err}
			return
		}
		defer resp.Body.Close()
		b := make([]byte, 16)
		n, _ := resp.Body.Read(b)
		res <- result{body: string(b[:n])}
	}()
	<-started

	shut := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		shut <- srv.Shutdown(ctx)
	}()
	// Shutdown marks the router not ready before it waits for the request.
	for {
		if e.do("GET", "/readyz", "").Code == http.StatusServiceUnavailable {
			break
		}
		select {
		case err := <-shut:
			t.Fatalf("Shutdown returned early: %v", err)
		default:
		}
	}
	close(release)
	if r := <-res; r.err != nil || r.body != "done" {
		t.Fatalf("in-flight request: %q, %v", r.body, r.err)
	}
	if err := <-shut; err != nil {
		t.Errorf("Shutdown: %v", err)
	}
	if err := <-served; !errors.Is(err, http.ErrServerClosed) {
		t.Errorf("Serve: %v", err)
	}
}

// Covers: SEC-45 (part)
// Acceptance: Request size and slow clients (part)
func TestHTTPServerTimeouts(t *testing.T) {
	e := newEnv(t, serverDefault, map[string]string{"main": testutil.MinimalRealm("main")}, nil)
	srv := server.NewHTTPServer(":0", e.rt)
	if srv.ReadHeaderTimeout != 5*time.Second || srv.ReadTimeout != 10*time.Second ||
		srv.WriteTimeout != 60*time.Second || srv.IdleTimeout != 120*time.Second {
		t.Errorf("timeouts: header %v read %v write %v idle %v", srv.ReadHeaderTimeout, srv.ReadTimeout, srv.WriteTimeout, srv.IdleTimeout)
	}
	if srv.Handler != http.Handler(e.rt) {
		t.Error("the server does not serve the router")
	}
}

func TestRequestLog(t *testing.T) {
	e := newEnv(t, serverDefault, map[string]string{"main": testutil.MinimalRealm("main")}, nil)
	e.do("GET", "/main/jwks.json?code=abc&state=xyz", "")
	e.do("GET", "/nope/jwks.json?id_token_hint=t", "")
	e.do("GET", "/healthz", "")
	lines := e.log.lines(t)
	if len(lines) != 3 {
		t.Fatalf("got %d lines: %v", len(lines), lines)
	}
	want := []struct {
		path   string
		status float64
		realm  string
	}{{"/main/jwks.json", 200, "main"}, {"/nope/jwks.json", 404, ""}, {"/healthz", 200, ""}}
	for i, w := range want {
		l := lines[i]
		if l["msg"] != "request" || l["method"] != "GET" || l["path"] != w.path || l["status"] != w.status || l["realm"] != w.realm {
			t.Errorf("line %d: %v", i, l)
		}
		if l["client_ip"] != "192.0.2.10" {
			t.Errorf("line %d client_ip %v", i, l["client_ip"])
		}
		if _, ok := l["duration_ms"]; !ok {
			t.Errorf("line %d has no duration_ms", i)
		}
	}
	if s := mustJSON(lines); strings.Contains(s, "abc") || strings.Contains(s, "xyz") {
		t.Errorf("a query value was logged: %s", s)
	}
}

// Every http.Server the service starts is made by NewHTTPServer, so the fixed
// timeouts of TestHTTPServerTimeouts hold for all of them (the main listener,
// the redirect listener and the loopback listener of built-in TLS): no other
// file of the service builds one.
//
// Covers: SEC-45 (part)
// Acceptance: Request size and slow clients (part)
func TestEveryHTTPServerIsBuiltByNewHTTPServer(t *testing.T) {
	fset := token.NewFileSet()
	var found []string
	for _, root := range []string{"../../cmd", ".."} {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}
			f, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				return err
			}
			ast.Inspect(f, func(n ast.Node) bool {
				if lit, ok := n.(*ast.CompositeLit); ok {
					if sel, ok := lit.Type.(*ast.SelectorExpr); ok && sel.Sel.Name == "Server" {
						if id, ok := sel.X.(*ast.Ident); ok && id.Name == "http" {
							found = append(found, filepath.ToSlash(path))
						}
					}
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	slices.Sort(found)
	if want := []string{"../server/httpserver.go"}; !slices.Equal(found, want) {
		t.Errorf("http.Server literals in %v, want only %v", found, want)
	}
}

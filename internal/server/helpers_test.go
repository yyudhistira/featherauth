package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/logx"
	"github.com/yyudhistira/featherauth/internal/server"
	"github.com/yyudhistira/featherauth/internal/testutil"
)

var testStart = time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)

const (
	serverDefault  = "public_url: https://auth.example.com\n"
	serverPrefix   = "public_url: https://auth.example.com\nurls:\n  path_prefix: /auth\n"
	serverKeycloak = `public_url: https://auth.example.com
urls:
  path_prefix: /auth
  issuer: "{prefix}/realms/{realm}"
  endpoints:
    authorize: "{prefix}/realms/{realm}/protocol/openid-connect/auth"
    token: "{prefix}/realms/{realm}/protocol/openid-connect/token"
    userinfo: "{prefix}/realms/{realm}/protocol/openid-connect/userinfo"
    jwks: "{prefix}/realms/{realm}/protocol/openid-connect/certs"
    logout: "{prefix}/realms/{realm}/protocol/openid-connect/logout"
    callback: "{prefix}/realms/{realm}/broker/{provider}/endpoint"
`
)

// call is one handler invocation seen by the stub.
type call struct {
	Endpoint string
	Realm    config.RealmName
	Enabled  bool
	Provider config.ProviderKey
}

// stub implements server.Handlers and records every call.
type stub struct {
	mu    sync.Mutex
	calls []call
	// run, when set, runs inside every handler before it answers.
	run func(w http.ResponseWriter, r *http.Request)
}

var _ server.Handlers = (*stub)(nil)

func (s *stub) rec(name string, w http.ResponseWriter, r *http.Request) {
	info, ok := server.FromContext(r.Context())
	c := call{Endpoint: name}
	if ok {
		if info.Realm != nil {
			c.Realm = info.Realm.Name
			c.Enabled = info.Realm.Enabled
		}
		c.Provider = info.Provider
	}
	s.mu.Lock()
	s.calls = append(s.calls, c)
	s.mu.Unlock()
	if s.run != nil {
		s.run(w, r)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *stub) last(t *testing.T) call {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.calls) == 0 {
		t.Fatal("no handler was called")
	}
	return s.calls[len(s.calls)-1]
}

func (s *stub) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.calls)
}

func (s *stub) Discovery(w http.ResponseWriter, r *http.Request)        { s.rec("discovery", w, r) }
func (s *stub) Authorize(w http.ResponseWriter, r *http.Request)        { s.rec("authorize", w, r) }
func (s *stub) Callback(w http.ResponseWriter, r *http.Request)         { s.rec("callback", w, r) }
func (s *stub) CallbackContinue(w http.ResponseWriter, r *http.Request) { s.rec("continue", w, r) }
func (s *stub) Token(w http.ResponseWriter, r *http.Request)            { s.rec("token", w, r) }
func (s *stub) Userinfo(w http.ResponseWriter, r *http.Request)         { s.rec("userinfo", w, r) }
func (s *stub) JWKS(w http.ResponseWriter, r *http.Request)             { s.rec("jwks", w, r) }
func (s *stub) Logout(w http.ResponseWriter, r *http.Request)           { s.rec("logout", w, r) }
func (s *stub) Revoke(w http.ResponseWriter, r *http.Request)           { s.rec("revoke", w, r) }
func (s *stub) Sessions(w http.ResponseWriter, r *http.Request)         { s.rec("sessions", w, r) }
func (s *stub) AccountDelete(w http.ResponseWriter, r *http.Request)    { s.rec("account_delete", w, r) }
func (s *stub) Assets(w http.ResponseWriter, r *http.Request)           { s.rec("assets", w, r) }
func (s *stub) ProviderEvents(w http.ResponseWriter, r *http.Request)   { s.rec("provider_events", w, r) }
func (s *stub) DataDeletion(w http.ResponseWriter, r *http.Request)     { s.rec("data_deletion", w, r) }

// syncBuf is a log sink safe for concurrent writes.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

// lines returns the log lines parsed as JSON objects.
func (s *syncBuf) lines(t *testing.T) []map[string]any {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(s.b.String()), "\n") {
		if l == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("log line is not JSON: %q", l)
		}
		out = append(out, m)
	}
	return out
}

type env struct {
	rt  *server.Router
	h   *stub
	log *syncBuf
	src config.Source
	clk *clock.Fake
}

type pinger func() error

func (p pinger) Ping(_ context.Context) error { return p() }

// newEnv builds the router over a configuration with the given realms (name
// to realm YAML).
func newEnv(t *testing.T, serverYAML string, realms map[string]string, mw func(*server.Middleware)) *env {
	t.Helper()
	src := testutil.NewConfig(t, serverYAML, realms)
	return newEnvSrc(t, src, mw)
}

func newEnvSrc(t *testing.T, src config.Source, mw func(*server.Middleware)) *env {
	t.Helper()
	e := &env{h: &stub{}, log: &syncBuf{}, src: src, clk: clock.NewFake(testStart)}
	m := server.Middleware{Logger: logx.New(e.log, slog.LevelInfo, e.clk), Clock: e.clk}
	if mw != nil {
		mw(&m)
	}
	e.rt = server.NewHandler(src, e.h, m)
	return e
}

func (e *env) do(method, target string, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.RemoteAddr = "192.0.2.10:4000"
	rec := httptest.NewRecorder()
	e.rt.ServeHTTP(rec, req)
	return rec
}

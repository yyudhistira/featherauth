package main

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/logx"
	"github.com/yyudhistira/featherauth/internal/oidc"
	"github.com/yyudhistira/featherauth/internal/secure"
	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/testutil"
	"github.com/yyudhistira/featherauth/internal/testutil/configdir"
	"github.com/yyudhistira/featherauth/internal/testutil/server"
)

// outgoing records the outgoing connections of the process: the requests that
// reach http.DefaultTransport (where an http.Client without a transport ends)
// and the lookups of a host name that the resolver would send to a DNS server.
// A host given as an IP address needs no lookup, so it is recorded by the
// transport only; the source scan below covers the rest.
type outgoing struct {
	mu      sync.Mutex
	hosts   []string // hosts of requests through http.DefaultTransport
	lookups int      // names the resolver was asked to send to a DNS server
}

func (o *outgoing) RoundTrip(r *http.Request) (*http.Response, error) {
	o.mu.Lock()
	o.hosts = append(o.hosts, r.URL.Host)
	o.mu.Unlock()
	return http.DefaultTransport.(*http.Transport).RoundTrip(r)
}

// recordOutgoing swaps http.DefaultTransport and net.DefaultResolver for
// recording ones until the test ends. The lookup fails, so a name that is not
// in the hosts file does not leave the machine. It changes globals: the test
// must not use t.Parallel.
func recordOutgoing(t *testing.T) *outgoing {
	t.Helper()
	o := &outgoing{}
	origTransport, origResolver := http.DefaultTransport, net.DefaultResolver
	base := origTransport.(*http.Transport).Clone()
	http.DefaultTransport = recordingTransport{o, base}
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		o.mu.Lock()
		o.lookups++
		o.mu.Unlock()
		return nil, errors.New("no_telemetry_test: name lookups are not allowed")
	}}
	t.Cleanup(func() { http.DefaultTransport, net.DefaultResolver = origTransport, origResolver })
	return o
}

type recordingTransport struct {
	o    *outgoing
	base *http.Transport
}

func (r recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r.o.mu.Lock()
	r.o.hosts = append(r.o.hosts, req.URL.Host)
	r.o.mu.Unlock()
	return r.base.RoundTrip(req)
}

func (o *outgoing) seen() ([]string, int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return slices.Clone(o.hosts), o.lookups
}

// hostRecorder is a transport that records the host of each request it carries.
type hostRecorder struct {
	mu    sync.Mutex
	hosts []string
	next  http.RoundTripper
}

func (h *hostRecorder) RoundTrip(r *http.Request) (*http.Response, error) {
	h.mu.Lock()
	h.hosts = append(h.hosts, r.URL.Host)
	h.mu.Unlock()
	return h.next.RoundTrip(r)
}

// outgoingAllowed lists the non-test source files that may open an outgoing
// connection, and why. A directory ends with a slash.
var outgoingAllowed = map[string]string{
	"internal/provider/":                   "the providers' token, user-info, key, discovery, revocation, Graph, GitHub API and security-event configuration endpoints",
	"internal/oidc/backchannel_deliver.go": "the back-channel logout URIs of clients",
	"internal/store/postgresconn.go":       "the database",
	"cmd/featherauth/health.go":            "the health check, which asks the service itself on its own listener",
}

// outgoingUses returns what a source file does that can open an outgoing
// connection: the client, transport, dialer, resolver and lookup names of
// net/http, net and crypto/tls, and the import of a package whose purpose is to
// call out.
func outgoingUses(fset *token.FileSet, f *ast.File) []string {
	names := map[string][]string{ // import path -> selectors that call out
		"net/http":   {"Client", "Transport", "DefaultClient", "DefaultTransport", "Get", "Head", "Post", "PostForm"},
		"net":        {"Dial", "DialTCP", "DialUDP", "DialIP", "DialUnix", "DialTimeout", "Dialer", "Resolver", "DefaultResolver", "LookupHost", "LookupIP", "LookupAddr", "LookupCNAME", "LookupMX", "LookupNS", "LookupSRV", "LookupTXT", "LookupPort"},
		"crypto/tls": {"Dial", "DialWithDialer"},
	}
	whole := []string{"net/smtp", "net/rpc", "golang.org/x/oauth2", "github.com/coreos/go-oidc/v3/oidc"}
	local := map[string]string{} // local name -> import path
	var uses []string
	for _, imp := range f.Imports {
		path, _ := strconv.Unquote(imp.Path.Value)
		if _, ok := names[path]; ok {
			name := path[strings.LastIndex(path, "/")+1:]
			if imp.Name != nil {
				name = imp.Name.Name
			}
			local[name] = path
		}
		for _, w := range whole {
			if path == w || strings.HasPrefix(path, w+"/") {
				uses = append(uses, "imports "+path)
			}
		}
	}
	ast.Inspect(f, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		id, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		path, ok := local[id.Name]
		if ok && slices.Contains(names[path], sel.Sel.Name) {
			uses = append(uses, fmt.Sprintf("%s.%s at %s", id.Name, sel.Sel.Name, fset.Position(sel.Pos())))
		}
		return true
	})
	return uses
}

// scanOutgoing returns the source files under root (cmd and internal, tests and
// test support excluded) that can open an outgoing connection and are not in
// the allowed list.
func scanOutgoing(t *testing.T, root string, allowed map[string]string) []string {
	t.Helper()
	var bad []string
	fset := token.NewFileSet()
	for _, top := range []string{"cmd", "internal"} {
		if _, err := os.Stat(filepath.Join(root, top)); err != nil {
			continue
		}
		err := filepath.WalkDir(filepath.Join(root, top), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(root, path)
			rel = filepath.ToSlash(rel)
			if d.IsDir() {
				if strings.HasPrefix(rel, "internal/testutil") || strings.HasSuffix(d.Name(), "test") {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") {
				return nil
			}
			for prefix := range allowed {
				if rel == prefix || strings.HasSuffix(prefix, "/") && strings.HasPrefix(rel, prefix) {
					return nil
				}
			}
			f, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				return err
			}
			for _, u := range outgoingUses(fset, f) {
				bad = append(bad, rel+": "+u)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	sort.Strings(bad)
	return bad
}

// No telemetry: the service's only outgoing connections are to its database,
// to the configured providers and to the back-channel logout URIs of clients.
// The test records what a login, the token endpoint, userinfo, a refresh, the commands and the back-channel worker connect to, with
// http.DefaultTransport and the resolver replaced by recording ones (a client
// that does not use its own transport, or a call to a name, shows up), and scans
// the source for every place that can open a connection.
//
// Covers: SEC-46
// Acceptance: No telemetry
func TestNoTelemetry(t *testing.T) {
	t.Run("a flow reaches only the configured providers and the receiver", func(t *testing.T) {
		rec := recordOutgoing(t)
		e := server.New(t)
		app := server.ClientQuery
		env := serviceConfigDir(t, e)

		tk := e.Exchange(t, app, e.Login(t, app))
		bearer := http.Header{"Authorization": {"Bearer " + tk.AccessToken}}
		if r := e.NewClient().Request(t, http.MethodGet, e.Realm.EndpointURL(config.EndpointUserinfo, ""), "", bearer); r.Code != http.StatusOK {
			t.Fatalf("userinfo %d", r.Code)
		}
		if got := e.NewClient().PostToken(t, server.RefreshForm(app, tk.RefreshToken), nil).Tokens(t); got.Error != "" {
			t.Fatalf("refresh %q", got.Error)
		}
		for _, args := range [][]string{{"config", "check", e.ConfigDir()}, {"user", "list", "main", "--email", "ann@example.com"}} {
			if r := execAt(t, clock.NewFake(time.Unix(1_800_000_000, 0)), env, args...); r.code != 0 {
				t.Fatalf("%v: %+v", args, r)
			}
		}

		allowed := map[string]bool{}
		for _, m := range e.Mocks {
			u, err := url.Parse(m.URL())
			if err != nil {
				t.Fatal(err)
			}
			allowed[u.Host] = true
		}
		hosts, lookups := rec.seen()
		for _, h := range hosts {
			if !allowed[h] {
				t.Errorf("a request through http.DefaultTransport reached %q, not a configured provider", h)
			}
		}
		if lookups != 0 {
			t.Errorf("%d names were looked up, want none: every endpoint of the test is an address", lookups)
		}
	})

	t.Run("the back-channel worker posts only to the client's URI", func(t *testing.T) {
		rec := recordOutgoing(t)
		got := make(chan struct{}, 4)
		recv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			got <- struct{}{}
			w.WriteHeader(http.StatusOK)
		}))
		t.Cleanup(recv.Close)
		clk := clock.NewFake(time.Date(2026, 11, 19, 9, 0, 0, 0, time.UTC))
		st, _ := testutil.NewStoreFile(t)
		t.Cleanup(func() { _ = st.Close() })
		dir := configdir.New(t)
		dir.Server(t, "public_url: http://auth.example.test\nrequire_https: false\n")
		dir.RSAKey(t, "secrets/main/rsa.pem")
		dir.Realm(t, "main", "name: main\nkeys:\n  - {kid: rsa1, file: secrets/main/rsa.pem, state: active}\nclients:\n  app:\n    redirect_uris: [https://app.example.test/cb]\n    backchannel_logout_uri: "+strconv.Quote(recv.URL+"/logout")+"\n")
		loader, err := config.NewLoader(dir.Root, clk, nil)
		if err != nil {
			t.Fatal(err)
		}
		ctx := context.Background()
		var realm store.RealmID
		if err := st.Write(ctx, func(tx store.Tx) error {
			var err error
			realm, err = tx.Realms().Ensure(ctx, "main", "R1", clk.Now())
			if err != nil {
				return err
			}
			return tx.LogoutNotifications().Enqueue(ctx, store.LogoutNotification{
				ID: "n1", RealmID: realm, ClientID: "app", UserID: "u1", SessionID: "s1", NextAttemptAt: clk.Now(), CreatedAt: clk.Now(),
			})
		}); err != nil {
			t.Fatal(err)
		}
		hr := &hostRecorder{next: &http.Transport{}}
		d := oidc.NewDeliverer(oidc.DeliverConfig{
			Store: st, Source: loader, Clock: clk, Rand: secure.Default,
			Log: logx.New(&strings.Builder{}, 0, clk), Transport: hr,
		})
		d.Start()
		t.Cleanup(func() { _ = d.Stop(ctx) })
		clk.Advance(10 * time.Second)
		<-got // a worker that never posts ends in the test timeout
		u, _ := url.Parse(recv.URL)
		hr.mu.Lock()
		defer hr.mu.Unlock()
		if len(hr.hosts) == 0 {
			t.Fatal("the transport carried no post")
		}
		for _, h := range hr.hosts {
			if h != u.Host {
				t.Errorf("the worker posted to %q, want only %q", h, u.Host)
			}
		}
		if hosts, lookups := rec.seen(); len(hosts) != 0 || lookups != 0 {
			t.Errorf("the worker used http.DefaultTransport for %v or looked up %d names", hosts, lookups)
		}
	})

	t.Run("the recorder sees a call to another host", func(t *testing.T) {
		rec := recordOutgoing(t)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://telemetry.invalid/", nil)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = (&http.Client{Timeout: time.Second}).Do(req)
		if hosts, _ := rec.seen(); !slices.Equal(hosts, []string{"telemetry.invalid"}) {
			t.Fatalf("recorded hosts %v, want the call to telemetry.invalid", hosts)
		}
		_, err = (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", "telemetry.invalid:443")
		if err == nil {
			t.Fatal("a dial of an unknown name succeeded")
		}
		if _, lookups := rec.seen(); lookups == 0 {
			t.Fatal("the lookup of telemetry.invalid was not recorded")
		}
	})

	t.Run("only the named sources open outgoing connections", func(t *testing.T) {
		if bad := scanOutgoing(t, "../..", outgoingAllowed); len(bad) != 0 {
			t.Fatalf("sources outside the list of the design can call out:\n%s", strings.Join(bad, "\n"))
		}
		for path := range outgoingAllowed {
			if _, err := os.Stat(filepath.Join("../..", path)); err != nil {
				t.Errorf("the allowed source %s does not exist: %v", path, err)
			}
		}
		// A source outside the list that dials is found.
		root := t.TempDir()
		if err := os.MkdirAll(filepath.Join(root, "internal", "web"), 0o755); err != nil {
			t.Fatal(err)
		}
		src := "package web\n\nimport \"net/http\"\n\nvar c = &http.Client{}\n"
		if err := os.WriteFile(filepath.Join(root, "internal", "web", "beacon.go"), []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
		if bad := scanOutgoing(t, root, outgoingAllowed); len(bad) != 1 || !strings.HasPrefix(bad[0], "internal/web/beacon.go: http.Client") {
			t.Fatalf("the scan found %v, want internal/web/beacon.go", bad)
		}
	})
}

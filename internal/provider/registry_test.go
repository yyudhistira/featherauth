package provider_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/logx"
	"github.com/yyudhistira/featherauth/internal/provider"
	"github.com/yyudhistira/featherauth/internal/provider/providertest"
	"github.com/yyudhistira/featherauth/internal/testutil"
	"github.com/yyudhistira/featherauth/internal/testutil/mockidp"
)

var _ provider.Registry = (*provider.Pool)(nil)

func newPool(t *testing.T, src config.Source, clk clock.Clock) *provider.Pool {
	t.Helper()
	return provider.NewPool(src, clk, logx.New(&bytes.Buffer{}, slog.LevelDebug, clk))
}

const everyProvider = `  google:
    enabled: true
    client_id: g-id
    client_secret_file: secrets/main/google_secret
    hosted_domain: example.com
    endpoints: {authorize: "http://127.0.0.1:9/a", token: "http://127.0.0.1:9/t", jwks: "http://127.0.0.1:9/j"}
  apple:
    enabled: true
    client_id: com.example.web
    team_id: TEAM123456
    key_id: KEY1234567
    private_key_file: secrets/main/apple.p8
    store_refresh_token: false
  github:
    enabled: true
    client_id: gh-id
    client_secret_file: secrets/main/github_secret
    allow_signup: false
  facebook:
    enabled: true
    client_id: fb-id
    client_secret_file: secrets/main/facebook_secret
  corp:
    type: oidc
    enabled: true
    client_id: c-id
    client_secret_file: secrets/main/corp_secret
    issuer: "http://127.0.0.1:9"
    endpoints: {authorize: "http://127.0.0.1:9/a", token: "http://127.0.0.1:9/t", jwks: "http://127.0.0.1:9/j"}
  stealth:
    type: oidc
    enabled: true
    hidden: true
    client_id: s-id
    client_secret_file: secrets/main/stealth_secret
    issuer: "http://127.0.0.1:9"
    endpoints: {authorize: "http://127.0.0.1:9/a", token: "http://127.0.0.1:9/t", jwks: "http://127.0.0.1:9/j"}
  off:
    type: oidc
    client_id: o-id
    client_secret_file: secrets/main/off_secret
    issuer: "http://127.0.0.1:9"
`

var everySecrets = []string{"google", "github", "facebook", "corp", "stealth", "off"}

// Covers: FR-14 (part)
// Acceptance: Provider config (part)
func TestRegistryBuildsAdaptersFromConfig(t *testing.T) {
	l, _ := testutil.NewProviderConfig(t, everyProvider, everySecrets...)
	clk := clock.NewFake(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))
	reg := newPool(t, l, clk)
	r, _ := l.Current().Realm("main")
	query := func(p provider.Provider) url.Values {
		u, err := url.Parse(p.AuthURL("st", "nonce", "chal", provider.AuthOptions{}))
		if err != nil {
			t.Fatal(err)
		}
		return u.Query()
	}

	cases := []struct {
		key  string
		want func(t *testing.T, p provider.Provider)
	}{
		{"google", func(t *testing.T, p provider.Provider) {
			g, ok := p.(*provider.Google)
			if !ok || g.Name() != "google" || query(p).Get("hd") != "example.com" {
				t.Errorf("google adapter = %T", p)
			}
		}},
		{"apple", func(t *testing.T, p provider.Provider) {
			if _, ok := p.(*provider.Apple); !ok {
				t.Fatalf("apple adapter = %T", p)
			}
			if q := query(p); q.Get("scope") != "name email" || q.Get("response_mode") != "form_post" {
				t.Errorf("apple query = %v", q)
			}
		}},
		{"github", func(t *testing.T, p provider.Provider) {
			if _, ok := p.(*provider.GitHub); !ok {
				t.Fatalf("github adapter = %T", p)
			}
			if q := query(p); q.Get("allow_signup") != "false" || q.Get("code_challenge") != "chal" {
				t.Errorf("github query = %v", q)
			}
		}},
		{"facebook", func(t *testing.T, p provider.Provider) {
			if _, ok := p.(*provider.Facebook); !ok {
				t.Fatalf("facebook adapter = %T", p)
			}
			u, _ := url.Parse(p.AuthURL("st", "", "", provider.AuthOptions{}))
			if u.Path != "/v26.0/dialog/oauth" && !strings.HasSuffix(u.Path, "/v26.0/dialog/oauth") {
				t.Errorf("facebook authorize path = %q", u.Path)
			}
		}},
		{"corp", func(t *testing.T, p provider.Provider) {
			if o, ok := p.(*provider.OIDC); !ok || o.Name() != "oidc" {
				t.Errorf("oidc adapter = %T", p)
			}
		}},
		{"stealth", func(t *testing.T, p provider.Provider) {
			if _, ok := p.(*provider.OIDC); !ok {
				t.Errorf("hidden adapter = %T", p)
			}
		}},
	}
	for _, c := range cases {
		t.Run(c.key, func(t *testing.T) {
			p, ok := reg.Get("main", config.ProviderKey(c.key))
			if !ok {
				t.Fatal("Get found no adapter")
			}
			if got := query(p).Get("redirect_uri"); got != r.EndpointURL(config.EndpointCallback, config.ProviderKey(c.key)) {
				t.Errorf("redirect_uri = %q", got)
			}
			c.want(t, p)
			if again, _ := reg.Get("main", config.ProviderKey(c.key)); again != p {
				t.Error("Get built a new adapter instead of returning the cached one")
			}
		})
	}

	// the disabled provider and unknown names have no adapter
	for _, k := range []string{"off", "nope"} {
		if p, ok := reg.Get("main", config.ProviderKey(k)); ok || p != nil {
			t.Errorf("Get(%s) = %v, %v", k, p, ok)
		}
	}
	if p, ok := reg.Get("other", "google"); ok || p != nil {
		t.Errorf("an unknown realm gave %v", p)
	}
	if v := reg.Visible("other"); len(v) != 0 {
		t.Errorf("Visible(other) = %v", v)
	}
}

// Covers: FR-14 (part)
// Acceptance: Provider config (part)
func TestRegistryVisibleExcludesHiddenAndDisabledInOrder(t *testing.T) {
	l, _ := testutil.NewProviderConfig(t, everyProvider, everySecrets...)
	reg := newPool(t, l, clock.NewFake(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)))
	// login_page.provider_order defaults to google, apple, github, facebook;
	// the others follow by key; hidden and disabled providers are left out.
	got := reg.Visible("main")
	want := []config.ProviderKey{"google", "apple", "github", "facebook", "corp"}
	if !slices.Equal(got, want) {
		t.Errorf("Visible = %v, want %v", got, want)
	}
	// the caller may change the slice
	got[0] = "x"
	if again := reg.Visible("main"); again[0] != "google" {
		t.Errorf("Visible shares its slice: %v", again)
	}
}

// discoveryServer serves an OpenID Connect discovery document while up and a
// 503 while down, and counts every discovery request.
type discoveryServer struct {
	*httptest.Server
	up      atomic.Bool
	calls   atomic.Int64
	entered chan struct{} // receives once per request when set
	release chan struct{} // requests wait on it when set
}

func newDiscoveryServer(t *testing.T) *discoveryServer {
	t.Helper()
	d := &discoveryServer{}
	d.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		d.calls.Add(1)
		if d.entered != nil {
			d.entered <- struct{}{}
		}
		if d.release != nil {
			<-d.release
		}
		if !d.up.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		u := "http://" + r.Host
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": u, "authorization_endpoint": u + "/authorize", "token_endpoint": u + "/token", "jwks_uri": u + "/jwks",
			"id_token_signing_alg_values_supported": []string{"ES256"},
		})
	}))
	t.Cleanup(d.Close)
	return d
}

func discoveryProviders(issuer string) string {
	return "  corp:\n    type: oidc\n    enabled: true\n    client_id: c-id\n    client_secret_file: secrets/main/corp_secret\n" +
		"    issuer: \"" + issuer + "\"\n"
}

// Covers: FR-14 (part), FR-18 (part)
// Acceptance: Provider discovery down (part)
func TestRegistryDiscoveryDownStaysListedAndRetriesEveryThirtySeconds(t *testing.T) {
	d := newDiscoveryServer(t)
	l, _ := testutil.NewProviderConfig(t, discoveryProviders(d.URL), "corp")
	clk := clock.NewFake(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))
	reg := newPool(t, l, clk)

	// The configuration is valid and the provider is listed although its issuer is down.
	if v := reg.Visible("main"); len(v) != 1 || v[0] != "corp" {
		t.Fatalf("Visible = %v", v)
	}
	if p, ok := reg.Get("main", "corp"); ok || p != nil {
		t.Fatalf("Get while down = %v, %v", p, ok)
	}
	if d.calls.Load() != 1 {
		t.Fatalf("%d discovery calls, want 1", d.calls.Load())
	}
	// Not retried inside the 30 seconds.
	clk.Advance(29 * time.Second)
	if _, ok := reg.Get("main", "corp"); ok || d.calls.Load() != 1 {
		t.Errorf("after 29s: ok=%v, %d calls (want no retry)", ok, d.calls.Load())
	}
	if v := reg.Visible("main"); len(v) != 1 {
		t.Errorf("Visible while down = %v", v)
	}
	// After 30 seconds it is retried; still down gives another window of 30 seconds.
	clk.Advance(time.Second)
	if _, ok := reg.Get("main", "corp"); ok || d.calls.Load() != 2 {
		t.Errorf("after 30s: ok=%v, %d calls (want one retry)", ok, d.calls.Load())
	}
	clk.Advance(29 * time.Second)
	reg.Get("main", "corp")
	if d.calls.Load() != 2 {
		t.Errorf("a second window started late: %d calls", d.calls.Load())
	}
	// The issuer comes back; the next retry works and the adapter is kept.
	d.up.Store(true)
	clk.Advance(time.Second)
	p, ok := reg.Get("main", "corp")
	if !ok || p == nil || d.calls.Load() != 3 {
		t.Fatalf("after the issuer is back: ok=%v, %d calls", ok, d.calls.Load())
	}
	if again, _ := reg.Get("main", "corp"); again != p || d.calls.Load() != 3 {
		t.Errorf("a working provider is discovered again: %d calls", d.calls.Load())
	}
}

// Covers: FR-14 (part)
// Acceptance: Provider discovery down (part)
func TestRegistryConcurrentGetsShareOneDiscovery(t *testing.T) {
	d := newDiscoveryServer(t)
	d.up.Store(true)
	d.entered = make(chan struct{}, 16)
	d.release = make(chan struct{})
	l, _ := testutil.NewProviderConfig(t, discoveryProviders(d.URL), "corp")
	reg := newPool(t, l, clock.NewFake(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)))

	const n = 8
	got := make([]provider.Provider, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got[i], _ = reg.Get("main", "corp")
		}()
	}
	<-d.entered // one discovery is running; the others wait for it or find its result
	close(d.release)
	wg.Wait()
	if d.calls.Load() != 1 {
		t.Errorf("%d discovery calls for %d concurrent Gets, want 1", d.calls.Load(), n)
	}
	for i, p := range got {
		if p == nil || p != got[0] {
			t.Errorf("Get %d returned %v", i, p)
		}
	}
}

// Covers: FR-14 (part), FR-18 (part)
// Acceptance: Hot reload (part)
func TestRegistryReloadReplacesChangedAdaptersOnly(t *testing.T) {
	l, d := testutil.NewProviderConfig(t, everyProvider, everySecrets...)
	reg := newPool(t, l, clock.NewFake(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)))
	gh1, _ := reg.Get("main", "github")
	fb1, _ := reg.Get("main", "facebook")
	if gh1 == nil || fb1 == nil {
		t.Fatal("no adapters")
	}
	testutil.WriteProviders(t, l, d, strings.Replace(everyProvider, "allow_signup: false", "allow_signup: true", 1))
	gh2, ok := reg.Get("main", "github")
	if !ok || gh2 == gh1 {
		t.Errorf("a changed provider kept its adapter (ok=%v)", ok)
	}
	if q := mustQuery(t, gh2); q.Has("allow_signup") {
		t.Errorf("the new adapter still sends allow_signup: %v", q)
	}
	if fb2, _ := reg.Get("main", "facebook"); fb2 != fb1 {
		t.Error("an unchanged provider got a new adapter")
	}
	// a removed provider is gone
	testutil.WriteProviders(t, l, d, strings.Replace(everyProvider, "  stealth:", "  stealth2:", 1))
	if p, ok := reg.Get("main", "stealth"); ok || p != nil {
		t.Errorf("a removed provider is still there: %v", p)
	}
}

func mustQuery(t *testing.T, p provider.Provider) url.Values {
	t.Helper()
	u, err := url.Parse(p.AuthURL("st", "n", "c", provider.AuthOptions{}))
	if err != nil {
		t.Fatal(err)
	}
	return u.Query()
}

// Covers: FR-14 (part), FR-18 (part)
// Acceptance: Hot reload (part)
// Acceptance: Provider discovery down (part)
func TestRegistryReloadDoesNotDisturbARunningExchange(t *testing.T) {
	clk := clock.NewFake(time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC))
	srv := mockidp.New(t, clk, mockidp.Generic)
	srv.SetUser(mockidp.User{Sub: "sub-1", Email: "ann@example.com", EmailVerified: true, Name: "Ann"})
	providers := func(scopes string) string {
		return "  corp:\n    type: oidc\n    enabled: true\n    client_id: client-id\n    client_secret_file: secrets/main/corp_secret\n" +
			"    issuer: \"" + srv.URL() + "\"\n    scopes: [" + scopes + "]\n    timeout: 20s\n"
	}
	l, d := testutil.NewProviderConfig(t, providers("openid"), "corp")
	d.Write(t, "secrets/main/corp_secret", srv.ClientSecret()+"\n")
	testutil.WriteProviders(t, l, d, providers("openid"))
	reg := newPool(t, l, clk)

	p1, ok := reg.Get("main", "corp")
	if !ok {
		t.Fatal("no adapter")
	}
	sum := sha256.Sum256([]byte("v"))
	q := providertest.Authorize(t, p1.AuthURL("st", "n", base64.RawURLEncoding.EncodeToString(sum[:]), provider.AuthOptions{}))

	srv.Block()
	type result struct {
		id  provider.Identity
		err error
	}
	done := make(chan result, 1)
	go func() {
		id, err := p1.Exchange(context.Background(), provider.Callback{Code: q.Get("code")}, "v", "n")
		done <- result{id, err}
	}()
	<-srv.Blocked() // the exchange is at the provider

	testutil.WriteProviders(t, l, d, providers("openid, email")) // a reload that changes the provider
	p2, ok := reg.Get("main", "corp")
	if !ok || p2 == p1 {
		t.Fatalf("the reload did not replace the adapter (ok=%v)", ok)
	}

	srv.Unblock()
	res := <-done
	if res.err != nil || res.id.Subject != "sub-1" {
		t.Errorf("the running exchange was disturbed: %+v, %v", res.id, res.err)
	}
}

// closeCounter is an httptest server whose connections are reported when closed.
func closeCounter(t *testing.T, handler http.HandlerFunc) (*httptest.Server, <-chan struct{}) {
	t.Helper()
	closed := make(chan struct{}, 16)
	srv := httptest.NewUnstartedServer(handler)
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateClosed {
			closed <- struct{}{}
		}
	}
	srv.Start()
	t.Cleanup(srv.Close)
	return srv, closed
}

// Covers: FR-14 (part)
func TestAdaptersCloseIdleConnections(t *testing.T) {
	refuse := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
	}
	disco := func(w http.ResponseWriter, r *http.Request) {
		u := "http://" + r.Host
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": u, "authorization_endpoint": u + "/a", "token_endpoint": u + "/t", "jwks_uri": u + "/j",
			"id_token_signing_alg_values_supported": []string{"ES256"},
		})
	}
	clk := clock.NewFake(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))
	ctx := context.Background()
	redirect := "https://x.example/cb"

	type closer interface{ CloseIdleConnections() }
	cases := map[string]func(t *testing.T, base string) closer{
		"oidc": func(t *testing.T, base string) closer {
			p, err := provider.NewOIDC(ctx, provider.OIDCOptions{Issuer: base, ClientID: "i", RedirectURI: redirect, Timeout: time.Second, Clock: clk})
			if err != nil {
				t.Fatal(err)
			}
			return p // discovery left an idle connection
		},
		"github": func(t *testing.T, base string) closer {
			p, err := provider.NewGitHub(provider.GitHubOptions{ClientID: "i", ClientSecret: "s", RedirectURI: redirect, Timeout: time.Second, TokenURL: base + "/t"})
			if err != nil {
				t.Fatal(err)
			}
			_, _ = p.Exchange(ctx, provider.Callback{Code: "x"}, "v", "")
			return p
		},
		"facebook": func(t *testing.T, base string) closer {
			p, err := provider.NewFacebook(provider.FacebookOptions{ClientID: "i", ClientSecret: "s", RedirectURI: redirect, GraphVersion: "v26.0", Timeout: time.Second, TokenURL: base + "/t", Clock: clk})
			if err != nil {
				t.Fatal(err)
			}
			_, _ = p.Exchange(ctx, provider.Callback{Code: "x"}, "", "")
			return p
		},
		"apple": func(t *testing.T, base string) closer {
			_, pemKey := testutil.ECKey(t)
			p, err := provider.NewApple(ctx, provider.AppleOptions{
				OIDCOptions: provider.OIDCOptions{ClientID: "i", RedirectURI: redirect, Timeout: time.Second, Clock: clk, Endpoints: provider.OIDCEndpoints{Token: base + "/t"}},
				TeamID:      "T", KeyID: "K", PrivateKeyPEM: pemKey, Lifetime: time.Minute,
			})
			if err != nil {
				t.Fatal(err)
			}
			_, _ = p.Exchange(ctx, provider.Callback{Code: "x"}, "", "n")
			return p
		},
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			h := refuse
			if name == "oidc" {
				h = disco
			}
			srv, closed := closeCounter(t, h)
			build(t, srv.URL).CloseIdleConnections()
			<-closed // the adapter's idle connection was closed
		})
	}
}

// Covers: FR-14 (part), FR-18 (part)
// Acceptance: Hot reload (part)
func TestRegistryClosesIdleConnectionsOfReplacedAdapters(t *testing.T) {
	disco := func(w http.ResponseWriter, r *http.Request) {
		u := "http://" + r.Host
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": u, "authorization_endpoint": u + "/a", "token_endpoint": u + "/t", "jwks_uri": u + "/j",
			"id_token_signing_alg_values_supported": []string{"ES256"},
		})
	}
	srv, closed := closeCounter(t, disco)
	l, d := testutil.NewProviderConfig(t, discoveryProviders(srv.URL)+"    scopes: [openid]\n", "corp")
	reg := newPool(t, l, clock.NewFake(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)))
	p1, ok := reg.Get("main", "corp")
	if !ok {
		t.Fatal("no adapter")
	}
	testutil.WriteProviders(t, l, d, discoveryProviders(srv.URL)+"    scopes: [openid, email]\n")
	if p2, ok := reg.Get("main", "corp"); !ok || p2 == p1 {
		t.Fatalf("the adapter was not replaced (ok=%v)", ok)
	}
	<-closed // the replaced adapter's idle connection was closed
}

// Covers: SEC-13 (part)
func TestPoolLogsNoSecret(t *testing.T) {
	l, d := testutil.NewProviderConfig(t, everyProvider, everySecrets...)
	d.Write(t, "secrets/main/github_secret", "FAKE-POOL-SECRET-5e2b\n")
	testutil.WriteProviders(t, l, d, everyProvider)
	clk := clock.NewFake(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))
	reg := newPool(t, l, clk)
	reg.Get("main", "github")
	var buf bytes.Buffer
	log := logx.New(&buf, slog.LevelDebug, clk)
	log.Info("direct", "registry", reg)
	log.Info("nested", "details", map[string]any{"registry": reg})
	if strings.Contains(buf.String(), "FAKE-POOL-SECRET-5e2b") || !strings.Contains(buf.String(), "registry") {
		t.Errorf("log = %s", buf.String())
	}
}

// swapSource is a config.Source whose snapshot a test advances while callers
// read it. Current yields after it has read the snapshot, which widens the
// window in which another caller can read a newer one.
type swapSource struct {
	snaps []*config.Snapshot
	idx   atomic.Int64
}

func (s *swapSource) Current() *config.Snapshot {
	v := s.snaps[s.idx.Load()]
	runtime.Gosched()
	return v
}

// Covers: FR-14 (part), FR-18 (part)
// Acceptance: Hot reload (part)
func TestRegistryFollowsReloadsInOrderUnderConcurrentUse(t *testing.T) {
	const generations = 40
	provider1 := func(n int) string {
		return "  github:\n    enabled: true\n    client_id: gh-id\n    client_secret_file: secrets/main/github_secret\n" +
			"    scopes: [\"gen" + strconv.Itoa(n) + "\"]\n"
	}
	l, d := testutil.NewProviderConfig(t, provider1(0), "github")
	src := &swapSource{}
	src.snaps = append(src.snaps, l.Current())
	for n := 1; n < generations; n++ {
		testutil.WriteProviders(t, l, d, provider1(n))
		src.snaps = append(src.snaps, l.Current())
	}
	reg := newPool(t, src, clock.NewFake(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)))

	var (
		mu       sync.Mutex
		adapters = map[int]map[provider.Provider]bool{} // generation to the adapters seen for it
		wg       sync.WaitGroup
		done     atomic.Bool
		failures = make(chan string, 64)
	)
	genOf := func(p provider.Provider) int {
		u, _ := url.Parse(p.AuthURL("s", "", "c", provider.AuthOptions{}))
		n, err := strconv.Atoi(strings.TrimPrefix(u.Query().Get("scope"), "gen"))
		if err != nil {
			return -1
		}
		return n
	}
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			last := -1
			for !done.Load() {
				reg.Visible("main")
				p, ok := reg.Get("main", "github")
				if !ok {
					failures <- "Get found no adapter"
					return
				}
				g := genOf(p)
				if g < last {
					failures <- "a caller saw generation " + strconv.Itoa(g) + " after " + strconv.Itoa(last)
					return
				}
				last = g
				mu.Lock()
				if adapters[g] == nil {
					adapters[g] = map[provider.Provider]bool{}
				}
				adapters[g][p] = true
				mu.Unlock()
			}
		}()
	}
	for n := 1; n < generations; n++ {
		src.idx.Store(int64(n))
		runtime.Gosched()
	}
	done.Store(true)
	wg.Wait()
	close(failures)
	for f := range failures {
		t.Error(f)
	}
	for g, set := range adapters {
		if len(set) != 1 {
			t.Errorf("generation %d was built %d times, want once", g, len(set))
		}
	}
	// whatever happened, the registry ends on the last snapshot
	if p, _ := reg.Get("main", "github"); genOf(p) != generations-1 {
		t.Errorf("the registry ends on generation %d, want %d", genOf(p), generations-1)
	}
}

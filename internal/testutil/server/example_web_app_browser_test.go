//go:build browser

package server_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/chromedp"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/secure"
	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/testutil/mockidp"
	"github.com/yyudhistira/featherauth/internal/testutil/server"
)

const exampleAppHost = "app.example.com"

// exampleAppHandler serves the built example (examples/web-app/dist) as a
// single-page app: a path without a file falls back to index.html, and
// config.json names the test server, as an adopter edits it for theirs.
func exampleAppHandler(t *testing.T) http.Handler {
	t.Helper()
	dist, err := filepath.Abs(filepath.Join("..", "..", "..", "examples", "web-app", "dist"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dist, "index.html")); err != nil {
		t.Fatalf("%s has no index.html (%v): run `make example` to build the example web app", dist, err)
	}
	cfg, err := json.Marshal(map[string]string{
		"authority":                server.Issuer,
		"client_id":                "example-web",
		"redirect_uri":             "https://" + exampleAppHost + "/callback",
		"post_logout_redirect_uri": "https://" + exampleAppHost + "/",
	})
	if err != nil {
		t.Fatal(err)
	}
	files := http.FileServer(http.Dir(dist))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/config.json" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(cfg)
			return
		}
		if info, err := os.Stat(filepath.Join(dist, filepath.FromSlash(filepath.Clean("/"+r.URL.Path)))); err != nil || info.IsDir() {
			http.ServeFile(w, r, filepath.Join(dist, "index.html"))
			return
		}
		files.ServeHTTP(w, r)
	})
}

// exampleClientEntry returns the clients block of the shipped entry
// (examples/web-app/example-web-client.yaml) with its loopback origin replaced
// by the origin the test serves the app on, so that the entry that ships is
// the one tested.
func exampleClientEntry(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "examples", "web-app", "example-web-client.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	_, block, ok := strings.Cut(string(b), "\nclients:\n")
	if !ok || !strings.HasPrefix(block, "  example-web:") {
		t.Fatalf("example-web-client.yaml has no example-web block under clients:")
	}
	block = strings.ReplaceAll(block, "http://127.0.0.1:5173", "https://"+exampleAppHost)
	if strings.Contains(block, "http://127.0.0.1") {
		t.Fatalf("the client entry still names the loopback origin: %s", block)
	}
	return "clients:\n" + block
}

// pageText returns the text of the element, or "" when there is none.
func pageText(t *testing.T, ctx context.Context, id string) string {
	t.Helper()
	var s string
	if err := chromedp.Run(ctx, chromedp.Evaluate(`document.getElementById(`+quote(id)+`)?.textContent ?? ""`, &s)); err != nil {
		t.Fatal(err)
	}
	return s
}

func quote(s string) string { b, _ := json.Marshal(s); return string(b) }

// until waits for a JavaScript condition. The page navigates away while it
// waits (the redirects of sign-in and sign-out), which fails an evaluation in
// flight, so a failed evaluation is tried again. On a timeout it fails with
// what the page shows in #error.
func until(t *testing.T, ctx context.Context, what, cond string) {
	t.Helper()
	wait, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var last error
	for wait.Err() == nil {
		if last = chromedp.Run(wait, chromedp.Poll(cond, nil, chromedp.WithPollingInterval(100*time.Millisecond))); last == nil {
			return
		}
	}
	t.Fatalf("waiting for %s: last error %v (#error: %q, #status: %q)", what, last, pageText(t, ctx, "error"), pageText(t, ctx, "status"))
}

func noPageError(t *testing.T, ctx context.Context, step string) {
	t.Helper()
	if got := pageText(t, ctx, "error"); got != "" {
		t.Fatalf("after %s #error shows %q", step, got)
	}
}

// Covers: FR-61
// Acceptance: Example web app
// The built example (examples/web-app) against the in-process service in Chrome:
// it signs in as a public client, verifies the ID token's signature, shows the
// claims and userinfo's sub, refreshes with rotation on a button and signs out
// by RP-initiated logout, which revokes the session.
func TestBrowserExampleWebApp(t *testing.T) {
	handler := exampleAppHandler(t)
	s, ctx := start(t, nil)
	// The browser checks exp and iat with its own clock, so the service's
	// fake clock runs at the real time and stays there.
	s.env.Clock.Set(clock.Real().Now())
	// The mock identity provider is the realm's only provider, and the client
	// is the entry of examples/web-app/example-web-client.yaml for this origin.
	s.env.Reload(t, func(y string) string {
		head, _, _ := strings.Cut(y, "providers:\n")
		google := `providers:
  google:
    enabled: true
    client_id: client-id
    client_secret_file: secrets/main/google_secret
`
		return head + google + exampleClientEntry(t)
	})
	s.env.Mocks["google"].SetUser(mockidp.User{Sub: "sub-example", Name: "Ann Example", Email: "ann@example.com", EmailVerified: true})
	s.serveApp(exampleAppHost, handler)

	if err := chromedp.Run(ctx,
		chromedp.Navigate("https://"+exampleAppHost+"/"),
		chromedp.WaitVisible(`#signin`, chromedp.ByID),
	); err != nil {
		t.Fatalf("the page did not show #signin: %v (#error: %q)", err, pageText(t, ctx, "error"))
	}
	noPageError(t, ctx, "loading the page")

	// Sign in.
	if err := chromedp.Run(ctx, chromedp.Click(`#signin`, chromedp.ByID)); err != nil {
		t.Fatal(err)
	}
	until(t, ctx, "Signed in", `document.getElementById("status")?.textContent === "Signed in"`)
	until(t, ctx, "the verified signature", `document.getElementById("verified")?.textContent === "ID token signature verified"`)
	until(t, ctx, "userinfo", `document.getElementById("userinfo")?.textContent === "userinfo sub matches"`)
	noPageError(t, ctx, "sign-in")

	tokenPath := s.env.Realm.EndpointPath(config.EndpointToken, "")
	isToken := func(r seen) bool {
		return r.Host == "auth.example.com" && r.Path == tokenPath && r.Method == http.MethodPost && r.Status == http.StatusOK
	}
	exchange := s.find(isToken)
	if len(exchange) != 1 {
		t.Fatalf("%d token answers after sign-in, want 1", len(exchange))
	}
	var first struct {
		IDToken      string `json:"id_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal([]byte(exchange[0].Body), &first); err != nil || first.RefreshToken == "" {
		t.Fatalf("the code exchange gave no refresh token (%v)", err)
	}
	parts := strings.Split(first.IDToken, ".")
	if len(parts) != 3 {
		t.Fatalf("the ID token has %d parts", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var idClaims struct{ Sub string }
	if err := json.Unmarshal(raw, &idClaims); err != nil || idClaims.Sub == "" {
		t.Fatalf("ID token claims %q: %v", raw, err)
	}
	// The sub of the ID token is the service's user for the mock provider's subject.
	var user store.UserID
	var realm store.RealmID
	ctxDB := context.Background()
	if err := s.env.Store.Read(ctxDB, func(tx store.Tx) error {
		var err error
		if realm, err = tx.Realms().Find(ctxDB, "main"); err != nil {
			return err
		}
		id, err := tx.Identities().Find(ctxDB, realm, "google", "sub-example")
		user = id.UserID
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if idClaims.Sub != string(user) {
		t.Fatalf("the ID token's sub is %q, the mock user's is %q", idClaims.Sub, user)
	}
	claims := pageText(t, ctx, "claims")
	for _, want := range []string{string(user), "Ann Example", "ann@example.com"} {
		if !strings.Contains(claims, want) {
			t.Errorf("#claims %q does not show %q", claims, want)
		}
	}
	if got := pageText(t, ctx, "refreshes"); got != "0" {
		t.Errorf("#refreshes %q before a refresh, want 0", got)
	}
	userinfoPath := s.env.Realm.EndpointPath(config.EndpointUserinfo, "")
	isUserinfo := func(r seen) bool {
		return r.Host == "auth.example.com" && r.Path == userinfoPath && r.Method == http.MethodGet && r.Status == http.StatusOK
	}
	if got := len(s.find(isUserinfo)); got != 1 {
		t.Fatalf("%d successful userinfo answers after sign-in, want exactly 1", got)
	}

	// Tokens stay in memory: no storage of the page holds one, and the page
	// shows none.
	var stored, shown string
	if err := chromedp.Run(ctx,
		chromedp.Evaluate(`JSON.stringify([localStorage, sessionStorage])`, &stored),
		chromedp.Evaluate(`document.body.innerText`, &shown),
	); err != nil {
		t.Fatal(err)
	}
	var access struct {
		AccessToken string `json:"access_token"`
	}
	_ = json.Unmarshal([]byte(exchange[0].Body), &access)
	for _, secret := range []string{first.IDToken, first.RefreshToken, access.AccessToken} {
		if secret == "" || strings.Contains(stored, secret) || strings.Contains(shown, secret) {
			t.Fatalf("a token is empty, in the page's storage or on the page")
		}
	}

	// Refresh, on the button: one refresh, the first refresh token rotated.
	if err := chromedp.Run(ctx, chromedp.Click(`#refresh`, chromedp.ByID)); err != nil {
		t.Fatal(err)
	}
	until(t, ctx, "one refresh", `document.getElementById("refreshes")?.textContent === "1"`)
	noPageError(t, ctx, "the refresh")
	if got := len(s.find(isToken)); got != 2 {
		t.Fatalf("%d token answers after one refresh, want 2 (no automatic renewal)", got)
	}
	var second struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal([]byte(s.find(isToken)[1].Body), &second); err != nil || second.RefreshToken == "" || second.RefreshToken == first.RefreshToken {
		t.Fatalf("the refresh gave no new refresh token (%v)", err)
	}
	var old, current store.RefreshToken
	if err := s.env.Store.Read(ctxDB, func(tx store.Tx) error {
		var err error
		if old, err = tx.RefreshTokens().FindByHash(ctxDB, realm, secure.HashOf(first.RefreshToken)); err != nil {
			return err
		}
		current, err = tx.RefreshTokens().FindByHash(ctxDB, realm, secure.HashOf(second.RefreshToken))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if old.ReplacedBy != current.ID || current.SessionID != old.SessionID || !current.RevokedAt.IsZero() {
		t.Fatalf("the first token was not rotated into the second: old %+v, current %+v", old, current)
	}
	if got := len(s.find(isUserinfo)); got != 2 {
		t.Fatalf("%d successful userinfo answers after the refresh, want exactly 2", got)
	}
	until(t, ctx, "the signature of the refreshed token", `document.getElementById("verified")?.textContent === "ID token signature verified"`)

	// Sign out: the session is revoked in the store.
	if err := chromedp.Run(ctx, chromedp.Click(`#signout`, chromedp.ByID)); err != nil {
		t.Fatal(err)
	}
	until(t, ctx, "Signed out", `document.getElementById("status")?.textContent === "Signed out" && document.getElementById("signin") !== null && location.search === ""`)
	noPageError(t, ctx, "sign-out")
	live := true
	if err := s.env.Store.Read(ctxDB, func(tx store.Tx) error {
		var err error
		live, err = tx.RefreshTokens().SessionLive(ctxDB, realm, current.SessionID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if live {
		t.Fatal("the session is still live after sign-out")
	}
	for _, name := range []string{"verified", "claims", "refresh", "signout"} {
		if got := pageText(t, ctx, name); got != "" {
			t.Errorf("#%s still shows %q after sign-out", name, got)
		}
	}
}

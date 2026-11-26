package oidc_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/logx"
	"github.com/yyudhistira/featherauth/internal/oidc"
	"github.com/yyudhistira/featherauth/internal/secure"
	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/testutil"
	"github.com/yyudhistira/featherauth/internal/testutil/configdir"
	"github.com/yyudhistira/featherauth/internal/token"
)

// countingStore wraps a real store. It counts the transactions open at any moment,
// so a test can tell whether a call to a receiver ran inside one, and it can fail
// the next claim or delete on demand.
type countingStore struct {
	store.Store
	open      atomic.Int64
	failClaim atomic.Int64 // the next claims fail while this is positive
	failDone  atomic.Int64 // the next deletes of a delivered row fail while this is positive
	failFind  atomic.Bool  // every realm lookup fails while set
}

func (c *countingStore) Write(ctx context.Context, fn func(store.Tx) error) error {
	c.open.Add(1)
	defer c.open.Add(-1)
	return c.Store.Write(ctx, func(tx store.Tx) error { return fn(countedTx{tx, c}) })
}

func (c *countingStore) Read(ctx context.Context, fn func(store.Tx) error) error {
	c.open.Add(1)
	defer c.open.Add(-1)
	return c.Store.Read(ctx, func(tx store.Tx) error { return fn(countedTx{tx, c}) })
}

type countedTx struct {
	store.Tx
	c *countingStore
}

func (t countedTx) Realms() store.Realms { return countedRealms{t.Tx.Realms(), t.c} }

type countedRealms struct {
	store.Realms
	c *countingStore
}

func (r countedRealms) Find(ctx context.Context, name config.RealmName) (store.RealmID, error) {
	if r.c.failFind.Load() {
		return "", errors.New("disk on fire")
	}
	return r.Realms.Find(ctx, name)
}

func (t countedTx) LogoutNotifications() store.LogoutNotifications {
	return countedLogout{t.Tx.LogoutNotifications(), t.c}
}

type countedLogout struct {
	store.LogoutNotifications
	c *countingStore
}

func (l countedLogout) Claim(ctx context.Context, now time.Time, limit int) ([]store.LogoutNotification, error) {
	if l.c.failClaim.Add(-1) >= 0 {
		return nil, errors.New("disk on fire")
	}
	return l.LogoutNotifications.Claim(ctx, now, limit)
}

func (l countedLogout) Done(ctx context.Context, id store.LogoutNotificationID) error {
	if l.c.failDone.Add(-1) >= 0 {
		return errors.New("disk on fire")
	}
	return l.LogoutNotifications.Done(ctx, id)
}

// received is one post to a receiver.
type received struct {
	token    string // the logout_token field
	fields   int    // how many form fields the post carried
	ctype    string
	open     int64 // the transactions open when the post arrived
	attempts int   // the count of posts to the receiver so far, this one included
}

// deliverEnv is the worker with a real configuration, a real store on a temporary
// file, the fake clock and an httptest receiver.
type deliverEnv struct {
	t         *testing.T
	clk       *clock.Fake
	st        *countingStore
	path      string
	dir       *configdir.Dir
	loader    *config.Loader
	recv      *httptest.Server
	got       chan received
	hits      atomic.Int64
	elsewhere atomic.Int64 // posts to /elsewhere, a redirect target
	mu        sync.Mutex
	respond   func(n int, w http.ResponseWriter, r *http.Request)
	logBuf    *bytes.Buffer
	d         *oidc.Deliverer
	realmID   store.RealmID
}

const deliverRealm = "name: main\nkeys:\n  - {kid: rsa1, file: secrets/main/rsa.pem, state: active}\nclients:\n  app:\n    redirect_uris: [https://app.example.test/cb]\n%s  frag:\n    redirect_uris: [https://frag.example.test/cb]\n"

// newDeliverEnv starts a receiver and a configuration whose app client posts to it.
func newDeliverEnv(t *testing.T) *deliverEnv {
	t.Helper()
	e := &deliverEnv{t: t, clk: clock.NewFake(time.Date(2026, 11, 19, 9, 0, 0, 0, time.UTC)), got: make(chan received, 256), logBuf: &bytes.Buffer{}}
	e.respond = func(_ int, w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }
	e.recv = httptest.NewServer(http.HandlerFunc(e.serve))
	t.Cleanup(e.recv.Close)

	st, path := testutil.NewStoreFile(t)
	e.st = &countingStore{Store: st}
	e.path = path
	t.Cleanup(func() { _ = st.Close() })

	e.dir = configdir.New(t)
	e.dir.Server(t, "public_url: http://auth.example.test\nrequire_https: false\n")
	e.dir.RSAKey(t, "secrets/main/rsa.pem")
	e.writeRealm(e.recv.URL + "/logout")
	loader, err := config.NewLoader(e.dir.Root, e.clk, nil)
	if err != nil {
		t.Fatal(err)
	}
	e.loader = loader
	if err := e.st.Write(context.Background(), func(tx store.Tx) error {
		id, err := tx.Realms().Ensure(context.Background(), "main", "R1", e.clk.Now())
		e.realmID = id
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return e
}

// writeRealm writes the realm with app's back-channel logout URI (empty removes it)
// and loads it.
func (e *deliverEnv) writeRealm(uri string) {
	e.t.Helper()
	line := ""
	if uri != "" {
		line = fmt.Sprintf("    backchannel_logout_uri: %q\n", uri)
	}
	y := fmt.Sprintf(deliverRealm, line)
	e.dir.Realm(e.t, "main", y)
	if e.loader != nil {
		if res := e.loader.Reload(context.Background()); len(res.Diagnostics) != 0 || !res.Applied {
			e.t.Fatalf("the reload: applied %v, diagnostics %v", res.Applied, res.Diagnostics)
		}
	}
}

// serve is the receiver: it records each post and answers with the response of
// the test.
func (e *deliverEnv) serve(w http.ResponseWriter, r *http.Request) {
	n := int(e.hits.Add(1))
	if r.URL.Path == "/elsewhere" {
		e.elsewhere.Add(1)
		w.WriteHeader(http.StatusOK)
		return
	}
	_ = r.ParseForm()
	e.got <- received{
		token: r.PostForm.Get("logout_token"), fields: len(r.PostForm), ctype: r.Header.Get("Content-Type"),
		open: e.st.open.Load(), attempts: n,
	}
	e.mu.Lock()
	respond := e.respond
	e.mu.Unlock()
	respond(n, w, r)
}

func (e *deliverEnv) setRespond(f func(n int, w http.ResponseWriter, r *http.Request)) {
	e.mu.Lock()
	e.respond = f
	e.mu.Unlock()
}

// source is the configuration the worker reads.
func (e *deliverEnv) source() config.Source { return e.loader }

// newDeliverer makes a worker over the environment. timeout 0 is the service's 5 s.
func (e *deliverEnv) newDeliverer(timeout time.Duration) *oidc.Deliverer {
	e.t.Helper()
	return oidc.NewDeliverer(oidc.DeliverConfig{
		Store: e.st, Source: e.source(), Clock: e.clk, Rand: secure.Default,
		Log: logx.New(e.logBuf, slog.LevelDebug, e.clk), Timeout: timeout,
	})
}

// start starts a worker and remembers it for the cleanup.
func (e *deliverEnv) start(timeout time.Duration) *oidc.Deliverer {
	e.t.Helper()
	d := e.newDeliverer(timeout)
	d.Start()
	e.d = d
	e.t.Cleanup(func() { _ = d.Stop(context.Background()) })
	return d
}

// enqueue writes a row for session s1 of app, due now, with the attempts given.
func (e *deliverEnv) enqueue(id, client, session string, attempts int) {
	e.t.Helper()
	now := e.clk.Now()
	if err := e.st.Write(context.Background(), func(tx store.Tx) error {
		return tx.LogoutNotifications().Enqueue(context.Background(), store.LogoutNotification{
			ID: store.LogoutNotificationID(id), RealmID: e.realmID, ClientID: config.ClientID(client), UserID: "u1",
			SessionID: store.SessionID(session), Attempts: attempts, NextAttemptAt: now, CreatedAt: now,
		})
	}); err != nil {
		e.t.Fatal(err)
	}
}

// rows reads logout_notifications from the database file, without changing it.
func (e *deliverEnv) rows() []string {
	e.t.Helper()
	db, err := sql.Open("sqlite", e.path)
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	rs, err := db.Query(`SELECT id || ' ' || session_id || ' ' || attempts FROM logout_notifications ORDER BY id`)
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = rs.Close() }()
	var out []string
	for rs.Next() {
		var s string
		if err := rs.Scan(&s); err != nil {
			e.t.Fatal(err)
		}
		out = append(out, s)
	}
	return out
}

// idle waits for the rounds the worker has started.
func (e *deliverEnv) idle() {
	e.t.Helper()
	if err := e.d.Idle(context.Background()); err != nil {
		e.t.Fatal(err)
	}
}

// expect returns the next post, failing the test when none arrives.
func (e *deliverEnv) expect() received {
	e.t.Helper()
	return <-e.got
}

// claims decodes a compact JWT without checking it.
func claims(t *testing.T, raw string) (header, payload map[string]any) {
	t.Helper()
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatalf("a token of %d parts", len(parts))
	}
	for i, dst := range []*map[string]any{&header, &payload} {
		b, err := base64.RawURLEncoding.DecodeString(parts[i])
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(b, dst); err != nil {
			t.Fatal(err)
		}
	}
	return header, payload
}

// verifyLogoutToken checks the signature of a logout token with the realm's
// published keys, and returns its header and claims.
func (e *deliverEnv) verifyLogoutToken(raw string) (map[string]any, map[string]any) {
	e.t.Helper()
	snap := e.loader.Current()
	realm, _ := snap.Realm("main")
	ks, err := token.NewKeySet(realm, snap.Secrets())
	if err != nil {
		e.t.Fatal(err)
	}
	set, err := jwk.Parse(ks.JWKS())
	if err != nil {
		e.t.Fatal(err)
	}
	if _, err := jws.Verify([]byte(raw), jws.WithKeySet(set, jws.WithInferAlgorithmFromKey(true))); err != nil {
		e.t.Fatalf("the logout token does not verify with the JWKS: %v", err)
	}
	return claims(e.t, raw)
}

// wantToken checks a delivered logout token: its header, its claims for the
// session, and that it was issued at iat with a two-minute life.
func (e *deliverEnv) wantToken(rec received, iat time.Time) (jti string) {
	e.t.Helper()
	header, payload := e.verifyLogoutToken(rec.token)
	if header["typ"] != "logout+jwt" || header["alg"] != "RS256" {
		e.t.Errorf("header %v, want typ logout+jwt and alg RS256", header)
	}
	if payload["iss"] != "http://auth.example.test/main" || payload["aud"] != "app" || payload["sub"] != "u1" || payload["sid"] != "s1" {
		e.t.Errorf("claims %v", payload)
	}
	if _, ok := payload["nonce"]; ok {
		e.t.Errorf("a logout token carries a nonce: %v", payload)
	}
	if got := payload["iat"]; got != float64(iat.Unix()) {
		e.t.Errorf("iat %v, want %d (the time of the try)", got, iat.Unix())
	}
	if got := payload["exp"]; got != float64(iat.Add(2*time.Minute).Unix()) {
		e.t.Errorf("exp %v, want iat plus 2 minutes", got)
	}
	if ev, _ := payload["events"].(map[string]any); ev == nil || len(ev) != 1 || ev["http://schemas.openid.net/event/backchannel-logout"] == nil {
		e.t.Errorf("events %v, want the back-channel event with {}", payload["events"])
	}
	jti, _ = payload["jti"].(string)
	if jti == "" {
		e.t.Error("no jti")
	}
	return jti
}

// Covers: FR-43, SEC-35
// Acceptance: Back-channel logout
// A due row is posted once as a form with one field, a logout token that verifies
// with the realm's keys and carries the claims of SEC-35; the row is then deleted,
// and no transaction is open during the post.
func TestDeliveryPostsAVerifiableLogoutToken(t *testing.T) {
	e := newDeliverEnv(t)
	e.enqueue("n1", "app", "s1", 0)
	e.start(0)
	e.clk.Advance(5 * time.Second)
	rec := e.expect()
	if rec.fields != 1 || rec.ctype != "application/x-www-form-urlencoded" {
		t.Fatalf("the post carried %d fields as %q, want one form field", rec.fields, rec.ctype)
	}
	if rec.open != 0 {
		t.Fatalf("%d transactions open during the call", rec.open)
	}
	e.wantToken(rec, e.clk.Now())
	e.idle()
	if rows := e.rows(); len(rows) != 0 {
		t.Fatalf("rows after the delivery: %v", rows)
	}
	if strings.Contains(e.logBuf.String(), rec.token) {
		t.Fatal("the log holds the logout token")
	}
}

// Covers: FR-43
// Acceptance: Back-channel logout
// A failed try is tried again at the times the claim scheduled (1 and then 5
// minutes after the one before), with a new jti and a new iat each time.
func TestFailedTriesRetryWithANewTokenAndIat(t *testing.T) {
	e := newDeliverEnv(t)
	e.setRespond(func(n int, w http.ResponseWriter, _ *http.Request) {
		if n < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	e.enqueue("n1", "app", "s1", 0)
	e.start(0)
	var iats []time.Time
	var jtis []string
	for _, wait := range []time.Duration{5 * time.Second, time.Minute, 5 * time.Minute} {
		e.clk.Advance(wait)
		rec := e.expect()
		iats = append(iats, e.clk.Now())
		jtis = append(jtis, e.wantToken(rec, e.clk.Now()))
		e.idle()
	}
	if iats[1].Sub(iats[0]) != time.Minute || iats[2].Sub(iats[1]) != 5*time.Minute {
		t.Fatalf("tries at %v, want 1 and 5 minutes apart", iats)
	}
	if jtis[0] == jtis[1] || jtis[1] == jtis[2] {
		t.Fatalf("the tries reuse a jti: %v", jtis)
	}
	if rows := e.rows(); len(rows) != 0 {
		t.Fatalf("rows after the third try, which succeeded: %v", rows)
	}
}

// Covers: FR-43
// Acceptance: Back-channel logout
// A row that fails five times is deleted with a warning naming the client and the
// session, and is not sent again.
func TestGivesUpAfterFiveTriesWithAWarning(t *testing.T) {
	e := newDeliverEnv(t)
	e.setRespond(func(_ int, w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusBadGateway) })
	e.enqueue("n1", "app", "s1", 0)
	e.start(0)
	for _, wait := range []time.Duration{5 * time.Second, time.Minute, 5 * time.Minute, 30 * time.Minute, 2 * time.Hour} {
		e.clk.Advance(wait)
		e.expect()
		e.idle()
	}
	if rows := e.rows(); len(rows) != 0 {
		t.Fatalf("rows after the fifth try: %v", rows)
	}
	log := e.logBuf.String()
	fifth := `{"time":"2026-11-19T11:36:05Z","level":"WARN","msg":"back-channel logout: giving up after 5 tries","client":"app","session":"s1","attempt":5,"status":502,"error":null}`
	if strings.Count(log, "giving up after 5 tries") != 1 || !strings.Contains(log, fifth) {
		t.Fatalf("want one warning from the fifth try, naming the client, session, attempt and status: %s", log)
	}
	e.clk.Advance(3 * time.Hour)
	e.idle()
	select {
	case rec := <-e.got:
		t.Fatalf("a row given up was sent again: %+v", rec)
	default:
	}
}

// Covers: FR-43
// Acceptance: Back-channel logout
// A redirect is not followed: the 302 is the answer, a failure of the try, and the
// target gets nothing.
func TestRedirectIsNotFollowedAndCountsAsAFailure(t *testing.T) {
	e := newDeliverEnv(t)
	e.setRespond(func(_ int, w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", e.recv.URL+"/elsewhere")
		w.WriteHeader(http.StatusFound)
	})
	e.enqueue("n1", "app", "s1", 0)
	e.start(0)
	e.clk.Advance(5 * time.Second)
	e.expect()
	e.idle()
	if n := e.elsewhere.Load(); n != 0 {
		t.Fatalf("the redirect was followed %d times", n)
	}
	if rows := e.rows(); len(rows) != 1 || !strings.HasSuffix(rows[0], " 1") {
		t.Fatalf("rows %v, want the row with one try counted", rows)
	}
}

// Covers: FR-43
// Acceptance: Back-channel logout
// A response body of any size is read up to 64 KB and discarded: a large 200 is a
// delivery, and a large 500 is a failure.
func TestLargeBodiesAreDiscarded(t *testing.T) {
	big := strings.Repeat("x", 100<<10)
	e := newDeliverEnv(t)
	e.setRespond(func(_ int, w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, big)
	})
	e.enqueue("n1", "app", "s1", 0)
	e.start(0)
	e.clk.Advance(5 * time.Second)
	e.expect()
	e.idle()
	if rows := e.rows(); len(rows) != 0 {
		t.Fatalf("a 200 with a large body was not a delivery: %v", rows)
	}

	e.setRespond(func(_ int, w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, big)
	})
	e.enqueue("n2", "app", "s2", 0)
	e.clk.Advance(5 * time.Second)
	e.expect()
	e.idle()
	if rows := e.rows(); len(rows) != 1 || !strings.HasPrefix(rows[0], "n2 s2 1") {
		t.Fatalf("a 500 with a large body was not a failed try: %v", rows)
	}
}

// Covers: FR-43
// Acceptance: Back-channel logout
// A receiver that hangs is cut off by the client's timeout, which counts as a try.
func TestHungReceiverTimesOutAndCountsAsATry(t *testing.T) {
	e := newDeliverEnv(t)
	e.setRespond(func(_ int, _ http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
	e.enqueue("n1", "app", "s1", 0)
	e.start(100 * time.Millisecond)
	e.clk.Advance(5 * time.Second)
	e.expect()
	e.idle()
	if rows := e.rows(); len(rows) != 1 || !strings.HasSuffix(rows[0], " 1") {
		t.Fatalf("rows %v, want the timed-out try counted", rows)
	}
}

// Covers: FR-43
// Acceptance: Back-channel logout
// Stopping during a call cuts it off; the call counts as a try, and the row is sent
// again by the next start.
func TestStopDuringACallCountsItAsATry(t *testing.T) {
	e := newDeliverEnv(t)
	e.setRespond(func(_ int, _ http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
	e.enqueue("n1", "app", "s1", 0)
	first := e.newDeliverer(time.Minute) // only a cancel can end the call within the test
	first.Start()
	e.clk.Advance(5 * time.Second)
	e.expect() // the call is in flight
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := first.Stop(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("a stop that cuts calls off reports %v, want context.Canceled", err)
	}
	if rows := e.rows(); len(rows) != 1 || !strings.HasSuffix(rows[0], " 1") {
		t.Fatalf("rows %v, want the cut-off call counted as a try", rows)
	}
	// The call ended by the cancel, not by its timeout.
	if !strings.Contains(e.logBuf.String(), "context canceled") {
		t.Fatalf("the call did not end by the cancel: %s", e.logBuf.String())
	}

	e.setRespond(func(_ int, w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	e.start(0)
	e.clk.Advance(time.Minute)
	rec := e.expect()
	e.wantToken(rec, e.clk.Now())
	e.idle()
	if rows := e.rows(); len(rows) != 0 {
		t.Fatalf("rows after the restart's delivery: %v", rows)
	}
}

// Covers: FR-43
// Acceptance: Back-channel logout
// A stop waits for the calls in flight: the call finishes, its 200 deletes the row,
// and nothing starts after the stop.
func TestStopWaitsForCallsInFlight(t *testing.T) {
	e := newDeliverEnv(t)
	release := make(chan struct{})
	e.setRespond(func(_ int, w http.ResponseWriter, _ *http.Request) {
		<-release
		w.WriteHeader(http.StatusOK)
	})
	e.enqueue("n1", "app", "s1", 0)
	d := e.newDeliverer(0)
	d.Start()
	e.clk.Advance(5 * time.Second)
	e.expect() // in flight
	stopped := make(chan error, 1)
	go func() { stopped <- d.Stop(context.Background()) }()
	close(release)
	if err := <-stopped; err != nil {
		t.Fatalf("the stop: %v", err)
	}
	if rows := e.rows(); len(rows) != 0 {
		t.Fatalf("the call that finished did not delete its row: %v", rows)
	}
	e.enqueue("n2", "app", "s2", 0)
	e.clk.Advance(time.Minute)
	select {
	case rec := <-e.got:
		t.Fatalf("a call started after the stop: %+v", rec)
	default:
	}
}

// Covers: FR-43
// Acceptance: Back-channel logout
// Rows of a client without a URI, of a client the configuration no longer names,
// and of a client whose URI was removed are deleted without a call.
func TestRowsWithoutAURIAreDeletedUnsent(t *testing.T) {
	e := newDeliverEnv(t)
	e.enqueue("n1", "frag", "s1", 0)
	e.enqueue("n2", "gone", "s2", 0)
	e.start(0)
	e.clk.Advance(5 * time.Second)
	e.idle()
	if rows := e.rows(); len(rows) != 0 {
		t.Fatalf("rows of clients without a URI: %v", rows)
	}
	select {
	case rec := <-e.got:
		t.Fatalf("a client without a URI was posted to: %+v", rec)
	default:
	}

	e.writeRealm("")
	e.enqueue("n3", "app", "s3", 0)
	e.clk.Advance(5 * time.Second)
	e.idle()
	if rows := e.rows(); len(rows) != 0 {
		t.Fatalf("a row whose URI was removed: %v", rows)
	}
}

// Covers: FR-43
// Acceptance: Back-channel logout
// A row that already has five attempts is deleted with a warning and not sent.
func TestRowWithFiveAttemptsIsDeletedUnsent(t *testing.T) {
	e := newDeliverEnv(t)
	e.enqueue("n1", "app", "s1", 5)
	e.start(0)
	e.clk.Advance(5 * time.Second)
	e.idle()
	select {
	case rec := <-e.got:
		t.Fatalf("a row with five attempts was sent: %+v", rec)
	default:
	}
	if rows := e.rows(); len(rows) != 0 {
		t.Fatalf("rows %v, want the row deleted", rows)
	}
	if !strings.Contains(e.logBuf.String(), "giving up") {
		t.Fatalf("no warning: %s", e.logBuf.String())
	}
}

// Covers: FR-43
// Acceptance: Back-channel logout
// A stopped worker starts no round: its timer is stopped and a due row waits for the
// next start.
func TestStoppedWorkerStartsNoRound(t *testing.T) {
	e := newDeliverEnv(t)
	d := e.start(0)
	if err := d.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.enqueue("n1", "app", "s1", 0)
	e.clk.Advance(time.Minute)
	select {
	case rec := <-e.got:
		t.Fatalf("a stopped worker posted: %+v", rec)
	default:
	}
	if rows := e.rows(); len(rows) != 1 {
		t.Fatalf("rows %v, want the row waiting", rows)
	}
}

// Covers: FR-43
// Acceptance: Back-channel logout
// Without a configuration no row is claimed: the rows keep their tries for the next
// start.
func TestNoConfigurationClaimsNothing(t *testing.T) {
	e := newDeliverEnv(t)
	e.enqueue("n1", "app", "s1", 0)
	d := oidc.NewDeliverer(oidc.DeliverConfig{
		Store: e.st, Source: config.Static(nil), Clock: e.clk, Rand: secure.Default,
		Log: logx.New(e.logBuf, slog.LevelDebug, e.clk),
	})
	d.Start()
	e.clk.Advance(5 * time.Second)
	if err := d.Idle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if rows := e.rows(); len(rows) != 1 || !strings.HasSuffix(rows[0], " 0") {
		t.Fatalf("rows %v, want the row with no try counted", rows)
	}
	_ = d.Stop(context.Background())
}

// Covers: FR-43
// Acceptance: Back-channel logout
// A failing claim or delete changes nothing: the rows are claimed again by a later
// round, and a delivered row whose delete failed is posted again with a new jti.
func TestStorageFailuresLeaveTheRowsForALaterRound(t *testing.T) {
	e := newDeliverEnv(t)
	e.enqueue("n1", "app", "s1", 0)
	e.st.failClaim.Store(1)
	e.start(0)
	e.clk.Advance(5 * time.Second)
	e.idle()
	if rows := e.rows(); len(rows) != 1 || !strings.HasSuffix(rows[0], " 0") {
		t.Fatalf("rows %v, want the failed claim to leave the row alone", rows)
	}
	if !strings.Contains(e.logBuf.String(), "cannot claim the due rows") {
		t.Fatalf("no error logged for the failed claim: %s", e.logBuf.String())
	}
	select {
	case rec := <-e.got:
		t.Fatalf("a failed claim posted: %+v", rec)
	default:
	}

	e.st.failDone.Store(1)
	e.clk.Advance(5 * time.Second)
	first := e.expect()
	e.idle()
	if rows := e.rows(); len(rows) != 1 {
		t.Fatalf("rows %v, want the row still there after the failed delete", rows)
	}
	if !strings.Contains(e.logBuf.String(), "cannot delete the delivered row") {
		t.Fatalf("no error logged for the failed delete: %s", e.logBuf.String())
	}
	e.clk.Advance(time.Minute)
	second := e.expect()
	e.idle()
	if first.token == second.token {
		t.Fatal("the row was posted again with the same token")
	}
	if rows := e.rows(); len(rows) != 0 {
		t.Fatalf("rows after the second delivery: %v", rows)
	}
}

// Covers: FR-43
// Acceptance: Back-channel logout
// Each call that a round makes starts without a transaction open and the rounds
// finish before Stop returns: no worker goroutine outlives the stop.
func TestRoundsAreConcurrencySafe(t *testing.T) {
	e := newDeliverEnv(t)
	for i := 0; i < 8; i++ {
		e.enqueue(fmt.Sprintf("n%02d", i), "app", fmt.Sprintf("s%02d", i), 0)
	}
	e.start(0)
	e.clk.Advance(5 * time.Second)
	for i := 0; i < 4; i++ {
		rec := e.expect()
		if rec.open != 0 {
			t.Fatalf("%d transactions open during a call", rec.open)
		}
	}
	e.idle()
	if rows := e.rows(); len(rows) != 4 {
		t.Fatalf("rows after the first round: %v, want the four not claimed left", rows)
	}
	e.clk.Advance(5 * time.Second)
	for i := 0; i < 4; i++ {
		e.expect()
	}
	e.idle()
	if rows := e.rows(); len(rows) != 0 {
		t.Fatalf("rows after the deliveries: %v", rows)
	}
}

// Covers: FR-43
// Acceptance: Back-channel logout
// The log of a delivery holds neither the logout token nor the receiver's URI.
func TestDeliveryLogTellsNothingSecret(t *testing.T) {
	e := newDeliverEnv(t)
	e.enqueue("n1", "app", "s1", 0)
	e.start(0)
	e.clk.Advance(5 * time.Second)
	rec := e.expect()
	e.idle()
	logs := e.logBuf.String()
	if strings.Contains(logs, rec.token) || strings.Contains(logs, e.recv.URL) {
		t.Fatalf("the log holds the token or the URI: %s", logs)
	}
}

// Covers: FR-43
// Acceptance: Back-channel logout
// The response body is read up to 64 KB and no further: an endless 200 is still a
// delivery, which only a bounded read can finish within the timeout.
func TestEndlessBodyIsReadUpTo64KB(t *testing.T) {
	e := newDeliverEnv(t)
	e.setRespond(func(_ int, w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		chunk := []byte(strings.Repeat("x", 1024))
		for {
			if _, err := w.Write(chunk); err != nil {
				return
			}
			if r.Context().Err() != nil {
				return
			}
		}
	})
	e.enqueue("n1", "app", "s1", 0)
	e.start(time.Minute) // a read without a limit would hit this timeout
	e.clk.Advance(5 * time.Second)
	e.expect()
	e.idle()
	if rows := e.rows(); len(rows) != 0 {
		t.Fatalf("an endless 200 was not a delivery; the body was not bounded: %v", rows)
	}
}

// Covers: FR-43
// Acceptance: Back-channel logout
// A configured realm the store does not know yet has no rows to deliver: the round
// skips it without an error and delivers the rows of the realms it knows.
func TestConfiguredRealmUnknownToTheStoreIsSkipped(t *testing.T) {
	e := newDeliverEnv(t)
	e.dir.RSAKey(t, "secrets/other/rsa.pem")
	e.dir.Realm(t, "other", "name: other\nkeys:\n  - {kid: rsa-other, file: secrets/other/rsa.pem, state: active}\nclients:\n  app:\n    redirect_uris: [https://app.other.example.test/cb]\n")
	if res := e.loader.Reload(context.Background()); len(res.Diagnostics) != 0 {
		t.Fatalf("the reload: %v", res.Diagnostics)
	}
	e.enqueue("n1", "app", "s1", 0)
	e.start(0)
	e.clk.Advance(5 * time.Second)
	e.expect()
	e.idle()
	if rows := e.rows(); len(rows) != 0 {
		t.Fatalf("rows %v, want the row of main delivered", rows)
	}
	if strings.Contains(e.logBuf.String(), "cannot claim") {
		t.Fatalf("the round failed on the realm the store does not know: %s", e.logBuf.String())
	}
}

// Covers: FR-43
// Acceptance: Back-channel logout
// A row of a realm the configuration does not name is deleted unsent.
func TestRowOfAnUnconfiguredRealmIsDeletedUnsent(t *testing.T) {
	e := newDeliverEnv(t)
	now := e.clk.Now()
	if err := e.st.Write(context.Background(), func(tx store.Tx) error {
		return tx.LogoutNotifications().Enqueue(context.Background(), store.LogoutNotification{
			ID: "n1", RealmID: "R-gone", ClientID: "app", UserID: "u1", SessionID: "s1", NextAttemptAt: now, CreatedAt: now,
		})
	}); err != nil {
		t.Fatal(err)
	}
	e.start(0)
	e.clk.Advance(5 * time.Second)
	e.idle()
	select {
	case rec := <-e.got:
		t.Fatalf("a row of an unconfigured realm was posted: %+v", rec)
	default:
	}
	if rows := e.rows(); len(rows) != 0 {
		t.Fatalf("rows %v, want the row deleted", rows)
	}
}

// Covers: FR-43
// Acceptance: Back-channel logout
// A realm lookup that fails (not because the realm is unknown) stops the round
// before any row is claimed.
func TestRealmLookupFailureClaimsNothing(t *testing.T) {
	e := newDeliverEnv(t)
	e.enqueue("n1", "app", "s1", 0)
	e.st.failFind.Store(true)
	e.start(0)
	e.clk.Advance(5 * time.Second)
	e.idle()
	e.st.failFind.Store(false)
	select {
	case rec := <-e.got:
		t.Fatalf("a round posted after a failed realm lookup: %+v", rec)
	default:
	}
	if rows := e.rows(); len(rows) != 1 || !strings.HasSuffix(rows[0], " 0") {
		t.Fatalf("rows %v, want the row untouched", rows)
	}
	if !strings.Contains(e.logBuf.String(), "cannot claim the due rows") {
		t.Fatalf("no error logged: %s", e.logBuf.String())
	}
}

// Covers: FR-43, SEC-13
// Acceptance: Back-channel logout
// Whatever goes wrong with a try, the log holds neither the logout token, nor the
// URI's query or credentials, nor the URI itself: the failure is logged as its
// status or its error, cleaned of the URL.
func TestFailureLogsTellNothingSecret(t *testing.T) {
	const (
		user  = "uSerAcct-9"
		pass  = "pW-p4ss-w0rd-7"
		query = "code=qCode-s3cr3t-5"
	)
	redirect := func(_ int, w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "/elsewhere?code=qCode-s3cr3t-5")
		w.WriteHeader(http.StatusFound)
	}
	fail := func(_ int, w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusInternalServerError) }
	hang := func(_ int, _ http.ResponseWriter, r *http.Request) { <-r.Context().Done() }
	scenarios := []struct {
		name        string
		respond     func(n int, w http.ResponseWriter, r *http.Request)
		timeout     time.Duration
		unreachable bool
		tries       int
		want        string // what the log must say about the failure
	}{
		{name: "500 answer", respond: fail, tries: 1, want: `"status":500`},
		{name: "redirect answer", respond: redirect, tries: 1, want: `"status":302`},
		{name: "hung receiver", respond: hang, timeout: 100 * time.Millisecond, tries: 1, want: "Timeout"},
		{name: "unreachable receiver", unreachable: true, tries: 1, want: "refused"},
		{name: "given up after five tries", respond: fail, tries: 5, want: "giving up after 5 tries"},
	}
	waits := []time.Duration{5 * time.Second, time.Minute, 5 * time.Minute, 30 * time.Minute, 2 * time.Hour}
	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			e := newDeliverEnv(t)
			hostport := strings.TrimPrefix(e.recv.URL, "http://")
			if sc.unreachable {
				l, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				hostport = l.Addr().String()
				_ = l.Close() // nothing listens there now
			}
			uri := "http://" + user + ":" + pass + "@" + hostport + "/logout?" + query
			e.writeRealm(uri)
			if sc.respond != nil {
				e.setRespond(sc.respond)
			}
			e.enqueue("n1", "app", "s1", 0)
			e.start(sc.timeout)
			var tokens []string
			for i := 0; i < sc.tries; i++ {
				e.clk.Advance(waits[i])
				if !sc.unreachable {
					tokens = append(tokens, e.expect().token)
				}
				e.idle()
			}
			logs := e.logBuf.String()
			if !strings.Contains(logs, sc.want) {
				t.Fatalf("the log does not say %q: %s", sc.want, logs)
			}
			for _, tok := range tokens {
				if tok != "" && strings.Contains(logs, tok) {
					t.Errorf("the log holds the logout token")
				}
			}
			for _, secret := range []string{query, "qCode-s3cr3t-5", pass, user, uri} {
				if strings.Contains(logs, secret) {
					t.Errorf("the log holds %q: %s", secret, logs)
				}
			}
		})
	}
}

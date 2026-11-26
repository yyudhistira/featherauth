package oidc_test

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/clock"
)

// roundClients is a realm of four clients, each with a receiver path of its own on
// the test receiver, so a test can make one receiver hang and the others answer.
const roundClients = "name: main\nkeys:\n  - {kid: rsa1, file: secrets/main/rsa.pem, state: active}\nclients:\n%s"

// roundEnv is a deliverEnv with four clients c1 to c4 that post to /c1 to /c4, and
// a recorder of the calls the receiver gets (the buffer of deliverEnv.got holds the
// few calls these tests make, and nothing reads it).
type roundEnv struct {
	*deliverEnv
	mu       sync.Mutex
	paths    []string // the paths called, in the order the calls arrived
	inflight int
	maxFlows int                                           // the most calls in flight at once
	started  chan string                                   // a call has arrived: its path
	behave   func(path string, n int, r *http.Request) int // the status to answer, after any wait
	calls    map[string]int                                // the calls so far by path
}

func newRoundEnv(t *testing.T) *roundEnv {
	t.Helper()
	e := &roundEnv{deliverEnv: newDeliverEnv(t), started: make(chan string, 64), calls: map[string]int{}}
	var clients strings.Builder
	for i := 1; i <= 4; i++ {
		fmt.Fprintf(&clients, "  c%d:\n    redirect_uris: [https://c%d.example.test/cb]\n    backchannel_logout_uri: %q\n", i, i, e.recv.URL+fmt.Sprintf("/c%d", i))
	}
	e.dir.Realm(t, "main", fmt.Sprintf(roundClients, clients.String()))
	if res := e.loader.Reload(context.Background()); len(res.Diagnostics) != 0 || !res.Applied {
		t.Fatalf("the reload: applied %v, diagnostics %v", res.Applied, res.Diagnostics)
	}
	e.behave = func(string, int, *http.Request) int { return http.StatusOK }
	e.setRespond(func(_ int, w http.ResponseWriter, r *http.Request) {
		e.mu.Lock()
		e.paths = append(e.paths, r.URL.Path)
		e.calls[r.URL.Path]++
		n := e.calls[r.URL.Path]
		e.inflight++
		e.maxFlows = max(e.maxFlows, e.inflight)
		behave := e.behave
		e.mu.Unlock()
		e.started <- r.URL.Path
		status := behave(r.URL.Path, n, r)
		e.mu.Lock()
		e.inflight--
		e.mu.Unlock()
		w.WriteHeader(status)
	})
	return e
}

// hang waits until the client gives up on the call.
func hang(r *http.Request) int {
	<-r.Context().Done()
	return http.StatusOK
}

func (e *roundEnv) enqueueRound() {
	e.t.Helper()
	for i := 1; i <= 4; i++ {
		e.enqueue(fmt.Sprintf("n%d", i), fmt.Sprintf("c%d", i), fmt.Sprintf("s%d", i), 0)
	}
}

func (e *roundEnv) seen() ([]string, int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.paths...), e.maxFlows
}

// Four notices of four clients; the first receiver does not answer on its first
// call and the others answer 200. One round posts the rows one after another, so
// the three others are delivered in the same round after the first call's
// timeout, and no two calls overlap; the first row keeps its place with one more
// try and is delivered at its next try. The test's 100ms timeout stands in for
// the design's 5 seconds, because the HTTP client's timeout is the one timer that
// the fake clock does not move.
// Covers: FR-43
// Acceptance: Back-channel rounds
func TestBackchannelRoundWithAHungReceiverDeliversTheOthers(t *testing.T) {
	// NFR-15, row "Back-channel rounds".
	e := newRoundEnv(t)
	e.behave = func(path string, n int, r *http.Request) int {
		if path == "/c1" && n == 1 {
			return hang(r)
		}
		return http.StatusOK
	}
	e.enqueueRound()
	e.start(100 * time.Millisecond)
	e.clk.Advance(5 * time.Second)
	e.idle()

	paths, maxFlows := e.seen()
	if want := []string{"/c1", "/c2", "/c3", "/c4"}; fmt.Sprint(paths) != fmt.Sprint(want) {
		t.Fatalf("calls %v, want the rows posted in their order %v", paths, want)
	}
	if maxFlows != 1 {
		t.Errorf("%d calls overlapped, want the rows posted one after another", maxFlows)
	}
	if rows := e.rows(); len(rows) != 1 || rows[0] != "n1 s1 1" {
		t.Fatalf("rows %v after the round, want only the first, with one try", rows)
	}
	// The first row's next try is a minute after its first: not before.
	e.clk.Advance(59 * time.Second)
	e.idle()
	if paths, _ := e.seen(); len(paths) != 4 {
		t.Fatalf("calls %v before the next try was due", paths)
	}
	e.clk.Advance(time.Second)
	e.idle()
	paths, _ = e.seen()
	if len(paths) != 5 || paths[4] != "/c1" {
		t.Fatalf("calls %v, want the first row tried again at its next try", paths)
	}
	if rows := e.rows(); len(rows) != 0 {
		t.Fatalf("rows %v after the first row was delivered", rows)
	}
}

// A round takes at most four calls: with every receiver hung, the four calls run
// one after another, so the round lasts the time of four timeouts (at most 20
// seconds with the design's 5), and each row has one more try.
// Covers: FR-43
// Acceptance: Back-channel rounds
func TestBackchannelRoundOfHungReceiversRunsTheCallsInSequence(t *testing.T) {
	// NFR-15, row "Back-channel rounds".
	const timeout = 150 * time.Millisecond
	e := newRoundEnv(t)
	e.behave = func(_ string, _ int, r *http.Request) int { return hang(r) }
	e.enqueueRound()
	e.start(timeout)
	real := clock.Real()
	begin := real.Now()
	e.clk.Advance(5 * time.Second)
	e.idle()
	took := real.Now().Sub(begin)

	if _, maxFlows := e.seen(); maxFlows != 1 {
		t.Errorf("%d calls overlapped", maxFlows)
	}
	if took < 4*timeout {
		t.Errorf("the round took %v, less than the four timeouts of %v: the calls ran together", took, 4*timeout)
	}
	if took > 4*timeout+3*time.Second {
		t.Errorf("the round took %v, want about the four timeouts of %v", took, 4*timeout)
	}
	if rows := e.rows(); fmt.Sprint(rows) != "[n1 s1 1 n2 s2 1 n3 s3 1 n4 s4 1]" {
		t.Fatalf("rows %v, want each row kept with one try", rows)
	}
}

// Ticks while a round is still running overlap nothing: round one holds four rows
// and a fifth waits, and the fifth is posted only after round one's last call, by
// the round that follows. (The tick's own test is in the internal tests.)
// Covers: FR-43
// Acceptance: Back-channel rounds
func TestBackchannelNextRoundStartsOnlyAfterTheRoundBefore(t *testing.T) {
	// NFR-15, row "Back-channel rounds".
	e := newRoundEnv(t)
	release := make(chan struct{})
	e.behave = func(path string, n int, _ *http.Request) int {
		if path == "/c1" && n == 1 {
			<-release
		}
		return http.StatusOK
	}
	e.enqueueRound()
	e.enqueue("n5", "c4", "s5", 0)
	e.start(0)

	e.clk.Advance(5 * time.Second)
	if p := <-e.started; p != "/c1" {
		t.Fatalf("the first call went to %s", p)
	}
	// Two more ticks while the first call is in flight.
	e.clk.Advance(5 * time.Second)
	e.clk.Advance(5 * time.Second)
	close(release)
	e.idle()

	paths, maxFlows := e.seen()
	if want := []string{"/c1", "/c2", "/c3", "/c4", "/c4"}; fmt.Sprint(paths) != fmt.Sprint(want) {
		t.Fatalf("calls %v, want %v: the fifth row follows the four of the round before", paths, want)
	}
	if maxFlows != 1 {
		t.Errorf("%d calls overlapped", maxFlows)
	}
	if rows := e.rows(); len(rows) != 0 {
		t.Fatalf("rows %v after the fifth row was delivered", rows)
	}
}

// A receiver that never answers costs only its own row: the other three rows are
// delivered in the first round, and the first row is dropped after its own fifth
// failed try, with the warning that names its client and session, and not before.
// Covers: FR-43
// Acceptance: Back-channel rounds
func TestBackchannelHungReceiverRowIsDroppedOnlyAfterItsFifthTry(t *testing.T) {
	// NFR-15, row "Back-channel rounds".
	e := newRoundEnv(t)
	e.behave = func(path string, _ int, r *http.Request) int {
		if path == "/c1" {
			return hang(r)
		}
		return http.StatusOK
	}
	e.enqueueRound()
	e.start(100 * time.Millisecond)
	waits := []time.Duration{5 * time.Second, time.Minute, 5 * time.Minute, 30 * time.Minute, 2 * time.Hour}
	for i, wait := range waits {
		e.clk.Advance(wait)
		e.idle()
		rows := e.rows()
		if i < len(waits)-1 {
			if want := fmt.Sprintf("[n1 s1 %d]", i+1); fmt.Sprint(rows) != want {
				t.Fatalf("rows %v after try %d, want %s: the row is kept until its fifth failed try", rows, i+1, want)
			}
			continue
		}
		if len(rows) != 0 {
			t.Fatalf("rows %v after the fifth failed try, want the row dropped", rows)
		}
	}
	paths, _ := e.seen()
	if len(paths) != 8 {
		t.Fatalf("calls %v, want the first row five times and the others once", paths)
	}
	log := e.logBuf.String()
	if strings.Count(log, "giving up after 5 tries") != 1 || !strings.Contains(log, `"client":"c1","session":"s1","attempt":5`) {
		t.Fatalf("want one warning naming client c1 and session s1 from the fifth try: %s", log)
	}
}

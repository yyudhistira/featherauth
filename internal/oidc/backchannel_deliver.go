package oidc

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/secure"
	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/token"
)

// The delivery schedule of back-channel logout (FR-43): the worker looks for due
// rows every deliverEvery, claims at most deliverBatch of them, and gives a row up
// after deliverFinalTry tries. The waits between tries are the store's.
const (
	deliverEvery     = 5 * time.Second
	deliverBatch     = 4
	deliverFinalTry  = 5
	deliverBodyLimit = 64 << 10
	deliverTimeout   = 5 * time.Second
)

// DeliverConfig is what the back-channel logout worker needs.
type DeliverConfig struct {
	// Store holds logout_notifications; required.
	Store store.Store
	// Source is the configuration, read at every round; required.
	Source config.Source
	// Clock is the source of time and of the worker's timer; required.
	Clock clock.Clock
	// Rand is the source of the ids (jti) of the logout tokens; required.
	Rand secure.Source
	// Log is the service logger (logx); required.
	Log *slog.Logger
	// Transport carries the posts; nil uses a transport of its own.
	Transport http.RoundTripper
	// Timeout bounds each post; zero is the 5 seconds of the design.
	Timeout time.Duration
}

// Deliverer sends the back-channel logout tokens of logout_notifications. A round
// claims the due rows in one short write transaction, then posts each token with
// no transaction open: a 200 or a 204 deletes the row, and any other answer
// leaves it for the try that the claim scheduled. The worker re-arms its timer
// on the configured clock, so a test moves time with the fake clock.
type Deliverer struct {
	cfg       DeliverConfig
	client    *http.Client
	transport http.RoundTripper
	base      context.Context // the context of the rounds; cancelled when a stop runs out of time
	cancel    context.CancelFunc

	mu       sync.Mutex
	stopping bool
	timer    clock.Timer
	rounds   int           // 1 while a burst of rounds is in flight, else 0
	again    bool          // a tick came during a round: one more round follows it
	idle     chan struct{} // closed while no round is in flight
}

// NewDeliverer returns a worker. It does nothing until Start.
func NewDeliverer(cfg DeliverConfig) *Deliverer {
	if cfg.Timeout <= 0 {
		cfg.Timeout = deliverTimeout
	}
	tr := cfg.Transport
	if tr == nil {
		tr = &http.Transport{}
	}
	base, cancel := context.WithCancel(context.Background())
	idle := make(chan struct{})
	close(idle)
	return &Deliverer{
		cfg: cfg,
		client: &http.Client{Timeout: cfg.Timeout, Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse // a redirect is the answer, not a target
		}},
		transport: tr, base: base, cancel: cancel, idle: idle,
	}
}

// Start arms the timer: the first round is due one interval from now.
func (d *Deliverer) Start() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.arm()
}

// arm sets the next tick; the caller holds mu.
func (d *Deliverer) arm() {
	d.timer = d.cfg.Clock.AfterFunc(deliverEvery, d.tick)
}

// tick starts a round in its own goroutine, and arms the next tick. A stopping
// worker starts nothing, so no row is claimed after a stop has begun. A tick that
// finds a round still running starts none: the next round starts only when the
// round before has ended (NFR-15). The ticks that came meanwhile are remembered,
// so one round follows at once, and rows that fell due during a long round wait no
// longer than that round.
func (d *Deliverer) tick() {
	d.mu.Lock()
	if d.stopping {
		d.mu.Unlock()
		return
	}
	d.arm()
	if d.rounds > 0 {
		d.again = true
		d.mu.Unlock()
		return
	}
	d.idle = make(chan struct{})
	d.rounds++
	d.mu.Unlock()
	go d.run()
}

// run makes the rounds of one burst: the one a tick started and, while ticks came
// during a round and the worker is not stopping, one more after it. It is the
// only goroutine that makes rounds, so no two rounds overlap.
func (d *Deliverer) run() {
	for {
		d.round(d.base)
		d.mu.Lock()
		if d.again && !d.stopping {
			d.again = false
			d.mu.Unlock()
			continue
		}
		d.again = false
		d.rounds--
		if d.rounds == 0 {
			close(d.idle)
		}
		d.mu.Unlock()
		return
	}
}

// quiet returns a channel that is closed while no round is in flight.
func (d *Deliverer) quiet() <-chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.idle
}

// Idle waits until no round is in flight, or until ctx ends.
func (d *Deliverer) Idle(ctx context.Context) error {
	select {
	case <-d.quiet():
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Stop ends the worker: it stops the timer, starts no round, and waits for the
// rounds in flight. When ctx ends first, the calls in flight are cut off, and
// each counts as a try (its claim already counted it); Stop then returns ctx's
// error once they have returned.
func (d *Deliverer) Stop(ctx context.Context) error {
	d.mu.Lock()
	d.stopping = true
	if d.timer != nil {
		d.timer.Stop()
	}
	d.mu.Unlock()
	var err error
	select {
	case <-d.quiet():
	case <-ctx.Done():
		d.cancel()
		<-d.quiet()
		err = ctx.Err()
	}
	// No call is in flight now: the idle connections of the transport go too.
	if c, ok := d.transport.(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
	}
	return err
}

// round delivers one batch of due rows. A configuration that is not loaded claims
// nothing, so the rows keep their tries for a later round.
func (d *Deliverer) round(ctx context.Context) {
	snap := d.cfg.Source.Current()
	if snap == nil {
		return
	}
	now := d.cfg.Clock.Now()
	realms := map[store.RealmID]*config.Realm{}
	var rows []store.LogoutNotification
	err := d.cfg.Store.Write(ctx, func(tx store.Tx) error {
		for _, r := range snap.Realms() {
			id, err := tx.Realms().Find(ctx, r.Name)
			if errors.Is(err, store.ErrNotFound) {
				continue
			}
			if err != nil {
				return err
			}
			realms[id] = r
		}
		var err error
		rows, err = tx.LogoutNotifications().Claim(ctx, now, deliverBatch)
		return err
	})
	if err != nil {
		d.cfg.Log.ErrorContext(ctx, "back-channel logout: cannot claim the due rows", "error", err)
		return
	}
	for _, n := range rows {
		d.deliver(ctx, snap, realms[n.RealmID], n)
	}
}

// deliver makes one try for a claimed row, outside any transaction.
func (d *Deliverer) deliver(ctx context.Context, snap *config.Snapshot, realm *config.Realm, n store.LogoutNotification) {
	attrs := []any{"client", string(n.ClientID), "session", string(n.SessionID)}
	if realm == nil {
		d.drop(ctx, n, "the realm is not in the configuration", attrs...)
		return
	}
	cl := realm.Clients[n.ClientID]
	if cl == nil || cl.BackchannelLogoutURI == "" {
		d.drop(ctx, n, "the client has no back-channel logout URI", attrs...)
		return
	}
	if n.Attempts >= deliverFinalTry {
		d.drop(ctx, n, "giving up: the row has had its 5 tries already", attrs...)
		return
	}
	tries := n.Attempts + 1
	attrs = append(attrs, "attempt", tries)
	jti, err := secure.NewID(d.cfg.Rand, d.cfg.Clock)
	if err != nil {
		d.cfg.Log.ErrorContext(ctx, "back-channel logout: cannot make the token id", append(attrs, "error", err)...)
		return
	}
	iss := token.NewIssuer(d.cfg.Clock, d.cfg.Rand, snap.Secrets())
	raw, err := iss.Logout(realm, cl, token.UserID(n.UserID), token.SessionID(n.SessionID), jti)
	if err != nil {
		d.cfg.Log.ErrorContext(ctx, "back-channel logout: cannot sign the token", append(attrs, "error", err)...)
		return
	}
	status, err := d.post(ctx, cl.BackchannelLogoutURI, raw)
	if err == nil && (status == http.StatusOK || status == http.StatusNoContent) {
		d.done(ctx, n, attrs...)
		return
	}
	if tries >= deliverFinalTry {
		d.drop(ctx, n, "giving up after 5 tries", append(attrs, "status", status, "error", err)...)
		return
	}
	d.cfg.Log.WarnContext(ctx, "back-channel logout failed; it is tried again", append(attrs, "status", status, "error", err)...)
}

// post sends the logout token as the one form field of a POST and reads the
// answer's body up to deliverBodyLimit, which is discarded.
func (d *Deliverer) post(ctx context.Context, uri, raw string) (int, error) {
	form := url.Values{"logout_token": {raw}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uri, strings.NewReader(form))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := d.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, deliverBodyLimit))
	return resp.StatusCode, nil
}

// done deletes a delivered row.
func (d *Deliverer) done(ctx context.Context, n store.LogoutNotification, attrs ...any) {
	err := d.cfg.Store.Write(ctx, func(tx store.Tx) error {
		return tx.LogoutNotifications().Done(ctx, n.ID)
	})
	if err != nil {
		d.cfg.Log.ErrorContext(ctx, "back-channel logout: cannot delete the delivered row", append(attrs, "error", err)...)
	}
}

// drop deletes a row that is not sent again, with a warning when the row was given
// up or had no URI to go to.
func (d *Deliverer) drop(ctx context.Context, n store.LogoutNotification, why string, attrs ...any) {
	err := d.cfg.Store.Write(ctx, func(tx store.Tx) error {
		return tx.LogoutNotifications().Drop(ctx, n.ID)
	})
	if err != nil {
		d.cfg.Log.ErrorContext(ctx, "back-channel logout: cannot delete the row", append(attrs, "error", err)...)
		return
	}
	if strings.HasPrefix(why, "giving up") {
		d.cfg.Log.WarnContext(ctx, "back-channel logout: "+why, attrs...)
		return
	}
	d.cfg.Log.InfoContext(ctx, "back-channel logout not sent: "+why, attrs...)
}

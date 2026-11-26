package oidc_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"

	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/logx"
	"github.com/yyudhistira/featherauth/internal/oidc"
	"github.com/yyudhistira/featherauth/internal/secure"
	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/testutil/server"
	"github.com/yyudhistira/featherauth/internal/token"
)

// liveConfig is the configuration of the test server, as it is after a reload.
type liveConfig struct{ e *server.Env }

func (c liveConfig) Current() *config.Snapshot { return c.e.Snapshot }

// hostRewrite sends every request of the worker to the test receiver, keeping the
// path and the TLS trust of the receiver: the client URI names another host.
type hostRewrite struct {
	base http.RoundTripper
	host string
}

func (h hostRewrite) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Host = h.host
	return h.base.RoundTrip(req)
}

// backchannelRig is the worker of the test server with a TLS receiver for the
// client's back-channel logout URI.
type backchannelRig struct {
	e    *server.Env
	recv *httptest.Server
	got  chan string // the logout token of each post, in order
	hits atomic.Int64
	d    *oidc.Deliverer
}

func newBackchannelRig(t *testing.T, e *server.Env) *backchannelRig {
	t.Helper()
	r := &backchannelRig{e: e, got: make(chan string, 64)}
	r.recv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.hits.Add(1)
		_ = req.ParseForm()
		r.got <- req.PostForm.Get("logout_token")
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(r.recv.Close)
	host := strings.TrimPrefix(r.recv.URL, "https://")
	r.d = oidc.NewDeliverer(oidc.DeliverConfig{
		Store: e.Store, Source: liveConfig{e}, Clock: e.Clock, Rand: secure.Default,
		Log:       logx.New(io.Discard, slog.LevelDebug, e.Clock),
		Transport: hostRewrite{base: r.recv.Client().Transport, host: host},
	})
	t.Cleanup(func() { _ = r.d.Stop(context.Background()) })
	return r
}

// deliveredSessions starts the worker, moves to its first tick, and collects the
// posts: one per expected session, each a logout token that verifies with the
// realm's keys. No row is left.
func (r *backchannelRig) deliveredSessions(t *testing.T, want []string) {
	t.Helper()
	r.d.Start()
	r.e.Clock.Advance(5 * time.Second)
	var got []string
	for range want {
		raw := <-r.got
		snap := r.e.Snapshot
		realm, _ := snap.Realm("main")
		ks, err := token.NewKeySet(realm, snap.Secrets())
		if err != nil {
			t.Fatal(err)
		}
		set, err := jwk.Parse(ks.JWKS())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := jws.Verify([]byte(raw), jws.WithKeySet(set, jws.WithInferAlgorithmFromKey(true))); err != nil {
			t.Fatalf("a logout token does not verify: %v", err)
		}
		header, payload := claims(t, raw)
		if header["typ"] != "logout+jwt" || payload["aud"] != "web" {
			t.Errorf("header %v claims %v", header, payload)
		}
		got = append(got, payload["sid"].(string))
	}
	if err := r.d.Idle(context.Background()); err != nil {
		t.Fatal(err)
	}
	slices.Sort(got)
	slices.Sort(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("delivered for sessions %v, want %v", got, want)
	}
	select {
	case raw := <-r.got:
		t.Fatalf("an extra logout token was posted: %s", raw)
	default:
	}
	if rows := queuedRows(t, r.e); len(rows) != 0 {
		t.Fatalf("rows left after the delivery: %v", rows)
	}
}

// Covers: FR-43, SEC-35
// Acceptance: Back-channel logout
// Every kind of revocation of a session of the client with the URI is delivered
// once, as a logout token for that session that verifies with the realm's keys;
// the client without the URI gets nothing, and a session revoked before gets no
// second delivery.
func TestEveryKindOfRevocationIsDelivered(t *testing.T) {
	app, frag := server.ClientQuery, server.ClientFragment
	sid := func(tk server.Tokens) string { return sidOf(t, tk.AccessToken) }
	kinds := []struct {
		name string
		run  func(t *testing.T, e *server.Env, a, b, f server.Tokens)
		want func(a, b, f server.Tokens) []string
	}{
		{"the logout with id_token_hint", func(t *testing.T, e *server.Env, a, b, f server.Tokens) {
			wantSignedOut(t, logout(t, e, http.MethodGet, url.Values{"id_token_hint": {a.IDToken}}, nil))
		}, func(a, b, f server.Tokens) []string { return []string{sid(a)} }},
		{"the logout by refresh token", func(t *testing.T, e *server.Env, a, b, f server.Tokens) {
			if r := logout(t, e, http.MethodPost, url.Values{"refresh_token": {a.RefreshToken}, "client_id": {app.ID}}, nil); r.Code != 204 {
				t.Fatalf("status %d", r.Code)
			}
		}, func(a, b, f server.Tokens) []string { return []string{sid(a)} }},
		{"the bearer logout", func(t *testing.T, e *server.Env, a, b, f server.Tokens) {
			if r := signOut(t, e, a, nil); r.Code != 204 {
				t.Fatalf("status %d", r.Code)
			}
		}, func(a, b, f server.Tokens) []string { return []string{sid(a)} }},
		{"the session field", func(t *testing.T, e *server.Env, a, b, f server.Tokens) {
			if r := signOut(t, e, a, url.Values{"session": {sid(b)}}); r.Code != 204 {
				t.Fatalf("status %d", r.Code)
			}
		}, func(a, b, f server.Tokens) []string { return []string{sid(b)} }},
		{"sign out everywhere", func(t *testing.T, e *server.Env, a, b, f server.Tokens) {
			if r := signOut(t, e, a, url.Values{"all_sessions": {"true"}}); r.Code != 204 {
				t.Fatalf("status %d", r.Code)
			}
		}, func(a, b, f server.Tokens) []string { return []string{sid(a), sid(b)} }},
		{"the revocation endpoint", func(t *testing.T, e *server.Env, a, b, f server.Tokens) {
			wantRevokeAnswer(t, revoke(t, e, revokeForm(app, a.RefreshToken), nil))
		}, func(a, b, f server.Tokens) []string { return []string{sid(a)} }},
		{"a reuse of a rotated refresh token", func(t *testing.T, e *server.Env, a, b, f server.Tokens) {
			wantTokens(t, refresh(t, e, app, a.RefreshToken))
			e.Clock.Advance(time.Minute)
			if r := refresh(t, e, app, a.RefreshToken); r.Code != 400 {
				t.Fatalf("reuse: status %d", r.Code)
			}
		}, func(a, b, f server.Tokens) []string { return []string{sid(a)} }},
		{"an expired session", func(t *testing.T, e *server.Env, a, b, f server.Tokens) {
			e.Clock.Advance(800 * time.Hour) // the refresh tokens expired
			wantRevokeAnswer(t, revoke(t, e, revokeForm(app, a.RefreshToken), nil))
		}, func(a, b, f server.Tokens) []string { return []string{sid(a)} }},
		{"disabling the user", func(t *testing.T, e *server.Env, a, b, f server.Tokens) {
			if err := e.Users.Disable(context.Background(), "admin", "main", store.UserID(jwtClaim(t, a.IDToken, "sub"))); err != nil {
				t.Fatal(err)
			}
		}, func(a, b, f server.Tokens) []string { return []string{sid(a), sid(b)} }},
		{"deleting the user", func(t *testing.T, e *server.Env, a, b, f server.Tokens) {
			if r := deleteAccountWith(t, e, http.MethodDelete, a.AccessToken); r.Code != 204 {
				t.Fatalf("status %d %q", r.Code, r.Body)
			}
		}, func(a, b, f server.Tokens) []string { return []string{sid(a), sid(b)} }},
		{"a session revoked by the administration commands", func(t *testing.T, e *server.Env, a, b, f server.Tokens) {
			if _, err := e.Users.RevokeSession(context.Background(), "admin", "main", store.UserID(jwtClaim(t, a.IDToken, "sub")), store.SessionID(sid(a))); err != nil {
				t.Fatal(err)
			}
		}, func(a, b, f server.Tokens) []string { return []string{sid(a)} }},
		{"a session of the client without the URI", func(t *testing.T, e *server.Env, a, b, f server.Tokens) {
			if r := signOut(t, e, f, nil); r.Code != 204 {
				t.Fatalf("status %d", r.Code)
			}
		}, func(a, b, f server.Tokens) []string { return nil }},
		{"a session revoked before, by a second logout", func(t *testing.T, e *server.Env, a, b, f server.Tokens) {
			if r := signOut(t, e, a, nil); r.Code != 204 {
				t.Fatalf("first: %d", r.Code)
			}
			if r := signOut(t, e, a, nil); r.Code != 204 {
				t.Fatalf("second: %d", r.Code)
			}
		}, func(a, b, f server.Tokens) []string { return []string{sid(a)} }},
	}
	for _, k := range kinds {
		t.Run(k.name, func(t *testing.T) {
			e := backchannelEnv(t)
			r := newBackchannelRig(t, e)
			a := exchange(t, e, app)
			b := exchange(t, e, app)
			f := exchange(t, e, frag)
			k.run(t, e, a, b, f)
			want := k.want(a, b, f)
			if want == nil {
				r.d.Start()
				e.Clock.Advance(5 * time.Second)
				if err := r.d.Idle(context.Background()); err != nil {
					t.Fatal(err)
				}
				if n := r.hits.Load(); n != 0 {
					t.Fatalf("%d posts for a client without the URI", n)
				}
				return
			}
			r.deliveredSessions(t, want)
		})
	}
}

// Covers: FR-43
// Acceptance: Back-channel logout
// A row queued while the service runs (by the administration commands) is sent at
// the next tick of the worker, five seconds of the fake clock later.
func TestRowQueuedWhileTheWorkerRunsIsSentWithinFiveSeconds(t *testing.T) {
	app := server.ClientQuery
	e := backchannelEnv(t)
	r := newBackchannelRig(t, e)
	a := exchange(t, e, app)
	r.d.Start()
	if _, err := e.Users.RevokeSessions(context.Background(), "admin", "main", store.UserID(jwtClaim(t, a.IDToken, "sub"))); err != nil {
		t.Fatal(err)
	}
	r.deliveredSessions(t, []string{sidOf(t, a.AccessToken)})
}

package provider_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/provider"
	"github.com/yyudhistira/featherauth/internal/testutil/mockidp"
)

var _ provider.EventReceiver = (*provider.Apple)(nil)

// one is the one event of a ParseEvent result: an adapter whose body holds
// one event returns exactly one, and any other count is an error.
func one(evs []provider.Event, err error) (provider.Event, error) {
	if err != nil {
		return provider.Event{}, err
	}
	if len(evs) != 1 {
		return provider.Event{}, fmt.Errorf("%d events, want 1", len(evs))
	}
	return evs[0], nil
}

// eventTime is the fixed clock of appleEnv.
var eventTime = time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)

func newAppleEvents(t testing.TB, audiences ...string) (*provider.Apple, *mockidp.Server) {
	t.Helper()
	env, srv := appleEnv(t)
	// The mock answers on loopback at once. A short timeout would let a fetch of
	// the keys fail under load, which is ErrUnavailable and not a refusal.
	env.Timeout = 5 * time.Second
	p, _ := newApple(t, env, func(o *provider.AppleOptions) { o.NotificationAudiences = audiences })
	return p, srv
}

// eventClaims are the claims of a valid notification, to be changed by a test.
func eventClaims(srv *mockidp.Server, events string) map[string]any {
	now := eventTime
	return map[string]any{
		"iss": provider.AppleIssuer, "aud": srv.ClientID(), "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
		"jti": "j1", "events": events,
	}
}

const consentEvent = `{"type":"consent-revoked","sub":"001.abc","event_time":1}`

// Covers: FR-31, SEC-22
// Acceptance: Apple events (part)
func TestAppleParseEventTypes(t *testing.T) {
	p, srv := newAppleEvents(t)
	for _, typ := range []string{"consent-revoked", "account-delete", "email-disabled", "email-enabled", "something-new"} {
		t.Run(typ, func(t *testing.T) {
			claims := eventClaims(srv, `{"type":"`+typ+`","sub":"001.abc"}`)
			ev, err := one(p.ParseEvent(context.Background(), []byte(srv.SignedClaims(claims))))
			if err != nil {
				t.Fatal(err)
			}
			want := provider.Event{Type: typ, Subject: "001.abc", ID: "j1", Expires: eventTime.Add(time.Hour)}
			if ev.Type != want.Type || ev.Subject != want.Subject || ev.ID != want.ID || !ev.Expires.Equal(want.Expires) {
				t.Errorf("event = %+v, want %+v", ev, want)
			}
		})
	}
}

// Covers: FR-31, SEC-22
// Acceptance: Apple events (part)
func TestAppleParseEventAudience(t *testing.T) {
	p, srv := newAppleEvents(t, "com.example.app")
	body := func(aud any) []byte {
		c := eventClaims(srv, consentEvent)
		c["aud"] = aud
		return []byte(srv.SignedClaims(c))
	}
	for _, c := range []struct {
		name string
		aud  any
		ok   bool
	}{
		{"client id", srv.ClientID(), true},
		{"notification audience", "com.example.app", true},
		{"one of several", []string{"other", "com.example.app"}, true},
		{"another audience", "com.example.other", false},
		{"no audience", nil, false},
		{"empty audience", "", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := one(p.ParseEvent(context.Background(), body(c.aud)))
			if (err == nil) != c.ok {
				t.Fatalf("err = %v, want ok=%v", err, c.ok)
			}
			if err != nil && !errors.Is(err, provider.ErrInvalidEvent) {
				t.Errorf("err = %v, want ErrInvalidEvent", err)
			}
		})
	}
}

// Covers: FR-31, SEC-22
// Acceptance: Apple events (part)
func TestAppleParseEventRejects(t *testing.T) {
	p, srv := newAppleEvents(t)
	valid := srv.SignedEvent(srv.ClientID(), "consent-revoked", "001.abc")
	var env struct{ Payload string }
	if err := json.Unmarshal([]byte(valid), &env); err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(env.Payload, ".")
	other := mockidp.New(t, clock.NewFake(eventTime), mockidp.Apple) // another key set
	with := func(mod func(map[string]any)) string {
		c := eventClaims(srv, consentEvent)
		mod(c)
		return srv.SignedClaims(c)
	}
	cases := []struct{ name, body string }{
		{"not JSON", `not json`},
		{"no payload", `{}`},
		{"empty payload", `{"payload":""}`},
		{"payload not a string", `{"payload":5}`},
		{"payload not a JWT", `{"payload":"abc"}`},
		{"altered signature", `{"payload":"` + parts[0] + "." + parts[1] + "." + parts[2][:len(parts[2])-4] + `AAAA"}`},
		{"altered claims", `{"payload":"` + parts[0] + "." + parts[1] + "A." + parts[2] + `"}`},
		{"signed by another key", other.SignedClaims(eventClaims(srv, consentEvent))},
		{"wrong issuer", with(func(c map[string]any) { c["iss"] = "https://evil.example" })},
		{"expired", with(func(c map[string]any) { c["exp"] = time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC).Unix() })},
		{"no expiry, issued 25 hours ago", with(func(c map[string]any) {
			delete(c, "exp")
			c["iat"] = eventTime.Add(-25 * time.Hour).Unix()
		})},
		{"no events", with(func(c map[string]any) { delete(c, "events") })},
		{"events not JSON", with(func(c map[string]any) { c["events"] = "{" })},
		{"events not a string", with(func(c map[string]any) { c["events"] = 7 })},
		{"type not a string", with(func(c map[string]any) { c["events"] = `{"type":1,"sub":"x"}` })},
		{"sub not a string", with(func(c map[string]any) { c["events"] = `{"type":"consent-revoked","sub":1}` })},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := one(p.ParseEvent(context.Background(), []byte(c.body)))
			if !errors.Is(err, provider.ErrInvalidEvent) {
				t.Fatalf("err = %v, want ErrInvalidEvent", err)
			}
		})
	}
}

// Covers: FR-31, SEC-22
// Acceptance: Apple events (part)
func TestAppleParseEventUnknownSubjectOrTypeIsParsed(t *testing.T) {
	p, srv := newAppleEvents(t)
	for _, events := range []string{`{"type":"consent-revoked"}`, `{"sub":"x"}`, `{}`} {
		c := eventClaims(srv, events)
		if _, err := one(p.ParseEvent(context.Background(), []byte(srv.SignedClaims(c)))); err != nil {
			t.Errorf("%s: %v", events, err)
		}
	}
}

// FuzzAppleEventPayload feeds ParseEvent arbitrary bodies. It never panics and
// fails closed: every body it accepts carries a signature of Apple's keys, so a
// mutated seed is accepted only when it still verifies, and every refusal is
// ErrInvalidEvent.
func FuzzAppleEventPayload(f *testing.F) {
	p, srv := newAppleEvents(f)
	valid := srv.SignedEvent(srv.ClientID(), "consent-revoked", "001.abc")
	// Fetch the keys once, so that a seed never needs the network in a worker.
	if _, err := one(p.ParseEvent(context.Background(), []byte(valid))); err != nil {
		f.Fatal(err)
	}
	f.Add([]byte(valid))
	f.Add([]byte(srv.SignedClaims(eventClaims(srv, `{"type":"x"}`))))
	objectEvents := eventClaims(srv, "")
	objectEvents["events"] = map[string]any{"type": "account-deleted", "sub": "001.abc"}
	f.Add([]byte(srv.SignedClaims(objectEvents)))
	stringEvents := eventClaims(srv, `{"type":"account-delete","sub":"001.abc"}`)
	delete(stringEvents, "jti")
	f.Add([]byte(srv.SignedClaims(stringEvents)))
	f.Add([]byte(`{"payload":"a.b.c"}`))
	f.Add([]byte(`{"payload":null}`))
	f.Add([]byte(`[]`))
	f.Add([]byte(``))
	f.Fuzz(func(t *testing.T, body []byte) {
		ev, err := one(p.ParseEvent(context.Background(), body))
		if err != nil {
			if !errors.Is(err, provider.ErrInvalidEvent) {
				t.Fatalf("err = %v, want ErrInvalidEvent", err)
			}
			return
		}
		var env struct{ Payload string }
		if json.Unmarshal(body, &env) != nil || strings.Count(env.Payload, ".") != 2 {
			t.Fatalf("accepted %q as %+v", body, ev)
		}
	})
}

// Covers: FR-31, SEC-22, SEC-27
// Acceptance: Apple event formats (part)
func TestAppleParseEventFormats(t *testing.T) {
	p, srv := newAppleEvents(t)
	object := map[string]any{"type": "account-deleted", "sub": "001.abc"}
	for _, c := range []struct {
		name, typ string
		events    any
	}{
		{"string, account-delete", "account-delete", `{"type":"account-delete","sub":"001.abc"}`},
		{"string, account-deleted", "account-deleted", `{"type":"account-deleted","sub":"001.abc"}`},
		{"object, account-deleted", "account-deleted", object},
		{"object, account-delete", "account-delete", map[string]any{"type": "account-delete", "sub": "001.abc"}},
		{"object, consent-revoked", "consent-revoked", map[string]any{"type": "consent-revoked", "sub": "001.abc"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			claims := eventClaims(srv, "")
			claims["events"] = c.events
			ev, err := one(p.ParseEvent(context.Background(), []byte(srv.SignedClaims(claims))))
			if err != nil {
				t.Fatal(err)
			}
			if ev.Type != c.typ || ev.Subject != "001.abc" {
				t.Errorf("event = %+v, want type %q and subject 001.abc", ev, c.typ)
			}
		})
	}
	// A claim that holds no event is refused, as an object or in a string.
	for _, c := range []struct {
		name   string
		events any
	}{
		{"null", nil},
		{"string null", "null"},
		{"empty string", ""},
		{"string array", "[]"},
		{"number", 7},
		{"string with a non-string sub", `{"type":"account-deleted","sub":5}`},
	} {
		t.Run("refused: "+c.name, func(t *testing.T) {
			claims := eventClaims(srv, "")
			claims["events"] = c.events
			_, err := one(p.ParseEvent(context.Background(), []byte(srv.SignedClaims(claims))))
			if !errors.Is(err, provider.ErrInvalidEvent) {
				t.Fatalf("err = %v, want ErrInvalidEvent", err)
			}
		})
	}
}

// Covers: FR-31, SEC-22, SEC-27
// Acceptance: Apple event formats (part)
func TestAppleParseEventWithoutExpiry(t *testing.T) {
	p, srv := newAppleEvents(t)
	now := eventTime
	for _, c := range []struct {
		name string
		iat  any // nil removes the claim
		ok   bool
		// expires is the time the id is remembered until, for an accepted payload.
		expires time.Time
	}{
		{"issued an hour ago", now.Add(-time.Hour).Unix(), true, now.Add(24 * time.Hour)},
		{"issued 24 hours ago", now.Add(-24 * time.Hour).Unix(), true, now.Add(24 * time.Hour)},
		{"issued 25 hours ago", now.Add(-25 * time.Hour).Unix(), false, time.Time{}},
		{"issued 5 minutes ahead", now.Add(5 * time.Minute).Unix(), true, now.Add(5*time.Minute + 24*time.Hour)},
		{"issued 6 minutes ahead", now.Add(6 * time.Minute).Unix(), false, time.Time{}},
		{"no issue time", nil, false, time.Time{}},
	} {
		t.Run(c.name, func(t *testing.T) {
			claims := eventClaims(srv, consentEvent)
			delete(claims, "exp")
			if c.iat == nil {
				delete(claims, "iat")
			} else {
				claims["iat"] = c.iat
			}
			ev, err := one(p.ParseEvent(context.Background(), []byte(srv.SignedClaims(claims))))
			if (err == nil) != c.ok {
				t.Fatalf("err = %v, want ok=%v", err, c.ok)
			}
			if err != nil {
				if !errors.Is(err, provider.ErrInvalidEvent) {
					t.Fatalf("err = %v, want ErrInvalidEvent", err)
				}
				return
			}
			if !ev.Expires.Equal(c.expires) {
				t.Errorf("Expires = %v, want %v", ev.Expires, c.expires)
			}
		})
	}
}

// Covers: SEC-27 (part)
// Acceptance: Event replay (part)
func TestAppleParseEventIDAndExpiry(t *testing.T) {
	p, srv := newAppleEvents(t)
	ctx := context.Background()

	t.Run("jti and exp", func(t *testing.T) {
		claims := eventClaims(srv, consentEvent)
		ev, err := one(p.ParseEvent(ctx, []byte(srv.SignedClaims(claims))))
		if err != nil {
			t.Fatal(err)
		}
		if ev.ID != "j1" || !ev.Expires.Equal(eventTime.Add(time.Hour)) {
			t.Errorf("ID %q, Expires %v; want j1 and the exp", ev.ID, ev.Expires)
		}
	})

	t.Run("no jti: the payload is the id", func(t *testing.T) {
		claims := eventClaims(srv, consentEvent)
		delete(claims, "jti")
		body := srv.SignedClaims(claims)
		ev, err := one(p.ParseEvent(ctx, []byte(body)))
		if err != nil {
			t.Fatal(err)
		}
		var env struct{ Payload string }
		if err := json.Unmarshal([]byte(body), &env); err != nil {
			t.Fatal(err)
		}
		if ev.ID != env.Payload {
			t.Errorf("ID is not the signed payload")
		}
	})

	t.Run("an empty jti counts as none", func(t *testing.T) {
		claims := eventClaims(srv, consentEvent)
		claims["jti"] = ""
		body := srv.SignedClaims(claims)
		ev, err := one(p.ParseEvent(ctx, []byte(body)))
		if err != nil {
			t.Fatal(err)
		}
		var env struct{ Payload string }
		_ = json.Unmarshal([]byte(body), &env)
		if ev.ID != env.Payload {
			t.Errorf("ID is not the signed payload")
		}
	})

	t.Run("a non-string jti is refused", func(t *testing.T) {
		claims := eventClaims(srv, consentEvent)
		claims["jti"] = 5
		_, err := one(p.ParseEvent(ctx, []byte(srv.SignedClaims(claims))))
		if !errors.Is(err, provider.ErrInvalidEvent) {
			t.Fatalf("err = %v, want ErrInvalidEvent", err)
		}
	})

	t.Run("an expiry that is now is refused (RFC 7519 4.1.4)", func(t *testing.T) {
		claims := eventClaims(srv, consentEvent)
		claims["exp"] = eventTime.Unix()
		_, err := one(p.ParseEvent(ctx, []byte(srv.SignedClaims(claims))))
		if !errors.Is(err, provider.ErrInvalidEvent) {
			t.Fatalf("err = %v, want ErrInvalidEvent", err)
		}
	})
	t.Run("an expiry one second ahead is accepted", func(t *testing.T) {
		claims := eventClaims(srv, consentEvent)
		claims["exp"] = eventTime.Add(time.Second).Unix()
		ev, err := one(p.ParseEvent(ctx, []byte(srv.SignedClaims(claims))))
		if err != nil {
			t.Fatal(err)
		}
		if !ev.Expires.Equal(eventTime.Add(time.Second)) {
			t.Errorf("Expires = %v", ev.Expires)
		}
	})
	t.Run("an expiry that has passed is refused", func(t *testing.T) {
		claims := eventClaims(srv, consentEvent)
		claims["exp"] = eventTime.Add(-time.Second).Unix()
		_, err := one(p.ParseEvent(ctx, []byte(srv.SignedClaims(claims))))
		if !errors.Is(err, provider.ErrInvalidEvent) {
			t.Fatalf("err = %v, want ErrInvalidEvent", err)
		}
	})
}

// Covers: FR-31, SEC-22
// Acceptance: Apple event formats (part)
func TestAppleParseEventKeysUnavailable(t *testing.T) {
	p, srv := newAppleEvents(t)
	body := []byte(srv.SignedEvent(srv.ClientID(), "consent-revoked", "001.abc"))
	srv.FailJWKS(100) // no key is cached yet, and the key endpoint answers 500
	_, err := one(p.ParseEvent(context.Background(), body))
	if !errors.Is(err, provider.ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
	if errors.Is(err, provider.ErrInvalidEvent) {
		t.Errorf("keys that cannot be fetched are also reported as an invalid event")
	}
	srv.FailJWKS(0)
	if _, err := one(p.ParseEvent(context.Background(), body)); err != nil {
		t.Fatalf("after the keys are back: %v", err)
	}
}

// Covers: FR-31, SEC-22, SEC-27
// Acceptance: Apple event formats (part)
func TestAppleParseEventFractionalTimes(t *testing.T) {
	p, srv := newAppleEvents(t)
	ctx := context.Background()
	t.Run("fractional exp", func(t *testing.T) {
		claims := eventClaims(srv, consentEvent)
		claims["exp"] = float64(eventTime.Add(time.Hour).Unix()) + 0.5 // NumericDate may be fractional
		ev, err := one(p.ParseEvent(ctx, []byte(srv.SignedClaims(claims))))
		if err != nil {
			t.Fatalf("err = %v, want the payload accepted", err)
		}
		if !ev.Expires.Equal(eventTime.Add(time.Hour)) {
			t.Errorf("Expires = %v, want the whole second of exp", ev.Expires)
		}
	})
	t.Run("fractional iat without exp", func(t *testing.T) {
		claims := eventClaims(srv, consentEvent)
		delete(claims, "exp")
		claims["iat"] = float64(eventTime.Unix()) - 0.5
		ev, err := one(p.ParseEvent(ctx, []byte(srv.SignedClaims(claims))))
		if err != nil {
			t.Fatalf("err = %v, want the payload accepted", err)
		}
		if !ev.Expires.Equal(eventTime.Add(24 * time.Hour)) {
			t.Errorf("Expires = %v, want 24 hours after the receipt", ev.Expires)
		}
	})
}

// Covers: FR-31, SEC-22, SEC-27
// Acceptance: Apple event formats (part)
func TestAppleParseEventKeyOutageIsNeverAnInvalidEvent(t *testing.T) {
	p, srv := newAppleEvents(t)
	body := []byte(srv.SignedEvent(srv.ClientID(), "consent-revoked", "001.abc"))
	// Several callers verify the same valid event while the key endpoint fails
	// for the first fetches. Each one gets the outage (ErrUnavailable) or, when
	// its keys arrive, the event: never ErrInvalidEvent, which would make Apple
	// drop the event for good (the per-call key fetch error, SEC-27).
	srv.FailJWKS(2)
	srv.Block()
	const callers = 8
	results := make(chan error, callers)
	for range callers {
		go func() {
			_, err := one(p.ParseEvent(context.Background(), body))
			results <- err
		}()
	}
	<-srv.Blocked() // a fetch of the keys has reached the endpoint
	srv.Unblock()
	for range callers {
		err := <-results
		if errors.Is(err, provider.ErrInvalidEvent) {
			t.Errorf("a valid event during a key outage is an invalid event: %v", err)
		} else if err != nil && !errors.Is(err, provider.ErrUnavailable) {
			t.Errorf("err = %v, want nil or ErrUnavailable", err)
		}
	}
	if _, err := one(p.ParseEvent(context.Background(), body)); err != nil {
		t.Fatalf("after the outage: %v", err)
	}
}

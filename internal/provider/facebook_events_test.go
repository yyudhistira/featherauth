package provider_test

import (
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/provider"
	"github.com/yyudhistira/featherauth/internal/testutil/mockidp"
)

var (
	_ provider.EventReceiver  = (*provider.Facebook)(nil)
	_ provider.EventConfirmer = (*provider.Facebook)(nil)
)

// metaForm is the body Meta posts for a signed_request.
func metaForm(sr string) []byte { return []byte(url.Values{"signed_request": {sr}}.Encode()) }

func metaPayload(now time.Time, mod func(m map[string]any)) map[string]any {
	m := map[string]any{"algorithm": "HMAC-SHA256", "issued_at": now.Unix(), "user_id": "10001"}
	if mod != nil {
		mod(m)
	}
	return m
}

// Covers: FR-40, SEC-33
// Acceptance: Meta deletion callback (part)
func TestFacebookParseEventAcceptsASignedRequest(t *testing.T) {
	env, srv := facebookEnv(t, annFacebook)
	p := newFacebook(t, env, nil)
	secret, now := srv.ClientSecret(), env.Clock.Now()
	payload := metaPayload(now, nil)
	sr := mockidp.SignedRequest(secret, payload)
	part := strings.SplitN(sr, ".", 2)[1]

	ev, err := one(p.ParseEvent(t.Context(), metaForm(sr)))
	if err != nil {
		t.Fatal(err)
	}
	if ev.Type != "account-delete" || ev.Subject != "10001" || ev.ID != part || !ev.Expires.Equal(now.Add(time.Hour)) {
		t.Errorf("event %+v, want account-delete of 10001, id the payload part, expiry an hour on", ev)
	}
	if !p.ConfirmsEvents() {
		t.Error("the adapter does not ask for a confirmation answer")
	}

	t.Run("a signature with padding is the same request", func(t *testing.T) {
		sig, _, _ := strings.Cut(sr, ".")
		padded := sig + "=" // 32 bytes encode to 43 characters and one padding character
		ev2, err := one(p.ParseEvent(t.Context(), metaForm(padded+"."+part)))
		if err != nil || ev2.ID != ev.ID {
			t.Errorf("padded signature: %+v, %v", ev2, err)
		}
	})
	t.Run("a payload part with padding is used as received", func(t *testing.T) {
		padded := part
		for len(padded)%4 != 0 {
			padded += "="
		}
		if padded == part {
			t.Skip("the payload needs no padding")
		}
		ev2, err := one(p.ParseEvent(t.Context(), metaForm(mockidp.SignedPart(secret, padded))))
		if err != nil || ev2.ID != padded {
			t.Errorf("padded payload: %+v, %v", ev2, err)
		}
	})
	t.Run("the boundaries of issued_at are accepted", func(t *testing.T) {
		for name, issued := range map[string]time.Time{
			"exactly an hour old":          now.Add(-time.Hour),
			"exactly five minutes ahead":   now.Add(5 * time.Minute),
			"just now":                     now,
			"half an hour old":             now.Add(-30 * time.Minute),
			"a second under the old limit": now.Add(-time.Hour + time.Second),
		} {
			ev, err := one(p.ParseEvent(t.Context(), metaForm(mockidp.SignedRequest(secret, metaPayload(issued, nil)))))
			if err != nil {
				t.Errorf("%s: %v", name, err)
				continue
			}
			// Remembered until an hour after the later of issued_at and now.
			want := now.Add(time.Hour)
			if issued.After(now) {
				want = issued.Add(time.Hour)
			}
			if !ev.Expires.Equal(want) {
				t.Errorf("%s: expires %v, want %v", name, ev.Expires, want)
			}
		}
	})
	t.Run("a fractional issued_at counts by its whole seconds", func(t *testing.T) {
		pl := metaPayload(now, func(m map[string]any) { m["issued_at"] = float64(now.Unix()) + 0.5 })
		if _, err := one(p.ParseEvent(t.Context(), metaForm(mockidp.SignedRequest(secret, pl)))); err != nil {
			t.Error(err)
		}
	})
	t.Run("the clock decides: later the same request is too old", func(t *testing.T) {
		env.Clock.(*clock.Fake).Advance(time.Hour + time.Second)
		if _, err := one(p.ParseEvent(t.Context(), metaForm(sr))); !errors.Is(err, provider.ErrInvalidEvent) {
			t.Errorf("err = %v, want ErrInvalidEvent", err)
		}
	})
}

// Covers: FR-40, SEC-33
// Acceptance: Meta deletion callback (part)
func TestFacebookParseEventRefuses(t *testing.T) {
	env, srv := facebookEnv(t, annFacebook)
	p := newFacebook(t, env, nil)
	secret, now := srv.ClientSecret(), env.Clock.Now()
	good := mockidp.SignedRequest(secret, metaPayload(now, nil))
	sig, part, _ := strings.Cut(good, ".")
	enc := base64.RawURLEncoding.EncodeToString
	signed := func(mod func(m map[string]any)) []byte {
		return metaForm(mockidp.SignedRequest(secret, metaPayload(now, mod)))
	}
	other := mockidp.SignedRequest(secret, metaPayload(now, func(m map[string]any) { m["user_id"] = "99999" }))
	otherPart := strings.SplitN(other, ".", 2)[1]

	rows := []struct {
		name string
		body []byte
	}{
		{"an empty body", nil},
		{"no signed_request", []byte("other=1")},
		{"an empty signed_request", []byte("signed_request=")},
		{"two signed_requests", []byte("signed_request=" + url.QueryEscape(good) + "&signed_request=" + url.QueryEscape(good))},
		{"a body that is not a form", []byte("signed_request=%zz")},
		{"a JSON body", []byte(`{"signed_request":"` + good + `"}`)},
		{"one part", metaForm(part)},
		{"three parts", metaForm(good + ".x")},
		{"an empty signature part", metaForm("." + part)},
		{"an empty payload part", metaForm(sig + ".")},
		{"a signature that is not base64url", metaForm("!!!." + part)},
		{"a line feed in the signature", metaForm(sig[:10] + "\n" + sig[10:] + "." + part)},
		{"a carriage return in the payload part", metaForm(mockidp.SignedPart(secret, part[:10]+"\r"+part[10:]))},
		{"a signature whose unused bits are set", metaForm(sig[:len(sig)-1] + "d." + part)}, // the last of 43 characters holds 4 bits of 6
		{"a payload that is not base64url", metaForm(mockidp.SignedPart(secret, "!!!"))},
		{"a signature of another payload", metaForm(sig + "." + otherPart)},
		{"a truncated signature", metaForm(sig[:len(sig)-2] + "." + part)},
		{"a signature of another secret", metaForm(mockidp.SignedRequest("another-secret", metaPayload(now, nil)))},
		{"a character of the standard base64 alphabet in the signature", metaForm("+" + sig[1:] + "." + part)},
		{"a payload that is not JSON", metaForm(mockidp.SignedPart(secret, enc([]byte("not json"))))},
		{"a payload that is a JSON array", metaForm(mockidp.SignedPart(secret, enc([]byte("[1]"))))},
		{"a payload that is null", metaForm(mockidp.SignedPart(secret, enc([]byte("null"))))},
		{"another algorithm", signed(func(m map[string]any) { m["algorithm"] = "HMAC-SHA1" })},
		{"a lower case algorithm", signed(func(m map[string]any) { m["algorithm"] = "hmac-sha256" })},
		{"no algorithm", signed(func(m map[string]any) { delete(m, "algorithm") })},
		{"an algorithm that is not a string", signed(func(m map[string]any) { m["algorithm"] = 1 })},
		{"issued two hours ago", signed(func(m map[string]any) { m["issued_at"] = now.Add(-2 * time.Hour).Unix() })},
		{"issued an hour and a second ago", signed(func(m map[string]any) { m["issued_at"] = now.Add(-time.Hour - time.Second).Unix() })},
		{"issued five minutes and a second ahead", signed(func(m map[string]any) { m["issued_at"] = now.Add(5*time.Minute + time.Second).Unix() })},
		{"no issued_at", signed(func(m map[string]any) { delete(m, "issued_at") })},
		{"an issued_at that is a string", signed(func(m map[string]any) { m["issued_at"] = "1" })},
		{"an issued_at that is null", signed(func(m map[string]any) { m["issued_at"] = nil })},
		{"no user_id", signed(func(m map[string]any) { delete(m, "user_id") })},
		{"an empty user_id", signed(func(m map[string]any) { m["user_id"] = "" })},
		{"a user_id that is a number", signed(func(m map[string]any) { m["user_id"] = 10001 })},
		{"a user_id that is null", signed(func(m map[string]any) { m["user_id"] = nil })},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			ev, err := one(p.ParseEvent(t.Context(), row.body))
			if !errors.Is(err, provider.ErrInvalidEvent) {
				t.Fatalf("event %+v, err %v, want ErrInvalidEvent", ev, err)
			}
			// The error names no part of the request and no secret (SEC-13).
			for _, leak := range []string{secret, sig, part, "10001"} {
				if leak != "" && strings.Contains(err.Error(), leak) {
					t.Errorf("the error %q holds %q", err, leak)
				}
			}
		})
	}
}

// Covers: SEC-33 (part)
func FuzzFacebookParseEvent(f *testing.F) {
	const secret = "fuzz-secret"
	now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	good := mockidp.SignedRequest(secret, metaPayload(now, nil))
	for _, seed := range []string{
		"", "signed_request=", "signed_request=a.b", "signed_request=" + url.QueryEscape(good), "signed_request=" + url.QueryEscape(good+"="),
		"signed_request=" + url.QueryEscape(good) + "&signed_request=x", "signed_request=%zz", "signed_request=....",
		"signed_request=" + url.QueryEscape(mockidp.SignedRequest(secret, map[string]any{"algorithm": "none"})),
		"signed_request=" + url.QueryEscape(mockidp.SignedPart(secret, "bnVsbA")),
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		env, _ := facebookEnv(t, annFacebook)
		p := newFacebook(t, env, func(o *provider.FacebookOptions) { o.ClientSecret = secret })
		ev, err := one(p.ParseEvent(t.Context(), body))
		if err != nil {
			if !errors.Is(err, provider.ErrInvalidEvent) {
				t.Fatalf("err %v is not ErrInvalidEvent", err)
			}
			return
		}
		// An accepted body carries a signature over its payload part.
		form, perr := url.ParseQuery(string(body))
		if perr != nil || len(form["signed_request"]) != 1 {
			t.Fatalf("accepted %q that is not one signed_request", body)
		}
		sig, part, _ := strings.Cut(form.Get("signed_request"), ".")
		want, _, _ := strings.Cut(mockidp.SignedPart(secret, part), ".")
		if strings.TrimRight(sig, "=") != want || ev.ID != part || ev.Subject == "" || ev.Type != "account-delete" {
			t.Fatalf("accepted %q as %+v", body, ev)
		}
	})
}

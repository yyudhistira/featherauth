//go:build postgres

package main

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/yyudhistira/featherauth/internal/testutil/server"
)

// cookieHeader returns the Cookie header that sends back the cookies a response set.
func cookieHeader(hdr http.Header) string {
	var parts []string
	for _, line := range hdr.Values("Set-Cookie") {
		parts = append(parts, strings.SplitN(line, ";", 2)[0])
	}
	return strings.Join(parts, "; ")
}

// A login started on one instance finishes on the other: the authorize request
// goes to instance a, the provider's callback to instance b, with the cookie of
// a's answer. The login row is in the shared database, so b finds it and answers
// with the client's redirect (a provider's error here, as the mock is not used).
//
// Covers: FR-54 (part)
// Acceptance: Several instances (part)
func TestLoginStartedOnOneInstanceFinishesOnTheOther(t *testing.T) {
	a, b, _, _ := startTwoInstances(t)

	q := server.Authorize(server.ClientQuery, "corp")
	code, hdr, _ := a.do(http.MethodGet, "/main/authorize?"+q.Encode(), nil)
	if code != http.StatusFound {
		t.Fatalf("authorize on instance a answered %d", code)
	}
	loc, err := url.Parse(hdr.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	state := loc.Query().Get("state")
	if state == "" {
		t.Fatalf("the provider redirect carries no state: %s", hdr.Get("Location"))
	}
	cookies := cookieHeader(hdr)
	if cookies == "" {
		t.Fatal("authorize set no cookie")
	}

	callback := "/main/callback/corp?" + url.Values{"state": {state}, "error": {"access_denied"}}.Encode()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, b.url(callback), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Cookie", cookies)
	resp, err := b.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("callback on instance b answered %d, want the client's redirect", resp.StatusCode)
	}
	back := resp.Header.Get("Location")
	if !strings.HasPrefix(back, "https://app.example.com/callback") || !strings.Contains(back, "error=access_denied") {
		t.Fatalf("instance b did not finish the login started on a: %s", back)
	}
}

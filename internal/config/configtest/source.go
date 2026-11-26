// Package configtest holds the contract suite every config.Source must pass.
package configtest

import (
	"strings"
	"sync"
	"testing"

	"github.com/yyudhistira/featherauth/internal/config"
)

// mustCurrent returns the current snapshot and stops the test when there is
// none, so a broken source fails cleanly instead of panicking later.
func mustCurrent(t *testing.T, src config.Source) *config.Snapshot {
	t.Helper()
	s := src.Current()
	if s == nil {
		t.Fatal("Current() returned nil")
	}
	return s
}

// RunSource runs the Source contract. newSource returns a source whose
// snapshot has at least one realm, and where that realm has at least one
// client, and which no one changes while the suite runs.
func RunSource(t *testing.T, newSource func(t *testing.T) config.Source) {
	t.Helper()

	t.Run("current is never nil", func(t *testing.T) {
		mustCurrent(t, newSource(t))
	})

	t.Run("current is stable without changes", func(t *testing.T) {
		src := newSource(t)
		if a, b := mustCurrent(t, src), mustCurrent(t, src); a != b {
			t.Error("two calls without a change returned different snapshots")
		}
	})

	t.Run("realms are consistent with lookup", func(t *testing.T) {
		s := mustCurrent(t, newSource(t))
		realms := s.Realms()
		if len(realms) == 0 {
			t.Fatal("snapshot has no realm")
		}
		for i, r := range realms {
			got, ok := s.Realm(r.Name)
			if !ok || got != r {
				t.Errorf("Realm(%q) does not return the realm listed at %d", r.Name, i)
			}
			if i > 0 && realms[i-1].Name >= r.Name {
				t.Errorf("Realms not sorted by name: %q before %q", realms[i-1].Name, r.Name)
			}
		}
	})

	t.Run("issuer has no trailing slash and starts with public_url", func(t *testing.T) {
		s := mustCurrent(t, newSource(t))
		for _, r := range s.Realms() {
			iss := r.Issuer()
			if strings.HasSuffix(iss, "/") {
				t.Errorf("issuer %q ends with /", iss)
			}
			if !strings.HasPrefix(iss, s.Server().PublicURL+"/") {
				t.Errorf("issuer %q does not start with public_url %q", iss, s.Server().PublicURL)
			}
		}
	})

	t.Run("snapshot returns copies of its slices", func(t *testing.T) {
		s := mustCurrent(t, newSource(t))
		for _, r := range s.Realms() {
			for id, c := range r.Clients {
				if u := c.PostLogoutURIs(); len(u) > 0 {
					want := u[0]
					u[0] = "https://mutated.invalid/"
					if got := c.PostLogoutURIs()[0]; got != want {
						t.Errorf("client %s: mutating PostLogoutURIs changed it to %q", id, got)
					}
				}
			}
		}
		if p := s.Server().TrustedProxies; len(p) > 0 {
			want := p[0]
			p[0] = "mutated"
			if got := s.Server().TrustedProxies[0]; got != want {
				t.Errorf("mutating Server().TrustedProxies changed it to %q", got)
			}
		}
	})

	t.Run("concurrent readers", func(t *testing.T) {
		src := newSource(t)
		names := func(s *config.Snapshot) string {
			var b strings.Builder
			for _, r := range s.Realms() {
				b.WriteString(string(r.Name) + "|" + r.Issuer() + ";")
			}
			return b.String()
		}
		want := names(mustCurrent(t, src))
		var wg sync.WaitGroup
		errs := make(chan string, 8)
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for range 100 {
					s := src.Current()
					if s == nil {
						errs <- "Current() returned nil"
						return
					}
					if got := names(s); got != want {
						errs <- "realms changed between calls: " + got + " vs " + want
						return
					}
				}
			}()
		}
		wg.Wait()
		close(errs)
		for e := range errs {
			t.Error(e)
		}
	})
}

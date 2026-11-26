package providertest

import (
	"context"
	"net/http"
	"testing"
	"time"
)

// recorder is a testing.TB that counts failures instead of failing.
type recorder struct {
	testing.TB
	errors   int
	cleanups []func()
}

func (r *recorder) Errorf(string, ...any) { r.errors++ }
func (r *recorder) Helper()               {}
func (r *recorder) Cleanup(fn func())     { r.cleanups = append(r.cleanups, fn) }

// Covers: SEC-03 (part)
// Acceptance: Provider adapters (part)
func TestGuardCatchesTheDefaultClient(t *testing.T) {
	orig := http.DefaultTransport
	rec := &recorder{TB: t}
	guardDefaultTransport(rec)

	// A call through http.DefaultClient, as go-oidc or x/oauth2 make without a
	// client in the context, must reach the failing transport.
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://127.0.0.1:1/jwks", nil)
	if err != nil {
		t.Fatal(err)
	}
	// A client without a transport falls back to http.DefaultTransport, as
	// http.DefaultClient does.
	resp, err := (&http.Client{Timeout: time.Second}).Do(req)
	if err == nil {
		resp.Body.Close()
		t.Error("the default client made a request")
	}
	if rec.errors != 1 {
		t.Errorf("the guard recorded %d failures, want 1", rec.errors)
	}

	for _, fn := range rec.cleanups {
		fn()
	}
	if http.DefaultTransport != orig {
		t.Error("http.DefaultTransport is not restored")
	}
}

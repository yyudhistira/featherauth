package server_test

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/yyudhistira/featherauth/internal/server"
)

func prefixes(t *testing.T, cidrs ...string) []netip.Prefix {
	t.Helper()
	var out []netip.Prefix
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, p)
	}
	return out
}

// Covers: SEC-11 (part)
// Acceptance: Client IP (part)
func TestClientIP(t *testing.T) {
	tests := []struct {
		name    string
		remote  string
		xff     []string
		trusted []string
		want    string
	}{
		{"no header", "192.0.2.10:4000", nil, nil, "192.0.2.10"},
		{"forged header from an untrusted address is ignored", "192.0.2.10:4000", []string{"203.0.113.5"}, []string{"127.0.0.1/32"}, "192.0.2.10"},
		{"forged header with no trusted proxies is ignored", "127.0.0.1:4000", []string{"203.0.113.5"}, nil, "127.0.0.1"},
		{"trusted proxy, one entry", "127.0.0.1:4000", []string{"198.51.100.7"}, []string{"127.0.0.1/32"}, "198.51.100.7"},
		{"forged first entry through a trusted proxy is ignored", "127.0.0.1:4000", []string{"6.6.6.6, 198.51.100.7"}, []string{"127.0.0.1/32"}, "198.51.100.7"},
		{"trusted entries on the right are skipped", "10.0.0.1:4000", []string{"6.6.6.6, 198.51.100.7, 10.0.0.2"}, []string{"10.0.0.0/8"}, "198.51.100.7"},
		{"several header lines are read as one list", "127.0.0.1:4000", []string{"6.6.6.6", "198.51.100.7"}, []string{"127.0.0.1/32"}, "198.51.100.7"},
		{"spaces around entries", "127.0.0.1:4000", []string{" 6.6.6.6 ,  198.51.100.7 "}, []string{"127.0.0.1/32"}, "198.51.100.7"},
		{"every entry trusted uses the connection", "10.0.0.1:4000", []string{"10.0.0.3, 10.0.0.2"}, []string{"10.0.0.0/8"}, "10.0.0.1"},
		{"an entry that is not an address uses the connection", "127.0.0.1:4000", []string{"6.6.6.6, not-an-ip"}, []string{"127.0.0.1/32"}, "127.0.0.1"},
		{"an empty header uses the connection", "127.0.0.1:4000", []string{""}, []string{"127.0.0.1/32"}, "127.0.0.1"},
		{"IPv6 connection and entry", "[::1]:4000", []string{"2001:db8::7"}, []string{"::1/128"}, "2001:db8::7"},
		{"IPv4-mapped connection matches an IPv4 prefix", "[::ffff:127.0.0.1]:4000", []string{"198.51.100.7"}, []string{"127.0.0.1/32"}, "198.51.100.7"},
		{"IPv4-mapped entry is unmapped", "127.0.0.1:4000", []string{"::ffff:198.51.100.7"}, []string{"127.0.0.1/32"}, "198.51.100.7"},
		{"connection without a port", "192.0.2.10", nil, nil, "192.0.2.10"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = tt.remote
			for _, v := range tt.xff {
				r.Header.Add("X-Forwarded-For", v)
			}
			if got := server.ClientIP(r, prefixes(t, tt.trusted...)); got.String() != tt.want {
				t.Errorf("got %v, want %s", got, tt.want)
			}
		})
	}
}

func TestClientIPOfAnUnparsableConnection(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "@"
	if got := server.ClientIP(r, nil); got.IsValid() {
		t.Errorf("got %v, want the zero address", got)
	}
}

// Covers: SEC-11 (part)
// Acceptance: Client IP (part)
func TestClientIPMiddlewareUsesTheLiveTrustedProxies(t *testing.T) {
	src, dir := newConfigDir(t, "public_url: https://auth.example.com\ntrusted_proxies: [\"127.0.0.1/32\"]\n")
	var got netip.Addr
	h := server.ClientIPMiddleware(src)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got, _ = server.ClientIPFrom(r.Context())
	}))
	serve := func() {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = "127.0.0.1:1"
		r.Header.Set("X-Forwarded-For", "198.51.100.7")
		h.ServeHTTP(httptest.NewRecorder(), r)
	}
	serve()
	if got.String() != "198.51.100.7" {
		t.Fatalf("through a trusted proxy: %v", got)
	}
	dir.Server(t, "public_url: https://auth.example.com\n")
	if res := src.Reload(t.Context()); !res.Applied {
		t.Fatalf("reload: %+v", res)
	}
	serve()
	if got.String() != "127.0.0.1" {
		t.Fatalf("after dropping the proxy from trusted_proxies: %v", got)
	}
}

func TestClientIPFromWithoutTheMiddleware(t *testing.T) {
	if _, ok := server.ClientIPFrom(t.Context()); ok {
		t.Error("an address from nowhere")
	}
}

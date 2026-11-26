//go:build postgres

package main

import (
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/testutil"
	"github.com/yyudhistira/featherauth/internal/testutil/server"
)

// postToken sends one request to the token endpoint of s from the client address
// xff (a forwarded address, which the trusted proxy 127.0.0.1 supplies), or from
// the connection's own address when xff is empty, and returns the status.
func postToken(t *testing.T, s *service, xff string) int {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, s.url("/main/token"), strings.NewReader("grant_type=none"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	resp, err := s.http.Do(req)
	if err != nil {
		t.Fatalf("POST token: %v", err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

// startTwoInstances starts two services on one Postgres database, the first
// after the second has its migrations, as one deploy replaces the other.
func startTwoInstances(t *testing.T) (*service, *service, *testutil.PostgresProxy, *server.Env) {
	t.Helper()
	// rate_limit.store database is set after database.yaml names Postgres: the
	// environment loads its configuration when it is made, which needs SQLite's
	// default driver for the database setting to be valid.
	e := server.New(t, server.WithServerSetting("trusted_proxies: [\"127.0.0.1/32\"]\n"))
	srv := testutil.NewPostgresServer(t)
	pg := srv.NewDatabase(t)
	proxy := testutil.NewPostgresProxy(t, srv.Addr(), nil)
	writeConfig(t, e.ConfigDir(), "secrets/postgres_password", srv.Password+"\n")
	backups := filepath.Join(t.TempDir(), "backups")
	writeConfig(t, e.ConfigDir(), "database.yaml", fmt.Sprintf(`driver: postgres
postgres:
  host: %s
  port: %d
  database: %s
  user: %s
  password_file: secrets/postgres_password
  sslmode: disable
backup:
  directory: %s
  at: "03:00"
  keep: 3
`, srv.Host, proxy.Port(), pg.Database, pg.User, backups))
	editFile(t, filepath.Join(e.ConfigDir(), "server.yaml"), func(y string) string { return y + "rate_limit:\n  store: database\n" })
	a := startServiceIn(t, e, e.ConfigDir(), e.Clock)
	b := startServiceIn(t, e, e.ConfigDir(), e.Clock)
	return a, b, proxy, e
}

// Two instances on one Postgres database share one count per client key and
// minute: 31 requests spread over both are refused on the 31st whichever instance
// serves it, also for the /64 of an IPv6 address; the next minute starts from
// zero; with the count failing, one instance counts its own requests and logs the
// failure once a minute.
//
// The other pass conditions are proven by (part) tests: the hourly job leaves
// only the current window (TestCleanupDeletesTheRateLimitWindowsBeforeTheCurrentMinute
// in internal/store/maintenance_test.go, and the Postgres store contract
// RateLimitsDeleteBefore); config check reports the option on SQLite
// (TestSharedRateLimitNeedsDriverPostgres in internal/config/ratelimit_test.go);
// a hung count is given up after one second (TestHungCountIsGivenUpAfterOneSecond
// in internal/server/ratelimit_shared_test.go). Together with this test they
// cover the row.
//
// Covers: FR-53
// Acceptance: Shared rate limit
func TestSharedRateLimitAcrossTwoInstances(t *testing.T) {
	a, b, proxy, e := startTwoInstances(t)

	// 31 requests from one address, 15 to each instance: the 31st is refused.
	for i := 0; i < 30; i++ {
		s := a
		if i%2 == 1 {
			s = b
		}
		if code := postToken(t, s, "192.0.2.10"); code == http.StatusTooManyRequests {
			t.Fatalf("request %d of 30 refused", i+1)
		}
	}
	if code := postToken(t, a, "192.0.2.10"); code != http.StatusTooManyRequests {
		t.Fatalf("the 31st request to instance a answered %d, want 429", code)
	}
	if code := postToken(t, b, "192.0.2.10"); code != http.StatusTooManyRequests {
		t.Fatalf("the 32nd request to instance b answered %d, want 429", code)
	}

	// Addresses of one /64 share one count; another /64 counts apart.
	for i := 1; i <= 30; i++ {
		s := a
		if i%2 == 0 {
			s = b
		}
		if code := postToken(t, s, fmt.Sprintf("2001:db8:10::%x", i)); code == http.StatusTooManyRequests {
			t.Fatalf("address %d of the /64 refused", i)
		}
	}
	if code := postToken(t, b, "2001:db8:10::ffff"); code != http.StatusTooManyRequests {
		t.Fatalf("the 31st address of the /64 answered %d, want 429", code)
	}
	if code := postToken(t, a, "2001:db8:11::1"); code == http.StatusTooManyRequests {
		t.Fatal("another /64 is refused")
	}

	// The next minute of the service clock starts from zero.
	e.Clock.Advance(time.Minute)
	if code := postToken(t, a, "192.0.2.10"); code == http.StatusTooManyRequests {
		t.Fatal("the next minute did not start from zero")
	}

	// The count fails (the database is unreachable): instance a counts for itself,
	// refuses its 31st request, and logs the failure once.
	proxy.Stop()
	for i := 1; i <= 30; i++ {
		if code := postToken(t, a, "192.0.2.90"); code == http.StatusTooManyRequests {
			t.Fatalf("request %d refused by the own limit", i)
		}
	}
	if code := postToken(t, a, "192.0.2.90"); code != http.StatusTooManyRequests {
		t.Fatalf("the 31st request with the count failing answered %d, want 429", code)
	}
	if n := a.logs.count("rate limit count failed"); n != 1 {
		t.Fatalf("%d failure lines in one minute, want 1", n)
	}
	proxy.Start(t)
}

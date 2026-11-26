package main

import (
	"sort"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"
)

// The fixture module has exactly one violation of each rule, plus allowed
// imports that must not be reported. Files behind build tags (browser,
// load, ops, postgres) are checked too, including a package with only tagged files.
func TestFixtureViolations(t *testing.T) {
	problems, err := check("testdata/mod")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		`internal/clock/rand.go:3: import "crypto/rand" is forbidden here; use internal/secure`,
		`internal/config/config.go:3: config imports token, which is not below it (ranks: config 2, token 4)`,
		`internal/secure/s.go:10: time.Now is forbidden here; use internal/clock`,
		`internal/mystery/m.go:1: unknown component "mystery"; add it to the rank table in tools/archcheck`,
		`internal/oidc/browser_test.go:11: time.Now is forbidden here; use internal/clock`,
		`internal/oidc/oidc_test.go:12: time.Since is forbidden here; use internal/clock`,
		`internal/provider/provider.go:3: provider imports token, which is not below it (ranks: provider 4, token 4)`,
		`internal/provider/redirect.go:8: http.Client in provider needs a CheckRedirect func that refuses redirects (SEC-26)`,
		`internal/provider/redirect.go:14: http.Client in provider needs a CheckRedirect func that refuses redirects (SEC-26)`,
		`internal/store/postgres_test.go:12: time.Now is forbidden here; use internal/clock`,
		`internal/store/postgres_test.go:14: http.Client.Get sends a request without a context; build it with http.NewRequestWithContext and call Do`,
		`internal/store/store.go:3: store imports token, which is not below it (ranks: store 3, token 4)`,
		`internal/token/ctx.go:14: http.Client.Get sends a request without a context; build it with http.NewRequestWithContext and call Do`,
		`internal/token/ctx.go:15: http.Client.Head sends a request without a context; build it with http.NewRequestWithContext and call Do`,
		`internal/token/ctx.go:17: http.Client.Post sends a request without a context; build it with http.NewRequestWithContext and call Do`,
		`internal/token/ctx.go:18: http.Client.PostForm sends a request without a context; build it with http.NewRequestWithContext and call Do`,
		`internal/token/loadonly/ops_test.go:13: http.Client.Get sends a request without a context; build it with http.NewRequestWithContext and call Do`,
		`internal/token/loadonly/l.go:5: import "log" is forbidden; use internal/logx`,
		`internal/token/token.go:14: time.Now is forbidden here; use internal/clock`,
		`internal/token/more.go:6: dot import of "strings" is forbidden; import it by name`,
		`internal/token/zero.go:9: struct field of type http.Client; hold a *http.Client built with a literal that sets Timeout`,
		`internal/token/zero.go:13: struct field of type http.Server; hold a *http.Server built with a literal that sets its timeouts`,
		`internal/token/zero.go:17: var of type http.Client has no Timeout; build it with a literal that sets Timeout`,
		`internal/token/zero.go:20: var of type http.Client has no Timeout; build it with a literal that sets Timeout`,
		`internal/token/zero.go:21: var of type http.Server has no timeouts; build it with a literal that sets them`,
		`internal/token/zero.go:24: http.Client with Timeout 0 (no timeout)`,
		`internal/token/zero.go:25: http.Server with ReadTimeout 0 (no timeout)`,
		`internal/token/more.go:13: slog.Info is forbidden outside internal/logx; use a logger from logx.New`,
		`internal/token/more.go:14: slog.Default is forbidden outside internal/logx; use a logger from logx.New`,
		`internal/token/more.go:15: time.Sleep is forbidden here; use internal/clock`,
		`internal/token/more.go:16: time.After is forbidden here; use internal/clock`,
		`internal/token/more.go:17: http.NewRequest is forbidden; use http.NewRequestWithContext`,
		`internal/token/more.go:18: http.Client without Timeout`,
		`internal/token/more.go:20: http.ListenAndServe is forbidden; use an http.Server with read, write and idle timeouts`,
		`internal/token/more.go:21: http.Server without WriteTimeout, IdleTimeout`,
		`internal/token/more.go:23: new(http.Client) has no Timeout; use a literal that sets it`,
		`internal/token/more.go:25: new(http.Server) has no timeouts; use a literal that sets them`,
		`internal/token/token.go:16: http.Get is forbidden; use a client with a timeout`,
		`internal/token/token.go:17: http.DefaultClient is forbidden; use a client with a timeout`,
		`internal/token/token.go:4: import "math/rand" is forbidden here; use internal/secure`,
		`internal/user/revoke.go:10: RefreshTokens.RevokeSession ends sessions in revokeWithoutQueue without store.QueueLogouts in the same function; the back-channel logouts would not be queued (FR-43)`,
		`internal/user/revoke.go:23: RefreshTokens.DeleteUser ends sessions in deleteWithoutQueue without store.QueueLogouts in the same function; the back-channel logouts would not be queued (FR-43)`,
		`internal/user/user.go:4: import "log" is forbidden; use internal/logx`,
		`internal/user/user.go:6: non-test code imports test-support package clock/clocktest`,
		`internal/web/web.go:3: import "text/template" is forbidden in web; use html/template`,
	}
	sort.Strings(want)
	if strings.Join(problems, "\n") != strings.Join(want, "\n") {
		t.Fatalf("problems:\n  %s\nwant:\n  %s", strings.Join(problems, "\n  "), strings.Join(want, "\n  "))
	}
}

// The repository itself must pass.
func TestRepository(t *testing.T) {
	problems, err := check("../..")
	if err != nil {
		t.Fatal(err)
	}
	if len(problems) != 0 {
		t.Fatalf("problems:\n  %s", strings.Join(problems, "\n  "))
	}
}

func TestComponentOf(t *testing.T) {
	cases := []struct{ rel, comp string }{
		{"internal/token", "token"},
		{"internal/store/storetest", "store"},
		{"internal/provider/google", "provider"},
		{"internal/testutil/mockidp", "testutil"},
		{"cmd/featherauth", "cmd"},
		{"tools/trace", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := componentOf(c.rel); got != c.comp {
			t.Errorf("componentOf(%q) = %q, want %q", c.rel, got, c.comp)
		}
	}
}

func TestIsTestSupport(t *testing.T) {
	for rel, want := range map[string]bool{
		"internal/testutil":              true,
		"internal/testutil/mockidp":      true,
		"internal/store/storetest":       true,
		"internal/clock/clocktest":       true,
		"internal/provider/providertest": true,
		"internal/store":                 false,
		"internal/token":                 false,
		"internal/latest":                false,
	} {
		if got := isTestSupport(rel); got != want {
			t.Errorf("isTestSupport(%q) = %v, want %v", rel, got, want)
		}
	}
}

// The revoking methods are read from the store's RefreshTokens interface: the
// repository's are exactly the calls that end sessions, and the rotation's
// RevokeOthers is not one of them.
func TestRevokingMethodsOfTheRepository(t *testing.T) {
	pkgs, err := packages.Load(&packages.Config{Mode: packages.NeedName | packages.NeedTypes, Dir: "../.."}, "./internal/store")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for name := range revokingMethodsOf(pkgs) {
		got = append(got, name)
	}
	sort.Strings(got)
	if want := []string{"DeleteUser", "RevokeSession", "RevokeUser"}; strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("revoking methods %v, want %v", got, want)
	}
}

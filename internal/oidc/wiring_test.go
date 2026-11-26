package oidc_test

import (
	"strconv"
	"testing"

	"github.com/yyudhistira/featherauth/internal/testutil/mockidp"
	"github.com/yyudhistira/featherauth/internal/testutil/server"
)

// Covers: FR-05 (part), FR-12 (part)
func TestLoginForEveryProviderAndResponseMode(t *testing.T) {
	for i, prov := range server.Providers {
		t.Run(prov, func(t *testing.T) {
			env := server.New(t)
			env.Mocks[prov].SetUser(mockidp.User{
				Sub:  strconv.Itoa(1001 + i), // GitHub ids are numbers
				Name: "Ann Lee", Email: prov + "@example.com", EmailVerified: true,
				Emails: []mockidp.Email{{Email: prov + "@example.com", Primary: true, Verified: true}},
			})
			for _, app := range server.Clients {
				t.Run(app.Mode, func(t *testing.T) {
					c := env.NewClient()
					res := c.Login(t, server.Authorize(app, prov))
					if res.Mode != app.Mode || res.URL != app.RedirectURI {
						t.Errorf("delivered by %s to %s, want %s to %s", res.Mode, res.URL, app.Mode, app.RedirectURI)
					}
					if res.Values.Get("state") != "st-1" || res.Values.Get("iss") != server.Issuer || res.Values.Has("error") {
						t.Fatalf("result %v", res.Values)
					}
					if g := env.Exchange(t, app, res); g.AccessToken == "" || g.IDToken == "" {
						t.Errorf("grant %+v", g)
					}
					if n := env.Mocks[prov].TokenCalls(); n < 1 {
						t.Errorf("the provider's token endpoint was not called")
					}
					if left := c.Cookies(); len(left) != 0 {
						t.Errorf("state cookies left in the browser: %v", left)
					}
				})
			}
		})
	}
}

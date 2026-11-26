package oidc_test

import (
	"net/url"
	"testing"

	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/testutil"
)

// authzServerYAML names two provider hint parameters, so the order of
// login.provider_hint_params is exercised.
const authzServerYAML = "public_url: https://auth.example.com\nlogin:\n  provider_hint_params: [provider, idp]\n"

// authzClients are the clients of the authorize tests.
const authzClients = `clients:
  web:
    redirect_uris: [https://app.example.com/callback]
  native:
    redirect_uris: ["http://127.0.0.1:8080/cb", "http://[::1]:9090/cb", "com.example.app:/callback"]
  srv:
    type: confidential
    client_secret_file: secrets/main/srv_secret
    redirect_uris: [https://srv.example.com/callback]
  legacy:
    require_pkce: false
    refresh_idle_lifetime: 24h
    session_max_lifetime: 720h
    redirect_uris: [https://legacy.example.com/callback]
  frag:
    response_mode: fragment
    redirect_uris: [https://frag.example.com/callback]
  posting:
    response_mode: form_post
    redirect_uris: [https://post.example.com/callback]
  ssooff:
    sso: false
    redirect_uris: [https://off.example.com/callback]
`

// authzRealm loads the realm "main" with authzClients.
func authzRealm(t testing.TB) *config.Realm {
	t.Helper()
	snap := authzSource(t).Current()
	r, ok := snap.Realm("main")
	if !ok {
		t.Fatal("realm main missing")
	}
	return r
}

func authzSource(t testing.TB) config.Source {
	t.Helper()
	return testutil.NewConfigWithSecrets(t, authzServerYAML,
		map[string]string{"main": testutil.RealmYAML("main", authzClients)}, "secrets/main/srv_secret")
}

// challenge is a valid S256 code challenge: 43 base64url characters.
const challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

// goodRequest is a valid request of the public client "web".
func goodRequest(kv ...string) url.Values {
	v := url.Values{
		"client_id":             {"web"},
		"redirect_uri":          {"https://app.example.com/callback"},
		"response_type":         {"code"},
		"scope":                 {"openid"},
		"state":                 {"st-1"},
		"nonce":                 {"n-1"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] == "-" {
			v.Del(kv[i])
		} else {
			v.Set(kv[i], kv[i+1])
		}
	}
	return v
}

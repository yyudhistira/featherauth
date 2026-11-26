package token_test

import (
	"encoding/base64"
	"errors"
	"net/url"
	"testing"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/testutil/configdir"
	"github.com/yyudhistira/featherauth/internal/token"
)

// oddSecret holds characters that Basic credentials form-encode.
const oddSecret = "p+a%ss: wörd/é&="

func clientAuthEnv(t *testing.T) (*config.Realm, config.Secrets, string) {
	t.Helper()
	d := configdir.New(t)
	d.Server(t, "public_url: https://auth.example.com\n")
	d.Realm(t, "main", `name: main
keys:
  - { kid: rsa-new, file: secrets/rsa-new.pem, state: active }
providers:
  google:
    enabled: true
    client_id: 1234.apps.googleusercontent.com
    client_secret_file: secrets/google_secret
clients:
  spa:
    redirect_uris: [https://spa.example.com/callback]
  srv:
    type: confidential
    client_secret_file: secrets/srv_secret
    redirect_uris: [https://srv.example.com/callback]
  "my app+é":
    type: confidential
    client_secret_file: secrets/odd_secret
    redirect_uris: [https://odd.example.com/callback]
  blank:
    type: confidential
    client_secret_file: secrets/blank_secret
    redirect_uris: [https://blank.example.com/callback]
`)
	d.Write(t, "secrets/odd_secret", oddSecret+"\n")
	// Config refuses an empty secret file, so the client "blank" gets its empty
	// secret from blankSecrets below: the authentication code must still never
	// accept an empty configured secret.
	d.Write(t, "secrets/blank_secret", "placeholder\n")
	d.RSAKey(t, "secrets/rsa-new.pem")
	d.Secret(t, "secrets/google_secret")
	d.Secret(t, "secrets/srv_secret")
	l, err := config.NewLoader(d.Root, clock.NewFake(issueTime), nil)
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}
	snap := l.Current()
	r, ok := snap.Realm("main")
	if !ok {
		t.Fatal("no realm main")
	}
	return r, blankSecrets{snap.Secrets()}, snap.Secrets().ClientSecret("main", config.ClientSecretOf, "srv")
}

// blankSecrets reports an empty secret for the client "blank".
type blankSecrets struct{ config.Secrets }

func (b blankSecrets) ClientSecret(realm string, kind config.SecretKind, id string) string {
	if kind == config.ClientSecretOf && id == "blank" {
		return ""
	}
	return b.Secrets.ClientSecret(realm, kind, id)
}

func basic(id, secret string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(id)+":"+url.QueryEscape(secret)))
}

// Covers: FR-07 (part)
// Acceptance: Confidential client (part)
func TestAuthenticateClient(t *testing.T) {
	r, sec, good := clientAuthEnv(t)
	form := func(kv ...string) url.Values {
		v := url.Values{}
		for i := 0; i < len(kv); i += 2 {
			v.Set(kv[i], kv[i+1])
		}
		return v
	}
	tests := []struct {
		name       string
		form       url.Values
		authz      string
		wantClient string
		wantMethod token.Method
		wantCode   string
		wantBasic  bool
	}{
		{"basic right", nil, basic("srv", good), "srv", token.MethodBasic, "", false},
		{"basic right, empty form secret", form("client_secret", ""), basic("srv", good), "srv", token.MethodBasic, "", false},
		{"basic right, same client_id in form", form("client_id", "srv"), basic("srv", good), "srv", token.MethodBasic, "", false},
		{"basic form-encoded id and secret", nil, basic("my app+é", oddSecret), "my app+é", token.MethodBasic, "", false},
		{"post id and secret with special characters", form("client_id", "my app+é", "client_secret", oddSecret), "", "my app+é", token.MethodPost, "", false},
		{"basic secret not form-decoded is wrong", nil, "Basic " + base64.StdEncoding.EncodeToString([]byte("my+app:"+oddSecret)), "", token.MethodBasic, token.CodeInvalidClient, true},
		{"basic invalid percent-escape in secret", nil, "Basic " + base64.StdEncoding.EncodeToString([]byte("srv:%zz")), "", token.MethodBasic, token.CodeInvalidClient, true},
		{"basic invalid percent-escape in id", nil, "Basic " + base64.StdEncoding.EncodeToString([]byte("s%rv:x")), "", token.MethodBasic, token.CodeInvalidClient, true},
		{"bare Basic scheme", nil, "Basic", "", token.MethodBasic, token.CodeInvalidClient, true},
		{"Basic with empty credential", nil, "Basic ", "", token.MethodBasic, token.CodeInvalidClient, true},
		{"empty configured secret, empty presented", form("client_id", "blank"), "", "", token.MethodNone, token.CodeInvalidClient, false},
		{"empty configured secret, post", form("client_id", "blank", "client_secret", "x"), "", "", token.MethodPost, token.CodeInvalidClient, false},
		{"empty configured secret, basic", nil, basic("blank", ""), "", token.MethodNone, token.CodeInvalidClient, true},
		{"repeated client_id", url.Values{"client_id": {"srv", "srv"}, "client_secret": {good}}, "", "", token.MethodNone, token.CodeInvalidRequest, false},
		{"repeated client_secret", url.Values{"client_id": {"srv"}, "client_secret": {good, good}}, "", "", token.MethodNone, token.CodeInvalidRequest, false},
		{"repeated client_id with basic", url.Values{"client_id": {"srv", "srv"}}, basic("srv", good), "", token.MethodNone, token.CodeInvalidRequest, true},
		{"basic wrong", nil, basic("srv", "nope"), "", token.MethodBasic, token.CodeInvalidClient, true},
		{"basic empty secret", nil, basic("srv", ""), "", token.MethodNone, token.CodeInvalidClient, true},
		{"basic unknown client", nil, basic("ghost", good), "", token.MethodBasic, token.CodeInvalidClient, true},
		{"basic malformed", nil, "Basic !!!", "", token.MethodBasic, token.CodeInvalidClient, true},
		{"basic without colon", nil, "Basic " + base64.StdEncoding.EncodeToString([]byte("srv")), "", token.MethodBasic, token.CodeInvalidClient, true},
		{"basic id differs from form id", form("client_id", "spa"), basic("srv", good), "", token.MethodBasic, token.CodeInvalidRequest, true},
		{"post right", form("client_id", "srv", "client_secret", good), "", "srv", token.MethodPost, "", false},
		{"post wrong", form("client_id", "srv", "client_secret", "nope"), "", "", token.MethodPost, token.CodeInvalidClient, false},
		{"post missing secret", form("client_id", "srv"), "", "", token.MethodNone, token.CodeInvalidClient, false},
		{"post empty secret on confidential", form("client_id", "srv", "client_secret", ""), "", "", token.MethodNone, token.CodeInvalidClient, false},
		{"post unknown client", form("client_id", "ghost", "client_secret", good), "", "", token.MethodPost, token.CodeInvalidClient, false},
		{"no client at all", nil, "", "", token.MethodNone, token.CodeInvalidClient, false},
		{"both methods", form("client_id", "srv", "client_secret", good), basic("srv", good), "", token.MethodNone, token.CodeInvalidRequest, true},
		{"both methods, wrong secrets", form("client_id", "srv", "client_secret", "x"), basic("srv", "y"), "", token.MethodNone, token.CodeInvalidRequest, true},
		{"public none", form("client_id", "spa"), "", "spa", token.MethodNone, "", false},
		{"public with empty secret in form", form("client_id", "spa", "client_secret", ""), "", "spa", token.MethodNone, "", false},
		{"public with empty basic secret", nil, basic("spa", ""), "spa", token.MethodNone, "", false},
		{"public sending a secret by post", form("client_id", "spa", "client_secret", "x"), "", "", token.MethodPost, token.CodeInvalidClient, false},
		{"public sending a secret by basic", nil, basic("spa", "x"), "", token.MethodBasic, token.CodeInvalidClient, true},
		{"other scheme is ignored", form("client_id", "spa"), "Bearer abc", "spa", token.MethodNone, "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, m, err := token.AuthenticateClient(r, sec, tc.form, tc.authz)
			if tc.wantCode == "" {
				if err != nil {
					t.Fatalf("err = %v", err)
				}
				if c != r.Clients[config.ClientID(tc.wantClient)] || c == nil {
					t.Fatalf("client = %v, want %s", c, tc.wantClient)
				}
				if m != tc.wantMethod {
					t.Fatalf("method = %v, want %v", m, tc.wantMethod)
				}
				return
			}
			var ae *token.ClientAuthError
			if !errors.As(err, &ae) {
				t.Fatalf("err = %v, want *ClientAuthError", err)
			}
			if c != nil {
				t.Fatalf("client = %v on error", c)
			}
			if ae.Code != tc.wantCode || ae.Basic != tc.wantBasic {
				t.Fatalf("got code %q basic %v, want %q %v", ae.Code, ae.Basic, tc.wantCode, tc.wantBasic)
			}
			if m != tc.wantMethod {
				t.Fatalf("method = %v, want %v", m, tc.wantMethod)
			}
		})
	}
}

func TestClientAuthErrorText(t *testing.T) {
	err := &token.ClientAuthError{Code: token.CodeInvalidClient}
	if got := err.Error(); got != "token: client authentication: invalid_client" {
		t.Fatalf("Error() = %q", got)
	}
}

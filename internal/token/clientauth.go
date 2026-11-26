package token

import (
	"encoding/base64"
	"net/url"
	"strings"

	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/secure"
)

// Method is how a client authenticated at the token endpoint.
type Method string

// The client authentication methods.
const (
	// MethodNone is a client id with no secret (public clients).
	MethodNone Method = "none"
	// MethodBasic is client_secret_basic (RFC 6749 section 2.3.1).
	MethodBasic Method = "client_secret_basic"
	// MethodPost is client_secret_post.
	MethodPost Method = "client_secret_post"
)

// The OAuth error codes client authentication returns.
const (
	CodeInvalidRequest = "invalid_request"
	CodeInvalidClient  = "invalid_client"
)

// ClientAuthError is a failed client authentication. Basic tells whether the
// client sent an Authorization: Basic header, so that the handler answers
// invalid_client with 401 and WWW-Authenticate: Basic. Client is the id of a
// known confidential client whose secret was wrong or missing, so the failure
// can be recorded with it (SEC-25); it is empty for every other failure.
type ClientAuthError struct {
	Code        string
	Description string
	Basic       bool
	Client      config.ClientID
}

// Error implements error.
func (e *ClientAuthError) Error() string { return "token: client authentication: " + e.Code }

var _ error = (*ClientAuthError)(nil)

// AuthenticateClient authenticates the client of a token endpoint request
// from the form and the Authorization header. Confidential clients must send
// their secret with client_secret_basic or client_secret_post; public clients
// send only their client_id, and a non-empty secret from them is refused. An
// empty secret counts as absent.
func AuthenticateClient(r *config.Realm, secrets config.Secrets, form url.Values, authz string) (*config.Client, Method, error) {
	basicUsed := false
	var id, basicSecret string
	if scheme, cred, _ := strings.Cut(authz, " "); strings.EqualFold(scheme, "Basic") {
		basicUsed = true
		var valid bool
		if id, basicSecret, valid = decodeBasic(strings.TrimSpace(cred)); !valid {
			return nil, MethodBasic, &ClientAuthError{Code: CodeInvalidClient, Description: "malformed Authorization header", Basic: true}
		}
	}
	fail := func(m Method, code, desc string) (*config.Client, Method, error) {
		return nil, m, &ClientAuthError{Code: code, Description: desc, Basic: basicUsed}
	}

	// RFC 6749 section 3.2: a parameter must not be repeated.
	if len(form["client_id"]) > 1 || len(form["client_secret"]) > 1 {
		return fail(MethodNone, CodeInvalidRequest, "client_id and client_secret must not be repeated")
	}
	formSecret := form.Get("client_secret")
	if basicUsed && formSecret != "" {
		return fail(MethodNone, CodeInvalidRequest, "more than one client authentication method")
	}
	if formID := form.Get("client_id"); formID != "" {
		if basicUsed && formID != id {
			return fail(MethodBasic, CodeInvalidRequest, "client_id does not match the Authorization header")
		}
		id = formID
	}
	if id == "" {
		return fail(MethodNone, CodeInvalidClient, "client authentication failed")
	}

	method, secret := MethodNone, ""
	switch {
	case basicSecret != "":
		method, secret = MethodBasic, basicSecret
	case formSecret != "":
		method, secret = MethodPost, formSecret
	case basicUsed:
		method = MethodBasic
	}

	c, ok := r.Clients[config.ClientID(id)]
	if !ok {
		// Accepted early return: client ids are not secret and the error is
		// identical to a wrong secret, so timing reveals nothing useful.
		return fail(method, CodeInvalidClient, "client authentication failed")
	}
	if c.Type == config.Public {
		if secret != "" {
			return fail(method, CodeInvalidClient, "a public client must not send a client secret")
		}
		return c, MethodNone, nil
	}
	// An empty configured secret never matches: secret is non-empty here
	// or rejected, and Equal of a non-empty and an empty string is false.
	want := secrets.ClientSecret(string(r.Name), config.ClientSecretOf, id)
	if secret == "" || !secure.Equal(secret, want) {
		if secret == "" {
			method = MethodNone
		}
		return nil, method, &ClientAuthError{
			Code: CodeInvalidClient, Description: "client authentication failed",
			Basic: basicUsed, Client: config.ClientID(id),
		}
	}
	return c, method, nil
}

// decodeBasic splits a Basic credential into its form-decoded id and secret.
func decodeBasic(cred string) (id, secret string, ok bool) {
	raw, err := base64.StdEncoding.DecodeString(cred)
	if err != nil {
		return "", "", false
	}
	i, s, found := strings.Cut(string(raw), ":")
	if !found {
		return "", "", false
	}
	id, err1 := url.QueryUnescape(i)
	secret, err2 := url.QueryUnescape(s)
	if err1 != nil || err2 != nil {
		return "", "", false
	}
	return id, secret, true
}

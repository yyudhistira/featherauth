package oidc

import (
	"log/slog"
	"net/http"

	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/server"
	"github.com/yyudhistira/featherauth/internal/token"
)

// UserinfoConfig is what the userinfo endpoint needs.
type UserinfoConfig struct {
	// Bearer authenticates the request; required.
	Bearer *BearerAuth
	// Log is the service logger (logx); required.
	Log *slog.Logger
}

// Userinfo is the userinfo endpoint (OIDC Core 5.3): the claims of the stored
// profile of the token's user, chosen by user_data.claims alone.
type Userinfo struct {
	bearer *BearerAuth
	log    *slog.Logger
}

// NewUserinfo returns the userinfo endpoint.
func NewUserinfo(c UserinfoConfig) *Userinfo { return &Userinfo{bearer: c.Bearer, log: c.Log} }

var _ http.Handler = (*Userinfo)(nil)

// ServeHTTP answers GET and POST /{realm}/userinfo. A preflight is answered
// by the CORS middleware. The Origin of the request is checked against the
// web_origins of the token's azp client; for any other origin the response
// carries no Access-Control-Allow-Origin, so a browser does not hand it to the
// page.
func (u *Userinfo) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	info, ok := server.FromContext(r.Context())
	if !ok || info.Realm == nil {
		serverError(w, r, info)
		return
	}
	if !server.AllowMethods(w, r, http.MethodGet, http.MethodPost, http.MethodOptions) {
		return
	}
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	claims, usr, berr := u.bearer.Bearer(r, info.Realm, config.EndpointUserinfo)
	if berr != nil {
		writeBearerFailure(w, r, u.log, berr, "userinfo")
		return
	}
	// A client removed since the token was issued is nil: no origin is allowed
	// and the allowed-origins claim is left out.
	client := info.Realm.Clients[config.ClientID(claims.Azp)]
	// No refusal: an origin that does not match only goes without
	// Access-Control-Allow-Origin (design: Userinfo and CORS).
	_ = server.AllowOrigin(w, r, client)

	body := token.ProfileClaims(info.Realm, client, token.Subject{
		ID: token.UserID(usr.ID), Email: usr.Email, EmailVerified: usr.EmailVerified, Name: usr.Name,
	})
	body["sub"] = string(usr.ID)
	writeJSON(w, http.StatusOK, body)
}

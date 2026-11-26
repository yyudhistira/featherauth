package oidc

import (
	"context"
	"errors"
	"log/slog"
	"mime"
	"net/http"

	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/server"
	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/store/audit"
	"github.com/yyudhistira/featherauth/internal/token"
)

// codeExchanger is what the token endpoint needs of the code service.
type codeExchanger interface {
	Exchange(ctx context.Context, in token.ExchangeInput) (*token.Grant, error)
}

// refreshExchanger is what the token endpoint needs of the refresh service.
type refreshExchanger interface {
	Refresh(ctx context.Context, in token.RefreshInput) (*token.Grant, error)
}

// auditWriter is what the token endpoint needs of the audit writer: it
// records a reuse that revoked a session.
type auditWriter interface {
	Write(ctx context.Context, e audit.Event) error
}

var (
	_ codeExchanger    = (*token.Codes)(nil)
	_ refreshExchanger = (*token.Refresher)(nil)
	_ auditWriter      = (*audit.Writer)(nil)
)

// TokenConfig is what the token endpoint needs.
type TokenConfig struct {
	// Codes exchanges login codes; required.
	Codes *token.Codes
	// Refresher exchanges refresh tokens; required.
	Refresher *token.Refresher
	// Audit records the reuse of a token that revoked a session; required.
	Audit auditWriter
	// Log is the service logger (logx); required.
	Log *slog.Logger
}

// Token is the token endpoint: client authentication, then the code or the
// refresh grant.
type Token struct {
	codes   codeExchanger
	refresh refreshExchanger
	audit   auditWriter
	log     *slog.Logger
}

// NewToken returns the token endpoint.
func NewToken(c TokenConfig) *Token {
	return &Token{codes: c.Codes, refresh: c.Refresher, audit: c.Audit, log: c.Log}
}

var _ http.Handler = (*Token)(nil)

// ServeHTTP answers a request to /{realm}/token. The realm and the snapshot
// come from the request context (server.FromContext).
func (t *Token) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	info, ok := server.FromContext(r.Context())
	if !ok || info.Realm == nil {
		serverError(w, r, info)
		return
	}
	if !server.AllowMethods(w, r, http.MethodPost, http.MethodOptions) {
		return
	}
	if r.Method == http.MethodOptions {
		// A preflight is answered by the CORS middleware; any other OPTIONS
		// request is not a token request.
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/x-www-form-urlencoded" {
		WriteJSONError(w, Error{Code: token.CodeInvalidRequest, Description: "the request must be application/x-www-form-urlencoded"})
		return
	}
	if err := r.ParseForm(); err != nil {
		WriteJSONError(w, Error{Code: token.CodeInvalidRequest, Description: "the request body cannot be read"})
		return
	}
	// Only the body counts: a secret or a code in the URL is not accepted.
	form := r.PostForm

	realm := info.Realm
	client, _, err := token.AuthenticateClient(realm, info.Snapshot.Secrets(), form, r.Header.Get("Authorization"))
	if err != nil {
		logClientAuthFailure(r.Context(), t.log, err)
		if !writeClientAuthError(w, realm, err) {
			t.fail(w, r, err)
		}
		return
	}
	if !server.AllowOrigin(w, r, client) {
		WriteJSONError(w, Error{Code: token.CodeInvalidRequest, Description: "origin not allowed for this client"})
		return
	}

	var grant *token.Grant
	switch form.Get("grant_type") {
	case "authorization_code":
		grant, err = t.codes.Exchange(r.Context(), token.ExchangeInput{
			Realm: realm, Client: client, Code: form.Get("code"),
			RedirectURI: form.Get("redirect_uri"), Verifier: form.Get("code_verifier"),
			DPoP: dpopRequest(r, realm),
		})
	case "refresh_token":
		grant, err = t.refresh.Refresh(r.Context(), token.RefreshInput{
			Realm: realm, Client: client, Token: form.Get("refresh_token"), DPoP: dpopRequest(r, realm),
		})
	default:
		WriteJSONError(w, Error{Code: "unsupported_grant_type", Description: "grant_type must be authorization_code or refresh_token"})
		return
	}
	if err != nil {
		t.fail(w, r, err)
		return
	}
	WriteTokenResponse(w, grant)
}

// fail answers the error of a grant: an OAuth refusal as it is, an
// unavailable store as 503 and anything else as 500. A refusal that names a
// reuse is recorded first.
func (t *Token) fail(w http.ResponseWriter, r *http.Request, err error) {
	var ge *token.GrantError
	switch {
	case errors.As(err, &ge):
		if ge.Reuse != nil {
			t.recordReuse(r.Context(), ge.Reuse)
		}
		WriteJSONError(w, Error{Code: ge.Code, Description: ge.Description})
	case errors.Is(err, store.ErrUnavailable):
		t.log.WarnContext(r.Context(), "token endpoint: the store is unavailable", "err", err)
		WriteJSONError(w, Error{Code: "temporarily_unavailable", Description: "the service is temporarily unavailable", Status: http.StatusServiceUnavailable})
	default:
		t.log.ErrorContext(r.Context(), "token endpoint failed", "err", err)
		WriteJSONError(w, Error{Code: "server_error", Description: "the request could not be completed", Status: http.StatusInternalServerError})
	}
}

// recordReuse records a reused token that the endpoint refused (SEC-25). When
// the revocation ended an active token, it logs a warning and writes one
// session.reuse_detected row, after the revocation has committed; the row is
// written outside the request's cancellation, so a client that hangs up does
// not lose it. When the revocation ended nothing, it logs an information line
// only.
func (t *Token) recordReuse(ctx context.Context, ru *token.Reuse) {
	fields := []any{
		"user_id", string(ru.User), "client", string(ru.Client),
		"session", string(ru.Session), "kind", string(ru.Kind),
	}
	if !ru.Ended {
		t.log.InfoContext(ctx, "token endpoint: a reused token was refused, its session was already revoked", fields...)
		return
	}
	t.log.WarnContext(ctx, "token endpoint: a reused token revoked its session", fields...)
	err := t.audit.Write(context.WithoutCancel(ctx), audit.Event{
		Realm: ru.Realm, Actor: "system", Action: "session.reuse_detected", User: store.UserID(ru.User),
		Details: map[string]any{"client": string(ru.Client), "session": string(ru.Session), "kind": string(ru.Kind)},
	})
	if err != nil {
		t.log.ErrorContext(ctx, "token endpoint: the reuse could not be recorded", "err", err)
	}
}

// logClientAuthFailure warns about a failed client authentication of a known
// confidential client, with its client id (SEC-25). The secret is not logged.
// Any other failure is answered without a log line here.
func logClientAuthFailure(ctx context.Context, log *slog.Logger, err error) {
	var ce *token.ClientAuthError
	if errors.As(err, &ce) && ce.Client != "" {
		log.WarnContext(ctx, "client authentication failed", "client", string(ce.Client))
	}
}

// writeClientAuthError answers a client authentication failure: 400, or 401
// with WWW-Authenticate: Basic for an invalid_client of the Basic method. It
// returns false, writing nothing, for any other error.
func writeClientAuthError(w http.ResponseWriter, realm *config.Realm, err error) bool {
	var ce *token.ClientAuthError
	if !errors.As(err, &ce) {
		return false
	}
	status := http.StatusBadRequest
	if ce.Code == token.CodeInvalidClient && ce.Basic {
		status = http.StatusUnauthorized
		w.Header().Set("WWW-Authenticate", `Basic realm="`+string(realm.Name)+`"`)
	}
	WriteJSONError(w, Error{Code: ce.Code, Description: ce.Description, Status: status})
	return true
}

// dpopRequest is the DPoP header of a token request, with the request method
// and the token endpoint's URL that its proof is checked against (FR-44).
func dpopRequest(r *http.Request, realm *config.Realm) token.DPoPRequest {
	return token.DPoPRequest{Header: r.Header.Values("DPoP"), Method: r.Method, URL: realm.EndpointURL(config.EndpointToken, "")}
}

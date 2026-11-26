package oidc

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"

	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/provider"
	"github.com/yyudhistira/featherauth/internal/secure"
	"github.com/yyudhistira/featherauth/internal/server"
	"github.com/yyudhistira/featherauth/internal/user"
)

// eventUsers is what the events endpoint needs of the user manager.
type eventUsers interface {
	ProviderEvents(ctx context.Context, realm config.RealmName, prov config.ProviderKey, evs []provider.Event) ([]user.EventResult, error)
}

var _ eventUsers = (*user.Manager)(nil)

// EventsConfig is what the provider events endpoint needs.
type EventsConfig struct {
	// Registry gives the provider adapters; required.
	Registry provider.Registry
	// Users acts on the events; required.
	Users *user.Manager
	// Rand is the source of the confirmation codes; required.
	Rand secure.Source
	// Log is the service logger (logx); required.
	Log *slog.Logger
}

// Events is the provider events endpoint, POST /{realm}/events/{provider}
// (FR-31): Apple's server-to-server notifications, Meta's data-deletion
// callback (FR-40) and Google's security event tokens (FR-48).
type Events struct {
	reg   provider.Registry
	users eventUsers
	rand  secure.Source
	log   *slog.Logger
}

// NewEvents returns the provider events endpoint.
func NewEvents(c EventsConfig) *Events {
	return &Events{reg: c.Registry, users: c.Users, rand: c.Rand, log: c.Log}
}

var _ http.Handler = (*Events)(nil)

// ServeHTTP answers a POST of /{realm}/events/{provider}. The adapter verifies
// the signed payload: one that fails gets 400, and one whose keys cannot be
// fetched gets 503, so the provider sends it again. A verified token's events
// are acted on once (SEC-27): a handled, unknown or repeated event gets the
// adapter's status (200, or 202 for Google) with no body, so the provider does
// not retry; a change that fails in the store gets 500 and remembers nothing.
// For an adapter that asks for it (Meta), a verified event is answered 200 with
// the JSON of confirm instead.
func (ev *Events) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	info, ok := server.FromContext(r.Context())
	if !ok || info.Realm == nil {
		serverError(w, r, info)
		return
	}
	if !server.AllowMethods(w, r, http.MethodPost) {
		return
	}
	adapter, ok := ev.reg.Get(info.Realm.Name, info.Provider)
	receiver, _ := adapter.(provider.EventReceiver)
	if !ok || receiver == nil {
		http.NotFound(w, r)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		WriteJSONError(w, Error{Code: "invalid_request", Description: "the request body could not be read"})
		return
	}
	events, err := receiver.ParseEvent(r.Context(), body)
	if errors.Is(err, provider.ErrUnavailable) {
		ev.log.WarnContext(r.Context(), "provider event not verified: the provider's keys could not be fetched", "provider", string(info.Provider))
		WriteJSONError(w, Error{Code: "temporarily_unavailable", Description: "the provider's keys could not be fetched", Status: http.StatusServiceUnavailable})
		return
	}
	if err != nil {
		ev.log.WarnContext(r.Context(), "provider event rejected", "provider", string(info.Provider), "reason", err.Error())
		WriteJSONError(w, Error{Code: "invalid_request", Description: "the event could not be verified"})
		return
	}
	res, err := ev.users.ProviderEvents(r.Context(), info.Realm.Name, info.Provider, events)
	if err != nil {
		ev.log.ErrorContext(r.Context(), "provider event failed", "provider", string(info.Provider), "events", len(events), "error", err)
		WriteJSONError(w, Error{Code: "server_error", Description: "the request could not be completed", Status: http.StatusInternalServerError})
		return
	}
	for i, event := range events {
		ev.logResult(r.Context(), string(info.Provider), event, res[i])
	}
	if confirmer, ok := adapter.(provider.EventConfirmer); ok && confirmer.ConfirmsEvents() {
		ev.confirm(w, r, info)
		return
	}
	status := http.StatusOK
	if answerer, ok := adapter.(provider.EventAnswerer); ok {
		status = answerer.EventStatus()
	}
	w.WriteHeader(status)
}

// confirmation is the answer Meta's data-deletion callback needs: the URL where
// the user can see the status, and the confirmation code it carries.
type confirmation struct {
	URL  string `json:"url"`
	Code string `json:"confirmation_code"`
}

// confirm answers a verified event with a new confirmation code of 22 letters
// and digits and the data-deletion page URL that carries it. The repeat of an
// event gets the same kind of answer with a code of its own.
func (ev *Events) confirm(w http.ResponseWriter, r *http.Request, info server.Info) {
	code, err := secure.Alphanumeric(ev.rand, 22)
	if err != nil {
		ev.log.ErrorContext(r.Context(), "provider event: no confirmation code", "provider", string(info.Provider), "error", err)
		WriteJSONError(w, Error{Code: "server_error", Description: "the request could not be completed", Status: http.StatusInternalServerError})
		return
	}
	writeJSON(w, http.StatusOK, confirmation{
		URL:  info.Realm.EndpointURL(config.EndpointDataDeletion, "") + "?code=" + code,
		Code: code,
	})
}

// logResult logs an event that changed nothing. The audit rows of a change are
// written by the user manager.
func (ev *Events) logResult(ctx context.Context, prov string, event provider.Event, res user.EventResult) {
	switch res {
	case user.EventRepeated:
		ev.log.InfoContext(ctx, "provider event already acted on, ignored", "provider", prov, "event", event.Type)
	case user.EventUnknownSubject:
		ev.log.InfoContext(ctx, "provider event for an unknown subject ignored", "provider", prov, "event", event.Type)
	case user.EventUnknownType:
		ev.log.InfoContext(ctx, "provider event of an unknown type ignored", "provider", prov, "event", event.Type)
	case user.EventLogOnly:
		if event.State != "" {
			ev.log.InfoContext(ctx, "provider event", "provider", prov, "event", event.Type, "verification_state", event.State)
			return
		}
		ev.log.InfoContext(ctx, "provider event", "provider", prov, "event", event.Type)
	}
}

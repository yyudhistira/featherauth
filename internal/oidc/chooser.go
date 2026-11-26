package oidc

import (
	"context"
	"log/slog"
	"net/url"
	"slices"
	"unicode/utf8"

	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/provider"
	"github.com/yyudhistira/featherauth/internal/web"
)

// selection is the outcome of choosing the provider of a request: exactly one
// of a provider to send the user to, an error to deliver to the client, or the
// buttons of the chooser page (which may be none).
type selection struct {
	key     config.ProviderKey
	adapter provider.Provider
	err     *RedirectError
	buttons []web.Provider
}

// maxLoggedHint bounds the hint that is logged: it comes from the request.
const maxLoggedHint = 64

// chooseProvider picks the provider of a request (FR-04). A hint that names an
// enabled provider, hidden or not, selects it. A hint that names none, or a
// disabled one, is not an error: it is logged and the chooser is shown. With
// no hint, one enabled visible provider is used directly and any other number
// gets the chooser, whose buttons link back to the same request with the hint
// added. original holds the request's parameters, which the links keep.
//
// Registry.Get cannot tell an unknown provider from one whose discovery is
// failing, so the configuration is read first: a provider that is configured
// and enabled (or visible) but has no adapter now is temporarily unavailable.
func chooseProvider(ctx context.Context, reg provider.Registry, log *slog.Logger, req AuthRequest, original url.Values) selection {
	realm := req.Realm
	visible := reg.Visible(realm.Name)

	use := func(key config.ProviderKey) selection {
		a, ok := reg.Get(realm.Name, key)
		if !ok {
			return selection{key: key, err: unavailable(req)}
		}
		return selection{key: key, adapter: a}
	}

	switch {
	case req.Hint != "":
		key := config.ProviderKey(req.Hint)
		if cfg, ok := realm.Providers[key]; ok && cfg.Enabled {
			return use(key)
		}
		hint := req.Hint
		hint = truncateUTF8(hint, maxLoggedHint)
		log.InfoContext(ctx, "provider hint names an unknown or disabled provider; showing the chooser",
			"realm", string(realm.Name), "provider", hint)
	case len(visible) == 1:
		return use(visible[0])
	}

	path := realm.EndpointPath(config.EndpointAuthorize, "")
	hintParam := "provider"
	if names := realm.ProviderHintParams(); len(names) > 0 {
		hintParam = names[0]
	}
	buttons := make([]web.Provider, 0, len(visible))
	for _, key := range visible {
		cfg := realm.Providers[key]
		q := make(url.Values, len(original)+1)
		for k, v := range original {
			q[k] = slices.Clone(v)
		}
		q.Set(hintParam, string(key))
		buttons = append(buttons, web.Provider{Key: key, Name: cfg.DisplayName, Brand: cfg.Type, Href: path + "?" + q.Encode()})
	}
	return selection{buttons: buttons}
}

// truncateUTF8 cuts s to at most n bytes, at a rune boundary.
func truncateUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// unavailable is the error of a provider that is configured but cannot be
// used now (its discovery is failing).
func unavailable(req AuthRequest) *RedirectError {
	code, description := provider.MapError(provider.ErrUnavailable)
	return &RedirectError{Err: Error{Code: code, Description: description}, Mode: req.ResponseMode, RedirectURI: req.RedirectURI, State: req.State}
}

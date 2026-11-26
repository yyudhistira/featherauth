// Package oidc holds the protocol handlers of the service. This file and
// response.go are the shared kit: the OAuth error type and the writers of
// errors, token responses and authorization results.
package oidc

import (
	"encoding/json"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/yyudhistira/featherauth/internal/token"
)

// Error is an OAuth error: the code and description of the response and its
// HTTP status. It is mapped to HTTP in the writers below.
type Error struct {
	Code        string
	Description string
	// Status is the HTTP status; 0 means 400 for WriteJSONError and 401 for
	// WriteBearerError.
	Status int
	// Scheme is the challenge scheme of a bearer endpoint's WWW-Authenticate:
	// "DPoP" for an answer to a DPoP request (FR-44), which also names the
	// algorithms; empty means Bearer.
	Scheme string
}

// Error implements error.
func (e Error) Error() string { return "oidc: " + e.Code + ": " + e.Description }

var _ error = Error{}

// errorBody is the JSON of an error response.
type errorBody struct {
	Error       string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

func noStore(h http.Header) {
	h.Set("Cache-Control", "no-store")
	h.Set("Pragma", "no-cache")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	b, _ := json.Marshal(v) // the bodies are plain structs: Marshal cannot fail
	h := w.Header()
	h.Set("Content-Type", "application/json")
	noStore(h)
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

// WriteJSONError answers with the OAuth error JSON (RFC 6749 §5.2). Like every
// token response it carries Cache-Control: no-store and Pragma: no-cache. A
// handler that needs more headers, such as WWW-Authenticate: Basic for
// invalid_client, sets them before calling it.
func WriteJSONError(w http.ResponseWriter, e Error) {
	status := e.Status
	if status == 0 {
		status = http.StatusBadRequest
	}
	writeJSON(w, status, errorBody{Error: e.Code, Description: e.Description})
}

// WriteBearerError answers a bearer endpoint's error: the JSON body of
// WriteJSONError and a WWW-Authenticate header (RFC 6750 §3) such as
// `Bearer error="invalid_token"`. params are added to the header after the
// error, sorted by name; max_age is a number and is written without quotes
// (RFC 9470), every other value in quotes.
func WriteBearerError(w http.ResponseWriter, e Error, params map[string]string) {
	status := e.Status
	if status == 0 {
		status = http.StatusUnauthorized
	}
	var parts []string
	if e.Code != "" {
		parts = append(parts, "error="+strconv.Quote(e.Code))
	}
	for _, k := range slices.Sorted(maps.Keys(params)) {
		if k == "max_age" {
			parts = append(parts, k+"="+params[k])
			continue
		}
		parts = append(parts, k+"="+quoteParam(params[k]))
	}
	hdr := "Bearer"
	if e.Scheme == "DPoP" {
		hdr = "DPoP"
		parts = append(parts, "algs="+quoteParam("ES256 RS256"))
	}
	if len(parts) > 0 {
		hdr += " " + strings.Join(parts, ", ")
	}
	w.Header().Set("WWW-Authenticate", hdr)
	if e.Code == "" {
		noStore(w.Header())
		w.WriteHeader(status)
		return
	}
	writeJSON(w, status, errorBody{Error: e.Code, Description: e.Description})
}

// quoteParam writes a header parameter value as an HTTP quoted-string.
func quoteParam(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}

// tokenBody is the token response, in the order of the design.
type tokenBody struct {
	AccessToken      string `json:"access_token"`
	IDToken          string `json:"id_token"`
	RefreshToken     string `json:"refresh_token"`
	TokenType        string `json:"token_type"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
	Scope            string `json:"scope"`
}

// WriteTokenResponse answers a successful token request. It carries
// Cache-Control: no-store and Pragma: no-cache, so no proxy or browser keeps a
// token.
func WriteTokenResponse(w http.ResponseWriter, g *token.Grant) {
	writeJSON(w, http.StatusOK, tokenBody{
		AccessToken:      g.AccessToken,
		IDToken:          g.IDToken,
		RefreshToken:     g.RefreshToken,
		TokenType:        tokenTypeOf(g),
		ExpiresIn:        g.ExpiresIn,
		RefreshExpiresIn: g.RefreshExpiresIn,
		Scope:            g.Scope,
	})
}

// tokenTypeOf is the token_type of a token response: DPoP for an answer bound
// to a key (FR-44), otherwise Bearer.
func tokenTypeOf(g *token.Grant) string {
	if g.TokenType == "" {
		return "Bearer"
	}
	return g.TokenType
}

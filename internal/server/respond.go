package server

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"runtime/debug"
	"slices"
	"strings"
)

// statusWriter remembers the status of the answer.
type statusWriter struct {
	http.ResponseWriter
	code int
}

func (w *statusWriter) WriteHeader(code int) {
	if w.code == 0 {
		w.code = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.code == 0 {
		w.code = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

// Unwrap lets http.ResponseController reach the real writer.
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *statusWriter) status() int {
	if w.code == 0 {
		return http.StatusOK
	}
	return w.code
}

func (w *statusWriter) wrote() bool { return w.code != 0 }

var errorPage = template.Must(template.New("error").Parse(
	`<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>{{.Status}} {{.Text}}</title></head>
<body><h1>{{.Text}}</h1><p>{{.Description}}</p></body></html>
`))

// writeError answers an error the router gives itself: OAuth error JSON on an
// API endpoint, a plain HTML page on a browser endpoint.
func writeError(w http.ResponseWriter, k Kind, status int, code, description string) {
	w.Header().Set("Cache-Control", "no-store")
	if k == KindBrowser {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(status)
		_ = errorPage.Execute(w, struct {
			Status      int
			Text        string
			Description string
		}{status, http.StatusText(status), description})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": description})
}

// recoverPanic turns a panic in a handler into a logged 500. The panic value
// is not logged, only its type, because it can hold anything.
func (rt *Router) recoverPanic(w *statusWriter, r *http.Request, info *Info) {
	rec := recover()
	if rec == nil {
		return
	}
	if rec == http.ErrAbortHandler {
		panic(rec)
	}
	rt.log.LogAttrs(r.Context(), slog.LevelError, "panic",
		slog.String("panic_type", fmt.Sprintf("%T", rec)),
		slog.String("path", r.URL.Path),
		slog.String("stack", string(debug.Stack())),
	)
	if !w.wrote() {
		writeError(w, info.Kind, http.StatusInternalServerError, "server_error", "internal error")
	}
}

// AllowMethods reports whether the request's method is one of allowed. When it
// is not, it answers 405 with an Allow header listing allowed (in the order
// given), the OAuth error JSON on an API endpoint and a plain HTML page on a
// browser endpoint, and returns false; the handler then does nothing more.
func AllowMethods(w http.ResponseWriter, r *http.Request, allowed ...string) bool {
	if slices.Contains(allowed, r.Method) {
		return true
	}
	kind := KindAPI
	if info, ok := FromContext(r.Context()); ok {
		kind = info.Kind
	}
	w.Header().Set("Allow", strings.Join(allowed, ", "))
	writeError(w, kind, http.StatusMethodNotAllowed, "invalid_request", "method not allowed")
	return false
}

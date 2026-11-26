// Package logx builds the service's JSON logger. A wrapping handler redacts
// sensitive values (SEC-13) by key before slog expands groups, so a value is
// hidden when its own key is sensitive and when any enclosing group's name
// is: at the top level, in groups, in values from LogValuer (also inside
// containers), under WithGroup and With, in any map (by key for string keys,
// and in the values of every map), slice or array (url.Values and
// http.Header included), and in raw JSON bytes. Keys are compared after
// normalizing letter case, dashes, dots, spaces and camelCase, ignoring one
// trailing "s". URLs are logged without query or fragment, also inside
// errors from outgoing HTTP calls. Free text and the fields of plain structs
// are not inspected; a type that holds secrets implements slog.LogValuer.
package logx

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"reflect"
	"strings"
	"time"
	"unicode"

	"github.com/yyudhistira/featherauth/internal/clock"
)

// Redacted replaces every sensitive value in the log.
const Redacted = "[redacted]"

// sensitiveKeys and sensitiveSuffixes are matched against the normalized
// key (see normalizeKey), so "X-Auth-Token", "accessToken", "user.email" and
// "access_token" are treated alike.
var sensitiveKeys = map[string]bool{
	"token": true, "access_token": true, "refresh_token": true, "id_token": true,
	"id_token_hint": true, "code": true, "code_verifier": true, "state": true,
	"nonce": true, "client_secret": true, "secret": true, "password": true,
	"authorization": true, "cookie": true, "set_cookie": true, "email": true,
	"login_hint": true,
	// the DPoP key and header in every spelling: dpop is the canonical form
	// (net/http writes the header Dpop), d_po_p is what "DPoP" normalizes to.
	"dpop": true, "d_po_p": true,
}

var sensitiveSuffixes = []string{
	"_token", "_secret", "_password", "_email", "_key", "_code",
	"_hint", "_authorization", "_cookie",
}

// isSensitive reports whether key names a secret. One trailing "s" is
// ignored, so plurals such as "tokens" and "api_keys" match too.
func isSensitive(key string) bool {
	k := normalizeKey(key)
	if matchesSensitive(k) {
		return true
	}
	singular, ok := strings.CutSuffix(k, "s")
	return ok && singular != "" && matchesSensitive(singular)
}

func matchesSensitive(k string) bool {
	if sensitiveKeys[k] {
		return true
	}
	for _, s := range sensitiveSuffixes {
		if strings.HasSuffix(k, s) {
			return true
		}
	}
	return false
}

// normalizeKey lowercases key, turns dashes, dots and spaces into
// underscores, and splits camelCase words: "X-Auth-Token" -> "x_auth_token",
// "accessToken" -> "access_token", "IDToken" -> "id_token".
func normalizeKey(key string) string {
	r := []rune(key)
	var b strings.Builder
	for i, c := range r {
		switch {
		case c == '-' || c == '.' || c == ' ':
			b.WriteByte('_')
			continue
		case unicode.IsUpper(c) && i > 0:
			prev := r[i-1]
			nextLower := i+1 < len(r) && unicode.IsLower(r[i+1])
			if unicode.IsLower(prev) || unicode.IsDigit(prev) || (unicode.IsUpper(prev) && nextLower) {
				b.WriteByte('_')
			}
		}
		b.WriteRune(unicode.ToLower(c))
	}
	return b.String()
}

// New returns a JSON logger writing to w at the given level. The time of
// each line comes from c, not from the system clock.
func New(w io.Writer, level slog.Level, c clock.Clock) *slog.Logger {
	return NewLeveled(w, level, c)
}

// NewLeveled is New with a level the caller can change while the logger is in
// use, such as a *slog.LevelVar.
func NewLeveled(w io.Writer, level slog.Leveler, c clock.Clock) *slog.Logger {
	inner := slog.NewJSONHandler(w, &slog.HandlerOptions{
		Level: level,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) == 0 && a.Key == slog.TimeKey {
				return slog.Time(slog.TimeKey, c.Now())
			}
			return a
		},
	})
	return slog.New(&redactor{inner: inner})
}

// redactor redacts attributes before the inner handler sees them. slog's
// ReplaceAttr is not enough on its own: it is never called for an attribute
// whose value is a group, so a sensitive key naming a group would pass.
type redactor struct {
	inner slog.Handler
	all   bool // inside a group whose name is sensitive: every value is hidden
}

var _ slog.Handler = (*redactor)(nil)

func (h *redactor) Enabled(ctx context.Context, l slog.Level) bool {
	return h.inner.Enabled(ctx, l)
}

func (h *redactor) Handle(ctx context.Context, r slog.Record) error {
	out := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
	r.Attrs(func(a slog.Attr) bool {
		out.AddAttrs(redact(a, h.all, 0))
		return true
	})
	return h.inner.Handle(ctx, out)
}

func (h *redactor) WithAttrs(attrs []slog.Attr) slog.Handler {
	red := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		red[i] = redact(a, h.all, 0)
	}
	return &redactor{inner: h.inner.WithAttrs(red), all: h.all}
}

func (h *redactor) WithGroup(name string) slog.Handler {
	return &redactor{inner: h.inner.WithGroup(name), all: h.all || isSensitive(name)}
}

// redact resolves a's value and hides it when a's key, or an enclosing
// group's name (all), is sensitive. Groups are redacted member by member,
// down to maxDepth; deeper values (such as a LogValue that contains itself)
// are replaced by the marker.
func redact(a slog.Attr, all bool, depth int) slog.Attr {
	if depth > maxDepth {
		return slog.String(a.Key, Redacted)
	}
	v := a.Value.Resolve()
	if all || isSensitive(a.Key) {
		return slog.String(a.Key, Redacted)
	}
	switch v.Kind() {
	case slog.KindGroup:
		members := v.Group()
		out := make([]slog.Attr, len(members))
		for i, m := range members {
			out[i] = redact(m, false, depth+1)
		}
		return slog.Attr{Key: a.Key, Value: slog.GroupValue(out...)}
	case slog.KindAny:
		if s, ok := sanitizeDepth(v.Any(), depth+1); ok {
			return slog.Any(a.Key, s)
		}
	}
	return slog.Attr{Key: a.Key, Value: v}
}

// maxDepth bounds how deep sanitize walks nested values; anything deeper,
// such as a map that contains itself, is replaced by the marker.
const maxDepth = 32

// sanitizeDepth returns a copy of v that is safe to log, or false when v
// needs no change; depth counts the levels already walked. It resolves
// LogValuers, walks every map (whatever its named type; values under
// sensitive string keys are hidden, and the values of maps with other keys
// are cleaned too) and every slice and array by reflection;
// follows pointers to them; parses raw JSON bytes and cleans the result,
// hiding bytes that are not JSON whole; and redacts URLs, also inside errors.
func sanitizeDepth(v any, depth int) (any, bool) {
	if depth > maxDepth {
		return Redacted, true
	}
	// A LogValuer inside a map or slice would otherwise be serialized as
	// plain JSON, which ignores LogValue and shows every field.
	if lv, ok := v.(slog.LogValuer); ok {
		return valueToAny(slog.AnyValue(lv), depth), true
	}
	switch x := v.(type) {
	case nil:
		return nil, false
	case *url.URL:
		if x == nil {
			return nil, false
		}
		return redactURL(x), true
	case url.URL:
		return redactURL(&x), true
	case error:
		return redactErrorURLs(x), true
	case json.RawMessage:
		return sanitizeBytes(x, depth), true
	case []byte:
		return sanitizeBytes(x, depth), true
	}

	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Pointer:
		if rv.IsNil() {
			return nil, false
		}
		switch rv.Elem().Kind() {
		case reflect.Map, reflect.Slice, reflect.Array:
			return sanitizeDepth(rv.Elem().Interface(), depth+1)
		}
	case reflect.Map:
		if rv.IsNil() {
			return nil, false
		}
		// Each key is judged by its actual value, so a string held in an
		// any-typed key is checked by name too. Other keys (ints, named
		// numbers, nil) name nothing and are written as text, as JSON would;
		// if two keys give the same text, the later one gets its type
		// appended, again until the name is free, so no value is dropped.
		out := make(map[string]any, rv.Len())
		for it := rv.MapRange(); it.Next(); {
			key := it.Key()
			if key.Kind() == reflect.Interface && !key.IsNil() {
				key = key.Elem()
			}
			var k string
			sensitive := false
			if key.Kind() == reflect.String {
				k = key.String()
				sensitive = isSensitive(k)
			} else {
				k = fmt.Sprint(key.Interface())
			}
			for {
				if _, taken := out[k]; !taken {
					break
				}
				k = fmt.Sprintf("%s (%T)", k, key.Interface())
			}
			if sensitive {
				out[k] = Redacted
				continue
			}
			out[k] = sanitizedOrSelf(it.Value().Interface(), depth+1)
		}
		return out, true
	case reflect.Slice, reflect.Array:
		if rv.Kind() == reflect.Slice && rv.IsNil() {
			return nil, false
		}
		if rv.Type().Elem().Kind() == reflect.Uint8 && rv.Kind() == reflect.Slice {
			return sanitizeBytes(rv.Bytes(), depth), true // a named []byte type
		}
		out := make([]any, rv.Len())
		for i := range rv.Len() {
			out[i] = sanitizedOrSelf(rv.Index(i).Interface(), depth+1)
		}
		return out, true
	}
	return nil, false
}

// valueToAny turns a resolved slog value into plain data for the JSON
// handler: a group becomes a map with sensitive keys hidden (an inline group,
// with an empty key, is merged into its parent), any other value is cleaned
// like a top-level one.
func valueToAny(v slog.Value, depth int) any {
	if depth > maxDepth {
		return Redacted
	}
	v = v.Resolve()
	switch v.Kind() {
	case slog.KindGroup:
		out := map[string]any{}
		addGroup(out, v.Group(), depth)
		return out
	case slog.KindAny:
		return sanitizedOrSelf(v.Any(), depth+1)
	}
	return v.Any()
}

func addGroup(out map[string]any, attrs []slog.Attr, depth int) {
	for _, a := range attrs {
		val := a.Value.Resolve()
		switch {
		case isSensitive(a.Key):
			out[a.Key] = Redacted
		case a.Key == "" && val.Kind() == slog.KindGroup:
			addGroup(out, val.Group(), depth+1)
		default:
			out[a.Key] = valueToAny(val, depth+1)
		}
	}
}

func sanitizedOrSelf(v any, depth int) any {
	if s, ok := sanitizeDepth(v, depth); ok {
		return s
	}
	return v
}

// sanitizeBytes logs JSON bytes (such as a provider's response body) as
// their cleaned structure, and any other bytes as the marker.
func sanitizeBytes(b []byte, depth int) any {
	var parsed any
	if err := json.Unmarshal(b, &parsed); err != nil {
		return Redacted
	}
	return sanitizedOrSelf(parsed, depth+1)
}

// redactURL returns u as a string with its query and fragment, which can
// hold tokens and codes, replaced by the marker, and its user information, which
// holds credentials, replaced by the marker as well (SEC-13).
func redactURL(u *url.URL) string {
	c := *u
	hasUser := c.User != nil
	hasQuery := c.RawQuery != "" || c.ForceQuery
	hasFragment := c.Fragment != ""
	c.User = nil
	c.RawQuery, c.ForceQuery, c.Fragment, c.RawFragment = "", false, "", ""
	s := c.String()
	if hasUser {
		if i := strings.Index(s, "://"); i >= 0 {
			s = s[:i+3] + Redacted + "@" + s[i+3:]
		}
	}
	if hasQuery {
		s += "?" + Redacted
	}
	if hasFragment {
		s += "#" + Redacted
	}
	return s
}

// redactErrorURLs returns err's message with the URL of every *url.Error in
// its chain redacted. The HTTP client reports failures as *url.Error, whose
// message holds the full request URL.
func redactErrorURLs(err error) string {
	msg := err.Error()
	for _, ue := range urlErrors(err) {
		if u, perr := url.Parse(ue.URL); perr == nil {
			msg = strings.ReplaceAll(msg, ue.URL, redactURL(u))
		} else {
			msg = strings.ReplaceAll(msg, ue.URL, Redacted)
		}
	}
	return msg
}

// urlErrors walks err's chain, including joined errors.
func urlErrors(err error) []*url.Error {
	var found []*url.Error
	var walk func(error)
	walk = func(e error) {
		if e == nil {
			return
		}
		if ue, ok := e.(*url.Error); ok {
			found = append(found, ue)
		}
		switch w := e.(type) {
		case interface{ Unwrap() error }:
			walk(w.Unwrap())
		case interface{ Unwrap() []error }:
			for _, x := range w.Unwrap() {
				walk(x)
			}
		}
	}
	walk(err)
	return found
}

// Path returns the escaped path of u without its query, which can hold
// codes, state and ID tokens.
func Path(u *url.URL) string {
	if p := u.EscapedPath(); p != "" {
		return p
	}
	return "/"
}

// RequestLine is one line of the request log.
type RequestLine struct {
	Method   string
	Path     string // from Path: never the query
	Status   int
	Duration time.Duration
	Realm    string
	ClientIP string
}

// Request writes a request log line.
func Request(ctx context.Context, l *slog.Logger, r RequestLine) {
	l.LogAttrs(ctx, slog.LevelInfo, "request",
		slog.String("method", r.Method),
		slog.String("path", r.Path),
		slog.Int("status", r.Status),
		slog.Float64("duration_ms", float64(r.Duration.Microseconds())/1000),
		slog.String("realm", r.Realm),
		slog.String("client_ip", r.ClientIP),
	)
}

// AuditEvent mirrors a row of the audit_events table.
type AuditEvent struct {
	ID        string
	RealmID   string
	Actor     string // "admin", "system" or "provider:<name>"
	Action    string
	UserID    string // empty when the event concerns no user
	Details   map[string]any
	CreatedAt time.Time
}

// Audit writes an audit event as a log line marked audit: true.
func Audit(ctx context.Context, l *slog.Logger, e AuditEvent) {
	l.LogAttrs(ctx, slog.LevelInfo, "audit",
		slog.Bool("audit", true),
		slog.String("id", e.ID),
		slog.String("realm_id", e.RealmID),
		slog.String("actor", e.Actor),
		slog.String("action", e.Action),
		slog.String("user_id", e.UserID),
		slog.Any("details", e.Details),
		slog.Time("created_at", e.CreatedAt.UTC()),
	)
}

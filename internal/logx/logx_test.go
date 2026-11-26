package logx_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/logx"
)

var at = time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)

const secretValue = "s3cr3t-value"

func newLogger(t *testing.T) (*slog.Logger, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	return logx.New(&buf, slog.LevelDebug, clock.NewFake(at)), &buf
}

// decode returns the single JSON line written to buf.
func decode(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("want one log line, got %d: %s", len(lines), buf.String())
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &m); err != nil {
		t.Fatalf("log line is not JSON: %v: %s", err, lines[0])
	}
	return m
}

func assertNoSecret(t *testing.T, buf *bytes.Buffer) {
	t.Helper()
	if strings.Contains(buf.String(), secretValue) {
		t.Fatalf("log output contains the secret: %s", buf.String())
	}
}

var sensitiveKeys = []string{
	"token", "access_token", "refresh_token", "id_token", "id_token_hint", "code",
	"code_verifier", "state", "nonce", "client_secret", "secret", "password",
	"authorization", "cookie", "set-cookie", "email",
	"emails", "login_hint",
	// case does not matter, and the suffixes _token, _secret, _password,
	// _email, _emails, _key, _code, _hint, _authorization and _cookie are
	// sensitive too
	"Authorization", "EMAIL", "provider_refresh_token", "apple_client_secret", "admin_password", "user_email",
	"github_emails", "signing_key", "api_key", "auth_code", "logout_hint",
	// header names with dashes, and camelCase from decoded provider JSON
	"X-Auth-Token", "Proxy-Authorization", "Set-Cookie", "X-Session-Cookie",
	"accessToken", "idToken", "IDToken", "refreshToken", "clientSecret", "userEmail", "apiKey", "authCode",
	// one trailing s is ignored, and dots and spaces count as underscores
	"tokens", "cookies", "secrets", "passwords", "codes", "states", "nonces", "api_keys", "accessTokens",
	"user.email", "Access Token",
	// the DPoP proof key, and the DPoP header as net/http keeps it (SEC-13)
	"dpop", "Dpop", "dpops",
	// every other spelling of the DPoP header and key
	"DPoP", "DPOP", "d-po-p",
}

// shapes are the ways a sensitive key can reach the logger.
var shapes = map[string]func(l *slog.Logger, key string){
	"top level":          func(l *slog.Logger, key string) { l.Info("m", key, secretValue) },
	"With":               func(l *slog.Logger, key string) { l.With(key, secretValue).Info("m") },
	"in Group":           func(l *slog.Logger, key string) { l.Info("m", slog.Group("g", slog.Group("h", key, secretValue))) },
	"in WithGroup":       func(l *slog.Logger, key string) { l.WithGroup("req").Info("m", key, secretValue) },
	"in LogValuer":       func(l *slog.Logger, key string) { l.Info("m", "v", valuer{slog.String(key, secretValue)}) },
	"names a Group":      func(l *slog.Logger, key string) { l.Info("m", slog.Group(key, "value", secretValue)) },
	"names a LogValuer":  func(l *slog.Logger, key string) { l.Info("m", key, valuer{slog.String("raw", secretValue)}) },
	"names a WithGroup":  func(l *slog.Logger, key string) { l.WithGroup(key).Info("m", "raw", secretValue) },
	"names a With group": func(l *slog.Logger, key string) { l.WithGroup(key).With("raw", secretValue).Info("m") },
	"in map": func(l *slog.Logger, key string) {
		l.Info("m", "form", map[string]any{"inner": map[string]any{key: secretValue}})
	},
	"names a map":    func(l *slog.Logger, key string) { l.Info("m", key, map[string]any{"raw": secretValue}) },
	"in string map":  func(l *slog.Logger, key string) { l.Info("m", "claims", map[string]string{key: secretValue}) },
	"in url.Values":  func(l *slog.Logger, key string) { l.Info("m", "query", url.Values{key: {secretValue}}) },
	"in http.Header": func(l *slog.Logger, key string) { l.Info("m", "header", http.Header{key: {secretValue}}) },
	"in non-canonical header map": func(l *slog.Logger, key string) {
		h := http.Header{}
		h[key] = []string{secretValue}
		l.Info("m", "header", h)
	},
	"in slice of maps":    func(l *slog.Logger, key string) { l.Info("m", "list", []any{map[string]any{key: secretValue}}) },
	"in typed map slice":  func(l *slog.Logger, key string) { l.Info("m", "list", []map[string]any{{key: secretValue}}) },
	"in string map slice": func(l *slog.Logger, key string) { l.Info("m", "list", []map[string]string{{key: secretValue}}) },
	"in slice in map": func(l *slog.Logger, key string) {
		l.Info("m", "body", map[string]any{"items": []any{map[string]any{key: secretValue}}})
	},
	"in named map":         func(l *slog.Logger, key string) { l.Info("m", "claims", claims{key: secretValue}) },
	"in map of slices":     func(l *slog.Logger, key string) { l.Info("m", "m", map[string][]string{key: {secretValue}}) },
	"in typed-key map":     func(l *slog.Logger, key string) { l.Info("m", "m", map[clientID]string{clientID(key): secretValue}) },
	"in pointer to map":    func(l *slog.Logger, key string) { l.Info("m", "m", &map[string]any{key: secretValue}) },
	"in array":             func(l *slog.Logger, key string) { l.Info("m", "a", [1]map[string]string{{key: secretValue}}) },
	"in named slice":       func(l *slog.Logger, key string) { l.Info("m", "a", claimList{{key: secretValue}}) },
	"in json.RawMessage":   func(l *slog.Logger, key string) { l.Info("m", "body", rawJSON(key)) },
	"in map with any keys": func(l *slog.Logger, key string) { l.Info("m", "cfg", map[any]any{key: secretValue}) },
	"named string in any key": func(l *slog.Logger, key string) {
		l.Info("m", "cfg", map[any]any{clientID(key): secretValue})
	},
	"LogValuer in map": func(l *slog.Logger, key string) {
		l.Info("m", "d", map[string]any{"v": valuer{slog.String(key, secretValue)}})
	},
	"LogValuer in slice": func(l *slog.Logger, key string) { l.Info("m", "d", []any{valuer{slog.String(key, secretValue)}}) },
	"LogValuer pointer in map": func(l *slog.Logger, key string) {
		l.Info("m", "d", map[string]any{"v": &valuer{slog.String(key, secretValue)}})
	},
	"LogValuer nested group in map": func(l *slog.Logger, key string) {
		l.Info("m", "d", map[string]any{"v": valuer{slog.Group("g", slog.String(key, secretValue))}})
	},
	"in JSON bytes": func(l *slog.Logger, key string) { l.Info("m", "body", []byte(rawJSON(key))) },
}

type claims map[string]any

type claimList []claims

type clientID string

func rawJSON(key string) json.RawMessage {
	k, _ := json.Marshal(key)
	return json.RawMessage(`{"items":[{` + string(k) + `:"` + secretValue + `"}]}`)
}

// valuer is a LogValuer that expands to a group.
type valuer struct{ a slog.Attr }

func (v valuer) LogValue() slog.Value { return slog.GroupValue(v.a) }

// Covers: SEC-13 (part)
func TestRedactsSensitiveKeysInEveryShape(t *testing.T) {
	for _, key := range sensitiveKeys {
		for name, logIt := range shapes {
			t.Run(key+"/"+name, func(t *testing.T) {
				l, buf := newLogger(t)
				logIt(l, key)
				assertNoSecret(t, buf)
				if !strings.Contains(buf.String(), logx.Redacted) {
					t.Fatalf("no redaction marker in %s", buf.String())
				}
			})
		}
	}
}

func TestTopLevelValueIsTheMarker(t *testing.T) {
	l, buf := newLogger(t)
	l.Info("m", "id_token", valuer{slog.String("raw", secretValue)})
	if got := decode(t, buf)["id_token"]; got != logx.Redacted {
		t.Fatalf("id_token = %v, want %q", got, logx.Redacted)
	}
}

func TestKeepsOrdinaryKeys(t *testing.T) {
	l, buf := newLogger(t)
	l.Info("m", "user_id", "u1", "client_id", "web", "path", "/main/token", "status", 200)
	m := decode(t, buf)
	for key, want := range map[string]any{"user_id": "u1", "client_id": "web", "path": "/main/token", "status": 200.0} {
		if m[key] != want {
			t.Errorf("%s = %v, want %v", key, m[key], want)
		}
	}
}

func TestMapsKeepOrdinaryValues(t *testing.T) {
	l, buf := newLogger(t)
	l.Info("m", "query", url.Values{"client_id": {"web"}, "code": {secretValue}})
	q, _ := decode(t, buf)["query"].(map[string]any)
	if got, _ := q["client_id"].([]any); len(got) != 1 || got[0] != "web" {
		t.Fatalf("query.client_id = %v, want [web]", q["client_id"])
	}
	if q["code"] != logx.Redacted {
		t.Fatalf("query.code = %v, want %q", q["code"], logx.Redacted)
	}
}

func TestTimeComesFromTheClock(t *testing.T) {
	l, buf := newLogger(t)
	l.Info("m")
	if got := decode(t, buf)["time"]; got != "2026-10-25T12:00:00Z" {
		t.Fatalf("time = %v, want the fake clock's instant", got)
	}
}

func TestLevel(t *testing.T) {
	var buf bytes.Buffer
	l := logx.New(&buf, slog.LevelWarn, clock.NewFake(at))
	l.Info("hidden")
	l.Warn("shown")
	if strings.Contains(buf.String(), "hidden") || !strings.Contains(buf.String(), "shown") {
		t.Fatalf("level filtering wrong: %s", buf.String())
	}
}

// Covers: SEC-13 (part)
func TestPathDropsQuery(t *testing.T) {
	for raw, want := range map[string]string{
		"https://auth.example.com/main/callback/google?code=x&state=y": "/main/callback/google",
		"https://auth.example.com/a%20b?x=1":                           "/a%20b",
		"https://auth.example.com":                                     "/",
	} {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if got := logx.Path(u); got != want {
			t.Errorf("Path(%s) = %q, want %q", raw, got, want)
		}
	}
}

func TestRequestLine(t *testing.T) {
	l, buf := newLogger(t)
	logx.Request(context.Background(), l, logx.RequestLine{
		Method: "POST", Path: "/main/token", Status: 400, Duration: 1500 * time.Microsecond,
		Realm: "main", ClientIP: "203.0.113.7",
	})
	m := decode(t, buf)
	for key, want := range map[string]any{
		"msg": "request", "method": "POST", "path": "/main/token", "status": 400.0,
		"duration_ms": 1.5, "realm": "main", "client_ip": "203.0.113.7",
	} {
		if m[key] != want {
			t.Errorf("%s = %v, want %v", key, m[key], want)
		}
	}
}

// Covers: SEC-13 (part)
func TestAuditLine(t *testing.T) {
	l, buf := newLogger(t)
	logx.Audit(context.Background(), l, logx.AuditEvent{
		ID: "01JAUDIT", RealmID: "main", Actor: "provider:apple", Action: "user.delete", UserID: "u1",
		Details:   map[string]any{"reason": "account-delete", "email": secretValue},
		CreatedAt: at,
	})
	assertNoSecret(t, buf)
	m := decode(t, buf)
	for key, want := range map[string]any{
		"msg": "audit", "audit": true, "id": "01JAUDIT", "realm_id": "main", "actor": "provider:apple",
		"action": "user.delete", "user_id": "u1", "created_at": "2026-10-25T12:00:00Z",
	} {
		if m[key] != want {
			t.Errorf("%s = %v, want %v", key, m[key], want)
		}
	}
	d, _ := m["details"].(map[string]any)
	if d["reason"] != "account-delete" || d["email"] != logx.Redacted {
		t.Errorf("details = %v, want reason kept and email redacted", d)
	}
}

// Covers: SEC-13 (part)
func TestURLsLoseQueryAndFragment(t *testing.T) {
	u, err := url.Parse("https://graph.example.com/me?access_token=" + secretValue + "&fields=id#code=" + secretValue)
	if err != nil {
		t.Fatal(err)
	}
	const want = "https://graph.example.com/me?[redacted]#[redacted]"
	for name, v := range map[string]any{"*url.URL": u, "url.URL": *u} {
		t.Run(name, func(t *testing.T) {
			l, buf := newLogger(t)
			l.Info("m", "target", v)
			assertNoSecret(t, buf)
			if got := decode(t, buf)["target"]; got != want {
				t.Fatalf("target = %v, want %q", got, want)
			}
		})
	}
}

// Covers: SEC-13 (part)
func TestErrorsFromOutgoingCallsLoseQuery(t *testing.T) {
	urlErr := &url.Error{
		Op:  "Get",
		URL: "https://graph.example.com/me?access_token=" + secretValue,
		Err: context.DeadlineExceeded,
	}
	const want = `Get "https://graph.example.com/me?[redacted]": context deadline exceeded`
	for name, err := range map[string]error{
		"*url.Error":         urlErr,
		"wrapped *url.Error": fmt.Errorf("facebook: %w", urlErr),
	} {
		t.Run(name, func(t *testing.T) {
			l, buf := newLogger(t)
			l.Info("m", "err", err)
			assertNoSecret(t, buf)
			if got, _ := decode(t, buf)["err"].(string); !strings.HasSuffix(got, want) {
				t.Fatalf("err = %q, want it to end with %q", got, want)
			}
		})
	}

	// An error without a URL is logged as its message.
	l, buf := newLogger(t)
	l.Info("m", "err", errors.New("plain failure"))
	if got := decode(t, buf)["err"]; got != "plain failure" {
		t.Fatalf("err = %v, want the message", got)
	}
}

func TestURLAndErrorEdgeCases(t *testing.T) {
	plain, _ := url.Parse("https://auth.example.com/main/token")
	userOnly := &url.URL{Scheme: "https", User: url.User("alice"), Host: "db.example.com", Path: "/x"}
	withPassword, _ := url.Parse("https://user:" + secretValue + "@db.example.com/x")
	bad := &url.Error{Op: "Get", URL: "http://[::1%" + secretValue, Err: errors.New("bad host")}
	first := &url.Error{Op: "Get", URL: "https://a.example.com/?code=" + secretValue, Err: errors.New("x")}
	second := &url.Error{Op: "Post", URL: "https://b.example.com/?state=" + secretValue, Err: errors.New("y")}

	cases := []struct {
		name string
		v    any
		want string
	}{
		{"no query is unchanged", plain, "https://auth.example.com/main/token"},
		{"credentials hidden", withPassword, "https://" + logx.Redacted + "@db.example.com/x"},
		{"username alone hidden", userOnly, "https://" + logx.Redacted + "@db.example.com/x"},
		{"unparsable URL hidden whole", bad, `Get "` + logx.Redacted + `": bad host`},
		{"joined errors", errors.Join(first, second),
			`Get "https://a.example.com/?[redacted]": x` + "\n" + `Post "https://b.example.com/?[redacted]": y`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			l, buf := newLogger(t)
			l.Info("m", "v", c.v)
			assertNoSecret(t, buf)
			if got := decode(t, buf)["v"]; got != c.want {
				t.Fatalf("v = %q, want %q", got, c.want)
			}
		})
	}
}

func TestKeyNormalization(t *testing.T) {
	// Keys that only look similar stay visible.
	l, buf := newLogger(t)
	l.Info("m", "status", 200, "client_id", "web", "kid", "main-2026", "token_count", 3, "Content-Type", "x",
		"access", "address", "process", "redirect_uris", "ids", "hints")
	m := decode(t, buf)
	for _, key := range []string{"status", "client_id", "kid", "token_count", "Content-Type", "access", "address", "process", "redirect_uris", "ids", "hints"} {
		if m[key] == logx.Redacted {
			t.Errorf("%s was redacted", key)
		}
	}
}

func TestSlicesKeepOrdinaryValues(t *testing.T) {
	l, buf := newLogger(t)
	l.Info("m", "list", []any{"plain", map[string]any{"id": "u1", "email": secretValue}, 3})
	assertNoSecret(t, buf)
	list, _ := decode(t, buf)["list"].([]any)
	if len(list) != 3 || list[0] != "plain" || list[2] != 3.0 {
		t.Fatalf("list = %v", list)
	}
	if item, _ := list[1].(map[string]any); item["id"] != "u1" || item["email"] != logx.Redacted {
		t.Fatalf("list[1] = %v", list[1])
	}
}

func TestRawBytes(t *testing.T) {
	cases := []struct {
		name string
		v    any
		want any
	}{
		{"JSON kept as structure", json.RawMessage(`{"id":"u1","access_token":"x"}`), map[string]any{"id": "u1", "access_token": logx.Redacted}},
		{"JSON array", json.RawMessage(`[1,"a"]`), []any{1.0, "a"}},
		{"not JSON hidden whole", json.RawMessage("access_token=" + secretValue), logx.Redacted},
		{"plain bytes hidden whole", []byte("code=" + secretValue), logx.Redacted},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			l, buf := newLogger(t)
			l.Info("m", "v", c.v)
			assertNoSecret(t, buf)
			got, _ := json.Marshal(decode(t, buf)["v"])
			want, _ := json.Marshal(c.want)
			if string(got) != string(want) {
				t.Fatalf("v = %s, want %s", got, want)
			}
		})
	}
}

// selfRef's LogValue returns a group that contains selfRef again, like a
// tree node that logs its parent.
type selfRef struct{}

func (selfRef) LogValue() slog.Value { return slog.GroupValue(slog.Any("self", selfRef{})) }

// A LogValue that refers to itself is cut off with the marker instead of
// overflowing the stack (which would kill the process), at the top level
// and inside containers.
func TestSelfReferencingLogValue(t *testing.T) {
	cases := map[string]func(l *slog.Logger){
		"top level": func(l *slog.Logger) { l.Info("m", "v", selfRef{}) },
		"in group":  func(l *slog.Logger) { l.Info("m", slog.Group("g", "v", selfRef{})) },
		"With":      func(l *slog.Logger) { l.With("v", selfRef{}).Info("m") },
		"in map":    func(l *slog.Logger) { l.Info("m", "v", map[string]any{"node": selfRef{}}) },
		"in slice":  func(l *slog.Logger) { l.Info("m", "v", []any{selfRef{}}) },
	}
	for name, logIt := range cases {
		t.Run(name, func(t *testing.T) {
			l, buf := newLogger(t)
			logIt(l)
			if !strings.Contains(buf.String(), logx.Redacted) {
				t.Fatalf("no marker where the cycle was cut: %.200s", buf.String())
			}
		})
	}
}

func TestNilAndCycles(t *testing.T) {
	var nilMap map[string]any
	var nilPtr *map[string]any
	cyclic := map[string]any{"id": "u1"}
	cyclic["self"] = cyclic

	l, buf := newLogger(t)
	l.Info("m", "a", nilMap, "b", nilPtr, "c", cyclic)
	m := decode(t, buf)
	if m["a"] != nil || m["b"] != nil {
		t.Errorf("nil values: a = %v, b = %v, want null", m["a"], m["b"])
	}
	if !strings.Contains(buf.String(), logx.Redacted) {
		t.Errorf("a cyclic map is not cut off with the marker: %s", buf.String())
	}
}

// identity mirrors provider.Identity: its LogValue shows only the subject,
// and the struct's other fields must never reach the log, also when the
// value sits inside a map or slice (for example in audit details).
type identity struct {
	Subject      string
	Email        string
	RefreshToken string
}

func (i identity) LogValue() slog.Value { return slog.GroupValue(slog.String("subject", i.Subject)) }

// Covers: SEC-13 (part)
func TestLogValuerInsideContainers(t *testing.T) {
	id := identity{Subject: "s1", Email: "leak@example.com", RefreshToken: secretValue}
	cases := map[string]func(l *slog.Logger){
		"direct":         func(l *slog.Logger) { l.Info("m", "v", id) },
		"in map":         func(l *slog.Logger) { l.Info("m", "v", map[string]any{"identity": id}) },
		"in slice":       func(l *slog.Logger) { l.Info("m", "v", []identity{id}) },
		"pointer in map": func(l *slog.Logger) { l.Info("m", "v", map[string]any{"identity": &id}) },
		"audit details": func(l *slog.Logger) {
			logx.Audit(context.Background(), l, logx.AuditEvent{Action: "link", Details: map[string]any{"identity": id}})
		},
	}
	for name, logIt := range cases {
		t.Run(name, func(t *testing.T) {
			l, buf := newLogger(t)
			logIt(l)
			out := buf.String()
			if strings.Contains(out, secretValue) || strings.Contains(out, "leak@example.com") {
				t.Fatalf("struct fields leaked: %s", out)
			}
			if !strings.Contains(out, `"subject":"s1"`) {
				t.Fatalf("LogValue was not used: %s", out)
			}
		})
	}
}

func TestLogValuerScalarAndInlineGroup(t *testing.T) {
	l, buf := newLogger(t)
	l.Info("m", "v", map[string]any{
		"n":      valuer{slog.Int("count", 2)},
		"scalar": scalarValuer{},
		"inline": valuer{slog.Group("", slog.String("a", "1"), slog.String("password", secretValue))},
	})
	assertNoSecret(t, buf)
	v, _ := decode(t, buf)["v"].(map[string]any)
	if n, _ := v["n"].(map[string]any); n["count"] != 2.0 {
		t.Errorf("v.n = %v", v["n"])
	}
	if v["scalar"] != "plain" {
		t.Errorf("v.scalar = %v, want plain", v["scalar"])
	}
	if in, _ := v["inline"].(map[string]any); in["a"] != "1" || in["password"] != logx.Redacted {
		t.Errorf("v.inline = %v, want a=1 and the password hidden", v["inline"])
	}
}

type scalarValuer struct{}

func (scalarValuer) LogValue() slog.Value { return slog.StringValue("plain") }

type slot int

// Covers: SEC-13 (part)
func TestMapsWithOtherKeysHaveTheirValuesCleaned(t *testing.T) {
	id := identity{Subject: "s1", Email: "leak@example.com", RefreshToken: secretValue}
	cases := map[string]any{
		"int key, LogValuer value":  map[int]any{1: id},
		"int key, map value":        map[int]map[string]string{1: {"email": secretValue}},
		"named key, slice value":    map[slot][]any{2: {map[string]any{"refresh_token": secretValue}}},
		"bool key, JSON bytes":      map[bool]json.RawMessage{true: json.RawMessage(`{"access_token":"` + secretValue + `"}`)},
		"int key inside string map": map[string]any{"by_slot": map[int]any{3: id}},
	}
	for name, v := range cases {
		t.Run(name, func(t *testing.T) {
			l, buf := newLogger(t)
			l.Info("m", "v", v)
			out := buf.String()
			if strings.Contains(out, secretValue) || strings.Contains(out, "leak@example.com") {
				t.Fatalf("leaked: %s", out)
			}
		})
	}

	// Keys keep their text form and ordinary values stay visible.
	l, buf := newLogger(t)
	l.Info("m", "v", map[int]string{7: "seven"}, "nil", map[int]any(nil))
	m := decode(t, buf)
	if v, _ := m["v"].(map[string]any); v["7"] != "seven" {
		t.Errorf("v = %v, want {7: seven}", m["v"])
	}
	if m["nil"] != nil {
		t.Errorf("nil map logged as %v, want null", m["nil"])
	}
}

// With keys of type any, 1 and "1" have the same text; both values are kept.
func TestCollidingKeysAreKept(t *testing.T) {
	l, buf := newLogger(t)
	l.Info("m", "v", map[any]any{1: "int one", "1": "string one", nil: "nil key"})
	v, _ := decode(t, buf)["v"].(map[string]any)
	got := map[string]bool{}
	for _, x := range v {
		got[fmt.Sprint(x)] = true
	}
	for _, want := range []string{"int one", "string one", "nil key"} {
		if !got[want] {
			t.Errorf("value %q missing from %v", want, v)
		}
	}
	if len(v) != 3 {
		t.Errorf("v has %d keys, want 3: %v", len(v), v)
	}
}

// A renamed key can itself be taken by a literal key; renaming continues
// until the name is free, whatever the map's iteration order.
func TestRenamedKeyCanCollideAgain(t *testing.T) {
	for i := 0; i < 50; i++ {
		l, buf := newLogger(t)
		l.Info("m", "v", map[any]any{1: "a", "1": "b", "1 (string)": "c", "1 (int)": "d"})
		v, _ := decode(t, buf)["v"].(map[string]any)
		got := map[string]bool{}
		for _, x := range v {
			got[fmt.Sprint(x)] = true
		}
		if len(v) != 4 || !got["a"] || !got["b"] || !got["c"] || !got["d"] {
			t.Fatalf("run %d: v = %v, want all four values", i, v)
		}
	}
}

// A level changed on a LevelVar applies to the logger at once.
func TestNewLeveledFollowsALevelVar(t *testing.T) {
	var buf bytes.Buffer
	level := new(slog.LevelVar) // info
	log := logx.NewLeveled(&buf, level, clock.NewFake(at))
	ctx := context.Background()
	log.DebugContext(ctx, "hidden at info")
	if buf.Len() != 0 {
		t.Fatalf("a debug line at info: %s", buf.String())
	}
	level.Set(slog.LevelDebug)
	log.DebugContext(ctx, "shown at debug")
	if !strings.Contains(buf.String(), "shown at debug") {
		t.Fatalf("no debug line after the level changed: %q", buf.String())
	}
	buf.Reset()
	level.Set(slog.LevelError)
	log.WarnContext(ctx, "hidden at error")
	log.ErrorContext(ctx, "shown at error")
	if strings.Contains(buf.String(), "hidden at error") || !strings.Contains(buf.String(), "shown at error") {
		t.Fatalf("level error: %q", buf.String())
	}
}

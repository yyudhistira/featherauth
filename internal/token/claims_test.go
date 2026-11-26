package token_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/token"
)

// xorshift is a small deterministic generator, so the property test is
// repeatable and needs neither math/rand nor the clock.
type xorshift uint64

func (x *xorshift) next() uint64 {
	v := uint64(*x)
	v ^= v << 13
	v ^= v >> 7
	v ^= v << 17
	*x = xorshift(v)
	return v
}

func (x *xorshift) intn(n int) int { return int(x.next() % uint64(n)) }

// randomString mixes ASCII (with the four special characters, quotes,
// backslash and control characters) and non-ASCII runes of every width.
func (x *xorshift) randomString() string {
	special := []rune{'>', '?', '~', 0x7f, '"', '\\', '\n', 0, '<', '&', '/', '-', '_'}
	wide := []rune{0xe9, 0x4e16, 0x2028, 0x1f600, 0x10ffff, 0xfffd}
	var b strings.Builder
	for i, n := 0, x.intn(24); i < n; i++ {
		switch x.intn(4) {
		case 0:
			b.WriteRune(special[x.intn(len(special))])
		case 1:
			b.WriteRune(wide[x.intn(len(wide))])
		default:
			b.WriteRune(rune('a' + x.intn(26)))
		}
	}
	return b.String()
}

// Covers: FR-22 (part)
// Acceptance: ASCII payload (part)
func TestEncodeClaimsBase64Property(t *testing.T) {
	x := xorshift(0x9e3779b97f4a7c15)
	for i := 0; i < 2000; i++ {
		exp := int64(x.intn(2000000000))
		list := []any{x.randomString(), x.randomString()}
		nestedKey, nestedVal := x.randomString(), x.randomString()
		claims := map[string]any{
			x.randomString(): x.randomString(),
			"name":           x.randomString(),
			"list":           list,
			"nested":         map[string]any{nestedKey: nestedVal},
			"exp":            time.Unix(exp, 0).UTC(),
		}
		// What a JSON decoder must read back: the input, with the time as a number.
		want := map[string]any{"exp": float64(exp), "list": list, "nested": map[string]any{nestedKey: nestedVal}}
		for k, v := range claims {
			if _, ok := want[k]; !ok {
				want[k] = v
			}
		}
		want["exp"], want["list"], want["nested"] = float64(exp), list, map[string]any{nestedKey: nestedVal}
		raw, err := token.EncodeClaims(claims)
		if err != nil {
			t.Fatalf("EncodeClaims: %v", err)
		}
		for _, c := range raw {
			if c >= 0x7f || (c < 0x20) {
				t.Fatalf("payload %q has byte %#x that is not printable ASCII", raw, c)
			}
		}
		url := base64.RawURLEncoding.EncodeToString(raw)
		if strings.ContainsAny(url, "-_") {
			t.Fatalf("base64url of %q contains - or _: %s", raw, url)
		}
		std := url
		if pad := len(std) % 4; pad != 0 {
			std += strings.Repeat("=", 4-pad)
		}
		dec, err := base64.StdEncoding.DecodeString(std)
		if err != nil {
			t.Fatalf("plain base64 decode: %v", err)
		}
		if !bytes.Equal(dec, raw) {
			t.Fatalf("plain base64 differs: %q vs %q", dec, raw)
		}
		var got map[string]any
		if err := json.Unmarshal(dec, &got); err != nil {
			t.Fatalf("payload is not JSON: %v", err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("round trip differs: got %v, want %v", got, want)
		}
	}
}

func TestEncodeClaims(t *testing.T) {
	tests := []struct {
		name string
		in   map[string]any
		want string
	}{
		{"sorted keys", map[string]any{"b": 1, "a": "x", "c": true}, `{"a":"x","b":1,"c":true}`},
		{"empty", map[string]any{}, `{}`},
		{"nil map", nil, `{}`},
		{"the four characters", map[string]any{"s": ">?~\x7f"}, `{"s":"\u003e\u003f\u007e\u007f"}`},
		{"no other ASCII escaping", map[string]any{"s": "<&/-_ '"}, `{"s":"<&/-_ '"}`},
		{"quote and backslash", map[string]any{"s": "a\"b\\c"}, `{"s":"a\"b\\c"}`},
		{"control", map[string]any{"s": "a\nb\x01"}, `{"s":"a\nb\u0001"}`},
		{"non-ASCII", map[string]any{"s": "é世"}, `{"s":"\u00e9\u4e16"}`},
		{"astral as surrogate pair", map[string]any{"s": "😀"}, `{"s":"\ud83d\ude00"}`},
		{"non-ASCII key", map[string]any{"é>": 1}, `{"\u00e9\u003e":1}`},
		{"time as integer", map[string]any{"exp": time.Unix(1700000000, 999).UTC()}, `{"exp":1700000000}`},
		{"nested time and escapes", map[string]any{"l": []any{time.Unix(5, 0), "~"}, "m": map[string]any{"t": time.Unix(6, 0)}}, `{"l":[5,"\u007e"],"m":{"t":6}}`},
		{"string slice", map[string]any{"o": []string{"a?", "b"}}, `{"o":["a\u003f","b"]}`},
		{"nil value", map[string]any{"n": nil}, `{"n":null}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := token.EncodeClaims(tt.in)
			if err != nil {
				t.Fatalf("EncodeClaims: %v", err)
			}
			if string(got) != tt.want {
				t.Fatalf("got %s, want %s", got, tt.want)
			}
		})
	}
}

func TestEncodeClaimsInvalidUTF8(t *testing.T) {
	got, err := token.EncodeClaims(map[string]any{"s": "a\xffb"})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"s":"a\ufffdb"}`; string(got) != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestEncodeClaimsUnsupportedValue(t *testing.T) {
	if _, err := token.EncodeClaims(map[string]any{"f": func() {}}); err == nil {
		t.Fatal("expected an error for a value that cannot be encoded")
	}
	if _, err := token.EncodeClaims(map[string]any{"l": []any{func() {}}}); err == nil {
		t.Fatal("expected an error for a nested value that cannot be encoded")
	}
}

func FuzzEncodeClaims(f *testing.F) {
	for _, s := range []string{"", "plain", ">?~\x7f", "é世😀", "a\"b\\c\n\x00", "\xff\xfe", "  ", "-_"} {
		f.Add(s, s, int64(0))
	}
	f.Add("name", "Zoë >?~", int64(1700000000))
	f.Fuzz(func(t *testing.T, key, val string, sec int64) {
		claims := map[string]any{key: val, "exp": time.Unix(sec, 0).UTC(), "l": []any{val}}
		raw, err := token.EncodeClaims(claims)
		if err != nil {
			t.Fatalf("EncodeClaims: %v", err)
		}
		for _, c := range raw {
			if c < 0x20 || c >= 0x7f || c == '>' || c == '?' || c == '~' {
				t.Fatalf("payload %q has unescaped byte %#x", raw, c)
			}
		}
		var got map[string]any
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatalf("payload is not JSON: %v", err)
		}
		if _, ok := got["exp"].(float64); !ok {
			t.Fatalf("exp is not a number in %s", raw)
		}
		url := base64.RawURLEncoding.EncodeToString(raw)
		if strings.ContainsAny(url, "-_") {
			t.Fatalf("base64url of %q contains - or _", raw)
		}
	})
}

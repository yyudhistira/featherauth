package token

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"
	"unicode/utf16"
)

// EncodeClaims encodes a claim set as the JSON payload of a token: keys
// sorted, times as integer Unix seconds, and ASCII only. Non-ASCII text and
// the ASCII characters '>', '?', '~' and DEL are written as \uXXXX, so the
// base64url form of the payload contains no '-' or '_' and a consumer that
// decodes it with plain base64 reads the same JSON. No other ASCII character
// is escaped beyond what JSON requires. A time.Time is converted only inside
// map[string]any and []any values, not inside other container types. Signing signs exactly these bytes.
func EncodeClaims(m map[string]any) ([]byte, error) {
	if m == nil {
		m = map[string]any{}
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(normalizeClaim(m)); err != nil {
		return nil, fmt.Errorf("encode claims: %w", err)
	}
	return escapeJSON(bytes.TrimRight(buf.Bytes(), "\n")), nil
}

// normalizeClaim replaces every time.Time, at any depth of the maps and
// slices a claim set is built from, with its Unix time in seconds.
func normalizeClaim(v any) any {
	switch x := v.(type) {
	case time.Time:
		return x.Unix()
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k] = normalizeClaim(e)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = normalizeClaim(e)
		}
		return out
	}
	return v
}

// escapeJSON rewrites encoded JSON so that it is ASCII only and the four
// characters are escaped. Those characters occur only inside strings, since
// the encoder emits nothing else outside them, and the encoder only emits
// valid UTF-8.
func escapeJSON(in []byte) []byte {
	out := make([]byte, 0, len(in))
	for _, r := range string(in) {
		switch {
		case r == '>' || r == '?' || r == '~' || r == 0x7f || (r >= 0x80 && r <= 0xffff):
			out = fmt.Appendf(out, `\u%04x`, r)
		case r > 0xffff:
			hi, lo := utf16.EncodeRune(r)
			out = fmt.Appendf(out, `\u%04x\u%04x`, hi, lo)
		default:
			out = append(out, byte(r))
		}
	}
	return out
}

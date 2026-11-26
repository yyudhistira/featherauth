package mockidp

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
)

// SignedRequest returns a Meta signed_request for payload: the base64url
// HMAC-SHA256 of the payload part under secret, a dot, and the payload part,
// which is the base64url of the payload's JSON.
func SignedRequest(secret string, payload map[string]any) string {
	b, err := json.Marshal(payload)
	if err != nil {
		panic(err) // a test passes a plain map
	}
	return SignedPart(secret, base64.RawURLEncoding.EncodeToString(b))
}

// SignedPart signs a payload part that is already encoded, as it is, and
// returns "<signature>.<part>".
func SignedPart(secret, part string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(part))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)) + "." + part
}

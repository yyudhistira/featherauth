package provider

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/yyudhistira/featherauth/internal/secure"
)

// Meta's signed_request limits (SEC-33).
const (
	metaMaxAge   = time.Hour
	metaMaxAhead = 5 * time.Minute
)

var (
	_ EventReceiver  = (*Facebook)(nil)
	_ EventConfirmer = (*Facebook)(nil)
)

// ConfirmsEvents implements EventConfirmer: Meta's data-deletion callback
// wants a confirmation code and a status URL in the answer.
func (*Facebook) ConfirmsEvents() bool { return true }

// ParseEvent implements EventReceiver for Meta's data-deletion callback. body
// is the form Meta posted, with exactly one signed_request: two base64url parts
// joined by a dot, the HMAC-SHA256 signature of the payload part (exactly as
// received) under the app secret, and the JSON payload. The signature is
// checked, in constant time, before the payload is read; the payload's
// algorithm must be HMAC-SHA256, its issued_at at most an hour old and at most
// five minutes ahead, and its user_id a non-empty string. The event is an
// account-delete of that user. Its ID is the payload part, which a repeat
// carries again, and it is kept until an hour after the later of issued_at and
// now (SEC-33). Every failure is ErrInvalidEvent, and no error text holds a
// part of the request or the secret.
func (f *Facebook) ParseEvent(_ context.Context, body []byte) ([]Event, error) {
	ev, err := f.parseEvent(body)
	if err != nil {
		return nil, err
	}
	return []Event{ev}, nil
}

// parseEvent reads the signed_request; see ParseEvent.
func (f *Facebook) parseEvent(body []byte) (Event, error) {
	invalid := func(why string) (Event, error) {
		return Event{}, fmt.Errorf("%w: %s", ErrInvalidEvent, why)
	}
	form, err := url.ParseQuery(string(body))
	if err != nil {
		return invalid("the body is not a form")
	}
	if len(form["signed_request"]) != 1 {
		return invalid("the body must hold exactly one signed_request")
	}
	sigPart, payloadPart, ok := strings.Cut(form.Get("signed_request"), ".")
	if !ok || sigPart == "" || payloadPart == "" || strings.Contains(payloadPart, ".") {
		return invalid("the signed_request must be two parts")
	}
	sig, err := decodeBase64URL(sigPart)
	if err != nil {
		return invalid("the signature is not base64url")
	}
	mac := hmac.New(sha256.New, []byte(f.clientSecret))
	mac.Write([]byte(payloadPart))
	if !secure.Equal(string(sig), string(mac.Sum(nil))) {
		return invalid("the signature does not match")
	}
	raw, err := decodeBase64URL(payloadPart)
	if err != nil {
		return invalid("the payload is not base64url")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return invalid("the payload is not a JSON object")
	}
	var algorithm, userID string
	if json.Unmarshal(fields["algorithm"], &algorithm) != nil || algorithm != "HMAC-SHA256" {
		return invalid("the algorithm is not HMAC-SHA256")
	}
	var issued json.Number
	if r := fields["issued_at"]; len(r) == 0 || (r[0] != '-' && (r[0] < '0' || r[0] > '9')) || json.Unmarshal(r, &issued) != nil {
		return invalid("the payload has no issued_at")
	}
	at, err := numericDate(&issued)
	if err != nil {
		return invalid("the payload's issued_at is not a time")
	}
	now := f.clock.Now()
	if now.Sub(at) > metaMaxAge || at.Sub(now) > metaMaxAhead {
		return invalid("the request was issued more than an hour ago or more than five minutes ahead")
	}
	if json.Unmarshal(fields["user_id"], &userID) != nil || userID == "" {
		return invalid("the payload has no user_id")
	}
	from := now
	if at.After(now) {
		from = at
	}
	return Event{Set: EventSetMeta, Type: "account-delete", Subject: userID, ID: payloadPart, Expires: from.Add(metaMaxAge)}, nil
}

// decodeBase64URL decodes base64url with or without the = padding. Go's
// decoders skip a carriage return and a line feed; a part holding one is not
// canonical and is refused, and so is a last character with unused bits set
// (the strict decoders).
func decodeBase64URL(s string) ([]byte, error) {
	if strings.ContainsAny(s, "\r\n") {
		return nil, base64.CorruptInputError(strings.IndexAny(s, "\r\n"))
	}
	if strings.HasSuffix(s, "=") {
		return base64.URLEncoding.Strict().DecodeString(s)
	}
	return base64.RawURLEncoding.Strict().DecodeString(s)
}

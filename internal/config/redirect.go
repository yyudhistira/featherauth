package config

import (
	"fmt"
	"net/url"
	"strings"
)

// ValidateRedirectURI checks a redirect or post-logout URI of a client of
// type t (FR-32). It returns nil for an accepted URI and otherwise an error
// diagnostic with the reason only; the caller sets File, Line and Field.
func ValidateRedirectURI(raw string, t ClientType) *Diagnostic {
	if raw == "" {
		return uriError("must not be empty")
	}
	u, err := url.Parse(raw)
	switch {
	case err != nil:
		return uriError("%q is not a valid URI", raw)
	case u.Scheme == "":
		return uriError("%q must be an absolute URI with a scheme", raw)
	case u.Fragment != "" || strings.Contains(raw, "#"):
		return uriError("%q must not have a fragment (RFC 6749 section 3.1.2)", raw)
	case strings.Contains(raw, "*"):
		return uriError("%q must not contain a wildcard; redirect URIs match exactly", raw)
	}
	switch u.Scheme {
	case "javascript", "data", "file":
		return uriError("%q: the scheme %s is not allowed", raw, u.Scheme)
	case "https":
		if u.Host == "" {
			return uriError("%q must have a host", raw)
		}
	case "http":
		host := u.Hostname()
		switch {
		case host == "127.0.0.1" || host == "::1":
			if t == Confidential {
				return uriError("%q is a loopback URI, which only a public client may use (RFC 8252 section 7.3)", raw)
			}
		case strings.EqualFold(host, "localhost"):
			return uriError("%q: http is allowed only for 127.0.0.1 and [::1]; use http://127.0.0.1 instead of localhost (RFC 8252 section 8.3)", raw)
		default:
			return uriError("%q: http is allowed only for 127.0.0.1 and [::1]; use https", raw)
		}
	}
	return nil
}

// ValidateWebOrigin checks a web_origins entry: a bare origin, scheme and
// host with an optional port and nothing else. It returns nil or an error
// diagnostic with the reason only.
func ValidateWebOrigin(raw string) *Diagnostic {
	if raw == "" {
		return uriError("must not be empty")
	}
	if strings.Contains(raw, "*") {
		return uriError("%q must not contain a wildcard; list each origin", raw)
	}
	u, err := url.Parse(raw)
	switch {
	case err != nil:
		return uriError("%q is not a valid origin", raw)
	case u.Scheme == "" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(raw, "#"):
		return uriError("%q must be a bare origin such as https://app.example.com: scheme, host and optional port, with no path, query or fragment", raw)
	}
	return nil
}

func uriError(format string, args ...any) *Diagnostic {
	return &Diagnostic{Severity: Error, Message: fmt.Sprintf(format, args...)}
}

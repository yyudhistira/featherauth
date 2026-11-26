package oidc_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yyudhistira/featherauth/internal/oidc"
	"github.com/yyudhistira/featherauth/internal/token"
)

func TestErrorImplementsError(t *testing.T) {
	var err error = oidc.Error{Code: "invalid_grant", Description: "code expired", Status: 400}
	var e oidc.Error
	if !errors.As(err, &e) || e.Code != "invalid_grant" {
		t.Errorf("errors.As: %+v", e)
	}
	if err.Error() == "" {
		t.Error("empty error text")
	}
}

func TestWriteJSONError(t *testing.T) {
	tests := []struct {
		name   string
		e      oidc.Error
		status int
		body   string
	}{
		{"all fields", oidc.Error{Code: "invalid_request", Description: "code_verifier is malformed", Status: 400},
			400, `{"error":"invalid_request","error_description":"code_verifier is malformed"}`},
		{"401", oidc.Error{Code: "invalid_client", Description: "unknown client", Status: 401},
			401, `{"error":"invalid_client","error_description":"unknown client"}`},
		{"503", oidc.Error{Code: "temporarily_unavailable", Description: "try again", Status: 503},
			503, `{"error":"temporarily_unavailable","error_description":"try again"}`},
		{"status defaults to 400", oidc.Error{Code: "invalid_grant", Description: "expired"},
			400, `{"error":"invalid_grant","error_description":"expired"}`},
		{"no description", oidc.Error{Code: "unsupported_grant_type", Status: 400},
			400, `{"error":"unsupported_grant_type"}`},
		{"markup is escaped", oidc.Error{Code: "invalid_request", Description: `a "quoted" <b>&`, Status: 400},
			400, `{"error":"invalid_request","error_description":"a \"quoted\" ` + "\\u003cb\\u003e\\u0026" + `"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			oidc.WriteJSONError(rec, tt.e)
			if rec.Code != tt.status {
				t.Errorf("status %d, want %d", rec.Code, tt.status)
			}
			if got := rec.Body.String(); got != tt.body {
				t.Errorf("body %s, want %s", got, tt.body)
			}
			h := rec.Header()
			for k, v := range map[string]string{
				"Content-Type":  "application/json",
				"Cache-Control": "no-store",
				"Pragma":        "no-cache",
			} {
				if h.Get(k) != v {
					t.Errorf("%s = %q, want %q", k, h.Get(k), v)
				}
			}
			var m map[string]string
			if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
				t.Errorf("not JSON: %v", err)
			}
		})
	}
}

func TestWriteBearerError(t *testing.T) {
	tests := []struct {
		name   string
		e      oidc.Error
		params map[string]string
		status int
		header string
		body   string
	}{
		{"invalid token", oidc.Error{Code: "invalid_token", Description: "the token is expired", Status: 401}, nil,
			401, `Bearer error="invalid_token"`, `{"error":"invalid_token","error_description":"the token is expired"}`},
		{"insufficient scope", oidc.Error{Code: "insufficient_scope", Description: "client may not delete accounts", Status: 403}, nil,
			403, `Bearer error="insufficient_scope"`, `{"error":"insufficient_scope","error_description":"client may not delete accounts"}`},
		{"insufficient user authentication", oidc.Error{Code: "insufficient_user_authentication", Description: "sign in again", Status: 401},
			map[string]string{"max_age": "600"},
			401, `Bearer error="insufficient_user_authentication", max_age=600`, `{"error":"insufficient_user_authentication","error_description":"sign in again"}`},
		{"status defaults to 401", oidc.Error{Code: "invalid_token"}, nil,
			401, `Bearer error="invalid_token"`, `{"error":"invalid_token"}`},
		{"other parameters are quoted and sorted", oidc.Error{Code: "invalid_token", Status: 401},
			map[string]string{"scope": `a"b\c`, "realm": "main"},
			401, `Bearer error="invalid_token", realm="main", scope="a\"b\\c"`, `{"error":"invalid_token"}`},
		{"no error code", oidc.Error{Status: 401}, nil, 401, `Bearer`, ``},
		{"no error code with a parameter", oidc.Error{Status: 401}, map[string]string{"realm": "main"}, 401, `Bearer realm="main"`, ``},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			oidc.WriteBearerError(rec, tt.e, tt.params)
			if rec.Code != tt.status {
				t.Errorf("status %d, want %d", rec.Code, tt.status)
			}
			if got := rec.Header().Get("WWW-Authenticate"); got != tt.header {
				t.Errorf("WWW-Authenticate = %s, want %s", got, tt.header)
			}
			if got := rec.Body.String(); got != tt.body {
				t.Errorf("body %s, want %s", got, tt.body)
			}
			if tt.body != "" && rec.Header().Get("Content-Type") != "application/json" {
				t.Errorf("content type %q", rec.Header().Get("Content-Type"))
			}
			if rec.Header().Get("Cache-Control") != "no-store" {
				t.Errorf("Cache-Control = %q", rec.Header().Get("Cache-Control"))
			}
		})
	}
}

func TestWriteTokenResponse(t *testing.T) {
	rec := httptest.NewRecorder()
	oidc.WriteTokenResponse(rec, &token.Grant{
		AccessToken: "at", IDToken: "idt", RefreshToken: "rt",
		ExpiresIn: 900, RefreshExpiresIn: 2592000, Scope: "openid",
	})
	if rec.Code != http.StatusOK {
		t.Errorf("status %d", rec.Code)
	}
	want := `{"access_token":"at","id_token":"idt","refresh_token":"rt","token_type":"Bearer","expires_in":900,"refresh_expires_in":2592000,"scope":"openid"}`
	if got := rec.Body.String(); got != want {
		t.Errorf("body %s\nwant %s", got, want)
	}
	h := rec.Header()
	for k, v := range map[string]string{
		"Content-Type":  "application/json",
		"Cache-Control": "no-store",
		"Pragma":        "no-cache",
	} {
		if h.Get(k) != v {
			t.Errorf("%s = %q, want %q", k, h.Get(k), v)
		}
	}
}

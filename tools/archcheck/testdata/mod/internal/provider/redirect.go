package provider

import (
	"net/http"
	"time"
)

var followsRedirects = &http.Client{Timeout: time.Second}

var refusesRedirects = &http.Client{Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}}

var nilRedirects = &http.Client{Timeout: time.Second, CheckRedirect: nil}

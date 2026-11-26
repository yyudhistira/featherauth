//go:build postgres

package store

import (
	"net/http"
	"testing"
	"time"
)

func TestPostgres(t *testing.T) {
	_ = time.Now()
	c := &http.Client{Timeout: time.Second}
	_, _ = c.Get("http://example.com")
}

//go:build ops

package loadonly

import (
	"net/http"
	"testing"
	"time"
)

func TestOps(t *testing.T) {
	c := &http.Client{Timeout: time.Second}
	_, _ = c.Get("http://example.com")
}

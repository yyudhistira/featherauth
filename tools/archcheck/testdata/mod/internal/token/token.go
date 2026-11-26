package token

import (
	"math/rand"
	"net/http"
	"time"

	"example.com/fixture/internal/clock"
)

var _ = clock.Now

func Bad() {
	_ = time.Now()
	_ = rand.Int()
	_, _ = http.Get("http://example.com")
	_ = http.DefaultClient
}

package oidc

import (
	"testing"
	"time"

	"example.com/fixture/internal/clock/clocktest"
)

func TestX(t *testing.T) {
	_ = clocktest.Now
	_ = time.Since(time.Time{})
}

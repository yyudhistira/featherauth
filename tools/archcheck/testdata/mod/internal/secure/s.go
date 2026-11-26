package secure

import (
	"crypto/rand"
	"time"
)

var _ = rand.Reader

func Now() time.Time { return time.Now() }

package user

import (
	"log"

	"example.com/fixture/internal/clock/clocktest"
)

var _ = clocktest.Now

func L() { log.Print("x") }

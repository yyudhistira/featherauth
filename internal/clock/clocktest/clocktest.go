// Package clocktest is the contract every clock.Clock implementation must
// pass, including test fakes.
package clocktest

import (
	"sync"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/clock"
)

// Run checks that c returns UTC instants that never go back, also when read
// from several goroutines at once.
func Run(t *testing.T, c clock.Clock) {
	t.Helper()

	t.Run("UTC", func(t *testing.T) {
		if loc := c.Now().Location(); loc != time.UTC {
			t.Fatalf("Now().Location() = %v, want UTC", loc)
		}
	})

	t.Run("NeverGoesBack", func(t *testing.T) {
		prev := c.Now()
		for i := 0; i < 1000; i++ {
			now := c.Now()
			if now.Before(prev) {
				t.Fatalf("Now() went back from %v to %v", prev, now)
			}
			prev = now
		}
	})

	t.Run("ConcurrentReads", func(t *testing.T) {
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < 100; j++ {
					_ = c.Now()
				}
			}()
		}
		wg.Wait()
	})

	t.Run("TimerStopBeforeFire", func(t *testing.T) {
		fired := make(chan struct{}, 1)
		tm := c.AfterFunc(time.Hour, func() { fired <- struct{}{} })
		if !tm.Stop() {
			t.Fatal("Stop() = false for a timer that had not fired")
		}
		if tm.Stop() {
			t.Fatal("second Stop() = true, want false")
		}
		select {
		case <-fired:
			t.Fatal("a stopped timer fired")
		default:
		}
	})
}

// RunTimers checks the timers of a fake clock, which a test moves with
// advance. advance must move the clock forward by exactly d and run the due
// timers before it returns.
func RunTimers(t *testing.T, c clock.Clock, advance func(d time.Duration)) {
	t.Helper()

	t.Run("FiresOnceAfterItsDuration", func(t *testing.T) {
		n := 0
		c.AfterFunc(10*time.Second, func() { n++ })
		advance(9 * time.Second)
		if n != 0 {
			t.Fatalf("fired %d times before its duration", n)
		}
		advance(time.Second)
		if n != 1 {
			t.Fatalf("fired %d times at its duration, want 1", n)
		}
		advance(time.Hour)
		if n != 1 {
			t.Fatalf("fired %d times in total, want 1", n)
		}
	})

	t.Run("StopPreventsFiring", func(t *testing.T) {
		n := 0
		tm := c.AfterFunc(time.Second, func() { n++ })
		if !tm.Stop() {
			t.Fatal("Stop() = false before the timer fired")
		}
		advance(time.Minute)
		if n != 0 {
			t.Fatal("a stopped timer fired")
		}
	})

	t.Run("StopAfterFiringReportsFalse", func(t *testing.T) {
		tm := c.AfterFunc(time.Second, func() {})
		advance(time.Second)
		if tm.Stop() {
			t.Fatal("Stop() = true after the timer fired")
		}
	})

	t.Run("TimersFireInOrderOfDueTime", func(t *testing.T) {
		var got []int
		c.AfterFunc(3*time.Second, func() { got = append(got, 3) })
		c.AfterFunc(time.Second, func() { got = append(got, 1) })
		c.AfterFunc(2*time.Second, func() { got = append(got, 2) })
		advance(time.Minute)
		if len(got) != 3 || got[0] != 1 || got[1] != 2 || got[2] != 3 {
			t.Fatalf("fired in order %v, want [1 2 3]", got)
		}
	})

	t.Run("CallbackSeesItsDueTimeAndMayReschedule", func(t *testing.T) {
		start := c.Now()
		var seen []time.Duration
		var f func()
		f = func() {
			seen = append(seen, c.Now().Sub(start))
			if len(seen) < 3 {
				c.AfterFunc(time.Second, f)
			}
		}
		c.AfterFunc(time.Second, f)
		advance(10 * time.Second)
		want := []time.Duration{time.Second, 2 * time.Second, 3 * time.Second}
		if len(seen) != 3 || seen[0] != want[0] || seen[1] != want[1] || seen[2] != want[2] {
			t.Fatalf("callbacks saw %v, want %v", seen, want)
		}
		if got := c.Now().Sub(start); got != 10*time.Second {
			t.Fatalf("clock moved %v, want 10s", got)
		}
	})

	t.Run("NonPositiveDurationFiresOnNextAdvance", func(t *testing.T) {
		n := 0
		c.AfterFunc(0, func() { n++ })
		if n != 0 {
			t.Fatal("fired before the clock moved")
		}
		advance(0)
		if n != 1 {
			t.Fatalf("fired %d times, want 1", n)
		}
	})
}

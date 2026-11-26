// Package clock is the only source of the current time. Everything else
// takes a Clock, so tests can control time with a Fake instead of sleeping.
package clock

import (
	"fmt"
	"sync"
	"time"
)

// Clock returns the current instant, always in UTC.
type Clock interface {
	Now() time.Time
	// AfterFunc runs f once d has passed on this clock. The real clock runs
	// f in its own goroutine; a Fake runs it synchronously, on the goroutine
	// that calls Advance or Set and reaches the due time.
	AfterFunc(d time.Duration, f func()) Timer
}

// Timer is a pending call made by AfterFunc.
type Timer interface {
	// Stop prevents the call and reports whether it did: false means the
	// function already ran or the timer was already stopped.
	Stop() bool
}

var (
	_ Clock = realClock{}
	_ Clock = (*Fake)(nil)
)

// Real returns the system clock.
func Real() Clock { return realClock{} }

type realClock struct{}

func (realClock) Now() time.Time { return time.Now().UTC() }

func (realClock) AfterFunc(d time.Duration, f func()) Timer { return time.AfterFunc(d, f) }

// Fake is a clock that moves only when told to. It is safe for concurrent
// use and never goes back. Timers made with AfterFunc run on the goroutine
// that moves the clock, in order of their due time (then of creation), while
// Now reports the instant at which each is due.
type Fake struct {
	mu     sync.Mutex
	now    time.Time
	seq    int
	timers []*fakeTimer // pending timers
}

type fakeTimer struct {
	clock *Fake
	when  time.Time
	seq   int
	f     func()
}

var _ Timer = (*fakeTimer)(nil)

// NewFake returns a fake clock that starts at t.
func NewFake(t time.Time) *Fake {
	return &Fake{now: t.UTC()}
}

func (f *Fake) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

// AfterFunc implements Clock. The function runs during the Advance or Set
// that reaches the due time, or during the next one when d is not positive.
func (f *Fake) AfterFunc(d time.Duration, fn func()) Timer {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seq++
	t := &fakeTimer{clock: f, when: f.now.Add(d), seq: f.seq, f: fn}
	f.timers = append(f.timers, t)
	return t
}

// Stop implements Timer.
func (t *fakeTimer) Stop() bool {
	f := t.clock
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, p := range f.timers {
		if p == t {
			f.timers = append(f.timers[:i], f.timers[i+1:]...)
			return true
		}
	}
	return false
}

// Advance moves the clock forward by d and runs the timers that fall due. A
// negative d panics, because a clock that goes back would break the Clock
// contract.
func (f *Fake) Advance(d time.Duration) {
	if d < 0 {
		panic(fmt.Sprintf("clock: Advance(%v): a clock cannot go back", d))
	}
	f.mu.Lock()
	target := f.now.Add(d)
	f.moveTo(target)
}

// Set moves the clock to t, which must not be earlier than the current
// instant, and runs the timers that fall due.
func (f *Fake) Set(t time.Time) {
	f.mu.Lock()
	if t.Before(f.now) {
		now := f.now
		f.mu.Unlock()
		panic(fmt.Sprintf("clock: Set(%v) is before %v: a clock cannot go back", t, now))
	}
	f.moveTo(t.UTC())
}

// moveTo runs due timers one by one, then sets the clock to target. It is
// called with f.mu held and releases it.
func (f *Fake) moveTo(target time.Time) {
	for {
		var next *fakeTimer
		for _, t := range f.timers {
			if t.when.After(target) {
				continue
			}
			if next == nil || t.when.Before(next.when) || (t.when.Equal(next.when) && t.seq < next.seq) {
				next = t
			}
		}
		if next == nil {
			break
		}
		for i, p := range f.timers {
			if p == next {
				f.timers = append(f.timers[:i], f.timers[i+1:]...)
				break
			}
		}
		if next.when.After(f.now) {
			f.now = next.when
		}
		fn := next.f
		f.mu.Unlock()
		fn()
		f.mu.Lock()
	}
	if target.After(f.now) {
		f.now = target
	}
	f.mu.Unlock()
}

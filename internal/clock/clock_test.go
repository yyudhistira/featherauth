package clock_test

import (
	"sync"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/clock/clocktest"
)

var start = time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)

func TestRealContract(t *testing.T) {
	clocktest.Run(t, clock.Real())
}

func TestFakeContract(t *testing.T) {
	f := clock.NewFake(start)
	clocktest.Run(t, f)

	// The contract also holds while another goroutine advances the clock.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			f.Advance(time.Millisecond)
		}
	}()
	clocktest.Run(t, f)
	wg.Wait()
}

func TestFakeTimersOnAdvance(t *testing.T) {
	f := clock.NewFake(start)
	clocktest.RunTimers(t, f, f.Advance)
}

func TestFakeTimersOnSet(t *testing.T) {
	f := clock.NewFake(start)
	clocktest.RunTimers(t, f, func(d time.Duration) { f.Set(f.Now().Add(d)) })
}

func TestFakeStopFromACallback(t *testing.T) {
	f := clock.NewFake(start)
	n := 0
	var second clock.Timer
	f.AfterFunc(time.Second, func() { second.Stop() })
	second = f.AfterFunc(2*time.Second, func() { n++ })
	f.Advance(time.Minute)
	if n != 0 {
		t.Fatal("a timer stopped by an earlier callback fired")
	}
}

func TestRealTimerFiresOnce(t *testing.T) {
	done := make(chan struct{}, 2)
	clock.Real().AfterFunc(0, func() { done <- struct{}{} })
	<-done // the test deadline bounds the wait; nothing sleeps
	if len(done) != 0 {
		t.Fatal("fired twice")
	}
}

func TestFakeStartsAtGivenInstantInUTC(t *testing.T) {
	amsterdam := time.FixedZone("CET", 3600)
	f := clock.NewFake(start.In(amsterdam))
	if got := f.Now(); !got.Equal(start) || got.Location() != time.UTC {
		t.Fatalf("Now() = %v, want %v in UTC", got, start)
	}
}

func TestFakeAdvanceAndSet(t *testing.T) {
	f := clock.NewFake(start)
	f.Advance(90 * time.Second)
	if got, want := f.Now(), start.Add(90*time.Second); !got.Equal(want) {
		t.Fatalf("after Advance: Now() = %v, want %v", got, want)
	}
	later := start.Add(24 * time.Hour)
	f.Set(later)
	if got := f.Now(); !got.Equal(later) {
		t.Fatalf("after Set: Now() = %v, want %v", got, later)
	}
}

func TestFakeRefusesToGoBack(t *testing.T) {
	cases := map[string]func(f *clock.Fake){
		"Advance negative": func(f *clock.Fake) { f.Advance(-time.Second) },
		"Set earlier":      func(f *clock.Fake) { f.Set(start.Add(-time.Second)) },
	}
	for name, fn := range cases {
		t.Run(name, func(t *testing.T) {
			f := clock.NewFake(start)
			defer func() {
				if recover() == nil {
					t.Fatal("did not panic")
				}
				if got := f.Now(); !got.Equal(start) {
					t.Fatalf("Now() = %v after the refused change, want %v", got, start)
				}
			}()
			fn(f)
		})
	}
}

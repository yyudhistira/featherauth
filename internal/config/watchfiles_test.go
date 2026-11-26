package config_test

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/config"
)

// filesRig runs WatchFiles on two files of one directory with a fake watcher.
type filesRig struct {
	w      *fakeWatcher
	clk    *clock.Fake
	dir    string
	cert   string
	key    string
	calls  chan struct{}
	trace  chan string
	cancel context.CancelFunc
	done   chan error
}

func startFilesWatch(t *testing.T, w *fakeWatcher) *filesRig {
	t.Helper()
	dir := t.TempDir()
	r := &filesRig{
		w: w, clk: clock.NewFake(time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)), dir: dir,
		cert: filepath.Join(dir, "tls_cert.pem"), key: filepath.Join(dir, "tls_key.pem"),
		calls: make(chan struct{}, 8), trace: make(chan string, 32), done: make(chan error, 1),
	}
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	t.Cleanup(cancel)
	go func() {
		r.done <- config.WatchFilesWith(ctx, r.clk, []string{r.cert, r.key},
			func() { r.calls <- struct{}{} },
			func() (config.Watcher, error) { return w, nil },
			func(s string) { r.trace <- s })
	}()
	r.expect(t, "watching")
	return r
}

// expect waits for the next trace stage; the test deadline bounds the wait.
func (r *filesRig) expect(t *testing.T, stage string) {
	t.Helper()
	if got := <-r.trace; got != stage {
		t.Fatalf("trace %q, want %q", got, stage)
	}
}

// Covers: FR-52 (part)
// Acceptance: Built-in TLS with files (part)
func TestWatchFilesReloadsOnceAfterTheDebounce(t *testing.T) {
	r := startFilesWatch(t, newFakeWatcher())
	if got := r.w.watched(); !slices.Equal(got, []string{r.dir}) {
		t.Fatalf("watched %v, want the directory once", got)
	}

	// Another file of the directory, and a change of mode alone, are ignored.
	r.w.events <- fsnotify.Event{Name: filepath.Join(r.dir, "other.txt"), Op: fsnotify.Write}
	r.expect(t, "ignored")
	r.w.events <- fsnotify.Event{Name: r.cert, Op: fsnotify.Chmod}
	r.expect(t, "ignored")

	// A write to the certificate arms the debounce, and a second write restarts it.
	r.w.events <- fsnotify.Event{Name: r.cert, Op: fsnotify.Write}
	r.expect(t, "armed")
	r.clk.Advance(config.DebounceDelay - time.Nanosecond)
	if len(r.calls) != 0 {
		t.Fatal("reloaded before the debounce elapsed")
	}
	r.w.events <- fsnotify.Event{Name: r.cert, Op: fsnotify.Write}
	r.expect(t, "armed")
	r.clk.Advance(config.DebounceDelay - time.Nanosecond)
	if len(r.calls) != 0 {
		t.Fatal("a new event did not restart the debounce")
	}
	r.clk.Advance(time.Nanosecond)
	r.expect(t, "reloaded")
	if len(r.calls) != 1 {
		t.Fatalf("%d reloads, want 1", len(r.calls))
	}

	// A key file replaced by rename (the Create event of the new name) reloads too.
	r.w.events <- fsnotify.Event{Name: r.key, Op: fsnotify.Create}
	r.expect(t, "armed")
	r.clk.Advance(config.DebounceDelay)
	r.expect(t, "reloaded")
	if len(r.calls) != 2 {
		t.Fatalf("%d reloads after the key, want 2", len(r.calls))
	}

	r.cancel()
	if err := <-r.done; err != nil {
		t.Fatalf("WatchFiles returned %v", err)
	}
	select {
	case <-r.w.closed:
	default:
		t.Error("the watcher was not closed")
	}
}

// Covers: FR-52 (part)
// Acceptance: Built-in TLS with files (part)
func TestWatchFilesFailsWhenADirectoryCannotBeWatched(t *testing.T) {
	w := newFakeWatcher()
	dir := t.TempDir()
	w.addErr = map[string]error{dir: errors.New("no inotify watches left")}
	err := config.WatchFilesWith(t.Context(), clock.Real(), []string{filepath.Join(dir, "tls_key.pem")},
		func() {}, func() (config.Watcher, error) { return w, nil }, func(string) {})
	if err == nil {
		t.Fatal("WatchFiles returned nil for a directory it cannot watch")
	}
}

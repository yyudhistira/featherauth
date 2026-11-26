package config_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/config"
)

// fakeWatcher delivers the events a test sends and records what is watched.
type fakeWatcher struct {
	events chan fsnotify.Event
	errs   chan error
	mu     sync.Mutex
	added  []string
	addErr map[string]error
	closed chan struct{}
}

func newFakeWatcher() *fakeWatcher {
	return &fakeWatcher{events: make(chan fsnotify.Event), errs: make(chan error), closed: make(chan struct{})}
}

func (w *fakeWatcher) Add(p string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.addErr[p]; err != nil {
		return err
	}
	w.added = append(w.added, p)
	return nil
}
func (w *fakeWatcher) Events() <-chan fsnotify.Event { return w.events }
func (w *fakeWatcher) Errors() <-chan error          { return w.errs }
func (w *fakeWatcher) Close() error                  { close(w.closed); return nil }
func (w *fakeWatcher) watched() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]string(nil), w.added...)
}

// watchRig runs Watch with a fake watcher.
type watchRig struct {
	d      *cfgDir
	l      *config.Loader
	clk    *clock.Fake
	w      *fakeWatcher
	trace  chan string
	cancel context.CancelFunc
	done   chan error
	logs   *bytes.Buffer
}

func startWatch(t *testing.T) *watchRig {
	t.Helper()
	d := newCfgDir(t)
	d.realm("a", "A0", "")
	l, clk, logs := d.loader(t)
	r := &watchRig{d: d, l: l, clk: clk, w: newFakeWatcher(), trace: make(chan string, 64), done: make(chan error, 1), logs: logs}
	config.SetWatcherFactory(l, func() (config.Watcher, error) { return r.w, nil })
	config.SetTrace(l, func(s string) { r.trace <- s })
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	t.Cleanup(cancel)
	go func() { r.done <- l.Watch(ctx) }()
	r.expect(t, "watching")
	return r
}

// expect waits for the next trace stage; the test deadline bounds the wait.
func (r *watchRig) expect(t *testing.T, stage string) {
	t.Helper()
	if got := <-r.trace; got != stage {
		t.Fatalf("trace %q, want %q", got, stage)
	}
}

func (r *watchRig) send(ev fsnotify.Event) { r.w.events <- ev }

func (r *watchRig) realmName(t *testing.T) string {
	a, _ := r.l.Current().Realm("a")
	return a.DisplayName
}

// Covers: FR-15 (part), FR-18 (part)
// Acceptance: Hot reload (part)
func TestWatchReloadsAfterTheDebounceOnTheInjectedClock(t *testing.T) {
	r := startWatch(t)
	root := r.d.root
	if got := r.w.watched(); !slices.Contains(got, root) || !slices.Contains(got, filepath.Join(root, "realms")) {
		t.Fatalf("watched %v, want the config directory and realms", got)
	}

	r.d.realm("a", "A1", "")
	file := filepath.Join(root, "realms", "a.yaml")
	r.send(fsnotify.Event{Name: file, Op: fsnotify.Write})
	r.expect(t, "armed")

	r.clk.Advance(config.DebounceDelay - time.Nanosecond)
	if got := r.realmName(t); got != "A0" {
		t.Fatalf("reloaded before the debounce elapsed: %s", got)
	}
	// Another event restarts the wait.
	r.send(fsnotify.Event{Name: file, Op: fsnotify.Create})
	r.expect(t, "armed")
	r.clk.Advance(config.DebounceDelay - time.Nanosecond)
	if got := r.realmName(t); got != "A0" {
		t.Fatalf("a new event did not restart the debounce: %s", got)
	}
	r.clk.Advance(time.Nanosecond)
	r.expect(t, "reloaded")
	if got := r.realmName(t); got != "A1" {
		t.Fatalf("realm a = %s after the debounce, want A1", got)
	}

	// The burst caused one reload only.
	r.clk.Advance(time.Hour)
	r.cancel()
	if err := <-r.done; err != nil {
		t.Fatalf("Watch returned %v", err)
	}
	select {
	case s := <-r.trace:
		t.Fatalf("unexpected trace %q: more than one reload", s)
	default:
	}
	select {
	case <-r.w.closed:
	default:
		t.Error("the watcher was not closed")
	}
}

// Covers: FR-15 (part)
func TestWatchIgnoresChmodAndStopsTimerOnCancel(t *testing.T) {
	r := startWatch(t)
	r.d.realm("a", "A1", "")
	file := filepath.Join(r.d.root, "realms", "a.yaml")
	r.send(fsnotify.Event{Name: file, Op: fsnotify.Chmod})
	r.expect(t, "ignored")
	r.clk.Advance(time.Hour)
	if got := r.realmName(t); got != "A0" {
		t.Fatalf("a chmod event caused a reload: %s", got)
	}
	r.send(fsnotify.Event{Name: file, Op: fsnotify.Write})
	r.expect(t, "armed")
	r.cancel()
	<-r.done
	r.clk.Advance(time.Hour) // the pending timer was stopped
	if got := r.realmName(t); got != "A0" {
		t.Fatalf("reload after Watch returned: %s", got)
	}
}

// Covers: FR-15 (part)
func TestWatchAddsNewDirectoriesAndLogsWatcherErrors(t *testing.T) {
	r := startWatch(t)
	sub := filepath.Join(r.d.root, "locales")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	r.send(fsnotify.Event{Name: sub, Op: fsnotify.Create})
	r.expect(t, "armed")
	if !slices.Contains(r.w.watched(), sub) {
		t.Errorf("new directory not watched: %v", r.w.watched())
	}

	r.w.errs <- errors.New("queue overflow")
	r.expect(t, "error")
	r.cancel()
	<-r.done
	if out := r.logs.String(); !strings.Contains(out, "queue overflow") {
		t.Errorf("watcher error not logged: %s", out)
	}
}

func TestWatchFailsWhenTheConfigDirectoryCannotBeWatched(t *testing.T) {
	d := newCfgDir(t)
	d.realm("a", "A", "")
	l, _, _ := d.loader(t)
	boom := errors.New("no inotify")
	w := newFakeWatcher()
	w.addErr = map[string]error{d.root: boom}
	config.SetWatcherFactory(l, func() (config.Watcher, error) { return w, nil })
	if err := l.Watch(context.Background()); !errors.Is(err, boom) {
		t.Fatalf("Watch = %v, want %v", err, boom)
	}
	select {
	case <-w.closed:
	default:
		t.Error("the watcher was not closed")
	}

	config.SetWatcherFactory(l, func() (config.Watcher, error) { return nil, boom })
	if err := l.Watch(context.Background()); !errors.Is(err, boom) {
		t.Fatalf("Watch = %v, want %v", err, boom)
	}
}

// A subdirectory that cannot be watched is logged and does not stop Watch.
func TestWatchContinuesWhenASubdirectoryCannotBeWatched(t *testing.T) {
	d := newCfgDir(t)
	d.realm("a", "A", "")
	l, _, logs := d.loader(t)
	w := newFakeWatcher()
	w.addErr = map[string]error{filepath.Join(d.root, "secrets"): errors.New("denied")}
	config.SetWatcherFactory(l, func() (config.Watcher, error) { return w, nil })
	trace := make(chan string, 8)
	config.SetTrace(l, func(s string) { trace <- s })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- l.Watch(ctx) }()
	<-trace
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), "denied") {
		t.Errorf("not logged: %s", logs.String())
	}
}

// A real file write reaches the loader through fsnotify. Nothing sleeps: the
// test waits on the loader's own signals and moves the debounce with the
// fake clock.
//
// Covers: FR-15 (part), FR-18 (part)
// Acceptance: Hot reload (part)
func TestWatchReloadsOnARealFileWrite(t *testing.T) {
	d := newCfgDir(t)
	d.realm("a", "A0", "")
	l, clk, _ := d.loader(t)
	trace := make(chan string, 64)
	config.SetTrace(l, func(s string) { trace <- s })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- l.Watch(ctx) }()
	defer func() { cancel(); <-done }()
	if got := <-trace; got != "watching" {
		t.Fatalf("trace %q", got)
	}

	d.realm("a", "A1", "")
	for {
		got := <-trace // blocks until fsnotify delivers an event
		if got == "armed" {
			break
		}
	}
	clk.Advance(config.DebounceDelay)
	for {
		if got := <-trace; got == "reloaded" {
			break
		}
	}
	if a, _ := l.Current().Realm("a"); a.DisplayName != "A1" {
		t.Fatalf("realm a = %q after the write, want A1", a.DisplayName)
	}
}

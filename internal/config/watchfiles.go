package config

import (
	"context"
	"log/slog"
	"maps"
	"path/filepath"
	"slices"

	"github.com/fsnotify/fsnotify"

	"github.com/yyudhistira/featherauth/internal/clock"
)

// WatchFiles calls fn when one of the files in paths changes (a write, a
// creation, which is a file replaced by rename, or a removal). The events are
// debounced by DebounceDelay on c, so that a write of several files causes one
// call. The directories of the files are watched. It returns nil when ctx is
// done and an error when a directory cannot be watched.
func WatchFiles(ctx context.Context, c clock.Clock, log *slog.Logger, paths []string, fn func()) error {
	return watchFiles(ctx, newFSWatcher, c, log, paths, fn, func(string) {})
}

// watchFiles is WatchFiles with the watcher and a trace of its stages, for
// tests: "watching", "ignored", "armed" and "reloaded".
func watchFiles(ctx context.Context, newWatcher func() (watcher, error), c clock.Clock, log *slog.Logger, paths []string, fn func(), trace func(string)) error {
	w, err := newWatcher()
	if err != nil {
		return err
	}
	defer w.Close()
	want := map[string]bool{}
	dirs := map[string]bool{}
	for _, p := range paths {
		p = filepath.Clean(p)
		want[p] = true
		dirs[filepath.Dir(p)] = true
	}
	for _, d := range slices.Sorted(maps.Keys(dirs)) {
		if err := w.Add(d); err != nil {
			return err
		}
	}
	trace("watching")

	fire := make(chan struct{}, 1)
	var timer clock.Timer
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return nil
		case ev, ok := <-w.Events():
			if !ok {
				return nil
			}
			if ev.Op&^fsnotify.Chmod == 0 || !want[filepath.Clean(ev.Name)] {
				trace("ignored")
				continue
			}
			if timer != nil {
				timer.Stop()
			}
			timer = c.AfterFunc(debounce, func() {
				select {
				case fire <- struct{}{}:
				default:
				}
			})
			trace("armed")
		case err, ok := <-w.Errors():
			if !ok {
				return nil
			}
			log.ErrorContext(ctx, "file watcher error", "error", err)
		case <-fire:
			fn()
			trace("reloaded")
		}
	}
}

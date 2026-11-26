package config

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/yyudhistira/featherauth/internal/clock"
)

// debounce is how long Watch waits after the last file event before it
// reloads, so an editor's burst of writes causes one reload.
const debounce = 250 * time.Millisecond

// watcher is the part of fsnotify.Watcher that Watch uses.
type watcher interface {
	Add(path string) error
	Events() <-chan fsnotify.Event
	Errors() <-chan error
	Close() error
}

type fsWatcher struct{ w *fsnotify.Watcher }

var _ watcher = fsWatcher{}

func newFSWatcher() (watcher, error) {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	return fsWatcher{w}, nil
}

func (f fsWatcher) Add(p string) error            { return f.w.Add(p) }
func (f fsWatcher) Events() <-chan fsnotify.Event { return f.w.Events }
func (f fsWatcher) Errors() <-chan error          { return f.w.Errors }
func (f fsWatcher) Close() error                  { return f.w.Close() }

// Watch reloads the configuration when a file in the directory or in one of
// its subdirectories changes, once the events have stopped for the debounce
// time on the loader's clock. It returns nil when ctx is done and an error
// when the directory cannot be watched. The restart of a process is never
// started from here.
func (l *Loader) Watch(ctx context.Context) error {
	w, err := l.newWatcher()
	if err != nil {
		return err
	}
	defer w.Close()
	if err := w.Add(l.dir); err != nil {
		return err
	}
	l.addSubdirs(w, l.dir)
	l.log.Info("watching the configuration directory")
	l.tr("watching")

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
			if ev.Op&^fsnotify.Chmod == 0 {
				l.tr("ignored")
				continue
			}
			if ev.Has(fsnotify.Create) {
				if fi, err := os.Stat(ev.Name); err == nil && fi.IsDir() {
					l.addSubdirs(w, ev.Name)
				}
			}
			if timer != nil {
				timer.Stop()
			}
			timer = l.clock.AfterFunc(debounce, func() {
				select {
				case fire <- struct{}{}:
				default:
				}
			})
			l.tr("armed")
		case err, ok := <-w.Errors():
			if !ok {
				return nil
			}
			l.log.Error("file watcher error", "error", err)
			l.tr("error")
		case <-fire:
			l.Reload(ctx)
			l.tr("reloaded")
		}
	}
}

// addSubdirs watches the directories below root. One that cannot be watched
// is logged; the others still are.
func (l *Loader) addSubdirs(w watcher, root string) {
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() || p == l.dir {
			return nil
		}
		if err := w.Add(p); err != nil {
			l.log.Warn("cannot watch directory", "directory", p, "error", err)
		}
		return nil
	})
}

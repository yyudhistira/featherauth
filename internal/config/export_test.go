package config

import (
	"context"
	"io"
	"log/slog"
	"reflect"
	"slices"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/logx"
)

// Watcher lets tests supply a file watcher.
type Watcher = watcher

// DebounceDelay is how long the loader waits after the last file event.
const DebounceDelay = debounce

// SetWatcherFactory replaces the file watcher the loader's Watch creates.
func SetWatcherFactory(l *Loader, f func() (Watcher, error)) { l.newWatcher = f }

// SetTrace sets a function called at "watching", "armed" and "reloaded".
func SetTrace(l *Loader, f func(string)) { l.trace = f }

// CheckDuplicateRealms reports realm names used by more than one file.
func CheckDuplicateRealms(realms []RealmSource) []Diagnostic { return checkDuplicateRealms(realms) }

// ServerOptionNames lists every option of server.yaml.
func ServerOptionNames() []string {
	var out []string
	optionLeaves(reflect.ValueOf(&ServerFile{}).Elem(), "", func(p string, _ reflect.Value) { out = append(out, p) })
	slices.Sort(out)
	return out
}

// ServerOptionLive reports how the loader classifies an option of server.yaml.
func ServerOptionLive(option string) (live, known bool) {
	live, known = serverOptionLive[option]
	return live, known
}

// WatchFilesWith is WatchFiles with a file watcher and a trace supplied by the
// test; its errors are not logged.
func WatchFilesWith(ctx context.Context, c clock.Clock, paths []string, fn func(), newWatcher func() (Watcher, error), trace func(string)) error {
	return watchFiles(ctx, newWatcher, c, logx.New(io.Discard, slog.LevelError, c), paths, fn, trace)
}

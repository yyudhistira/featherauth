package store

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/logx"
)

// BackupSchedule takes a snapshot every day at backup.at (server local time)
// and keeps the newest backup.keep, as Snapshot does. Its timer is the
// clock's, so a fake clock drives it in tests. A failed snapshot is logged
// and the schedule goes on with the next day.
type BackupSchedule struct {
	st    Store
	dir   string
	hour  int
	min   int
	keep  int
	clock clock.Clock
	log   *slog.Logger

	ctx    context.Context
	cancel context.CancelFunc

	mu      sync.Mutex
	timer   clock.Timer
	stopped bool
	running sync.WaitGroup
}

// StartBackups starts the daily snapshots described by cfg. With an empty
// directory or an empty At there is no built-in schedule and the returned
// schedule does nothing. It fails when At is not HH:MM or Keep is below 1. l
// may be nil.
func StartBackups(st Store, cfg config.BackupConfig, c clock.Clock, l *slog.Logger) (*BackupSchedule, error) {
	ctx, cancel := context.WithCancel(context.Background())
	b := &BackupSchedule{st: st, dir: cfg.Directory, keep: cfg.Keep, clock: c, log: l, ctx: ctx, cancel: cancel}
	if cfg.Directory == "" || cfg.At == "" {
		b.stopped = true
		return b, nil
	}
	at, err := time.Parse("15:04", cfg.At)
	if err != nil || at.Format("15:04") != cfg.At {
		cancel()
		return nil, fmt.Errorf("store: backup time %q is not HH:MM", cfg.At)
	}
	if cfg.Keep < 1 {
		cancel()
		return nil, fmt.Errorf("store: backup.keep must be 1 or more, got %d", cfg.Keep)
	}
	b.hour, b.min = at.Hour(), at.Minute()
	if b.log == nil {
		b.log = logx.New(io.Discard, slog.LevelError, c)
	}
	b.mu.Lock()
	b.arm()
	b.mu.Unlock()
	return b, nil
}

// next returns the first set minute after now, in the server's local time.
func (b *BackupSchedule) next(now time.Time) time.Time {
	l := now.Local()
	t := time.Date(l.Year(), l.Month(), l.Day(), b.hour, b.min, 0, 0, time.Local)
	if !t.After(l) {
		t = time.Date(l.Year(), l.Month(), l.Day()+1, b.hour, b.min, 0, 0, time.Local)
	}
	return t
}

// arm sets the timer for the next snapshot. b.mu is held.
func (b *BackupSchedule) arm() {
	now := b.clock.Now()
	b.timer = b.clock.AfterFunc(b.next(now).Sub(now), b.fire)
}

func (b *BackupSchedule) fire() {
	b.mu.Lock()
	if b.stopped {
		b.mu.Unlock()
		return
	}
	b.running.Add(1)
	b.mu.Unlock()
	defer b.running.Done()

	now := b.clock.Now()
	b.snapshot(now)

	b.mu.Lock()
	if !b.stopped {
		b.arm()
	}
	b.mu.Unlock()
}

// snapshot writes one snapshot named from now and logs the outcome. Nothing
// it meets stops the schedule.
func (b *BackupSchedule) snapshot(now time.Time) {
	if err := os.MkdirAll(b.dir, 0o700); err != nil {
		b.log.LogAttrs(b.ctx, slog.LevelError, "backup failed", slog.Any("error", err))
		return
	}
	path, err := Snapshot(b.ctx, b.st, b.dir, now.Local(), b.keep)
	if err != nil {
		b.log.LogAttrs(b.ctx, slog.LevelError, "backup failed", slog.Any("error", err))
		return
	}
	b.log.LogAttrs(b.ctx, slog.LevelInfo, "backup written", slog.String("path", path))
}

// Stop ends the schedule and waits for a snapshot in progress. It is safe to
// call more than once.
func (b *BackupSchedule) Stop() {
	b.mu.Lock()
	b.stopped = true
	if b.timer != nil {
		b.timer.Stop()
	}
	b.mu.Unlock()
	b.cancel()
	b.running.Wait()
}

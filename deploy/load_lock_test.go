//go:build darwin || dragonfly || freebsd || illumos || linux || netbsd || openbsd

package deploy_test

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
)

// takeLoadLock takes the exclusive lock of the load runs on the file at path
// (flock, without waiting), creating the file and its directory when missing.
// When another process, or another take in this one, holds it, it fails at
// once with the message of the design and changes nothing. The lock lasts
// until release is called or the process ends in any way: the system drops it
// with the process, so a crashed run never blocks the next one (docs/DESIGN.md,
// Load verification, step 1).
func takeLoadLock(path string) (release func() error, err error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, fmt.Errorf("another load run is using the compose project featherauth-load (lock %s); wait for it to end", path)
		}
		return nil, fmt.Errorf("lock %s: %w", path, err)
	}
	return f.Close, nil
}

// loadLockHelperEnv makes the test binary a helper process that takes the lock
// at the path it names, reports it on stdout and holds it until it is killed.
const loadLockHelperEnv = "FEATHERAUTH_LOAD_LOCK_HELPER"

// One load run at a time (Load verification, step 1): a second take of the
// lock while one is held fails at once with the message of the design and
// changes nothing; a take after the release succeeds; and a take after the
// process that held the lock was killed succeeds, because the system drops
// the lock with the process.
func TestLoadLockRefusesASecondRun(t *testing.T) {
	if p := os.Getenv(loadLockHelperEnv); p != "" {
		if _, err := takeLoadLock(p); err != nil {
			_, _ = os.Stdout.WriteString("error: " + err.Error() + "\n")
			os.Exit(1)
		}
		_, _ = os.Stdout.WriteString("locked\n")
		_, _ = io.Copy(io.Discard, os.Stdin) // hold until killed or the parent ends
		os.Exit(0)
	}

	path := filepath.Join(t.TempDir(), "featherauth", "load.lock")
	want := "another load run is using the compose project featherauth-load (lock " + path + "); wait for it to end"

	release, err := takeLoadLock(path)
	if err != nil {
		t.Fatalf("first take: %v", err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := takeLoadLock(path); err == nil || err.Error() != want {
		t.Fatalf("second take while held: %v, want %q", err, want)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) || before.Mode() != after.Mode() {
		t.Error("the refused take changed the lock file")
	}
	if _, err := takeLoadLock(path); err == nil {
		t.Error("the refused take released the lock")
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
	release, err = takeLoadLock(path)
	if err != nil {
		t.Fatalf("take after the release: %v", err)
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}

	// A helper process takes the lock and reports it; while it lives the lock
	// is refused, and once it is killed the lock can be taken again.
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestLoadLockRefusesASecondRun$")
	cmd.Env = append(os.Environ(), loadLockHelperEnv+"="+path)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stdin.Close() }()
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || line != "locked\n" {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatalf("helper: %q, %v", line, err)
	}
	if _, err := takeLoadLock(path); err == nil || err.Error() != want {
		t.Errorf("take while the helper holds the lock: %v, want %q", err, want)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	release, err = takeLoadLock(path)
	if err != nil {
		t.Fatalf("take after the holder was killed: %v", err)
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
}

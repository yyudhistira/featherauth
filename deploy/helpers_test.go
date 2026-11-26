//go:build conformance || load || ops

package deploy_test

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/clock"
)

// Helpers of the docker-based suites (build tags conformance, load and ops).

// pause waits for d on the real clock (the only timer source allowed; the
// docker-based suites run on clock.Real), or until ctx ends.
func pause(ctx context.Context, d time.Duration) {
	done := make(chan struct{})
	tm := clock.Real().AfterFunc(d, func() { close(done) })
	defer tm.Stop()
	select {
	case <-done:
	case <-ctx.Done():
	}
}

// openPermissions makes the files world-readable for the image's user, which
// the default strict_permissions refuses, so the suite's server.yaml turns it off.
func openPermissions(t *testing.T, root string) {
	t.Helper()
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return os.Chmod(p, 0o755)
		}
		return os.Chmod(p, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
}

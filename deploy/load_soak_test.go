//go:build load && (darwin || dragonfly || freebsd || illumos || linux || netbsd || openbsd)

package deploy_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/clock"
)

// detail is one reading of the service process and its data directory.
type detail struct {
	rss, hwm, anon, file int // kB
	threads, fds         int
	db, wal              int // bytes
}

var detailRe = regexp.MustCompile(`(?m)^(VmRSS|VmHWM|RssAnon|RssFile|Threads):\s+(\d+)`)

// detail reads /proc/1 of the service container (joining its process
// namespace) and lists its data directory.
func (s *loadStack) detail() (detail, error) {
	script := `grep -E '^(VmRSS|VmHWM|RssAnon|RssFile|Threads):' /proc/1/status; echo "fds $(ls /proc/1/fd | wc -l)"; ls -l /var/lib/featherauth`
	out, err := s.docker("run", "--rm", "--pid=container:"+loadSvc, "--volumes-from", loadSvc+":ro", loadProbe, "sh", "-c", script)
	if err != nil {
		return detail{}, fmt.Errorf("%v: %s", err, out)
	}
	var d detail
	for _, m := range detailRe.FindAllStringSubmatch(out, -1) {
		n, _ := strconv.Atoi(m[2])
		switch m[1] {
		case "VmRSS":
			d.rss = n
		case "VmHWM":
			d.hwm = n
		case "RssAnon":
			d.anon = n
		case "RssFile":
			d.file = n
		case "Threads":
			d.threads = n
		}
	}
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		switch {
		case len(f) == 2 && f[0] == "fds":
			d.fds, _ = strconv.Atoi(f[1])
		case len(f) >= 9 && strings.HasSuffix(f[8], "featherauth.db"):
			d.db, _ = strconv.Atoi(f[4])
		case len(f) >= 9 && strings.HasSuffix(f[8], "featherauth.db-wal"):
			d.wal, _ = strconv.Atoi(f[4])
		}
	}
	return d, nil
}

var gcTimedRe = regexp.MustCompile(`^(\S+) gc \d+ @.* (\d+)->\d+->(\d+) MB, \d+ MB goal, (\d+) MB stacks`)

// gcByMinute returns, for every minute since from, the largest live heap and
// the largest goroutine stacks (MB) the garbage collector traced
// (LOAD_GODEBUG=gctrace=1).
func (s *loadStack) gcByMinute(from time.Time, minutes int) (live, stacks []int) {
	out := s.must("logs", "--timestamps", "--since", from.Format(time.RFC3339Nano), loadSvc)
	live, stacks = make([]int, minutes), make([]int, minutes)
	for _, l := range strings.Split(out, "\n") {
		m := gcTimedRe.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		at, err := time.Parse(time.RFC3339Nano, m[1])
		if err != nil {
			continue
		}
		i := int(at.Sub(from) / time.Minute)
		if i < 0 || i >= minutes {
			continue
		}
		lv, _ := strconv.Atoi(m[3])
		st, _ := strconv.Atoi(m[4])
		live[i], stacks[i] = max(live[i], lv), max(stacks[i], st)
	}
	return live, stacks
}

// soakPhase runs a k6 scenario and reads the service every minute.
func (s *loadStack) soakPhase(rep *report, name, scenario string, d time.Duration) {
	s.t.Helper()
	var rows []detail
	stopped := make(chan struct{})
	done := make(chan struct{})
	t0 := clock.Real().Now()
	go func() {
		defer close(done)
		for {
			pause(context.Background(), time.Minute)
			select {
			case <-stopped:
				return
			default:
			}
			if x, err := s.detail(); err == nil {
				rows = append(rows, x)
			}
		}
	}()
	s.k6(name, scenario, "https://"+loadHost, strconv.Itoa(int(d.Seconds()))+"s")
	close(stopped)
	<-done
	live, stacks := s.gcByMinute(t0, len(rows)+1)
	rep.add("%s: %s for %v; per minute: VmRSS, VmHWM, RssAnon, RssFile (kB), threads, fds, database and WAL (bytes), live Go heap and goroutine stacks (MB, from gctrace)", name, scenario, d)
	for i, x := range rows {
		rep.add("%s minute %2d: rss %d hwm %d anon %d file %d threads %d fds %d db %d wal %d heap %d stacks %d", name, i+1, x.rss, x.hwm, x.anon, x.file, x.threads, x.fds, x.db, x.wal, live[i], stacks[i])
	}
}

// TestLoadSoakMemory investigates the resident memory of a long steady run:
// phase A is steady load, which adds rows to the database; phase B, on the
// same process right after seeding again, sends userinfo and JWKS only, so the
// database gets no new rows. Memory that keeps rising in B is a leak; memory
// that rises only with the database in A is the page cache filling. It runs
// only when LOAD_SOAK_A is set (a duration, for example 35m); LOAD_SOAK_B
// (default 10m, within the 15 minutes the access tokens of the seeding live).
// Start the service with LOAD_GODEBUG=gctrace=1 to get the heap columns.
func TestLoadSoakMemory(t *testing.T) {
	a := envDuration(t, "LOAD_SOAK_A", 0)
	if a == 0 {
		t.Skip("set LOAD_SOAK_A to run the soak memory investigation")
	}
	b := envDuration(t, "LOAD_SOAK_B", 10*time.Minute)
	if b > 12*time.Minute { // the access tokens of the seeding live 15 minutes and phase B must not refresh
		t.Fatalf("LOAD_SOAK_B %v is over 12 minutes: the access tokens of the seeding would expire", b)
	}
	s := newLoadStack(t)
	rep := &report{t: t}
	defer func() {
		_ = os.WriteFile(filepath.Join(s.out, "soak-memory.txt"), []byte(strings.Join(rep.lines, "\n")+"\n"), 0o644)
	}()
	s.seed(1000)
	if err := s.ready(context.Background(), loadCaddy); err != nil {
		t.Fatal(err)
	}
	s.soakPhase(rep, "A", "steady", a)
	s.seed(1000)
	s.soakPhase(rep, "B", "readonly", b)
}

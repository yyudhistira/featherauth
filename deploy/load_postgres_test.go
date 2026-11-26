//go:build load && (darwin || dragonfly || freebsd || illumos || linux || netbsd || openbsd)

package deploy_test

import (
	"fmt"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The database file the load stack writes for each driver: SQLite needs one
// only for the read connections knob, Postgres names its container and its
// password file (the file the test writes to the configuration directory).
func TestLoadDatabaseYAML(t *testing.T) {
	for _, c := range []struct {
		name, driver, readConns, maxConns, want string
	}{
		{"sqlite default writes no file", "sqlite", "", "", ""},
		{"sqlite read connections", "sqlite", "2", "", "driver: sqlite\nsqlite:\n  path: /var/lib/featherauth/featherauth.db\n  read_connections: 2\n"},
		{"postgres", "postgres", "", "", "driver: postgres\npostgres:\n  host: postgres\n  password_file: secrets/postgres_password\n  sslmode: disable\n"},
		{"postgres pool size", "postgres", "", "100", "driver: postgres\npostgres:\n  host: postgres\n  password_file: secrets/postgres_password\n  sslmode: disable\n  max_open_conns: 100\n"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := loadDatabaseYAML(c.driver, c.readConns, c.maxConns); got != c.want {
				t.Errorf("loadDatabaseYAML(%q, %q, %q) =\n%q\nwant\n%q", c.driver, c.readConns, c.maxConns, got, c.want)
			}
		})
	}
}

// Docker prints the memory of a container as "used / limit", with binary
// units; the load tables are in kB (1024 bytes), as /proc/<pid>/status.
func TestParseDockerMemUsage(t *testing.T) {
	for _, c := range []struct {
		in   string
		want int
		err  bool
	}{
		{"38.5MiB / 7.6GiB", 39424, false},
		{"1.2GiB / 7.6GiB", 1258291, false},
		{"512KiB / 1GiB", 512, false},
		{"100B / 0B", 0, false},
		{"", 0, true},
		{"n/a", 0, true},
		{"12XB / 1GiB", 0, true},
	} {
		t.Run(c.in, func(t *testing.T) {
			got, err := parseDockerMemUsage(c.in)
			if (err != nil) != c.err {
				t.Fatalf("parseDockerMemUsage(%q) error = %v, want error %v", c.in, err, c.err)
			}
			if got != c.want {
				t.Errorf("parseDockerMemUsage(%q) = %d kB, want %d", c.in, got, c.want)
			}
		})
	}
}

// The held peak and burst figures of NFR-03 and NFR-04 per driver, as
// docs/REQUIREMENTS.md publishes them and DESIGN.md (Load verification, Decide)
// states them. A measurement at or above its figure fails; there is no margin.
func TestPeakLimitsPerDriver(t *testing.T) {
	for _, c := range []struct {
		driver                                string
		userinfoP95, jwksP95, tokenP99, burst float64
	}{
		{"sqlite", 3, 2, 15000, 3000},
		{"postgres", 5000, 64, 7000, 3000},
	} {
		got := peakLimitsFor(c.driver)
		if got.userinfoP95 != c.userinfoP95 || got.jwksP95 != c.jwksP95 || got.tokenP99 != c.tokenP99 || got.burstTokenP99 != c.burst {
			t.Errorf("%s: limits %+v, want userinfo %v jwks %v token %v burst %v ms", c.driver, got, c.userinfoP95, c.jwksP95, c.tokenP99, c.burst)
		}
	}
}

// overLimit is the whole rule: at the figure fails, no margin; a missing
// measurement (negative) fails too.
func TestOverLimitHasNoMargin(t *testing.T) {
	for _, c := range []struct {
		name            string
		measured, limit float64
		want            bool
	}{
		{"below", 2.99, 3, false},
		{"at the figure", 3, 3, true},
		{"just above", 3.01, 3, true},
		{"twenty percent above", 3.6, 3, true},
		{"no measurement", -1, 3, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := overLimit(c.measured, c.limit); got != c.want {
				t.Errorf("overLimit(%v, %v) = %v, want %v", c.measured, c.limit, got, c.want)
			}
		})
	}
}

// The compose profiles of a command of the load stack: the Postgres container
// needs --profile postgres in every command that must see it (up and the
// teardown), and k6 needs --profile run. COMPOSE_PROFILES is not used, because
// a --profile flag replaces it, so the teardown would miss the container.
func TestComposeProfilesPerDriver(t *testing.T) {
	for _, c := range []struct {
		name, driver string
		run          bool
		want         []string
	}{
		{"sqlite up", "sqlite", false, nil},
		{"sqlite teardown", "sqlite", true, []string{"--profile", "run"}},
		{"postgres up", "postgres", false, []string{"--profile", "postgres"}},
		{"postgres teardown", "postgres", true, []string{"--profile", "run", "--profile", "postgres"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := composeProfiles(c.driver, c.run); !slices.Equal(got, c.want) {
				t.Errorf("composeProfiles(%q, %v) = %v, want %v", c.driver, c.run, got, c.want)
			}
		})
	}
}

// composeProfiles returns the --profile flags of a compose command of the load
// stack: postgres with driver postgres, and run (k6 and its teardown) when run
// is set. The flags go after -f file.
func composeProfiles(driver string, run bool) []string {
	var args []string
	if run {
		args = append(args, "--profile", "run")
	}
	if driver == "postgres" {
		args = append(args, "--profile", "postgres")
	}
	return args
}

// loadPgContainer is the Postgres container of the Postgres variant (compose
// project featherauth-load, service postgres).
const loadPgContainer = "featherauth-load-postgres-1"

// loadDriver is the driver of this load run, from LOAD_DRIVER: sqlite (the
// default) or postgres.
func loadDriver(t *testing.T) string {
	t.Helper()
	switch d := os.Getenv("LOAD_DRIVER"); d {
	case "", "sqlite":
		return "sqlite"
	case "postgres":
		return "postgres"
	default:
		t.Fatalf("LOAD_DRIVER %q: want sqlite or postgres", d)
		return ""
	}
}

// resultsFile is the file in LOAD_OUT that a run's report goes to: results.txt
// for SQLite and results-postgres.txt for Postgres, so that neither run
// overwrites the other's report.
func resultsFile(driver string) string {
	if driver == "postgres" {
		return "results-postgres.txt"
	}
	return "results.txt"
}

// loadDatabaseYAML is the database.yaml the load stack writes: nothing for
// SQLite unless readConns (the read connections knob) is set, and the Postgres
// block for the Postgres variant, which reaches the container by its service
// name on the compose network (no TLS there, as in compose.postgres.yaml). A
// non-empty maxConns (LOAD_PG_MAX_CONNS, an experiment) sets the pool size.
func loadDatabaseYAML(driver, readConns, maxConns string) string {
	if driver == "postgres" {
		y := "driver: postgres\npostgres:\n  host: postgres\n  password_file: secrets/postgres_password\n  sslmode: disable\n"
		if maxConns != "" {
			y += "  max_open_conns: " + maxConns + "\n"
		}
		return y
	}
	if readConns == "" {
		return ""
	}
	return "driver: sqlite\nsqlite:\n  path: /var/lib/featherauth/featherauth.db\n  read_connections: " + readConns + "\n"
}

// peakLimits are the held peak and burst limits in milliseconds of a driver:
// NFR-03 (userinfo and JWKS p95), NFR-04 (refresh p99 at the held peak and at
// the burst).
type peakLimits struct {
	userinfoP95, jwksP95, tokenP99, burstTokenP99 float64
}

func peakLimitsFor(driver string) peakLimits {
	if driver == "postgres" {
		return peakLimits{userinfoP95: 5000, jwksP95: 64, tokenP99: 7000, burstTokenP99: 3000}
	}
	return peakLimits{userinfoP95: 3, jwksP95: 2, tokenP99: 15000, burstTokenP99: 3000}
}

// overLimit reports a measurement that fails its figure: at or above it, or
// not measured (negative).
func overLimit(measured, limit float64) bool { return measured < 0 || measured >= limit }

var dockerUnits = map[string]float64{
	"B": 1, "kB": 1e3, "KB": 1e3, "KiB": 1 << 10, "MB": 1e6, "MiB": 1 << 20,
	"GB": 1e9, "GiB": 1 << 30, "TB": 1e12, "TiB": 1 << 40,
}

var dockerMemRe = regexp.MustCompile(`^([0-9.]+)([A-Za-z]+)$`)

// parseDockerMemUsage reads the used part of docker stats' MemUsage ("38.5MiB /
// 7.6GiB") and returns it in kB of 1024 bytes.
func parseDockerMemUsage(s string) (int, error) {
	used, _, _ := strings.Cut(s, " / ")
	m := dockerMemRe.FindStringSubmatch(strings.TrimSpace(used))
	if m == nil {
		return 0, fmt.Errorf("docker memory %q: no number and unit", s)
	}
	unit, ok := dockerUnits[m[2]]
	if !ok {
		return 0, fmt.Errorf("docker memory %q: unit %q unknown", s, m[2])
	}
	n, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0, fmt.Errorf("docker memory %q: %w", s, err)
	}
	return int(n * unit / 1024), nil
}

// pgStats reads the Postgres container once with docker stats: its memory in
// kB and its CPU as a percentage of one CPU, both -1 when docker fails. The
// container has no limit, so the memory is what Postgres uses, not a share.
func (s *loadStack) pgStats() (kB int, cpu float64) {
	out, err := s.docker("stats", "--no-stream", "--format", "{{.MemUsage}}|{{.CPUPerc}}", loadPgContainer)
	if err != nil {
		return -1, -1
	}
	mem, pct, _ := strings.Cut(strings.TrimSpace(out), "|")
	kB, err = parseDockerMemUsage(mem)
	if err != nil {
		return -1, -1
	}
	cpu, err = strconv.ParseFloat(strings.TrimSuffix(strings.TrimSpace(pct), "%"), 64)
	if err != nil {
		return -1, -1
	}
	return kB, cpu
}

// pgLine summarizes the Postgres container's readings of a run (memory and
// CPU), or "" for a run without Postgres.
func pgLine(xs []sample) string {
	lo, hi, sum, n, top := 1<<30, 0, 0.0, 0, 0.0
	for _, x := range xs {
		if x.pgKB < 0 {
			continue
		}
		lo, hi = min(lo, x.pgKB), max(hi, x.pgKB)
		sum += x.pgCPU
		top = max(top, x.pgCPU)
		n++
	}
	if n == 0 {
		return ""
	}
	return fmt.Sprintf("postgres container (apart from the service, no limit): memory %d..%d kB, CPU mean %.1f%% max %.1f%% of one CPU", lo, hi, sum/float64(n), top)
}

// TestPeakMemoryLimitPerDriver: the peak memory limit in kB is 120 MB for both
// drivers (the owner's target of 2026-11-21).
func TestPeakMemoryLimitPerDriver(t *testing.T) {
	if got := peakMemoryLimitKB("sqlite"); got != 120000 {
		t.Errorf("sqlite limit = %d kB, want 120000", got)
	}
	if got := peakMemoryLimitKB("postgres"); got != 120000 {
		t.Errorf("postgres limit = %d kB, want 120000", got)
	}
}

// peakMemoryLimitKB is the peak memory limit in kB of a driver (1000-byte kB,
// as the test has always compared): 120 MB for SQLite and Postgres alike.
func peakMemoryLimitKB(driver string) int {
	return 120 * 1000
}

package deploy_test

import (
	"os/exec"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// composeHA is the part of compose.ha.yaml the test reads.
type composeHA struct {
	Services map[string]struct {
		Ports       []string `yaml:"ports"`
		ReadOnly    bool     `yaml:"read_only"`
		CapDrop     []string `yaml:"cap_drop"`
		CapAdd      []string `yaml:"cap_add"`
		SecurityOpt []string `yaml:"security_opt"`
		Volumes     []string `yaml:"volumes"`
		DependsOn   map[string]struct {
			Condition string `yaml:"condition"`
		} `yaml:"depends_on"`
	} `yaml:"services"`
}

// Several instances: two FeatherAuth services on one Postgres, behind
// Caddy. The instances publish no port, only Caddy publishes one, on loopback;
// both instances keep the hardening of SEC-31; Caddy waits for both to answer
// their health check.
//
// Covers: FR-54 (part)
// Acceptance: Several instances (part)
func TestComposeHAHasTwoInstancesBehindCaddy(t *testing.T) {
	var c composeHA
	if err := yaml.Unmarshal([]byte(readFile(t, "compose.ha.yaml")), &c); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"postgres", "app1", "app2", "caddy"} {
		if _, ok := c.Services[name]; !ok {
			t.Fatalf("compose.ha.yaml has no %s service", name)
		}
	}
	for _, name := range []string{"app1", "app2"} {
		svc := c.Services[name]
		if len(svc.Ports) != 0 {
			t.Errorf("%s publishes %v; only Caddy publishes", name, svc.Ports)
		}
		if !svc.ReadOnly || !slices.Equal(svc.CapDrop, []string{"ALL"}) || len(svc.CapAdd) != 0 ||
			!slices.Contains(svc.SecurityOpt, "no-new-privileges:true") {
			t.Errorf("%s lacks the hardening of SEC-31", name)
		}
		if !slices.ContainsFunc(svc.Volumes, func(v string) bool { return strings.HasSuffix(v, ":/etc/featherauth:ro") }) {
			t.Errorf("%s does not mount the configuration read-only", name)
		}
		if svc.DependsOn["postgres"].Condition != "service_healthy" {
			t.Errorf("%s does not wait for Postgres to be healthy", name)
		}
	}
	caddy := c.Services["caddy"]
	if !slices.Equal(caddy.Ports, []string{"127.0.0.1:8080:8080"}) {
		t.Errorf("caddy ports %v, want only 127.0.0.1:8080", caddy.Ports)
	}
	for _, name := range []string{"app1", "app2"} {
		if caddy.DependsOn[name].Condition != "service_healthy" {
			t.Errorf("caddy starts before %s answers its health check", name)
		}
	}
	caddyfile := readFile(t, "Caddyfile.ha")
	for _, want := range []string{"app1:8080", "app2:8080", "health_uri /readyz", "lb_try_duration 30s", "lb_try_interval 250ms"} {
		if !slices.ContainsFunc(activeLines(caddyfile), func(l string) bool { return strings.Contains(l, want) }) {
			t.Errorf("Caddyfile.ha lacks an active %q", want)
		}
	}
	// The hold is by lb_try_duration alone: Caddy stops at whichever of the
	// duration and lb_retries comes first, so a count of tries would end the
	// hold within about a second when no instance is ready (More than one
	// instance).
	for _, l := range activeLines(caddyfile) {
		if strings.HasPrefix(l, "lb_retries") {
			t.Errorf("Caddyfile.ha has an active %q line", l)
		}
	}
	requireKeepaliveOff(t, "Caddyfile.ha", caddyfile)
}

// The scripts of the rolling deploy have a valid shell syntax (their behaviour
// is checked by TestOpsRollingDeploy with docker).
//
// Covers: FR-54 (part)
// Acceptance: Several instances (part)
func TestRollingDeployScriptsParse(t *testing.T) {
	for _, script := range []string{"ops/rolling-deploy.sh", "ops/check-rolling.sh"} {
		if out, err := exec.Command("sh", "-n", script).CombinedOutput(); err != nil {
			t.Errorf("%s: %v\n%s", script, err, out)
		}
	}
}

// composePostgresService is the hardening part of a postgres service.
type composePostgresService struct {
	Services map[string]struct {
		Image       string   `yaml:"image"`
		ReadOnly    bool     `yaml:"read_only"`
		CapDrop     []string `yaml:"cap_drop"`
		CapAdd      []string `yaml:"cap_add"`
		SecurityOpt []string `yaml:"security_opt"`
		Tmpfs       []string `yaml:"tmpfs"`
		Volumes     []string `yaml:"volumes"`
	} `yaml:"services"`
}

// The postgres service of compose.ha.yaml has the same hardening settings as
// that of compose.postgres.yaml, and both name exactly the add-backs, the
// tmpfs at /var/run/postgresql and no tmpfs at /tmp (SEC-44).
//
// Covers: SEC-44 (part)
// Acceptance: Hardened Postgres container (part)
func TestComposeHAPostgresHardeningMatchesComposePostgres(t *testing.T) {
	load := func(name string) composePostgresService {
		var c composePostgresService
		if err := yaml.Unmarshal([]byte(readFile(t, name)), &c); err != nil {
			t.Fatal(err)
		}
		if _, ok := c.Services["postgres"]; !ok {
			t.Fatalf("%s has no postgres service", name)
		}
		return c
	}
	single, ha := load("compose.postgres.yaml").Services["postgres"], load("compose.ha.yaml").Services["postgres"]
	for name, svc := range map[string]struct {
		ReadOnly    bool
		CapDrop     []string
		CapAdd      []string
		SecurityOpt []string
		Tmpfs       []string
	}{
		"compose.postgres.yaml": {single.ReadOnly, single.CapDrop, single.CapAdd, single.SecurityOpt, single.Tmpfs},
		"compose.ha.yaml":       {ha.ReadOnly, ha.CapDrop, ha.CapAdd, ha.SecurityOpt, ha.Tmpfs},
	} {
		if !svc.ReadOnly {
			t.Errorf("%s: the postgres root filesystem is not read-only", name)
		}
		if !slices.Equal(svc.CapDrop, []string{"ALL"}) {
			t.Errorf("%s: cap_drop %v, want [ALL]", name, svc.CapDrop)
		}
		if !slices.Equal(svc.CapAdd, []string{"CHOWN", "DAC_OVERRIDE", "SETGID", "SETUID"}) {
			t.Errorf("%s: cap_add %v, want CHOWN DAC_OVERRIDE SETGID SETUID", name, svc.CapAdd)
		}
		if !slices.Equal(svc.SecurityOpt, []string{"no-new-privileges:true"}) {
			t.Errorf("%s: security_opt %v, want no-new-privileges:true", name, svc.SecurityOpt)
		}
		if !slices.Equal(svc.Tmpfs, []string{"/var/run/postgresql"}) {
			t.Errorf("%s: tmpfs %v, want only /var/run/postgresql (no /tmp)", name, svc.Tmpfs)
		}
	}
	if !slices.Equal(single.Volumes, ha.Volumes) {
		t.Errorf("volumes differ: %v and %v", single.Volumes, ha.Volumes)
	}
	if single.Image != ha.Image {
		t.Errorf("the images differ: %s and %s", single.Image, ha.Image)
	}
}

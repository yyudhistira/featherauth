package deploy_test

import (
	"slices"
	"testing"

	"go.yaml.in/yaml/v3"
)

// The Postgres variant of the load stack (deploy/load/compose.yaml) runs
// Postgres in its own container, measured apart from the service: the image is
// the one compose.postgres.yaml pins, the container sits behind the profile
// postgres (so the SQLite runs do not start it), publishes no port, mounts the
// password file read-only, and the service waits for its health check only
// when the profile is on (required: false).
//
// Covers: FR-35 (part)
// Acceptance: Load on Postgres (part)
func TestLoadComposePostgresVariant(t *testing.T) {
	type service struct {
		Image    string   `yaml:"image"`
		Ports    []string `yaml:"ports"`
		Volumes  []string `yaml:"volumes"`
		Profiles []string `yaml:"profiles"`
		// DependsOn is a list in some services and a map in others.
		DependsOn any `yaml:"depends_on"`
	}
	var load struct {
		Services map[string]service `yaml:"services"`
		Volumes  map[string]any     `yaml:"volumes"`
	}
	if err := yaml.Unmarshal([]byte(readFile(t, "load/compose.yaml")), &load); err != nil {
		t.Fatal(err)
	}
	var pinned struct {
		Services map[string]service `yaml:"services"`
	}
	if err := yaml.Unmarshal([]byte(readFile(t, "compose.postgres.yaml")), &pinned); err != nil {
		t.Fatal(err)
	}
	pg, ok := load.Services["postgres"]
	if !ok {
		t.Fatal("deploy/load/compose.yaml has no postgres service")
	}
	if want := pinned.Services["postgres"].Image; pg.Image != want {
		t.Errorf("load postgres image %q, want the image compose.postgres.yaml pins: %q", pg.Image, want)
	}
	if !slices.Equal(pg.Profiles, []string{"postgres"}) {
		t.Errorf("postgres profiles = %v, want [postgres] so that the SQLite runs do not start it", pg.Profiles)
	}
	if len(pg.Ports) != 0 {
		t.Errorf("postgres publishes %v; the database must not be reachable from the host", pg.Ports)
	}
	if !slices.Contains(pg.Volumes, "postgres-data:/var/lib/postgresql") {
		t.Errorf("postgres volumes %v do not hold its data in the named volume postgres-data", pg.Volumes)
	}
	if _, ok := load.Volumes["postgres-data"]; !ok {
		t.Error("the volume postgres-data is not declared")
	}
	if !slices.Contains(pg.Volumes, "${LOAD_CONFIG:?}/secrets/postgres_password:/run/secrets/postgres_password:ro") {
		t.Errorf("postgres volumes %v do not mount the password file read-only", pg.Volumes)
	}
	deps, _ := load.Services["featherauth"].DependsOn.(map[string]any)
	dep, _ := deps["postgres"].(map[string]any)
	if dep["condition"] != "service_healthy" || dep["required"] != false {
		t.Errorf("featherauth depends on postgres as %v, want condition service_healthy with required: false", dep)
	}
}

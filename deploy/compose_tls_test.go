package deploy_test

import (
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// composeTLS is the part of compose.tls.yaml the test reads.
type composeTLS struct {
	Services map[string]struct {
		Ports       []string `yaml:"ports"`
		Volumes     []string `yaml:"volumes"`
		ReadOnly    bool     `yaml:"read_only"`
		CapDrop     []string `yaml:"cap_drop"`
		CapAdd      []string `yaml:"cap_add"`
		SecurityOpt []string `yaml:"security_opt"`
		Tmpfs       []string `yaml:"tmpfs"`
	} `yaml:"services"`
}

// Built-in TLS runs the service alone and publishes its HTTPS and redirect
// listeners as the host's ports 443 and 80, with the settings of SEC-31 kept:
// read-only root, every capability dropped, no capability added, no new
// privileges. The loopback listener is not published.
//
// Covers: FR-52 (part), SEC-41 (part), SEC-31 (part)
// Acceptance: Built-in TLS with files (part)
func TestComposeTLSPublishesHTTPSAndRedirectWithTheHardening(t *testing.T) {
	var c composeTLS
	if err := yaml.Unmarshal([]byte(readFile(t, "compose.tls.yaml")), &c); err != nil {
		t.Fatal(err)
	}
	if len(c.Services) != 1 {
		t.Fatalf("compose.tls.yaml runs %d services, want featherauth alone", len(c.Services))
	}
	svc, ok := c.Services["featherauth"]
	if !ok {
		t.Fatal("compose.tls.yaml has no featherauth service")
	}
	if want := []string{"443:8443", "80:8081"}; !slices.Equal(svc.Ports, want) {
		t.Errorf("ports %v, want %v: the host's 443 and 80 to the HTTPS and redirect listeners", svc.Ports, want)
	}
	if !svc.ReadOnly {
		t.Error("the root filesystem is not read-only")
	}
	if !slices.Equal(svc.CapDrop, []string{"ALL"}) {
		t.Errorf("cap_drop %v, want [ALL]", svc.CapDrop)
	}
	if len(svc.CapAdd) != 0 {
		t.Errorf("cap_add %v: built-in TLS needs no capability", svc.CapAdd)
	}
	if !slices.Contains(svc.SecurityOpt, "no-new-privileges:true") {
		t.Errorf("security_opt %v lacks no-new-privileges", svc.SecurityOpt)
	}
	if !slices.ContainsFunc(svc.Tmpfs, func(s string) bool { return strings.HasPrefix(s, "/tmp") }) {
		t.Errorf("tmpfs %v lacks /tmp", svc.Tmpfs)
	}
	if !slices.ContainsFunc(svc.Volumes, func(v string) bool { return strings.HasSuffix(v, ":/etc/featherauth:ro") }) {
		t.Errorf("volumes %v: the configuration directory, with the pair in it, is not mounted read-only", svc.Volumes)
	}
}

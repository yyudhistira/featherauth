package deploy_test

import (
	"encoding/json"
	"regexp"
	"slices"
	"strings"
	"testing"
)

const exampleDir = "../examples/web-app/"

// Covers: FR-61 (part)
// Acceptance: Example web app project
// The example is its own Node project: exact versions of the dependencies the
// design names and no others, a lockfile with an integrity hash for each
// package, a Node version file the Dockerfile agrees with, and a Go module stub
// so that ./... of the FeatherAuth module never enters the tree.
func TestExampleWebAppIsASeparatePinnedProject(t *testing.T) {
	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal([]byte(readFile(t, exampleDir+"package.json")), &pkg); err != nil {
		t.Fatal(err)
	}
	wantDeps := []string{"jose", "oidc-client-ts", "react", "react-dom"}
	wantDev := []string{"@vitejs/plugin-react", "vite"}
	for _, set := range []struct {
		name string
		got  map[string]string
		want []string
	}{{"dependencies", pkg.Dependencies, wantDeps}, {"devDependencies", pkg.DevDependencies, wantDev}} {
		if len(set.got) != len(set.want) {
			t.Errorf("%s are %v, want exactly %v", set.name, set.got, set.want)
		}
		for _, name := range set.want {
			if !regexp.MustCompile(`^\d+\.\d+\.\d+$`).MatchString(set.got[name]) {
				t.Errorf("%s %s is %q, want an exact version", set.name, name, set.got[name])
			}
		}
	}

	var lock struct {
		Packages map[string]struct {
			Resolved  string `json:"resolved"`
			Integrity string `json:"integrity"`
		} `json:"packages"`
	}
	if err := json.Unmarshal([]byte(readFile(t, exampleDir+"package-lock.json")), &lock); err != nil {
		t.Fatal(err)
	}
	for path, p := range lock.Packages {
		if path == "" {
			continue
		}
		if !strings.HasPrefix(p.Integrity, "sha512-") || !strings.HasPrefix(p.Resolved, "https://registry.npmjs.org/") {
			t.Errorf("lockfile package %s has no integrity hash or a registry other than npmjs: %+v", path, p)
		}
	}

	if got := readFile(t, exampleDir+"go.mod"); strings.TrimSpace(got) != "module example.invalid/webapp" {
		t.Errorf("go.mod is %q, want only the module line", got)
	}

	node := strings.TrimSpace(readFile(t, exampleDir+".node-version"))
	if !regexp.MustCompile(`^\d+\.\d+\.\d+$`).MatchString(node) {
		t.Fatalf(".node-version is %q, want an exact version", node)
	}
	if !strings.Contains(readFile(t, exampleDir+"Dockerfile"), "FROM node:"+node+"-alpine@sha256:") {
		t.Errorf("the Dockerfile does not build with node %s pinned by digest", node)
	}
}

// Covers: FR-61 (part)
// Acceptance: Example web app images
// OPS-03: both images of the example's Dockerfile are pinned by digest, Caddy by
// the same version and digest as the compose files of this directory, and the
// compose file publishes the page on 127.0.0.1 only.
func TestExampleWebAppImagesArePinnedAndPublishedOnLoopback(t *testing.T) {
	df := readFile(t, exampleDir+"Dockerfile")
	from := regexp.MustCompile(`(?m)^FROM (\S+)`).FindAllStringSubmatch(df, -1)
	if len(from) != 2 {
		t.Fatalf("the Dockerfile has %d stages, want 2 (node, caddy)", len(from))
	}
	for _, m := range from {
		if !regexp.MustCompile(`@sha256:[0-9a-f]{64}$`).MatchString(m[1]) {
			t.Errorf("image %q is not pinned by digest", m[1])
		}
	}
	caddy := readCompose(t, "compose.caddy.yaml").Services["caddy"].Image
	if from[1][1] != caddy {
		t.Errorf("the example serves with %q, compose.caddy.yaml with %q", from[1][1], caddy)
	}
	svc, ok := readCompose(t, exampleDir+"compose.yaml").Services["web-app"]
	if !ok {
		t.Fatal("the example compose.yaml has no web-app service")
	}
	if len(svc.Ports) != 1 || svc.Ports[0] != "127.0.0.1:5173:5173" {
		t.Errorf("ports %v, want only 127.0.0.1:5173:5173", svc.Ports)
	}
	// The Caddyfile the Dockerfile writes sets the two security headers, and
	// config.json comes from the host file, read-only, so editing it needs no
	// rebuild.
	for _, want := range []string{
		`header Content-Security-Policy "default-src '"'"'self'"'"'; connect-src '"'"'self'"'"' https:; frame-ancestors '"'"'none'"'"'; base-uri '"'"'none'"'"'; object-src '"'"'none'"'"'"`,
		"header X-Content-Type-Options nosniff",
	} {
		if !strings.Contains(df, want) {
			t.Errorf("the Dockerfile's Caddyfile lacks %q", want)
		}
	}
	if len(svc.Volumes) == 0 || !slices.Contains(svc.Volumes, "./public/config.json:/srv/config.json:ro") {
		t.Errorf("volumes %v, want ./public/config.json:/srv/config.json:ro", svc.Volumes)
	}
}

// Covers: FR-61 (part)
// Acceptance: Example web app CI
// OPS-03: the browser job installs Node with an action pinned by commit hash,
// reading the version from .node-version, before make browser; make browser
// builds the example first, and make example runs npm ci and the build.
func TestCIBrowserJobBuildsTheExampleWithPinnedNode(t *testing.T) {
	w, _ := readWorkflow(t, "ci.yml")
	j := w.Jobs["browser"]
	node := stepIndex(j, func(s workflowStep) bool { return strings.HasPrefix(s.Uses, "actions/setup-node@") })
	run := stepIndex(j, func(s workflowStep) bool { return s.Run == "make browser" })
	if node < 0 || run < 0 || node > run {
		t.Fatalf("the browser job installs Node at step %d and runs make browser at %d", node, run)
	}
	s := j.Steps[node]
	if !regexp.MustCompile(`^actions/setup-node@[0-9a-f]{40}$`).MatchString(s.Uses) {
		t.Errorf("setup-node is %q, want a full commit hash", s.Uses)
	}
	if s.With["node-version-file"] != "examples/web-app/.node-version" {
		t.Errorf("node-version-file is %q", s.With["node-version-file"])
	}

	mk := readFile(t, "../Makefile")
	if !regexp.MustCompile(`(?m)^browser:.*\bexample\b`).MatchString(mk) {
		t.Error("make browser does not depend on example")
	}
	target := regexp.MustCompile(`(?ms)^example:.*?\n\n`).FindString(mk)
	for _, cmd := range []string{"npm ci", "npm run build"} {
		if !strings.Contains(target, cmd) {
			t.Errorf("make example does not run %q", cmd)
		}
	}
	if !strings.Contains(target, "examples/web-app") {
		t.Error("make example does not work in examples/web-app")
	}
}

package deploy_test

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The pinned actions of the signing steps, by the commit each release tag names
// (checked against the GitHub API when they were pinned): sigstore/cosign-installer
// v4.1.3, anchore/sbom-action v0.24.3 and actions/attest-build-provenance v4.2.2.
var signingPins = map[string]string{
	"sigstore/cosign-installer":       "756fe2d284c7292c4e9b62c8a28f1e5629c59532",
	"anchore/sbom-action":             "66cbf4bc1f1c0d2edc94016e65bc221b6bb0ad6c",
	"actions/attest-build-provenance": "4d101475d8b20a2381f78447822ac1eab6504dd8",
}

// Covers: SEC-42 (part)
// Acceptance: Signed images (part)
//
// compose.yaml and the other compose files of the image take FEATHERAUTH_TAG
// without a default: the image line fails with a message naming the variable, so
// a host never runs an image nobody chose.
func TestComposeFilesRequireTheImageTag(t *testing.T) {
	required := regexp.MustCompile(`image: ghcr\.io/yyudhistira/featherauth:\$\{FEATHERAUTH_TAG:\?[^}]*FEATHERAUTH_TAG[^}]*\}`)
	for _, name := range []string{"compose.yaml", "compose.tls.yaml", "compose.ha.yaml"} {
		text := readFile(t, name)
		if !required.MatchString(text) {
			t.Errorf("%s: the image line does not require FEATHERAUTH_TAG with a message naming it", name)
		}
		if strings.Contains(text, ":-latest") {
			t.Errorf("%s still falls back to the tag latest", name)
		}
	}
}

// Covers: SEC-42 (part)
// Acceptance: Signed images (part)
//
// The build job of deploy.yml alone gets id-token and attestations, and after the
// push it signs the image by digest, attaches the SPDX SBOM as an attestation and
// records the build provenance. Every action is pinned by the commit it names.
func TestDeployBuildSignsTheImageAfterThePush(t *testing.T) {
	w, _ := readWorkflow(t, "deploy.yml")
	build := w.Jobs["build"]
	want := map[string]string{"contents": "read", "packages": "write", "id-token": "write", "attestations": "write"}
	if len(build.Permissions) != len(want) {
		t.Fatalf("build permissions = %v, want %v", build.Permissions, want)
	}
	for k, v := range want {
		if build.Permissions[k] != v {
			t.Errorf("build permissions %s = %q, want %q", k, build.Permissions[k], v)
		}
	}
	for jn, j := range w.Jobs {
		if jn == "build" {
			continue
		}
		for _, k := range []string{"id-token", "attestations", "packages"} {
			if _, ok := j.Permissions[k]; ok && j.Permissions[k] == "write" {
				t.Errorf("job %s has %s: write; only build may", jn, k)
			}
		}
	}

	push := stepIndex(build, func(s workflowStep) bool { return strings.Contains(s.Run, "docker push") })
	if push < 0 {
		t.Fatal("build has no push step")
	}
	after := func(name string, match func(workflowStep) bool) int {
		t.Helper()
		i := stepIndex(build, match)
		if i < 0 {
			t.Fatalf("build has no %s step", name)
		}
		if i < push {
			t.Errorf("%s runs before the push", name)
		}
		return i
	}
	digest := after("digest record", func(s workflowStep) bool { return s.ID == "digest" })
	after("cosign install", func(s workflowStep) bool { return strings.HasPrefix(s.Uses, "sigstore/cosign-installer@") })
	sign := after("cosign sign", func(s workflowStep) bool { return strings.Contains(s.Run, "cosign sign") })
	sbom := after("SBOM", func(s workflowStep) bool { return strings.HasPrefix(s.Uses, "anchore/sbom-action@") })
	attest := after("cosign attest", func(s workflowStep) bool { return strings.Contains(s.Run, "cosign attest") })
	prov := after("build provenance", func(s workflowStep) bool { return strings.HasPrefix(s.Uses, "actions/attest-build-provenance@") })
	if !(digest < sign && sign < attest && sbom < attest && attest < prov) {
		t.Errorf("steps out of order: digest %d, sign %d, sbom %d, attest %d, provenance %d", digest, sign, sbom, attest, prov)
	}
	if s := build.Steps[sign]; !strings.Contains(s.Run, "cosign sign --yes") || !strings.Contains(s.Run, "$IMAGE_DIGEST") {
		t.Errorf("cosign sign does not sign the digest: %q", s.Run)
	}
	if s := build.Steps[attest]; !strings.Contains(s.Run, "--type spdxjson") {
		t.Errorf("cosign attest does not attach the SPDX SBOM: %q", s.Run)
	}
	if s := build.Steps[prov]; s.With["push-to-registry"] != "true" {
		t.Errorf("build provenance is not pushed to the registry: %v", s.With)
	}
	// Build provenance is stored by GitHub only for a public repository (a private
	// one gets "Feature not available for user-owned private repositories"), so the
	// step runs when the repository is public and is skipped otherwise. The
	// condition is the boolean of the event's repository, negated, so a payload
	// without the field runs the step and fails loudly rather than skipping it.
	if s := build.Steps[prov]; s.If != "${{ !github.event.repository.private }}" {
		t.Errorf("build provenance is not conditional on the repository being public: if = %q", s.If)
	}

	pin := regexp.MustCompile(`^([\w.-]+/[\w./-]+)@([0-9a-f]{40})$`)
	for _, s := range build.Steps {
		m := pin.FindStringSubmatch(s.Uses)
		if m == nil {
			if s.Uses != "" {
				t.Errorf("action %q is not pinned by a full commit SHA", s.Uses)
			}
			continue
		}
		if want, ok := signingPins[m[1]]; ok && want != m[2] {
			t.Errorf("%s is pinned to %s, the commit of its checked release is %s", m[1], m[2], want)
		}
	}
	for name := range signingPins {
		found := slices.ContainsFunc(build.Steps, func(s workflowStep) bool { return strings.HasPrefix(s.Uses, name+"@") })
		if !found {
			t.Errorf("build does not use %s", name)
		}
	}
}

package deploy_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Every container image and CI action the project uses names an immutable
// reference (OPS-03): a digest for an image, a commit hash for an action. Three
// things are not pinned and are named here: the image of this project in the
// shipped compose files, whose tag FEATHERAUTH_TAG must set (the compose file
// stops without it), a local action (./...), and an image that a compose file
// builds itself from a Dockerfile under a local name.

var (
	digestRef     = regexp.MustCompile(`@sha256:[0-9a-f]{64}$`)
	commitRef     = regexp.MustCompile(`^[^@\s]+@[0-9a-f]{40}$`)
	fromLine      = regexp.MustCompile(`(?im)^FROM\s+(?:--\S+\s+)*(\S+)(?:\s+AS\s+(\S+))?`)
	imageLine     = regexp.MustCompile(`(?m)^\s*image:\s*["']?([^\s"'#]+)`)
	usesLine      = regexp.MustCompile(`(?m)^\s*(?:-\s*)?uses:\s*["']?([^\s"'#]+)`)
	projectImage  = regexp.MustCompile(`^ghcr\.io/[^/\s]+/featherauth:\$\{FEATHERAUTH_TAG:\?`)
	buildLine     = regexp.MustCompile(`(?m)^\s*build:`)
	tagVariable   = regexp.MustCompile(`\$\{FEATHERAUTH_TAG(:?[-+=?])?`)
	localBuildRef = regexp.MustCompile(`^featherauth-[a-z0-9-]+:[a-z0-9.-]+$`)
)

// unpinnedReferences returns what is not pinned in one file, by its kind: a
// Dockerfile, a compose file or a workflow.
func unpinnedReferences(kind, content string) []string {
	var bad []string
	switch kind {
	case "dockerfile":
		stages := map[string]bool{"scratch": true}
		for _, m := range fromLine.FindAllStringSubmatch(content, -1) {
			if !digestRef.MatchString(m[1]) && !stages[strings.ToLower(m[1])] {
				bad = append(bad, "FROM "+m[1])
			}
			if m[2] != "" {
				stages[strings.ToLower(m[2])] = true
			}
		}
	case "compose":
		builds := buildLine.MatchString(content)
		for _, m := range imageLine.FindAllStringSubmatch(content, -1) {
			ref := m[1]
			switch {
			case digestRef.MatchString(ref), projectImage.MatchString(ref):
			case builds && localBuildRef.MatchString(ref):
			default:
				bad = append(bad, "image "+ref)
			}
		}
		for _, m := range tagVariable.FindAllStringSubmatch(content, -1) {
			if m[1] != ":?" { // a default (:- or -) or no check at all would pick a tag nobody chose
				bad = append(bad, "FEATHERAUTH_TAG without :? in "+m[0])
			}
		}
	case "workflow":
		for _, m := range usesLine.FindAllStringSubmatch(content, -1) {
			ref := m[1]
			if strings.HasPrefix(ref, "./") {
				continue
			}
			if strings.HasPrefix(ref, "docker://") {
				if !digestRef.MatchString(ref) {
					bad = append(bad, "uses "+ref)
				}
				continue
			}
			if !commitRef.MatchString(ref) {
				bad = append(bad, "uses "+ref)
			}
		}
	}
	return bad
}

// pinnedFiles returns the files of the repository by kind, without node_modules,
// test data and the git directory.
func pinnedFiles(t *testing.T) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	err := filepath.WalkDir("..", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "node_modules", ".git", "testdata", "dist":
				return fs.SkipDir
			}
			return nil
		}
		name := d.Name()
		slash := filepath.ToSlash(path)
		switch {
		case strings.HasPrefix(name, "Dockerfile"):
			out["dockerfile"] = append(out["dockerfile"], path)
		case strings.HasPrefix(name, "compose") && (strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml")):
			out["compose"] = append(out["compose"], path)
		case strings.Contains(slash, ".github/workflows/") && (strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml")):
			out["workflow"] = append(out["workflow"], path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range out {
		sort.Strings(v)
	}
	return out
}

// The Dockerfiles, compose files and workflows of the repository, the example
// web app's included, pin every image by digest and every action by commit hash;
// the setup-node action of the browser job is one of them. The rows of the table
// of fixtures prove the check finds a floating tag, a branch and a default tag.
//
// Acceptance: Pinned references
func TestEveryImageAndActionIsPinned(t *testing.T) {
	digest := "@sha256:" + strings.Repeat("a", 64)
	commit := "@" + strings.Repeat("b", 40)
	for _, tc := range []struct {
		name, kind, content string
		want                []string
	}{
		{"pinned from", "dockerfile", "FROM node:24-alpine" + digest + " AS build\nFROM caddy:2" + digest + "\n", nil},
		{"floating from", "dockerfile", "FROM node:24-alpine AS build\n", []string{"FROM node:24-alpine"}},
		{"from an earlier stage and scratch", "dockerfile", "FROM golang:1" + digest + " AS build\nFROM scratch\nFROM build\n", nil},
		{"from with a platform", "dockerfile", "FROM --platform=$BUILDPLATFORM golang:1\n", []string{"FROM golang:1"}},
		{"pinned image", "compose", "services:\n  a:\n    image: caddy:2" + digest + "\n", nil},
		{"floating image", "compose", "services:\n  a:\n    image: caddy:latest\n", []string{"image caddy:latest"}},
		{"image of the project with a required tag", "compose", "services:\n  a:\n    image: ghcr.io/o/featherauth:${FEATHERAUTH_TAG:?set it}\n", nil},
		{"image of the project with a default tag", "compose", "services:\n  a:\n    image: ghcr.io/o/featherauth:${FEATHERAUTH_TAG:-latest}\n", []string{"image ghcr.io/o/featherauth:${FEATHERAUTH_TAG:-latest}", "FEATHERAUTH_TAG without :? in ${FEATHERAUTH_TAG:-"}},
		{"local image of a build", "compose", "services:\n  a:\n    build: .\n    image: featherauth-x:local\n", nil},
		{"local looking image without a build", "compose", "services:\n  a:\n    image: featherauth-x:local\n", []string{"image featherauth-x:local"}},
		{"action by hash", "workflow", "jobs:\n  j:\n    steps:\n      - uses: actions/checkout" + commit + " # v1\n", nil},
		{"action by tag", "workflow", "jobs:\n  j:\n    steps:\n      - uses: actions/checkout@v4\n", []string{"uses actions/checkout@v4"}},
		{"action by short hash", "workflow", "jobs:\n  j:\n    steps:\n      - uses: actions/setup-node@949feb2\n", []string{"uses actions/setup-node@949feb2"}},
		{"local workflow", "workflow", "jobs:\n  j:\n    uses: ./.github/workflows/ci.yml\n", nil},
		{"docker action by tag", "workflow", "jobs:\n  j:\n    steps:\n      - uses: docker://alpine:3\n", []string{"uses docker://alpine:3"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := unpinnedReferences(tc.kind, tc.content)
			if strings.Join(got, "|") != strings.Join(tc.want, "|") {
				t.Fatalf("unpinned %q, want %q", got, tc.want)
			}
		})
	}

	files := pinnedFiles(t)
	for _, want := range []string{
		"../deploy/Dockerfile", "../deploy/conformance/Dockerfile.runner", "../examples/web-app/Dockerfile",
		"../deploy/compose.yaml", "../deploy/compose.postgres.yaml", "../deploy/load/compose.yaml", "../examples/web-app/compose.yaml",
		"../.github/workflows/ci.yml", "../.github/workflows/deploy.yml",
	} {
		found := false
		for _, group := range files {
			for _, f := range group {
				found = found || f == want
			}
		}
		if !found {
			t.Errorf("%s was not checked (found %v)", want, files)
		}
	}
	for kind, group := range files {
		for _, path := range group {
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			for _, bad := range unpinnedReferences(kind, string(b)) {
				t.Errorf("%s: %s is not pinned by a digest or a commit hash", path, bad)
			}
		}
	}
	ci := readFile(t, "../.github/workflows/ci.yml")
	if !regexp.MustCompile(`uses: actions/setup-node@[0-9a-f]{40}\b`).MatchString(ci) {
		t.Error("ci.yml has no actions/setup-node pinned by a commit hash")
	}
}

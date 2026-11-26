package deploy_test

import (
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

// errNoPreviousRelease means there is neither PREV_IMAGE nor a release tag: the
// upgrade ops tests skip on it, and on nothing else.
var errNoPreviousRelease = errors.New("no previous release to upgrade from")

// previousRelease decides what the upgrade ops tests upgrade from. With prevImage
// set it returns that image as is. Otherwise a shallow repository is an error
// (a checkout without the tags must never pass for "no release"), and the newest
// tag vMAJOR.MINOR.PATCH is returned; with no such tag the error is
// errNoPreviousRelease. Every other failure is a plain error.
func previousRelease(dir, prevImage string) (image, tag string, err error) {
	if prevImage != "" {
		return prevImage, "", nil
	}
	run := func(args ...string) (string, error) {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		out, err := cmd.Output()
		return strings.TrimSpace(string(out)), err
	}
	shallow, err := run("rev-parse", "--is-shallow-repository")
	if err != nil {
		return "", "", fmt.Errorf("git rev-parse --is-shallow-repository: %w", err)
	}
	if shallow == "true" {
		return "", "", errors.New("fetch the full history and the tags (fetch-depth: 0, fetch-tags: true)")
	}
	out, err := run("tag", "-l", "--sort=-version:refname", "v[0-9]*.[0-9]*.[0-9]*")
	if err != nil {
		return "", "", fmt.Errorf("git tag -l: %w", err)
	}
	for _, line := range strings.Split(out, "\n") {
		if releaseTag.MatchString(line) {
			return "", line, nil
		}
	}
	return "", "", errNoPreviousRelease
}

var releaseTag = regexp.MustCompile(`^v\d+\.\d+\.\d+$`)

// gitIn runs git in dir with a fixed identity and returns its output.
func gitIn(t *testing.T, dir string, args ...string) string {
	t.Helper()
	full := append([]string{"-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false", "-c", "protocol.file.allow=always"}, args...)
	cmd := exec.Command("git", full...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// sourceRepo makes a repository with two commits and the given tags on the first.
func sourceRepo(t *testing.T, tags ...string) string {
	t.Helper()
	dir := t.TempDir()
	gitIn(t, dir, "init", "-q")
	gitIn(t, dir, "commit", "-q", "--allow-empty", "-m", "one")
	for _, tag := range tags {
		gitIn(t, dir, "tag", tag)
	}
	gitIn(t, dir, "commit", "-q", "--allow-empty", "-m", "two")
	return dir
}

// The upgrade ops tests decide in previousRelease which previous image they use;
// the decision is checked here, without docker, on temporary repositories. It
// proves the precondition of the upgrade rows only (OPS-04 to OPS-06 in the
// design), not the upgrade itself.
//
// Acceptance: Upgrade, rollback and migration time on SQLite (part)
// Acceptance: Upgrade, rollback and migration time on Postgres (part)
func TestPreviousReleaseDecision(t *testing.T) {
	tagged := sourceRepo(t, "v0.4.0", "v0.5.0", "v0.10.0", "not-a-release")
	untagged := sourceRepo(t)
	shallow := t.TempDir()
	gitIn(t, shallow, "clone", "-q", "--depth", "1", "file://"+tagged, ".")
	if gitIn(t, shallow, "rev-parse", "--is-shallow-repository") != "true" {
		t.Fatal("the fixture clone is not shallow")
	}
	full := t.TempDir()
	gitIn(t, full, "clone", "-q", "--tags", "file://"+tagged, ".")
	noTags := t.TempDir()
	gitIn(t, noTags, "clone", "-q", "--no-tags", "file://"+tagged, ".")

	tests := []struct {
		name      string
		dir, prev string
		wantImage string
		wantTag   string
		wantErr   error
		wantText  string
	}{
		{name: "shallow clone fails", dir: shallow, wantText: "fetch the full history and the tags (fetch-depth: 0, fetch-tags: true)"},
		{name: "full clone uses the newest tag", dir: full, wantTag: "v0.10.0"},
		{name: "full clone without a tag skips", dir: untagged, wantErr: errNoPreviousRelease},
		{name: "full clone without tags skips", dir: noTags, wantErr: errNoPreviousRelease},
		{name: "PREV_IMAGE is used as is", dir: untagged, prev: "example/image:1", wantImage: "example/image:1"},
		{name: "PREV_IMAGE wins over a shallow clone", dir: shallow, prev: "example/image:2", wantImage: "example/image:2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			image, tag, err := previousRelease(tt.dir, tt.prev)
			switch {
			case tt.wantErr != nil:
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("err = %v, want %v", err, tt.wantErr)
				}
			case tt.wantText != "":
				if err == nil || errors.Is(err, errNoPreviousRelease) || !strings.Contains(err.Error(), tt.wantText) {
					t.Fatalf("err = %v, want one containing %q and not the skip", err, tt.wantText)
				}
			case err != nil:
				t.Fatal(err)
			}
			if image != tt.wantImage || tag != tt.wantTag {
				t.Errorf("image, tag = %q, %q; want %q, %q", image, tag, tt.wantImage, tt.wantTag)
			}
		})
	}
}

// A directory that is not a git repository is an error, not a skip.
//
// Acceptance: Upgrade, rollback and migration time on SQLite (part)
func TestPreviousReleaseNotARepositoryFails(t *testing.T) {
	_, _, err := previousRelease(t.TempDir(), "")
	if err == nil || errors.Is(err, errNoPreviousRelease) {
		t.Fatalf("err = %v, want a failure that is not the skip", err)
	}
}

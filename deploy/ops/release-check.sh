#!/bin/sh
# The release check (make release-check): every release check a program can do,
# in the order of DESIGN.md (Test suites outside make check, Release check) and
# docs/RELEASING.md (The release check). One line per item (pass, fail, or
# skipped: no change since <hash>), the run stops at the first failure and names
# it, and the result lines for the release gate section of docs/RESULTS.md are
# written to release-out/results.md.
#
#   sh deploy/ops/release-check.sh              items 1 to 10, on the checked-out commit
#                                               (items 1 and 2 only on the gate commit: the short path)
#   TAG=vX.Y.Z sh deploy/ops/release-check.sh   items 11 to 13, on the published release
#
# Needs git, gh (logged in), cosign, docker, jq, go and npm, and network access.
# Variables: TAG; RELEASE_CONFIG_DIR (a real configuration directory for item 4);
# RELEASE_REPO (default yyudhistira/featherauth); RELEASE_IMAGE (default
# ghcr.io/<repo>); RELEASE_OUT (default release-out); RELEASE_REMOTE (default
# origin, where item 13 reads the tags); PREV_IMAGE (item 5: the previous
# release's image, default the newest release tag's image).
#
# The script writes only pass, fail, not applicable and no change since values,
# never an acceptance (RELEASING.md). It never runs conformance or load unless the
# shared path list deploy/release-paths.txt says their area changed.
set -u
set -f # the path lists hold globs (deploy/load*_test.go) that git expands, not the shell

root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root" || exit 2
slug=${RELEASE_REPO:-yyudhistira/featherauth}
image=${RELEASE_IMAGE:-ghcr.io/$slug}
outdir=${RELEASE_OUT:-release-out}
remote=${RELEASE_REMOTE:-origin}
iss=https://token.actions.githubusercontent.com
alpine_img=alpine:3.22@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f
paths_file=deploy/release-paths.txt
results_file=docs/RESULTS.md
mkdir -p "$outdir" || exit 2
results=$outdir/results.md
: >"$results"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# emit N NAME KIND ARG DETAIL: prints the item's line and records its result.
# KIND: pass, fail, nochange (ARG is the hash), na (ARG is the reason).
emit() {
  case $2:$3 in
    *:pass) shown=pass rec=pass ;;
    *:fail) shown=fail rec=fail ;;
    *:nochange) shown="skipped: no change since $4" rec="no change since $4" ;;
    *:na) shown="not applicable: $4" rec="not applicable: $4" ;;
  esac
  printf 'item %s: %s: %s\n' "$1" "$2" "$shown"
  printf '| %s | %s | %s |\n' "$1" "$rec" "$5" >>"$results"
}

# stop N NAME DETAIL: the item failed: record it, say why and stop.
stop() {
  emit "$1" "$2" fail "" "$3"
  echo "not ready: item $1 ($2) failed: $3"
  exit 1
}

# The paths of a check in deploy/release-paths.txt.
paths_of() { awk -v n="$1" '$1 == n { $1 = ""; print }' "$paths_file"; }

# section_commit TITLE: the first "- Commit: <hash>" of a "## TITLE" section of docs/RESULTS.md.
section_commit() {
  [ -f "$results_file" ] || return 0
  awk -v t="## $1" '
    /^## / { on = ($0 == t) }
    on && /^- Commit: [0123456789abcdef]{40}[ \t]*$/ { print $3; exit }' "$results_file"
}

# changed_since NAME HASH: 0 when the paths of the check changed since HASH, or
# HASH is empty or unknown (the check must run); 1 when they did not change.
changed_since() {
  [ -n "$2" ] || return 0
  git cat-file -e "$2^{commit}" 2>/dev/null || return 0
  # shellcheck disable=SC2046
  git diff --quiet "$2" HEAD -- $(paths_of "$1") 2>/dev/null && return 1
  return 0
}

digest_of() { docker buildx imagetools inspect "$1" --format '{{json .Manifest}}' 2>/dev/null | jq -r .digest 2>/dev/null; }

jobs_of() { gh api "repos/$slug/actions/runs/$1/jobs?per_page=100" --jq '.jobs[] | [.name, .conclusion] | @tsv' 2>/dev/null; }

# required_jobs_ok: reads "name<TAB>conclusion" lines (names may carry the prefix
# "checks / " of the reusable workflow and a matrix suffix). Every one of the
# jobs check, browser, ops and postgres must be present and every instance must
# be a success. Prints the problems and returns 1 otherwise.
required_jobs_ok() {
  awk -F'\t' '
    BEGIN { split("check browser ops postgres", req, " "); for (i in req) seen[req[i]] = 0 }
    { n = $1; sub(/^checks \/ /, "", n); sub(/ \(.*\)$/, "", n)
      for (i in req) if (n == req[i]) { seen[n]++; if ($2 != "success") bad = bad " " $1 "=" $2 } }
    END { for (i in req) if (seen[req[i]] == 0) bad = bad " " req[i] "=missing"
          if (bad != "") { print "jobs not green:" bad; exit 1 } }'
}

# ---------------------------------------------------------------- after the tag
if [ -n "${TAG:-}" ]; then
  case $TAG in
    v[0123456789]*.[0123456789]*.[0123456789]*) ;;
    *) echo "TAG must be vMAJOR.MINOR.PATCH" >&2; exit 2 ;;
  esac
  case $TAG in *[!v0123456789.]* | *..* | v.* | *.) echo "TAG must be vMAJOR.MINOR.PATCH" >&2; exit 2 ;; esac
  commit=$(git rev-list -n1 "refs/tags/$TAG" 2>/dev/null) || commit=
  [ -n "$commit" ] || stop 11 "tag run" "the tag $TAG is not in this repository (git fetch --tags)"

  # 11. The tag run.
  rel_digest=$(digest_of "$image:$TAG")
  case $rel_digest in sha256:*) ;; *) stop 11 "tag run" "the image $image:$TAG does not exist" ;; esac
  printed=$(docker run --rm "$image@$rel_digest" version 2>/dev/null | tr -d '\r\n')
  [ "$printed" = "$TAG" ] || stop 11 "tag run" "the image prints '$printed', want $TAG"
  run=$(gh api "repos/$slug/actions/workflows/deploy.yml/runs?event=push&per_page=100" \
    --jq '[.workflow_runs[] | select(.head_branch == "'"$TAG"'")] | max_by(.id) | [.id, .conclusion, .created_at] | @tsv' 2>/dev/null) || run=
  tab=$(printf '\t')
  IFS=$tab read -r run_id run_conclusion run_created <<EOF
$run
EOF
  [ -n "${run_id:-}" ] && [ "$run_id" != null ] || stop 11 "tag run" "no deploy run for the tag $TAG"
  [ "$run_conclusion" = success ] || stop 11 "tag run" "the deploy run $run_id of $TAG concluded $run_conclusion"
  tag_jobs=$(jobs_of "$run_id") || stop 11 "tag run" "the jobs of the tag run $run_id are not available (gh failed)"
  deploy_job=$(printf '%s\n' "$tag_jobs" | awk -F'\t' '$1 == "deploy" { print $2 }')
  [ "$deploy_job" != success ] || stop 11 "tag run" "the deploy job ran in the tag run $run_id (a tag never deploys)"
  versions=$(gh api "users/${slug%%/*}/packages/container/${slug##*/}/versions?per_page=100" --paginate \
    --jq '.[] | .created_at as $c | (.metadata.container.tags // [])[] | [., $c] | @tsv' 2>/dev/null) \
    || stop 11 "tag run" "the package versions are not available"
  printf '%s\n' "$versions" | awk -F'\t' '$1 == "latest" { found = 1 } END { exit !found }' && stop 11 "tag run" "the package has a latest tag"
  newhash=$(printf '%s\n' "$versions" | awk -F'\t' -v s="$run_created" '$1 ~ /^[0123456789abcdef]{40}$/ && $2 >= s { print $1 }' | head -n1)
  [ -z "$newhash" ] || stop 11 "tag run" "the tag run pushed a commit-hash tag: $newhash"
  emit 11 "tag run" pass "" "run $run_id, image $rel_digest prints $TAG, no latest, no new commit-hash tag"

  # 12. Signatures, SBOM and provenance, by digest, with the exact identity.
  commit_digest=$(digest_of "$image:$commit")
  case $commit_digest in sha256:*) ;; *) stop 12 "signatures" "the commit image $image:$commit does not exist" ;; esac
  for pair in "$rel_digest refs/tags/$TAG" "$commit_digest refs/heads/main"; do
    d=${pair%% *}
    id=https://github.com/$slug/.github/workflows/deploy.yml@${pair#* }
    cosign verify --certificate-oidc-issuer "$iss" --certificate-identity "$id" "$image@$d" >/dev/null 2>&1 \
      || stop 12 "signatures" "cosign verify failed for $image@$d with the identity ${pair#* }"
    cosign verify-attestation --type spdxjson --certificate-oidc-issuer "$iss" --certificate-identity "$id" "$image@$d" >/dev/null 2>&1 \
      || stop 12 "signatures" "cosign verify-attestation (SBOM) failed for $image@$d with the identity ${pair#* }"
  done
  private=$(gh api "repos/$slug" --jq .private 2>/dev/null) || stop 12 "signatures" "the repository is not readable by gh"
  if [ "$private" = false ]; then
    for d in "$rel_digest" "$commit_digest"; do
      gh attestation verify "oci://$image@$d" --repo "$slug" --signer-workflow "$slug/.github/workflows/deploy.yml" >/dev/null 2>&1 \
        || stop 12 "signatures" "gh attestation verify failed for $image@$d"
    done
    prov="provenance verified"
  else
    prov="gh attestation verify: not applicable (private repository)"
  fi
  emit 12 "signatures" pass "" "release $rel_digest and commit $commit_digest: signature and SBOM verified; $prov"

  # 13. Earlier release tags and digests against the table of the release gate.
  # The table of every release tag as it is now is written to the results.
  recorded=$(awk '/^### Release tags/ { on = 1; next } /^#/ { on = 0 }
    on && /^\| v[0123456789]+\.[0123456789]+\.[0123456789]+ \|/ { gsub(/[ |]+/, " "); print $1, $2, $3 }' "$results_file" 2>/dev/null)
  remote_tags=$(git ls-remote --tags "$remote" 'refs/tags/v*' 2>/dev/null) || stop 13 "release tags" "cannot read the tags of $remote"
  tag_commit() { # the commit a tag points to (peeled when annotated)
    printf '%s\n' "$remote_tags" | awk -v r="refs/tags/$1" '$2 == r "^{}" { p = $1 } $2 == r { c = $1 } END { print (p != "" ? p : c) }'
  }
  {
    printf '\n### Release tags\n\n| Tag | Commit | Image digest |\n| --- | --- | --- |\n'
    printf '%s\n' "$remote_tags" | awk '{ sub("refs/tags/", "", $2) } $2 !~ /\^\{\}$/ && $2 ~ /^v[0123456789]+\.[0123456789]+\.[0123456789]+$/ { print $2 }' | sort -V | while read -r t; do
      printf '| %s | %s | %s |\n' "$t" "$(tag_commit "$t")" "$(digest_of "$image:$t")"
    done
  } >>"$results"
  if [ -z "$recorded" ]; then
    emit 13 "earlier tags" na "first release: the table of release tags is only written" "table written to $results"
  else
    n=0
    while read -r t c d; do
      [ -n "$t" ] || continue
      n=$((n + 1))
      now=$(tag_commit "$t")
      [ "$now" = "$c" ] || stop 13 "earlier tags" "the tag $t moved: it was $c and is $now"
      nowd=$(digest_of "$image:$t")
      [ "$nowd" = "$d" ] || stop 13 "earlier tags" "the image of $t changed: it was $d and is $nowd"
    done <<EOF
$recorded
EOF
    emit 13 "earlier tags" pass "" "$n earlier tags and their image digests are unchanged"
  fi
  echo "post-tag checks passed"
  exit 0
fi

# ------------------------------------------------------------------- before the tag
sha=$(git rev-parse HEAD) || exit 2
tab=$(printf '\t')

# gate_row ROW: the value of a row of the release gate section of docs/RESULTS.md.
gate_row() { awk -F'|' -v k="$1" '/^## / { on = ($0 == "## Release gate") } on && $2 ~ "^ *" k " *$" { gsub(/^ +| +$/, "", $3); print $3 }' "$results_file" 2>/dev/null; }
gate_release=$(awk '/^## / { on = ($0 == "## Release gate") } on && /^- Release:/ { sub(/^- Release:[ \t]*/, ""); sub(/[ \t]+$/, ""); print; exit }' "$results_file" 2>/dev/null)

# Short path on the gate commit (DESIGN.md, Release check): the gate names a
# release with no tag yet and a commit that is a proper ancestor of HEAD, and
# the change between them is a documentation change by the rule and list of CI
# (changed-files.sh). Then the code its run checked is the code of HEAD: only
# items 1 and 2 run, and the gate's rows are checked. Any other case, and any
# failure of changed-files.sh, runs items 1 to 10.
short=
gate_commit=$(section_commit "Release gate")
case $gate_release in
  v[0123456789]*.[0123456789]*.[0123456789]*)
    if ! git rev-parse -q --verify "refs/tags/$gate_release" >/dev/null 2>&1 &&
      [ -n "$gate_commit" ] && [ "$gate_commit" != "$sha" ] &&
      git cat-file -e "$gate_commit^{commit}" 2>/dev/null &&
      git merge-base --is-ancestor "$gate_commit" "$sha" 2>/dev/null; then
      answer=$(GITHUB_OUTPUT='' sh deploy/ops/changed-files.sh "$slug" compare "$gate_commit" "$sha" 2>/dev/null) || answer=
      [ "$answer" != docs_only=true ] || short=1
    fi
    ;;
esac
if [ -n "$short" ]; then
  echo "gate: HEAD $sha differs from $gate_commit only in documentation files: items 3 to 10 as recorded in the release gate of $gate_release"
fi

# 1. The deploy run of the commit and every job of the checks. A deploy run of a
# documentation-only commit (its checks / docs job ran) counts when its scan and
# docs jobs are green and its first parent passes item 1 by these same rules,
# through at most 20 documentation-only commits.
cur=$sha
of=
docs_hops=0
how=
while :; do
  run=$(gh api "repos/$slug/actions/workflows/deploy.yml/runs?head_sha=$cur&event=push&per_page=100" \
    --jq '[.workflow_runs[] | select(.head_branch == "main" and .head_sha == "'"$cur"'")] | max_by(.id) | [.id, .conclusion] | @tsv' 2>/dev/null) \
    || stop 1 "CI of the commit" "${how}the workflow runs are not available (gh logged in?)"
  IFS=$tab read -r run_id run_conclusion <<EOF
$run
EOF
  [ -n "${run_id:-}" ] && [ "$run_id" != null ] || stop 1 "CI of the commit" "${how}no deploy run for the push of $cur to main"
  [ "$run_conclusion" = success ] || stop 1 "CI of the commit" "${how}the deploy run $run_id$of concluded $run_conclusion"
  jobs=$(jobs_of "$run_id") || stop 1 "CI of the commit" "${how}the jobs of deploy run $run_id are not available (gh failed)"
  docs_ran=$(printf '%s\n' "$jobs" | awk -F'\t' '$1 == "checks / docs" && $2 != "skipped" && $2 != "" { n++ } END { print n + 0 }')
  if [ "$docs_ran" -gt 0 ]; then
    docs_hops=$((docs_hops + 1))
    [ "$docs_hops" -le 20 ] || stop 1 "CI of the commit" "${how}more than 20 documentation-only commits before a commit whose checks ran in full"
    problems=$(printf '%s\n' "$jobs" | awk -F'\t' '
      BEGIN { seen["scan"] = 0; seen["docs"] = 0 }
      { n = $1; sub(/^checks \/ /, "", n); if (n in seen) { seen[n]++; if ($2 != "success") bad = bad " " $1 "=" $2 } }
      END { for (k in seen) if (seen[k] == 0) bad = bad " checks / " k "=missing"
            if (bad != "") { print "jobs not green:" bad; exit 1 } }') \
      || stop 1 "CI of the commit" "${how}deploy run $run_id$of is a documentation change: $problems"
    how="${how}deploy run $run_id of $cur is a documentation change (scan and docs green); "
    parent=$(git rev-parse -q --verify "$cur^1" 2>/dev/null) || stop 1 "CI of the commit" "${how}$cur has no parent"
    cur=$parent
    of=" of $cur"
    continue
  fi
  ran=$(printf '%s\n' "$jobs" | awk -F'\t' '$1 ~ /^checks/ && $2 != "skipped" && $2 != "" { n++ } END { print n + 0 }')
  if [ "$ran" -gt 0 ]; then
    problems=$(printf '%s\n' "$jobs" | required_jobs_ok) || stop 1 "CI of the commit" "${how}deploy run $run_id$of: $problems"
    how="${how}deploy run $run_id$of, its checks ran and every job is green"
  else
    head=$(gh api "repos/$slug/commits/$cur/pulls?per_page=100" \
      --jq '[.[] | select(.merged_at != null and .merge_commit_sha == "'"$cur"'") | .head.sha] | unique | .[]' 2>/dev/null) || head=
    case $head in
      "" | *[!0123456789abcdef]*) stop 1 "CI of the commit" "${how}the checks of deploy run $run_id$of were skipped and the merged pull request is not found" ;;
    esac
    ci=$(gh api "repos/$slug/actions/workflows/ci.yml/runs?head_sha=$head&event=pull_request&per_page=100" \
      --jq '[.workflow_runs[] | select(.head_sha == "'"$head"'")] | max_by(.id) | [.id, .conclusion] | @tsv' 2>/dev/null) || ci=
    IFS=$tab read -r ci_id ci_conclusion <<EOF
$ci
EOF
    [ -n "${ci_id:-}" ] && [ "$ci_id" != null ] || stop 1 "CI of the commit" "${how}the checks of deploy run $run_id$of were skipped and the ci run of the pull request is not found"
    [ "$ci_conclusion" = success ] || stop 1 "CI of the commit" "${how}the ci run $ci_id of the merged pull request concluded $ci_conclusion"
    ci_jobs=$(jobs_of "$ci_id") || stop 1 "CI of the commit" "${how}the jobs of ci run $ci_id are not available (gh failed)"
    problems=$(printf '%s\n' "$ci_jobs" | required_jobs_ok) || stop 1 "CI of the commit" "${how}ci run $ci_id: $problems"
    how="${how}deploy run $run_id$of (checks skipped), ci run $ci_id of the merged pull request, every job green"
  fi
  break
done
emit 1 "CI of the commit" pass "" "$how"

# 2. tools/trace/pending.txt has no entry.
pending=tools/trace/pending.txt
[ -f "$pending" ] || stop 2 "pending.txt" "$pending is missing"
entries=$(grep -v -e '^[[:space:]]*#' -e '^[[:space:]]*$' "$pending" | tr '\n' ' ')
[ -z "$entries" ] || stop 2 "pending.txt" "entries remain: $entries"
emit 2 "pending.txt" pass "" "no entry"

# The short path ends here: the gate's rows describe the commit it names, and
# rows 1 and 2 of this run describe HEAD. Every row 1 to 10 and M1 to M6 is
# filled and none is fail, and rows 1 and 2 are pass.
if [ -n "$short" ]; then
  problems=
  for r in 1 2 3 4 5 6 7 8 9 10 M1 M2 M3 M4 M5 M6; do
    v=$(gate_row "$r")
    if [ -z "$v" ]; then
      problems="$problems $r(empty)"
    elif [ "$v" = fail ]; then
      problems="$problems $r(fail)"
    elif { [ "$r" = 1 ] || [ "$r" = 2 ]; } && [ "$v" != pass ]; then
      problems="$problems $r(not pass)"
    fi
  done
  if [ -n "$problems" ]; then
    echo "not ready: the rows of the release gate in $results_file are not filled or are fail:$problems"
    exit 1
  fi
  echo "ready to tag"
  exit 0
fi

# 3. Modules against the Tech stack, govulncheck, and the example web app.
stack=$(awk '/^## Tech stack and code structure/ { on = 1; next } /^## / { on = 0 } on' docs/DESIGN.md)
[ -n "$stack" ] || stop 3 "modules" "the Tech stack section of docs/DESIGN.md is not found"
# Test tools of the repository rules (CLAUDE.md): not part of the stack table.
tools_allowed="golang.org/x/vuln honnef.co/go/tools"
direct=$(awk '
  /^require[ \t]*\(/ { on = 1; next }
  on && /^\)/ { on = 0; next }
  on && $0 !~ /\/\/ *indirect/ && NF >= 2 { print $1 }
  /^require[ \t]+[^(]/ && $0 !~ /\/\/ *indirect/ { print $2 }' go.mod)
[ -n "$direct" ] || stop 3 "modules" "no direct requirement found in go.mod"
for m in $direct; do
  ok=
  for a in $tools_allowed; do [ "$m" = "$a" ] && ok=1; done
  base=$(printf '%s' "$m" | sed 's#/v[0123456789][0123456789]*$##')
  short=${base#github.com/}
  if [ -z "$ok" ]; then
    printf '%s\n' "$stack" | grep -qF -e "$m" -e "$base" -e "$short" && ok=1
  fi
  [ -n "$ok" ] || stop 3 "modules" "the direct requirement $m is not in the Tech stack of docs/DESIGN.md"
done
make vuln >"$tmp/vuln.out" 2>&1 || stop 3 "modules" "govulncheck found something: $(tail -n 3 "$tmp/vuln.out" | tr '\n' ' ')"
pkg=examples/web-app/package.json
[ -f "$pkg" ] || stop 3 "modules" "$pkg is missing"
bad=$(jq -r '((.dependencies // {}) + (.devDependencies // {})) | to_entries[] | select(.value | test("^[0-9]+\\.[0-9]+\\.[0-9]+$") | not) | "\(.key)@\(.value)"' "$pkg") \
  || stop 3 "modules" "$pkg cannot be read"
[ -z "$bad" ] || stop 3 "modules" "the example web app has dependencies without an exact version: $(printf '%s' "$bad" | tr '\n' ' ')"
example_section=$(awk '/^## Example web app/ { on = 1; next } /^## / { on = 0 } on' docs/DESIGN.md)
[ -n "$example_section" ] || stop 3 "modules" "the Example web app section of docs/DESIGN.md is not found"
for n in $(jq -r '((.dependencies // {}) + (.devDependencies // {})) | keys[]' "$pkg"); do
  printf '%s\n' "$example_section" | grep -qF -- "$n" || stop 3 "modules" "the example web app depends on $n, which the Example web app section of docs/DESIGN.md does not name"
done
(cd examples/web-app && npm audit --omit=dev --audit-level=high) >"$tmp/npm.out" 2>&1 \
  || stop 3 "modules" "npm audit found a high vulnerability: $(tail -n 3 "$tmp/npm.out" | tr '\n' ' ')"
emit 3 "modules" pass "" "direct requirements are in the Tech stack, govulncheck and npm audit find nothing, exact versions in package.json"

# 4. The commit image: signature, then config check with no network.
digest=$(digest_of "$image:$sha")
case $digest in sha256:*) ;; *) stop 4 "config check" "the commit image $image:$sha does not exist" ;; esac
id=https://github.com/$slug/.github/workflows/deploy.yml@refs/heads/main
cosign verify --certificate-oidc-issuer "$iss" --certificate-identity "$id" "$image@$digest" >/dev/null 2>&1 \
  || stop 4 "config check" "cosign verify failed for $image@$digest with the identity of deploy.yml at refs/heads/main"
conf=featherauth-release-check-config-$$
cleanup_conf() { docker volume rm -f "$conf" >/dev/null 2>&1 || true; }
trap 'cleanup_conf; rm -rf "$tmp"' EXIT
docker volume create "$conf" >/dev/null 2>&1 || stop 4 "config check" "cannot create a docker volume"
docker run --rm --user 0 -v "$conf:/c" "$alpine_img" sh -c 'chown 65532:65532 /c && chmod 700 /c' >/dev/null 2>&1 \
  || stop 4 "config check" "cannot prepare the volume for the examples"
run_img() { docker run --rm --network none --user 65532:65532 "$@"; }
for step in "config init /etc/featherauth" \
  "keys generate /etc/featherauth/secrets/example/signing-2026-10.pem" \
  "keys generate --type ec /etc/featherauth/secrets/example/signing-ec-1.pem" \
  "keys generate --type encryption /etc/featherauth/secrets/encryption_key"; do
  # shellcheck disable=SC2086
  run_img -v "$conf:/etc/featherauth" "$image@$digest" $step >"$tmp/step.out" 2>&1 \
    || stop 4 "config check" "the example setup step '$step' failed: $(tail -n 2 "$tmp/step.out" | tr '\n' ' ')"
done
# config check prints its diagnostics on stdout; stderr holds docker's own notices
# (such as a platform mismatch), which are not configuration warnings.
run_img -v "$conf:/etc/featherauth:ro" "$image@$digest" config check /etc/featherauth >"$tmp/examples.out" 2>"$tmp/examples.err" \
  || stop 4 "config check" "config check of the shipped examples exited non-zero: $(cat "$tmp/examples.out" "$tmp/examples.err" | tr '\n' ' ')"
warn=$(grep -vx ok "$tmp/examples.out" | tr '\n' ' ')
detail="signature verified; config check of the shipped examples exit 0"
[ -z "$warn" ] || detail="$detail, warnings: $warn"
if [ -n "${RELEASE_CONFIG_DIR:-}" ]; then
  run_img -v "$RELEASE_CONFIG_DIR:/etc/featherauth:ro" "$image@$digest" config check /etc/featherauth >"$tmp/real.out" 2>"$tmp/real.err" \
    || stop 4 "config check" "config check of RELEASE_CONFIG_DIR exited non-zero: $(cat "$tmp/real.out" "$tmp/real.err" | tr '\n' ' ')"
  warn=$(grep -vx ok "$tmp/real.out" | tr '\n' ' ')
  detail="$detail; RELEASE_CONFIG_DIR exit 0"
  [ -z "$warn" ] || detail="$detail, warnings: $warn"
else
  detail="$detail; RELEASE_CONFIG_DIR not set: the shipped examples only"
fi
emit 4 "config check" pass "" "$detail"

# 5 and 6. The upgrade and the Postgres restore, as ops tests with two images.
prev_tag=$(git tag -l 'v[0123456789]*.[0123456789]*.[0123456789]*' | sort -V | tail -n 1)
prev=${PREV_IMAGE:-}
[ -n "$prev" ] || { [ -z "$prev_tag" ] || prev=$image:$prev_tag; }
if [ -z "$prev" ]; then
  emit 5 "upgrade and rollback" na "there is no previous release" "no release tag exists, so there is no previous image"
else
  docker pull "$prev" >/dev/null 2>&1 || stop 5 "upgrade and rollback" "cannot pull the previous image $prev"
  docker pull "$image:$sha" >/dev/null 2>&1 || stop 5 "upgrade and rollback" "cannot pull the commit image $image:$sha"
  PREV_IMAGE=$prev NEW_IMAGE=$image:$sha go test -tags ops -count=1 -v -timeout 60m -run '^TestOpsUpgrade' ./deploy/ >"$tmp/upgrade.out" 2>&1 \
    || stop 5 "upgrade and rollback" "the upgrade ops tests failed: $(grep -e '^--- FAIL' -e 'FAIL:' "$tmp/upgrade.out" | head -n 3 | tr '\n' ' ')"
  timings=$(grep -e 'migration time' "$tmp/upgrade.out" | sed 's/^[[:space:]]*[abcdefghijklmnopqrstuvwxyz_.]*:[0123456789]*: //' | tr '\n' ';')
  emit 5 "upgrade and rollback" pass "" "previous $prev, candidate $image:$sha, SQLite and Postgres; $timings"
fi
# The restore test starts containers from NEW_IMAGE and does not pull it; item 5,
# which pulls it otherwise, does not run at the first release.
docker pull "$image:$sha" >/dev/null 2>&1 || stop 6 "Postgres restore" "cannot pull the commit image $image:$sha"
NEW_IMAGE=$image:$sha go test -tags ops -count=1 -timeout 30m -run '^TestOpsPostgresRestore$' ./deploy/ >"$tmp/pgrestore.out" 2>&1 \
  || stop 6 "Postgres restore" "the Postgres restore ops test failed: $(tail -n 3 "$tmp/pgrestore.out" | tr '\n' ' ')"
emit 6 "Postgres restore" pass "" "pg_dump encrypted with age, restored on a clean Postgres, users and a refresh token intact"

# 7. Conformance, only when its paths changed since the commit of its section.
c=$(section_commit Conformance)
if changed_since conformance "$c"; then
  make conformance >"$tmp/conformance.out" 2>&1 \
    || stop 7 "conformance" "make conformance failed: $(tail -n 3 "$tmp/conformance.out" | tr '\n' ' ')"
  emit 7 "conformance" pass "" "make conformance on $sha; record the run in the conformance section of docs/RESULTS.md"
else
  emit 7 "conformance" nochange "$c" "the conformance paths of $paths_file did not change since $c"
fi

# 8. Load, SQLite then Postgres, only when its paths changed.
c=$(section_commit Load)
if changed_since load "$c"; then
  make load >"$tmp/load.out" 2>&1 || stop 8 "load" "make load failed: $(tail -n 3 "$tmp/load.out" | tr '\n' ' ')"
  make load LOAD_DRIVER=postgres >"$tmp/load-pg.out" 2>&1 \
    || stop 8 "load" "make load LOAD_DRIVER=postgres failed: $(tail -n 3 "$tmp/load-pg.out" | tr '\n' ' ')"
  emit 8 "load" pass "" "make load and make load LOAD_DRIVER=postgres on $sha; record the run in the load section of docs/RESULTS.md"
else
  emit 8 "load" nochange "$c" "the load paths of $paths_file did not change since $c"
fi

# 9. The manual checks with a path list: required, or no change since the commit of the latest result.
# browser and apple name the commit of the browser section; tls and workflow the
# commit of the previous release gate, when that gate's row passed or claimed no change.
manual_lines=
for pair in "M3 browser" "M4 apple" "M5 tls" "M6 workflow"; do
  row=${pair% *}
  name=${pair#* }
  case $name in
    browser | apple) c=$(section_commit Browser) ;;
    *)
      c=$(section_commit "Release gate")
      case $(gate_row "$row") in pass | "no change since "*) ;; *) c= ;; esac
      ;;
  esac
  if changed_since "$name" "$c"; then
    echo "item 9: manual check $row ($name): required"
    manual_lines="$manual_lines$row required;"
  else
    echo "item 9: manual check $row ($name): no change since $c"
    printf '| %s | no change since %s | the %s paths of %s did not change since %s |\n' "$row" "$c" "$name" "$paths_file" "$c" >>"$results"
  fi
done
emit 9 "manual checks" pass "" "listed above: required or no change since"

# 10. The result lines are written; the release is ready only when the manual rows are filled.
emit 10 "result lines" pass "" "written to $results"
# The rows count only when the section's "- Release:" names a version with no tag
# yet (the release being prepared); the section of an earlier release, or one
# naming no release, counts as empty. gate_release is read above.
gate_rows=1
note=
case $gate_release in
  v[0123456789]*.[0123456789]*.[0123456789]*)
    if git rev-parse -q --verify "refs/tags/$gate_release" >/dev/null 2>&1; then
      gate_rows=
      note=" (the gate names $gate_release, which is already tagged: write the section of the release being prepared)"
    fi
    ;;
  *) gate_rows=; note=" (the gate names no release version in its '- Release:' line)" ;;
esac
cell() { if [ -n "$gate_rows" ]; then gate_row "$1"; fi; }
problems=
for m in M1 M2 M3 M4 M5 M6; do
  v=$(cell "$m")
  [ -n "$v" ] || problems="$problems $m(empty)"
  [ "$v" != fail ] || problems="$problems $m(fail)"
done
for i in 1 2 3 4 5 6 7 8 9 10; do
  [ "$(cell "$i")" != fail ] || problems="$problems $i(fail)"
done
if [ -n "$problems" ]; then
  echo "not ready: the rows of the release gate in $results_file are not filled or are fail:$problems$note"
  exit 1
fi
echo "ready to tag"

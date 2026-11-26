#!/bin/sh
# Decides whether deploy.yml may skip its checks job:
#   sh deploy/ops/tested-tree.sh <owner/name> <40-hex sha> <branch|tag>
# Prints exactly one line, skip=true or skip=false, and appends it to the file
# named by $GITHUB_OUTPUT when that is set. It uses `gh api` only (GH_TOKEN comes
# from the environment).
#
# skip=true only when
#   branch: the commit is the merge commit of exactly one merged pull request
#           (all candidates must have the same head commit), and the newest
#           status ci/tested-tree on that head commit is in state success, was
#           created by github-actions[bot], and its description (a git tree
#           hash) is equal to the tree of the commit;
#   tag:    the commit has a successful deploy.yml run for a push to main.
# Every other case gives skip=false and exit 0: no pull request, a missing or
# different status, a failing gh, empty or malformed JSON, an unexpected shape.
# Nothing from an API answer is evaluated or printed except the final line.
# Bad usage exits 2 and prints nothing to stdout.
set -eu

if [ "$#" -ne 3 ]; then
  echo "usage: tested-tree.sh <owner/name> <sha> <branch|tag>" >&2
  exit 2
fi
repo=$1
sha=$2
mode=$3

# The values come from the workflow: accept only plain characters. $sha and
# $repo are put into endpoints and into jq expressions below.
case "$repo" in
  ""|/*|*/|*/*/*|-*|.*|*/.|*/..|*[!ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_./-]*) bad_repo=1 ;;
  */*) bad_repo=0 ;;
  *) bad_repo=1 ;;
esac
if [ "$bad_repo" -ne 0 ]; then echo "invalid repository" >&2; exit 2; fi
case "$sha" in
  *[!0123456789abcdef]*) echo "invalid sha" >&2; exit 2 ;;
esac
if [ "${#sha}" -ne 40 ]; then echo "invalid sha" >&2; exit 2; fi
case "$mode" in
  branch|tag) ;;
  *) echo "invalid mode" >&2; exit 2 ;;
esac

finish() {
  echo "skip=$1"
  if [ -n "${GITHUB_OUTPUT:-}" ]; then
    echo "skip=$1" >> "$GITHUB_OUTPUT"
  fi
  exit 0
}

no() {
  echo "checks run: $1" >&2
  finish false
}

is_sha() {
  case "$1" in
    ""|*[!0123456789abcdef]*) return 1 ;;
  esac
  [ "${#1}" -eq 40 ]
}

if [ "$mode" = tag ]; then
  n=$(gh api "repos/$repo/actions/workflows/deploy.yml/runs?head_sha=$sha&event=push&status=success&per_page=100" \
    --jq '[.workflow_runs[] | select(.head_branch == "main" and .conclusion == "success" and .event == "push" and .head_sha == "'"$sha"'")] | length' \
    2>/dev/null) || no "the list of workflow runs is not available"
  case "$n" in
    ""|0|*[!0123456789]*) no "no successful run on main for this commit" ;;
  esac
  echo "a successful run on main exists for this commit" >&2
  finish true
fi

# branch: the head commits of the merged pull requests whose merge commit is $sha.
heads=$(gh api "repos/$repo/commits/$sha/pulls?per_page=100" \
  --jq '[.[] | select(.merged_at != null and .merge_commit_sha == "'"$sha"'") | .head.sha] | unique | .[]' \
  2>/dev/null) || no "the pull requests are not available"
case "$heads" in
  "") no "no merged pull request" ;;
  *"
"*) no "more than one candidate pull request" ;;
esac
head=$heads
is_sha "$head" || no "unexpected pull request answer"

tab=$(printf '\t')
status=$(gh api "repos/$repo/commits/$head/statuses?per_page=100" \
  --jq '[.[] | select(.context == "ci/tested-tree")] | max_by(.id) | [.state, .creator.login, .description] | @tsv' \
  2>/dev/null) || no "the statuses are not available"
IFS=$tab read -r state login desc <<EOF2 || true
$status
EOF2
[ "$state" = success ] || no "no successful ci/tested-tree status"
[ "$login" = "github-actions[bot]" ] || no "the status was not created by github-actions[bot]"
is_sha "$desc" || no "the status description is not a tree hash"

tree=$(gh api "repos/$repo/git/commits/$sha" --jq .tree.sha 2>/dev/null) || no "the tree of the commit is not available"
is_sha "$tree" || no "unexpected commit answer"
[ "$tree" = "$desc" ] || no "the tree differs from the tested tree"
echo "the tree of this commit was tested on its pull request" >&2
finish true

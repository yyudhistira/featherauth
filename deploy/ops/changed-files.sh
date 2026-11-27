#!/bin/sh
# Decides whether a change is documentation-only:
#   sh deploy/ops/changed-files.sh <owner/name> compare <base 40-hex sha> <head 40-hex sha>
#   sh deploy/ops/changed-files.sh <owner/name> commit <40-hex sha>
# compare is for a pull request: the files between the two commits of the event
# (not the pull request's own file list, which GitHub may compute late).
# Prints exactly one line, docs_only=<true|false>, and appends it to the file
# named by $GITHUB_OUTPUT when that is set. It uses `gh api` only (GH_TOKEN comes
# from the environment).
#
# docs_only=true only when the list of changed files is read completely, is not
# empty, and every file is either a documentation file of the list below (under
# its filename and under its previous_filename) or a Go file whose change only
# adds or removes comments (see comment_only below). The list is documented in
# docs/DESIGN.md (CI/CD, "Documentation-only changes") and lives only here; the
# test TestOnlyTheReaderSetReadsDocumentation fails when it differs from the
# design, and when a test outside the reader set (the docs job of ci.yml), a
# tool, the Makefile or a workflow reads one of these files.
# A Go file with a comment-only patch is also fetched at the head commit and must
# hold no backquote (see comment_only below); at most 50 such files are fetched,
# more make the change a code change.
# GitHub lists at most 3000 files of a comparison and 300 of a commit: at the
# limit the list may be incomplete, so the answer is false.
# Every other case gives false and exit 0: a failing gh, empty or
# malformed JSON, an unexpected shape. Nothing from an API answer is evaluated or
# printed except the final line. Bad usage exits 2 and prints nothing to stdout.
set -eu
set -f

# BEGIN list
# doc_files: files by their path; doc_dirs: every file under these directories;
# doc_md_dirs: every file whose name ends in .md anywhere under these directories.
doc_files='README.md CLAUDE.md deploy/ASSETS.md examples/web-app/README.md tools/trace/pending.txt'
doc_dirs='.claude/'
doc_md_dirs='docs/'
# END list

usage() {
  echo "usage: changed-files.sh <owner/name> compare <base sha> <head sha> | <owner/name> commit <sha>" >&2
  exit 2
}
[ "$#" -ge 3 ] || usage
repo=$1
mode=$2

# The values come from the workflow: accept only plain characters. They are put
# into endpoints.
case "$repo" in
  ""|/*|*/|*/*/*|-*|.*|*/.|*/..|*[!ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_./-]*) bad_repo=1 ;;
  */*) bad_repo=0 ;;
  *) bad_repo=1 ;;
esac
if [ "$bad_repo" -ne 0 ]; then echo "invalid repository" >&2; exit 2; fi

check_sha() {
  case "$1" in
    *[!0123456789abcdef]*) echo "invalid sha" >&2; exit 2 ;;
  esac
  if [ "${#1}" -ne 40 ]; then echo "invalid sha" >&2; exit 2; fi
}

case "$mode" in
  compare)
    [ "$#" -eq 4 ] || usage
    check_sha "$3"
    check_sha "$4"
    endpoint="repos/$repo/compare/$3...$4?per_page=100"
    head_sha=$4
    limit=3000
    ;;
  commit)
    [ "$#" -eq 3 ] || usage
    check_sha "$3"
    endpoint="repos/$repo/commits/$3?per_page=100"
    head_sha=$3
    limit=300
    ;;
  *) echo "invalid mode" >&2; exit 2 ;;
esac

finish() {
  echo "docs_only=$1"
  if [ -n "${GITHUB_OUTPUT:-}" ]; then
    echo "docs_only=$1" >> "$GITHUB_OUTPUT"
  fi
  exit 0
}

no() {
  echo "not documentation-only: $1" >&2
  finish false
}

# One line "#" per file, then the filename and the previous filename (when it is
# not null) as JSON strings, then the line "=go" when the file is a Go file whose
# change only touches comments. A name with a newline stays on one line (@json),
# so it cannot pass for two names; a name that is not a string is not in the
# list. Both answers are an object with a files list, which GitHub paginates;
# with --paginate the filter runs on every page and the outputs are joined, so
# the files are counted over all pages.
#
# comment_only is true only when the file is a .go file of the module (plain
# name, not under testdata) that is modified in place (status modified, no
# previous_filename: not added, removed or renamed) and whose patch is a string
# that is complete (the number of + and - lines are the additions and deletions
# GitHub counts: a truncated patch differs) and in which
#   - no line, changed or context, holds a directive or a thing the compiler or
#     the tools read: //go:, // +build, //export, //line and /*line, import "C",
#     #cgo, #include, #define, Covers:, Acceptance: (a blank line next to a Covers:
#     line would detach it from its test, tools/trace reads it), Output: and
#     Unordered output: (Example functions are tests), lint:, nolint and
#     Deprecated: (tools read them);
#   - no changed line holds a backquote;
#   - every changed line is blank, starts with // or is inside a block comment
#     that is opened and closed in the same run of changed lines (a block comment
#     is closed only by */ followed by nothing or by a // comment; anything
#     else, such as code on the same line, is not comment-only).
# The added and the removed lines are checked as two separate texts. A context
# line, a hunk header or the end of the patch ends a run: a block comment still
# open there makes the file not comment-only. The patch cannot show whether a
# changed blank or // line is inside a raw string opened outside its window, so
# every Go file that passed these checks is also fetched at the head commit
# (contents API) and is comment-only only when the whole file holds no backquote
# at all (no raw string, no struct tag); a failed, empty, malformed or too large
# (not base64) answer makes it a code change. There is one fetch per file, none
# once the answer is false, and none at all when more than 50 Go files qualify
# (the rate limit of the token).
# The jq below runs in gh (gojq) and in the jq of the tests: only the common
# features are used.
names='def trim: sub("^[ \t\r]+"; "");
def closes: test("\\*/");
def after: sub("^.*?\\*/"; "") | trim;
def tail_ok: . == "" or startswith("//");
def step($b): trim as $t
  | if $b then
      if ($t | closes) then (if ($t | after | tail_ok) then {ok: true, b: false} else {ok: false, b: false} end)
      else {ok: true, b: true} end
    elif $t == "" or ($t | startswith("//")) then {ok: true, b: false}
    elif ($t | startswith("/*")) then
      ($t[2:]) as $a
      | if ($a | closes) then (if ($a | after | tail_ok) then {ok: true, b: false} else {ok: false, b: false} end)
        else {ok: true, b: true} end
    else {ok: false, b: false} end;
def comment_only:
  (.patch) as $p
  | if (.filename | type) != "string" or ($p | type) != "string" or $p == "" then false
    elif (.filename | test("^[A-Za-z0-9_./-]+\\.go$") | not) or (.filename | test("(^|/)testdata/")) then false
    elif .status != "modified" or .previous_filename != null then false
    elif ($p | test("//go:|// ?\\+build|//export|//line |/\\*line|import \"C\"|#cgo|#include|#define|Covers:|Acceptance:|Output:|Unordered output:|lint:|nolint|Deprecated:")) then false
    else
      . as $f
      | reduce ($p | split("\n"))[] as $l ({ok: true, mb: false, pb: false, a: 0, d: 0};
          ($l[0:1]) as $c
          | if $c == "+" or $c == "-" then
              ($l[1:]) as $body
              | (if $c == "+" then .pb else .mb end) as $b
              | ($body | step($b)) as $r
              | (if $body | test("`") then false else $r.ok end) as $ok
              | .ok = (.ok and $ok)
              | (if $c == "+" then .pb = $r.b | .a += 1 else .mb = $r.b | .d += 1 end)
            elif $c == "\\" then .
            else (if .mb or .pb then .ok = false else . end) | .mb = false | .pb = false
            end)
      | .ok and (.mb | not) and (.pb | not) and .a == $f.additions and .d == $f.deletions
    end;
.[] | "#", (.filename | @json), (if .previous_filename == null then empty else (.previous_filename | @json) end), (if comment_only then "=go" else empty end)'
out=$(gh api --paginate "$endpoint" \
  --jq '.files | if type == "array" then ('"$names"') else error("not a list") end' 2>/dev/null) ||
  no "the list of changed files is not available"

# A name is a JSON string here: "README.md" with its quotes.
is_doc() {
  for f in $doc_files; do
    if [ "$1" = "\"$f\"" ]; then return 0; fi
  done
  for d in $doc_dirs; do
    case "$1" in
      "\"$d"?*'"') return 0 ;;
    esac
  done
  for d in $doc_md_dirs; do
    case "$1" in
      "\"$d"?*'.md"') return 0 ;;
    esac
  done
  return 1
}

# A file is of one class: doc (every name in the list), go (a Go file with a
# comment-only change) or code (anything else). docs_only: no code file.
count=0
n_code=0
n_go=0
go_names=
nl='
'
cur_name=
cur=0 # 1 while a file is being read
names_n=0
all_doc=1
is_go=0

flush() {
  [ "$cur" -eq 1 ] || return 0
  if [ "$all_doc" -eq 1 ]; then
    :
  elif [ "$is_go" -eq 1 ]; then
    n_go=$((n_go + 1))
    go_names="$go_names$cur_name$nl"
  else
    n_code=$((n_code + 1))
  fi
}

while IFS= read -r line; do
  if [ -z "$line" ]; then
    continue # no output at all (an empty list) leaves one empty line
  elif [ "$line" = "#" ]; then
    flush
    count=$((count + 1))
    cur=1
    names_n=0
    all_doc=1
    is_go=0
  elif [ "$line" = "=go" ]; then
    is_go=1
  else
    names_n=$((names_n + 1))
    if [ "$names_n" -eq 1 ]; then cur_name=$line; fi
    if ! is_doc "$line"; then all_doc=0; fi
  fi
done <<EOF2
$out
EOF2
flush

[ "$count" -gt 0 ] || no "no files listed"
[ "$count" -lt "$limit" ] || no "the list may be incomplete ($limit files or more)"
[ "$n_code" -eq 0 ] || no "a file is not in the list"
[ "$n_go" -le 50 ] || no "more than 50 Go files would have to be fetched"

# A Go file is clean when its content at the head commit has no backquote. The
# name is plain (the jq above accepts only letters, digits and _ . / -).
clean_file() {
  p=${1#\"}
  p=${p%\"}
  r=$(gh api "repos/$repo/contents/$p?ref=$head_sha" \
    --jq 'if type == "object" and .type == "file" and .encoding == "base64" and (.content | type) == "string" and .content != "" then (.content | gsub("\n"; "") | @base64d | if contains("`") then "backquote" else "clean" end) else error("not a file") end' 2>/dev/null) || return 1
  [ "$r" = clean ]
}
while IFS= read -r g; do
  [ -n "$g" ] || continue
  clean_file "$g" || no "a Go file could not be read or holds a backquote"
done <<EOF3
$go_names
EOF3
echo "every changed file is in the list or only changes comments" >&2
finish true

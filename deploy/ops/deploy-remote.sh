#!/bin/sh
# Runs on the host, fed to `sh -s` over SSH by deploy.yml:
#   sh -s -- <new-tag> <directory-with-compose.yaml> < deploy-remote.sh
# Pulls and starts the new tag, waits up to READY_WAIT seconds (default 30) for
# /readyz (through `featherauth healthcheck` in the container), and on failure
# starts the previous tag again. Exits 0 only when the new tag is ready.
# It never touches the configuration directory.
set -eu

# The values come from the workflow through the remote shell: accept only
# plain characters, so nothing in them is interpreted.
if [ "$#" -ne 2 ]; then
  echo "usage: deploy-remote.sh <tag> <directory>" >&2
  exit 2
fi
tag=$1
dir=$2
case "$tag" in
  ""|[-.]*|*[!ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-]*) echo "invalid tag" >&2; exit 2 ;;
esac
case "$dir" in
  ""|-*|*[!ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_./-]*) echo "invalid directory" >&2; exit 2 ;;
esac
wait_s=${READY_WAIT:-30}
cd -- "$dir"

# The tag that runs now, from the running container's image reference.
prev=
cid=$(docker compose ps -q featherauth 2>/dev/null || true)
if [ -n "$cid" ]; then
  prev=$(docker inspect --format '{{.Config.Image}}' "$cid" 2>/dev/null || true)
  # Only a name:tag reference counts: a digest reference (name@sha256:...) or
  # one without a tag gives no previous tag.
  case "$prev" in *@*|sha256:*|"") prev= ;; *:*) prev=${prev##*:} ;; *) prev= ;; esac
  case "$prev" in ""|[-.]*|*[!ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-]*) prev= ;; esac
fi

ready() {
  deadline=$(( $(date +%s) + wait_s ))
  while :; do
    if docker compose exec -T featherauth /featherauth healthcheck >/dev/null 2>&1; then
      return 0
    fi
    [ "$(date +%s)" -lt "$deadline" ] || return 1
    sleep 1
  done
}

FEATHERAUTH_TAG=$tag
export FEATHERAUTH_TAG
docker compose pull
docker compose up -d
if ready; then
  echo "deployed $tag"
  exit 0
fi

echo "$tag is not ready after ${wait_s}s" >&2
if [ -z "$prev" ] || [ "$prev" = "$tag" ]; then
  echo "no previous tag to roll back to" >&2
  exit 1
fi
FEATHERAUTH_TAG=$prev
docker compose up -d
if ready; then
  echo "rolled back to $prev" >&2
else
  echo "rollback to $prev is not ready" >&2
fi
exit 1

#!/bin/sh
# CI check of the hardened Postgres container (SEC-44). Needs docker with
# compose. Run from the repository root: deploy/ops_test.go (make ops) runs it.
#
# It starts the postgres service of deploy/compose.postgres.yaml on an empty
# volume and again on the volume it filled, and asserts with docker inspect the
# settings the design lists: a read-only root, every capability dropped with
# exactly the documented add-backs, no-new-privileges and only the data volume
# and the tmpfs at /var/run/postgresql writable (no /tmp mount). Then, for each add-back, it starts the same
# service with that one add-back removed, on an empty and on a filled volume,
# and requires that the container does not become healthy: the list holds
# nothing the image does not need. Any failed assertion exits non-zero.
set -eu

project=featherauth-ci-pg
export FEATHERAUTH_TAG=ci-check-pg
tmp=$(mktemp -d)
export FEATHERAUTH_CONFIG=$tmp/c
mkdir -p "$FEATHERAUTH_CONFIG/secrets"
printf '%s\n' fixture-postgres-password >"$FEATHERAUTH_CONFIG/secrets/postgres_password"
chmod 0600 "$FEATHERAUTH_CONFIG/secrets/postgres_password"

# The add-backs the design lists, one per word. The check below proves that
# the compose file holds exactly these.
addbacks="CHOWN DAC_OVERRIDE SETGID SETUID"

# compose FILE ARGS...: the postgres service of the file, with compose.yaml
# (which the overlay extends). Only the postgres service is ever started, so no
# image of FeatherAuth is needed.
compose() {
  f=$1
  shift
  docker compose -p "$project" --project-directory deploy -f deploy/compose.yaml -f "$f" "$@"
}
overlay=deploy/compose.postgres.yaml

cleanup() {
  compose "$overlay" down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$tmp"
}
trap cleanup EXIT

fail() { echo "FAIL: $*"; exit 1; }

# cid FILE: the id of the postgres container.
cid() { compose "$1" ps -a -q postgres; }

# healthy FILE: 0 when the container becomes healthy without a restart, 1 when
# it exits, restarts or is not healthy after 90 seconds.
healthy() {
  i=0
  while [ "$i" -lt 90 ]; do
    id=$(cid "$1")
    if [ -n "$id" ]; then
      state=$(docker inspect "$id" --format '{{.State.Status}} {{.RestartCount}} {{if .State.Health}}{{.State.Health.Status}}{{end}}')
      case $state in
        "running 0 healthy") return 0 ;;
        "running 0 "* | "created 0 "*) ;;
        *) return 1 ;;
      esac
    fi
    i=$((i + 1))
    sleep 1
  done
  return 1
}

# check_settings ID: the hardening of the container.
check_settings() {
  inspect() { docker inspect "$1" --format "$2"; }
  [ "$(inspect "$1" '{{.HostConfig.ReadonlyRootfs}}')" = true ] || fail "the root filesystem is not read-only"
  [ "$(inspect "$1" '{{json .HostConfig.CapDrop}}')" = '["ALL"]' ] || fail "the capabilities are not all dropped"
  want=$(printf '%s\n' $addbacks | sort | tr '\n' ' ')
  got=$(inspect "$1" '{{range .HostConfig.CapAdd}}{{.}} {{end}}' | sed 's/CAP_//g' | tr ' ' '\n' | sort | tr '\n' ' ' | sed 's/^ *//')
  want=$(printf '%s' "$want" | sed 's/^ *//')
  [ "$got" = "$want" ] || fail "CapAdd is '$got', want '$want'"
  inspect "$1" '{{json .HostConfig.SecurityOpt}}' | grep -q 'no-new-privileges:true' || fail "no-new-privileges is not set"
  tmpfs=$(inspect "$1" '{{range $k, $v := .HostConfig.Tmpfs}}{{$k}} {{end}}' | tr ' ' '\n' | sort | tr '\n' ' ' | sed 's/^ *//')
  [ "$tmpfs" = "/var/run/postgresql " ] || fail "the tmpfs paths are '$tmpfs', want /var/run/postgresql alone"
  mounts=$(inspect "$1" '{{range .Mounts}}{{.Destination}} {{end}}')
  case " $mounts" in *" /tmp "*) fail "the container has a mount at /tmp" ;; esac
  rw=$(inspect "$1" '{{range .Mounts}}{{if .RW}}{{.Destination}} {{end}}{{end}}')
  [ "$rw" = "/var/lib/postgresql " ] || fail "the writable mounts are '$rw', want the data volume alone"
  if docker exec "$1" touch /fa-write-probe 2>/dev/null; then fail "the root filesystem accepts a write"; fi
  if docker exec "$1" touch /var/lib/postgresql/fa-write-probe 2>/dev/null; then
    docker exec "$1" rm -f /var/lib/postgresql/fa-write-probe
  else
    fail "the data volume does not accept a write"
  fi
}

compose "$overlay" down -v --remove-orphans >/dev/null 2>&1 || true

# 1. The shipped file, on an empty volume.
compose "$overlay" up -d postgres >/dev/null 2>&1 || fail "postgres did not start"
healthy "$overlay" || { compose "$overlay" logs postgres | tail -20; fail "postgres is not healthy on an empty volume"; }
id=$(cid "$overlay")
check_settings "$id"
echo "postgres hardening ok"
echo "postgres healthy on an empty volume"

# Fill the volume: a table with a row, which must still be there after a restart.
docker exec "$id" psql -U featherauth -d featherauth -v ON_ERROR_STOP=1 -c 'create table fa_fill (x int); insert into fa_fill values (42);' >/dev/null \
  || fail "cannot write to the database"

# 2. The same file, on the filled volume: the container is stopped and started.
compose "$overlay" stop postgres >/dev/null 2>&1
compose "$overlay" up -d postgres >/dev/null 2>&1 || fail "postgres did not start on the filled volume"
healthy "$overlay" || { compose "$overlay" logs postgres | tail -20; fail "postgres is not healthy on a filled volume"; }
id=$(cid "$overlay")
check_settings "$id"
[ "$(docker exec "$id" psql -U featherauth -d featherauth -At -c 'select x from fa_fill')" = 42 ] || fail "the filled volume lost its data"
echo "postgres healthy on a filled volume"

# 3. Each add-back is needed: the file with that line removed, on a filled
# volume (the one just filled) and on an empty one, must not become healthy.
total=$(printf '%s\n' $addbacks | wc -l)
n=0
for cap in $addbacks; do
  n=$((n + 1))
  variant=$tmp/without-$cap.yaml
  grep -qx "      - $cap" "$overlay" || fail "$overlay has no add-back line for $cap"
  grep -vx "      - $cap" "$overlay" >"$variant"
  grep -q "^      - $cap\$" "$variant" && fail "the variant still holds $cap"

  compose "$variant" stop postgres >/dev/null 2>&1 || true
  compose "$variant" up -d postgres >/dev/null 2>&1 || true
  if healthy "$variant"; then fail "postgres is healthy on a filled volume without $cap"; fi
  compose "$variant" down -v --remove-orphans >/dev/null 2>&1 || true

  compose "$variant" up -d postgres >/dev/null 2>&1 || true
  if healthy "$variant"; then fail "postgres is healthy on an empty volume without $cap"; fi
  compose "$variant" down -v --remove-orphans >/dev/null 2>&1 || true
  echo "postgres add-back $cap needed"

  # Fill the volume again for the next add-back, with the shipped file.
  [ "$n" -lt "$total" ] || continue
  compose "$overlay" up -d postgres >/dev/null 2>&1 || fail "postgres did not start"
  healthy "$overlay" || fail "postgres is not healthy after the variant of $cap"
  docker exec "$(cid "$overlay")" psql -U featherauth -d featherauth -v ON_ERROR_STOP=1 -c 'create table fa_fill (x int);' >/dev/null \
    || fail "cannot write to the database"
done
echo "postgres hardening check passed"

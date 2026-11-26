#!/bin/sh
# CI check of the upgrade, the rollback and the restore by image (OPS-04, OPS-05,
# OPS-06): the rows "Upgrade and rollback by image" and "Previous release on a
# migrated database" of DESIGN.md. Needs docker with compose, curl and openssl.
# Run from the repository root; deploy/ops_test.go (make ops) starts the mock
# identity provider and a user switch, builds or takes the two images and runs it.
#
#   CHECK_UPGRADE_DRIVER    sqlite or postgres
#   PREV_IMAGE, NEW_IMAGE   the previous release's image and the candidate's
#   CHECK_UPGRADE_IDP_PORT  the port of the mock identity provider on the host
#   CHECK_UPGRADE_SWITCH_PORT  a loopback port of the test: GET /?sub=NAME makes the
#                              mock identity provider sign in the user NAME
#   CHECK_UPGRADE_USERS     users to seed (default 1000, the load test's seed)
#
# Flow, on the shipped compose files (compose.yaml, plus compose.postgres.yaml):
#  1. the previous image starts on a new database and signs in USERS users
#     (each ends with a refresh token), as the load test seeds;
#  2. a backup is taken (the snapshot of `featherauth backup`, or pg_dump);
#  3. the previous image is stopped and FEATHERAUTH_TAG is set to the candidate:
#     it migrates at startup with no manual step; the timestamps of the
#     container's start, its first log line and its `listening` line are printed
#     for the test to compare with the 1 second limit; an old refresh token and a
#     new sign-in work;
#  4. FEATHERAUTH_TAG is set back: the previous image starts on the migrated
#     data and serves a refresh of the token the candidate issued and a sign-in;
#  5. the backup of step 2 is restored by the steps of the user guide
#     (7.5 SQLite: stop, remove -wal and -shm, copy, owner 65532 mode 600, up -d;
#     10.4 Postgres: stop, pg_restore --clean --if-exists, up -d) and the
#     previous image serves the data of the backup: the sign-in made after the
#     backup is gone, and the refresh token the candidate consumed works again.
set -eu

driver=${CHECK_UPGRADE_DRIVER:?set CHECK_UPGRADE_DRIVER to sqlite or postgres}
prev_src=${PREV_IMAGE:?set PREV_IMAGE to the previous release image}
new_src=${NEW_IMAGE:?set NEW_IMAGE to the candidate image}
idp_port=${CHECK_UPGRADE_IDP_PORT:?set CHECK_UPGRADE_IDP_PORT}
switch_port=${CHECK_UPGRADE_SWITCH_PORT:?set CHECK_UPGRADE_SWITCH_PORT}
users=${CHECK_UPGRADE_USERS:-1000}
case $driver in sqlite | postgres) ;; *) echo "CHECK_UPGRADE_DRIVER must be sqlite or postgres" >&2; exit 2 ;; esac

alpine_img=alpine:3.22@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f
base=ghcr.io/yyudhistira/featherauth
prev_tag=ci-prev-$driver
new_tag=ci-new-$driver
project=featherauth-ci-upgrade-$driver
tmp=$(mktemp -d)
export FEATHERAUTH_CONFIG=$tmp/c
idp=http://host.docker.internal:$idp_port
redir=https://app.example.com/callback

printf '%s\n' 'services:' '  featherauth:' '    extra_hosts:' '      - "host.docker.internal:host-gateway"' >"$tmp/idp.yaml"
files="-f deploy/compose.yaml"
[ "$driver" != postgres ] || files="$files -f deploy/compose.postgres.yaml"
dc() { docker compose -p "$project" $files -f "$tmp/idp.yaml" "$@"; }

cleanup() {
  dc down -v --remove-orphans >/dev/null 2>&1 || true
  docker rmi "$base:$prev_tag" "$base:$new_tag" >/dev/null 2>&1 || true
  chmod -R u+rwX "$tmp" 2>/dev/null || true
  rm -rf "$tmp"
}
trap cleanup EXIT

fail() { echo "FAIL: $*"; exit 1; }

docker tag "$prev_src" "$base:$prev_tag"
docker tag "$new_src" "$base:$new_tag"

# The configuration is the one the previous release writes, so that the candidate
# must accept the configuration of the release the operator already runs.
hostuser="$(id -u):$(id -g)"
gen="docker run --rm --user $hostuser --entrypoint /featherauth -v $tmp:/cfg $base:$prev_tag"
$gen config init /cfg/c >/dev/null
sed -i.bak 's#^public_url:.*#public_url: http://localhost:8080#; s#^require_https:.*#require_https: false#' "$tmp/c/server.yaml"
sed -i.bak 's#^strict_permissions:.*#strict_permissions: false#' "$tmp/c/server.yaml"
# The seeding signs users in from one address, as the load test does: the rate limit is off.
sed -i.bak 's#^  per_ip_per_minute:.*#  per_ip_per_minute: 0#' "$tmp/c/server.yaml"
grep -q '^  per_ip_per_minute: 0' "$tmp/c/server.yaml" || fail "could not turn the rate limit off"
sed -i.bak -e '/^  oidc:/,/^clients:/ s/^    enabled: false/    enabled: true/' \
  -e "/^  oidc:/,/^clients:/ s#^    issuer: .*#    issuer: $idp#" \
  -e '/^  oidc:/,/^clients:/ { /^    endpoints:/,/^      jwks:/d; }' "$tmp/c/realms/example.yaml"
sed -n '/^  oidc:/,/^clients:/p' "$tmp/c/realms/example.yaml" | grep -q '^    enabled: true' || fail "could not enable oidc in the fixture realm"
$gen keys generate --type rsa /cfg/c/secrets/example/signing-2026-10.pem >/dev/null
$gen keys generate --type ec /cfg/c/secrets/example/apple_key.p8 >/dev/null
$gen keys generate --type encryption /cfg/c/secrets/encryption_key >/dev/null
echo fixture-client-secret >"$tmp/c/secrets/example/client_secret"
if [ "$driver" = postgres ]; then
  printf '%s\n' fixture-postgres-password >"$tmp/c/secrets/postgres_password"
  cat >"$tmp/c/database.yaml" <<'YAML'
driver: postgres
postgres:
  host: postgres
  port: 5432
  database: featherauth
  user: featherauth
  password_file: secrets/postgres_password
  sslmode: disable
backup:
  directory: /var/backups/featherauth
  keep: 7
YAML
fi
chmod -R a+rX "$tmp"
if [ "$driver" = postgres ]; then
  docker run --rm --user 0:0 -v "$tmp/c/secrets:/s" "$alpine_img" sh -c 'chown 65532:65532 /s/postgres_password && chmod 0600 /s/postgres_password' \
    || fail "cannot set the password file owner"
fi

# --- the sign-in, as the load test seeds and as check-image.sh logs in
verifier=$(openssl rand -hex 32)
challenge=$(printf %s "$verifier" | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')
location() { tr -d '\r' | sed -n 's/^[Ll]ocation: //p'; }
json() { sed -n "s/.*\"$1\": *\"\\([^\"]*\\)\".*/\\1/p"; }
base_url=http://localhost:8080/example

# login SUB: signs the user SUB in through the mock identity provider and sets
# access and refresh. A failure ends the check.
login() {
  jar=$tmp/jar
  rm -f "$jar"
  curl -s -o /dev/null "http://127.0.0.1:$switch_port/?sub=$1" || fail "the user switch does not answer"
  loc1=$(curl -s -o /dev/null -c "$jar" -D - "$base_url/authorize?client_id=web&redirect_uri=$redir&response_type=code&scope=openid&state=s$1&nonce=n$1&code_challenge=$challenge&code_challenge_method=S256&provider=oidc" | location)
  case $loc1 in "$idp/authorize?"*) ;; *) fail "authorize did not redirect to the provider for $1: ${loc1%%\?*}" ;; esac
  loc2=$(curl -s -o /dev/null -D - --resolve "host.docker.internal:$idp_port:127.0.0.1" "$loc1" | location)
  case $loc2 in http://localhost:8080/example/callback/oidc\?*) ;; *) fail "the provider did not return to the callback for $1: ${loc2%%\?*}" ;; esac
  loc3=$(curl -s -o /dev/null -D - -b "$jar" "$loc2" | location)
  code=$(printf %s "$loc3" | sed -n 's/.*[?&]code=\([^&]*\).*/\1/p')
  [ -n "$code" ] || fail "the callback returned no login code for $1: ${loc3%%\?*}"
  tok=$(curl -s -X POST "$base_url/token" -d grant_type=authorization_code --data-urlencode "code=$code" -d client_id=web \
    --data-urlencode "redirect_uri=$redir" -d "code_verifier=$verifier")
  access=$(printf %s "$tok" | json access_token)
  refresh=$(printf %s "$tok" | json refresh_token)
  [ -n "$access" ] && [ -n "$refresh" ] || fail "the token exchange for $1 gave no access and refresh token"
}

# subject: the sub of the access token, from userinfo.
subject() { curl -s -H "Authorization: Bearer $1" "$base_url/userinfo" | json sub; }

# refresh_with TOKEN: sets access and refresh to the new pair; returns 1 when
# the token endpoint refuses.
refresh_with() {
  tok=$(curl -s -X POST "$base_url/token" -d grant_type=refresh_token -d client_id=web --data-urlencode "refresh_token=$1")
  access=$(printf %s "$tok" | json access_token)
  refresh=$(printf %s "$tok" | json refresh_token)
  [ -n "$access" ] && [ -n "$refresh" ]
}

wait_ready() {
  i=0
  until curl -sf http://127.0.0.1:8080/readyz >/dev/null 2>&1; do
    i=$((i + 1))
    [ "$i" -lt 60 ] || { dc logs --no-color featherauth | tail -20; fail "the service did not become ready: $1"; }
    sleep 1
  done
}

has_user() { # EMAIL: 0 when the realm holds a user with that email
  dc exec -T featherauth /featherauth user list example --email "$1" | grep -q "\"email\": *\"$1\""
}

# --- 1. the previous image, on a new database, seeded
export FEATHERAUTH_TAG=$prev_tag
dc up -d --wait --wait-timeout 120 --no-build || { dc logs --no-color | tail -30; fail "the previous image did not start"; }
wait_ready "previous image"
echo "previous image started"
i=0
r_first= sub_first=
while [ "$i" -lt "$users" ]; do
  login "$(printf 'u%05d' "$i")"
  if [ "$i" -eq 0 ]; then
    r_first=$refresh
    sub_first=$(subject "$access")
    [ -n "$sub_first" ] || fail "userinfo gave no sub for the first user"
  fi
  i=$((i + 1))
  [ $((i % 250)) -ne 0 ] || echo "seeded $i of $users users"
done
echo "upgrade seed ok $users"

# --- 2. the backup taken before the upgrade
if [ "$driver" = sqlite ]; then
  snap=$(dc exec -T featherauth /featherauth backup | sed -n 's#^wrote /var/backups/featherauth/##p' | tr -d '\r')
  case $snap in featherauth-????????-????.db) ;; *) fail "unexpected snapshot name '$snap'" ;; esac
else
  dc exec -T postgres pg_dump --username=featherauth --format=custom --no-owner featherauth >"$tmp/pre-upgrade.dump" \
    || fail "pg_dump failed"
  [ -s "$tmp/pre-upgrade.dump" ] || fail "pg_dump wrote nothing"
fi
echo "upgrade backup ok"

# --- 3. the candidate image on the same data
dc stop featherauth >/dev/null
export FEATHERAUTH_TAG=$new_tag
dc up -d --wait --wait-timeout 120 --no-build || { dc logs --no-color | tail -30; fail "the candidate image did not start on the old data"; }
cid=$(dc ps -q featherauth)
started=$(docker inspect "$cid" --format '{{.State.StartedAt}}')
logs=$(docker logs --timestamps "$cid" 2>&1)
first=$(printf '%s\n' "$logs" | sed -n '1s/ .*//p')
listening=$(printf '%s\n' "$logs" | grep '"msg":"listening"' | head -n 1 | sed 's/ .*//')
[ -n "$first" ] && [ -n "$listening" ] || { printf '%s\n' "$logs"; fail "the candidate's log has no first line or no listening line"; }
echo "migration timestamps $driver started=$started first=$first listening=$listening"
wait_ready "candidate image"
# The old refresh token (issued by the previous release) still refreshes.
refresh_with "$r_first" || fail "the candidate does not refresh a token the previous release issued"
[ "$(subject "$access")" = "$sub_first" ] || fail "the refreshed token belongs to another user"
r_new=$refresh
login after-upgrade
has_user after-upgrade@example.com || fail "the sign-in on the candidate did not create its user"
echo "upgrade new image ok"

# --- 4. back to the previous image on the migrated data
dc stop featherauth >/dev/null
export FEATHERAUTH_TAG=$prev_tag
dc up -d --wait --wait-timeout 120 --no-build || { dc logs --no-color | tail -30; fail "the previous image did not start on the migrated data"; }
wait_ready "previous image on the migrated data"
refresh_with "$r_new" || fail "the previous image does not refresh a token the candidate issued"
login after-rollback
echo "rollback to previous image ok"

# --- 5. the backup of step 2, restored, and the previous image on it
dc stop featherauth >/dev/null
if [ "$driver" = sqlite ]; then
  # The steps of USER_GUIDE.md 7.5, as root in a throwaway container on the two volumes.
  docker run --rm --user 0:0 -v "${project}_data:/data" -v "${project}_backups:/bk:ro" "$alpine_img" sh -c \
    "rm -f /data/featherauth.db-wal /data/featherauth.db-shm && cp /bk/$snap /data/featherauth.db && chown 65532:65532 /data/featherauth.db && chmod 600 /data/featherauth.db" \
    || fail "the restore of the snapshot failed"
else
  dc exec -T postgres pg_restore --username=featherauth --dbname=featherauth --clean --if-exists --no-owner <"$tmp/pre-upgrade.dump" \
    || fail "pg_restore failed"
fi
dc up -d --wait --wait-timeout 120 --no-build || { dc logs --no-color | tail -30; fail "the previous image did not start on the restored data"; }
wait_ready "previous image on the restored data"
if has_user after-upgrade@example.com; then fail "the restored data still holds the user of the sign-in made after the backup"; fi
refresh_with "$r_first" || fail "the restored data does not hold the refresh token the backup held"
[ "$(subject "$access")" = "$sub_first" ] || fail "the restored refresh token belongs to another user"
login after-restore
echo "restore ok"
echo "upgrade check passed"

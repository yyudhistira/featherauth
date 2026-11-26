#!/bin/sh
# CI check of the Postgres backup and restore (OPS-08, OPS-07): the row "Postgres
# restore" of DESIGN.md. Needs docker with compose, curl and openssl; age runs in a
# throwaway Alpine container (apk needs network), as in check-offsite.sh.
# Run from the repository root; deploy/upgrade_ops_test.go (make ops) starts the
# mock identity provider and runs it.
#
#   RESTORE_IMAGE            the candidate image
#   CHECK_PGR_IDP_PORT       the port of the mock identity provider on the host
#
# Flow, on compose.postgres.yaml: a user signs in (a session and a refresh token);
# the pg_dump and age job of USER_GUIDE.md 10.4 writes the encrypted copy with the
# public key only (the container's age stands for the host's); the copy is age
# output, holds no clear text and does not decrypt with another key; the stack
# and its volumes are removed (a clean host); a new Postgres is started, the copy
# is decrypted with the private key and restored with the documented pg_restore;
# the service starts on it, the earlier refresh token works and a new sign-in works.
set -eu

img_src=${RESTORE_IMAGE:?set RESTORE_IMAGE to the candidate image}
idp_port=${CHECK_PGR_IDP_PORT:?set CHECK_PGR_IDP_PORT}
alpine_img=alpine:3.22@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f
base=ghcr.io/yyudhistira/featherauth
tag=ci-pgrestore
project=featherauth-ci-pgrestore
tools=featherauth-ci-pgrestore-tools:latest
tmp=$(mktemp -d)
export FEATHERAUTH_CONFIG=$tmp/c
export FEATHERAUTH_TAG=$tag
idp=http://host.docker.internal:$idp_port
redir=https://app.example.com/callback
email=restore-user@example.com
hostuser="$(id -u):$(id -g)"

printf '%s\n' 'services:' '  featherauth:' '    extra_hosts:' '      - "host.docker.internal:host-gateway"' >"$tmp/idp.yaml"
compose="docker compose -p $project -f deploy/compose.yaml -f deploy/compose.postgres.yaml -f $tmp/idp.yaml"
dc() { $compose "$@"; }
cleanup() {
  dc down -v --remove-orphans >/dev/null 2>&1 || true
  docker rmi "$base:$tag" "$tools" >/dev/null 2>&1 || true
  chmod -R u+rwX "$tmp" 2>/dev/null || true
  rm -rf "$tmp"
}
trap cleanup EXIT
fail() { echo "FAIL: $*"; exit 1; }

docker tag "$img_src" "$base:$tag"
printf 'FROM %s\nRUN apk add --no-cache age\n' "$alpine_img" | docker build -q -t "$tools" - >/dev/null
# agebox runs age or age-keygen in the tools container, with the key directory mounted.
agebox() { docker run --rm -i --user "$hostuser" -v "$tmp/priv:/priv" -v "$tmp/bk:/bk" "$tools" "$@"; }

gen="docker run --rm --user $hostuser --entrypoint /featherauth -v $tmp:/cfg $base:$tag"
$gen config init /cfg/c >/dev/null
sed -i.bak 's#^public_url:.*#public_url: http://localhost:8080#; s#^require_https:.*#require_https: false#' "$tmp/c/server.yaml"
sed -i.bak 's#^strict_permissions:.*#strict_permissions: false#' "$tmp/c/server.yaml"
sed -i.bak -e '/^  oidc:/,/^clients:/ s/^    enabled: false/    enabled: true/' \
  -e "/^  oidc:/,/^clients:/ s#^    issuer: .*#    issuer: $idp#" \
  -e '/^  oidc:/,/^clients:/ { /^    endpoints:/,/^      jwks:/d; }' "$tmp/c/realms/example.yaml"
sed -n '/^  oidc:/,/^clients:/p' "$tmp/c/realms/example.yaml" | grep -q '^    enabled: true' || fail "could not enable oidc in the fixture realm"
$gen keys generate --type rsa /cfg/c/secrets/example/signing-2026-10.pem >/dev/null
$gen keys generate --type ec /cfg/c/secrets/example/apple_key.p8 >/dev/null
$gen keys generate --type encryption /cfg/c/secrets/encryption_key >/dev/null
echo fixture-client-secret >"$tmp/c/secrets/example/client_secret"
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
chmod -R a+rX "$tmp"
docker run --rm --user 0:0 -v "$tmp/c/secrets:/s" "$alpine_img" sh -c 'chown 65532:65532 /s/postgres_password && chmod 0600 /s/postgres_password' \
  || fail "cannot set the password file owner"

# The key pair is made apart from the server's files; only the public key is used by the job.
mkdir -p "$tmp/priv" "$tmp/bk"
agebox sh -c 'age-keygen -o /priv/key.txt 2>/dev/null; age-keygen -y /priv/key.txt >/priv/pub.txt; age-keygen -o /priv/other.txt 2>/dev/null'
pub=$(cat "$tmp/priv/pub.txt")
case $pub in age1*) ;; *) fail "no public key" ;; esac

verifier=$(openssl rand -hex 32)
challenge=$(printf %s "$verifier" | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')
location() { tr -d '\r' | sed -n 's/^[Ll]ocation: //p'; }
json() { sed -n "s/.*\"$1\": *\"\\([^\"]*\\)\".*/\\1/p"; }
base_url=http://localhost:8080/example
login() {
  jar=$tmp/jar
  rm -f "$jar"
  loc1=$(curl -s -o /dev/null -c "$jar" -D - "$base_url/authorize?client_id=web&redirect_uri=$redir&response_type=code&scope=openid&state=s1&nonce=n1&code_challenge=$challenge&code_challenge_method=S256&provider=oidc" | location)
  case $loc1 in "$idp/authorize?"*) ;; *) fail "authorize did not redirect to the provider: ${loc1%%\?*}" ;; esac
  loc2=$(curl -s -o /dev/null -D - --resolve "host.docker.internal:$idp_port:127.0.0.1" "$loc1" | location)
  case $loc2 in http://localhost:8080/example/callback/oidc\?*) ;; *) fail "the provider did not return to the callback: ${loc2%%\?*}" ;; esac
  loc3=$(curl -s -o /dev/null -D - -b "$jar" "$loc2" | location)
  code=$(printf %s "$loc3" | sed -n 's/.*[?&]code=\([^&]*\).*/\1/p')
  [ -n "$code" ] || fail "the callback returned no login code: ${loc3%%\?*}"
  tok=$(curl -s -X POST "$base_url/token" -d grant_type=authorization_code --data-urlencode "code=$code" -d client_id=web \
    --data-urlencode "redirect_uri=$redir" -d "code_verifier=$verifier")
  access=$(printf %s "$tok" | json access_token)
  refresh=$(printf %s "$tok" | json refresh_token)
  [ -n "$access" ] && [ -n "$refresh" ] || fail "the token exchange gave no access and refresh token"
}
subject() { curl -s -H "Authorization: Bearer $1" "$base_url/userinfo" | json sub; }
wait_ready() {
  i=0
  until curl -sf http://127.0.0.1:8080/readyz >/dev/null 2>&1; do
    i=$((i + 1))
    [ "$i" -lt 60 ] || { dc logs --no-color featherauth | tail -20; fail "the service did not become ready: $1"; }
    sleep 1
  done
}

# 1. The stack, a user with a session.
dc up -d --wait --wait-timeout 120 --no-build || { dc logs --no-color | tail -30; fail "the stack did not start"; }
wait_ready "the stack"
login
r_old=$refresh
sub_old=$(subject "$access")
[ -n "$sub_old" ] || fail "userinfo gave no sub"
echo "pg restore: user signed in"

# 2. The documented job (USER_GUIDE.md 10.4): pg_dump through the container, encrypted
# with the public key before anything touches the disk, with pipefail. The container's
# age stands for the host's.
f=$tmp/bk/featherauth-20261124-0330.dump.age
bash -o pipefail -c "$compose exec -T postgres pg_dump --username=featherauth --format=custom --no-owner featherauth | docker run --rm -i --user $hostuser $tools age -r $pub > $f.partial && mv $f.partial $f" \
  || fail "the pg_dump and age job failed"
[ -s "$f" ] || fail "the encrypted copy is empty"
[ ! -e "$f.partial" ] || fail "the job left a .partial file"
echo "pg restore: encrypted copy written"

# 3. The copy holds no clear text and cannot be read without the private key. The
# control: the plain dump holds the fixture email, so the clear-text check can fail.
dc exec -T postgres pg_dump --username=featherauth --format=custom --no-owner featherauth >"$tmp/plain.dump" || fail "control: pg_dump failed"
grep -q PGDMP "$tmp/plain.dump" || fail "control: the plain dump has no PGDMP header"
# The custom format is compressed, so the control reads the dump as SQL text.
dc exec -T postgres pg_restore -f - <"$tmp/plain.dump" | grep -q "$email" || fail "control: the plain dump does not hold the fixture email, so the clear text check proves nothing"
rm -f "$tmp/plain.dump"
head -c 21 "$f" | grep -q '^age-encryption.org/v1' || fail "the copy is not an age file"
grep -q PGDMP "$f" && fail "the copy holds the pg_dump header in clear"
grep -q "$email" "$f" && fail "the copy holds the fixture email in clear"
if agebox age -d -i /priv/other.txt "/bk/${f##*/}" >/dev/null 2>&1; then
  fail "the copy decrypts with a key that is not the private key"
fi
echo "pg restore: copy unreadable without the private key"

# 4. A clean host: the stack and its volumes are gone; a new Postgres, then the restore.
dc down -v --remove-orphans >/dev/null 2>&1
dc up -d --wait --wait-timeout 120 postgres || { dc logs --no-color postgres | tail -20; fail "the new postgres did not start"; }
agebox age -d -i /priv/key.txt "/bk/${f##*/}" \
  | dc exec -T postgres pg_restore --username=featherauth --dbname=featherauth --clean --if-exists --no-owner \
  || fail "the decrypt and pg_restore failed"
dc up -d --wait --wait-timeout 120 --no-build || { dc logs --no-color | tail -30; fail "the service did not start on the restored database"; }
wait_ready "restored database"
echo "pg restore: restored and started"

# 5. Users and sessions are intact: the earlier refresh token works, as the same user.
tok=$(curl -s -X POST "$base_url/token" -d grant_type=refresh_token -d client_id=web --data-urlencode "refresh_token=$r_old")
a2=$(printf %s "$tok" | json access_token)
[ -n "$a2" ] || fail "the earlier refresh token does not work on the restored database: $tok"
[ "$(subject "$a2")" = "$sub_old" ] || fail "the refreshed token belongs to another user"
dc exec -T featherauth /featherauth user list example --email "$email" | grep -q "\"email\": *\"$email\"" || fail "the restored database lacks the user"
login
[ "$(subject "$access")" = "$sub_old" ] || fail "a new sign-in on the restored database gave another user"
echo "pg restore: refresh and sign-in work"
echo "pg restore check passed"

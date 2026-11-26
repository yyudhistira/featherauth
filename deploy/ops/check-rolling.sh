#!/bin/sh
# CI check of the rolling deploy. Needs docker with compose, curl and
# openssl. Run from the repository root with CHECK_ROLLING_IDP_PORT set to the
# port on the host of the mock identity provider (deploy/ops_test.go starts it).
#
# It starts compose.ha.yaml (two instances on Postgres behind Caddy), then runs a
# loop of logins and refreshes through Caddy, and runs rolling-deploy.sh during
# the loop. Caddy spreads the requests over the two instances, so the logins
# alternate between them. The check passes when every request of the loop
# succeeded and the loop ran through the whole deploy.
set -eu

idp_port=${CHECK_ROLLING_IDP_PORT:?set CHECK_ROLLING_IDP_PORT to the port of the mock identity provider}
project=featherauth-ha-ci
export FEATHERAUTH_TAG=ci-rolling
img=ghcr.io/yyudhistira/featherauth:$FEATHERAUTH_TAG
tmp=$(mktemp -d)
export FEATHERAUTH_CONFIG=$tmp/c
# The instances reach the mock identity provider on the host as host.docker.internal.
printf '%s\n' 'services:' '  app1:' '    extra_hosts:' '      - "host.docker.internal:host-gateway"' \
  '  app2:' '    extra_hosts:' '      - "host.docker.internal:host-gateway"' >"$tmp/idp.yaml"
compose="docker compose -p $project -f deploy/compose.ha.yaml -f $tmp/idp.yaml"
probe_img=nginx:1.28-alpine@sha256:a8b39bd9cf0f83869a2162827a0caf6137ddf759d50a171451b335cecc87d236
loop_pid=""
cleanup() {
  [ -z "$loop_pid" ] || kill "$loop_pid" 2>/dev/null || true
  $compose down -v --remove-orphans >/dev/null 2>&1 || true
  chmod -R u+rwX "$tmp" 2>/dev/null || true
  rm -rf "$tmp"
}
trap cleanup EXIT

fail() { echo "FAIL: $*"; exit 1; }

# login_once runs one login through Caddy, as the check-image script does, then
# one refresh of its refresh token. It returns non-zero on any failed step; it
# never exits, because the loop runs it in the background.
login_once() {
  verifier=$(openssl rand -hex 32)
  challenge=$(printf %s "$verifier" | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')
  st=$(openssl rand -hex 8)
  nonce=$(openssl rand -hex 8)
  redir=https://app.example.com/callback
  jar=$tmp/jar.$$
  location() { tr -d '\r' | sed -n 's/^[Ll]ocation: //p'; }
  loc1=$(curl -s -o /dev/null -c "$jar" -D - "http://localhost:8080/example/authorize?client_id=web&redirect_uri=$redir&response_type=code&scope=openid&state=$st&nonce=$nonce&code_challenge=$challenge&code_challenge_method=S256&provider=oidc" | location) || return 1
  case $loc1 in "http://host.docker.internal:$idp_port/authorize?"*) ;; *) return 1 ;; esac
  loc2=$(curl -s -o /dev/null -D - --resolve "host.docker.internal:$idp_port:127.0.0.1" "$loc1" | location) || return 1
  case $loc2 in http://localhost:8080/example/callback/oidc\?*) ;; *) return 1 ;; esac
  loc3=$(curl -s -o /dev/null -D - -b "$jar" "$loc2" | location) || return 1
  code=$(printf %s "$loc3" | sed -n 's/.*[?&]code=\([^&]*\).*/\1/p')
  [ -n "$code" ] || return 1
  tok=$(curl -s -X POST "http://localhost:8080/example/token" -d grant_type=authorization_code \
    --data-urlencode "code=$code" -d client_id=web --data-urlencode "redirect_uri=$redir" -d "code_verifier=$verifier") || return 1
  refresh=$(printf %s "$tok" | sed -n 's/.*"refresh_token": *"\([^"]*\)".*/\1/p')
  [ -n "$refresh" ] || return 1
  ref=$(curl -s -X POST "http://localhost:8080/example/token" -d grant_type=refresh_token -d client_id=web \
    --data-urlencode "refresh_token=$refresh") || return 1
  printf %s "$ref" | grep -q '"access_token"' || return 1
  return 0
}

# Fixture configuration: the example realm with the mock identity provider as its
# oidc provider, fixture keys and secrets, the Postgres database. The containers
# run as uid 65532, so the files are readable through their other bits (as in
# check-image.sh, the fixture sets strict_permissions to a warning).
gen="docker run --rm --user $(id -u):$(id -g) --entrypoint /featherauth -v $tmp:/cfg $img"
$compose build >/dev/null
$gen config init /cfg/c >/dev/null
sed -i.bak 's#^public_url:.*#public_url: http://localhost:8080#; s#^require_https:.*#require_https: false#' "$tmp/c/server.yaml"
sed -i.bak 's#^strict_permissions:.*#strict_permissions: false#' "$tmp/c/server.yaml"
sed -i.bak -e 's#^  per_ip_per_minute:.*#  per_ip_per_minute: 0#' -e 's#^  store: memory#  store: database#' "$tmp/c/server.yaml"
idp=http://host.docker.internal:$idp_port
sed -i.bak -e '/^  oidc:/,/^clients:/ s/^    enabled: false/    enabled: true/' \
  -e "/^  oidc:/,/^clients:/ s#^    issuer: .*#    issuer: $idp#" \
  -e '/^  oidc:/,/^clients:/ { /^    endpoints:/,/^      jwks:/d; }' "$tmp/c/realms/example.yaml"
$gen keys generate --type rsa /cfg/c/secrets/example/signing-2026-10.pem >/dev/null
$gen keys generate --type ec /cfg/c/secrets/example/apple_key.p8 >/dev/null
$gen keys generate --type encryption /cfg/c/secrets/encryption_key >/dev/null
echo fixture-client-secret >"$tmp/c/secrets/example/client_secret"
mkdir -p "$tmp/c/secrets"
chmod -R a+rX "$tmp"
printf '%s\n' "fixture-postgres-password" >"$tmp/c/secrets/postgres_password"
docker run --rm --user 0:0 --entrypoint sh -v "$tmp/c/secrets:/s" "$probe_img" \
  -c 'chown 65532:65532 /s/postgres_password && chmod 0600 /s/postgres_password' || fail "cannot set the password file owner"
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

$compose up -d --wait --wait-timeout 180 || { $compose logs; fail "the HA stack did not turn healthy"; }
echo "ha stack healthy"

# The loop of logins and refreshes runs in the background; each step is recorded.
results=$tmp/results
: >"$results"
touch "$tmp/run"
(
  while [ -f "$tmp/run" ]; do
    if login_once; then echo ok >>"$results"; else echo fail >>"$results"; fi
  done
) &
loop_pid=$!

# Give the loop a head start, then replace both instances.
i=0
until [ "$(wc -l <"$results")" -ge 5 ]; do
  i=$((i + 1)); [ "$i" -lt 60 ] || fail "the loop made no requests before the deploy"
  sleep 1
done
ROLLING_PROJECT=$project ROLLING_EXTRA=$tmp/idp.yaml sh deploy/ops/rolling-deploy.sh || { rm -f "$tmp/run"; fail "rolling deploy failed"; }
echo "rolling deploy ok"

# The loop runs a while on the new instances too, then stops.
before=$(wc -l <"$results")
i=0
until [ "$(wc -l <"$results")" -ge $((before + 5)) ]; do
  i=$((i + 1)); [ "$i" -lt 60 ] || fail "the loop stopped after the deploy"
  sleep 1
done
rm -f "$tmp/run"
wait "$loop_pid" 2>/dev/null || true
loop_pid=""

total=$(wc -l <"$results")
failed=$(grep -c fail "$results" || true)
[ "$failed" = 0 ] || fail "$failed of $total logins or refreshes failed during the deploy"
echo "no request failed: $total logins and refreshes"
echo "ha login ok"

# The logins alternated between the instances: both served requests (their logs
# hold request lines).
for svc in app1 app2; do
  $compose logs --no-color "$svc" 2>&1 | grep -q '"path"' || fail "$svc served no request during the check"
done
echo "both instances served"
echo "rolling check passed"

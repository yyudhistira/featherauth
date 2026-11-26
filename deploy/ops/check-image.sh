#!/bin/sh
# CI checks of the image and compose files. Needs docker with
# compose, curl and openssl.
# Run from the repository root with CHECK_IMAGE_IDP_PORT set to the port on
# the host of the mock identity provider: deploy/ops_test.go (make ops) starts
# it and sets the variable.
# Port 8080 on the host loopback must be free (compose.yaml publishes it).
set -eu

idp_port=${CHECK_IMAGE_IDP_PORT:?set CHECK_IMAGE_IDP_PORT to the port of the mock identity provider}
project=featherauth-ci
export FEATHERAUTH_TAG=ci-check
img=ghcr.io/yyudhistira/featherauth:$FEATHERAUTH_TAG
tmp=$(mktemp -d)
export FEATHERAUTH_CONFIG=$tmp/c
# The container reaches the mock identity provider on the host as
# host.docker.internal. This override adds that name and nothing else.
printf '%s\n' 'services:' '  featherauth:' '    extra_hosts:' '      - "host.docker.internal:host-gateway"' >"$tmp/idp.yaml"
compose="docker compose -p $project -f deploy/compose.yaml -f $tmp/idp.yaml"
# The PostgreSQL stack (compose.postgres.yaml), the same project and override.
compose_pg="docker compose -p $project -f deploy/compose.yaml -f deploy/compose.postgres.yaml -f $tmp/idp.yaml"
# The built-in TLS stack (compose.tls.yaml), its own project.
tls_project=featherauth-ci-tls
# The override of the mock identity provider's host name is the one of the other
# stacks: the TLS stack's instance must reach the provider for the login below.
compose_tls="docker compose -p $tls_project -f deploy/compose.tls.yaml -f $tmp/idp.yaml"
ctl=featherauth-ci-control
net=featherauth-ci-other
cleanup() {
  $compose down -v --remove-orphans >/dev/null 2>&1 || true
  $compose_pg down -v --remove-orphans >/dev/null 2>&1 || true
  $compose_tls down -v --remove-orphans >/dev/null 2>&1 || true
  docker rm -f "$ctl" >/dev/null 2>&1 || true
  docker network rm "$net" >/dev/null 2>&1 || true
  docker rmi "$img" >/dev/null 2>&1 || true
  chmod -R u+rwX "$tmp" 2>/dev/null || true
  rm -rf "$tmp"
}
trap cleanup EXIT

fail() { echo "FAIL: $*"; exit 1; }

# login_check: the login through the container, as the one imported user. It
# is run by the SQLite stack and by the PostgreSQL stack.
login_check() {
  # Login through the container: the example's web client starts a login at the
  # oidc provider (the mock identity provider on the host), which signs in at once
  # and returns to the callback; the callback returns a login code, which the token
  # endpoint exchanges with the PKCE verifier. The user is the imported one.
  verifier=$(openssl rand -hex 32)
  challenge=$(printf %s "$verifier" | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')
  ci_state=$(openssl rand -hex 8)
  ci_nonce=$(openssl rand -hex 8)
  redir=https://app.example.com/callback
  jar=$tmp/jar
  location() { tr -d '\r' | sed -n 's/^[Ll]ocation: //p'; }
  loc1=$(curl -s -o /dev/null -c "$jar" -D - "http://localhost:8080/example/authorize?client_id=web&redirect_uri=$redir&response_type=code&scope=openid&state=$ci_state&nonce=$ci_nonce&code_challenge=$challenge&code_challenge_method=S256&provider=oidc" | location)
  case $loc1 in "$idp/authorize?"*) ;; *) fail "authorize did not redirect to the provider: ${loc1%%\?*}" ;; esac
  loc2=$(curl -s -o /dev/null -D - --resolve "host.docker.internal:$idp_port:127.0.0.1" "$loc1" | location)
  case $loc2 in http://localhost:8080/example/callback/oidc\?*) ;; *) fail "the provider did not return to the callback: ${loc2%%\?*}" ;; esac
  loc3=$(curl -s -o /dev/null -D - -b "$jar" "$loc2" | location)
  code=$(printf %s "$loc3" | sed -n 's/.*[?&]code=\([^&]*\).*/\1/p')
  [ -n "$code" ] || fail "the callback did not return a login code: ${loc3%%\?*}"
  tok=$(curl -s -X POST "http://localhost:8080/example/token" -d grant_type=authorization_code \
    --data-urlencode "code=$code" -d client_id=web --data-urlencode "redirect_uri=$redir" -d "code_verifier=$verifier")
  access=$(printf %s "$tok" | sed -n 's/.*"access_token": *"\([^"]*\)".*/\1/p')
  [ -n "$access" ] || fail "the token exchange gave no access token"
  info=$(curl -s -H "Authorization: Bearer $access" "http://localhost:8080/example/userinfo")
  printf %s "$info" | grep -Eq '"sub": *"ci-import-1"' || fail "the login did not sign in the imported user: $info"
  # A refresh: the token endpoint rotates the refresh token and signs a new access token.
  refresh=$(printf %s "$tok" | sed -n 's/.*"refresh_token": *"\([^"]*\)".*/\1/p')
  [ -n "$refresh" ] || fail "the token exchange gave no refresh token"
  ref=$(curl -s -X POST "http://localhost:8080/example/token" -d grant_type=refresh_token -d client_id=web --data-urlencode "refresh_token=$refresh")
  printf %s "$ref" | grep -q '"access_token"' || fail "the refresh gave no access token"
  echo "login ok"
}


# Build through compose, so the file under test builds its own image.
$compose build

# compose refuses to render the stack without FEATHERAUTH_TAG: the image
# line fails with a message that names the variable.
if out=$(env -u FEATHERAUTH_TAG $compose config 2>&1); then fail "compose renders without FEATHERAUTH_TAG"; fi
printf %s "$out" | grep -q FEATHERAUTH_TAG || fail "compose does not name FEATHERAUTH_TAG: $out"
echo "compose refuses without the image tag"

# Under 30 MB.
size=$(docker image inspect "$img" --format '{{.Size}}')
[ "$size" -lt 31457280 ] || fail "image is $size bytes, limit 31457280"

# Runs as non-root.
user=$(docker image inspect "$img" --format '{{.Config.User}}')
case "$user" in ""|0|root|0:*|root:*) fail "image runs as '$user'" ;; esac

# Compose binds the port to 127.0.0.1 (static check of the rendered file).
$compose config | grep -q 'host_ip: 127.0.0.1' || fail "compose port is not bound to 127.0.0.1"
docker compose -f deploy/compose.yaml -f deploy/compose.caddy.yaml config >/dev/null

# Configuration with fixture secrets (generated here, never real). The
# containers run as uid 65532, which has no shell, so the files are made with
# a throwaway container of the same image run as the host user (so the files
# are owned by the host user on Linux, where bind mounts keep owners, and can
# be changed and removed here) and then made world-readable
# (chmod) so that uid 65532 can read them through the read-only mount.
gen="docker run --rm --user $(id -u):$(id -g) --entrypoint /featherauth -v $tmp:/cfg $img"
$gen config init /cfg/c >/dev/null
sed -i.bak 's#^public_url:.*#public_url: http://localhost:8080#; s#^require_https:.*#require_https: false#' "$tmp/c/server.yaml"
# The fixture secret files are readable by uid 65532 through their other bits
# (the chmod below), which the default strict_permissions refuses: the bind
# mount keeps the host user as owner on Linux. The default is tested in config
# and cmd; this fixture is the one place that sets the warning instead.
sed -i.bak 's#^strict_permissions:.*#strict_permissions: false#' "$tmp/c/server.yaml"
# Google is enabled, so that the service must read the client secret file.
sed -i.bak '/^  google:/,/^  [abcdefghijklmnopqrstuvwxyz]*:/ s/^    enabled: false/    enabled: true/' "$tmp/c/realms/example.yaml"
grep -A6 '^  google:' "$tmp/c/realms/example.yaml" | grep -q 'enabled: true' || fail "could not enable google in the fixture realm"
# The example's oidc provider is the mock identity provider on the host, found
# by discovery (its endpoints block is removed), so a login goes through it.
idp=http://host.docker.internal:$idp_port
sed -i.bak -e '/^  oidc:/,/^clients:/ s/^    enabled: false/    enabled: true/' \
  -e "/^  oidc:/,/^clients:/ s#^    issuer: .*#    issuer: $idp#" \
  -e '/^  oidc:/,/^clients:/ { /^    endpoints:/,/^      jwks:/d; }' "$tmp/c/realms/example.yaml"
sed -n '/^  oidc:/,/^clients:/p' "$tmp/c/realms/example.yaml" | grep -q '^    enabled: true' || fail "could not enable oidc in the fixture realm"
sed -n '/^  oidc:/,/^clients:/p' "$tmp/c/realms/example.yaml" | grep -q "^    issuer: $idp\$" || fail "could not point oidc at the mock identity provider"
sed -n '/^  oidc:/,/^clients:/p' "$tmp/c/realms/example.yaml" | grep -q '^    endpoints:' && fail "oidc still overrides its endpoints"
$gen keys generate --type rsa /cfg/c/secrets/example/signing-2026-10.pem >/dev/null
$gen keys generate --type ec /cfg/c/secrets/example/apple_key.p8 >/dev/null
$gen keys generate --type encryption /cfg/c/secrets/encryption_key >/dev/null
echo fixture-client-secret >"$tmp/c/secrets/example/client_secret"
chmod -R a+rX "$tmp"

# Start the real compose file on fresh named volumes and wait for healthy.
# Healthy also proves that uid 65532 can create the SQLite file on the fresh
# data volume.
$compose up -d --wait --wait-timeout 60 || { $compose logs; fail "service did not turn healthy"; }

# The running container's published host address is 127.0.0.1 only.
cid=$($compose ps -q featherauth)
hostip=$(docker inspect "$cid" --format '{{(index (index .NetworkSettings.Ports "8080/tcp") 0).HostIp}}')
[ "$hostip" = 127.0.0.1 ] || fail "published HostIp is '$hostip'"
n=$(docker inspect "$cid" --format '{{len (index .NetworkSettings.Ports "8080/tcp")}}')
[ "$n" = 1 ] || fail "port 8080 has $n bindings"

# Container hardening (SEC-31): the four settings of the running container.
inspect() { docker inspect "$cid" --format "$1"; }
[ "$(inspect '{{.HostConfig.ReadonlyRootfs}}')" = true ] || fail "the root filesystem is not read-only"
[ "$(inspect '{{json .HostConfig.CapDrop}}')" = '["ALL"]' ] || fail "the capabilities are not all dropped"
inspect '{{json .HostConfig.SecurityOpt}}' | grep -q 'no-new-privileges:true' || fail "no-new-privileges is not set"
inspect '{{json .HostConfig.Tmpfs}}' | grep -q '"/tmp"' || fail "/tmp is not a tmpfs"
echo "container settings ok"

# The image's health check (FR-16): featherauth healthcheck every 10 seconds,
# unhealthy after 6 failed checks in a row. docker prints the interval as a
# duration ("10s").
[ "$(inspect '{{json .Config.Healthcheck.Test}}')" = '["CMD","/featherauth","healthcheck"]' ] || fail "the health check is not featherauth healthcheck"
[ "$(inspect '{{.Config.Healthcheck.Interval}}')" = 10s ] || fail "the health check interval is not 10 seconds"
[ "$(inspect '{{.Config.Healthcheck.Retries}}')" = 6 ] || fail "the health check does not allow 6 retries"
echo "health check ok"

# The same settings on a probe container. The service image has no shell, so the
# probe runs the pinned image that check-proxy.sh uses, with the service's user
# and settings: a write to /tmp works and a write to / fails.
# SQLite's own temporary files under the /tmp tmpfs are not forced beyond what
# the probe, the backup and the login exercise.
probe_img=nginx:1.28-alpine@sha256:a8b39bd9cf0f83869a2162827a0caf6137ddf759d50a171451b335cecc87d236
docker run --rm --read-only --cap-drop ALL --security-opt no-new-privileges:true \
  --tmpfs /tmp --user 65532:65532 "$probe_img" \
  sh -c 'echo ok >/tmp/probe && cat /tmp/probe >/dev/null && if echo x >/probe-root 2>/dev/null; then exit 1; fi' \
  || fail "the probe with the service's settings"
echo "probe ok"

# Import through the container: a user with the identity of the login below.
# The file comes on standard input (docker cp cannot write into a container
# whose root filesystem is read-only).
imp=$tmp/import.json
printf '%s\n' '[{"id":"ci-import-1","name":"CI Import","identities":[{"provider":"oidc","subject":"ci-user"}]}]' >"$imp"
$compose exec -T featherauth /featherauth import /dev/stdin --realm example <"$imp" >"$tmp/import.out" 2>"$tmp/import.err" \
  || { cat "$tmp/import.err"; fail "import failed"; }
grep -Eq '"created": *1' "$tmp/import.out" || fail "import did not create the user: $(cat "$tmp/import.out")"
echo "import ok"

login_check

# The data and backup volumes are writable by the non-root user.
$compose exec -T featherauth /featherauth backup | grep -q '^wrote ' || fail "backup did not write"
echo "backup ok"

# Reload with SIGHUP in the read-only container: the service loads the
# configuration again, and it is ready afterwards.
loaded() { $compose logs --no-color featherauth 2>&1 | grep -c 'configuration loaded' || true; }
before=$(loaded)
$compose kill -s HUP featherauth >/dev/null || fail "cannot send SIGHUP"
i=0
until [ "$(loaded)" -gt "$before" ]; do
  i=$((i + 1)); [ "$i" -lt 20 ] || { $compose logs featherauth; fail "the service did not reload after SIGHUP"; }
  sleep 1
done
$compose exec -T featherauth /featherauth healthcheck | grep -q '^ready' || fail "the service is not ready after the reload"
echo "reload ok"

# Secret scan (SEC-09, SEC-13): none of the fixture secrets (the client secret,
# the body lines of every key file, a fixture email and the values sent in the
# requests below) is in the image files and layers, in the image metadata and
# history, in the database and backup files, or in the container's logs.
fx_code=fixture-query-code-91c3d2
fx_bearer=fixture-bearer-5d7e1a
fx_cookie=fixture-cookie-a2f8b6
fx_state=fixture-state-77b1c4
fx_nonce=fixture-nonce-3e90d8
fx_email=fixture-user@fixture.example
pat=$tmp/patterns
{
  printf '%s\n' fixture-client-secret "$fx_code" "$fx_bearer" "$fx_cookie" "$fx_state" "$fx_nonce" "$fx_email"
  for f in "$tmp"/c/secrets/encryption_key "$tmp"/c/secrets/example/*; do
    grep -v '^-----' "$f" | awk 'length($0) >= 16'
  done
} | sort -u >"$pat"
[ "$(wc -l <"$pat")" -ge 12 ] || fail "too few fixture secret patterns"
# scan DIR: succeeds when no pattern is in any file under DIR. grep exits 0 for
# a match, 1 for none and 2 for an error (an unreadable file): an error fails
# the check, it does not count as clean.
scan() {
  chmod -R u+rwX "$1" 2>/dev/null || true
  rc=0
  grep -rlaF -f "$pat" "$1" >/dev/null 2>"$tmp/grep.err" || rc=$?
  case $rc in
    0) return 1 ;;
    1) return 0 ;;
    *) cat "$tmp/grep.err"; fail "grep failed ($rc) scanning $1" ;;
  esac
}
mkdir "$tmp/control"; head -n 1 "$pat" >"$tmp/control/planted"
scan "$tmp/control" && fail "the secret scan did not find a planted secret"
rm -rf "$tmp/control"

# The service really loads the fixture client secret: config check passes with
# the file and fails, naming it, without it.
cfgcheck="docker run --rm --entrypoint /featherauth"
$cfgcheck -v "$tmp/c:/cfg:ro" "$img" config check /cfg >/dev/null || fail "config check fails on the fixture configuration"
cp -R "$tmp/c" "$tmp/c2"; rm "$tmp/c2/secrets/example/client_secret"
if out=$($cfgcheck -v "$tmp/c2:/cfg:ro" "$img" config check /cfg 2>&1); then
  fail "config check passes without the client secret file"
fi
echo "$out" | grep -q client_secret || fail "config check does not name the missing client secret file: $out"

# Requests that carry fixture values in the places SEC-13 lists: query string
# (code, state, nonce, login_hint), Authorization and Cookie headers, a form body.
base=http://127.0.0.1:8080/example
curl -s -o /dev/null "$base/authorize?client_id=x&state=$fx_state&nonce=$fx_nonce&login_hint=$fx_email&code=$fx_code" \
  -H "Authorization: Bearer $fx_bearer" -H "Cookie: fa_state=$fx_cookie"
curl -s -o /dev/null "$base/userinfo?access_token=$fx_bearer" -H "Authorization: Bearer $fx_bearer"
curl -s -o /dev/null -X POST "$base/token" -d "grant_type=authorization_code&code=$fx_code&client_secret=fixture-client-secret"
$compose logs featherauth >"$tmp/service.log" 2>&1
grep -q '"path"' "$tmp/service.log" || fail "the container logged no request line, the log scan would prove nothing"
mkdir "$tmp/logs"; mv "$tmp/service.log" "$tmp/logs/"

mkdir "$tmp/save" "$tmp/layers"
docker save "$img" | tar -xf - -C "$tmp/save"
# Unpack every layer: each saved file that is not JSON metadata (or the legacy
# layout's <id>/VERSION marker) must be a tar archive, or the check fails.
find "$tmp/save" -type f >"$tmp/blobs.txt"
n=0
while IFS= read -r blob; do
  [ "$(basename "$blob")" = VERSION ] && continue
  case $(head -c 1 "$blob") in "{"|"[") continue ;; esac
  n=$((n + 1))
  mkdir "$tmp/layers/$n"
  tar -xf "$blob" -C "$tmp/layers/$n" || fail "cannot unpack the saved file $blob"
done <"$tmp/blobs.txt"
[ "$n" -ge 2 ] || fail "only $n layers unpacked, the layer scan would prove nothing"
find "$tmp/layers" -name featherauth -type f | grep -q . || fail "the unpacked layers hold no binary"
scan "$tmp/save" || fail "a fixture secret is in the image files"
scan "$tmp/layers" || fail "a fixture secret is in an image layer"
mkdir "$tmp/meta"
docker image inspect "$img" >"$tmp/meta/inspect.json"
docker history --no-trunc "$img" >"$tmp/meta/history.txt"
scan "$tmp/meta" || fail "a fixture secret is in the image metadata or history"
# The files the service wrote: the database and the backup.
mkdir "$tmp/data"
docker cp "$cid:/var/lib/featherauth/." "$tmp/data/" || fail "cannot copy the data directory"
docker cp "$cid:/var/backups/featherauth/." "$tmp/data/" || fail "cannot copy the backup directory"
[ -n "$(find "$tmp/data" -type f)" ] || fail "no database or backup file to scan"
scan "$tmp/data" || fail "a fixture secret is in the database or a backup"
scan "$tmp/logs" || fail "a fixture secret is in the container logs"
echo "secret scan passed"

# Network probe from another container network, with a positive control: a
# second container deliberately published on 0.0.0.0 must be reachable by the
# same probe, otherwise the probe proves nothing. Where the host is not
# reachable through the network gateway (Docker Desktop runs containers in a
# VM) the control fails and the probe is skipped; the HostIp checks above stay.
docker network create "$net" >/dev/null
gw=$(docker network inspect "$net" --format '{{(index .IPAM.Config 0).Gateway}}')
probe() {
  docker run --rm --network "$net" -e "FEATHERAUTH_LISTEN=$gw:$1" \
    --entrypoint /featherauth "$img" healthcheck >/dev/null 2>&1
}
docker run -d --name "$ctl" -p 0.0.0.0:18080:8080 -v "$FEATHERAUTH_CONFIG:/etc/featherauth:ro" "$img" >/dev/null
i=0
until docker exec "$ctl" /featherauth healthcheck >/dev/null 2>&1; do
  i=$((i + 1)); [ "$i" -lt 30 ] || fail "control container did not start"; sleep 1
done
if probe 18080; then
  probe 8080 && fail "published port reachable from another network"
  echo "network probe: control reachable, compose port unreachable"
else
  echo "network probe skipped: the host is not reachable through the network gateway here"
fi

# PostgreSQL (compose.postgres.yaml): the same image on driver postgres.
# The SQLite stack and the probe container go first: the configuration is
# changed to driver postgres, and the password file is written in the
# configuration directory.
$compose down -v --remove-orphans >/dev/null 2>&1 || true
docker rm -f "$ctl" >/dev/null 2>&1 || true
pgpw=fixture-postgres-password
printf '%s\n' "$pgpw" >"$tmp/c/secrets/postgres_password"
chmod 0644 "$tmp/c/secrets/postgres_password"
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

# check_hardening CID: the four settings of SEC-31 on a running container.
check_hardening() {
  cid=$1
  inspect() { docker inspect "$cid" --format "$1"; }
  [ "$(inspect '{{.HostConfig.ReadonlyRootfs}}')" = true ] || fail "the root filesystem is not read-only"
  [ "$(inspect '{{json .HostConfig.CapDrop}}')" = '["ALL"]' ] || fail "the capabilities are not all dropped"
  inspect '{{json .HostConfig.SecurityOpt}}' | grep -q 'no-new-privileges:true' || fail "no-new-privileges is not set"
  inspect '{{json .HostConfig.Tmpfs}}' | grep -q '"/tmp"' || fail "/tmp is not a tmpfs"
}

# strict_permissions (SEC-09) for the password file, checked by config check in
# the image: a copy of the configuration with the default setting and every
# secret file at mode 0600 passes, and the password file at 0644 is an error
# that names it. The container runs as the host user here, so it can read
# the copy's files (the service's own uid cannot read a host-owned 0600 file).
strict="$tmp/strict"
rm -rf "$strict"
cp -R "$tmp/c" "$strict"
sed -i.bak '/^strict_permissions:/d' "$strict/server.yaml"
chmod -R go-rwx "$strict"
strictcheck="docker run --rm --user $(id -u):$(id -g) -v $strict:/cfg:ro --entrypoint /featherauth $img config check /cfg"
chmod 0600 "$strict/secrets/postgres_password"
$strictcheck >/dev/null 2>&1 || fail "config check refuses a 0600 password file with the default setting"
chmod 0644 "$strict/secrets/postgres_password"
if out=$($strictcheck 2>&1); then fail "config check accepts a 0644 password file with the default setting"; fi
printf %s "$out" | grep -q 'postgres.password_file' || fail "config check does not name the password file: $out"
echo "postgres password file strict ok"

# The layout the README documents: the password file owned by uid 65532 (the
# service's user) with mode 0600. The owner is set by a root container of the
# pinned alpine-based image (chown works on the bind mount on Linux; on Docker
# Desktop it is the VM's view of the file). The stack below starts with this
# layout: the featherauth container reads the file as uid 65532, and the
# Postgres container reads it as root at its first start.
docker run --rm --user 0:0 --entrypoint sh -v "$tmp/c/secrets:/s" "$probe_img" \
  -c 'chown 65532:65532 /s/postgres_password && chmod 0600 /s/postgres_password' || fail "cannot set the password file owner"
docker run --rm --entrypoint stat -v "$tmp/c/secrets:/s:ro" "$probe_img" -c '%u:%a' /s/postgres_password \
  | grep -qx '65532:600' || fail "the password file is not owned by 65532 with mode 0600"
$compose_pg up -d --wait --wait-timeout 120 || { $compose_pg logs; fail "the PostgreSQL stack did not turn healthy"; }
echo "postgres password file layout ok"
pgcid=$($compose_pg ps -q postgres)
facid=$($compose_pg ps -q featherauth)
check_hardening "$facid"
# The database publishes no port: no host port binding at all.
[ "$(docker inspect "$pgcid" --format '{{json .HostConfig.PortBindings}}')" = '{}' ] || fail "postgres publishes a port"
# The Postgres container is hardened too (SEC-44); deploy/ops/check-postgres.sh
# proves the whole list, this is the stack that the login below runs through.
[ "$(docker inspect "$pgcid" --format '{{.HostConfig.ReadonlyRootfs}}')" = true ] || fail "the postgres root filesystem is not read-only"
[ "$(docker inspect "$pgcid" --format '{{json .HostConfig.CapDrop}}')" = '["ALL"]' ] || fail "postgres does not drop all capabilities"
docker inspect "$pgcid" --format '{{json .HostConfig.SecurityOpt}}' | grep -q 'no-new-privileges:true' || fail "postgres has no no-new-privileges"
echo "postgres container settings ok"
echo "postgres port private ok"

# The same login, through the service on PostgreSQL, and the commands of the
# CLI against the same database.
$compose_pg exec -T featherauth /featherauth import /dev/stdin --realm example <"$imp" >"$tmp/import-pg.out" 2>"$tmp/import-pg.err" \
  || { cat "$tmp/import-pg.err"; fail "import on postgres failed"; }
grep -Eq '"created": *1' "$tmp/import-pg.out" || fail "import on postgres did not create the user: $(cat "$tmp/import-pg.out")"
echo "postgres import ok"
login_check
echo "postgres login ok"
$compose_pg exec -T featherauth /featherauth user get example ci-import-1 | grep -Eq '"id": *"ci-import-1"' || fail "user get on postgres"
$compose_pg exec -T featherauth /featherauth session list example ci-import-1 | grep -q '"session_id"' || fail "session list on postgres shows no session"
echo "postgres cli ok"

# The built-in snapshot is for SQLite: backup exits 1, names pg_dump and writes nothing.
if out=$($compose_pg exec -T featherauth /featherauth backup 2>&1); then fail "backup succeeded on postgres"; fi
printf %s "$out" | grep -q pg_dump || fail "backup on postgres does not name pg_dump: $out"
$compose_pg exec -T featherauth /featherauth healthcheck | grep -q '^ready' || fail "the service on postgres is not ready"
echo "postgres backup refused"


# Secret scan of the PostgreSQL stack: the password is not in the logs of the
# two containers or in the database's files.
printf '%s\n' "$pgpw" >>"$pat"
mkdir "$tmp/logs-pg" "$tmp/pgdata"
$compose_pg logs --no-color >"$tmp/logs-pg/compose.log" 2>&1
docker logs "$pgcid" >"$tmp/logs-pg/postgres.log" 2>&1
docker cp "$pgcid:/var/lib/postgresql/." "$tmp/pgdata/" || fail "cannot copy the database directory"
[ -n "$(find "$tmp/pgdata" -type f)" ] || fail "no database file to scan"
scan "$tmp/logs-pg" || fail "the password is in the container logs"
scan "$tmp/pgdata" || fail "the password is in the database files"
echo "postgres secret scan passed"
echo "postgres stack checks passed"

# Built-in TLS (compose.tls.yaml): the container serves HTTPS on the host's
# port 443 with a test certificate, plain HTTP on port 80 redirects to the URL
# under public_url, the loopback listener answers only the health endpoints, TLS
# 1.1 is refused, and the container keeps the settings of SEC-31 with no
# capability added. The stack starts on the same image, with its own
# configuration directory: the example server.tls.yaml.example as server.yaml,
# the fixture realm and keys, and a SQLite database.
$compose_tls down -v --remove-orphans >/dev/null 2>&1 || true
tlsdir=$tmp/tls
rm -rf "$tlsdir"
mkdir "$tlsdir"
# The fixture configuration is copied without the Postgres password file: the
# postgres stack above made it readable by uid 65532 only, and the host user
# cannot open it (cp would fail with Permission denied).
(cd "$tmp/c" && tar -cf - --exclude=./secrets/postgres_password .) | (cd "$tlsdir" && tar -xf -)
printf '%s\n' 'driver: sqlite' >"$tlsdir/database.yaml"
cp deploy/config.example/server.tls.yaml.example "$tlsdir/server.yaml"
# The fixture key is readable by uid 65532 through its other bits, as the
# fixture secrets above are: strict_permissions is the default in the example
# and is set to the warning for this fixture only (see the note above).
sed -i.bak 's#^strict_permissions:.*#strict_permissions: false#' "$tlsdir/server.yaml"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 \
  -keyout "$tlsdir/secrets/tls_key.pem" -out "$tlsdir/secrets/tls_cert.pem" \
  -subj /CN=auth.example.com -addext subjectAltName=DNS:auth.example.com >/dev/null 2>&1 \
  || fail "cannot make the test certificate"
chmod -R a+rX "$tlsdir"
FEATHERAUTH_CONFIG=$tlsdir $compose_tls up -d --wait --wait-timeout 60 \
  || { $compose_tls logs; fail "the TLS stack did not turn healthy"; }
tcid=$($compose_tls ps -q featherauth)

# The container's settings (SEC-31) and no capability added (SEC-41).
tinspect() { docker inspect "$tcid" --format "$1"; }
[ "$(tinspect '{{.HostConfig.ReadonlyRootfs}}')" = true ] || fail "the TLS container root filesystem is not read-only"
[ "$(tinspect '{{json .HostConfig.CapDrop}}')" = '["ALL"]' ] || fail "the TLS container capabilities are not all dropped"
tinspect '{{json .HostConfig.CapAdd}}' | grep -Eq '^(null|\[\])$' || fail "the TLS container adds a capability"
tinspect '{{json .HostConfig.SecurityOpt}}' | grep -q 'no-new-privileges:true' || fail "the TLS container allows new privileges"
tinspect '{{json .HostConfig.Tmpfs}}' | grep -q '"/tmp"' || fail "the TLS container has no /tmp tmpfs"
echo "tls container settings ok"

# The published ports are the host's 443 and 80, and there is no other binding.
# Docker lists one entry for each address family (IPv4 and IPv6), so every entry
# is checked, not the first one. The map is keyed by container port: 8443 is the
# HTTPS listener and 8081 the redirect listener.
ports=$(tinspect '{{json .NetworkSettings.Ports}}')
https_ports=$(tinspect '{{range (index .NetworkSettings.Ports "8443/tcp")}}{{.HostPort}} {{end}}')
redirect_ports=$(tinspect '{{range (index .NetworkSettings.Ports "8081/tcp")}}{{.HostPort}} {{end}}')
all_ports=$(tinspect '{{range $p, $v := .NetworkSettings.Ports}}{{range $v}}{{.HostPort}} {{end}}{{end}}')
[ -n "$https_ports" ] || fail "the HTTPS listener is not published: $ports"
for p in $https_ports; do
  [ "$p" = 443 ] || fail "the HTTPS listener is published on host port $p, not 443: $ports"
done
[ -n "$redirect_ports" ] || fail "the redirect listener is not published: $ports"
for p in $redirect_ports; do
  [ "$p" = 80 ] || fail "the redirect listener is published on host port $p, not 80: $ports"
done
[ "$(printf %s "$all_ports" | wc -w)" = "$(printf %s "$https_ports $redirect_ports" | wc -w)" ] \
  || fail "the TLS container has other published ports: $ports"
echo "tls ports ok"

# HTTPS serves the discovery document, with the test certificate verified against
# its name (the host name is resolved to the loopback address here).
tls_url=https://auth.example.com
curl -s -f --cacert "$tlsdir/secrets/tls_cert.pem" --resolve auth.example.com:443:127.0.0.1 \
  "$tls_url/example/.well-known/openid-configuration" | grep -Eq '"issuer": *"https://auth.example.com/example"' \
  || fail "HTTPS does not serve the discovery document"
echo "tls https ok"

# A login over HTTPS through the TLS stack: the example's oidc provider is the mock
# identity provider on the host, the authorization request and the callback go to
# the service's HTTPS listener, and the token exchange and userinfo follow.
tls_curl() { curl -s --cacert "$tlsdir/secrets/tls_cert.pem" --resolve auth.example.com:443:127.0.0.1 "$@"; }
tls_location() { tr -d '\r' | sed -n 's/^[Ll]ocation: //p'; }
verifier=$(openssl rand -hex 32)
challenge=$(printf %s "$verifier" | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')
tls_state=$(openssl rand -hex 8)
tls_nonce=$(openssl rand -hex 8)
tjar=$tmp/tjar
tls_redir=https://app.example.com/callback
tloc1=$(tls_curl -o /dev/null -c "$tjar" -D - "$tls_url/example/authorize?client_id=web&redirect_uri=$tls_redir&response_type=code&scope=openid&state=$tls_state&nonce=$tls_nonce&code_challenge=$challenge&code_challenge_method=S256&provider=oidc" | tls_location)
case $tloc1 in "$idp/authorize?"*) ;; *) fail "the HTTPS authorize did not redirect to the provider: ${tloc1%%\?*}" ;; esac
tloc2=$(curl -s -o /dev/null -D - --resolve "host.docker.internal:$idp_port:127.0.0.1" "$tloc1" | tls_location)
case $tloc2 in "$tls_url/example/callback/oidc?"*) ;; *) fail "the provider did not return to the HTTPS callback: ${tloc2%%\?*}" ;; esac
tloc3=$(tls_curl -o /dev/null -D - -b "$tjar" "$tloc2" | tls_location)
tcode=$(printf %s "$tloc3" | sed -n 's/.*[?&]code=\([^&]*\).*/\1/p')
[ -n "$tcode" ] || fail "the HTTPS callback returned no login code: ${tloc3%%\?*}"
ttok=$(tls_curl -X POST "$tls_url/example/token" -d grant_type=authorization_code \
  --data-urlencode "code=$tcode" -d client_id=web --data-urlencode "redirect_uri=$tls_redir" -d "code_verifier=$verifier")
taccess=$(printf %s "$ttok" | sed -n 's/.*"access_token": *"\([^"]*\)".*/\1/p')
[ -n "$taccess" ] || fail "the HTTPS token exchange gave no access token"
tls_curl -H "Authorization: Bearer $taccess" "$tls_url/example/userinfo" | grep -q '"sub"' || fail "the HTTPS userinfo gave no subject"
echo "tls login ok"

# Plain HTTP on port 80 answers 301 to the URL under public_url.
loc=$(curl -s -o /dev/null -D - "http://127.0.0.1:80/example/authorize?client_id=web" | tr -d '\r' | sed -n 's/^[Ll]ocation: //p')
[ "$loc" = "https://auth.example.com/example/authorize?client_id=web" ] || fail "the redirect does not point at public_url: $loc"
echo "tls redirect ok"

# The loopback listener, inside the container's network namespace, answers
# /readyz and answers 404 for an endpoint.
probe() { docker run --rm --network "container:$tcid" "$probe_img" "$@"; }
probe wget -q -O - http://127.0.0.1:8080/readyz | grep -q '^ok' || fail "the loopback listener does not answer /readyz"
probe wget -S -O /dev/null http://127.0.0.1:8080/example/authorize 2>&1 | grep -q ' 404 ' || fail "the loopback listener does not answer 404 for /authorize"
echo "tls loopback ok"

# TLS 1.2 is served and TLS 1.1 is refused.
echo | openssl s_client -connect 127.0.0.1:443 -servername auth.example.com -tls1_2 >/dev/null 2>&1 \
  || fail "the HTTPS listener refuses TLS 1.2"
if echo | openssl s_client -connect 127.0.0.1:443 -servername auth.example.com -tls1_1 >/dev/null 2>&1; then
  fail "the HTTPS listener accepts TLS 1.1"
fi
echo "tls version ok"

# The key of the pair is in no log of the TLS stack (SEC-09).
$compose_tls logs --no-color >"$tmp/logs-tls.log" 2>&1
grep -q '"path"' "$tmp/logs-tls.log" || fail "the TLS stack logged no request line, the log scan would prove nothing"
grep -v '^-----' "$tlsdir/secrets/tls_key.pem" | awk 'length($0) >= 16' >"$tmp/tls-key-lines"
rc=0
grep -qaF -f "$tmp/tls-key-lines" "$tmp/logs-tls.log" || rc=$?
[ "$rc" = 1 ] || fail "the TLS key is in the container log (grep exit $rc)"
echo "tls secret scan passed"
$compose_tls down -v --remove-orphans >/dev/null 2>&1 || true
echo "tls stack checks passed"

echo "image checks passed"

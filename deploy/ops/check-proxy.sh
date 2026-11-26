#!/bin/sh
# CI checks of the proxy examples. Needs docker, curl and openssl.
# Run from the repository root: deploy/ops/check-proxy.sh
# Host ports 18081 and 18443 on the loopback must be free.
set -eu

caddy_img=caddy:2.11.9@sha256:9c1b76fb701c1f77383d3124d9f626e38bcf83bc1255ed47475d4f2420701d03
nginx_img=nginx:1.28-alpine@sha256:a8b39bd9cf0f83869a2162827a0caf6137ddf759d50a171451b335cecc87d236
# The oldest nginx the example must work on: Ubuntu 24.04 ships 1.24.
nginx_old_img=nginx:1.24-alpine@sha256:77e5d4a6ad906c5d3793764085706577fa705b1dc6f244ea0241c4b5e2155385
host=auth.example.com
tmp=$(mktemp -d)
ng=featherauth-ci-nginx
cd_=featherauth-ci-caddy
cleanup() {
  docker rm -f "$ng" "$cd_" featherauth-ci-nginx-ctl featherauth-ci-nginx-err >/dev/null 2>&1 || true
  rm -rf "$tmp"
}
trap cleanup EXIT

fail() { echo "FAIL: $*"; exit 1; }

# A throwaway self-signed certificate, at the paths the examples use.
mkdir -p "$tmp/certs"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=$host" \
  -keyout "$tmp/certs/privkey.pem" -out "$tmp/certs/fullchain.pem" >/dev/null 2>&1
chmod a+rX "$tmp" "$tmp/certs"; chmod a+r "$tmp/certs/"*

# Caddy: the example as written (Let's Encrypt), the paid-certificate variant
# (tls line enabled) and the compose.caddy.yaml variant (upstream
# featherauth:8080), each checked with caddy validate.
cp deploy/Caddyfile.example "$tmp/Caddyfile.le"
sed 's|^    # tls |    tls |; s|/etc/ssl/auth/|/certs/|g' deploy/Caddyfile.example >"$tmp/Caddyfile.paid"
sed 's#127\.0\.0\.1:8080#featherauth:8080#' deploy/Caddyfile.example >"$tmp/Caddyfile.compose"
sed 's#127\.0\.0\.1:8080#featherauth:8080#' "$tmp/Caddyfile.paid" >"$tmp/Caddyfile.compose-paid"
grep -q '^    tls /certs/fullchain.pem /certs/privkey.pem$' "$tmp/Caddyfile.paid" || fail "paid variant was not derived"
grep -q '^    reverse_proxy featherauth:8080' "$tmp/Caddyfile.compose" || fail "compose variant was not derived"
for v in le paid compose compose-paid; do
  docker run --rm -v "$tmp/Caddyfile.$v:/etc/caddy/Caddyfile:ro" -v "$tmp/certs:/certs:ro" \
    "$caddy_img" caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null 2>&1 \
    || { docker run --rm -v "$tmp/Caddyfile.$v:/etc/caddy/Caddyfile:ro" -v "$tmp/certs:/certs:ro" \
      "$caddy_img" caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile; fail "caddy validate: $v"; }
done
echo "caddy validate passed: 4 variants"

# The compose.caddy.yaml health check needs the admin API: run the compose
# variant with the paid certificate (no ACME) and ask the API on 127.0.0.1:2019
# the way the healthcheck does.
docker run -d --name "$cd_" -v "$tmp/Caddyfile.compose-paid:/etc/caddy/Caddyfile:ro" -v "$tmp/certs:/certs:ro" \
  "$caddy_img" >/dev/null
i=0
until docker exec "$cd_" wget -q -O /dev/null http://127.0.0.1:2019/config/ >/dev/null 2>&1; do
  i=$((i + 1)); [ "$i" -lt 20 ] || { docker logs "$cd_"; fail "caddy admin API not reachable"; }
  sleep 1
done
echo "caddy admin API reachable"

# nginx: nginx -t on the example with the certificate at the paths it names.
docker run --rm \
  -v "$PWD/deploy/nginx.example.conf:/etc/nginx/conf.d/default.conf:ro" \
  -v "$tmp/certs:/etc/letsencrypt/live/$host:ro" \
  "$nginx_img" nginx -t || fail "nginx -t"
docker run --rm \
  -v "$PWD/deploy/nginx.example.conf:/etc/nginx/conf.d/default.conf:ro" \
  -v "$tmp/certs:/etc/letsencrypt/live/$host:ro" \
  "$nginx_old_img" nginx -t || fail "nginx -t on nginx 1.24"

# Real access log: requests with a query string, on the HTTPS and the HTTP
# server block, must leave no query in the access log, and the 301 and the
# forwarded headers must be there. A positive control: the same request is
# logged with $request by a second server block, so the check cannot pass
# merely because nothing was logged. The upstream is a netcat-free stub: the
# nginx container itself answers on 127.0.0.1:8080 through a third server block.
cat >"$tmp/stub.conf" <<'STUB'
server {
    listen 127.0.0.1:8080;
    location / {
        add_header X-Seen-Host $http_host always;
        add_header X-Seen-XFF $http_x_forwarded_for always;
        add_header X-Seen-Proto $http_x_forwarded_proto always;
        return 200 "ok\n";
    }
}
STUB
docker run -d --name "$ng" -p 127.0.0.1:18081:80 -p 127.0.0.1:18443:443 \
  -v "$PWD/deploy/nginx.example.conf:/etc/nginx/conf.d/default.conf:ro" \
  -v "$tmp/stub.conf:/etc/nginx/conf.d/stub.conf:ro" \
  -v "$tmp/certs:/etc/letsencrypt/live/$host:ro" \
  "$nginx_img" >/dev/null
i=0
until curl -sk --resolve "$host:18443:127.0.0.1" "https://$host:18443/healthz" -o /dev/null; do
  i=$((i + 1)); [ "$i" -lt 20 ] || { docker logs "$ng"; fail "nginx did not start"; }
  sleep 1
done

secret=SECRETCODE-fixture-0123456789
hdrs=$(curl -sk --resolve "$host:18443:127.0.0.1" -H 'X-Forwarded-For: 203.0.113.9' \
  "https://$host:18443/callback?code=$secret&state=$secret" -D - -o /dev/null)
echo "$hdrs" | grep -qi "^x-seen-host: $host" || fail "Host not forwarded: $hdrs"
echo "$hdrs" | grep -qi '^x-seen-xff: 203.0.113.9, ' || fail "X-Forwarded-For not appended: $hdrs"
echo "$hdrs" | grep -qi '^x-seen-proto: https' || fail "X-Forwarded-Proto not forwarded: $hdrs"

# Port 80: 301 to HTTPS (the Location keeps the query; it is not logged).
code=$(curl -s --resolve "$host:18081:127.0.0.1" "http://$host:18081/authorize?id_token_hint=$secret" -o /dev/null -w '%{http_code}')
[ "$code" = 301 ] || fail "port 80 answered $code, want 301"

log=$(docker exec "$ng" cat /var/log/nginx/featherauth.access.log)
echo "$log" | grep -q '/callback[ ?]' || fail "access log has no /callback line: $log"
echo "$log" | grep -q '/authorize[ ?]' || fail "access log has no /authorize line: $log"
echo "$log" | grep -q "$secret" && fail "a query value reached the access log: $log"
echo "$log" | grep -q '?' && fail "a query string reached the access log: $log"

# Positive control: a $request format does log the secret.
docker exec "$ng" sh -c 'echo "log_format ctl \"\$request\"; server { listen 18090; access_log /tmp/ctl.log ctl; location / { return 200; } }" >/etc/nginx/conf.d/ctl.conf && nginx -s reload' >/dev/null 2>&1
i=0
until docker exec "$ng" wget -q -O /dev/null "http://127.0.0.1:18090/x?code=$secret" >/dev/null 2>&1; do
  i=$((i + 1)); [ "$i" -lt 20 ] || fail "control server block did not answer"
  sleep 1
done
docker exec "$ng" grep -q "$secret" /tmp/ctl.log || fail "control: a \$request format did not log the query, so the check proves nothing"

# Error log: with no upstream the request fails with 502 and nginx logs the
# request line and the upstream URL, query included, at level error. The
# example keeps that out; the control (level error) must show it.
# err_probe starts nginx with config file $2 as container $1 and no upstream,
# sends it a request whose query holds the fixture secret (nginx answers 502
# and logs the failed upstream), then prints the error log lines that contain
# the secret: nothing for the example, something for the level-error control.
err_probe() {
  docker run -d --name "$1" -v "$2:/etc/nginx/conf.d/default.conf:ro" \
    -v "$tmp/certs:/etc/letsencrypt/live/$host:ro" "$nginx_img" >/dev/null
  i=0
  until docker exec "$1" wget -q -O /dev/null --no-check-certificate "https://127.0.0.1:443/up" 2>/dev/null \
    || [ "$(docker exec "$1" wget -S -O /dev/null --no-check-certificate "https://127.0.0.1:443/up?code=$secret" 2>&1 | grep -c 'HTTP/1.1 502')" -gt 0 ]; do
    i=$((i + 1)); [ "$i" -lt 20 ] || { docker logs "$1"; fail "$1 did not answer"; }
    sleep 1
  done
  docker exec "$1" sh -c 'cat /var/log/nginx/featherauth.error.log; true' | grep "$secret" || true
  docker rm -f "$1" >/dev/null
}
sed 's/error.log crit;/error.log error;/' deploy/nginx.example.conf >"$tmp/nginx.ctl.conf"
[ -n "$(err_probe featherauth-ci-nginx-ctl "$tmp/nginx.ctl.conf")" ] || fail "control: the error log at level error did not show the query, so the check proves nothing"
[ -z "$(err_probe featherauth-ci-nginx-err "$PWD/deploy/nginx.example.conf")" ] || fail "a query string reached the nginx error log"

# Not checked here: Caddy's hold during a restart (the restart loop) and
# real certificates (the release check, docs/RELEASING.md).
echo "proxy checks passed"

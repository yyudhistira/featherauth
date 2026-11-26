#!/bin/sh
# CI check of the example web app's compose file (FR-61). Needs docker, curl and jq or python3.
# Run from the repository root: deploy/ops/check-example.sh
# Host port 5173 on the loopback must be free.
set -eu

compose=examples/web-app/compose.yaml
project=featherauth-ci-example
dc() { docker compose -p "$project" -f "$compose" "$@"; }
cleanup() { dc down -v --rmi local >/dev/null 2>&1 || true; }
trap cleanup EXIT

fail() { echo "FAIL: $*"; exit 1; }

# Built from the Dockerfile and healthy: the page answers inside the container.
dc up --build -d --wait >/dev/null || { dc logs 2>&1 | tail -n 20; fail "the example did not start"; }
echo "example started"

# Published on 127.0.0.1 only.
ports=$(dc port web-app 5173)
[ "$ports" = "127.0.0.1:5173" ] || fail "the example is published on '$ports', want 127.0.0.1:5173"
echo "example port loopback ok"

# The page and a single-page route, each with the two security headers exactly.
csp="default-src 'self'; connect-src 'self' https:; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"
for path in / "/callback?code=x&state=y"; do
  hdrs=$(curl -fsS -D - -o /dev/null "http://127.0.0.1:5173$path" | tr -d '\r')
  got=$(printf '%s\n' "$hdrs" | sed -n 's/^[Cc]ontent-[Ss]ecurity-[Pp]olicy: //p')
  [ "$got" = "$csp" ] || fail "$path sends Content-Security-Policy '$got', want '$csp'"
  got=$(printf '%s\n' "$hdrs" | sed -n 's/^[Xx]-[Cc]ontent-[Tt]ype-[Oo]ptions: //p')
  [ "$got" = "nosniff" ] || fail "$path sends X-Content-Type-Options '$got', want nosniff"
done
curl -fsS http://127.0.0.1:5173/ | grep -q '<div id="root">' || fail "/ is not the page"
curl -fsS "http://127.0.0.1:5173/callback?code=x&state=y" | grep -q '<div id="root">' || fail "/callback does not fall back to the page"
echo "example headers ok"

# The served config.json is the mounted public/config.json: parsed as JSON,
# the four fields compared one by one (not matched as text).
served=$(curl -fsS http://127.0.0.1:5173/config.json)
for field in client_id authority redirect_uri post_logout_redirect_uri; do
  if command -v jq >/dev/null 2>&1; then
    want=$(jq -er --arg f "$field" '.[$f]' examples/web-app/public/config.json) || fail "public/config.json has no $field"
    got=$(printf '%s' "$served" | jq -er --arg f "$field" '.[$f]') || fail "served config.json has no $field"
  else
    want=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' examples/web-app/public/config.json "$field") || fail "public/config.json has no $field"
    got=$(printf '%s' "$served" | python3 -c 'import json,sys; print(json.load(sys.stdin)[sys.argv[1]])' "$field") || fail "served config.json has no $field"
  fi
  [ "$got" = "$want" ] || fail "config.json $field is '$got', public/config.json has '$want'"
  [ "$field" != client_id ] || [ "$got" = "example-web" ] || fail "config.json client_id is '$got', want example-web"
done
echo "example page ok"
echo "example check passed"

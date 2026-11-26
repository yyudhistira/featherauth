#!/bin/sh
# rolling-deploy.sh: replaces the instances of compose.ha.yaml one after the
# other. For each instance: its container is recreated with the image
# and configuration of FEATHERAUTH_TAG, the old one gets SIGTERM and drains (it
# answers /readyz 503 at once), and the script waits until the new one answers
# /readyz (featherauth healthcheck inside the container) before the next old
# instance gets SIGTERM. Caddy sends the requests to the other instance meanwhile.
#
# Run from the repository root. Variables: FEATHERAUTH_TAG (required),
# ROLLING_PROJECT (the compose project, default featherauth-ha) and ROLLING_EXTRA
# (an extra compose file, for example a test override, optional).
set -eu

[ -n "${FEATHERAUTH_TAG:-}" ] || { echo "FAIL: set FEATHERAUTH_TAG to the image tag" >&2; exit 1; }
project=${ROLLING_PROJECT:-featherauth-ha}
extra=${ROLLING_EXTRA:-}
if [ -n "$extra" ]; then
  compose="docker compose -p $project -f deploy/compose.ha.yaml -f $extra"
else
  compose="docker compose -p $project -f deploy/compose.ha.yaml"
fi

for svc in app1 app2; do
  $compose up -d --no-deps --force-recreate "$svc" >/dev/null || { echo "FAIL: cannot replace instance $svc" >&2; exit 1; }
  i=0
  until $compose exec -T "$svc" /featherauth healthcheck >/dev/null 2>&1; do
    i=$((i + 1))
    if [ "$i" -ge 60 ]; then
      # The state of the container says whether it runs; no secret is printed.
      state=$($compose ps --format '{{.State}}' "$svc" 2>/dev/null || echo unknown)
      echo "FAIL: instance $svc did not become ready (not answering /readyz within 60 s after its replacement; container state: $state); the other instance keeps serving" >&2
      exit 1
    fi
    sleep 1
  done
  echo "replaced $svc"
done
echo "rolling deploy done"

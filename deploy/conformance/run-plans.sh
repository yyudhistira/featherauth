#!/bin/sh
# Runs the three test plans against FeatherAuth, inside the runner container.
# /out holds plan-config.json (written by the Go test) and receives the exported
# results of each plan. Exits non-zero when a plan has a failure, warning or skip
# that expected/<plan>-failures.json or <plan>-skips.json does not list.
set -u
cd /suite || exit 2
mkdir -p /out/export
status=0

run_plan() {
	tag="$1"
	name="$2"
	python3 -u scripts/run-test-plan.py \
		--export-dir /out/export \
		--expected-failures-file /expected/${tag}-failures.json \
		--expected-skips-file /expected/${tag}-skips.json \
		--verbose \
		"$name" /out/plan-config.json || status=1
}

# CONFORMANCE_PLANS (basic, config, logout; default all) selects plans, for a
# quicker run while fixing a failure.
run_plan_if() {
	case " ${CONFORMANCE_PLANS:-basic config logout} " in
	*" $1 "*) run_plan "$1" "$2" ;;
	esac
}

# Basic OP, Config OP and RP-Initiated Logout OP. FeatherAuth uses the code flow
# only, static clients and discovery.
run_plan_if basic 'oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]'
run_plan_if config 'oidcc-config-certification-test-plan'
run_plan_if logout 'oidcc-rp-initiated-logout-certification-test-plan[response_type=code][client_registration=static_client]'
python3 -I /dump-logs.py || echo "could not save the test logs"
exit "$status"

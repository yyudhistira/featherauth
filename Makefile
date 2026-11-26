# Make targets described in CLAUDE.md. `make check` must pass before every commit.

GO ?= go
PKGS := ./...

.PHONY: fmt fmtcheck vet test cover vuln trace arch check ops postgres browser example conformance load release-check

# Go files to format: every one except those under an installed node_modules
# (the example web app), which are not ours.
GOFILES = find . -name node_modules -prune -o -name '*.go' -print

fmt:
	$(GOFILES) | xargs gofmt -s -w
	$(GOFILES) | xargs $(GO) tool goimports -w -local github.com/yyudhistira/featherauth

# Fails when any file is not formatted; `make fmt` fixes it.
fmtcheck:
	@out="$$($(GOFILES) | xargs gofmt -s -l ; $(GOFILES) | xargs $(GO) tool goimports -l -local github.com/yyudhistira/featherauth)"; \
	if [ -n "$$out" ]; then echo "not formatted (run make fmt):"; echo "$$out"; exit 1; fi

vet:
	$(GO) vet $(PKGS)
	$(GO) tool staticcheck $(PKGS)

test:
	$(GO) test -race -count=1 $(PKGS)

# Race tests with coverage, then the per-package thresholds in tools/cover.
cover:
	$(GO) test -race -count=1 -covermode=atomic -coverprofile=cover.out $(PKGS)
	$(GO) run ./tools/cover -profile cover.out

vuln:
	$(GO) tool govulncheck $(PKGS)

# pending.txt may only shrink compared with TRACE_BASE and HEAD, and in every
# commit of TRACE_BASE..HEAD compared with its parent. TRACE_BASE= skips the rule.
TRACE_BASE ?= origin/main

trace:
	$(GO) run ./tools/trace $(if $(TRACE_BASE),-base "$(TRACE_BASE)" -base HEAD -history "$(TRACE_BASE)..HEAD",-base "" -history "")

arch:
	$(GO) run ./tools/archcheck

check: fmtcheck vet cover vuln trace arch

# Ops tests (build tag ops, needs docker): run the deploy/ops/check-*.sh scripts.
# CI runs this target; make check does not.
ops:
	$(GO) test -tags ops -count=1 -timeout 30m ./deploy/

# Postgres tests (build tag postgres, needs docker): starts a container of
# POSTGRES_VERSION on loopback, runs the tests against it through
# FEATHERAUTH_TEST_POSTGRES and removes the container, also when a test fails.
# CI runs this target on Postgres 15 and on the newest stable major; make check
# does not run it.
# 18 is the newest stable Postgres major as of 2026-11-15. Bump it here and the
# matrix of the postgres job in .github/workflows/ci.yml when a newer major ships
# (keep the oldest supported version, 15, in the matrix too).
POSTGRES_VERSION ?= 18
POSTGRES_PKGS = ./internal/testutil/ ./internal/store/ ./internal/token/ ./internal/oidc/ ./cmd/featherauth/
# A throwaway password for a container that only listens on loopback.
POSTGRES_PASSWORD = featherauth-test

postgres:
	@set -eu; \
	name="featherauth-test-postgres-$$$$"; \
	trap 'docker rm -fv "$$name" >/dev/null 2>&1' EXIT; \
	docker run -d --name "$$name" -p 127.0.0.1::5432 \
		-e POSTGRES_USER=featherauth -e POSTGRES_DB=featherauth \
		-e POSTGRES_PASSWORD=$(POSTGRES_PASSWORD) \
		postgres:$(POSTGRES_VERSION) >/dev/null; \
	port=$$(docker port "$$name" 5432/tcp | head -n 1 | sed 's/.*://'); \
	tries=0; \
	until docker exec "$$name" pg_isready -h 127.0.0.1 -p 5432 -U featherauth -d featherauth >/dev/null 2>&1; do \
		tries=$$((tries + 1)); \
		if [ $$tries -ge 60 ]; then echo "postgres $(POSTGRES_VERSION) did not start" >&2; docker logs "$$name" >&2; exit 1; fi; \
		sleep 1; \
	done; \
	FEATHERAUTH_TEST_POSTGRES="postgres://featherauth:$(POSTGRES_PASSWORD)@127.0.0.1:$$port/featherauth?sslmode=disable" \
		$(GO) test -tags postgres -race -count=1 -timeout 15m $(POSTGRES_PKGS)

# Browser tests (build tag browser, needs Chrome). CI runs this target;
# make check does not. List every package that holds browser tests here.
BROWSER_PKGS = ./internal/testutil/server/...

# The example web app (examples/web-app): npm ci installs exactly the lockfile
# and the build writes dist/, which TestBrowserExampleWebApp serves. It needs
# Node (the version of examples/web-app/.node-version); make check does not run it.
example:
	cd examples/web-app && npm ci --ignore-scripts && npm run build

browser: example
	$(GO) test -tags browser -count=1 -timeout 15m $(BROWSER_PKGS)

# OpenID conformance suite (build tag conformance, needs docker and network access
# to pull the pinned suite images): FeatherAuth, the mock identity provider and the
# Basic OP, Config OP and RP-Initiated Logout OP plans; see deploy/conformance/.
# The runner container is root, so on Linux the files in conformance-out/ are
# root-owned (remove them with sudo). Results are exported to conformance-out/.
# CONFORMANCE_PLANS (basic, config, logout) selects plans. Run before each
# release that changes protocol handling.
conformance:
	$(GO) test -tags conformance -count=1 -timeout 90m -run TestConformanceSuite ./deploy/

# Load verification (build tag load, needs docker): FeatherAuth limited to 1 CPU
# and 512 MB behind the Caddy and nginx examples, driven by k6 in a container
# (deploy/load/); the idle, steady, peak, restart-under-load, soak and
# rate-limiter scenarios and the restart loops through both proxies. The full
# run takes about 1 hour 45 minutes; the LOAD_* variables in
# deploy/load_test.go shorten it for trying the setup. Results go to load-out/
# and are recorded in the load section of docs/RESULTS.md. Run before each release that
# changes request handling, dependencies or the database layer. Host ports
# 18543 and 18544 (loopback) and the docker subnet 172.28.77.0/24 must be free.
# LOAD_DRIVER selects the database: sqlite (default) or postgres. With postgres
# the Postgres container of deploy/load/compose.yaml runs beside the service,
# and the scenarios run as TestLoadScenariosPostgres (the SQLite ones skip).
LOAD_DRIVER ?= sqlite
load:
	LOAD_DRIVER=$(LOAD_DRIVER) $(GO) test -tags load -count=1 -timeout 4h ./deploy/

# The release check (deploy/ops/release-check.sh): every release check a program can
# do, one line per item, the result lines in release-out/results.md. Before the tag
# it runs items 1 to 10 on the checked-out commit; make release-check TAG=vX.Y.Z runs
# items 11 to 13 on the published release.
# It needs git with the tags fetched, docker with compose and buildx, gh logged in, cosign, jq, Go, Node with npm, and network access (docs/RELEASING.md, The release check); make check does not run it.
TAG ?=
release-check:
	TAG=$(TAG) sh deploy/ops/release-check.sh

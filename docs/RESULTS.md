# Results

The latest result of each check that is run by hand or for a release, and only the latest: a new run replaces its section (git history keeps the earlier ones). Tests read this file. The layout and the rules for updating it are in [RELEASING.md](RELEASING.md); what each check does is in [DESIGN.md](DESIGN.md) (Test suites outside `make check`, Load verification, Release check). No code, token, `state`, provider payload, email or name is recorded here.

## Load

- Date: 2026-11-26
- Commit: 6d07549b52d06db860737e674920eee6226466cc
- Machine: Apple M2 Pro (12 cores, macOS 27.2.1), Docker Desktop 6.12.54-linuxkit (aarch64 VM with 12 CPUs and 8 GB), docker 28.5.2; FeatherAuth in a container limited with `cpus: 1` and `mem_limit: 512m`, Postgres (Postgres runs only) in its own container without a limit, the proxies, k6 and the mock identity provider on the same machine
- Tools: k6 1.4.2 (`grafana/k6:1.4.2`, pinned by digest in `deploy/load/compose.yaml`), Caddy 2.11.9, nginx 1.28, Postgres 18 (`postgres:18`, pinned by digest); the image built with Go 1.27.4 (`golang:1.27.4`, pinned by digest in `deploy/Dockerfile`); memory from `/proc/1/status` (`VmRSS`, `VmHWM`) of the service process and CPU from `docker stats`; percentiles from k6 (the client side, through Caddy) and from the service's own request log (`duration_ms`)

On 2026-11-26, on this commit, both runs were made with `-v` and passed: `make load` (SQLite) exited 0 in 5,527.0 s and `make load LOAD_DRIVER=postgres` exited 0 in 5,538.7 s, each holding the figures of NFR-01 to NFR-11 for its driver. Every figure below is from these two runs. Both runs had 0 failed requests in every scenario and the restart loops, and 0 request log lines with status 4xx or 5xx in every scenario whose log was read. Every scenario is on the real image, with a fresh database seeded with 1,000 users logged in through the mock identity provider (a refresh token each), `rate_limit.per_ip_per_minute: 0` (except the rate limiter scenario), the default log level and `https://auth.example.com` as `public_url`. The shapes are those of the Load verification: steady 20 iterations a second for 10 minutes (about 23 requests a second: 40% refresh, 35% userinfo, 20% JWKS, 5% a whole login), the held peak of 1,000 connections in a closed loop for 5 minutes, the burst of 1,000 refreshes at the same instant, and the soak of 1 hour.

### SQLite

#### Targets

| NFR id | Figure | Measured | Result |
| --- | --- | --- | --- |
| NFR-01 | Steady: p95 under 50 ms for `/token`, `/userinfo`, `/jwks.json`, no errors | client p95 11.4, 5.5 and 4.3 ms; service p95 7.70, 1.36 and 0.10 ms; no errors | met |
| NFR-02 | Held peak: no failed request | 323,762 requests in 5 minutes, 0 failed; 0 request log lines with 4xx or 5xx | met |
| NFR-03 | Held peak: `/userinfo` p95 under 3 ms, `/jwks.json` p95 under 2 ms | client p95 1.8 and 1.6 ms | met |
| NFR-04 | Refresh p99: burst under 3 s; held peak under 15 s | burst 2,527.8 ms; held peak 12,582.0 ms | met |
| NFR-05 | Login overhead under 100 ms | upper bound 12.85 ms: the sum of the service's p95 for authorize (1.04), callback (4.11) and `/token` (7.70 ms) | met |
| NFR-06 | Idle memory under 30 MB | `VmRSS` 23,204 kB after 60 seconds idle | met |
| NFR-07 | Memory under 120 MB at the held peak | `VmHWM` 92,624 kB, read 30 seconds after the 5-minute peak | met |
| NFR-08 | Soak: memory does not grow | mean of the second tenth of the minute samples 32,643 kB, of the last tenth 36,394 kB (11.5% more, within the 20% the test allows) | met |
| NFR-09 | Image under 30 MB | 8,731,975 bytes | met |
| NFR-10 | Startup under 2 seconds | 356.0 ms for `docker stop`, `docker start` and the first answer of `featherauth healthcheck` | met |
| NFR-11 | Restart interrupts service at most 5 seconds | Caddy (restart loop): nothing failed, slowest 262 ms; nginx (restart loop): 2 answers of 502, answering again 1.07 s after the first; Caddy (restart under load): nothing failed, slowest 1,322 ms | met |

#### Idle

The service restarted on the seeded database, warmed with one discovery and one JWKS request, then 60 seconds with no traffic: `VmRSS` 23,204 kB, `VmHWM` 23,204 kB.

#### Steady

20 iterations a second for 10 minutes through Caddy: 13,885 requests (23.1 a second), 0 failed, no 5xx and no 4xx in the service's log, 0 SQLite busy lines. `VmRSS` 33,220 to 36,172 kB; CPU of the container 6.6% of one CPU on average, 8.1% at most.

| Endpoint | n | client p50 / p95 / p99 / max (ms) | service p50 / p95 / p99 (ms) |
| --- | --- | --- | --- |
| `/token` (refresh) | 4,818 | 9.4 / 11.4 / 13.9 / 32.3 | 6.61 / 7.70 / 9.23 (5,430 with the 612 code exchanges) |
| `/token` (code exchange) | 612 | 4.5 / 7.1 / 7.9 / 15.7 | in the row above |
| `/userinfo` | 4,248 | 3.8 / 5.5 / 6.9 / 13.0 | 0.87 / 1.36 / 1.68 |
| `/jwks.json` | 2,371 | 2.8 / 4.3 / 5.3 / 14.3 | 0.04 / 0.10 / 0.13 |
| authorize | 612 | 3.6 / 5.3 / 7.4 / 16.1 | 0.67 / 1.04 / 2.55 |
| callback | 612 | 4.8 / 6.4 / 8.1 / 16.4 | 2.84 / 4.11 / 5.85 |

#### Peak

1,000 connections in a closed loop for 5 minutes through Caddy, on the one CPU: 323,762 requests (1,070 a second), 0 failed, 0 request log lines with 4xx or 5xx, 0 SQLite busy lines; the container's CPU 96.8% on average and 101.4% at most of one CPU. Memory: `VmRSS` 90,148 to 92,720 kB in the samples every 15 seconds during the run (`VmHWM` 92,720 kB at most); 30 seconds after it `VmRSS` 71,912 kB and `VmHWM` 92,624 kB (the figure compared with NFR-07).

| Endpoint | n | client p50 / p95 / p99 / max (ms) | service p50 / p95 / p99 (ms) |
| --- | --- | --- | --- |
| `/token` (refresh) | 108,587 | 1,935.5 / 8,247.1 / 12,582.0 / 31,795.3 | 1,933.19 / 8,245.70 / 12,579.96 |
| `/userinfo` | 107,588 | 1.2 / 1.8 / 4.9 / 173.1 | 0.14 / 0.23 / 0.33 |
| `/jwks.json` | 107,587 | 0.8 / 1.6 / 3.1 / 31.9 | 0.01 / 0.01 / 0.02 |

#### Burst

1,000 refreshes at the same instant: client p50 1,280.7, p95 2,395.1, p99 2,527.8, max 2,603.6 ms, 0 failed; service p50 1,213.30, p95 2,313.95, p99 2,454.76 ms; no 4xx and no 5xx, 0 SQLite busy lines. `VmRSS` 72,220 kB after it.

#### Restart under load

Steady load through Caddy for 2 minutes with `docker compose restart featherauth` one third of the way in (the command took 554 ms): 2,735 requests, 0 failed, slowest answer 1,322 ms. Client p95 and max (ms): `/token` (1,056) 11.3 and 1,321.9, `/userinfo` (839) 5.8 and 1,065.5, `/jwks.json` (472) 4.6 and 509.5.

#### Soak

Steady load for 1 hour: 82,781 requests, 0 failed, no 4xx and no 5xx, 0 SQLite busy lines. `VmRSS` at the start 31,580 kB and at the end 36,580 kB (`VmHWM` 36,580 kB); the minute samples between 32,280 and 33,672 kB for the first 38 minutes, then rising to 36,856 kB at most; the mean of the second tenth of the minute samples 32,643 kB and of the last tenth 36,394 kB, 11.5% more, within the 20% the test allows. CPU of the service 7.0% on average and 10.0% at most of one CPU. Client p95: `/token` 11.3 ms, `/userinfo` 5.2 ms, `/jwks.json` 4.0 ms (service: 8.29, 1.29 and 0.07 ms).

#### Rate limiter

The default limit (30 a minute per address) with load spread over many source addresses: steady load for 10 minutes through nginx, which appends the peer to the `X-Forwarded-For` header k6 sends (a different address for every request), with `trusted_proxies` naming the compose network. 13,942 requests (23.2 a second), 0 failed, no 4xx and no 5xx; 13,309 distinct client addresses in the request log. Service p50 / p95 (ms) against the steady run without the limiter:

| Endpoint | steady, no limit | limiter, nginx |
| --- | --- | --- |
| `/token` | 6.61 / 7.70 | 6.28 / 7.29 |
| `/userinfo` | 0.87 / 1.36 | 0.66 / 1.10 |
| `/jwks.json` | 0.04 / 0.10 | 0.03 / 0.07 |
| authorize | 0.67 / 1.04 | 0.50 / 0.84 |
| callback | 2.84 / 4.11 | 3.01 / 4.45 |

The limiter and the spread addresses add under 1 ms at the 95th percentile.

#### Restart loops

20 refreshes through each example proxy, one every 10 ms, while `docker compose restart featherauth` runs (`TestLoadRestartLoop`):

- Caddy (`Caddyfile.example`, `lb_try_duration 10s`): 20 refreshes, all 200, slowest 262 ms; the restart command took 275 ms.
- nginx (`nginx.example.conf`): 20 refreshes, 13 answers of 200, then 2 of 502 while the service restarted, then 5 of 200; the first 200 after the gap (which took 1.05 s) came 1.07 s after the first 502, within the limit of 5 seconds; the restart command took 261 ms.

### Postgres

Postgres 18 (the image of `compose.postgres.yaml`) in its own container on the same host, with no resource limit; the service has the same limits and the `postgres` block of `database.yaml` with `sslmode: disable` on the compose network and the default pool of 20 connections.

#### Targets

| NFR id | Figure | Measured | Result |
| --- | --- | --- | --- |
| NFR-01 | Steady: p95 under 50 ms for `/token`, `/userinfo`, `/jwks.json`, no errors | client p95 11.1, 5.3 and 3.6 ms; service p95 8.64, 1.85 and 0.05 ms; no errors | met |
| NFR-02 | Held peak: no failed request | 350,952 requests in 5 minutes, 0 failed; 0 request log lines with 4xx or 5xx | met |
| NFR-03 | Held peak: `/userinfo` p95 under 5 s, `/jwks.json` p95 under 64 ms | `/userinfo` client p95 3,726.6 ms; `/jwks.json` client p95 51.6 ms | met |
| NFR-04 | Refresh p99: burst under 3 s; held peak under 7 s | burst 2,664.8 ms; held peak 5,714.1 ms | met |
| NFR-05 | Login overhead under 100 ms | upper bound 17.95 ms: the service's p95 for authorize (3.17), callback (6.14) and `/token` (8.64 ms) | met |
| NFR-06 | Idle memory under 30 MB | `VmRSS` 19,712 kB after 60 seconds idle | met |
| NFR-07 | Memory under 120 MB at the held peak | `VmHWM` 92,868 kB, read 30 seconds after the 5-minute peak | met |
| NFR-08 | Soak: memory does not grow | mean of the second tenth of the minute samples 27,276 kB, of the last tenth 28,038 kB | met |
| NFR-09 | Image under 30 MB | 8,731,975 bytes | met |
| NFR-10 | Startup under 2 seconds | 333.8 ms for `docker stop`, `docker start` and the first answer of `featherauth healthcheck` | met |
| NFR-11 | Restart interrupts service at most 5 seconds | Caddy (restart loop): nothing failed, slowest 259 ms; nginx (restart loop): 2 answers of 502, answering again 1.07 s after the first; Caddy (restart under load): nothing failed, slowest 527 ms | met |

#### Idle

The service restarted on the seeded database, warmed with one discovery and one JWKS request, then 60 seconds with no traffic: `VmRSS` 19,712 kB, `VmHWM` 19,712 kB. The Postgres container: 39,485 kB, CPU 0.0%.

#### Steady

20 iterations a second for 10 minutes through Caddy: 13,895 requests (23.2 a second), 0 failed, no 4xx and no 5xx in the service's log. `VmRSS` 26,444 to 28,960 kB; CPU of the service 5.4% on average and 6.8% at most of one CPU. The Postgres container 44,349 to 47,882 kB, CPU 2.2% on average and 6.0% at most.

| Endpoint | n | client p50 / p95 / p99 / max (ms) | service p50 / p95 / p99 (ms) |
| --- | --- | --- | --- |
| `/token` (refresh) | 4,831 | 9.5 / 11.1 / 12.3 / 32.8 | 7.44 / 8.64 / 9.33 (5,448 with the 617 code exchanges) |
| `/token` (code exchange) | 617 | 4.2 / 5.1 / 5.7 / 7.1 | in the row above |
| `/userinfo` | 4,170 | 3.4 / 5.3 / 6.5 / 16.7 | 1.14 / 1.85 / 2.72 |
| `/jwks.json` | 2,426 | 2.2 / 3.6 / 5.1 / 10.0 | 0.03 / 0.05 / 0.06 |
| authorize | 617 | 4.8 / 6.5 / 7.3 / 18.6 | 2.34 / 3.17 / 3.69 |
| callback | 617 | 5.5 / 7.8 / 8.6 / 10.2 | 4.05 / 6.14 / 6.98 |

#### Peak

1,000 connections in a closed loop for 5 minutes through Caddy, on the service's one CPU: 350,952 requests (1,165 a second), 0 failed, 0 request log lines with 4xx or 5xx. The service's CPU 99.5% on average and 100.8% at most of one CPU. Memory: `VmRSS` 92,452 to 93,244 kB in the samples every 15 seconds during the run (`VmHWM` 93,244 kB at most); 30 seconds after it `VmRSS` 92,452 kB and `VmHWM` 92,868 kB (the figure compared with NFR-07). The Postgres container during the run 92,487 to 161,689 kB, CPU 22.1% on average and 25.1% at most of one CPU; 30 seconds after it 125,132 kB, CPU 0.2%. The wait is the service's one saturated vCPU, applied to each network round trip to Postgres. The service answers `/jwks.json` in 0.01 ms (p95 of its request log), but on Postgres the requests waiting on the database keep the one CPU's queue full, so a JWKS request arriving on its new Caddy connection waits its turn: 51.6 ms at the client's p95.

| Endpoint | n | client p50 / p95 / p99 / max (ms) | service p50 / p95 / p99 (ms) |
| --- | --- | --- | --- |
| `/token` (refresh) | 117,482 | 902.9 / 3,754.5 / 5,714.1 / 14,685.9 | 898.58 / 3,728.20 / 5,707.91 |
| `/userinfo` | 116,987 | 892.9 / 3,726.6 / 5,793.2 / 16,294.9 | 888.46 / 3,720.79 / 5,790.58 |
| `/jwks.json` | 116,483 | 3.1 / 51.6 / 60.8 / 77.4 | 0.01 / 0.01 / 0.01 |

#### Burst

1,000 refreshes at the same instant: client p50 1,394.5, p95 2,562.1, p99 2,664.8, max 2,726.6 ms, 0 failed; service p50 1,289.86, p95 2,433.09, p99 2,524.45 ms; no 4xx and no 5xx. `VmRSS` 59,940 kB after it.

#### Restart under load

Steady load through Caddy for 2 minutes with a restart of the service's container one third of the way in (the command took 457 ms): 2,840 requests, 0 failed, slowest answer 527 ms. Client p95 and max (ms): `/token` (946) 11.0 and 527.1, `/userinfo` (882) 4.8 and 258.2, `/jwks.json` (480) 3.1 and 504.4.

#### Soak

Steady load for 1 hour: 83,081 requests, 0 failed, no 4xx and no 5xx. `VmRSS` at the start 26,000 kB and at the end 28,068 kB (`VmHWM` 28,068 kB), the minute samples 25,972 to 28,084 kB; the mean of the second tenth of the minute samples 27,276 kB and of the last tenth 28,038 kB, so it does not grow. CPU of the service 5.9% on average and 8.7% at most of one CPU. The Postgres container 123,187 to 138,547 kB, CPU 2.4% on average and 5.1% at most of one CPU. Client p95: `/token` 11.7 ms, `/userinfo` 5.2 ms, `/jwks.json` 3.4 ms (service: 9.28, 1.85 and 0.05 ms).

#### Rate limiter

The default limit (30 a minute per address) with the load spread over many source addresses through nginx, for 10 minutes: 13,748 requests (22.9 a second), 0 failed, no 4xx and no 5xx; 13,181 distinct client addresses in the service's log. Service p50 / p95 (ms) against the steady run without the limiter:

| Endpoint | steady, no limit | limiter, nginx |
| --- | --- | --- |
| `/token` | 7.44 / 8.64 | 7.75 / 9.24 |
| `/userinfo` | 1.14 / 1.85 | 1.15 / 1.86 |
| `/jwks.json` | 0.03 / 0.05 | 0.03 / 0.04 |
| authorize | 2.34 / 3.17 | 2.34 / 3.14 |
| callback | 4.05 / 6.14 | 5.17 / 6.51 |

The limiter and the spread addresses add under 1 ms at the 95th percentile.

#### Restart loops

20 refreshes through each example proxy, one every 10 ms, while the service restarts (`TestLoadRestartLoop`):

- Caddy (`Caddyfile.example`, `lb_try_duration 10s`): 20 refreshes, all 200, slowest 259 ms; the restart command took 314 ms.
- nginx (`nginx.example.conf`): 20 refreshes, 12 answers of 200, then 2 of 502 while the service restarted, then 6 of 200; the first 200 after the gap (which took 1.04 s) came 1.07 s after the first 502, within the limit of 5 seconds; the restart command took 242 ms.

## Conformance

- Date: 2026-11-26
- Commit: 6d07549b52d06db860737e674920eee6226466cc
- Suite: release-v5.3.4 (OpenID conformance suite commit 23353b36957d6466010de767c812d2c91ed37638; the images are pinned by digest in `deploy/conformance/compose.yaml`)

`TestConformanceSuite` (the test `make conformance` runs, with `-v`) passed in 79.9 seconds: FeatherAuth is the real image behind Caddy with an internal certificate authority, one realm `conf` with `sso.enabled`, one generic `oidc` provider `sso` pointing at the mock identity provider, and two static confidential clients (`suite1` with `client_secret_basic`, `suite2` with `client_secret_post`, both `require_pkce: false`). No test condition failed in any plan.

### Summary

| Plan | Passed | Review | Warning | Failed | Skipped |
| --- | --- | --- | --- | --- | --- |
| Basic OP | 19 | 4 | 5 | 0 | 7 |
| Config OP | 1 | 0 | 0 | 0 | 0 |
| RP-Initiated Logout OP | 3 | 8 | 0 | 0 | 0 |

A Review result is a test that passed every check and asks for a screenshot to be looked at for a certification: `oidcc-prompt-login`, `oidcc-max-age-1`, `oidcc-ensure-registered-redirect-uri`, `oidcc-ensure-request-object-with-redirect-uri`, and in the logout plan `oidcc-rp-initiated-logout-bad-post-logout-redirect-uri`, `-modified-id-token-hint`, `-bad-id-token-hint`, `-no-id-token-hint`, `-query-added-to-post-logout-redirect-uri`, `-no-params`, `-no-post-logout-redirect-uri` and `-only-state`. Every other test passed.

### Differences

None: every module matched `deploy/conformance/expected/`. There is no expected failure.

### Expected warnings and skips

The warnings and skips that `deploy/conformance/expected/` lists, with the reason of each.

| Test | Condition | Reason |
| --- | --- | --- |
| `oidcc-server` | `EnsureIdTokenDoesNotContainName`, `EnsureIdTokenDoesNotContainNonRequestedClaims` | `user_data.claims` decides the claims in every ID token and scopes do not filter them. |
| `oidcc-claims-essential` | `EnsureIdTokenDoesNotContainName` | The same. |
| `oidcc-userinfo-post-body` | `UserInfoEndpointWithAccessTokenInBodyNotSupported` | `/userinfo` takes the bearer token in the `Authorization` header (FR-09); the form-body method of RFC 6750 section 2.2 is optional and not offered. |
| `oidcc-ensure-request-with-acr-values-succeeds` | `ValidateIdTokenACRClaimAgainstAcrValuesRequest` | `acr_values` is ignored without error and there is no `acr` claim. |
| `oidcc-codereuse-30seconds` | `EnsureHttpStatusCodeIs4xx` | A reused code revokes the session, not the access tokens already issued: they are self-contained and stay valid until they expire (SEC-14). |
| `oidcc-scope-profile`, `oidcc-scope-email`, `oidcc-scope-address`, `oidcc-scope-phone`, `oidcc-scope-all`, `oidcc-alternate-happy-flow` | skipped | The discovery document lists `scopes_supported: ["openid"]` only, because scopes do not filter claims, so the suite skips the tests that need other scopes. |
| `oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported` | skipped | The authorize endpoint answers `request_not_supported`, which the OpenID Connect specification permits. |

## Browser

- Date: 2026-11-21

Chrome is tested by `make browser` (chromedp, build tag `browser`); Firefox and Safari are checked by hand against the in-process service (`TestManualServer`, build tag `manual`), and the Apple web flow on a real HTTPS domain with a real Apple account.

### Manual matrix

All cells are OK unless said otherwise. Chrome's `form_post`, JavaScript-off, Apple cross-site and two-tab checks are automated (`make browser`); the buttons were compared with each vendor's rules (labels, colours, one size, no scrolling at 360 by 640, sharp logos) by the owner on 2026-11-21 with five buttons (Google, Apple, GitHub, Facebook, GitLab).

| Browser | Version | form_post | Without JavaScript | Apple cross-site | Two tabs | Buttons desktop | Buttons phone | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Chrome | 157.0.8103.80 on macOS | automated | automated | automated | automated | OK | OK | Buttons checked 2026-11-21; screenshot at phone width seen, none at desktop width. |
| Firefox | 160.0 on macOS | OK | OK | OK | OK | OK | OK | Lists run 2026-11-14, buttons 2026-11-21. No CSP console violation. |
| Safari | 27.0.1 on macOS | OK | OK | OK | OK | OK | OK | Lists run 2026-11-14 (Safari 27), buttons 2026-11-21. No CSP console violation. |
| Safari on iOS | 27.2 (the iOS Simulator, not a phone) | OK | OK | OK | OK | not run | not run | Run 2026-11-14. |

### Apple web flow

Each run is on a real HTTPS domain behind nginx with a real Apple account. The `ASWebAuthenticationSession` and Chrome Custom Tabs rows and the iOS phone browser row were skipped by the owner's decision of 2026-11-21: real logins on the web are enough.

| Run | Browser and version | Date | Result | Notes |
| --- | --- | --- | --- | --- |
| Apple's web flow and notification pages read and compared with the design | read in a browser by the owner | 2026-11-21 | pass: no difference that needs a design change | "Request an authorization to the Sign in with Apple server" and "Processing changes for Sign in with Apple accounts" match the design: `response_mode` `form_post` when scopes are requested, an HTTPS `redirect_uri` with a domain name, the success fields `code`, `id_token`, `state` and `user`, the error fields `error` and `state`, the only error code `user_cancelled_authorize`, `user` only at the first authorization, a signed notification, the events `email-disabled`, `email-enabled`, `consent-revoked` and `account-deleted`. Apple's samples have `events` as an object and no `exp`; the real notification had `events` as a string and an `exp`; the design accepts both. |
| Apple login in `ASWebAuthenticationSession` (in-app session) on iOS | not run | 2026-11-21 | skipped (owner's decision) | Real logins on the web are enough. |
| Apple login in Chrome Custom Tabs on Android | not run | 2026-11-21 | skipped (owner's decision) | Real logins on the web are enough. |
| Apple login in Firefox | Firefox 160.0 on macOS | 2026-11-21 | pass | The code was exchanged, userinfo answered with the same `sub` and the name, and the refresh worked. |
| Apple login in Safari on macOS | Safari 27.0.1 on macOS | 2026-11-21 | pass | The code was received and exchanged, so the `Lax` cookie was found. |
| Apple login in Safari on iOS (the phone's browser) | not run | 2026-11-21 | skipped (owner's decision) | Real logins on the web are enough. |
| Second login keeps the name of the first login | Safari 27.0.1 on macOS | 2026-11-21 | pass | name stored: yes; `sub` unchanged at the second login. |
| Cancelled login: the `error` value Apple posts to the callback | Chrome 157.0.8103.80 on macOS | 2026-11-21 | pass: Apple posted `error=user_cancelled_authorize`, as the design says | The service answered `access_denied` with `state=s1`. The cancel was made at the confirmation screen of a first authorization (the app had been removed at appleid.apple.com); the sign-in page has no cancel control. |
| Server-to-server notification from Apple verified and acted on | notifications from Apple's own servers to the live server | 2026-11-21 | pass | Three `consent-revoked` notifications, each answered `200` and each with the audit line `identity.consent_revoked` for the user, with no email in it; the refresh with the token of the first login then answered `invalid_grant`. |
| Form of a real notification: `events` as object or string, event names, `exp` | the live server's proxy capture | 2026-11-21 | `events` as a string (JSON text); event `consent-revoked`; keys `type`, `sub`, `event_time`; `exp`, `iat` and `jti` present | Apple's samples show an object and no `exp`; the design accepts both forms and a payload with or without `exp`, so no design change follows. The captured body was deleted. |

## Release gate

- Release:
- Commit:
- Date:

No gate is recorded yet under the release check of `docs/RELEASING.md`. The conformance, load, browser and Apple results above stay in their own sections. Each row below is filled at the next release, with a value defined in `docs/RELEASING.md` and a detail; `TestReleaseGateResultsRecorded` (build tag `manual`) fails while any row is empty.

| Check | Result | Detail |
| --- | --- | --- |
| 1 |  |  |
| 2 |  |  |
| 3 |  |  |
| 4 |  |  |
| 5 |  |  |
| 6 |  |  |
| 7 |  |  |
| 8 |  |  |
| 9 |  |  |
| 10 |  |  |
| 11 |  |  |
| 12 |  |  |
| 13 |  |  |
| M1 |  |  |
| M2 |  |  |
| M3 |  |  |
| M4 |  |  |
| M5 |  |  |
| M6 |  |  |

### Release tags

| Tag | Commit | Image digest |
| --- | --- | --- |

No release is recorded yet: the first `make release-check TAG=...` writes this table.

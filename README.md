<p align="center"><img src="docs/assets/icon.png" alt="FeatherAuth" width="96"></p>

# FeatherAuth

**Social login for all your apps, from one small service you run yourself.**

FeatherAuth is a self-hosted OpenID Connect provider written in Go. Your web and mobile apps send users to it. It lets them sign in with Google, Apple, GitHub, Facebook or any other OpenID Connect provider, keeps its own user records, and returns standard tokens. Your APIs verify those tokens offline with public keys. It is one static binary in a container image measured at 8.7 MB, configured with plain text files that reload while it runs.

```text
phone / browser --HTTPS--> reverse proxy (Caddy or nginx) --plain HTTP--> FeatherAuth --> SQLite file or Postgres
                           certificate, port 80 redirect,                  serves its own pages and
                           routing by host name                            the OIDC endpoints on a local port

FeatherAuth --HTTPS--> Google, Apple, GitHub, Facebook, other OIDC providers
your API    --HTTPS--> FeatherAuth's public keys (JWKS), fetched once and cached
```

The proxy is optional: FeatherAuth can also end TLS itself from certificate files. In Docker its port is published on `127.0.0.1` only, so nothing reaches it except the proxy on the same host.

## Why FeatherAuth

**It is for you if:**

- you have one or more apps (iOS, Android, React Native, Flutter, single-page web, server-rendered) that need "Sign in with Google / Apple / GitHub / Facebook", and you want no provider secret inside any app;
- you want standard OIDC, so that any OIDC or OAuth 2 client library works and any API verifies tokens offline;
- you want your user data on your own server, with your own user ids that survive a change of provider;
- you want something small: one server with Docker is enough, and everything that varies is a text file.

**It is not for you if you need** passwords, magic links, passkeys or multi-factor sign-in; roles and permissions (FeatherAuth proves who a user is, your apps decide what they may do); an admin web interface or admin API; consent screens; or dynamic client registration. The full list of what it deliberately does not do is in [REQUIREMENTS.md, Non-goals](docs/REQUIREMENTS.md#non-goals).

**Compared with the alternatives.** A full identity server covers far more: passwords, MFA, federation protocols, admin interfaces. It also brings more to run, configure and keep patched. A hosted identity service needs no server at all, but your users' data and sign-in flow live with the vendor. FeatherAuth sits between the two. It covers social sign-in and standard OIDC tokens and nothing else, in a process that idles under 30 MB of memory and has no administration over the network.

## What you get

**Providers**
- Google (with an optional Workspace domain restriction), Apple (form-post callback, generated client secret, name kept from the first sign-in), GitHub (verified primary email), Facebook (`appsecret_proof` on every Graph call), and any single-issuer OpenID Connect provider from configuration alone.
- Each built-in button follows its provider's branding.
- Account notices from the providers: Apple's server-to-server notifications, Google's Cross-Account Protection security events, and Meta's data-deletion callback and instructions page.
- Your own user table, with several identities per user and automatic linking only on a verified email from a domain that never reassigns addresses.

**Standard protocols**
- OIDC authorization code flow with PKCE (`S256`) for every client, public and confidential.
- Discovery, JWKS, userinfo, RP-Initiated Logout, token revocation (RFC 7009) and Back-Channel Logout.
- Access tokens as RFC 9068 JWTs (`typ: at+jwt`, `RS256` or `ES256`), ID tokens in `RS256`, and rotating refresh tokens with reuse detection.
- `iss` in every authorization response (RFC 9207). Sender-constrained tokens with DPoP (RFC 9449), per client.
- An optional single sign-on browser session with silent `prompt=none`.
- Configurable endpoint paths and parameter names, for client libraries that expect a fixed URL layout.

**Security**
- Exact redirect URI matching, validated at load.
- A state cookie per sign-in, and a mix-up defence.
- Codes and refresh tokens stored only as hashes. The only provider token stored is Apple's refresh token (so that account deletion can revoke it), encrypted with AES-GCM, and that can be switched off.
- Secrets only in files with strict permissions, never in logs. Logs hold no tokens, codes, cookies or emails at any level.
- Rate limiting per IPv4 address or IPv6 `/64`.
- In-app account deletion guarded by a recent sign-in; sign out everywhere; a user's session list.

**Operations**
- One container image, read-only root filesystem, no Linux capabilities, non-root user.
- Hot reload of realms, clients and providers; `config check` validates offline with file and line numbers.
- Isolated realms (one per product or environment).
- SQLite by default with a built-in daily snapshot, and an encrypted off-server copy script. Postgres as an option, with a verified copy tool from SQLite.
- Several instances on one Postgres database, a shared rate limit, and rolling deploys with no failed request.
- Health endpoints, JSON logs, audit records.
- A command line for users, sessions, keys, import and backup.
- Built-in TLS from certificate files, or any reverse proxy (Caddy and nginx examples included).
- Signed images with a software bill of materials.

## Measured performance

**How it was measured:**

- **Machine:** the service in a container limited to **1 CPU and 512 MB of memory**, on an Apple M2 Pro under Docker Desktop.
- **Setup:** Caddy in front, and a database seeded with 1,000 users and their refresh tokens.
- **Load shapes:**
  - *Steady*: 20 requests a second, mixed, for 10 minutes.
  - *Held peak*: 1,000 connections kept busy in a closed loop on refresh, userinfo and JWKS for 5 minutes.
  - *Burst*: 1,000 refreshes sent at the same moment.

The figures are recorded in [docs/RESULTS.md](docs/RESULTS.md). They come from one run per database, both on the same commit and the same image.

| Load shape and measure | SQLite | Postgres |
| --- | --- | --- |
| Steady: p95 of refresh, userinfo, JWKS | 11.4, 5.5, 4.3 ms | 11.1, 5.3, 3.6 ms |
| Held peak: failed requests | 0 | 0 |
| Held peak: p95 of userinfo, JWKS | 1.8 ms, 1.6 ms | 3.7 s *, 51.6 ms * |
| Burst: refresh p99 | 2.5 s | 2.7 s |
| Held peak: refresh p99 | 12.6 s * | 5.7 s * |
| Steady: time added to a sign-in (upper bound) | 12.9 ms | 18.0 ms |
| Memory: idle / held peak | 23.2 MB / 92.6 MB | 19.7 MB / 92.9 MB |
| Startup to ready | 0.36 s | 0.33 s |
| Image size | 8.7 MB (one image for both databases) | |
| Restart behind Caddy, under steady load | 0 failed requests | 0 failed requests |

Figures marked * are the held peak's queueing tail: with 1,000 connections always waiting, the one CPU is saturated by RSA signing, and every request waits its turn. On Postgres the requests waiting on the database keep the CPU's queue full, so a JWKS request, which arrives on a new proxy connection, waits its turn too; serving it takes about 0.01 ms. They are far above the steady-load figures. The published targets ([REQUIREMENTS.md, NFR](docs/REQUIREMENTS.md#performance-and-size-requirements-nfr)) are set per database and load shape: where a target comes from a measurement it was set at the figure measured then plus 20%, rounded up to a whole unit, and a later run meets it by staying under it (for example held-peak refresh p99 under 15 s on SQLite and under 7 s on Postgres). A second CPU, or `tokens.algorithm: ES256` (much cheaper signing), adds capacity.

To reproduce, with Docker: `make load` (SQLite) and `make load LOAD_DRIVER=postgres`. The measured scenarios of each run take about 90 minutes, because they include a one-hour soak test. With building the image and setting up the stack, plan about 1 hour 45 minutes per run, 3 hours 30 minutes for both.

## Security posture

- **OpenID conformance suite.** The OpenID Foundation's suite runs against the real image (`make conformance`).
  - Plans: Basic OP, Config OP and RP-Initiated Logout OP.
  - Result: no failed tests. Every warning and skip is recorded with its reason in [docs/RESULTS.md](docs/RESULTS.md) (Conformance); for example, scopes do not filter claims, and request objects are answered "not supported".
  - This is a self-run of the suite, not an OpenID certification.
- **Following the OAuth security best practice** (RFC 9700):
  - PKCE `S256` is required for every client; `plain` and downgrades are refused;
  - redirect URIs match exactly;
  - refresh tokens rotate with reuse detection;
  - tokens of one kind cannot stand in for another;
  - provider calls follow no redirects.
- **Vetted libraries** for OAuth, OIDC and JWT, no hand-written cryptography, and `govulncheck` in CI.
- **Signed images.** Every published image is signed by digest with the release workflow's own identity (keyless) and carries an SPDX software bill of materials. The identity pattern below also accepts the images built from the `main` branch (tagged with a commit hash), so check and run a release tag `vX.Y.Z`, or better its digest:

```bash
ID='^https://github.com/yyudhistira/featherauth/\.github/workflows/deploy\.yml@refs/(heads/main|tags/v[0-9]+\.[0-9]+\.[0-9]+)$'
ISS=https://token.actions.githubusercontent.com
IMG=ghcr.io/yyudhistira/featherauth:vX.Y.Z
cosign verify --certificate-oidc-issuer "$ISS" --certificate-identity-regexp "$ID" "$IMG"
cosign verify-attestation --type spdxjson --certificate-oidc-issuer "$ISS" --certificate-identity-regexp "$ID" "$IMG"
# Build provenance: GitHub records it only for a public repository; where it exists:
gh attestation verify "oci://$IMG" --repo yyudhistira/featherauth --signer-workflow yyudhistira/featherauth/.github/workflows/deploy.yml
```

The known limits are written down rather than hidden: see [the guide's security notes](docs/USER_GUIDE.md#16-security-notes-for-operators). The main one is that access tokens stay valid until they expire (15 minutes by default) after a logout; APIs that need an immediate answer call `/userinfo`.

## Use cases

| | |
| --- | --- |
| Native mobile app | Sign-in in the system browser with PKCE; stays signed in for months or years with rotating (optionally device-bound) refresh tokens |
| Single-page web app | Sign-in from the browser, token exchange from JavaScript for your registered origins |
| Server-rendered app or backend for a frontend | Confidential client with a secret kept on your server |
| An API | Verifies access tokens offline with the realm's JWKS |
| Several products | One isolated realm per product or environment |
| Operators and scripts | Text configuration and a command line, run where the data is |
| The person signing in | Chooses a provider; can sign out, sign out everywhere, or delete the account from the app |

## First setup

This is the quick start of the [user guide](docs/USER_GUIDE.md#3-quick-start-one-server-with-docker), shortened. Replace `vX.Y.Z` with a release tag and `auth.example.com` with your host.

**You need:**

- a Linux host with Docker and the Docker Compose plugin;
- `curl`, `jq` and `openssl`;
- a domain name whose DNS points at the host, with ports 80 and 443 open;
- a checkout of this repository on the host (`/opt/featherauth-src` below);
- a released image tag. Release images are tagged `vX.Y.Z` only, never `latest`; every release and its notes are on the repository's [Releases page](https://github.com/yyudhistira/featherauth/releases).

No FeatherAuth binary is needed on the host: the configuration and the keys are written with the image alone. The compose files and `Caddyfile.example` still come from the checkout of the repository (the guide's backup step also copies `backup-offsite.sh` from it). Run all the commands below **in one shell**: step 4 uses the `IMG` variable and the `run` function defined in step 2.

```bash
# 1. Files, and the .env that every later docker compose call in /opt/featherauth reads
SRC=/opt/featherauth-src
sudo mkdir -p /opt/featherauth
sudo cp $SRC/deploy/compose.yaml $SRC/deploy/compose.caddy.yaml $SRC/deploy/Caddyfile.example /opt/featherauth/
sudo cp /opt/featherauth/Caddyfile.example /opt/featherauth/Caddyfile
printf 'FEATHERAUTH_TAG=vX.Y.Z\nFEATHERAUTH_CONFIG=/opt/featherauth/config\nCOMPOSE_FILE=compose.yaml:compose.caddy.yaml\n' | sudo tee /opt/featherauth/.env

# 2. Configuration and keys, written by one-off containers of the image as its user (uid 65532):
#    no FeatherAuth binary on the host, no network, read-only root
IMG=ghcr.io/yyudhistira/featherauth:vX.Y.Z
sudo install -d -o 65532 -g 65532 -m 700 /opt/featherauth/config
run() { sudo docker run --rm --user 65532:65532 --network none --read-only -v /opt/featherauth/config:/etc/featherauth "$IMG" "$@"; }
run config init /etc/featherauth
run keys generate /etc/featherauth/secrets/main/signing-1.pem
run keys generate --type encryption /etc/featherauth/secrets/encryption_key
sudo mv /opt/featherauth/config/realms/example.yaml /opt/featherauth/config/realms/main.yaml
```

3. Edit the files as root:
   - `config/server.yaml`: `public_url: https://auth.example.com`.
   - `config/realms/main.yaml`:
     - `name: main`;
     - replace the example key entry (`secrets/example/signing-2026-10.pem`, which does not exist) with the key you generated: `{ kid: main-1, file: secrets/main/signing-1.pem, state: active }`;
     - one provider with `enabled: true`, its `client_id` and `client_secret_file`, and its secret in that file ([provider steps](docs/USER_GUIDE.md#4-set-up-the-providers));
     - one client ([client example](docs/USER_GUIDE.md#5-add-a-client-and-test-a-sign-in)).
   - `Caddyfile`: your host name, and the upstream line `reverse_proxy featherauth:8080 {` instead of `127.0.0.1:8080`.

```bash
# 4. Permissions, offline check, start (COMPOSE_FILE adds Caddy)
sudo chown -R 65532:65532 /opt/featherauth/config
sudo find /opt/featherauth/config -type d -exec chmod 700 {} \;
sudo find /opt/featherauth/config -type f -exec chmod 600 {} \;
run config check /etc/featherauth
cd /opt/featherauth && sudo docker compose up -d

# 5. Wait until featherauth shows "healthy", then check
sudo docker compose ps
curl -sS http://127.0.0.1:8080/readyz                                   # ok
curl -sS https://auth.example.com/main/.well-known/openid-configuration | head -c 300
```

Then:

- set `trusted_proxies` to the compose network's range ([guide 3.4](docs/USER_GUIDE.md#34-put-a-proxy-in-front-caddy));
- run a test sign-in with the `curl` steps of [guide section 5](docs/USER_GUIDE.md#5-add-a-client-and-test-a-sign-in).

Commands inside the running container use the binary's path, `/featherauth`. For example:

```bash
sudo docker compose exec featherauth /featherauth user get main <user id>
```

Rate limits, backups, key rotation, upgrades and scaling are in the [user guide](docs/USER_GUIDE.md). For example, which endpoints the rate limit covers is in its configuration chapter, section 13.3.

## Use it from an app

Any standard OIDC library works. The repository ships a small runnable example, [examples/web-app/](examples/web-app/): a React single-page app built with Vite. It uses the widely used library [oidc-client-ts](https://github.com/authts/oidc-client-ts) for the flow and [jose](https://github.com/panva/jose) to verify the ID token's signature, which oidc-client-ts does not check. It shows:

- sign-in as a public client with the authorization code flow and PKCE;
- the verified claims, and whether the `sub` that userinfo returns (called by the app itself once per sign-in and once per refresh) matches;
- a refresh with the refresh token, only when you press **Refresh**;
- sign-out through RP-initiated logout.

Tokens are kept in memory only, so reloading the page signs you out. The Docker variant serves the app through Caddy with a Content-Security-Policy and `X-Content-Type-Options: nosniff`. It is a separate Node project, so FeatherAuth itself gains no dependency. These lines are taken from its `src/auth.js` and `src/App.jsx`:

```js
import { InMemoryWebStorage, UserManager, WebStorageStateStore } from "oidc-client-ts";
import { createRemoteJWKSet, jwtVerify } from "jose";

// config.json: authority https://auth.example.com/example, client_id example-web,
// redirect_uri http://127.0.0.1:5173/callback, post_logout_redirect_uri http://127.0.0.1:5173/
const auth = new UserManager({
  authority: config.authority,
  client_id: config.client_id,
  redirect_uri: config.redirect_uri,
  post_logout_redirect_uri: config.post_logout_redirect_uri,
  response_type: "code", // the library adds PKCE (S256), state and nonce
  scope: "openid",
  loadUserInfo: false, // the app calls userinfo itself (userinfoSub): once per sign-in and once per refresh
  automaticSilentRenew: false,
  userStore: new WebStorageStateStore({ store: new InMemoryWebStorage() }),
});

auth.signinRedirect();                                   // Sign in
const user = await auth.signinRedirectCallback();       // back on /callback
const metadata = await auth.metadataService.getMetadata();
const jwks = createRemoteJWKSet(new URL(metadata.jwks_uri));
const { payload } = await jwtVerify(user.id_token, jwks, {
  issuer: config.authority,
  audience: config.client_id,
  algorithms: ["RS256"],
  typ: "JWT",
  clockTolerance: 300, // seconds of difference allowed between this clock and the server's
});
await auth.signinSilent();                               // Refresh: uses the refresh token
auth.signoutRedirect();                                  // Sign out
await auth.signoutRedirectCallback();                    // back on / after logout
```

To run it, you need FeatherAuth reachable over HTTPS with a provider you can sign in with, as in the [first setup](#first-setup).

1. Copy the `example-web:` block of [examples/web-app/example-web-client.yaml](examples/web-app/example-web-client.yaml) under `clients:` in your realm file, then reload with `sudo docker compose kill -s HUP featherauth`. The entry is for trying the example, not for production.
2. Set `authority` in `examples/web-app/public/config.json` to your realm's issuer (for example `https://auth.example.com/main`). The Docker variant mounts this file read-only, so a later change needs only a restart of the container, not a rebuild.
3. Start the app. It must run at `http://127.0.0.1:5173`, because FeatherAuth accepts plain `http` only on `127.0.0.1` and the post-logout URL matches exactly. Port 5173 on the host must be free.

```sh
# with Node (the version in examples/web-app/.node-version)
cd examples/web-app && npm ci --ignore-scripts && npm run dev

# or with Docker only, from the repository root
docker compose -f examples/web-app/compose.yaml up --build
```

Open <http://127.0.0.1:5173/> and press **Sign in**. The example's [README](examples/web-app/README.md) explains the rest. For mobile apps, server-side apps and APIs that check tokens, see the guide's [integration chapter](docs/USER_GUIDE.md#6-integrate-an-app-or-an-api).

## Where to go next

| Document | For |
| --- | --- |
| [docs/USER_GUIDE.md](docs/USER_GUIDE.md) | Setting up, integrating apps and APIs, running, upgrading, scaling, every option |
| [docs/REQUIREMENTS.md](docs/REQUIREMENTS.md) | What FeatherAuth must do and why: goals, non-goals, product, operations, security and performance requirements |
| [docs/DESIGN.md](docs/DESIGN.md) | How it is built and tested, in full detail |
| [Releases](https://github.com/yyudhistira/featherauth/releases) | The release notes: every behaviour change and breaking change of each release, and what to check before you upgrade |
| [docs/RELEASING.md](docs/RELEASING.md) | How releases are cut and verified |

## Licence

FeatherAuth is licensed under the [Apache License 2.0](LICENSE).

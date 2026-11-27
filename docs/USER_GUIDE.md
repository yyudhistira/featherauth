# FeatherAuth user guide

This guide is for the people who run FeatherAuth (operators) and the people who connect apps and APIs to it (app developers). It starts with the shortest path to a working sign-in and goes into detail afterwards. What FeatherAuth must do is in [REQUIREMENTS.md](REQUIREMENTS.md); how it does it, in full detail, is in [DESIGN.md](DESIGN.md).

Examples use neutral names: the host `auth.example.com`, the realm `main`, the clients `web` and `mobile`. Replace them with yours.

Contents:

1. What FeatherAuth does
2. How a sign-in works (data flow)
3. Quick start: one server with Docker
4. Set up the providers
5. Add a client and test a sign-in
6. Integrate an app or an API
7. Run it day to day
8. Emergency key rotation
9. Upgrade and roll back
10. Databases: SQLite and Postgres
11. Scale up
12. Change the configuration safely
13. Configuration options
14. Deploy tools and commands
15. Troubleshooting
16. Security notes for operators

---

## 1. What FeatherAuth does

FeatherAuth is a small, self-hosted login service. Your apps send users to it; it lets the user sign in with Google, Apple, GitHub, Facebook or any other OpenID Connect provider; it keeps its own user records; and it returns standard OpenID Connect (OIDC) tokens. Your APIs check those tokens offline with public keys.

It proves **who** a user is. It does not decide what a user may do: permissions and roles stay in your apps.

Typical uses:

| You have | FeatherAuth gives you |
| --- | --- |
| A mobile app (iOS, Android, React Native, Flutter) | Sign-in through the system browser, with PKCE and long-lived refresh tokens; no provider secret in the app |
| A single-page web app | Sign-in from the browser, token exchange from JavaScript (CORS for your origins) |
| A server-rendered app or a backend for a frontend | Sign-in with a client secret kept on your server |
| An API | Tokens it verifies with the realm's public keys (JWKS), no call to FeatherAuth needed |
| Several products | One isolated realm per product or environment, each with its own users, keys, providers and clients |
| An operator or a script | Text configuration that reloads while running, and a command line for users, sessions, keys, backups and checks |

FeatherAuth does not offer passwords, email sending, roles, consent screens, an admin web interface or an admin HTTP API, dynamic client registration, front-channel logout, token introspection or telemetry. The full list is in REQUIREMENTS.md (Non-goals).

## 2. How a sign-in works (data flow)

### Where requests travel

```text
phone / browser --HTTPS--> reverse proxy (Caddy or nginx) --plain HTTP--> FeatherAuth --> SQLite file or Postgres
                           certificate, port 80 redirect,                  serves its own pages and
                           routing by host name                            the OIDC endpoints on a local port

FeatherAuth --HTTPS--> Google, Apple, GitHub, Facebook, other OIDC providers (code exchange, keys, user info)
FeatherAuth --HTTPS--> your apps' servers (back-channel logout notices, only if you configure them)
your API    --HTTPS--> FeatherAuth's JWKS (public keys, fetched once and cached)
```

- The **reverse proxy** is the public front door: it ends HTTPS, redirects port 80 and routes by host name. FeatherAuth can also end TLS itself (section 3.6).
- **FeatherAuth** is one Go program in a small container. It serves the provider chooser and error pages itself. In Docker its port is published on `127.0.0.1` only, so only the proxy on the same host reaches it.
- The **real sign-in** happens on the provider's own pages.
- FeatherAuth sends no telemetry. Its only outgoing calls are to its database, to your configured providers and to the back-channel logout addresses of your clients.

### The sign-in (authorization code flow with PKCE)

```text
 App                     Browser                  FeatherAuth                   Provider
  |  1. open /main/authorize?client_id=..&redirect_uri=..&code_challenge=..&state=..  |
  |----------------------->|------------------------->|                              |
  |                        |  2. chooser page (or straight on with provider=...)    |
  |                        |<-------------------------|                              |
  |                        |  3. sign in at the provider ---------------------------->|
  |                        |  4. back to /main/callback/google?code=..               |
  |                        |------------------------->|  5. exchange code, check ID   |
  |                        |                          |     token, find/create user   |
  |                        |                          |<----------------------------->|
  |  6. redirect_uri?code=..&state=..&iss=..          |                              |
  |<-----------------------|<-------------------------|                              |
  |  7. POST /main/token (code + code_verifier, or client secret)                    |
  |-------------------------------------------------->|                              |
  |  8. access token, ID token, refresh token         |                              |
  |<--------------------------------------------------|                              |
  |  9. call your API with the access token; the API checks it with the JWKS         |
```

- The code in step 6 works once and for 60 seconds (`tokens.code_lifetime`).
- If the user cancels or the provider fails, step 6 returns `error` (for example `access_denied` or `temporarily_unavailable`) with `state` and `iss`, and the app decides what to show.
- If the request itself is invalid before the client and its redirect URI are known to be good, the browser gets an error page and is never redirected.

### Tokens

| Token | What it is | Lifetime (default) | Who checks it |
| --- | --- | --- | --- |
| Access token | JWT with header `typ: at+jwt` (RFC 9068), signed with the realm's algorithm (`RS256` or `ES256`); claims `iss`, `sub`, `aud`, `client_id`, `azp`, `exp`, `iat`, `jti`, `auth_time`, `sid`, `scope`, `nonce` and the realm's user claims | 15 minutes | Your API, offline |
| ID token | JWT, always `RS256`, for the app only | same as the access token | The app's OIDC library |
| Refresh token | An opaque random value (or a JWT with `refresh_token_format: jwt`), stored only as a hash on the server | 30 days unused (`refresh_idle_lifetime`), 90 days in total (`session_max_lifetime`) | FeatherAuth only |

`sub` is FeatherAuth's own user id and never changes. Every client gets the same small set of user claims; scopes other than `openid` are ignored.

### Refresh

Each refresh returns a new refresh token and the old one stops working (rotation). A token used again after the short grace window (`refresh_reuse_grace`, 30 seconds) is treated as stolen: the whole session ends and the operator sees a `session.reuse_detected` audit record. Within the grace window a retry after a lost answer still works.

A session lives as long as it is used within `refresh_idle_lifetime`, up to `session_max_lifetime` (`0` means no cap). A mobile app that should stay signed in for years gets long values on its own client (section 13.5).

### Logout

| How | What ends |
| --- | --- |
| Browser to the logout endpoint with `id_token_hint` (RP-initiated logout) | That session; redirect only to a registered `post_logout_redirect_uri` |
| App `POST`s its `refresh_token` to the logout endpoint | That session (`204`) |
| `POST` with `Authorization: Bearer <access token>` | That session; with `all_sessions=true` every session of the user, with `session=<id>` one session (client option `allow_session_management`) |
| The revocation endpoint (RFC 7009) | The session of the token |

Access tokens already issued stay valid until they expire (15 minutes by default). FeatherAuth's own `/userinfo` refuses them at once. If a client has `backchannel_logout_uri`, its server gets a signed logout token for every session that ends.

### Single sign-on (optional)

With `sso.enabled: true` in a realm, a completed sign-in also leaves a browser session cookie. A later sign-in from the same browser, for any client with `sso: true`, gets a code straight away without the chooser or the provider. `prompt=none` then works for silent renewal in web apps. A logout through the browser, or the end of a session that came from it, ends the browser session.

## 3. Quick start: one server with Docker

What you need:

- a Linux host with Docker and the Docker Compose plugin (`docker compose`);
- `curl`, `jq` and `openssl` on the host, for the checks and the test sign-in;
- a DNS name for the service (`auth.example.com`) pointing at the host, with ports 80 and 443 open;
- a checkout of this repository on the host, for the compose files and scripts (for example `git clone` into `/opt/featherauth-src`);
- a released image tag.

Release images are published as `ghcr.io/yyudhistira/featherauth:vX.Y.Z`. Every release and its release notes are on the repository's [Releases page](https://github.com/yyudhistira/featherauth/releases). Release images are tagged `vX.Y.Z` only; no `latest` tag is published, so you always name a version. Section 14.4 says how to verify an image's signature before you run it.

### 3.1 Get the files

```bash
SRC=/opt/featherauth-src           # your checkout of the repository
sudo mkdir -p /opt/featherauth
sudo cp $SRC/deploy/compose.yaml $SRC/deploy/compose.caddy.yaml $SRC/deploy/compose.postgres.yaml \
        $SRC/deploy/compose.tls.yaml $SRC/deploy/Caddyfile.example /opt/featherauth/
sudo cp $SRC/deploy/ops/backup-offsite.sh /opt/featherauth/ && sudo chmod 755 /opt/featherauth/backup-offsite.sh
```

`compose.yaml` runs FeatherAuth alone with its port on `127.0.0.1:8080`, a read-only root filesystem, no Linux capabilities and `no-new-privileges`. Three variables control it:

- `FEATHERAUTH_TAG`: the image tag. It is required: without it compose stops with a message.
- `FEATHERAUTH_CONFIG`: the host directory with the configuration, mounted read-only at `/etc/featherauth` (default `./config`).
- `COMPOSE_FILE`: the compose files to use, separated by `:`. Later sections extend it: `compose.yaml:compose.caddy.yaml` with Caddy (3.4), and `:compose.postgres.yaml` added for Postgres (10.2).

Put them in a `.env` file next to the compose files. Every later `docker compose` call run in `/opt/featherauth` reads it, so `up`, `pull`, `stop`, `start` and `exec` always use the same files:

```bash
printf 'FEATHERAUTH_TAG=vX.Y.Z\nFEATHERAUTH_CONFIG=/opt/featherauth/config\nCOMPOSE_FILE=compose.yaml\n' | sudo tee /opt/featherauth/.env
```

### 3.2 Write the configuration

The service runs as uid `65532`. The configuration directory and its secret files must be readable by that user and by nobody else: directories `700`, files `600`. Group or other bits on a secret file stop the service (`strict_permissions: true`).

The binary is inside the image, so you need no FeatherAuth binary on the host. A one-off container of the image writes the examples and the keys. It runs as the service's user, with no network, a read-only root, and the directory mounted **read-write**; only these one-off containers mount it read-write, while the running service mounts it read-only. This is the supported way on a host that has only Docker, for the first setup and for every later key (7.6, 8). "No binary on the host" covers the configuration and the keys only: the compose files, `Caddyfile.example` and `backup-offsite.sh` still come from the checkout of the repository (3.1). Define `run` once and run the commands of this section and of 3.3 to 3.6 **in the same shell**: the later `run config check` steps use the `IMG` variable and the `run` function defined here. In a new shell, define both again.

```bash
IMG=ghcr.io/yyudhistira/featherauth:vX.Y.Z
sudo install -d -o 65532 -g 65532 -m 700 /opt/featherauth/config
run() { sudo docker run --rm --user 65532:65532 --network none --read-only -v /opt/featherauth/config:/etc/featherauth "$IMG" "$@"; }

run config init /etc/featherauth
run keys generate /etc/featherauth/secrets/main/signing-1.pem
run keys generate --type encryption /etc/featherauth/secrets/encryption_key
sudo mv /opt/featherauth/config/realms/example.yaml /opt/featherauth/config/realms/main.yaml
```

What these write:

- `config init` writes `server.yaml`, `database.yaml`, `realms/example.yaml`, `locales/en.yaml.example` and `server.tls.yaml.example`, each with a comment on every option. It refuses to run when any of them exists already.
- `keys generate` writes a key owned by uid `65532` with mode `0600`, creating missing directories, and never overwrites a file.
- For a realm with `tokens.algorithm: ES256`, also run `run keys generate --type ec /etc/featherauth/secrets/main/signing-ec-1.pem`.

The example realm file names its key `secrets/example/signing-2026-10.pem`, a file that does not exist. You therefore point its `keys` entry at the key you generated (below). Until then `config check` reports the missing key file.

Edit the files as root (`sudo nano` or `sudo -e`). Only a few lines need to change:

- `server.yaml`: `public_url: https://auth.example.com`. Leave `listen: ":8080"`. `trusted_proxies` is set in 3.4.
- `realms/main.yaml`:
  - `name: main` (it must equal the file name) and `display_name`.
  - `keys`: replace the example entry (`kid: example-2026-10`, `file: secrets/example/signing-2026-10.pem`) with `{ kid: main-1, file: secrets/main/signing-1.pem, state: active }`, the key you generated. The `kid` must be unique across realms.
  - `login_page.contact`: an email address or `https` URL, shown on error pages (required once Facebook is on).
  - `providers`: section 4.
  - `clients`: delete the examples; section 5.

Then set the owner and modes. Use `find`, not `chmod -R`, so that directories keep their `x` bit:

```bash
sudo chown -R 65532:65532 /opt/featherauth/config
sudo find /opt/featherauth/config -type d -exec chmod 700 {} \;
sudo find /opt/featherauth/config -type f -exec chmod 600 {} \;
```

Check it offline. Inside the container the directory is `/etc/featherauth`, so pass that path:

```bash
run config check /etc/featherauth
```

`config check` prints `ok`, or one line per finding as `file:line: severity: field: reason`. It exits `1` on any error and `0` when there are only warnings.

### 3.3 Start it

```bash
cd /opt/featherauth
sudo docker compose up -d
sudo docker compose ps                     # wait until the state shows "healthy"
curl -sS http://127.0.0.1:8080/readyz      # ok
```

The image's health check runs `featherauth healthcheck` every 10 seconds, with a 5-second timeout and a 5-second start period, and reports the container unhealthy after 6 failures in a row.

### 3.4 Put a proxy in front: Caddy

**Caddy in Docker** (a host with no proxy yet):

```bash
cd /opt/featherauth
sudo cp Caddyfile.example Caddyfile
# edit Caddyfile: replace auth.example.com with your host name,
# and use the line "reverse_proxy featherauth:8080 {" instead of 127.0.0.1:8080
sudo sed -i 's/^COMPOSE_FILE=.*/COMPOSE_FILE=compose.yaml:compose.caddy.yaml/' .env
sudo docker compose up -d
```

- Create the `Caddyfile` before Caddy starts: if it is missing, Docker creates a directory of that name in its place.
- Caddy gets and renews a Let's Encrypt certificate by itself and redirects HTTP to HTTPS. Keep its `caddy_data` volume, which holds the certificates.
- Leave Caddy's admin API on (do not add `admin off`): its health check uses it.
- `lb_try_duration 10s` makes Caddy hold requests for up to 10 seconds while FeatherAuth restarts, so a restart fails no request.
- Keep the `transport http { keepalive off }` block inside `reverse_proxy`: it is required. It makes Caddy open a new connection to FeatherAuth for every request. Without it, Caddy may send a request on an idle connection that the stopping service is closing; it cannot safely send a `POST` (such as a token refresh) a second time, so that request fails with `502` instead of being held.
- For a bought certificate, enable the `tls <cert> <key>` line and reload Caddy after replacing the files.

FeatherAuth believes the client address in `X-Forwarded-For` only from addresses in `trusted_proxies`. Put the compose network's range in `server.yaml`.

The network is named `<project>_default`. The project is the name of the directory that holds the compose files (`featherauth` for `/opt/featherauth`), unless you set `COMPOSE_PROJECT_NAME`. `sudo docker network ls` lists the networks.

```bash
sudo docker network inspect featherauth_default --format '{{(index .IPAM.Config 0).Subnet}}'
# server.yaml:  trusted_proxies: ["172.18.0.0/16"]   (use the printed range)
```

`trusted_proxies` is a live option: the service reloads it by itself. Without it, the rate limit counts every user as the proxy's address.

**Caddy (or another proxy) on the host:** keep the upstream `127.0.0.1:8080` and `COMPOSE_FILE=compose.yaml`. A proxy on the host reaches the container from the Docker network's gateway, so list the gateway as a `/32` (or the network range):

```bash
sudo docker network inspect featherauth_default --format '{{(index .IPAM.Config 0).Gateway}}'
```

### 3.5 Or nginx on the host

`deploy/nginx.example.conf` holds a `log_format` and two server blocks:

- port 80: the ACME challenge and a `301` to HTTPS;
- port 443: forwarding to `127.0.0.1:8080` with `Host`, `X-Forwarded-For` and `X-Forwarded-Proto`.

Keep `COMPOSE_FILE=compose.yaml`.

1. Copy the `log_format` line and the **port 80 block** to `/etc/nginx/conf.d/featherauth.conf`, with your host name, and make sure `/var/www` exists. Then run `sudo nginx -t && sudo systemctl reload nginx`.
2. Get the certificate: `sudo certbot certonly --webroot -w /var/www -d auth.example.com --deploy-hook "nginx -s reload"`. Renewal runs from Certbot's timer; check it with `sudo certbot renew --dry-run`.
3. Add the **port 443 block** and reload nginx again.
4. Set `trusted_proxies` to the Docker gateway (see 3.4).

The example's access log records `$uri`, not `$request`, so the query strings that carry codes and tokens never reach it. Its error log is set to level `crit`, because nginx's error log would otherwise record the full URL when the upstream is down. Keep both settings.

The example opens a new connection to FeatherAuth for every request (nginx's default when no `upstream` block with `keepalive` is added); keep it that way.

nginx cannot hold requests during a restart: it answers `502` for the second or so the service is down. Apps that retry a failed refresh hide this. With nginx older than 1.25.1, `listen 443 ssl http2;` is the form it accepts; newer versions also accept `http2 on;`.

### 3.6 Or let FeatherAuth end TLS itself

For a host with no proxy at all, use `compose.tls.yaml` **in place of** `compose.yaml`.

1. Copy the TLS example over `server.yaml`. This replaces the `server.yaml` you edited in 3.2, so set `public_url` again afterwards:

   ```bash
   sudo cp /opt/featherauth/config/server.tls.yaml.example /opt/featherauth/config/server.yaml
   sudo nano /opt/featherauth/config/server.yaml          # public_url: https://auth.example.com
   ```

2. Put your certificate chain at `config/secrets/tls_cert.pem` and its private key at `config/secrets/tls_key.pem`. Both are checked like secret files, so both need owner `65532` and mode `600`:

   ```bash
   sudo chown -R 65532:65532 /opt/featherauth/config
   sudo find /opt/featherauth/config -type d -exec chmod 700 {} \;
   sudo find /opt/featherauth/config -type f -exec chmod 600 {} \;
   ```

3. Run `config check` (3.2), switch the compose file and start:

   ```bash
   cd /opt/featherauth
   sudo sed -i 's/^COMPOSE_FILE=.*/COMPOSE_FILE=compose.tls.yaml/' .env
   sudo docker compose up -d
   ```

How it behaves:

- With `tls.mode: files` the service serves HTTPS on `tls.listen` (`:8443` in the example, published as the host's port 443).
- It answers plain HTTP on `tls.http_listen` (`:8081`, published as port 80) with a `301` to HTTPS.
- It keeps `listen` on a loopback address (`127.0.0.1:8080`) for `/healthz` and `/readyz` only. That port is not published; `featherauth healthcheck` calls it inside the container.
- It accepts TLS 1.2 and newer.
- A replaced certificate pair is loaded without a restart, on a file change or `SIGHUP`. A broken pair is logged and the old one keeps serving.
- `trusted_proxies` must be empty in this mode.

There is no built-in ACME: renew the files yourself (for example with Certbot in standalone or DNS mode).

### 3.7 Check it

```bash
curl -sI http://auth.example.com/healthz                               # 301 to https
curl -sS https://auth.example.com/healthz                              # ok
curl -sS https://auth.example.com/main/.well-known/openid-configuration | head -c 300   # issuer https://auth.example.com/main
```

## 4. Set up the providers

Create every provider app under **your own** accounts, so that the client ids stay yours. Each provider redirects back to one URL per realm:

```text
https://auth.example.com/<realm>/callback/<provider key>
```

The provider key is the name under `providers:` in the realm file (`google`, `apple`, `github`, `facebook`, or your own name for a generic OIDC provider).

Each client secret goes in its own file under `secrets/`, one line, mode `600`, owned by `65532`. Write it with an editor (`sudo nano`), not with `echo`, so it stays out of your shell history. In the realm file, set `enabled: true` (the example has `false` everywhere; with no provider enabled the page says "No sign-in method is available right now."). Then set `client_id` and `client_secret_file`.

After each change, fix the modes (3.2) and run `config check`. The service reloads the realm by itself; to be sure, send `SIGHUP` with `sudo docker compose kill -s HUP featherauth`.

### Google

1. In the Google Cloud console, create an OAuth client of type **Web application**.
2. Add the authorized redirect URI `https://auth.example.com/main/callback/google`.
3. Realm file:

   ```yaml
   providers:
     google:
       enabled: true
       client_id: 1234.apps.googleusercontent.com
       client_secret_file: secrets/main/google_secret
   ```

- To accept only one Google Workspace domain, set `hosted_domain: example.com`. It is enforced on the ID token's `hd` claim.
- Google's Cross-Account Protection events are covered in section 7.9.

### Apple

Needs a paid Apple Developer Program membership.

1. In Certificates, Identifiers & Profiles, create (or reuse) an **App ID** with the Sign in with Apple capability. This is the primary App ID.
2. Create a **Services ID**, for example `com.example.signin`. Its identifier is the provider's `client_id` (not your app's bundle id). Enable Sign in with Apple and configure it:
   - primary App ID: the one of step 1;
   - domain: `auth.example.com`;
   - return URL: `https://auth.example.com/main/callback/apple`.
3. On the primary App ID's Capabilities tab, edit Sign in with Apple, choose "Enable as a primary App ID", and set the **Server to Server Notification Endpoint** to `https://auth.example.com/main/events/apple`. Apple takes one endpoint per primary App ID, so one realm receives the events of the apps grouped under it.
4. Create a **key** with Sign in with Apple enabled for that App ID. Download the `.p8` file (only possible once) and note its Key ID. Your Team ID is the App ID Prefix shown on any App ID page.
5. Copy the `.p8` to `config/secrets/main/apple_key.p8` (owner `65532`, mode `600`) and keep the original in a password manager.
6. Realm file:

   ```yaml
   providers:
     apple:
       enabled: true
       client_id: com.example.signin        # the Services ID
       client_secret_file: ""
       team_id: ABCDE12345
       key_id: ABC123DEFG
       private_key_file: secrets/main/apple_key.p8
       store_refresh_token: true             # needs secrets.encryption_key_files
       notification_audiences: [com.example.app]   # the primary App ID's bundle id
   ```

Things to know about Apple:

- Apple needs an `https` return URL with a domain name, so Apple sign-in does not work in local development over plain HTTP.
- Apple sends the user's name only at the first authorization; FeatherAuth stores it then.
- `scopes` for Apple accepts only `name` and `email`, each at most once, in any order; `[]` asks for neither. The default is `[name, email]`. Any other value is refused at load, at reload and by `config check` (`Apple supports only the scopes name and email`), so a realm file that lists another value must be fixed before it loads. Without `email`, Apple sends no email: the user then has none in FeatherAuth, no email claims, and is never linked to another account by email.
- To see a "first" sign-in again, remove the app at appleid.apple.com, Sign-In and Security, Sign in with Apple.
- Users may hide their email behind Apple's private relay. A person who signs in with Apple and with another provider then gets two accounts (section 7.7 shows how to join them).
- On iOS the user sees Apple's web sign-in in the browser tab, not the system's Sign in with Apple sheet.
- App Store Review Guideline 4.8: an iOS app that offers Google, Facebook or GitHub sign-in must also offer Sign in with Apple. `config check` warns when a realm has a public client with a custom-scheme redirect, one of those providers on, and Apple off or hidden.

### GitHub

1. GitHub, Settings, Developer settings, OAuth Apps, New OAuth App. Set the homepage to `https://auth.example.com` and the authorization callback URL to `https://auth.example.com/main/callback/github`.
2. Copy the Client ID, generate a client secret and write it to `secrets/main/github_secret`.
3. Realm file:

   ```yaml
   providers:
     github:
       enabled: true
       client_id: Iv1.0123456789abcdef
       client_secret_file: secrets/main/github_secret
   ```

By default, sign-in needs a verified primary email at GitHub (`require_verified_email: true`). `allow_signup: false` admits existing GitHub accounts only.

### Facebook (Meta)

1. On developers.facebook.com, create an app with the use case "authenticate users with Facebook Login". Add Facebook Login for the Web.
2. Under Valid OAuth Redirect URIs, add `https://auth.example.com/main/callback/facebook`.
3. Under App settings, Basic, set:
   - App Domains: `auth.example.com`;
   - a Privacy Policy URL;
   - the data deletion instructions URL: `https://auth.example.com/main/data-deletion`.

   Meta can also call a data-deletion callback: enter `https://auth.example.com/main/events/facebook` (the provider events path with the Facebook provider's key). FeatherAuth then deletes or unlinks the user and answers with a confirmation code.
4. In Development mode only people with a role on the app can sign in, which is enough for testing. The `email` and `public_profile` permissions need no App Review.
5. Copy the App ID and App Secret (to `secrets/main/facebook_secret`).
6. Realm file:

   ```yaml
   login_page:
     contact: privacy@example.com      # required when Facebook is enabled
   providers:
     facebook:
       enabled: true
       client_id: "1234567890"
       client_secret_file: secrets/main/facebook_secret
   ```

Facebook does not say whether an email is verified, so FeatherAuth never trusts or links on a Facebook email. Every Graph API call carries `appsecret_proof`, so you can turn on "Require App Secret" in the Meta app. Meta retires Graph API versions: check `graph_version` (default `v26.0`) once a year.

### Any other OpenID Connect provider

Any provider with a single issuer works from configuration alone. The example below uses GitLab.com: create an application with the redirect URI `https://auth.example.com/main/callback/gitlab`, Confidential on, and the scopes `openid`, `profile` and `email`.

```yaml
providers:
  gitlab:                    # your own key; it is the {provider} in the callback URL
    type: oidc
    enabled: true
    display_name: GitLab
    client_id: <application id>
    client_secret_file: secrets/main/gitlab_secret
    issuer: https://gitlab.com
    scopes: [openid, email, profile]
    trust_email: false
```

Delete the example's `endpoints:` block so that discovery from `issuer` is used. Multi-tenant issuers (such as Microsoft Entra's `common` endpoint) are not supported. `trust_email` defaults to `false` for generic providers: set it to `true` only if you trust that provider's `email_verified`.

## 5. Add a client and test a sign-in

A **client** is one app. Add it under `clients:` in the realm file:

```yaml
clients:
  web:                                   # the client_id
    name: Web app
    type: public                         # browser and mobile apps cannot keep a secret
    redirect_uris: [https://app.example.com/callback]
    web_origins: [https://app.example.com]   # for an SPA that calls /token from JavaScript
```

Redirect URIs must match exactly: no wildcards, no fragments, and plain `http` only on `127.0.0.1` or `[::1]` (use `127.0.0.1`, not `localhost`).

Test a sign-in with `curl` and a browser. You need `curl`, `jq` and `openssl`. Run **all** the lines below in **one** shell, because the later commands use the variables of the first ones:

```bash
H=https://auth.example.com R=main C=web U=https://app.example.com/callback P=google
UE=$(printf %s "$U" | jq -sRr @uri)          # the redirect URI, URL-encoded
V=$(openssl rand -base64 48 | tr -d '=+/' | cut -c1-64)
CH=$(printf %s "$V" | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')
echo "$H/$R/authorize?response_type=code&client_id=$C&redirect_uri=$UE&scope=openid&state=s1&nonce=n1&code_challenge=$CH&code_challenge_method=S256&provider=$P"
```

1. Open the printed URL in a browser and sign in.
2. The browser is sent to `https://app.example.com/callback?code=...&state=s1&iss=...`. If no app runs at that address yet, the browser shows an error such as "site can't be reached"; that is expected. Read the `code` from the address bar and copy it.
3. Within 60 seconds, from a directory you can write to, in the same shell:

```bash
CODE=<paste>
curl -sS $H/$R/token -d grant_type=authorization_code -d client_id=$C --data-urlencode code=$CODE \
  --data-urlencode redirect_uri=$U -d code_verifier=$V -o tok.json
jq 'keys' tok.json
curl -sS -H "Authorization: Bearer $(jq -r .access_token tok.json)" $H/$R/userinfo | jq
curl -sS $H/$R/token -d grant_type=refresh_token -d client_id=$C --data-urlencode refresh_token="$(jq -r .refresh_token tok.json)" | jq 'keys'
rm tok.json
```

A code works once. For a new attempt, run the first block again (a new verifier) and sign in again.

Leave out `provider=` to see the chooser page.

## 6. Integrate an app or an API

Use any standard OIDC client library and point it at the discovery document. A complete, runnable example of a single-page app (React, Vite and the library oidc-client-ts) is in [examples/web-app/](../examples/web-app/): sign-in with PKCE, an ID token signature check with the jose library (with 300 seconds of clock tolerance), the user's claims and a userinfo call of its own once per sign-in and once per refresh, refresh with the refresh token on a button, and RP-initiated logout, with tokens kept in memory only. Its client entry, the public client `example-web`, ships as `examples/web-app/example-web-client.yaml`: copy its `example-web:` block under `clients:` in your realm file and reload. The app runs at `http://127.0.0.1:5173`; its own README gives the commands. The flows of the other kinds of app below are the same protocol with a different client type. The discovery document is at:

```text
https://auth.example.com/<realm>/.well-known/openid-configuration
```

Discovery lists every endpoint. The defaults are below; each path can be changed (section 13.2), and discovery always shows the configured one:

| Endpoint | Default path |
| --- | --- |
| Authorize | `/{realm}/authorize` (GET or form POST) |
| Token | `/{realm}/token` (POST, form body only) |
| Userinfo | `/{realm}/userinfo` (GET or POST) |
| JWKS | `/{realm}/jwks.json` |
| Logout | `/{realm}/logout` (GET or form POST) |
| Revocation | `/{realm}/revoke` (POST) |
| Sessions of the user | `/{realm}/sessions` (GET) |
| Account deletion | `/{realm}/account` (DELETE) |
| Health | `/healthz`, `/readyz` |

Rules for every app:

- Always send `scope=openid`, `state`, `nonce` and a PKCE challenge with `code_challenge_method=S256`. `plain` is refused.
- To skip the chooser, add `provider=<provider key>` (the parameter names are set by `login.provider_hint_params`).
- `prompt=login`, `prompt=select_account`, `prompt=consent`, `max_age` and `login_hint` are passed on to the provider where it has an equivalent. Without them, a user cannot switch accounts after logout, because the browser keeps the provider's session.
- Treat a `503` or `temporarily_unavailable` as "try again", not as "signed out". FeatherAuth never answers a transient failure with `invalid_grant` or `invalid_token`.

### Single-page web app

- `type: public`, `redirect_uris` with your `https` callback, `web_origins` with your origin.
- For local development the app may run on plain `http` at `127.0.0.1` (not `localhost`, which is refused), for example `http://127.0.0.1:5173`. Register that callback, the post-logout URL and the origin `http://127.0.0.1:5173` in `web_origins`, as the example's client entry does. A public client's loopback redirect URI may use any port; a post-logout return URL must match a registered one exactly.
- `response_mode` is `query` by default; `fragment` and `form_post` are available.
- Keep tokens in memory. The refresh token always rotates, so store the new one after each refresh.
- With `sso.enabled` on the realm, silent renewal with `prompt=none` works as a top-level redirect (not in a hidden iframe: the pages forbid framing).

### Mobile app (iOS, Android, React Native, Flutter)

- `type: public`. Use the system browser session (ASWebAuthenticationSession on iOS, Custom Tabs on Android) through a library such as AppAuth, or its React Native or Flutter wrapper.
- Prefer an app-claimed HTTPS link as the redirect URI; a custom scheme (`com.example.app:/callback`) works too, but another app can claim the same scheme, and only PKCE then protects the code. A loopback redirect (`http://127.0.0.1:{port}/callback`) may use any port.
- Store the refresh token in the iOS Keychain or the Android Keystore.
- To stay signed in for a long time, give the mobile client long lifetimes:

  ```yaml
  clients:
    mobile:
      type: public
      redirect_uris: [com.example.app:/callback]
      refresh_idle_lifetime: 17520h    # 2 years unused
      session_max_lifetime: 0          # no absolute limit
  ```

- For stronger protection of long-lived tokens, set `dpop: allowed` or `dpop: required` on the client. The app then binds its tokens to a key that never leaves the device (DPoP, RFC 9449); proofs use `ES256` or `RS256`.
- App stores require in-app account deletion: set `allow_account_delete: true` on the client and call `DELETE /account` with an access token from a recent sign-in. A sign-in older than `tokens.account_delete_max_auth_age` (10 minutes) gets `401` with `insufficient_user_authentication`; sign the user in again with `prompt=login` or `max_age` and retry. Also ask the user to confirm in your own interface, because some providers let an unlocked browser pass without a new password.
- "Sign out of all devices": set `allow_session_management: true` and `POST` to the logout endpoint with the access token and `all_sessions=true`. `GET /sessions` lists the user's sessions, and `session=<id>` ends one of them.

### Server-rendered app or backend for a frontend

- `type: confidential` with `client_secret_file`. Use a secret of at least 32 characters: `openssl rand -base64 48 > <file>` (as `umask 077`).
- The client authenticates at `/token` with `client_secret_basic` (an `Authorization: Basic` header) or `client_secret_post` (form fields), never both.
- PKCE is still required.
- Keep tokens on the server.
- `refresh_token_rotation: false` is possible for a confidential client only (weaker: the same refresh token is returned each time).
- To learn on your server that a session ended, set `backchannel_logout_uri` to an `https` URL. FeatherAuth then `POST`s a form with one field `logout_token`: a JWT with `typ: logout+jwt`, signed `RS256`, carrying `sid` and `sub`. Answer `200` or `204`. Deliveries are retried after 1 minute, 5 minutes, 30 minutes and 2 hours, and may arrive more than once, so act by `sid`. Notices are posted one after another, at most 4 per round with a 5-second limit per call, so a receiver that hangs delays other clients' notices by at most 20 seconds per round; a slow receiver never causes another client's notice to be dropped.

### An API that verifies tokens

Verify every access token offline:

1. Fetch the realm's JWKS (`jwks_uri` in discovery) and cache it. It is served with `Cache-Control: public, max-age=300`, so refetch at most every 5 minutes, and at once when a token names an unknown `kid`.
2. Check the header `typ: at+jwt` (this refuses ID tokens and JWT refresh tokens), the signature with the key of the token's `kid`, and the `alg` of the realm (`RS256` by default, or `ES256`).
3. Check `iss` equals the realm's issuer (for example `https://auth.example.com/main`, no trailing slash), `exp` is in the future, and `aud` is your API.

By default an access token's `aud` is the client id. Set the client's `audience` to your API's identifier so that the API can check `aud` meaningfully.

After a logout or a user deletion, an access token stays valid until it expires (15 minutes by default). For an immediate check, call `/userinfo` with the token: it looks the user up and refuses a deleted or disabled user at once. A bound (DPoP) token carries `cnf.jkt`; your API decides whether it checks it.

User claims in tokens and userinfo are chosen per realm by `user_data.claims` (default `name`, `email`, `email_verified`, `preferred_username`). To keep emails and names out of access tokens (they reach every API and its logs), set `user_data.access_token_claims: []` or a shorter list. The claim `allowed-origins` (the client's `web_origins`) can be added for APIs that build their CORS list from the token.

## 7. Run it day to day

Every `docker compose` command in sections 7 to 10 and 12 runs in `/opt/featherauth`, where `.env` names the image tag, the configuration directory and the compose files (`COMPOSE_FILE`). The stack of several instances (section 11) has its own commands.

### 7.1 Configuration reload

The service watches its configuration directory and also reloads on `SIGHUP`:

```bash
sudo docker compose kill -s HUP featherauth
```

- A reload validates the new configuration first. If it is invalid, the error is logged with file, line and field, and the last good configuration keeps serving. Each realm reloads on its own, so a broken realm file never affects another.
- Changes apply to the next request; requests in flight keep the old configuration. Tokens already issued keep their claims.
- Removing a client or disabling a realm fails new sign-ins at once and refreshes at their next use.
- Files in `realms/` whose name starts with a dot (editor swap files) are ignored.
- Options marked `restart` (section 13), all of `database.yaml`, and the encryption and Postgres password files are not changed by a reload. The log then says `restart required` with the option names.

### 7.2 Health

| Check | Answers |
| --- | --- |
| `GET /healthz` | `200` `ok` while the process runs |
| `GET /readyz` | `200` `ok` when the database answers; `503` `not ready` when it does not, and from the moment shutdown starts |
| `featherauth healthcheck` | Calls `/readyz` on the listen address with a 3-second timeout; prints `ready` and exits `0`, or exits `1` |

The image's own health check (the `HEALTHCHECK` of `deploy/Dockerfile`) runs `featherauth healthcheck` every 10 seconds, with a 5-second timeout and a 5-second start period, and marks the container unhealthy after 6 failures in a row.

On `SIGTERM` the service answers `/readyz` with `503` at once, stops taking connections, lets requests in flight finish for up to 30 seconds, and exits `0`. The shipped compose files set `stop_grace_period: 35s` on the FeatherAuth service, so `docker compose stop`, `restart` and `up -d` wait for this drain; without it Docker kills the process 10 seconds after `SIGTERM`. Keep it in your own compose files, and pass `--timeout 35` to a plain `docker stop`.

### 7.3 Logs

Logs are JSON lines on standard output (`sudo docker compose logs featherauth`). The main lines are:

- `request`: one per request, with `method`, `path`, `status`, `duration_ms`, `realm` and `client_ip`;
- `configuration loaded`, with `realm_count`;
- `configuration not applied; the last good configuration keeps serving`, at error level;
- `restart required`, with `options`;
- audit lines, with `audit: true`.

Set the level with `log_level` (`debug`, `info`, `warn`, `error`; a live option). At every level, logs never hold tokens, codes, `state`, `nonce`, client secrets, cookies or emails. URLs are logged without their query string. Users appear by their user id.

Warnings worth watching:

- `session.reuse_detected`: a refresh token or code was used twice, which is a sign of theft.
- Failed client authentication of a confidential client.
- A full rate-limit table.
- Back-channel deliveries that gave up.
- A provider that cannot be reached.

There is no `/metrics` endpoint; the request lines are the measurement.

### 7.4 Audit records

Every change to users and sessions is written to the `audit_events` table and to the log as an audit line. Each record has the actor (`admin` for the CLI, `system`, or `provider:<key>`), the action, the user id and details that never hold secrets or emails. The actions are:

- `user.update` (with the changed field names), `user.disable`, `user.enable`, `user.delete`, `user.import`;
- `identity.link`, `identity.unlink`, `identity.auto_link`, `identity.consent_revoked`, `identity.sessions_revoked`;
- `user.sessions_revoked`, `realm.sessions_revoked`;
- `keys.sealed_listed`, `identity.token_resealed`, `identity.token_cleared` (the key commands of 8.2);
- `session.reuse_detected`.

Audit records are kept; they are never pruned.

### 7.5 Backups (SQLite)

- The service writes a consistent snapshot every day at `backup.at` (default `"03:00"`, server local time) to `backup.directory` (default `/var/backups/featherauth`, the `backups` volume), named `featherauth-YYYYMMDD-HHMM.db`, and keeps the newest `backup.keep` (default 7).
- A failed snapshot (a full disk, for example) is logged at error level, leaves the older ones alone, and is tried again the next day; it never stops the service.
- Take one on demand, for example before an upgrade: `sudo docker compose exec featherauth /featherauth backup` prints `wrote <path>`.

Never copy the live database file with `cp`: it is not safe while the service runs.

**Off the server, encrypted.** `backup-offsite.sh` (copied from `deploy/ops/` to `/opt/featherauth/` in 3.1) encrypts the newest snapshot with [age](https://age-encryption.org) and copies it with `rclone` or `rsync`. With `CONFIG_DIR` set, it also copies an encrypted tar of the configuration directory, which holds your keys. Only the age **public** key is on the server; keep the private key elsewhere. Run it from the host's cron as root after the daily snapshot:

```bash
30 3 * * * AGE_RECIPIENT=age1... CONFIG_DIR=/opt/featherauth/config BACKUP_DIR=/var/lib/docker/volumes/featherauth_backups/_data /opt/featherauth/backup-offsite.sh rsync backup@vault.example.com:featherauth/
```

- Usage: `backup-offsite.sh rclone|rsync <destination>`.
  - `rsync`: the destination is a directory, and a trailing slash is added.
  - `rclone`: a remote path such as `remote:featherauth`.
- Find `BACKUP_DIR` with `docker volume inspect featherauth_backups --format '{{ .Mountpoint }}'` (the prefix is the compose project name, which is the directory name).
- The script only adds files. Clean up old copies at the destination yourself.

**Restore (SQLite).** Do this on a test host after any upgrade that changes the schema, so that you know it works.

```bash
age -d -i <private key> -o featherauth.db featherauth-YYYYMMDD-HHMM.db.age
sudo docker compose stop featherauth
DATA=$(sudo docker volume inspect featherauth_data --format '{{ .Mountpoint }}')
sudo rm -f "$DATA/featherauth.db-wal" "$DATA/featherauth.db-shm"
sudo cp featherauth.db "$DATA/featherauth.db" && sudo chown 65532:65532 "$DATA/featherauth.db" && sudo chmod 600 "$DATA/featherauth.db"
sudo docker compose up -d
```

The configuration copy unpacks with `age -d -i <private key> <file>.tar.age | tar -x`. Postgres backups are in section 10.4.

### 7.6 Signing keys and planned rotation

Each realm has its own signing keys in its file. Every key is published in the realm's JWKS:

- `state: active` signs new tokens. A realm has exactly one active RSA key (it signs ID tokens), and with `tokens.algorithm: ES256` also exactly one active EC P-256 key.
- `state: verify_only` is only published.

Rotate in two steps, so that no API sees a token signed by a key it has not cached:

1. Generate a new key (`run keys generate ...`, the one-off container of 3.2) and add it as `verify_only` with a new `kid`. Reload, then wait at least 5 minutes (the JWKS cache time).
2. Make the new key `active` and the old one `verify_only`. Reload. Remove the old key once the longest token it signed has expired (the access token lifetime).

You can bring an existing key: keep its `kid`, so that tokens it signed still verify. For a key that may have leaked, see section 8.

**Encryption key.** `secrets.encryption_key_files` in `server.yaml` lists the keys that encrypt the Apple refresh tokens FeatherAuth stores (so that account deletion can revoke them at Apple). Each file holds 32 random bytes as base64 (`keys generate --type encryption`). The first key encrypts and every listed key decrypts. To rotate, add a new first file and restart; then `keys sealed` shows which stored tokens the old key still seals, `keys reseal` moves them to the new key, and the old file can be removed once `keys sealed` prints `[]` in every realm (8.2 gives the commands). A key is needed only when an enabled provider has `store_refresh_token: true` (Apple's default).

### 7.7 Users

The user commands open the database directly, so run them where the data is. On Docker:

```bash
sudo docker compose exec featherauth /featherauth user get main <user id>
```

| Command | Does |
| --- | --- |
| `user get <realm> <id>` | JSON with `id`, `email`, `email_verified`, `name`, `disabled`, `created_at`, `updated_at`, `identities` (`provider`, `subject`) |
| `user list <realm> --email <address>` | Users with that email, ignoring case and spaces |
| `user update <realm> <id> [--name <text>] [--email <address>] [--email-verified true\|false] [--disabled true\|false]` | Changes fields. A new email clears `email_verified` unless `--email-verified true` is given |
| `user disable <realm> <id>` / `user enable <realm> <id>` | Disabling ends every session and refuses new sign-ins at once; enabling does not bring sessions back |
| `user delete <realm> <id> [--skip-revocation]` | Deletes the user, identities and sessions, and revokes a stored Apple token at Apple. If the configuration or its encryption key cannot be used, it refuses; `--skip-revocation` deletes without revoking |
| `user link <realm> <id> <provider> <subject>` | Joins a provider identity to a user (for example two accounts of one person). Refused when the identity is linked already: unlink it first |
| `user unlink <realm> <id> <provider> <subject>` | Removes an identity |

The commands may run while the service runs, and changes apply at once. Each change prints its audit line on standard error. Exit codes for every command: `0` success, `1` failure (not found, conflict, invalid value), `2` usage error.

**Import users** from another system:

```bash
sudo docker compose exec -T featherauth /featherauth import /dev/stdin --realm main < users.json
```

The file is a JSON list of `{id?, email, email_verified, name, disabled, identities: [{provider, subject}]}`.

- Ids are kept when given, so each user's `sub` survives the move. A row without `id` gets a new one in the realm's `user_data.id_format`.
- The whole file is validated first, and nothing is written if it fails.
- Running it twice is safe: existing users are left as they are.
- Users without identities are skipped unless `--include-without-identity` is given. Such users are linked at their first social sign-in only by a verified email on an auto-link domain.
- It prints `{created, existing, skipped}`.

### 7.8 Sessions

| Command | Does |
| --- | --- |
| `session list <realm> <user id>` | JSON list of active sessions: `session_id`, `client_id`, `started_at`, `auth_time`, `last_used_at`, `expires_at` |
| `session revoke <realm> <user id>` | Ends every session of the user |
| `session revoke <realm> <user id> --session <id>` | Ends one session |
| `session revoke <realm> --all` | Ends every session of the realm (for a leaked signing key) |

Each run that ended a session writes one audit record.

### 7.9 Provider account events

- **Apple** notifies the endpoint you set in 4, Apple step 3, when a user stops using Sign in with Apple or deletes the Apple account:
  - `consent-revoked` ends the user's sessions;
  - `account-delete` deletes the user (or unlinks Apple if the user has other identities);
  - email-forwarding changes are only logged.
- **Meta** calls the data-deletion callback (4, Facebook step 3).
- **Google Cross-Account Protection** sends security events to `https://auth.example.com/<realm>/events/<google provider key>`. Register the receiver once through Google's RISC API. You need a service account with the RISC Configuration Admin role (`roles/riscconfigs.admin`) in the project of the OAuth client, and a bearer token made from its key (`$RISC_TOKEN`, valid one hour):

  ```sh
  curl -sS -X POST https://risc.googleapis.com/v1beta/stream:update \
    -H "Authorization: Bearer $RISC_TOKEN" -H "Content-Type: application/json" \
    --data '{
      "delivery": {
        "delivery_method": "https://schemas.openid.net/secevent/risc/delivery-method/push",
        "url": "https://auth.example.com/main/events/google"
      },
      "events_requested": [
        "https://schemas.openid.net/secevent/risc/event-type/sessions-revoked",
        "https://schemas.openid.net/secevent/oauth/event-type/tokens-revoked",
        "https://schemas.openid.net/secevent/risc/event-type/account-disabled",
        "https://schemas.openid.net/secevent/oauth/event-type/token-revoked",
        "https://schemas.openid.net/secevent/risc/event-type/account-enabled",
        "https://schemas.openid.net/secevent/risc/event-type/account-credential-change-required",
        "https://schemas.openid.net/secevent/risc/event-type/verification"
      ]
    }'
  # Ask for a verification event; the log shows it with verification_state.
  curl -sS -X POST https://risc.googleapis.com/v1beta/stream:verify \
    -H "Authorization: Bearer $RISC_TOKEN" -H "Content-Type: application/json" \
    --data '{"state": "check-1"}'
  ```

  - A revoking event (`sessions-revoked`, `tokens-revoked`, `account-disabled`) ends the user's sessions; the user stays.
  - Google sends no events for Google Workspace users.
  - The token's issuer, and the issuer of each event's subject, are accepted when they equal the issuer of Google's configuration or differ from it by one trailing slash (Google's documents spell it both ways); nothing else is relaxed.
  - Deliveries count against the rate limit like any caller.

The event endpoints answer:

| Answer | Meaning |
| --- | --- |
| `200` (Google: `202`) | Handled, unknown or repeated |
| `400` | Fails verification |
| `503` | The provider's keys cannot be fetched; the provider retries |
| `500` | A database failure; the provider retries |

## 8. Emergency key rotation

Use this when a secret may have leaked and the old one must stop working now: a realm's signing key, the encryption key, or a confidential client's secret. For a planned rotation use 7.6, which causes no failures.

Before you start:

- `<config>` is the configuration directory on the host (`/opt/featherauth/config` in this guide). Write key files and edit the configuration there, as root.
- Generate keys with the one-off container `run` of 3.2 (define `IMG` and `run` in your shell first): it mounts the directory read-write. The running container's mount is read-only.
- Commands that touch data (`session revoke`, `user unlink`, `user delete`, `keys sealed`, `keys reseal`, `keys clear-sealed`) run in the running container: `sudo docker compose exec featherauth /featherauth ...`.
- `config check` runs as in 3.2: `run config check /etc/featherauth`.
- Work through one section in one sitting: the exposed secret stays valid until its step is done.
- Never paste a secret value into a ticket, a chat or a log.

### 8.1 Exposed signing key

1. Make a new key with a `kid` the exposed key never had, with the one-off container of 3.2: `run keys generate /etc/featherauth/secrets/<realm>/signing-new.pem`. For an `ES256` realm, also make `keys generate --type ec /etc/featherauth/secrets/<realm>/signing-ec-new.pem`.
2. In `realms/<realm>.yaml`, in **one** edit, replace the exposed key's entry with the new one as `state: active`.
   - Do not keep the exposed key as `verify_only`: it must stop at once.
   - Keep exactly one active key of each type. A key of the other type that is not exposed stays as it is.
3. Run `config check`. It must exit `0` (`ok`, or warnings only). On an error, fix the file first and do not reload.
4. Reload: `sudo docker compose kill -s HUP featherauth`. The log shows `configuration loaded`. A `configuration not applied` line means the old configuration still runs; fix and reload again.
5. End the sessions a forged token could have made: `session revoke <realm> --all`. It writes one `realm.sessions_revoked` audit line, and users sign in again at their next request.
6. Delete the exposed key file, and replace or delete the off-server configuration archives made before the rotation (they hold the key).
7. Check:
   - `curl https://auth.example.com/<realm>/jwks.json` lists the new key and not the old one;
   - `sudo docker compose exec featherauth /featherauth healthcheck` prints `ready`.

What fails, and for how long, from step 4 on:

| Who | What happens | Until |
| --- | --- | --- |
| FeatherAuth's own endpoints (`/userinfo`, `DELETE /account`, logout by access token) with a token of the exposed key | `401` `invalid_token`, at once | Not applicable: the refusal is immediate |
| RP-initiated logout with an ID token hint of the exposed key | Refused with an error page; nothing ends | Step 5 ends the session |
| Refresh | Keeps working (a refresh token is checked against its stored session), and returns tokens signed by the new key | Step 5; refresh fails from then on |
| New sign-ins | Tokens signed by the new key, which the JWKS publishes at once | Not applicable |
| An API with a cached JWKS | Refuses the new tokens until it fetches the JWKS again, and still accepts tokens of the exposed key, which expire by themselves (15 minutes by default) | At most 300 seconds after its last fetch, if it honours `max-age`; longer if it caches longer. Restarting the API or clearing its key cache ends it sooner |

### 8.2 Exposed encryption key

The encryption key seals the Apple refresh tokens FeatherAuth stores. It is read at start, so this needs a restart. Each sealed value is marked with the id of its key: the first 8 hex characters of the SHA-256 of the key's 32 raw bytes.

1. Make a new key with the one-off container of 3.2: `run keys generate --type encryption /etc/featherauth/secrets/encryption_key_new`.
2. In `server.yaml`, put the new file first and keep the exposed one after it: `encryption_key_files: [secrets/encryption_key_new, secrets/encryption_key]`. The new key seals from now on, and the old one can still open what it sealed.
3. Run `config check` (exit `0`).
4. Restart: `sudo docker compose restart featherauth` (a `SIGHUP` does not read the key again). Then run `healthcheck`.
5. Find the exposed key's id:

   ```bash
   sudo sh -c 'base64 -d /opt/featherauth/config/secrets/encryption_key | sha256sum | cut -c1-8'
   ```

6. In each realm, list the identities whose stored token that key sealed. The list names identities, never tokens, and the command writes a `keys.sealed_listed` audit line:

   ```bash
   sudo docker compose exec featherauth /featherauth keys sealed main --key-id 1a2b3c4d
   # [{"user_id": "...", "provider": "apple", "subject": "..."}, ...]   or [] when none
   ```

7. Remove the exposure from every listed identity, choosing one of two commands:
   - **`keys reseal`** decrypts each token with the exposed key and seals it again under the first (new) key, so the token still works for a later revoke at Apple. It needs the exposed key still listed, and a different first key. It prints `{"resealed": n, "skipped": n, "failed": [...]}` and exits `1` if any value failed.
   - **`keys clear-sealed`** sets each stored token to none. It needs no key, but it revokes nothing at Apple. It prints `{"cleared": n, "skipped": n}`.

   ```bash
   sudo docker compose exec featherauth /featherauth keys reseal main --key-id 1a2b3c4d
   ```

   Each identity changed gets its own audit line (`identity.token_resealed` or `identity.token_cleared`). A token the service replaced or dropped meanwhile, for example after a new Apple sign-in, is counted as `skipped` and left alone. If a run stops part way, run it again: it does the rest.
8. Run `keys sealed` again for every realm. When it prints `[]` everywhere, no stored value needs the exposed key. Then remove the key from `encryption_key_files`, restart, and delete the file and its copies in the off-server archives.

The commands may run while the service runs. Rotation does not protect copies already taken: a copy of the database made before step 7 can still be opened with the exposed key.

### 8.3 Exposed client secret

1. Write a new secret into the client's `client_secret_file`, as one line, mode `600`. For example, with `umask 077`, `openssl rand -base64 48 > <file>` (64 characters; at least 32 are needed to avoid a warning).
2. Run `config check`. It must exit `0` and show no warning about the secret's length.
3. Reload (`SIGHUP`). From then on the old secret is refused with `invalid_client`, at once. The app's code exchanges and refreshes fail until it has the new secret.
4. A secret change ends no session. If the old secret may have been used together with a stolen refresh token, run `session revoke <realm> --all`.

### 8.4 Afterwards

Keep the audit lines of the commands with the incident record. FeatherAuth's logs hold no secrets; if one ever shows up in a log, treat it as a second leak and start again.

## 9. Upgrade and roll back

### 9.1 Versions and what they promise

Releases are tagged `vMAJOR.MINOR.PATCH`, and each publishes the image `ghcr.io/yyudhistira/featherauth:vX.Y.Z`. `featherauth version` prints it. A published tag is never moved or overwritten; a fix is a new version.

FeatherAuth follows semantic versioning:

- A patch release fixes bugs.
- A minor release adds compatible features.
- A **breaking change** comes only in a new minor version while the major version is `0`, and only in a new major version from `1.0.0` on. Breaking changes are:
  - an option, default, endpoint, claim or error code renamed or removed;
  - a stricter validation;
  - a database migration that cannot be undone by running the previous image and restoring a backup.
- The release notes are published with each release on the repository's [Releases page](https://github.com/yyudhistira/featherauth/releases). They list every behaviour change and every breaking change, each with what you must check, and every new option with its default. Read them before you upgrade.

### 9.2 Upgrade

The available versions, each with its release notes, are on the repository's [Releases page](https://github.com/yyudhistira/featherauth/releases). No `latest` tag is published, so an upgrade is always a version you name.

1. Read the release notes of every version between yours and the new one.
2. Check the new configuration rules offline: `sudo docker run --rm --user 65532:65532 -v /opt/featherauth/config:/etc/featherauth:ro ghcr.io/yyudhistira/featherauth:vNEW config check /etc/featherauth`.
3. Take a backup: `sudo docker compose exec featherauth /featherauth backup` (SQLite), or a `pg_dump` (10.4).
4. Set the new tag in `.env` and start it. `COMPOSE_FILE` in `.env` keeps the same overlays:

   ```bash
   cd /opt/featherauth
   sudo sed -i 's/^FEATHERAUTH_TAG=.*/FEATHERAUTH_TAG=vNEW/' .env
   sudo docker compose pull && sudo docker compose up -d
   ```
5. Wait until `sudo docker compose ps` shows `healthy`, and check `curl -sS http://127.0.0.1:8080/readyz`.

At start the new version applies its database migrations by itself. Each migration is meant to take under a second and to stay compatible with the previous version, so the previous version still runs on the migrated database. With one instance the service is unavailable for a few seconds: Caddy holds requests during the gap, and nginx answers `502`. With several instances on Postgres a rolling deploy has no gap (section 11).

**Proxy and compose files copied from an older release.** Your copies in `/opt/featherauth` are not replaced by an upgrade. Compare them with the new release's `deploy/` files, and in particular:

- **Caddy:** your `Caddyfile` must have this block inside `reverse_proxy` (3.4); add it if it is missing, then restart Caddy in Docker with `cd /opt/featherauth && sudo docker compose restart caddy` (a Caddy on the host: `sudo systemctl reload caddy`):

  ```caddyfile
  transport http {
      keepalive off
  }
  ```

  Without it, a restart can fail a `POST` (such as a token refresh) with `502` although Caddy is set to hold requests.
- **Any other proxy:** it must open a new connection to FeatherAuth for every request and keep no idle connection to it for reuse. The nginx example already does.
- **Compose files:** the FeatherAuth service needs `stop_grace_period: 35s` (7.2), so that a restart lets requests in flight finish.

### 9.3 Roll back

- **Code only:** set the previous tag and recreate the container. This is enough for every release whose notes name no breaking change of the database, because the previous version runs on the migrated database:

  ```bash
  cd /opt/featherauth
  sudo sed -i 's/^FEATHERAUTH_TAG=.*/FEATHERAUTH_TAG=vPREV/' .env
  sudo docker compose up -d
  ```

- **Code and data:** restore the backup taken before the upgrade only when the release notes name a breaking change of the database (a migration that cannot be undone), or when the data itself went wrong. Anything written since the backup is lost. The whole sequence is: set the old tag, stop, restore, then `up -d`. A plain `start` would keep the container of the new image; `up -d` recreates it from the tag in `.env`.

  ```bash
  cd /opt/featherauth
  sudo sed -i 's/^FEATHERAUTH_TAG=.*/FEATHERAUTH_TAG=vPREV/' .env
  sudo docker compose stop featherauth
  # SQLite: the restore commands of 7.5 (decrypt, remove -wal and -shm, copy, owner and mode)
  # Postgres: the pg_restore command of 10.4
  sudo docker compose up -d
  ```

Old tags stay available, because they are never moved.

## 10. Databases: SQLite and Postgres

### 10.1 SQLite (default)

SQLite needs no setup: the file is `sqlite.path` (default `/var/lib/featherauth/featherauth.db`, on the `data` volume). Writes go through one connection and queue inside the service. The CLI can run beside the service: SQLite's locking and `sqlite.busy_timeout` handle it.

Only **one service process** may use a SQLite file. For several instances, use Postgres.

### 10.2 Postgres

Postgres 15 or newer. `deploy/compose.postgres.yaml` adds a `postgres` container (pinned image) with its own `postgres-data` volume and no published port, so only the compose network reaches it. Its user and database are both `featherauth`, which are the defaults of `database.yaml`.

1. Write the password to `config/secrets/postgres_password` **before** the first start: one line, owner `65532`, mode `600`. The compose file mounts this file into the Postgres container. If the file is missing, Docker creates a directory of that name instead.

   ```bash
   sudo nano /opt/featherauth/config/secrets/postgres_password
   sudo chown 65532:65532 /opt/featherauth/config/secrets/postgres_password && sudo chmod 600 /opt/featherauth/config/secrets/postgres_password
   ```

   FeatherAuth reads it as uid `65532`. The Postgres image's start script reads it as root before it drops to its own user, so the one file serves both.
2. In `database.yaml`:

   ```yaml
   driver: postgres
   postgres:
     host: postgres
     password_file: secrets/postgres_password
     sslmode: disable
   ```

   `sslmode: disable` is right only for this container: it serves no TLS and the traffic stays on the private compose network. For a database elsewhere, use `require`, or `verify-full` with `root_cert_file` for a private certificate authority.
3. Add the overlay to `COMPOSE_FILE` in `.env` (for example `COMPOSE_FILE=compose.yaml:compose.caddy.yaml:compose.postgres.yaml`), then start:

   ```bash
   cd /opt/featherauth
   sudo docker compose up -d
   ```

   The service waits for the database's health check. The CLI works the same way: `sudo docker compose exec featherauth /featherauth user get main <id>`.

With built-in TLS (3.6), combine the two files the same way: `COMPOSE_FILE=compose.tls.yaml:compose.postgres.yaml`.

The Postgres container is hardened like the FeatherAuth container: a read-only root filesystem, every Linux capability dropped except `CHOWN`, `DAC_OVERRIDE`, `SETGID` and `SETUID` (measured on the pinned image: its start script runs as root, reads the password file and drops to the `postgres` user, and needs exactly these), and `no-new-privileges`. Only its data volume and a `tmpfs` at `/var/run/postgresql` (the socket) are writable. The same settings apply to the Postgres service of `compose.ha.yaml`. Plain text on the private compose network stays accepted, because no port is published.

### 10.3 Move from SQLite to Postgres

`db copy` reads the SQLite database named by one `database.yaml` and writes the Postgres database named by another. Each file's `password_file` is read relative to **that file's own directory**. The Postgres container must be running during the copy, and the service must be stopped, because a row written after the copy starts is not copied.

```bash
cd /opt/featherauth
IMG=ghcr.io/yyudhistira/featherauth:vX.Y.Z      # the tag you run

# 1. Stop the service. Write the password file (10.2 step 1), add the overlay, start only Postgres
sudo docker compose stop featherauth
sudo sed -i 's/^COMPOSE_FILE=\(.*\)/COMPOSE_FILE=\1:compose.postgres.yaml/' .env
sudo docker compose up -d postgres
sudo docker compose ps postgres                  # wait for "healthy"

# 2. The target file, in a directory of its own, with the password file next to it
sudo mkdir -p /opt/featherauth/pg/secrets
sudo cp config/secrets/postgres_password pg/secrets/postgres_password
printf 'driver: postgres\npostgres:\n  host: postgres\n  password_file: secrets/postgres_password\n  sslmode: disable\n' | sudo tee pg/database.yaml
sudo chown -R 65532:65532 pg && sudo find pg -type d -exec chmod 700 {} \; && sudo find pg -type f -exec chmod 600 {} \;

# 3. Copy, in a one-off container on the compose network, with the SQLite data volume
sudo docker run --rm --user 65532:65532 --network featherauth_default \
  -v /opt/featherauth/config:/etc/featherauth:ro \
  -v /opt/featherauth/pg:/etc/featherauth-pg:ro \
  -v featherauth_data:/var/lib/featherauth \
  $IMG db copy --from /etc/featherauth/database.yaml --to /etc/featherauth-pg/database.yaml

# 4. Switch database.yaml to Postgres and start
sudo cp -p pg/database.yaml config/database.yaml
sudo rm -r pg
sudo docker compose up -d
```

In step 2, `secrets/postgres_password` resolves to `/opt/featherauth/pg/secrets/postgres_password` (seen in the container as `/etc/featherauth-pg/secrets/postgres_password`). After step 4 the same line resolves to `config/secrets/postgres_password`.

What `db copy` does:

- The target must be empty. A target with rows, or a source at another schema version, is refused with exit `1`, and nothing is written.
- It migrates the target, writes every table in one transaction, compares row counts and checksums, and prints `<table> <rows> ok` for each table, then `copied`.
- A difference rolls the target back and prints `<table> <source rows> <target rows> differs` (exit `1`).
- Any other pair of drivers is a usage error (exit `2`).

Tokens, sessions and user ids carry over. The SQLite file is not changed: to go back, restore `database.yaml` to SQLite and start on it again; what was written to Postgres since is lost. There is no copy from Postgres back to SQLite.

### 10.4 Back up and restore Postgres

`featherauth backup` and the daily snapshot are SQLite only. On Postgres, `backup` exits `1` with a message that names `pg_dump`. Use a host cron job that dumps through the container and encrypts before anything touches the disk. It runs in `/opt/featherauth`, so `.env` supplies the compose files:

```sh
30 3 * * * cd /opt/featherauth && bash -o pipefail -c 'f=/var/backups/featherauth-pg/featherauth-$(date +\%Y\%m\%d-\%H\%M).dump.age; docker compose exec -T postgres pg_dump --username=featherauth --format=custom --no-owner featherauth | age -r age1... > "$f.partial" && mv "$f.partial" "$f"'
```

- `pipefail` makes a failing `pg_dump` fail the job. A failed run leaves a `.partial` file. Watch the job's exit status and check that the newest file is not empty.
- Create `/var/backups/featherauth-pg` first.
- Copy the files off the server as for SQLite. The job only adds files; clean up yourself.
- For a database elsewhere, run the same `pg_dump` with `PGHOST`, `PGUSER`, `PGDATABASE`, `PGSSLMODE` and a `PGPASSFILE` (its own file, mode `600`).

Restore (rehearse on a copy first):

```bash
cd /opt/featherauth
sudo docker compose stop featherauth
age -d -i <private key> <file>.dump.age | sudo docker compose exec -T postgres pg_restore --username=featherauth --dbname=featherauth --clean --if-exists --no-owner
sudo docker compose up -d
```

## 11. Scale up

One instance on 1 vCPU and 512 MB serves the sized load (about 1,000 users, 5,000 sign-ins a day) with room to spare, and survives 1,000 simultaneous requests without errors. The measured figures are in REQUIREMENTS.md (NFR). In order of effort:

1. **A second vCPU.** Refreshes are limited by RSA signing on one core.
2. **`tokens.algorithm: ES256`.** Access tokens are signed with EC P-256, which is far cheaper to sign. ID tokens stay `RS256`. The realm needs one active EC key besides its RSA key, and your APIs must accept `ES256`.
3. **Postgres** (section 10).
4. **Several instances** on one Postgres database.

### 11.1 Several instances

`deploy/compose.ha.yaml` runs two instances (`app1`, `app2`), its own Postgres, and Caddy with active health checks on `/readyz` (`deploy/Caddyfile.ha`), published on `127.0.0.1:8080`. It is for **Postgres only**: the instances have no data volume.

It runs from a **checkout of the repository**: the rolling deploy script uses the paths `deploy/compose.ha.yaml` and the project name `featherauth-ha`. Its `FEATHERAUTH_CONFIG` defaults to `deploy/config` inside the checkout, so pass both variables on every command. `sudo env` passes them through `sudo`:

```bash
cd /opt/featherauth-src
HA="sudo env FEATHERAUTH_CONFIG=/opt/featherauth/config FEATHERAUTH_TAG=vX.Y.Z docker compose -p featherauth-ha -f deploy/compose.ha.yaml"
```

1. **Stop the single stack.** Both stacks publish `127.0.0.1:8080`. Run `cd /opt/featherauth && sudo docker compose down`, then go back to the checkout. `down` keeps the volumes.
2. **Bring up the stack's Postgres.** The stack has its own volume (`featherauth-ha_postgres-data`), empty at first.
   - Write the password file first (10.2 step 1); the stack's Postgres reads it too.
   - Run `$HA up -d postgres`, then wait until `$HA ps postgres` shows `healthy`.
3. **Copy the data into it, while `database.yaml` still names your current database.**
   - **From SQLite:** run steps 2 and 3 of 10.3 (the `pg/` target directory and the one-off `db copy` container), with `--network featherauth-ha_default` in place of `--network featherauth_default`.
   - **From the single stack's Postgres:** take a `pg_dump` (10.4), then restore it with `$HA exec -T postgres pg_restore ...` (same flags as 10.4).
4. **Switch the configuration.**
   - `database.yaml` names the stack's database as in 10.2: `driver: postgres`, `host: postgres`, `password_file: secrets/postgres_password`, `sslmode: disable`. Coming from SQLite, this is step 4 of 10.3: `sudo cp -p /opt/featherauth/pg/database.yaml /opt/featherauth/config/database.yaml`, then `sudo rm -r /opt/featherauth/pg`.
   - Set `rate_limit.store: database` in `server.yaml` if the limit must hold across the instances.
5. **Start everything:** `$HA up -d`.
6. **Trusted proxies.** Set `trusted_proxies` to the range of the `featherauth-ha_default` network: `sudo docker network inspect featherauth-ha_default --format '{{(index .IPAM.Config 0).Subnet}}'`.

`Caddyfile.ha` sets `transport http { keepalive off }` in its `reverse_proxy` block, so Caddy opens a new connection to an instance for every request. Keep it. A checkout of an older release lacks it: update the checkout (or add the block as in 9.2), then run `$HA up -d --force-recreate caddy`. Without it, a `POST` sent while an instance stops can fail with `502` during a rolling deploy. The instances in `compose.ha.yaml` have `stop_grace_period: 35s`, so a replaced instance can finish its requests.

As shipped, the stack serves plain HTTP on `127.0.0.1:8080`, so put your proxy in front of it as in 3.4 (on the host) or 3.5. To let its Caddy face the internet instead, replace `:8080` in `Caddyfile.ha` with the host name (Caddy then gets the certificate itself) and publish ports 80 and 443 for the `caddy` service.

How it behaves:

- Every instance reads the same configuration directory. A reload reaches them at slightly different moments; reload them one after the other if that matters.
- A sign-in may start on one instance and finish on another: its state is in the database.
- Migrations run once, under a Postgres lock. A back-channel notice is sent by one instance.
- **Rate limit:** with `rate_limit.store: memory` (default) each instance counts for itself, so the effective limit is `per_ip_per_minute` times the number of instances. With `rate_limit.store: database` (Postgres only, needs a restart) the instances share one count per client and minute. It is a fixed window, so up to twice the limit can pass around a minute boundary. If the count fails or takes over a second, that instance falls back to its own memory count and logs it once a minute.

### 11.2 Rolling deploy

From the checkout, with both variables:

```bash
cd /opt/featherauth-src
sudo env FEATHERAUTH_CONFIG=/opt/featherauth/config FEATHERAUTH_TAG=vNEW deploy/ops/rolling-deploy.sh
```

- It recreates `app1` with the new tag, waits until it answers `/readyz` (at most 60 seconds), then does the same for `app2`. Meanwhile Caddy sends requests to the other instance.
- A replaced instance gets `SIGTERM` and drains: requests in flight finish for up to 30 seconds, within the 35-second stop grace period.
- It prints `replaced app1`, `replaced app2` and `rolling deploy done`. If an instance does not become ready, it stops with `FAIL` and the other instance keeps serving.
- `ROLLING_PROJECT` sets the compose project (default `featherauth-ha`). `ROLLING_EXTRA` adds a compose file.
- Afterwards, use `FEATHERAUTH_TAG=vNEW` in your later `$HA` commands too.
- **Roll back** the same way: run the script with the previous tag, `sudo env FEATHERAUTH_CONFIG=/opt/featherauth/config FEATHERAUTH_TAG=vPREV deploy/ops/rolling-deploy.sh`. For a data restore, follow 9.3 with the `$HA` commands.

Scaling beyond 1,000 concurrent users has no measured targets yet; it is on the roadmap.

## 12. Change the configuration safely

1. Edit on the host, as root, and keep the modes (directories `700`, files `600`, owner `65532`).
2. Run `config check` against the directory (3.2). It shows the same diagnostics the service would log.
3. For realm files and `live` options of `server.yaml`: save the file and the service reloads (or send `SIGHUP`). Check the log for `configuration loaded`.
4. For `restart` options and anything in `database.yaml`: the running service logs `restart required` and keeps the old values. Restart it yourself after `config check`: `cd /opt/featherauth && sudo docker compose restart featherauth` (`.env` keeps the overlays). The service never restarts itself.
5. Some changes affect users:
   - a realm's `name` cannot change once it has users;
   - removing a client or provider fails its sign-ins and refreshes;
   - disabling a realm (`enabled: false`) refuses sign-ins and refreshes, while discovery and the keys stay up.

## 13. Configuration options

The configuration directory looks like this:

```text
/etc/featherauth/            (the host's FEATHERAUTH_CONFIG, mounted read-only)
  server.yaml                public URL, listener, TLS, rate limits, logs, paths
  database.yaml              database and backups (read at start only)
  realms/
    main.yaml                one file per realm; the file name is the realm name
  locales/                   optional translation files
  secrets/
    encryption_key
    main/signing-1.pem       one file per secret, named from the realm file
    main/google_secret
```

Every option is in the commented example files of `deploy/config.example/` (written by `config init`). Rules that hold for every file:

- Unknown options are errors.
- A file holds one YAML document.
- Durations use Go syntax (`30s`, `15m`, `720h`). A duration must be above zero unless its row says what `0` means; negative durations are always refused.
- Paths of secret files are relative to the configuration directory.
- A secret file holds its value as text; one trailing newline is ignored.
- "required" means there is no default.

In `server.yaml`, **live** options apply on reload; **restart** options need a restart.

### 13.1 Basics and network (`server.yaml`)

| Option | Default | Meaning and values | Takes effect | Change it when |
| --- | --- | --- | --- | --- |
| `public_url` | required | External base URL, part of every issuer and redirect URL. `https://host`, no trailing slash | restart | Always: your host name |
| `listen` | `":8080"` | Address the service listens on (`host:port` or `:port`). The environment variable `FEATHERAUTH_LISTEN` overrides it | restart | Another port; with `tls.mode: files` it must be a loopback address |
| `trusted_proxies` | `[]` | CIDRs of the proxies whose `X-Forwarded-For` is believed, read from the right. Empty: the header is ignored | live | You run a proxy (3.4) |
| `require_https` | `true` | Requires an `https` `public_url`, `https` URLs and `Secure` cookies | restart | Only `false` for local development |
| `log_level` | `info` | `debug`, `info`, `warn`, `error` | live | Debugging |
| `strict_permissions` | `true` | A secret file readable by group or others is an error; `false` makes it a warning | restart | Keep `true` |

Environment variables: `FEATHERAUTH_CONFIG_DIR` (default `/etc/featherauth`) and `FEATHERAUTH_LISTEN`. Everything else comes from files.

### 13.2 TLS and paths (`server.yaml`)

| Option | Default | Meaning and values | Takes effect |
| --- | --- | --- | --- |
| `tls.mode` | `none` | `none`: a proxy ends TLS. `files`: the service ends TLS from files (3.6) | restart |
| `tls.listen` | `":443"` | HTTPS listener with `files` | restart |
| `tls.http_listen` | `":80"` | Plain listener that answers `301` to HTTPS; empty opens none | restart |
| `tls.cert_file` | required with `files` | PEM certificate chain | restart |
| `tls.key_file` | required with `files` | PEM private key (a secret file) | restart |
| `urls.path_prefix` | `""` | `{prefix}` in the templates below, and part of the issuer; empty or a path starting with `/` (for example `/auth`) | restart |
| `urls.issuer` | `{prefix}/{realm}` | Issuer path; discovery is always `<issuer>/.well-known/openid-configuration` | restart |
| `urls.endpoints.authorize` | `{prefix}/{realm}/authorize` | Starts a sign-in | restart |
| `urls.endpoints.token` | `{prefix}/{realm}/token` | Code exchange and refresh | restart |
| `urls.endpoints.userinfo` | `{prefix}/{realm}/userinfo` | User info | restart |
| `urls.endpoints.jwks` | `{prefix}/{realm}/jwks.json` | Public keys | restart |
| `urls.endpoints.logout` | `{prefix}/{realm}/logout` | Logout | restart |
| `urls.endpoints.revoke` | `{prefix}/{realm}/revoke` | Token revocation | restart |
| `urls.endpoints.sessions` | `{prefix}/{realm}/sessions` | Sessions of the signed-in user | restart |
| `urls.endpoints.callback` | `{prefix}/{realm}/callback/{provider}` | Where providers return; registered at each provider | restart |
| `urls.endpoints.account_delete` | `{prefix}/{realm}/account` | Account deletion | restart |
| `urls.endpoints.assets` | `{prefix}/{realm}/assets` | Stylesheet and logos | restart |
| `urls.endpoints.provider_events` | `{prefix}/{realm}/events/{provider}` | Apple, Google and Meta events; registered at the provider | restart |
| `urls.endpoints.data_deletion` | `{prefix}/{realm}/data-deletion` | Data-deletion instructions page | restart |
| `login.provider_hint_params` | `[provider]` | Parameter names accepted on authorize to skip the chooser | live |
| `logout.redirect_params` | `[post_logout_redirect_uri]` | Parameter names accepted for the logout return URL; a name other than `post_logout_redirect_uri` is a legacy name | live |

The path options exist for client libraries that build URLs themselves and for provider registrations you must keep. Rules for the templates:

- every template contains `{realm}`;
- `callback` and `provider_events` contain `{provider}`, and no other template (nor `urls.issuer`) may;
- no other placeholders are allowed;
- every path starts with `/`;
- no two endpoints may have the same path;
- the realm names `admin`, `healthz` and `readyz` are reserved.

### 13.3 Rate limit and secrets (`server.yaml`)

| Option | Default | Meaning and values | Takes effect |
| --- | --- | --- | --- |
| `rate_limit.per_ip_per_minute` | `30` | Requests per minute per client on authorize, callback, token, revocation and provider events. The client is an IPv4 address or an IPv6 `/64`. `0` disables. Raise it if many users share one address | live |
| `rate_limit.store` | `memory` | `memory`: each instance counts for itself (at most 100,000 clients remembered; when full, new clients get `429`). `database`: one count for all instances (only with `driver: postgres`) | restart |
| `secrets.encryption_key_files` | `[secrets/encryption_key]` | Keys that encrypt stored Apple refresh tokens; the first encrypts, all decrypt; each holds 32 random bytes as base64. Required when an enabled provider has `store_refresh_token: true`; otherwise a missing file is skipped | restart |

### 13.4 Database and backups (`database.yaml`, read at start only)

| Option | Default | Meaning and values |
| --- | --- | --- |
| `driver` | `sqlite` | `sqlite` or `postgres` |
| `sqlite.path` | `/var/lib/featherauth/featherauth.db` | Database file, on the data volume |
| `sqlite.busy_timeout` | `5s` | How long a writer (such as a CLI command) waits for the lock; above zero |
| `sqlite.journal_mode` | `wal` | `wal` (other modes only for filesystems that cannot support it) |
| `sqlite.read_connections` | `4` | Read connections, 1 or more; writes use one separate connection |
| `postgres.host` | required with `postgres` | Server host |
| `postgres.port` | `5432` | Server port |
| `postgres.database` | `featherauth` | Database name |
| `postgres.user` | `featherauth` | User name |
| `postgres.password_file` | required with `postgres` | File with the password; read and permission-checked only with `driver: postgres` |
| `postgres.sslmode` | `require` | `disable`, `require`, `verify-full` |
| `postgres.root_cert_file` | `""` | CA certificate for `verify-full`; empty uses the system store. Not permission-checked (it is public) |
| `postgres.max_open_conns` | `20` | Pool size; `0` means no limit |
| `postgres.max_idle_conns` | `5` | Idle connections kept; `0` keeps none; capped at `max_open_conns` |
| `postgres.conn_max_lifetime` | `30m` | Connection reuse limit; above zero |
| `postgres.connect_timeout` | `5s` | Time allowed to open one connection: TCP connect, TLS and the startup and authentication exchange together; above zero. A server that does not answer fails the attempt within this time, so `/readyz` answers `503` instead of hanging |
| `backup.directory` | `/var/backups/featherauth` | Where SQLite snapshots go; empty disables backup |
| `backup.at` | `"03:00"` | Daily snapshot time, `HH:MM`, server local time; empty for no schedule |
| `backup.keep` | `7` | Newest snapshots kept, 1 or more |

### 13.5 Realm file (`realms/<name>.yaml`)

**Identity and switches**

| Option | Default | Meaning and values |
| --- | --- | --- |
| `name` | required | Lowercase letters, digits, dashes; equals the file name; the `{realm}` in URLs; cannot change once users exist; `admin`, `healthz`, `readyz` reserved |
| `display_name` | the `name` | Shown on the login page; plain text |
| `enabled` | `true` | `false` refuses sign-ins (error page) and refreshes (`invalid_grant`); discovery and the JWKS stay up |

**Tokens and sessions** (clients can override the three lifetimes marked *)

| Option | Default | Meaning and values |
| --- | --- | --- |
| `tokens.access_token_lifetime` * | `15m` | Access and ID tokens; 1 minute or more |
| `tokens.refresh_idle_lifetime` * | `720h` | Session ends if unused this long |
| `tokens.session_max_lifetime` * | `2160h` | Absolute session limit from sign-in; `0` for none |
| `tokens.code_lifetime` | `60s` | One-time sign-in code; 10 to 300 seconds |
| `tokens.login_timeout` | `10m` | Time a user may take at the provider |
| `tokens.refresh_reuse_grace` | `30s` | A just-rotated refresh token still works this long (for retries); `0` disables. Raise it to a few minutes if apps get signed out by concurrent refreshes |
| `tokens.refresh_token_rotation` | `true` | Rotation for confidential clients; `false` is weaker. Public clients always rotate |
| `tokens.account_delete_max_auth_age` | `10m` | How recent a sign-in must be for `DELETE /account` |
| `tokens.algorithm` | `RS256` | `RS256` or `ES256` for access tokens and JWT refresh tokens; ID tokens are always `RS256` |
| `tokens.refresh_token_format` | `opaque` | `opaque` or `jwt` (for client libraries that decode it); validity is always decided on the server |
| `sso.enabled` | `false` | Browser single sign-on session (section 2) |
| `sso.idle_lifetime` | `8h` | Browser session ends if unused this long |
| `sso.max_lifetime` | `720h` | Browser session ends this long after the sign-in that made it |

**Keys**

| Option | Default | Meaning and values |
| --- | --- | --- |
| `keys` | required, at least one | List of `{kid, file, state}`, all published in the JWKS |
| `keys[].kid` | required | Key id; unique across realms |
| `keys[].file` | required | PEM private key: RSA 2048 bits or more, or EC P-256 |
| `keys[].state` | required | `active` (exactly one RSA; plus exactly one EC with `ES256`; an active EC key with `RS256` is an error) or `verify_only` |

**User data**

| Option | Default | Meaning and values |
| --- | --- | --- |
| `user_data.attributes` | `[email, name]` | What is stored; any of `email`, `name` |
| `user_data.claims` | `[name, email, email_verified, preferred_username]` | Claims in ID tokens, userinfo and (unless set below) access tokens; also `allowed-origins`. `preferred_username` is the email, else the user id |
| `user_data.access_token_claims` | not set | The claims of `user_data.claims` that access tokens carry; `[]` carries none; not set (or an empty value) means all of them. The example file sets it to the full default list, which has the same effect as not set; whatever your file says is what applies |
| `user_data.keep_name_if_missing` | `true` | Never overwrite a stored name with an empty one (Apple sends it once) |
| `user_data.id_format` | `uuid` | Format of new user ids: `uuid` (random, lowercase, hyphenated) or `ulid` (26 characters, sortable by time). Existing ids never change |
| `user_data.auto_link_domains` | `[gmail.com, googlemail.com, icloud.com, me.com, mac.com]` | Email domains on which accounts may be joined automatically. Add a company domain only if you accept that a reassigned address joins its new owner to the old account |

**Login page and headers**

| Option | Default | Meaning and values |
| --- | --- | --- |
| `login_page.logo_url` | `""` | Logo on the chooser; empty or an `https` URL |
| `login_page.accent_color` | `"#2563eb"` | Links and generic-provider buttons; built-in buttons keep their own branding |
| `login_page.contact` | `""` | Email or `https` URL on the error and data-deletion pages; required with Facebook |
| `login_page.provider_order` | `[google, apple, github, facebook]` | Button order; unlisted providers follow |
| `login_page.default_locale` | `en` | Language when the browser's is not supported |
| `login_page.supported_locales` | `[en]` | Languages offered. `en` and `id` (Indonesian) are built in. Another language needs a file `locales/<code>.yaml` mapping message ids to text (start from `locales/en.yaml.example`); a file for a built-in language replaces single messages; a missing message falls back to English |
| `security_headers.content_security_policy` | `default-src 'none'; style-src 'self'; img-src 'self' https:; frame-ancestors 'none'; form-action 'self'` | CSP of the pages; empty omits it |
| `security_headers.hsts` | `max-age=31536000; includeSubDomains` | HSTS header (over HTTPS only); empty omits it |

### 13.6 Providers (`providers.<key>` in the realm file)

Common options:

| Option | Default | Meaning and values |
| --- | --- | --- |
| `type` | the key | `google`, `apple`, `github`, `facebook` or `oidc` |
| `enabled` | `false` | Turns it on |
| `display_name` | `Google`, `Apple`, `GitHub`, `Facebook`; the key for `oidc` | Button text |
| `hidden` | `false` | No button, but the provider hint still works |
| `client_id` | required when enabled | Client id at the provider |
| `client_secret_file` | required when enabled (not Apple) | Secret file |
| `scopes` | per provider | Scopes requested from the provider |
| `trust_email` | per provider | Believe the provider's verified-email flag |
| `auto_link` | `true` | Join to an existing user with the same verified email on an auto-link domain; only with `trust_email: true` |
| `sync_mode` | `import` | `import` copies name and email at first sign-in; `force` refreshes them at every sign-in |
| `timeout` | `10s` | Time for each call to the provider; above zero, at most `30s` |
| `endpoints.authorize`, `.token`, `.userinfo`, `.jwks` | the provider's own | Overrides. `jwks` only for Google, Apple and `oidc`; `userinfo` for Google, `oidc`, GitHub (`/user`) and Facebook (`/me`), not Apple. For Google and `oidc`, user info is called only when `endpoints.userinfo` is set |

Per provider:

| Provider | Option | Default | Meaning and values |
| --- | --- | --- | --- |
| Google | `scopes` | `[openid, email, profile]` | |
| Google | `trust_email` | `true` | |
| Google | `hosted_domain` | `""` | One Workspace domain only, checked on the `hd` claim |
| Google | `endpoints.risc_configuration` | Google's RISC configuration URL | Where the keys and issuer of security events come from |
| Apple | `client_id` | required | The Services ID |
| Apple | `team_id`, `key_id` | required | Team ID and key ID |
| Apple | `private_key_file` | required | The `.p8` key |
| Apple | `client_secret_lifetime` | `5m` | Lifetime of each generated client secret; up to 6 months |
| Apple | `store_refresh_token` | `true` | Keep Apple's refresh token (encrypted) so deletion can revoke it; `false` stores nothing |
| Apple | `scopes` | `[name, email]` | Only `name` and `email`, each at most once; `[]` asks for neither; any other value fails at load. Without `email` Apple gives no email, so the user has none and is never auto-linked |
| Apple | `trust_email` | `true` | |
| Apple | `notification_audiences` | `[]` | Extra `aud` values accepted on Apple's notifications (for example the primary App ID) |
| GitHub | `scopes` | `[read:user, user:email]` | `user:email` is needed for the email list |
| GitHub | `pkce` | `true` | Send PKCE to GitHub |
| GitHub | `allow_signup` | `true` | `false` admits existing GitHub accounts only |
| GitHub | `require_verified_email` | `true` | Refuse a sign-in without a verified primary email |
| GitHub | `trust_email` | `true` | |
| Facebook | `graph_version` | `v26.0` | Graph API version; check yearly |
| Facebook | `flow` | `oauth` | Only `oauth` |
| Facebook | `scopes` | `[public_profile, email]` | |
| Facebook | `fields` | `[id, name, email]` | Fields read from `/me` |
| Facebook | `require_email` | `false` | Refuse a sign-in without an email |
| Facebook | `trust_email` | `false` | `true` is accepted with a warning; Facebook gives no verified flag |
| `oidc` | `issuer` | required | Issuer of a single-issuer provider; discovery is derived from it |
| `oidc` | `scopes` | `[openid, email, profile]` | |
| `oidc` | `trust_email` | `false` | A missing `email_verified` counts as unverified |

### 13.7 Clients (`clients.<client_id>` in the realm file)

| Option | Default | Meaning and values |
| --- | --- | --- |
| `name` | the client id | Display name |
| `description` | `""` | Free text |
| `type` | `public` | `public` (no secret, PKCE) or `confidential` (secret) |
| `client_secret_file` | required for `confidential` | Secret file; shorter than 32 characters gives a warning |
| `redirect_uris` | required | Exact URIs: custom scheme, HTTPS app link, HTTPS URL or loopback; loopback of a public client may vary in port; no loopback for confidential clients |
| `post_logout_redirect_uris` | `[]` | Allowed logout return URLs; empty means the `redirect_uris` |
| `web_origins` | `[]` | Bare origins (scheme, host, optional port) allowed to call token, userinfo, sessions, JWKS and discovery from a browser |
| `require_pkce` | `true` | `false` is an exception for a legacy app (with a warning). For a public client it needs effective lifetimes of `refresh_idle_lifetime` at most `24h` and `session_max_lifetime` above 0 and at most `720h` |
| `response_mode` | `query` | `query`, `fragment` or `form_post`, when the request names none |
| `audience` | the client id | `aud` of this client's access tokens; set it to your API's identifier |
| `access_token_lifetime`, `refresh_idle_lifetime`, `session_max_lifetime` | the realm's | Per-client lifetimes (`0` for `session_max_lifetime` means none) |
| `refresh_token_rotation` | the realm's | Confidential clients only; `false` is refused for a public client |
| `allow_account_delete` | `false` | This client's tokens may call `DELETE /account` |
| `allow_session_management` | `false` | This client's tokens may list sessions, end one, or end all |
| `backchannel_logout_uri` | `""` | `https` URL (no fragment) that receives logout tokens; `http` only with `require_https: false` |
| `dpop` | `off` | `off`, `allowed` (bind when the app sends a proof) or `required` |
| `sso` | `true` | Take part in the realm's single sign-on session |

## 14. Deploy tools and commands

### 14.1 Files in `deploy/`

| File | Use |
| --- | --- |
| `Dockerfile` | Builds the image: a static binary at `/featherauth` on a distroless non-root base (uid `65532`), entry point `/featherauth`, command `serve`, health check `featherauth healthcheck` every 10 s, 5 s timeout, 5 s start period, unhealthy after 6 failures |
| `compose.yaml` | FeatherAuth alone, port `127.0.0.1:8080`, hardened; volumes `data` and `backups`. Needs `FEATHERAUTH_TAG`; `FEATHERAUTH_CONFIG` defaults to `./config`. Combine with the overlays through `COMPOSE_FILE` in `.env` (3.1) |
| `compose.caddy.yaml` | Add to `compose.yaml`: Caddy on ports 80 and 443 with `Caddyfile` and the `caddy_data` volume |
| `Caddyfile.example` | Caddy site with Let's Encrypt (or a bought certificate), the restart hold, and a new upstream connection per request (`keepalive off`) |
| `nginx.example.conf` | The two nginx server blocks and the log format without query strings |
| `compose.postgres.yaml` | Add to `compose.yaml`: Postgres with the `postgres-data` volume, password from `secrets/postgres_password` |
| `compose.tls.yaml` | Instead of `compose.yaml`: FeatherAuth ending TLS itself on the host's ports 443 and 80 |
| `compose.ha.yaml`, `Caddyfile.ha` | On its own, from the checkout, Postgres only: two instances, their own Postgres, Caddy with health checks, on `127.0.0.1:8080`; project `featherauth-ha` (11.1) |
| `config.example/` | The commented configuration that `config init` writes |
| `ops/backup-offsite.sh` | Encrypted off-server copy; copied to `/opt/featherauth/` in 3.1 and run from the host's cron (7.5) |
| `ops/rolling-deploy.sh` | Rolling replacement of the instances of `compose.ha.yaml`; run from the checkout's root with `FEATHERAUTH_TAG` and `FEATHERAUTH_CONFIG` set (11.2) |
| `ops/deploy-remote.sh` | Used by the example pipeline below: pulls a tag, waits for `/readyz`, and starts the previous tag again on failure |

### 14.2 Command line

Run `featherauth` with no command, or an unknown one, to print the usage. In Docker, the binary is `/featherauth` inside the container (`docker compose exec featherauth /featherauth ...`). Exit codes: `0` success, `1` failure, `2` usage error.

| Command | Does |
| --- | --- |
| `serve` | Runs the service (the image's default command) |
| `version` | Prints the version |
| `config init <dir>` | Writes the commented examples; refuses if any exists |
| `config check <dir>` | Validates offline; `ok` or `file:line: severity: field: reason` lines |
| `keys generate [--type rsa\|ec\|encryption] [--bits N] <file>` | New key, mode `0600`, never overwrites; RSA 2048 by default, `--bits` (2048 or more) for RSA only; prints `wrote <file>` |
| `keys sealed <realm> --key-id <id>` | JSON list of the identities (`user_id`, `provider`, `subject`) whose stored provider token the encryption key `<id>` (8 lowercase hex characters) sealed; never prints a token; audited (8.2) |
| `keys reseal <realm> --key-id <id>` | Seals those tokens again under the first key; needs `<id>` listed and a different first key; prints `{resealed, skipped, failed}`; exits `1` if any failed (8.2) |
| `keys clear-sealed <realm> --key-id <id>` | Sets those tokens to none, revoking nothing; prints `{cleared, skipped}` (8.2) |
| `user get\|list\|update\|disable\|enable\|delete\|link\|unlink <realm> ...` | Section 7.7 |
| `session list <realm> <user id>`, `session revoke <realm> <user id> [--session <id>]`, `session revoke <realm> --all` | Section 7.8 |
| `import <file> --realm <name> [--include-without-identity]` | Section 7.7 |
| `db copy --from <file> --to <file>` | Section 10.3 |
| `backup` | One SQLite snapshot to `backup.directory`; prints `wrote <path>` |
| `healthcheck` | Calls `/readyz` of the running service (`FEATHERAUTH_LISTEN`, else `listen`); prints `ready` |

The commands that open the database (`user`, `session`, `keys sealed`, `keys reseal`, `keys clear-sealed`, `import`, `backup`, `db copy`) read `database.yaml` from `FEATHERAUTH_CONFIG_DIR`. `user delete`, `session revoke` and `user disable` also read the realm configuration, to revoke Apple tokens and to queue back-channel logout notices; without a usable configuration they still act and log a warning (except `user delete`, see 7.7).

### 14.3 Example: the project's own push-to-main pipeline

The repository's GitHub Actions show one way to automate deploys. You can adapt it; it is not needed to run FeatherAuth.

- `ci.yml` runs on pull requests: vet, tests and `govulncheck` (less for a documentation-only change, see below).
- `deploy.yml` runs on a push to `main`:
  1. the same checks;
  2. builds the image, tags it with the commit SHA and pushes it to `ghcr.io`;
  3. connects to the host over SSH and runs `deploy/ops/deploy-remote.sh`, which does `docker compose pull && up -d` with the new tag in the deploy directory;
  4. waits up to 30 seconds for `/readyz`, and starts the previous tag again on failure.
- A change that touches only documentation (the Markdown guides and design files, `tools/trace/pending.txt`, `.claude/`, or only comments in Go files) runs only the scan for private keys and the tests that read those documents, both on a pull request and on a push to `main`. On `main` this holds only when the parent commit's deploy run succeeded; such a push builds and pushes the image but does not deploy it. Every other change runs all the checks.
- A pushed tag `vX.Y.Z` only builds and publishes the release image, and never deploys.
- Repository secrets: `DEPLOY_HOST`, `DEPLOY_USER`, `DEPLOY_SSH_KEY` and `DEPLOY_KNOWN_HOSTS` (the host's `known_hosts` line).
- Repository variables:
  - `DEPLOY_PATH`: the host directory with `compose.yaml`. While it is not set, the deploy job is skipped and only the image is built.
  - `RUNNER`, optional: a self-hosted runner label.
- The host must be able to pull from `ghcr.io` (a public package, or one `docker login`).
- The deploy uses `compose.yaml`, or the files in `COMPOSE_FILE` on the host. It never touches the configuration directory.
- The first deploy on a new host is manual (section 3).

### 14.4 Verify an image

Every published image is signed by its digest with the release workflow's identity and carries a software bill of materials (SPDX).

The identity pattern below accepts images built from a release tag **and** images built from the `main` branch (each commit of `main` also gets an image, tagged with its commit hash). To be sure you run a release, check and run a release tag `vX.Y.Z`, or better its digest (`ghcr.io/yyudhistira/featherauth@sha256:...`), which cannot change under you.

```bash
ID='^https://github.com/yyudhistira/featherauth/\.github/workflows/deploy\.yml@refs/(heads/main|tags/v[0-9]+\.[0-9]+\.[0-9]+)$'
ISS=https://token.actions.githubusercontent.com
IMG=ghcr.io/yyudhistira/featherauth:vX.Y.Z
cosign verify --certificate-oidc-issuer "$ISS" --certificate-identity-regexp "$ID" "$IMG"
cosign verify-attestation --type spdxjson --certificate-oidc-issuer "$ISS" --certificate-identity-regexp "$ID" "$IMG"
```

The build provenance is recorded by GitHub only for a public repository. Where it exists, check it too:

```bash
gh attestation verify "oci://$IMG" --repo yyudhistira/featherauth --signer-workflow yyudhistira/featherauth/.github/workflows/deploy.yml
```

## 15. Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| Compose says `set FEATHERAUTH_TAG to the image tag` | Set `FEATHERAUTH_TAG` in `.env` or the environment. To find the running tag: `docker inspect <container> --format '{{.Config.Image}}'` |
| Compose says `no configuration file provided` | Run `docker compose` in the directory with the compose files (`/opt/featherauth`) |
| `config check`: `cannot read server.yaml` | Pass `/etc/featherauth`, the path inside the container, not the host path |
| `config check`: "cannot read secret file" for every file | A directory lost its `x` bit. Use the two `find` lines of 3.2 (directories `700`, files `600`, owner `65532`); never `chmod -R 600` |
| `sudo chmod 600 dir/*` or `sudo ls dir/*` finds nothing | Your own shell expands `*` and cannot read the directory; name the file or use `sudo find` |
| The service does not start: a secret file "readable by its group or others" | Mode `600` on the file, or `strict_permissions: false` (not recommended) |
| The chooser says "No sign-in method is available right now." | No provider has `enabled: true` in that realm |
| Error page "The request is not valid" | The client id is unknown or the redirect URI is not registered exactly; check `clients:` (add a client next to the others rather than replacing one) |
| `code_challenge must be 43 base64url characters` | The PKCE challenge is empty or malformed; in the curl test, run all lines in one shell |
| `invalid_grant` at the token call | The code was used already, is older than 60 seconds, or the verifier is from another attempt |
| `invalid_client` | Wrong or missing secret for a confidential client, or a secret sent by a public client |
| The app is signed out after a refresh | A refresh token was used twice after the grace window (look for `session.reuse_detected`); fix concurrent refreshes in the app or raise `tokens.refresh_reuse_grace` |
| Many `429` answers | Many users behind one address, or no `trusted_proxies`, so everyone counts as the proxy. Set `trusted_proxies`, or raise `rate_limit.per_ip_per_minute` |
| An API refuses new tokens after a key change | Its cached JWKS is older than the change; it refetches within 300 seconds, or restart it |
| `502` from nginx during a deploy | nginx cannot hold requests; it lasts about a second. Use Caddy for no gap, or several instances |
| `502` from Caddy during a restart, often on a `POST` such as a refresh | The `Caddyfile` lacks `transport http { keepalive off }` inside `reverse_proxy` (copied from an older release); add it and reload Caddy (9.2) |
| Requests cut off about 10 seconds into a restart or deploy | Docker killed the service before its 30-second drain ended: set `stop_grace_period: 35s` on the FeatherAuth service in your compose file (7.2) |
| The log says `restart required` | You changed a `restart` option or `database.yaml`; restart the service after `config check` |
| `configuration not applied` in the log | The new configuration is invalid; the old one keeps serving. Run `config check` |
| `curl: (23) Failure writing output` | You ran the token test in a directory you cannot write to; use `~` |
| `/readyz` answers `503` | The database cannot be reached, or the service is shutting down. On Postgres, a server that does not answer within `postgres.connect_timeout` (5 s) also gives `503`: check `postgres.host`, the network and the firewall |
| The container shows `unhealthy` | The health check (`featherauth healthcheck` every 10 s, 5 s timeout, 5 s start period) failed 6 times in a row: `/readyz` did not answer `200`. Look at `docker compose logs featherauth` for a database or configuration error |
| A file you mount became a directory (`Caddyfile`, `postgres_password`) | It did not exist when the container started, so Docker created a directory. Remove the directory, create the file, start again |
| `featherauth: not found` in `docker compose exec` | The binary is `/featherauth` inside the container |
| `backup` fails with a message naming `pg_dump` | You are on Postgres; use the `pg_dump` job (10.4) |
| Apple sign-in fails in local development | Apple needs an `https` return URL with a domain name |

## 16. Security notes for operators

- **Keep secrets in files only.** Mode `600`, owner `65532`, never in the repository, the image or a ticket. Use client secrets of at least 32 characters.
- **Encrypt the host's disk.** The SQLite file, the local snapshots and the Postgres volume hold users' emails and names in clear. Only the off-server copies are encrypted. Encrypt the disk, including Docker's data directory.
- **Logs.** FeatherAuth never logs tokens, codes, `state`, secrets, cookies or emails, at any level. Keep it that way in front of it:
  - the proxy must not log query strings (the nginx example logs `$uri`, and its error log is at `crit`);
  - a Caddy `log` directive, if you add one, must drop the query;
  - the request log keeps the full client address, so an attack can be traced.
- **Keep the proxy the only way in.** Publish the port on `127.0.0.1` only and set `trusted_proxies` to the proxy's address. A header from anyone else is ignored.
- **HTTPS only.** Keep `require_https: true` outside local development.
- **Hardened containers.** The FeatherAuth container and the bundled Postgres container both run with a read-only root, `no-new-privileges` and dropped capabilities. FeatherAuth holds none. Postgres keeps only `CHOWN`, `DAC_OVERRIDE`, `SETGID` and `SETUID`, which its start script needs, and can write only its data volume and `/var/run/postgresql` (10.2). Do not remove these settings when you adapt the compose files.
- **No network administration.** There is no admin port or admin API. Whoever can run the CLI on the host can change users, so protect shell and Docker access to the host.

Accepted risks you should know:

- **Access tokens outlive logout.** After logout, deletion or disabling, issued access tokens stay valid until they expire (15 minutes by default). APIs that need an immediate answer call `/userinfo`.
- **Default audience.** An access token's `aud` defaults to the client id, the same as the ID token's. Set `audience` per client so that APIs can tell them apart by more than the token type.
- **Rate-limit table full.** An attacker with 100,000 addresses or IPv6 `/64` prefixes in one minute can fill the rate limit's table, so new clients get `429` while it lasts. Stop such floods at a firewall or the proxy.
- **Provider re-authentication.** Google, Apple and GitHub cannot be forced to ask for a password again: a "recent" sign-in proves a pass through the provider in that browser. Apps confirm account deletion themselves.
- **PKCE exception.** A public client with `require_pkce: false` is protected only by the exact redirect match. That is why its sessions are limited to short lifetimes. Use it only while a legacy app is updated.
- **GitHub and Facebook revocations.** A user who removes your app at GitHub or Facebook keeps their FeatherAuth session until the refresh token expires.
- **Company domains.** Keep company domains off `user_data.auto_link_domains` unless you accept that a reassigned address joins its new owner to the old account.

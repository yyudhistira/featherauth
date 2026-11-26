# FeatherAuth example web app

A small React single-page app, built with Vite, that signs a user in to FeatherAuth as a **public client** with the authorization code flow and PKCE. It is the code to copy when you build your own app.

- [`oidc-client-ts`](https://github.com/authts/oidc-client-ts) runs the flow (`src/auth.js`).
- [`jose`](https://github.com/panva/jose) verifies the ID token's signature against the realm's JWKS; `oidc-client-ts` checks the token's claims but not its signature.
- Tokens are kept **in memory only**, so reloading the page signs you out.
- The page shows the verified claims, whether userinfo's `sub` matches, and the access token expiry.
- **Refresh** uses the refresh token and runs only when you press the button: refresh tokens rotate, so two refreshes sent at once with one token would be a reuse.
- **Sign out** is RP-initiated logout (`id_token_hint`, then back to the app).

It is a separate Node project. FeatherAuth itself gains no dependency, and the Go module never enters this directory.

## Before you start

You need a running FeatherAuth reached over HTTPS (see the quick start in the main README) with at least one provider that you can sign in with.

1. Add the client entry. Copy the `example-web:` block of [`example-web-client.yaml`](example-web-client.yaml) under `clients:` of the realm file you use, then reload: `docker compose kill -s HUP featherauth` (or send `SIGHUP`). The entry is for trying the example, not for production.
2. Set `authority` in [`public/config.json`](public/config.json) to your realm's issuer, for example `https://auth.example.com/example`. The other three values already match the client entry.

The app must run at `http://127.0.0.1:5173`, not `localhost`: FeatherAuth accepts plain `http` only on `127.0.0.1` or `[::1]`, and the post-logout URL must match exactly, so the port is fixed.

## Run it

With Node (the version in [`.node-version`](.node-version)):

```sh
cd examples/web-app
npm ci --ignore-scripts
npm run dev
```

`--ignore-scripts` runs no package's install script, as in the Dockerfile and `make example`; the dev server starts and works without them.

With Docker only, from the repository root (edit `public/config.json` first; `compose.yaml` mounts it read-only over the image's copy, so a later edit needs only a restart of the container, not a rebuild):

```sh
docker compose -f examples/web-app/compose.yaml up --build
```

The container's Caddy sends two security headers on every page: `Content-Security-Policy: default-src 'self'; connect-src 'self' https:; frame-ancestors 'none'; base-uri 'none'; object-src 'none'` and `X-Content-Type-Options: nosniff`. The policy lets the page call your FeatherAuth over HTTPS only.

Then open <http://127.0.0.1:5173/> and press **Sign in**. After you sign in with your provider the page shows "Signed in", "ID token signature verified", your claims and "userinfo sub matches". **Refresh** counts one refresh, and **Sign out** ends the session and shows "Signed out".

`npm run build` writes the site to `dist/`; `config.json` there can be edited without a rebuild, so one build serves any FeatherAuth.

The app calls userinfo itself, once after each sign-in and once after each refresh (`loadUserInfo` is off in the library), and the ID token check allows 300 seconds of clock difference (`clockTolerance`).

## Files

| File | Holds |
| --- | --- |
| `src/auth.js` | The `UserManager` and the ID token check |
| `src/App.jsx` | The page |
| `public/config.json` | `authority`, `client_id`, `redirect_uri`, `post_logout_redirect_uri` |
| `example-web-client.yaml` | The client entry to copy into a realm file |
| `Dockerfile`, `compose.yaml` | Build with Node, serve with Caddy on `127.0.0.1:5173` |

Its dependencies are pinned to exact versions in `package.json` and `package-lock.json` and are updated by hand; `npm audit --omit=dev --audit-level=high` finds nothing.

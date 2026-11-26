import { InMemoryWebStorage, UserManager, WebStorageStateStore } from "oidc-client-ts";
import { createRemoteJWKSet, jwtVerify } from "jose";

// config.json is read at start, so one build serves any FeatherAuth.
export async function loadConfig() {
  const res = await fetch("/config.json", { cache: "no-store" });
  if (!res.ok) {
    throw new Error(`config.json: HTTP ${res.status}`);
  }
  const config = await res.json();
  for (const key of ["authority", "client_id", "redirect_uri", "post_logout_redirect_uri"]) {
    if (typeof config[key] !== "string" || config[key] === "") {
      throw new Error(`config.json: "${key}" is missing`);
    }
  }
  return config;
}

// One UserManager. Tokens live in memory only: the user store is an
// InMemoryWebStorage, so a reload of the page signs the user out. The sign-in
// state across the redirect stays in the library's default state store
// (sessionStorage), which holds no token. Refresh tokens rotate, so nothing
// refreshes by itself: automaticSilentRenew is off and only the button asks.
export function createAuth(config) {
  return new UserManager({
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
}

// oidc-client-ts checks the claims of the ID token (iss, aud, nonce, exp) but
// not its signature, so it is verified here against the keys of the
// authority's JWKS. It returns the verified claims.
export async function verifyIdToken(auth, config, user) {
  if (!user.id_token) {
    throw new Error("the token response has no id_token");
  }
  const metadata = await auth.metadataService.getMetadata();
  const jwks = createRemoteJWKSet(new URL(metadata.jwks_uri));
  const { payload } = await jwtVerify(user.id_token, jwks, {
    issuer: config.authority,
    audience: config.client_id,
    algorithms: ["RS256"],
    typ: "JWT",
    clockTolerance: 300, // seconds of difference allowed between this clock and the server's
  });
  return payload;
}

// Calls the userinfo endpoint with the access token and returns its sub.
export async function userinfoSub(auth, user) {
  const metadata = await auth.metadataService.getMetadata();
  const res = await fetch(metadata.userinfo_endpoint, {
    headers: { Authorization: `Bearer ${user.access_token}` },
  });
  if (!res.ok) {
    throw new Error(`userinfo: HTTP ${res.status}`);
  }
  return (await res.json()).sub;
}

// The error and error_description of a failed step.
export function describeError(err) {
  return {
    error: err?.error ?? err?.name ?? "error",
    error_description: err?.error_description ?? err?.message ?? String(err),
  };
}

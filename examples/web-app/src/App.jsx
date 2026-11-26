import { useEffect, useRef, useState } from "react";

import { createAuth, describeError, loadConfig, userinfoSub, verifyIdToken } from "./auth.js";

const CLAIMS = ["sub", "name", "email", "email_verified", "preferred_username", "auth_time", "exp"];

function show(name, value) {
  if (name === "auth_time" || name === "exp") {
    return `${value} (${new Date(value * 1000).toISOString()})`;
  }
  return String(value);
}

export default function App() {
  const [ready, setReady] = useState(false);
  const [status, setStatus] = useState("Signed out");
  const [claims, setClaims] = useState(null);
  const [subMatches, setSubMatches] = useState(false);
  const [expires, setExpires] = useState(null);
  const [refreshes, setRefreshes] = useState(0);
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);
  const auth = useRef(null);
  const config = useRef(null);
  const started = useRef(false);

  // Checks a user the library returned, then shows it; false when a check
  // failed, which discards the user.
  async function accept(user) {
    try {
      const verified = await verifyIdToken(auth.current, config.current, user);
      const sub = await userinfoSub(auth.current, user);
      setClaims(verified);
      setSubMatches(sub === verified.sub);
      setExpires(user.expires_at);
      setStatus("Signed in");
      return true;
    } catch (err) {
      await auth.current.removeUser();
      setClaims(null);
      setSubMatches(false);
      setExpires(null);
      setStatus("Error");
      setError(describeError(err));
      return false;
    }
  }

  useEffect(() => {
    // The callback consumes a single-use code: run the start once only.
    if (started.current) {
      return;
    }
    started.current = true;
    (async () => {
      try {
        config.current = await loadConfig();
        auth.current = createAuth(config.current);
        const url = new URL(window.location.href);
        const redirect = new URL(config.current.redirect_uri);
        if (url.pathname === redirect.pathname && url.origin === redirect.origin) {
          const user = await auth.current.signinRedirectCallback();
          window.history.replaceState({}, "", "/");
          await accept(user);
        } else if (url.searchParams.has("state")) {
          // The return from the logout endpoint: /?state=...
          await auth.current.signoutRedirectCallback();
          window.history.replaceState({}, "", "/");
          setStatus("Signed out");
        }
      } catch (err) {
        window.history.replaceState({}, "", "/");
        setStatus("Error");
        setError(describeError(err));
      }
      setReady(true);
    })();
  }, []);

  // Runs one step of a button: a failure shows its error and keeps the page.
  async function run(step) {
    setError(null);
    setBusy(true);
    try {
      await step();
    } catch (err) {
      setStatus("Error");
      setError(describeError(err));
    }
    setBusy(false);
  }

  const signedIn = status === "Signed in";

  return (
    <main>
      <h1>FeatherAuth example web app</h1>
      {ready && <p id="status">{status}</p>}
      <p>
        {ready && !signedIn && (
          <button id="signin" disabled={busy} onClick={() => run(() => auth.current.signinRedirect())}>
            Sign in
          </button>
        )}
        {signedIn && (
          <>
            <button
              id="refresh"
              disabled={busy}
              onClick={() =>
                run(async () => {
                  // Only this button refreshes: refresh tokens rotate, so two
                  // refreshes with one token would be a reuse.
                  const user = await auth.current.signinSilent();
                  if (!user) {
                    throw new Error("the refresh returned no user");
                  }
                  if (await accept(user)) {
                    setRefreshes((n) => n + 1);
                  }
                })
              }
            >
              Refresh
            </button>{" "}
            <button id="signout" disabled={busy} onClick={() => run(() => auth.current.signoutRedirect())}>
              Sign out
            </button>
          </>
        )}
      </p>
      {signedIn && claims && (
        <>
          <p id="verified">ID token signature verified</p>
          <table id="claims">
            <tbody>
              {CLAIMS.filter((name) => claims[name] !== undefined).map((name) => (
                <tr key={name}>
                  <th>{name}</th>
                  <td>{show(name, claims[name])}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <p id="userinfo">{subMatches ? "userinfo sub matches" : "userinfo sub does not match"}</p>
          <p>
            Access token expires: <span id="expires">{new Date(expires * 1000).toISOString()}</span>
          </p>
          <p>
            Refreshes: <span id="refreshes">{refreshes}</span>
          </p>
        </>
      )}
      <div id="error">{error && `${error.error}: ${error.error_description}`}</div>
    </main>
  );
}

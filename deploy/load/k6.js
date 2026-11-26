// k6 script of the load verification (docs/DESIGN.md, Load verification),
// driven by deploy/load_test.go (build tag load). Environment:
//   BASE      base URL of the proxy in front of FeatherAuth
//   SCENARIO  readonly (userinfo and JWKS only), steady (arrival rate, mixed requests), peak (closed loop) or burst
//             (one refresh per VU at the same instant)
//   DURATION  length of the run (k6 duration)
//   RATE      requests per second of the steady scenario
//   VUS       concurrent connections of the peak scenario
//   SPREAD    1 sends a different X-Forwarded-For address with every request
//   NAME      name of the summary file /data/summary-<NAME>.json
// /data/tokens.json holds one {access_token, refresh_token} per seeded user; a
// VU keeps the refresh token of its own user (the public client rotates it on
// every use), so no two VUs use one token.
import http from 'k6/http';
import { SharedArray } from 'k6/data';
import { check } from 'k6';
import { sha256 } from 'k6/crypto';

const tokens = new SharedArray('tokens', () => JSON.parse(open('/data/tokens.json')));
const base = __ENV.BASE;
const realm = 'load';
const scenario = __ENV.SCENARIO || 'steady';
const spread = __ENV.SPREAD === '1';
const clientID = 'load-app';
const redirectURI = 'http://127.0.0.1:9/cb';
const verifier = 'load-verifier-0123456789-0123456789-0123456789-abcdefghij';
const challenge = sha256(verifier, 'base64rawurl');

const eps = ['token', 'userinfo', 'jwks', 'login_authorize', 'login_idp', 'login_callback', 'login_token'];
const thresholds = {};
for (const ep of eps) {
  thresholds[`http_req_duration{ep:${ep}}`] = ['max>=0'];
  thresholds[`http_reqs{ep:${ep}}`] = ['count>=0'];
  thresholds[`http_req_failed{ep:${ep}}`] = ['rate>=0'];
  thresholds[`checks{ep:${ep}}`] = ['rate>=0'];
}

const scenarios = {
  // burst: 1000 refreshes at the same instant, one per VU (the design's
  // "1,000 simultaneous requests").
  // readonly: userinfo and JWKS only, with the access tokens of the seeding,
  // so the database gets no new rows (the seeding is at most 15 minutes old).
  readonly: {
    executor: 'constant-arrival-rate', rate: Number(__ENV.RATE || 20), timeUnit: '1s',
    duration: __ENV.DURATION || '10m', preAllocatedVUs: 100, maxVUs: 400,
  },
  burst: {
    executor: 'per-vu-iterations', vus: Number(__ENV.VUS || 1000), iterations: 1, maxDuration: '5m',
  },
  steady: {
    executor: 'constant-arrival-rate', rate: Number(__ENV.RATE || 20), timeUnit: '1s',
    duration: __ENV.DURATION || '10m', preAllocatedVUs: 100, maxVUs: 400,
  },
  peak: {
    executor: 'constant-vus', vus: Number(__ENV.VUS || 1000), duration: __ENV.DURATION || '5m',
  },
};

export const options = {
  insecureSkipTLSVerify: true,
  scenarios: { [scenario]: scenarios[scenario] },
  thresholds,
  summaryTrendStats: ['avg', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
};

let st = null; // per VU: its user, refresh token, access token and its age

let sent = 0; // requests of this VU, to make every source address its own

function headers(extra) {
  const h = Object.assign({}, extra);
  if (spread) {
    // A different address for every request of every VU (10.x.x.x to 11.x.x.x,
    // outside the proxies' network), without Math.random, which gives the VUs
    // the same sequence.
    sent++;
    h['X-Forwarded-For'] = `${10 + (__VU >> 8)}.${__VU & 255}.${(sent >> 8) & 255}.${sent & 255}`;
  }
  return h;
}

function refresh() {
  const res = http.post(`${base}/${realm}/token`,
    { grant_type: 'refresh_token', client_id: clientID, refresh_token: st.refresh },
    { headers: headers(), tags: { ep: 'token' }, responseType: 'text' });
  const ok = check(res, { 'status is 200': (r) => r.status === 200 }, { ep: 'token' });
  if (ok) {
    const b = res.json();
    st.refresh = b.refresh_token;
    st.access = b.access_token;
    st.accessAt = Date.now();
  }
}

function userinfo() {
  // readonly never refreshes: it must add no rows
  if (scenario !== 'readonly' && (!st.access || Date.now() - st.accessAt > 10 * 60 * 1000)) {
    refresh();
  }
  const res = http.get(`${base}/${realm}/userinfo`,
    { headers: headers({ Authorization: `Bearer ${st.access}` }), tags: { ep: 'userinfo' }, responseType: 'text' });
  check(res, { 'status is 200': (r) => r.status === 200 }, { ep: 'userinfo' });
}

function jwks() {
  const res = http.get(`${base}/${realm}/jwks.json`, { headers: headers(), tags: { ep: 'jwks' }, responseType: 'text' });
  check(res, { 'status is 200': (r) => r.status === 200 }, { ep: 'jwks' });
}

// login runs one login through the mock identity provider: the authorize
// request, the mock's redirect, FeatherAuth's callback and the code exchange.
function login() {
  const q = `client_id=${clientID}&redirect_uri=${encodeURIComponent(redirectURI)}&response_type=code&scope=openid` +
    `&state=st-${__VU}-${__ITER}&nonce=n-${__VU}&code_challenge=${challenge}&code_challenge_method=S256`;
  const step = (url, ep, params) => {
    const res = http.get(url, Object.assign({ redirects: 0, headers: headers(), tags: { ep }, responseType: 'text' }, params));
    check(res, { 'status is 302': (r) => r.status === 302 }, { ep });
    return res;
  };
  const a = step(`${base}/${realm}/authorize?${q}`, 'login_authorize');
  if (a.status !== 302) return;
  const m = step(a.headers['Location'], 'login_idp');
  if (m.status !== 302) return;
  const c = step(m.headers['Location'], 'login_callback');
  if (c.status !== 302) return;
  const code = /[?&]code=([^&]+)/.exec(c.headers['Location']);
  if (!code) {
    check(null, { 'code delivered': () => false }, { ep: 'login_callback' });
    return;
  }
  const t = http.post(`${base}/${realm}/token`,
    { grant_type: 'authorization_code', client_id: clientID, code: code[1], redirect_uri: redirectURI, code_verifier: verifier },
    { headers: headers(), tags: { ep: 'login_token' }, responseType: 'text' });
  check(t, { 'status is 200': (r) => r.status === 200 }, { ep: 'login_token' });
}

export default function () {
  let r;
  if (st === null) {
    st = { user: (__VU - 1) % tokens.length, refresh: null, access: null, accessAt: 0 };
    st.refresh = tokens[st.user].refresh_token;
    if (scenario === 'readonly') {
      st.access = tokens[st.user].access_token;
      st.accessAt = Date.now();
    }
  }
  if (scenario === 'readonly') {
    (Math.random() < 0.5 ? userinfo : jwks)();
  } else if (scenario === 'burst') {
    refresh();
  } else if (scenario === 'peak') {
    // the peak mixes /token (refresh), /userinfo and /jwks.json equally
    [refresh, userinfo, jwks][__ITER % 3]();
  } else if ((r = Math.random()) < 0.05) {
    login(); // about 5%: login callbacks
  } else if (r < 0.45) {
    refresh(); // 40%
  } else if (r < 0.80) {
    userinfo(); // 35%
  } else {
    jwks(); // 20%
  }
}

export function handleSummary(data) {
  return { [`/data/summary-${__ENV.NAME || 'run'}.json`]: JSON.stringify(data) };
}

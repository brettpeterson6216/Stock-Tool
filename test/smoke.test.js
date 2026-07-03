// ============================================================
//  Smoke tests — ImpliedLens server
//
//  Uses node:test (built-in, Node ≥ 18) and node:assert.
//  Starts the Express server against an in-memory SQLite DB
//  so no external services are required.
//
//  Run with:  node --test test/smoke.test.js
// ============================================================
"use strict";

const { test, before, after } = require("node:test");
const assert  = require("node:assert/strict");
const fs      = require("node:fs");
const http    = require("node:http");
const os      = require("node:os");
const path    = require("node:path");

const testDbPath = path.join(os.tmpdir(), `il-smoke-test-${process.pid}.db`).replace(/\\/g, "/");
try { fs.unlinkSync(testDbPath); } catch (_) {}
const legacyCss = fs.readFileSync(path.join(__dirname, "..", "public", "legacy-app.css"), "utf8");

// ── Configure test environment before requiring app modules ──
process.env.NODE_ENV        = "test";
process.env.TURSO_URL       = `file:${testDbPath}`;
process.env.TURSO_AUTH_TOKEN = "";
process.env.SESSION_SECRET  = "smoke-test-secret-do-not-use-in-prod";
process.env.FINNHUB_KEY     = "test-key";
process.env.ADMIN_SECRET    = "test-admin-secret-abc123";
process.env.PORT            = "0"; // OS picks free port

let server, baseUrl;
const nativeFetch = global.fetch;
const externalFetches = [];

// Keep smoke tests deterministic and fast: local app requests stay real,
// while external market providers are represented as unavailable.
global.fetch = (url, options) => {
  const target = String(url);
  if (target.startsWith("http://127.0.0.1:")) return nativeFetch(url, options);
  externalFetches.push(target);
  return Promise.resolve(new Response(JSON.stringify({ error: "upstream unavailable in smoke test" }), {
    status: 503,
    headers: { "Content-Type": "application/json" },
  }));
};

// ── Helpers ───────────────────────────────────────────────────
async function req(path, opts = {}) {
  return fetch(baseUrl + path, {
    redirect: "manual",
    ...opts,
    headers: { "Content-Type": "application/json", ...(opts.headers || {}) },
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
}

function cookieFromResponse(response) {
  // Extract individual Set-Cookie headers safely.
  // Node 18+ fetch (undici) supports getSetCookie(); fall back to comma-join split.
  let rawCookies;
  if (typeof response.headers.getSetCookie === "function") {
    rawCookies = response.headers.getSetCookie();
  } else {
    const joined = response.headers.get("set-cookie") || "";
    // rudimentary split that avoids splitting on commas inside cookie values
    rawCookies = joined ? [joined] : [];
  }
  // Keep only name=value from each Set-Cookie (strip Path, HttpOnly, etc.)
  const cookie = rawCookies
    .map(c => c.split(";")[0].trim())
    .filter(Boolean)
    .join("; ");
  return cookie;
}

async function loginSession(identifier, password = "Password123") {
  const loginRes = await req("/api/auth/login", {
    method: "POST",
    body: { identifier, password },
  });
  const cookie = cookieFromResponse(loginRes);
  // Fetch CSRF token for this session
  const csrfRes = await req("/api/csrf", { headers: { cookie } });
  const { token } = await csrfRes.json();
  return { cookie, csrfToken: token };
}

// Sign up, log in and return { cookie, csrfToken }
async function makeSession(username, email, password = "Password123") {
  await req("/api/auth/signup", {
    method: "POST",
    body: { username, email, password },
  });
  return loginSession(email, password);
}

// ── Lifecycle ─────────────────────────────────────────────────
before(async () => {
  const { initDb } = require("../lib/db");
  const app        = require("../server"); // returns express app when required from tests
  await initDb();

  await new Promise((resolve, reject) => {
    server = app.listen(0, "127.0.0.1", () => {
      const port = server.address().port;
      baseUrl = `http://127.0.0.1:${port}`;
      resolve();
    });
    server.once("error", reject);
  });
});

after(async () => {
  if (server) await new Promise(resolve => server.close(resolve));
  try { require("../lib/db").db.close(); } catch (_) {}
  global.fetch = nativeFetch;
  // Clean up test DB
  try { require("node:fs").unlinkSync(testDbPath); } catch (_) {}
});

// ═══════════════════════════════════════════════════════════════
//  1. CSRF protection
// ═══════════════════════════════════════════════════════════════
test("GET / serves the homepage with a successful status", async () => {
  const res = await req("/");
  assert.equal(res.status, 200);
  const html = await res.text();
  assert.match(html, /ImpliedLens/);
  assert.match(html, /Create free account for 5\/day/);
  assert.match(html, /function startGuestSignup/);
  assert.match(html, /analysis_resumed_after_auth/);
  assert.match(html, /function openBillingPortal/);
  assert.match(html, /ImpliedLensMath\.annualizedVolatility\(c,252\)\*100/);
  assert.match(html, /const _initialParams = new URLSearchParams\(window\.location\.search\)/);
  assert.match(html, /!document\.getElementById\('sec-' \+ id\)/);
  assert.match(html, /const activeSection = new URLSearchParams\(window\.location\.search\)\.get\('section'\)/);
  assert.match(html, /Build an AI Portfolio Guide you can actually understand/);
  assert.match(html, /Illustrative AAPL workspace/);
  assert.match(html, /function setPricingPeriod\(period\)/);
  assert.match(html, /id="mbn-workspace"/);
  assert.match(html, /aria-label="Home"/);
  assert.match(html, /viewport-fit=cover/);
  assert.match(html, /legacy-app\.css\?v=20260703-2/);
  assert.match(legacyCss, /input,select,textarea\{font-size:16px!important\}/);
  assert.match(legacyCss, /#main-nav\[data-view="tool"\] #nav-ticker-bar\{display:none!important\}/);
  assert.match(legacyCss, /\.nav-acct-wrap,\.nav-acct-btn\{min-width:0;max-width:100%\}/);
  assert.match(legacyCss, /\.nav-acct-menu\{right:0;min-width:min\(220px,calc\(100vw - 1\.5rem\)\)/);
  assert.match(html, /workspace-system\.js\?v=20260703-6/);
  assert.match(html, /workspace-system\.css\?v=20260702-1/);
  assert.match(html, /__initialWorkspaceTab/);
  assert.match(res.headers.get("cache-control"), /no-cache/);
});

test("Public brand and acquisition pages are available", async () => {
  for (const [path, marker] of [["/research-process", "Research the business"], ["/compound-calculator", "Compound Interest Scenario Calculator"]]) {
    const res = await req(path);
    assert.equal(res.status, 200);
    assert.match(await res.text(), new RegExp(marker));
  }
});

test("Direct HTML pages are never served with long-lived browser caching", async () => {
  for (const pagePath of ["/login.html", "/signup.html", "/admin-analytics.html"]) {
    const res = await req(pagePath);
    assert.equal(res.status, 200);
    assert.match(res.headers.get("cache-control"), /no-cache/);
  }
});

test("Sitemap exposes the expanded curated ticker acquisition set", async () => {
  const res = await req("/sitemap.xml");
  assert.equal(res.status, 200);
  assert.match(res.headers.get("content-type"), /application\/xml/);
  const xml = await res.text();
  const stockUrls = xml.match(/<loc>[^<]+\/stock\//g) || [];
  assert.ok(stockUrls.length >= 100, "sitemap should include at least 100 curated ticker pages");
  assert.match(xml, /\/stock\/AAPL<\/loc>/);
  assert.match(xml, /\/stock\/XLU<\/loc>/);
});

test("Ticker landing pages explain free allowances and protect uncurated pages from indexing", async () => {
  const curated = await req("/stock/AAPL");
  assert.equal(curated.status, 200);
  const curatedHtml = await curated.text();
  assert.match(curatedHtml, /<meta name="robots" content="index,follow">/);
  assert.match(curatedHtml, /Guests get 2 analyses\/day/);
  assert.match(curatedHtml, /Create a free account for 5\/day/);
  assert.match(curatedHtml, /landing_page_view/);
  assert.match(curatedHtml, /Questions to answer before investing in AAPL/);
  assert.match(curatedHtml, /<meta property="og:image"\s+content="[^"]+\/social-card\.png">/);
  assert.match(curatedHtml, /<meta name="twitter:card"\s+content="summary_large_image">/);
  assert.match(curatedHtml, /<meta name="twitter:image"\s+content="[^"]+\/social-card\.png">/);

  const uncurated = await req("/stock/NOTREAL");
  assert.equal(uncurated.status, 200);
  assert.match(await uncurated.text(), /<meta name="robots" content="noindex,follow">/);
});

test("Ticker landing pages reject malformed symbols instead of creating junk pages", async () => {
  for (const pagePath of ["/stock/AAPL!", "/stock/%3Ftoken%3Devil", "/stock/THIS-TICKER-IS-FAR-TOO-LONG"]) {
    const res = await req(pagePath);
    assert.equal(res.status, 404);
  }
});

test("Auth pages preserve a local return path and expose attribution hooks", async () => {
  for (const [pagePath, marker] of [["/signup", "signup_page_viewed"], ["/login", "login_page_viewed"]]) {
    const res = await req(`${pagePath}?next=https%3A%2F%2Fevil.example%2Fsteal&source=smoke&ticker=AAPL`);
    assert.equal(res.status, 200);
    const html = await res.text();
    assert.match(html, /function safeNext/);
    assert.match(html, new RegExp(marker));
    assert.match(html, /body: JSON\.stringify\(\{ [^}]*analytics/);
  }
});

test("Public pages expose canonical, favicon, and social metadata", async () => {
  for (const pagePath of ["/about", "/blog", "/data-sources", "/privacy", "/terms", "/research-process", "/compound-calculator"]) {
    const res = await req(pagePath);
    assert.equal(res.status, 200);
    const html = await res.text();
    assert.match(html, new RegExp(`<link rel="canonical" href="https://impliedlens\\.com${pagePath}">`));
    assert.match(html, /<link rel="icon" type="image\/svg\+xml" href="\/logo\.svg">/);
    assert.match(html, /<meta property="og:title"/);
    assert.match(html, /<meta property="og:description"/);
    assert.match(html, /<meta property="og:image" content="https:\/\/impliedlens\.com\/social-card\.png">/);
    assert.match(html, /<meta property="og:image:width" content="1200">/);
    assert.match(html, /<meta name="twitter:card" content="summary_large_image">/);
    assert.match(html, /<meta name="twitter:image" content="https:\/\/impliedlens\.com\/social-card\.png">/);
  }
});

test("GET /social-card.png serves a large PNG social preview", async () => {
  const res = await req("/social-card.png");
  assert.equal(res.status, 200);
  assert.match(res.headers.get("content-type"), /image\/png/);
  assert.ok(Number(res.headers.get("content-length")) > 100000);
});

test("GET /gold-ripple-background.jpg serves the shared gold backdrop", async () => {
  const res = await req("/gold-ripple-background.jpg");
  assert.equal(res.status, 200);
  assert.match(res.headers.get("content-type"), /image\/jpeg/);
  assert.ok(Number(res.headers.get("content-length")) > 100000);
});

test("GET /favicon.ico serves the brand mark", async () => {
  const res = await req("/favicon.ico");
  assert.equal(res.status, 200);
  assert.match(res.headers.get("content-type"), /image\/svg\+xml/);
  assert.match(await res.text(), /<svg/);
});

test("Apple Home Screen icon and web app manifest are available", async () => {
  const home = await req("/");
  const html = await home.text();
  assert.match(html, /<link rel="apple-touch-icon" sizes="180x180" href="\/apple-touch-icon\.png">/);
  assert.match(html, /<link rel="manifest" href="\/site\.webmanifest">/);

  for (const asset of ["/apple-touch-icon.png", "/app-icon-192.png", "/app-icon-512.png"]) {
    const res = await req(asset);
    assert.equal(res.status, 200);
    assert.match(res.headers.get("content-type"), /image\/png/);
    assert.ok(Number(res.headers.get("content-length")) > 10000);
  }

  const manifest = await req("/site.webmanifest");
  assert.equal(manifest.status, 200);
  assert.match(manifest.headers.get("content-type"), /manifest\+json|application\/json/);
  const data = await manifest.json();
  assert.equal(data.short_name, "ImpliedLens");
  assert.equal(data.theme_color, "#f9f8f5");
});

test("GET /healthz reports database and build health", async () => {
  const res = await req("/healthz");
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.ok, true);
  assert.equal(body.database, "ok");
  assert.ok(body.version);
  assert.ok(body.commit);
  assert.equal(res.headers.get("cache-control"), "no-store");
});

test("GET / compresses the homepage when the client accepts gzip", async () => {
  const res = await req("/", { headers: { "Accept-Encoding": "gzip" } });
  assert.equal(res.status, 200);
  assert.equal(res.headers.get("content-encoding"), "gzip");
});

test("GET /api/version exposes the running build", async () => {
  const res = await req("/api/version");
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.ok(body.version);
  assert.ok(body.startedAt);
  assert.equal(res.headers.get("cache-control"), "no-store");
});

test("POST /api/auth/logout without CSRF token returns 403", async () => {
  const { cookie } = await makeSession("csrf_user1", "csrf1@test.com");
  const res = await req("/api/auth/logout", {
    method: "POST",
    headers: { cookie },
    // no X-CSRF-Token header
  });
  assert.equal(res.status, 403, "should reject logout without CSRF");
});

test("POST /api/auth/logout with wrong CSRF token returns 403", async () => {
  const { cookie } = await makeSession("csrf_user2", "csrf2@test.com");
  const res = await req("/api/auth/logout", {
    method: "POST",
    headers: { cookie, "X-CSRF-Token": "wrong-token" },
  });
  assert.equal(res.status, 403, "should reject logout with wrong CSRF token");
});

test("POST /api/auth/logout with correct CSRF token succeeds", async () => {
  const { cookie, csrfToken } = await makeSession("csrf_user3", "csrf3@test.com");
  const res = await req("/api/auth/logout", {
    method: "POST",
    headers: { cookie, "X-CSRF-Token": csrfToken },
  });
  assert.equal(res.status, 200, "should accept logout with correct CSRF token");
});

test("Usernames are normalized and enforced case-insensitively", async () => {
  const first = await req("/api/auth/signup", {
    method: "POST",
    body: { username: "CaseUser", email: "case_user1@test.com", password: "Password123" },
  });
  assert.equal(first.status, 201);
  assert.equal((await first.json()).user.username, "caseuser");

  const duplicate = await req("/api/auth/signup", {
    method: "POST",
    body: { username: "CASEUSER", email: "case_user2@test.com", password: "Password123" },
  });
  assert.equal(duplicate.status, 409);

  const login = await req("/api/auth/login", {
    method: "POST",
    body: { identifier: "CaSeUsEr", password: "Password123" },
  });
  assert.equal(login.status, 200);
});

test("Changing a password rotates the current session and invalidates other sessions", async () => {
  await req("/api/auth/signup", {
    method: "POST",
    body: { username: "password_sessions", email: "password_sessions@test.com", password: "Password123" },
  });
  const first = await loginSession("password_sessions@test.com");
  const second = await loginSession("password_sessions@test.com");

  const changed = await req("/api/auth/change-password", {
    method: "POST",
    headers: { cookie: first.cookie, "X-CSRF-Token": first.csrfToken },
    body: { currentPassword: "Password123", newPassword: "NewPassword456" },
  });
  assert.equal(changed.status, 200);
  const changedBody = await changed.json();
  assert.equal(changedBody.ok, true);
  assert.equal(changedBody.csrfToken.length, 64);

  const rotatedCookie = cookieFromResponse(changed);
  const current = await req("/api/auth/me", { headers: { cookie: rotatedCookie } });
  assert.equal((await current.json()).user.email, "password_sessions@test.com");

  const other = await req("/api/auth/me", { headers: { cookie: second.cookie } });
  assert.equal((await other.json()).user, null);
  assert.equal((await req("/api/auth/login", { method: "POST", body: { identifier: "password_sessions@test.com", password: "Password123" } })).status, 401);
  assert.equal((await req("/api/auth/login", { method: "POST", body: { identifier: "password_sessions@test.com", password: "NewPassword456" } })).status, 200);
});

test("Account changes enforce username and password length limits", async () => {
  const { cookie, csrfToken } = await makeSession("account_limits", "account_limits@test.com");
  const username = await req("/api/auth/change-username", {
    method: "POST",
    headers: { cookie, "X-CSRF-Token": csrfToken },
    body: { username: "a".repeat(33) },
  });
  assert.equal(username.status, 400);

  const password = await req("/api/auth/change-password", {
    method: "POST",
    headers: { cookie, "X-CSRF-Token": csrfToken },
    body: { currentPassword: "Password123", newPassword: "a".repeat(201) },
  });
  assert.equal(password.status, 400);
});

// ═══════════════════════════════════════════════════════════════
//  2. Cloud saves — free registered users
// ═══════════════════════════════════════════════════════════════
test("Free user can POST to /api/saves (cloud saves are free)", async () => {
  const { cookie, csrfToken } = await makeSession("free_saver", "free_saver@test.com");
  const res = await req("/api/saves", {
    method: "POST",
    headers: { cookie, "X-CSRF-Token": csrfToken },
    body: { ticker: "AAPL", type: "price", label: "Test save", data: { note: "test" } },
  });
  assert.equal(res.status, 200, "free user should be able to save analysis");
  const body = await res.json();
  assert.ok(body.ok, "response should have ok:true");
  assert.ok(typeof body.id === "number", "response should return numeric id");
});

test("Saved analyses reject invalid tickers and malformed payloads", async () => {
  const { cookie, csrfToken } = await makeSession("save_validation", "save_validation@test.com");
  const headers = { cookie, "X-CSRF-Token": csrfToken };
  assert.equal((await req("/api/saves", { method: "POST", headers, body: { ticker: "?bad", type: "price", data: {} } })).status, 400);
  assert.equal((await req("/api/saves", { method: "POST", headers, body: { ticker: "AAPL", type: "price", data: [] } })).status, 400);
});

test("Guest (no session) cannot POST to /api/saves", async () => {
  const res = await req("/api/saves", {
    method: "POST",
    body: { ticker: "AAPL", type: "price", label: "Guest save", data: {} },
    // no cookie, no CSRF
  });
  // CSRF check fires first (403), or auth check (401) — either means blocked
  assert.ok([401, 403].includes(res.status), `expected 401 or 403, got ${res.status}`);
});

test("Free user can GET saved analyses", async () => {
  const { cookie } = await makeSession("free_reader", "free_reader@test.com");
  const res = await req("/api/saves", { headers: { cookie } });
  assert.equal(res.status, 200, "free user can read their saves");
  const body = await res.json();
  assert.ok(Array.isArray(body), "saves response should be an array");
});

test("Guest cannot read the synced investment workspace", async () => {
  const res = await req("/api/workspace/theses");
  assert.equal(res.status, 401);
});

test("Authenticated user can create, update, read, and delete a thesis", async () => {
  const { cookie, csrfToken } = await makeSession("workspace_thesis", "workspace_thesis@test.com");
  const headers = { cookie, "X-CSRF-Token": csrfToken };
  const created = await req("/api/workspace/theses/AMD", {
    method: "PUT", headers,
    body: { status: "watching", thesis: "Data-center share expands.", catalysts: ["MI-series adoption"], risks: ["Execution"], sell_conditions: ["Share loss"], target_price: 220, bear_price: 110, conviction: 4 },
  });
  assert.equal(created.status, 200);
  assert.equal((await created.json()).conviction, 4);

  const list = await req("/api/workspace/theses", { headers: { cookie } });
  const rows = await list.json();
  assert.equal(rows.length, 1);
  assert.deepEqual(rows[0].catalysts, ["MI-series adoption"]);

  const removed = await req("/api/workspace/theses/AMD", { method: "DELETE", headers });
  assert.equal(removed.status, 200);
});

test("Thesis review dates must be real calendar dates", async () => {
  const { cookie, csrfToken } = await makeSession("workspace_dates", "workspace_dates@test.com");
  const headers = { cookie, "X-CSRF-Token": csrfToken };
  for (const reviewDate of ["not-a-date", "2026-02-30"]) {
    const res = await req("/api/workspace/theses/AAPL", {
      method: "PUT",
      headers,
      body: { thesis: "Validate the date", review_date: reviewDate, conviction: 3 },
    });
    assert.equal(res.status, 400);
  }
});

test("Authenticated user can maintain portfolio positions and watchlist items", async () => {
  const { cookie, csrfToken } = await makeSession("workspace_assets", "workspace_assets@test.com");
  const headers = { cookie, "X-CSRF-Token": csrfToken };
  const position = await req("/api/workspace/positions/MSFT", { method: "PUT", headers, body: { shares: 2.5, cost_basis: 400, sector: "Technology", notes: "Core" } });
  assert.equal(position.status, 200);
  assert.equal((await position.json()).shares, 2.5);
  const watch = await req("/api/workspace/watchlist/NVDA", { method: "PUT", headers, body: { target_price: 190, note: "Wait for valuation" } });
  assert.equal(watch.status, 200);

  const summary = await req("/api/workspace/summary", { headers: { cookie } });
  const body = await summary.json();
  assert.equal(body.positions, 1);
  assert.equal(body.watchlist, 1);
  assert.equal(body.invested, 1000);

  assert.equal((await req("/api/workspace/positions/MSFT", { method: "DELETE", headers })).status, 200);
  assert.equal((await req("/api/workspace/watchlist/NVDA", { method: "DELETE", headers })).status, 200);
});

test("Workspace mutations require CSRF protection", async () => {
  const { cookie } = await makeSession("workspace_csrf", "workspace_csrf@test.com");
  const res = await req("/api/workspace/watchlist/AAPL", { method: "PUT", headers: { cookie }, body: { note: "No token" } });
  assert.equal(res.status, 403);
});

test("Portfolio guide is member-only, validated, saved, and totals 100 percent", async () => {
  assert.equal((await req("/api/workspace/portfolio-profile")).status, 401);
  const { cookie, csrfToken } = await makeSession("portfolio_guide", "portfolio_guide@test.com");
  const headers = { cookie, "X-CSRF-Token": csrfToken };
  const invalid = await req("/api/workspace/portfolio-profile", { method: "PUT", headers, body: { goal: "growth" } });
  assert.equal(invalid.status, 400);

  const saved = await req("/api/workspace/portfolio-profile", {
    method: "PUT",
    headers,
    body: {
      goal: "growth",
      horizon_years: 18,
      risk_tolerance: "aggressive",
      liquidity_need: "low",
      experience: "experienced",
      income_stability: "very_stable",
      preference: "active",
    },
  });
  assert.equal(saved.status, 200);
  const profile = await saved.json();
  assert.equal(profile.model.archetype, "Growth");
  assert.equal(profile.model.educationalOnly, true);
  assert.equal(profile.model.allocations.reduce((sum, row) => sum + row.percent, 0), 100);
  assert.ok(profile.model.allocations.some(row => row.asset === "Research sleeve"));

  const fetched = await req("/api/workspace/portfolio-profile", { headers: { cookie } });
  assert.equal(fetched.status, 200);
  assert.equal((await fetched.json()).goal, "growth");
  const summary = await req("/api/workspace/summary", { headers: { cookie } });
  assert.equal((await summary.json()).activation.portfolioProfile, true);
});

test("Review digest requires a scheduled review and is concurrency-safe per day", async () => {
  const { cookie, csrfToken } = await makeSession("review_digest", "review_digest@test.com");
  const headers = { cookie, "X-CSRF-Token": csrfToken };
  const empty = await req("/api/workspace/review-reminder", { method: "POST", headers, body: {} });
  assert.equal(empty.status, 400);

  const today = new Date().toISOString().slice(0, 10);
  assert.equal((await req("/api/workspace/theses/AAPL", {
    method: "PUT",
    headers,
    body: { thesis: "Review the evidence", review_date: today, conviction: 3 },
  })).status, 200);
  const attempts = await Promise.all([
    req("/api/workspace/review-reminder", { method: "POST", headers, body: {} }),
    req("/api/workspace/review-reminder", { method: "POST", headers, body: {} }),
  ]);
  assert.ok(attempts.every(response => response.status === 200));
  const results = await Promise.all(attempts.map(response => response.json()));
  assert.deepEqual(results.map(result => result.alreadySent).sort(), [false, true]);
  const duplicate = await req("/api/workspace/review-reminder", { method: "POST", headers, body: {} });
  assert.equal(duplicate.status, 200);
  assert.equal((await duplicate.json()).alreadySent, true);
});

test("Resend responses are only successful when a delivery id is returned", () => {
  const { interpretResendResponse } = require("../lib/email");
  assert.equal(interpretResendResponse({ data: null, error: { message: "Rejected" } }).sent, false);
  assert.equal(interpretResendResponse({ data: null, error: null }).sent, false);
  assert.deepEqual(interpretResendResponse({ data: { id: "email_1" }, error: null }), {
    sent: true,
    simulated: false,
    id: "email_1",
  });
});

test("Provider health endpoint exposes an observation snapshot", async () => {
  const res = await req("/api/providers/health");
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.ok(Array.isArray(body.providers));
  assert.ok(["observing", "operational", "stale", "degraded"].includes(body.status));
  assert.equal(typeof body.stale, "boolean");
  assert.equal(typeof body.message, "string");
});

test("Provider health marks old successful observations as stale", () => {
  const { recordProvider, snapshot } = require("../lib/provider-health");
  const realNow = Date.now;
  recordProvider("Stale provider test", true, 12);
  try {
    Date.now = () => realNow() + 16 * 60 * 1000;
    const body = snapshot();
    assert.equal(body.status, "stale");
    assert.equal(body.stale, true);
  } finally {
    Date.now = realNow;
  }
});

test("Honest feedback analytics events are accepted", async () => {
  const res = await req("/api/track", { method: "POST", body: { event: "feedback_rated", properties: { rating: 1 } } });
  assert.equal(res.status, 200);
  assert.equal((await res.json()).ok, true);
});

test("Growth funnel events are accepted and unknown client events are rejected", async () => {
  for (const event of [
    "landing_page_view", "landing_cta_clicked", "guest_signup_prompt_viewed",
    "guest_signup_started", "signup_page_viewed", "analysis_resumed_after_auth",
    "checkout_requires_login", "signup_started_from_upgrade",
    "checkout_resumed_after_auth", "checkout_blocked_unverified",
    "activation_checklist_viewed", "thesis_saved", "watchlist_saved", "position_saved",
    "portfolio_questionnaire_started", "portfolio_profile_saved", "portfolio_guide_viewed",
    "review_reminder_requested", "billing_portal_opened", "checkout_cancelled",
  ]) {
    const res = await req("/api/track", { method: "POST", body: { event, properties: { ticker: "AAPL" } } });
    assert.equal(res.status, 200, `${event} should be accepted`);
  }
  const unknown = await req("/api/track", { method: "POST", body: { event: "made_up_growth_event" } });
  assert.equal(unknown.status, 400);
});

test("Anonymous funnel analytics use a stable hashed guest actor", async () => {
  const cookieRes = await req("/api/csrf");
  const setCookie = cookieRes.headers.get("set-cookie") || "";
  const gid = (setCookie.match(/il_gid=([^;]+)/) || [])[1];
  assert.ok(gid);
  const cookie = `il_gid=${gid}`;

  for (const event of ["landing_page_view", "landing_cta_clicked"]) {
    const res = await req("/api/track", {
      method: "POST",
      headers: { cookie },
      body: { event, properties: { ticker: "SMOKE" } },
    });
    assert.equal(res.status, 200);
  }

  const { db } = require("../lib/db");
  const tracked = await db.execute({
    sql: "SELECT properties FROM analytics_events WHERE event IN ('landing_page_view','landing_cta_clicked') AND json_extract(properties, '$.ticker') = 'SMOKE' ORDER BY id",
  });
  const actors = tracked.rows.map(row => JSON.parse(row.properties).guest_actor);
  assert.equal(actors.length, 2);
  assert.equal(actors[0], actors[1]);
  assert.equal(actors[0].length, 24);
  assert.notEqual(actors[0], gid);

  const admin = await req("/api/admin/analytics", { headers: { "X-Admin-Secret": process.env.ADMIN_SECRET } });
  assert.equal(admin.status, 200);
  const body = await admin.json();
  assert.ok(Array.isArray(body.uniqueFunnel));
  assert.ok(Array.isArray(body.acquisitionByTicker));
  assert.ok(Array.isArray(body.activation));
  assert.ok(body.retention && typeof body.retention === "object");
  const smoke = body.acquisitionByTicker.find(row => row.ticker === "SMOKE");
  assert.equal(Number(smoke.unique_views), 1);
  assert.equal(Number(smoke.unique_ctas), 1);
});

// ═══════════════════════════════════════════════════════════════
//  3. Pro gate — free users get 403 on Pro endpoints
// ═══════════════════════════════════════════════════════════════
test("Free user gets 403 on /api/financials/:ticker", async () => {
  const { cookie } = await makeSession("pro_gate_user", "progate@test.com");
  const res = await req("/api/financials/AAPL", { headers: { cookie } });
  assert.equal(res.status, 403, "free user should get 403 on Pro-gated financials");
  const body = await res.json();
  assert.ok(body.requiresPro, "response should indicate Pro required");
});

test("Earnings-call research is Pro-gated", async () => {
  const { cookie } = await makeSession("calls_gate_user", "calls_gate@test.com");
  const res = await req("/api/calls/AAPL", { headers: { cookie } });
  assert.equal(res.status, 403);
  assert.equal((await res.json()).requiresPro, true);
});

test("Pro earnings-call research degrades gracefully when transcripts are unavailable", async () => {
  const email = "calls_pro@test.com";
  const { cookie, csrfToken } = await makeSession("calls_pro_user", email);
  const granted = await req("/api/admin/grant-pro", {
    method: "POST",
    headers: { cookie, "X-CSRF-Token": csrfToken, "X-Admin-Secret": process.env.ADMIN_SECRET },
    body: { email },
  });
  assert.equal(granted.status, 200);
  const res = await req("/api/calls/AAPL", { headers: { cookie } });
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.deepEqual(body.transcripts, []);
  assert.match(body.links.sec, /sec\.gov/);
});

test("Pro users do not receive free analysis quota state", async () => {
  const email = "limit_pro@test.com";
  const { cookie, csrfToken } = await makeSession("limit_pro_user", email);
  assert.equal((await req("/api/admin/grant-pro", {
    method: "POST",
    headers: { cookie, "X-CSRF-Token": csrfToken, "X-Admin-Secret": process.env.ADMIN_SECRET },
    body: { email },
  })).status, 200);
  const res = await req("/api/me/limit", { headers: { cookie } });
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.plan, "pro");
  assert.equal(body.limit, null);
  assert.equal(body.remaining, null);
});

test("Pro data routes reject malformed tickers before contacting providers", async () => {
  const email = "pro_ticker_validation@test.com";
  const { cookie, csrfToken } = await makeSession("pro_ticker_validation", email);
  assert.equal((await req("/api/admin/grant-pro", {
    method: "POST",
    headers: { cookie, "X-CSRF-Token": csrfToken, "X-Admin-Secret": process.env.ADMIN_SECRET },
    body: { email },
  })).status, 200);
  externalFetches.length = 0;
  const res = await req("/api/analyst/%3Ftoken%3Devil", { headers: { cookie } });
  assert.equal(res.status, 400);
  assert.equal(externalFetches.length, 0);
});

test("Guest gets 401 on /api/financials/:ticker", async () => {
  const res = await req("/api/financials/AAPL");
  assert.equal(res.status, 401, "guest should get 401 on Pro-gated route");
  const body = await res.json();
  assert.ok(body.requiresLogin, "response should indicate login required");
});

test("Free user gets 403 on /api/sec/:ticker", async () => {
  const { cookie } = await makeSession("sec_gate_user", "secgate@test.com");
  const res = await req("/api/sec/AAPL", { headers: { cookie } });
  assert.equal(res.status, 403, "free user should get 403 on SEC endpoint");
});

// ═══════════════════════════════════════════════════════════════
//  4. Admin endpoint hardening
// ═══════════════════════════════════════════════════════════════
test("Admin route rejects request with no secret", async () => {
  // Must have CSRF too — get a session first
  const { cookie, csrfToken } = await makeSession("admin_test1", "admintest1@test.com");
  const res = await req("/api/admin/grant-pro", {
    method: "POST",
    headers: { cookie, "X-CSRF-Token": csrfToken },
    body: { email: "admintest1@test.com" },
  });
  assert.equal(res.status, 403, "should reject missing admin secret");
});

test("Admin route rejects request with wrong secret", async () => {
  const { cookie, csrfToken } = await makeSession("admin_test2", "admintest2@test.com");
  const res = await req("/api/admin/grant-pro", {
    method: "POST",
    headers: { cookie, "X-CSRF-Token": csrfToken, "X-Admin-Secret": "wrong-secret" },
    body: { email: "admintest2@test.com" },
  });
  assert.equal(res.status, 403, "should reject wrong admin secret");
});

test("Admin route rejects secret passed in body (header-only policy)", async () => {
  const { cookie, csrfToken } = await makeSession("admin_test3", "admintest3@test.com");
  const res = await req("/api/admin/grant-pro", {
    method: "POST",
    headers: { cookie, "X-CSRF-Token": csrfToken },
    // secret in body, not header
    body: { email: "admintest3@test.com", secret: "test-admin-secret-abc123" },
  });
  assert.equal(res.status, 403, "should reject admin secret passed in request body");
});

test("Admin route grants Pro with correct header secret", async () => {
  const { cookie, csrfToken } = await makeSession("admin_test4", "admintest4@test.com");
  const res = await req("/api/admin/grant-pro", {
    method: "POST",
    headers: {
      cookie, "X-CSRF-Token": csrfToken,
      "X-Admin-Secret": "test-admin-secret-abc123",
    },
    body: { email: "admintest4@test.com" },
  });
  assert.equal(res.status, 200, "should accept valid admin secret in header");
  const body = await res.json();
  assert.ok(body.ok, "response should have ok:true");
  assert.equal(body.action, "granted");
});

// ═══════════════════════════════════════════════════════════════
//  5. Guest quota enforcement
// ═══════════════════════════════════════════════════════════════
test("GET /api/csrf returns a token for any session", async () => {
  const res = await req("/api/csrf");
  assert.equal(res.status, 200, "/api/csrf should always return 200");
  const body = await res.json();
  assert.ok(typeof body.token === "string" && body.token.length === 64,
    "CSRF token should be a 64-char hex string");
});

test("Preview quota bypass works for AAPL with preview=1", async () => {
  // /api/quote/:ticker is not Pro-gated, but uses checkAnalysisLimit
  // with preview=1 it should not consume quota
  const res = await req("/api/quote/AAPL?range=1d&preview=1");
  // Will fail with upstream error (no real Finnhub key) but not with 429
  assert.notEqual(res.status, 429, "preview=1 should not trigger quota 429");
});

test("Market routes reject malformed tickers before contacting providers", async () => {
  externalFetches.length = 0;
  const res = await req("/api/news/%3Ftoken%3Devil");
  assert.equal(res.status, 400);
  assert.equal(externalFetches.length, 0);
});

test("Quote requests default unsupported ranges and intervals to allowlisted values", async () => {
  const { cookie } = await makeSession("quote_allowlist", "quote_allowlist@test.com");
  externalFetches.length = 0;
  const res = await req("/api/quote/RANGE?range=forever&interval=evil", { headers: { cookie } });
  assert.notEqual(res.status, 429);
  const yahooRequest = externalFetches.find(url => url.includes("/v8/finance/chart/RANGE"));
  assert.ok(yahooRequest);
  assert.match(yahooRequest, /interval=1d&range=1y/);
});

// ═══════════════════════════════════════════════════════════════
//  6. Quota dedup — one ticker = one credit per day
// ═══════════════════════════════════════════════════════════════
test("Quota dedup: repeated calls for same ticker don't multiply credits", async () => {
  const { cookie } = await makeSession("dedup_user1", "dedup1@test.com");

  // Clear the dedup cache so we start fresh (exported for tests)
  const { _dedupCache } = require("../lib/plan");
  _dedupCache.clear();

  // Call /api/quote/TSLA twice for the same user
  const r1 = await req("/api/quote/TSLA?range=1y", { headers: { cookie } });
  const r2 = await req("/api/quote/TSLA?range=1y", { headers: { cookie } });

  // Neither should be blocked (below limit)
  assert.notEqual(r1.status, 429, "First TSLA call should not be rate-limited");
  assert.notEqual(r2.status, 429, "Second TSLA call (same ticker) should not be rate-limited");

  // Used header after first call should be 1
  const used1 = Number(r1.headers.get("X-Analyses-Used"));
  assert.equal(used1, 1, "First call should report 1 analysis used");

  // Used header after second call (deduped) should still be 1
  const used2 = Number(r2.headers.get("X-Analyses-Used"));
  assert.equal(used2, 1, "Second call for same ticker should still report 1 (deduped)");
});

test("Quota dedup: different tickers each cost one credit", async () => {
  const { cookie } = await makeSession("dedup_user2", "dedup2@test.com");
  const { _dedupCache } = require("../lib/plan");
  _dedupCache.clear();

  const r1 = await req("/api/quote/AAPL?range=1y", { headers: { cookie } });
  const r2 = await req("/api/quote/MSFT?range=1y", { headers: { cookie } });
  const r3 = await req("/api/quote/NVDA?range=1y", { headers: { cookie } });

  assert.equal(Number(r1.headers.get("X-Analyses-Used")), 1, "1st ticker → 1 used");
  assert.equal(Number(r2.headers.get("X-Analyses-Used")), 2, "2nd ticker → 2 used");
  assert.equal(Number(r3.headers.get("X-Analyses-Used")), 3, "3rd ticker → 3 used");
});

test("Free user is locked out after exactly 5 distinct tickers", async () => {
  const { cookie } = await makeSession("quota_exact", "quotaexact@test.com");
  const { _dedupCache } = require("../lib/plan");
  _dedupCache.clear();

  const tickers = ["A", "B", "C", "D", "E", "F"];
  const statuses = [];
  for (const t of tickers) {
    const r = await req(`/api/quote/${t}?range=1y`, { headers: { cookie } });
    statuses.push(r.status);
  }
  // First 5 should not be 429; 6th should be 429
  assert.ok(statuses.slice(0, 5).every(s => s !== 429), "First 5 analyses should not be blocked");
  assert.equal(statuses[5], 429, "6th distinct ticker should return 429");
});

test("Free user can reopen an already-counted ticker after reaching the limit", async () => {
  const { cookie } = await makeSession("quota_reopen", "quotareopen@test.com");
  for (const ticker of ["AA", "BB", "CC", "DD", "EE"]) {
    const res = await req(`/api/quote/${ticker}?range=1y`, { headers: { cookie } });
    assert.notEqual(res.status, 429);
  }
  const reopened = await req("/api/quote/AA?range=1y", { headers: { cookie } });
  assert.notEqual(reopened.status, 429, "Previously counted ticker should remain accessible");
  assert.equal(Number(reopened.headers.get("X-Analyses-Used")), 5);
});

test("Guest gid cookie is set on first request", async () => {
  const res = await req("/api/csrf");
  const setCookie = res.headers.get("set-cookie") || "";
  assert.ok(setCookie.includes("il_gid="), "Response should set il_gid cookie");
  assert.ok(setCookie.includes("HttpOnly"), "il_gid should be HttpOnly");
  assert.ok(setCookie.includes("Max-Age="), "il_gid should have Max-Age");
});

test("Guest gid cookie is reused on subsequent requests", async () => {
  // First request — get the gid
  const r1 = await req("/api/csrf");
  const cookie1 = r1.headers.get("set-cookie") || "";
  const gidMatch = cookie1.match(/il_gid=([^;]+)/);
  assert.ok(gidMatch, "Should receive il_gid on first request");
  const gid = gidMatch[1];

  // Second request sending the gid back — should NOT set a new one
  const r2 = await req("/api/csrf", { headers: { cookie: `il_gid=${gid}` } });
  const cookie2 = r2.headers.get("set-cookie") || "";
  // If gid is valid, server should not issue a new il_gid
  assert.ok(!cookie2.includes("il_gid="), "Valid il_gid should not be re-issued");
});

// ═══════════════════════════════════════════════════════════════
//  7. Email verification
// ═══════════════════════════════════════════════════════════════
test("New signup has email_verified=0 in response", async () => {
  const res = await req("/api/auth/signup", {
    method: "POST",
    body: { username: "verif_new1", email: "verifnew1@test.com", password: "Password123" },
  });
  assert.equal(res.status, 201, "Signup should succeed");
  const body = await res.json();
  assert.equal(Number(body.user.email_verified), 0, "New user should have email_verified=0");
});

test("Signup completion records sanitized acquisition attribution", async () => {
  const res = await req("/api/auth/signup", {
    method: "POST",
    body: {
      username: "attributed_signup",
      email: "attributed@test.com",
      password: "Password123",
      analytics: {
        source: "guest_limit_counter",
        ticker: "NVDA",
        entry_path: "/signup",
        return_path: "/",
        ignored_secret: "do-not-store",
      },
    },
  });
  assert.equal(res.status, 201);
  const { db } = require("../lib/db");
  const tracked = await db.execute({
    sql: "SELECT properties FROM analytics_events WHERE event = 'signup_completed' AND user_id = (SELECT id FROM users WHERE email = ?) ORDER BY id DESC LIMIT 1",
    args: ["attributed@test.com"],
  });
  const props = JSON.parse(tracked.rows[0].properties);
  assert.equal(props.source, "guest_limit_counter");
  assert.equal(props.ticker, "NVDA");
  assert.ok(!("ignored_secret" in props));
  assert.ok(!("username" in props));
});

test("/api/auth/me returns email_verified field", async () => {
  const { cookie } = await makeSession("verif_me1", "verifme1@test.com");
  const res = await req("/api/auth/me", { headers: { cookie } });
  const body = await res.json();
  assert.ok("email_verified" in body.user, "/auth/me should include email_verified");
});

test("Checkout is blocked for unverified email", async () => {
  const { cookie, csrfToken } = await makeSession("verif_block1", "verifblock1@test.com");
  const res = await req("/api/stripe/create-checkout", {
    method: "POST",
    headers: { cookie, "X-CSRF-Token": csrfToken },
    body: { annual: false },
  });
  // 503 if Stripe not configured, 403 if email unverified — we want 403
  assert.equal(res.status, 403, "Checkout should be blocked for unverified email");
  const body = await res.json();
  assert.ok(body.requiresEmailVerification, "Response should set requiresEmailVerification flag");
});

test("Checkout rejects requests without a CSRF token", async () => {
  const { cookie } = await makeSession("checkout_csrf1", "checkoutcsrf1@test.com");
  const res = await req("/api/stripe/create-checkout", {
    method: "POST",
    headers: { cookie },
    body: { annual: false },
  });
  assert.equal(res.status, 403);
});

test("Billing portal creation is POST-only and CSRF-protected", async () => {
  const { cookie } = await makeSession("portal_csrf1", "portalcsrf1@test.com");
  assert.equal((await req("/api/stripe/portal", { headers: { cookie } })).status, 404);
  assert.equal((await req("/api/stripe/portal", { method: "POST", headers: { cookie } })).status, 403);
});

test("Verification token flow: valid token marks user verified", async () => {
  const { cookie } = await makeSession("verif_flow1", "verifflow1@test.com");
  const { db } = require("../lib/db");

  // Get the user id
  const ur = await db.execute({ sql: "SELECT id FROM users WHERE email=?", args: ["verifflow1@test.com"] });
  const userId = Number(ur.rows[0].id);

  // Manually create a valid token (simulates the email link)
  const token  = "aaaa" + "0".repeat(60);
  const expiry = Date.now() + 60 * 60 * 1000;
  await db.execute({
    sql:  "INSERT INTO email_verif_tokens (token, user_id, expires_at) VALUES (?, ?, ?)",
    args: [token, userId, expiry],
  });

  // Hit the verify route
  const res = await req(`/api/verify-email?token=${token}`);
  assert.ok([200, 301, 302].includes(res.status), "Verify route should redirect");

  // Check user is now verified
  const ur2 = await db.execute({ sql: "SELECT email_verified FROM users WHERE id=?", args: [userId] });
  assert.equal(Number(ur2.rows[0].email_verified), 1, "User should be marked verified after token use");
});

test("Expired verification token is rejected", async () => {
  const { cookie } = await makeSession("verif_exp1", "verifexp1@test.com");
  const { db } = require("../lib/db");

  const ur = await db.execute({ sql: "SELECT id FROM users WHERE email=?", args: ["verifexp1@test.com"] });
  const userId = Number(ur.rows[0].id);

  const token  = "bbbb" + "0".repeat(60);
  const expiry = Date.now() - 1000; // already expired
  await db.execute({
    sql:  "INSERT INTO email_verif_tokens (token, user_id, expires_at) VALUES (?, ?, ?)",
    args: [token, userId, expiry],
  });

  const res = await req(`/api/verify-email?token=${token}`);
  // Should redirect to /?verif=expired
  const location = res.headers.get("location") || "";
  assert.ok(location.includes("expired"), "Expired token should redirect to ?verif=expired");
});

test("Resend verification is rate limited", async () => {
  const { cookie, csrfToken } = await makeSession("verif_rl1", "verifrl1@test.com");
  let lastStatus;
  // 3 allowed, 4th should be rate-limited
  for (let i = 0; i < 4; i++) {
    const r = await req("/api/auth/resend-verification", {
      method: "POST",
      headers: { cookie, "X-CSRF-Token": csrfToken },
    });
    lastStatus = r.status;
  }
  assert.equal(lastStatus, 429, "4th resend request should be rate-limited");
});

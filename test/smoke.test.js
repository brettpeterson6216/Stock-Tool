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
const http    = require("node:http");
const os      = require("node:os");
const path    = require("node:path");

const testDbPath = path.join(os.tmpdir(), `il-smoke-test-${process.pid}.db`).replace(/\\/g, "/");

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

// Keep smoke tests deterministic and fast: local app requests stay real,
// while external market providers are represented as unavailable.
global.fetch = (url, options) => {
  const target = String(url);
  if (target.startsWith("http://127.0.0.1:")) return nativeFetch(url, options);
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

// Sign up, log in and return { cookie, csrfToken }
async function makeSession(username, email, password = "Password123") {
  await req("/api/auth/signup", {
    method: "POST",
    body: { username, email, password },
  });
  const loginRes = await req("/api/auth/login", {
    method: "POST",
    body: { identifier: email, password },
  });
  // Extract individual Set-Cookie headers safely.
  // Node 18+ fetch (undici) supports getSetCookie(); fall back to comma-join split.
  let rawCookies;
  if (typeof loginRes.headers.getSetCookie === "function") {
    rawCookies = loginRes.headers.getSetCookie();
  } else {
    const joined = loginRes.headers.get("set-cookie") || "";
    // rudimentary split that avoids splitting on commas inside cookie values
    rawCookies = joined ? [joined] : [];
  }
  // Keep only name=value from each Set-Cookie (strip Path, HttpOnly, etc.)
  const cookie = rawCookies
    .map(c => c.split(";")[0].trim())
    .filter(Boolean)
    .join("; ");
  // Fetch CSRF token for this session
  const csrfRes = await req("/api/csrf", { headers: { cookie } });
  const { token } = await csrfRes.json();
  return { cookie, csrfToken: token };
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
  assert.match(await res.text(), /ImpliedLens/);
});

test("GET /healthz reports database and build health", async () => {
  const res = await req("/healthz");
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.ok, true);
  assert.equal(body.database, "ok");
  assert.ok(body.version);
  assert.ok(body.commit);
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

test("Provider health endpoint exposes an observation snapshot", async () => {
  const res = await req("/api/providers/health");
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.ok(Array.isArray(body.providers));
  assert.ok(["observing", "operational", "degraded"].includes(body.status));
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

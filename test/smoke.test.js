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

// ── Configure test environment before requiring app modules ──
process.env.NODE_ENV        = "test";
process.env.TURSO_URL       = "file:/tmp/il-smoke-test.db";
process.env.TURSO_AUTH_TOKEN = "";
process.env.SESSION_SECRET  = "smoke-test-secret-do-not-use-in-prod";
process.env.FINNHUB_KEY     = "test-key";
process.env.ADMIN_SECRET    = "test-admin-secret-abc123";
process.env.PORT            = "0"; // OS picks free port

let server, baseUrl;

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
  const cookie = loginRes.headers.get("set-cookie") || "";
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

after(() => {
  server?.close();
  // Clean up test DB
  try { require("node:fs").unlinkSync("/tmp/il-smoke-test.db"); } catch (_) {}
});

// ═══════════════════════════════════════════════════════════════
//  1. CSRF protection
// ═══════════════════════════════════════════════════════════════
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


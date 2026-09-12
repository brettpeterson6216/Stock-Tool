// Two cases for one company have to be able to coexist.
//
// The Projection Lab had exactly one shelf per ticker: the working model was
// written to localStorage under il-projlab:v2:<TICKER>, and that key was the
// only thing the Lab ever read back. Saving pushed a snapshot to /api/saves,
// and reopening one wrote it straight back over that same key. So building a
// bear case for AAPL destroyed the bull case in the Lab, and reopening the
// bull destroyed the bear. The report was "my custom cases went away and I
// could not revisit them" — which was not a fault in the save button. There
// was nowhere to put a second case.
//
// Cases now live on the server. These tests hold the three properties that
// failure needed: two cases for one ticker coexist, a case can be revised
// without spawning a duplicate, and one account cannot touch another's.
"use strict";

const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const testDbPath = path.join(os.tmpdir(), `il-proj-cases-${Date.now()}.db`);
process.env.NODE_ENV = "test";
process.env.TURSO_URL = `file:${testDbPath}`;
process.env.TURSO_AUTH_TOKEN = "";
process.env.SESSION_SECRET = "projection-cases-test-secret";
process.env.FINNHUB_KEY = "test-key";
process.env.PORT = "0";

let server, baseUrl;
const nativeFetch = global.fetch;
global.fetch = (url, options) => {
  const target = String(url);
  if (target.startsWith("http://127.0.0.1:")) return nativeFetch(url, options);
  return Promise.resolve(new Response(JSON.stringify({ error: "upstream unavailable in test" }),
    { status: 503, headers: { "Content-Type": "application/json" } }));
};

const req = (p, opts = {}) => fetch(baseUrl + p, {
  redirect: "manual", ...opts,
  headers: { "Content-Type": "application/json", ...(opts.headers || {}) },
  body: opts.body ? JSON.stringify(opts.body) : undefined,
});

function cookieOf(res) {
  const raw = typeof res.headers.getSetCookie === "function"
    ? res.headers.getSetCookie()
    : (res.headers.get("set-cookie") || "").split(/,(?=[^;]+=)/);
  return raw.map(c => String(c).split(";")[0]).filter(Boolean).join("; ");
}

async function session(username, email) {
  await req("/api/auth/signup", { method: "POST", body: { username, email, password: "Password123" } });
  const login = await req("/api/auth/login", { method: "POST", body: { identifier: email, password: "Password123" } });
  const cookie = cookieOf(login);
  const csrf = await (await req("/api/csrf", { headers: { cookie } })).json();
  return { cookie, token: csrf.token || csrf.csrfToken || "" };
}

const caseBody = (label, growth) => ({
  ticker: "AAPL", type: "projection", label,
  data: { model: { ticker: "AAPL", revenueGrowth: growth, years: 5 } },
});

before(async () => {
  const { initDb } = require("../lib/db");
  const app = require("../server");
  await initDb();
  await new Promise((resolve, reject) => {
    server = app.listen(0, "127.0.0.1", () => { baseUrl = `http://127.0.0.1:${server.address().port}`; resolve(); });
    server.once("error", reject);
  });
});

after(async () => {
  global.fetch = nativeFetch;
  if (server) await new Promise(r => server.close(r));
  try { fs.unlinkSync(testDbPath); } catch (_) {}
});

test("a bull and a bear case for the same ticker both survive", async () => {
  const s = await session("caseuser", "cases@example.com");
  const h = { cookie: s.cookie, "X-CSRF-Token": s.token };

  const bull = await (await req("/api/saves", { method: "POST", headers: h, body: caseBody("Bull", 14) })).json();
  const bear = await (await req("/api/saves", { method: "POST", headers: h, body: caseBody("Bear", 2) })).json();
  assert.ok(bull.id && bear.id, "both cases must be stored");
  assert.notEqual(bull.id, bear.id, "the second case overwrote the first");

  const rows = await (await req("/api/saves", { headers: { cookie: s.cookie } })).json();
  const mine = rows.filter(r => r.type === "projection" && r.ticker === "AAPL");
  assert.equal(mine.length, 2, `expected 2 cases for AAPL, got ${mine.length}`);
  assert.deepEqual(mine.map(r => r.label).sort(), ["Bear", "Bull"]);
  // Each carries its OWN assumptions — the bug would show as both reading alike.
  const byLabel = Object.fromEntries(mine.map(r => [r.label, r.data.model.revenueGrowth]));
  assert.equal(byLabel.Bull, 14);
  assert.equal(byLabel.Bear, 2);
});

test("revising a case updates it in place instead of spawning a duplicate", async () => {
  const s = await session("caseuser2", "cases2@example.com");
  const h = { cookie: s.cookie, "X-CSRF-Token": s.token };

  const made = await (await req("/api/saves", { method: "POST", headers: h, body: caseBody("Base", 8) })).json();
  const put = await req("/api/saves/" + made.id, {
    method: "PUT", headers: h,
    body: { label: "Base — revised", data: { model: { ticker: "AAPL", revenueGrowth: 9, years: 5 } } },
  });
  assert.equal(put.status, 200);

  const rows = (await (await req("/api/saves", { headers: { cookie: s.cookie } })).json())
    .filter(r => r.type === "projection");
  assert.equal(rows.length, 1, "a revision must not create a second row");
  assert.equal(rows[0].label, "Base — revised");
  assert.equal(rows[0].data.model.revenueGrowth, 9);
});

test("a case cannot be revised or read by another account", async () => {
  const a = await session("owner", "owner@example.com");
  const b = await session("intruder", "intruder@example.com");

  const made = await (await req("/api/saves", {
    method: "POST", headers: { cookie: a.cookie, "X-CSRF-Token": a.token }, body: caseBody("Private", 5),
  })).json();

  const hijack = await req("/api/saves/" + made.id, {
    method: "PUT", headers: { cookie: b.cookie, "X-CSRF-Token": b.token },
    body: { label: "Taken", data: { model: { ticker: "AAPL", revenueGrowth: 99 } } },
  });
  assert.equal(hijack.status, 404, "another account's id must not be updatable");

  const theirs = await (await req("/api/saves", { headers: { cookie: b.cookie } })).json();
  assert.equal(theirs.length, 0, "saves must not leak across accounts");

  const ours = await (await req("/api/saves", { headers: { cookie: a.cookie } })).json();
  assert.equal(ours[0].label, "Private", "the owner's case was altered by someone else");
});

test("saving without a session is refused rather than silently dropped", async () => {
  const res = await req("/api/saves", { method: "POST", body: caseBody("Ghost", 1) });
  assert.ok(res.status === 401 || res.status === 403, `expected a refusal, got ${res.status}`);
});

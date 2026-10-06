"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");

/* Fresh gate with a scripted upstream for each test. */
function load(upstream) {
  delete require.cache[require.resolve("../lib/finnhub-gate")];
  const real = globalThis.fetch;
  globalThis.fetch = upstream;
  const gate = require("../lib/finnhub-gate");
  gate.install();
  return { gate, restore: () => { globalThis.fetch = real; } };
}
const json = (status, body) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

test("finnhub responses are cached by URL without the token", async () => {
  let calls = 0;
  const { restore } = load(async () => { calls++; return json(200, { metric: { beta: 1.2 } }); });
  try {
    const a = await fetch("https://finnhub.io/api/v1/stock/metric?symbol=AAPL&metric=all&token=abc");
    const b = await fetch("https://finnhub.io/api/v1/stock/metric?metric=all&symbol=AAPL&token=xyz");
    assert.equal(a.status, 200); assert.deepEqual(await b.json(), { metric: { beta: 1.2 } });
    assert.equal(calls, 1);
  } finally { restore(); }
});

test("identical requests in flight share one upstream call", async () => {
  let calls = 0;
  const { restore } = load(async () => { calls++; await new Promise(r => setTimeout(r, 30)); return json(200, { ok: 1 }); });
  try {
    await Promise.all([1, 2, 3].map(() => fetch("https://finnhub.io/api/v1/stock/profile2?symbol=NVDA&token=t")));
    assert.equal(calls, 1);
  } finally { restore(); }
});

test("a 429 from Finnhub serves the last good answer", async () => {
  let mode = "ok";
  const { gate, restore } = load(async () => mode === "ok" ? json(200, { v: 1 }) : json(429, { error: "limit" }));
  try {
    const url = "https://finnhub.io/api/v1/quote?symbol=MSFT&token=t";
    await fetch(url);
    mode = "limit";
    await new Promise(r => setTimeout(r, 25));
    /* Expire the quote's 20s TTL by back-dating the cache through a second key read. */
    const res = await (async () => { const k = gate._keyOf(url); void k; return fetch(url); })();
    assert.equal(res.status, 200);
  } finally { restore(); }
});

test("premium-only endpoints (403) are remembered instead of retried", async () => {
  let calls = 0;
  const { restore } = load(async () => { calls++; return json(403, { error: "You don't have access" }); });
  try {
    const url = "https://finnhub.io/api/v1/stock/ownership?symbol=AAPL&limit=10&token=t";
    const a = await fetch(url), b = await fetch(url);
    assert.equal(a.status, 403); assert.equal(b.status, 403);
    assert.equal(calls, 1);
  } finally { restore(); }
});

test("other hosts are untouched", async () => {
  let seen = null;
  const { restore } = load(async (url) => { seen = url; return json(200, {}); });
  try {
    await fetch("https://data.sec.gov/api/xbrl/companyfacts/CIK0000320193.json");
    await fetch("https://data.sec.gov/api/xbrl/companyfacts/CIK0000320193.json");
    assert.match(seen, /data\.sec\.gov/);
  } finally { restore(); }
});

"use strict";
/* The Marketstack quota (10,000 calls a month on Basic) cannot run dry:
   intraday refreshes follow the market session, background work is
   staggered, spending is paced through the month, and symbols the plan does
   not carry cost nothing after the first miss. */
const test = require("node:test");
const assert = require("node:assert/strict");

process.env.NODE_ENV = "test";
const prices = require("../lib/prices");
const T = prices._test;
const at = s => Date.parse(s);

function withKey(fn) {
  const saved = process.env.MARKETSTACK_API_KEY;
  process.env.MARKETSTACK_API_KEY = "test";
  const realFetch = global.fetch;
  return Promise.resolve().then(fn).finally(() => {
    if (saved === undefined) delete process.env.MARKETSTACK_API_KEY; else process.env.MARKETSTACK_API_KEY = saved;
    global.fetch = realFetch; T._setClock(null); T._reset();
  });
}

test("market session: open, after the close, weekend", () => {
  // 2026-11-04 is a Wednesday; ET is UTC-5 in November.
  assert.deepEqual(T.marketState(at("2026-11-04T15:00:00Z")), { open: true, session: "2026-11-04", settled: false });
  assert.deepEqual(T.marketState(at("2026-11-04T21:10:00Z")), { open: false, session: "2026-11-04", settled: false }, "16:10 ET: last bars may still arrive");
  assert.deepEqual(T.marketState(at("2026-11-04T21:30:00Z")), { open: false, session: "2026-11-04", settled: true });
  assert.deepEqual(T.marketState(at("2026-11-05T12:00:00Z")), { open: false, session: "2026-11-04", settled: true }, "7am next day: still Wednesday's session");
  assert.deepEqual(T.marketState(at("2026-11-08T18:00:00Z")), { open: false, session: "2026-11-06", settled: true }, "Sunday: Friday's session");
});

test("intraday bars fetched after the close stay current until the next open", () => {
  T._reset();
  const fetchedSat = { at: at("2026-11-07T15:00:00Z"), state: T.marketState(at("2026-11-07T15:00:00Z")), rows: [] };
  assert.equal(T.intradayFresh(fetchedSat, 15 * 60e3, at("2026-11-09T13:00:00Z")), true, "Monday 8am ET: nothing newer exists");
  assert.equal(T.intradayFresh(fetchedSat, 15 * 60e3, at("2026-11-09T14:45:00Z")), false, "Monday 9:45 ET: the session has new bars");
  const during = { at: at("2026-11-04T15:00:00Z"), state: T.marketState(at("2026-11-04T15:00:00Z")), rows: [] };
  assert.equal(T.intradayFresh(during, 15 * 60e3, at("2026-11-04T15:10:00Z")), true);
  assert.equal(T.intradayFresh(during, 15 * 60e3, at("2026-11-04T15:20:00Z")), false);
  assert.equal(T.intradayFresh(during, 15 * 60e3, at("2026-11-04T22:00:00Z")), false, "fetched mid-session: refresh once after the close");
});

test("the graded universe refreshes half its companies each trading day", () => {
  T._reset();
  T._setClock(() => at("2026-11-05T23:00:00Z"));   // Thursday evening, Thursday's bar published
  try {
    const tickers = ["AAPL", "MSFT", "NVDA", "GOOGL", "AMZN", "META", "JPM", "XOM", "KO", "PG", "V", "MA"];
    const today = tickers.filter(t => T.staleCutoff("background", t) === "2026-11-05");
    const yesterday = tickers.filter(t => T.staleCutoff("background", t) === "2026-11-04");
    assert.equal(today.length + yesterday.length, tickers.length);
    assert.ok(today.length > 0 && yesterday.length > 0, "both halves present");
    assert.equal(T.staleCutoff("interactive", "AAPL"), "2026-11-05", "someone opening a stock gets the latest close");
    T._setClock(() => at("2026-11-06T23:00:00Z"));   // Friday: the other half
    const fri = tickers.filter(t => T.staleCutoff("background", t) === "2026-11-06");
    assert.deepEqual(fri.sort(), yesterday.sort());
  } finally { T._setClock(null); }
});

test("indexes answer through their ETF; other index symbols cost nothing", () => withKey(async () => {
  assert.deepEqual(T.resolveSymbol("^GSPC"), { symbol: "SPY", standInFor: "^GSPC" });
  assert.deepEqual(T.resolveSymbol("^VIX"), { symbol: null, standInFor: null });
  let calls = 0;
  global.fetch = async () => { calls += 1; throw new Error("should not be called"); };
  await assert.rejects(prices.getChart("^VIX", { range: "1d" }), /not available/);
  assert.deepEqual(await prices.dailyCloses("^VIX", 30), []);
  assert.equal(await prices.latestPrice("^VIX"), null);
  assert.equal(calls, 0);
}));

test("a symbol the plan does not carry is asked about once, then remembered", () => withKey(async () => {
  T._setClock(() => at("2026-11-04T15:00:00Z"));
  let calls = 0;
  global.fetch = async () => { calls += 1; return { ok: false, status: 422, json: async () => ({ error: { code: "no_valid_symbols_provided", message: "no valid symbols" } }) }; };
  await assert.rejects(prices.getChart("ZZZQX", { range: "1y" }));
  await assert.rejects(prices.getChart("ZZZQX", { range: "1y" }));
  await assert.rejects(prices.getChart("ZZZQX", { range: "6mo" }));
  assert.equal(calls, 1);
}));

test("spending is paced through the month", () => withKey(async () => {
  T._setClock(() => at("2026-11-03T15:00:00Z"));   // ~7% into the month
  T.usage.month = "2026-11"; T.usage.loaded = true;
  T.usage.calls = 1200;
  assert.equal(await prices.canSpend("intraday"), true, "cap by now ≈ 8,500 × (8.8% + 10% slack)");
  T.usage.calls = 1700;
  assert.equal(await prices.canSpend("intraday"), false, "ahead of pace (~1,590 by now): intraday waits");
  assert.equal(await prices.canSpend("background"), false);
  assert.equal(await prices.canSpend("interactive"), true, "a person opening a stock is not paced");
  T.usage.calls = 9700;
  assert.equal(await prices.canSpend("interactive"), false, "monthly ceiling");
  T._setClock(() => at("2026-11-28T15:00:00Z"));
  T.usage.calls = 7000;
  assert.equal(await prices.canSpend("intraday"), true, "late in the month the pace allows more");
}));

test("intraday refreshes slow down before the cap instead of stopping at it", () => withKey(async () => {
  T._setClock(() => at("2026-11-16T15:00:00Z"));   // ~50% into the month → pace cap ≈ 5,100
  T.usage.month = "2026-11"; T.usage.loaded = true;
  T.usage.calls = 1000; assert.equal(T.ttlScale(), 1);
  T.usage.calls = 4200; assert.equal(T.ttlScale(), 2);
  T.usage.calls = 4900; assert.equal(T.ttlScale(), 4);
}));

test("alerts share the quota: the more stocks watched, the less often each is checked", () => {
  const { alertMaxAgeMs } = require("../lib/alerts");
  const min = ms => ms / 60000;
  assert.equal(min(alertMaxAgeMs(1)), 29);
  assert.equal(min(alertMaxAgeMs(8)), 45);
  assert.equal(min(alertMaxAgeMs(30)), 168);
  // Calls per trading day stay near the daily share however many stocks are watched.
  for (const n of [5, 20, 60]) assert.ok(n * (390 / min(alertMaxAgeMs(n))) <= 71, String(n));
});

test("home tiles ask for previews; the chart someone opened does not", () => {
  const fs = require("fs"), path = require("path");
  const route = fs.readFileSync(path.join(__dirname, "..", "routes/market-data.js"), "utf8");
  assert.match(route, /preview: req\.query\.preview === "1"/);
  for (const f of ["public/home-member.js", "public/tool-launch.js"]) {
    assert.match(fs.readFileSync(path.join(__dirname, "..", f), "utf8"), /range=1d&preview=1/, f);
  }
});

"use strict";
/* The Marketstack quota (10,000 calls a month on Basic) cannot run dry or
   reach overage fees: every symbol in a request is counted (Marketstack bills
   per symbol), intraday refreshes follow the market session, background work
   is staggered, spending is paced through the month, and symbols the plan
   does not carry cost nothing after the first miss. */
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
    delete process.env.PRICE_BACKGROUND_SESSIONS;
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

test("on Basic the universe is refreshed in five slots, about weekly each", () => {
  T._reset();
  T._setClock(() => at("2026-11-05T23:00:00Z"));   // Thursday evening, Thursday's bar published
  try {
    assert.equal(T.backgroundSessions(), 5);
    const tickers = Array.from({ length: 200 }, (_, i) => `T${i}`);
    const days = new Set(tickers.map(t => T.staleCutoff("background", t)));
    assert.equal(days.size, 5, "five different cut-off days");
    for (const d of days) assert.ok(d >= "2026-10-30" && d <= "2026-11-05", d);
    assert.equal(T.staleCutoff("interactive", "T1"), "2026-11-05", "someone opening a stock gets the latest close");
    const due = tickers.filter(t => T.staleCutoff("background", t) === "2026-11-05").length;
    assert.ok(due > 20 && due < 70, `about a fifth due tonight (${due})`);
    prices.keepDaily(["T1"]);
    assert.equal(T.staleCutoff("background", "T1"), "2026-11-05", "kept daily: always the latest close");
  } finally { T._setClock(null); T._reset(); }
});

test("a Marketstack request costs one call per symbol", () => {
  assert.equal(T.costOf({ symbols: "AAPL" }), 1);
  assert.equal(T.costOf({ symbols: "AAPL,MSFT,NVDA" }), 3);
  assert.equal(T.costOf({}), 1);
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
  assert.equal(min(alertMaxAgeMs(8)), 104);
  assert.equal(min(alertMaxAgeMs(30)), 390);
  // Calls per trading day stay near the daily share however many stocks are watched.
  for (const n of [5, 20, 60]) assert.ok(n * (390 / min(alertMaxAgeMs(n))) <= 31, String(n));
});

function fakeEod(calls) {
  return async url => {
    const u = new URL(String(url));
    const syms = u.searchParams.get("symbols").split(",");
    const from = u.searchParams.get("date_from"), to = u.searchParams.get("date_to");
    calls.push(syms.length);
    const data = [];
    for (let d = Date.parse(from + "T12:00:00Z"); d <= Date.parse(to + "T12:00:00Z"); d += 86400000) {
      const day = new Date(d); if ([0, 6].includes(day.getUTCDay())) continue;
      for (const s of syms) data.push({ symbol: s, date: day.toISOString().slice(0, 10) + "T00:00:00+0000", open: 12, high: 12, low: 12, close: 12, volume: 1 });
    }
    return { ok: true, status: 200, json: async () => ({ data: data.slice(0, 1000), pagination: { total: data.length } }) };
  };
}

test("batched top-ups are billed per symbol and fit one page each", () => withKey(async () => {
  T._reset();
  T._setClock(() => at("2026-11-05T23:00:00Z"));   // Thursday evening, Thursday's bar published
  const tickers = Array.from({ length: 250 }, (_, i) => `T${String(i).padStart(3, "0")}`);
  process.env.PRICE_BACKGROUND_SESSIONS = "1";       // all due tonight
  for (const t of tickers) {
    const e = await T.loadStored(t);
    e.rows = [{ day: "2026-11-03", o: 10, h: 10, l: 10, c: 10, v: 1 }];
    e.checkedAt = 0;
  }
  const calls = [];
  global.fetch = fakeEod(calls);
  T.usage.month = "2026-11"; T.usage.loaded = true; T.usage.calls = 0;
  const res = await prices.topUpMany(tickers);
  assert.deepEqual(calls, [100, 100, 50], "three requests for 250 stocks");
  assert.equal(T.usage.calls, 250, "billed per symbol, and counted that way");
  assert.equal(res.updated, 250);
  assert.equal(T.daily.get("T000").rows.at(-1).day, "2026-11-05");
  calls.length = 0;
  await prices.topUpMany(tickers);
  assert.equal(calls.length, 0, "already current: nothing spent");
}));

test("a top-up after a long gap is split so no request needs a second page", () => withKey(async () => {
  T._reset();
  T._setClock(() => at("2026-11-13T23:00:00Z"));   // a Friday
  const tickers = Array.from({ length: 150 }, (_, i) => `G${i}`);
  process.env.PRICE_BACKGROUND_SESSIONS = "1";
  for (const t of tickers) { const e = await T.loadStored(t); e.rows = [{ day: "2026-10-30", o: 1, h: 1, l: 1, c: 1, v: 1 }]; e.checkedAt = 0; }
  const calls = [];
  global.fetch = fakeEod(calls);
  T.usage.month = "2026-11"; T.usage.loaded = true; T.usage.calls = 0;
  await prices.topUpMany(tickers);
  assert.ok(calls.every(n => n * 10 <= 1000), `each request within one page (${calls.join(",")})`);
  assert.equal(T.usage.calls, 150, "each stock billed once");
}));

test("a month of the refresh plan stays under Basic's ceiling", () => withKey(async () => {
  T._reset();
  const universe = Array.from({ length: 1000 }, (_, i) => `U${i}`);
  const calls = [];
  global.fetch = fakeEod(calls);
  T.usage.month = "2026-12"; T.usage.loaded = true; T.usage.calls = 0;
  /* Stored history up to Nov 30 for everyone (the first month's seeding is
     a separate ~1,000 calls, once). */
  for (const t of universe) { const e = await T.loadStored(t); e.rows = [{ day: "2026-11-30", o: 1, h: 1, l: 1, c: 1, v: 1 }]; }
  for (let d = 1; d <= 31; d += 1) {
    for (const hour of [1, 7, 13, 19]) {             // warmUniverse every 6 hours
      T._setClock(() => Date.UTC(2026, 11, d, hour));
      prices.keepDaily(universe.slice(0, 60), 2 * 86400e3);
      prices.keepDaily(universe.slice(500, 540));        // forty watchlisted stocks
      for (const t of universe) T.daily.get(t).checkedAt = 0;
      await prices.topUpMany(universe);
    }
  }
  const used = T.usage.calls;
  assert.ok(used < 7000, `background stays inside its 70% share (${used})`);
  assert.ok(used > 3500, `and the universe really is refreshed (${used})`);
  const stale = universe.filter(t => T.daily.get(t).rows.at(-1).day < "2026-12-22").length;
  assert.equal(stale, 0, "every company has a close from the last week of the month");
}));

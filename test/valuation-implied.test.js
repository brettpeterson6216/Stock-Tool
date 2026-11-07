"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const V = require("../public/app/valuation.js");

test("implied growth runs the projection backwards to today's price", () => {
  const base = { price: 200, revenue: 200e9, shares: 24e9, years: 5, margin: 0.5, exitPE: 25, shareChange: 0, required: 0.1 };
  const g = V.impliedGrowth(base);
  const out = V.project({ ...base, growth: g });
  assert.ok(Math.abs(out.valueToday - 200) < 1e-6);
  assert.ok(Math.abs(out.annualReturn - 0.1) < 1e-9);
});

test("buybacks lower the growth the price needs; dilution raises it", () => {
  const base = { price: 100, revenue: 10e9, shares: 1e9, margin: 0.2, exitPE: 20, required: 0.1 };
  const flat = V.impliedGrowth(base);
  assert.ok(V.impliedGrowth({ ...base, shareChange: -0.02 }) < flat);
  assert.ok(V.impliedGrowth({ ...base, shareChange: 0.02 }) > flat);
});

test("projection refuses incomplete inputs instead of inventing numbers", () => {
  assert.equal(V.project({ price: 0, revenue: 1, shares: 1, growth: 0.1, margin: 0.1, exitPE: 10 }), null);
  assert.equal(V.impliedGrowth({ price: 10, revenue: 1e9, shares: 1e8, margin: -0.1, exitPE: 10 }), null);
});

test("default cases bracket the base and mark unprofitable companies", () => {
  const d = V.defaults({ growth3y: 0.4, margin: 0.3, pe: 30 });
  assert.ok(d.bear.growth < d.base.growth && d.base.growth < d.bull.growth);
  assert.ok(d.base.growth <= 0.45, "starting growth is capped at 45%");
  assert.ok(d.base.growthEnd < d.base.growth, "and fades");
  assert.equal(d.unprofitable, false);
  const loss = V.defaults({ growth1y: 0.2, margin: -0.05, pe: null });
  assert.equal(loss.unprofitable, true);
  assert.ok(loss.base.margin > 0);
});

/* Codex audit F02: a 0% required return used to fall back to 10%. */
test("a 0% required return is used as 0%, not swapped for 10%", () => {
  const i = { price: 10, revenue: 100, shares: 10, years: 5, growth: 0, margin: 0.1, exitPE: 10, shareChange: 0 };
  const near = (a, b) => Math.abs(a - b) < 1e-4;
  assert.ok(near(V.project({ ...i, required: 0 }).valueToday, 10));
  assert.ok(near(V.project({ ...i, required: 0.05 }).valueToday, 7.8353));
  assert.ok(near(V.project({ ...i, required: 0.1 }).valueToday, 6.2092));
  const g = (r) => V.impliedGrowth({ ...i, required: r });
  assert.ok(Math.abs(g(0)) < 1e-9);
  assert.ok(near(g(0.05), 0.05));
  assert.ok(near(g(0.1), 0.1));
  for (const r of [0, 0.05, 0.1, 0.2]) {
    const out = V.project({ ...i, required: r, growth: g(r) });
    assert.ok(near(out.valueToday, i.price), "round trip at " + r);
  }
});

/* Codex audit F07: impossible inputs must not produce Infinity or NaN. */
test("impossible inputs are refused with a reason, never Infinity", () => {
  const i = { price: 10, revenue: 100, shares: 10, years: 5, growth: 0.05, margin: 0.1, exitPE: 10, shareChange: 0, required: 0.1 };
  assert.equal(V.project({ ...i, shareChange: -1 }), null);
  assert.equal(V.validate({ ...i, shareChange: -1 }).field, "shareChange");
  assert.equal(V.project({ ...i, required: -1 }), null);
  assert.equal(V.validate({ ...i, required: -1.5 }).field, "required");
  assert.equal(V.project({ ...i, growth: NaN }), null);
  assert.equal(V.impliedGrowth({ ...i, shareChange: -1 }), null);
  assert.equal(V.validate(i), null);
  const shrinking = V.project({ ...i, growth: -0.2 });
  assert.ok(shrinking && Number.isFinite(shrinking.valueToday), "negative growth stays usable");
});

test("recent quarters lead the growth seed; an acquisition jump is named, not used", () => {
  const q = [["2024-09-30", 265.7, 236], ["2024-12-31", 332.2, 236], ["2025-03-31", 329.3, 236], ["2025-06-30", 739.3, 260.2], ["2025-09-30", 725.1, 257.8],
    ["2025-12-31", 721.6, 258.8], ["2026-03-31", 782.6, 259.8], ["2026-06-30", 817.9, 256.9], ["2026-09-30", 847.2, 254.9]]
    .map(([end, r, sh]) => ({ end, revenue: r * 1e6, netIncome: r * 1e5, shares: sh * 1e6 }));
  const d = V.defaults({ price: 32.22, pe: 25.9, margin: 0.1, growth1y: 0.49, growth3y: 0.45, quarters: q });
  assert.equal(d.base.growth, 0.135, "the last two quarters, not the acquisition-inflated year");
  assert.match(d.notes[0], /acquisition/);
  assert.match(d.notes[0], /Jun 2025/);
  assert.equal(d.shareChange, -0.01);
});

test("growth fades in a straight line to the final-year rate", () => {
  const out = V.project({ price: 10, revenue: 100, shares: 10, years: 5, growth: 0.4, growthEnd: 0.04, margin: 0.1, exitPE: 20 });
  assert.deepEqual(out.growth.map(g => Math.round(g * 1000) / 1000), [0.4, 0.31, 0.22, 0.13, 0.04]);
  assert.equal(out.pricePath.length, 5);
  assert.ok(Math.abs(out.pricePath[4] - out.futurePrice) < 1e-9);
  const w = V.weighted({ bear: { ...out, futurePrice: 5 }, base: { ...out, futurePrice: 10 }, bull: { ...out, futurePrice: 20 } }, { bear: 0.25, base: 0.5, bull: 0.25 }, 10);
  assert.equal(w.futurePrice, 11.25);
});

test("P/E history uses trailing four-quarter EPS at each quarter end, and needs enough of it", () => {
  const day = d => Date.parse(d + "T16:00:00Z") / 1000;
  const bars = [];
  for (let t = day("2023-01-02"); t < day("2025-01-01"); t += 7 * 86400) bars.push({ time: t, close: t < day("2024-01-01") ? 40 : 80 });
  const ends = ["2023-03-31", "2023-06-30", "2023-09-30", "2023-12-31", "2024-03-31", "2024-06-30", "2024-09-30", "2024-12-31"];
  const q = ends.map(end => ({ end, eps: 1 }));        // $4 a year of earnings
  const h = V.peHistory(q, bars);
  assert.equal(h.points.length, 5);                     // the first full four quarters end 2023-12-31
  assert.equal(h.points[0].pe, 10);                     // $40 / $4
  assert.equal(h.points[1].pe, 20);                     // $80 / $4
  assert.equal(h.median, 20);
  assert.equal(h.low, 10);
  assert.equal(h.since, "2023-12-31");
  assert.equal(V.peHistory(q.slice(0, 4), bars), null, "under five quarters is no history");
  assert.equal(V.peHistory(q.map(x => ({ ...x, eps: -1 })), bars), null, "losses have no P/E");
});

test("DCF: present value of each year's free cash flow, a growing perpetuity, plus net cash", () => {
  const o = { revenuePath: [100, 100], fcfMargin0: 0.1, fcfMargin: 0.1, rate: 0.1, terminal: 0, netCash: 50, shares: 10, price: 15 };
  const out = V.dcf(o);
  // 10/1.1 + 10/1.21 + (10/0.1)/1.21 + 50
  const want = 10 / 1.1 + 10 / 1.21 + 100 / 1.21 + 50;
  assert.ok(Math.abs(out.equity - want) < 1e-9);
  assert.ok(Math.abs(out.value - want / 10) < 1e-9);
  assert.ok(Math.abs(out.terminalShare - (100 / 1.21) / (want - 50)) < 1e-9);
  const m = V.impliedFcfMargin(o);
  assert.ok(Math.abs(V.dcf({ ...o, fcfMargin: m }).value - 15) < 1e-6, "the implied margin prices the stock exactly");
});

test("DCF refuses a discount rate at or below the growth that follows", () => {
  const o = { revenuePath: [100], fcfMargin0: 0.1, fcfMargin: 0.1, rate: 0.03, terminal: 0.025, netCash: 0, shares: 1, price: 1 };
  assert.equal(V.dcf(o), null);
  assert.match(V.dcfProblem(o), /at least 1 point above/);
  assert.match(V.dcfProblem({ ...o, rate: 0.09, terminal: 0.08 }), /between −3% and 5%/);
});

test("risk stats: Sharpe and Sortino above cash, and a historical 1-in-20 bad day", () => {
  // 250 days alternating +2% / −1%, so 249 returns
  const closes = [100];
  for (let i = 0; i < 249; i++) closes.push(closes[i] * (i % 2 ? 0.99 : 1.02));
  const s = V.riskStats(closes, 0);
  const r = closes.slice(1).map((c, i) => c / closes[i] - 1);
  const mean = r.reduce((a, b) => a + b, 0) / r.length;
  const sd = Math.sqrt(r.reduce((a, b) => a + (b - mean) ** 2, 0) / (r.length - 1));
  assert.ok(Math.abs(s.sharpe - mean / sd * Math.sqrt(252)) < 1e-9);
  assert.ok(s.sortino > s.sharpe, "only the falls count as risk");
  assert.ok(Math.abs(s.var95 - 0.01) < 1e-9 && Math.abs(s.cvar95 - 0.01) < 1e-9);
  assert.ok(V.riskStats(closes, 0.05).sharpe < s.sharpe, "a higher cash rate lowers it");
  assert.equal(V.riskStats(closes.slice(0, 50), 0), null, "needs about six months of days");
});

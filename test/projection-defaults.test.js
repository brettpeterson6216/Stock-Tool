"use strict";
/* Golden tests for the Valuation Lab's default cases, seeded with the five
   stocks from the October 2026 analyst field test (live site data, Oct 5).
   Before these rules the defaults were: NVDA base $3,796 (revenue $3.18T),
   a Costco bear case with a loss, and nothing at all for Intel. */
const test = require("node:test");
const assert = require("node:assert/strict");
const M = require("../public/model-math.js");

const months = (a, b) => (Date.parse(b) - Date.parse(a)) / (30.44 * 864e5);
const STOCKS = {
  AAPL: { p: 334.17, fy: [416161e6, 391035e6], fyEnd: "2025-09-27", asOf: "2026-06-27", r: 466823e6, n: 128930e6, sh: 14594180000, shareCagr: -0.025 },
  NVDA: { p: 239.73, fy: [215938e6, 130497e6], fyEnd: "2026-01-25", asOf: "2026-07-26", r: 302970e6, n: 192880e6, sh: 24100000000, shareCagr: -0.004 },
  COST: { p: 921.07, fy: [275235e6, 254453e6], fyEnd: "2025-08-31", asOf: "2026-05-10", r: 293587e6, n: 8838e6, sh: 443478804, shareCagr: -0.001, targetMargin: 6 },
  JPM:  { p: 332.92, fy: [182447e6, 177556e6], fyEnd: "2025-12-31", asOf: "2026-06-30", r: 186330e6, n: 63630e6, sh: 2740000000, shareCagr: -0.03, financial: true, targetMargin: 20 },
  INTC: { p: 116.48, fy: [52853e6, 53101e6], fyEnd: "2025-12-27", asOf: "2026-06-27", r: 57032e6, n: -11289e6, sh: 5250000000, shareCagr: 0.02, targetMargin: 15 },
};
function build(t) {
  const s = STOCKS[t];
  const model = M.plCreateModel({
    ticker: t, baseYear: 2026, seeded: true, startPrice: s.p, dilutedShares: s.sh, baseRevenue: s.r, baseNetIncome: s.n,
    histGrowth: s.fy[0] / s.fy[1] - 1, ttmTrend: Math.pow(s.r / s.fy[0], 12 / months(s.fyEnd, s.asOf)) - 1,
    currentPE: s.n > 0 ? s.p / (s.n / s.sh) : NaN, shareCagr: s.shareCagr, financialSector: !!s.financial, targetMargin: s.targetMargin,
  });
  return { model, outlook: M.plCalculateOutlook(model), s };
}

test("every test stock gets three priced cases and a weighted value", () => {
  for (const t of Object.keys(STOCKS)) {
    const { outlook } = build(t);
    assert.equal(outlook.ok, true, t);
    for (const k of ["bear", "base", "bull"]) assert.ok(outlook.scenarios[k].terminal.priceMid > 0, `${t} ${k} priced`);
    assert.ok(outlook.expected && outlook.expected.price > 0, `${t} weighted value`);
  }
});

test("bear <= base <= bull for growth, margin, exit P/E and price, every year", () => {
  for (const t of Object.keys(STOCKS)) {
    const { model, outlook } = build(t);
    const sc = model.scenarios;
    for (let i = 0; i < 5; i++) {
      for (const f of ["revGrowth", "netMargin", "peLow", "peHigh"]) {
        assert.ok(sc.bear[f][i] <= sc.base[f][i] && sc.base[f][i] <= sc.bull[f][i], `${t} ${f} year ${i + 1}`);
      }
    }
    const mid = k => outlook.scenarios[k].terminal.priceMid;
    assert.ok(mid("bear") <= mid("base") && mid("base") <= mid("bull"), `${t} price order`);
  }
});

test("NVDA: growth fades, so the base case stays in a defensible range", () => {
  const { outlook, s } = build("NVDA");
  const t = outlook.scenarios.base.terminal;
  assert.ok(t.revenue < 1e12, "2031 revenue under $1T (was $3.18T)");
  assert.ok(t.priceMid > 250 && t.priceMid < 700, `base midpoint ${t.priceMid}`);
  assert.ok(Math.pow(t.priceMid / s.p, 1 / 5) - 1 < 0.25, "base implied return under 25% a year");
});

test("AAPL: P/E on TTM earnings and buybacks lift EPS", () => {
  const { model, outlook } = build("AAPL");
  assert.ok(model.assumptionNotes.currentPE > 37 && model.assumptionNotes.currentPE < 40);
  const t = outlook.scenarios.base.terminal;
  assert.ok(t.priceMid > 350 && t.priceMid < 500, `base midpoint ${t.priceMid}`);
  assert.ok(t.shares < STOCKS.AAPL.sh, "share count falls");
});

test("COST: bear margin moves by percentage and stays profitable", () => {
  const { model } = build("COST");
  assert.ok(model.scenarios.bear.netMargin[0] > 2 && model.scenarios.bear.netMargin[0] < 3);
  assert.ok(model.scenarios.bull.netMargin[0] < 4);
});

test("JPM: financials revert toward a 13x norm, not 20x", () => {
  const { model } = build("JPM");
  assert.equal(model.assumptionNotes.normPE, 13);
  assert.ok(model.assumptionNotes.exitPE[1] < 17);
});

test("INTC: a loss-maker gets a labelled path to profit, and bull grows faster than bear", () => {
  const { model } = build("INTC");
  assert.equal(model.assumptionNotes.turnaround, true);
  assert.ok(model.scenarios.bull.revGrowth[0] > model.scenarios.bear.revGrowth[0]);
  assert.ok(model.scenarios.base.netMargin[4] > 10, "base margin recovers by year 5");
});

test("negative history no longer inverts bull and bear", () => {
  const m = M.plCreateModel({ baseRevenue: 1e9, baseNetIncome: 1e8, histGrowth: -0.1, currentPE: 15, startPrice: 10, dilutedShares: 1e8, seeded: true });
  for (let i = 0; i < 5; i++) assert.ok(m.scenarios.bull.revGrowth[i] > m.scenarios.bear.revGrowth[i]);
});

test("share change compounds into EPS", () => {
  const m = M.plCreateModel({ baseRevenue: 1e9, baseNetIncome: 1e8, histGrowth: 0, currentPE: 15, startPrice: 10, dilutedShares: 1e8, seeded: true });
  ["bear", "base", "bull"].forEach(k => { m.scenarios[k].revGrowth.fill(0); m.scenarios[k].netMargin.fill(10); m.scenarios[k].shareChange.fill(-10); });
  const r = M.plCalculateProjection(m, "base");
  assert.ok(Math.abs(r.rows[1].shares - 1e8 * 0.81) < 1);
  assert.ok(Math.abs(r.rows[1].eps - 1e8 / (1e8 * 0.81)) < 1e-9);
});

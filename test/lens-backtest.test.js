"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
process.env.NODE_ENV = "test";
const B = require("../lib/lens-backtest");

test("share-count jumps that match a split are splits; buybacks are not", () => {
  assert.equal(B.splitFactor(2.46e9, 24.4e9), 10, "NVIDIA 10-for-1");
  assert.equal(B.splitFactor(1e9, 0.95e9), 1, "buybacks");
  assert.equal(B.splitFactor(1e9, 1.3e9), 1, "issuance");
  assert.equal(B.splitFactor(10e6, 1e6), 0.1, "1-for-10 reverse split");
});

test("month-ends are the last weekday of each month", () => {
  assert.deepEqual(B.monthEnds("2026-01-10", "2026-04-30"), ["2026-01-30", "2026-02-27", "2026-03-31", "2026-04-30"]);
});

function uni(n, q) {
  return { t: `C${n}`, n: `C${n}`, s: "Tech", g: null, px: 50, mc: 1e9, m: {
    peTTM: 40 - 30 * q, pegTTM: 3 - 2 * q, psTTM: 10 - 8 * q, pfcfShareTTM: 50 - 40 * q, evEbitdaTTM: 30 - 20 * q,
    revenueGrowthTTMYoy: 30 * q, revenueGrowthQuarterlyYoy: 30 * q, epsGrowthTTMYoy: 40 * q, revenueGrowth3Y: 20 * q, epsGrowth3Y: 25 * q,
    grossMarginTTM: 30 + 40 * q, operatingMarginTTM: 5 + 30 * q, netProfitMarginTTM: 3 + 25 * q, roeTTM: 5 + 30 * q, roiTTM: 4 + 20 * q,
    "totalDebt/totalEquityQuarterly": 2 - 1.5 * q, currentRatioQuarterly: 1 + q, netInterestCoverageTTM: 2 + 20 * q,
    "priceRelativeToS&P50013Week": -10 + 20 * q, "priceRelativeToS&P50026Week": -10 + 20 * q, "priceRelativeToS&P50052Week": -10 + 20 * q, "52WeekHigh": 60 } };
}

test("a score that predicts returns shows a positive, significant rank correlation", () => {
  let seed = 3; const rnd = () => (seed = (seed * 16807) % 2147483647) / 2147483647;
  const months = Array.from({ length: 12 }, (_, k) => {
    const rows = Array.from({ length: 60 }, (_, i) => uni(i, i / 59));
    const fwd = Object.fromEntries(rows.map((r, i) => [r.t, { 63: (i / 59) * 0.1 - 0.05 + (rnd() - 0.5) * 0.08, 126: (rnd() - 0.5) * 0.2 }]));
    return { day: `2025-${String(k + 1).padStart(2, "0")}-28`, rows, fwd };
  });
  const st = B.gradeStudy(months);
  const h = st.horizons[63];
  assert.equal(h.monthsTested, 12);
  assert.ok(h.rankCorrelation.mean > 0.3 && h.rankCorrelation.t > 2, JSON.stringify(h.rankCorrelation));
  assert.ok(h.topMinusBottomQuintile.mean > 0);
  assert.match(B.verdict(h.rankCorrelation), /reliably so far/);
  assert.match(B.verdict(st.horizons[126].rankCorrelation), /No reliable|somewhat|worse/);
});

test("the timing study walks forward and reports per-date correlations", () => {
  const mk = (k) => Array.from({ length: 700 }, (_, i) => { const c = 100 * Math.exp(0.0004 * i + 0.05 * Math.sin(i / (15 + k))); return { day: new Date(Date.UTC(2023, 0, 2) + i * 864e5).toISOString().slice(0, 10), close: c, high: c * 1.01, low: c * 0.99, volume: 1e6 }; });
  const series = Object.fromEntries(Array.from({ length: 25 }, (_, k) => [`T${k}`, mk(k)]));
  const st = B.timingStudy(series, mk(99));
  assert.ok(st.observations > 200, String(st.observations));
  assert.deepEqual(Object.keys(st.scorers).sort(), ["gauge", "lensSetup", "setup"]);
  for (const k of Object.keys(st.scorers)) {
    assert.ok(st.scorers[k].observations > 200, k + " " + st.scorers[k].observations);
    assert.ok(st.scorers[k].horizons[21].rankCorrelation.n > 5, k);
    assert.equal(st.scorers[k].horizons[63].buckets.length, 6);
    assert.ok(typeof st.scorers[k].verdict[63] === "string");
  }
});

"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const F = require("../lib/lens-factors");

/* A synthetic universe: 6 sectors × 12 companies. Within each sector,
   company i is better on every metric as i rises. */
function rnd(seed) { let x = seed; return () => (x = (x * 16807) % 2147483647) / 2147483647; }
function metricFor(i, n, r) {
  const q = i / (n - 1);               // 0 worst … 1 best
  return {
    peTTM: 60 - 45 * q + r() * 2, forwardPE: 50 - 38 * q, pegTTM: 3 - 2.4 * q, psTTM: 12 - 10 * q,
    pfcfShareTTM: 70 - 55 * q, evEbitdaTTM: 40 - 30 * q, pbQuarterly: 6 - 5 * q,
    revenueGrowthTTMYoy: -5 + 40 * q, revenueGrowthQuarterlyYoy: -8 + 45 * q, epsGrowthTTMYoy: -20 + 70 * q,
    revenueGrowth3Y: 0 + 30 * q, epsGrowth3Y: -5 + 40 * q,
    grossMarginTTM: 20 + 60 * q, operatingMarginTTM: -5 + 40 * q, netProfitMarginTTM: -8 + 35 * q,
    roeTTM: 0 + 40 * q, roiTTM: 0 + 30 * q,
    "totalDebt/totalEquityQuarterly": 3 - 2.8 * q, currentRatioQuarterly: 0.6 + 2.4 * q, netInterestCoverageTTM: 1 + 40 * q, beta: 2.2 - 1.6 * q,
    "priceRelativeToS&P50013Week": -20 + 40 * q, "priceRelativeToS&P50026Week": -25 + 50 * q, "priceRelativeToS&P50052Week": -30 + 60 * q,
    "52WeekHigh": 100,
  };
}
const SECTORS = ["Tech", "Health", "Finance", "Energy", "Industrials", "Staples"];
const universe = [];
const r = rnd(7);
SECTORS.forEach((s, si) => { for (let i = 0; i < 12; i++) universe.push({ t: `${s.slice(0, 2).toUpperCase()}${i}`, n: `${s} ${i}`, s, m: metricFor(i, 12, r), px: 60 + 39 * (i / 11), mc: 1e9 * (i + 1) }); });

test("the best company in its sector grades A on every factor and scores near 10", () => {
  const best = universe.find(u => u.t === "TE11");
  const g = F.gradeCompany({ ticker: "NEW", name: "New Co", sector: "Tech", metric: { ...best.m, peTTM: 10 }, price: 99 }, universe);
  assert.equal(g.status, "graded");
  g.factors.forEach(f => assert.match(f.grade, /^A/, `${f.label} ${f.grade}`));
  assert.ok(g.score >= 9, `score ${g.score}`);
  assert.equal(g.rank.position, 1);
  assert.equal(g.basis, "sector");
  assert.ok(g.strengths.length > 0 && g.watch.length === 0);
});

test("a failing factor caps the score however good the others are", () => {
  const best = universe.find(u => u.t === "TE11").m;
  const metric = { ...best, "totalDebt/totalEquityQuarterly": 9, currentRatioQuarterly: 0.2, netInterestCoverageTTM: 0.5, beta: 3 };
  const g = F.gradeCompany({ ticker: "LEV", name: "Levered", sector: "Tech", metric, price: 99 }, universe);
  const health = g.factors.find(f => f.key === "health");
  assert.equal(health.grade, "F");
  assert.ok(g.score <= 6.8, `score ${g.score}`);
  assert.ok(g.caps.length === 1 && /Financial health/.test(g.caps[0]), g.caps.join());
  assert.ok(g.uncapped > g.score);
});

test("losses rank as the most expensive P/E, and banks are judged on price to book", () => {
  const mid = universe.find(u => u.t === "FI6").m;
  const g = F.gradeCompany({ ticker: "BNK", name: "Bank", sector: "Finance", metric: { ...mid, peTTM: -4 }, price: 80 }, universe);
  const value = g.factors.find(f => f.key === "value");
  assert.equal(value.metrics.find(m => m.key === "peTTM").percentile, 0);
  assert.ok(value.metrics.some(m => m.key === "pbQuarterly"));
  assert.ok(!value.metrics.some(m => m.key === "evEbitdaTTM"));
  assert.ok(!g.factors.find(f => f.key === "profitability").metrics.some(m => m.key === "grossMarginTTM"));
});

test("a sector with too few peers is ranked against everyone, and unknown sectors are not rated", () => {
  const small = universe.concat([{ t: "UT0", n: "Util", s: "Utilities", m: metricFor(5, 12, r), px: 70 }]);
  const g = F.gradeCompany({ ticker: "UT1", name: "Util 1", sector: "Utilities", metric: metricFor(6, 12, r), price: 70 }, small);
  assert.equal(g.basis, "all");
  assert.equal(F.gradeCompany({ ticker: "X", sector: null, metric: {} }, universe).status, "not-rated");
});

test("plain-English verdict and grade scale", () => {
  const worst = universe.find(u => u.t === "EN0").m;
  const g = F.gradeCompany({ ticker: "BAD", name: "Bad Oil", sector: "Energy", metric: worst, price: 60 }, universe);
  assert.match(g.verdict, /^Bad Oil is not yet profitable and its sales are shrinking\./);
  assert.match(g.verdict, /lagging the market/);
  assert.equal(F.gradeFor(95), "A+"); assert.equal(F.gradeFor(55), "B-"); assert.equal(F.gradeFor(5), "F");
  assert.equal(F.labelFor(8.2), "Top-rated");
});

test("grading the whole universe stays fast", () => {
  const big = [];
  for (let k = 0; k < 25; k++) universe.forEach(u => big.push({ ...u, t: u.t + "_" + k }));
  const t0 = Date.now();
  F.gradeCompany({ ticker: "SPD", name: "Speed", sector: "Tech", metric: universe[5].m, price: 80 }, big.slice(0, 300));
  assert.ok(Date.now() - t0 < 1500, `${Date.now() - t0}ms`);
});

test("the LensToolkit page is built around the report card and the API ships grades", () => {
  const fs = require("node:fs"), path = require("node:path");
  const html = fs.readFileSync(path.join(__dirname, "..", "labs", "lens-score", "index.html"), "utf8");
  for (const id of ["rc-score", "rc-factors", "rc-peer-body", "rc-timing-title", "strength-list", "concern-list"]) assert.match(html, new RegExp(`id="${id}"`), id);
  assert.doesNotMatch(html, /data-view="scenario"|data-view="value"/, "the retired Value/Scenario tabs are back");
  const app = fs.readFileSync(path.join(__dirname, "..", "labs", "lens-score", "app.js"), "utf8");
  assert.match(app, /payload\.grades/);
  const route = fs.readFileSync(path.join(__dirname, "..", "routes", "lens-score.js"), "utf8");
  assert.match(route, /grades: payload\.grades \|\| null/, "compact payload drops the grades");
  const { cardPayload } = require("../routes/lens-score");
  const card = cardPayload({ ticker: "X", score: { technical: { bars: [] } }, provenance: {}, grades: { status: "graded", factors: [], strengths: [], watch: [], score: 7.1 } });
  assert.equal(card.grades.score, 7.1);
});

test("peer universe maps Finnhub industries and keeps only graded fields", () => {
  const peers = require("../lib/peer-universe");
  peers._reset();
  peers.put("ZZZ", { profile: { name: "Zed", finnhubIndustry: "Banking", marketCapitalization: 1000 }, metric: { peTTM: 9, junk: 1 }, price: 12 });
  const r = peers.get("ZZZ");
  assert.equal(r.s, "Finance"); assert.equal(r.mc, 1e9); assert.equal(r.m.peTTM, 9); assert.equal(r.m.junk, undefined);
  assert.equal(peers.all().length, 1);
  peers._reset();
});

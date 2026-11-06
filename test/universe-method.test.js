"use strict";
/* LensScore 3.0: a fixed universe from SEC data, industry peers, and the
   corrected metric definitions. */
const test = require("node:test");
const assert = require("node:assert/strict");
process.env.NODE_ENV = "test";
const F = require("../lib/lens-factors");
const groups = require("../lib/industry-groups");
const members = require("../lib/universe-members");
const peers = require("../lib/peer-universe");
const sec = require("../lib/sec-fundamentals");

test("SIC codes map to industry groups only inside the company's own sector", () => {
  assert.equal(groups.groupFor(3674, "Tech"), "semis");
  assert.equal(groups.groupFor(7372, "Tech"), "software");
  assert.equal(groups.groupFor(6022, "Finance"), "banks");
  assert.equal(groups.groupFor(6798, "Real Est."), "reits");
  assert.equal(groups.groupFor(2836, "Health"), "biotech");
  assert.equal(groups.groupFor(7370, "Comm."), null, "Alphabet is pinned to Communication: no software group");
  assert.equal(groups.groupFor(null, "Tech"), null);
  assert.equal(groups.label("semis"), "Semiconductors");
});

function row(t, s, g, q, extra = {}) {
  return { t, n: t, s, g, px: 50, mc: 1e9, m: {
    peTTM: 40 - 30 * q, pegTTM: 3 - 2 * q, psTTM: 10 - 8 * q, pfcfShareTTM: 50 - 40 * q, evEbitdaTTM: 30 - 20 * q,
    revenueGrowthTTMYoy: 30 * q, revenueGrowthQuarterlyYoy: 30 * q, epsGrowthTTMYoy: 40 * q, revenueGrowth3Y: 20 * q, epsGrowth3Y: 25 * q,
    grossMarginTTM: 30 + 40 * q, operatingMarginTTM: 5 + 30 * q, netProfitMarginTTM: 3 + 25 * q, roeTTM: 5 + 30 * q, roiTTM: 4 + 20 * q,
    "totalDebt/totalEquityQuarterly": 2 - 1.5 * q, currentRatioQuarterly: 1 + q, netInterestCoverageTTM: 2 + 20 * q,
    "priceRelativeToS&P50013Week": -10 + 20 * q, "priceRelativeToS&P50026Week": -10 + 20 * q, "priceRelativeToS&P50052Week": -10 + 20 * q, "52WeekHigh": 60,
    ...extra } };
}

test("a chipmaker is graded against chipmakers once there are 15 of them, else its sector", () => {
  const uni = [];
  for (let i = 0; i < 20; i++) uni.push(row(`SEM${i}`, "Tech", "semis", i / 19));
  for (let i = 0; i < 20; i++) uni.push(row(`SW${i}`, "Tech", "software", i / 19, { grossMarginTTM: 90, operatingMarginTTM: 40 }));
  const me = row("NEW", "Tech", "semis", 0.95).m;
  const g = F.gradeCompany({ ticker: "NEW", sector: "Tech", group: "semis", metric: me, price: 50 }, uni);
  assert.equal(g.basis, "industry");
  assert.equal(g.groupName, "Semiconductors");
  assert.equal(g.peerCount, 20);
  assert.equal(g.rank.sectorName, "Semiconductors");
  assert.equal(g.rank.of, 21, "ranked among chipmakers only");
  assert.ok(g.strengths.some(x => /semiconductors peers/.test(x.text)), g.strengths.map(x => x.text).join(" | "));
  const few = uni.filter(r => r.g !== "semis" || Number(r.t.slice(3)) < 10);
  const g2 = F.gradeCompany({ ticker: "NEW", sector: "Tech", group: "semis", metric: me, price: 50 }, few);
  assert.equal(g2.basis, "sector", "10 chipmakers is too few: sector peers instead");
  const all = F.gradeUniverse(uni);
  const top = all.find(r => r.ticker === "SEM19");
  assert.equal(top.groupRank, 1);
  assert.equal(top.groupCount, 20);
  assert.equal(top.groupName, "Semiconductors");
});

test("forward P/E is gone, cash and enterprise multiples weigh 1.5x, beta has left Financial health", () => {
  const value = F.FACTORS.find(f => f.key === "value");
  assert.ok(!value.metrics.some(m => m.k === "forwardPE"));
  assert.equal(value.metrics.find(m => m.k === "pfcfShareTTM").w, 1.5);
  assert.equal(value.metrics.find(m => m.k === "evEbitdaTTM").w, 1.5);
  const health = F.FACTORS.find(f => f.key === "health");
  assert.ok(!health.metrics.some(m => m.k === "beta"));
  assert.deepEqual(health.metrics.find(m => m.k === "equityToAssetsQuarterly").only, ["Finance"]);
  assert.equal(F.VERSION, "3.0.0");
});

test("ROIC is after-tax operating profit over debt plus equity minus cash", () => {
  const snap = { ttm: { revenue: 1000, operatingIncome: 200, netIncome: 150 }, prevTtm: {}, debt: 300, equity: 900, cash: 200, assets: 2000, taxRate: 0.2 };
  const m = sec.metricsFrom(snap, { price: null, rows: [], bench: [], ticker: "X" });
  assert.equal(Math.round(m.roiTTM * 10) / 10, 16, "200 × 0.8 / (300 + 900 − 200) = 16%");
  assert.equal(m.equityToAssetsQuarterly, 45);
});

test("point-in-time facts drop everything filed after the date", () => {
  const facts = { facts: { "us-gaap": { Revenues: { units: { USD: [
    { end: "2024-12-31", val: 1, filed: "2025-02-01" }, { end: "2025-03-31", val: 2, filed: "2025-05-01" },
  ] } } } } };
  const past = sec.factsAsOf(facts, "2025-03-01");
  assert.equal(past.facts["us-gaap"].Revenues.units.USD.length, 1);
  assert.equal(facts.facts["us-gaap"].Revenues.units.USD.length, 2, "the original is untouched");
});

test("the universe is the largest listed companies by public float, one common ticker each", () => {
  assert.equal(members.isCommonTicker("BRK-B"), true);
  assert.equal(members.isCommonTicker("BAC-PL"), false);
  assert.equal(members.isCommonTicker("ABCDW"), false);
  assert.equal(members.isCommonTicker("XYZ-WS"), false);
  const listed = { fields: ["cik", "name", "ticker", "exchange"], data: [
    [1, "Alpha", "GOOGL", "Nasdaq"], [1, "Alpha", "GOOG", "Nasdaq"], [2, "Big Bank", "BB", "NYSE"],
    [3, "OTC Co", "OTCX", "OTC"], [4, "Small", "SML", "NYSE"], [5, "No float", "NOF", "NYSE"], [2, "Big Bank", "BB-PA", "NYSE"],
  ] };
  const frames = [{ data: [{ cik: 1, val: 2e12, end: "2025-06-30" }, { cik: 2, val: 3e11, end: "2025-06-30" }, { cik: 3, val: 9e12, end: "2025-06-30" }, { cik: 4, val: 1e9, end: "2025-06-30" }] }];
  const list = members.buildList(listed, frames, { size: 2, prefer: new Set(["GOOGL"]) });
  assert.deepEqual(list.map(c => c.ticker), ["GOOGL", "BB"]);
  assert.deepEqual(members.recentQuarters(new Date("2026-11-06T00:00:00Z")), ["CY2026Q3I", "CY2026Q2I", "CY2026Q1I", "CY2025Q4I", "CY2025Q3I", "CY2025Q2I", "CY2025Q1I", "CY2024Q4I"],
    "a December company's latest float (June 2025, filed Feb 2026) is in CY2025Q2I");
});

test("a stock outside the universe is graded against it but never joins it", () => {
  peers._reset();
  peers.put("AAA", { name: "A", sector: "Tech", sic: 3674, metric: { peTTM: 10 }, price: 5 });
  peers.put("ZZZ", { name: "Z", sector: "Tech", sic: 3674, metric: { peTTM: 12 }, price: 5 });
  peers.setMembers(["AAA"]);
  assert.deepEqual(peers.all().map(r => r.t), ["AAA"]);
  assert.ok(peers.get("ZZZ"), "its own row is kept for its page");
  assert.equal(peers.get("AAA").g, "semis");
  peers._reset();
});

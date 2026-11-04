"use strict";
/* The link-preview image for a stock page (audit F06 follow-up). */
process.env.NODE_ENV = "test";
const test = require("node:test");
const assert = require("node:assert");
const peers = require("../lib/peer-universe");
const universeGrades = require("../lib/universe-grades");
const { dataFor } = require("../routes/og-image");
const og = require("../lib/og-card");

/* A small graded universe: the grading itself is tested elsewhere, so the
   grade source is stubbed with rows of the shape lib/lens-factors returns. */
function seed() {
  const rows = Array.from({ length: 40 }, (_, i) => ({
    ticker: i === 0 ? "NVDA" : "T" + String(i).padStart(2, "0"), name: i === 0 ? "NVIDIA CORP" : "Company " + i,
    sector: "Tech", sectorName: "Technology", price: 100 + i, marketCap: (40 - i) * 1e11,
    score: Math.round((9.9 - i * 0.2) * 10) / 10, label: i === 0 ? "Top-rated" : "Graded",
    grades: { value: "B-", growth: "A+", profitability: "A+", health: "B+", momentum: "B-" },
  }));
  universeGrades.current = () => ({ rows });
  universeGrades.get = t => rows.find(r => r.ticker === t) || null;
  peers._reset();
  peers.put("NVDA", { name: "NVIDIA CORP", sector: "Tech", industry: "Semiconductors", price: 100, metric: { "52WeekPriceReturnDaily": -5, marketCapitalization: 4e6 } });
}

test("a graded stock gets its own card; one we do not grade gets none", () => {
  seed();
  const d = dataFor("NVDA", "https://impliedlens.com");
  assert.ok(d, "graded data");
  assert.equal(d.ticker, "NVDA");
  assert.ok(Number.isFinite(d.score));
  assert.equal(d.url, "impliedlens.com/research/NVDA");
  assert.ok(d.rank && d.rank.of === 40);
  assert.equal(d.yearPct, -5);
  assert.equal(dataFor("ZZZZ", "https://impliedlens.com"), null);
});

test("the card renders as a 1200x630 PNG and leaves out what it does not have", () => {
  seed();
  const d = dataFor("NVDA", "https://impliedlens.com");
  const png = og.render(d);
  assert.equal(png.slice(1, 4).toString(), "PNG");
  assert.equal(png.readUInt32BE(16), 1200);
  assert.equal(png.readUInt32BE(20), 630);
  const svg = og.svgFor({ ...d, price: null, changePct: null, yearPct: null, marketCap: null });
  assert.doesNotMatch(svg, /PAST YEAR|MARKET CAP|today/);
  assert.doesNotMatch(svg, /NaN|undefined|Infinity/);
});

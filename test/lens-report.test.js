"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const A = require("../public/app/analysis.js");
const V = require("../public/app/valuation.js");

function hist(rows) {
  return { quarters: rows.map((r, i) => ({ end: `2024-${String(i + 1).padStart(2, "0")}-28`, ...r })) };
}
// 8 quarters: revenue 100 → 170, steady 20% net margin, shares flat.
const growing = hist(Array.from({ length: 8 }, (_, i) => {
  const revenue = 100 + i * 10;
  return { revenue, netIncome: revenue * 0.25, operatingIncome: revenue * 0.3, grossProfit: revenue * 0.6, operatingCashFlow: revenue * 0.3, freeCashFlow: revenue * 0.2, eps: revenue * 0.25 / 10, shares: 10 };
}));

test("twelve-month figures and growth come from the last four quarters", () => {
  const f = A.fundamentals(growing);
  assert.equal(f.revenue, 140 + 150 + 160 + 170);
  assert.equal(f.revenuePrev, 100 + 110 + 120 + 130);
  assert.ok(Math.abs(f.growth1y - (620 / 460 - 1) * 100) < 1e-9);
  assert.equal(f.netMargin, 25);
  assert.equal(f.shareChange, 0);
});

test("flags state the number behind them and only fire on real data", () => {
  const f = A.fundamentals(growing);
  const fl = A.flags({ fundamentals: f });
  const keys = fl.map(x => x.key);
  assert.ok(keys.includes("growth"), "35% growth is flagged as fast");
  assert.ok(keys.includes("margin"), "25% net margin is flagged");
  assert.ok(!keys.includes("loss") && !keys.includes("dilution") && !keys.includes("burn"));
  for (const x of fl) assert.match(x.detail, /\d/, `${x.key} carries a number`);
  assert.deepEqual(A.flags({}), [], "no data, no flags");
});

test("losses, cash burn and dilution are warning signs", () => {
  const bad = hist(Array.from({ length: 8 }, (_, i) => ({ revenue: 100, netIncome: -20, operatingIncome: -15, operatingCashFlow: -10, freeCashFlow: -25, eps: -0.2, shares: 100 + i * 3 })));
  const keys = A.flags({ fundamentals: A.fundamentals(bad) }).filter(x => x.tone === "bad").map(x => x.key);
  for (const k of ["loss", "burn", "dilution"]) assert.ok(keys.includes(k), k);
});

test("the report's valuation matches the Projection Lab's starting point", () => {
  const f = A.fundamentals(growing);
  const bars = Array.from({ length: 260 }, (_, i) => ({ time: 1.7e9 + i * 86400, close: 100 + i * 0.1 }));
  const p = A.priceFacts(bars, { regularMarketPrice: 126 });
  const v = A.valuation(f, p, 30, V);
  // The lab's own inputs: P/E from price over last-12-month EPS, recent quarters for growth.
  const eps = f.netIncome / f.shares;
  const d = V.defaults({ margin: f.netIncome / f.revenue, pe: 126 / eps, growth1y: f.growth1y / 100, growth3y: f.growth3y !== null ? f.growth3y / 100 : null, quarters: f.series });
  const g = V.impliedGrowth({ price: 126, revenue: f.revenue, shares: f.shares, years: 5, margin: d.base.margin, exitPE: d.base.exitPE, shareChange: d.shareChange, required: 0.1 });
  assert.ok(Math.abs(v.implied - g) < 1e-12);
  assert.ok(v.verdict && ["rich", "full", "fair", "cheap"].includes(v.verdict.key));
});

test("the story is short sentences built from the inputs", () => {
  const s = A.story({ name: "Acme", fundamentals: A.fundamentals(growing), grades: { status: "graded", score: 7.2, sectorName: "Technology", rank: { position: 3, of: 40 }, factors: [{ key: "value", grade: "C" }, { key: "growth", grade: "A" }] } });
  assert.match(s[0], /^Acme brought in \$620 of revenue/);
  assert.match(s[1], /7\.2 out of 10, #3 of 40, strongest on growth and weakest on value/);
});

test("history queries never alias a column to an SQL keyword", () => {
  // `AS then` is a syntax error in SQLite; it silently broke weekly movers and the track record.
  const src = require("node:fs").readFileSync(require("node:path").join(__dirname, "..", "lib", "lens-history.js"), "utf8");
  assert.doesNotMatch(src, /\bAS\s+(then|when|case|end|order|group|select|from|where)\b/i);
});

test("a cover-page share count far below the income statement's is not used for market cap", () => {
  const { metricsFrom } = require("../lib/sec-fundamentals.js");
  const m = metricsFrom({ sharesOutstanding: 7800, ttm: { netIncome: 2e9, eps: 6, revenue: 6e9 } }, { price: 200 });
  assert.ok(Math.abs(m.marketCapitalization - 200 * (2e9 / 6) / 1e6) < 1, `got ${m.marketCapitalization}`);
  const ok = metricsFrom({ sharesOutstanding: 3.3e8, ttm: { netIncome: 2e9, eps: 6, revenue: 6e9 } }, { price: 200 });
  assert.equal(ok.marketCapitalization, 200 * 3.3e8 / 1e6);
});

/* Codex audit F03: missing statements must never read as a clean report. */
test("without statements the summary carries the report card and says what did not run", () => {
  const A = require("../public/app/analysis.js");
  const grades = { factors: [{ key: "health", grade: "B" }], strengths: [{ text: "Return on capital 30%: well above peers." }], watch: [{ text: "Price to sales of 24x is higher than 70% of peers." }] };
  const input = { fundamentals: null, price: null, grades, valuation: null };
  const fl = A.flags(input);
  assert.ok(fl.some(f => f.tone === "bad" && /Price to sales/.test(f.title)), "the report card's watch-out appears as a warning");
  assert.ok(fl.some(f => f.tone === "good" && /Return on capital/.test(f.title)), "the report card's strength stands in");
  assert.equal(A.coverage(input).statements, false);
});

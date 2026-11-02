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

test("the report's valuation matches the Valuation tab's defaults", () => {
  const f = A.fundamentals(growing);
  const bars = Array.from({ length: 260 }, (_, i) => ({ time: 1.7e9 + i * 86400, close: 100 + i * 0.1 }));
  const p = A.priceFacts(bars, { regularMarketPrice: 126 });
  const v = A.valuation(f, p, 30, V);
  const d = V.defaults({ margin: 0.25, pe: 30, growth1y: f.growth1y / 100, growth3y: null });
  const g = V.impliedGrowth({ price: 126, revenue: f.revenue, shares: 10, years: 5, margin: d.base.margin, exitPE: d.base.exitPE, required: 0.1 });
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

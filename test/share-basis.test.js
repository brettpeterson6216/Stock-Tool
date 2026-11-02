"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const sec = require("../lib/sec-fundamentals");

/* Codex audit F01: Berkshire files in Class A equivalents; BRK.B trades at
   1/1500 of a Class A share. */
const brk = { sharesOutstanding: 941481, ttm: { revenue: 371e9, netIncome: 89e9, eps: 61800 }, equity: 650e9 };

test("BRK.B is valued on Class B equivalents, not Class A share counts", () => {
  const b = sec.quoteBasis(brk, { ticker: "BRK.B", price: 556.11 });
  assert.equal(b.ratio, 1500);
  assert.ok(b.mcap > 500e9 && b.mcap < 2e12, "company value in the hundreds of billions, got " + b.mcap);
  assert.ok(Math.abs(b.eps - 61800 / 1500) < 1e-9);
  assert.equal(b.plausible, true);
  const m = sec.metricsFrom(brk, { price: 556.11, ticker: "BRK.B" });
  assert.ok(m.psTTM > 1 && m.peTTM > 5, "ratios are no longer near zero");
});

test("an implausibly small market cap never reaches grading", () => {
  const m = sec.metricsFrom(brk, { price: 556.11, ticker: "XYZ" });
  assert.equal(m.psTTM, undefined);
  assert.equal(m.pbQuarterly, undefined);
  assert.equal(m.peTTM, undefined);
  assert.equal(m.marketCapitalization, undefined);
  assert.equal(sec.quoteBasis(brk, { ticker: "XYZ", price: 556.11 }).plausible, false);
});

test("ordinary companies are unchanged", () => {
  const snap = { sharesOutstanding: 24.4e9, ttm: { revenue: 165e9, netIncome: 86e9, eps: 3.5 } };
  const b = sec.quoteBasis(snap, { ticker: "NVDA", price: 200 });
  assert.equal(b.ratio, 1);
  assert.equal(b.shares, 24.4e9);
  assert.equal(b.plausible, true);
});

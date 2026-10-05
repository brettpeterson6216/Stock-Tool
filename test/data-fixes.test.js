"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { matchedTtm, latestDilutedShares } = require("../lib/ttm");

const u = (start, end, val, form, filed) => ({ start, end, val, form, filed: filed || end });
/* Bank-shaped facts: FY2025 revenue under Revenues, but the 2026 10-Qs tag
   revenue as RevenuesNetOfInterestExpense; net income has both. */
const gaap = {
  Revenues: { units: { USD: [u("2025-01-01", "2025-12-31", 182e9, "10-K")] } },
  RevenuesNetOfInterestExpense: { units: { USD: [
    u("2025-01-01", "2025-12-31", 182e9, "10-K"),
    u("2026-01-01", "2026-06-30", 95e9, "10-Q"),
    u("2025-01-01", "2025-06-30", 91e9, "10-Q"),
  ] } },
  NetIncomeLoss: { units: { USD: [
    u("2025-01-01", "2025-12-31", 57e9, "10-K"),
    u("2026-01-01", "2026-06-30", 33e9, "10-Q"),
    u("2025-01-01", "2025-06-30", 28e9, "10-Q"),
  ] } },
};

test("revenue and net income come from the same twelve months", () => {
  const REV = ["Revenues", "RevenueFromContractWithCustomerExcludingAssessedTax", "RevenuesNetOfInterestExpense"];
  const both = matchedTtm(gaap, REV, ["NetIncomeLoss"]);
  assert.equal(both.asOf, "2026-06-30");
  assert.equal(both.revenue.asOf, both.netIncome.asOf);
  assert.equal(both.revenue.val, 186e9);
  assert.equal(both.netIncome.val, 62e9);
});

test("without a matching revenue period, both fall back to the newest shared one", () => {
  const both = matchedTtm(gaap, ["Revenues"], ["NetIncomeLoss"]);
  assert.equal(both.asOf, "2025-12-31");
  assert.equal(both.netIncome.val, 57e9);
});

test("diluted shares come from the latest quarter, with a 3-year trend", () => {
  const rows = [
    u("2022-01-01", "2022-12-31", 1000, "10-K"), u("2023-01-01", "2023-12-31", 970, "10-K"),
    u("2024-01-01", "2024-12-31", 940, "10-K"), u("2025-01-01", "2025-12-31", 910, "10-K"),
    u("2026-04-01", "2026-06-30", 900, "10-Q"),
  ];
  const d = latestDilutedShares({ facts: { "us-gaap": { WeightedAverageNumberOfDilutedSharesOutstanding: { units: { shares: rows } } } } });
  assert.equal(d.val, 900);
  assert.ok(d.cagr3 < 0 && d.cagr3 > -0.04);
});

test("discount rate uses an adjusted beta and stays in a sane band", () => {
  const { suggestDiscountRate } = require("../routes/financials.js");
  assert.ok(suggestDiscountRate(2.25, 10) <= 13, "high-beta stock no longer 16.9%");
  assert.ok(suggestDiscountRate(1.1, 250) >= 6.5, "bank debt cannot drag it to the floor");
  assert.equal(suggestDiscountRate(null, 0), null);
});

test("estimates say 'unavailable' instead of 'available' with nulls", () => {
  const src = fs.readFileSync(path.join(__dirname, "..", "routes", "financials.js"), "utf8");
  assert.match(src, /status: hasEstimates \? "available" : "unavailable"/);
  assert.doesNotMatch(src, /const forwardPE = m\["peNormalizedAnnual"\]/);
});

test("the quote P/E prefers TTM over the year-old annual figure", () => {
  const src = fs.readFileSync(path.join(__dirname, "..", "routes", "market-data.js"), "utf8");
  assert.doesNotMatch(src, /peNormalizedAnnual\s*\|\|\s*m2?\.peBasicExclExtraTTM/);
  assert.match(src, /peBasicExclExtraTTM\s*\|\|\s*m\.peNormalizedAnnual/);
});

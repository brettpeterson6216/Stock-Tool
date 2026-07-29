"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const {
  annualSeries,
  deriveFundamentals,
  parseYahooChart,
  researchTicker,
  selectReferenceEps,
  trailingFourQuarterEps,
} = require("../lib/stock-research");

const celhQuarterlyActuals = [
  { period: "2026-03-31", actual: 0.47 },
  { period: "2025-12-31", actual: 0.42 },
  { period: "2025-09-30", actual: 0.26 },
  { period: "2025-06-30", actual: 0.41 },
];

test("trailing-four-quarter EPS uses four unique, consecutive reported quarters", () => {
  const result = trailingFourQuarterEps([
    ...celhQuarterlyActuals,
    { period: "2026-03-31", actual: 999 },
    { period: "not-a-date", actual: 2 },
  ]);
  assert.equal(result.value, 1.56);
  assert.equal(result.basis, "Trailing four-quarter actual EPS");
  assert.equal(result.asOf, "2026-03-31");
  assert.deepEqual(result.quarters, [
    "2026-03-31",
    "2025-12-31",
    "2025-09-30",
    "2025-06-30",
  ]);
});

test("CELH-style quarterly actuals outrank stale annual reported EPS", () => {
  const result = selectReferenceEps({
    reportedAnnualEps: { val: 0.25, end: "2025-12-31" },
    earnings: celhQuarterlyActuals,
  });
  assert.equal(result.value, 1.56);
  assert.equal(result.basis, "Trailing four-quarter actual EPS");
  assert.equal((10 / result.value).toFixed(1), "6.4");
});

test("dated forward annual consensus EPS remains the preferred valuation basis", () => {
  const result = selectReferenceEps({
    estimatedEps: { epsAvg: 2.1, period: "2027-12-31" },
    reportedAnnualEps: { val: 0.25, end: "2025-12-31" },
    earnings: celhQuarterlyActuals,
  });
  assert.equal(result.value, 2.1);
  assert.equal(result.basis, "Forward annual consensus EPS");
  assert.equal(result.asOf, "2027-12-31");
});

test("incomplete or stale quarterly evidence falls back to annual reported EPS", () => {
  const result = selectReferenceEps({
    reportedAnnualEps: { val: 0.75, end: "2025-12-31" },
    earnings: celhQuarterlyActuals.slice(0, 3),
  });
  assert.equal(result.value, 0.75);
  assert.equal(result.basis, "Latest annual reported diluted EPS");
});

test("four observations with a missing quarter are not mislabeled as trailing-four-quarter EPS", () => {
  const result = selectReferenceEps({
    reportedAnnualEps: { val: 0.25, end: "2025-12-31" },
    earnings: [
      { period: "2026-03-31", actual: 0.33 },
      { period: "2025-09-30", actual: -0.27 },
      { period: "2025-06-30", actual: 0.33 },
      { period: "2025-03-31", actual: 0.15 },
    ],
  });
  assert.equal(result.value, 0.25);
  assert.equal(result.basis, "Latest annual reported diluted EPS");
});

test("US share-class dots normalize to the provider-compatible dash without changing exchange suffixes", () => {
  assert.equal(researchTicker("brk.b"), "BRK-B");
  assert.equal(researchTicker("shop.to"), "SHOP.TO");
});

test("IFRS 20-F facts participate in the same reported-data pipeline as US GAAP facts", () => {
  const companyFacts = {
    facts: {
      facts: {
        "ifrs-full": {
          Revenue: {
            units: {
              USD: [
                { val: 100, start: "2024-01-01", end: "2024-12-31", filed: "2025-04-01", form: "20-F" },
                { val: 120, start: "2025-01-01", end: "2025-12-31", filed: "2026-04-01", form: "20-F" },
              ],
            },
          },
        },
      },
    },
  };
  const rows = annualSeries(companyFacts, ["Revenue"]);
  assert.deepEqual(rows.map(row => row.val), [100, 120]);
});

test("reported growth series never mixes currencies or concepts between years", () => {
  const companyFacts = {
    facts: {
      facts: {
        "ifrs-full": {
          Revenue: {
            units: {
              USD: [
                { val: 88, start: "2025-01-01", end: "2025-12-31", filed: "2026-04-01", form: "20-F" },
              ],
            },
          },
          RevenueFromContractsWithCustomers: {
            units: {
              TWD: [
                { val: 2000, start: "2023-01-01", end: "2023-12-31", filed: "2024-04-01", form: "20-F" },
                { val: 2400, start: "2024-01-01", end: "2024-12-31", filed: "2025-04-01", form: "20-F" },
                { val: 3000, start: "2025-01-01", end: "2025-12-31", filed: "2026-04-01", form: "20-F" },
              ],
            },
          },
        },
      },
    },
  };
  const rows = annualSeries(companyFacts, ["Revenue", "RevenueFromContractsWithCustomers"]);
  assert.deepEqual(rows.map(row => row.val), [2000, 2400, 3000]);
  assert.ok(rows.every(row => row.unit === "TWD"));
});

test("current provider metrics can rate non-SEC companies without fabricating filings", () => {
  const now = new Date().toISOString();
  const fundamentals = deriveFundamentals(null, 40, {
    metrics: {
      revenueGrowthQuarterlyYoy: 18,
      epsGrowthTTMYoy: 22,
      fcfPerShareTTM: 2.4,
      revenuePerShareTTM: 12,
      roiAnnual: 16,
      netProfitMarginTTM: 14,
      roeTTM: 19,
      netDebtAnnual: 100,
      ebitdaTTM: 250,
      interestCoverageAnnual: 9,
      shareGrowthAnnual: 1,
      peNormalizedAnnual: 24,
    },
    estimates: null,
    earnings: celhQuarterlyActuals,
    provenance: { retrievedAt: now },
  });
  assert.equal(fundamentals.freshness.status, "current");
  assert.equal(fundamentals.values.revenueGrowth, 0.18);
  assert.ok(Math.abs(fundamentals.values.fcfMargin - 0.2) < 1e-10);
  assert.equal(fundamentals.values.returnOnEquity, 0.19);
  assert.ok(fundamentals.coverage >= 0.8);
});

test("foreign-currency earnings are normalized before valuing a USD-listed security", () => {
  const retrievedAt = new Date().toISOString();
  const fundamentals = deriveFundamentals(null, 100, {
    metrics: {
      revenueGrowthQuarterlyYoy: 20,
      epsGrowthTTMYoy: 25,
      roiAnnual: 18,
      netProfitMarginTTM: 15,
      roeTTM: 20,
      peNormalizedAnnual: 25,
    },
    estimates: null,
    earnings: celhQuarterlyActuals.map(row => ({ ...row, actual: row.actual * 30 })),
    profile: { currency: "TWD" },
    provenance: { retrievedAt },
  }, { currency: "USD" });
  assert.equal(fundamentals.earningsCurrencyMismatch, true);
  assert.equal(fundamentals.referenceEpsBasis, "Provider-normalized earnings multiple");
  assert.equal(fundamentals.referenceEps, 4);
  assert.equal(fundamentals.values.forwardPE, 25);
});

test("stale market history is rejected instead of being presented as current LensScore evidence", () => {
  const start = Math.floor(Date.now() / 1000) - 900 * 86400;
  const timestamps = Array.from({ length: 80 }, (_, index) => start + index * 86400);
  const values = timestamps.map((_, index) => 100 + index);
  assert.throws(() => parseYahooChart({
    chart: {
      result: [{
        timestamp: timestamps,
        meta: { symbol: "OLD" },
        indicators: {
          quote: [{ open: values, high: values, low: values, close: values, volume: values }],
        },
      }],
    },
  }, "OLD", "Test provider"), /stale/i);
});

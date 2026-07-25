"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const {
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

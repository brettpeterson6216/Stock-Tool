"use strict";
const test = require("node:test");
const assert = require("node:assert");
const { ttmFromFacts, latestSharesFromFacts } = require("../lib/ttm");

// Apple-shaped: fiscal year ends late September.
const gaap = { Revenues: { units: { USD: [
  { start: "2023-10-01", end: "2024-09-28", val: 391, form: "10-K", filed: "2024-11-01" },
  { start: "2024-09-29", end: "2025-09-27", val: 416, form: "10-K", filed: "2025-10-31" },
  // FY2025 nine months (prior-year comparative, appears in the FY2026 10-Q too)
  { start: "2024-09-29", end: "2025-06-28", val: 313, form: "10-Q", filed: "2025-08-01" },
  // FY2026 year to date: six and nine months
  { start: "2025-09-28", end: "2026-03-28", val: 230, form: "10-Q", filed: "2026-05-01" },
  { start: "2025-09-28", end: "2026-06-27", val: 335, form: "10-Q", filed: "2026-07-31" },
  // a single quarter, must be ignored as YTD only when it is not fiscal-YTD
  { start: "2026-03-29", end: "2026-06-27", val: 105, form: "10-Q", filed: "2026-07-31" },
] } } };

test("TTM adds the newest year-to-date and removes the same period a year earlier", () => {
  const r = ttmFromFacts(gaap, ["Revenues"]);
  assert.strictEqual(r.basis, "ttm");
  assert.strictEqual(r.asOf, "2026-06-27");
  assert.strictEqual(r.val, 416 + 335 - 313);
});

test("Without a newer 10-Q the annual figure is returned", () => {
  const only = { Revenues: { units: { USD: gaap.Revenues.units.USD.filter(u => u.form === "10-K") } } };
  const r = ttmFromFacts(only, ["Revenues"]);
  assert.deepStrictEqual(r, { val: 416, asOf: "2025-09-27", basis: "annual" });
});

test("Without the prior-year comparative it falls back to annual rather than guessing", () => {
  const noPrior = { Revenues: { units: { USD: gaap.Revenues.units.USD.filter(u => u.end !== "2025-06-28") } } };
  assert.strictEqual(ttmFromFacts(noPrior, ["Revenues"]).basis, "annual");
});

test("The freshest concept wins when a company changed tags", () => {
  const mixed = { OldTag: { units: { USD: [{ start: "2019-01-01", end: "2019-12-31", val: 9, form: "10-K", filed: "2020-02-01" }] } }, Revenues: gaap.Revenues };
  assert.strictEqual(ttmFromFacts(mixed, ["OldTag", "Revenues"]).asOf, "2026-06-27");
});

test("Latest share count comes from the newest cover page", () => {
  const facts = { facts: { dei: { EntityCommonStockSharesOutstanding: { units: { shares: [
    { end: "2025-10-17", val: 14.9e9 }, { end: "2026-07-18", val: 14.7e9 } ] } } } } };
  assert.deepStrictEqual(latestSharesFromFacts(facts), { val: 14.7e9, asOf: "2026-07-18" });
});

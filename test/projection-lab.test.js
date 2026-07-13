"use strict";

/* Projection Lab v2 — canonical model engine tests.
   Includes the SOFI regression case from the FY2026 repair spec. */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const math = require("../public/model-math");

function sofiModel() {
  const model = math.plCreateModel({
    ticker: "SOFI",
    companyName: "SoFi Technologies",
    baseYear: 2026,
    startPrice: 18.18,
    dilutedShares: 1355979000,
    baseRevenue: 4655000000,
    baseNetIncome: 825000000,
    horizon: 5,
    source: "test seed",
    seeded: true,
  });
  model.scenarios.base.revGrowth = [30, 30, 22, 18, 15, 15, 15, 15, 15, 15];
  model.scenarios.base.netMargin = [18.5, 18.5, 20, 22, 24, 24, 24, 24, 24, 24];
  model.scenarios.base.peLow = [25, 24, 22, 20, 18, 18, 18, 18, 18, 18];
  model.scenarios.base.peHigh = [35, 34, 32, 30, 28, 28, 28, 28, 28, 28];
  return model;
}

function near(actual, expected, tolerance) {
  assert.ok(
    Math.abs(actual - expected) <= tolerance,
    `expected ${actual} to be within ${tolerance} of ${expected}`
  );
}

test("SOFI regression: base-year derived values", () => {
  const model = sofiModel();
  const derived = math.plBaseDerived(model);
  near(derived.netMargin, 0.1772, 0.001);      // ~17.7%, not 78%
  near(derived.eps, 0.6084, 0.001);            // ~$0.61
});

test("SOFI regression: base case year-by-year path", () => {
  const model = sofiModel();
  const result = math.plCalculateProjection(model, "base");
  assert.equal(result.ok, true);
  assert.equal(result.rows.length, 5);
  assert.equal(result.base.revenue, 4655000000); // table base column = entered revenue, not stale $619.4M

  const y2027 = result.rows[0];
  assert.equal(y2027.year, 2027);
  near(y2027.revenue, 6.0515e9, 0.001e9);
  near(y2027.netIncome, 1.1195e9, 0.002e9);
  near(y2027.eps, 0.8256, 0.002);
  near(y2027.priceLow, 20.64, 0.05);
  near(y2027.priceHigh, 28.90, 0.05);

  const y2028 = result.rows[1];
  near(y2028.revenue, 7.867e9, 0.01e9);
  near(y2028.netIncome, 1.455e9, 0.01e9);
  near(y2028.eps, 1.073, 0.005);
  near(y2028.priceLow, 25.76, 0.1);
  near(y2028.priceHigh, 36.49, 0.1);

  const y2029 = result.rows[2];
  near(y2029.revenue, 9.598e9, 0.02e9);
  near(y2029.eps, 1.416, 0.01);
  near(y2029.priceLow, 31.14, 0.15);
  near(y2029.priceHigh, 45.30, 0.2);

  const y2030 = result.rows[3];
  near(y2030.revenue, 11.33e9, 0.02e9);
  near(y2030.eps, 1.838, 0.01);
  near(y2030.priceLow, 36.75, 0.2);
  near(y2030.priceHigh, 55.12, 0.2);

  const y2031 = result.rows[4];
  near(y2031.revenue, 13.02e9, 0.02e9);
  near(y2031.netIncome, 3.13e9, 0.01e9);
  near(y2031.eps, 2.305, 0.01);
  near(y2031.priceLow, 41.49, 0.2);
  near(y2031.priceHigh, 64.54, 0.3);

  // CAGR sanity: ($41.49 / $18.18)^(1/5) − 1 ≈ 18%
  near(y2031.cagrLow, 0.179, 0.005);
  near(y2031.cagrHigh, 0.288, 0.005);
});

test("editing base revenue flows through every projected year", () => {
  const model = sofiModel();
  const before = math.plCalculateProjection(model, "base");
  model.baseRevenue = 9310000000; // 2× revenue
  const after = math.plCalculateProjection(model, "base");
  assert.equal(after.ok, true);
  for (let i = 0; i < 5; i += 1) {
    near(after.rows[i].revenue, before.rows[i].revenue * 2, 1);
    near(after.rows[i].priceLow, before.rows[i].priceLow * 2, 0.01);
  }
});

test("editing net income changes base margin and EPS but not projected revenue", () => {
  const model = sofiModel();
  const before = math.plCalculateProjection(model, "base");
  model.baseNetIncome = 1650000000;
  const after = math.plCalculateProjection(model, "base");
  near(after.base.netMargin, 0.3545, 0.001);
  near(after.base.eps, 1.2168, 0.001);
  // Projected years use the per-year margin assumptions, so revenue and forward prices are unchanged.
  assert.equal(after.rows[4].revenue, before.rows[4].revenue);
  assert.equal(after.rows[4].priceLow, before.rows[4].priceLow);
});

test("editing diluted shares changes EPS and valuation, not company financials", () => {
  const model = sofiModel();
  const before = math.plCalculateProjection(model, "base");
  model.dilutedShares = 2711958000; // 2× shares
  const after = math.plCalculateProjection(model, "base");
  near(after.rows[4].eps, before.rows[4].eps / 2, 0.001);
  near(after.rows[4].priceLow, before.rows[4].priceLow / 2, 0.01);
  assert.equal(after.rows[4].revenue, before.rows[4].revenue);
  assert.equal(after.rows[4].netIncome, before.rows[4].netIncome);
});

test("editing start price changes CAGR but not projected financials or prices", () => {
  const model = sofiModel();
  const before = math.plCalculateProjection(model, "base");
  model.startPrice = 9.09;
  const after = math.plCalculateProjection(model, "base");
  assert.equal(after.rows[4].revenue, before.rows[4].revenue);
  assert.equal(after.rows[4].priceLow, before.rows[4].priceLow);
  assert.ok(after.rows[4].cagrLow > before.rows[4].cagrLow);
  near(after.rows[4].cagrLow, Math.pow(41.49 / 9.09, 1 / 5) - 1, 0.005);
});

test("editing growth, margin, and P/E for one year affects that year forward", () => {
  const model = sofiModel();
  model.scenarios.base.revGrowth[0] = 50;
  const growthEdit = math.plCalculateProjection(model, "base");
  near(growthEdit.rows[0].revenue, 4655000000 * 1.5, 1);
  near(growthEdit.rows[1].revenue, 4655000000 * 1.5 * 1.3, 1);

  model.scenarios.base.netMargin[2] = 25;
  const marginEdit = math.plCalculateProjection(model, "base");
  near(marginEdit.rows[2].netIncome, marginEdit.rows[2].revenue * 0.25, 1);

  model.scenarios.base.peHigh[4] = 40;
  const peEdit = math.plCalculateProjection(model, "base");
  near(peEdit.rows[4].priceHigh, peEdit.rows[4].eps * 40, 0.01);
});

test("scenarios are independent: editing base does not touch bear or bull", () => {
  const model = sofiModel();
  const bearBefore = math.plCalculateProjection(model, "bear");
  const bullBefore = math.plCalculateProjection(model, "bull");
  model.scenarios.base.revGrowth = model.scenarios.base.revGrowth.map(() => 99);
  const bearAfter = math.plCalculateProjection(model, "bear");
  const bullAfter = math.plCalculateProjection(model, "bull");
  assert.deepEqual(bearAfter.rows, bearBefore.rows);
  assert.deepEqual(bullAfter.rows, bullBefore.rows);
});

test("switching horizons changes the terminal year without altering assumptions", () => {
  const model = sofiModel();
  model.selectedHorizon = 3;
  const three = math.plCalculateOutlook(model);
  assert.equal(three.ok, true);
  assert.equal(three.terminalYear, 2029);
  model.selectedHorizon = 5;
  const five = math.plCalculateOutlook(model);
  assert.equal(five.terminalYear, 2031);
  // 3y rows must match the first three 5y rows exactly.
  assert.deepEqual(three.scenarios.base.rows, five.scenarios.base.rows.slice(0, 3));
  model.selectedHorizon = 10;
  const ten = math.plCalculateOutlook(model);
  assert.equal(ten.terminalYear, 2036);
  assert.equal(ten.scenarios.base.rows.length, 10);
});

test("expected value is the weighted terminal midpoints, matching visible weights", () => {
  const model = sofiModel();
  const outlook = math.plCalculateOutlook(model);
  assert.equal(outlook.ok, true);
  const t = (k) => outlook.scenarios[k].terminal;
  const mid = (k) => (t(k).priceLow + t(k).priceHigh) / 2;
  const expected = 0.25 * mid("bear") + 0.5 * mid("base") + 0.25 * mid("bull");
  near(outlook.expected.price, expected, 0.001);
  near(outlook.expected.cagr, Math.pow(expected / 18.18, 1 / 5) - 1, 0.0001);
  // Changing weights changes the expected value.
  model.scenarioWeights = { bear: 10, base: 60, bull: 30 };
  const reweighted = math.plCalculateOutlook(model);
  near(reweighted.expected.price, 0.1 * mid("bear") + 0.6 * mid("base") + 0.3 * mid("bull"), 0.001);
});

test("weights that do not total 100% are rejected with clear feedback", () => {
  const model = sofiModel();
  model.scenarioWeights = { bear: 25, base: 50, bull: 30 };
  const outlook = math.plCalculateOutlook(model);
  assert.equal(outlook.ok, false);
  assert.match(outlook.error, /total 100%/);
  model.scenarioWeights = { bear: -5, base: 55, bull: 50 };
  assert.equal(math.plCalculateOutlook(model).ok, false);
});

test("invalid or empty inputs never produce NaN tables", () => {
  const model = sofiModel();
  model.startPrice = 0;
  assert.equal(math.plCalculateProjection(model, "base").ok, false);
  model.startPrice = -5;
  assert.equal(math.plCalculateProjection(model, "base").ok, false);
  model.startPrice = 18.18;
  model.dilutedShares = 0;
  assert.equal(math.plCalculateProjection(model, "base").ok, false);
  model.dilutedShares = 1355979000;
  model.baseRevenue = NaN;
  assert.equal(math.plCalculateProjection(model, "base").ok, false);
  model.baseRevenue = 4655000000;
  model.scenarios.base.revGrowth[1] = NaN;
  const res = math.plCalculateProjection(model, "base");
  assert.equal(res.ok, false);
  assert.match(res.error, /2028/);
  model.scenarios.base.revGrowth[1] = 30;
  model.scenarios.base.netMargin[0] = 250; // outside sane bounds
  assert.equal(math.plCalculateProjection(model, "base").ok, false);
});

test("negative earnings never produce a positive valuation range", () => {
  const model = sofiModel();
  model.scenarios.bear.netMargin = model.scenarios.bear.netMargin.map(() => -10);
  const res = math.plCalculateProjection(model, "bear");
  assert.equal(res.ok, true);
  res.rows.forEach((row) => {
    assert.ok(row.netIncome < 0);
    assert.equal(row.priceLow, null);
    assert.equal(row.priceHigh, null);
    assert.equal(row.cagrLow, null);
    assert.equal(row.negativeEarnings, true);
  });
  // The blended expected value must refuse to average in a fake number.
  const outlook = math.plCalculateOutlook(model);
  assert.equal(outlook.ok, true);
  assert.equal(outlook.expected, null);
});

test("P/E low above P/E high is reordered with a warning, never silent", () => {
  const model = sofiModel();
  model.scenarios.base.peLow[0] = 40;
  model.scenarios.base.peHigh[0] = 30;
  const res = math.plCalculateProjection(model, "base");
  assert.equal(res.ok, true);
  assert.equal(res.rows[0].peLow, 30);
  assert.equal(res.rows[0].peHigh, 40);
  assert.equal(res.warnings.length, 1);
  assert.match(res.warnings[0], /reordered/);
});

test("percent inputs are divided by 100 exactly once", () => {
  const model = sofiModel();
  model.scenarios.base.revGrowth[0] = 0.5; // 0.5% — must NOT be read as 50%
  const res = math.plCalculateProjection(model, "base");
  near(res.rows[0].revenue, 4655000000 * 1.005, 1);
});

test("plParseNumber handles commas, currency, and K/M/B suffixes", () => {
  assert.equal(math.plParseNumber("1,355,979,000"), 1355979000);
  assert.equal(math.plParseNumber("$4,655,000,000"), 4655000000);
  assert.equal(math.plParseNumber("4.655B"), 4655000000);
  assert.equal(math.plParseNumber("825m"), 825000000);
  assert.equal(math.plParseNumber("18.18"), 18.18);
  assert.equal(math.plParseNumber("500k"), 500000);
  assert.equal(math.plParseNumber("1.2T"), 1.2e12);
  assert.equal(math.plParseNumber("-0.35B"), -350000000);
  assert.ok(Number.isNaN(math.plParseNumber("")));
  assert.ok(Number.isNaN(math.plParseNumber("abc")));
  assert.ok(Number.isNaN(math.plParseNumber(null)));
});

test("saving and restoring a v2 model reproduces identical outputs", () => {
  const model = sofiModel();
  model.scenarioWeights = { bear: 20, base: 55, bull: 25 };
  model.userEdited = { baseRevenue: true };
  const restored = math.plMigrateSavedModel(JSON.parse(JSON.stringify(model)));
  assert.ok(restored);
  assert.equal(restored.version, math.PL_MODEL_VERSION);
  const a = math.plCalculateOutlook(model);
  const b = math.plCalculateOutlook(restored);
  assert.deepEqual(b.scenarios.base.rows, a.scenarios.base.rows);
  assert.deepEqual(b.expected, a.expected);
  assert.equal(restored.userEdited.baseRevenue, true);
});

test("legacy v1 saved models migrate into the canonical shape", () => {
  const v1 = {
    ticker: "SOFI",
    startPrice: 18.18,
    startShares: 1355979000,
    baseRevenue: 4655000000,
    baseMargin: 0.1772,
    baseYear: 2026,
    years: 5,
    active: "bull",
    scenarios: {
      bear: { revGrowth: [5], netMargin: [8], peLow: [10], peHigh: [15] },
      base: { revGrowth: [30, 30, 22, 18, 15], netMargin: [18.5, 18.5, 20, 22, 24], peLow: [25, 24, 22, 20, 18], peHigh: [35, 34, 32, 30, 28] },
      bull: { revGrowth: [40], netMargin: [25], peLow: [30], peHigh: [45] },
    },
  };
  const migrated = math.plMigrateSavedModel(v1);
  assert.ok(migrated);
  assert.equal(migrated.version, math.PL_MODEL_VERSION);
  assert.equal(migrated.ticker, "SOFI");
  assert.equal(migrated.selectedScenario, "bull");
  assert.equal(migrated.dilutedShares, 1355979000);
  near(migrated.baseNetIncome, 4655000000 * 0.1772, 1e5);
  assert.equal(migrated.seed.netIncomeDerived, true);
  const res = math.plCalculateProjection(migrated, "base");
  assert.equal(res.ok, true);
  near(res.rows[4].priceLow, 41.49, 0.35); // migrated margin is approximate
  assert.equal(math.plMigrateSavedModel({ junk: true }), null);
  assert.equal(math.plMigrateSavedModel(null), null);
});

test("CSV export matches the canonical calculation exactly", () => {
  const model = sofiModel();
  const built = math.plBuildCsv(model);
  assert.equal(built.ok, true);
  const lines = built.csv.split("\n");
  assert.equal(lines[0], "Implied Lens — Projection Lab");
  assert.ok(lines.includes("Start price,18.18"));
  assert.ok(lines.includes("Diluted shares,1355979000"));
  assert.ok(lines.includes("Base revenue,4655000000"));
  assert.ok(lines.includes("Base net income,825000000"));
  const outlook = math.plCalculateOutlook(model);
  const y2031 = outlook.scenarios.base.rows[4];
  const row = lines.find((l) => l.startsWith("base,2031"));
  assert.ok(row, "base 2031 row present");
  const cells = row.split(",");
  assert.equal(Number(cells[2]), y2031.revenue);           // raw revenue
  assert.equal(Number(cells[9]), +y2031.priceLow.toFixed(2));
  assert.equal(Number(cells[10]), +y2031.priceHigh.toFixed(2));
  const expLine = lines.find((l) => l.startsWith("Expected price (2031),"));
  assert.ok(expLine);
  near(Number(expLine.split(",")[1]), outlook.expected.price, 0.01);
});

test("reseeding builds a complete fresh model and records provenance", () => {
  const model = math.plCreateModel({
    ticker: "SOFI",
    baseYear: 2026,
    startPrice: 18.18,
    dilutedShares: 1355979000,
    baseRevenue: 4655000000,
    baseNetIncome: 825000000,
    histGrowth: 0.3,
    currentPE: 30,
    source: "FY2026 statements",
    seeded: true,
  });
  assert.equal(model.version, math.PL_MODEL_VERSION);
  assert.equal(model.seed.source, "FY2026 statements");
  assert.deepEqual(model.seed.values, {
    startPrice: 18.18,
    dilutedShares: 1355979000,
    baseRevenue: 4655000000,
    baseNetIncome: 825000000,
  });
  assert.equal(model.scenarios.base.revGrowth.length, math.PL_MAX_YEARS);
  const outlook = math.plCalculateOutlook(model);
  assert.equal(outlook.ok, true);
  // Bear < base < bull terminal midpoints for a sane auto-seed.
  const mid = (k) => outlook.scenarios[k].terminal.priceMid;
  assert.ok(mid("bear") < mid("base") && mid("base") < mid("bull"));
});

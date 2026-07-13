"use strict";

/* Projection Lab v2 — DOM integration test.
   Mounts the real UI in jsdom, drives the actual inputs, and asserts the
   rendered table / summary / exports all derive from the one canonical model.
   Skips cleanly when jsdom is not installed (it is an optional dev tool, not
   a runtime dependency):  npm i --no-save jsdom  to enable. */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

let JSDOM = null;
try { JSDOM = require("jsdom").JSDOM; } catch (e) { /* optional */ }

test("Projection Lab UI derives every component from the canonical model", { skip: !JSDOM && "jsdom not installed (npm i --no-save jsdom)" }, () => {
  const ROOT = path.join(__dirname, "..");
  const dom = new JSDOM('<!doctype html><html><body><div id="il-projlab-mount"></div></body></html>', {
    runScripts: "outside-only", pretendToBeVisual: true, url: "https://impliedlens.test/",
  });
  const { window } = dom;

  // App-state stub the lab seeds from (mirrors index.html's S + financialsRaw cache).
  window.S = {
    ticker: "SOFI",
    data: { meta: { symbol: "SOFI", longName: "SoFi Technologies, Inc.", currency: "USD", regularMarketPrice: 18.18, trailingPE: 29.9 } },
    financialsRaw: {
      incomeStatementHistory: { incomeStatementHistory: [
        { totalRevenue: { raw: 4655000000 }, netIncome: { raw: 825000000 }, endDate: { raw: 1782950400 } },
        { totalRevenue: { raw: 3581000000 }, netIncome: { raw: 498000000 }, endDate: { raw: 1751414400 } },
      ] },
      defaultKeyStatistics: { sharesOutstanding: { raw: 1355979000 } },
    },
  };

  window.eval(fs.readFileSync(path.join(ROOT, "public", "model-math.js"), "utf8"));
  window.eval(fs.readFileSync(path.join(ROOT, "public", "projection-lab.js"), "utf8"));

  window.ProjectionLab.mount("il-projlab-mount");
  const doc = window.document;
  const model = window.ProjectionLab._state();
  assert.equal(model.baseRevenue, 4655000000, "seeded revenue is the reported 4.655B, not stale data");
  assert.equal(model.baseNetIncome, 825000000);
  assert.equal(model.dilutedShares, 1355979000);

  // Apply the SOFI regression Base assumptions through the actual table inputs.
  const baseAssumptions = {
    revGrowth: [30, 30, 22, 18, 15],
    netMargin: [18.5, 18.5, 20, 22, 24],
    peLow: [25, 24, 22, 20, 18],
    peHigh: [35, 34, 32, 30, 28],
  };
  function setCell(field, yi, value) {
    const inp = doc.querySelector(`.plab2-cin[data-field="${field}"][data-yi="${yi}"]`);
    assert.ok(inp, `input ${field}[${yi}] exists`);
    inp.value = String(value);
    inp.dispatchEvent(new window.Event("input", { bubbles: true }));
  }
  for (const [field, vals] of Object.entries(baseAssumptions)) vals.forEach((v, yi) => setCell(field, yi, v));

  const out = (key, yi) => doc.querySelector(`[data-out="${key}:${yi}"]`).textContent;
  assert.equal(out("revenue", 0), "$6.05B", "2027 revenue compounds from the entered base revenue");
  assert.equal(out("revenue", 4), "$13.02B");
  assert.equal(out("priceLow", 4), "$41.49");
  assert.equal(out("priceHigh", 4), "$64.54");
  assert.equal(doc.querySelector('[data-basecell="revenue"]').textContent, "$4.66B", "base column = Model Foundation");
  assert.equal(doc.querySelector('[data-basecell="netMargin"]').textContent, "17.7%", "base margin ~17.7%, not 78%");

  // Foundation edit → instant recalculation everywhere.
  const revInput = doc.querySelector("#plab2-f-baseRevenue");
  revInput.value = "9.31B";
  revInput.dispatchEvent(new window.Event("input", { bubbles: true }));
  assert.equal(window.ProjectionLab._state().baseRevenue, 9310000000, "K/M/B suffix parsing");
  assert.equal(out("revenue", 0), "$12.10B", "table reacts instantly");
  doc.querySelector('.plab2-freset[data-fkey="baseRevenue"]').click();
  assert.equal(out("revenue", 0), "$6.05B", "reset-to-seeded restores the seeded value");

  // Start price only affects CAGR, never projected financials.
  const priceInput = doc.querySelector("#plab2-f-startPrice");
  priceInput.value = "9.09";
  priceInput.dispatchEvent(new window.Event("input", { bubbles: true }));
  assert.equal(out("priceLow", 4), "$41.49");
  assert.equal(out("cagrLow", 4), "35%");
  priceInput.value = "18.18";
  priceInput.dispatchEvent(new window.Event("input", { bubbles: true }));

  // Invalid input: rejected with a message, model and table untouched.
  const shInput = doc.querySelector("#plab2-f-dilutedShares");
  shInput.value = "0";
  shInput.dispatchEvent(new window.Event("input", { bubbles: true }));
  assert.match(doc.querySelector('[data-ferr="dilutedShares"]').textContent, /above zero/);
  assert.equal(window.ProjectionLab._state().dilutedShares, 1355979000);
  assert.equal(out("priceLow", 4), "$41.49");
  shInput.dispatchEvent(new window.Event("blur", { bubbles: true }));

  // Empty assumption cell never corrupts the model.
  const gInput = doc.querySelector('.plab2-cin[data-field="revGrowth"][data-yi="1"]');
  gInput.value = "";
  gInput.dispatchEvent(new window.Event("input", { bubbles: true }));
  assert.equal(window.ProjectionLab._state().scenarios.base.revGrowth[1], 30);
  assert.equal(out("revenue", 4), "$13.02B");

  // Scenario independence + summary/expected consistency.
  doc.querySelector(".plab2-tab-bear").click();
  assert.equal(window.ProjectionLab._state().selectedScenario, "bear");
  doc.querySelector(".plab2-tab-base").click();
  assert.equal(out("priceLow", 4), "$41.49", "base values intact after visiting bear");
  const outlook = window.ImpliedLensMath.plCalculateOutlook(window.ProjectionLab._state());
  const shownExpected = doc.querySelector(".plab2-exp-v strong").textContent;
  assert.equal(shownExpected, "$" + outlook.expected.price.toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 }),
    "expected-value strip matches weights × midpoints");
  assert.match(doc.querySelector(".plab2-exp").textContent, /Bear 25% · Base 50% · Bull 25%/);

  // Horizon control changes the terminal year without losing assumptions.
  [...doc.querySelectorAll(".plab2-yr")].find((b) => b.textContent === "3y").click();
  assert.match(doc.querySelector("#plab2-outcome").textContent, /2029/);
  [...doc.querySelectorAll(".plab2-yr")].find((b) => b.textContent === "5y").click();
  assert.equal(out("priceLow", 4), "$41.49");

  // Save → v2 key; remount restores identical outputs; CSV matches the engine.
  doc.querySelector("#plab2-save").click();
  assert.ok(window.localStorage.getItem("il-projlab:v2:SOFI"));
  window.ProjectionLab.mount("il-projlab-mount");
  assert.equal(out("priceLow", 4), "$41.49");
  const csv = window.ImpliedLensMath.plBuildCsv(window.ProjectionLab._state());
  const csvRow = csv.csv.split("\n").find((l) => l.startsWith("base,2031"));
  assert.equal(Number(csvRow.split(",")[2]), outlook.scenarios.base.rows[4].revenue, "CSV exports raw engine values");
});

"use strict";
const test = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const P = (...p) => path.join(__dirname, "..", ...p);
const sandbox = { window: {}, document: {} };
vm.runInNewContext(fs.readFileSync(P("public", "lens-charts.js"), "utf8"), sandbox);
const LC = sandbox.window.LensCharts;

test("Lens Charts exposes its four chart forms", () => {
  for (const k of ["bars", "lines", "range", "spark"]) assert.equal(typeof LC[k], "function", k);
});

test("axis ticks are round numbers that cover the data", () => {
  const t = LC.niceTicks(26.9e9, 165.2e9, 4);
  assert.ok(t[0] <= 26.9e9 && t[t.length - 1] >= 165.2e9);
  const step = t[1] - t[0];
  assert.ok([1, 2, 2.5, 5].some(m => Math.abs(step / Math.pow(10, Math.floor(Math.log10(step))) - m) < 1e-9), `step ${step}`);
  assert.deepEqual(Array.from(LC.niceTicks(-10, 25, 4)), [-10, 0, 10, 20, 30]);
});

test("money labels stay short", () => {
  assert.equal(LC.compact(165.2e9), "165B");
  assert.equal(LC.compact(4.58e12), "4.6T");
  assert.equal(LC.compact(18.4e6), "18M");
});

test("the research page wires the new charts in", () => {
  const html = fs.readFileSync(P("index.html"), "utf8");
  for (const id of ["fin-glance", "fin-glance-bars", "fin-glance-tiles", "il-chart-reads", "il-reads-grid", "il-worth", "il-worth-chart"]) {
    assert.match(html, new RegExp('id="' + id + '"'), id);
  }
  // Lens Charts loads before anything that draws with it.
  const at = f => html.indexOf('src="/' + f);
  assert.ok(at("lens-charts.js") > 0 && at("lens-charts.js") < at("fin-glance.js") && at("lens-charts.js") < at("chart-reads.js") && at("lens-charts.js") < at("index-chart.js"));
  const legacy = fs.readFileSync(P("public", "app-legacy.js"), "utf8");
  assert.match(legacy, /ILFinGlance\.render\(r\)/, "Financials no longer draws its charts");
  assert.match(legacy, /new CustomEvent\('il-estimates'\)/, "the valuation range is not told when estimates arrive");
});

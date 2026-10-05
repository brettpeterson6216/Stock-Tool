"use strict";
/* The price chart's interaction contract: it pans, zooms, backfills older
   bars at the same interval, takes time/price-anchored drawings, shows the
   company it is charting, and exports a clean branded image. */
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");

const root = path.join(__dirname, "..");
const read = f => fs.readFileSync(path.join(root, f), "utf8");
const engine = read("public/chart-engine.js");
const tools = read("public/chart-tools.js");
const studio = read("public/share-studio.js");

function loadTools() {
  const dom = new JSDOM("<!doctype html><html><head></head><body></body></html>", { url: "https://local.test", runScripts: "outside-only" });
  dom.window.eval(tools);
  return dom.window;
}

test("inline price chart is not made inert by the passive-chart rule", () => {
  const css = read("public/premium.css");
  assert.doesNotMatch(css, /#view-tool \.chart-wrap canvas\s*\{\s*pointer-events:\s*none/,
    "a blanket pointer-events:none on chart canvases stops the price chart panning in place");
  assert.match(css, /canvas:not\(\.tv-lightweight-charts canvas\)/);
});

test("wheel and pinch zoom are on, and candles can shrink well below their opening width", () => {
  assert.match(engine, /handleScale:\s*\{\s*mouseWheel:\s*true,\s*pinch:\s*true/);
  assert.match(engine, /handleScroll:\s*\{\s*mouseWheel:\s*true/);
  const min = Number((engine.match(/var MIN_SPACING = ([\d.]+)/) || [])[1]);
  assert.ok(min > 0 && min <= 1, "minBarSpacing should allow zooming out to about a pixel per bar");
  assert.match(engine, /minBarSpacing:\s*MIN_SPACING/);
});

test("panning to the left edge backfills older bars at the same interval", () => {
  assert.match(engine, /subscribeVisibleLogicalRangeChange/);
  assert.match(engine, /"5m":\s*\["1d",\s*"5d",\s*"1mo"\]/, "a 1D chart must backfill 5-minute bars, not jump to daily");
  assert.match(engine, /"1d":\s*\["1mo",[^\]]*"max"\]/);
  assert.match(engine, /"&interval=" \+ frame\.interval/, "the backfill request must pin the interval");
  assert.match(engine, /older\.concat\(frame\.rows\)/);
  assert.match(engine, /i\.setRows\(frame\.rows, older\.length\)/, "bars are prepended in place so a drag in progress survives");
});

test("re-rendering the same series keeps history the user already loaded", () => {
  assert.match(engine, /lastFrame\.key === chartKey/);
});

test("axis and readout times are shown in the exchange's time zone", () => {
  assert.match(engine, /exchangeTimezoneName/);
  assert.match(engine, /tickMarkFormatter:\s*tickLabel/);
});

test("the chart names the company in both views", () => {
  assert.match(engine, /class="ilr-sym"/);
  assert.match(engine, /function setExpandedTitle/);
  assert.match(engine, /createTextWatermark/);
});

test("drawings are anchored to time and price, so they survive pan, zoom and timeframe changes", () => {
  const w = loadTools();
  const T = w.ILChartTools;
  assert.ok(T && typeof T.attach === "function" && typeof T.tToL === "function");
  const rows = [];
  for (let i = 0; i < 50; i++) rows.push({ time: 1_700_000_000 + i * 86400 });
  assert.equal(T.tToL(rows, rows[10].time), 10);
  assert.equal(T.tToL(rows, rows[10].time + 43200), 10.5);
  assert.equal(T.tToL(rows, rows[0].time - 86400 * 3), -3, "times before the data extrapolate at the bar step");
  assert.equal(T.tToL(rows, rows[49].time + 86400 * 2), 51, "and after it");
  w.close();
});

test("the drawing kit covers the core technical-analysis tools", () => {
  for (const k of ["trend", "ray", "hline", "rect", "fib", "measure", "pen", "marker", "eraser"]) {
    assert.match(tools, new RegExp('k: "' + k + '"'), k + " tool missing");
  }
  assert.match(tools, /attachPrimitive/, "drawings must paint inside the chart canvas");
  assert.match(tools, /il-draw:v1:/, "drawings persist per ticker");
  assert.match(tools, /function undo\(\)/);
  assert.match(tools, /function redo\(\)/);
});

test("one toolbar serves the page and full screen and wraps instead of scrolling", () => {
  assert.match(tools, /function buildBar\(mode\)/);
  assert.match(tools, /mountFullBar/);
  assert.match(tools, /\.ilc-bar\{display:flex;flex-wrap:wrap/);
  assert.doesNotMatch(tools, /\.ilc-bar\{[^}]*overflow-x:\s*auto/);
});

test("chart-tools loads before the engine that calls it", () => {
  const html = read("index.html");
  const a = html.indexOf('src="/chart-tools.js'), b = html.indexOf('src="/chart-engine.js');
  assert.ok(a > 0 && b > a);
});

test("the share studio draws the chart from data with the real logo, not a UI screenshot", () => {
  assert.doesNotMatch(studio, /takeScreenshot/, "screenshots carry axis badges and the library logo into the image");
  assert.match(studio, /\/logo-mark\.png/);
  for (const k of ["onyx", "ivory", "midnight", "emerald", "graphite"]) assert.match(studio, new RegExp(k + ": \\{"));
  for (const k of ["wide", "square", "tall"]) assert.match(studio, new RegExp(k + ": \\{ w:"));
  assert.match(studio, /Plus Jakarta Sans/);
  assert.match(studio, /IBM Plex Sans/);
});

test("the old share studio markup is gone", () => {
  assert.doesNotMatch(read("index.html"), /share-studio-canvas/);
});

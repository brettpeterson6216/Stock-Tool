"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { JSDOM } = require("jsdom");
const { bundleStyles, styleLinks } = require("../lib/style-delivery");
const root = path.join(__dirname, "..");
const engine = fs.readFileSync(path.join(root, "public/chart-engine.js"), "utf8");

test("enhancement modules execute after the controller they extend", () => {
  const html = fs.readFileSync(path.join(root, "index.html"), "utf8");
  const scripts = [...html.matchAll(/<script\s+defer\s+src="([^"?]+)/g)].map(match => match[1]);
  const controller = scripts.indexOf("/app-legacy.js");
  assert.ok(controller > scripts.indexOf("/app-navigation.js"));
  for (const module of ["research-system", "product-system", "workspace-system", "chart-engine", "chart-analysis", "share-studio"]) {
    assert.ok(scripts.indexOf("/" + module + ".js") > controller, module + " must extend the loaded controller");
  }
});

test("chart installation waits for legacy state on slow connections", () => {
  const dom = new JSDOM('<div id="app-chart-toolbar"></div>', { url: "https://local.test", runScripts: "outside-only" });
  const w = dom.window;
  const timers = [];
  w.setTimeout = fn => { timers.push(fn); return timers.length; };
  w.LightweightCharts = { createChart() {} };
  w.eval(engine);
  timers.forEach(fn => fn());
  assert.equal(w.__ilChartEngine, undefined, "early fallback timer must not install before the app");
  const legacy = () => {};
  w.S = { inds: {}, charts: {} };
  w.buildPriceChart = legacy;
  w.document.dispatchEvent(new w.Event("DOMContentLoaded"));
  assert.equal(w.__ilChartEngine, true);
  assert.notEqual(w.buildPriceChart, legacy);
  w.close();
});

test("chart data rejects missing prices and timestamps without a zero-price cliff", () => {
  const code = engine.slice(engine.indexOf("  function rowsFrom("), engine.indexOf("  function dispose("));
  const rowsFrom = vm.runInNewContext(code + ";rowsFrom");
  const q = { close: [10, null, "", 0, 12, 13, 14], open: [null], high: [undefined], low: [null] };
  const result = rowsFrom({ timestamp: [3, 4, 5, 6, 2, 2, null], indicators: { quote: [q] } });
  assert.deepEqual(Array.from(result, x => [x.time,x.close]), [[2,12],[3,10]]);
  assert.equal(result[1].open, 10);
  assert.equal(result[1].high, 10);
  assert.equal(result[1].low, 10);
});

test("chart disposal removes both resize and scrub listeners once", () => {
  const code = engine.slice(engine.indexOf("  function dispose("), engine.indexOf("  function render("));
  const dispose = vm.runInNewContext(code + ";dispose");
  let removed = 0, disconnected = 0, readout = 0;
  const instance = { disposeReadout() { readout++; }, chart: {
    remove() { removed++; }, _ilResizeObserver: { disconnect() { disconnected++; } }
  } };
  dispose(instance); dispose(instance);
  assert.deepEqual([removed,disconnected,readout], [1,1,1]);
});

test("a slow technical read cannot overwrite a newer ticker", async () => {
  const dom = new JSDOM('<div class="chart-wrap"><div><canvas id="price-chart"></canvas></div></div><div id="app-chart-toolbar"></div>', { url: "https://local.test", runScripts: "outside-only" });
  const w = dom.window;
  w.localStorage.setItem("il-analysis-pref", JSON.stringify({ open: true, hidden: false }));
  w.S = { ticker: "AAPL", range: "1y" };
  const calls = [];
  w.fetch = (url, options) => new Promise(resolve => calls.push({ url, options, resolve }));
  w.eval(fs.readFileSync(path.join(root, "public/chart-analysis.js"), "utf8"));
  w.document.dispatchEvent(new w.Event("DOMContentLoaded"));
  w.S.ticker = "MSFT";
  w.document.dispatchEvent(new w.Event("il-chart-rendered"));
  assert.equal(calls.length, 2);
  assert.equal(calls[0].options.signal.aborted, true);
  calls[1].resolve({ ok: true, json: async () => ({ summary: "Current MSFT read" }) });
  await new Promise(resolve => setImmediate(resolve));
  calls[0].resolve({ ok: true, json: async () => ({ summary: "Stale AAPL read" }) });
  await new Promise(resolve => setImmediate(resolve));
  assert.match(w.document.querySelector(".ilan-body").textContent, /Current MSFT/);
  assert.doesNotMatch(w.document.querySelector(".ilan-body").textContent, /Stale AAPL/);
  w.close();
});

test("late price zones cannot be applied to a different company", async () => {
  const code = engine.slice(engine.indexOf("  var zoneCache ="), engine.indexOf("  window.ilToggleZones"));
  const calls = [];
  const state = { ticker: "AAPL", range: "1y" };
  const context = { S: state, window: { S: state }, fetch: url => new Promise(resolve => calls.push({ url, resolve })) };
  const fetchZones = vm.runInNewContext(code + ";fetchZones", context);
  let painted = 0;
  fetchZones(() => painted++);
  state.ticker = "MSFT";
  fetchZones(() => painted++);
  calls[1].resolve({ ok: true, json: async () => ({ lensSetup: { ok: true, ticker: "MSFT" } }) });
  await new Promise(resolve => setImmediate(resolve));
  calls[0].resolve({ ok: true, json: async () => ({ lensSetup: { ok: true, ticker: "AAPL" } }) });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(context.window.__ilLensZones.ticker, "MSFT");
  assert.equal(painted, 1);
});

test("bundles preserve ordered styles and rebase local font URLs", () => {
  const html = fs.readFileSync(path.join(root, "index.html"), "utf8");
  const delivered = bundleStyles(html);
  const links = styleLinks(delivered);
  assert.equal(links.length, 1);
  const content = fs.readFileSync(path.join(root,"public",links[0].href),"utf8");
  assert.ok(content.startsWith("/* Generated"));
  assert.match(content, /@layer premium,heritage/);
  assert.match(content, /url\(\/vendor\/fonts\//);
  assert.ok(content.indexOf("@layer heritage{") < content.indexOf("@layer premium{"));
  const unknown = '<link rel="stylesheet" media="print" href="/print.css"><link rel="stylesheet" href="https://example.org/site.css">';
  assert.equal(bundleStyles(unknown), unknown);
});

test("a month is drawn from intraday bars and a quarter from daily closes", () => {
  // This test used to assert the opposite for 1M: daily closes, on the
  // grounds that hourly bars over a month are noise. True about noise, wrong
  // about the picture — twenty-two daily closes across an 880x372 plot is
  // twenty straight segments with hard corners, and it read as a coarse
  // polyline rather than as a market. Rendered side by side from the same
  // month of real S&P data, hourly looked like a chart and daily looked
  // cheap, even though hourly is objectively busier. Density was what was
  // missing. 3M keeps daily closes: sixty-three points is already enough
  // line to read, and intraday over a quarter is a genuine hairball.
  const api = fs.readFileSync(path.join(root,"routes/market-data.js"),"utf8");
  assert.match(api, /"1M":\s*\{[^\n]+interval: "1h"/);
  assert.match(api, /"3M":\s*\{[^\n]+interval: "1d"/);
  assert.match(api, /"1Y":\s*\{[^\n]+interval: "1d"/);
});

test("section navigation retains the researched company and chart range", () => {
  const source = fs.readFileSync(path.join(root, "public/product-system.js"), "utf8");
  const code = source.slice(source.indexOf("  function syncToolUrl("), source.indexOf("  function renderTrust("));
  const app = { location: new URL("https://local.test/?view=tool&section=analyze"), IL_STATE: { ticker: "MSFT", range: "3mo" } };
  app.history = { replaceState(_state, _title, url) { app.location = new URL(url, app.location); } };
  app.openSection = section => app.history.replaceState(null, "", "/?view=tool&section=" + section);
  const document = { getElementById: id => id === "view-tool" ? { getClientRects: () => [{}] } : null };
  vm.runInNewContext(code + ";installUrlState();", { window: app, document, URL, URLSearchParams });
  app.openSection("financials");
  assert.equal(app.location.searchParams.get("section"), "financials");
  assert.equal(app.location.searchParams.get("symbol"), "MSFT");
  assert.equal(app.location.searchParams.get("range"), "3mo");
});

test("valuation history labels the reported year instead of the current year", () => {
  const source = fs.readFileSync(path.join(root, "public/valuation-lab.js"), "utf8");
  const code = source.slice(source.indexOf("  function statementYear("), source.indexOf("  /* ---- seeding"));
  const statementYear = vm.runInNewContext(code + ";statementYear", { raw: value => value && typeof value === "object" ? value.raw : value });
  assert.equal(statementYear({ endDate: { raw: Date.parse("2024-09-28T00:00:00Z") / 1000 } }), 2024);
  assert.equal(statementYear({ endDate: null }), null);
  assert.equal(statementYear({}), null);
});

test("a direct Watchlists link selects the watchlist editor on startup", () => {
  const dom = new JSDOM('<div id="view-tool"><div class="app-content-scroll"></div></div>', { url: "https://local.test/?view=tool&section=workspace", runScripts: "outside-only" });
  const w = dom.window;
  w.__initialWorkspaceTab = "watchlist";
  const Observer = w.MutationObserver;
  const observers = [];
  w.MutationObserver = function (callback) { const observer = new Observer(callback); observers.push(observer); return observer; };
  w.openSection = () => {};
  w.navGoTo = () => {};
  const source = fs.readFileSync(path.join(root, "public/workspace-system.js"), "utf8");
  w.eval(source.slice(0, source.indexOf("/* ── Live modeling:")));
  w.document.dispatchEvent(new w.Event("DOMContentLoaded"));
  assert.equal(w.document.querySelector(".il-ws-tab.active")?.dataset.tab, "watchlist");
  assert.equal(w.document.querySelector(".il-ws-panel.active")?.dataset.panel, "watchlist");
  observers.forEach(observer => observer.disconnect());
  w.close();
});

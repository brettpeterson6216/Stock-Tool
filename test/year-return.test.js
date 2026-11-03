"use strict";
/* One definition of "past year" everywhere (audit F04): the research page
   and chart (IL.yearReturn in public/app/core.js), the momentum grade and
   screener (returnOver in lib/sec-fundamentals.js) and the homepage demo
   card (routes/lens-score.js) must give the same number for the same closes. */
const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
process.env.NODE_ENV = "test";
const { returnOver } = require("../lib/sec-fundamentals");
const { cardPayload } = require("../routes/lens-score");

function loadIL() {
  const noop = () => {};
  const el = () => ({ addEventListener: noop, setAttribute: noop, classList: { add: noop, remove: noop, contains: () => false }, style: {}, querySelector: () => null, querySelectorAll: () => [] });
  const doc = { documentElement: el(), readyState: "complete", addEventListener: noop, querySelector: () => null, querySelectorAll: () => [], getElementById: () => null, createElement: el, head: el(), body: el() };
  const win = { document: doc, addEventListener: noop, matchMedia: () => ({ matches: false, addEventListener: noop }), localStorage: { getItem: () => null, setItem: noop }, location: { pathname: "/", search: "" }, fetch: () => Promise.reject(new Error("no network")), navigator: {} };
  win.window = win; win.self = win;
  const ctx = vm.createContext(Object.assign(win, { console, setTimeout, clearTimeout, Promise, Intl, Date, Math, JSON, URL, URLSearchParams, CustomEvent: function () {}, MutationObserver: function () { this.observe = noop; } }));
  vm.runInContext(fs.readFileSync(path.join(__dirname, "..", "public", "app", "core.js"), "utf8"), ctx);
  return ctx.IL;
}

// Trading days only, with a gap for weekends, about 14 months of history.
function series() {
  const out = [];
  let t = Date.UTC(2025, 8, 1, 20) / 1000, px = 100;
  for (let i = 0; out.length < 300; i++, t += 86400) {
    const dow = new Date(t * 1000).getUTCDay();
    if (dow === 0 || dow === 6) continue;
    px *= 1 + Math.sin(i / 9) * 0.01;
    out.push({ time: t, close: Math.round(px * 100) / 100 });
  }
  return out;
}

test("the research page, the momentum grade and the demo card agree on the past year", () => {
  const IL = loadIL();
  const bars = series();
  const rows = bars.map(b => ({ day: new Date(b.time * 1000).toISOString().slice(0, 10), close: b.close }));
  const client = IL.yearReturn(bars);
  const server = returnOver(rows, 52);
  assert.ok(Number.isFinite(client));
  assert.ok(Math.abs(client - server) < 1e-9, `client ${client} vs server ${server}`);
  const card = cardPayload({ score: { technical: { bars } } }).score.technical.bars;
  const demo = (card.at(-1).close / card[0].close - 1) * 100;
  assert.ok(Math.abs(demo - client) < 1e-9, `card ${demo} vs page ${client}`);
});

test("less than a year of prices gives no past-year figure rather than a shorter one", () => {
  const IL = loadIL();
  assert.equal(IL.yearReturn(series().slice(-120)), null);
});

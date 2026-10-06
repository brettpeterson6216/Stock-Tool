"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { buildFacts } = require("./helpers/synthetic-facts");
const { buildQuarterlyHistory, attachPrices, calendarLabel } = require("../lib/fundamentals-history");
const G = require("../public/growth-math.js");

const close = (a, b, tol = 1e-6) => Math.abs(a - b) <= tol * Math.max(1, Math.abs(b));
const rows = buildQuarterlyHistory(buildFacts());
const trueShares = i => 1e9 * Math.pow(0.995, i + 1);
const trueRev = i => 1e9 * Math.pow(1.03, i + 1);

test("one row per quarter, unbroken, oldest first", () => {
  assert.equal(rows.length, 42);
  assert.equal(rows[0].label, "Q1 2015");
  assert.equal(rows.at(-1).label, "Q2 2025");
  for (let i = 1; i < rows.length; i++) assert.ok(rows[i].end > rows[i - 1].end);
});

test("fourth quarters are the annual figure less the first nine months", () => {
  const q4 = rows.find(r => r.label === "Q4 2019");
  const i = rows.indexOf(q4);
  assert.ok(close(q4.revenue, trueRev(i)), "revenue");
  assert.ok(close(q4.netIncome, trueRev(i) * 0.2), "net income");
  assert.ok(q4.derived.includes("revenue"));
});

test("year-to-date cash flows become single quarters", () => {
  rows.forEach((r, i) => {
    assert.ok(close(r.operatingCashFlow, trueRev(i) * 0.25), r.label + " operating cash flow");
    assert.ok(close(r.freeCashFlow, trueRev(i) * 0.20), r.label + " free cash flow");
  });
});

test("revenue survives a change of XBRL tag", () => {
  const a = rows.find(r => r.label === "Q4 2017"), b = rows.find(r => r.label === "Q1 2018");
  assert.ok(a.revenue > 0 && b.revenue > a.revenue);
});

test("a stock split is detected and earlier shares and EPS are restated", () => {
  assert.deepEqual(rows.splits.map(s => s.ratio), [10]);
  rows.forEach((r, i) => {
    assert.ok(close(r.shares, trueShares(i), 1e-3), r.label + " shares");
    assert.ok(close(r.eps, trueRev(i) * 0.2 / trueShares(i), 1e-3), r.label + " EPS");
  });
});

test("quarter labels follow the calendar quarter the period ends in", () => {
  assert.equal(calendarLabel("2024-12-28").label, "Q4 2024");   // Apple-style 52/53-week quarter
  assert.equal(calendarLabel("2025-01-01").label, "Q4 2024");
  assert.equal(calendarLabel("2025-06-30").label, "Q2 2025");
});

test("prices attach to the close on or before each quarter end", () => {
  const copy = rows.map(r => ({ ...r }));
  const t = d => Date.parse(d + "T14:30:00Z") / 1000;
  attachPrices(copy, [{ time: t("2025-06-27"), close: 50 }, { time: t("2025-07-03"), close: 99 }]);
  assert.equal(copy.at(-1).price, 50);
  assert.equal(copy[0].price, null);
});

test("TTM, per-share, margin and valuation series", () => {
  const priced = rows.map(r => ({ ...r, price: 100 }));
  const rev = G.series(priced, "revenue", "ttm", 0);
  assert.equal(rev.length, 39, "the first three quarters have no TTM value");
  const i = priced.length - 1;
  const ttmRev = [0, 1, 2, 3].reduce((s, k) => s + trueRev(i - k), 0);
  assert.ok(close(rev.at(-1).value, ttmRev));
  const nm = G.series(priced, "netMargin", "ttm", 0).at(-1).value;
  assert.ok(close(nm, 20), "net margin 20%");
  const ttmEps = [0, 1, 2, 3].reduce((s, k) => s + trueRev(i - k) * 0.2 / trueShares(i - k), 0);
  assert.ok(close(G.series(priced, "pe", "q", 0).at(-1).value, 100 / ttmEps, 1e-3), "P/E is always trailing");
  assert.equal(G.series(priced, "revenue", "q", 3).length, 13, "3 years = 13 quarters of bars");
});

test("summary numbers and the plain-English read", () => {
  const pts = G.series(rows, "revenue", "ttm", 5);
  const st = G.stats(pts, "revenue");
  assert.ok(close(st.cagr, (Math.pow(1.03, 4) - 1) * 100, 1e-6), "CAGR of 3% a quarter");
  assert.ok(close(st.yoy, (Math.pow(1.03, 4) - 1) * 100, 1e-6));
  const text = G.read(rows, "revenue", "ttm", 5, "Synthetic");
  assert.match(text, /^Revenue went from \$[\d.]+B to \$[\d.]+B \(trailing twelve months\)/);
  assert.match(G.read(rows, "shares", "ttm", 5, "Synthetic"), /bought back stock/);
});

test("formatting", () => {
  assert.equal(G.format(1.234e9, "revenue"), "$1.2B");
  assert.equal(G.format(-5.5e8, "netIncome"), "−$550M");
  assert.equal(G.format(2.5, "eps"), "$2.50");
  assert.equal(G.format(24.44, "grossMargin"), "24.4%");
  assert.equal(G.format(31.2, "pe"), "31.2×");
  assert.equal(G.changeText(-1.5, "grossMargin"), "−1.5 pts");
});

test("the growth section is wired into the Financials tab", () => {
  const html = fs.readFileSync(path.join(__dirname, "..", "index.html"), "utf8");
  assert.match(html, /src="\/growth-math\.js/);
  assert.match(html, /src="\/growth-charts\.js/);
  const app = fs.readFileSync(path.join(__dirname, "..", "public", "app-legacy.js"), "utf8");
  assert.match(app, /ILGrowth\.load\(ticker\)/);
  const route = fs.readFileSync(path.join(__dirname, "..", "routes", "financials.js"), "utf8");
  assert.match(route, /router\.get\("\/fundamentals\/history\/:ticker", requireAccount/);
});

test("the site bar grows by the status-bar inset on notched phones", () => {
  const css = fs.readFileSync(path.join(__dirname, "..", "public", "research-premium.css"), "utf8");
  assert.match(css, /--bar-h:\s*calc\(62px \+ env\(safe-area-inset-top, 0px\)\)/);
  assert.match(css, /html body #main-nav \{[^}]*padding-top:\s*env\(safe-area-inset-top/);
});

test("Q4 is recovered when 10-Qs carry only three-month figures", () => {
  const { conceptQuarters } = require("../lib/fundamentals-history");
  const rows = [
    { start: "2024-01-01", end: "2024-03-31", val: 10 }, { start: "2024-04-01", end: "2024-06-30", val: 11 },
    { start: "2024-07-01", end: "2024-09-30", val: 12 }, { start: "2024-01-01", end: "2024-12-31", val: 50 },
  ];
  const q = conceptQuarters(rows, true);
  assert.equal(q.get("2024-12-31").val, 17);
  assert.equal(q.get("2024-12-31").derived, true);
});

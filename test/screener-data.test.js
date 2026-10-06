"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { _test: T } = require("../routes/market-data");

test("Finnhub industries map onto the screener's sector filter", () => {
  const cases = { Semiconductors: "Tech", Technology: "Tech", Communications: "Tech", Media: "Comm.", Telecommunication: "Comm.",
    Pharmaceuticals: "Health", Biotechnology: "Health", Banking: "Finance", Insurance: "Finance", Beverages: "Staples",
    Energy: "Energy", "Metals & Mining": "Materials", "Aerospace & Defense": "Industrials", Automobiles: "Cons.Disc",
    Retail: "Cons.Disc", "Real Estate": "Real Est.", Utilities: "Utilities", "N/A": null, "": null };
  for (const [ind, want] of Object.entries(cases)) assert.equal(T.sectorFromIndustry(ind), want, ind);
});

test("every sector the screener can assign has a filter option", () => {
  const html = require("node:fs").readFileSync(require("node:path").join(__dirname, "..", "index.html"), "utf8");
  for (const s of ["Tech", "Comm.", "Health", "Finance", "Staples", "Energy", "Materials", "Industrials", "Cons.Disc", "Real Est.", "Utilities"])
    assert.ok(html.includes(`<option value="${s}">`), s);
});

test("RSI is 100 on a straight rise and near 50 on a zigzag", () => {
  assert.equal(T.rsi14(Array.from({ length: 30 }, (_, i) => 100 + i)), 100);
  const zig = Array.from({ length: 60 }, (_, i) => 100 + (i % 2 ? 1 : -1));
  assert.ok(Math.abs(T.rsi14(zig) - 50) < 5);
  assert.equal(T.rsi14([1, 2, 3]), null);
});

test("share-class tickers use Yahoo's dash spelling", () => {
  assert.equal(T.yahooSymbol("BRK.B"), "BRK-B");
  assert.equal(T.yahooSymbol("BF.A"), "BF-A");
  assert.equal(T.yahooSymbol("AAPL"), "AAPL");
});

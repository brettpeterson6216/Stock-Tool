// How fine the bars are is a property of the window.
//
// 1M used to lead with daily closes: twenty-two points across an 880x372 plot,
// which is twenty straight segments with hard corners. Rendered beside the
// same month at hourly resolution it read as a coarse polyline rather than as
// a market — the complaint was "too jagged", and the fix was density, not
// smoothing. 1M now leads with hourly bars.
//
// The ladders also have to actually retreat. The old 1M ladder had a second
// rung FINER than its first and a third byte-identical to its first, so a
// thinly traded symbol re-issued the same request twice and called it a
// fallback.
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const src = fs.readFileSync(path.join(__dirname, "..", "routes", "market-data.js"), "utf8");
const block = src.slice(src.indexOf("const WINDOWS = {"), src.indexOf("const DEFAULT_WINDOW"));

// minutes per bar, so "coarser" is a number comparison
const MIN = { "1m": 1, "2m": 2, "5m": 5, "15m": 15, "30m": 30, "60m": 60, "90m": 90,
              "1h": 60, "1d": 1440, "1wk": 10080, "1mo": 43200 };

function ladders() {
  const out = {};
  for (const m of block.matchAll(/"(\w+)":\s*\{[^[]*\[([\s\S]*?)\]\s*\}/g)) {
    out[m[1]] = [...m[2].matchAll(/interval:\s*"([^"]+)",\s*range:\s*"([^"]+)",\s*min:\s*(\d+)/g)]
      .map(r => ({ interval: r[1], range: r[2], min: Number(r[3]) }));
  }
  return out;
}

test("every window declares a ladder with a first choice and at least one retreat", () => {
  const L = ladders();
  for (const key of ["1D", "1W", "1M", "3M", "1Y"]) {
    assert.ok(L[key], `${key} has no ladder`);
    assert.ok(L[key].length >= 2, `${key} has no fallback at all`);
    for (const rung of L[key]) assert.ok(MIN[rung.interval], `${key} uses an unknown interval ${rung.interval}`);
  }
});

const RANGE = { "1d": 1, "5d": 5, "1mo": 30, "3mo": 90, "6mo": 180, "1y": 365, "2y": 730 };

test("every retreat actually retreats — coarser bars, or a wider window", () => {
  // There are two honest ways to answer "that came back thin": ask for coarser
  // bars, or ask over a longer period. What is NOT a retreat is asking for
  // finer bars over the same period, which is exactly what 1M used to do.
  for (const [key, rungs] of Object.entries(ladders())) {
    for (let i = 1; i < rungs.length; i += 1) {
      const prev = rungs[i - 1], cur = rungs[i];
      // The final rung with min <= 2 is a floor, not a retreat: "give me any
      // data that exists" for a symbol too new to fill the window at all.
      // It is allowed to be finer, because for a stock listed three weeks ago
      // daily bars are the only thing that returns anything.
      if (i === rungs.length - 1 && cur.min <= 2) continue;
      const coarser = MIN[cur.interval] > MIN[prev.interval];
      const wider   = RANGE[cur.range] > RANGE[prev.range];
      assert.ok(coarser || wider,
        `${key} rung ${i + 1} (${cur.interval} over ${cur.range}) does not retreat from `
        + `rung ${i} (${prev.interval} over ${prev.range}) — it asks for the same period at the `
        + `same or finer resolution, which cannot help when the first ask came back thin`);
    }
  }
});

test("the floor rung is last, and is the only one allowed to be finer", () => {
  for (const [key, rungs] of Object.entries(ladders())) {
    rungs.forEach((r, i) => {
      if (r.min > 2) return;
      assert.equal(i, rungs.length - 1,
        `${key} puts a take-anything rung (min ${r.min}) at position ${i + 1} — everything below it is unreachable`);
    });
  }
});

test("no rung repeats the request above it", () => {
  for (const [key, rungs] of Object.entries(ladders())) {
    const seen = new Set();
    for (const r of rungs) {
      const sig = r.interval + "@" + r.range;
      assert.ok(!seen.has(sig),
        `${key} asks for ${sig} twice — the second call returns the same data and costs another round trip`);
      seen.add(sig);
    }
  }
});

test("a month is drawn from intraday bars, and a year is not", () => {
  const L = ladders();
  assert.ok(MIN[L["1M"][0].interval] < 1440,
    "1M leads with daily closes again — that is the coarse polyline the density fix removed");
  assert.equal(MIN[L["1Y"][0].interval], 1440,
    "1Y should stay on daily closes; 250 points is already dense");
});

test("the index chart labels the axis by span, not by bar spacing", () => {
  // With 1M on hourly bars, "bars are an hour apart" stopped meaning "one
  // session" — keyed to bar spacing, a month of hourly bars would print 09:30
  // and 10:30 across thirty days.
  const chart = fs.readFileSync(path.join(__dirname, "..", "public", "index-chart.js"), "utf8");
  assert.match(chart, /timeVisible:\s*intraday/, "the axis no longer consults the intraday flag");
  assert.match(chart, /var intraday = span/, "intraday is not derived from the series span");
});

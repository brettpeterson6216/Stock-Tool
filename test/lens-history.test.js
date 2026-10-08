"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const H = require("../lib/lens-history");
const F = require("../lib/lens-factors");

test("track record groups day-one score bands and compares with all companies", () => {
  const start = [
    { ticker: "A", score: 9.1, price: 100 }, { ticker: "B", score: 8.4, price: 50 },
    { ticker: "C", score: 5.0, price: 10 }, { ticker: "D", score: 1.2, price: 20 }, { ticker: "E", score: 7.0, price: 0 },
  ];
  const now = { A: 110, B: 55, C: 10, D: 15, E: 9 };
  const tr = H.trackRecord(start, t => now[t], { startDay: "2026-10-08", endDay: "2026-10-15" });
  assert.equal(tr.companies, 4, "a row without a starting price is skipped");
  const top = tr.bands.find(b => b.key === "top");
  assert.equal(top.count, 2); assert.equal(top.averageReturn, 10);
  assert.equal(tr.allAverage, -1.2);
  assert.equal(top.beatAll, 11.3);
  assert.equal(tr.bands.find(b => b.key === "bottom").averageReturn, -25);
});

test("snapshot rows keep the score, grades and price", () => {
  const rows = H.snapshotRows([{ ticker: "X", score: 7.2, grades: { value: "B" }, price: 12.5, sector: "Tech" }, { ticker: "Y", score: NaN }], "2026-10-08");
  assert.equal(rows.length, 1);
  assert.deepEqual(rows[0], { day: "2026-10-08", ticker: "X", score: 7.2, grades: '{"value":"B"}', price: 12.5, sector: "Tech" });
  assert.equal(H.bandOf(8).key, "top"); assert.equal(H.bandOf(2.9).key, "bottom");
});

test("grade filters compare letter grades in order", () => {
  assert.ok(F.gradeAtLeast("A+", "A-")); assert.ok(F.gradeAtLeast("B", "B-")); assert.ok(!F.gradeAtLeast("C+", "B-")); assert.ok(!F.gradeAtLeast(null, "C-"));
  assert.ok(F.gradeAtLeast(null, ""));
});

test("the screener ships grade filters and the leaderboard is wired", () => {
  const fs = require("node:fs"), path = require("node:path");
  const html = fs.readFileSync(path.join(__dirname, "..", "index.html"), "utf8");
  for (const id of ["scr-ls", "scr-g-value", "scr-g-momentum"]) assert.match(html, new RegExp(`id="${id}"`));
  assert.match(html, /data-sort="lensScore"/);
  const lab = fs.readFileSync(path.join(__dirname, "..", "labs", "lens-score", "index.html"), "utf8");
  assert.match(lab, /data-view="leaders"/); assert.match(lab, /id="rc-history-chart"/);
  const route = fs.readFileSync(path.join(__dirname, "..", "routes", "lens-score.js"), "utf8");
  assert.match(route, /router\.get\("\/lens-leaders"/); assert.match(route, /router\.get\("\/lens-history\/:ticker"/);
});

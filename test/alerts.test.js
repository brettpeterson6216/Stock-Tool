"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { evaluate, describe, LIMITS } = require("../lib/alerts");

test("price alerts fire at or through their level", () => {
  assert.equal(evaluate({ kind: "above", level: 100 }, { price: 100.5 }).hit, true);
  assert.equal(evaluate({ kind: "above", level: 100 }, { price: 99 }).hit, false);
  assert.equal(evaluate({ kind: "below", level: 50 }, { price: 50 }).hit, true);
  assert.equal(evaluate({ kind: "buy_zone", level: 178.8 }, { price: 180 }).hit, false);
  assert.equal(evaluate({ kind: "buy_zone", level: 178.8 }, { price: 178 }).hit, true);
  assert.equal(evaluate({ kind: "below", level: 50 }, { price: null }).hit, false, "no price, no alert");
});

test("grade alerts fire on a 1-point move or a letter change, not on +/- noise", () => {
  const baseline = { score: 7.2, grades: { value: "B-", growth: "A", profitability: "A", health: "B", momentum: "C+" } };
  const same = { score: 7.6, grades: { value: "B", growth: "A+", profitability: "A-", health: "B+", momentum: "C" } };
  assert.equal(evaluate({ kind: "score", baseline }, { grade: same }).hit, false);
  const letter = { ...same, grades: { ...same.grades, momentum: "B-" } };
  const r = evaluate({ kind: "score", baseline }, { grade: letter });
  assert.equal(r.hit, true); assert.deepEqual(r.changes, ["momentum"]);
  assert.match(describe({ kind: "score", ticker: "XYZ" }, r), /XYZ's LensScore moved from 7\.2 to 7\.6\. Grade changes: Momentum C\+ → B-\./);
  assert.equal(evaluate({ kind: "score", baseline }, { grade: { score: 8.3, grades: baseline.grades } }).hit, true);
});

test("plans have alert limits and the page wires the controls", () => {
  assert.ok(LIMITS.free < LIMITS.pro);
  const fs = require("node:fs"), path = require("node:path");
  const html = fs.readFileSync(path.join(__dirname, "..", "labs", "lens-score", "index.html"), "utf8");
  for (const id of ["rc-alert-zone", "rc-alert-score", "rc-alert-form", "rc-alert-list"]) assert.match(html, new RegExp(`id="${id}"`));
  const server = fs.readFileSync(path.join(__dirname, "..", "server.js"), "utf8");
  assert.match(server, /alertsRouter/);
});

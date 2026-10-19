"use strict";
/* "What to check next" on the stock page report card links real lessons. */
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");

test("every lesson the next steps link to exists", () => {
  const src = fs.readFileSync(path.join(__dirname, "..", "public/stock-report-card.js"), "utf8");
  const slugs = [...src.matchAll(/learn: "([a-z-]+)"/g)].map(m => m[1]);
  assert.ok(slugs.length >= 6);
  for (const s of slugs) assert.ok(fs.existsSync(path.join(__dirname, "..", "public/learn", `${s}.html`)), s);
});

test("each grade has a next step", () => {
  const src = fs.readFileSync(path.join(__dirname, "..", "public/stock-report-card.js"), "utf8");
  for (const k of ["value", "growth", "profitability", "health", "momentum"]) assert.match(src, new RegExp(`\\b${k}: \\{ why:`), k);
});

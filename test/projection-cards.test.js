"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const read = (f) => fs.readFileSync(path.join(__dirname, "..", f), "utf8");

test("the Valuation Lab's Share image button opens the card studio", () => {
  const lab = read("public/projection-lab.js");
  assert.match(lab, /window\.ILProjectionCards\.open\(PL\.model\)/);
  assert.match(lab, /> Share image<\/button>/);
  assert.match(read("index.html"), /<script defer src="\/projection-cards\.js"><\/script>/);
});

test("the card studio offers three cards in three sizes, all from the model's own math", () => {
  const src = read("public/projection-cards.js");
  for (const k of ["range", "scenarios", "build"]) assert.match(src, new RegExp(k + ": \\{ label"));
  for (const k of ["wide: { w: 1600, h: 900", "square: { w: 1080, h: 1080", "tall: { w: 1080, h: 1350"]) assert.ok(src.includes(k), k);
  assert.match(src, /plCalculateOutlook\(state\.model\)/);
  // every card carries the disclaimer and the site address
  assert.match(src, /Not investment advice\./);
  assert.match(src, /impliedlens\.com/);
});

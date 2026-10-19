"use strict";
/* Report card share image: the suggested post says only what the card says. */
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const vm = require("vm");

test("suggested post lists the score, rank and five grades, and links the stock", () => {
  const window = {};
  vm.runInNewContext(fs.readFileSync(path.join(__dirname, "..", "public/report-card-share.js"), "utf8"), { window, document: {}, navigator: {} });
  const S = window.ILReportCardShare;
  S._state.card = { ticker: "AAPL", grades: { status: "graded", score: 7.08, label: "Above average", rank: { position: 7, of: 19, sectorName: "Technology" },
    factors: [{ key: "value", grade: "C-" }, { key: "growth", grade: "C+" }, { key: "profitability", grade: "B" }, { key: "health", grade: "C+" }, { key: "momentum", grade: "B" }] } };
  const post = S._post();
  assert.match(post, /^\$AAPL report card: 7\.1\/10 \(Above average\), #7 of 19 in Technology\./);
  assert.match(post, /\nValue C-\nGrowth C\+\nProfit B\nHealth C\+\nMomentum B\n/);
  assert.match(post, /impliedlens\.com\/stock\/AAPL$/);
});

test("ungraded stocks do not open the studio", () => {
  const window = {};
  vm.runInNewContext(fs.readFileSync(path.join(__dirname, "..", "public/report-card-share.js"), "utf8"), { window, document: {}, navigator: {} });
  assert.doesNotThrow(() => window.ILReportCardShare.open({ ticker: "SPY", grades: { status: "ungraded" } }));
  assert.equal(window.ILReportCardShare._state.card, null);
});

"use strict";
const test = require("node:test");
const assert = require("node:assert");
process.env.NODE_ENV = "test";
const { cardPayload } = require("../routes/lens-score");

test("card payload keeps what the homepage demo shows and drops the heavy series", () => {
  const bars = Array.from({ length: 1260 }, (_, i) => ({ time: i, open: 1, high: 2, low: 0.5, close: 100 + i, volume: 10 }));
  const full = {
    schemaVersion: 7, ticker: "NVDA", company: "NVIDIA",
    score: { status: "graded", score: 5.7, lenses: { value: { score: 5.2 } }, components: { risk: 65 }, strengths: ["a"], concerns: ["b"],
      technical: { status: "ok", score: 7, bars, timing: [1, 2, 3], trendRegime: [4], zones: [5] } },
    market: { bars }, fundamentals: { values: {} }, earnings: {}, provenance: { asOf: { market: "x" }, retrievedAt: "y", sources: [] },
  };
  const card = cardPayload(full);
  assert.strictEqual(card.score.score, 5.7);
  assert.deepStrictEqual(card.score.lenses, full.score.lenses);
  assert.strictEqual(card.score.technical.bars.length, 252);
  assert.deepStrictEqual(card.score.technical.bars.at(-1), { close: 100 + 1259 });
  assert.ok(!("timing" in card.score.technical) && !("zones" in card.score.technical) && !("trendRegime" in card.score.technical));
  assert.ok(!("market" in card) && !("fundamentals" in card));
  assert.ok(JSON.stringify(card).length < JSON.stringify(full).length / 10);
});

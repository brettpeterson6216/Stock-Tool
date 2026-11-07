"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const rf = require("../lib/risk-free");

test("the T-bill rate is the latest real observation in FRED's CSV", () => {
  assert.deepEqual(rf.parseFredCsv("observation_date,DTB3\n2026-10-29,3.88\n2026-10-30,3.86\n2026-11-02,.\n"), { rate: 0.0386, asOf: "2026-10-30", source: "FRED DTB3" });
  assert.equal(rf.parseFredCsv("<html>error</html>"), null);
  assert.equal(rf.FALLBACK.source, "fallback");
});

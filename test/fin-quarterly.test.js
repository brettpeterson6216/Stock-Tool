"use strict";
/* Quarterly statements table (public/fin-quarterly.js). */
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const vm = require("vm");

function load() {
  const window = {};
  const document = { readyState: "complete", querySelector: () => null, querySelectorAll: () => [], getElementById: () => null, addEventListener() {} };
  vm.runInNewContext(fs.readFileSync(path.join(__dirname, "..", "public/fin-quarterly.js"), "utf8"), { window, document, localStorage: { getItem() { return null; }, setItem() {} }, fetch() {}, Promise });
  return window.ILFinQuarterly;
}
const q = (label, end, revenue, netIncome, extra = {}) => ({ label, end, revenue, grossProfit: revenue * 0.4, operatingIncome: revenue * 0.2, netIncome, eps: netIncome / 1e9, shares: 1e9, operatingCashFlow: revenue * 0.25, capex: revenue * 0.05, freeCashFlow: revenue * 0.2, derived: [], ...extra });
const DATA = { quarters: [
  q("Q1 2025", "2025-03-29", 100e9, 20e9), q("Q2 2025", "2025-06-28", 90e9, 18e9), q("Q3 2025", "2025-09-27", 95e9, 19e9),
  q("Q4 2025", "2025-12-27", 120e9, -5e9, { derived: ["revenue", "netIncome", "shares"] }), q("Q1 2026", "2026-03-28", 110e9, 22e9),
], calendar: "" };

test("newest quarter first, with its filing linked in the header", () => {
  const F = load();
  const html = F._table(F._rows.income, DATA, { "2026-03-28": { form: "10-Q", filed: "2026-05-01", url: "https://www.sec.gov/x" } });
  const heads = [...html.matchAll(/il-fq-lbl">([^<]+)</g)].map(m => m[1]);
  assert.deepEqual(heads, ["Q1 2026", "Q4 2025", "Q3 2025", "Q2 2025", "Q1 2025"]);
  assert.match(html, /href="https:\/\/www\.sec\.gov\/x"[^>]*>10-Q</);
});

test("cells carry exact numbers, growth compares with a year earlier, losses are marked", () => {
  const F = load();
  const html = F._table(F._rows.income, DATA, {});
  assert.match(html, /data-raw="110000000000">\$110\.00B/);
  assert.match(html, /data-raw="10(\.0+\d*)?">10\.0%/, "Q1 2026 vs Q1 2025 revenue +10%");
  assert.match(html, /class="fin-negative" data-raw="-5000000000"/);
});

test("derived fourth quarters are footnoted; a carried share count is not", () => {
  const F = load();
  const html = F._table(F._rows.income, DATA, {});
  const marks = (html.match(/il-fq-mark/g) || []).length;
  assert.equal(marks, 2, "Q4 revenue and net income; the share count is carried, not derived from the 10-K");
});

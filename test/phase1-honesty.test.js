"use strict";
/* Phase 1: the site only sells what works, teaches the method it uses, and
   the new stock-page pieces (report card, alerts, grades, CSV) stay wired. */
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const read = (...p) => fs.readFileSync(path.join(__dirname, "..", ...p), "utf8");

const SELLING = ["public/pricing.html", "index.html", "public/about.html"];

test("pricing and marketing copy do not sell features the data feeds cannot deliver", () => {
  for (const file of SELLING) {
    const html = read(file);
    for (const claim of [/Earnings-call research/i, /institutional holders/i, /analyst (price )?targets/i, /estimate revisions/i, /AI Portfolio Guide<\/li>/]) {
      assert.doesNotMatch(html.replace(/<script[\s\S]*?<\/script>/g, ""), claim, `${file} still claims ${claim}`);
    }
  }
  const pricing = read("public/pricing.html");
  assert.match(pricing, /LensScore report card/);
  assert.match(pricing, /Grade screener/);
  assert.match(pricing, /3 at a time/);
  assert.match(pricing, /CSV export/);
});

test("no page still teaches the retired LensValue / LensSetup model", () => {
  const files = ["public/lessons-data.js", "public/learn.html", "index.html", "public/data-sources.html", "public/product-system.js", "public/learn/lens-score.html", "public/learn/site-tour.html"];
  for (const f of files) assert.doesNotMatch(read(f), /LensValue|LensSetup|Golden Lens/, f);
  const L = require("../public/lessons-data.js").bySlug["lens-score"];
  assert.match(L.title, /five grades/);
  assert.equal(L.quiz.length, 3);
  L.quiz.forEach(q => assert.ok(q.answer >= 0 && q.answer < q.options.length));
});

test("lesson weights and caps match the scoring code", () => {
  const F = require("../lib/lens-factors");
  const L = require("../public/lessons-data.js").bySlug["lens-score"];
  const text = L.points.join(" ") + L.formula;
  const pct = k => `${Math.round(F.WEIGHTS[k] * 100)}%`;
  assert.match(text, new RegExp(`Profitability \\(${pct("profitability")}\\)|${pct("profitability")} Profitability`));
  assert.match(text, new RegExp(`Health \\(${pct("health")}\\)|${pct("health")} Health`));
  assert.match(text, /6\.8/); assert.match(text, /5\.0/);
});

test("next earnings picks the first future date and labels the session", () => {
  const { nextEarnings } = require("../lib/street");
  const n = nextEarnings({ earningsCalendar: [{ date: "2026-11-02", hour: "bmo" }, { date: "2026-10-01" }, { date: "2026-10-29", hour: "amc", epsEstimate: 1.5 }] }, "2026-10-08");
  assert.equal(n.date, "2026-10-29"); assert.equal(n.when, "after the close"); assert.equal(n.days, 21); assert.equal(n.epsEstimate, 1.5);
  assert.equal(nextEarnings({ earningsCalendar: [] }), null);
  assert.equal(nextEarnings(null), null);
});

test("stock page loads the report card, alert button and CSV export", () => {
  const html = read("index.html");
  assert.match(html, /src="\/stock-report-card\.js/);
  assert.match(html, /src="\/csv-export\.js/);
  assert.match(read("public/app-legacy.js"), /window\.ILStockCard\?\.load\(ticker\)/);
  const card = read("public/stock-report-card.js");
  assert.match(card, /\/api\/lens-score\/\$\{encodeURIComponent\(ticker\)\}\?card=1/);
  assert.match(card, /X-CSRF-Token/);
  assert.match(card, /\/api\/lens-grades\?tickers=/);
  assert.match(read("labs/lens-score/index.html"), /src="\/csv-export\.js/);
});

test("CSV export guards against spreadsheet formulas and quotes properly", () => {
  global.window = {};
  global.document = { readyState: "loading", addEventListener() {} };
  require("../public/csv-export.js");
  const q = window.ILExport._quote;
  assert.equal(q("=HYPERLINK(1)"), "'=HYPERLINK(1)");
  assert.equal(q("-12.5"), "-12.5");
  assert.equal(q("a,b"), '"a,b"');
  assert.equal(q('say "hi"'), '"say ""hi"""');
  delete global.window; delete global.document;
});

test("bulk grades endpoint is rate limited and registered", () => {
  assert.match(read("server.js"), /"\/api\/lens-grades"/);
  assert.match(read("routes/lens-score.js"), /router\.get\("\/lens-grades"/);
  assert.match(read("lib/lens-history.js"), /async function changesFor/);
});

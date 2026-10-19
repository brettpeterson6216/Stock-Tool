"use strict";
/* Earnings materials from SEC filings (lib/sec-earnings.js). */
const test = require("node:test");
const assert = require("node:assert/strict");
const E = require("../lib/sec-earnings");

const FILINGS = [
  { form: "8-K", filingDate: "2026-07-30", items: "2.02,9.01", accession: "0000320193-26-000070", primaryDocument: "a8k.htm" },
  { form: "10-Q", filingDate: "2026-08-01", reportDate: "2026-06-27", accession: "0000320193-26-000071", primaryDocument: "q3.htm" },
  { form: "8-K", filingDate: "2026-06-10", items: "5.07", accession: "0000320193-26-000060", primaryDocument: "vote.htm" },
  { form: "8-K", filingDate: "2026-04-30", items: "2.02,9.01", accession: "0000320193-26-000050", primaryDocument: "a8k.htm" },
  { form: "10-Q", filingDate: "2026-05-02", reportDate: "2026-03-28", accession: "0000320193-26-000051", primaryDocument: "q2.htm" },
  { form: "10-Q/A", filingDate: "2026-05-20", reportDate: "2026-03-28", accession: "0000320193-26-000055", primaryDocument: "q2a.htm" },
  { form: "8-K", filingDate: "2025-10-30", items: "2.02", accession: "0000320193-25-000090", primaryDocument: "a8k.htm" },
  { form: "10-K", filingDate: "2025-10-31", reportDate: "2025-09-27", accession: "0000320193-25-000091", primaryDocument: "k.htm" },
];
const Q = (label, end, revenue, netIncome, eps) => ({ label, end, revenue, netIncome, eps });
const QUARTERS = [
  Q("Q2 2025", "2025-06-28", 85e9, 21e9, 1.40), Q("Q3 2025", "2025-09-27", 95e9, 15e9, 1.00),
  Q("Q4 2025", "2025-12-27", 120e9, 34e9, 2.20), Q("Q1 2026", "2026-03-28", 90e9, 23e9, 1.50),
  Q("Q2 2026", "2026-06-27", 94e9, 23.1e9, 1.61),
];

test("results releases pair with their quarter and the 10-Q/10-K that followed", () => {
  const rows = E.buildReleases({ cik: "0000320193", filings: FILINGS, quarters: QUARTERS });
  assert.equal(rows.length, 3, "only Item 2.02 8-Ks");
  const [jul, apr, oct] = rows;
  assert.equal(jul.title, "Q2 2026 results");
  assert.equal(jul.quarter.revenue, 94e9);
  assert.equal(Math.round(jul.quarter.revenueYoY * 10) / 10, 10.6, "vs Q2 2025");
  assert.equal(jul.report.form, "10-Q");
  assert.match(jul.report.url, /\/320193\/000032019326000071\/q3\.htm$/);
  assert.equal(apr.report.form, "10-Q", "the original, not the amendment");
  assert.equal(oct.quarter.label, "Q3 2025");
  assert.equal(oct.report.form, "10-K");
  assert.equal(oct.quarter.revenueYoY, null, "no quarter a year earlier");
  assert.equal(jul.id, "0000320193-26-000070");
});

test("a release more than ~100 days after any quarter gets no numbers", () => {
  assert.equal(E.quarterForRelease(QUARTERS, "2027-03-01"), null);
  assert.equal(E.quarterForRelease(QUARTERS, "2026-07-30").label, "Q2 2026");
});

test("press release text: prose kept, tables and scripts dropped, entities decoded", () => {
  const html = `<html><head><title>x</title><style>p{}</style></head><body>
    <p>EXHIBIT 99.1</p>
    <p style="x">CUPERTINO, California &#8212; July 30, 2026 &#8212; The company today announced results for its quarter, with revenue of $94.0&nbsp;billion.</p>
    <table><tr><td>Net sales</td><td>94,036</td></tr></table>
    <div>&ldquo;We&rsquo;re pleased with the quarter,&rdquo; said the CEO.</div>
    <script>alert(1)</script>
    <ul><li>Services revenue reached an all-time high this quarter</li></ul>
    <p>Page 1</p></body></html>`;
  const p = E.releaseParagraphs(html);
  assert.equal(p.length, 3);
  assert.match(p[0], /^CUPERTINO, California — July 30, 2026 — /);
  assert.match(p[0], /\$94\.0 billion\./);
  assert.equal(p[1], "“We’re pleased with the quarter,” said the CEO.");
  assert.match(p[2], /^• Services revenue/);
  assert.ok(!p.join(" ").includes("94,036"), "tables are left out");
  assert.ok(!p.join(" ").includes("alert"), "scripts are left out");
});

test("the press release exhibit is found among the filing's files", () => {
  const items = [{ name: "a8k.htm", size: 30000 }, { name: "a8-kex991q3fy26.htm", size: 90000 }, { name: "a8-kex992q3fy26.htm", size: 40000 }, { name: "0000320193-26-000070-index.htm", size: 3000 }];
  assert.equal(E.pickExhibit(items, "a8k.htm"), "a8-kex991q3fy26.htm");
  assert.equal(E.pickExhibit([{ name: "a8k.htm" }, { name: "q32026results.htm", size: 50000 }, { name: "logo.jpg" }], "a8k.htm"), "q32026results.htm");
  assert.equal(E.pickExhibit([{ name: "a8k.htm" }], "a8k.htm"), null);
});

test("filing ids are validated before anything is fetched", async () => {
  await assert.rejects(E.releaseText("AAPL", "../../etc"), /Invalid filing id/);
});

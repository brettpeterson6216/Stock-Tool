"use strict";
/* The switch to licensed data: Finnhub and Yahoo are gated, prices go
   through one provider module, and grades, insider trades and the next
   earnings date come from SEC filings. */
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const read = (...p) => fs.readFileSync(path.join(__dirname, "..", ...p), "utf8");

test("data policy blocks Finnhub and Stooq, and Yahoo once a licensed price key exists", () => {
  const policy = require("../lib/data-policy");
  const saved = { f: process.env.FINNHUB_ENABLED, m: process.env.MARKETSTACK_API_KEY };
  delete process.env.FINNHUB_ENABLED; delete process.env.MARKETSTACK_API_KEY;
  assert.equal(policy.allowed("finnhub.io"), false);
  assert.equal(policy.allowed("stooq.com"), false);
  assert.equal(policy.allowed("query1.finance.yahoo.com"), true, "legacy prices until the key is set");
  assert.equal(policy.allowed("data.sec.gov"), true);
  assert.equal(policy.allowed("api.marketstack.com"), true);
  process.env.MARKETSTACK_API_KEY = "k";
  assert.equal(policy.allowed("query2.finance.yahoo.com"), false);
  process.env.FINNHUB_ENABLED = "1";
  assert.equal(policy.allowed("finnhub.io"), true, "only with a licence");
  if (saved.f === undefined) delete process.env.FINNHUB_ENABLED; else process.env.FINNHUB_ENABLED = saved.f;
  if (saved.m === undefined) delete process.env.MARKETSTACK_API_KEY; else process.env.MARKETSTACK_API_KEY = saved.m;
});

test("no request pretends to come from finance.yahoo.com", () => {
  for (const f of ["routes/analysis.js", "routes/market-data.js", "lib/prices.js", "lib/stock-research.js"]) {
    assert.doesNotMatch(read(f), /"(Origin|Referer)":\s*"https:\/\/finance\.yahoo\.com/, f);
  }
  assert.doesNotMatch(read("routes/market-data.js"), /stooq\.com/);
});

test("Marketstack EOD rows are split-adjusted, deduplicated and sorted", () => {
  const { normalizeEod } = require("../lib/prices")._test;
  const rows = normalizeEod([
    { date: "2026-06-12T00:00:00+0000", open: 120, high: 122, low: 119, close: 121, volume: 100, split_factor: 1 },
    { date: "2026-06-10T00:00:00+0000", open: 1000, high: 1010, low: 990, close: 1000, volume: 10, split_factor: 1 },
    { date: "2026-06-11T00:00:00+0000", open: 101, high: 102, low: 99, close: 100, volume: 100, split_factor: 10 },
    { date: "2026-06-11T00:00:00+0000", open: 101, high: 102, low: 99, close: 100, volume: 100, split_factor: 10 },
  ]);
  assert.deepEqual(rows.map(r => r.day), ["2026-06-10", "2026-06-11", "2026-06-12"]);
  assert.equal(rows[0].c, 100, "the pre-split close is divided by the 10:1 factor");
  assert.equal(rows[0].v, 100, "and volume multiplied");
  assert.equal(rows[1].c, 100);
});

test("daily rows aggregate into weekly and monthly bars and a Yahoo-shaped chart", () => {
  const { aggregate, toChart } = require("../lib/prices")._test;
  const days = [["2026-06-01", 10], ["2026-06-02", 12], ["2026-06-05", 11], ["2026-06-08", 13], ["2026-07-01", 15]]
    .map(([day, c]) => ({ day, o: c, h: c + 1, l: c - 1, c, v: 1 }));
  const weeks = aggregate(days, "1wk");
  assert.equal(weeks.length, 3);
  assert.equal(weeks[0].o, 10); assert.equal(weeks[0].c, 11); assert.equal(weeks[0].h, 13); assert.equal(weeks[0].v, 3);
  assert.equal(aggregate(days, "1mo").length, 2);
  const chart = toChart("AAPL", days, { prevClose: 13, name: "Apple Inc." });
  const r = chart.chart.result[0];
  assert.equal(r.meta.regularMarketPrice, 15); assert.equal(r.meta.longName, "Apple Inc.");
  assert.equal(r.timestamp.length, 5); assert.equal(r.indicators.quote[0].close[4], 15);
});

test("SIC codes map to sectors, with pinned exceptions", () => {
  const { sectorFromSic } = require("../lib/sec-fundamentals");
  assert.equal(sectorFromSic(3674, "NVDA"), "Tech");
  assert.equal(sectorFromSic(2834, "LLY"), "Health");
  assert.equal(sectorFromSic(6021, "JPM"), "Finance");
  assert.equal(sectorFromSic(6798, "O"), "Real Est.");
  assert.equal(sectorFromSic(4911, "NEE"), "Utilities");
  assert.equal(sectorFromSic(2911, "XOM"), "Energy");
  assert.equal(sectorFromSic(7370, "META"), "Comm.", "pinned");
  assert.equal(sectorFromSic(5331, "COST"), "Staples");
  assert.equal(sectorFromSic(null, "ZZZZ"), null);
});

/* Synthetic companyfacts: eight quarters with revenue, profit, EPS and cash
   flow (10-Q quarters plus 10-K years), and a balance sheet. */
function facts() {
  const q = (start, end, val, form = "10-Q", fy = 2026) => ({ start, end, val, form, filed: end.replace(/-\d\d$/, "-28"), fy, fp: "Q" });
  const ends = [["2024-07-01", "2024-09-30"], ["2024-10-01", "2024-12-31"], ["2025-01-01", "2025-03-31"], ["2025-04-01", "2025-06-30"],
    ["2025-07-01", "2025-09-30"], ["2025-10-01", "2025-12-31"], ["2026-01-01", "2026-03-31"], ["2026-04-01", "2026-06-30"]];
  const series = (vals) => ends.map(([s, e], i) => q(s, e, vals[i]));
  const usd = rows => ({ units: { USD: rows } });
  const inst = (val) => ({ units: { USD: [{ end: "2026-06-30", val, form: "10-Q", filed: "2026-07-28" }] } });
  return { entityName: "Testco", facts: { "us-gaap": {
    Revenues: usd(series([100, 100, 100, 100, 120, 120, 120, 120])),
    GrossProfit: usd(series([50, 50, 50, 50, 66, 66, 66, 66])),
    OperatingIncomeLoss: usd(series([20, 20, 20, 20, 30, 30, 30, 30])),
    NetIncomeLoss: usd(series([10, 10, 10, 10, 15, 15, 15, 15])),
    EarningsPerShareDiluted: { units: { "USD/shares": series([1, 1, 1, 1, 1.5, 1.5, 1.5, 1.5]) } },
    StockholdersEquity: inst(200), LongTermDebt: inst(100), CashAndCashEquivalentsAtCarryingValue: inst(40),
    AssetsCurrent: inst(150), LiabilitiesCurrent: inst(75),
    InterestExpense: usd([{ start: "2025-01-01", end: "2025-12-31", val: 6, form: "10-K", filed: "2026-02-20" }]),
  }, dei: { EntityCommonStockSharesOutstanding: { units: { shares: [{ end: "2026-07-20", val: 40, form: "10-Q", filed: "2026-07-28" }] } } } } };
}

test("SEC snapshot gives trailing figures, growth and the balance sheet", () => {
  const { snapshotFromFacts } = require("../lib/sec-fundamentals");
  const s = snapshotFromFacts(facts());
  assert.equal(s.ttm.revenue, 480); assert.equal(s.prevTtm.revenue, 400);
  assert.equal(s.ttm.netIncome, 60); assert.equal(s.ttm.eps, 6);
  assert.equal(s.equity, 200); assert.equal(s.debt, 100); assert.equal(s.cash, 40);
  assert.equal(s.sharesOutstanding, 40); assert.equal(s.interestExpense, 6);
});

test("metrics use the keys the grades read, with prices for value and momentum", () => {
  const { snapshotFromFacts, metricsFrom } = require("../lib/sec-fundamentals");
  const s = snapshotFromFacts(facts());
  const rows = [], bench = [];
  for (let i = 0; i < 420; i += 1) {
    const day = new Date(Date.UTC(2025, 5, 1) + i * 864e5);
    if ([0, 6].includes(day.getUTCDay())) continue;
    const d = day.toISOString().slice(0, 10);
    rows.push({ day: d, close: 60 + i * 0.05 + Math.sin(i) * 0.5, high: 61 + i * 0.05, low: 59 + i * 0.05 });
    bench.push({ day: d, close: 500 + i * 0.1 + Math.sin(i * 1.3) * 2 });
  }
  const m = metricsFrom(s, { rows, bench });
  const price = rows.at(-1).close;
  assert.ok(Math.abs(m.peTTM - price / 6) < 1e-9);
  assert.ok(Math.abs(m.psTTM - (price * 40) / 480) < 1e-9);
  assert.equal(Math.round(m.revenueGrowthTTMYoy), 20);
  assert.equal(Math.round(m.grossMarginTTM), 55);
  assert.equal(Math.round(m.netProfitMarginTTM * 10) / 10, 12.5);
  assert.equal(m.roeTTM, 30);
  assert.equal(m["totalDebt/totalEquityQuarterly"], 0.5);
  assert.equal(m.currentRatioQuarterly, 2);
  assert.equal(m.netInterestCoverageTTM, 20);
  assert.ok(Number.isFinite(m["priceRelativeToS&P50013Week"]));
  assert.ok(Number.isFinite(m.beta));
  assert.ok(m["52WeekHigh"] >= price);
  assert.equal(m.forwardPE, undefined, "no estimates, no forward P/E");
});

test("Form 4 parsing keeps open-market buys and sales only", () => {
  const { parseForm4 } = require("../lib/sec-filings");
  const xml = `<ownershipDocument><reportingOwner><reportingOwnerId><rptOwnerName>DOE JANE</rptOwnerName></reportingOwnerId>
    <reportingOwnerRelationship><isDirector>1</isDirector></reportingOwnerRelationship></reportingOwner><nonDerivativeTable>
    <nonDerivativeTransaction><transactionDate><value>2026-05-01</value></transactionDate><transactionCoding><transactionCode>P</transactionCode></transactionCoding>
    <transactionAmounts><transactionShares><value>1000</value></transactionShares><transactionPricePerShare><value>50.5</value><footnoteId id="F1"/></transactionPricePerShare>
    <transactionAcquiredDisposedCode><value>A</value></transactionAcquiredDisposedCode></transactionAmounts></nonDerivativeTransaction>
    <nonDerivativeTransaction><transactionDate><value>2026-05-02</value></transactionDate><transactionCoding><transactionCode>F</transactionCode></transactionCoding>
    <transactionAmounts><transactionShares><value>10</value></transactionShares></transactionAmounts></nonDerivativeTransaction></nonDerivativeTable></ownershipDocument>`;
  const out = parseForm4(xml);
  assert.equal(out.length, 1);
  assert.deepEqual({ name: out[0].name, role: out[0].role, code: out[0].code, change: out[0].change, price: out[0].price }, { name: "DOE JANE", role: "Director", code: "P", change: 1000, price: 50.5 });
});

test("next earnings is estimated from past results filings and labelled as an estimate", () => {
  const { estimateNextEarnings } = require("../lib/sec-filings");
  const f = (form, items, filingDate) => ({ form, items, filingDate });
  const filings = [f("8-K", "2.02,9.01", "2025-10-30"), f("8-K", "2.02,9.01", "2026-01-29"), f("8-K", "2.02", "2026-04-30"), f("8-K", "2.02,9.01", "2026-07-30"), f("8-K", "5.02", "2026-09-01")];
  const n = estimateNextEarnings(filings, "2026-10-19");
  assert.equal(n.date, "2026-10-29"); assert.equal(n.estimated, true); assert.equal(n.days, 10);
  assert.equal(estimateNextEarnings([], "2026-10-19"), null);
  const fallback = estimateNextEarnings([f("10-Q", "", "2026-08-05"), f("10-Q", "", "2026-05-06")], "2026-10-19");
  assert.ok(fallback.date >= "2026-10-19");
});

test("SEC snapshots refresh on a new 10-Q/10-K or after a month", () => {
  const { needsRefresh } = require("../lib/sec-universe");
  const entry = { snap: { asOf: "2026-08-01" }, fetchedAt: Date.parse("2026-08-02") };
  assert.equal(needsRefresh(entry, [{ form: "8-K", filingDate: "2026-09-01" }], Date.parse("2026-08-20")), false);
  assert.equal(needsRefresh(entry, [{ form: "10-Q", filingDate: "2026-10-30" }], Date.parse("2026-10-31")), true);
  assert.equal(needsRefresh(entry, [], Date.parse("2026-09-15")), true);
  assert.equal(needsRefresh(null, []), true);
});

test("analyst ratings and estimates are gone from what the site sells and shows", () => {
  for (const f of ["public/pricing.html", "index.html"]) {
    assert.doesNotMatch(read(f), /analyst rating/i, f);
  }
  assert.match(read("routes/market-data.js"), /available: false/);
  assert.match(read("routes/financials.js"), /analystDataAvailable: false/);
  assert.match(read("lib/lens-history.js"), /METHOD = "sec-1"/);
});

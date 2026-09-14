"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");
const tickerIndex = require("../lib/ticker-index");
const { searchTickers, _fromFinnhub } = require("../routes/search");

const read = rel => fs.readFileSync(path.join(ROOT, rel), "utf8");

// Every page that renders the header, plus the SPA. The header carries a
// search field on all of them; a field that behaves differently per page is
// the thing this whole feature replaces.
const PAGES = [
  "index.html",
  "public/about.html", "public/blog.html", "public/terms.html", "public/privacy.html",
  "public/data-sources.html", "public/research-process.html", "public/compound-calculator.html",
  "public/login.html", "public/signup.html", "public/reset-password.html",
  "public/admin-analytics.html", "public/learn.html", "public/pricing.html",
  "labs/lens-score/index.html",
];

// ── the index ───────────────────────────────────────────────────────────────

test("a symbol someone types exactly comes first", () => {
  assert.equal(tickerIndex.search("F")[0].symbol, "F");
  assert.equal(tickerIndex.search("MA")[0].symbol, "MA");
  assert.equal(tickerIndex.search("aapl")[0].symbol, "AAPL");
});

// The whole point of the feature: knowing the company but not the symbol was
// a dead end everywhere on the site.
test("a company name resolves to its symbol", () => {
  const cases = [
    ["apple", "AAPL"],
    ["ford", "F"],
    ["coca", "KO"],
    ["berkshire", "BRK.B"],
    ["johnson", "JNJ"],
    ["home depot", "HD"],
  ];
  for (const [query, symbol] of cases) {
    const hit = tickerIndex.search(query)[0];
    assert.ok(hit, `"${query}" found nothing`);
    assert.equal(hit.symbol, symbol, `"${query}" -> ${hit.symbol}`);
  }
});

// A bare letter used to be answered by whichever symbol was shortest, which
// put Abbott above Apple.
test("ties break on how often a name is searched, not alphabetically", () => {
  assert.equal(tickerIndex.search("A")[0].symbol, "AAPL");
  assert.equal(tickerIndex.search("T")[0].symbol, "T");
});

test("the query is normalized the same way on both sides", () => {
  assert.equal(tickerIndex.normalizeQuery("  aapl \n"), "AAPL");
  assert.equal(tickerIndex.normalizeQuery("home   depot"), "HOME DEPOT");
  assert.equal(tickerIndex.normalizeQuery(null), "");
  assert.equal(tickerIndex.normalizeQuery("x".repeat(80)).length, 48);
});

// EDGAR titles are inconsistently cased. One SHOUTING row beside a normal one
// reads as a rendering bug.
test("EDGAR's all-caps titles are made readable, and normal ones left alone", () => {
  assert.equal(tickerIndex.prettifyName("TESLA, INC."), "Tesla, Inc.");
  assert.equal(tickerIndex.prettifyName("BANK OF AMERICA CORP"), "Bank of America Corp");
  assert.equal(tickerIndex.prettifyName("Apple Inc."), "Apple Inc.");
  assert.match(tickerIndex.prettifyName("ACCENTURE PLC"), /PLC$/);
});

test("the SEC list fills in around the seed without overwriting its names", async () => {
  const before = tickerIndex.size();
  const ok = await tickerIndex.refreshFromSec({
    fetch: async () => ({
      ok: true,
      json: async () => ({
        "0": { cik_str: 320193, ticker: "AAPL", title: "APPLE INC." },
        "1": { cik_str: 1, ticker: "ZZTOP", title: "ZZ TOP HOLDINGS CORP" },
        "2": { cik_str: 2, ticker: "BAD SYMBOL!", title: "Nope" },
      }),
    }),
  });
  assert.equal(ok, true);
  assert.ok(tickerIndex.size() > before, "the index did not grow");
  assert.equal(tickerIndex.search("AAPL")[0].name, "Apple Inc.", "the curated name lost to EDGAR's");
  assert.equal(tickerIndex.search("zz top")[0].symbol, "ZZTOP");
  assert.equal(tickerIndex.search("BAD SYMBOL!").length, 0);
  assert.ok(tickerIndex.refreshedAt());
});

// A search that stops working because a third party is down is worse than a
// search that is a day stale.
test("a failed refresh leaves the working index alone", async () => {
  const size = tickerIndex.size();
  assert.equal(await tickerIndex.refreshFromSec({ fetch: async () => { throw new Error("network"); } }), false);
  assert.equal(await tickerIndex.refreshFromSec({ fetch: async () => ({ ok: false }) }), false);
  assert.equal(await tickerIndex.refreshFromSec({ fetch: async () => ({ ok: true, json: async () => ({}) }) }), false);
  assert.equal(tickerIndex.size(), size);
  assert.equal(tickerIndex.search("apple")[0].symbol, "AAPL");
});

// ── the endpoint ────────────────────────────────────────────────────────────

test("one character is answered from the index alone", async () => {
  let called = false;
  const out = await searchTickers("A", 8, { finnhubSearch: async () => { called = true; return []; } });
  assert.equal(called, false, "a single letter should not cost a vendor call");
  assert.equal(out.source, "index");
  assert.ok(out.results.length);
});

test("the vendor only fills the gap the index leaves, and never duplicates it", async () => {
  const out = await searchTickers("ARKK", 5, {
    finnhubSearch: async () => ([
      { symbol: "ARKK", name: "ARK Innovation ETF" },      // already in the index
      { symbol: "ARKW", name: "ARK Next Generation Internet ETF" },
    ]),
  });
  const symbols = out.results.map(r => r.symbol);
  assert.equal(new Set(symbols).size, symbols.length, "duplicate symbols: " + symbols.join(","));
  assert.ok(symbols.includes("ARKK"));
  assert.ok(symbols.includes("ARKW"), "the vendor result was dropped");
  assert.equal(out.source, "mixed");
});

test("an empty query is an empty answer, not an error", async () => {
  const out = await searchTickers("   ", 8, { finnhubSearch: async () => { throw new Error("never"); } });
  assert.deepEqual(out.results, []);
});

test("limit is honoured and clamped", async () => {
  assert.ok((await searchTickers("A", 3)).results.length <= 3);
  assert.ok((await searchTickers("A", 999)).results.length <= 25);
});

// Finnhub answers a US-exchange query with every listing of the company
// worldwide. AAPL.MX is not what someone searching here meant.
test("foreign listings and non-equities are filtered out of vendor results", () => {
  const kept = _fromFinnhub({
    result: [
      { symbol: "AAPL", displaySymbol: "AAPL", description: "APPLE INC", type: "Common Stock" },
      { symbol: "AAPL.MX", displaySymbol: "AAPL.MX", description: "APPLE INC", type: "Common Stock" },
      { symbol: "APC.DE", displaySymbol: "APC.DE", description: "APPLE INC", type: "Common Stock" },
      { symbol: "BRK.B", displaySymbol: "BRK.B", description: "BERKSHIRE HATHAWAY INC", type: "Common Stock" },
      { symbol: "AAPL240119C", displaySymbol: "AAPL240119C", description: "CALL", type: "option" },
    ],
  }).map(hit => hit.symbol);
  assert.deepEqual(kept, ["AAPL", "BRK.B"]);
});

// ── the wiring ──────────────────────────────────────────────────────────────

// "Connected across the site" is the requirement. A page that carries the
// search field but not the script has a search box that behaves like the old
// one, which is exactly the inconsistency being removed.
test("every page with the header also loads the search behaviour", () => {
  const missing = PAGES.filter(rel => !read(rel).includes("/ticker-search.js"));
  assert.deepEqual(missing, [], "pages with a search field and no search behaviour");
});

test("the search upgrades every input on the site, not just the header one", () => {
  const js = read("public/ticker-search.js");
  for (const selector of [
    "#nav-ticker-input",      // the header, on every page
    "#ihm-ticker",            // the dashboard's own search
    "#landing-search",        // the landing hero — the first box a visitor meets
    "#mmenu-ticker",          // the mobile menu
    "input[id$='-ticker']",   // main, quick, compare, thesis, learn, lab empty states
    "#cmp1",
    "[data-ticker-search]",   // the research workspace
  ]) {
    assert.ok(js.includes(selector), `${selector} is not upgraded`);
  }
});

// "Connected across the site" means the boxes a person actually types in. Each
// of these was found by listing every ticker input on a rendered page, not by
// reading the markup.
test("no ticker input on the home page is left on the old behaviour", () => {
  const js = read("public/ticker-search.js");
  const html = read("index.html");
  // Not every box with "search" in its id takes a company: the glossary filter
  // is a text filter over concepts and has no business suggesting NVDA.
  const NOT_A_TICKER_BOX = new Set(["edu-glossary-search"]);
  const ids = [...html.matchAll(/<input[^>]*id="([^"]*(?:ticker|search|cmp\d)[^"]*)"/g)]
    .map(m => m[1])
    .filter(id => !NOT_A_TICKER_BOX.has(id));
  const covered = id =>
    js.includes("#" + id) ||
    (/-ticker$/.test(id) && js.includes("input[id$='-ticker']")) ||
    new RegExp('id="' + id + '"[^>]*data-ticker-search').test(html) ||
    id === "nav-ticker-input";
  const missed = ids.filter(id => !covered(id));
  assert.deepEqual(missed, [], "ticker inputs with no suggestions behind them");
});

// The header block is hashed byte-for-byte across every page (see
// header-contract). Adding the listbox as markup would break that on 15
// documents at once, so it has to be built at runtime.
test("the search adds no markup to the header", () => {
  for (const rel of PAGES) {
    const nav = read(rel).match(/<nav id="main-nav"[\s\S]*?<\/nav>/);
    if (!nav) continue;
    assert.ok(!nav[0].includes("ts-list"), `${rel} has listbox markup in the header`);
    assert.ok(!nav[0].includes("ticker-search"), `${rel} has search markup in the header`);
  }
});

test("suggestion text is built as text nodes, never as innerHTML", () => {
  const js = read("public/ticker-search.js");
  // Company names come from EDGAR and from a vendor. The only innerHTML in the
  // file is the static clear-button icon.
  const assignments = js.match(/\.innerHTML\s*=\s*([^\n;]+)/g) || [];
  for (const line of assignments) {
    assert.ok(/^\.innerHTML\s*=\s*(''|""|'<svg|"<svg)/.test(line.trim()), `unsafe innerHTML: ${line.trim().slice(0, 60)}`);
  }
});

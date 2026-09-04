"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");
const html = fs.readFileSync(path.join(ROOT, "index.html"), "utf8");
const js = fs.readFileSync(path.join(ROOT, "public", "landing-market.js"), "utf8");
const css = fs.readFileSync(path.join(ROOT, "public", "clean-pass.css"), "utf8");

const HERO = html.slice(html.indexOf('id="il-hero-live"') - 200, html.indexOf('class="il-landing-copy"'));

// What this replaced: an illustration of a magnifying glass over candlesticks
// whose readout said AAPL 191.62, implied move 4.23%, options sentiment
// Bullish, IV rank 64. There is no options endpoint in this codebase, so three
// of those five rows could never be real, and the "Sample data" line meant to
// disclose it was clipped off the bottom of its own container.
test("the hero ships no prices, percentages or tickers of its own", () => {
  const invented = [
    [/\b\d{1,3}\.\d{2}\b/, "a hardcoded price"],
    [/[+-]?\d+(\.\d+)?%/, "a hardcoded percentage"],
    [/\b(AAPL|MSFT|NVDA|TSLA|AMZN|META|GOOGL)\b/, "a hardcoded ticker"],
    [/implied move/i, "an implied-move readout"],
    [/options sentiment/i, "an options-sentiment readout"],
    [/IV rank/i, "an IV-rank readout"],
  ];
  for (const [re, what] of invented) {
    assert.doesNotMatch(HERO, re, `the hero markup contains ${what}`);
  }
});

test("the old illustration and its mobile twin are gone for good", () => {
  for (const marker of ["il-hero-mock", "ihx-scene", "ihx-r-row", "ihx-r-foot", "prime-mobile-hero-card", "pmhc-price"]) {
    assert.ok(!html.includes(marker), `${marker} is back in the landing page`);
  }
});

// Every value comes from one request, the same one the terminal lower down
// already makes.
test("every hero value is read from the market summary response", () => {
  assert.match(js, /function renderHero\(/, "the hero renderer is gone");
  assert.match(js, /overview\.price/, "the price must come from the response");
  assert.match(js, /overview\.changePct/, "the change must come from the response");
  assert.match(js, /overview\.closes/, "the chart must come from the response");
  assert.match(js, /data\.asOf/, "the freshness stamp must come from the response");
  // one fetch, two consumers
  const fetches = js.match(/fetch\(/g) || [];
  assert.equal(fetches.length, 1, "the hero must share the terminal's request, not add another");
});

// A hero that invents a number when the provider is down is the problem this
// replaced. It has to degrade to saying nothing.
test("a failed fetch produces a stated empty state, not a shaped number", () => {
  assert.match(js, /if \(!overview \|\| !Number\.isFinite\(Number\(overview\.price\)\)\)/,
    "the renderer must test for a real price before painting one");
  assert.match(js, /'Unavailable'/, "the status chip must be able to say Unavailable");
  assert.match(html, /Market data is unavailable right now\./, "the empty state copy is gone");
  assert.match(js, /The market data provider did not respond\./, "the empty state must name the cause");
});

// [hidden] is only display:none at user-agent weight; an !important display
// rule beats it, which left the unavailable message painted over a chart that
// had loaded fine.
test("the empty state hides when data arrives", () => {
  assert.match(
    css,
    /\.ihl-empty\[hidden\]\s*\{[^}]*display:\s*none\s*!important/,
    "the hidden attribute must win against the component's own display rule"
  );
});

// The block it replaced hardcoded background:#091013, which is why it sat in
// the light page as a dark slab.
test("the hero paints from theme tokens", () => {
  // Bound the slice to the hero's own block. Reading to the end of the file
  // swept in later sections and failed on the gold CTA gradient in the member
  // home, which is deliberate and identical in both themes.
  const start = css.indexOf("LIVE MARKET HERO");
  assert.ok(start !== -1, "the hero styles are gone");
  const next = css.indexOf("═══\n   ", start + 200);
  const block = css.slice(start, next === -1 ? css.length : next);
  const literals = [...block.matchAll(/(?:background|border-color)\s*:\s*([^;!}]+)/g)]
    .map(m => m[1].trim())
    .filter(v => !/var\(--/.test(v) && !/^(transparent|none|inherit|initial|unset)$/i.test(v))
    // The gold accent is intentionally the same in both themes.
    .filter(v => !/#edca79|#c98d2c|#e3b25a|#c08f3a/i.test(v))
    .filter(v => /#[0-9a-f]{3,8}|rgba?\(/i.test(v));
  assert.deepEqual(literals, [], "the hero must not hardcode a surface colour");
});

// ── The home page serves two audiences from one URL ────────────────────────
const homeCss = fs.readFileSync(path.join(ROOT, "public", "clean-pass.css"), "utf8");
const memberJs = fs.readFileSync(path.join(ROOT, "public", "home-member.js"), "utf8");

test("the signed-in and signed-out homes cannot both be hidden", () => {
  // Written with one :not(#id) fewer, the signed-in rule lost to the base hide
  // and neither page rendered. Id count is compared before class count, so the
  // two rules have to carry the same id weight for the class to break the tie.
  const ids = sel => (sel.match(/:not\(#|#[A-Za-z]/g) || []).length;
  const hide = homeCss.match(/^(html:not\(#cp1\)[^{,]*#il-home-member) \{ display: none/m);
  const show = homeCss.match(/^(html\.il-hint-in:not\(#cp1\)[^{,]*#il-home-member) \{ display: flex/m);
  assert.ok(hide && show, "the two-audience rules are gone");
  assert.equal(ids(show[1]), ids(hide[1]),
    `show carries ${ids(show[1])} ids against hide's ${ids(hide[1])}`);
});

test("the visitor page is what an unresolved session falls back to", () => {
  // Showing a stranger an empty workspace is the worse failure of the two.
  const catchIdx = memberJs.lastIndexOf(".catch(");
  assert.ok(catchIdx !== -1, "the session check has no failure path");
  assert.match(memberJs.slice(catchIdx, catchIdx + 400), /il-hint-out/,
    "a failed session check must fall back to the visitor page");
  assert.doesNotMatch(
    homeCss,
    /html\.il-hint-unknown[^{]*#il-home-member \{ display: flex/,
    "an unknown session must not render the member home"
  );
});

test("member counts are read, never invented", () => {
  assert.match(memberJs, /workspace\/summary/, "counts must come from the workspace summary");
  assert.match(memberJs, /\/api\/saves/, "recent analyses must come from the saves endpoint");
  assert.match(memberJs, /Number\.isFinite\(n\)/, "a missing count must not render as a number");
  assert.match(memberJs, /counts are unavailable right now/, "a failed count must say so rather than show zero");
});

test("the dashboard offers places to go, not a lecture on how to use it", () => {
  assert.match(homeCss, /#il-home-member \[hidden\][\s\S]{0,140}display: none !important/,
    "[hidden] must win against the component's own display rule");
  const html = fs.readFileSync(path.join(ROOT, "index.html"), "utf8");

  // The three numbered steps told someone who had already signed up and
  // logged in to search for a ticker, next to the box that already invited
  // them to. Four named tools are what replaced them.
  assert.doesNotMatch(html, /id="ihm-start"/, "the numbered how-to steps are back");
  assert.doesNotMatch(html, /ihm-step-n/, "the numbered how-to steps are back");
  for (const tool of ["Projection Lab", "Valuation Lab", "Compare", "Screener"]) {
    assert.ok(html.includes(">" + tool + "<"), `the ${tool} link is missing from the tool rail`);
  }
  assert.match(html, /class="il-startpaths"/, "the visitor page needs its three ways in");
});

test("the search, the tools and the favourites each get their own column", () => {
  const html = fs.readFileSync(path.join(ROOT, "index.html"), "utf8");
  // Favourites had to sit beside the search as well as beside the chart, so
  // the search moved inside the middle column and the rail starts at the top.
  const grid = html.slice(html.indexOf('class="ihm-grid"'), html.indexOf('</section>\n\n<section class="il-landing"'));
  for (const cls of ["ihm-col-tools", "ihm-col-main", "ihm-col-side"]) {
    assert.ok(grid.includes(cls), `${cls} is not inside the grid`);
  }
  assert.ok(grid.indexOf('id="ihm-search"') > 0, "the search is outside the grid again, so it spans the page");
  assert.match(homeCss, /grid-template-columns: 236px minmax\(0, 1fr\) 320px/, "the three-column grid is gone");
  assert.match(homeCss, /max-width: 620px !important/, "the ticker field is unbounded again");
});

// ── The dashboard has to fill the screen ──────────────────────────────────
test("the member dashboard has a working half, not just a greeting", () => {
  const html = fs.readFileSync(path.join(ROOT, "index.html"), "utf8");
  for (const [id, what] of [
    ["ihm-chart", "the overlaid index chart"],
    ["ihm-indexes", "the index row"],
    ["ihm-sectors", "the sector strip"],
    ["ihm-populars", "the popular companies"],
    ["ihm-favs", "the favourites list"],
    ["ihm-news", "the news list"]
  ]) {
    assert.ok(html.includes(`id="${id}"`), `${what} is missing from the dashboard`);
  }
  assert.match(html, /class="ihm-grid"/, "the two-column layout is gone");
});

// A greeting, a search box, four tiles and a short list ended around 760px on
// a 1440x900 screen, and the footer filled the rest.
test("the footer is pushed to the bottom rather than floating up", () => {
  const css = fs.readFileSync(path.join(ROOT, "public", "clean-pass.css"), "utf8");
  const block = css.slice(css.indexOf("THE MEMBER DASHBOARD, FILLED"));
  assert.match(block, /min-height:\s*100vh\s*!important/, "the page must be at least a viewport tall");
  assert.match(block, />\s*footer\s*\{[^}]*margin-top:\s*auto\s*!important/, "the footer must be pushed down by the layout");
});

// Number(null) is 0 and 0 is finite, so a watchlist row with no target read
// "target 0.00" - a real-looking price of zero.
test("a watchlist row with no target does not invent one", () => {
  const js = fs.readFileSync(path.join(ROOT, "public", "home-member.js"), "utf8");
  assert.match(js, /item\.target_price != null/, "null must be excluded before the finite check");
  assert.match(js, /Number\(item\.target_price\) > 0/, "zero is not a target price");
});

// Every figure on this page is a quote or a count the API returned.
test("the dashboard panels state their own failures", () => {
  const js = fs.readFileSync(path.join(ROOT, "public", "home-member.js"), "utf8");
  for (const msg of ["Index data unavailable.", "Quotes unavailable right now.", "Sector data unavailable."]) {
    assert.ok(js.includes(msg), `missing the failure state: ${msg}`);
  }
  assert.match(js, /preview=1/, "quotes must use the preview path so they cost no analysis quota");
});

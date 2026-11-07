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
// surface.css is loaded after clean-pass.css and is where the dashboard's
// layout now lives, so a contract about the layout has to read both.
const surfaceCss = fs.readFileSync(path.join(ROOT, "public", "surface.css"), "utf8");
const memberJs = "";

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

test("the chart takes its height from the window, not from a constant", () => {
  assert.match(surfaceCss, /\.ilx-plot \{ height: clamp\(\d+px, calc\(100vh - \d+px\), \d+px\)/,
    "the plot is back to a fixed height, so it cannot fit a short screen or use a tall one");
  const m = surfaceCss.match(/\.ilx-plot \{ height: clamp\((\d+)px, calc\(100vh - (\d+)px\), (\d+)px\)/);
  const [, floor, offset, ceiling] = m.map(Number);
  assert.ok(floor >= 180 && floor <= 260, `a ${floor}px floor is not a chart`);
  assert.ok(ceiling >= floor, "the ceiling is below the floor");
  // At a 1080p window - 960px of page once Chrome's chrome is taken off -
  // the plot has to leave room for everything else in the column.
  const at1080 = Math.min(ceiling, Math.max(floor, 960 - offset));
  assert.ok(at1080 >= 210 && at1080 <= 340,
    `at a 960px page viewport the plot resolves to ${at1080}px, which does not fit the column`);
});

// ── The dashboard has to fill the screen ──────────────────────────────────
test("the footer is pushed to the bottom rather than floating up", () => {
  const css = fs.readFileSync(path.join(ROOT, "public", "clean-pass.css"), "utf8");
  const block = css.slice(css.indexOf("THE MEMBER DASHBOARD, FILLED"));
  assert.match(block, /min-height:\s*100vh\s*!important/, "the page must be at least a viewport tall");
  assert.match(block, />\s*footer\s*\{[^}]*margin-top:\s*auto\s*!important/, "the footer must be pushed down by the layout");
});

// Number(null) is 0 and 0 is finite, so a watchlist row with no target read
// "target 0.00" - a real-looking price of zero.

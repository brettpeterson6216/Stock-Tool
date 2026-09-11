// The link preview.
//
// A card posted to X in September 2026 still rendered artwork from July: a
// downscaled screenshot of the whole landing page, every label illegible at
// feed size. Two separate faults produced that.
//
//   1. The artwork. A social card is read at about 500px wide in a timeline,
//      so it has to be composed for that size, not be a page shrunk to fit.
//   2. The URL. og:image lives in meta content="", and lib/asset-stamp.js only
//      ever rewrote href="" and src="". Every scraper caches og:image by URL
//      and https://impliedlens.com/social-card.png is a fixed string, so once
//      a platform had the old picture there was no deploy that could replace
//      it. That is the fault that made the first one permanent.
//
// These tests hold both, plus the two ways a page can silently lose its card.
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const { STAMP, stampHtml } = require("../lib/asset-stamp");

const ROOT = path.join(__dirname, "..");
const P = (...p) => path.join(ROOT, ...p);
const CARD = P("public", "social-card.png");

const PAGES = ["index.html", "public/about.html", "public/blog.html", "public/signup.html",
  "public/login.html", "public/terms.html", "public/privacy.html", "public/data-sources.html",
  "public/research-process.html", "public/compound-calculator.html", "labs/lens-score/index.html"];

test("the card is a 1200x630 PNG", () => {
  assert.ok(fs.existsSync(CARD), "public/social-card.png is missing");
  const b = fs.readFileSync(CARD);
  assert.deepEqual([...b.subarray(0, 8)], [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a], "not a PNG");
  // IHDR width/height are the first two big-endian uint32s of the first chunk.
  assert.equal(b.readUInt32BE(16), 1200, "width must be 1200 — every platform crops from this ratio");
  assert.equal(b.readUInt32BE(20), 630, "height must be 630");
  // X rejects images over 5MB; a card under ~40KB is a sign the art is missing.
  assert.ok(b.length > 40_000, `card is only ${b.length} bytes — is the artwork there?`);
  assert.ok(b.length < 5_000_000, `card is ${(b.length / 1e6).toFixed(1)}MB — X will not fetch it`);
});

test("the chart on the card is real market data, not a drawn squiggle", () => {
  // A stock research tool whose card shows an invented line is advertising the
  // wrong thing. The bars are committed so the claim is checkable.
  const d = JSON.parse(fs.readFileSync(P("brand", "social-card-data.json"), "utf8"));
  assert.ok(d.rows.length >= 60, "too few bars to read as a real chart");
  assert.match(d.source, /Yahoo/i);
  for (const [date, o, h, l, c] of d.rows) {
    assert.match(date, /^\d{4}-\d{2}-\d{2}$/);
    assert.ok(h >= Math.max(o, c) && l <= Math.min(o, c) && l > 0,
      `${date} is not a coherent OHLC bar — ${o}/${h}/${l}/${c}`);
  }
});

test("every page's card URL carries the build stamp, so a new card actually reaches the scrapers", () => {
  for (const page of PAGES) {
    const html = stampHtml(fs.readFileSync(P(page), "utf8"));
    const imgs = [...html.matchAll(/<meta[^>]*(?:property="og:image"|name="twitter:image")[^>]*content="([^"]+)"/g)]
      .map(m => m[1]);
    assert.ok(imgs.length >= 1, `${page} declares no og:image at all — it shares with no picture`);
    for (const url of imgs) {
      assert.ok(url.includes("/social-card.png"), `${page} points og:image at ${url}, not the card`);
      assert.ok(url.startsWith("https://"),
        `${page} uses a relative og:image (${url}); scrapers do not resolve those`);
      assert.ok(url.endsWith(`?v=${STAMP}`),
        `${page} serves the card at a URL that never changes (${url}) — every platform that cached the old artwork keeps it forever`);
    }
  }
});

test("no page offers an SVG as its card", () => {
  // signup.html pointed og:image at /logo.svg. No major scraper renders SVG,
  // so the page that new users are invited through shared with no image.
  for (const page of PAGES) {
    const html = fs.readFileSync(P(page), "utf8");
    for (const m of html.matchAll(/<meta[^>]*(?:og:image|twitter:image)"[^>]*content="([^"]+)"/g)) {
      assert.doesNotMatch(m[1], /\.svg/i, `${page} offers an SVG card: ${m[1]}`);
    }
  }
});

test("the pages that get shared declare a large card and describe it", () => {
  for (const page of PAGES) {
    const html = fs.readFileSync(P(page), "utf8");
    assert.match(html, /<meta name="twitter:card" content="summary_large_image">/,
      `${page} has no summary_large_image, so X renders the thumbnail card`);
    assert.match(html, /(?:og:image:alt|twitter:image:alt)"[^>]*content="[^"]{12,}"/,
      `${page} gives the card no alt text`);
  }
});

test("the brand is written one way", () => {
  // It was both "Implied Lens" and "ImpliedLens" across titles and meta, so
  // X's title chip and the site header disagreed with each other.
  for (const page of PAGES) {
    const html = fs.readFileSync(P(page), "utf8");
    const head = html.slice(0, html.indexOf("</head>") + 1 || 4000);
    assert.doesNotMatch(head, /Implied Lens/,
      `${page} still writes the brand with a space in its <head>`);
  }
});

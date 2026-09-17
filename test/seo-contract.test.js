/* The SEO plan's acceptance checklist, as assertions.
 *
 * Every test here corresponds to a line in the implementation plan, and each
 * one was written against a real defect found on the live site rather than
 * against the plan in the abstract. */
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");
const { PRODUCT_CONFIG, getPublicProductConfig } = require("../lib/product-config");
const { renderProductTemplate, productOffersJsonLd } = require("../lib/product-template");
const { ACQUISITION_TICKERS, buildSitemapXml } = require("../lib/acquisition-tickers");
const facts = require("../lib/stock-landing-facts");

test("the homepage does not tell Google the product is free", () => {
  /* It declared `"price": "0"` while charging $7.99 and $60. A rich result
     reading "Free" for a product that asks for a card is a financial claim
     the page does not support -- the exact thing section 10 forbids. */
  const rendered = renderProductTemplate(fs.readFileSync(path.join(ROOT, "index.html"), "utf8"));
  const block = rendered.match(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/)[1];
  const parsed = JSON.parse(block);
  assert.ok(Array.isArray(parsed.offers), "offers is not a list of the real plans");

  const money = getPublicProductConfig();
  const prices = parsed.offers.map(o => o.price).sort();
  assert.deepEqual(
    prices,
    ["0.00",
     (money.pricing.annual.unitAmountCents / 100).toFixed(2),
     (money.pricing.monthly.unitAmountCents / 100).toFixed(2)].sort(),
    "the declared offers are not the configured prices"
  );
  for (const offer of parsed.offers) {
    assert.equal(offer.priceCurrency, "USD");
    assert.match(offer["@type"], /Offer/);
  }
  // And it follows the catalog rather than a literal.
  const bumped = productOffersJsonLd({
    ...money,
    pricing: { ...money.pricing, monthly: { ...money.pricing.monthly, unitAmountCents: 1234 } },
  });
  assert.match(bumped, /"12\.34"/);
});

test("the sitemap is generated from the ticker universe, not hand-maintained", () => {
  const xml = buildSitemapXml("https://impliedlens.com");
  const locs = [...xml.matchAll(/<loc>([^<]+)<\/loc>/g)].map(m => m[1]);
  for (const ticker of ACQUISITION_TICKERS) {
    assert.ok(
      locs.includes(`https://impliedlens.com/stock/${ticker}`),
      `${ticker} is published but missing from the sitemap`
    );
  }
  assert.equal(new Set(locs).size, locs.length, "the sitemap repeats a URL");
});

test("private and internal surfaces are kept out of the index", () => {
  const robots = fs.readFileSync(path.join(ROOT, "public", "robots.txt"), "utf8");
  for (const blocked of ["/admin-analytics", "/login", "/signup", "/reset-password", "/api/"]) {
    assert.ok(robots.includes(`Disallow: ${blocked}`), `robots.txt does not block ${blocked}`);
  }
  assert.match(robots, /^Sitemap: https:\/\/impliedlens\.com\/sitemap\.xml$/m);

  /* robots.txt asks a crawler not to fetch a URL; it does not keep one out of
     the index if it is linked from anywhere. The dashboard needs the meta tag
     as well, and it had neither. */
  const admin = fs.readFileSync(path.join(ROOT, "public", "admin-analytics.html"), "utf8");
  assert.match(admin, /<meta name="robots" content="noindex[^"]*">/);
});

test("the Search Console tag appears only when a token is configured", () => {
  const home = fs.readFileSync(path.join(ROOT, "index.html"), "utf8");
  assert.ok(home.includes("{{GOOGLE_SITE_VERIFICATION_TAG}}"), "the homepage has no slot for the tag");
  /* An empty content="" tag reads to Google as a failed verification, so an
     unconfigured deployment must emit nothing at all. */
  assert.doesNotMatch(renderProductTemplate(home), /google-site-verification/);
});

// ── the part the plan actually cares about: pages worth indexing ────────────

const FIXTURE = {
  company: { name: "Example Corporation" },
  fundamentals: {
    reportedAsOf: "2026-06-30T00:00:00Z",
    coverage: 0.8,
    freshness: { status: "current" },
    fields: {
      revenueGrowth: { value: 0.081, source: "Derived from SEC filing", asOf: "2026-06-30T00:00:00Z" },
      profitMargin:  { value: 0.247, source: "Derived from SEC filing", asOf: "2026-06-30T00:00:00Z" },
      netDebtEbitda: { value: 1.4,   source: "Derived from SEC filing", asOf: "2026-06-30T00:00:00Z" },
      forwardPE:     { value: 28.4,  source: "Finnhub provider metric", asOf: "2026-09-10T00:00:00Z" },
      nothingHere:   { value: null,  source: "Finnhub provider metric", asOf: null },
    },
    earnings: [
      { period: "Q1", actual: 1.64, estimate: 1.60 },
      { period: "Q2", actual: 1.53, estimate: 1.57 },
    ],
  },
};

test("percentages and multiples are not printed as each other", () => {
  /* Margins and growth are fractions in the bundle; leverage and the forward
     multiple are multiples. Confusing the two is a factor-of-100 error in a
     number a visitor might act on. */
  assert.equal(facts.formatValue(0.247, { unit: "pct" }), "24.7%");
  assert.equal(facts.formatValue(0.081, { unit: "pct", signed: true }), "+8.1%");
  assert.equal(facts.formatValue(-0.023, { unit: "pct", signed: true }), "−2.3%");
  assert.equal(facts.formatValue(1.4, { unit: "x" }), "1.4×");
  assert.equal(facts.formatValue(null, { unit: "pct" }), null);
});

test("a field with no value is omitted, never invented or padded", () => {
  const summary = facts.summarize(FIXTURE, "EXMP");
  const keys = summary.groups.flatMap(g => g.rows).map(r => r.key);
  assert.ok(!keys.includes("nothingHere"), "a null field was rendered anyway");
  assert.ok(keys.includes("revenueGrowth"));
  // Nothing at all to say -> no section, rather than a page of dashes.
  assert.equal(facts.summarize({ fundamentals: { fields: {}, earnings: [] } }, "NIL"), null);
  assert.equal(facts.summarize(null, "NIL"), null);
});

test("every figure carries the source and date it came from", () => {
  const summary = facts.summarize(FIXTURE, "EXMP");
  for (const row of summary.groups.flatMap(g => g.rows)) {
    assert.ok(row.source, `${row.key} lost its source attribution`);
    assert.ok(row.asOf, `${row.key} lost its as-of date`);
  }
});

test("the prose is built from the values, and shrinks when they are missing", () => {
  const full = facts.summarize(FIXTURE, "EXMP").narrative.join(" ");
  assert.match(full, /revenue up 8\.1%/);
  assert.match(full, /net margin of 24\.7%/);
  assert.doesNotMatch(full, /undefined|NaN|null/);

  const sparse = facts.summarize({
    company: { name: "Thin Co" },
    fundamentals: { fields: { revenueGrowth: FIXTURE.fundamentals.fields.revenueGrowth }, earnings: [] },
  }, "THIN");
  assert.equal(sparse.narrative.length, 1, "a one-fact company produced more than one sentence");
  assert.doesNotMatch(sparse.narrative.join(" "), /margin|balance sheet|model/);
});

test("earnings rows report the surprise against the estimate", () => {
  const summary = facts.summarize(FIXTURE, "EXMP");
  assert.equal(summary.earnings.length, 2);
  const [latest] = summary.earnings;            // most recent first
  assert.equal(latest.period, "Q2");
  assert.equal(latest.beat, false);
  assert.match(latest.surprise, /^−2\.5%$/);
});

test("hydration is capped, because the uncapped version took production down", async () => {
  facts.clearLandingFacts();
  /* The warm-up walked all 103 published tickers at one every 20 seconds.
     buildResearchBundle -> loadCompanyFacts caches the whole SEC companyfacts
     JSON per CIK for thirty minutes — tens of megabytes each — and the
     research cache caps at 300 ENTRIES rather than bytes, so the walk held
     about a hundred of them at once and OOMed the server roughly twenty
     minutes after every deploy.

     The walk is gone and on-demand hydration is capped, so a crawler reading
     the whole sitemap in one pass cannot reproduce it. */
  for (let i = 0; i < 40; i += 1) facts.landingFacts(`T${i}`);
  await new Promise(r => setTimeout(r, 50));

  const attempted = [...Array(40).keys()].filter(i => facts.landingFacts(`T${i}`) !== undefined).length;
  assert.equal(attempted, 40, "every request should still answer, cap or no cap");
  assert.ok(facts.hydrationsInLastHour() <= 10,
    `hydration cap exceeded: ${facts.hydrationsInLastHour()} in the last hour`);

  /* And the walk itself must stay gone rather than being quietly restored. */
  assert.equal(facts.startLandingWarmup(["AAA", "BBB"]), null,
    "the warm-up is back; see why it was removed");
  const server = fs.readFileSync(path.join(ROOT, "server.js"), "utf8");
  assert.doesNotMatch(server, /^\s*startLandingWarmup\(/m,
    "server.js calls the warm-up again");
});

test("a primed ticker is served from cache and not re-fetched", () => {
  facts.clearLandingFacts();
  const summary = facts.summarize(FIXTURE, "EXMP");
  facts.primeLandingFacts("EXMP", summary);
  assert.equal(facts.landingFacts("EXMP"), summary);
});

test("the prose names the company, whatever shape the bundle carries it in", () => {
  /* bundle.company is a STRING in stock-research.js, not an object. Reading
     .name off it returned undefined, so every sentence on every live page
     opened "AAPL shows revenue up 16.4%" rather than naming the company —
     which is the one thing the prose is for. Caught by reading the deployed
     page, not by any test that existed. */
  const withString = { ...FIXTURE, company: "Example Corporation" };
  assert.match(facts.summarize(withString, "EXMP").narrative[0], /Example Corporation \(EXMP\)/);

  const withObject = { ...FIXTURE, company: { name: "Example Corporation" } };
  assert.match(facts.summarize(withObject, "EXMP").narrative[0], /Example Corporation \(EXMP\)/);

  // An explicit hint from the route wins over both.
  const hinted = facts.summarize(withString, "EXMP", "Hinted Name");
  assert.match(hinted.narrative[0], /Hinted Name \(EXMP\)/);

  // And with nothing at all it degrades to the symbol rather than "undefined".
  const bare = facts.summarize({ ...FIXTURE, company: undefined }, "EXMP");
  assert.match(bare.narrative[0], /^On the most recently reported figures, EXMP shows/);
  assert.doesNotMatch(bare.narrative.join(" "), /undefined/);
});

// Where the top tabs actually take you.
//
// Three faults, all of them the header promising something the app did not do.
//
//   Pricing pointed at /?pricing=1 — the landing page with a modal over it.
//   There was no page, no URL to share, nothing for a search engine, and
//   site-nav.js could never mark the tab active because markActiveTab derives
//   the active tab from the path and the path had not changed. So clicking
//   Pricing left Dashboard lit.
//
//   Watchlists called openWorkspaceWatchlist, which clicked the watchlist tab
//   SYNCHRONOUSLY after navGoTo. navGoTo renders asynchronously, so the tab did
//   not exist yet, querySelector returned null, and the click never happened —
//   you landed on the Workspace's default tab and had to click Watchlist a
//   second time.
//
//   The rail carried two headings: a static "Research tools" div no code ever
//   touched, above the one renderSidebarGroup rewrites. On the Watchlists tab
//   it read "Research tools" over "Watchlists".
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");
const P = (...p) => path.join(ROOT, ...p);
const read = (...p) => fs.readFileSync(P(...p), "utf8");

const PAGES = ["index.html", ...fs.readdirSync(P("public")).filter(f => f.endsWith(".html")).map(f => "public/" + f),
               "labs/lens-score/index.html"];

test("Pricing is a page, not a modal over the landing page", () => {
  assert.match(read("server.js"), /app\.get\(\["\/pricing"/, "no /pricing route");
  assert.ok(fs.existsSync(P("public", "pricing.html")), "public/pricing.html is missing");
  const nav = read("public", "site-nav.js");
  assert.doesNotMatch(nav, /key === "pricing" && location\.pathname === "\/" && openPricing\(\)/,
    "the Pricing click is still intercepted into a modal, so the tab can never be marked active");
});

test("every page points Pricing at the page", () => {
  for (const page of PAGES) {
    const html = read(page);
    if (!html.includes("nav-pricing-link")) continue;
    assert.match(html, /href="\/pricing" id="nav-pricing-link"/,
      `${page} still sends Pricing to a query string`);
  }
});

test("the pricing page says what it costs and where the money goes", () => {
  /* The price is a {{token}} in the source now — one catalog feeds the page,
     Terms and the Stripe validation, so they cannot drift. Render before
     asserting, or this checks the placeholder instead of the price. */
  const { renderProductTemplate } = require("../lib/product-template");
  const html = renderProductTemplate(read("public", "pricing.html"));
  /* Strip markup before asserting copy: the amount sits inside <strong> and
     the interval outside it, so a regex run against raw HTML looks for
     "$19.00 a month" across a closing tag and never matches. */
  const text = html.replace(/<[^>]+>/g, "");
  assert.match(text, /\$\d+(?:\.\d\d)?\s*(?:\/|a )\s*month/, "no price on the pricing page");
  assert.match(html, /cancel/i, "does not say how to cancel");
  assert.match(html, /data-sources/, "does not point at where the data comes from");
  assert.match(html, /not investment advice/i, "no disclaimer");
  assert.match(html, /<title>Pricing — ImpliedLens<\/title>/);
});


"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { PRODUCT_CONFIG } = require("../lib/product-config");
const {
  annualSavingsPercent,
  renderProductTemplate,
} = require("../lib/product-template");
const { getPublicProductConfig } = require("../lib/product-config");

const ROOT = path.join(__dirname, "..");

test("all public product promises resolve from the canonical plan configuration", () => {
  for (const rel of ["index.html", "public/pricing.html", "public/terms.html", "public/privacy.html", "public/data-sources.html"]) {
    const source = fs.readFileSync(path.join(ROOT, rel), "utf8");
    const rendered = renderProductTemplate(source);
    assert.doesNotMatch(rendered, /\{\{[A-Z0-9_]+\}\}/, `${rel} contains an unresolved product token`);
  }
  const pricing = renderProductTemplate(fs.readFileSync(path.join(ROOT, "public/pricing.html"), "utf8"));
  assert.ok(pricing.includes(`$${(PRODUCT_CONFIG.pricing.monthly.unitAmountCents / 100).toFixed(2)}`));
  assert.ok(pricing.includes(`$${(PRODUCT_CONFIG.pricing.annual.unitAmountCents / 100).toFixed(2)}`));
  /* These three arrived asserting the wording of a DIFFERENT pricing page —
     the one in the workspace this test came from. This repository's pricing
     page is its own copy, so the assertions are matched to what it actually
     says. What matters is unchanged and is what is checked: the trial length
     on the page is the trial length in the catalog, and the page states the
     card requirement truthfully. It previously promised "a trial that does not
     ask for a card" while checkout was configured with
     payment_method_collection: "always" — a page contradicting the checkout it
     leads to, which is the exact failure this catalog exists to prevent. */
  assert.match(pricing, new RegExp(`${PRODUCT_CONFIG.trial.days}-day trial`));
  assert.ok(
    pricing.includes(PRODUCT_CONFIG.trial.requiresCard
      ? "A valid payment method is required"
      : "No payment method is required"),
    "the pricing page does not state the card requirement that checkout enforces"
  );
});

test("provider disclosures are generated from the registry and omit retired claims", () => {
  const page = renderProductTemplate(fs.readFileSync(path.join(ROOT, "public/data-sources.html"), "utf8"));
  for (const provider of ["Yahoo Finance", "Finnhub", "SEC EDGAR", "FINRA OTC Transparency", "Stooq"]) {
    assert.match(page, new RegExp(provider));
  }
  assert.doesNotMatch(page, /\bFRED\b/);
  assert.match(page, /Show the observation timestamp returned by the provider/);
  assert.match(page, /delayed, aggregated OTC activity/i);
});

test("billing and privacy pages state the behavior the repository actually implements", () => {
  const terms = renderProductTemplate(fs.readFileSync(path.join(ROOT, "public/terms.html"), "utf8"));
  const privacy = renderProductTemplate(fs.readFileSync(path.join(ROOT, "public/privacy.html"), "utf8"));
  assert.match(terms, /valid payment method is required/i);
  assert.match(terms, /billing portal/i);
  assert.doesNotMatch(terms, /\$0\.99/);
  assert.match(privacy, /<code>il\.sid<\/code>/);
  assert.match(privacy, /<code>il_gid<\/code>/);
  assert.match(privacy, /does not offer a one-click account-deletion control/i);
});

/* The in-app pricing card used to hold its own copy of the numbers -- the
   markup said 7.99 and the toggle in app-legacy.js said 7.99 and 59.99, none
   of it connected to the catalog. That is how the marketing pages could drift
   to $19/$180 while the app kept charging $7.99 and nothing failed. */
test("the in-app pricing card is rendered from the catalog, not from literals", () => {
  const source = fs.readFileSync(path.join(ROOT, "index.html"), "utf8");
  assert.ok(
    source.includes('id="pricing-pro-amount">{{PLAN_MONTHLY_AMOUNT}}<'),
    "the pricing card carries a hard-coded amount again"
  );
  assert.ok(
    source.includes('<meta name="il-product" content="{{PUBLIC_PRODUCT_CONFIG_ATTR}}">'),
    "index.html no longer embeds the canonical product configuration"
  );
  /* It must stay a meta attribute. The homepage CSP has no 'unsafe-inline' in
     script-src, so moving this into an inline <script> would leave the page
     running on app-legacy.js's fallback literals with nothing to say so. */
  assert.doesNotMatch(source, /<script[^>]*>\s*window\.__ilProduct/);

  const rendered = renderProductTemplate(source);
  const monthly = (PRODUCT_CONFIG.pricing.monthly.unitAmountCents / 100).toFixed(2);
  assert.ok(rendered.includes(`id="pricing-pro-amount">${monthly}<`));

  // The embed must survive HTML-attribute decoding as valid JSON.
  const embed = rendered.match(/<meta name="il-product" content="([^"]*)">/);
  assert.ok(embed, "the product embed did not render");
  assert.doesNotMatch(embed[1], /["<>]/, "the embed would break out of its attribute");
  const decoded = embed[1]
    .replace(/&quot;/g, '"').replace(/&#39;/g, "'")
    .replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&");
  const parsed = JSON.parse(decoded);
  assert.equal(parsed.pricing.monthly.unitAmountCents, PRODUCT_CONFIG.pricing.monthly.unitAmountCents);
  assert.equal(parsed.pricing.annual.unitAmountCents, PRODUCT_CONFIG.pricing.annual.unitAmountCents);
  assert.equal(parsed.trial.days, PRODUCT_CONFIG.trial.days);
  // The embed is public: it must not be a channel for anything that is not.
  assert.doesNotMatch(decoded, /price_|sk_|secret|stripe/i);
});

test("no shipped page states a plan price that did not come from the catalog", () => {
  const monthly = (PRODUCT_CONFIG.pricing.monthly.unitAmountCents / 100).toFixed(2);
  const annual = (PRODUCT_CONFIG.pricing.annual.unitAmountCents / 100).toFixed(2);
  const allowed = new Set([monthly, annual]);
  const pages = ["index.html", "public/pricing.html", "public/terms.html", "public/privacy.html"];
  for (const rel of pages) {
    const rendered = renderProductTemplate(fs.readFileSync(path.join(ROOT, rel), "utf8"));
    const priced = rendered.match(/\$\s?(\d+(?:\.\d{2})?)\s*(?:a |per |\/)\s*(?:month|year|mo\b|yr\b)/gi) || [];
    for (const claim of priced) {
      const amount = claim.match(/(\d+(?:\.\d{2})?)/)[1];
      assert.ok(
        allowed.has(amount) || allowed.has(Number(amount).toFixed(2)),
        `${rel} advertises ${claim.trim()}, which is not a configured plan price`
      );
    }
  }
});

/* The upgrade modal and the billing toggle quoted the price and the annual
   saving in plain markup. They happened to be right; nothing made them stay
   right. A price that appears in five places is a price that will disagree
   with itself eventually -- which is the whole reason this test file exists. */
test("the homepage quotes no plan number it did not get from the catalog", () => {
  const source = fs.readFileSync(path.join(ROOT, "index.html"), "utf8");
  for (const literal of ["$7.99", "$59.99", "$5.00", "SAVE 37%", "save 37%", "7-day"]) {
    assert.ok(
      !source.includes(literal),
      `index.html hard-codes "${literal}" instead of using a product token`
    );
  }

  const rendered = renderProductTemplate(source);
  const money = getPublicProductConfig();
  const savings = annualSavingsPercent(money);
  assert.ok(rendered.includes(`save ${savings}%`), "the billing toggle lost its saving figure");
  assert.ok(rendered.includes(`SAVE ${savings}%`), "the upgrade modal lost its saving figure");
  assert.ok(rendered.includes(`${PRODUCT_CONFIG.trial.days}-day free trial`));
  assert.ok(rendered.includes(`${money.pricing.annual.formatted} billed yearly`));
  assert.ok(rendered.includes(`${money.pricing.monthly.formatted}<span class="plan-opt-per">/mo`));
});

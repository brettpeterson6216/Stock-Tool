"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { PRODUCT_CONFIG } = require("../lib/product-config");
const { renderProductTemplate } = require("../lib/product-template");

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

"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const {
  ENV_KEYS,
  PRODUCT_CONFIG,
  PRO_SECTIONS,
  clearStripeCatalogVerifierCache,
  createProductConfig,
  formatUsdCents,
  getPublicProductConfig,
  serializePublicProductConfig,
  verifyStripeCatalog,
} = require("../lib/product-config");

test("canonical product configuration matches the repository-backed offer", () => {
  assert.equal(PRODUCT_CONFIG.currency, "usd");
  assert.deepEqual(PRODUCT_CONFIG.pricing, {
    /* Amounts come from the config, not from literals. This test asserts the
       SHAPE of the offer - one monthly price and one annual price, in whole
       cents, on the right interval - which is what must never change by
       accident. The amount itself is a business decision and lives in one
       place; hard-coding it here means every price change breaks the suite
       and teaches whoever is changing it to edit tests until they pass. */
    monthly: { unitAmountCents: PRODUCT_CONFIG.pricing.monthly.unitAmountCents, interval: "month", intervalCount: 1 },
    annual: { unitAmountCents: PRODUCT_CONFIG.pricing.annual.unitAmountCents, interval: "year", intervalCount: 1 },
  });
  /* Unlike the price, the trial length is pinned here on purpose: it is sent
     to Stripe as trial_period_days on every checkout, so changing it changes
     what customers are actually granted, and that should not pass silently. */
  assert.deepEqual(PRODUCT_CONFIG.trial, { days: 30, requiresCard: true });
  assert.deepEqual(PRODUCT_CONFIG.analysisLimits, { guestDaily: 2, registeredFreeDaily: 5 });
  assert.equal(PRODUCT_CONFIG.checkout.allowPromotionCodes, true);
  assert.deepEqual(PRODUCT_CONFIG.proSections, [...PRO_SECTIONS]);
  assert.deepEqual(PRODUCT_CONFIG.proSections, [
    "financials", "advmetrics", "projection", "dcf", "screener", "earnings",
    "secfilings", "institutional", "analyst", "darkpool", "calls",
  ]);
  assert.equal(Object.isFrozen(PRODUCT_CONFIG.pricing.monthly), true);
  assert.equal(Object.isFrozen(PRODUCT_CONFIG.proSections), true);
});

test("explicit plan environment overrides are parsed strictly", () => {
  const config = createProductConfig({
    [ENV_KEYS.monthlyPriceCents]: "899",
    [ENV_KEYS.annualPriceCents]: "6999",
    [ENV_KEYS.trialDays]: "14",
    [ENV_KEYS.trialRequiresCard]: "false",
    [ENV_KEYS.guestDailyLimit]: "3",
    [ENV_KEYS.registeredFreeDailyLimit]: "8",
    [ENV_KEYS.allowPromotionCodes]: "false",
  });

  assert.equal(config.pricing.monthly.unitAmountCents, 899);
  assert.equal(config.pricing.annual.unitAmountCents, 6999);
  assert.deepEqual(config.trial, { days: 14, requiresCard: false });
  assert.deepEqual(config.analysisLimits, { guestDaily: 3, registeredFreeDaily: 8 });
  assert.equal(config.checkout.allowPromotionCodes, false);

  assert.throws(
    () => createProductConfig({ [ENV_KEYS.monthlyPriceCents]: "7.99" }),
    /must be a whole number/
  );
  assert.throws(
    () => createProductConfig({ [ENV_KEYS.trialDays]: "" }),
    /must be a whole number/
  );
  assert.throws(
    () => createProductConfig({ [ENV_KEYS.trialRequiresCard]: "yes" }),
    /must be exactly/
  );
});

test("public helpers format prices and expose only allow-listed plan data", () => {
  assert.equal(formatUsdCents(799), "$7.99");
  assert.equal(formatUsdCents(5999), "$59.99");
  assert.throws(() => formatUsdCents(7.99), /safe integer/);

  const publicConfig = getPublicProductConfig();
  assert.equal(publicConfig.currency, "USD");
  assert.equal(publicConfig.pricing.monthly.formatted, formatUsdCents(PRODUCT_CONFIG.pricing.monthly.unitAmountCents));
  assert.equal(publicConfig.pricing.annual.formatted, formatUsdCents(PRODUCT_CONFIG.pricing.annual.unitAmountCents));
  assert.equal(Object.hasOwn(publicConfig, "stripePriceIds"), false);
  assert.equal(Object.isFrozen(publicConfig), true);

  const serialized = serializePublicProductConfig();
  assert.deepEqual(JSON.parse(serialized), publicConfig);
  assert.doesNotMatch(serialized, /STRIPE|price_|secret/i);
});

test("Stripe catalog verification validates both recurring prices and caches success", async () => {
  clearStripeCatalogVerifierCache();
  const prices = {
    price_monthly: {
      currency: "usd", unit_amount: PRODUCT_CONFIG.pricing.monthly.unitAmountCents, active: true,
      recurring: { interval: "month", interval_count: 1 },
    },
    price_annual: {
      currency: "usd", unit_amount: PRODUCT_CONFIG.pricing.annual.unitAmountCents, active: true,
      recurring: { interval: "year", interval_count: 1 },
    },
  };
  let retrievals = 0;
  const stripe = {
    prices: {
      retrieve: async (id) => {
        retrievals++;
        return prices[id];
      },
    },
  };

  const args = {
    stripe,
    priceIds: { monthly: "price_monthly", annual: "price_annual" },
  };
  const first = await verifyStripeCatalog(args);
  const second = await verifyStripeCatalog(args);

  assert.equal(first.ready, true);
  assert.equal(first.prices.monthly.ready, true);
  assert.equal(first.prices.annual.ready, true);
  assert.strictEqual(second, first);
  assert.equal(retrievals, 2);
  assert.doesNotMatch(JSON.stringify(first), /price_monthly|price_annual/);
});

test("Stripe catalog failures are complete and do not expose IDs or provider errors", async () => {
  clearStripeCatalogVerifierCache();
  const stripe = {
    prices: {
      retrieve: async (id) => {
        if (id === "price_monthly_private") {
          return {
            currency: "eur", unit_amount: 700, active: false,
            recurring: { interval: "year", interval_count: 2 },
          };
        }
        throw new Error(`No such price: ${id}`);
      },
    },
  };
  const result = await verifyStripeCatalog({
    stripe,
    priceIds: { monthly: "price_monthly_private", annual: "price_annual_private" },
  });

  assert.equal(result.ready, false);
  assert.deepEqual(result.prices.monthly.checks, {
    configured: true,
    retrievable: true,
    currency: false,
    unitAmount: false,
    active: false,
    recurringInterval: false,
  });
  assert.equal(result.prices.annual.checks.retrievable, false);
  assert.doesNotMatch(JSON.stringify(result), /private|No such price|price_monthly|price_annual/);
});

/* The advertised price and the charged price were once two different numbers:
   the pricing page said $19/month while Stripe billed $7.99. These tests exist
   so that can only happen again if someone edits the one line that means it. */
test("the configured price is the price Stripe is expected to charge", () => {
  assert.equal(PRODUCT_CONFIG.pricing.monthly.unitAmountCents, 799);
  /* 6000 is what the live Stripe account actually holds -- the /readyz catalog
     check read it back. It was believed to be 5999 by everyone including the
     account owner, and the page said $59.99 while the card was billed $60.00. */
  assert.equal(PRODUCT_CONFIG.pricing.annual.unitAmountCents, 6000);
  const money = getPublicProductConfig();
  assert.equal(money.pricing.monthly.formatted, "$7.99");
  assert.equal(money.pricing.annual.formatted, "$60.00");
});

test("a catalog mismatch reports both amounts, not just a false", async () => {
  clearStripeCatalogVerifierCache();
  const stripe = {
    prices: {
      retrieve: async (id) => ({
        id,
        currency: "usd",
        active: true,
        unit_amount: id.includes("month") ? 1900 : 6000,
        recurring: {
          interval: id.includes("month") ? "month" : "year",
          interval_count: 1,
        },
      }),
    },
  };
  const result = await verifyStripeCatalog({
    stripe,
    priceIds: { monthly: "price_month_x", annual: "price_year_x" },
    cacheTtlMs: 0,
  });

  assert.equal(result.ready, false);
  // The whole point: an operator can read what Stripe holds without opening it.
  assert.equal(result.prices.monthly.expected.formatted, "$7.99");
  assert.equal(result.prices.monthly.observed.formatted, "$19.00");
  assert.equal(result.prices.monthly.observed.interval, "month");
  // The half that agrees still says so.
  assert.equal(result.prices.annual.ready, true);
  assert.equal(result.prices.annual.observed.formatted, "$60.00");
  // Reporting the amount must not start leaking the price ID.
  assert.doesNotMatch(JSON.stringify(result), /price_month_x|price_year_x/);
});

test("an unreachable price still reports what was expected of it", async () => {
  clearStripeCatalogVerifierCache();
  const result = await verifyStripeCatalog({
    stripe: { prices: { retrieve: async () => { throw new Error("network"); } } },
    priceIds: { monthly: "price_gone_a", annual: "price_gone_b" },
    cacheTtlMs: 0,
  });
  assert.equal(result.prices.monthly.observed, null);
  assert.equal(result.prices.monthly.expected.formatted, "$7.99");
  assert.doesNotMatch(JSON.stringify(result), /network|price_gone/);
});

/* app-legacy.js carries fallback price literals for the case where the
   il-product meta embed is missing or unparseable. They are a second copy of
   the catalog, and a second copy is exactly how $59.99 outlived the move to
   $60.00: nothing failed when they disagreed, the page just quoted a number
   Stripe was not charging. This test is the thing that fails instead. */
test("app-legacy's fallback prices still equal the catalog", () => {
  const fs = require("node:fs");
  const path = require("node:path");
  const source = fs.readFileSync(
    path.join(__dirname, "..", "public", "app-legacy.js"), "utf8"
  );

  const read = (label) => {
    const m = source.match(
      new RegExp("var\\s+" + label + "\\s*=\\s*\\(p && p\\." + label +
                 "[^)]*\\)\\s*\\|\\|\\s*(\\d+)")
    );
    assert.ok(m, `could not find the ${label} fallback in app-legacy.js`);
    return Number(m[1]);
  };

  assert.equal(read("monthly"), PRODUCT_CONFIG.pricing.monthly.unitAmountCents);
  assert.equal(read("annual"), PRODUCT_CONFIG.pricing.annual.unitAmountCents);

  const trial = source.match(/return \(cfg && cfg\.trial && cfg\.trial\.days\) \|\| (\d+)/);
  assert.ok(trial, "could not find the trial-days fallback in app-legacy.js");
  assert.equal(Number(trial[1]), PRODUCT_CONFIG.trial.days);
});

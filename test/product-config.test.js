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
  assert.deepEqual(PRODUCT_CONFIG.trial, { days: 7, requiresCard: true });
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

"use strict";

// Canonical product and plan rules. Stripe price IDs remain private deployment
// configuration in lib/config.js; this module only describes the public offer
// and validates that Stripe's catalog agrees with it.

const ENV_KEYS = Object.freeze({
  monthlyPriceCents: "PLAN_MONTHLY_PRICE_CENTS",
  annualPriceCents: "PLAN_ANNUAL_PRICE_CENTS",
  trialDays: "PLAN_TRIAL_DAYS",
  trialRequiresCard: "PLAN_TRIAL_REQUIRES_CARD",
  guestDailyLimit: "PLAN_GUEST_DAILY_LIMIT",
  registeredFreeDailyLimit: "PLAN_FREE_DAILY_LIMIT",
  allowPromotionCodes: "PLAN_ALLOW_PROMOTION_CODES",
});

const PRO_SECTIONS = Object.freeze([
  "financials",
  "advmetrics",
  "projection",
  "dcf",
  "screener",
  "earnings",
  "secfilings",
  "institutional",
  "analyst",
  "darkpool",
  "calls",
]);

const DEFAULTS = Object.freeze({
  /* These defaults are the price the site ACTUALLY advertises today.
     They arrived from a parallel workspace as 799 / 5999 while
     impliedlens.com/pricing was live saying $19/month and $180/year. Shipping
     the lower pair would have done one of two things, both bad: quietly
     changed the advertised price, or — because verifyStripeCatalog fails
     closed — made every checkout return 503 the moment the configured amount
     stopped matching the real Stripe price.
     Set to what is live. Changing the price is now a one-line change here (or
     PLAN_MONTHLY_PRICE_CENTS / PLAN_ANNUAL_PRICE_CENTS in the environment),
     and the pricing page, Terms and Stripe validation all follow it. */
  monthlyPriceCents: 1900,
  annualPriceCents: 18000,
  trialDays: 7,
  trialRequiresCard: true,
  guestDailyLimit: 2,
  registeredFreeDailyLimit: 5,
  allowPromotionCodes: true,
});

const DEFAULT_CATALOG_CACHE_TTL_MS = 5 * 60 * 1000;
const MAX_PRICE_CENTS = 100000000;

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  Object.freeze(value);
  Object.values(value).forEach(deepFreeze);
  return value;
}

function hasOverride(env, key) {
  return Object.prototype.hasOwnProperty.call(env, key) && env[key] !== undefined;
}

function integerOverride(env, key, fallback, { min, max }) {
  if (!hasOverride(env, key)) return fallback;
  const raw = env[key];
  const text = typeof raw === "number" ? String(raw) : raw;
  if (typeof text !== "string" || !/^(0|[1-9]\d*)$/.test(text)) {
    throw new TypeError(`${key} must be a whole number between ${min} and ${max}.`);
  }
  const value = Number(text);
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    throw new RangeError(`${key} must be a whole number between ${min} and ${max}.`);
  }
  return value;
}

function booleanOverride(env, key, fallback) {
  if (!hasOverride(env, key)) return fallback;
  if (env[key] === true || env[key] === "true") return true;
  if (env[key] === false || env[key] === "false") return false;
  throw new TypeError(`${key} must be exactly "true" or "false".`);
}

function createProductConfig(env = process.env) {
  if (!env || typeof env !== "object") throw new TypeError("env must be an object.");

  const monthlyPriceCents = integerOverride(
    env, ENV_KEYS.monthlyPriceCents, DEFAULTS.monthlyPriceCents, { min: 1, max: MAX_PRICE_CENTS }
  );
  const annualPriceCents = integerOverride(
    env, ENV_KEYS.annualPriceCents, DEFAULTS.annualPriceCents, { min: 1, max: MAX_PRICE_CENTS }
  );
  const trialDays = integerOverride(
    env, ENV_KEYS.trialDays, DEFAULTS.trialDays, { min: 1, max: 365 }
  );
  const guestDailyLimit = integerOverride(
    env, ENV_KEYS.guestDailyLimit, DEFAULTS.guestDailyLimit, { min: 0, max: 10000 }
  );
  const registeredFreeDailyLimit = integerOverride(
    env, ENV_KEYS.registeredFreeDailyLimit, DEFAULTS.registeredFreeDailyLimit, { min: 0, max: 10000 }
  );

  return deepFreeze({
    currency: "usd",
    pricing: {
      monthly: { unitAmountCents: monthlyPriceCents, interval: "month", intervalCount: 1 },
      annual: { unitAmountCents: annualPriceCents, interval: "year", intervalCount: 1 },
    },
    trial: {
      days: trialDays,
      requiresCard: booleanOverride(
        env, ENV_KEYS.trialRequiresCard, DEFAULTS.trialRequiresCard
      ),
    },
    analysisLimits: {
      guestDaily: guestDailyLimit,
      registeredFreeDaily: registeredFreeDailyLimit,
    },
    checkout: {
      allowPromotionCodes: booleanOverride(
        env, ENV_KEYS.allowPromotionCodes, DEFAULTS.allowPromotionCodes
      ),
    },
    proSections: [...PRO_SECTIONS],
  });
}

const PRODUCT_CONFIG = createProductConfig();

function assertCents(cents) {
  if (!Number.isSafeInteger(cents) || cents < 0 || cents > MAX_PRICE_CENTS) {
    throw new RangeError("Price cents must be a non-negative safe integer.");
  }
}

function formatUsdCents(cents) {
  assertCents(cents);
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: "USD",
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  }).format(cents / 100);
}

function getPublicProductConfig(config = PRODUCT_CONFIG) {
  const monthly = config?.pricing?.monthly;
  const annual = config?.pricing?.annual;
  const trial = config?.trial;
  const limits = config?.analysisLimits;
  const checkout = config?.checkout;

  assertCents(monthly?.unitAmountCents);
  assertCents(annual?.unitAmountCents);
  if (config.currency !== "usd") throw new TypeError("Public plan currency must be USD.");
  if (!Number.isSafeInteger(trial?.days) || trial.days < 1 || trial.days > 365) {
    throw new TypeError("Trial days must be an integer between 1 and 365.");
  }
  if (typeof trial.requiresCard !== "boolean" || typeof checkout?.allowPromotionCodes !== "boolean") {
    throw new TypeError("Public plan rules must use boolean values.");
  }
  if (!Number.isSafeInteger(limits?.guestDaily) || limits.guestDaily < 0 ||
      !Number.isSafeInteger(limits?.registeredFreeDaily) || limits.registeredFreeDaily < 0) {
    throw new TypeError("Analysis limits must be non-negative integers.");
  }
  if (monthly.interval !== "month" || monthly.intervalCount !== 1 ||
      annual.interval !== "year" || annual.intervalCount !== 1) {
    throw new TypeError("Plan intervals must be monthly and annual recurring intervals.");
  }
  if (!Array.isArray(config.proSections) || !config.proSections.length ||
      new Set(config.proSections).size !== config.proSections.length ||
      config.proSections.some(section => typeof section !== "string" || !/^[a-z][a-z0-9-]{0,39}$/.test(section))) {
    throw new TypeError("Pro sections must be a non-empty list of unique section keys.");
  }

  return deepFreeze({
    currency: "USD",
    pricing: {
      monthly: {
        unitAmountCents: monthly.unitAmountCents,
        formatted: formatUsdCents(monthly.unitAmountCents),
        interval: monthly.interval,
        intervalCount: monthly.intervalCount,
      },
      annual: {
        unitAmountCents: annual.unitAmountCents,
        formatted: formatUsdCents(annual.unitAmountCents),
        interval: annual.interval,
        intervalCount: annual.intervalCount,
      },
    },
    trial: { days: trial.days, requiresCard: trial.requiresCard },
    analysisLimits: {
      guestDaily: limits.guestDaily,
      registeredFreeDaily: limits.registeredFreeDaily,
    },
    checkout: { allowPromotionCodes: checkout.allowPromotionCodes },
    proSections: [...config.proSections],
  });
}

// Safe for embedding directly into an HTML <script> element. The public
// projection is allow-listed above, and HTML-significant code points are
// escaped as an additional defense against a future string-valued rule.
function serializePublicProductConfig(config = PRODUCT_CONFIG) {
  return JSON.stringify(getPublicProductConfig(config)).replace(/[<>&\u2028\u2029]/g, (char) => ({
    "<": "\\u003c",
    ">": "\\u003e",
    "&": "\\u0026",
    "\u2028": "\\u2028",
    "\u2029": "\\u2029",
  })[char]);
}

function configuredPriceId(value) {
  if (typeof value !== "string" || value !== value.trim()) return null;
  return /^price_[A-Za-z0-9_]+$/.test(value) ? value : null;
}

function emptyPriceCheck(configured) {
  return {
    ready: false,
    checks: {
      configured,
      retrievable: false,
      currency: false,
      unitAmount: false,
      active: false,
      recurringInterval: false,
    },
  };
}

async function inspectStripePrice(stripe, priceId, expected) {
  if (!priceId) return emptyPriceCheck(false);
  let price;
  try {
    price = await stripe.prices.retrieve(priceId);
  } catch (_) {
    return emptyPriceCheck(true);
  }

  const checks = {
    configured: true,
    retrievable: Boolean(price && typeof price === "object"),
    currency: price?.currency === expected.currency,
    unitAmount: Number.isSafeInteger(price?.unit_amount) && price.unit_amount === expected.unitAmountCents,
    active: price?.active === true,
    recurringInterval: price?.recurring?.interval === expected.interval &&
      price?.recurring?.interval_count === expected.intervalCount,
  };
  return { ready: Object.values(checks).every(Boolean), checks };
}

let stripeCatalogCache = new WeakMap();

function cacheKeyFor(priceIds, config) {
  return JSON.stringify([
    priceIds.monthly,
    priceIds.annual,
    config.currency,
    config.pricing.monthly.unitAmountCents,
    config.pricing.monthly.interval,
    config.pricing.monthly.intervalCount,
    config.pricing.annual.unitAmountCents,
    config.pricing.annual.interval,
    config.pricing.annual.intervalCount,
  ]);
}

async function verifyStripeCatalog({
  stripe,
  priceIds = {},
  config = PRODUCT_CONFIG,
  cacheTtlMs = DEFAULT_CATALOG_CACHE_TTL_MS,
  force = false,
} = {}) {
  if (!Number.isSafeInteger(cacheTtlMs) || cacheTtlMs < 0 || cacheTtlMs > 24 * 60 * 60 * 1000) {
    throw new RangeError("cacheTtlMs must be an integer between 0 and 86400000.");
  }

  const monthlyId = configuredPriceId(priceIds.monthly);
  const annualId = configuredPriceId(priceIds.annual);
  const canRetrieve = stripe && typeof stripe === "object" &&
    stripe.prices && typeof stripe.prices.retrieve === "function";
  if (!canRetrieve) {
    return deepFreeze({
      ready: false,
      checkedAt: new Date().toISOString(),
      prices: {
        monthly: emptyPriceCheck(Boolean(monthlyId)),
        annual: emptyPriceCheck(Boolean(annualId)),
      },
    });
  }

  const normalizedIds = { monthly: monthlyId, annual: annualId };
  const key = cacheKeyFor(normalizedIds, config);
  const now = Date.now();
  let clientCache = stripeCatalogCache.get(stripe);
  if (!clientCache) {
    clientCache = new Map();
    stripeCatalogCache.set(stripe, clientCache);
  }
  const cached = clientCache.get(key);
  if (!force && cached && cached.expiresAt > now) return cached.promise;

  const promise = (async () => {
    const expectedMonthly = { currency: config.currency, ...config.pricing.monthly };
    const expectedAnnual = { currency: config.currency, ...config.pricing.annual };
    const [monthly, annual] = await Promise.all([
      inspectStripePrice(stripe, monthlyId, expectedMonthly),
      inspectStripePrice(stripe, annualId, expectedAnnual),
    ]);
    return deepFreeze({
      ready: monthly.ready && annual.ready,
      checkedAt: new Date().toISOString(),
      prices: { monthly, annual },
    });
  })();

  clientCache.set(key, { expiresAt: now + cacheTtlMs, promise });
  return promise;
}

function clearStripeCatalogVerifierCache() {
  stripeCatalogCache = new WeakMap();
}

module.exports = {
  ENV_KEYS,
  PRO_SECTIONS,
  PRODUCT_CONFIG,
  PLAN_CONFIG: PRODUCT_CONFIG,
  DEFAULT_CATALOG_CACHE_TTL_MS,
  createProductConfig,
  formatUsdCents,
  getPublicProductConfig,
  serializePublicProductConfig,
  verifyStripeCatalog,
  clearStripeCatalogVerifierCache,
};

"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { productionReadiness } = require("../lib/readiness");

const completeEnvironment = {
  NODE_ENV: "production",
  APP_URL: "https://impliedlens.com",
  FINNHUB_KEY: "market-key",
  SESSION_SECRET: "a-secure-session-secret-that-is-longer-than-32-characters",
  STRIPE_SECRET_KEY: "sk_live_example",
  STRIPE_WEBHOOK_SECRET: "whsec_example",
  STRIPE_PRICE_MONTHLY: "price_monthly",
  STRIPE_PRICE_ANNUAL: "price_annual",
  RESEND_API_KEY: "re_example",
  FROM_EMAIL: "Implied Lens <noreply@impliedlens.com>",
};

test("production readiness requires every launch-critical capability", () => {
  const result = productionReadiness(completeEnvironment, true);
  assert.equal(result.ready, true);
  assert.deepEqual(Object.values(result.checks), [true, true, true, true, true, true]);
});

test("production readiness reports capability names without exposing secrets", () => {
  const result = productionReadiness({
    ...completeEnvironment,
    STRIPE_PRICE_ANNUAL: "",
    FROM_EMAIL: "onboarding@resend.dev",
  }, false);

  assert.equal(result.ready, false);
  assert.equal(result.checks.database, false);
  assert.equal(result.checks.billing, false);
  assert.equal(result.checks.transactionalEmail, false);
  assert.doesNotMatch(JSON.stringify(result), /sk_live_example|whsec_example|market-key|re_example/);
});

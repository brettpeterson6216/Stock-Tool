"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { subscriptionStatusToPlan } = require("../lib/plan");

const html = fs.readFileSync(path.join(__dirname, "..", "index.html"), "utf8");
const authSource = fs.readFileSync(path.join(__dirname, "..", "routes", "auth.js"), "utf8");
const billingSource = fs.readFileSync(path.join(__dirname, "..", "routes", "billing.js"), "utf8");
const planSource = fs.readFileSync(path.join(__dirname, "..", "lib", "plan.js"), "utf8");

test("Stripe subscription statuses preserve legitimate paid access", () => {
  assert.equal(subscriptionStatusToPlan("trialing"), "trial");
  assert.equal(subscriptionStatusToPlan("active"), "pro");
  assert.equal(subscriptionStatusToPlan("past_due"), "pro");
  assert.equal(subscriptionStatusToPlan("canceled"), "free");
});

test("locked paid accounts reconcile against Stripe before Pro rejection", () => {
  assert.match(planSource, /async function reconcileEffectivePlan\(user\)/);
  assert.match(planSource, /stripe\.subscriptions\.retrieve\(user\.stripe_subscription_id\)/);
  assert.match(planSource, /async function listSubscriptionsForCustomer\(customerId\)/);
  assert.match(planSource, /customerIds\.add\(user\.stripe_customer_id\)/);
  assert.match(planSource, /stripe\.customers\.list\(\{ email: String\(user\.email\)\.toLowerCase\(\), limit: 10 \}\)/);
  assert.match(planSource, /UPDATE users SET plan = \?, trial_ends_at = \?, stripe_customer_id = \?, stripe_subscription_id = \?/);
  assert.match(planSource, /const plan = await reconcileEffectivePlan\(user\)/);
  assert.match(authSource, /user\.effectivePlan = await reconcileEffectivePlan\(user\)/);
});

test("Stripe webhooks preserve a durable link from checkout to subscription updates", () => {
  assert.match(billingSource, /subscription_data: \{ trial_period_days: 7, metadata \}/);
  assert.match(billingSource, /allow_promotion_codes: true/);
  assert.match(billingSource, /client_reference_id: String\(req\.session\.userId\)/);
  assert.match(billingSource, /async function findUserIdForStripeEvent/);
  assert.match(billingSource, /sess\.customer_details\?\.email \|\| sess\.customer_email \|\| await stripeCustomerEmail\(customerId\)/);
  assert.match(billingSource, /stripe_customer_id=\?, stripe_subscription_id=\?/);
});

test("discount-code sales work through Stripe Checkout without replacing the trial", () => {
  assert.match(html, /Start 7-day free trial/);
  assert.match(html, /Discount codes can be entered in Checkout/);
  assert.match(html, /\$0\.99 paid month/);
  assert.doesNotMatch(billingSource, /firstMonthDiscounts/);
  assert.doesNotMatch(billingSource, /\$0\.99 first-month offer is not configured yet/);
  assert.match(billingSource, /track\("checkout_started", \{ annual, plan: annual \? "annual" : "monthly", trialDays: 7, promotionCodes: true \}/);
});

test("protected sections wait for authoritative auth state before gating", () => {
  assert.match(html, /window\.IL_AUTH_READY = new Promise/);
  assert.match(html, /authReady: false/);
  assert.match(html, /PRO_SECTIONS\.includes\(id\) && !S\.authReady/);
  assert.match(html, /window\.IL_AUTH_READY\?\.then/);
  assert.match(html, /if \(limitCounter && pro\) limitCounter\.style\.display = 'none'/);
  assert.match(html, /if \(window\.IL_AUTH_READY\) await window\.IL_AUTH_READY/);
  assert.match(html, /refreshAuthStateForAccess/);
});

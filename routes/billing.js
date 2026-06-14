// ============================================================
//  Billing routes — Stripe checkout, webhook, portal
// ============================================================
const express = require("express");
const Stripe  = require("stripe");

const { db }                                                    = require("../lib/db");
const { validateCsrf } = require("../lib/csrf");
const { track }        = require("../lib/analytics");
const { STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET,
        STRIPE_PRICE_MONTHLY, STRIPE_PRICE_ANNUAL, APP_URL }   = require("../lib/config");

const stripe = STRIPE_SECRET_KEY ? Stripe(STRIPE_SECRET_KEY) : null;
const router = express.Router();

// ============================================================
//  POST /api/stripe/create-checkout
// ============================================================
router.post("/stripe/create-checkout", validateCsrf, async (req, res) => {
  if (!req.session.userId)    return res.status(401).json({ error: "Login required." });
  const annual = req.body?.annual === true;

  try {
    const userRow  = await db.execute({
      sql: "SELECT id, email, plan, trial_ends_at, stripe_customer_id, stripe_subscription_id, email_verified FROM users WHERE id = ?",
      args: [req.session.userId],
    });
    const user     = userRow.rows[0];
    if (!user)     return res.status(404).json({ error: "User not found." });
    if (!user.email_verified) {
      return res.status(403).json({
        error: "Please verify your email before starting a trial. Check your inbox or resend from account settings.",
        requiresEmailVerification: true,
      });
    }

    if (!stripe) return res.status(503).json({ error: "Payments not configured yet." });

    if (user.stripe_subscription_id) {
      try {
        const current = await stripe.subscriptions.retrieve(user.stripe_subscription_id);
        if (["active", "trialing", "past_due"].includes(current.status)) {
          return res.status(409).json({
            error: "You already have a subscription. Manage it from your billing portal.",
            hasSubscription: true,
          });
        }
      } catch (e) {
        if (e?.code !== "resource_missing") throw e;
      }
    }

    const priceId = annual ? STRIPE_PRICE_ANNUAL : STRIPE_PRICE_MONTHLY;
    if (!priceId) return res.status(503).json({ error: "Price not configured." });

    const params = {
      mode: "subscription",
      payment_method_types: ["card"],
      line_items: [{ price: priceId, quantity: 1 }],
      subscription_data: { trial_period_days: 7 },
      success_url: `${APP_URL}/?upgraded=1`,
      cancel_url:  `${APP_URL}/?checkout=cancelled`,
      metadata: { userId: String(req.session.userId) },
    };
    if (user.stripe_customer_id) {
      params.customer = user.stripe_customer_id;
    } else {
      params.customer_email = user.email;
    }

    const checkoutSession = await stripe.checkout.sessions.create(params, {
      idempotencyKey: `checkout:${req.session.userId}:${annual ? "annual" : "monthly"}:${Math.floor(Date.now() / (5 * 60 * 1000))}`,
    });
    track("checkout_started", { annual, plan: annual ? "annual" : "monthly" },
          req.sessionID, req.session.userId).catch(() => {});
    res.json({ url: checkoutSession.url });
  } catch (err) {
    console.error("Stripe checkout error:", err);
    res.status(500).json({ error: "Could not create checkout session." });
  }
});

// ============================================================
//  POST /api/stripe/webhook
// ============================================================
router.post("/stripe/webhook", async (req, res) => {
  if (!stripe) return res.status(503).send("Not configured");
  const sig = req.headers["stripe-signature"];
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.rawBody, sig, STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error("Webhook signature error:", err.message);
    return res.status(400).send("Webhook error: " + err.message);
  }

  try {
    const processed = await db.execute({
      sql: "SELECT 1 FROM stripe_events WHERE event_id = ? LIMIT 1",
      args: [event.id],
    });
    if (processed.rows.length) return res.json({ received: true, duplicate: true });

    switch (event.type) {
      case "checkout.session.completed": {
        const sess   = event.data.object;
        const userId = sess.metadata && sess.metadata.userId;
        if (!userId || !sess.subscription) break;
        const sub    = await stripe.subscriptions.retrieve(sess.subscription);
        const plan   = sub.status === "trialing" ? "trial" : "pro";
        const trialEnd = sub.trial_end ? new Date(sub.trial_end * 1000).toISOString() : null;
        await db.execute({
          sql:  "UPDATE users SET plan=?, trial_ends_at=?, stripe_customer_id=?, stripe_subscription_id=? WHERE id=?",
          args: [plan, trialEnd, sess.customer, sess.subscription, userId],
        });
        track("checkout_completed", { plan, trial: plan === "trial" }, null, Number(userId)).catch(() => {});
        break;
      }
      case "customer.subscription.updated": {
        const sub = event.data.object;
        const r   = await db.execute({ sql: "SELECT id FROM users WHERE stripe_customer_id=?", args: [sub.customer] });
        if (!r.rows.length) break;
        let plan = "free";
        if (sub.status === "active")   plan = "pro";
        if (sub.status === "trialing") plan = "trial";
        const trialEnd = sub.trial_end ? new Date(sub.trial_end * 1000).toISOString() : null;
        await db.execute({ sql: "UPDATE users SET plan=?, trial_ends_at=? WHERE id=?", args: [plan, trialEnd, r.rows[0].id] });
        break;
      }
      case "customer.subscription.deleted": {
        const sub = event.data.object;
        const r   = await db.execute({ sql: "SELECT id FROM users WHERE stripe_customer_id=?", args: [sub.customer] });
        if (!r.rows.length) break;
        await db.execute({ sql: "UPDATE users SET plan='free', trial_ends_at=NULL WHERE id=?", args: [r.rows[0].id] });
        break;
      }
      case "invoice.payment_failed": {
        // Stripe may retry a failed invoice while the subscription remains active
        // or past_due. Access is updated from customer.subscription.updated.
        break;
      }
      default:
        console.log(`[stripe] unhandled webhook event: ${event.type}`);
    }
    await db.execute({
      sql: "INSERT OR IGNORE INTO stripe_events (event_id, event_type) VALUES (?, ?)",
      args: [event.id, event.type],
    });
  } catch (err) {
    console.error(`[stripe] webhook handler error on event ${event.type}:`, err);
    return res.status(500).json({ error: "Webhook processing failed." });
  }

  res.json({ received: true });
});

// ============================================================
//  POST /api/stripe/portal
// ============================================================
router.post("/stripe/portal", validateCsrf, async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: "Login required." });
  if (!stripe)             return res.status(503).json({ error: "Payments not configured." });
  try {
    const r          = await db.execute({ sql: "SELECT stripe_customer_id FROM users WHERE id = ?", args: [req.session.userId] });
    const customerId = r.rows[0]?.stripe_customer_id;
    if (!customerId) return res.status(404).json({ error: "No subscription found." });
    const portalSession = await stripe.billingPortal.sessions.create({
      customer:   customerId,
      return_url: `${APP_URL}/`,
    });
    res.json({ url: portalSession.url });
  } catch (err) {
    console.error("portal error:", err);
    res.status(500).json({ error: "Could not open the billing portal." });
  }
});

module.exports = router;

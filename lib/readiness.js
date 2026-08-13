"use strict";

function present(value) {
  return typeof value === "string" && value.trim().length > 0;
}

function productionReadiness(env = process.env, databaseReady = true) {
  const appUrl = String(env.APP_URL || "");
  const fromEmail = String(env.FROM_EMAIL || "");
  const checks = {
    database: Boolean(databaseReady),
    marketData: present(env.FINNHUB_KEY),
    secureSessions: present(env.SESSION_SECRET) && String(env.SESSION_SECRET).length >= 32 && !/change-me|replace-this/i.test(env.SESSION_SECRET),
    billing: [env.STRIPE_SECRET_KEY, env.STRIPE_WEBHOOK_SECRET, env.STRIPE_PRICE_MONTHLY, env.STRIPE_PRICE_ANNUAL].every(present),
    transactionalEmail: present(env.RESEND_API_KEY) && present(fromEmail) && !/onboarding@resend\.dev/i.test(fromEmail),
    publicUrl: /^https:\/\//i.test(appUrl),
  };

  return {
    ready: Object.values(checks).every(Boolean),
    environment: env.NODE_ENV || "development",
    checks,
  };
}

module.exports = { productionReadiness };

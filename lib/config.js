// Centralised config. Require this first -- it calls dotenv.config().
// In production, FINNHUB_KEY and SESSION_SECRET must be set or the
// server will refuse to start (see warnMissingEnv in server.js).
require("dotenv").config();

module.exports = {
  PORT:                  process.env.PORT || 3000,
  SESSION_SECRET:        process.env.SESSION_SECRET || "change-me-in-production-please",
  FINNHUB_KEY:           process.env.FINNHUB_KEY || "",
  BCRYPT_ROUNDS:         12,
  STRIPE_SECRET_KEY:     process.env.STRIPE_SECRET_KEY || "",
  STRIPE_WEBHOOK_SECRET: process.env.STRIPE_WEBHOOK_SECRET || "",
  STRIPE_PRICE_MONTHLY:  process.env.STRIPE_PRICE_MONTHLY || "",
  STRIPE_PRICE_ANNUAL:   process.env.STRIPE_PRICE_ANNUAL || "",
  APP_URL:               process.env.APP_URL || "http://localhost:" + (process.env.PORT || 3000),
  ADMIN_SECRET:          process.env.ADMIN_SECRET || "",
  FROM_EMAIL:            process.env.FROM_EMAIL || "ImpliedLens <onboarding@resend.dev>",
};

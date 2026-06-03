// ============================================================
//  Implied Lens — entry point
//
//  Responsibilities here:
//    • load config (must be first — sets up dotenv)
//    • create express app + middleware stack
//    • mount route modules
//    • initialise database and start listening
//
//  All business logic lives in:
//    lib/config.js        — env vars / constants
//    lib/db.js            — Turso client, TursoStore, initDb
//    lib/plan.js          — getEffectivePlan, requirePro, checkAnalysisLimit
//    lib/email.js         — sendEmail helper
//    routes/auth.js       — signup, login, logout, saves, password reset, admin
//    routes/billing.js    — Stripe checkout, webhook, billing portal
//    routes/market-data.js — quote, screener, news, movers, analyst-signals
//    routes/financials.js — financials, earnings, metrics, SEC, estimates,
//                           analyst, institutional, darkpool, me/limit
// ============================================================

const cfg = require("./lib/config"); // dotenv loaded here first
const { PORT, SESSION_SECRET } = cfg;

// Validate env vars at startup.
// In production: missing FINNHUB_KEY or SESSION_SECRET is fatal.
// In development: emit a warning and continue with fallbacks.
(function checkEnv() {
  const isProd = process.env.NODE_ENV === "production";
  const missing = [];
  if (!process.env.FINNHUB_KEY)   missing.push("FINNHUB_KEY");
  if (!process.env.SESSION_SECRET) missing.push("SESSION_SECRET");
  if (isProd && !process.env.STRIPE_SECRET_KEY)     missing.push("STRIPE_SECRET_KEY");
  if (isProd && !process.env.STRIPE_WEBHOOK_SECRET) missing.push("STRIPE_WEBHOOK_SECRET");

  if (missing.length === 0) return;

  if (isProd) {
    console.error("[config] FATAL: required env vars not set: " + missing.join(", ") + ". Refusing to start.");
    process.exit(1);
  } else {
    missing.forEach(k => console.warn("[config] WARNING: " + k + " not set -- using insecure dev fallback."));
  }
}());

const path    = require("path");
const express = require("express");
const session = require("express-session");
const helmet  = require("helmet");

const { TursoStore, initDb } = require("./lib/db");

// ---- Route modules ----
const authRouter        = require("./routes/auth");
const billingRouter     = require("./routes/billing");
const marketDataRouter  = require("./routes/market-data");
const financialsRouter  = require("./routes/financials");

// ============================================================
//  App setup
// ============================================================
const app = express();
app.set("trust proxy", 1);

// Content-Security-Policy
// unsafe-inline is required for both script-src AND script-src-attr because
// index.html uses inline <script> blocks and inline onclick= event handlers
// throughout. script-src-attr defaults to 'none' in Helmet, which silently
// blocks every onclick= attribute — that was the root cause of the UI being
// completely non-interactive after Helmet was added.
// A future nonce-based refactor could eliminate unsafe-inline entirely.
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc:     ["'self'"],
      scriptSrc:      ["'self'", "'unsafe-inline'",
                       "https://cdnjs.cloudflare.com",
                       "https://cdn.jsdelivr.net"],
      // Must explicitly allow unsafe-inline here too — Helmet defaults this
      // directive to 'none', which blocks all onclick= / onchange= handlers.
      scriptSrcAttr:  ["'unsafe-inline'"],
      styleSrc:       ["'self'", "'unsafe-inline'",
                       "https://fonts.googleapis.com"],
      fontSrc:        ["'self'", "https://fonts.gstatic.com"],
      imgSrc:         ["'self'", "data:", "https:"],
      // All API calls route through our own origin. cdn.jsdelivr.net is required
      // for the globe's world-atlas JSON fetch. cdnjs.cloudflare.com is required
      // for hammer.js (used by Chart.js touch support).
      connectSrc:     ["'self'", "https://cdn.jsdelivr.net",
                       "https://cdnjs.cloudflare.com"],
      objectSrc:      ["'none'"],
      frameAncestors: ["'none'"],
      formAction:     ["'self'"],
      baseUri:        ["'self'"],
    },
  },
}));

// Static public assets (logo, robots.txt, sitemap.xml, …)
app.use(express.static(path.join(__dirname, "public"), {
  maxAge: "7d",
  etag: true,
  setHeaders(res, filePath) {
    if (filePath.endsWith(".svg"))        res.setHeader("Content-Type", "image/svg+xml");
    if (filePath.endsWith("robots.txt"))  res.setHeader("Content-Type", "text/plain");
    if (filePath.endsWith("sitemap.xml")) res.setHeader("Content-Type", "application/xml");
  },
}));

// Raw-body capture for Stripe webhook signature verification
app.use(express.json({ limit: "64kb", verify: (req, _res, buf) => { req.rawBody = buf; } }));
app.use(express.urlencoded({ extended: false, limit: "64kb" }));

app.use(session({
  store: new TursoStore(),
  name: "il.sid",
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 1000 * 60 * 60 * 24 * 7,
  },
}));

// ============================================================
//  Route mounting
// ============================================================
app.use("/api",         authRouter);        // /api/auth/*, /api/saves, /api/admin/*
app.use("/api",         billingRouter);     // /api/stripe/*
app.use("/api",         marketDataRouter);  // /api/quote/*, /api/screener, /api/news/*, /api/market/*
app.use("/api",         financialsRouter);  // /api/financials/*, /api/earnings/*, /api/metrics/*,
                                            // /api/sec/*, /api/estimates/*, /api/analyst/*,
                                            // /api/institutional/*, /api/darkpool/*, /api/me/limit

// ============================================================
//  Static HTML pages
// ============================================================
app.get(["/login",  "/login.html"],  (req, res) => res.sendFile(path.join(__dirname, "public", "login.html")));
app.get(["/signup", "/signup.html"], (req, res) => res.sendFile(path.join(__dirname, "public", "signup.html")));
app.get(["/reset-password", "/reset-password.html"], (req, res) =>
  res.sendFile(path.join(__dirname, "public", "reset-password.html"))
);

app.get(["/about", "/about.html"], (_req, res) => res.sendFile(path.join(__dirname, "public", "about.html")));

app.get(["/blog",  "/blog.html"],  (_req, res) => res.sendFile(path.join(__dirname, "public", "blog.html")));

// ============================================================
//  CSRF token endpoint — returns (or creates) per-session token
// ============================================================
const { getOrCreateToken } = require("./lib/csrf");
const { track }            = require("./lib/analytics");
const rateLimit            = require("express-rate-limit");
app.get("/api/csrf", (req, res) => {
  // Ensure a session exists before issuing a token
  if (!req.session) return res.status(500).json({ error: "Session unavailable." });
  const token = getOrCreateToken(req);
  res.json({ token });
});

// ============================================================
//  Conversion / analytics tracking endpoint
// ============================================================
const trackLimiter = rateLimit({
  windowMs: 60 * 1000,      // 1 minute
  max: 60,                   // 60 events per minute per IP
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Rate limit exceeded." },
});

app.post("/api/track", trackLimiter, async (req, res) => {
  const { event, properties } = req.body;
  if (!event || typeof event !== "string") {
    return res.status(400).json({ error: "event required" });
  }
  // Allowlist of events the client is permitted to send
  const CLIENT_EVENTS = new Set([
    "page_view", "analyze_started", "analyze_completed",
    "pro_gate_viewed", "upgrade_modal_opened", "daily_limit_reached",
    "checkout_redirect", "plan_badge_clicked", "pricing_viewed",
  ]);
  if (!CLIENT_EVENTS.has(event)) {
    return res.status(400).json({ error: "Unknown event." });
  }
  const props = (properties && typeof properties === "object") ? properties : {};
  // Strip any user-supplied ids — we derive them server-side
  delete props.user_id;
  track(event, props, req.sessionID, req.session.userId || null).catch(() => {});
  res.json({ ok: true });
});

// ============================================================
//  Trust & legal pages
// ============================================================
app.get(["/privacy", "/privacy.html"],         (_req, res) => res.sendFile(path.join(__dirname, "public", "privacy.html")));
app.get(["/terms",   "/terms.html"],            (_req, res) => res.sendFile(path.join(__dirname, "public", "terms.html")));
app.get(["/data-sources", "/data-sources.html"],(_req, res) => res.sendFile(path.join(__dirname, "public", "data-sources.html")));

// SPA catch-all — must be last
app.get("*", (_req, res) => res.sendFile(path.join(__dirname, "index.html")));

// ============================================================
//  Start
// ============================================================
// When run directly (node server.js): initialise DB and start listening.
// When required as a module (tests): export the app so the test can
// call initDb() itself and app.listen() on a free port.
if (require.main === module) {
  initDb().then(() => {
    app.listen(PORT, () => console.log(`Implied Lens running on port ${PORT}`));
  }).catch(err => { console.error("DB init failed:", err); process.exit(1); });
}

module.exports = app;

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
//                           analyst, institutional, FINRA OTC activity, me/limit
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

  // Email delivery is non-fatal but must be loud: a broken config means new
  // users can never verify their accounts.
  if (isProd) {
    const fromEmail = process.env.FROM_EMAIL || "";
    if (!process.env.RESEND_API_KEY) {
      console.warn("[config] WARNING: RESEND_API_KEY not set \u2014 verification and password-reset emails will NOT be sent. New users cannot verify their accounts.");
    }
    if (!fromEmail || /resend\.dev/i.test(fromEmail)) {
      console.warn("[config] WARNING: FROM_EMAIL is unset or the Resend sandbox (onboarding@resend.dev). Resend only delivers sandbox mail to your own account address, so new users get nothing. Verify a domain in Resend and set FROM_EMAIL, e.g. noreply@impliedlens.com.");
    }
  }

  if (missing.length === 0) return;

  if (isProd) {
    console.error("[config] FATAL: required env vars not set: " + missing.join(", ") + ". Refusing to start.");
    process.exit(1);
  } else {
    missing.forEach(k => console.warn("[config] WARNING: " + k + " not set -- using insecure dev fallback."));
  }
}());

const path    = require("path");
const fs      = require("fs");
const crypto  = require("crypto");
const express = require("express");
const session = require("express-session");
const helmet  = require("helmet");
const rateLimit = require("express-rate-limit");
const compression = require("compression");

const { db, TursoStore, initDb } = require("./lib/db");
const { guestIdMiddleware }  = require("./lib/plan");
const buildInfo = require("./lib/build-info");

// ---- Route modules ----
const authRouter        = require("./routes/auth");
const billingRouter     = require("./routes/billing");
const marketDataRouter  = require("./routes/market-data");
const financialsRouter  = require("./routes/financials");
const lensScoreRouter   = require("./routes/lens-score");
const stockLandingRouter = require("./routes/stock-landing");
const workspaceRouter     = require("./routes/workspace");
const providerHealth      = require("./lib/provider-health");
const { productionReadiness } = require("./lib/readiness");
const { buildSitemapXml } = require("./lib/acquisition-tickers");

// ============================================================
//  App setup
// ============================================================
const app = express();
app.set("trust proxy", 1);
app.use((_req, res, next) => {
  res.setHeader("X-ImpliedLens-Build", buildInfo.shortCommit);
  next();
});

// Content-Security-Policy
// Executable JavaScript is external, so script-src does not allow inline code.
// The legacy UI still has inline event attributes; script-src-attr remains
// narrowly enabled until those handlers move to delegated listeners.
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc:     ["'self'"],
      scriptSrc:      ["'self'",
                       "https://cdnjs.cloudflare.com",
                       "https://cdn.jsdelivr.net"],
      // Helmet defaults this directive to 'none', which would block the legacy
      // onclick= / onchange= handlers that remain in the current UI.
      scriptSrcAttr:  ["'unsafe-inline'"],
      styleSrc:       ["'self'", "'unsafe-inline'",
                       "https://fonts.googleapis.com",
                       "https://cdn.jsdelivr.net"],
      fontSrc:        ["'self'", "https://fonts.gstatic.com",
                       "https://cdn.jsdelivr.net"],
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
app.use(compression());

// HTML is deployment-sensitive and should always be revalidated. Fingerprinted
// static assets keep their longer cache policy below.
app.use((req, res, next) => {
  if (req.method === "GET" && !req.path.startsWith("/api/") && (req.path === "/" || req.path.endsWith(".html") || !path.extname(req.path))) {
    res.setHeader("Cache-Control", "no-cache, must-revalidate");
  }
  next();
});

// Static public assets (logo, robots.txt, sitemap.xml, …)
app.get("/favicon.ico", (_req, res) => {
  res.type("image/svg+xml");
  res.sendFile(path.join(__dirname, "public", "logo.svg"));
});

app.get("/sitemap.xml", (_req, res) => {
  res.type("application/xml");
  res.setHeader("Cache-Control", "public, max-age=3600");
  res.send(buildSitemapXml(cfg.APP_URL));
});

app.use(express.static(path.join(__dirname, "public"), {
  maxAge: "7d",
  etag: true,
  setHeaders(res, filePath) {
    if (filePath.endsWith(".html"))       res.setHeader("Cache-Control", "no-cache, must-revalidate");
    if (filePath.endsWith(".svg"))        res.setHeader("Content-Type", "image/svg+xml");
    if (filePath.endsWith("robots.txt"))  res.setHeader("Content-Type", "text/plain");
    if (filePath.endsWith("sitemap.xml")) res.setHeader("Content-Type", "application/xml");
  },
}));

// Raw-body capture for Stripe webhook signature verification
app.use(express.json({ limit: "64kb", verify: (req, _res, buf) => { req.rawBody = buf; } }));
app.use(express.urlencoded({ extended: false, limit: "64kb" }));

// Durable guest-ID cookie — must come before session middleware
app.use(guestIdMiddleware);

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
const marketDataLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 180,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many market-data requests. Please try again shortly." },
});
app.use([
  "/api/quote",
  "/api/news",
  "/api/market",
  "/api/screener",
  "/api/financials",
  "/api/earnings",
  "/api/calls",
  "/api/metrics",
  "/api/sec",
  "/api/estimates",
  "/api/analyst",
  "/api/institutional",
  "/api/darkpool",
  "/api/lens-score",
], marketDataLimiter);

app.use("/api",         authRouter);        // /api/auth/*, /api/saves, /api/admin/*
app.use("/api",         billingRouter);     // /api/stripe/*
app.use("/api",         marketDataRouter);  // /api/quote/*, /api/screener, /api/news/*, /api/market/*
app.use("/api",         financialsRouter);  // /api/financials/*, /api/earnings/*, /api/metrics/*,
                                            // /api/sec/*, /api/estimates/*, /api/analyst/*,
                                            // /api/institutional/*, /api/darkpool/*, /api/me/limit
app.use("/api",         lensScoreRouter);    // /api/lens-score/*
app.use("/api",         workspaceRouter);    // /api/workspace/*

// ============================================================
//  Static HTML pages
// ============================================================
app.get("/", (_req, res) => res.sendFile(path.join(__dirname, "index.html")));

app.get(["/login",  "/login.html"],  (req, res) => res.sendFile(path.join(__dirname, "public", "login.html")));
app.get(["/signup", "/signup.html"], (req, res) => res.sendFile(path.join(__dirname, "public", "signup.html")));
app.get(["/reset-password", "/reset-password.html"], (req, res) =>
  res.sendFile(path.join(__dirname, "public", "reset-password.html"))
);

app.get(["/about", "/about.html"], (_req, res) => res.sendFile(path.join(__dirname, "public", "about.html")));

app.get(["/blog",  "/blog.html"],  (_req, res) => res.sendFile(path.join(__dirname, "public", "blog.html")));
app.get(["/research-process", "/research-process.html"], (_req, res) => res.sendFile(path.join(__dirname, "public", "research-process.html")));
app.get(["/compound-calculator", "/compound-calculator.html"], (_req, res) => res.sendFile(path.join(__dirname, "public", "compound-calculator.html")));

// Production LensScore surface. It reuses the same independently tested
// browser engine as the private lab, but is served from a stable public route
// and consumes only the canonical live research endpoint.
const lensScoreRoot = path.join(__dirname, "labs", "lens-score");
app.use("/lens-score/assets", express.static(lensScoreRoot, {
  etag: true,
  maxAge: process.env.NODE_ENV === "production" ? "1h" : 0,
  index: false,
}));
app.get(["/lens-score", "/lens-score/"], async (_req, res) => {
  try {
    const source = await fs.promises.readFile(path.join(lensScoreRoot, "index.html"), "utf8");
    const html = source
      .replace('<meta name="robots" content="noindex,nofollow,noarchive">', '<meta name="robots" content="index,follow">')
      .replaceAll("/__lab/lens-score/assets/", "/lens-score/assets/")
      .replace("Reported data · production candidate", "Reported data · live research")
      .replace('<link rel="icon" href="/logo.svg" type="image/svg+xml">', '<link rel="canonical" href="https://impliedlens.com/lens-score"><link rel="icon" href="/logo.svg" type="image/svg+xml">');
    res.type("html").send(html);
  } catch (error) {
    console.error("[lens-score-page]", error.message);
    res.status(500).send("LensScore is temporarily unavailable.");
  }
});

// Development-only product lab. This route is intentionally absent in
// production so prototypes cannot be discovered or indexed on the live site.
if (process.env.NODE_ENV !== "production") {
  const lensScoreLabRoot = path.join(__dirname, "labs", "lens-score");
  app.use("/__lab/lens-score/assets", express.static(lensScoreLabRoot, {
    etag: false,
    maxAge: 0,
    index: false,
    setHeaders(res) {
      res.setHeader("Cache-Control", "no-store");
      res.setHeader("X-Robots-Tag", "noindex, nofollow, noarchive");
    },
  }));
  app.get(["/__lab/lens-score", "/__lab/lens-score/"], (_req, res) => {
    res.setHeader("Cache-Control", "no-store");
    res.setHeader("X-Robots-Tag", "noindex, nofollow, noarchive");
    res.sendFile(path.join(lensScoreLabRoot, "index.html"));
  });
}

// ============================================================
//  CSRF token endpoint — returns (or creates) per-session token
// ============================================================
const { getOrCreateToken } = require("./lib/csrf");
const { track }            = require("./lib/analytics");
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
    "landing_page_view", "landing_cta_clicked",
    "guest_signup_prompt_viewed", "guest_signup_started",
    "signup_page_viewed", "login_page_viewed", "analysis_resumed_after_auth",
    "checkout_requires_login", "signup_started_from_upgrade",
    "login_started_from_upgrade", "checkout_resumed_after_auth",
    "checkout_blocked_unverified",
    "feedback_opened", "feedback_rated", "feedback_email_opened", "feedback_shared",
    "research_shared", "call_research_loaded", "call_transcript_opened", "call_scorecard_saved",
    "wealth_plan_run", "wealth_plan_shared",
    "activation_checklist_viewed", "thesis_saved", "watchlist_saved", "position_saved",
    "portfolio_questionnaire_started", "portfolio_profile_saved", "portfolio_guide_viewed",
    "review_reminder_requested", "billing_portal_opened", "checkout_cancelled",
  ]);
  if (!CLIENT_EVENTS.has(event)) {
    return res.status(400).json({ error: "Unknown event." });
  }
  const props = {};
  if (properties && typeof properties === "object" && !Array.isArray(properties)) {
    for (const [key, value] of Object.entries(properties).slice(0, 12)) {
      if (key === "user_id" || key.length > 50) continue;
      if (typeof value === "string") props[key] = value.slice(0, 250);
      else if (typeof value === "number" || typeof value === "boolean" || value === null) props[key] = value;
    }
  }
  if (!req.session.userId && req.guestId) {
    props.guest_actor = crypto.createHash("sha256").update(req.guestId).digest("hex").slice(0, 24);
  }
  track(event, props, req.sessionID, req.session.userId || null).catch(() => {});
  res.json({ ok: true });
});

// ============================================================
//  Email verification — top-level route (handler in routes/auth.js)
// ============================================================
// The verify-email handler lives in routes/auth.js (mounted at /api),
// so the canonical URL is /api/verify-email?token=...
// Provide a top-level alias so verification links work without /api prefix.
app.get("/verify-email", (req, res) => {
  const qs = req.url.includes("?") ? req.url.slice(req.url.indexOf("?")) : "";
  res.redirect(301, "/api/verify-email" + qs);
});

// ============================================================
//  Trust & legal pages
// ============================================================
app.get(["/privacy", "/privacy.html"],         (_req, res) => res.sendFile(path.join(__dirname, "public", "privacy.html")));
app.get(["/terms",   "/terms.html"],            (_req, res) => res.sendFile(path.join(__dirname, "public", "terms.html")));
app.get(["/data-sources", "/data-sources.html"],(_req, res) => res.sendFile(path.join(__dirname, "public", "data-sources.html")));

// Ticker landing pages — server-rendered SEO pages for /stock/:ticker
app.use("/", stockLandingRouter);

app.get("/healthz", async (_req, res) => {
  res.setHeader("Cache-Control", "no-store");
  try {
    await db.execute("SELECT 1");
    res.json({ ok: true, database: "ok", providers: providerHealth.snapshot(), ...buildInfo });
  } catch (_) {
    res.status(503).json({ ok: false, database: "unavailable", ...buildInfo });
  }
});

// Deployment readiness is intentionally stricter than liveness. It never
// returns secret values; it only reports whether each launch-critical system is
// configured and reachable.
app.get("/readyz", async (_req, res) => {
  res.setHeader("Cache-Control", "no-store");
  let databaseReady = true;
  try {
    await db.execute("SELECT 1");
  } catch (_) {
    databaseReady = false;
  }
  const readiness = productionReadiness(process.env, databaseReady);
  res.status(readiness.ready ? 200 : 503).json({ ...readiness, ...buildInfo });
});

app.get("/api/providers/health", (_req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.json(providerHealth.snapshot());
});

app.get("/api/version", (_req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.json(buildInfo);
});

app.use("/api", (_req, res) => res.status(404).json({ error: "API route not found." }));

// SPA catch-all — must be last
app.get("*", (_req, res) => res.status(404).sendFile(path.join(__dirname, "index.html")));

// ============================================================
//  Start
// ============================================================
// When run directly (node server.js): initialise DB and start listening.
// When required as a module (tests): export the app so the test can
// call initDb() itself and app.listen() on a free port.
// ── Automatic weekly review digest ─────────────────────────────────────────
// At most one email per user per ISO week, only when a thesis review is due
// within 7 days. Reuses lifecycle_email_log for idempotent claims.
async function runReviewDigests() {
  try {
    const { sendEmail } = require("./lib/email");
    const monday = (() => { const d = new Date(); const day = (d.getUTCDay() + 6) % 7; d.setUTCDate(d.getUTCDate() - day); return d.toISOString().slice(0, 10); })();
    const users = await db.execute({ sql: `
      SELECT u.id, u.email FROM users u WHERE u.email IS NOT NULL AND EXISTS (
        SELECT 1 FROM investment_theses t
        WHERE t.user_id = u.id AND t.review_date IS NOT NULL AND t.review_date != ''
          AND t.review_date <= date('now', '+7 days') AND t.review_date >= date('now', '-30 days')
      ) LIMIT 200` });
    for (const u of ((users && users.rows) || [])) {
      try {
      const claim = await db.execute({
        sql: "INSERT OR IGNORE INTO lifecycle_email_log (user_id,email_type,reference_key) VALUES (?,'review_digest_auto',?)",
        args: [u.id, monday],
      });
      if (!Number(claim.rowsAffected || 0)) continue;
      const due = await db.execute({
        sql: "SELECT ticker,status,review_date FROM investment_theses WHERE user_id=? AND review_date IS NOT NULL AND review_date <= date('now','+7 days') AND review_date >= date('now','-30 days') ORDER BY review_date ASC LIMIT 20",
        args: [u.id],
      });
      if (!due || !due.rows || !due.rows.length) continue;
      const esc = v => String(v ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
      const items = due.rows.map(r => `<li style="margin-bottom:6px"><strong>${esc(r.ticker)}</strong> — ${esc(r.status || "thesis")} — review ${esc(r.review_date)}</li>`).join("");
      const result = await sendEmail({
        to: u.email,
        subject: `Implied Lens: ${due.rows.length} thesis review${due.rows.length === 1 ? "" : "s"} due this week`,
        html: `<div style="font-family:Arial,sans-serif;max-width:560px"><h2 style="color:#9A6A18">Your reviews are due</h2><p>You set these review dates when you saved each thesis. Check the evidence before changing a position — not the price.</p><ul>${items}</ul><p><a href="${process.env.APP_URL || "https://impliedlens.com"}/?view=tool&section=workspace" style="color:#9A6A18;font-weight:bold">Open your workspace →</a></p><p style="color:#999;font-size:12px">Not investment advice. You receive this because a saved thesis has a review date this week.</p></div>`,
      });
      if (!result?.sent && !result?.simulated) {
        await db.execute({ sql: "DELETE FROM lifecycle_email_log WHERE user_id=? AND email_type='review_digest_auto' AND reference_key=?", args: [u.id, monday] }).catch(() => {});
      }
      } catch (perUserErr) {
        console.error("[review-digest] user", u && u.id, "failed:", (perUserErr && (perUserErr.stack || perUserErr.message)) || perUserErr);
      }
    }
  } catch (e) { console.error("[review-digest] error:", (e && (e.stack || e.message)) || e); }
}

if (require.main === module) {
  initDb().then(() => {
    app.listen(PORT, () => console.log(`Implied Lens running on port ${PORT}`));
    setTimeout(runReviewDigests, 90 * 1000);               // shortly after boot
    setInterval(runReviewDigests, 6 * 60 * 60 * 1000);     // then every 6 hours
  }).catch(err => { console.error("DB init failed:", err); process.exit(1); });
}

module.exports = app;

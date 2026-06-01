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

app.get("/about", (_req, res) => res.send(`<!DOCTYPE html><html lang="en"><head>
  <meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>About — ImpliedLens</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Playfair+Display:ital,wght@0,400;0,600;1,400&family=Inter:wght@300;400;500;600&display=swap" rel="stylesheet">
  <style>
    *{margin:0;padding:0;box-sizing:border-box}
    body{font-family:'Inter',sans-serif;background:#08090D;color:rgba(220,225,232,.9);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:2rem}
    .wrap{max-width:640px;width:100%;text-align:center}
    .logo{font-family:'Playfair Display',serif;font-size:1.8rem;color:#fff;margin-bottom:.25rem}
    .logo em{color:#C8882A;font-style:italic}
    .tagline{font-size:.85rem;color:rgba(220,225,232,.4);letter-spacing:.1em;text-transform:uppercase;margin-bottom:2.5rem}
    h1{font-family:'Playfair Display',serif;font-size:2.2rem;margin-bottom:1rem;line-height:1.3}
    p{font-size:.95rem;color:rgba(220,225,232,.65);line-height:1.8;margin-bottom:1.25rem}
    .socials{display:flex;gap:1rem;justify-content:center;margin:2rem 0}
    .soc-btn{display:inline-flex;align-items:center;gap:8px;padding:.65rem 1.4rem;border-radius:8px;border:1px solid rgba(200,136,42,.35);color:#C8882A;text-decoration:none;font-size:.85rem;font-weight:500;transition:all .18s}
    .soc-btn:hover{background:rgba(200,136,42,.1);border-color:#C8882A}
    .back{display:inline-block;margin-top:1.5rem;color:rgba(220,225,232,.4);font-size:.8rem;text-decoration:none}
    .back:hover{color:#C8882A}
  </style></head><body>
  <div class="wrap">
    <div class="logo">Implied<em>Lens</em></div>
    <div class="tagline">Stock Analysis Platform</div>
    <h1>Built for the self-directed investor.</h1>
    <p>ImpliedLens gives individual investors access to the same analytical tools used by professional analysts — DCF valuation, financial statement analysis, earnings history, risk metrics, and more — without the Bloomberg price tag.</p>
    <p>The platform pulls data directly from SEC EDGAR filings, Yahoo Finance, and Finnhub, so every number you see traces back to a primary source.</p>
    <p>Follow along as we build and improve the platform.</p>
    <div class="socials">
      <a href="https://x.com/ImpliedLens" target="_blank" class="soc-btn">𝕏 @ImpliedLens</a>
      <a href="https://instagram.com/ImpliedLens" target="_blank" class="soc-btn">📸 @ImpliedLens</a>
    </div>
    <a href="/" class="back">← Back to ImpliedLens</a>
  </div>
</body></html>`));

app.get("/blog", (_req, res) => res.send(`<!DOCTYPE html><html lang="en"><head>
  <meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Blog — ImpliedLens</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Playfair+Display:ital,wght@0,400;0,600;1,400&family=Inter:wght@300;400;500;600&display=swap" rel="stylesheet">
  <style>
    *{margin:0;padding:0;box-sizing:border-box}
    body{font-family:'Inter',sans-serif;background:#08090D;color:rgba(220,225,232,.9);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:2rem}
    .wrap{max-width:640px;width:100%;text-align:center}
    .logo{font-family:'Playfair Display',serif;font-size:1.8rem;color:#fff;margin-bottom:.25rem}
    .logo em{color:#C8882A;font-style:italic}
    .tagline{font-size:.85rem;color:rgba(220,225,232,.4);letter-spacing:.1em;text-transform:uppercase;margin-bottom:2.5rem}
    h1{font-family:'Playfair Display',serif;font-size:2.2rem;margin-bottom:1rem;line-height:1.3}
    p{font-size:.95rem;color:rgba(220,225,232,.65);line-height:1.8;margin-bottom:1.25rem}
    .socials{display:flex;gap:1rem;justify-content:center;flex-wrap:wrap;margin:2rem 0}
    .soc-btn{display:inline-flex;align-items:center;gap:8px;padding:.65rem 1.4rem;border-radius:8px;border:1px solid rgba(200,136,42,.35);color:#C8882A;text-decoration:none;font-size:.85rem;font-weight:500;transition:all .18s}
    .soc-btn:hover{background:rgba(200,136,42,.1);border-color:#C8882A}
    .pill{display:inline-block;padding:.25rem .75rem;border-radius:100px;background:rgba(200,136,42,.12);color:#C8882A;font-size:.72rem;font-weight:600;letter-spacing:.06em;margin-bottom:1.5rem}
    .back{display:inline-block;margin-top:1.5rem;color:rgba(220,225,232,.4);font-size:.8rem;text-decoration:none}
    .back:hover{color:#C8882A}
  </style></head><body>
  <div class="wrap">
    <div class="logo">Implied<em>Lens</em></div>
    <div class="tagline">Stock Analysis Platform</div>
    <span class="pill">COMING SOON</span>
    <h1>Market insights &amp; platform updates.</h1>
    <p>The ImpliedLens blog is where we'll share analysis walkthroughs, feature updates, investing frameworks, and how to get the most out of the platform.</p>
    <p>In the meantime, follow us on social for updates and market commentary.</p>
    <div class="socials">
      <a href="https://x.com/ImpliedLens" target="_blank" class="soc-btn">𝕏 @ImpliedLens</a>
      <a href="https://instagram.com/ImpliedLens" target="_blank" class="soc-btn">📸 @ImpliedLens</a>
    </div>
    <a href="/" class="back">← Back to ImpliedLens</a>
  </div>
</body></html>`));

// ============================================================
//  CSRF token endpoint — returns (or creates) per-session token
// ============================================================
const { getOrCreateToken } = require("./lib/csrf");
app.get("/api/csrf", (req, res) => {
  // Ensure a session exists before issuing a token
  if (!req.session) return res.status(500).json({ error: "Session unavailable." });
  const token = getOrCreateToken(req);
  res.json({ token });
});

// SPA catch-all — must be last
app.get("*", (_req, res) => res.sendFile(path.join(__dirname, "index.html")));

// ============================================================
//  Start
// ============================================================
initDb().then(() => {
  app.listen(PORT, () => console.log(`Implied Lens running on port ${PORT}`));
}).catch(err => { console.error("DB init failed:", err); process.exit(1); });

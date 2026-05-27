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
// unsafe-inline is retained for scripts/styles because index.html relies heavily
// on inline <script> blocks and inline event handlers — a future nonce-based
// refactor should eliminate it. All other directives are locked down.
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc:     ["'self'"],
      scriptSrc:      ["'self'", "'unsafe-inline'",
                       "https://cdnjs.cloudflare.com",
                       "https://cdn.jsdelivr.net"],
      styleSrc:       ["'self'", "'unsafe-inline'",
                       "https://fonts.googleapis.com"],
      fontSrc:        ["'self'", "https://fonts.gstatic.com"],
      imgSrc:         ["'self'", "data:", "https:"],
      // All API calls route through our own origin. cdn.jsdelivr.net is required
      // for the globe's world-atlas JSON fetch (index.html line ~4638).
      connectSrc:     ["'self'", "https://cdn.jsdelivr.net"],
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

function _page(title, content) {
  return `<!DOCTYPE html><html lang="en"><head>
  <meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>${title} — ImpliedLens</title>
  <meta name="robots" content="index,follow">
  <link rel="icon" type="image/svg+xml" href="/logo.svg">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Playfair+Display:ital,wght@0,400;0,600;1,400&family=Inter:wght@300;400;500;600&display=swap" rel="stylesheet">
  <style>
    *{margin:0;padding:0;box-sizing:border-box}
    body{font-family:'Inter',sans-serif;background:#08090D;color:rgba(220,225,232,.88);min-height:100vh}
    a{color:#C8882A;text-decoration:none}a:hover{text-decoration:underline}
    .nav{display:flex;align-items:center;justify-content:space-between;padding:1rem 2rem;border-bottom:1px solid rgba(255,255,255,.06);max-width:1100px;margin:0 auto}
    .logo{font-family:'Playfair Display',serif;font-size:1.5rem;color:#fff}.logo em{color:#C8882A;font-style:italic}
    .nav-links{display:flex;gap:1.5rem;font-size:.84rem}
    .nav-links a{color:rgba(220,225,232,.5);transition:color .15s}.nav-links a:hover{color:#C8882A;text-decoration:none}
    .wrap{max-width:780px;margin:0 auto;padding:3rem 2rem}
    h1{font-family:'Playfair Display',serif;font-size:2rem;line-height:1.3;margin-bottom:1rem;color:#fff}
    h2{font-family:'Playfair Display',serif;font-size:1.25rem;margin:2rem 0 .75rem;color:#fff}
    p{font-size:.92rem;color:rgba(220,225,232,.65);line-height:1.85;margin-bottom:1.1rem}
    .pill{display:inline-block;padding:.25rem .8rem;border-radius:100px;background:rgba(200,136,42,.12);color:#C8882A;font-size:.7rem;font-weight:600;letter-spacing:.07em;text-transform:uppercase;margin-bottom:1.75rem}
    .features{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:1rem;margin:1.5rem 0}
    .feat{background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.07);border-radius:10px;padding:1.1rem 1.2rem}
    .feat-icon{font-size:1.4rem;margin-bottom:.5rem}
    .feat-title{font-size:.84rem;font-weight:600;color:#fff;margin-bottom:.25rem}
    .feat-desc{font-size:.76rem;color:rgba(220,225,232,.5);line-height:1.6}
    .cta-row{display:flex;gap:1rem;flex-wrap:wrap;margin:2rem 0}
    .btn-gold{display:inline-flex;align-items:center;gap:6px;padding:.7rem 1.5rem;border-radius:8px;background:#C8882A;color:#fff;font-size:.85rem;font-weight:600;transition:background .15s}
    .btn-gold:hover{background:#A06A18;text-decoration:none}
    .btn-outline{display:inline-flex;align-items:center;gap:6px;padding:.7rem 1.5rem;border-radius:8px;border:1px solid rgba(200,136,42,.4);color:#C8882A;font-size:.85rem;font-weight:500;transition:all .15s}
    .btn-outline:hover{background:rgba(200,136,42,.08);text-decoration:none}
    .socials{display:flex;gap:1rem;flex-wrap:wrap;margin:1.5rem 0}
    .soc-btn{display:inline-flex;align-items:center;gap:8px;padding:.6rem 1.2rem;border-radius:8px;border:1px solid rgba(200,136,42,.3);color:#C8882A;font-size:.82rem;font-weight:500;transition:all .15s}
    .soc-btn:hover{background:rgba(200,136,42,.1);text-decoration:none}
    .footer{text-align:center;padding:2rem;font-size:.75rem;color:rgba(220,225,232,.25);border-top:1px solid rgba(255,255,255,.05);margin-top:3rem}
    @media(max-width:600px){.nav{padding:.75rem 1rem}.wrap{padding:2rem 1rem}.features{grid-template-columns:1fr}}
  </style></head><body>
  <div class="nav">
    <a href="/" class="logo">Implied<em>Lens</em></a>
    <div class="nav-links">
      <a href="/about">About</a>
      <a href="/blog">Blog</a>
      <a href="/login">Sign in</a>
      <a href="/signup">Get started</a>
    </div>
  </div>
  ${content}
  <div class="footer">© ${new Date().getFullYear()} ImpliedLens · Built for the self-directed investor</div>
</body></html>`;
}

app.get("/about", (_req, res) => {
  const content = `<div class="wrap">
    <span class="pill">About ImpliedLens</span>
    <h1>Institutional-grade analysis,<br>built for individual investors.</h1>
    <p>ImpliedLens gives self-directed investors access to the same analytical tools used by professional analysts — DCF valuation, SEC filing browser, earnings history, institutional holdings, analyst targets, dark pool data, and a full stock screener — without the Bloomberg price tag.</p>
    <p>Every number on the platform traces back to a primary source: SEC EDGAR filings, Yahoo Finance, and Finnhub. No black boxes. No hand-waving.</p>
    <div class="features">
      <div class="feat"><div class="feat-icon">📊</div><div class="feat-title">Financial Statements</div><div class="feat-desc">Full income, balance sheet, and cash flow from SEC EDGAR.</div></div>
      <div class="feat"><div class="feat-icon">🧮</div><div class="feat-title">DCF Valuation</div><div class="feat-desc">Multi-stage discounted cash flow model with scenario inputs.</div></div>
      <div class="feat"><div class="feat-icon">📅</div><div class="feat-title">Earnings History</div><div class="feat-desc">EPS surprises, beat/miss streaks, and forward estimates.</div></div>
      <div class="feat"><div class="feat-icon">🏛</div><div class="feat-title">Institutional Holdings</div><div class="feat-desc">13F data: who owns shares and how positions are changing.</div></div>
      <div class="feat"><div class="feat-icon">🌑</div><div class="feat-title">Dark Pool Data</div><div class="feat-desc">OTC volume, short interest, and block trade flow.</div></div>
      <div class="feat"><div class="feat-icon">🔍</div><div class="feat-title">Stock Screener</div><div class="feat-desc">Filter 200+ stocks by sector, P/E, momentum, and more.</div></div>
    </div>
    <h2>Why we built this</h2>
    <p>Professional research terminals cost thousands per month. Most individual investors rely on fragmented free tools — one site for charts, another for filings, another for fundamentals. ImpliedLens brings everything into one place, with a clean interface designed for deep research, not noise.</p>
    <div class="cta-row">
      <a href="/signup" class="btn-gold">Start free →</a>
      <a href="/" class="btn-outline">See the platform</a>
    </div>
    <h2>Follow along</h2>
    <p>We're building in public. Follow for platform updates, market insights, and investing frameworks.</p>
    <div class="socials">
      <a href="https://x.com/ImpliedLens" target="_blank" class="soc-btn">𝕏 @ImpliedLens</a>
      <a href="https://instagram.com/ImpliedLens" target="_blank" class="soc-btn">📸 @ImpliedLens</a>
    </div>
  </div>`;
  res.send(_page('About', content));
});

app.get("/blog", (_req, res) => {
  const content = `<div class="wrap">
    <span class="pill">Blog — Coming Soon</span>
    <h1>Market insights &amp;<br>platform updates.</h1>
    <p>The ImpliedLens blog is where we'll publish analysis walkthroughs, feature updates, deep-dives on valuation frameworks, and how to get the most out of the platform.</p>
    <h2>What to expect</h2>
    <div class="features">
      <div class="feat"><div class="feat-icon">📖</div><div class="feat-title">How-to guides</div><div class="feat-desc">Step-by-step walkthroughs of DCF models, screener setups, and earnings analysis.</div></div>
      <div class="feat"><div class="feat-icon">🏗</div><div class="feat-title">Platform updates</div><div class="feat-desc">What's new, what's improved, and what's coming next on ImpliedLens.</div></div>
      <div class="feat"><div class="feat-icon">💡</div><div class="feat-title">Investing frameworks</div><div class="feat-desc">Mental models for evaluating stocks, managing risk, and reading between the lines.</div></div>
    </div>
    <p>In the meantime, follow us on social for market commentary and quick platform tips.</p>
    <div class="socials">
      <a href="https://x.com/ImpliedLens" target="_blank" class="soc-btn">𝕏 @ImpliedLens</a>
      <a href="https://instagram.com/ImpliedLens" target="_blank" class="soc-btn">📸 @ImpliedLens</a>
    </div>
    <div class="cta-row">
      <a href="/signup" class="btn-gold">Try the platform free →</a>
    </div>
  </div>`;
  res.send(_page('Blog', content));
});

// SPA catch-all — must be last
app.get("*", (_req, res) => res.sendFile(path.join(__dirname, "index.html")));

// ============================================================
//  Start
// ============================================================
initDb().then(() => {
  app.listen(PORT, () => console.log(`Implied Lens running on port ${PORT}`));
}).catch(err => { console.error("DB init failed:", err); process.exit(1); });

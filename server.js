// ============================================================
//  Implied Lens -- Auth server
//  Database: Turso (free hosted libSQL / SQLite)
//    @libsql/client  (async API)
//    bcryptjs        (password hashing, 12 rounds)
//    express-session
//    stripe
// ============================================================

require("dotenv").config();

const path      = require("path");
const express   = require("express");
const session   = require("express-session");
const bcrypt    = require("bcryptjs");
const helmet    = require("helmet");
const rateLimit = require("express-rate-limit");
const { createClient } = require("@libsql/client");
const Stripe = require("stripe");
// yahoo-finance2 removed: Yahoo blocks server-side requests and hangs indefinitely.
// All data now served via Finnhub + FINRA + SEC.

const PORT                 = process.env.PORT || 3000;
const SESSION_SECRET       = process.env.SESSION_SECRET || "change-me-in-production-please";
const FINNHUB_KEY          = process.env.FINNHUB_KEY    || "d7n43rpr01qppri3flo0d7n43rpr01qppri3flog";
const BCRYPT_ROUNDS        = 12;
const STRIPE_SECRET_KEY    = process.env.STRIPE_SECRET_KEY    || "";
const STRIPE_WEBHOOK_SECRET= process.env.STRIPE_WEBHOOK_SECRET|| "";
const STRIPE_PRICE_MONTHLY = process.env.STRIPE_PRICE_MONTHLY || "";
const STRIPE_PRICE_ANNUAL  = process.env.STRIPE_PRICE_ANNUAL  || "";
const APP_URL              = process.env.APP_URL || "http://localhost:" + (process.env.PORT || 3000);
const stripe               = STRIPE_SECRET_KEY ? Stripe(STRIPE_SECRET_KEY) : null;

// ---- Turso client ----
const db = createClient({
  url:       process.env.TURSO_URL       || "file:local.db",
  authToken: process.env.TURSO_AUTH_TOKEN || undefined,
});

// ---- DB setup (runs once on startup) ----
async function initDb() {
  await db.execute(`
    CREATE TABLE IF NOT EXISTS users (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      username      TEXT    UNIQUE NOT NULL,
      email         TEXT    UNIQUE NOT NULL,
      password_hash TEXT    NOT NULL,
      created_at    TEXT    NOT NULL DEFAULT (datetime("now"))
    )
  `);
  await db.execute(`CREATE INDEX IF NOT EXISTS idx_users_email    ON users(email)`);
  await db.execute(`CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)`);
  await db.execute(`
    CREATE TABLE IF NOT EXISTS sessions (
      sid     TEXT PRIMARY KEY,
      expires INTEGER NOT NULL,
      data    TEXT NOT NULL
    )
  `);
  await db.execute(`CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires)`);

  // Add plan columns if they do not exist yet
  const planCols = [
    "plan TEXT NOT NULL DEFAULT 'free'",
    "trial_ends_at TEXT",
    "stripe_customer_id TEXT",
    "stripe_subscription_id TEXT",
    "analysis_date TEXT",
    "analysis_count INTEGER NOT NULL DEFAULT 0",
  ];
  for (const col of planCols) {
    try { await db.execute("ALTER TABLE users ADD COLUMN " + col); } catch (_) {}
  }

  // Password reset tokens
  await db.execute(`
    CREATE TABLE IF NOT EXISTS reset_tokens (
      token      TEXT PRIMARY KEY,
      user_id    INTEGER NOT NULL,
      expires_at INTEGER NOT NULL,
      used       INTEGER NOT NULL DEFAULT 0
    )
  `);

  console.log("Database initialised");
}

// ---- Plan helper ----
function getEffectivePlan(user) {
  if (user.plan === "pro") return "pro";
  if (user.plan === "trial" && user.trial_ends_at && new Date(user.trial_ends_at) > new Date()) return "trial";
  return "free";
}

// ============================================================
//  Async SQLite-backed session store for Turso
// ============================================================
class TursoStore extends session.Store {
  get(sid, cb) {
    db.execute({ sql: "SELECT data, expires FROM sessions WHERE sid = ?", args: [sid] })
      .then(res => {
        const row = res.rows[0];
        if (!row) return cb(null, null);
        if (Number(row.expires) < Date.now()) {
          db.execute({ sql: "DELETE FROM sessions WHERE sid = ?", args: [sid] }).catch(() => {});
          return cb(null, null);
        }
        try { cb(null, JSON.parse(row.data)); } catch (e) { cb(e); }
      })
      .catch(cb);
  }

  set(sid, sess, cb) {
    const expires = sess.cookie && sess.cookie.expires
      ? new Date(sess.cookie.expires).getTime()
      : Date.now() + 7 * 24 * 60 * 60 * 1000;
    db.execute({
      sql:  "INSERT INTO sessions (sid, expires, data) VALUES (?, ?, ?) ON CONFLICT(sid) DO UPDATE SET expires = excluded.expires, data = excluded.data",
      args: [sid, expires, JSON.stringify(sess)],
    })
      .then(() => cb && cb(null))
      .catch(e => cb && cb(e));
  }

  destroy(sid, cb) {
    db.execute({ sql: "DELETE FROM sessions WHERE sid = ?", args: [sid] })
      .then(() => cb && cb(null))
      .catch(e => cb && cb(e));
  }

  touch(sid, sess, cb) { this.set(sid, sess, cb); }
}

// Cleanup expired sessions every hour
setInterval(() => {
  db.execute({ sql: "DELETE FROM sessions WHERE expires < ?", args: [Date.now()] }).catch(() => {});
}, 60 * 60 * 1000);

// ---- App ----
const app = express();
app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: false }));

// ── Serve static public assets (logo, robots.txt, sitemap.xml, etc.) ──
app.use(express.static(path.join(__dirname, "public"), {
  maxAge: "7d",
  etag: true,
  setHeaders(res, filePath) {
    if (filePath.endsWith(".svg"))       res.setHeader("Content-Type", "image/svg+xml");
    if (filePath.endsWith("robots.txt")) res.setHeader("Content-Type", "text/plain");
    if (filePath.endsWith("sitemap.xml"))res.setHeader("Content-Type", "application/xml");
  }
}));

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

// ---- Validation ----
const EMAIL_RE    = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const USERNAME_RE = /^[a-zA-Z0-9_.\-]{3,32}$/;

function validateSignup({ username, email, password }) {
  const errors = [];
  if (!username || !USERNAME_RE.test(username))
    errors.push("Username must be 3-32 chars (letters, numbers, _ . -).");
  if (!email || !EMAIL_RE.test(email))
    errors.push("Please enter a valid email address.");
  if (!password || password.length < 8)
    errors.push("Password must be at least 8 characters.");
  if (password && password.length > 200)
    errors.push("Password is too long.");
  return errors;
}

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many attempts. Try again in 15 minutes." },
});

// ============================================================
//  Auth API
// ============================================================
const api = express.Router();
api.use(authLimiter);

api.post("/auth/signup", async (req, res) => {
  try {
    const username = String(req.body.username || "").trim();
    const email    = String(req.body.email    || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    const errors = validateSignup({ username, email, password });
    if (errors.length) return res.status(400).json({ error: errors.join(" ") });

    const byUser  = await db.execute({ sql: "SELECT id FROM users WHERE username = ? LIMIT 1", args: [username] });
    if (byUser.rows.length) return res.status(409).json({ error: "That username is already taken." });

    const byEmail = await db.execute({ sql: "SELECT id FROM users WHERE email = ? LIMIT 1", args: [email] });
    if (byEmail.rows.length) return res.status(409).json({ error: "An account with that email already exists." });

    const hash = await bcrypt.hash(password, BCRYPT_ROUNDS);
    let ins;
    try {
      ins = await db.execute({ sql: "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)", args: [username, email, hash] });
    } catch (dbErr) {
      const msg = (dbErr.message || "").toLowerCase();
      if (msg.includes("unique") && msg.includes("username"))
        return res.status(409).json({ error: "That username is already taken." });
      if (msg.includes("unique") && msg.includes("email"))
        return res.status(409).json({ error: "An account with that email already exists." });
      if (msg.includes("unique"))
        return res.status(409).json({ error: "That username or email is already taken." });
      throw dbErr;
    }
    const userId = Number(ins.lastInsertRowid);

    const userRow = await db.execute({ sql: "SELECT id, username, email, created_at FROM users WHERE id = ?", args: [userId] });
    req.session.userId = userId;
    return res.status(201).json({ user: userRow.rows[0] || null });
  } catch (err) {
    console.error("signup error:", err);
    return res.status(500).json({ error: "Could not create account." });
  }
});

api.post("/auth/login", async (req, res) => {
  try {
    const identifier = String(req.body.identifier || req.body.username || req.body.email || "").trim();
    const password   = String(req.body.password || "");

    if (!identifier || !password)
      return res.status(400).json({ error: "Please enter your username/email and password." });

    const lookup = identifier.includes("@") ? identifier.toLowerCase() : identifier;
    const result = await db.execute({ sql: "SELECT id, username, email, password_hash FROM users WHERE username = ? OR email = ? LIMIT 1", args: [lookup, lookup] });
    const row = result.rows[0];
    if (!row) return res.status(401).json({ error: "No account found with that username or email." });

    const ok = await bcrypt.compare(password, row.password_hash);
    if (!ok) return res.status(401).json({ error: "Incorrect password." });

    req.session.userId = Number(row.id);
    return res.json({ user: { id: Number(row.id), username: row.username, email: row.email } });
  } catch (err) {
    console.error("login error:", err);
    return res.status(500).json({ error: "Login failed." });
  }
});

api.post("/auth/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("il.sid");
    res.json({ ok: true });
  });
});

api.get("/auth/me", async (req, res) => {
  if (!req.session.userId) return res.json({ user: null });
  try {
    const result = await db.execute({
      sql: "SELECT id, username, email, created_at, plan, trial_ends_at FROM users WHERE id = ?",
      args: [req.session.userId],
    });
    const user = result.rows[0] || null;
    if (user) user.effectivePlan = getEffectivePlan(user);
    return res.json({ user });
  } catch (err) {
    return res.json({ user: null });
  }
});

app.use("/api", api);

// ============================================================
//  Stripe -- checkout + webhook
// ============================================================
app.post("/api/stripe/create-checkout", async (req, res) => {
  if (!stripe) return res.status(503).json({ error: "Payments not configured yet." });
  if (!req.session.userId) return res.status(401).json({ error: "Login required." });

  const priceId = req.body.annual ? STRIPE_PRICE_ANNUAL : STRIPE_PRICE_MONTHLY;
  if (!priceId) return res.status(503).json({ error: "Price not configured." });

  try {
    const userRow = await db.execute({
      sql: "SELECT id, email, stripe_customer_id FROM users WHERE id = ?",
      args: [req.session.userId],
    });
    const user = userRow.rows[0];
    if (!user) return res.status(404).json({ error: "User not found." });

    const params = {
      mode: "subscription",
      payment_method_types: ["card"],
      line_items: [{ price: priceId, quantity: 1 }],
      subscription_data: { trial_period_days: 7 },
      success_url: APP_URL + "/?upgraded=1",
      cancel_url: APP_URL + "/",
      metadata: { userId: String(req.session.userId) },
    };
    if (user.stripe_customer_id) {
      params.customer = user.stripe_customer_id;
    } else {
      params.customer_email = user.email;
    }

    const checkoutSession = await stripe.checkout.sessions.create(params);
    res.json({ url: checkoutSession.url });
  } catch (err) {
    console.error("Stripe checkout error:", err);
    res.status(500).json({ error: "Could not create checkout session." });
  }
});

app.post("/api/stripe/webhook", async (req, res) => {
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
    switch (event.type) {
      case "checkout.session.completed": {
        const sess = event.data.object;
        const userId = sess.metadata && sess.metadata.userId;
        if (!userId || !sess.subscription) break;
        const sub = await stripe.subscriptions.retrieve(sess.subscription);
        const plan = sub.status === "trialing" ? "trial" : "pro";
        const trialEnd = sub.trial_end ? new Date(sub.trial_end * 1000).toISOString() : null;
        await db.execute({
          sql: "UPDATE users SET plan=?, trial_ends_at=?, stripe_customer_id=?, stripe_subscription_id=? WHERE id=?",
          args: [plan, trialEnd, sess.customer, sess.subscription, userId],
        });
        break;
      }
      case "customer.subscription.updated": {
        const sub = event.data.object;
        const r = await db.execute({ sql: "SELECT id FROM users WHERE stripe_customer_id=?", args: [sub.customer] });
        if (!r.rows.length) break;
        let plan = "free";
        if (sub.status === "active") plan = "pro";
        else if (sub.status === "trialing") plan = "trial";
        const trialEnd = sub.trial_end ? new Date(sub.trial_end * 1000).toISOString() : null;
        await db.execute({ sql: "UPDATE users SET plan=?, trial_ends_at=? WHERE id=?", args: [plan, trialEnd, r.rows[0].id] });
        break;
      }
      case "customer.subscription.deleted": {
        const sub = event.data.object;
        const r = await db.execute({ sql: "SELECT id FROM users WHERE stripe_customer_id=?", args: [sub.customer] });
        if (!r.rows.length) break;
        await db.execute({ sql: "UPDATE users SET plan='free', trial_ends_at=NULL WHERE id=?", args: [r.rows[0].id] });
        break;
      }
      case "invoice.payment_failed": {
        const inv = event.data.object;
        const r = await db.execute({ sql: "SELECT id FROM users WHERE stripe_customer_id=?", args: [inv.customer] });
        if (!r.rows.length) break;
        await db.execute({ sql: "UPDATE users SET plan='free' WHERE id=?", args: [r.rows[0].id] });
        break;
      }
    }
  } catch (err) {
    console.error("Webhook handler error:", err);
  }

  res.json({ received: true });
});

// ============================================================
//  Finnhub proxy -- news
// ============================================================
app.get("/api/news/:ticker", async (req, res) => {
  try {
    const ticker = req.params.ticker.toUpperCase();
    const to   = new Date().toISOString().split("T")[0];
    const from = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString().split("T")[0];
    const url  = "https://finnhub.io/api/v1/company-news?symbol=" + ticker + "&from=" + from + "&to=" + to + "&token=" + FINNHUB_KEY;
    const r    = await fetch(url);
    const data = await r.json();
    res.json(Array.isArray(data) ? data.slice(0, 10) : []);
  } catch (e) {
    console.error("news error:", e);
    res.json([]);
  }
});

// ============================================================
//  Finnhub proxy -- screener (top 35 stocks)
// ============================================================
const SCREENER_TICKERS = [
  "AAPL","MSFT","NVDA","GOOGL","AMZN","META","TSLA","BRK-B","LLY","JPM",
  "V","UNH","XOM","MA","AVGO","JNJ","PG","HD","COST","MRK",
  "ABBV","CVX","PEP","KO","WMT","BAC","CRM","TMO","ORCL","AMD",
  "NFLX","ADBE","QCOM","TXN","INTC"
];

app.get("/api/screener", async (req, res) => {
  try {
    const results = await Promise.allSettled(
      SCREENER_TICKERS.map(async (ticker) => {
        const [qRes, mRes] = await Promise.all([
          fetch("https://finnhub.io/api/v1/quote?symbol=" + ticker + "&token=" + FINNHUB_KEY),
          fetch("https://finnhub.io/api/v1/stock/metric?symbol=" + ticker + "&metric=all&token=" + FINNHUB_KEY)
        ]);
        const [q, md] = await Promise.all([qRes.json(), mRes.json()]);
        const m = md.metric || {};
        return {
          ticker,
          price: q.c || 0,
          change1D: q.pc > 0 ? ((q.c - q.pc) / q.pc * 100) : 0,
          change1Y: m["52WeekPriceReturnDaily"] || null,
          marketCap: m.marketCapitalization ? m.marketCapitalization * 1e6 : null,
          pe: m.peBasicExclExtraTTM || m.peTTM || null,
          pb: m.pbQuarterly || null,
          dividendYield: m.dividendYieldIndicatedAnnual || 0,
          beta: m.beta || null,
        };
      })
    );
    const stocks = results
      .filter(r => r.status === "fulfilled" && r.value.price > 0)
      .map(r => r.value);
    res.json(stocks);
  } catch (e) {
    console.error("screener error:", e);
    res.status(500).json({ error: "Screener fetch failed" });
  }
});


// ============================================================
//  Password reset
// ============================================================
const crypto = require('crypto');

api.post('/auth/forgot-password', async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  if (!email) return res.status(400).json({ error: 'Email is required.' });
  try {
    const result = await db.execute({ sql: 'SELECT id FROM users WHERE email = ?', args: [email] });
    // Always return success to prevent email enumeration
    if (!result.rows.length) return res.json({ ok: true });

    const token   = crypto.randomBytes(32).toString('hex');
    const expires = Date.now() + 60 * 60 * 1000; // 1 hour
    await db.execute({
      sql:  'INSERT INTO reset_tokens (token, user_id, expires_at) VALUES (?, ?, ?)',
      args: [token, result.rows[0].id, expires],
    });
    const resetUrl = APP_URL + '/reset-password?token=' + token;
    // TODO: Send email with resetUrl. For now, log it so you can find it in Render logs.
    console.log('PASSWORD RESET LINK for', email, ':', resetUrl);
    return res.json({ ok: true });
  } catch (err) {
    console.error('forgot-password error:', err);
    return res.status(500).json({ error: 'Something went wrong.' });
  }
});

api.post('/auth/reset-password', async (req, res) => {
  const { token, password } = req.body;
  if (!token || !password || password.length < 8)
    return res.status(400).json({ error: 'Invalid request.' });
  try {
    const r = await db.execute({
      sql:  'SELECT user_id, expires_at, used FROM reset_tokens WHERE token = ?',
      args: [token],
    });
    const row = r.rows[0];
    if (!row)                         return res.status(400).json({ error: 'Invalid or expired link.' });
    if (row.used)                     return res.status(400).json({ error: 'This link has already been used.' });
    if (Number(row.expires_at) < Date.now()) return res.status(400).json({ error: 'This link has expired. Please request a new one.' });

    const hash = await bcrypt.hash(password, BCRYPT_ROUNDS);
    await db.execute({ sql: 'UPDATE users SET password_hash = ? WHERE id = ?', args: [hash, row.user_id] });
    await db.execute({ sql: 'UPDATE reset_tokens SET used = 1 WHERE token = ?', args: [token] });
    return res.json({ ok: true });
  } catch (err) {
    console.error('reset-password error:', err);
    return res.status(500).json({ error: 'Could not reset password.' });
  }
});

// ============================================================
//  Change password (logged-in user)
// ============================================================
api.post('/auth/change-password', async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Not logged in.' });
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword || newPassword.length < 8)
    return res.status(400).json({ error: 'New password must be at least 8 characters.' });
  try {
    const r = await db.execute({
      sql: 'SELECT password_hash FROM users WHERE id = ?',
      args: [req.session.userId],
    });
    const user = r.rows[0];
    if (!user) return res.status(404).json({ error: 'User not found.' });
    const match = await bcrypt.compare(currentPassword, user.password_hash);
    if (!match) return res.status(400).json({ error: 'Current password is incorrect.' });
    const hash = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);
    await db.execute({ sql: 'UPDATE users SET password_hash = ? WHERE id = ?', args: [hash, req.session.userId] });
    return res.json({ ok: true });
  } catch (err) {
    console.error('change-password error:', err);
    return res.status(500).json({ error: 'Something went wrong.' });
  }
});

// ============================================================
//  Stripe billing portal
// ============================================================
app.get('/api/stripe/portal', async (req, res) => {
  if (!stripe) return res.status(503).json({ error: 'Payments not configured.' });
  if (!req.session.userId) return res.redirect('/login');
  try {
    const r = await db.execute({
      sql: 'SELECT stripe_customer_id FROM users WHERE id = ?',
      args: [req.session.userId],
    });
    const customerId = r.rows[0]?.stripe_customer_id;
    if (!customerId) return res.redirect('/#pricing');
    const session = await stripe.billingPortal.sessions.create({
      customer:   customerId,
      return_url: APP_URL + '/',
    });
    res.redirect(session.url);
  } catch (err) {
    console.error('portal error:', err);
    res.redirect('/#pricing');
  }
});

// ============================================================
//  Yahoo Finance proxy (avoids CORS issues on client)
// ============================================================
// Helper: fetch with timeout (AbortController)
async function fetchWithTimeout(url, options = {}, timeoutMs = 5000) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, { ...options, signal: ctrl.signal });
    clearTimeout(timer);
    return res;
  } catch (e) {
    clearTimeout(timer);
    throw e;
  }
}

// ============================================================
//  Analysis rate limiter  (free = 5/day, guest = 2/day)
// ============================================================
const FREE_DAILY_LIMIT  = 5;
const GUEST_DAILY_LIMIT = 2;

async function checkAnalysisLimit(req, res, next) {
  const today = new Date().toISOString().slice(0, 10); // 'YYYY-MM-DD'

  if (req.session.userId) {
    // ── Logged-in user ──────────────────────────────────────
    let row;
    try {
      const r = await db.execute({
        sql:  'SELECT plan, trial_ends_at, analysis_date, analysis_count FROM users WHERE id = ?',
        args: [req.session.userId],
      });
      row = r.rows[0];
    } catch (_) { return next(); } // DB error → don't block the user

    if (!row) return next();

    const plan = getEffectivePlan(row);
    if (plan === 'pro' || plan === 'trial') {
      res.setHeader('X-Plan', plan);
      return next(); // unlimited
    }

    // Free plan — check daily count
    const count     = row.analysis_date === today ? (Number(row.analysis_count) || 0) : 0;
    const remaining = FREE_DAILY_LIMIT - count;

    if (remaining <= 0) {
      return res.status(429).json({
        error:        'Daily limit reached',
        limitReached: true,
        limit:        FREE_DAILY_LIMIT,
        remaining:    0,
        plan:         'free',
      });
    }

    // Increment counter
    try {
      await db.execute({
        sql:  'UPDATE users SET analysis_date = ?, analysis_count = ? WHERE id = ?',
        args: [today, count + 1, req.session.userId],
      });
    } catch (_) {}

    res.setHeader('X-Plan',               plan);
    res.setHeader('X-Analyses-Used',      String(count + 1));
    res.setHeader('X-Analyses-Remaining', String(remaining - 1));
    res.setHeader('X-Analyses-Limit',     String(FREE_DAILY_LIMIT));
    return next();

  } else {
    // ── Guest (not logged in) — track by session ────────────
    if (req.session.guestDate !== today) {
      req.session.guestDate  = today;
      req.session.guestCount = 0;
    }
    const count     = req.session.guestCount || 0;
    const remaining = GUEST_DAILY_LIMIT - count;

    if (remaining <= 0) {
      return res.status(429).json({
        error:         'Daily limit reached',
        limitReached:  true,
        limit:         GUEST_DAILY_LIMIT,
        remaining:     0,
        requiresLogin: true,
        plan:          'guest',
      });
    }

    req.session.guestCount = count + 1;
    res.setHeader('X-Plan',               'guest');
    res.setHeader('X-Analyses-Used',      String(count + 1));
    res.setHeader('X-Analyses-Remaining', String(remaining - 1));
    res.setHeader('X-Analyses-Limit',     String(GUEST_DAILY_LIMIT));
    return next();
  }
}

app.get('/api/quote/:ticker', checkAnalysisLimit, async (req, res) => {
  try {
    const ticker = req.params.ticker.toUpperCase().replace(/[^A-Z0-9.\-^]/g, '');
    if (!ticker) return res.status(400).json({ error: 'No ticker' });
    const range = (req.query.range || '1y').replace(/[^a-z0-9]/gi, '');

    const YH = {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
      'Accept': 'application/json, text/plain, */*',
      'Accept-Language': 'en-US,en;q=0.9',
      'Origin': 'https://finance.yahoo.com',
      'Referer': 'https://finance.yahoo.com/',
    };

    let data = null;

    // Attempt 1: Yahoo Finance v8 chart (query2) — 4-second timeout so we fail fast if blocked
    try {
      const u = `https://query2.finance.yahoo.com/v8/finance/chart/${encodeURIComponent(ticker)}?interval=1d&range=${range}&includePrePost=false`;
      const r = await fetchWithTimeout(u, { headers: YH }, 4000);
      if (r.ok) {
        const j = await r.json();
        if (j?.chart?.result?.[0]?.timestamp?.length) {
          console.log(`[quote] Yahoo query2 OK for ${ticker}`);
          data = j;
        }
      } else {
        console.log(`[quote] Yahoo query2 ${r.status} for ${ticker}`);
      }
    } catch (e) {
      console.log(`[quote] Yahoo query2 failed for ${ticker}: ${e.message}`);
    }

    // Attempt 2: Yahoo Finance v8 chart (query1) — 4-second timeout
    if (!data) {
      try {
        const u = `https://query1.finance.yahoo.com/v8/finance/chart/${encodeURIComponent(ticker)}?interval=1d&range=${range}&includePrePost=false`;
        const r = await fetchWithTimeout(u, { headers: YH }, 4000);
        if (r.ok) {
          const j = await r.json();
          if (j?.chart?.result?.[0]?.timestamp?.length) {
            console.log(`[quote] Yahoo query1 OK for ${ticker}`);
            data = j;
          }
        } else {
          console.log(`[quote] Yahoo query1 ${r.status} for ${ticker}`);
        }
      } catch (e) {
        console.log(`[quote] Yahoo query1 failed for ${ticker}: ${e.message}`);
      }
    }

    // Attempt 3: Yahoo Finance v7 CSV download — different endpoint, sometimes bypasses blocks
    if (!data) {
      try {
        const now2   = Math.floor(Date.now() / 1000);
        const rangeSecs = { '1d':86400,'5d':5*86400,'1mo':30*86400,'3mo':90*86400,'6mo':180*86400,'1y':365*86400,'2y':730*86400,'5y':1825*86400 };
        const period1 = now2 - (rangeSecs[range] || 365*86400);
        const csvUrl = `https://query1.finance.yahoo.com/v7/finance/download/${encodeURIComponent(ticker)}?period1=${period1}&period2=${now2}&interval=1d&events=history&includeAdjustedClose=true`;
        const r = await fetchWithTimeout(csvUrl, { headers: YH }, 4000);
        if (r.ok) {
          const csv = await r.text();
          const lines = csv.trim().split('\n').slice(1).filter(l => l && !l.startsWith('Date') && !l.includes('<') && !l.startsWith('No data'));
          if (lines.length > 2) {
            const timestamps=[], opens=[], highs=[], lows=[], closes=[], vols=[];
            for (const line of lines) {
              const [date,,o,h,l,c,,v] = line.split(',');  // Date,Open,High,Low,Close,Adj Close,Volume
              if (!date || !c || isNaN(parseFloat(c))) continue;
              timestamps.push(Math.floor(new Date(date).getTime()/1000));
              opens.push(parseFloat(o)||null); highs.push(parseFloat(h)||null);
              lows.push(parseFloat(l)||null);  closes.push(parseFloat(c));
              vols.push(parseInt(v)||null);
            }
            if (timestamps.length > 2) {
              console.log(`[quote] Yahoo v7 CSV OK for ${ticker} (${timestamps.length} rows)`);
              data = { chart: { result: [{ meta: {
                symbol: ticker, currency: 'USD', exchangeName: '', instrumentType: 'EQUITY',
                longName: ticker, shortName: ticker,
                regularMarketPrice: closes[closes.length-1],
                previousClose: closes[closes.length-2] || null,
                chartPreviousClose: closes[closes.length-2] || null,
              }, timestamp: timestamps, indicators: {
                quote: [{ open: opens, high: highs, low: lows, close: closes, volume: vols }],
                adjclose: [{ adjclose: closes }]
              }}], error: null }};
            }
          }
        } else {
          console.log(`[quote] Yahoo v7 CSV ${r.status} for ${ticker}`);
        }
      } catch (e) {
        console.log(`[quote] Yahoo v7 CSV failed for ${ticker}: ${e.message}`);
      }
    }

    // Attempt 4: Stooq CSV (free, no auth, works from server IPs)
    if (!data) {
      try {
        const now3 = new Date();
        const rangeDays = { '1d':5,'5d':10,'1mo':35,'3mo':95,'6mo':185,'1y':370,'2y':740,'5y':1830 };
        const days = rangeDays[range] || 370;
        const from = new Date(now3 - days * 86400000);
        const fmt  = d => d.toISOString().slice(0,10).replace(/-/g,'');
        const stooqUrl = `https://stooq.com/q/d/l/?s=${encodeURIComponent(ticker)}.US&d1=${fmt(from)}&d2=${fmt(now3)}&i=d`;
        const r = await fetchWithTimeout(stooqUrl, { headers: { 'User-Agent': 'Mozilla/5.0' } }, 8000);
        if (r.ok) {
          const csv = await r.text();
          const lines = csv.trim().split('\n').slice(1).filter(l => l && !l.startsWith('No data') && !l.includes('<'));
          if (lines.length > 2) {
            const timestamps=[], opens=[], highs=[], lows=[], closes=[], vols=[];
            for (const line of lines) {
              const [date,o,h,l,c,v] = line.split(',');
              if (!date || !c || isNaN(parseFloat(c))) continue;
              timestamps.push(Math.floor(new Date(date).getTime()/1000));
              opens.push(parseFloat(o)||null); highs.push(parseFloat(h)||null);
              lows.push(parseFloat(l)||null);  closes.push(parseFloat(c));
              vols.push(parseInt(v)||null);
            }
            if (timestamps.length > 2) {
              console.log(`[quote] Stooq OK for ${ticker} (${timestamps.length} rows)`);
              const FH = FINNHUB_KEY;
              const [qr, pr, mr] = await Promise.all([
                fetchWithTimeout(`https://finnhub.io/api/v1/quote?symbol=${ticker}&token=${FH}`, {}, 4000).catch(()=>null),
                fetchWithTimeout(`https://finnhub.io/api/v1/stock/profile2?symbol=${ticker}&token=${FH}`, {}, 4000).catch(()=>null),
                fetchWithTimeout(`https://finnhub.io/api/v1/stock/metric?symbol=${ticker}&metric=all&token=${FH}`, {}, 4000).catch(()=>null),
              ]);
              const qt = qr?.ok ? await qr.json().catch(()=>({})) : {};
              const pf = pr?.ok ? await pr.json().catch(()=>({})) : {};
              const mt = mr?.ok ? await mr.json().catch(()=>({})) : {};
              const m2 = mt.metric || {};
              const price2  = qt.c  || closes[closes.length-1];
              const shares2 = pf.shareOutstanding ? pf.shareOutstanding * 1e6 : null;
              data = { chart: { result: [{ meta: {
                symbol: ticker, currency: pf.currency||'USD', exchangeName: pf.exchange||'',
                instrumentType: 'EQUITY', longName: pf.name||ticker, shortName: pf.name||ticker,
                regularMarketPrice: price2, previousClose: qt.pc||null, chartPreviousClose: qt.pc||null,
                regularMarketVolume: qt.v||vols[vols.length-1]||null,
                averageDailyVolume3Month: m2['3MonthAverageTradingVolume'] ? m2['3MonthAverageTradingVolume']*1e6 : null,
                marketCap: shares2 && price2 ? shares2*price2 : null,
                fiftyTwoWeekHigh: m2['52WeekHigh']||null, fiftyTwoWeekLow: m2['52WeekLow']||null,
                trailingPE: m2.peNormalizedAnnual||m2.peBasicExclExtraTTM||null,
              }, timestamp: timestamps, indicators: {
                quote: [{ open: opens, high: highs, low: lows, close: closes, volume: vols }],
                adjclose: [{ adjclose: closes }]
              }}], error: null }};
            }
          } else {
            console.log(`[quote] Stooq returned no rows for ${ticker}: ${csv.slice(0,200)}`);
          }
        } else {
          console.log(`[quote] Stooq ${r.status} for ${ticker}`);
        }
      } catch (e) {
        console.log(`[quote] Stooq failed for ${ticker}: ${e.message}`);
      }
    }

    if (!data) {
      console.log(`[quote] All sources exhausted for ${ticker}`);
      return res.status(404).json({ error: `No price data found for "${ticker}". Check the ticker symbol.` });
    }

    // Augment meta with Finnhub real-time data if missing
    const result = data.chart.result[0];
    if (!result.meta.marketCap || !result.meta.fiftyTwoWeekHigh) {
      try {
        const FH = FINNHUB_KEY;
        const [qr, pr, mr] = await Promise.all([
          fetchWithTimeout(`https://finnhub.io/api/v1/quote?symbol=${ticker}&token=${FH}`, {}, 4000).catch(()=>null),
          fetchWithTimeout(`https://finnhub.io/api/v1/stock/profile2?symbol=${ticker}&token=${FH}`, {}, 4000).catch(()=>null),
          fetchWithTimeout(`https://finnhub.io/api/v1/stock/metric?symbol=${ticker}&metric=all&token=${FH}`, {}, 4000).catch(()=>null),
        ]);
        const qt = qr?.ok ? await qr.json().catch(()=>({})) : {};
        const pf = pr?.ok ? await pr.json().catch(()=>({})) : {};
        const mt = mr?.ok ? await mr.json().catch(()=>({})) : {};
        const m  = mt.metric || {};
        const shares = pf.shareOutstanding ? pf.shareOutstanding*1e6 : null;
        const price  = qt.c || result.meta.regularMarketPrice;
        result.meta.longName              = result.meta.longName  || pf.name || ticker;
        result.meta.shortName             = result.meta.shortName || pf.name || ticker;
        result.meta.regularMarketPrice    = price || result.meta.regularMarketPrice;
        result.meta.previousClose         = qt.pc || result.meta.previousClose;
        result.meta.chartPreviousClose    = qt.pc || result.meta.chartPreviousClose;
        result.meta.regularMarketVolume   = qt.v  || result.meta.regularMarketVolume;
        result.meta.marketCap             = (shares && price) ? shares*price : result.meta.marketCap;
        result.meta.fiftyTwoWeekHigh      = m['52WeekHigh']  || result.meta.fiftyTwoWeekHigh;
        result.meta.fiftyTwoWeekLow       = m['52WeekLow']   || result.meta.fiftyTwoWeekLow;
        result.meta.trailingPE            = m.peNormalizedAnnual || m.peBasicExclExtraTTM || result.meta.trailingPE;
        result.meta.averageDailyVolume3Month = m['3MonthAverageTradingVolume']
          ? m['3MonthAverageTradingVolume']*1e6 : result.meta.averageDailyVolume3Month;
      } catch (_) {}
    }

    res.json(data);
  } catch (e) {
    console.error('[quote] proxy error:', e.message);
    res.status(500).json({ error: 'Failed to fetch quote data: ' + e.message });
  }
});

// ============================================================
//  Yahoo Finance quoteSummary helper  (used by financials/earnings/analyst)
// ============================================================
// Yahoo Finance blocks server-side requests — always return null so Finnhub fallbacks run immediately.
async function getYahooSummary(_ticker, _modules) {
  return null;
}

// ============================================================
//  Financials proxy  (Finnhub financials-reported + metric)
// ============================================================
app.get('/api/financials/:ticker', async (req, res) => {
  const ticker = req.params.ticker.toUpperCase().replace(/[^A-Z0-9.]/g, '');
  const UA = 'ImpliedLens/1.0 brettpeterson6216@gmail.com';

  try {
    // Step 1: Resolve CIK from SEC's authoritative ticker map
    let cik = null;
    try {
      const r = await fetchWithTimeout('https://www.sec.gov/files/company_tickers.json', { headers: { 'User-Agent': UA } }, 6000);
      if (r.ok) {
        const data = await r.json();
        const entry = Object.values(data).find(e => e.ticker?.toUpperCase() === ticker);
        if (entry) cik = String(entry.cik_str).padStart(10, '0');
      }
    } catch(_) {}

    // Fallback: EDGAR full-text search
    if (!cik) {
      try {
        const r = await fetchWithTimeout(
          `https://efts.sec.gov/LATEST/search-index?q=%22${encodeURIComponent(ticker)}%22&forms=10-K`,
          { headers: { 'User-Agent': UA, 'Accept': 'application/json' } }, 5000
        );
        if (r.ok) {
          const d = await r.json();
          const hit = (d?.hits?.hits || [])[0];
          if (hit?._source?.entity_id) cik = String(hit._source.entity_id).padStart(10, '0');
        }
      } catch(_) {}
    }

    if (!cik) {
      console.log(`[financials] ${ticker}: CIK not found (ETF/fund)`);
      return res.json({ noStatements: true, quoteSummary: { result: [{ defaultKeyStatistics:{}, financialData:{} }] } });
    }

    console.log(`[financials] ${ticker}: CIK=${cik}`);

    // Step 2: Fetch XBRL company facts from SEC EDGAR (free, no auth)
    const factsResp = await fetchWithTimeout(
      `https://data.sec.gov/api/xbrl/companyfacts/CIK${cik}.json`,
      { headers: { 'User-Agent': UA } }, 15000
    );
    if (!factsResp.ok) throw new Error(`companyfacts ${factsResp.status}`);
    const facts = await factsResp.json();
    const gaap = facts.facts?.['us-gaap'] || {};

    // Step 3: Extract annual (10-K) series for a list of concept names
    function annualSeries(concepts) {
      for (const concept of concepts) {
        const units = gaap[concept]?.units?.USD || gaap[concept]?.units?.shares || [];
        const byYear = {};
        for (const u of units) {
          if (u.form !== '10-K') continue;
          const yr = u.fy || u.end?.slice(0, 4);
          if (!yr) continue;
          if (!byYear[yr] || u.filed > byYear[yr].filed) byYear[yr] = u;
        }
        const sorted = Object.values(byYear)
          .sort((a, b) => (b.fy || b.end) > (a.fy || a.end) ? 1 : -1)
          .slice(0, 4);
        if (sorted.length) return sorted;
      }
      return [];
    }

    // Step 4: Pull series for each financial line item
    const revSeries    = annualSeries(['Revenues','RevenueFromContractWithCustomerExcludingAssessedTax','SalesRevenueNet','RevenueFromContractWithCustomerIncludingAssessedTax']);
    const cogsSeries   = annualSeries(['CostOfGoodsAndServicesSold','CostOfRevenue','CostOfGoodsSold']);
    const gpSeries     = annualSeries(['GrossProfit']);
    const opexSeries   = annualSeries(['OperatingExpenses','CostsAndExpenses']);
    const opinSeries   = annualSeries(['OperatingIncomeLoss']);
    const niSeries     = annualSeries(['NetIncomeLoss','ProfitLoss']);
    const epsBasSeries = annualSeries(['EarningsPerShareBasic']);
    const epsDilSeries = annualSeries(['EarningsPerShareDiluted']);
    const cashSeries   = annualSeries(['CashAndCashEquivalentsAtCarryingValue','Cash']);
    const stiSeries    = annualSeries(['ShortTermInvestments','AvailableForSaleSecuritiesCurrent']);
    const tcaSeries    = annualSeries(['AssetsCurrent']);
    const tasSeries    = annualSeries(['Assets']);
    const ltdSeries    = annualSeries(['LongTermDebt','LongTermDebtNoncurrent']);
    const tlbSeries    = annualSeries(['Liabilities']);
    const equSeries    = annualSeries(['StockholdersEquity','StockholdersEquityIncludingPortionAttributableToNoncontrollingInterest']);
    const ocfSeries    = annualSeries(['NetCashProvidedByUsedInOperatingActivities']);
    const capexSeries  = annualSeries(['PaymentsToAcquirePropertyPlantAndEquipment','CapitalExpenditures']);
    const icfSeries    = annualSeries(['NetCashProvidedByUsedInInvestingActivities']);
    const fcfSeries    = annualSeries(['NetCashProvidedByUsedInFinancingActivities']);
    const cchSeries    = annualSeries(['CashAndCashEquivalentsPeriodIncreaseDecrease','NetIncreaseDecreaseInCashAndCashEquivalents']);

    const backbone = revSeries.length ? revSeries : (niSeries.length ? niSeries : opinSeries);
    if (!backbone.length) {
      console.log(`[financials] ${ticker}: no annual XBRL data found (ETF?)`);
      return res.json({ noStatements: true, quoteSummary: { result: [{ defaultKeyStatistics:{}, financialData:{} }] } });
    }

    const years = backbone.map(b => String(b.fy || b.end?.slice(0, 4)));

    function pickVal(series, yr) {
      const e = series.find(s => String(s.fy || s.end?.slice(0, 4)) === yr);
      return e ? { raw: e.val } : null;
    }

    const incS = years.map(yr => ({
      endDate:               { fmt: yr, raw: Math.floor(new Date(`${yr}-12-31`).getTime() / 1000) },
      totalRevenue:          pickVal(revSeries,    yr),
      costOfRevenue:         pickVal(cogsSeries,   yr),
      grossProfit:           pickVal(gpSeries,     yr),
      totalOperatingExpenses:pickVal(opexSeries,   yr),
      operatingIncome:       pickVal(opinSeries,   yr),
      netIncome:             pickVal(niSeries,     yr),
      basicEps:              pickVal(epsBasSeries, yr),
      dilutedEps:            pickVal(epsDilSeries, yr),
    }));

    const balS = years.map(yr => ({
      endDate:               { fmt: yr, raw: Math.floor(new Date(`${yr}-12-31`).getTime() / 1000) },
      cash:                  pickVal(cashSeries, yr),
      shortTermInvestments:  pickVal(stiSeries,  yr),
      totalCurrentAssets:    pickVal(tcaSeries,  yr),
      totalAssets:           pickVal(tasSeries,  yr),
      longTermDebt:          pickVal(ltdSeries,  yr),
      totalLiab:             pickVal(tlbSeries,  yr),
      totalStockholderEquity:pickVal(equSeries,  yr),
    }));

    const cfS = years.map(yr => {
      const capexEntry = capexSeries.find(s => String(s.fy || s.end?.slice(0, 4)) === yr);
      return {
        endDate:               { fmt: yr, raw: Math.floor(new Date(`${yr}-12-31`).getTime() / 1000) },
        totalCashFromOperatingActivities:      pickVal(ocfSeries,  yr),
        capitalExpenditures:                   capexEntry ? { raw: -Math.abs(capexEntry.val) } : null,
        totalCashflowsFromInvestingActivities: pickVal(icfSeries,  yr),
        totalCashFromFinancingActivities:      pickVal(fcfSeries,  yr),
        changeInCash:                          pickVal(cchSeries,  yr),
      };
    });

    // Step 5: Augment with Finnhub metric ratios (valuation multiples etc.)
    let m = {}, shares = null;
    try {
      const [mr, pr] = await Promise.all([
        fetchWithTimeout(`https://finnhub.io/api/v1/stock/metric?symbol=${ticker}&metric=all&token=${FINNHUB_KEY}`, {}, 5000),
        fetchWithTimeout(`https://finnhub.io/api/v1/stock/profile2?symbol=${ticker}&token=${FINNHUB_KEY}`, {}, 5000),
      ]);
      const [md, pd] = await Promise.all([mr.json().catch(()=>({})), pr.json().catch(()=>({}))]);
      m = md.metric || {};
      shares = pd.shareOutstanding ? pd.shareOutstanding * 1e6 : null;
    } catch(_) {}

    const n   = v => (v != null && !isNaN(v)) ? { raw: v } : null;
    const pct = v => (v != null && !isNaN(v)) ? { raw: v / 100 } : null;

    const defaultKeyStatistics = {
      trailingPE:                   n(m.peNormalizedAnnual || m.peBasicExclExtraTTM),
      forwardPE:                    null,
      priceToBook:                  n(m.pbQuarterly),
      priceToSalesTrailing12Months: n(m.psTTM),
      enterpriseToEbitda:           n(m.evEbitdaTTM),
      enterpriseToRevenue:          null,
      sharesOutstanding:            n(shares),
      bookValuePerShare:            n(m.bookValuePerShareQuarterly),
    };
    const financialData = {
      grossMargins:     pct(m.grossMarginAnnual    ?? m.grossMarginTTM),
      operatingMargins: pct(m.operatingProfitMarginAnnual ?? m.operatingProfitMarginTTM),
      profitMargins:    pct(m.netProfitMarginAnnual ?? m.netProfitMarginTTM),
      returnOnEquity:   pct(m.roeTTM  ?? m.roeRfy),
      returnOnAssets:   pct(m.roaTTM  ?? m.roaRfy),
      revenueGrowth:    pct(m.revenueGrowthQuarterlyYoy ?? m.revenueGrowth3Y),
      earningsGrowth:   pct(m.epsGrowthTTMYoy ?? m.epsGrowth3Y),
      debtToEquity:     n(m.totalDebt2EquityQuarterly ?? m.totalDebt2EquityAnnual),
      currentRatio:     n(m.currentRatioQuarterly  ?? m.currentRatioAnnual),
      quickRatio:       n(m.quickRatioQuarterly    ?? m.quickRatioAnnual),
      freeCashflow:     (m.fcfPerShareTTM != null && shares) ? n(m.fcfPerShareTTM * shares) : null,
    };

    console.log(`[financials] ${ticker}: EDGAR OK — years: ${years.join(', ')}`);
    return res.json({
      quoteSummary: { result: [{
        incomeStatementHistory:            { incomeStatementHistory:  incS },
        balanceSheetHistory:               { balanceSheetStatements:  balS },
        cashflowStatementHistory:          { cashflowStatements:      cfS  },
        incomeStatementHistoryQuarterly:   { incomeStatementHistory:  [] },
        balanceSheetHistoryQuarterly:      { balanceSheetStatements:  [] },
        cashflowStatementHistoryQuarterly: { cashflowStatements:      [] },
        defaultKeyStatistics,
        financialData,
      }]}
    });

  } catch (e) {
    console.error('[financials] error:', e.message);
    res.status(500).json({ error: 'Failed to fetch financials: ' + e.message });
  }
});

// ============================================================
//  Earnings proxy  (Finnhub stock/earnings)
// ============================================================
app.get('/api/earnings/:ticker', async (req, res) => {
  try {
    const ticker = req.params.ticker.toUpperCase();
    const url = `https://finnhub.io/api/v1/stock/earnings?symbol=${ticker}&limit=20&token=${FINNHUB_KEY}`;
    const r = await fetch(url);
    if (!r.ok) return res.status(r.status).json({ error: 'Finnhub returned ' + r.status });
    const data = await r.json();
    res.json(data);
  } catch (e) {
    console.error('earnings proxy error:', e.message);
    res.status(500).json({ error: 'Failed to fetch earnings.' });
  }
});

// ============================================================
//  Finnhub fundamentals proxy  (avoids CORS from browser)
// ============================================================
app.get('/api/metrics/:ticker', async (req, res) => {
  try {
    const ticker = req.params.ticker.toUpperCase();
    const url = `https://finnhub.io/api/v1/stock/metric?symbol=${ticker}&metric=all&token=${FINNHUB_KEY}`;
    const r = await fetch(url);
    if (!r.ok) return res.status(r.status).json({ error: 'Finnhub returned ' + r.status });
    res.json(await r.json());
  } catch (e) {
    console.error('metrics proxy error:', e.message);
    res.status(500).json({ error: 'Failed to fetch metrics.' });
  }
});

// ============================================================
//  SEC EDGAR filings proxy
// ============================================================
app.get('/api/me/limit', async (req, res) => {
  const today = new Date().toISOString().slice(0, 10);
  if (!req.session.userId) {
    const guestCount = req.session.guestDate === today ? (req.session.guestCount || 0) : 0;
    return res.json({ plan: 'guest', used: guestCount, limit: GUEST_DAILY_LIMIT, remaining: GUEST_DAILY_LIMIT - guestCount });
  }
  try {
    const r = await db.execute({
      sql: 'SELECT plan, trial_ends_at, analysis_date, analysis_count FROM users WHERE id = ?',
      args: [req.session.userId],
    });
    const row = r.rows[0];
    if (!row) return res.json({ plan: 'free', used: 0, limit: FREE_DAILY_LIMIT, remaining: FREE_DAILY_LIMIT });
    const plan = getEffectivePlan(row);
    if (plan === 'pro' || plan === 'trial') return res.json({ plan, used: 0, limit: null, remaining: null });
    const used = row.analysis_date === today ? (Number(row.analysis_count) || 0) : 0;
    res.json({ plan, used, limit: FREE_DAILY_LIMIT, remaining: FREE_DAILY_LIMIT - used });
  } catch (e) {
    res.json({ plan: 'free', used: 0, limit: FREE_DAILY_LIMIT, remaining: FREE_DAILY_LIMIT });
  }
});

app.get('/api/sec/:ticker'
, async (req, res) => {
  const ticker = req.params.ticker.toUpperCase().replace(/[^A-Z0-9.]/g,'');
  if (!ticker) return res.status(400).json({ error: 'No ticker' });
  const UA = 'ImpliedLens/1.0 brettpeterson6216@gmail.com';
  try {
    // Strategy 1: EDGAR full-text search for company filings
    let entityId = null, entityName = ticker;
    const cikUrl = `https://efts.sec.gov/LATEST/search-index?q=%22${encodeURIComponent(ticker)}%22&forms=10-K,10-Q,8-K`;
    try {
      const cikResp = await fetch(cikUrl, { headers: { 'User-Agent': UA, 'Accept': 'application/json' } });
      if (cikResp.ok) {
        const cikData = await cikResp.json();
        const hits = cikData?.hits?.hits || [];
        if (hits.length) {
          entityId   = hits[0]?._source?.entity_id;
          entityName = hits[0]?._source?.entity_name || ticker;
        }
      }
    } catch(_) {}

    // Strategy 2: EDGAR company tickers JSON (authoritative ticker→CIK map)
    if (!entityId) {
      try {
        const tcResp = await fetch('https://www.sec.gov/files/company_tickers.json', { headers: { 'User-Agent': UA } });
        if (tcResp.ok) {
          const tcData = await tcResp.json();
          const entry = Object.values(tcData).find(e => e.ticker?.toUpperCase() === ticker);
          if (entry) { entityId = entry.cik_str; entityName = entry.title || ticker; }
        }
      } catch(_) {}
    }

    if (!entityId) return res.json({ filings: [], entity: ticker });

    const paddedCik = String(entityId).padStart(10, '0');

    // Step 2: fetch submission history for this CIK
    const subUrl = `https://data.sec.gov/submissions/CIK${paddedCik}.json`;
    const subResp = await fetch(subUrl, { headers: { 'User-Agent': UA } });
    if (!subResp.ok) return res.json({ filings: [], entity: ticker });
    const sub = await subResp.json();

    const recent = sub.filings?.recent;
    const filings = [];
    const TYPES = new Set(['10-K','10-Q','8-K','DEF 14A','S-1','10-K/A','10-Q/A']);
    if (recent && recent.form) {
      for (let i = 0; i < recent.form.length && filings.length < 40; i++) {
        if (!TYPES.has(recent.form[i])) continue;
        const accDashes = recent.accessionNumber[i]; // e.g. 0000320193-24-000123
        const accNoDashes = accDashes.replace(/-/g,'');
        filings.push({
          form:        recent.form[i],
          date:        recent.filingDate[i],
          description: recent.primaryDocDescription?.[i] || '',
          primaryDoc:  recent.primaryDocument?.[i] || '',
          accession:   accDashes,
          viewerUrl:   `https://www.sec.gov/Archives/edgar/data/${parseInt(entityId)}/${accNoDashes}/${recent.primaryDocument?.[i] || ''}`,
          indexUrl:    `https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&CIK=${paddedCik}&type=${encodeURIComponent(recent.form[i])}&dateb=&owner=include&count=10`
        });
      }
    }
    res.json({ entity: sub.name || ticker, cik: paddedCik, filings });
  } catch (e) {
    console.error('SEC proxy error:', e.message);
    res.status(500).json({ error: 'Failed to fetch SEC data.' });
  }
});
// ============================================================
//  Analyst price targets + recommendations  (Finnhub)
// ============================================================
app.get('/api/analyst/:ticker', async (req, res) => {
  const ticker = req.params.ticker.toUpperCase();
  try {
    // Finnhub: price targets + recommendations
    const [ptResp, recResp] = await Promise.all([
      fetch(`https://finnhub.io/api/v1/stock/price-target?symbol=${ticker}&token=${FINNHUB_KEY}`),
      fetch(`https://finnhub.io/api/v1/stock/recommendation?symbol=${ticker}&token=${FINNHUB_KEY}`)
    ]);
    const [pt, rec] = await Promise.all([ptResp.json(), recResp.json()]);

    // Key statistics from Finnhub metric (replaces the old Yahoo call which blocks server-side)
    let yahooFd = {};
    try {
      const [metricResp, quoteResp] = await Promise.all([
        fetch(`https://finnhub.io/api/v1/stock/metric?symbol=${ticker}&metric=all&token=${FINNHUB_KEY}`),
        fetch(`https://finnhub.io/api/v1/quote?symbol=${ticker}&token=${FINNHUB_KEY}`),
      ]);
      const [metricData, quoteData] = await Promise.all([metricResp.json(), quoteResp.json()]);
      const m = metricData.metric || {};
      yahooFd = {
        targetMeanPrice:  null,   // already in Finnhub pt above
        targetHighPrice:  null,
        targetLowPrice:   null,
        targetMedianPrice:null,
        numberOfAnalystOpinions: null,
        recommendationMean: null,
        recommendationKey: null,
        priceToBook:   m.pbQuarterly || null,
        trailingPE:    m.peNormalizedAnnual || m.peBasicExclExtraTTM || null,
        forwardPE:     null,
        priceToSales:  m.psTTM || null,
        marketCap:     m.marketCapitalization ? m.marketCapitalization * 1e6 : null,
        enterpriseValue: null,
        currentPrice:  quoteData.c || null,
      };
    } catch(_) {}

    // Merge: prefer Finnhub, fall back to Yahoo
    const merged = {
      targetMean:  pt.targetMean  || yahooFd.targetMeanPrice  || null,
      targetHigh:  pt.targetHigh  || yahooFd.targetHighPrice  || null,
      targetLow:   pt.targetLow   || yahooFd.targetLowPrice   || null,
      targetMedian:pt.targetMedian|| yahooFd.targetMedianPrice|| null,
      numberOfAnalysts: pt.numberOfAnalysts || yahooFd.numberOfAnalystOpinions || null,
      lastUpdated: pt.lastUpdated || null,
      symbol: ticker,
    };
    res.json({ priceTarget: merged, recommendations: rec, yahooFd });
  } catch (e) {
    console.error('analyst proxy error:', e.message);
    res.status(500).json({ error: 'Failed to fetch analyst data.' });
  }
});

// ============================================================
//  Institutional ownership  (Finnhub)
// ============================================================
app.get('/api/institutional/:ticker', async (req, res) => {
  const ticker = req.params.ticker.toUpperCase();
  try {
    const r = await fetch(`https://finnhub.io/api/v1/stock/ownership?symbol=${ticker}&limit=10&token=${FINNHUB_KEY}`);
    const data = await r.json();
    res.json(data);
  } catch (e) {
    console.error('institutional proxy error:', e.message);
    res.status(500).json({ error: 'Failed to fetch institutional data.' });
  }
});

// ============================================================
//  Dark pool / short interest  (FINRA OTC + Finnhub)
// ============================================================
app.get('/api/darkpool/:ticker', async (req, res) => {
  const ticker = req.params.ticker.toUpperCase();
  try {
    // FINRA OTC dark pool weekly summary — properly URL-encoded
    const compareFilters = encodeURIComponent(JSON.stringify([
      { fieldName:'issueSymbolIdentifier', compareType:'equal', fieldValue: ticker }
    ]));
    const sortFields = encodeURIComponent(JSON.stringify([{ fieldName:'weekStartDate', sortType:'DESC' }]));
    const finraUrl = `https://api.finra.org/data/group/OTCMarket/name/weeklySummary?compareFilters=${compareFilters}&fields=weekStartDate,totalWeeklyShareQuantity,totalWeeklyTradeCount,lastSalePrice&limit=8&sortFields=${sortFields}`;

    // Fetch FINRA dark pool data + Finnhub metric for share stats (Yahoo removed — blocks server-side)
    const [finraResp, metricResp] = await Promise.all([
      fetch(finraUrl, { headers: { 'Accept':'application/json', 'User-Agent':'ImpliedLens/1.0 brettpeterson6216@gmail.com' } }).catch(()=>null),
      fetch(`https://finnhub.io/api/v1/stock/metric?symbol=${ticker}&metric=all&token=${FINNHUB_KEY}`).catch(()=>null),
    ]);

    const finraData = (finraResp?.ok) ? await finraResp.json().catch(()=>[]) : [];
    const metricData = (metricResp?.ok) ? await metricResp.json().catch(()=>({})) : {};
    const m = metricData.metric || {};

    // Short interest not available on Finnhub free tier — show available share stats
    const siData = {
      sharesShort:         null,
      shortRatio:          null,
      shortPercentOfFloat: null,
      dateShortInterest:   null,
      sharesOutstanding:   m.sharesOutstanding || null,
      floatShares:         null,
    };
    res.json({ darkpool: Array.isArray(finraData) ? finraData : [], shortInterest: siData });
  } catch (e) {
    console.error('darkpool proxy error:', e.message);
    res.status(500).json({ error: 'Failed to fetch dark pool data.' });
  }
});

// ============================================================
//  Static pages
// ============================================================
app.get(["/login", "/login.html"], (req, res) =>
  res.sendFile(path.join(__dirname, "public", "login.html"))
);
app.get(["/signup", "/signup.html"], (req, res) =>
  res.sendFile(path.join(__dirname, "public", "signup.html"))
);
app.get(["/reset-password", "/reset-password.html"], (req, res) =>
  res.sendFile(path.join(__dirname, "public", "reset-password.html"))
);
app.get("*", (req, res) =>
  res.sendFile(path.join(__dirname, "index.html"))
);

initDb().then(() => {
  app.listen(PORT, () => console.log(`Implied Lens running on port ${PORT}`));
}).catch(err => { console.error("DB init failed:", err); process.exit(1); });

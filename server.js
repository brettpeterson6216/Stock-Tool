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
      subscription_data: { trial_period_days: 14 },
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
app.get('/api/quote/:ticker', async (req, res) => {
  try {
    const ticker = req.params.ticker.toUpperCase();
    const range  = (req.query.range || '1y').replace(/[^a-z0-9]/gi, '');
    const url    = `https://query1.finance.yahoo.com/v8/finance/chart/${ticker}?interval=1d&range=${range}&includePrePost=false`;
    const r = await fetch(url, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'application/json',
      }
    });
    if (!r.ok) return res.status(r.status).json({ error: 'Yahoo Finance returned ' + r.status });
    const data = await r.json();
    res.json(data);
  } catch (e) {
    console.error('quote proxy error:', e.message);
    res.status(500).json({ error: 'Failed to fetch quote data.' });
  }
});


// ============================================================
//  Yahoo Finance crumb cache  (required for quoteSummary v10)
// ============================================================
let _yfCrumb   = null;
let _yfCookies = null;
let _yfCrumbAt = 0;
const YF_CRUMB_TTL = 25 * 60 * 1000; // refresh every 25 min

async function getYahooCrumb() {
  if (_yfCrumb && (Date.now() - _yfCrumbAt) < YF_CRUMB_TTL) return { crumb: _yfCrumb, cookies: _yfCookies };
  try {
    // Step 1 — accept the consent cookie
    const consent = await fetch('https://fc.yahoo.com/', {
      headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36', 'Accept': '*/*' },
      redirect: 'follow',
    });
    const rawCookies = consent.headers.getSetCookie ? consent.headers.getSetCookie() : [];
    const cookieStr  = rawCookies.map(c => c.split(';')[0]).join('; ');

    // Step 2 — fetch crumb
    const crumbRes = await fetch('https://query1.finance.yahoo.com/v1/test/getcrumb', {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': '*/*',
        'Cookie': cookieStr,
      },
    });
    const crumb = (await crumbRes.text()).trim();
    if (!crumb || crumb.includes('<')) throw new Error('bad crumb: ' + crumb.slice(0, 40));
    _yfCrumb   = crumb;
    _yfCookies = cookieStr;
    _yfCrumbAt = Date.now();
    console.log('Yahoo crumb refreshed:', crumb.slice(0, 8) + '...');
    return { crumb, cookies: cookieStr };
  } catch (e) {
    console.error('getYahooCrumb failed:', e.message);
    return { crumb: null, cookies: null };
  }
}

// ============================================================
//  Financials proxy  (Yahoo Finance quoteSummary)
// ============================================================
app.get('/api/financials/:ticker', async (req, res) => {
  try {
    const ticker  = req.params.ticker.toUpperCase();
    const modules = 'incomeStatementHistory,incomeStatementHistoryQuarterly,balanceSheetHistory,balanceSheetHistoryQuarterly,cashflowStatementHistory,cashflowStatementHistoryQuarterly,defaultKeyStatistics,financialData';
    const { crumb, cookies } = await getYahooCrumb();
    const crumbParam = crumb ? `&crumb=${encodeURIComponent(crumb)}` : '';
    const url = `https://query1.finance.yahoo.com/v10/finance/quoteSummary/${ticker}?modules=${modules}${crumbParam}`;
    const headers = {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      'Accept': 'application/json',
    };
    if (cookies) headers['Cookie'] = cookies;
    const r = await fetch(url, { headers });
    if (!r.ok) {
      // If 401, force crumb refresh and retry once
      if (r.status === 401) {
        _yfCrumb = null; _yfCookies = null; _yfCrumbAt = 0;
        const { crumb: c2, cookies: k2 } = await getYahooCrumb();
        const url2 = `https://query1.finance.yahoo.com/v10/finance/quoteSummary/${ticker}?modules=${modules}${c2 ? '&crumb=' + encodeURIComponent(c2) : ''}`;
        const h2 = { ...headers };
        if (k2) h2['Cookie'] = k2;
        const r2 = await fetch(url2, { headers: h2 });
        if (!r2.ok) return res.status(r2.status).json({ error: 'Yahoo returned ' + r2.status + ' (after crumb retry)' });
        return res.json(await r2.json());
      }
      return res.status(r.status).json({ error: 'Yahoo returned ' + r.status });
    }
    res.json(await r.json());
  } catch (e) {
    console.error('financials proxy error:', e.message);
    res.status(500).json({ error: 'Failed to fetch financials.' });
  }
});

// ============================================================
//  Earnings proxy  (Finnhub stock/earnings)
// ============================================================
app.get('/api/earnings/:ticker', async (req, res) => {
  try {
    const ticker = req.params.ticker.toUpperCase();
    const url = `https://finnhub.io/api/v1/stock/earnings?symbol=${ticker}&limit=12&token=${FINNHUB_KEY}`;
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
app.get('/api/sec/:ticker', async (req, res) => {
  const ticker = req.params.ticker.toUpperCase().replace(/[^A-Z0-9.]/g,'');
  if (!ticker) return res.status(400).json({ error: 'No ticker' });
  const UA = 'ImpliedLens/1.0 brettpeterson6216@gmail.com';
  try {
    // Step 1: look up CIK via EDGAR company search JSON
    const cikUrl = `https://efts.sec.gov/LATEST/search-index?q=%22${ticker}%22&forms=10-K&dateRange=custom&startdt=2018-01-01`;
    const cikResp = await fetch(cikUrl, { headers: { 'User-Agent': UA, 'Accept': 'application/json' } });
    const cikData = await cikResp.json();
    const hits = cikData?.hits?.hits || [];
    if (!hits.length) return res.json({ filings: [], entity: ticker });

    // Find best-matching entity (prefer exact ticker match in entity_name or file_num)
    const entityId = hits[0]?._source?.entity_id;
    if (!entityId) return res.json({ filings: [], entity: hits[0]?._source?.entity_name || ticker });

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
//  Static pages
// ============================================================
app.get(["/login", "/login.html"], (req, res) =>
  res.sendFile(path.join(__dirname, "login.html"))
);
app.get(["/signup", "/signup.html"], (req, res) =>
  res.sendFile(path.join(__dirname, "signup.html"))
);
app.get("*", (req, res) =>
  res.sendFile(path.join(__dirname, "index.html"))
);

initDb().then(() => {
  app.listen(PORT, () => console.log(`Implied Lens running on port ${PORT}`));
}).catch(err => { console.error("DB init failed:", err); process.exit(1); });

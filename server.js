// ============================================================
//  Implied Lens -- Auth server
//  Database: Turso (free hosted libSQL / SQLite)
//    @libsql/client  (async API)
//    bcryptjs        (password hashing, 12 rounds)
//    express-session
//
//  Passwords are NEVER stored in plaintext. They are hashed
//  with bcrypt (12 rounds) before insert. The DB stores only
//  the one-way hash, which cannot be reversed.
// ============================================================

require('dotenv').config();

const path      = require('path');
const express   = require('express');
const session   = require('express-session');
const bcrypt    = require('bcryptjs');
const helmet    = require('helmet');
const rateLimit = require('express-rate-limit');
const { createClient } = require('@libsql/client');
const Stripe = require('stripe');

const PORT                 = process.env.PORT || 3000;
const SESSION_SECRET       = process.env.SESSION_SECRET || 'change-me-in-production-please';
const FINNHUB_KEY          = process.env.FINNHUB_KEY    || 'd7n43rpr01qppri3flo0d7n43rpr01qppri3flog';
const BCRYPT_ROUNDS        = 12;
const STRIPE_SECRET_KEY    = process.env.STRIPE_SECRET_KEY    || '';
const STRIPE_WEBHOOK_SECRET= process.env.STRIPE_WEBHOOK_SECRET|| '';
const STRIPE_PRICE_MONTHLY = process.env.STRIPE_PRICE_MONTHLY || '';
const STRIPE_PRICE_ANNUAL  = process.env.STRIPE_PRICE_ANNUAL  || '';
const APP_URL              = process.env.APP_URL || 'http://localhost:' + (process.env.PORT || 3000);
const stripe               = STRIPE_SECRET_KEY ? Stripe(STRIPE_SECRET_KEY) : null;

// ---- Turso client ----
const db = createClient({
  url:       process.env.TURSO_URL       || 'file:local.db',
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
      created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
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

  // Add plan columns if they don't exist yet (ALTER TABLE has no IF NOT EXISTS in SQLite)
  const planCols = [
    "plan TEXT NOT NULL DEFAULT 'free'",
    'trial_ends_at TEXT',
    'stripe_customer_id TEXT',
    'stripe_subscription_id TEXT',
  ];
  for (const col of planCols) {
    try { await db.execute('ALTER TABLE users ADD COLUMN ' + col); } catch (_) {}
  }

  console.log('Database initialised');
}

// ---- Plan helper ----
function getEffectivePlan(user) {
  if (user.plan === 'pro') return 'pro';
  if (user.plan === 'trial' && user.trial_ends_at && new Date(user.trial_ends_at) > new Date()) return 'trial';
  return 'free';
}

// ============================================================
//  Async SQLite-backed session store for Turso
// ============================================================
class TursoStore extends session.Store {
  get(sid, cb) {
    db.execute({ sql: 'SELECT data, expires FROM sessions WHERE sid = ?', args: [sid] })
      .then(res => {
        const row = res.rows[0];
        if (!row) return cb(null, null);
        if (Number(row.expires) < Date.now()) {
          db.execute({ sql: 'DELETE FROM sessions WHERE sid = ?', args: [sid] }).catch(() => {});
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
      sql:  'INSERT INTO sessions (sid, expires, data) VALUES (?, ?, ?) ON CONFLICT(sid) DO UPDATE SET expires = excluded.expires, data = excluded.data',
      args: [sid, expires, JSON.stringify(sess)],
    })
      .then(() => cb && cb(null))
      .catch(e => cb && cb(e));
  }

  destroy(sid, cb) {
    db.execute({ sql: 'DELETE FROM sessions WHERE sid = ?', args: [sid] })
      .then(() => cb && cb(null))
      .catch(e => cb && cb(e));
  }

  touch(sid, sess, cb) { this.set(sid, sess, cb); }
}

// Cleanup expired sessions every hour
setInterval(() => {
  db.execute({ sql: 'DELETE FROM sessions WHERE expires < ?', args: [Date.now()] }).catch(() => {});
}, 60 * 60 * 1000);

// ---- App ----
const app = express();
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '64kb', verify: (req, _res, buf) => { req.rawBody = buf; } }));
app.use(express.urlencoded({ extended: false, limit: '64kb' }));

app.use(session({
  store: new TursoStore(),
  name: 'il.sid',
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 1000 * 60 * 60 * 24 * 7,
  },
}));

// ---- Validation ----
const EMAIL_RE    = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const USERNAME_RE = /^[a-zA-Z0-9_.-]{3,32}$/;

function validateSignup({ username, email, password }) {
  const errors = [];
  if (!username || !USERNAME_RE.test(username))
    errors.push('Username must be 3-32 chars (letters, numbers, _ . -).');
  if (!email || !EMAIL_RE.test(email))
    errors.push('Please enter a valid email address.');
  if (!password || password.length < 8)
    errors.push('Password must be at least 8 characters.');
  if (password && password.length > 200)
    errors.push('Password is too long.');
  return errors;
}

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many attempts. Try again in 15 minutes.' },
});

// ============================================================
//  Auth API
// ============================================================
const api = express.Router();
api.use(authLimiter);

api.post('/auth/signup', async (req, res) => {
  try {
    const username = String(req.body.username || '').trim();
    const email    = String(req.body.email    || '').trim().toLowerCase();
    const password = String(req.body.password || '');

    const errors = validateSignup({ username, email, password });
    if (errors.length) return res.status(400).json({ error: errors.join(' ') });

    const byUser  = await db.execute({ sql: 'SELECT id FROM users WHERE username = ? LIMIT 1', args: [username] });
    if (byUser.rows.length) return res.status(409).json({ error: 'That username is already taken.' });

    const byEmail = await db.execute({ sql: 'SELECT id FROM users WHERE email = ? LIMIT 1', args: [email] });
    if (byEmail.rows.length) return res.status(409).json({ error: 'An account with that email already exists.' });

    const hash = await bcrypt.hash(password, BCRYPT_ROUNDS);
    let ins;
    try {
      ins = await db.execute({ sql: 'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)', args: [username, email, hash] });
    } catch (dbErr) {
      const msg = (dbErr.message || '').toLowerCase();
      if (msg.includes('unique') && msg.includes('username'))
        return res.status(409).json({ error: 'That username is already taken.' });
      if (msg.includes('unique') && msg.includes('email'))
        return res.status(409).json({ error: 'An account with that email already exists.' });
      if (msg.includes('unique'))
        return res.status(409).json({ error: 'That username or email is already taken.' });
      throw dbErr;
    }
    const userId = Number(ins.lastInsertRowid);

    const userRow = await db.execute({ sql: 'SELECT id, username, email, created_at FROM users WHERE id = ?', args: [userId] });
    req.session.userId = userId;
    return res.status(201).json({ user: userRow.rows[0] || null });
  } catch (err) {
    console.error('signup error:', err);
    return res.status(500).json({ error: 'Could not create account.' });
  }
});

api.post('/auth/login', async (req, res) => {
  try {
    const identifier = String(req.body.identifier || req.body.username || req.body.email || '').trim();
    const password   = String(req.body.password || '');

    if (!identifier || !password)
      return res.status(400).json({ error: 'Please enter your username/email and password.' });

    const lookup = identifier.includes('@') ? identifier.toLowerCase() : identifier;
    const result = await db.execute({ sql: 'SELECT id, username, email, password_hash FROM users WHERE username = ? OR email = ? LIMIT 1', args: [lookup, lookup] });
    const row = result.rows[0];
    if (!row) return res.status(401).json({ error: 'Invalid credentials.' });

    const ok = await bcrypt.compare(password, row.password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials.' });

    req.session.userId = Number(row.id);
    return res.json({ user: { id: Number(row.id), username: row.username, email: row.email } });
  } catch (err) {
    console.error('login error:', err);
    return res.status(500).json({ error: 'Login failed.' });
  }
});

api.post('/auth/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('il.sid');
    res.json({ ok: true });
  });
});

api.get('/auth/me', async (req, res) => {
  if (!req.session.userId) return res.json({ user: null });
  try {
    const result = await db.execute({
      sql: 'SELECT id, username, email, created_at, plan, trial_ends_at FROM users WHERE id = ?',
      args: [req.session.userId],
    });
    const user = result.rows[0] || null;
    if (user) user.effectivePlan = getEffectivePlan(user);
    return res.json({ user });
  } catch (err) {
    return res.json({ user: null });
  }
});

app.use('/api', api);

// ============================================================
//  Stripe -- checkout + webhook
// ============================================================
app.post('/api/stripe/create-checkout', async (req, res) => {
  if (!stripe) return res.status(503).json({ error: 'Payments not configured yet.' });
  if (!req.session.userId) return res.status(401).json({ error: 'Login required.' });

  const priceId = req.body.annual ? STRIPE_PRICE_ANNUAL : STRIPE_PRICE_MONTHLY;
  if (!priceId) return res.status(503).json({ error: 'Price not configured.' });

  try {
    const userRow = await db.execute({
      sql: 'SELECT id, email, stripe_customer_id FROM users WHERE id = ?',
      args: [req.session.userId],
    });
    const user = userRow.rows[0];
    if (!user) return res.status(404).json({ error: 'User not found.' });

    const params = {
      mode: 'subscription',
      payment_method_types: ['card'],
      line_items: [{ price: priceId, quantity: 1 }],
      subscription_data: { trial_period_days: 14 },
      success_url: APP_URL + '/?upgraded=1',
      cancel_url: APP_URL + '/',
      metadata: { userId: String(req.session.userId) },
    };
    if (user.stripe_customer_id) {
      params.customer = user.stripe_customer_id;
    } else {
      params.customer_email = user.email;
    }

    const session = await stripe.checkout.sessions.create(params);
    res.json({ url: session.url });
  } catch (err) {
    console.error('Stripe checkout error:', err);
    res.status(500).json({ error: 'Could not create checkout session.' });
  }
});

app.post('/api/stripe/webhook', async (req, res) => {
  if (!stripe) return res.status(503).send('Not configured');
  const sig = req.headers['stripe-signature'];
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.rawBody, sig, STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error('Webhook signature error:', err.message);
    return res.status(400).send('Webhook error: ' + err.message);
  }

  try {
    switch (event.type) {
      case 'checkout.session.completed': {
        const sess = event.data.object;
        const userId = sess.metadata && sess.metadata.userId;
        if (!userId || !sess.subscription) break;
        const sub = await stripe.subscriptions.retrieve(sess.subscription);
        const plan = sub.status === 'trialing' ? 'trial' : 'pro';
        const trialEnd = sub.trial_end ? new Date(sub.trial_end * 1000).toISOString() : null;
        await db.execute({
          sql: 'UPDATE users SET plan=?, trial_ends_at=?, stripe_customer_id=?, stripe_subscription_id=? WHERE id=?',
          args: [plan, trialEnd, sess.customer, sess.subscription, userId],
        });
        break;
      }
      case 'customer.subscription.updated': {
        const sub = event.data.object;
        const r = await db.execute({ sql: 'SELECT id FROM users WHERE stripe_customer_id=?', args: [sub.customer] });
        if (!r.rows.length) break;
        let plan = 'free';
        if (sub.status === 'active') plan = 'pro';
        else if (sub.status === 'trialing') plan = 'trial';
        const trialEnd = sub.trial_end ? new Date(sub.trial_end * 1000).toISOString() : null;
        await db.execute({ sql: 'UPDATE users SET plan=?, trial_ends_at=? WHERE id=?', args: [plan, trialEnd, r.rows[0].id] });
        break;
      }
      case 'customer.subscription.deleted': {
        const sub = event.data.object;
        const r = await db.execute({ sql: 'SELECT id FROM users WHERE stripe_customer_id=?', args: [sub.customer] });
        if (!r.rows.length) break;
        await db.execute({ sql: "UPDATE users SET plan='free', trial_ends_at=NULL WHERE id=?", args: [r.rows[0].id] });
        break;
      }
      case 'invoice.payment_failed': {
        const inv = event.data.object;
        const r = await db.execute({ sql: 'SELECT id FROM users WHERE stripe_customer_id=?', args: [inv.customer] });
        if (!r.rows.length) break;
        await db.execute({ sql: "UPDATE users SET plan='free' WHERE id=?", args: [r.rows[0].id] });
        break;
      }
    }
  } catch (err) {
    console.error('Webhook handler error:', err);
  }

  res.json({ received: true });
});

// ============================================================
//  Finnhub proxy -- news
// ============================================================
app.get('/api/news/:ticker', async (req, res) => {
  try {
    const ticker = req.params.ticker.toUpperCase();
    const to   = new Date().toISOString().split('T')[0];
    const from = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString().split('T')[0];
    const url  = 'https://finnhub.io/api/v1/company-news?symbol=' + ticker + '&from=' + from + '&to=' + to + '&token=' + FINNHUB_KEY;
    const r    = await fetch(url);
    const data = await r.json();
    res.json(Array.isArray(data) ? data.slice(0, 10) : []);
  } catch (e) {
    console.error('news error:', e);
    res.json([]);
  }
});

// ============================================================
//  Finnhub proxy -- screener (top 35 stocks)
// ============================================================
const SCREENER_TICKERS = [
  'AAPL','MSFT','NVDA','GOOGL','AMZN','META','TSLA','BRK-B','LLY','JPM',
  'V','UNH','XOM','MA','AVGO','JNJ','PG','HD','COST','MRK',
  'ABBV','CVX','PEP','KO','WMT','BAC','CRM','TMO','ORCL','AMD',
  'NFLX','ADBE','QCOM','TXN','INTC'
];

app.get('/api/screener', async (req, res) => {
  try {
    const results = await Promise.allSettled(
      SCREENER_TICKERS.map(async (ticker) => {
        const [qRes, mRes] = await Promise.all([
          fetch('https://finnhub.io/api/v1/quote?symbol=' + ticker + '&token=' + FINNHUB_KEY),
          fetch('https://finnhub.io/api/v1/stock/metric?symbol=' + ticker + '&metric=all&token=' + FINNHUB_KEY)
        ]);
        const [q, md] = await Promise.all([qRes.json(), mRes.json()]);
        const m = md.metric || {};
        return {
          ticker,
          price: q.c || 0,
          change1D: q.pc > 0 ? ((q.c - q.pc) / q.pc * 100) : 0,
          change1Y: m['52WeekPriceReturnDaily'] || null,
          marketCap: m.marketCapitalization ? m.marketCapitalization * 1e6 : null,
          pe: m.peBasicExclExtraTTM || m.peTTM || null,
          pb: m.pbQuarterly || null,
          dividendYield: m.dividendYieldIndicatedAnnual || 0,
          beta: m.beta || null,
        };
      })
    );
    const stocks = results
      .filter(r => r.status === 'fulfilled' && r.value.price > 0)
      .map(r => r.value);
    res.json(stocks);
  } catch (e) {
    console.error('screener error:', e);
    res.status(500).json({ error: 'Screener fetch failed' });
  }
});

// ============================================================
//  Pages
// ============================================================
function requireAuth(req, res, next) {
  if (!req.session.userId) return res.redirect('/login');
  next();
}

app.get(['/login', '/login.html'], (req, res) =>
  res.sendFile(path.join(__dirname, 'public', 'login.html'))
);
app.get(['/signup', '/signup.html', '/register'], (req, res) =>
  res.sendFile(path.join(__dirname, 'public', 'signup.html'))
);

app.get('/', requireAuth, (req, res) =>
  res.sendFile(path.join(__dirname, 'index.html'))
);
app.get('/index.html', requireAuth, (req, res) =>
  res.sendFile(path.join(__dirname, 'index.html'))
);

app.use('/public', express.static(path.join(__dirname, 'public')));
app.use(express.static(path.join(__dirname), { index: false }));

app.use((req, res) => res.status(404).send('Not found'));

// ---- Start ----
initDb().then(() => {
  app.listen(PORT, () => {
    console.log('Implied Lens running at http://localhost:' + PORT);
  });
}).catch(err => {
  console.error('Failed to initialise database:', err);
  process.exit(1);
});

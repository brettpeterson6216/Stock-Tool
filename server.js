// ============================================================
//  StockVision Pro -- Auth server
//  Free stack -- PURE JAVASCRIPT, no native compile required:
//    Node.js (built-in node:sqlite -- requires Node >= 22)
//    Express
//    bcryptjs   (password hashing, 12 rounds)
//    express-session
//
//  Passwords are NEVER stored in plaintext. They are hashed
//  with bcrypt (12 rounds) before insert. The DB stores only
//  the one-way hash, which cannot be reversed.
// ============================================================

require('dotenv').config();

const path      = require('path');
const fs        = require('fs');
const express   = require('express');
const session   = require('express-session');
const bcrypt    = require('bcryptjs');
const helmet    = require('helmet');
const rateLimit = require('express-rate-limit');
const { DatabaseSync } = require('node:sqlite');

const PORT           = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || 'change-me-in-production-please';
const FINNHUB_KEY    = process.env.FINNHUB_KEY || 'd7n43rpr01qppri3flo0d7n43rpr01qppri3flog';
const BCRYPT_ROUNDS  = 12;
const DB_DIR         = path.join(__dirname, 'data');
const DB_FILE        = path.join(DB_DIR, 'app.db');

// ---- ensure data dir exists ----
if (!fs.existsSync(DB_DIR)) fs.mkdirSync(DB_DIR, { recursive: true });

// ---- DB setup ----
const db = new DatabaseSync(DB_FILE);
db.exec('PRAGMA journal_mode = WAL');
db.exec('PRAGMA foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    UNIQUE NOT NULL,
    email         TEXT    UNIQUE NOT NULL,
    password_hash TEXT    NOT NULL,
    created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
  );
`);
db.exec('CREATE INDEX IF NOT EXISTS idx_users_email    ON users(email);');
db.exec('CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);');

const userStmts = {
  findByLogin:    db.prepare('SELECT id, username, email, password_hash FROM users WHERE username = ? OR email = ? LIMIT 1'),
  findByUsername: db.prepare('SELECT id FROM users WHERE username = ? LIMIT 1'),
  findByEmail:    db.prepare('SELECT id FROM users WHERE email    = ? LIMIT 1'),
  insertUser:     db.prepare('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)'),
  getUserById:    db.prepare('SELECT id, username, email, created_at FROM users WHERE id = ?'),
};

// ============================================================
//  Tiny SQLite-backed session store (no extra dependency)
// ============================================================
db.exec(`
  CREATE TABLE IF NOT EXISTS sessions (
    sid     TEXT PRIMARY KEY,
    expires INTEGER NOT NULL,
    data    TEXT NOT NULL
  );
`);
db.exec('CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires);');

const sessStmts = {
  get:     db.prepare('SELECT data, expires FROM sessions WHERE sid = ?'),
  set:     db.prepare('INSERT INTO sessions (sid, expires, data) VALUES (?, ?, ?) ON CONFLICT(sid) DO UPDATE SET expires = excluded.expires, data = excluded.data'),
  destroy: db.prepare('DELETE FROM sessions WHERE sid = ?'),
  cleanup: db.prepare('DELETE FROM sessions WHERE expires < ?'),
};

class SqliteStore extends session.Store {
  get(sid, cb) {
    try {
      const row = sessStmts.get.get(sid);
      if (!row) return cb(null, null);
      if (Number(row.expires) < Date.now()) {
        sessStmts.destroy.run(sid);
        return cb(null, null);
      }
      cb(null, JSON.parse(row.data));
    } catch (e) { cb(e); }
  }
  set(sid, sess, cb) {
    try {
      const expires = sess.cookie && sess.cookie.expires
        ? new Date(sess.cookie.expires).getTime()
        : Date.now() + 7 * 24 * 60 * 60 * 1000;
      sessStmts.set.run(sid, expires, JSON.stringify(sess));
      cb && cb(null);
    } catch (e) { cb && cb(e); }
  }
  destroy(sid, cb) {
    try { sessStmts.destroy.run(sid); cb && cb(null); }
    catch (e) { cb && cb(e); }
  }
  touch(sid, sess, cb) { this.set(sid, sess, cb); }
}
setInterval(() => { try { sessStmts.cleanup.run(Date.now()); } catch (_) {} }, 60 * 60 * 1000);

// ---- App ----
const app = express();
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '64kb' }));
app.use(express.urlencoded({ extended: false, limit: '64kb' }));

app.use(session({
  store: new SqliteStore(),
  name: 'svp.sid',
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

    if (userStmts.findByUsername.get(username))
      return res.status(409).json({ error: 'That username is already taken.' });
    if (userStmts.findByEmail.get(email))
      return res.status(409).json({ error: 'An account with that email already exists.' });

    const hash = await bcrypt.hash(password, BCRYPT_ROUNDS);
    const info = userStmts.insertUser.run(username, email, hash);
    const userId = Number(info.lastInsertRowid);

    req.session.userId = userId;
    const user = userStmts.getUserById.get(userId);
    return res.status(201).json({ user });
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
    const row = userStmts.findByLogin.get(lookup, lookup);
    if (!row) return res.status(401).json({ error: 'Invalid credentials.' });

    const ok = await bcrypt.compare(password, row.password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials.' });

    req.session.userId = Number(row.id);
    return res.json({
      user: { id: Number(row.id), username: row.username, email: row.email },
    });
  } catch (err) {
    console.error('login error:', err);
    return res.status(500).json({ error: 'Login failed.' });
  }
});

api.post('/auth/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('svp.sid');
    res.json({ ok: true });
  });
});

api.get('/auth/me', (req, res) => {
  if (!req.session.userId) return res.json({ user: null });
  const user = userStmts.getUserById.get(req.session.userId);
  return res.json({ user: user || null });
});

app.use('/api', api);

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

app.listen(PORT, () => {
  console.log('StockVision Pro server running at http://localhost:' + PORT);
  console.log('DB: ' + DB_FILE);
});

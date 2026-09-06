// ============================================================
//  Database — Turso/libSQL client, session store, schema init
// ============================================================
require("./config"); // ensure dotenv is loaded first

const { createClient } = require("@libsql/client");
const session          = require("express-session");

// ---- Turso client (singleton) ----
const rawDb = createClient({
  url:       process.env.TURSO_URL        || "file:local.db",
  authToken: process.env.TURSO_AUTH_TOKEN || undefined,
});

// ---- Statement normalisation ----
// The two libSQL backends disagree about a statement written as
// `{ sql }` with no `args`. The local `file:` client happily runs it; the
// HTTP client used against Turso in production hands it to
// `stmtToHrana`, which calls `Object.entries(stmt.args)` and throws
// "Cannot convert undefined or null to object". That difference means a
// missing `args` passes every local test and then fails only in
// production — which is exactly how it reached us. Default it here so both
// backends behave the same, and so one omitted `args` can never again take
// out a background job. Strings and array/object args are passed through
// untouched.
function normaliseStmt(stmt) {
  if (stmt && typeof stmt === "object" && typeof stmt.sql === "string" && stmt.args == null) {
    return { ...stmt, args: [] };
  }
  return stmt;
}

function wrapExecutor(target) {
  const execute = target.execute.bind(target);
  const batch   = typeof target.batch === "function" ? target.batch.bind(target) : null;
  target.execute = (stmtOrSql, args) => execute(normaliseStmt(stmtOrSql), args);
  if (batch) target.batch = (stmts, mode) => batch(Array.isArray(stmts) ? stmts.map(normaliseStmt) : stmts, mode);
  return target;
}

const db = wrapExecutor(rawDb);

// Transactions hand back a separate object with its own execute/batch, so it
// needs the same treatment.
if (typeof rawDb.transaction === "function") {
  const transaction = rawDb.transaction.bind(rawDb);
  db.transaction = async mode => wrapExecutor(await transaction(mode));
}

// ============================================================
//  Async SQLite-backed session store
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
      .catch(e  => cb && cb(e));
  }

  destroy(sid, cb) {
    db.execute({ sql: "DELETE FROM sessions WHERE sid = ?", args: [sid] })
      .then(() => cb && cb(null))
      .catch(e  => cb && cb(e));
  }

  touch(sid, sess, cb) { this.set(sid, sess, cb); }
}

// Purge expired sessions every hour without keeping short-lived processes alive.
const sessionCleanupTimer = setInterval(() => {
  db.execute({ sql: "DELETE FROM sessions WHERE expires < ?", args: [Date.now()] }).catch(() => {});
}, 60 * 60 * 1000);
sessionCleanupTimer.unref?.();

// ============================================================
//  Schema initialisation (run once on startup)
// ============================================================
async function initDb() {
  await db.execute(`
    CREATE TABLE IF NOT EXISTS users (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      username      TEXT    UNIQUE NOT NULL,
      email         TEXT    UNIQUE NOT NULL,
      password_hash TEXT    NOT NULL,
      created_at    TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
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

  await db.execute(`
    CREATE TABLE IF NOT EXISTS saved_analyses (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id     INTEGER NOT NULL,
      ticker      TEXT    NOT NULL,
      type        TEXT    NOT NULL DEFAULT 'price',
      label       TEXT,
      data        TEXT    NOT NULL,
      created_at  TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);
  await db.execute(`CREATE INDEX IF NOT EXISTS idx_saves_user ON saved_analyses(user_id)`);

  // Add plan columns if they do not exist yet (idempotent migrations)
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

  await db.execute(`
    CREATE TABLE IF NOT EXISTS reset_tokens (
      token      TEXT PRIMARY KEY,
      user_id    INTEGER NOT NULL,
      expires_at INTEGER NOT NULL,
      used       INTEGER NOT NULL DEFAULT 0
    )
  `);

  await db.execute(`
    CREATE TABLE IF NOT EXISTS analytics_events (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      event       TEXT    NOT NULL,
      session_id  TEXT,
      user_id     INTEGER,
      properties  TEXT,
      created_at  TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);
  await db.execute(`CREATE INDEX IF NOT EXISTS idx_analytics_event   ON analytics_events(event)`);
  await db.execute(`CREATE INDEX IF NOT EXISTS idx_analytics_created ON analytics_events(created_at)`);
  await db.execute(`CREATE INDEX IF NOT EXISTS idx_analytics_user    ON analytics_events(user_id)`);

  await db.execute(`
    CREATE TABLE IF NOT EXISTS analysis_usage (
      subject_id  TEXT NOT NULL,
      ticker      TEXT NOT NULL,
      usage_date  TEXT NOT NULL,
      created_at  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (subject_id, ticker, usage_date)
    )
  `);
  await db.execute(`CREATE INDEX IF NOT EXISTS idx_analysis_usage_subject_date ON analysis_usage(subject_id, usage_date)`);

  await db.execute(`
    CREATE TABLE IF NOT EXISTS stripe_events (
      event_id      TEXT PRIMARY KEY,
      event_type    TEXT NOT NULL,
      processed_at  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // email_verified column — default 0 for new users, 1 for existing (grandfathered)
  // We cannot set default=1 via ALTER TABLE for existing rows, so we do it explicitly.
  try { await db.execute("ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 0"); } catch (_) {}
  // Grandfather all accounts that existed before verification was added
  await db.execute(`UPDATE users SET email_verified = 1 WHERE email_verified = 0 AND created_at < '2026-06-04'`);

  await db.execute(`
    CREATE TABLE IF NOT EXISTS email_verif_tokens (
      token      TEXT    PRIMARY KEY,
      user_id    INTEGER NOT NULL,
      expires_at INTEGER NOT NULL,
      used       INTEGER NOT NULL DEFAULT 0
    )
  `);
  await db.execute(`CREATE INDEX IF NOT EXISTS idx_verif_user ON email_verif_tokens(user_id)`);

  await db.execute(`
    CREATE TABLE IF NOT EXISTS investment_theses (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      ticker TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'watching',
      thesis TEXT NOT NULL DEFAULT '',
      catalysts TEXT NOT NULL DEFAULT '[]',
      risks TEXT NOT NULL DEFAULT '[]',
      sell_conditions TEXT NOT NULL DEFAULT '[]',
      target_price REAL,
      bear_price REAL,
      review_date TEXT,
      conviction INTEGER NOT NULL DEFAULT 3,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(user_id, ticker)
    )
  `);
  await db.execute(`CREATE INDEX IF NOT EXISTS idx_theses_user ON investment_theses(user_id)`);

  await db.execute(`
    CREATE TABLE IF NOT EXISTS portfolio_positions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      ticker TEXT NOT NULL,
      shares REAL NOT NULL,
      cost_basis REAL NOT NULL,
      sector TEXT,
      notes TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(user_id, ticker)
    )
  `);
  await db.execute(`CREATE INDEX IF NOT EXISTS idx_positions_user ON portfolio_positions(user_id)`);

  await db.execute(`
    CREATE TABLE IF NOT EXISTS watchlist_items (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      ticker TEXT NOT NULL,
      note TEXT,
      target_price REAL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(user_id, ticker)
    )
  `);
  await db.execute(`CREATE INDEX IF NOT EXISTS idx_watchlist_user ON watchlist_items(user_id)`);

  await db.execute(`
    CREATE TABLE IF NOT EXISTS member_portfolio_profiles (
      user_id INTEGER PRIMARY KEY,
      goal TEXT NOT NULL,
      horizon_years INTEGER NOT NULL,
      risk_tolerance TEXT NOT NULL,
      liquidity_need TEXT NOT NULL,
      experience TEXT NOT NULL,
      income_stability TEXT NOT NULL,
      preference TEXT NOT NULL,
      answers TEXT NOT NULL DEFAULT '{}',
      model TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await db.execute(`
    CREATE TABLE IF NOT EXISTS lifecycle_email_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      email_type TEXT NOT NULL,
      reference_key TEXT NOT NULL,
      sent_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(user_id, email_type, reference_key)
    )
  `);
  await db.execute(`CREATE INDEX IF NOT EXISTS idx_lifecycle_email_user ON lifecycle_email_log(user_id)`);

  console.log("Database initialised");
}

module.exports = { db, TursoStore, initDb, normaliseStmt };

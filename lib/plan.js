// ============================================================
//  Plan helpers — effective plan logic, Pro middleware,
//  analysis rate-limiter with per-ticker dedup
// ============================================================
const { db }    = require("./db");
const crypto    = require("crypto");

const FREE_DAILY_LIMIT  = 5;
const GUEST_DAILY_LIMIT = 2;
const PREVIEW_QUOTE_TICKERS = new Set([
  "AAPL", "NVDA", "MSFT", "TSLA", "AMZN", "META", "GOOGL", "SPY",
  "^GSPC", "^IXIC", "^DJI", "^VIX",
]);

// Emails granted complimentary Pro access
const GIFTED_EMAILS = new Set(
  (process.env.GIFTED_EMAILS || "").split(",").map(e => e.trim().toLowerCase()).filter(Boolean)
);

// Retained as a compatibility export for older tests. Quota state is durable
// in analysis_usage and no longer depends on this process-local cache.
const _dedupCache = new Map();

// ── Guest ID cookie helpers ────────────────────────────────────────────────
const GID_COOKIE   = "il_gid";
const GID_MAX_AGE  = 90 * 24 * 60 * 60; // 90 days in seconds

function _generateGuestId() {
  return crypto.randomBytes(20).toString("hex");
}

function _parseGuestIdFromHeader(cookieHeader) {
  if (!cookieHeader) return null;
  const match = cookieHeader.match(new RegExp(`(?:^|;\\s*)${GID_COOKIE}=([^;]+)`));
  return match ? match[1] : null;
}

/**
 * Middleware — must be mounted BEFORE session middleware.
 * Reads or creates the durable guest-ID cookie (il_gid).
 * Attaches req.guestId for use in checkAnalysisLimit.
 */
function guestIdMiddleware(req, res, next) {
  let gid = _parseGuestIdFromHeader(req.headers.cookie);
  if (!gid || !/^[0-9a-f]{40}$/.test(gid)) {
    gid = _generateGuestId();
    // Set: httpOnly, SameSite=Lax, Secure in prod, 90-day max-age
    const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
    res.setHeader("Set-Cookie",
      `${GID_COOKIE}=${gid}; Max-Age=${GID_MAX_AGE}; Path=/; HttpOnly; SameSite=Lax${secure}`
    );
  }
  req.guestId = gid;
  next();
}

/**
 * Returns 'pro', 'trial', or 'free' for a user row from the DB.
 */
function getEffectivePlan(user) {
  if (GIFTED_EMAILS.has((user.email || "").toLowerCase())) return "pro";
  if (user.plan === "pro") return "pro";
  if (user.plan === "trial" && user.trial_ends_at && new Date(user.trial_ends_at) > new Date()) return "trial";
  return "free";
}

/**
 * Middleware — allows only logged-in pro/trial users.
 */
async function requirePro(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: "Login required.", requiresLogin: true });
  }
  try {
    const r = await db.execute({
      sql:  "SELECT email, plan, trial_ends_at FROM users WHERE id = ?",
      args: [req.session.userId],
    });
    const user = r.rows[0];
    if (!user) return res.status(401).json({ error: "User not found.", requiresLogin: true });
    const plan = getEffectivePlan(user);
    if (plan === "pro" || plan === "trial") {
      res.setHeader("X-Plan", plan);
      return next();
    }
    return res.status(403).json({ error: "Pro plan required.", requiresPro: true, plan: "free" });
  } catch (e) {
    console.error("requirePro error:", e);
    return res.status(500).json({ error: "Could not verify plan." });
  }
}

/**
 * Middleware — enforces daily analysis quota.
 * Dedup logic: one ticker per (user/guest, ticker, day) only ever counts once.
 * Multiple /api/quote calls for the same ticker during one session cost 1 credit.
 */
async function checkAnalysisLimit(req, res, next) {
  const today  = new Date().toISOString().slice(0, 10);
  const ticker = String(req.params.ticker || "").toUpperCase().replace(/[^A-Z0-9.\-^]/g, "");
  const isPreview = req.query.preview === "1" && PREVIEW_QUOTE_TICKERS.has(ticker);

  if (isPreview) {
    res.setHeader("X-Plan", "preview");
    return next();
  }

  let subjectId;
  let limit;
  let plan;
  let requiresLogin = false;

  if (req.session.userId) {
    let row;
    try {
      const r = await db.execute({
        sql:  "SELECT email, plan, trial_ends_at FROM users WHERE id = ?",
        args: [req.session.userId],
      });
      row = r.rows[0];
    } catch (e) {
      console.error("[quota] user lookup failed:", e);
      return res.status(503).json({ error: "Analysis limit service unavailable. Please try again." });
    }

    if (!row) return res.status(401).json({ error: "User not found.", requiresLogin: true });

    plan = getEffectivePlan(row);
    if (plan === "pro" || plan === "trial") {
      res.setHeader("X-Plan", plan);
      return next();
    }
    subjectId = `u:${req.session.userId}`;
    limit = FREE_DAILY_LIMIT;
  } else {
    plan = "guest";
    subjectId = `g:${req.guestId || req.sessionID}`;
    limit = GUEST_DAILY_LIMIT;
    requiresLogin = true;
  }

  let tx;
  try {
    tx = await db.transaction("write");
    const existing = await tx.execute({
      sql: "SELECT 1 FROM analysis_usage WHERE subject_id = ? AND ticker = ? AND usage_date = ? LIMIT 1",
      args: [subjectId, ticker, today],
    });
    const countResult = await tx.execute({
      sql: "SELECT COUNT(*) AS cnt FROM analysis_usage WHERE subject_id = ? AND usage_date = ?",
      args: [subjectId, today],
    });
    let count = Number(countResult.rows[0]?.cnt || 0);

    if (!existing.rows.length && count < limit) {
      await tx.execute({
        sql: "INSERT INTO analysis_usage (subject_id, ticker, usage_date) VALUES (?, ?, ?)",
        args: [subjectId, ticker, today],
      });
      count++;
    } else if (!existing.rows.length && count >= limit) {
      await tx.commit();
      tx.close();
      return res.status(429).json({
        error: "Daily limit reached",
        limitReached: true,
        limit,
        remaining: 0,
        requiresLogin,
        plan,
      });
    }

    await tx.commit();
    tx.close();
    const remaining = Math.max(0, limit - count);
    res.setHeader("X-Plan", plan);
    res.setHeader("X-Analyses-Used", String(count));
    res.setHeader("X-Analyses-Remaining", String(remaining));
    res.setHeader("X-Analyses-Limit", String(limit));
    return next();
  } catch (e) {
    if (tx && !tx.closed) {
      try { await tx.rollback(); } catch (_) {}
      tx.close();
    }
    console.error("[quota] transaction failed:", e);
    return res.status(503).json({ error: "Analysis limit service unavailable. Please try again." });
  }
}

module.exports = {
  getEffectivePlan, requirePro, checkAnalysisLimit,
  guestIdMiddleware,
  FREE_DAILY_LIMIT, GUEST_DAILY_LIMIT,
  _dedupCache, // exported for tests
};

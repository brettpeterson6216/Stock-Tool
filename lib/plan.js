// ============================================================
//  Plan helpers — effective plan logic, Pro middleware,
//  analysis rate-limiter with per-ticker dedup
// ============================================================
const { db }    = require("./db");
const crypto    = require("crypto");
const { SESSION_SECRET } = require("./config");

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

// ── Dedup cache ────────────────────────────────────────────────────────────
// Key: "u:<userId>:<ticker>:<YYYY-MM-DD>"  (logged-in)
//      "g:<guestId>:<ticker>:<YYYY-MM-DD>" (guest)
// Value: true (already counted today for this ticker)
//
// The Map is bounded by DAU × avg-tickers/user per day.
// It is cleared at midnight to prevent stale keys accumulating.
const _dedupCache = new Map();

function _clearDedup() {
  _dedupCache.clear();
  console.log("[quota] Dedup cache cleared at midnight.");
}

// Schedule clear at next midnight, then every 24 h
(function scheduleMidnightClear() {
  const now  = new Date();
  const next = new Date(now);
  next.setDate(next.getDate() + 1);
  next.setHours(0, 0, 1, 0); // 00:00:01 next day
  const ms = next.getTime() - now.getTime();
  setTimeout(() => {
    _clearDedup();
    setInterval(_clearDedup, 24 * 60 * 60 * 1000);
  }, ms);
}());

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

  // ── Logged-in user path ───────────────────────────────────────────────
  if (req.session.userId) {
    let row;
    try {
      const r = await db.execute({
        sql:  "SELECT email, plan, trial_ends_at, analysis_date, analysis_count FROM users WHERE id = ?",
        args: [req.session.userId],
      });
      row = r.rows[0];
    } catch (_) { return next(); }

    if (!row) return next();

    const plan = getEffectivePlan(row);
    if (plan === "pro" || plan === "trial") {
      res.setHeader("X-Plan", plan);
      return next();
    }

    // Reset count if it's a new day
    const count = row.analysis_date === today ? (Number(row.analysis_count) || 0) : 0;

    // ── Dedup: same ticker already counted for this user today ───────────
    const dedupKey = `u:${req.session.userId}:${ticker}:${today}`;
    if (_dedupCache.has(dedupKey)) {
      // Ticker already counted — pass through without incrementing
      const remaining = FREE_DAILY_LIMIT - count;
      if (remaining <= 0) {
        console.log(`[quota] BLOCKED uid=${req.session.userId} ticker=${ticker} count=${count}/${FREE_DAILY_LIMIT} (dedup cached)`);
        return res.status(429).json({
          error: "Daily limit reached", limitReached: true,
          limit: FREE_DAILY_LIMIT, remaining: 0, plan: "free",
        });
      }
      console.log(`[quota] DEDUP uid=${req.session.userId} ticker=${ticker} count=${count}/${FREE_DAILY_LIMIT} (no increment)`);
      res.setHeader("X-Plan",               plan);
      res.setHeader("X-Analyses-Used",      String(count));
      res.setHeader("X-Analyses-Remaining", String(remaining));
      res.setHeader("X-Analyses-Limit",     String(FREE_DAILY_LIMIT));
      return next();
    }

    // New ticker for today — check limit before incrementing
    const remaining = FREE_DAILY_LIMIT - count;
    if (remaining <= 0) {
      console.log(`[quota] BLOCKED uid=${req.session.userId} ticker=${ticker} count=${count}/${FREE_DAILY_LIMIT}`);
      return res.status(429).json({
        error: "Daily limit reached", limitReached: true,
        limit: FREE_DAILY_LIMIT, remaining: 0, plan: "free",
      });
    }

    // Increment and mark dedup
    try {
      await db.execute({
        sql:  "UPDATE users SET analysis_date = ?, analysis_count = ? WHERE id = ?",
        args: [today, count + 1, req.session.userId],
      });
    } catch (_) {}

    _dedupCache.set(dedupKey, true);
    console.log(`[quota] INCREMENT uid=${req.session.userId} ticker=${ticker} ${count} → ${count + 1}/${FREE_DAILY_LIMIT}`);

    res.setHeader("X-Plan",               plan);
    res.setHeader("X-Analyses-Used",      String(count + 1));
    res.setHeader("X-Analyses-Remaining", String(remaining - 1));
    res.setHeader("X-Analyses-Limit",     String(FREE_DAILY_LIMIT));
    return next();
  }

  // ── Guest path — uses durable guestId cookie ─────────────────────────
  const guestId = req.guestId || req.sessionID; // fallback to session if middleware not mounted
  const guestDateKey  = `gd:${guestId}:${today}`;
  const guestCountKey = `gc:${guestId}:${today}`;

  // Count how many distinct tickers this guest has analyzed today
  // We store individual ticker dedup keys in the cache and count them
  const dedupKey = `g:${guestId}:${ticker}:${today}`;
  const alreadyCounted = _dedupCache.has(dedupKey);

  // Count distinct tickers for this guest today by scanning cache keys
  // (fast: Map.has is O(1), we need to count g:<guestId>:*:<today> keys)
  let guestCount = 0;
  for (const k of _dedupCache.keys()) {
    if (k.startsWith(`g:${guestId}:`) && k.endsWith(`:${today}`)) guestCount++;
  }

  if (alreadyCounted) {
    // Ticker already counted — pass through
    const remaining = GUEST_DAILY_LIMIT - guestCount;
    if (remaining <= 0) {
      console.log(`[quota] BLOCKED guest=${guestId.slice(0,8)} ticker=${ticker} count=${guestCount}/${GUEST_DAILY_LIMIT} (dedup cached)`);
      return res.status(429).json({
        error: "Daily limit reached", limitReached: true,
        limit: GUEST_DAILY_LIMIT, remaining: 0, requiresLogin: true, plan: "guest",
      });
    }
    console.log(`[quota] DEDUP guest=${guestId.slice(0,8)} ticker=${ticker} count=${guestCount}/${GUEST_DAILY_LIMIT} (no increment)`);
    res.setHeader("X-Plan",               "guest");
    res.setHeader("X-Analyses-Used",      String(guestCount));
    res.setHeader("X-Analyses-Remaining", String(remaining));
    res.setHeader("X-Analyses-Limit",     String(GUEST_DAILY_LIMIT));
    return next();
  }

  // New ticker for this guest today
  const remaining = GUEST_DAILY_LIMIT - guestCount;
  if (remaining <= 0) {
    console.log(`[quota] BLOCKED guest=${guestId.slice(0,8)} ticker=${ticker} count=${guestCount}/${GUEST_DAILY_LIMIT}`);
    return res.status(429).json({
      error: "Daily limit reached", limitReached: true,
      limit: GUEST_DAILY_LIMIT, remaining: 0, requiresLogin: true, plan: "guest",
    });
  }

  _dedupCache.set(dedupKey, true);
  console.log(`[quota] INCREMENT guest=${guestId.slice(0,8)} ticker=${ticker} ${guestCount} → ${guestCount + 1}/${GUEST_DAILY_LIMIT}`);

  res.setHeader("X-Plan",               "guest");
  res.setHeader("X-Analyses-Used",      String(guestCount + 1));
  res.setHeader("X-Analyses-Remaining", String(remaining - 1));
  res.setHeader("X-Analyses-Limit",     String(GUEST_DAILY_LIMIT));
  return next();
}

module.exports = {
  getEffectivePlan, requirePro, checkAnalysisLimit,
  guestIdMiddleware,
  FREE_DAILY_LIMIT, GUEST_DAILY_LIMIT,
  _dedupCache, // exported for tests
};

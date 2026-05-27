// ============================================================
//  Plan helpers — effective plan logic, Pro middleware,
//  analysis rate-limiter
// ============================================================
const { db } = require("./db");

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
 * Returns 401 if unauthenticated, 403 if on free plan.
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
 * Middleware — enforces daily analysis quota (free = 5/day, guest = 2/day).
 * Pro/trial users bypass this check entirely.
 */
async function checkAnalysisLimit(req, res, next) {
  const today = new Date().toISOString().slice(0, 10);
  const previewTicker = String(req.params.ticker || "").toUpperCase();

  if (req.query.preview === "1" && PREVIEW_QUOTE_TICKERS.has(previewTicker)) {
    res.setHeader("X-Plan", "preview");
    return next();
  }

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

    const count     = row.analysis_date === today ? (Number(row.analysis_count) || 0) : 0;
    const remaining = FREE_DAILY_LIMIT - count;

    if (remaining <= 0) {
      return res.status(429).json({
        error: "Daily limit reached", limitReached: true,
        limit: FREE_DAILY_LIMIT, remaining: 0, plan: "free",
      });
    }

    try {
      await db.execute({
        sql:  "UPDATE users SET analysis_date = ?, analysis_count = ? WHERE id = ?",
        args: [today, count + 1, req.session.userId],
      });
    } catch (_) {}

    res.setHeader("X-Plan",               plan);
    res.setHeader("X-Analyses-Used",      String(count + 1));
    res.setHeader("X-Analyses-Remaining", String(remaining - 1));
    res.setHeader("X-Analyses-Limit",     String(FREE_DAILY_LIMIT));
    return next();

  } else {
    if (req.session.guestDate !== today) {
      req.session.guestDate  = today;
      req.session.guestCount = 0;
    }
    const count     = req.session.guestCount || 0;
    const remaining = GUEST_DAILY_LIMIT - count;

    if (remaining <= 0) {
      return res.status(429).json({
        error: "Daily limit reached", limitReached: true,
        limit: GUEST_DAILY_LIMIT, remaining: 0, requiresLogin: true, plan: "guest",
      });
    }

    req.session.guestCount = count + 1;
    res.setHeader("X-Plan",               "guest");
    res.setHeader("X-Analyses-Used",      String(count + 1));
    res.setHeader("X-Analyses-Remaining", String(remaining - 1));
    res.setHeader("X-Analyses-Limit",     String(GUEST_DAILY_LIMIT));
    return next();
  }
}

module.exports = { getEffectivePlan, requirePro, checkAnalysisLimit, FREE_DAILY_LIMIT, GUEST_DAILY_LIMIT };

"use strict";

const express = require("express");
const { db } = require("../lib/db");
const { validateCsrf } = require("../lib/csrf");
const { sendEmail } = require("../lib/email");
const { track } = require("../lib/analytics");

const router = express.Router();
const TICKER_RE = /^[A-Z0-9.^-]{1,15}$/;

function workspaceError(res, error) {
  console.error("[workspace] request failed:", error.message || error);
  return res.status(500).json({ error: "Workspace service unavailable. Please try again." });
}

function requireUser(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: "Log in to sync your workspace." });
  next();
}

function ticker(value) {
  const clean = String(value || "").trim().toUpperCase();
  return TICKER_RE.test(clean) ? clean : null;
}

function text(value, max = 4000) {
  return String(value || "").trim().slice(0, max);
}

function numberOrNull(value) {
  if (value === "" || value === null || value === undefined) return null;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function dateOrNull(value) {
  const clean = String(value || "").trim();
  if (!clean) return null;
  if (!/^\d{4}-\d{2}-\d{2}$/.test(clean)) return undefined;
  const [year, month, day] = clean.split("-").map(Number);
  const parsed = new Date(Date.UTC(year, month - 1, day));
  if (parsed.getUTCFullYear() !== year || parsed.getUTCMonth() !== month - 1 || parsed.getUTCDate() !== day) {
    return undefined;
  }
  return clean;
}

function list(value) {
  const source = Array.isArray(value) ? value : String(value || "").split(/\r?\n/);
  return source.map(item => text(item, 280)).filter(Boolean).slice(0, 20);
}

function parseJson(value) {
  try { return JSON.parse(value || "[]"); } catch (_) { return []; }
}

function parseObject(value) {
  try {
    const parsed = JSON.parse(value || "{}");
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
  } catch (_) { return {}; }
}

function html(value) {
  return String(value || "").replace(/[&<>"']/g, char => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[char]));
}

function portfolioProfileRow(row) {
  if (!row) return null;
  return {
    goal: row.goal,
    horizon_years: Number(row.horizon_years),
    risk_tolerance: row.risk_tolerance,
    liquidity_need: row.liquidity_need,
    experience: row.experience,
    income_stability: row.income_stability,
    preference: row.preference,
    answers: parseObject(row.answers),
    model: parseObject(row.model),
    created_at: row.created_at,
    updated_at: row.updated_at,
  };
}

function choice(value, allowed) {
  const clean = String(value || "").trim().toLowerCase();
  return allowed.includes(clean) ? clean : null;
}

function buildPortfolioGuide(body = {}) {
  const goal = choice(body.goal, ["retirement", "growth", "income", "capital_preservation"]);
  const risk = choice(body.risk_tolerance, ["conservative", "balanced", "aggressive"]);
  const liquidity = choice(body.liquidity_need, ["low", "medium", "high"]);
  const experience = choice(body.experience, ["new", "intermediate", "experienced"]);
  const income = choice(body.income_stability, ["variable", "stable", "very_stable"]);
  const preference = choice(body.preference, ["passive", "blended", "active"]);
  const horizon = Number(body.horizon_years);
  if (!goal || !risk || !liquidity || !experience || !income || !preference ||
      !Number.isInteger(horizon) || horizon < 1 || horizon > 50) {
    return { error: "Complete each portfolio-guide question with a valid answer." };
  }

  let score = ({ conservative: -2, balanced: 0, aggressive: 2 })[risk];
  score += horizon <= 3 ? -2 : horizon <= 7 ? -1 : horizon >= 15 ? 2 : horizon >= 8 ? 1 : 0;
  score += ({ low: 0, medium: -1, high: -2 })[liquidity];
  score += ({ new: -1, intermediate: 0, experienced: 1 })[experience];
  score += ({ variable: -1, stable: 0, very_stable: 1 })[income];
  score += ({ capital_preservation: -2, income: -1, retirement: 0, growth: 1 })[goal];

  const archetype = score <= -3 ? "Defensive" : score >= 4 ? "Growth" : "Balanced";
  const allocations = archetype === "Defensive"
    ? { "US equity": 25, "International equity": 10, "Investment-grade bonds": 45, "Short-term reserves": 20 }
    : archetype === "Growth"
      ? { "US equity": 60, "International equity": 25, "Investment-grade bonds": 10, "Short-term reserves": 5 }
      : { "US equity": 45, "International equity": 20, "Investment-grade bonds": 25, "Short-term reserves": 10 };
  if (preference === "active" && archetype === "Growth") {
    allocations["US equity"] -= 5;
    allocations["Research sleeve"] = 5;
  }

  const model = {
    archetype,
    score,
    allocations: Object.entries(allocations).map(([asset, percent]) => ({ asset, percent })),
    rationale: [
      `${horizon}-year horizon with ${risk} stated risk tolerance.`,
      `${liquidity} near-term liquidity need and ${income.replace("_", " ")} income stability.`,
      `${preference} management preference with a ${goal.replace("_", " ")} primary goal.`,
    ],
    guardrails: [
      "Keep high-interest debt and an emergency reserve outside this model.",
      "Rebalance when an allocation drifts by about 5 percentage points or at a scheduled review.",
      "Use diversified, low-cost vehicles when translating asset classes into investments.",
      "Revisit the questionnaire after major income, family, tax, or time-horizon changes.",
    ],
    educationalOnly: true,
    disclosure: "This is an educational model allocation, not personalized investment advice. It does not consider your full finances, taxes, debts, legal constraints, or suitability.",
  };
  return {
    profile: { goal, horizon_years: horizon, risk_tolerance: risk, liquidity_need: liquidity, experience, income_stability: income, preference },
    model,
  };
}

function thesisRow(row) {
  return {
    ...row,
    id: Number(row.id),
    conviction: Number(row.conviction),
    target_price: numberOrNull(row.target_price),
    bear_price: numberOrNull(row.bear_price),
    catalysts: parseJson(row.catalysts),
    risks: parseJson(row.risks),
    sell_conditions: parseJson(row.sell_conditions),
  };
}

function positionRow(row) {
  return { ...row, id: Number(row.id), shares: Number(row.shares), cost_basis: Number(row.cost_basis) };
}

function watchlistRow(row) {
  return { ...row, id: Number(row.id), target_price: numberOrNull(row.target_price) };
}

router.use("/workspace", requireUser);

router.get("/workspace/summary", async (req, res) => {
  try {
    const [theses, positions, watchlist, profile, analyzed, reviewSchedule, dueReviews] = await Promise.all([
      db.execute({ sql: "SELECT COUNT(*) AS count FROM investment_theses WHERE user_id=?", args: [req.session.userId] }),
      db.execute({ sql: "SELECT COUNT(*) AS count, COALESCE(SUM(shares * cost_basis),0) AS invested FROM portfolio_positions WHERE user_id=?", args: [req.session.userId] }),
      db.execute({ sql: "SELECT COUNT(*) AS count FROM watchlist_items WHERE user_id=?", args: [req.session.userId] }),
      db.execute({ sql: "SELECT 1 FROM member_portfolio_profiles WHERE user_id=? LIMIT 1", args: [req.session.userId] }),
      db.execute({ sql: "SELECT 1 FROM analytics_events WHERE user_id=? AND event='analyze_completed' LIMIT 1", args: [req.session.userId] }),
      db.execute({ sql: "SELECT 1 FROM investment_theses WHERE user_id=? AND review_date IS NOT NULL AND review_date != '' LIMIT 1", args: [req.session.userId] }),
      db.execute({ sql: "SELECT COUNT(*) AS count FROM investment_theses WHERE user_id=? AND review_date IS NOT NULL AND review_date <= date('now', '+7 days')", args: [req.session.userId] }),
    ]);
    const activation = {
      analyzed: Boolean(analyzed.rows.length),
      thesis: Number(theses.rows[0]?.count || 0) > 0,
      watchlist: Number(watchlist.rows[0]?.count || 0) > 0,
      portfolioProfile: Boolean(profile.rows.length),
      reviewScheduled: Boolean(reviewSchedule.rows.length),
    };
    res.json({
      theses: Number(theses.rows[0]?.count || 0),
      positions: Number(positions.rows[0]?.count || 0),
      invested: Number(positions.rows[0]?.invested || 0),
      watchlist: Number(watchlist.rows[0]?.count || 0),
      dueReviews: Number(dueReviews.rows[0]?.count || 0),
      activation,
      activationCompleted: Object.values(activation).filter(Boolean).length,
      activationTotal: Object.keys(activation).length,
    });
  } catch (error) { workspaceError(res, error); }
});

router.get("/workspace/portfolio-profile", async (req, res) => {
  try {
    const result = await db.execute({ sql: "SELECT * FROM member_portfolio_profiles WHERE user_id=? LIMIT 1", args: [req.session.userId] });
    res.json(portfolioProfileRow(result.rows[0]));
  } catch (error) { workspaceError(res, error); }
});

router.put("/workspace/portfolio-profile", validateCsrf, async (req, res) => {
  const guide = buildPortfolioGuide(req.body || {});
  if (guide.error) return res.status(400).json({ error: guide.error });
  try {
    const profile = guide.profile;
    await db.execute({
      sql: `INSERT INTO member_portfolio_profiles
        (user_id,goal,horizon_years,risk_tolerance,liquidity_need,experience,income_stability,preference,answers,model,updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP)
        ON CONFLICT(user_id) DO UPDATE SET goal=excluded.goal,horizon_years=excluded.horizon_years,
        risk_tolerance=excluded.risk_tolerance,liquidity_need=excluded.liquidity_need,experience=excluded.experience,
        income_stability=excluded.income_stability,preference=excluded.preference,answers=excluded.answers,
        model=excluded.model,updated_at=CURRENT_TIMESTAMP`,
      args: [req.session.userId, profile.goal, profile.horizon_years, profile.risk_tolerance, profile.liquidity_need,
        profile.experience, profile.income_stability, profile.preference, JSON.stringify(profile), JSON.stringify(guide.model)],
    });
    track("portfolio_profile_saved", { archetype: guide.model.archetype }, req.sessionID, req.session.userId).catch(() => {});
    const result = await db.execute({ sql: "SELECT * FROM member_portfolio_profiles WHERE user_id=? LIMIT 1", args: [req.session.userId] });
    res.json(portfolioProfileRow(result.rows[0]));
  } catch (error) { workspaceError(res, error); }
});

router.post("/workspace/review-reminder", validateCsrf, async (req, res) => {
  const referenceKey = new Date().toISOString().slice(0, 10);
  let claimed = false;
  try {
    const [userResult, reviewResult] = await Promise.all([
      db.execute({ sql: "SELECT email FROM users WHERE id=? LIMIT 1", args: [req.session.userId] }),
      db.execute({ sql: "SELECT ticker,status,review_date FROM investment_theses WHERE user_id=? AND review_date IS NOT NULL AND review_date <= date('now', '+7 days') ORDER BY review_date ASC LIMIT 30", args: [req.session.userId] }),
    ]);
    if (!reviewResult.rows.length) return res.status(400).json({ error: "Schedule a thesis review due within the next 7 days first." });
    const email = userResult.rows[0]?.email;
    if (!email) return res.status(404).json({ error: "Member email not found." });
    const claim = await db.execute({
      sql: "INSERT OR IGNORE INTO lifecycle_email_log (user_id,email_type,reference_key) VALUES (?,'review_digest',?)",
      args: [req.session.userId, referenceKey],
    });
    claimed = Number(claim.rowsAffected || 0) > 0;
    if (!claimed) return res.json({ ok: true, alreadySent: true, count: reviewResult.rows.length });
    const rows = reviewResult.rows.map(row => `<li><strong>${html(row.ticker)}</strong> - ${html(row.status)} - review ${html(row.review_date)}</li>`).join("");
    const result = await sendEmail({
      to: email,
      subject: `ImpliedLens review list: ${reviewResult.rows.length} decision${reviewResult.rows.length === 1 ? "" : "s"} due`,
      html: `<h2>Your upcoming investment reviews</h2><p>Review the evidence, thesis, and sell conditions before changing a position.</p><ul>${rows}</ul><p><a href="${html(process.env.APP_URL || "https://www.impliedlens.com")}/?view=tool&section=workspace">Open your workspace</a></p>`,
    });
    if (!result?.sent && !result?.simulated) {
      await db.execute({ sql: "DELETE FROM lifecycle_email_log WHERE user_id=? AND email_type='review_digest' AND reference_key=?", args: [req.session.userId, referenceKey] });
      claimed = false;
      return res.status(502).json({ error: "Could not send the review email. Please try again." });
    }
    claimed = false;
    track("review_reminder_requested", { count: reviewResult.rows.length }, req.sessionID, req.session.userId).catch(() => {});
    res.json({ ok: true, alreadySent: false, simulated: Boolean(result.simulated), count: reviewResult.rows.length });
  } catch (error) {
    if (claimed) {
      await db.execute({ sql: "DELETE FROM lifecycle_email_log WHERE user_id=? AND email_type='review_digest' AND reference_key=?", args: [req.session.userId, referenceKey] }).catch(() => {});
    }
    workspaceError(res, error);
  }
});

router.get("/workspace/theses", async (req, res) => {
  try {
    const result = await db.execute({ sql: "SELECT * FROM investment_theses WHERE user_id=? ORDER BY updated_at DESC LIMIT 200", args: [req.session.userId] });
    res.json(result.rows.map(thesisRow));
  } catch (error) { workspaceError(res, error); }
});

router.get("/workspace/theses/:ticker", async (req, res) => {
  const symbol = ticker(req.params.ticker);
  if (!symbol) return res.status(400).json({ error: "Invalid ticker." });
  try {
    const result = await db.execute({ sql: "SELECT * FROM investment_theses WHERE user_id=? AND ticker=? LIMIT 1", args: [req.session.userId, symbol] });
    res.json(result.rows[0] ? thesisRow(result.rows[0]) : null);
  } catch (error) { workspaceError(res, error); }
});

router.put("/workspace/theses/:ticker", validateCsrf, async (req, res) => {
  const symbol = ticker(req.params.ticker);
  if (!symbol) return res.status(400).json({ error: "Invalid ticker." });
  const body = req.body || {};
  const status = ["watching", "owned", "passed", "review"].includes(body.status) ? body.status : "watching";
  const conviction = Math.max(1, Math.min(5, Number(body.conviction) || 3));
  const reviewDate = dateOrNull(body.review_date);
  if (reviewDate === undefined) return res.status(400).json({ error: "Review date must be a valid YYYY-MM-DD date." });
  try {
    await db.execute({
      sql: `INSERT INTO investment_theses
        (user_id,ticker,status,thesis,catalysts,risks,sell_conditions,target_price,bear_price,review_date,conviction,updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP)
        ON CONFLICT(user_id,ticker) DO UPDATE SET status=excluded.status,thesis=excluded.thesis,catalysts=excluded.catalysts,
        risks=excluded.risks,sell_conditions=excluded.sell_conditions,target_price=excluded.target_price,bear_price=excluded.bear_price,
        review_date=excluded.review_date,conviction=excluded.conviction,updated_at=CURRENT_TIMESTAMP`,
      args: [req.session.userId, symbol, status, text(body.thesis), JSON.stringify(list(body.catalysts)),
        JSON.stringify(list(body.risks)), JSON.stringify(list(body.sell_conditions)), numberOrNull(body.target_price),
        numberOrNull(body.bear_price), reviewDate, conviction],
    });
    const result = await db.execute({ sql: "SELECT * FROM investment_theses WHERE user_id=? AND ticker=?", args: [req.session.userId, symbol] });
    res.json(thesisRow(result.rows[0]));
  } catch (error) { workspaceError(res, error); }
});

router.delete("/workspace/theses/:ticker", validateCsrf, async (req, res) => {
  const symbol = ticker(req.params.ticker);
  if (!symbol) return res.status(400).json({ error: "Invalid ticker." });
  try {
    await db.execute({ sql: "DELETE FROM investment_theses WHERE user_id=? AND ticker=?", args: [req.session.userId, symbol] });
    res.json({ ok: true });
  } catch (error) { workspaceError(res, error); }
});

router.get("/workspace/positions", async (req, res) => {
  try {
    const result = await db.execute({ sql: "SELECT * FROM portfolio_positions WHERE user_id=? ORDER BY updated_at DESC LIMIT 200", args: [req.session.userId] });
    res.json(result.rows.map(positionRow));
  } catch (error) { workspaceError(res, error); }
});

router.put("/workspace/positions/:ticker", validateCsrf, async (req, res) => {
  const symbol = ticker(req.params.ticker);
  const body = req.body || {};
  const shares = Number(body.shares);
  const costBasis = Number(body.cost_basis);
  if (!symbol || !Number.isFinite(shares) || shares <= 0 || !Number.isFinite(costBasis) || costBasis < 0) {
    return res.status(400).json({ error: "Ticker, positive shares, and a valid cost basis are required." });
  }
  try {
    await db.execute({
      sql: `INSERT INTO portfolio_positions (user_id,ticker,shares,cost_basis,sector,notes,updated_at) VALUES (?,?,?,?,?,?,CURRENT_TIMESTAMP)
        ON CONFLICT(user_id,ticker) DO UPDATE SET shares=excluded.shares,cost_basis=excluded.cost_basis,sector=excluded.sector,notes=excluded.notes,updated_at=CURRENT_TIMESTAMP`,
      args: [req.session.userId, symbol, shares, costBasis, text(body.sector, 80), text(body.notes, 1000)],
    });
    const result = await db.execute({ sql: "SELECT * FROM portfolio_positions WHERE user_id=? AND ticker=?", args: [req.session.userId, symbol] });
    res.json(positionRow(result.rows[0]));
  } catch (error) { workspaceError(res, error); }
});

router.delete("/workspace/positions/:ticker", validateCsrf, async (req, res) => {
  const symbol = ticker(req.params.ticker);
  if (!symbol) return res.status(400).json({ error: "Invalid ticker." });
  try {
    await db.execute({ sql: "DELETE FROM portfolio_positions WHERE user_id=? AND ticker=?", args: [req.session.userId, symbol] });
    res.json({ ok: true });
  } catch (error) { workspaceError(res, error); }
});

router.get("/workspace/watchlist", async (req, res) => {
  try {
    const result = await db.execute({ sql: "SELECT * FROM watchlist_items WHERE user_id=? ORDER BY created_at DESC LIMIT 200", args: [req.session.userId] });
    res.json(result.rows.map(watchlistRow));
  } catch (error) { workspaceError(res, error); }
});

router.put("/workspace/watchlist/:ticker", validateCsrf, async (req, res) => {
  const symbol = ticker(req.params.ticker);
  if (!symbol) return res.status(400).json({ error: "Invalid ticker." });
  const body = req.body || {};
  try {
    await db.execute({
      sql: `INSERT INTO watchlist_items (user_id,ticker,note,target_price) VALUES (?,?,?,?)
        ON CONFLICT(user_id,ticker) DO UPDATE SET note=excluded.note,target_price=excluded.target_price`,
      args: [req.session.userId, symbol, text(body.note, 500), numberOrNull(body.target_price)],
    });
    const result = await db.execute({ sql: "SELECT * FROM watchlist_items WHERE user_id=? AND ticker=?", args: [req.session.userId, symbol] });
    res.json(watchlistRow(result.rows[0]));
  } catch (error) { workspaceError(res, error); }
});

router.delete("/workspace/watchlist/:ticker", validateCsrf, async (req, res) => {
  const symbol = ticker(req.params.ticker);
  if (!symbol) return res.status(400).json({ error: "Invalid ticker." });
  try {
    await db.execute({ sql: "DELETE FROM watchlist_items WHERE user_id=? AND ticker=?", args: [req.session.userId, symbol] });
    res.json({ ok: true });
  } catch (error) { workspaceError(res, error); }
});

module.exports = router;

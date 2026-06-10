"use strict";

const express = require("express");
const { db } = require("../lib/db");
const { validateCsrf } = require("../lib/csrf");

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

function list(value) {
  const source = Array.isArray(value) ? value : String(value || "").split(/\r?\n/);
  return source.map(item => text(item, 280)).filter(Boolean).slice(0, 20);
}

function parseJson(value) {
  try { return JSON.parse(value || "[]"); } catch (_) { return []; }
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
    const [theses, positions, watchlist] = await Promise.all([
      db.execute({ sql: "SELECT COUNT(*) AS count FROM investment_theses WHERE user_id=?", args: [req.session.userId] }),
      db.execute({ sql: "SELECT COUNT(*) AS count, COALESCE(SUM(shares * cost_basis),0) AS invested FROM portfolio_positions WHERE user_id=?", args: [req.session.userId] }),
      db.execute({ sql: "SELECT COUNT(*) AS count FROM watchlist_items WHERE user_id=?", args: [req.session.userId] }),
    ]);
    res.json({
      theses: Number(theses.rows[0]?.count || 0),
      positions: Number(positions.rows[0]?.count || 0),
      invested: Number(positions.rows[0]?.invested || 0),
      watchlist: Number(watchlist.rows[0]?.count || 0),
    });
  } catch (error) { workspaceError(res, error); }
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
  const status = ["watching", "owned", "passed", "review"].includes(req.body.status) ? req.body.status : "watching";
  const conviction = Math.max(1, Math.min(5, Number(req.body.conviction) || 3));
  try {
    await db.execute({
      sql: `INSERT INTO investment_theses
        (user_id,ticker,status,thesis,catalysts,risks,sell_conditions,target_price,bear_price,review_date,conviction,updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP)
        ON CONFLICT(user_id,ticker) DO UPDATE SET status=excluded.status,thesis=excluded.thesis,catalysts=excluded.catalysts,
        risks=excluded.risks,sell_conditions=excluded.sell_conditions,target_price=excluded.target_price,bear_price=excluded.bear_price,
        review_date=excluded.review_date,conviction=excluded.conviction,updated_at=CURRENT_TIMESTAMP`,
      args: [req.session.userId, symbol, status, text(req.body.thesis), JSON.stringify(list(req.body.catalysts)),
        JSON.stringify(list(req.body.risks)), JSON.stringify(list(req.body.sell_conditions)), numberOrNull(req.body.target_price),
        numberOrNull(req.body.bear_price), text(req.body.review_date, 20) || null, conviction],
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
  const shares = Number(req.body.shares);
  const costBasis = Number(req.body.cost_basis);
  if (!symbol || !Number.isFinite(shares) || shares <= 0 || !Number.isFinite(costBasis) || costBasis < 0) {
    return res.status(400).json({ error: "Ticker, positive shares, and a valid cost basis are required." });
  }
  try {
    await db.execute({
      sql: `INSERT INTO portfolio_positions (user_id,ticker,shares,cost_basis,sector,notes,updated_at) VALUES (?,?,?,?,?,?,CURRENT_TIMESTAMP)
        ON CONFLICT(user_id,ticker) DO UPDATE SET shares=excluded.shares,cost_basis=excluded.cost_basis,sector=excluded.sector,notes=excluded.notes,updated_at=CURRENT_TIMESTAMP`,
      args: [req.session.userId, symbol, shares, costBasis, text(req.body.sector, 80), text(req.body.notes, 1000)],
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
  try {
    await db.execute({
      sql: `INSERT INTO watchlist_items (user_id,ticker,note,target_price) VALUES (?,?,?,?)
        ON CONFLICT(user_id,ticker) DO UPDATE SET note=excluded.note,target_price=excluded.target_price`,
      args: [req.session.userId, symbol, text(req.body.note, 500), numberOrNull(req.body.target_price)],
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

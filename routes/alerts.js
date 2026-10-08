"use strict";
const express = require("express");
const { db } = require("../lib/db");
const { validateCsrf } = require("../lib/csrf");
const { getEffectivePlan, normalizeTicker } = require("../lib/plan");
const Alerts = require("../lib/alerts");
const universeGrades = require("../lib/universe-grades");

const router = express.Router();

async function currentUser(req, res) {
  if (!req.session.userId) { res.status(401).json({ error: "Log in to set alerts.", requiresLogin: true }); return null; }
  const r = await db.execute({ sql: "SELECT id, email, plan, trial_ends_at FROM users WHERE id = ?", args: [req.session.userId] });
  if (!r.rows[0]) { res.status(401).json({ error: "Log in to set alerts.", requiresLogin: true }); return null; }
  return r.rows[0];
}

router.get("/alerts", async (req, res) => {
  try {
    const user = await currentUser(req, res);
    if (!user) return;
    const plan = getEffectivePlan(user);
    res.json({ alerts: await Alerts.list(user.id), limit: Alerts.LIMITS[plan] || Alerts.LIMITS.free, plan });
  } catch (error) {
    console.error("[alerts] list failed:", error.message);
    res.status(500).json({ error: "Alerts are unavailable right now." });
  }
});

router.post("/alerts", validateCsrf, async (req, res) => {
  try {
    const user = await currentUser(req, res);
    if (!user) return;
    const body = req.body || {};
    const ticker = normalizeTicker(body.ticker);
    if (!ticker) return res.status(400).json({ error: "Invalid ticker." });
    let baseline = null;
    if (body.kind === "score") {
      const g = universeGrades.get(ticker);
      if (!g) return res.status(400).json({ error: "This company is not graded yet, so a grade alert cannot be set." });
      baseline = { score: g.score, grades: g.grades };
    }
    const out = await Alerts.create(user.id, getEffectivePlan(user), { ticker, kind: body.kind, level: body.level, baseline, note: body.note });
    res.json({ ok: true, ...out, alerts: await Alerts.list(user.id) });
  } catch (error) {
    res.status(error.status || 500).json({ error: error.status ? error.message : "Could not save the alert.", upgrade: !!error.upgrade });
  }
});

router.delete("/alerts/:id", validateCsrf, async (req, res) => {
  try {
    const user = await currentUser(req, res);
    if (!user) return;
    await Alerts.remove(user.id, req.params.id);
    res.json({ ok: true, alerts: await Alerts.list(user.id) });
  } catch (error) {
    res.status(500).json({ error: "Could not delete the alert." });
  }
});

module.exports = router;

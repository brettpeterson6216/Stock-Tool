"use strict";
/* ═══════════════════════════════════════════════════════════════════════════
   Email alerts.

     above       price closes or trades at/above a level        (one-shot)
     below       price at/below a level                         (one-shot)
     buy_zone    price reaches the top of the nearest buy zone  (one-shot)
     score       LensScore moves 1.0+ or a factor changes letter (repeats;
                 the baseline moves to the new grades after each email)

   A checker runs every ten minutes. Price alerts are checked while US
   markets trade; grade alerts once after the close, when grades refresh.
   ═══════════════════════════════════════════════════════════════════════════ */

const { db } = require("./db");
const { sendEmail } = require("./email");

const KINDS = ["above", "below", "buy_zone", "score"];
const LIMITS = { free: 3, trial: 25, pro: 50 };

let ready = null;
function ensure() {
  if (!ready) {
    ready = (async () => {
      await db.execute({ sql: `CREATE TABLE IF NOT EXISTS price_alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        ticker TEXT NOT NULL,
        kind TEXT NOT NULL,
        level REAL,
        baseline TEXT,
        note TEXT,
        active INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        triggered_at TEXT,
        last_value REAL
      )`, args: [] });
      await db.execute({ sql: "CREATE INDEX IF NOT EXISTS idx_price_alerts_user ON price_alerts(user_id, active)", args: [] });
      await db.execute({ sql: "CREATE INDEX IF NOT EXISTS idx_price_alerts_active ON price_alerts(active, ticker)", args: [] });
    })().catch(e => { ready = null; throw e; });
  }
  return ready;
}

function rowOut(r) {
  let baseline = null;
  try { baseline = r.baseline ? JSON.parse(r.baseline) : null; } catch (_) { baseline = null; }
  return {
    id: Number(r.id), ticker: r.ticker, kind: r.kind, level: r.level == null ? null : Number(r.level), baseline,
    note: r.note || "", active: !!Number(r.active), createdAt: r.created_at, triggeredAt: r.triggered_at || null,
    lastValue: r.last_value == null ? null : Number(r.last_value),
  };
}

async function list(userId) {
  await ensure();
  const res = await db.execute({ sql: "SELECT * FROM price_alerts WHERE user_id = ? ORDER BY active DESC, created_at DESC LIMIT 100", args: [userId] });
  return res.rows.map(rowOut);
}

async function create(userId, plan, { ticker, kind, level, baseline, note }) {
  await ensure();
  if (!KINDS.includes(kind)) throw Object.assign(new Error("Unknown alert type."), { status: 400 });
  if (kind !== "score" && !(Number(level) > 0)) throw Object.assign(new Error("Enter a price above zero."), { status: 400 });
  const limit = LIMITS[plan] || LIMITS.free;
  const count = await db.execute({ sql: "SELECT COUNT(*) AS n FROM price_alerts WHERE user_id = ? AND active = 1", args: [userId] });
  if (Number(count.rows[0]?.n || 0) >= limit) {
    throw Object.assign(new Error(plan === "free"
      ? `Free accounts can keep ${limit} alerts at once. Delete one, or upgrade to Pro for ${LIMITS.pro}.`
      : `You have reached ${limit} active alerts. Delete one to add another.`), { status: 403, upgrade: plan === "free" });
  }
  const dup = await db.execute({
    sql: "SELECT id FROM price_alerts WHERE user_id = ? AND ticker = ? AND kind = ? AND active = 1 AND (level IS ? OR level = ?)",
    args: [userId, ticker, kind, kind === "score" ? null : Number(level), kind === "score" ? null : Number(level)],
  });
  if (dup.rows[0]) return { id: Number(dup.rows[0].id), duplicate: true };
  const res = await db.execute({
    sql: "INSERT INTO price_alerts (user_id, ticker, kind, level, baseline, note) VALUES (?, ?, ?, ?, ?, ?)",
    args: [userId, ticker, kind, kind === "score" ? null : Number(level), baseline ? JSON.stringify(baseline) : null, String(note || "").slice(0, 200)],
  });
  return { id: Number(res.lastInsertRowid) };
}

async function remove(userId, id) {
  await ensure();
  await db.execute({ sql: "DELETE FROM price_alerts WHERE user_id = ? AND id = ?", args: [userId, Number(id)] });
}

/* ── evaluation (pure, exported for tests) ──────────────────────────────── */
const LETTER = g => (g ? g[0] : null);
function evaluate(alert, { price, grade }) {
  if (alert.kind === "above") return Number(price) >= alert.level ? { hit: true, value: Number(price) } : { hit: false };
  if (alert.kind === "below" || alert.kind === "buy_zone") return Number(price) > 0 && Number(price) <= alert.level ? { hit: true, value: Number(price) } : { hit: false };
  if (alert.kind === "score") {
    if (!grade || !alert.baseline) return { hit: false };
    const b = alert.baseline;
    const moved = Math.abs(Number(grade.score) - Number(b.score)) >= 1;
    const changes = Object.keys(grade.grades || {}).filter(k => b.grades && b.grades[k] && LETTER(b.grades[k]) !== LETTER(grade.grades[k]));
    if (!moved && !changes.length) return { hit: false };
    return { hit: true, value: Number(grade.score), changes, from: b, to: { score: grade.score, grades: grade.grades } };
  }
  return { hit: false };
}

const NAMES = { value: "Value", growth: "Growth", profitability: "Profitability", health: "Financial health", momentum: "Momentum" };
function describe(alert, result) {
  const t = alert.ticker;
  const money = v => `$${Number(v).toFixed(Number(v) >= 1000 ? 0 : 2)}`;
  if (alert.kind === "above") return `${t} traded at ${money(result.value)}, at or above your ${money(alert.level)} alert.`;
  if (alert.kind === "below") return `${t} traded at ${money(result.value)}, at or below your ${money(alert.level)} alert.`;
  if (alert.kind === "buy_zone") return `${t} reached its buy zone: ${money(result.value)}, at or below the zone top of ${money(alert.level)}.`;
  const parts = [`${t}'s LensScore moved from ${Number(result.from.score).toFixed(1)} to ${Number(result.to.score).toFixed(1)}.`];
  if (result.changes.length) parts.push(`Grade changes: ${result.changes.map(k => `${NAMES[k] || k} ${result.from.grades[k]} → ${result.to.grades[k]}`).join(", ")}.`);
  return parts.join(" ");
}

/* ── checker ────────────────────────────────────────────────────────────── */
function etNow(now = new Date()) {
  const p = Object.fromEntries(new Intl.DateTimeFormat("en-US", {
    timeZone: "America/New_York", weekday: "short", hour: "numeric", minute: "numeric", hour12: false, year: "numeric", month: "2-digit", day: "2-digit",
  }).formatToParts(now).map(x => [x.type, x.value]));
  return { weekday: p.weekday, mins: (Number(p.hour) % 24) * 60 + Number(p.minute), day: `${p.year}-${p.month}-${p.day}` };
}

async function latestPrice(ticker) {
  const sym = String(ticker).replace(/^([A-Z]{1,5})\.([A-Z]{1,2})$/, "$1-$2");
  try {
    const r = await fetch(`https://query1.finance.yahoo.com/v8/finance/chart/${encodeURIComponent(sym)}?interval=5m&range=1d`, {
      headers: { "User-Agent": "Mozilla/5.0" }, signal: AbortSignal.timeout(8000),
    });
    if (!r.ok) return null;
    const j = await r.json();
    const v = Number(j?.chart?.result?.[0]?.meta?.regularMarketPrice);
    return v > 0 ? v : null;
  } catch (_) { return null; }
}

let lastScoreDay = null;
async function runOnce({ force = false } = {}) {
  await ensure();
  const { weekday, mins, day } = etNow();
  const weekend = ["Sat", "Sun"].includes(weekday);
  const marketHours = !weekend && mins >= 9 * 60 + 30 && mins <= 16 * 60 + 5;
  const scoreTime = !weekend && mins >= 16 * 60 + 30 && lastScoreDay !== day;
  if (!force && !marketHours && !scoreTime) return { skipped: true };
  const kinds = force ? KINDS : [...(marketHours ? ["above", "below", "buy_zone"] : []), ...(scoreTime ? ["score"] : [])];
  if (scoreTime) lastScoreDay = day;
  const res = await db.execute({
    sql: `SELECT a.*, u.email FROM price_alerts a JOIN users u ON u.id = a.user_id WHERE a.active = 1 AND a.kind IN (${kinds.map(() => "?").join(",")}) LIMIT 2000`,
    args: kinds,
  });
  const alerts = res.rows.map(r => ({ ...rowOut(r), userId: Number(r.user_id), email: r.email }));
  const prices = {};
  const tickers = [...new Set(alerts.filter(a => a.kind !== "score").map(a => a.ticker))];
  for (const t of tickers) prices[t] = await latestPrice(t);
  const universeGrades = require("./universe-grades");
  const hits = [];
  for (const a of alerts) {
    const result = evaluate(a, { price: prices[a.ticker], grade: a.kind === "score" ? universeGrades.get(a.ticker) : null });
    if (!result.hit) continue;
    hits.push({ a, result, text: describe(a, result) });
    if (a.kind === "score") {
      await db.execute({ sql: "UPDATE price_alerts SET baseline = ?, triggered_at = CURRENT_TIMESTAMP, last_value = ? WHERE id = ?", args: [JSON.stringify(result.to), result.value, a.id] });
    } else {
      await db.execute({ sql: "UPDATE price_alerts SET active = 0, triggered_at = CURRENT_TIMESTAMP, last_value = ? WHERE id = ?", args: [result.value, a.id] });
    }
  }
  const byUser = new Map();
  hits.forEach(h => { if (h.a.email) (byUser.get(h.a.email) || byUser.set(h.a.email, []).get(h.a.email)).push(h); });
  const base = process.env.APP_URL || "https://impliedlens.com";
  const esc = v => String(v ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  for (const [email, list] of byUser) {
    const items = list.map(h => `<li style="margin-bottom:10px"><strong>${esc(h.a.ticker)}</strong>: ${esc(h.text)}${h.a.note ? `<br><span style="color:#777">Your note: ${esc(h.a.note)}</span>` : ""}<br><a href="${base}/lens-score?ticker=${encodeURIComponent(h.a.ticker)}" style="color:#9A6A18">Open the report card</a></li>`).join("");
    const subject = list.length === 1 ? `ImpliedLens alert: ${list[0].a.ticker}` : `ImpliedLens: ${list.length} alerts triggered`;
    await sendEmail({
      to: email, subject,
      html: `<div style="font-family:Arial,sans-serif;max-width:560px"><h2 style="color:#9A6A18">Your alert${list.length === 1 ? "" : "s"}</h2><ul style="padding-left:18px">${items}</ul><p style="color:#999;font-size:12px">Prices from Yahoo Finance, checked every 10 minutes while US markets are open. Price alerts switch off after they fire; grade alerts keep watching. Manage alerts on the LensToolkit page. Not investment advice.</p></div>`,
    }).catch(() => {});
  }
  return { checked: alerts.length, triggered: hits.length };
}

function start({ everyMs = 10 * 60 * 1000 } = {}) {
  const run = () => runOnce().catch(e => console.warn("[alerts] run failed:", String(e.message || e).slice(0, 160)));
  setTimeout(run, 60 * 1000).unref?.();
  setInterval(run, everyMs).unref?.();
}

module.exports = { KINDS, LIMITS, list, create, remove, evaluate, describe, runOnce, start, ensure };

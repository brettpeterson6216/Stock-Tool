"use strict";
/* ═══════════════════════════════════════════════════════════════════════════
   The weekly grade-change email.

   Saturday morning (US Eastern), one email per member who has a watchlist:
   each company's LensScore and its change over the week, any letter grades
   that moved, and the week's biggest score changes across everything we grade.
   A reason to come back every week, built only from data we already keep.

   Rules:
     · At most one per user per week (lifecycle_email_log claim, released if
       the send fails so the next hourly run retries).
     · Never to anyone who unsubscribed (users.digest_opt_out).
     · Every email carries a signed one-click unsubscribe link and the
       List-Unsubscribe headers mail providers look for.
     · Statements are always { sql, args } (see test/review-digest.test.js:
       the production libSQL client throws on an object without args).
   ═══════════════════════════════════════════════════════════════════════════ */
const crypto = require("crypto");
const { db } = require("./db");
const { SESSION_SECRET, APP_URL } = require("./config");
const universeGrades = require("./universe-grades");
const LensHistory = require("./lens-history");

const KEYS = ["value", "growth", "profitability", "health", "momentum"];
const LABEL = { value: "Value", growth: "Growth", profitability: "Profitability", health: "Financial health", momentum: "Momentum" };
const RANK = { "A+": 13, A: 12, "A-": 11, "B+": 10, B: 9, "B-": 8, "C+": 7, C: 6, "C-": 5, "D+": 4, D: 3, "D-": 2, F: 1 };

function base() { return String(process.env.APP_URL || APP_URL || "https://impliedlens.com").replace(/\/+$/, ""); }

function unsubscribeToken(userId) {
  return crypto.createHmac("sha256", String(SESSION_SECRET)).update("weekly-digest:" + Number(userId)).digest("hex").slice(0, 32);
}
function verifyUnsubscribe(userId, token) {
  const want = Buffer.from(unsubscribeToken(userId));
  const got = Buffer.from(String(token || ""));
  return want.length === got.length && crypto.timingSafeEqual(want, got);
}
function unsubscribeUrl(userId) {
  return `${base()}/unsubscribe/weekly?u=${Number(userId)}&t=${unsubscribeToken(userId)}`;
}

/* Saturday in New York, 08:00–20:59. Returns the week key (that Saturday). */
function dueWeek(now = new Date()) {
  const { day, weekday, hour } = LensHistory.etParts(now);
  if (weekday !== "Sat" || hour < 8 || hour > 20) return null;
  return day;
}

const esc = v => String(v ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const signed = (n, d = 1) => (n > 0 ? "+" : n < 0 ? "−" : "") + Math.abs(n).toFixed(d);

/* Pure: the email for one member. rows = [{ ticker, name, score, change, grades, before }]. */
function buildEmail({ username, rows, movers, since, userId }) {
  const graded = rows.filter(r => Number.isFinite(r.score));
  const letterMoves = [];
  graded.forEach(r => KEYS.forEach(k => {
    const a = r.before && r.before[k], b = r.grades && r.grades[k];
    if (a && b && a !== b) letterMoves.push({ ticker: r.ticker, factor: LABEL[k], from: a, to: b, up: (RANK[b] || 0) > (RANK[a] || 0) });
  }));
  const biggest = graded.filter(r => Number.isFinite(r.change) && r.change !== 0).sort((a, b) => Math.abs(b.change) - Math.abs(a.change))[0];
  const subject = biggest
    ? `${biggest.ticker} ${biggest.change > 0 ? "up" : "down"} ${Math.abs(biggest.change).toFixed(1)} on the LensScore this week`
    : letterMoves.length ? `${letterMoves.length} grade change${letterMoves.length === 1 ? "" : "s"} on your watchlist`
    : "Your watchlist this week";
  const gold = "#9A6A18", line = "#E5E2DA", muted = "#6B7179";
  const cell = "padding:10px 8px;border-top:1px solid " + line;
  const table = graded.length ? `<table role="presentation" cellpadding="0" cellspacing="0" style="width:100%;border-collapse:collapse;font-size:14px">
    <tr style="color:${muted};font-size:12px;text-align:left"><th style="padding:6px 8px">Company</th><th style="padding:6px 8px;text-align:right">LensScore</th><th style="padding:6px 8px;text-align:right">This week</th></tr>
    ${graded.map(r => `<tr><td style="${cell}"><a href="${base()}/research/${encodeURIComponent(r.ticker)}" style="color:#16181B;font-weight:bold;text-decoration:none">${esc(r.ticker)}</a> <span style="color:${muted}">${esc(r.name || "")}</span></td>
      <td style="${cell};text-align:right;font-weight:bold">${r.score.toFixed(1)}</td>
      <td style="${cell};text-align:right;color:${r.change > 0 ? "#17804F" : r.change < 0 ? "#C23B33" : muted}">${Number.isFinite(r.change) && r.change !== 0 ? signed(r.change) : "no change"}</td></tr>`).join("")}
  </table>` : "";
  const moves = letterMoves.length ? `<h3 style="font-size:15px;margin:22px 0 6px">Grades that moved</h3><ul style="padding-left:18px;margin:0">${letterMoves.slice(0, 12).map(m =>
    `<li style="margin:4px 0"><b>${esc(m.ticker)}</b> ${esc(m.factor)} ${esc(m.from)} → <b style="color:${m.up ? "#17804F" : "#C23B33"}">${esc(m.to)}</b></li>`).join("")}</ul>` : "";
  const market = movers && (movers.up.length || movers.down.length) ? `<h3 style="font-size:15px;margin:22px 0 6px">Biggest changes across all graded stocks</h3><p style="margin:0;color:${muted};font-size:13px">${
    [...movers.up.slice(0, 3), ...movers.down.slice(0, 2)].map(m => `<a href="${base()}/research/${encodeURIComponent(m.ticker)}" style="color:${gold};text-decoration:none;font-weight:bold">${esc(m.ticker)}</a> ${m.then.toFixed(1)} → ${m.now.toFixed(1)}`).join(" · ")}</p>` : "";
  const html = `<div style="font-family:Arial,Helvetica,sans-serif;max-width:600px;margin:0 auto;color:#16181B">
    <p style="font-size:13px;color:${muted};margin:0 0 4px">ImpliedLens weekly</p>
    <h2 style="font-size:20px;margin:0 0 6px">${esc(username ? `${username}, here` : "Here")} is your watchlist this week</h2>
    <p style="margin:0 0 16px;color:${muted};font-size:14px">LensScore grades each company against its sector peers from SEC filings and a year of prices${since ? `. Changes since ${esc(since)}` : ""}.</p>
    ${table}${moves}${market}
    <p style="margin:24px 0"><a href="${base()}/" style="background:#E5B65A;color:#17130A;padding:11px 18px;border-radius:10px;font-weight:bold;text-decoration:none;display:inline-block">Open your dashboard</a></p>
    <p style="color:#999;font-size:12px;line-height:1.5">Research, not investment advice. You get this because you have a watchlist on ImpliedLens.<br><a href="${unsubscribeUrl(userId)}" style="color:#999">Unsubscribe from the weekly email</a></p>
  </div>`;
  return { subject, html, count: graded.length };
}

async function moversNow() {
  try { const l = await LensHistory.leaders(); return l.movers || null; } catch (_) { return null; }
}

/* One pass. Safe to call every hour: it does nothing outside the Saturday
   window, and the per-user claim makes repeats no-ops. */
async function runWeeklyDigest({ now = new Date(), force = false, send } = {}) {
  const week = force ? LensHistory.etParts(now).day : dueWeek(now);
  if (!week) return { skipped: "not-due" };
  const sendEmail = send || require("./email").sendEmail;
  const out = { week, sent: 0, skipped: 0, failed: 0 };
  try {
    const users = await db.execute({
      sql: `SELECT u.id, u.email, u.username FROM users u
            WHERE u.email IS NOT NULL AND u.email != '' AND COALESCE(u.digest_opt_out, 0) = 0
              AND EXISTS (SELECT 1 FROM watchlist_items w WHERE w.user_id = u.id)
            LIMIT 1000`,
      args: [],
    });
    const movers = await moversNow();
    for (const u of users.rows || []) {
      try {
        const claim = await db.execute({
          sql: "INSERT OR IGNORE INTO lifecycle_email_log (user_id,email_type,reference_key) VALUES (?,'weekly_grades',?)",
          args: [u.id, week],
        });
        if (!Number(claim.rowsAffected || 0)) { out.skipped++; continue; }
        const release = () => db.execute({ sql: "DELETE FROM lifecycle_email_log WHERE user_id=? AND email_type='weekly_grades' AND reference_key=?", args: [u.id, week] }).catch(() => {});
        const wl = await db.execute({ sql: "SELECT ticker FROM watchlist_items WHERE user_id=? ORDER BY created_at DESC LIMIT 40", args: [u.id] });
        const tickers = wl.rows.map(r => String(r.ticker).toUpperCase());
        const [ch, before] = await Promise.all([
          LensHistory.changesFor(tickers).catch(() => ({ since: null, changes: {} })),
          LensHistory.gradesBefore(tickers).catch(() => ({ since: null, grades: {} })),
        ]);
        const rows = tickers.map(t => {
          const g = universeGrades.get(t);
          return g ? { ticker: t, name: g.name, score: Number(g.score), grades: g.grades, change: ch.changes[t] ? ch.changes[t].change : null, before: before.grades[t] || null } : { ticker: t };
        });
        const mail = buildEmail({ username: u.username, rows, movers, since: ch.since || before.since, userId: u.id });
        if (!mail.count) { await release(); out.skipped++; continue; }
        const result = await sendEmail({
          to: u.email, subject: mail.subject, html: mail.html,
          headers: { "List-Unsubscribe": `<${unsubscribeUrl(u.id)}>`, "List-Unsubscribe-Post": "List-Unsubscribe=One-Click" },
        });
        if (result && (result.sent || result.simulated)) out.sent++;
        else { await release(); out.failed++; }
      } catch (perUser) {
        out.failed++;
        console.error("[weekly-digest] user", u && u.id, "failed:", String(perUser && (perUser.stack || perUser.message) || perUser).slice(0, 300));
      }
    }
  } catch (e) {
    console.error("[weekly-digest] error:", String(e && (e.stack || e.message) || e).slice(0, 300));
    out.error = true;
  }
  if (out.sent || out.failed) console.log("[weekly-digest]", JSON.stringify(out));
  return out;
}

async function setOptOut(userId, optOut) {
  await db.execute({ sql: "UPDATE users SET digest_opt_out = ? WHERE id = ?", args: [optOut ? 1 : 0, Number(userId)] });
}

module.exports = { runWeeklyDigest, buildEmail, dueWeek, unsubscribeToken, verifyUnsubscribe, unsubscribeUrl, setOptOut };

"use strict";
/* ═══════════════════════════════════════════════════════════════════════════
   LensScore history and track record.

   Once a trading day, after the close, the grade of every covered company is
   saved (score, five grades, price). That gives each company a score history
   and lets us publish an honest track record: how the companies in each
   score band at the first snapshot have done since, measured with real
   prices, survivors and losers alike.
   ═══════════════════════════════════════════════════════════════════════════ */

const universeGrades = require("./universe-grades");
const peers = require("./peer-universe");

const MIN_UNIVERSE = 120;          // never snapshot a half-loaded peer set
const BANDS = [
  { key: "top", label: "Top-rated (8.0+)", min: 8 },
  { key: "above", label: "Above average (6.5–7.9)", min: 6.5 },
  { key: "middle", label: "Middle (4.5–6.4)", min: 4.5 },
  { key: "below", label: "Below average (3.0–4.4)", min: 3 },
  { key: "bottom", label: "Bottom-rated (under 3.0)", min: -1 },
];

function dbOrNull() {
  if (process.env.NODE_ENV === "test" || process.env.PEER_UNIVERSE_DB === "0") return null;
  try { return require("./db").db; } catch (_) { return null; }
}
let ready = null;
function ensure(db) {
  if (!ready) {
    ready = (async () => {
      await db.execute({ sql: "CREATE TABLE IF NOT EXISTS lens_history (day TEXT NOT NULL, ticker TEXT NOT NULL, score REAL NOT NULL, grades TEXT NOT NULL, price REAL, sector TEXT, PRIMARY KEY (day, ticker))", args: [] });
      await db.execute({ sql: "CREATE INDEX IF NOT EXISTS idx_lens_history_ticker ON lens_history(ticker, day)", args: [] });
    })().catch(e => { ready = null; throw e; });
  }
  return ready;
}

function etParts(now = new Date()) {
  const p = Object.fromEntries(new Intl.DateTimeFormat("en-US", {
    timeZone: "America/New_York", year: "numeric", month: "2-digit", day: "2-digit", weekday: "short", hour: "numeric", hour12: false,
  }).formatToParts(now).map(x => [x.type, x.value]));
  return { day: `${p.year}-${p.month}-${p.day}`, weekday: p.weekday, hour: Number(p.hour) % 24 };
}

/* Rows to store for a snapshot (pure; exported for tests). */
function snapshotRows(gradedRows, day) {
  return gradedRows.filter(r => Number.isFinite(r.score)).map(r => ({
    day, ticker: r.ticker, score: r.score, grades: JSON.stringify(r.grades || {}), price: Number(r.price) > 0 ? r.price : null, sector: r.sector || null,
  }));
}

async function lastDay(db) {
  const res = await db.execute({ sql: "SELECT MAX(day) AS d FROM lens_history", args: [] });
  return res.rows[0]?.d || null;
}

/* Take today's snapshot if it is due. First ever snapshot: as soon as the
   peer set is loaded. After that: weekdays after 16:00 New York time. */
async function maybeSnapshot({ force = false } = {}) {
  const db = dbOrNull();
  if (!db) return { skipped: "no-db" };
  await ensure(db);
  const { day, weekday, hour } = etParts();
  const graded = universeGrades.current().rows;
  if (graded.length < MIN_UNIVERSE && !force) return { skipped: "universe-loading", size: graded.length };
  const last = await lastDay(db);
  if (last === day) return { skipped: "done", day };
  const firstEver = !last;
  const due = firstEver || force || (!["Sat", "Sun"].includes(weekday) && hour >= 16);
  if (!due) return { skipped: "not-due", day };
  const rows = snapshotRows(graded, day);
  const stmts = rows.map(r => ({
    sql: "INSERT INTO lens_history (day, ticker, score, grades, price, sector) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(day, ticker) DO UPDATE SET score = excluded.score, grades = excluded.grades, price = excluded.price, sector = excluded.sector",
    args: [r.day, r.ticker, r.score, r.grades, r.price, r.sector],
  }));
  for (let i = 0; i < stmts.length; i += 100) await db.batch(stmts.slice(i, i + 100), "write");
  console.log(`[lens-history] snapshot ${day}: ${rows.length} companies`);
  return { saved: rows.length, day };
}

function start({ everyMs = 30 * 60 * 1000, firstDelayMs = 3 * 60 * 1000 } = {}) {
  const run = () => maybeSnapshot().catch(e => console.warn("[lens-history] snapshot failed:", String(e.message || e).slice(0, 160)));
  setTimeout(run, firstDelayMs).unref?.();
  setInterval(run, everyMs).unref?.();
}

async function historyFor(ticker, { limit = 260 } = {}) {
  const db = dbOrNull();
  if (!db) return [];
  await ensure(db);
  const res = await db.execute({
    sql: "SELECT day, score, grades, price FROM lens_history WHERE ticker = ? ORDER BY day DESC LIMIT ?",
    args: [String(ticker || "").toUpperCase(), limit],
  });
  return res.rows.map(r => ({ day: r.day, score: Number(r.score), grades: safeJson(r.grades), price: r.price == null ? null : Number(r.price) })).reverse();
}

function safeJson(s) { try { return JSON.parse(s); } catch (_) { return {}; } }

function bandOf(score) { return BANDS.find(b => score >= b.min) || BANDS[BANDS.length - 1]; }

/* Track record (pure): start rows from the first snapshot, current prices. */
function trackRecord(startRows, priceNow, { startDay, endDay } = {}) {
  const groups = Object.fromEntries(BANDS.map(b => [b.key, { ...b, returns: [] }]));
  const all = [];
  for (const r of startRows) {
    const p0 = Number(r.price), p1 = Number(priceNow(r.ticker));
    if (!(p0 > 0) || !(p1 > 0)) continue;
    const ret = (p1 / p0 - 1) * 100;
    groups[bandOf(Number(r.score)).key].returns.push(ret);
    all.push(ret);
  }
  const avg = a => a.length ? a.reduce((s, x) => s + x, 0) / a.length : null;
  const round = v => v == null ? null : Math.round(v * 10) / 10;
  return {
    startDay: startDay || null, endDay: endDay || null,
    companies: all.length,
    allAverage: round(avg(all)),
    bands: BANDS.map(b => ({ key: b.key, label: b.label, count: groups[b.key].returns.length, averageReturn: round(avg(groups[b.key].returns)),
      beatAll: groups[b.key].returns.length && all.length ? round(avg(groups[b.key].returns) - avg(all)) : null })),
  };
}

async function leaders() {
  const graded = universeGrades.current().rows;
  const bySector = {};
  graded.forEach(r => { (bySector[r.sector] = bySector[r.sector] || []).push(r); });
  const sectors = Object.entries(bySector).map(([sector, list]) => ({
    sector, sectorName: list[0].sectorName, count: list.length,
    top: list.slice().sort((a, b) => b.score - a.score).slice(0, 3).map(slim),
  })).sort((a, b) => b.count - a.count);
  const out = { asOf: new Date().toISOString(), universe: graded.length, top: graded.slice(0, 10).map(slim), sectors, movers: null, trackRecord: null, historyStarts: null };

  const db = dbOrNull();
  if (!db) return out;
  await ensure(db);
  const days = await db.execute({ sql: "SELECT DISTINCT day FROM lens_history ORDER BY day ASC", args: [] });
  const list = days.rows.map(r => r.day);
  if (!list.length) return out;
  out.historyStarts = list[0];
  const latest = list[list.length - 1];
  const weekAgoIdx = Math.max(0, list.length - 6);
  const compareDay = list[weekAgoIdx];
  if (compareDay !== latest) {
    const res = await db.execute({ sql: "SELECT a.ticker, a.score AS now, b.score AS then FROM lens_history a JOIN lens_history b ON a.ticker = b.ticker AND b.day = ? WHERE a.day = ?", args: [compareDay, latest] });
    const deltas = res.rows.map(r => ({ ticker: r.ticker, now: Number(r.now), then: Number(r.then), change: Math.round((Number(r.now) - Number(r.then)) * 10) / 10 }))
      .filter(d => d.change !== 0);
    const name = t => universeGrades.get(t)?.name || t;
    out.movers = {
      since: compareDay,
      up: deltas.slice().sort((a, b) => b.change - a.change).slice(0, 5).map(d => ({ ...d, name: name(d.ticker) })),
      down: deltas.slice().sort((a, b) => a.change - b.change).slice(0, 5).map(d => ({ ...d, name: name(d.ticker) })),
    };
  }
  if (list.length >= 2) {
    const first = list[0];
    const res = await db.execute({ sql: "SELECT ticker, score, price FROM lens_history WHERE day = ?", args: [first] });
    out.trackRecord = trackRecord(res.rows, t => peers.get(t)?.px, { startDay: first, endDay: latest });
  }
  return out;
}

function slim(r) { return { ticker: r.ticker, name: r.name, score: r.score, label: r.label, sectorName: r.sectorName, grades: r.grades, sectorRank: r.sectorRank, sectorCount: r.sectorCount }; }

module.exports = { start, maybeSnapshot, historyFor, leaders, trackRecord, snapshotRows, bandOf, etParts, BANDS };

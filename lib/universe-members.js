"use strict";
/* ═══════════════════════════════════════════════════════════════════════════
   The graded universe: which companies every LensScore is ranked against.

   It used to be ~290 popular tickers plus whatever anyone happened to open,
   so a stock's rank could move because a stranger looked at an obscure name.
   Now it is a fixed list, rebuilt weekly from live SEC data:

     1. Every company with a NYSE or Nasdaq listing
        (sec.gov/files/company_tickers_exchange.json).
     2. Its public float, the market value of shares held by outsiders that
        each company reports on its annual report's cover page (the dei
        EntityPublicFloat frames for the last four quarters).
     3. The largest UNIVERSE_SIZE companies by float (default 1,000, roughly
        the S&P 500 plus the larger mid caps), one ticker per company, with no
        warrants, units, rights or preferred shares.

   The popular list the site already covered is kept as well, so no page loses
   its grade. Anyone can open any stock and get a grade; stocks outside the
   list are graded against it but never join it.
   ═══════════════════════════════════════════════════════════════════════════ */

const sec = require("./sec-fundamentals");

const SIZE = Math.max(100, Math.min(3000, Number(process.env.UNIVERSE_SIZE || 1000)));
const MAX_AGE_MS = 7 * 24 * 3600 * 1000;
const EXCHANGES = new Set(["NYSE", "NASDAQ"]);

let state = { at: 0, tickers: [], source: "none", built: null };
let fallback = () => [];

/* Pure: which listed tickers can stand for a company in the universe. */
function isCommonTicker(t) {
  const s = String(t || "").toUpperCase();
  if (!/^[A-Z]{1,5}(?:[.-][A-Z])?$/.test(s)) return false;          // no "BAC-PL", "XYZ-WT"
  if (/[.-](?:W|WS|U|R|P)$/.test(s)) return false;                    // warrants, units, rights, preferred
  if (s.length === 5 && /[WUR]$/.test(s)) return false;               // Nasdaq 5th-letter warrant/unit/right
  return true;
}

/* Quarters to read the public float from: the last four completed ones. */
function recentQuarters(now = new Date()) {
  const out = [];
  let y = now.getUTCFullYear(), q = Math.floor(now.getUTCMonth() / 3);   // current quarter index 0..3 → last completed is q
  for (let i = 0; i < 4; i += 1) {
    if (q === 0) { y -= 1; q = 4; }
    out.push(`CY${y}Q${q}I`);
    q -= 1;
  }
  return out;
}

/* Pure: build the list from the two SEC files.
   listed: { fields: [...], data: [[cik, name, ticker, exchange], ...] }
   frames: [{ data: [{ cik, val, end }] }, ...] (newest first)
   prefer: tickers to choose when a company has more than one class. */
function buildList(listed, frames, { size = SIZE, prefer = new Set() } = {}) {
  const f = listed?.fields || [];
  const ix = k => f.indexOf(k);
  const iCik = ix("cik"), iName = ix("name"), iTicker = ix("ticker"), iEx = ix("exchange");
  const byCik = new Map();
  for (const row of listed?.data || []) {
    const ex = String(row[iEx] || "").toUpperCase();
    const ticker = String(row[iTicker] || "").toUpperCase();
    if (!EXCHANGES.has(ex) || !isCommonTicker(ticker)) continue;
    const cik = Number(row[iCik]);
    const cur = byCik.get(cik);
    if (!cur) byCik.set(cik, { cik, name: row[iName], ticker, alt: [] });
    else if (prefer.has(ticker) && !prefer.has(cur.ticker)) { cur.alt.push(cur.ticker); cur.ticker = ticker; }
    else cur.alt.push(ticker);
  }
  const float = new Map();
  for (const fr of frames || []) {
    for (const d of fr?.data || []) {
      const cik = Number(d.cik), v = Number(d.val);
      if (!byCik.has(cik) || !(v > 0)) continue;
      const prev = float.get(cik);
      if (!prev || String(d.end) > prev.end) float.set(cik, { val: v, end: String(d.end) });
    }
  }
  return [...byCik.values()]
    .filter(c => float.has(c.cik))
    .map(c => ({ ticker: c.ticker, name: c.name, cik: c.cik, publicFloat: float.get(c.cik).val }))
    .sort((a, b) => b.publicFloat - a.publicFloat)
    .slice(0, size);
}

/* ── storage ───────────────────────────────────────────────────────────── */
function dbOrNull() {
  if (process.env.NODE_ENV === "test" || process.env.PEER_UNIVERSE_DB === "0") return null;
  try { return require("./db").db; } catch (_) { return null; }
}
async function ensure(db) {
  await db.execute({ sql: "CREATE TABLE IF NOT EXISTS universe_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)", args: [] });
}
async function loadStored() {
  const db = dbOrNull();
  if (!db) return null;
  try {
    await ensure(db);
    const r = await db.execute({ sql: "SELECT value FROM universe_meta WHERE key = 'members'", args: [] });
    return r.rows[0] ? JSON.parse(r.rows[0].value) : null;
  } catch (_) { return null; }
}
async function saveStored(value) {
  const db = dbOrNull();
  if (!db) return;
  try {
    await ensure(db);
    await db.execute({ sql: "INSERT INTO universe_meta (key, value) VALUES ('members', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", args: [JSON.stringify(value)] });
  } catch (_) { /* memory still has it */ }
}

/* Rebuild from SEC (one ticker file + four float frames). */
async function rebuild() {
  const listed = await sec.secJson("https://www.sec.gov/files/company_tickers_exchange.json", 30000);
  const frames = [];
  for (const q of recentQuarters()) {
    try { frames.push(await sec.secJson(`https://data.sec.gov/api/xbrl/frames/dei/EntityPublicFloat/USD/${q}.json`, 30000)); }
    catch (_) { /* a quarter not published yet */ }
  }
  const list = buildList(listed, frames, { prefer: new Set(fallback()) });
  if (list.length < 200) throw new Error(`universe build returned only ${list.length} companies`);
  const value = { at: Date.now(), list };
  await saveStored(value);
  return value;
}

let loading = null;
async function ensureLoaded({ allowRebuild = true } = {}) {
  if (state.at && Date.now() - state.at < MAX_AGE_MS) return state;
  if (loading) return loading;
  loading = (async () => {
    let v = await loadStored();
    if ((!v || Date.now() - v.at > MAX_AGE_MS) && allowRebuild) {
      try { v = await rebuild(); }
      catch (e) { console.warn("[universe] SEC rebuild failed:", String(e.message || e).slice(0, 160)); }
    }
    if (v && v.list && v.list.length) {
      const merged = [...new Set([...v.list.map(c => c.ticker), ...fallback()])];
      state = { at: v.at, tickers: merged, source: "sec", built: new Date(v.at).toISOString(), size: v.list.length };
      console.log(`[universe] ${v.list.length} companies by public float (+${merged.length - v.list.length} popular), built ${state.built}`);
    }
    return state;
  })().finally(() => { loading = null; });
  return loading;
}

/* The tickers to grade. Before the first build, the popular list. */
function list() { return state.tickers.length ? state.tickers : fallback(); }
function isBuilt() { return state.source === "sec"; }
function setFallback(fn) { fallback = typeof fn === "function" ? fn : () => []; }
function status() { return { source: state.source, built: state.built, size: state.size || 0, tickers: list().length }; }
function _set(tickers) { state = { at: Date.now(), tickers, source: "sec", built: new Date().toISOString(), size: tickers.length }; }

module.exports = { list, ensureLoaded, rebuild, isBuilt, setFallback, status, buildList, isCommonTicker, recentQuarters, SIZE, _set };

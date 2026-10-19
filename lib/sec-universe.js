"use strict";
/* ═══════════════════════════════════════════════════════════════════════════
   The graded universe, built from SEC filings and licensed prices.

   For each company: its SEC profile (name, SIC → sector), a snapshot of its
   reported figures (refreshed when it files a new 10-Q/10-K, or monthly), and
   its daily prices from lib/prices.js. lib/sec-fundamentals.js turns those
   into the ratios the grades use, and the row goes into lib/peer-universe.js.

   Snapshots are stored in the database so a restart does not re-download
   every company's filings. A background pass runs a few hours after boot and
   then daily; any stock someone opens is graded on demand through
   forTicker().
   ═══════════════════════════════════════════════════════════════════════════ */

const sec = require("./sec-fundamentals");
const prices = require("./prices");
const peers = require("./peer-universe");

const SNAP_MAX_AGE = 30 * 24 * 3600 * 1000;
const snaps = new Map();       // ticker -> { snap, fetchedAt, profile }
let bench = { at: 0, rows: [] };

function dbOrNull() {
  if (process.env.NODE_ENV === "test" || process.env.PEER_UNIVERSE_DB === "0") return null;
  try { return require("./db").db; } catch (_) { return null; }
}
let ready = null;
function ensure(db) {
  if (!ready) {
    ready = db.execute({ sql: "CREATE TABLE IF NOT EXISTS sec_snapshots (ticker TEXT PRIMARY KEY, data TEXT NOT NULL, fetched_at INTEGER NOT NULL)", args: [] })
      .catch(e => { ready = null; throw e; });
  }
  return ready;
}
async function loadSnap(ticker) {
  if (snaps.has(ticker)) return snaps.get(ticker);
  const db = dbOrNull();
  if (!db) return null;
  try {
    await ensure(db);
    const r = await db.execute({ sql: "SELECT data, fetched_at FROM sec_snapshots WHERE ticker = ?", args: [ticker] });
    if (!r.rows[0]) return null;
    const entry = { ...JSON.parse(r.rows[0].data), fetchedAt: Number(r.rows[0].fetched_at) };
    snaps.set(ticker, entry);
    return entry;
  } catch (_) { return null; }
}
async function saveSnap(ticker, entry) {
  snaps.set(ticker, entry);
  const db = dbOrNull();
  if (!db) return;
  try {
    await ensure(db);
    const { fetchedAt, ...data } = entry;
    await db.execute({ sql: "INSERT INTO sec_snapshots (ticker, data, fetched_at) VALUES (?, ?, ?) ON CONFLICT(ticker) DO UPDATE SET data = excluded.data, fetched_at = excluded.fetched_at", args: [ticker, JSON.stringify(data), fetchedAt] });
  } catch (_) { /* memory still has it */ }
}

/* Pure: does the filing index show a 10-Q/10-K newer than the snapshot? */
function needsRefresh(entry, filings, now = Date.now()) {
  if (!entry || !entry.snap) return true;
  if (now - entry.fetchedAt > SNAP_MAX_AGE) return true;
  const latest = (filings || []).filter(f => /^(10-Q|10-K|20-F|40-F)/.test(f.form || "")).map(f => f.filingDate).sort().at(-1);
  return Boolean(latest && entry.snap.asOf && latest > entry.snap.asOf);
}

/* Profile + snapshot for one company, refreshing from SEC when needed.
   `facts` can be passed in when the caller already loaded them. */
async function companyData(ticker, { facts = null } = {}) {
  const t = String(ticker || "").toUpperCase();
  let entry = await loadSnap(t);
  let sub = null;
  try { sub = await sec.submissions(t); } catch (_) { /* use stored data */ }
  const filings = sub ? sec.recentFilings(sub) : [];
  if (needsRefresh(entry, filings)) {
    let f = facts;
    if (!f) {
      const id = await sec.cikFor(t);
      if (!id) throw new Error("No SEC filer for this ticker.");
      f = await sec.secJson(`https://data.sec.gov/api/xbrl/companyfacts/CIK${id.cik}.json`, 20000);
    }
    const snap = sec.snapshotFromFacts(f);
    entry = {
      snap,
      profile: {
        name: sub?.name || snap.name || t,
        sic: sub?.sic || entry?.profile?.sic || null,
        industry: sub?.sicDescription || entry?.profile?.industry || null,
        fiscalYearEnd: sub?.fiscalYearEnd || null,
        exchange: (sub?.exchanges || [])[0] || null,
      },
      fetchedAt: Date.now(),
    };
    await saveSnap(t, entry);
  } else if (sub && entry) {
    entry.profile = { ...entry.profile, name: sub.name || entry.profile?.name, sic: sub.sic || entry.profile?.sic, industry: sub.sicDescription || entry.profile?.industry };
  }
  return { ...entry, filings, sector: sec.sectorFromSic(entry?.profile?.sic, t) };
}

async function benchmark(kind = "interactive") {
  if (bench.rows.length && Date.now() - bench.at < 6 * 3600 * 1000) return bench.rows;
  try {
    const rows = await prices.dailyCloses("SPY", 800, kind);
    if (rows.length) bench = { at: Date.now(), rows };
  } catch (_) { /* momentum grades wait for the benchmark */ }
  return bench.rows;
}

/* Grade inputs for one company. `rows` = daily closes when the caller has
   them (the LensToolkit already loaded five years); otherwise fetched. */
async function forTicker(ticker, { rows = null, facts = null, kind = "interactive" } = {}) {
  const t = String(ticker || "").toUpperCase();
  const data = await companyData(t, { facts });
  const daily = rows && rows.length ? rows : await prices.dailyCloses(t, 800, kind);
  const b = await benchmark(kind);
  const price = daily.at(-1)?.close ?? null;
  const metric = sec.metricsFrom(data.snap, { price, rows: daily.slice(-560), bench: b.slice(-560) });
  if (data.sector) peers.put(t, { name: data.profile?.name, sector: data.sector, industry: data.profile?.industry, metric, price });
  return { ticker: t, name: data.profile?.name || t, sector: data.sector, industry: data.profile?.industry || null, metric, price, snap: data.snap, filings: data.filings, profile: data.profile, rows: daily.slice(-260) };
}

/* Background pass over the universe: one company at a time. */
let running = false, last = { at: null, done: 0, failed: 0 };
async function refresh(tickers) {
  if (running) return last;
  running = true;
  const started = Date.now();
  let done = 0, failed = 0;
  try {
    await peers.load();
    for (const t of tickers) {
      if (!(await prices.canSpend("background"))) break;
      try { await forTicker(t, { kind: "background" }); done += 1; }
      catch (_) { failed += 1; }
    }
  } finally {
    running = false;
    last = { at: new Date(started).toISOString(), done, failed, ms: Date.now() - started };
    console.log(`[sec-universe] refreshed ${done} companies (${failed} failed) in ${Math.round((Date.now() - started) / 1000)}s`);
  }
  return last;
}
function start(tickers, { firstDelayMs = 90 * 1000, everyMs = 24 * 3600 * 1000 } = {}) {
  const run = () => refresh(tickers()).catch(e => console.warn("[sec-universe] refresh failed:", String(e.message || e).slice(0, 160)));
  setTimeout(run, firstDelayMs).unref?.();
  setInterval(run, everyMs).unref?.();
}
const status = () => ({ running, ...last, snapshots: snaps.size });

module.exports = { forTicker, companyData, refresh, start, status, needsRefresh, benchmark };

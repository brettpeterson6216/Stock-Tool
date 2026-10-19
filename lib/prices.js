"use strict";
/* ═══════════════════════════════════════════════════════════════════════════
   Prices: the one place the site gets stock prices from.

   Every chart, quote, alert check, momentum grade and screener row asks this
   module. Which provider answers is decided here:

     · Marketstack (licensed for commercial use) when MARKETSTACK_API_KEY is
       set. Daily bars are stored in the database and topped up, intraday bars
       (15-minute, from IEX) are cached for 15 minutes, and a monthly request
       budget keeps the plan's quota from running out.
     · Yahoo Finance as a legacy fallback only while no key is set
       (lib/data-policy.js switches it off as soon as the key exists).

   getChart() answers in Yahoo's chart shape ({ chart: { result: [...] } })
   because the front end and lib/stock-research.js already read that shape;
   nothing downstream needs to know which provider was used except the
   source label.
   ═══════════════════════════════════════════════════════════════════════════ */

const DAY = 86400, MS_DAY = DAY * 1000;
const MS_BASE = process.env.MARKETSTACK_BASE_URL || "https://api.marketstack.com/v2";
const MONTHLY_LIMIT = Number(process.env.MARKETSTACK_MONTHLY_LIMIT || 10000);
const INTRADAY_TTL_MS = 15 * 60 * 1000;
const DAILY_TOPUP_MS = 4 * 60 * 60 * 1000;   // re-check for a new daily bar at most every 4 hours per ticker

const RANGE_DAYS = { "1d": 1, "5d": 5, "1mo": 31, "3mo": 92, "6mo": 183, "1y": 366, "2y": 731, "5y": 1827, "10y": 3653, "max": 3653 };

function provider() { return process.env.MARKETSTACK_API_KEY ? "marketstack" : "yahoo"; }
function sourceLabel() { return provider() === "marketstack" ? "Marketstack" : "Yahoo Finance chart (legacy)"; }
function msSymbol(t) { return String(t || "").toUpperCase().replace(/-/g, "."); }
function yahooSymbol(t) { return String(t || "").replace(/^([A-Z]{1,5})\.([A-Z]{1,2})$/, "$1-$2"); }
const finite = v => v !== null && v !== undefined && v !== "" && Number.isFinite(Number(v));
const dayOf = ts => new Date(ts * 1000).toISOString().slice(0, 10);

/* ── storage ───────────────────────────────────────────────────────────── */
function dbOrNull() {
  if (process.env.NODE_ENV === "test" || process.env.PRICES_DB === "0") return null;
  try { return require("./db").db; } catch (_) { return null; }
}
let ready = null;
function ensure(db) {
  if (!ready) {
    ready = (async () => {
      await db.execute({ sql: "CREATE TABLE IF NOT EXISTS price_daily (ticker TEXT NOT NULL, day TEXT NOT NULL, o REAL, h REAL, l REAL, c REAL NOT NULL, v REAL, PRIMARY KEY (ticker, day))", args: [] });
      await db.execute({ sql: "CREATE TABLE IF NOT EXISTS price_usage (month TEXT NOT NULL, provider TEXT NOT NULL, calls INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (month, provider))", args: [] });
    })().catch(e => { ready = null; throw e; });
  }
  return ready;
}

const daily = new Map();       // ticker -> { rows: [{day,o,h,l,c,v}], checkedAt, loadedFromDb }
const intraday = new Map();    // ticker|interval -> { at, rows }
const inflight = new Map();

/* ── budget ────────────────────────────────────────────────────────────── */
const usage = { month: null, calls: 0, loaded: false };
function monthKey(d = new Date()) { return d.toISOString().slice(0, 7); }
async function loadUsage() {
  const m = monthKey();
  if (usage.month !== m) { usage.month = m; usage.calls = 0; usage.loaded = false; }
  if (usage.loaded) return;
  const db = dbOrNull();
  if (db) {
    try {
      await ensure(db);
      const r = await db.execute({ sql: "SELECT calls FROM price_usage WHERE month = ? AND provider = 'marketstack'", args: [m] });
      usage.calls = Math.max(usage.calls, Number(r.rows[0]?.calls || 0));
    } catch (_) { /* counting continues in memory */ }
  }
  usage.loaded = true;
}
async function countCalls(n) {
  usage.calls += n;
  const db = dbOrNull();
  if (!db) return;
  try {
    await db.execute({ sql: "INSERT INTO price_usage (month, provider, calls) VALUES (?, 'marketstack', ?) ON CONFLICT(month, provider) DO UPDATE SET calls = calls + excluded.calls", args: [usage.month, n] });
  } catch (_) { /* best effort */ }
}
/* Share of the monthly quota each kind of work may use. People opening pages
   come first; background refreshes stop early so the quota never runs dry. */
const SHARE = { background: 0.70, intraday: 0.85, interactive: 0.97 };
async function canSpend(kind, n = 1) {
  await loadUsage();
  return usage.calls + n <= MONTHLY_LIMIT * (SHARE[kind] || SHARE.interactive);
}

/* ── Marketstack ───────────────────────────────────────────────────────── */
async function msGet(path, params) {
  const url = new URL(MS_BASE.replace(/\/$/, "") + path);
  url.searchParams.set("access_key", process.env.MARKETSTACK_API_KEY);
  Object.entries(params).forEach(([k, v]) => { if (v !== undefined && v !== null) url.searchParams.set(k, String(v)); });
  const r = await fetch(url, { signal: AbortSignal.timeout(10000) });
  await countCalls(1);
  const j = await r.json().catch(() => ({}));
  if (!r.ok || j.error) {
    const msg = j?.error?.message || j?.error?.code || `HTTP ${r.status}`;
    throw Object.assign(new Error(`Marketstack: ${msg}`), { status: r.status });
  }
  return j;
}

/* Raw Marketstack EOD rows → split-adjusted daily rows (oldest first).
   Prices before a split are divided by the split factor so the chart has no
   cliff; dividends are not adjusted (the same convention as most charts). */
function normalizeEod(rows) {
  const list = (Array.isArray(rows) ? rows : [])
    .filter(r => r && r.date && finite(r.close))
    .map(r => ({ day: String(r.date).slice(0, 10), o: Number(r.open), h: Number(r.high), l: Number(r.low), c: Number(r.close), v: finite(r.volume) ? Number(r.volume) : null, split: finite(r.split_factor) ? Number(r.split_factor) : 1 }))
    .sort((a, b) => a.day.localeCompare(b.day));
  const byDay = new Map(list.map(r => [r.day, r]));
  const out = [...byDay.values()];
  let factor = 1;
  for (let i = out.length - 1; i >= 0; i -= 1) {
    const r = out[i];
    if (factor !== 1) {
      r.o /= factor; r.h /= factor; r.l /= factor; r.c /= factor;
      if (finite(r.v)) r.v *= factor;
    }
    if (r.split && r.split !== 1 && r.split > 0) factor *= r.split;
    delete r.split;
  }
  return out;
}

async function msEod(ticker, from, to) {
  const rows = [];
  let offset = 0;
  for (let page = 0; page < 4; page += 1) {
    const j = await msGet("/eod", { symbols: msSymbol(ticker), date_from: from, date_to: to, limit: 1000, offset, sort: "ASC" });
    const data = Array.isArray(j.data) ? j.data : (Array.isArray(j.data?.eod) ? j.data.eod : []);
    rows.push(...data);
    const total = Number(j.pagination?.total || data.length);
    offset += data.length;
    if (!data.length || offset >= total) break;
  }
  return normalizeEod(rows);
}

function normalizeIntraday(rows) {
  return (Array.isArray(rows) ? rows : [])
    .filter(r => r && r.date && (finite(r.last) || finite(r.close)))
    .map(r => {
      const c = finite(r.last) ? Number(r.last) : Number(r.close);
      return { ts: Math.floor(Date.parse(r.date) / 1000), o: finite(r.open) ? Number(r.open) : c, h: finite(r.high) ? Number(r.high) : c, l: finite(r.low) ? Number(r.low) : c, c, v: finite(r.volume) ? Number(r.volume) : null };
    })
    .filter(r => finite(r.ts))
    .sort((a, b) => a.ts - b.ts);
}

async function msIntraday(ticker, interval, fromDay) {
  const j = await msGet("/intraday", { symbols: msSymbol(ticker), interval, date_from: fromDay, limit: 1000, sort: "ASC" });
  return normalizeIntraday(Array.isArray(j.data) ? j.data : j.data?.intraday);
}

/* ── daily store ───────────────────────────────────────────────────────── */
async function loadStored(ticker) {
  const entry = daily.get(ticker) || { rows: [], checkedAt: 0, loadedFromDb: false };
  if (!entry.loadedFromDb) {
    const db = dbOrNull();
    if (db) {
      try {
        await ensure(db);
        const r = await db.execute({ sql: "SELECT day, o, h, l, c, v FROM price_daily WHERE ticker = ? ORDER BY day ASC", args: [ticker] });
        const stored = r.rows.map(x => ({ day: x.day, o: Number(x.o), h: Number(x.h), l: Number(x.l), c: Number(x.c), v: x.v == null ? null : Number(x.v) }));
        if (stored.length) entry.rows = mergeRows(entry.rows, stored);
      } catch (_) { /* memory only */ }
    }
    entry.loadedFromDb = true;
  }
  daily.set(ticker, entry);
  return entry;
}
function mergeRows(a, b) {
  const m = new Map(a.map(r => [r.day, r]));
  b.forEach(r => m.set(r.day, r));
  return [...m.values()].sort((x, y) => x.day.localeCompare(y.day));
}
async function persist(ticker, rows) {
  const db = dbOrNull();
  if (!db || !rows.length) return;
  try {
    await ensure(db);
    for (let i = 0; i < rows.length; i += 200) {
      await db.batch(rows.slice(i, i + 200).map(r => ({
        sql: "INSERT INTO price_daily (ticker, day, o, h, l, c, v) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(ticker, day) DO UPDATE SET o = excluded.o, h = excluded.h, l = excluded.l, c = excluded.c, v = excluded.v",
        args: [ticker, r.day, r.o, r.h, r.l, r.c, r.v],
      })), "write");
    }
  } catch (_) { /* memory still has them */ }
}

/* A split shows up as a new daily row with split_factor; older stored rows are
   then unadjusted. When the new rows contain a split, refetch the whole span. */
function hasSplit(raw) { return (raw || []).some(r => finite(r.split_factor) && Number(r.split_factor) !== 1); }

/* Make sure stored daily bars cover `days` back to the latest trading day. */
async function ensureDaily(ticker, days, kind = "interactive") {
  const key = `${ticker}|${days}`;
  if (inflight.has(key)) return inflight.get(key);
  const p = (async () => {
    const entry = await loadStored(ticker);
    const today = new Date().toISOString().slice(0, 10);
    const wantFrom = new Date(Date.now() - days * MS_DAY).toISOString().slice(0, 10);
    const first = entry.rows[0]?.day, last = entry.rows.at(-1)?.day;
    if (!first || first > addDays(wantFrom, 5)) {
      // Missing history: one fetch for the whole span (cheaper than many).
      if (!(await canSpend(kind, Math.ceil(days / 1400) + 1))) return entry.rows;
      const rows = await msEod(ticker, wantFrom, today);
      entry.rows = mergeRows(entry.rows, rows);
      entry.checkedAt = Date.now();
      await persist(ticker, rows);
    } else if (Date.now() - entry.checkedAt > DAILY_TOPUP_MS && last < staleCutoff(kind)) {
      if (!(await canSpend(kind))) return entry.rows;
      const j = await msGet("/eod", { symbols: msSymbol(ticker), date_from: addDays(last, 1), date_to: today, limit: 1000, sort: "ASC" });
      const raw = Array.isArray(j.data) ? j.data : [];
      entry.checkedAt = Date.now();
      if (hasSplit(raw)) {
        const rows = await msEod(ticker, first, today);
        entry.rows = rows;
        await persist(ticker, rows);
      } else {
        const rows = normalizeEod(raw);
        entry.rows = mergeRows(entry.rows, rows);
        await persist(ticker, rows);
      }
    }
    return entry.rows;
  })().finally(() => inflight.delete(key));
  inflight.set(key, p);
  return p;
}
function addDays(day, n) { return new Date(Date.parse(day + "T12:00:00Z") + n * MS_DAY).toISOString().slice(0, 10); }
/* Latest weekday on or before today (exchange holidays just mean one wasted check). */
function lastTradingDay(now = new Date()) {
  const et = new Date(now.toLocaleString("en-US", { timeZone: "America/New_York" }));
  let d = new Date(Date.UTC(et.getFullYear(), et.getMonth(), et.getDate()));
  if (et.getHours() < 17) d = new Date(d - MS_DAY);   // today's bar is published after the close
  while ([0, 6].includes(d.getUTCDay())) d = new Date(d - MS_DAY);
  return d.toISOString().slice(0, 10);
}

/* Background refreshes (the graded universe) accept bars up to three trading
   days old, so ~300 companies cost ~2,000 calls a month instead of ~6,500. */
function staleCutoff(kind) {
  let d = lastTradingDay();
  if (kind !== "background") return d;
  let n = 0;
  while (n < 3) { d = addDays(d, -1); const wd = new Date(d + "T12:00:00Z").getUTCDay(); if (wd !== 0 && wd !== 6) n += 1; }
  return d;
}

/* Pure: aggregate daily rows into weekly or monthly bars. */
function aggregate(rows, unit) {
  const key = r => {
    if (unit === "1mo") return r.day.slice(0, 7);
    const d = new Date(r.day + "T12:00:00Z");
    const monday = new Date(d - ((d.getUTCDay() + 6) % 7) * MS_DAY);
    return monday.toISOString().slice(0, 10);
  };
  const out = [];
  for (const r of rows) {
    const k = key(r);
    const last = out.at(-1);
    if (last && last.k === k) {
      last.h = Math.max(last.h, r.h); last.l = Math.min(last.l, r.l); last.c = r.c;
      last.v = (last.v || 0) + (r.v || 0);
    } else out.push({ k, day: r.day, o: r.o, h: r.h, l: r.l, c: r.c, v: r.v });
  }
  return out.map(({ k, ...r }) => r);
}

/* Pure: rows → Yahoo chart payload. */
function toChart(ticker, bars, { prevClose = null, price = null, high52 = null, low52 = null, name = null, granularity = "1d", source = "Marketstack" } = {}) {
  const ts = bars.map(b => (b.ts != null ? b.ts : Math.floor(Date.parse(b.day + "T20:00:00Z") / 1000)));
  const last = bars.at(-1);
  const meta = {
    symbol: ticker, currency: "USD", exchangeName: null, instrumentType: "EQUITY",
    longName: name || ticker, shortName: name || ticker,
    regularMarketPrice: price ?? last?.c ?? null,
    previousClose: prevClose, chartPreviousClose: prevClose,
    regularMarketTime: ts.at(-1) || null,
    regularMarketVolume: last?.v ?? null,
    fiftyTwoWeekHigh: high52, fiftyTwoWeekLow: low52,
    dataGranularity: granularity, source,
  };
  return { chart: { result: [{ meta, timestamp: ts, indicators: { quote: [{
    open: bars.map(b => b.o), high: bars.map(b => b.h), low: bars.map(b => b.l), close: bars.map(b => b.c), volume: bars.map(b => b.v),
  }], adjclose: [{ adjclose: bars.map(b => b.c) }] } }], error: null } };
}

async function marketstackChart(ticker, range, interval, opts) {
  const days = RANGE_DAYS[range] || 366;
  // At least ~2.2 years in one request (one call returns up to 1,000 rows):
  // the grades' momentum and beta need two years, and fetching it with the
  // first chart avoids a second call for the same company.
  const needDaily = Math.max(days, 800) + 10;
  const rows = await ensureDaily(ticker, needDaily);
  if (!rows.length) throw new Error("No price data from Marketstack.");
  const year = rows.filter(r => r.day >= new Date(Date.now() - 365 * MS_DAY).toISOString().slice(0, 10));
  const high52 = year.length ? Math.max(...year.map(r => r.h)) : null;
  const low52 = year.length ? Math.min(...year.map(r => r.l)) : null;
  const lastDaily = rows.at(-1);
  let bars, granularity = interval, price = lastDaily.c, prevClose = rows.at(-2)?.c ?? null;

  if (range === "1d" || range === "5d") {
    const iv = range === "1d" ? "15min" : "1hour";
    const k = `${ticker}|${iv}`;
    let hit = intraday.get(k);
    if (!hit || Date.now() - hit.at > INTRADAY_TTL_MS) {
      if (await canSpend("intraday")) {
        try {
          const from = new Date(Date.now() - (range === "1d" ? 4 : 9) * MS_DAY).toISOString().slice(0, 10);
          hit = { at: Date.now(), rows: await msIntraday(ticker, iv, from) };
          intraday.set(k, hit);
        } catch (_) { /* fall back to daily bars below */ }
      }
    }
    const ir = hit?.rows || [];
    if (ir.length) {
      const lastDay = new Date(ir.at(-1).ts * 1000).toISOString().slice(0, 10);
      const keepFrom = range === "1d"
        ? Date.parse(lastDay + "T00:00:00Z") / 1000
        : ir.at(-1).ts - 7 * DAY;
      bars = ir.filter(r => r.ts >= keepFrom);
      granularity = iv;
      price = ir.at(-1).c;
      const before = rows.filter(r => r.day < lastDay);
      prevClose = before.at(-1)?.c ?? prevClose;
    } else {
      bars = rows.slice(range === "1d" ? -2 : -6);
      granularity = "1d";
    }
  } else {
    const from = range === "ytd" ? `${new Date().getUTCFullYear()}-01-01` : new Date(Date.now() - days * MS_DAY).toISOString().slice(0, 10);
    let span = range === "max" ? rows : rows.filter(r => r.day >= from);
    const before = rows.filter(r => r.day < (span[0]?.day || from));
    if (interval === "1wk" || interval === "1mo") { span = aggregate(span, interval); granularity = interval; }
    bars = span;
    prevClose = rows.at(-2)?.c ?? null;
    if (before.length) opts.chartPreviousClose = before.at(-1).c;
  }
  const chart = toChart(ticker, bars, { prevClose, price, high52, low52, name: opts.name, granularity });
  if (opts.chartPreviousClose) chart.chart.result[0].meta.chartPreviousClose = opts.chartPreviousClose;
  return chart;
}

/* ── Yahoo (legacy, only until a licensed key is set) ─────────────────── */
async function yahooChart(ticker, range, interval) {
  const hosts = ["query2", "query1"];
  let lastErr = null;
  for (const host of hosts) {
    try {
      const url = `https://${host}.finance.yahoo.com/v8/finance/chart/${encodeURIComponent(yahooSymbol(ticker))}?interval=${encodeURIComponent(interval)}&range=${encodeURIComponent(range)}&includePrePost=false&events=div%2Csplits`;
      const r = await fetch(url, { headers: { "User-Agent": "Mozilla/5.0 (compatible; ImpliedLens/1.2; +https://impliedlens.com)", Accept: "application/json" }, signal: AbortSignal.timeout(9000) });
      if (!r.ok) { lastErr = new Error(`HTTP ${r.status}`); continue; }
      const j = await r.json();
      if (j?.chart?.result?.[0]?.timestamp?.length) return j;
      lastErr = new Error("empty");
    } catch (e) { lastErr = e; }
  }
  throw lastErr || new Error("Price history unavailable.");
}

const AUTO_INTERVAL = { "1d": "5m", "5d": "30m", "1mo": "1d", "3mo": "1d", "6mo": "1d", "ytd": "1d", "1y": "1d", "2y": "1d", "5y": "1wk", "10y": "1wk", "max": "1mo" };

/* getChart(ticker, { range, interval, name }) → Yahoo-shaped chart payload
   plus `source`. Throws when no provider has data. */
async function getChart(ticker, { range = "1y", interval, name = null } = {}) {
  const t = String(ticker || "").toUpperCase();
  const iv = interval || AUTO_INTERVAL[range] || "1d";
  if (provider() === "marketstack") {
    const chart = await marketstackChart(t, range, iv, { name });
    return { ...chart, source: "Marketstack" };
  }
  const chart = await yahooChart(t, range, iv);
  return { ...chart, source: "Yahoo Finance chart (legacy)" };
}

/* Daily closes for the last `days` days: [{ day, close }] oldest first.
   Background callers pass kind "background" so they stop early on quota. */
async function dailyCloses(ticker, days = 400, kind = "interactive") {
  const t = String(ticker || "").toUpperCase();
  if (provider() === "marketstack") {
    const rows = await ensureDaily(t, days, kind);
    const from = new Date(Date.now() - days * MS_DAY).toISOString().slice(0, 10);
    return rows.filter(r => r.day >= from).map(r => ({ day: r.day, close: r.c, high: r.h, low: r.l, volume: r.v }));
  }
  const range = days > 731 ? "5y" : days > 366 ? "2y" : "1y";
  const j = await yahooChart(t, range, "1d");
  const res = j.chart.result[0];
  const q = res.indicators.quote[0];
  return res.timestamp.map((ts, i) => ({ day: dayOf(ts), close: q.close[i], high: q.high[i], low: q.low[i], volume: q.volume[i] }))
    .filter(r => finite(r.close));
}

/* Latest price (intraday when the plan has it, else the last close). */
async function latestPrice(ticker, kind = "intraday") {
  const t = String(ticker || "").toUpperCase();
  try {
    if (provider() === "marketstack") {
      const k = `${t}|15min`;
      let hit = intraday.get(k);
      if ((!hit || Date.now() - hit.at > INTRADAY_TTL_MS) && await canSpend(kind)) {
        try { hit = { at: Date.now(), rows: await msIntraday(t, "15min", new Date(Date.now() - 4 * MS_DAY).toISOString().slice(0, 10)) }; intraday.set(k, hit); } catch (_) { /* below */ }
      }
      if (hit?.rows?.length) return hit.rows.at(-1).c;
      const rows = await ensureDaily(t, 30, kind);
      return rows.at(-1)?.c ?? null;
    }
    const j = await yahooChart(t, "1d", "5m");
    const v = Number(j?.chart?.result?.[0]?.meta?.regularMarketPrice);
    return v > 0 ? v : null;
  } catch (_) { return null; }
}

async function snapshot() {
  await loadUsage().catch(() => {});
  return { provider: provider(), source: sourceLabel(), month: usage.month, calls: usage.calls, monthlyLimit: provider() === "marketstack" ? MONTHLY_LIMIT : null, cachedTickers: daily.size };
}

function _reset() { daily.clear(); intraday.clear(); usage.month = null; usage.calls = 0; usage.loaded = false; }

module.exports = {
  getChart, dailyCloses, latestPrice, provider, sourceLabel, snapshot, canSpend,
  _test: { normalizeEod, normalizeIntraday, aggregate, toChart, lastTradingDay, msSymbol, _reset, usage },
};

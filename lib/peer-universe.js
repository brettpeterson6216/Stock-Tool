"use strict";
/* ═══════════════════════════════════════════════════════════════════════════
   Peer universe: the comparison set behind LensScore's factor grades.

   A P/E of 30 is cheap for a chip designer and expensive for a utility, so
   every grade is a percentile against companies in the same sector. This
   module keeps one compact row per company (sector, size, price and the
   ratios the grades use, computed from SEC filings and licensed prices by
   lib/sec-universe.js). Rows arrive from the background refresh of the
   popular universe and from any stock someone opens.

   Rows are also written to the database so a restart (every deploy) starts
   with yesterday's peers instead of an empty table while enrichment refills.
   ═══════════════════════════════════════════════════════════════════════════ */

const KEEP = [
  "peTTM", "forwardPE", "psTTM", "pfcfShareTTM", "evEbitdaTTM", "pegTTM", "pbQuarterly",
  "revenueGrowthTTMYoy", "revenueGrowthQuarterlyYoy", "epsGrowthTTMYoy", "revenueGrowth3Y", "epsGrowth3Y",
  "grossMarginTTM", "operatingMarginTTM", "netProfitMarginTTM", "roeTTM", "roiTTM",
  "totalDebt/totalEquityQuarterly", "currentRatioQuarterly", "netInterestCoverageTTM",
  "priceRelativeToS&P50013Week", "priceRelativeToS&P50026Week", "priceRelativeToS&P50052Week",
  "13WeekPriceReturnDaily", "26WeekPriceReturnDaily", "52WeekPriceReturnDaily",
  "52WeekHigh", "52WeekLow", "beta", "dividendYieldIndicatedAnnual", "marketCapitalization",
];
const MAX_AGE = 3 * 24 * 3600 * 1000;      // older rows are ignored for ranking

const rows = new Map();                     // ticker -> row
let version = 0;                            // bumps on every change
let loaded = false, loading = null;

function sectorFromIndustry(ind) {
  const s = String(ind || "");
  if (!s || s === "N/A") return null;
  if (/utilit/i.test(s)) return "Utilities";
  if (/real estate|reit/i.test(s)) return "Real Est.";
  if (/pharma|biotech|health|life sciences|medical/i.test(s)) return "Health";
  if (/semiconductor|technolog|software|internet|it services|electronic|communications|computer/i.test(s)) return "Tech";
  if (/media|telecom|entertainment|interactive/i.test(s)) return "Comm.";
  if (/bank|financ|insurance|capital markets|asset management/i.test(s)) return "Finance";
  if (/beverage|food|tobacco|consumer products|household|personal products/i.test(s)) return "Staples";
  if (/energy|oil|gas|coal/i.test(s)) return "Energy";
  if (/chemical|metals|mining|paper|forest|packaging|steel|construction materials/i.test(s)) return "Materials";
  if (/aerospace|defense|machinery|industrial|airline|logistics|transport|road|rail|marine|electrical|building|construction|commercial services|professional services|trading compan/i.test(s)) return "Industrials";
  if (/retail|automobile|auto |hotel|restaurant|leisure|textile|apparel|luxury|diversified consumer|distributors|homebuild|consumer/i.test(s)) return "Cons.Disc";
  return null;
}

/* Finnhub files big-box grocers and discount stores under "Retail", which
   would grade Costco against Nike and Amazon. GICS puts them in Consumer
   Staples (food and staples retailing); follow that. */
const STAPLES_RETAIL = new Set(["WMT", "COST", "KR", "DG", "DLTR", "TGT", "BJ", "SYY", "ACI", "PSMT"]);
function sectorFor(ticker, industry) {
  const t = String(ticker || "").toUpperCase();
  if (STAPLES_RETAIL.has(t)) return "Staples";
  return sectorFromIndustry(industry);
}

const SECTOR_NAMES = {
  "Tech": "Technology", "Comm.": "Communication", "Health": "Healthcare", "Finance": "Financials",
  "Staples": "Consumer Staples", "Cons.Disc": "Consumer Discretionary", "Energy": "Energy",
  "Materials": "Materials", "Industrials": "Industrials", "Real Est.": "Real Estate", "Utilities": "Utilities",
};

function slim(metric) {
  const out = {};
  for (const k of KEEP) {
    const v = metric ? Number(metric[k]) : NaN;
    if (Number.isFinite(v)) out[k] = v;
  }
  return out;
}

/* Record a company from SEC filings + licensed prices (lib/sec-universe.js):
   { name, sector, industry, metric, price }. Rows carry src "sec"; rows built
   from the old Finnhub feed are dropped (see load()). */
function put(ticker, { name, sector, industry, metric, price } = {}) {
  const t = String(ticker || "").toUpperCase();
  if (!t || !metric) return null;
  const prev = rows.get(t) || {};
  const m = slim(metric);
  if (!Object.keys(m).length) return null;
  const row = {
    t,
    n: name || prev.n || t,
    i: industry || prev.i || null,
    s: (STAPLES_RETAIL.has(t) ? "Staples" : sector) || prev.s || null,
    mc: Number(m.marketCapitalization) > 0 ? m.marketCapitalization * 1e6 : prev.mc || null,
    px: Number(price) > 0 ? Number(price) : prev.px || null,
    m,
    src: "sec",
    at: Date.now(),
  };
  rows.set(t, row);
  version++;
  persist(row);
  return row;
}

function setPrice(ticker, price) {
  const r = rows.get(String(ticker || "").toUpperCase());
  if (r && Number(price) > 0) r.px = Number(price);
}

function get(ticker) { return rows.get(String(ticker || "").toUpperCase()) || null; }

function all({ maxAge = MAX_AGE } = {}) {
  const now = Date.now();
  return [...rows.values()].filter(r => r.s && r.src === "sec" && now - r.at < maxAge);
}

/* ── persistence (best effort; never in tests) ──────────────────────────── */
function dbOrNull() {
  if (process.env.NODE_ENV === "test" || process.env.PEER_UNIVERSE_DB === "0") return null;
  try { return require("./db").db; } catch (_) { return null; }
}
let tableReady = null;
function ensureTable(db) {
  if (!tableReady) {
    tableReady = db.execute({
      sql: "CREATE TABLE IF NOT EXISTS peer_metrics (ticker TEXT PRIMARY KEY, data TEXT NOT NULL, updated_at INTEGER NOT NULL)",
      args: [],
    }).catch(e => { tableReady = null; throw e; });
  }
  return tableReady;
}
function persist(row) {
  const db = dbOrNull();
  if (!db) return;
  ensureTable(db)
    .then(() => db.execute({
      sql: "INSERT INTO peer_metrics (ticker, data, updated_at) VALUES (?, ?, ?) ON CONFLICT(ticker) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at",
      args: [row.t, JSON.stringify(row), row.at],
    }))
    .catch(e => console.warn("[peers] save failed:", String(e.message || e).slice(0, 120)));
}
async function load() {
  if (loaded) return rows.size;
  if (loading) return loading;
  const db = dbOrNull();
  if (!db) { loaded = true; return rows.size; }
  loading = (async () => {
    try {
      await ensureTable(db);
      const res = await db.execute({ sql: "SELECT data FROM peer_metrics WHERE updated_at > ?", args: [Date.now() - MAX_AGE] });
      let dropped = 0;
      for (const r of res.rows) {
        try {
          const row = JSON.parse(r.data);
          if (row.src !== "sec") { dropped += 1; continue; }
          if (STAPLES_RETAIL.has(row.t)) row.s = "Staples";
          const cur = rows.get(row.t);
          if (!cur || cur.at < row.at) { rows.set(row.t, row); version++; }
        } catch (_) { /* skip a bad row */ }
      }
      /* Rows built from Finnhub's personal-use feed may not be kept or shown. */
      if (dropped) await db.execute({ sql: "DELETE FROM peer_metrics WHERE data NOT LIKE '%\"src\":\"sec\"%'", args: [] }).catch(() => {});
      console.log(`[peers] loaded ${res.rows.length - dropped} peer rows (${dropped} legacy rows removed)`);
    } catch (e) {
      console.warn("[peers] load failed:", String(e.message || e).slice(0, 120));
    } finally { loaded = true; loading = null; }
    return rows.size;
  })();
  return loading;
}

function _reset() { rows.clear(); loaded = false; loading = null; version++; }
const getVersion = () => version;

module.exports = { getVersion, put, setPrice, get, all, load, sectorFromIndustry, sectorFor, SECTOR_NAMES, KEEP, _reset };

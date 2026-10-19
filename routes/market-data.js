// ============================================================
//  Market-data routes
//    GET /api/news/:ticker            (free)
//    GET /api/screener                (Pro)
//    GET /api/quote/:ticker           (rate-limited, free)
//    GET /api/market/analyst-signals  (free — home dashboard)
//    GET /api/market/movers           (free)
// ============================================================
const express = require("express");

const { FINNHUB_KEY }              = require("../lib/config");
const { requirePro, checkAnalysisLimit, normalizeTicker } = require("../lib/plan");
const { recordProvider } = require("../lib/provider-health");
const prices = require("../lib/prices");
const secUniverse = require("../lib/sec-universe");

const router = express.Router();
const _responseCache = new Map();
const MAX_CACHE_ENTRIES = 500;
const VALID_RANGES = new Set(["1d", "5d", "1mo", "3mo", "6mo", "1y", "2y", "5y", "10y", "ytd", "max"]);
const VALID_INTERVALS = new Set(["1m", "2m", "5m", "15m", "30m", "60m", "90m", "1h", "1d", "5d", "1wk", "1mo", "3mo"]);

function getCached(key, ttlMs) {
  const entry = _responseCache.get(key);
  if (!entry || Date.now() - entry.ts >= ttlMs) {
    if (entry) _responseCache.delete(key);
    return null;
  }
  return entry.data;
}

function setCached(key, data) {
  if (_responseCache.size >= MAX_CACHE_ENTRIES) {
    const oldest = _responseCache.keys().next().value;
    if (oldest) _responseCache.delete(oldest);
  }
  _responseCache.set(key, { data, ts: Date.now() });
}

function marketSessionAt(date = new Date()) {
  const parts = new Intl.DateTimeFormat("en-US", {
    timeZone: "America/New_York",
    weekday: "short",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  }).formatToParts(date);
  const value = Object.fromEntries(parts.map(part => [part.type, part.value]));
  if (["Sat", "Sun"].includes(value.weekday)) return "closed";
  const minutes = Number(value.hour) * 60 + Number(value.minute);
  if (minutes < 4 * 60) return "closed";
  if (minutes < 9 * 60 + 30) return "pre-market";
  if (minutes < 16 * 60) return "regular";
  if (minutes < 20 * 60) return "after-hours";
  return "closed";
}

// ---- Fetch with timeout helper ----
async function fetchWithTimeout(url, options = {}, timeoutMs = 5000) {
  const ctrl  = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, { ...options, signal: ctrl.signal });
    clearTimeout(timer);
    return res;
  } catch (e) {
    clearTimeout(timer);
    throw e;
  }
}

// ============================================================
//  News
// ============================================================
/* Company "news" is the company's own SEC filings: 8-Ks (results, deals,
   management changes) and periodic reports, each linked to the filing.
   Licensed headline feeds cost far more than this site's data budget, and
   the filings are the primary source the headlines are written from. */
const ITEM_TITLES = {
  "1.01": "Signed a material agreement", "1.02": "Ended a material agreement", "1.03": "Bankruptcy or receivership",
  "2.01": "Completed an acquisition or sale of assets", "2.02": "Reported quarterly results", "2.03": "Took on new debt or obligations",
  "2.05": "Announced restructuring costs", "2.06": "Reported an impairment", "3.01": "Listing or exchange notice",
  "3.02": "Sold unregistered shares", "4.01": "Changed auditor", "5.02": "Executive or board change",
  "5.03": "Changed its bylaws or fiscal year", "5.07": "Shareholder vote results", "7.01": "Shared information with investors (Reg FD)",
  "8.01": "Announced other events",
};
const secFilings = require("../lib/sec-filings");
const secData = require("../lib/sec-fundamentals");
router.get("/news/:ticker", async (req, res) => {
  const ticker = normalizeTicker(req.params.ticker);
  if (!ticker) return res.status(400).json({ error: "Invalid ticker." });
  const started = Date.now();
  try {
    const cacheKey = `news:${ticker}`;
    const cached = getCached(cacheKey, 30 * 60 * 1000);
    if (cached) return res.json(cached);
    const id = await secData.cikFor(ticker);
    if (!id) { setCached(cacheKey, []); return res.json([]); }
    const sub = await secData.submissions(ticker);
    const since = new Date(Date.now() - 120 * 86400000).toISOString().slice(0, 10);
    const items = secData.recentFilings(sub)
      .filter(f => f.filingDate >= since && (f.form === "8-K" || /^(10-Q|10-K)$/.test(f.form)))
      .slice(0, 10)
      .map(f => {
        const codes = String(f.items || "").split(",").map(x => x.trim()).filter(c => ITEM_TITLES[c]);
        const what = f.form === "8-K" ? (codes.map(c => ITEM_TITLES[c])[0] || "Filed a current report") : f.form === "10-K" ? "Filed its annual report (10-K)" : "Filed its quarterly report (10-Q)";
        const acc = String(f.accession || "").replace(/-/g, "");
        return {
          headline: `${sub.name || ticker}: ${what}`,
          summary: codes.length > 1 ? codes.slice(1).map(c => ITEM_TITLES[c]).join("; ") : "",
          source: `SEC ${f.form}`,
          url: f.primaryDocument ? `https://www.sec.gov/Archives/edgar/data/${Number(id.cik)}/${acc}/${f.primaryDocument}` : null,
          datetime: Math.floor(Date.parse((f.acceptance || f.filingDate + "T12:00:00Z")) / 1000),
          category: "filing",
        };
      });
    recordProvider("SEC EDGAR", true, Date.now() - started, `${items.length} filings for ${ticker}`);
    setCached(cacheKey, items);
    res.json(items);
  } catch (e) {
    recordProvider("SEC EDGAR", false, Date.now() - started, e.message);
    res.json([]);
  }
});

// ============================================================
//  Screener — Pro only
// ============================================================
const SCREENER_TICKERS = [
  // Technology
  "AAPL","MSFT","NVDA","GOOGL","AMZN","META","AVGO","AMD","QCOM","TXN",
  "INTC","ORCL","CRM","ADBE","CSCO","IBM","AMAT","KLAC","LRCX","PANW",
  "CRWD","SNOW","PLTR","NET","MDB","DDOG","ZS","NOW","INTU","FTNT",
  // Consumer Discretionary
  "TSLA","HD","MCD","NKE","LOW","BKNG","TGT","TJX","SBUX","CMG",
  "MAR","HLT","F","GM","ABNB","EBAY","ETSY","LULU","DG",
  // Consumer Staples
  "WMT","PG","KO","PEP","COST","PM","MO","CL","MDLZ","GIS","KHC","HSY",
  // Healthcare
  "LLY","UNH","JNJ","MRK","ABBV","TMO","ABT","BMY","PFE","AMGN",
  "GILD","ISRG","VRTX","REGN","CVS","CI","MDT","BSX","DHR","HCA",
  // Financials
  "JPM","BAC","WFC","GS","MS","V","MA","BLK","AXP","C",
  "SCHW","USB","PNC","COF","ICE","CME","CB","MET","PRU","AFL",
  // Energy
  "XOM","CVX","COP","EOG","SLB","PSX","VLO","MPC","OXY","KMI",
  // Industrials
  "GE","CAT","HON","UPS","FDX","RTX","LMT","NOC","DE","MMM",
  "EMR","ETN","ITW","GD","TDG","ODFL","URI","WAB","CARR",
  // Materials
  "LIN","APD","SHW","NEM","FCX","NUE","VMC","MLM","ALB","DOW",
  // Real Estate
  "PLD","AMT","CCI","EQIX","SPG","O","PSA","EXR","WELL","AVB",
  // Utilities
  "NEE","SO","DUK","D","EXC","SRE","AEP","XEL","WEC",
  // Popular growth and retail names (also widen the LensScore peer groups)
  "MU","ARM","MRVL","ANET","SMCI","DELL","HPE","TSM","ASML","ADI","NXPI","ON","MCHP",
  "SHOP","UBER","APP","TTD","U","RBLX","IONQ","RGTI","SOUN","PATH","OKTA","TWLO","HUBS","WDAY","TEAM","ADSK",
  "NFLX","DIS","CMCSA","T","VZ","TMUS","SPOT","RDDT","PINS","SNAP","TTWO","EA","WBD","ROKU",
  "SOFI","HOOD","COIN","AFRM","UPST","PYPL","XYZ","NU","ALLY","KKR","BX","APO",
  "HIMS","TEM","DXCM","ZTS","MRNA","IDXX","ELV","HUM","GEHC","PODD",
  "RKLB","ASTS","BA","LUV","DAL","UAL","PH","AXON","JCI","PWR","CEG","VST","OKLO","SMR",
  "MELI","CPNG","DASH","LYFT","CAVA","WING","DECK","ONON","RCL","CCL","ORLY","AZO","ROST","YUM","DPZ",
  "CELH","MNST","KDP","STZ","KR","SYY","EL","KMB",
  "WMB","OKE","HAL","DVN","FANG","ENPH","FSLR",
  "CTVA","ECL","DD","IP","CF",
  "DLR","VICI","IRM","ARE",
  "AES","PCG","ED","PEG","EIX",
  // ETFs
  "SPY","QQQ","IWM","DIA","XLF","XLK","XLV","XLE","GLD","TLT",
];

const SCREENER_ETFS = new Set(["SPY","QQQ","IWM","DIA","XLF","XLK","XLV","XLE","GLD","TLT"]);

const SCREENER_SECTOR = {
  AAPL:"Tech",MSFT:"Tech",NVDA:"Tech",GOOGL:"Tech",AMZN:"Cons.Disc",META:"Tech",
  AVGO:"Tech",AMD:"Tech",QCOM:"Tech",TXN:"Tech",INTC:"Tech",ORCL:"Tech",
  CRM:"Tech",ADBE:"Tech",CSCO:"Tech",IBM:"Tech",AMAT:"Tech",KLAC:"Tech",
  LRCX:"Tech",PANW:"Tech",CRWD:"Tech",SNOW:"Tech",PLTR:"Tech",NET:"Tech",
  MDB:"Tech",DDOG:"Tech",ZS:"Tech",NOW:"Tech",INTU:"Tech",FTNT:"Tech",
  TSLA:"Cons.Disc",HD:"Cons.Disc",MCD:"Cons.Disc",NKE:"Cons.Disc",LOW:"Cons.Disc",
  BKNG:"Cons.Disc",TGT:"Cons.Disc",TJX:"Cons.Disc",SBUX:"Cons.Disc",CMG:"Cons.Disc",
  MAR:"Cons.Disc",HLT:"Cons.Disc",F:"Cons.Disc",GM:"Cons.Disc",ABNB:"Cons.Disc",
  EBAY:"Cons.Disc",ETSY:"Cons.Disc",LULU:"Cons.Disc",DG:"Cons.Disc",
  WMT:"Staples",PG:"Staples",KO:"Staples",PEP:"Staples",COST:"Staples",
  PM:"Staples",MO:"Staples",CL:"Staples",MDLZ:"Staples",GIS:"Staples",
  KHC:"Staples",HSY:"Staples",
  LLY:"Health",UNH:"Health",JNJ:"Health",MRK:"Health",ABBV:"Health",
  TMO:"Health",ABT:"Health",BMY:"Health",PFE:"Health",AMGN:"Health",
  GILD:"Health",ISRG:"Health",VRTX:"Health",REGN:"Health",CVS:"Health",
  CI:"Health",MDT:"Health",BSX:"Health",DHR:"Health",HCA:"Health",
  JPM:"Finance",BAC:"Finance",WFC:"Finance",GS:"Finance",MS:"Finance",
  V:"Finance",MA:"Finance",BLK:"Finance",AXP:"Finance",C:"Finance",
  SCHW:"Finance",USB:"Finance",PNC:"Finance",COF:"Finance",ICE:"Finance",
  CME:"Finance",CB:"Finance",MET:"Finance",PRU:"Finance",AFL:"Finance",
  XOM:"Energy",CVX:"Energy",COP:"Energy",EOG:"Energy",SLB:"Energy",
  PSX:"Energy",VLO:"Energy",MPC:"Energy",OXY:"Energy",KMI:"Energy",
  GE:"Industrials",CAT:"Industrials",HON:"Industrials",UPS:"Industrials",
  FDX:"Industrials",RTX:"Industrials",LMT:"Industrials",NOC:"Industrials",
  DE:"Industrials",MMM:"Industrials",EMR:"Industrials",ETN:"Industrials",
  ITW:"Industrials",GD:"Industrials",TDG:"Industrials",ODFL:"Industrials",
  URI:"Industrials",WAB:"Industrials",CARR:"Industrials",
  LIN:"Materials",APD:"Materials",SHW:"Materials",NEM:"Materials",
  FCX:"Materials",NUE:"Materials",VMC:"Materials",MLM:"Materials",
  ALB:"Materials",DOW:"Materials",
  PLD:"Real Est.",AMT:"Real Est.",CCI:"Real Est.",EQIX:"Real Est.",
  SPG:"Real Est.",O:"Real Est.",PSA:"Real Est.",EXR:"Real Est.",
  WELL:"Real Est.",AVB:"Real Est.",
  NEE:"Utilities",SO:"Utilities",DUK:"Utilities",D:"Utilities",
  EXC:"Utilities",SRE:"Utilities",AEP:"Utilities",XEL:"Utilities",WEC:"Utilities",
  SPY:"ETF",QQQ:"ETF",IWM:"ETF",DIA:"ETF",XLF:"ETF",
  XLK:"ETF",XLV:"ETF",XLE:"ETF",GLD:"ETF",TLT:"ETF",
};

let _screenerCache = { data: null, ts: 0 };
const SCREENER_TTL = 20 * 60 * 1000;

/* ── Screener enrichment ─────────────────────────────────────────────────
   The screener used to be today's Yahoo most-actives/gainers/losers only,
   with sector "Other" for 90% of rows and revenue growth, EPS growth, beta
   and RSI blank for every row (audit 2026-10-06). Now: the curated large-cap
   list plus today's movers, each filled in from Finnhub (sector, growth,
   beta, valuation) and a Yahoo daily chart (price, 1D/1Y change, RSI-14).
   A background job fills rows at low priority through lib/finnhub-gate, so
   it never starves someone's stock page; results are kept for a day. */
const ENRICH_TTL = 6 * 3600 * 1000, PRICE_TTL = 6 * 3600 * 1000;
const _enrich = new Map();   // ticker -> { at, priceAt, sector, revenueGrowth, ... }
let _enrichRunning = false;

const peers = require("../lib/peer-universe");
const universeGrades = require("../lib/universe-grades");
const sectorFromIndustry = peers.sectorFromIndustry;
function rsi14(closes) {
  if (closes.length < 16) return null;
  let g = 0, l = 0;
  for (let i = 1; i <= 14; i++) { const d = closes[i] - closes[i - 1]; if (d > 0) g += d; else l -= d; }
  g /= 14; l /= 14;
  for (let i = 15; i < closes.length; i++) {
    const d = closes[i] - closes[i - 1];
    g = (g * 13 + Math.max(d, 0)) / 14; l = (l * 13 + Math.max(-d, 0)) / 14;
  }
  return l === 0 ? 100 : 100 - 100 / (1 + g / l);
}
/* One screener row: company figures from SEC filings, prices from the
   licensed provider (lib/sec-universe.js does both and also feeds the
   LensScore peer set). Background priority, so it stops early on quota. */
async function enrichOne(ticker) {
  const prev = _enrich.get(ticker) || {};
  const out = { ...prev };
  const now = Date.now();
  try {
    const co = await secUniverse.forTicker(ticker, { kind: "background" });
    const m = co.metric || {};
    const closes = (co.rows || []).map(r => r.close).filter(v => Number.isFinite(v) && v > 0);
    out.at = now; out.priceAt = now;
    out.name = co.name || prev.name || null;
    out.sector = co.sector || prev.sector || null;
    out.marketCap = Number(m.marketCapitalization) > 0 ? m.marketCapitalization * 1e6 : prev.marketCap ?? null;
    out.revenueGrowth = Number.isFinite(m.revenueGrowthTTMYoy) ? m.revenueGrowthTTMYoy : null;
    out.epsGrowth = Number.isFinite(m.epsGrowthTTMYoy) ? m.epsGrowthTTMYoy : null;
    out.beta = Number.isFinite(m.beta) ? m.beta : null;
    out.pe = Number(m.peTTM) > 0 ? Number(m.peTTM) : null;
    out.pb = Number(m.pbQuarterly) > 0 ? Number(m.pbQuarterly) : null;
    out.dividendYield = Number.isFinite(m.dividendYieldIndicatedAnnual) ? m.dividendYieldIndicatedAnnual : null;
    if (closes.length >= 2) {
      out.price = closes.at(-1);
      out.change1D = (closes.at(-1) / closes.at(-2) - 1) * 100;
      out.change1Y = Number.isFinite(m["52WeekPriceReturnDaily"]) ? m["52WeekPriceReturnDaily"] : (closes.at(-1) / closes[0] - 1) * 100;
      out.rsi = rsi14(closes.slice(-120));
      out.asOf = co.rows.at(-1)?.day ? Math.floor(Date.parse(co.rows.at(-1).day + "T21:00:00Z") / 1000) : null;
    }
  } catch (_) { /* ETFs and foreign listings have no SEC facts */ }
  _enrich.set(ticker, out);
}
function startEnrichment(tickers) {
  if (_enrichRunning) return;
  const todo = tickers.filter(t => {
    const e = _enrich.get(t);
    return !e || !e.at || Date.now() - e.at > ENRICH_TTL || !e.priceAt || Date.now() - e.priceAt > PRICE_TTL;
  });
  if (!todo.length) return;
  _enrichRunning = true;
  (async () => {
    try {
      const queue = todo.map(t => ({ t, tries: 0 }));
      /* A ticker that failed (SEC busy, price quota) goes back on the
         queue, up to three tries, instead of waiting six hours. */
      const worker = async () => {
        while (queue.length) {
          const job = queue.shift();
          await enrichOne(job.t);
          const e = _enrich.get(job.t);
          if ((!e || !e.at) && job.tries < 2) { job.tries++; queue.push(job); await new Promise(r => setTimeout(r, 2000)); }
        }
      };
      await Promise.all([worker(), worker(), worker()]);
    } catch (e) { console.warn("[screener] enrichment stopped:", e.message); }
    finally { _enrichRunning = false; _screenerCache.ts = 0; }
  })();
}
function screenerRow(ticker, base) {
  const e = _enrich.get(ticker) || {};
  const pick = (a, b) => (a !== null && a !== undefined ? a : b);
  const row = {
    ticker,
    name: pick(base && base.name, e.name) || ticker,
    sector: SCREENER_SECTOR[ticker] || e.sector || "Other",
    price: pick(base && base.price, e.price) || 0,
    change1D: pick(base && base.change1D, e.change1D),
    change1Y: pick(base && base.change1Y, e.change1Y),
    revenueGrowth: e.revenueGrowth ?? null,
    marketCap: pick(base && base.marketCap, e.marketCap),
    pe: pick(base && base.pe, e.pe),
    pb: pick(base && base.pb, e.pb),
    dividendYield: pick(base && base.dividendYield, e.dividendYield),
    beta: pick(base && base.beta, e.beta),
    rsi: e.rsi ?? null,
    epsGrowth: e.epsGrowth ?? null,
    averageVolume: pick(base && base.averageVolume, e.averageVolume),
    asOf: pick(base && base.asOf, e.asOf),
    source: `SEC filings + ${prices.sourceLabel()}`,
    enriched: !!e.at,
  };
  const lg = universeGrades.get(ticker);
  if (lg) { row.lensScore = lg.score; row.grades = lg.grades; row.sectorRank = lg.sectorRank; row.sectorCount = lg.sectorCount; }
  return row;
}

/* Keep the popular names warm. Their Finnhub metrics and profiles sit in the
   gate's cache, so a stock page for any of them answers from cache instead of
   spending the shared per-minute quota (live audit 2026-10-06: a burst of
   page loads ran it out and metrics/analyst answered 503 for niche names). */
if (process.env.NODE_ENV === "production") {
  const warm = () => startEnrichment([...new Set(SCREENER_TICKERS)].filter(t => !SCREENER_ETFS.has(t)));
  setTimeout(warm, 20 * 1000).unref();
  setInterval(warm, 6 * 3600 * 1000).unref();
}

router.get("/screener", requirePro, async (req, res) => {
  if (_screenerCache.data && Date.now() - _screenerCache.ts < SCREENER_TTL) {
    res.setHeader("X-Screener-Enriching", _enrichRunning ? "1" : "0");
    return res.json(_screenerCache.data);
  }
  const universe = [...new Set(SCREENER_TICKERS)].filter(t => !SCREENER_ETFS.has(t));
  startEnrichment(universe);
  const rows = universe.map(t => screenerRow(t, null)).filter(r => r.price > 0);
  if (!rows.length) return res.status(503).json({ error: "Screener data is warming up. Try again in a minute." });
  _screenerCache = { data: rows, ts: Date.now() };
  res.setHeader("X-Screener-Enriching", _enrichRunning ? "1" : "0");
  res.json(rows);
});

// ============================================================
//  Quote (Yahoo → Stooq fallback, rate-limited)
// ============================================================
// Yahoo summary helper — always returns null (Yahoo blocks server-side)
async function getYahooSummary(_ticker, _modules) { return null; }

router.get("/quote/:ticker", checkAnalysisLimit, async (req, res) => {
  const started = Date.now();
  try {
    const ticker = normalizeTicker(req.params.ticker);
    if (!ticker) return res.status(400).json({ error: "Invalid ticker." });
    const rawRange = String(req.query.range || "1y").toLowerCase();
    const range = VALID_RANGES.has(rawRange) ? rawRange : "1y";
    const rawInterval = String(req.query.interval || "").toLowerCase();
    // Auto-pick a sensible interval per range so long ranges return COMPLETE
    // history (Yahoo caps daily-interval responses on multi-year ranges).
    const AUTO_INTERVAL = {
      "1d":"5m","5d":"30m","1mo":"1d","3mo":"1d","6mo":"1d",
      "ytd":"1d","1y":"1d","2y":"1d","5y":"1wk","10y":"1wk","max":"1mo"
    };
    let interval = VALID_INTERVALS.has(rawInterval) ? rawInterval : (AUTO_INTERVAL[range] || "1d");
    const cacheKey = `quote:${ticker}:${range}:${interval}`;
    const cached = getCached(cacheKey, 60 * 1000);
    if (cached) return res.json(cached);

    /* Prices come from lib/prices.js (Marketstack when licensed, Yahoo only
       as a legacy fallback before that); company figures for the header
       (market cap, P/E, beta) come from SEC filings. No unlicensed source is
       called here. */
    let data = null;
    let source = null;
    try {
      const chart = await prices.getChart(ticker, { range, interval, preview: req.query.preview === "1" });
      source = chart.source;
      data = { chart: chart.chart };
    } catch (e) { console.log(`[quote] ${prices.sourceLabel()} failed for ${ticker}: ${e.message}`); }

    if (!data?.chart?.result?.[0]?.timestamp?.length) {
      recordProvider("Market prices", false, Date.now() - started, `No price data for ${ticker}`);
      return res.status(404).json({ error: `No price data found for "${ticker}". Check the ticker symbol.` });
    }

    const result = data.chart.result[0];
    try {
      // Filings for a company nobody has opened yet take a few seconds; the
      // chart does not wait for them (the next view has them cached).
      const pending = secUniverse.forTicker(ticker, { kind: "interactive" });
      pending.catch(() => {});
      const co = await Promise.race([
        pending,
        new Promise((_, reject) => setTimeout(() => reject(new Error("slow")), 2500)),
      ]);
      const m = co.metric || {};
      const price = Number(result.meta.regularMarketPrice) || co.price;
      const shares = co.snap?.sharesOutstanding;
      result.meta.longName = co.name || result.meta.longName || ticker;
      result.meta.shortName = result.meta.shortName && result.meta.shortName !== ticker ? result.meta.shortName : (co.name || ticker);
      if (shares && price) result.meta.marketCap = shares * price;
      if (m.peTTM > 0) { result.meta.trailingPE = m.peTTM; result.meta.peBasis = "ttm"; }
      if (Number.isFinite(m.beta)) result.meta.beta = m.beta;
      result.meta.fiftyTwoWeekHigh = result.meta.fiftyTwoWeekHigh || m["52WeekHigh"] || null;
      result.meta.fiftyTwoWeekLow = result.meta.fiftyTwoWeekLow || m["52WeekLow"] || null;
      result.meta.sector = co.sector || null;
      result.meta.industry = co.industry || null;
    } catch (_) { /* ETFs and foreign listings have no SEC facts; the chart still shows */ }

    const timestamps = result.timestamp || [];
    const latestTimestamp = timestamps.length ? timestamps[timestamps.length - 1] : null;
    const ageSeconds = latestTimestamp ? Math.max(0, Math.round(Date.now() / 1000 - latestTimestamp)) : null;
    data.impliedLens = {
      source: source || "Aggregated market data",
      retrievedAt: new Date().toISOString(),
      asOf: latestTimestamp ? new Date(latestTimestamp * 1000).toISOString() : null,
      latestTimestamp,
      ageSeconds,
      interval,
      range,
      marketSession: marketSessionAt(),
      delayStatus: "provider-dependent",
      delayed: null,
      fallback: /legacy/i.test(source || ""),
      synthetic: false,
    };
    setCached(cacheKey, data);
    recordProvider(prices.provider() === "marketstack" ? "Marketstack" : "Yahoo Finance", true, Date.now() - started, source);
    res.json(data);
  } catch (e) {
    recordProvider("Market prices", false, Date.now() - started, e.message);
    console.error("[quote] proxy error:", e.message);
    res.status(503).json({
      error: "Live market data is currently unavailable for this ticker.",
      synthetic: false,
    });
  }
});

// ============================================================
//  Home-dashboard analyst signals (free — key stays server-side)
// ============================================================
router.get("/market/analyst-signals", (_req, res) => {
  // Analyst ratings need a licensed feed the site does not have.
  res.json({ available: false, buy: 0, hold: 0, sell: 0 });
});

// ============================================================
//  Market movers (gainers / losers / most active)
// ============================================================
/* Movers among the ~300 companies the site grades, from their latest daily
   closes (the licensed price feed does not sell a whole-market movers list). */
router.get("/market/movers", (req, res) => {
  const requestedType = String(req.query.type || "gainers");
  const type = ["gainers", "losers", "active"].includes(requestedType) ? requestedType : "gainers";
  startEnrichment([...new Set(SCREENER_TICKERS)].filter(t => !SCREENER_ETFS.has(t)));
  const rows = [..._enrich.entries()]
    .map(([symbol, e]) => ({ symbol, name: e.name || symbol, price: e.price, chgPct: e.change1D, cap: e.marketCap || 0, asOf: e.asOf ? new Date(e.asOf * 1000).toISOString().slice(0, 10) : null }))
    .filter(r => Number.isFinite(r.price) && r.price > 0 && Number.isFinite(r.chgPct));
  /* The universe refreshes half its companies each evening (lib/prices.js),
     so compare only companies whose latest close is the newest one: a
     two-day-old move must not sit beside yesterday's. */
  const newest = rows.reduce((m, r) => (r.asOf && r.asOf > m ? r.asOf : m), "");
  const fresh = rows.filter(r => r.asOf === newest);
  if (fresh.length >= 12) rows.splice(0, rows.length, ...fresh);
  const sorted = type === "losers" ? rows.sort((a, b) => a.chgPct - b.chgPct)
    : type === "active" ? rows.sort((a, b) => Math.abs(b.chgPct) * Math.log10(b.cap + 10) - Math.abs(a.chgPct) * Math.log10(a.cap + 10))
    : rows.sort((a, b) => b.chgPct - a.chgPct);
  res.json(sorted.slice(0, 6).map(({ cap, ...r }) => r));
});

// ============================================================
//  Public landing summary — live index, sectors, breadth, news
/* ═══════════════════════════════════════════════════════════════════════════
   HOW LONG A WINDOW IS DECIDES HOW FINE THE BARS ARE.

   An earlier pass moved 1M from hourly to daily closes on the grounds that
   more points is more zigzag: over the same month the S&P changes direction
   81 times hourly and 12 times daily across the same 2.4 points of range.
   That reasoning is sound about noise and wrong about the picture. Twenty-two
   daily closes across an 880x372 plot is twenty straight segments with hard
   corners - it reads as a coarse polyline, not as a market. Rendered side by
   side from the same month of real S&P data, the daily version looks cheap
   and the hourly version looks like a chart, even though the hourly one is
   objectively busier. "Smoother" was not what was missing; density was.

   So 1M asks for hourly bars again, with daily closes as the retreat rather
   than the default - the opposite of what it was. Note the retreats now
   actually retreat: the old 1M ladder had a second rung FINER than its first
   and a third byte-identical to its first, so a thin symbol re-issued the
   same request twice and called it a fallback.

   The interval is still a property of the window rather than a thing to
   maximise - 1Y stays on daily closes, where 250 points is already dense. Each
   window still carries a ladder because Yahoo does not guarantee every
   interval for every symbol; the first rung is the conventional choice and
   the rest are retreats. Whatever answers is reported back as `interval` and
   `points`, so the resolution is checkable rather than assumed.
   ═══════════════════════════════════════════════════════════════════════════ */
const WINDOWS = {
  "1D": { label: "1 day",    ladder: [ { interval: "2m",  range: "1d",  min: 90 },
                                       { interval: "5m",  range: "1d",  min: 30 },
                                       { interval: "15m", range: "1d",  min: 10 } ] },
  "1W": { label: "1 week",   ladder: [ { interval: "15m", range: "5d",  min: 90 },
                                       { interval: "30m", range: "5d",  min: 40 },
                                       { interval: "1h",  range: "5d",  min: 10 } ] },
  "1M": { label: "30 days",  ladder: [ { interval: "1h",  range: "1mo", min: 60 },
                                       { interval: "90m", range: "1mo", min: 40 },
                                       { interval: "1d",  range: "1mo", min: 2  } ] },
  "3M": { label: "3 months", ladder: [ { interval: "1d",  range: "3mo", min: 40 },
                                       { interval: "1wk", range: "3mo", min: 8 },
                                       { interval: "1d",  range: "6mo", min: 2  } ] },
  "1Y": { label: "1 year",   ladder: [ { interval: "1d",  range: "1y",  min: 150 },
                                       { interval: "1wk", range: "1y",  min: 30 },
                                       { interval: "1d",  range: "6mo", min: 2  } ] },
};
const DEFAULT_WINDOW = "1M";
function normaliseWindow(value) {
  const key = String(value || "").toUpperCase();
  return Object.prototype.hasOwnProperty.call(WINDOWS, key) ? key : DEFAULT_WINDOW;
}

// ============================================================
// This endpoint exists so the reference-matched landing terminal can remain
// honest. Every displayed number is returned by a provider and the entire
// response is cached, rather than fabricating a polished marketing preview.
router.get("/market/landing-summary", async (req, res) => {
  const chartWindow = normaliseWindow(req.query && req.query.window);
  const cacheKey = "market:landing-summary:" + chartWindow;
  const cached = getCached(cacheKey, 5 * 60 * 1000);
  if (cached) return res.json(cached);

  // The three indexes are drawn as overlaid lines on one chart, so they need
  // their own point series, not just a headline number. The sector ETFs only
  // need today's move, which is what a single daily bar already carries.
  const INDEX_SYMBOLS = [
    ["^GSPC", "S&P 500"],
    ["^IXIC", "Nasdaq"],
    ["^DJI", "Dow Jones"],
  ];
  const symbols = [
    ...INDEX_SYMBOLS,
    ["XLK", "Technology"],
    ["XLC", "Comm. Services"],
    ["XLI", "Industrials"],
    ["XLF", "Financials"],
    ["XLE", "Energy"],
    ["XLRE", "Real Estate"],
  ];

  const SERIES_LADDER = WINDOWS[chartWindow].ladder;

  /* Index levels need an index licence; with the licensed provider the
     three lines are the ETFs that track them (SPY, QQQ, DIA). */
  const ETF_FOR = { "^GSPC": "SPY", "^IXIC": "QQQ", "^DJI": "DIA" };
  async function fetchSeries(symbol, interval, range) {
    const sym = prices.provider() === "marketstack" ? (ETF_FOR[symbol] || symbol) : symbol;
    const payload = await prices.getChart(sym, { range, interval, preview: true });
    const result = payload?.chart?.result?.[0];
    if (!result) throw new Error(`${symbol} returned no result`);
    const rawCloses = result?.indicators?.quote?.[0]?.close || [];
    const rawStamps = result?.timestamp || [];
    // Keep the timestamp with its close: a gap has to stay a gap, or the
    // series silently shifts and every point after it is on the wrong date.
    //
    // The null check has to happen BEFORE the Number(): Number(null) is 0, and
    // 0 passes Number.isFinite. Yahoo returns null closes for bars that have
    // not printed - the current hour, a halt, a thin session - so every one of
    // them used to survive this filter as a price of zero, normalise to
    // -100%, and pull the whole chart flat against the floor with a cliff at
    // the front. It is intermittent because it depends on what Yahoo happens
    // to be missing at the moment of the request.
    const points = [];
    for (let i = 0; i < rawCloses.length; i += 1) {
      if (rawCloses[i] == null || rawStamps[i] == null) continue;
      const close = Number(rawCloses[i]);
      const at = Number(rawStamps[i]);
      if (!Number.isFinite(close) || close <= 0) continue;
      if (!Number.isFinite(at)) continue;
      points.push([at, close]);
    }
    return { meta: result.meta || {}, points };
  }

  // The last close that belongs to an earlier session than the final bar.
  function priorSessionClose(points) {
    if (!Array.isArray(points) || points.length < 2) return null;
    const dayOf = at => new Date(at * 1000).toLocaleDateString("en-CA", { timeZone: "America/New_York" });
    const lastDay = dayOf(points[points.length - 1][0]);
    for (let i = points.length - 2; i >= 0; i -= 1) {
      if (dayOf(points[i][0]) !== lastDay) return points[i][1];
    }
    return null;
  }

  async function loadChart(symbol, name, wantSeries) {
    let best = null;
    let used = null;
    for (const rung of (wantSeries ? SERIES_LADDER : SERIES_LADDER.slice(-1))) {
      try {
        const attempt = await fetchSeries(symbol, rung.interval, rung.range);
        if (!best || attempt.points.length > best.points.length) { best = attempt; used = rung; }
        if (attempt.points.length >= rung.min) { best = attempt; used = rung; break; }
      } catch (_) { /* try the next rung */ }
    }
    if (!best) throw new Error(`${symbol} returned no usable series`);

    const meta = best.meta;
    const closes = best.points.map(p => p[1]);
    const price = Number(meta.regularMarketPrice ?? closes.at(-1));
    if (!(price > 0)) throw new Error(`${symbol} did not return a price`);

    /* chartPreviousClose is the close before the chart's RANGE, not before
       today. Over a one-month range it is the price a month ago, so using it
       as "previous close" turned every sector chip into a monthly figure
       sitting under a heading that said "today": production was reporting
       Industrials -6.08% and Energy +9.44% on a day when Yahoo's own meta had
       XLI at +0.30% and XLE at -0.85%. It is only correct when the range is a
       single day, which is never the case here, so it is not used at all.

       meta.previousClose is the right number when Yahoo sends it. When it
       does not, the series itself has the answer: the last close belonging to
       an earlier calendar day in the exchange's own timezone. Dividing epoch
       seconds by 86400 would put the boundary at UTC midnight, which is
       mid-session in New York. */
    const previousClose = Number.isFinite(Number(meta.previousClose)) && Number(meta.previousClose) > 0
      ? Number(meta.previousClose)
      : priorSessionClose(best.points);
    const changePct = previousClose > 0 ? ((price - previousClose) / previousClose) * 100 : null;

    // Cap the payload: beyond a few hundred points a line chart this size is
    // drawing several samples per pixel.
    const MAX = 420;
    const series = best.points.length > MAX
      ? best.points.filter((_, i) => i % Math.ceil(best.points.length / MAX) === 0)
      : best.points;

    return {
      symbol,
      name: prices.provider() === "marketstack" && ETF_FOR[symbol] ? `${name} (${ETF_FOR[symbol]})` : name,
      price, changePct,
      closes: series.map(p => p[1]),
      stamps: wantSeries ? series.map(p => p[0]) : undefined,
      interval: used ? used.interval : null,
      range: used ? used.range : null,
      points: series.length,
    };
  }

  const started = Date.now();
  const indexSet = new Set(INDEX_SYMBOLS.map(([symbol]) => symbol));
  const settled = await Promise.allSettled(
    symbols.map(([symbol, name]) => loadChart(symbol, name, indexSet.has(symbol)))
  );
  const quotes = settled.filter(item => item.status === "fulfilled").map(item => item.value);
  const overview = quotes.find(item => item.symbol === "^GSPC") || null;
  const indexes = quotes.filter(item => indexSet.has(item.symbol));
  const sectors = quotes.filter(item => !indexSet.has(item.symbol));
  const measured = sectors.filter(item => Number.isFinite(item.changePct));
  const advancing = measured.filter(item => item.changePct >= 0).length;
  const breadth = measured.length ? Math.round((advancing / measured.length) * 100) : null;

  let news = [];
  if (require("../lib/data-policy").finnhubAllowed() && FINNHUB_KEY) {
    try {
      const newsResponse = await fetchWithTimeout(`https://finnhub.io/api/v1/news?category=general&token=${FINNHUB_KEY}`, {}, 4500);
      if (newsResponse.ok) {
        const payload = await newsResponse.json();
        news = (Array.isArray(payload) ? payload : []).slice(0, 3).map(item => ({
          headline: String(item?.headline || "").trim(),
          source: String(item?.source || "Market news").trim(),
          url: /^https?:\/\//i.test(String(item?.url || "")) ? item.url : null,
          datetime: Number(item?.datetime) || null,
        })).filter(item => item.headline);
      }
    } catch (_) {}
  }

  const result = {
    window: chartWindow,
    windowLabel: WINDOWS[chartWindow].label,
    overview,
    indexes,
    sectors,
    breadth,
    advancing,
    measured: measured.length,
    news,
    asOf: new Date().toISOString(),
    source: prices.provider() === "marketstack" ? "Marketstack · SPY, QQQ, DIA" : "Market data",
    synthetic: false,
  };
  setCached(cacheKey, result);
  recordProvider(prices.provider() === "marketstack" ? "Marketstack" : "Yahoo Finance", Boolean(overview), Date.now() - started, `${quotes.length}/${symbols.length} landing symbols`);
  return res.json(result);
});

module.exports = router;
router._test = { sectorFromIndustry: (...a) => sectorFromIndustry(...a), rsi14: (...a) => rsi14(...a), yahooSymbol: (...a) => yahooSymbol(...a) };
/* Yahoo spells share classes with a dash (BRK-B); SEC and most users use a
   dot (BRK.B). Without this, Berkshire's quote and chart returned 404. */
function yahooSymbol(t) { return String(t || "").replace(/^([A-Z]{1,5})\.([A-Z]{1,2})$/, "$1-$2"); }

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
router.get("/news/:ticker", async (req, res) => {
  const ticker = normalizeTicker(req.params.ticker);
  if (!ticker) return res.status(400).json({ error: "Invalid ticker." });
  const started = Date.now();
  try {
    const cacheKey = `news:${ticker}`;
    const cached = getCached(cacheKey, 5 * 60 * 1000);
    if (cached) return res.json(cached);
    const to     = new Date().toISOString().split("T")[0];
    const from   = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString().split("T")[0];
    const url    = `https://finnhub.io/api/v1/company-news?symbol=${ticker}&from=${from}&to=${to}&token=${FINNHUB_KEY}`;
    const r      = await fetchWithTimeout(url);
    if (!r.ok) console.warn(`[news] Finnhub returned ${r.status} for ${ticker}`);
    const data   = await r.json();
    const items = Array.isArray(data) ? data.slice(0, 10) : [];
    recordProvider("Finnhub", r.ok, Date.now() - started, r.ok ? "News available" : `HTTP ${r.status}`);
    setCached(cacheKey, items);
    res.json(items);
  } catch (e) {
    recordProvider("Finnhub", false, Date.now() - started, e.message);
    console.error(`[news] error for ${ticker}:`, e.message);
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
  "AMZN","MAR","HLT","F","GM","ABNB","EBAY","ETSY","LULU","DG",
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
  // ETFs
  "SPY","QQQ","IWM","DIA","XLF","XLK","XLV","XLE","GLD","TLT",
];

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

function yahooRaw(value) {
  const raw = value && typeof value === "object" ? value.raw : value;
  return raw !== null && raw !== undefined && raw !== "" && Number.isFinite(Number(raw))
    ? Number(raw)
    : null;
}

async function loadYahooScreenerUniverse() {
  const screens = ["most_actives", "day_gainers", "day_losers"];
  const settled = await Promise.allSettled(screens.map(async (screen) => {
    const url = `https://query1.finance.yahoo.com/v1/finance/screener/predefined/saved?formatted=true&scrIds=${screen}&start=0&count=100`;
    const response = await fetchWithTimeout(url, {
      headers: { "User-Agent": "Mozilla/5.0" },
    }, 8000);
    if (!response.ok) throw new Error(`Yahoo screener ${screen} returned ${response.status}`);
    const payload = await response.json();
    return payload?.finance?.result?.[0]?.quotes || [];
  }));

  const byTicker = new Map();
  settled.forEach((result) => {
    if (result.status !== "fulfilled") return;
    result.value.forEach((quote) => {
      const ticker = normalizeTicker(quote?.symbol);
      const price = yahooRaw(quote?.regularMarketPrice);
      if (!ticker || !(price > 0) || quote?.quoteType !== "EQUITY") return;
      const dividendRatio = yahooRaw(quote.trailingAnnualDividendYield);
      const dividendYield = dividendRatio !== null && dividendRatio >= 0 && dividendRatio <= 0.25
        ? dividendRatio * 100
        : null;
      byTicker.set(ticker, {
        ticker,
        name: quote.shortName || quote.longName || ticker,
        sector: SCREENER_SECTOR[ticker] || "Other",
        price,
        change1D: yahooRaw(quote.regularMarketChangePercent) ?? 0,
        change1Y: yahooRaw(quote.fiftyTwoWeekChangePercent),
        revenueGrowth: null,
        marketCap: yahooRaw(quote.marketCap),
        pe: yahooRaw(quote.trailingPE) ?? yahooRaw(quote.forwardPE),
        pb: yahooRaw(quote.priceToBook),
        dividendYield,
        beta: yahooRaw(quote.beta),
        rsi: null,
        epsGrowth: null,
        averageVolume: yahooRaw(quote.averageDailyVolume3Month),
        asOf: yahooRaw(quote.regularMarketTime),
        source: quote.quoteSourceName || "Yahoo Finance screener",
      });
    });
  });
  return [...byTicker.values()];
}

router.get("/screener", requirePro, async (req, res) => {
  if (_screenerCache.data && Date.now() - _screenerCache.ts < SCREENER_TTL) {
    return res.json(_screenerCache.data);
  }
  const started = Date.now();
  try {
    const yahooUniverse = await loadYahooScreenerUniverse();
    if (yahooUniverse.length >= 10) {
      _screenerCache = { data: yahooUniverse, ts: Date.now() };
      recordProvider("Yahoo Finance", true, Date.now() - started, `${yahooUniverse.length} screener symbols`);
      return res.json(yahooUniverse);
    }
    recordProvider("Yahoo Finance", false, Date.now() - started, "Screener universe was empty");
  } catch (error) {
    recordProvider("Yahoo Finance", false, Date.now() - started, error.message);
  }
  try {
    const CHUNK     = 20;
    const allStocks = [];
    for (let i = 0; i < SCREENER_TICKERS.length; i += CHUNK) {
      const chunk   = SCREENER_TICKERS.slice(i, i + CHUNK);
      const results = await Promise.allSettled(
        chunk.map(async (ticker) => {
          const [qRes, mRes] = await Promise.all([
            fetchWithTimeout(`https://finnhub.io/api/v1/quote?symbol=${ticker}&token=${FINNHUB_KEY}`),
            fetchWithTimeout(`https://finnhub.io/api/v1/stock/metric?symbol=${ticker}&metric=all&token=${FINNHUB_KEY}`),
          ]);
          const [q, md] = await Promise.all([qRes.json(), mRes.json()]);
          const m = md.metric || {};
          return {
            ticker,
            sector:        SCREENER_SECTOR[ticker] || "Other",
            price:         q.c || 0,
            change1D:      q.pc > 0 ? ((q.c - q.pc) / q.pc * 100) : 0,
            change1Y:      m["52WeekPriceReturnDaily"]     || null,
            revenueGrowth: m["revenueGrowthTTMYoy"]        || null,
            marketCap:     m.marketCapitalization ? m.marketCapitalization * 1e6 : null,
            pe:            m.peBasicExclExtraTTM || m.peTTM || null,
            pb:            m.pbQuarterly                   || null,
            dividendYield: m.dividendYieldIndicatedAnnual  || 0,
            beta:          m.beta                          || null,
            rsi:           m.rsi14                         || null,
            epsGrowth:     m.epsGrowthTTMYoy               || null,
          };
        })
      );
      allStocks.push(
        ...results
          .filter(r => r.status === "fulfilled" && r.value.price > 0)
          .map(r => r.value)
      );
      if (i + CHUNK < SCREENER_TICKERS.length) {
        await new Promise(r => setTimeout(r, 400)); // respect Finnhub rate limit
      }
    }
    _screenerCache = { data: allStocks, ts: Date.now() };
    res.json(allStocks);
  } catch (e) {
    console.error("screener error:", e);
    res.status(500).json({ error: "Screener fetch failed" });
  }
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

    const YH = {
      "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
      "Accept": "application/json, text/plain, */*",
      "Accept-Language": "en-US,en;q=0.9",
      "Origin": "https://finance.yahoo.com",
      "Referer": "https://finance.yahoo.com/",
    };

    let data = null;
    let source = null;

    // Attempt 1: Yahoo Finance v8 chart (query2)
    try {
      const u = `https://query2.finance.yahoo.com/v8/finance/chart/${encodeURIComponent(ticker)}?interval=${interval}&range=${range}&includePrePost=false`;
      const r = await fetchWithTimeout(u, { headers: YH }, 4000);
      if (r.ok) {
        const j = await r.json();
        if (j?.chart?.result?.[0]?.timestamp?.length) {
          console.log(`[quote] Yahoo query2 OK for ${ticker}`);
          data = j;
          source = "Yahoo Finance chart";
        }
      }
    } catch (e) { console.log(`[quote] Yahoo query2 failed for ${ticker}: ${e.message}`); }

    // Attempt 2: Yahoo Finance v8 chart (query1)
    if (!data) {
      try {
        const u = `https://query1.finance.yahoo.com/v8/finance/chart/${encodeURIComponent(ticker)}?interval=${interval}&range=${range}&includePrePost=false`;
        const r = await fetchWithTimeout(u, { headers: YH }, 4000);
        if (r.ok) {
          const j = await r.json();
          if (j?.chart?.result?.[0]?.timestamp?.length) {
          console.log(`[quote] Yahoo query1 OK for ${ticker}`);
          data = j;
          source = "Yahoo Finance chart";
          }
        }
      } catch (e) { console.log(`[quote] Yahoo query1 failed for ${ticker}: ${e.message}`); }
    }

    // Attempt 3: Yahoo Finance v7 CSV
    if (!data) {
      try {
        const now2      = Math.floor(Date.now() / 1000);
        const rangeSecs = { "1d":86400,"5d":5*86400,"1mo":30*86400,"3mo":90*86400,"6mo":180*86400,"1y":365*86400,"2y":730*86400,"5y":1825*86400,"10y":3650*86400,"max":10950*86400 };
        // "max" → start at the epoch so we get the company's full listed history.
        const period1   = range === "max" ? 0 : now2 - (rangeSecs[range] || 365*86400);
        const csvInterval = (range === "5y" || range === "10y") ? "1wk" : (range === "max" ? "1mo" : "1d");
        const csvUrl    = `https://query1.finance.yahoo.com/v7/finance/download/${encodeURIComponent(ticker)}?period1=${period1}&period2=${now2}&interval=${csvInterval}&events=history&includeAdjustedClose=true`;
        const r         = await fetchWithTimeout(csvUrl, { headers: YH }, 4000);
        if (r.ok) {
          const csv   = await r.text();
          const lines = csv.trim().split("\n").slice(1).filter(l => l && !l.startsWith("Date") && !l.includes("<") && !l.startsWith("No data"));
          if (lines.length > 2) {
            const timestamps=[], opens=[], highs=[], lows=[], closes=[], vols=[];
            for (const line of lines) {
              const [date,,o,h,l,c,,v] = line.split(",");
              if (!date || !c || isNaN(parseFloat(c))) continue;
              timestamps.push(Math.floor(new Date(date).getTime()/1000));
              opens.push(parseFloat(o)||null); highs.push(parseFloat(h)||null);
              lows.push(parseFloat(l)||null);  closes.push(parseFloat(c));
              vols.push(parseInt(v)||null);
            }
            if (timestamps.length > 2) {
              console.log(`[quote] Yahoo v7 CSV OK for ${ticker} (${timestamps.length} rows)`);
              data = { chart: { result: [{ meta: {
                symbol: ticker, currency: "USD", exchangeName: "", instrumentType: "EQUITY",
                longName: ticker, shortName: ticker,
                regularMarketPrice: closes[closes.length-1],
                previousClose: closes[closes.length-2] || null,
                chartPreviousClose: closes[closes.length-2] || null,
              }, timestamp: timestamps, indicators: {
                quote: [{ open: opens, high: highs, low: lows, close: closes, volume: vols }],
                adjclose: [{ adjclose: closes }],
              }}], error: null }};
              source = "Yahoo Finance historical CSV";
            }
          }
        }
      } catch (e) { console.log(`[quote] Yahoo v7 CSV failed for ${ticker}: ${e.message}`); }
    }

    // Attempt 4: Stooq CSV
    if (!data) {
      try {
        const now3     = new Date();
        const rangeDays = { "1d":5,"5d":10,"1mo":35,"3mo":95,"6mo":185,"1y":370,"2y":740,"5y":1830,"10y":3660,"max":10960 };
        const days     = rangeDays[range] || 370;
        const from     = new Date(now3 - days * 86400000);
        const fmt      = d => d.toISOString().slice(0,10).replace(/-/g,"");
        const stooqUrl = `https://stooq.com/q/d/l/?s=${encodeURIComponent(ticker)}.US&d1=${fmt(from)}&d2=${fmt(now3)}&i=d`;
        const r        = await fetchWithTimeout(stooqUrl, { headers: { "User-Agent": "Mozilla/5.0" } }, 8000);
        if (r.ok) {
          const csv   = await r.text();
          const lines = csv.trim().split("\n").slice(1).filter(l => l && !l.startsWith("No data") && !l.includes("<"));
          if (lines.length > 2) {
            const timestamps=[], opens=[], highs=[], lows=[], closes=[], vols=[];
            for (const line of lines) {
              const [date,o,h,l,c,v] = line.split(",");
              if (!date || !c || isNaN(parseFloat(c))) continue;
              timestamps.push(Math.floor(new Date(date).getTime()/1000));
              opens.push(parseFloat(o)||null); highs.push(parseFloat(h)||null);
              lows.push(parseFloat(l)||null);  closes.push(parseFloat(c));
              vols.push(parseInt(v)||null);
            }
            if (timestamps.length > 2) {
              console.log(`[quote] Stooq OK for ${ticker} (${timestamps.length} rows)`);
              const FH = FINNHUB_KEY;
              const [qr, pr, mr] = await Promise.all([
                fetchWithTimeout(`https://finnhub.io/api/v1/quote?symbol=${ticker}&token=${FH}`,             {}, 4000).catch(()=>null),
                fetchWithTimeout(`https://finnhub.io/api/v1/stock/profile2?symbol=${ticker}&token=${FH}`,   {}, 4000).catch(()=>null),
                fetchWithTimeout(`https://finnhub.io/api/v1/stock/metric?symbol=${ticker}&metric=all&token=${FH}`, {}, 4000).catch(()=>null),
              ]);
              const qt = qr?.ok ? await qr.json().catch(()=>({})) : {};
              const pf = pr?.ok ? await pr.json().catch(()=>({})) : {};
              const mt = mr?.ok ? await mr.json().catch(()=>({})) : {};
              const m2 = mt.metric || {};
              const price2  = qt.c || closes[closes.length-1];
              const shares2 = pf.shareOutstanding ? pf.shareOutstanding * 1e6 : null;
              data = { chart: { result: [{ meta: {
                symbol: ticker, currency: pf.currency||"USD", exchangeName: pf.exchange||"",
                instrumentType: "EQUITY", longName: pf.name||ticker, shortName: pf.name||ticker,
                regularMarketPrice: price2, previousClose: qt.pc||null, chartPreviousClose: qt.pc||null,
                regularMarketVolume: qt.v||vols[vols.length-1]||null,
                averageDailyVolume3Month: m2["3MonthAverageTradingVolume"] ? m2["3MonthAverageTradingVolume"]*1e6 : null,
                marketCap: shares2 && price2 ? shares2*price2 : null,
                fiftyTwoWeekHigh: m2["52WeekHigh"]||null, fiftyTwoWeekLow: m2["52WeekLow"]||null,
                trailingPE: m2.peNormalizedAnnual||m2.peBasicExclExtraTTM||null,
              }, timestamp: timestamps, indicators: {
                quote: [{ open: opens, high: highs, low: lows, close: closes, volume: vols }],
                adjclose: [{ adjclose: closes }],
              }}], error: null }};
              source = "Stooq historical prices + Finnhub snapshot";
            }
          } else {
            console.log(`[quote] Stooq returned no rows for ${ticker}: ${csv.slice(0,200)}`);
          }
        }
      } catch (e) { console.log(`[quote] Stooq failed for ${ticker}: ${e.message}`); }
    }

    if (!data) {
      console.log(`[quote] All sources exhausted for ${ticker}`);
      recordProvider("Market prices", false, Date.now() - started, `No price data for ${ticker}`);
      return res.status(404).json({ error: `No price data found for "${ticker}". Check the ticker symbol.` });
    }

    // Augment meta with Finnhub real-time data if missing
    const result = data.chart.result[0];
    if (!result.meta.marketCap || !result.meta.fiftyTwoWeekHigh) {
      try {
        const FH = FINNHUB_KEY;
        const [qr, pr, mr] = await Promise.all([
          fetchWithTimeout(`https://finnhub.io/api/v1/quote?symbol=${ticker}&token=${FH}`,             {}, 4000).catch(()=>null),
          fetchWithTimeout(`https://finnhub.io/api/v1/stock/profile2?symbol=${ticker}&token=${FH}`,   {}, 4000).catch(()=>null),
          fetchWithTimeout(`https://finnhub.io/api/v1/stock/metric?symbol=${ticker}&metric=all&token=${FH}`, {}, 4000).catch(()=>null),
        ]);
        const qt = qr?.ok ? await qr.json().catch(()=>({})) : {};
        const pf = pr?.ok ? await pr.json().catch(()=>({})) : {};
        const mt = mr?.ok ? await mr.json().catch(()=>({})) : {};
        const m  = mt.metric || {};
        const shares = pf.shareOutstanding ? pf.shareOutstanding*1e6 : null;
        const price  = qt.c || result.meta.regularMarketPrice;
        result.meta.longName              = result.meta.longName  || pf.name || ticker;
        result.meta.shortName             = result.meta.shortName || pf.name || ticker;
        result.meta.regularMarketPrice    = price || result.meta.regularMarketPrice;
        result.meta.previousClose         = qt.pc || result.meta.previousClose;
        result.meta.chartPreviousClose    = qt.pc || result.meta.chartPreviousClose;
        result.meta.regularMarketVolume   = qt.v  || result.meta.regularMarketVolume;
        result.meta.marketCap             = (shares && price) ? shares*price : result.meta.marketCap;
        result.meta.fiftyTwoWeekHigh      = m["52WeekHigh"]  || result.meta.fiftyTwoWeekHigh;
        result.meta.fiftyTwoWeekLow       = m["52WeekLow"]   || result.meta.fiftyTwoWeekLow;
        result.meta.trailingPE            = m.peNormalizedAnnual || m.peBasicExclExtraTTM || result.meta.trailingPE;
        result.meta.averageDailyVolume3Month = m["3MonthAverageTradingVolume"]
          ? m["3MonthAverageTradingVolume"]*1e6 : result.meta.averageDailyVolume3Month;
      } catch (_) {}
    }

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
      fallback: Boolean(source && (source.startsWith("Stooq") || source.includes("historical CSV"))),
      synthetic: false,
    };
    setCached(cacheKey, data);
    recordProvider(source?.startsWith("Stooq") ? "Stooq" : "Yahoo Finance", true, Date.now() - started, source);
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
router.get("/market/analyst-signals", async (req, res) => {
  const raw     = String(req.query.tickers || "");
  const tickers = raw.split(",").map(normalizeTicker).filter(Boolean).slice(0, 10);
  if (!tickers.length) return res.json({ buy: 0, hold: 0, sell: 0 });
  const cacheKey = `signals:${tickers.sort().join(",")}`;
  const cached = getCached(cacheKey, 10 * 60 * 1000);
  if (cached) return res.json(cached);
  try {
    const results = await Promise.allSettled(
      tickers.map(t =>
        fetchWithTimeout(`https://finnhub.io/api/v1/stock/recommendation?symbol=${t}&token=${FINNHUB_KEY}`)
          .then(r => r.ok ? r.json() : null).catch(() => null)
      )
    );
    let buy = 0, hold = 0, sell = 0;
    results.forEach(res => {
      if (res.status !== "fulfilled" || !res.value?.length) return;
      const l = res.value[0];
      buy  += (l.strongBuy  || 0) + (l.buy   || 0);
      hold += (l.hold       || 0);
      sell += (l.strongSell || 0) + (l.sell  || 0);
    });
    const result = { buy, hold, sell };
    setCached(cacheKey, result);
    res.json(result);
  } catch (e) {
    console.error("analyst-signals error:", e.message);
    res.json({ buy: 0, hold: 0, sell: 0 });
  }
});

// ============================================================
//  Market movers (gainers / losers / most active)
// ============================================================
router.get("/market/movers", async (req, res) => {
  const requestedType = String(req.query.type || "gainers");
  const type = ["gainers", "losers", "active"].includes(requestedType) ? requestedType : "gainers";
  const cacheKey = `movers:${type}`;
  const cached = getCached(cacheKey, 2 * 60 * 1000);
  if (cached) return res.json(cached);
  const scrIds = type === "losers" ? "day_losers" : type === "active" ? "most_actives" : "day_gainers";
  try {
    const url = `https://query1.finance.yahoo.com/v1/finance/screener/predefined/saved?formatted=true&scrIds=${scrIds}&start=0&count=6`;
    const r   = await fetchWithTimeout(url, { headers: { "User-Agent": "Mozilla/5.0" } }, 6000);
    const j   = await r.json();
    const quotes = j?.finance?.result?.[0]?.quotes || [];
    const items  = quotes.map(q => ({
      symbol: q.symbol,
      name:   q.shortName || q.longName || q.symbol,
      price:  q.regularMarketPrice?.raw ?? q.regularMarketPrice ?? 0,
      chgPct: q.regularMarketChangePercent?.raw ?? q.regularMarketChangePercent ?? 0,
    }));
    setCached(cacheKey, items);
    return res.json(items);
  } catch (e) {
    return res.json([]);
  }
});

// ============================================================
//  Public landing summary — live index, sectors, breadth, news
// ============================================================
// This endpoint exists so the reference-matched landing terminal can remain
// honest. Every displayed number is returned by a provider and the entire
// response is cached, rather than fabricating a polished marketing preview.
router.get("/market/landing-summary", async (_req, res) => {
  const cacheKey = "market:landing-summary";
  const cached = getCached(cacheKey, 5 * 60 * 1000);
  if (cached) return res.json(cached);

  const YH = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124 Safari/537.36",
    Accept: "application/json, text/plain, */*",
  };
  const symbols = [
    ["^GSPC", "S&P 500"],
    ["XLK", "Technology"],
    ["XLC", "Comm. Services"],
    ["XLI", "Industrials"],
    ["XLF", "Financials"],
    ["XLE", "Energy"],
    ["XLRE", "Real Estate"],
  ];

  async function loadChart(symbol, name) {
    const url = `https://query1.finance.yahoo.com/v8/finance/chart/${encodeURIComponent(symbol)}?interval=1d&range=1mo&includePrePost=false`;
    const response = await fetchWithTimeout(url, { headers: YH }, 5000);
    if (!response.ok) throw new Error(`${symbol} returned ${response.status}`);
    const payload = await response.json();
    const result = payload?.chart?.result?.[0];
    const meta = result?.meta || {};
    const closes = (result?.indicators?.quote?.[0]?.close || []).filter(Number.isFinite);
    const price = Number(meta.regularMarketPrice ?? closes.at(-1));
    const previousClose = Number(meta.previousClose ?? meta.chartPreviousClose ?? closes.at(-2));
    if (!(price > 0)) throw new Error(`${symbol} did not return a price`);
    const changePct = previousClose > 0 ? ((price - previousClose) / previousClose) * 100 : null;
    return { symbol, name, price, changePct, closes: closes.slice(-22) };
  }

  const started = Date.now();
  const settled = await Promise.allSettled(symbols.map(([symbol, name]) => loadChart(symbol, name)));
  const quotes = settled.filter(item => item.status === "fulfilled").map(item => item.value);
  const overview = quotes.find(item => item.symbol === "^GSPC") || null;
  const sectors = quotes.filter(item => item.symbol !== "^GSPC");
  const measured = sectors.filter(item => Number.isFinite(item.changePct));
  const advancing = measured.filter(item => item.changePct >= 0).length;
  const breadth = measured.length ? Math.round((advancing / measured.length) * 100) : null;

  let news = [];
  if (FINNHUB_KEY) {
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
    overview,
    sectors,
    breadth,
    advancing,
    measured: measured.length,
    news,
    asOf: new Date().toISOString(),
    source: "Yahoo Finance charts" + (news.length ? " + Finnhub general news" : ""),
    synthetic: false,
  };
  setCached(cacheKey, result);
  recordProvider("Yahoo Finance", Boolean(overview), Date.now() - started, `${quotes.length}/${symbols.length} landing symbols`);
  return res.json(result);
});

module.exports = router;

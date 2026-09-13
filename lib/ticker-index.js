"use strict";

// ============================================================
//  Ticker index — the spine of company-name search
// ============================================================
// A visitor who knows the company but not the symbol had no way in: every
// search box on the site took a symbol and nothing else. Typing "apple" got
// you an error.
//
// The lookup has to be instant (it runs on every keystroke) and it must not
// spend a vendor call per keystroke, so the index lives in memory:
//
//   1. SEED below — a curated list, committed, so search works on a cold boot,
//      in tests, and if the network is unavailable. Its names are the ones a
//      person recognises ("Alphabet Inc.", not "ALPHABET INC").
//   2. SEC company_tickers.json — every registrant with a listed ticker,
//      fetched once at boot and refreshed daily. Free, no key, no rate limit,
//      and we already identify ourselves to EDGAR elsewhere. Seed names win on
//      collision; SEC fills in the several thousand companies the seed misses.
//   3. Anything still unmatched (new listings, most ETFs) falls through to the
//      Finnhub search endpoint in routes/search.js — one call, cached.
//
// Nothing here throws on a failed refresh. A stale index is a working search.

const SEED = [
  ["AAPL",  "Apple Inc."],
  ["MSFT",  "Microsoft Corporation"],
  ["NVDA",  "NVIDIA Corporation"],
  ["AMZN",  "Amazon.com, Inc."],
  ["GOOGL", "Alphabet Inc."],
  ["GOOG",  "Alphabet Inc."],
  ["META",  "Meta Platforms, Inc."],
  ["TSLA",  "Tesla, Inc."],
  ["BRK.B", "Berkshire Hathaway Inc."],
  ["BRK.A", "Berkshire Hathaway Inc."],
  ["JPM",   "JPMorgan Chase & Co."],
  ["V",     "Visa Inc."],
  ["MA",    "Mastercard Incorporated"],
  ["AVGO",  "Broadcom Inc."],
  ["LLY",   "Eli Lilly and Company"],
  ["WMT",   "Walmart Inc."],
  ["XOM",   "Exxon Mobil Corporation"],
  ["UNH",   "UnitedHealth Group Incorporated"],
  ["COST",  "Costco Wholesale Corporation"],
  ["ORCL",  "Oracle Corporation"],
  ["HD",    "The Home Depot, Inc."],
  ["PG",    "The Procter & Gamble Company"],
  ["NFLX",  "Netflix, Inc."],
  ["JNJ",   "Johnson & Johnson"],
  ["ABBV",  "AbbVie Inc."],
  ["BAC",   "Bank of America Corporation"],
  ["KO",    "The Coca-Cola Company"],
  ["CRM",   "Salesforce, Inc."],
  ["AMD",   "Advanced Micro Devices, Inc."],
  ["CVX",   "Chevron Corporation"],
  ["MRK",   "Merck & Co., Inc."],
  ["PEP",   "PepsiCo, Inc."],
  ["TMO",   "Thermo Fisher Scientific Inc."],
  ["ADBE",  "Adobe Inc."],
  ["CSCO",  "Cisco Systems, Inc."],
  ["MCD",   "McDonald's Corporation"],
  ["ACN",   "Accenture plc"],
  ["IBM",   "International Business Machines Corporation"],
  ["GE",    "GE Aerospace"],
  ["CAT",   "Caterpillar Inc."],
  ["QCOM",  "QUALCOMM Incorporated"],
  ["NOW",   "ServiceNow, Inc."],
  ["INTU",  "Intuit Inc."],
  ["TXN",   "Texas Instruments Incorporated"],
  ["AMAT",  "Applied Materials, Inc."],
  ["DIS",   "The Walt Disney Company"],
  ["NKE",   "NIKE, Inc."],
  ["UBER",  "Uber Technologies, Inc."],
  ["PLTR",  "Palantir Technologies Inc."],
  ["SHOP",  "Shopify Inc."],
  ["XYZ",   "Block, Inc."],
  ["SQ",    "Block, Inc."],
  ["PYPL",  "PayPal Holdings, Inc."],
  ["COIN",  "Coinbase Global, Inc."],
  ["ROKU",  "Roku, Inc."],
  ["SNAP",  "Snap Inc."],
  ["BA",    "The Boeing Company"],
  ["GS",    "The Goldman Sachs Group, Inc."],
  ["MS",    "Morgan Stanley"],
  ["C",     "Citigroup Inc."],
  ["BLK",   "BlackRock, Inc."],
  ["SCHW",  "The Charles Schwab Corporation"],
  ["SOFI",  "SoFi Technologies, Inc."],
  ["RIVN",  "Rivian Automotive, Inc."],
  ["LCID",  "Lucid Group, Inc."],
  ["F",     "Ford Motor Company"],
  ["GM",    "General Motors Company"],
  ["TM",    "Toyota Motor Corporation"],
  ["NVO",   "Novo Nordisk A/S"],
  ["PFE",   "Pfizer Inc."],
  ["BMY",   "Bristol-Myers Squibb Company"],
  ["GILD",  "Gilead Sciences, Inc."],
  ["ISRG",  "Intuitive Surgical, Inc."],
  ["ABT",   "Abbott Laboratories"],
  ["DHR",   "Danaher Corporation"],
  ["LOW",   "Lowe's Companies, Inc."],
  ["TGT",   "Target Corporation"],
  ["SBUX",  "Starbucks Corporation"],
  ["CMG",   "Chipotle Mexican Grill, Inc."],
  ["DE",    "Deere & Company"],
  ["LMT",   "Lockheed Martin Corporation"],
  ["RTX",   "RTX Corporation"],
  ["NOC",   "Northrop Grumman Corporation"],
  ["UPS",   "United Parcel Service, Inc."],
  ["FDX",   "FedEx Corporation"],
  ["INTC",  "Intel Corporation"],
  ["MU",    "Micron Technology, Inc."],
  ["ARM",   "Arm Holdings plc"],
  ["SMCI",  "Super Micro Computer, Inc."],
  ["MSTR",  "MicroStrategy Incorporated"],
  ["HOOD",  "Robinhood Markets, Inc."],
  ["ABNB",  "Airbnb, Inc."],
  ["DASH",  "DoorDash, Inc."],
  ["SNOW",  "Snowflake Inc."],
  ["CRWD",  "CrowdStrike Holdings, Inc."],
  ["PANW",  "Palo Alto Networks, Inc."],
  ["NET",   "Cloudflare, Inc."],
  ["DDOG",  "Datadog, Inc."],
  ["MDB",   "MongoDB, Inc."],
  ["ZS",    "Zscaler, Inc."],
  ["TTD",   "The Trade Desk, Inc."],
  ["SPOT",  "Spotify Technology S.A."],
  ["LYFT",  "Lyft, Inc."],
  ["PINS",  "Pinterest, Inc."],
  ["RBLX",  "Roblox Corporation"],
  ["ZM",    "Zoom Communications Inc."],
  ["OKTA",  "Okta, Inc."],
  ["TEAM",  "Atlassian Corporation"],
  ["WDAY",  "Workday, Inc."],
  ["ADSK",  "Autodesk, Inc."],
  ["ANET",  "Arista Networks, Inc."],
  ["DELL",  "Dell Technologies Inc."],
  ["ON",    "ON Semiconductor Corporation"],
  ["LRCX",  "Lam Research Corporation"],
  ["KLAC",  "KLA Corporation"],
  ["ADI",   "Analog Devices, Inc."],
  ["NXPI",  "NXP Semiconductors N.V."],
  ["MRVL",  "Marvell Technology, Inc."],
  ["ASML",  "ASML Holding N.V."],
  ["TSM",   "Taiwan Semiconductor Manufacturing Company Limited"],
  ["BABA",  "Alibaba Group Holding Limited"],
  ["PDD",   "PDD Holdings Inc."],
  ["NIO",   "NIO Inc."],
  ["SE",    "Sea Limited"],
  ["MELI",  "MercadoLibre, Inc."],
  ["WBD",   "Warner Bros. Discovery, Inc."],
  ["CMCSA", "Comcast Corporation"],
  ["T",     "AT&T Inc."],
  ["VZ",    "Verizon Communications Inc."],
  ["TMUS",  "T-Mobile US, Inc."],
  ["CVS",   "CVS Health Corporation"],
  ["ELV",   "Elevance Health, Inc."],
  ["ZTS",   "Zoetis Inc."],
  ["VRTX",  "Vertex Pharmaceuticals Incorporated"],
  ["REGN",  "Regeneron Pharmaceuticals, Inc."],
  ["AMGN",  "Amgen Inc."],
  ["BIIB",  "Biogen Inc."],
  ["MRNA",  "Moderna, Inc."],
  ["SPY",   "SPDR S&P 500 ETF Trust"],
  ["QQQ",   "Invesco QQQ Trust"],
  ["DIA",   "SPDR Dow Jones Industrial Average ETF Trust"],
  ["IWM",   "iShares Russell 2000 ETF"],
  ["VTI",   "Vanguard Total Stock Market ETF"],
  ["VOO",   "Vanguard S&P 500 ETF"],
  ["ARKK",  "ARK Innovation ETF"],
  ["GLD",   "SPDR Gold Shares"],
  ["SLV",   "iShares Silver Trust"],
  ["TLT",   "iShares 20+ Year Treasury Bond ETF"],
  ["HYG",   "iShares iBoxx $ High Yield Corporate Bond ETF"],
  ["USO",   "United States Oil Fund, LP"],
  ["SMH",   "VanEck Semiconductor ETF"],
  ["XLK",   "Technology Select Sector SPDR Fund"],
  ["XLF",   "Financial Select Sector SPDR Fund"],
  ["XLE",   "Energy Select Sector SPDR Fund"],
  ["XLV",   "Health Care Select Sector SPDR Fund"],
  ["XLY",   "Consumer Discretionary Select Sector SPDR Fund"],
  ["XLP",   "Consumer Staples Select Sector SPDR Fund"],
  ["XLI",   "Industrial Select Sector SPDR Fund"],
  ["XLU",   "Utilities Select Sector SPDR Fund"],
];

const SEC_URL = "https://www.sec.gov/files/company_tickers.json";
const REFRESH_MS = 24 * 60 * 60 * 1000;

const seedNames = new Map(SEED.map(([symbol, name]) => [symbol, name]));
let index = SEED.map(([symbol, name], rank) => ({ symbol, name, seed: true, rank }));
let bySymbol = new Map(index.map(entry => [entry.symbol, entry]));
let lastRefresh = 0;
let refreshing = null;

/** Uppercase, strip the punctuation a person types but a symbol never has. */
function normalizeQuery(value) {
  return String(value == null ? "" : value).trim().replace(/\s+/g, " ").toUpperCase().slice(0, 48);
}

// Scored lowest-first. The order encodes what a person means when they type
// three characters: they almost always mean a symbol that starts that way,
// and only then a company whose name does.
function score(entry, q) {
  const symbol = entry.symbol;
  const name = entry.name.toUpperCase();
  if (symbol === q) return 0;
  if (symbol.startsWith(q)) return 1;
  if (name.startsWith(q)) return 2;
  // "MOTORS" should find Ford Motor Company, so match on word starts too.
  if (name.includes(" " + q) || name.includes("(" + q)) return 3;
  if (name.includes(q)) return 4;
  if (symbol.includes(q)) return 5;
  return Infinity;
}

/**
 * Rank the index against a query. Returns [{symbol, name}], best first.
 * Ties break on SEED order, which is roughly "how often is this searched" —
 * so a bare "A" offers Apple before Abbott, rather than whichever symbol
 * happened to be shortest.
 */
function search(query, limit = 8) {
  const q = normalizeQuery(query);
  if (!q) return [];
  const hits = [];
  for (const entry of index) {
    const s = score(entry, q);
    if (s !== Infinity) hits.push({ entry, s });
  }
  hits.sort((a, b) =>
    a.s - b.s ||
    a.entry.rank - b.entry.rank ||
    a.entry.symbol.length - b.entry.symbol.length ||
    (a.entry.symbol < b.entry.symbol ? -1 : a.entry.symbol > b.entry.symbol ? 1 : 0)
  );
  return hits.slice(0, Math.max(1, Math.min(25, limit))).map(hit => ({
    symbol: hit.entry.symbol,
    name: hit.entry.name,
  }));
}

/** The name we know for a symbol, or "" — used to label a raw-symbol result. */
function nameFor(symbol) {
  const entry = bySymbol.get(normalizeQuery(symbol));
  return entry ? entry.name : "";
}

function size() { return index.length; }
function refreshedAt() { return lastRefresh ? new Date(lastRefresh).toISOString() : null; }

/**
 * Replace the index with SEED + the SEC registrant list. Safe to call at any
 * time: on any failure the current index is left exactly as it was.
 */
async function refreshFromSec(options = {}) {
  const fetchImpl = options.fetch || globalThis.fetch;
  const userAgent = options.userAgent || process.env.SEC_USER_AGENT || "ImpliedLens/1.2 support@impliedlens.com";
  const timeoutMs = options.timeoutMs || 10000;
  if (typeof fetchImpl !== "function") return false;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetchImpl(SEC_URL, {
      headers: { "User-Agent": userAgent, "Accept-Encoding": "gzip, deflate" },
      signal: controller.signal,
    });
    if (!response || !response.ok) return false;
    const payload = await response.json();
    const rows = Array.isArray(payload) ? payload : Object.values(payload || {});
    if (!rows.length) return false;

    const next = new Map();
    SEED.forEach(([symbol, name], rank) => next.set(symbol, { symbol, name, seed: true, rank }));
    for (const row of rows) {
      const symbol = normalizeQuery(row && (row.ticker || row.symbol));
      const title = String((row && (row.title || row.name)) || "").trim();
      if (!symbol || !title || !/^[A-Z][A-Z0-9.\-]{0,9}$/.test(symbol)) continue;
      if (next.has(symbol)) continue;                 // the curated name wins
      next.set(symbol, { symbol, name: prettifyName(title), seed: false, rank: Infinity });
    }
    index = [...next.values()];
    bySymbol = next;
    lastRefresh = Date.now();
    return true;
  } catch {
    return false;
  } finally {
    clearTimeout(timer);
  }
}

// EDGAR titles are inconsistently cased — "Apple Inc.", "TESLA, INC.",
// "NVIDIA CORP". Shouting one row next to a normal one in the same dropdown
// looks broken, so title-case anything that is all caps and leave the rest
// alone. Known initialisms stay upright.
const UPPER_WORDS = new Set(["I", "II", "III", "IV", "V", "VI", "USA", "US", "UK", "PLC", "NV", "SA", "AG", "LP", "LLC", "REIT", "ETF", "AI", "3D", "PNC", "ADR"]);
const LOWER_WORDS = new Set(["and", "of", "the", "for", "de", "da"]);
function prettifyName(title) {
  if (!/[a-z]/.test(title)) {
    return title.toLowerCase().replace(/[A-Za-z0-9']+/g, (word, offset) => {
      const upper = word.toUpperCase();
      if (UPPER_WORDS.has(upper)) return upper;
      if (offset > 0 && LOWER_WORDS.has(word)) return word;
      return word.charAt(0).toUpperCase() + word.slice(1);
    });
  }
  return title;
}

/**
 * Called once from server.js. Kicks off a refresh now and every 24h, and never
 * lets either one reject into the boot path.
 */
function startBackgroundRefresh(options = {}) {
  const run = () => {
    if (refreshing) return refreshing;
    refreshing = refreshFromSec(options).finally(() => { refreshing = null; });
    return refreshing;
  };
  const timer = setInterval(run, REFRESH_MS);
  if (typeof timer.unref === "function") timer.unref();
  return run();
}

module.exports = {
  SEED,
  SEC_URL,
  REFRESH_MS,
  normalizeQuery,
  search,
  nameFor,
  size,
  refreshedAt,
  refreshFromSec,
  startBackgroundRefresh,
  prettifyName,
  _seedNames: seedNames,
};

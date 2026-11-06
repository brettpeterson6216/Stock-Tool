"use strict";

const express = require("express");
const { checkAnalysisLimit, normalizeTicker } = require("../lib/plan");
const { buildResearchBundle, loadCompanyFacts } = require("../lib/stock-research");
const LensScoreEngine = require("../lib/lens-score-engine");
const LensFactors = require("../lib/lens-factors");
const peers = require("../lib/peer-universe");
const { buildQuarterlyHistory } = require("../lib/fundamentals-history");

const router = express.Router();
const responseCache = new Map();
const inFlight = new Map();
const RESPONSE_TTL_MS = 10 * 60 * 1000;
const RESPONSE_CACHE_LIMIT = 100;
// Last good payload per ticker. If a provider blips, we serve this (real,
// dated data, flagged as stale) instead of a hard error.
const lastGood = new Map();
const LAST_GOOD_TTL_MS = 12 * 60 * 60 * 1000;
// While US markets trade, a score's price should be minutes old, not ten.
const MARKET_HOURS_TTL_MS = 2 * 60 * 1000;
function usMarketOpen(now = new Date()) {
  const parts = Object.fromEntries(new Intl.DateTimeFormat("en-US", {
    timeZone: "America/New_York", weekday: "short", hour: "numeric", minute: "numeric", hour12: false,
  }).formatToParts(now).map(p => [p.type, p.value]));
  if (parts.weekday === "Sat" || parts.weekday === "Sun") return false;
  const mins = (Number(parts.hour) % 24) * 60 + Number(parts.minute);
  return mins >= 9 * 60 + 30 && mins < 16 * 60 + 5;
}

function cachedPayload(ticker) {
  const entry = responseCache.get(ticker);
  if (!entry || Date.now() > entry.expiresAt) {
    if (entry) responseCache.delete(ticker);
    return null;
  }
  return entry.payload;
}

function storePayload(ticker, payload) {
  if (responseCache.size >= RESPONSE_CACHE_LIMIT) {
    responseCache.delete(responseCache.keys().next().value);
  }
  const complete = (payload.provenance?.sources || []).every(source => source.status === "available")
    && payload.grades?.status === "graded";
  const ttlMs = complete ? (usMarketOpen() ? MARKET_HOURS_TTL_MS : RESPONSE_TTL_MS) : 15 * 1000;
  responseCache.set(ticker, { expiresAt: Date.now() + ttlMs, payload });
  if (payload?.score?.status === "graded") {
    if (lastGood.size >= RESPONSE_CACHE_LIMIT && !lastGood.has(ticker)) lastGood.delete(lastGood.keys().next().value);
    lastGood.set(ticker, { at: Date.now(), payload });
  }
  return payload;
}

/* Grades come from SEC filings (lib/sec-universe.js) and licensed prices;
   the next earnings date is estimated from the company's past results
   filings. Analyst ratings and estimates need a licensed feed the site does
   not have, so the report card does not show them. */
const secUniverse = require("../lib/sec-universe");
const industryGroups = require("../lib/industry-groups");
const secFilings = require("../lib/sec-filings");
const prices = require("../lib/prices");
function streetView(co) {
  const next = secFilings.estimateNextEarnings(co.filings || []);
  return next ? { nextEarnings: next } : null;
}

async function gradeTicker(ticker, research) {
  await peers.load();
  const rows = (research.market?.bars || []).map(b => ({ day: new Date(b.time * 1000).toISOString().slice(0, 10), close: b.close, high: b.high, low: b.low }));
  let facts = null;
  try { facts = (await loadCompanyFacts(ticker))?.facts || null; } catch (_) { /* fetched below if needed */ }
  const co = await secUniverse.forTicker(ticker, { rows, facts });
  if (!co.sector) {
    return { status: "not-rated", version: LensFactors.VERSION, reason: "This company's SEC industry code does not map to a sector we grade." };
  }
  const graded = LensFactors.gradeCompany({
    ticker,
    name: co.name || research.company || ticker,
    sector: co.sector,
    group: industryGroups.groupFor(co.sic, co.sector),
    metric: co.metric,
    price: co.price,
    marketCap: Number(co.metric.marketCapitalization) > 0 ? co.metric.marketCapitalization * 1e6 : null,
  }, peers.all());
  graded.industry = co.industry || null;
  graded.street = streetView(co);
  graded.secOverrides = [];
  graded.source = `SEC filings for every company, ranked within its industry or sector; prices from ${prices.sourceLabel()}.`;
  graded.asOf = new Date().toISOString();
  return graded;
}

async function calculatePayload(ticker) {
  const research = await buildResearchBundle(ticker, { range: "5y", interval: "1d" });
  const score = LensScoreEngine.scoreLens({
    bars: research.market.bars,
    fundamentals: research.fundamentals.values,
    metadata: {
      ticker,
      company: research.company,
      source: research.provenance.sources
        .filter(source => source.status === "available")
        .map(source => source.name)
        .join(" + "),
      marketAsOf: research.provenance.asOf.market,
      fundamentalsAsOf: research.provenance.asOf.fundamentals,
      synthetic: false,
    },
  });
  const grades = await gradeTicker(ticker, research).catch(error => ({
    status: "not-rated", version: LensFactors.VERSION, reason: `Peer grading failed: ${String(error?.message || error).slice(0, 160)}`,
  }));
  return {
    schemaVersion: research.schemaVersion,
    ticker,
    company: research.company,
    grades,
    score,
    market: research.market,
    fundamentals: research.fundamentals,
    earnings: research.earnings,
    provenance: research.provenance,
  };
}

async function getPayload(ticker) {
  const cached = cachedPayload(ticker);
  if (cached) return { payload: cached, cacheStatus: "HIT" };
  if (inFlight.has(ticker)) {
    return { payload: await inFlight.get(ticker), cacheStatus: "COALESCED" };
  }
  const pending = calculatePayload(ticker)
    .then(payload => storePayload(ticker, payload))
    .finally(() => inFlight.delete(ticker));
  inFlight.set(ticker, pending);
  return { payload: await pending, cacheStatus: "MISS" };
}

function compactPayload(payload) {
  return {
    schemaVersion: payload.schemaVersion,
    ticker: payload.ticker,
    company: payload.company,
    market: {
      ticker: payload.market?.ticker || payload.ticker,
      meta: payload.market?.meta || {},
      bars: (payload.market?.bars || []).map(bar => [
        bar.time,
        bar.open,
        bar.high,
        bar.low,
        bar.close,
        bar.volume,
      ]),
    },
    fundamentals: payload.fundamentals,
    provenance: payload.provenance,
    grades: payload.grades || null,
  };
}

// The homepage demo card shows the score, its parts, the reasons and a
// one-year line. The full payload is ~770KB of JSON (5 years of bars,
// regime and timing series); this is a few KB.
function cardGrades(g) {
  if (g.status !== "graded") return { status: g.status, reason: g.reason || null };
  return {
    status: g.status, version: g.version, score: g.score, label: g.label, tone: g.tone, sectorName: g.sectorName,
    rank: g.rank, verdict: g.verdict, caps: g.caps,
    factors: g.factors.map(f => ({ key: f.key, label: f.label, grade: f.grade, percentile: f.percentile, tone: f.tone })),
    strengths: g.strengths.slice(0, 3), watch: g.watch.slice(0, 3),
    peers: (g.peers || []).filter(p => !p.self).slice(0, 3).map(p => p.ticker),
    street: g.street ? { ratings: null, earnings: null, nextEarnings: g.street.nextEarnings || null } : null,
  };
}

/* The past 52 weeks of closes with their dates, starting at the close on or
   before 52 weeks ago, so the card's "past year" is the same figure as the
   research page's (audit F04). */
function yearBars(bars) {
  const list = (bars || []).filter(b => b && Number.isFinite(Number(b.close)) && Number.isFinite(Number(b.time)));
  if (!list.length) return [];
  const last = Number(list.at(-1).time), unit = last > 1e12 ? 1000 : 1;
  const from = last - 364 * 86400 * unit;
  let at = 0;
  for (let i = list.length - 1; i >= 0; i--) if (Number(list[i].time) <= from) { at = i; break; }
  return list.slice(at).map(b => ({ time: Number(b.time), close: Number(b.close) }));
}

function cardPayload(payload) {
  const score = payload.score || {};
  const tech = score.technical || {};
  const { timing, trendRegime, zones, bars, ...techRest } = tech;
  return {
    schemaVersion: payload.schemaVersion,
    ticker: payload.ticker,
    company: payload.company,
    score: { ...score, technical: { ...techRest, bars: yearBars(bars) } },
    timing: timing && Number.isFinite(Number(timing.timingScore)) ? { score: Number(timing.timingScore), key: timing.key || null } : null,
    buyZone: zones?.support?.[0] ? { lower: zones.support[0].lower, upper: zones.support[0].upper } : null,
    grades: payload.grades ? cardGrades(payload.grades) : null,
    provenance: { asOf: payload.provenance?.asOf, retrievedAt: payload.provenance?.retrievedAt },
  };
}

router.get("/lens-score/:ticker", checkAnalysisLimit, async (req, res) => {
  const ticker = normalizeTicker(req.params.ticker);
  if (!ticker) return res.status(400).json({ error: "Invalid ticker." });

  res.setHeader("Cache-Control", "private, max-age=30, stale-while-revalidate=120");
  try {
    const { payload, cacheStatus } = await getPayload(ticker);
    res.setHeader("X-LensScore-Cache", cacheStatus);
    res.setHeader("X-Data-Retrieved-At", payload.provenance.retrievedAt);
    res.setHeader("X-Market-As-Of", payload.provenance.asOf.market || "");
    res.setHeader("X-Fundamentals-As-Of", payload.provenance.asOf.fundamentals || "");
    if (req.query.card === "1") {
      res.setHeader("X-LensScore-Mode", "card");
      return res.json(cardPayload(payload));
    }
    if (req.query.compact === "1") {
      res.setHeader("X-LensScore-Mode", "compact");
      return res.json(compactPayload(payload));
    }
    return res.json(payload);
  } catch (error) {
    const message = String(error?.message || "Research data unavailable.").slice(0, 240);
    console.error(`[lens-score] ${ticker}:`, message);
    const good = lastGood.get(ticker);
    if (good && Date.now() - good.at < LAST_GOOD_TTL_MS && !/invalid ticker/i.test(message)) {
      res.setHeader("X-LensScore-Cache", "STALE");
      const stale = { ...good.payload, servedStale: true, staleReason: message };
      if (req.query.card === "1") return res.json({ ...cardPayload(good.payload), servedStale: true });
      return res.json(req.query.compact === "1" ? { ...compactPayload(good.payload), servedStale: true } : stale);
    }
    return res.status(/invalid ticker/i.test(message) ? 400 : 503).json({
      ticker,
      status: "not-rated",
      score: null,
      synthetic: false,
      error: message,
      reason: "LensScore does not substitute synthetic market or company data.",
    });
  }
});

/* Score history for one company (one point per trading day since history
   began) and the leaderboard: top-rated overall and per sector, biggest
   score changes over about a week, and the running track record. */
const LensHistory = require("../lib/lens-history");
router.get("/lens-history/:ticker", async (req, res) => {
  const ticker = normalizeTicker(req.params.ticker);
  if (!ticker) return res.status(400).json({ error: "Invalid ticker." });
  try {
    res.setHeader("Cache-Control", "private, max-age=300");
    res.json({ ticker, points: await LensHistory.historyFor(ticker) });
  } catch (error) {
    res.status(503).json({ error: "Score history is unavailable right now." });
  }
});
/* Everything about how the LensScore is made, for /methodology: every
   metric and weight, the caps, the peer rules, the universe, the data
   sources, the live test results and the change log. Read from the code that
   grades, so the page cannot drift from what the grades actually do. */
const LensBacktest = require("../lib/lens-backtest");
const universeMembers = require("../lib/universe-members");
const METHOD_LOG = [
  { date: "2026-11-06", version: "3.0.0", change: "Fixed universe of about 1,000 of the largest US-listed companies by public float, rebuilt weekly from SEC data; stocks people open are graded against it but no longer join it. Industry peer groups (when at least 15 are graded) before sector. Forward P/E removed (SEC filings carry no estimates). Free cash flow and EV/EBITDA weigh 1.5x in Value, PEG 0.75x. ROIC is now after-tax operating profit over debt plus equity minus cash. Beta left Financial health; banks and insurers are judged on equity to assets. Weekly point-in-time backtest published." },
  { date: "2026-10-20", version: "2.0.0", change: "Grades built from SEC filings and licensed prices for every company, replacing a personal-use data feed." },
];
router.get("/lens-method", async (_req, res) => {
  try {
    const bt = await LensBacktest.load().catch(() => null);
    const lb = await LensHistory.leaders().catch(() => null);
    res.setHeader("Cache-Control", "public, max-age=600");
    res.json({
      version: LensFactors.VERSION,
      weights: LensFactors.WEIGHTS,
      factors: LensFactors.FACTORS.map(f => ({ key: f.key, label: f.label, question: f.question,
        metrics: f.metrics.map(m => ({ key: m.k, label: m.label, better: m.dir > 0 ? "higher" : "lower", weight: m.w || 1, only: m.only || null, skip: m.skip || null, why: m.why })) })),
      caps: [
        "One failing grade (Value or Profitability under the 13th percentile, Health under the 20th, Growth or Momentum under the 27th) holds the score at 6.8 or below.",
        "Two failing grades hold it at 5.0 or below.",
        "Weak profits together with a weak balance sheet hold it at 4.0 or below.",
        "Negative shareholders' equity holds it at 4.5 or below.",
      ],
      peers: { minIndustry: industryGroups.MIN_INDUSTRY_PEERS, minSector: 8, groups: industryGroups.GROUPS.map(([key, label, sector]) => ({ key, label, sector: LensFactors.SECTOR_NAMES[sector] || sector })) },
      universe: { ...universeMembers.status(), graded: universeGrades.current().rows.length, target: universeMembers.SIZE },
      sources: [
        { name: "SEC EDGAR", use: "Every company figure: revenue, profit, cash flow, balance sheet, share count, industry code. Refreshed when a company files a 10-Q or 10-K, and at least every 30 days." },
        { name: prices.sourceLabel(), use: "Daily closes for prices, valuation ratios, momentum and the S&P 500 benchmark (SPY). Topped up every trading day." },
      ],
      backtest: bt,
      backtestStatus: LensBacktest.status(),
      liveRecord: lb && lb.trackRecord ? { since: lb.historyStarts, record: lb.trackRecord } : null,
      log: METHOD_LOG,
    });
  } catch (e) {
    res.status(503).json({ error: "Method details are unavailable right now." });
  }
});

/* Grades for a list of tickers (watchlists, the dashboard). Read from the
   graded peer universe, so it is cheap and does not count as an analysis.
   Companies outside the universe come back as null. */
const universeGrades = require("../lib/universe-grades");
router.get("/lens-grades", async (req, res) => {
  const tickers = [...new Set(String(req.query.tickers || "").split(",").map(t => normalizeTicker(t)).filter(Boolean))].slice(0, 60);
  if (!tickers.length) return res.status(400).json({ error: "Pass tickers=AAPL,MSFT." });
  try {
    const { since, changes } = await LensHistory.changesFor(tickers).catch(() => ({ since: null, changes: {} }));
    const out = {};
    tickers.forEach(t => {
      const g = universeGrades.get(t);
      out[t] = g ? { score: g.score, label: g.label, tone: g.score >= 8 ? "strong" : g.score >= 6.5 ? "positive" : g.score >= 4.5 ? "neutral" : g.score >= 3 ? "weak" : "severe", grades: g.grades, sectorName: g.sectorName,
        change: changes[t] ? changes[t].change : null } : null;
    });
    res.setHeader("Cache-Control", "private, max-age=120");
    res.json({ since, grades: out });
  } catch (error) {
    res.status(503).json({ error: "Grades are unavailable right now." });
  }
});

let leadersCache = { at: 0, body: null };
router.get("/lens-leaders", async (_req, res) => {
  try {
    if (!leadersCache.body || Date.now() - leadersCache.at > 5 * 60 * 1000) {
      const body = await LensHistory.leaders();
      if (body.universe >= 20) leadersCache = { at: Date.now(), body };
      else return res.status(503).json({ error: "Grades are still loading. Try again in a few minutes.", universe: body.universe });
    }
    res.setHeader("Cache-Control", "public, max-age=120");
    res.json(leadersCache.body);
  } catch (error) {
    res.status(503).json({ error: "The leaderboard is unavailable right now." });
  }
});

// Popular tickers are scored in the background so the homepage demo and the
// LensToolkit open instantly instead of computing five years of research on
// the visitor's click. Started by server.js only (never in tests); timers are
// unref'd so they never hold the process open.
const WARM_TICKERS = ["AAPL", "NVDA", "MSFT", "TSLA", "AMZN", "META", "GOOGL"];
function startWarmup({ firstDelayMs = 20 * 1000, everyMs = 9 * 60 * 1000 } = {}) {
  let running = false;
  async function warm() {
    if (running) return;
    running = true;
    for (const ticker of WARM_TICKERS) {
      try { await getPayload(ticker); } catch (error) {
        console.warn(`[lens-score] warm-up ${ticker}:`, String(error?.message || error).slice(0, 160));
      }
    }
    running = false;
  }
  setTimeout(warm, firstDelayMs).unref?.();
  setInterval(warm, everyMs).unref?.();
}

module.exports = router;
module.exports.usMarketOpen = usMarketOpen;
module.exports.cardPayload = cardPayload;
module.exports.startWarmup = startWarmup;

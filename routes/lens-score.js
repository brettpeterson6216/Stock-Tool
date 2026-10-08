"use strict";

const express = require("express");
const { checkAnalysisLimit, normalizeTicker } = require("../lib/plan");
const { buildResearchBundle, loadFinnhubResearch, loadCompanyFacts } = require("../lib/stock-research");
const LensScoreEngine = require("../lib/lens-score-engine");
const LensFactors = require("../lib/lens-factors");
const peers = require("../lib/peer-universe");
const { buildQuarterlyHistory } = require("../lib/fundamentals-history");
const { finnhubJson } = require("../lib/finnhub-gate");
const { FINNHUB_KEY } = require("../lib/config");

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

/* Latest-quarter and TTM revenue growth from the company's own SEC filings.
   Finnhub's growth uses its own revenue definition, which is badly off for
   some companies (lenders especially); peers still use Finnhub so the
   comparison stays like-for-like everywhere else. */
function secGrowth(facts) {
  try {
    const q = buildQuarterlyHistory(facts, { maxQuarters: 9 });
    const last = q.at(-1);
    if (!last || Date.now() - Date.parse(last.end) > 200 * 86400000) return {};
    const out = {};
    const yearAgo = q.length >= 5 ? q.at(-5) : null;
    const gap = yearAgo ? (Date.parse(last.end) - Date.parse(yearAgo.end)) / 86400000 : 0;
    if (yearAgo && gap > 330 && gap < 400 && last.revenue > 0 && yearAgo.revenue > 0) out.revenueGrowthQuarterlyYoy = (last.revenue / yearAgo.revenue - 1) * 100;
    if (q.length >= 8) {
      const sum = a => a.reduce((s, r) => s + (r.revenue || 0), 0);
      const cur = sum(q.slice(-4)), prev = sum(q.slice(-8, -4));
      if (q.slice(-8).every(r => r.revenue > 0) && prev > 0) out.revenueGrowthTTMYoy = (cur / prev - 1) * 100;
    }
    return out;
  } catch (_) { return {}; }
}

async function gradeTicker(ticker, research) {
  await peers.load();
  const [fh, company] = await Promise.all([
    loadFinnhubResearch(ticker).catch(() => null),
    loadCompanyFacts(ticker).catch(() => null),
  ]);
  const price = research.market?.bars?.at(-1)?.close ?? null;
  /* The research bundle's Finnhub calls can come back empty when the shared
     quota is busy (and that empty answer is cached for minutes). Ask again
     directly at interactive priority, then fall back to the peer row. */
  let profile = fh?.profile || null;
  let fhMetric = fh?.metrics || null;
  if (!profile || !fhMetric) {
    const base = "https://finnhub.io/api/v1/stock";
    const [p2, m2] = await Promise.all([
      profile ? null : finnhubJson(`${base}/profile2?symbol=${encodeURIComponent(ticker)}&token=${FINNHUB_KEY}`, { priority: "high", timeoutMs: 6000 }),
      fhMetric ? null : finnhubJson(`${base}/metric?symbol=${encodeURIComponent(ticker)}&metric=all&token=${FINNHUB_KEY}`, { priority: "high", timeoutMs: 6000 }),
    ]);
    if (!profile && p2 && p2.name) profile = p2;
    if (!fhMetric && m2 && m2.metric) fhMetric = m2.metric;
  }
  const known = peers.get(ticker);
  const metric = { ...(fhMetric || known?.m || {}) };
  const overrides = company?.facts ? secGrowth(company.facts) : {};
  Object.assign(metric, overrides);
  if (profile || fhMetric) peers.put(ticker, { profile, metric: fhMetric, price });
  const sector = peers.sectorFor(ticker, profile?.finnhubIndustry) || known?.s || null;
  const graded = LensFactors.gradeCompany({
    ticker,
    name: profile?.name || known?.n || research.company || ticker,
    sector,
    metric,
    price,
    marketCap: Number(profile?.marketCapitalization) > 0 ? Number(profile.marketCapitalization) * 1e6 : known?.mc || null,
  }, peers.all());
  graded.industry = profile?.finnhubIndustry || known?.i || null;
  graded.secOverrides = Object.keys(overrides);
  graded.source = "Finnhub fundamentals and price returns for every company, ranked within sector; revenue growth from SEC filings where current.";
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
  };
}

function cardPayload(payload) {
  const score = payload.score || {};
  const tech = score.technical || {};
  const { timing, trendRegime, zones, bars, ...techRest } = tech;
  return {
    schemaVersion: payload.schemaVersion,
    ticker: payload.ticker,
    company: payload.company,
    score: { ...score, technical: { ...techRest, bars: (bars || []).slice(-252).map(bar => ({ close: bar.close })) } },
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

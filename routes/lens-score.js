"use strict";

const express = require("express");
const { checkAnalysisLimit, normalizeTicker } = require("../lib/plan");
const { buildResearchBundle } = require("../lib/stock-research");
const LensScoreEngine = require("../lib/lens-score-engine");

const router = express.Router();
const responseCache = new Map();
const inFlight = new Map();
const RESPONSE_TTL_MS = 2 * 60 * 1000;
const RESPONSE_CACHE_LIMIT = 100;
// Last good payload per ticker. If a provider blips, we serve this (real,
// dated data, flagged as stale) instead of a hard error.
const lastGood = new Map();
const LAST_GOOD_TTL_MS = 12 * 60 * 60 * 1000;

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
  const complete = (payload.provenance?.sources || []).every(source => source.status === "available");
  const ttlMs = complete ? RESPONSE_TTL_MS : 15 * 1000;
  responseCache.set(ticker, { expiresAt: Date.now() + ttlMs, payload });
  if (payload?.score?.status === "graded") {
    if (lastGood.size >= RESPONSE_CACHE_LIMIT && !lastGood.has(ticker)) lastGood.delete(lastGood.keys().next().value);
    lastGood.set(ticker, { at: Date.now(), payload });
  }
  return payload;
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
  return {
    schemaVersion: research.schemaVersion,
    ticker,
    company: research.company,
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

module.exports = router;

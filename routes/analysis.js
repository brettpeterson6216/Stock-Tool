"use strict";

/* ═══════════════════════════════════════════════════════════════════════════
   GET /api/analysis/:ticker?range=1y

   Computes the technical read server-side from the same OHLCV the chart draws,
   then optionally asks Claude to narrate those computed numbers.

   The model never receives raw price history and never computes anything — it
   receives the finished signal set and is constrained to describing it. If no
   API key is configured the deterministic prose is used instead, so the
   feature degrades to "slightly plainer wording", never to "unavailable".
   ═══════════════════════════════════════════════════════════════════════════ */

const express = require("express");
const router = express.Router();
const { analyze } = require("../lib/technical-analysis");

const CACHE = new Map();
const TTL_MS = 5 * 60 * 1000;
const MAX_CACHE = 400;

function cacheGet(key) {
  const hit = CACHE.get(key);
  if (!hit) return null;
  if (Date.now() - hit.at > TTL_MS) { CACHE.delete(key); return null; }
  return hit.value;
}

function cacheSet(key, value) {
  if (CACHE.size >= MAX_CACHE) CACHE.delete(CACHE.keys().next().value);
  CACHE.set(key, { at: Date.now(), value });
}

const VALID_RANGES = new Set(["1d", "5d", "1mo", "3mo", "6mo", "ytd", "1y", "2y", "5y", "10y", "max"]);
const AUTO_INTERVAL = {
  "1d": "5m", "5d": "30m", "1mo": "1d", "3mo": "1d", "6mo": "1d",
  "ytd": "1d", "1y": "1d", "2y": "1d", "5y": "1wk", "10y": "1wk", "max": "1mo"
};

const YH_HEADERS = {
  "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "Accept": "application/json, text/plain, */*",
  "Accept-Language": "en-US,en;q=0.9",
  "Origin": "https://finance.yahoo.com",
  "Referer": "https://finance.yahoo.com/"
};

async function fetchWithTimeout(url, ms = 6000) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), ms);
  try {
    return await fetch(url, { headers: YH_HEADERS, signal: ctrl.signal });
  } finally {
    clearTimeout(timer);
  }
}

async function loadSeries(ticker, range, interval) {
  const hosts = ["query2", "query1"];
  for (const host of hosts) {
    try {
      const url = `https://${host}.finance.yahoo.com/v8/finance/chart/${encodeURIComponent(ticker)}` +
        `?interval=${interval}&range=${range}&includePrePost=false`;
      const r = await fetchWithTimeout(url);
      if (!r.ok) continue;
      const j = await r.json();
      const res = j?.chart?.result?.[0];
      if (!res?.timestamp?.length) continue;
      const q = res.indicators?.quote?.[0] || {};
      const rows = res.timestamp
        .map((ts, i) => ({ ts, o: q.open?.[i], h: q.high?.[i], l: q.low?.[i], c: q.close?.[i], v: q.volume?.[i] }))
        .filter((row) => Number.isFinite(Number(row.c)));
      return {
        timestamp: rows.map((r2) => r2.ts),
        open: rows.map((r2) => Number(r2.o ?? r2.c)),
        high: rows.map((r2) => Number(r2.h ?? r2.c)),
        low: rows.map((r2) => Number(r2.l ?? r2.c)),
        close: rows.map((r2) => Number(r2.c)),
        volume: rows.map((r2) => Number(r2.v ?? 0)),
        meta: res.meta || {}
      };
    } catch (_) { /* try the next host */ }
  }
  return null;
}

/* ── Deterministic prose, used when no model is configured ───────────────── */
function deterministicSummary(a, symbol) {
  const by = {};
  a.signals.forEach((s) => { by[s.key] = s; });
  const out = [];

  if (by.trend) {
    out.push(`${symbol} is in a ${by.trend.state}. ${by.trend.detail.join(". ")}.`);
  }
  if (by.momentum && by.momentum.value) {
    out.push(`Momentum reads ${by.momentum.state} — ${by.momentum.value}. ${by.momentum.detail.join(" ")}.`);
  }
  if (by.levels && by.levels.detail.length) {
    out.push(by.levels.detail.join(". ") + ".");
  }
  if (by.volatility) {
    out.push(`Volatility is ${by.volatility.state} at ${by.volatility.value}. ${by.volatility.detail.join(". ")}.`);
  }
  if (a.invalidation) out.push(a.invalidation.text);
  return out.join(" ");
}

/* ── Claude narration ────────────────────────────────────────────────────── */
const SYSTEM_PROMPT = [
  "You write the technical read for ImpliedLens, a stock research workspace.",
  "",
  "You are given signals that have ALREADY been computed from price history. Your job is to",
  "describe what they say, in plain language, and nothing else.",
  "",
  "Hard rules:",
  "- Use only the numbers provided. Never introduce a figure that is not in the input.",
  "- Never predict a price, target, or direction. Never say buy, sell, hold, or rate the stock.",
  "- Describe what the evidence currently shows and name the level that would change it.",
  "- Say 'the chart shows' or 'price is', not 'the stock will'.",
  "- Prefer specifics over adjectives. 'RSI 61, firm but not stretched' beats 'strong momentum'.",
  "- If signals disagree, say so plainly. Disagreement is information, not a problem to resolve.",
  "- Calm and evidence-led. No hype, no emoji, no exclamation marks.",
  "",
  "Format: 2 to 4 short paragraphs, no headings, no bullet points, under 160 words total."
].join("\n");

async function narrate(analysis, symbol) {
  const key = process.env.ANTHROPIC_API_KEY;
  if (!key) return { text: deterministicSummary(analysis, symbol), source: "computed" };

  const payload = {
    symbol,
    asOf: analysis.asOf,
    barsAnalyzed: analysis.bars,
    timeframe: analysis.range,
    price: analysis.price,
    signals: analysis.signals.map((s) => ({
      area: s.label, state: s.state, headline: s.value, detail: s.detail
    })),
    levelThatWouldChangeThis: analysis.invalidation ? analysis.invalidation.level : null,
    computedFacts: analysis.facts
  };

  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 20000);
    const r = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-api-key": key,
        "anthropic-version": "2023-06-01"
      },
      body: JSON.stringify({
        model: process.env.ANTHROPIC_MODEL || "claude-sonnet-4-5",
        max_tokens: 500,
        system: SYSTEM_PROMPT,
        messages: [{
          role: "user",
          content: "Write the technical read for these computed signals:\n\n" +
                   JSON.stringify(payload, null, 2)
        }]
      }),
      signal: ctrl.signal
    });
    clearTimeout(timer);
    if (!r.ok) throw new Error("model responded " + r.status);
    const j = await r.json();
    const text = (j.content || []).map((b) => b.text || "").join("").trim();
    if (!text) throw new Error("empty completion");
    return { text, source: "model" };
  } catch (e) {
    // Never fail the request because narration failed.
    return { text: deterministicSummary(analysis, symbol), source: "computed", note: e.message };
  }
}

router.get("/analysis/:ticker", async (req, res) => {
  const ticker = String(req.params.ticker || "").toUpperCase().replace(/[^A-Z0-9.\-^=]/g, "").slice(0, 12);
  if (!ticker) return res.status(400).json({ error: "Invalid ticker." });

  const rawRange = String(req.query.range || "1y").toLowerCase();
  const range = VALID_RANGES.has(rawRange) ? rawRange : "1y";
  const interval = AUTO_INTERVAL[range] || "1d";
  const wantsProse = req.query.explain === "1";
  const cacheKey = `${ticker}:${range}:${wantsProse ? "prose" : "signals"}`;

  const cached = cacheGet(cacheKey);
  if (cached) return res.json({ ...cached, cached: true });

  try {
    const series = await loadSeries(ticker, range, interval);
    if (!series) {
      return res.status(404).json({ error: `No price history available for ${ticker}.` });
    }

    const analysis = analyze(series, { range, interval });
    if (!analysis.ok) return res.status(422).json({ error: analysis.reason });

    const body = {
      symbol: ticker,
      name: series.meta.longName || series.meta.shortName || ticker,
      ...analysis
    };

    if (wantsProse) {
      const n = await narrate(analysis, ticker);
      body.summary = n.text;
      body.summarySource = n.source;
    }

    cacheSet(cacheKey, body);
    res.json(body);
  } catch (e) {
    console.error("[analysis]", e.message);
    res.status(503).json({ error: "Technical analysis is unavailable right now." });
  }
});

module.exports = router;

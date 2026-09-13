// ============================================================
//  Ticker / company search
//    GET /api/search?q=&limit=      (free, no auth)
// ============================================================
// Every search box on the site used to accept a symbol and nothing else, so a
// visitor who knew the company but not its ticker had no way in. This answers
// both: it ranks the in-memory registrant index first (instant, no vendor
// call), and only reaches for Finnhub when the index cannot fill the list —
// new listings and most ETFs are not SEC registrants with tickers.
const express = require("express");

const { FINNHUB_KEY } = require("../lib/config");
const { recordProvider } = require("../lib/provider-health");
const tickerIndex = require("../lib/ticker-index");

const router = express.Router();

const CACHE_TTL_MS = 10 * 60 * 1000;
const MAX_CACHE_ENTRIES = 400;
const _cache = new Map();

function getCached(key) {
  const entry = _cache.get(key);
  if (!entry || Date.now() - entry.ts >= CACHE_TTL_MS) {
    if (entry) _cache.delete(key);
    return null;
  }
  return entry.data;
}

function setCached(key, data) {
  if (_cache.size >= MAX_CACHE_ENTRIES) {
    const oldest = _cache.keys().next().value;
    if (oldest) _cache.delete(oldest);
  }
  _cache.set(key, { data, ts: Date.now() });
}

// Finnhub returns every listing of a company worldwide for a US-exchange
// query — AAPL, AAPL.MX, AAPL.SW, APC.DE. A person searching here wants the
// US line. One optional class letter (BRK.B) is a US symbol; two or more
// characters after the dot is a foreign venue.
const US_SYMBOL = /^[A-Z][A-Z0-9-]{0,5}(\.[A-Z])?$/;
const TRADEABLE_TYPES = new Set(["Common Stock", "ADR", "ETP", "ETF", "REIT", "GDR", ""]);

function fromFinnhub(payload) {
  const rows = Array.isArray(payload && payload.result) ? payload.result : [];
  const out = [];
  for (const row of rows) {
    const symbol = String((row && (row.displaySymbol || row.symbol)) || "").trim().toUpperCase();
    const name = String((row && row.description) || "").trim();
    if (!symbol || !name || !US_SYMBOL.test(symbol)) continue;
    if (!TRADEABLE_TYPES.has(String((row && row.type) || "").trim())) continue;
    out.push({ symbol, name: tickerIndex.prettifyName(name) });
  }
  return out;
}

async function finnhubSearch(query, timeoutMs = 3500) {
  if (!FINNHUB_KEY) return [];
  const cacheKey = "fh:" + query;
  const cached = getCached(cacheKey);
  if (cached) return cached;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const url = `https://finnhub.io/api/v1/search?q=${encodeURIComponent(query)}&exchange=US&token=${FINNHUB_KEY}`;
    const response = await fetch(url, { signal: controller.signal });
    if (!response.ok) {
      recordProvider("finnhub", false);
      return [];
    }
    const results = fromFinnhub(await response.json());
    recordProvider("finnhub", true);
    setCached(cacheKey, results);
    return results;
  } catch {
    recordProvider("finnhub", false);
    return [];
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Index first, vendor second, deduped by symbol, never longer than `limit`.
 * Exported so the test can drive it without an HTTP server or a key.
 */
async function searchTickers(rawQuery, rawLimit, options = {}) {
  const query = tickerIndex.normalizeQuery(rawQuery);
  const limit = Math.max(1, Math.min(25, Number(rawLimit) || 8));
  if (!query) return { query: "", results: [], source: "index" };

  const local = tickerIndex.search(query, limit);
  // One character is a prefix, not a question — the index answers it well and
  // the vendor would return noise.
  if (local.length >= limit || query.length < 2) {
    return { query, results: local, source: "index" };
  }

  const remote = await (options.finnhubSearch || finnhubSearch)(query);
  if (!remote.length) return { query, results: local, source: "index" };

  const seen = new Set(local.map(hit => hit.symbol));
  const merged = local.slice();
  for (const hit of remote) {
    if (seen.has(hit.symbol)) continue;
    seen.add(hit.symbol);
    merged.push(hit);
    if (merged.length >= limit) break;
  }
  return { query, results: merged, source: local.length ? "mixed" : "finnhub" };
}

router.get("/search", async (req, res) => {
  try {
    const payload = await searchTickers(req.query.q, req.query.limit);
    // Suggestions age slowly and the same prefixes are typed all day.
    res.set("Cache-Control", "public, max-age=300");
    res.json(payload);
  } catch (error) {
    res.status(500).json({ error: "Search is unavailable.", results: [] });
  }
});

module.exports = router;
module.exports.searchTickers = searchTickers;
module.exports._fromFinnhub = fromFinnhub;

"use strict";
/* ═══════════════════════════════════════════════════════════════════════════
   Finnhub gate: one cache, one rate limit, stale-on-error.

   Finnhub's plan allows about 60 calls a minute. One stock page fans out to a
   dozen Finnhub calls (metrics, profile, estimates, targets, recommendations,
   earnings, news…), so two or three people researching at once — or one
   person flipping between tickers — ran the key out and every Finnhub-backed
   panel answered "currently unavailable". The audit on 2026-10-06 saw
   metrics and estimates return 503 for every ticker after the seventh.

   This wraps global fetch for finnhub.io only:
     · responses are cached by URL (token removed) with a TTL per endpoint;
     · identical requests in flight share one upstream call;
     · calls are spaced to stay under the plan limit, interactive first,
       background warmers (priority "low") only with spare capacity;
     · when Finnhub says no (429/5xx/network), the last good answer is served;
     · 401/403 (endpoint not in the plan) is remembered for a day so a
       premium-only endpoint stops burning quota on every page view.
   Every other host goes straight to the real fetch.
   ═══════════════════════════════════════════════════════════════════════════ */

const HOST = "finnhub.io";
const PER_MINUTE = Number(process.env.FINNHUB_PER_MINUTE || 55);
const LOW_SHARE = 0.4;                         // background may use 40% of the budget
const MIN = 60 * 1000, HOUR = 60 * MIN;

const TTL = [
  [/\/quote\b/, 20 * 1000],
  [/\/company-news\b/, 10 * MIN],
  [/\/news\b/, 10 * MIN],
  [/\/search\b/, 6 * HOUR],
  [/\/stock\/profile2\b/, 24 * HOUR],
  [/\/stock\/metric\b/, 6 * HOUR],
  [/\/stock\/recommendation\b/, 6 * HOUR],
  [/\/stock\/price-target\b/, 6 * HOUR],
  [/\/stock\/earnings\b/, 3 * HOUR],
  [/\/calendar\/earnings\b/, 3 * HOUR],
  [/-estimate\b/, 12 * HOUR],
  [/\/stock\/insider-transactions\b/, 6 * HOUR],
  [/\/stock\/insider-sentiment\b/, 12 * HOUR],
  [/\/stock\/transcripts/, 24 * HOUR],
  [/\/stock\/ownership\b/, 12 * HOUR],
];
const DEFAULT_TTL = 30 * MIN;
const STALE_MAX = 7 * 24 * HOUR;
const DENIED_TTL = 24 * HOUR;
const MAX_ENTRIES = 6000;

const cache = new Map();      // key -> { at, status, body, contentType }
const inflight = new Map();   // key -> Promise<entry>
const stamps = [];            // upstream call times in the last minute
const stats = { hits: 0, misses: 0, stale: 0, limited: 0, denied: 0, upstream: 0 };
let realFetch = null;

function isFinnhub(url) {
  try { return new URL(url).hostname.endsWith(HOST); } catch (_) { return false; }
}
function keyOf(url) {
  const u = new URL(url);
  u.searchParams.delete("token");
  u.searchParams.sort();
  return u.pathname + "?" + u.searchParams.toString();
}
function ttlFor(key) {
  for (const [re, ms] of TTL) if (re.test(key)) return ms;
  return DEFAULT_TTL;
}
function respond(entry, extra) {
  const headers = { "content-type": entry.contentType || "application/json", "x-finnhub-cache": extra || "hit" };
  return new Response(entry.body, { status: entry.status, headers });
}
function trim() {
  if (cache.size <= MAX_ENTRIES) return;
  const drop = [...cache.entries()].sort((a, b) => a[1].at - b[1].at).slice(0, cache.size - MAX_ENTRIES);
  drop.forEach(([k]) => cache.delete(k));
}

/* Wait for a slot inside the per-minute budget. Background callers only get
   the lower share; interactive callers get the whole budget. */
async function acquire(priority, deadline) {
  const cap = priority === "low" ? Math.max(1, Math.floor(PER_MINUTE * LOW_SHARE)) : PER_MINUTE;
  for (;;) {
    const now = Date.now();
    while (stamps.length && now - stamps[0] > MIN) stamps.shift();
    if (stamps.length < cap) { stamps.push(now); return true; }
    const wait = MIN - (now - stamps[0]) + 25;
    if (now + wait > deadline) return false;
    await new Promise(r => setTimeout(r, Math.min(wait, 1000)));
  }
}

async function gatedFetch(url, options = {}) {
  const target = typeof url === "string" ? url : url && url.url;
  if (!target || !isFinnhub(target) || (options.method && options.method !== "GET")) return realFetch(url, options);
  const key = keyOf(target);
  const priority = options.priority === "low" || (options.headers && options.headers["x-priority"] === "low") ? "low" : "high";
  const now = Date.now();
  const hit = cache.get(key);
  if (hit) {
    const fresh = hit.status === 200 ? now - hit.at < ttlFor(key)
      : (hit.status === 401 || hit.status === 403) ? now - hit.at < DENIED_TTL : false;
    if (fresh) { stats.hits++; return respond(hit, hit.status === 200 ? "hit" : "denied"); }
  }
  if (inflight.has(key)) {
    const e = await inflight.get(key);
    return e ? respond(e, "shared") : new Response(JSON.stringify({ error: "Finnhub unavailable" }), { status: 503 });
  }
  const job = (async () => {
    /* Interactive requests wait up to ~6 s for a slot, background up to 45 s. */
    const ok = await acquire(priority, Date.now() + (priority === "low" ? 45000 : 3500));
    if (!ok) {
      stats.limited++;
      if (hit && hit.status === 200 && now - hit.at < STALE_MAX) { stats.stale++; return { ...hit, stale: true }; }
      return { at: Date.now(), status: 429, body: JSON.stringify({ error: "Finnhub rate limit (local)" }), contentType: "application/json", transient: true };
    }
    stats.misses++; stats.upstream++;
    try {
      const res = await realFetch(url, options);
      const body = await res.text();
      const entry = { at: Date.now(), status: res.status, body, contentType: res.headers.get("content-type") || "application/json" };
      if (res.status === 200) { cache.set(key, entry); trim(); return entry; }
      if (res.status === 401 || res.status === 403) { stats.denied++; cache.set(key, entry); return entry; }
      /* 429 / 5xx: fall back to the last good answer. */
      if (hit && hit.status === 200 && Date.now() - hit.at < STALE_MAX) { stats.stale++; return { ...hit, stale: true }; }
      return { ...entry, transient: true };
    } catch (error) {
      if (hit && hit.status === 200 && Date.now() - hit.at < STALE_MAX) { stats.stale++; return { ...hit, stale: true }; }
      throw error;
    }
  })();
  inflight.set(key, job.catch(() => null));
  try {
    const entry = await job;
    return respond(entry, entry.stale ? "stale" : "miss");
  } finally {
    inflight.delete(key);
  }
}

function install() {
  if (realFetch) return;
  realFetch = globalThis.fetch.bind(globalThis);
  globalThis.fetch = gatedFetch;
}

/* For background warmers: fetch a Finnhub URL at low priority, JSON or null. */
async function finnhubJson(url, { priority = "low", timeoutMs = 8000 } = {}) {
  try {
    const res = await globalThis.fetch(url, { priority, signal: AbortSignal.timeout(timeoutMs) });
    if (!res.ok) return null;
    return await res.json();
  } catch (_) { return null; }
}

function snapshot() {
  return { ...stats, cached: cache.size, lastMinute: stamps.filter(t => Date.now() - t < MIN).length, perMinute: PER_MINUTE };
}

module.exports = { install, finnhubJson, snapshot, _keyOf: keyOf, _gatedFetch: gatedFetch, _reset: () => { cache.clear(); inflight.clear(); stamps.length = 0; } };

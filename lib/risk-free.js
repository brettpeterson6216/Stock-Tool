"use strict";
/* ═══════════════════════════════════════════════════════════════════════════
   The cash rate for risk-adjusted returns (Sharpe, Sortino): the yield on
   3-month US Treasury bills, from the St. Louis Fed's daily series (DTB3,
   no key needed). Read once a day; if FRED cannot be reached the last good
   reading is kept, and before any reading a stated fallback is used.
   ═══════════════════════════════════════════════════════════════════════════ */

const URL_DTB3 = "https://fred.stlouisfed.org/graph/fredgraph.csv?id=DTB3";
const FALLBACK = { rate: 0.039, asOf: null, source: "fallback" };   // DTB3 was ~3.9% in autumn 2026
const DAY = 24 * 3600 * 1000;

let cache = { at: 0, value: null };
let inflight = null;

/* Pure: the latest numeric observation in FRED's two-column CSV
   ("observation_date,DTB3" then "2026-10-30,3.86"; holidays are "."). */
function parseFredCsv(text) {
  const lines = String(text || "").trim().split(/\r?\n/);
  for (let i = lines.length - 1; i > 0; i -= 1) {
    const [d, v] = lines[i].split(",");
    const n = Number(v);
    if (/^\d{4}-\d{2}-\d{2}$/.test(String(d).trim()) && v && v.trim() !== "." && Number.isFinite(n) && n > -5 && n < 25) {
      return { rate: Math.round(n * 100) / 10000, asOf: d.trim(), source: "FRED DTB3" };
    }
  }
  return null;
}

async function current({ fetchImpl = globalThis.fetch } = {}) {
  if (cache.value && Date.now() - cache.at < DAY) return cache.value;
  if (process.env.NODE_ENV === "test") return cache.value || FALLBACK;
  if (inflight) return inflight;
  inflight = (async () => {
    try {
      const ctl = new AbortController();
      const t = setTimeout(() => ctl.abort(), 8000);
      const r = await fetchImpl(`${URL_DTB3}&cosd=${new Date(Date.now() - 45 * DAY).toISOString().slice(0, 10)}`, { signal: ctl.signal, headers: { "User-Agent": "ImpliedLens/1.0" } });
      clearTimeout(t);
      const v = r.ok ? parseFredCsv(await r.text()) : null;
      if (v) cache = { at: Date.now(), value: v };
      else cache = { at: Date.now() - DAY + 3600 * 1000, value: cache.value };   // retry in an hour
    } catch (_) {
      cache = { at: Date.now() - DAY + 3600 * 1000, value: cache.value };
    }
    return cache.value || FALLBACK;
  })().finally(() => { inflight = null; });
  return inflight;
}

module.exports = { current, parseFredCsv, FALLBACK };

"use strict";

/* ═══════════════════════════════════════════════════════════════════════════
   Per-ticker substance for the /stock/:ticker landing pages.

   Measured before writing this: every landing page rendered ~242 words, and
   209 of them were identical across every ticker — the feature grid, the
   generic research questions, the footer. The only per-ticker text was the
   name, the price and the industry tag. That is the shape Google calls a
   doorway page, and it is exactly what section 7 of the SEO plan warns
   against: "thousands of thin pages that only swap a ticker symbol".

   This module turns the research bundle the product already computes into
   attributed, per-ticker facts for the page. Three rules it does not break:

     1. Nothing is invented. A field with no value is omitted, not estimated,
        not filled with "N/A" padding to bulk the page out.
     2. Every figure keeps the source and as-of date the bundle gave it, and
        the page shows them. The site's whole claim is that you can see where
        a number came from; a landing page that drops the attribution is
        making that claim falsely to the visitor who arrived from search.
     3. The prose is generated from the values, never from a template with a
        ticker slotted in. If there is nothing to say, it says nothing.
   ═══════════════════════════════════════════════════════════════════════════ */

const { buildResearchBundle } = require("./stock-research");

/* How each field reads. Units are not cosmetic: margins, growth and the
   model's upside are FRACTIONS in the bundle (0.23 → 23%), while leverage,
   coverage and the forward multiple are MULTIPLES (2.4 → 2.4×). Printing one
   as the other is off by a factor of a hundred, in a number a visitor might
   act on. */
const FIELDS = Object.freeze({
  forwardPE:         { label: "Forward P/E",        unit: "x",   group: "valuation" },
  dcfUpside:         { label: "Model upside",       unit: "pct", group: "valuation", signed: true },
  bearDownside:      { label: "Conservative case",  unit: "pct", group: "valuation", signed: true },
  impliedGrowthGap:  { label: "Implied growth gap", unit: "pct", group: "valuation", signed: true },
  revenueGrowth:     { label: "Revenue growth",     unit: "pct", group: "growth",    signed: true },
  epsGrowth:         { label: "EPS growth",         unit: "pct", group: "growth",    signed: true },
  dilution:          { label: "Share count change", unit: "pct", group: "growth",    signed: true },
  profitMargin:      { label: "Net margin",         unit: "pct", group: "quality" },
  fcfMargin:         { label: "Free cash flow margin", unit: "pct", group: "quality" },
  roic:              { label: "Return on invested capital", unit: "pct", group: "quality" },
  returnOnEquity:    { label: "Return on equity",   unit: "pct", group: "quality" },
  netDebtEbitda:     { label: "Net debt / EBITDA",  unit: "x",   group: "balance" },
  interestCoverage:  { label: "Interest coverage",  unit: "x",   group: "balance" },
  capitalRatio:      { label: "Equity / assets",    unit: "pct", group: "balance" },
});

const GROUPS = Object.freeze([
  ["valuation", "Valuation"],
  ["growth",    "Growth"],
  ["quality",   "Profitability and returns"],
  ["balance",   "Balance sheet"],
]);

function finite(v) { return typeof v === "number" && Number.isFinite(v); }

function formatValue(value, spec) {
  if (!finite(value)) return null;
  if (spec.unit === "pct") {
    const pct = value * 100;
    const digits = Math.abs(pct) >= 100 ? 0 : 1;
    const body = `${Math.abs(pct).toFixed(digits)}%`;
    if (!spec.signed) return body;
    return `${pct > 0 ? "+" : pct < 0 ? "−" : ""}${body}`;
  }
  return `${value.toFixed(value >= 100 ? 0 : 1)}×`;
}

function shortDate(iso) {
  if (!iso) return null;
  const d = new Date(iso);
  return Number.isNaN(d.getTime())
    ? null
    : d.toLocaleDateString("en-US", { year: "numeric", month: "short", day: "numeric", timeZone: "UTC" });
}

/* The bundle reports each field as { value, source, asOf }. Rows without a
   value are dropped here rather than rendered as a dash: a table of dashes is
   thin content that also looks broken. */
function rowsFrom(fundamentals) {
  const fields = fundamentals?.fields || {};
  const rows = [];
  for (const [key, spec] of Object.entries(FIELDS)) {
    const field = fields[key];
    const text = formatValue(field?.value, spec);
    if (!text) continue;
    rows.push({
      key,
      group: spec.group,
      label: spec.label,
      value: text,
      source: field.source || null,
      asOf: shortDate(field.asOf),
    });
  }
  return rows;
}

function earningsRows(fundamentals) {
  const list = Array.isArray(fundamentals?.earnings) ? fundamentals.earnings : [];
  return list
    .filter(row => finite(row?.actual))
    .slice(-4)
    .reverse()
    .map(row => {
      const surprise = finite(row.estimate) && row.estimate !== 0
        ? ((row.actual - row.estimate) / Math.abs(row.estimate)) * 100
        : null;
      return {
        period: row.period || (row.year && row.quarter ? `Q${row.quarter} ${row.year}` : null),
        actual: row.actual.toFixed(2),
        estimate: finite(row.estimate) ? row.estimate.toFixed(2) : null,
        surprise: finite(surprise)
          ? `${surprise > 0 ? "+" : surprise < 0 ? "−" : ""}${Math.abs(surprise).toFixed(1)}%`
          : null,
        beat: finite(surprise) ? surprise >= 0 : null,
      };
    });
}

/* Sentences assembled from the values that exist. Each clause is guarded by
   its own field, so a company with only two reported figures gets two
   clauses, not a paragraph of hedging around the twelve that are missing. */
function narrative(name, ticker, rows, earnings) {
  const by = Object.fromEntries(rows.map(r => [r.key, r]));
  const out = [];
  const subject = name && name !== ticker ? `${name} (${ticker})` : ticker;
  /* "+8.1%" is right in a table and wrong in a sentence. */
  const direction = key => {
    const row = by[key];
    if (!row) return null;
    const magnitude = row.value.replace(/^[+−]/, "");
    return `${row.value.startsWith("−") ? "down" : "up"} ${magnitude}`;
  };
  const list = parts => (parts.length > 1
    ? `${parts.slice(0, -1).join(", ")} and ${parts.at(-1)}`
    : parts[0]);

  const growth = [];
  if (by.revenueGrowth) growth.push(`revenue ${direction("revenueGrowth")}`);
  if (by.epsGrowth) growth.push(`earnings per share ${direction("epsGrowth")}`);
  if (growth.length) {
    out.push(`On the most recently reported figures, ${subject} shows ${list(growth)} year over year.`);
  }

  const quality = [];
  if (by.profitMargin) quality.push(`a net margin of ${by.profitMargin.value}`);
  if (by.fcfMargin) quality.push(`a free cash flow margin of ${by.fcfMargin.value}`);
  if (by.roic) quality.push(`a ${by.roic.value} return on invested capital`);
  else if (by.returnOnEquity) quality.push(`a ${by.returnOnEquity.value} return on equity`);
  if (quality.length) out.push(`The business runs ${list(quality)}.`);

  const balance = [];
  if (by.netDebtEbitda) balance.push(`net debt at ${by.netDebtEbitda.value} EBITDA`);
  if (by.interestCoverage) balance.push(`interest covered ${by.interestCoverage.value} over by operating income`);
  if (balance.length) out.push(`Its balance sheet carries ${list(balance)}.`);

  if (by.dcfUpside) {
    const upside = by.dcfUpside.value.startsWith("−")
      ? `${by.dcfUpside.value.replace("−", "")} below the current price`
      : `${by.dcfUpside.value.replace("+", "")} above the current price`;
    let sentence = `The ImpliedLens normalized earnings-value model places the shares ${upside} under its disclosed assumptions, which you can change.`;
    if (by.impliedGrowthGap) {
      const gap = by.impliedGrowthGap.value.startsWith("−")
        ? `${by.impliedGrowthGap.value.replace("−", "")} less growth than`
        : `${by.impliedGrowthGap.value.replace("+", "")} more growth than`;
      sentence += ` At today's price the market is implying ${gap} the reported figures support.`;
    }
    out.push(sentence);
  }

  if (earnings.length) {
    const scored = earnings.filter(e => e.beat !== null);
    const beats = scored.filter(e => e.beat).length;
    if (scored.length) {
      out.push(`Across the last ${scored.length} reported quarter${scored.length === 1 ? "" : "s"}, ${ticker} came in ahead of the consensus estimate ${beats === 0 ? "no times" : beats === scored.length ? "every time" : `${beats} time${beats === 1 ? "" : "s"}`}.`);
    }
  }

  return out;
}

function summarize(bundle, ticker, nameHint) {
  const fundamentals = bundle?.fundamentals;
  if (!fundamentals) return null;
  const rows = rowsFrom(fundamentals);
  const earnings = earningsRows(fundamentals);
  if (!rows.length && !earnings.length) return null;

  /* bundle.company is a STRING in stock-research.js, not an object. Reading
     .name off it gave undefined, so every sentence on every live page opened
     "AAPL shows revenue up 16.4%" instead of naming the company — the one
     thing the prose exists to do. Both shapes are accepted now, and the route
     passes the name it already resolved as the first choice. */
  const name = nameHint
    || (typeof bundle?.company === "string" ? bundle.company : bundle?.company?.name)
    || bundle?.profile?.name
    || ticker;
  return {
    ticker,
    groups: GROUPS
      .map(([key, label]) => ({ key, label, rows: rows.filter(r => r.group === key) }))
      .filter(group => group.rows.length),
    earnings,
    narrative: narrative(name, ticker, rows, earnings),
    reportedAsOf: shortDate(fundamentals.reportedAsOf),
    coverage: finite(fundamentals.coverage) ? Math.round(fundamentals.coverage * 100) : null,
    stale: fundamentals.freshness?.status === "stale",
  };
}

/* ── caching ────────────────────────────────────────────────────────────────
   A landing page must not wait on the full research pipeline, and 103 indexed
   pages must not turn a crawl into 103 concurrent SEC and provider fetches.

   So: serve whatever is cached, refresh in the background, and let the first
   request for a cold ticker render without the section rather than hang.
   Fundamentals move quarterly; six hours is already far finer than the data.
   ──────────────────────────────────────────────────────────────────────── */
const TTL_MS = 6 * 60 * 60 * 1000;
const MAX_INFLIGHT = 2;
const cache = new Map();
let inflight = 0;

function refresh(ticker, nameHint) {
  if (inflight >= MAX_INFLIGHT) return;
  inflight += 1;
  buildResearchBundle(ticker, { range: "5y", interval: "1mo" })
    .then(bundle => {
      const summary = summarize(bundle, ticker, nameHint);
      cache.set(ticker, { summary, at: Date.now() });
    })
    .catch(() => {
      /* Remember the failure too, or every crawl of a ticker whose filings we
         cannot read re-queues the same work. */
      cache.set(ticker, { summary: null, at: Date.now() });
    })
    .finally(() => { inflight -= 1; });
}

function landingFacts(ticker, nameHint) {
  const entry = cache.get(ticker);
  if (!entry) { refresh(ticker, nameHint); return null; }
  if (Date.now() - entry.at > TTL_MS) refresh(ticker, nameHint);
  return entry.summary;
}

/* ── warming ────────────────────────────────────────────────────────────────
   Without this, the first crawl of each page gets the thin version and the
   deep one only appears on the second visit — so whichever version Google
   happens to fetch first is the one that gets indexed. A slow walk of the
   published set fills the cache within about half an hour of a deploy while
   putting one request at a time on the providers, which is gentler than the
   crawl it replaces.

   Interval, not a burst: 103 tickers × two upstreams each, fired at boot,
   is the kind of thing that gets an API key rate-limited. */
function startLandingWarmup(tickers, { intervalMs = 20000 } = {}) {
  const queue = [...tickers];
  if (!queue.length) return null;
  let i = 0;
  const timer = setInterval(() => {
    if (i >= queue.length) { clearInterval(timer); return; }
    const ticker = queue[i];
    const entry = cache.get(ticker);
    /* Skip anything a real request already cached; only advance when there is
       room, so a slow upstream throttles the walk instead of stacking it. */
    if (entry && Date.now() - entry.at < TTL_MS) { i += 1; return; }
    if (inflight >= MAX_INFLIGHT) return;
    refresh(ticker);
    i += 1;
  }, intervalMs);
  if (typeof timer.unref === "function") timer.unref();
  return timer;
}

function primeLandingFacts(ticker, summary) {
  cache.set(ticker, { summary, at: Date.now() });
}

function clearLandingFacts() { cache.clear(); inflight = 0; }

module.exports = {
  FIELDS,
  GROUPS,
  formatValue,
  rowsFrom,
  earningsRows,
  narrative,
  summarize,
  landingFacts,
  startLandingWarmup,
  primeLandingFacts,
  clearLandingFacts,
};

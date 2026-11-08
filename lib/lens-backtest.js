"use strict";
/* ═══════════════════════════════════════════════════════════════════════════
   Does the LensScore work? The honest test.

   Two studies, run on the server in the background and published as they
   come out, good or bad, on /methodology:

   1. Grades, point in time. At each past month-end, every company in the
      graded universe is graded using only the SEC figures that had been FILED
      by that date (lib/sec-fundamentals.js factsAsOf) and prices up to that
      date, exactly as the live grades are built. We then measure what each
      score band did over the next 3 and 6 months against the S&P 500 (SPY).
   2. Timing. LensSetup (lib/lens-setup-engine.js), the live timing read, is
      computed walk-forward on each company's price history (each reading sees
      only the bars before it) and compared with the next 1 and 3 months.

   Known limits, stated on the page with the results:
     · The universe is today's list, so companies that were delisted or fell
       out of it are missing (survivorship bias flatters every band a little,
       the spread between bands much less).
     · The window is the price history we hold (about three and a half years).
     · Restatements: a figure later restated keeps its first-filed value until
       the restatement is filed, which is the point-in-time behaviour we want.
   ═══════════════════════════════════════════════════════════════════════════ */

const F = require("./lens-factors");
const groups = require("./industry-groups");
const { lensSetup } = require("./lens-setup-engine");

const finite = v => v !== null && v !== undefined && v !== "" && Number.isFinite(Number(v));
const mean = a => (a.length ? a.reduce((s, x) => s + x, 0) / a.length : null);
const median = a => { if (!a.length) return null; const v = [...a].sort((x, y) => x - y); const m = Math.floor(v.length / 2); return v.length % 2 ? v[m] : (v[m - 1] + v[m]) / 2; };
const r4 = v => (finite(v) ? Math.round(v * 1e4) / 1e4 : null);

/* Pure: Spearman rank correlation. */
function ranks(a) {
  const idx = a.map((v, i) => [v, i]).sort((x, y) => x[0] - y[0]);
  const out = new Array(a.length);
  for (let i = 0; i < idx.length;) {
    let j = i; while (j + 1 < idx.length && idx[j + 1][0] === idx[i][0]) j += 1;
    const r = (i + j) / 2 + 1;
    for (let k = i; k <= j; k += 1) out[idx[k][1]] = r;
    i = j + 1;
  }
  return out;
}
function pearson(x, y) {
  const n = x.length; if (n < 3) return null;
  const mx = mean(x), my = mean(y);
  let a = 0, b = 0, c = 0;
  for (let i = 0; i < n; i += 1) { const dx = x[i] - mx, dy = y[i] - my; a += dx * dy; b += dx * dx; c += dy * dy; }
  return b > 0 && c > 0 ? a / Math.sqrt(b * c) : null;
}
function spearman(x, y) { return x.length >= 3 ? pearson(ranks(x), ranks(y)) : null; }
/* Mean of monthly values with a t-statistic (is it reliably above zero?). */
function meanT(values) {
  const v = values.filter(finite);
  if (v.length < 2) return { mean: v.length ? r4(v[0]) : null, t: null, n: v.length };
  const m = mean(v), sd = Math.sqrt(v.reduce((s, x) => s + (x - m) ** 2, 0) / (v.length - 1));
  return { mean: r4(m), t: sd > 0 ? Math.round((m / (sd / Math.sqrt(v.length))) * 100) / 100 : null, n: v.length };
}

/* Split factor between a past share count and today's (same company):
   a ratio near a common split (2, 3, 4, 5, 8, 10, 15, 20...) is a split;
   anything else is buybacks or issuance and is ignored. */
const SPLITS = [2, 3, 4, 5, 6, 8, 10, 12, 15, 20, 25, 30, 40, 50];
function splitFactor(sharesThen, sharesNow) {
  if (!(sharesThen > 0) || !(sharesNow > 0)) return 1;
  const r = sharesNow / sharesThen;
  const near = k => SPLITS.find(s => Math.abs(k / s - 1) < 0.12);
  if (r >= 1.6) return near(r) || 1;
  if (r <= 1 / 1.6) { const k = near(1 / r); return k ? 1 / k : 1; }
  return 1;
}

/* Index of the last row on or before `day`. Rows oldest first. */
function indexOnOrBefore(rows, day) {
  let lo = 0, hi = rows.length - 1, ans = -1;
  while (lo <= hi) { const mid = (lo + hi) >> 1; if (rows[mid].day <= day) { ans = mid; lo = mid + 1; } else hi = mid - 1; }
  return ans;
}
function forward(rows, i, h) {
  if (i < 0 || i + h >= rows.length) return null;
  const a = rows[i].close, b = rows[i + h].close;
  return a > 0 && b > 0 ? b / a - 1 : null;
}

/* Month-ends (last weekday) between two days. */
function monthEnds(fromDay, toDay) {
  const out = [];
  let d = new Date(fromDay.slice(0, 7) + "-01T12:00:00Z");
  while (true) {
    const next = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth() + 1, 1, 12));
    let e = new Date(next - 864e5);
    while ([0, 6].includes(e.getUTCDay())) e = new Date(e - 864e5);
    const s = e.toISOString().slice(0, 10);
    if (s > toDay) break;
    if (s >= fromDay) out.push(s);
    d = next;
  }
  return out;
}

const BANDS = [
  { key: "top", label: "Top-rated (8.0+)", min: 8 },
  { key: "above", label: "Above average (6.5–7.9)", min: 6.5 },
  { key: "middle", label: "Middle (4.5–6.4)", min: 4.5 },
  { key: "below", label: "Below average (3.0–4.4)", min: 3 },
  { key: "bottom", label: "Bottom-rated (under 3.0)", min: -1 },
];
const bandOf = s => BANDS.find(b => s >= b.min).key;

/* Pure: one month's cross-section → [score, excess return by horizon]. */
function gradeMonth(mo) {
  return F.gradeUniverse(mo.rows).map(g => ({ score: g.score, fwd: mo.fwd[g.ticker] || {} }));
}
/* Pure: summarise graded months. graded: [[{score, fwd}], ...] */
function summarizeGrades(graded, horizons = [63, 126]) {
  const out = { months: graded.length, horizons: {} };
  for (const h of horizons) {
    const byBand = Object.fromEntries(BANDS.map(b => [b.key, []]));
    const ic = [], spread = [];
    let obs = 0;
    for (const list of graded) {
      const pairs = list.map(x => [x.score, x.fwd[h]]).filter(([, r]) => finite(r));
      if (pairs.length < 30) continue;
      obs += pairs.length;
      pairs.forEach(([sc, r]) => byBand[bandOf(sc)].push(r));
      ic.push(spearman(pairs.map(p => p[0]), pairs.map(p => p[1])));
      const sorted = [...pairs].sort((a, b) => b[0] - a[0]);
      const q = Math.max(1, Math.floor(sorted.length / 5));
      spread.push(mean(sorted.slice(0, q).map(p => p[1])) - mean(sorted.slice(-q).map(p => p[1])));
    }
    out.horizons[h] = {
      observations: obs,
      monthsTested: ic.filter(finite).length,
      rankCorrelation: meanT(ic),
      topMinusBottomQuintile: { ...meanT(spread), positiveMonths: spread.filter(x => x > 0).length },
      bands: BANDS.map(b => ({ key: b.key, label: b.label, observations: byBand[b.key].length,
        meanExcess: r4(mean(byBand[b.key])), medianExcess: r4(median(byBand[b.key])),
        beatRate: byBand[b.key].length ? r4(byBand[b.key].filter(x => x > 0).length / byBand[b.key].length) : null })),
    };
  }
  return out;
}
/* Pure: the grade study from monthly cross-sections (tests; the job grades
   month by month with pauses so the server stays responsive).
   months: [{ day, rows: [peer rows {t,s,g,m,px}], fwd: { [ticker]: { [h]: excess return } } }] */
function gradeStudy(months, horizons = [63, 126]) {
  return { ...summarizeGrades(months.map(gradeMonth), horizons), firstDay: months[0]?.day || null, lastDay: months.at(-1)?.day || null };
}

/* The timing reads a visitor can see, each scored from a window of bars that
   ends on the observation date:
     gauge  the "Lens Timing" gauge on the LensToolkit page (0 stretched,
            10 pulled back), from the LensToolkit engine;
     setup  that engine's overall setup score (0-10);
     lensSetup  LensSetup v2, the zones-and-structure read behind the chart. */
const toolkit = require("./lens-score-engine");
const TIMING_SCORERS = {
  gauge: { label: "Lens Timing gauge (LensToolkit)", score: bars => { const t = toolkit.analyzeTechnical(bars); return t && t.timing && finite(t.timing.timingScore) ? Number(t.timing.timingScore) : null; } },
  setup: { label: "Setup score (LensToolkit)", score: bars => { const t = toolkit.analyzeTechnical(bars); return t && t.status === "ok" && finite(t.setupScore) ? Number(t.setupScore) / 10 : null; } },
  lensSetup: { label: "LensSetup v2 (chart zones)", score: bars => { const r = lensSetup({ close: bars.map(b => b.close), high: bars.map(b => b.high), low: bars.map(b => b.low), volume: bars.map(b => b.volume) }); return r && finite(r.score) ? Number(r.score) : null; } },
};

/* Pure: one walk-forward reading at bar i (it sees only bars up to i). */
function toBars(rows) {
  return rows.map(r => ({ time: Math.floor(Date.parse(r.day + "T21:00:00Z") / 1000), open: r.open ?? r.close, high: r.high ?? r.close, low: r.low ?? r.close, close: r.close, volume: r.volume ?? 0 }));
}
function observeAt(t, rows, bars, bench, i, horizons, scorers) {
  const prefix = bars.slice(Math.max(0, i - 400), i + 1);
  const o = { t, day: rows[i].day, scores: {} };
  for (const [k, sc] of Object.entries(scorers)) {
    let v = null;
    try { v = sc.score(prefix); } catch (_) { v = null; }
    if (finite(v)) o.scores[k] = Number(v);
  }
  if (!Object.keys(o.scores).length) return null;
  const bi = indexOnOrBefore(bench, rows[i].day);
  for (const h of horizons) {
    const r = forward(rows, i, h), b = bi >= 0 ? forward(bench, bi, h) : null;
    o[h] = finite(r) && finite(b) ? r - b : null;
  }
  return o;
}
function sampleIndexes(n, { sampleEvery = 21, minBars = 252, horizons = [21, 63] } = {}) {
  const out = [], maxH = Math.max(...horizons);
  for (let i = minBars; i + maxH < n; i += sampleEvery) out.push(i);
  return out;
}
/* Pure: walk-forward timing readings for one company. */
function timingObservations(t, rows, bench, opts = {}) {
  const horizons = opts.horizons || [21, 63], scorers = opts.scorers || TIMING_SCORERS;
  if (!rows || rows.length < (opts.minBars || 252) + Math.max(...horizons) + 1) return [];
  const bars = toBars(rows);
  return sampleIndexes(rows.length, opts).map(i => observeAt(t, rows, bars, bench, i, horizons, scorers)).filter(Boolean);
}
function summarizeTiming(obs, tickers, horizons = [21, 63], scorers = TIMING_SCORERS) {
  const out = { observations: obs.length, tickers, scorers: {} };
  for (const [k, sc] of Object.entries(scorers)) {
    const mine = obs.filter(o => finite(o.scores[k])).map(o => ({ ...o, score: o.scores[k] }));
    const res = { label: sc.label, observations: mine.length, horizons: {} };
    for (const h of horizons) {
      const pts = mine.filter(o => finite(o[h]));
      const buckets = [[0, 3], [3, 4], [4, 5], [5, 6], [6, 7], [7, 10.01]].map(([lo, hi]) => {
        const v = pts.filter(o => o.score >= lo && o.score < hi).map(o => o[h]);
        return { range: `${lo}\u2013${hi > 10 ? 10 : hi}`, observations: v.length, meanExcess: r4(mean(v)), beatRate: v.length ? r4(v.filter(x => x > 0).length / v.length) : null };
      });
      /* Correlation per sample date, then averaged: one big pooled number
         would mostly measure which months were good for everything. */
      const byDay = new Map();
      pts.forEach(o => { (byDay.get(o.day) || byDay.set(o.day, []).get(o.day)).push(o); });
      const ic = [...byDay.values()].filter(v => v.length >= 20).map(v => spearman(v.map(o => o.score), v.map(o => o[h])));
      res.horizons[h] = { observations: pts.length, rankCorrelation: meanT(ic), buckets };
    }
    res.verdict = { 21: verdict(res.horizons[21]?.rankCorrelation), 63: verdict(res.horizons[63]?.rankCorrelation) };
    out.scorers[k] = res;
  }
  return out;
}
/* Pure: the timing study. seriesByTicker: { T: rows [{day, close, high, low, volume}] }, bench: SPY rows. */
function timingStudy(seriesByTicker, bench, opts = {}) {
  const obs = Object.entries(seriesByTicker).flatMap(([t, rows]) => timingObservations(t, rows, bench, opts));
  return summarizeTiming(obs, Object.keys(seriesByTicker).length, opts.horizons, opts.scorers);
}

/* Plain-English verdict for a study, used on the page. */
function verdict(rc, spreadT) {
  if (!rc || !finite(rc.mean) || rc.n < 6) return "Not enough history yet to say.";
  const t = finite(rc.t) ? rc.t : 0;
  if (rc.mean > 0.02 && t >= 2) return "Higher scores have been followed by better returns, reliably so far.";
  if (rc.mean > 0 && t >= 1) return "Higher scores have been followed by somewhat better returns, but not reliably yet.";
  if (rc.mean < -0.02 && t <= -2) return "Higher scores have been followed by worse returns. The method needs rework.";
  return "No reliable relationship between the score and later returns so far.";
}

/* ── the server job ───────────────────────────────────────────────────── */
const yieldLoop = () => new Promise(r => setImmediate(r));
const sleep = ms => new Promise(r => setTimeout(r, ms));

/* The job shares the web server's process, so it must never take the site
   down. On 2026-11-07 a run hit the V8 heap limit (Render exit 134) near the
   end: every month's cross-section is held until grading, and one large
   filer's companyfacts file is tens of MB of JSON. So:
     · a company whose facts file is larger than MAX_FACTS_CHARS is skipped;
     · before each company the heap is checked, and above HEAP_STOP of the
       limit the run stops and publishes what it has, saying so. */
const v8 = require("node:v8");
const MAX_FACTS_CHARS = Math.max(2e6, Number(process.env.BACKTEST_MAX_FACTS_MB || 18) * 1e6);
const HEAP_STOP = Math.min(0.9, Math.max(0.4, Number(process.env.BACKTEST_HEAP_STOP || 0.62)));
function heapShare() {
  const limit = v8.getHeapStatistics().heap_size_limit || 0;
  return limit ? process.memoryUsage().heapUsed / limit : 0;
}
const mb = n => Math.round(n / 1048576);

async function run({ tickers, log = console.log, heap = heapShare } = {}) {
  const sec = require("./sec-fundamentals");
  const secUniverse = require("./sec-universe");
  const prices = require("./prices");
  const DAYS = Math.max(800, Number(process.env.BACKTEST_PRICE_DAYS || 1300));
  const started = Date.now();
  const bench = (await prices.dailyCloses("SPY", DAYS, "background")).filter(r => finite(r.close));
  if (bench.length < 400) throw new Error("not enough SPY history for the backtest");
  const firstDay = bench[Math.min(bench.length - 1, 260)].day;        // a year of prices before the first test date
  const lastDay = bench[Math.max(0, bench.length - 64)].day;          // three months after the last
  const days = monthEnds(firstDay, lastDay);
  const months = days.map(day => ({ day, rows: [], fwd: {} }));
  const timingObs = [];
  let timingTickers = 0;
  let done = 0, skipped = 0, tooBig = 0, stoppedAt = null;
  log(`[backtest] starting: ${tickers.length} companies, heap ${mb(process.memoryUsage().heapUsed)} MB (${Math.round(heap() * 100)}% of limit)`);
  for (const t of tickers) {
    if (heap() > HEAP_STOP) {
      await sleep(3000);                       // let the collector catch up once
      if (heap() > HEAP_STOP) { stoppedAt = done; log(`[backtest] stopping early at ${done} companies: heap ${Math.round(heap() * 100)}% of its limit`); break; }
    }
    try {
      const rows = (await prices.dailyCloses(t, DAYS, "background")).filter(r => finite(r.close));
      if (rows.length < 300) { skipped += 1; continue; }
      {
        const bars = toBars(rows);
        for (const i of sampleIndexes(rows.length)) {
          const o = observeAt(t, rows, bars, bench, i, [21, 63], TIMING_SCORERS);
          if (o) timingObs.push(o);
          await yieldLoop();
        }
        timingTickers += 1;
      }
      const id = await sec.cikFor(t);
      if (!id) { skipped += 1; continue; }
      const co = await secUniverse.companyData(t, { kind: "background" });
      if (!co.sector) { skipped += 1; continue; }
      let raw = await sec.secText(`https://data.sec.gov/api/xbrl/companyfacts/CIK${id.cik}.json`, 30000);
      if (raw.length > MAX_FACTS_CHARS) { raw = null; tooBig += 1; skipped += 1; continue; }
      let facts = JSON.parse(raw);
      raw = null;
      const sharesNow = co.snap?.sharesOutstanding;
      const group = groups.groupFor(co.profile?.sic, co.sector);
      for (const mo of months) {
        const i = indexOnOrBefore(rows, mo.day);
        if (i < 252) continue;
        const snap = sec.snapshotFromFacts(sec.factsAsOf(facts, mo.day));
        if (!snap || !snap.ttm || !finite(snap.ttm.revenue)) continue;
        const S = splitFactor(snap.sharesOutstanding, sharesNow);
        const window = rows.slice(Math.max(0, i - 559), i + 1).map(r => ({ ...r, close: r.close * S, high: (r.high ?? r.close) * S }));
        const bi = indexOnOrBefore(bench, mo.day);
        const metric = sec.metricsFrom(snap, { price: window.at(-1).close, rows: window, bench: bench.slice(Math.max(0, bi - 559), bi + 1), ticker: t });
        mo.rows.push({ t, n: t, s: co.sector, g: group, m: metric, px: window.at(-1).close, mc: finite(metric.marketCapitalization) ? metric.marketCapitalization * 1e6 : null });
        mo.fwd[t] = {};
        for (const h of [63, 126]) {
          const r = forward(rows, i, h), b = forward(bench, bi, h);
          if (finite(r) && finite(b)) mo.fwd[t][h] = r - b;
        }
        await yieldLoop();
      }
      facts = null;
      done += 1;
      if (done % 50 === 0) log(`[backtest] ${done} companies processed, heap ${mb(process.memoryUsage().heapUsed)} MB (${Math.round(heap() * 100)}% of limit)`);
    } catch (_) { skipped += 1; }
    await yieldLoop();
  }
  if (stoppedAt !== null && done < 150) throw new Error(`stopped at ${done} companies for memory; too few to publish`);
  const graded = [];
  for (const mo of months.filter(m => m.rows.length >= 30)) { graded.push(gradeMonth(mo)); await yieldLoop(); }
  const grades = summarizeGrades(graded);
  const timing = summarizeTiming(timingObs, timingTickers);
  const result = {
    at: new Date().toISOString(), ms: Date.now() - started, model: F.VERSION, timingModel: `LensToolkit ${toolkit.VERSION || ""} + lens-setup/2.0`.trim(),
    companies: done, skipped, of: tickers.length, stoppedEarly: stoppedAt !== null, window: { from: days[0] || null, to: days.at(-1) || null },
    grades: { ...grades, verdict: { 63: verdict(grades.horizons[63]?.rankCorrelation), 126: verdict(grades.horizons[126]?.rankCorrelation) } },
    timing,
    limits: [
      "The universe is today's list, so companies that were delisted or dropped out are missing (survivorship bias).",
      "The test window is the price history we hold, about three and a half years, so it covers one market cycle at most.",
      "Returns are price returns against SPY, before dividends and costs.",
      ...(stoppedAt !== null ? [`This run stopped after ${stoppedAt} of ${tickers.length} companies to stay within the server's memory; the results cover those companies only.`] : []),
      ...(tooBig ? [`${tooBig} companies with very large SEC filing histories were left out of the grade study for the same reason.`] : []),
    ],
  };
  return result;
}

/* Stored results + weekly schedule. */
function dbOrNull() {
  if (process.env.NODE_ENV === "test") return null;
  try { return require("./db").db; } catch (_) { return null; }
}
let latest = null, running = false;
async function load() {
  if (latest) return latest;
  const db = dbOrNull();
  if (!db) return null;
  try {
    await db.execute({ sql: "CREATE TABLE IF NOT EXISTS universe_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)", args: [] });
    const r = await db.execute({ sql: "SELECT value FROM universe_meta WHERE key = 'backtest'", args: [] });
    latest = r.rows[0] ? JSON.parse(r.rows[0].value) : null;
  } catch (_) { /* none yet */ }
  return latest;
}
async function save(result) {
  latest = result;
  const db = dbOrNull();
  if (!db) return;
  try {
    await db.execute({ sql: "INSERT INTO universe_meta (key, value) VALUES ('backtest', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", args: [JSON.stringify(result)] });
  } catch (_) { /* memory still has it */ }
}
function start(tickersFn, { firstDelayMs = 3 * 3600 * 1000, everyMs = 7 * 24 * 3600 * 1000 } = {}) {
  const go = async () => {
    if (running) return;
    const prev = await load();
    if (prev && Date.now() - Date.parse(prev.at) < everyMs - 3600 * 1000) return;
    running = true;
    try {
      const res = await run({ tickers: tickersFn() });
      await save(res);
      console.log(`[backtest] done: ${res.companies} companies, ${res.grades.months} months, ${Math.round(res.ms / 60000)} min`);
    } catch (e) { console.warn("[backtest] failed:", String(e.message || e).slice(0, 160)); }
    finally { running = false; }
  };
  setTimeout(go, firstDelayMs).unref?.();
  setInterval(go, 6 * 3600 * 1000).unref?.();
}
function status() { return { running, at: latest?.at || null }; }

module.exports = { run, start, load, status, gradeStudy, timingStudy, timingObservations, verdict, splitFactor, monthEnds, spearman, meanT, BANDS };

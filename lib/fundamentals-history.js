"use strict";
/* ═══════════════════════════════════════════════════════════════════════════
   Quarterly fundamentals history from SEC XBRL company facts.

   Turns a companyfacts document into one row per fiscal quarter — revenue,
   gross profit, operating income, net income, diluted EPS, operating cash
   flow, capex, free cash flow and diluted shares — for the growth charts.

   Three things the raw facts do not give you directly, handled here:
     · Cash-flow statements in a 10-Q are year-to-date (3, 6, 9 months). The
       quarter is the difference between consecutive year-to-date figures that
       share the same fiscal-year start.
     · A 10-K reports the full year, not the fourth quarter. Q4 is the full
       year less the nine-month figure (same rule as above).
     · Companies change tags over time (Revenues → RevenueFromContract…), and
       some report a total and a subset in the same filing. Revenue takes the
       largest figure reported for the quarter; every other metric takes the
       first tag in its priority list that has a value.

   Every derived value is flagged so the UI can say so.
   ═══════════════════════════════════════════════════════════════════════════ */

const FORMS = new Set(["10-K", "10-K/A", "10-Q", "10-Q/A", "10-KT", "10-KT/A"]);

const METRICS = Object.freeze({
  revenue: {
    concepts: [
      "Revenues", "RevenueFromContractWithCustomerExcludingAssessedTax", "RevenueFromContractWithCustomerIncludingAssessedTax",
      "SalesRevenueNet", "SalesRevenueGoodsNet", "SalesRevenueServicesNet", "RevenuesNetOfInterestExpense",
      "Revenue", "RevenueFromContractsWithCustomers",
    ],
    pick: "max", cumulative: true,
  },
  grossProfit: { concepts: ["GrossProfit"], cumulative: true },
  costOfRevenue: { concepts: ["CostOfRevenue", "CostOfGoodsAndServicesSold", "CostOfGoodsSold", "CostOfGoodsAndServiceExcludingDepreciationDepletionAndAmortization"], cumulative: true },
  operatingIncome: { concepts: ["OperatingIncomeLoss", "ProfitLossFromOperatingActivities"], cumulative: true },
  netIncome: { concepts: ["NetIncomeLoss", "ProfitLoss", "NetIncomeLossAvailableToCommonStockholdersBasic"], cumulative: true },
  eps: { concepts: ["EarningsPerShareDiluted", "EarningsPerShareBasicAndDiluted", "DilutedEarningsLossPerShare", "EarningsPerShareBasic"], cumulative: true, units: ["USD/shares"] },
  operatingCashFlow: {
    concepts: ["NetCashProvidedByUsedInOperatingActivities", "NetCashProvidedByUsedInOperatingActivitiesContinuingOperations", "CashFlowsFromUsedInOperatingActivities"],
    cumulative: true,
  },
  capex: {
    concepts: ["PaymentsToAcquirePropertyPlantAndEquipment", "PaymentsToAcquireProductiveAssets", "PaymentsForCapitalImprovements",
      "PaymentsToAcquireOtherPropertyPlantAndEquipment", "PurchaseOfPropertyPlantAndEquipmentClassifiedAsInvestingActivities"],
    cumulative: true,
  },
  shares: {
    concepts: ["WeightedAverageNumberOfDilutedSharesOutstanding", "WeightedAverageNumberOfShareOutstandingBasicAndDiluted",
      "WeightedAverageNumberOfSharesOutstandingBasic", "AdjustedWeightedAverageShares"],
    cumulative: false, units: ["shares"],
  },
});

const DAY = 86400000;
function days(a, b) { return (new Date(b) - new Date(a)) / DAY; }
function isQuarter(d) { return d >= 70 && d <= 115; }
function finite(v) { return typeof v === "number" && Number.isFinite(v); }

/* All facts for one concept, newest filing per (start, end). */
function conceptRows(facts, concept, units) {
  const tax = facts?.facts?.["us-gaap"]?.[concept] ? facts.facts["us-gaap"][concept]
    : facts?.facts?.["ifrs-full"]?.[concept] ? facts.facts["ifrs-full"][concept] : null;
  if (!tax || !tax.units) return [];
  const prefer = units || ["USD", "USD/shares", "shares"];
  const unit = prefer.find(u => Array.isArray(tax.units[u]) && tax.units[u].length)
    || (units ? null : Object.keys(tax.units).find(u => Array.isArray(tax.units[u]) && tax.units[u].length));
  if (!unit) return [];
  const best = new Map();
  for (const f of tax.units[unit]) {
    if (!f || !finite(f.val) || !f.start || !f.end || !FORMS.has(f.form)) continue;
    const key = f.start + "|" + f.end;
    const prev = best.get(key);
    if (!prev || String(f.filed || "") > String(prev.filed || "")) best.set(key, f);
  }
  return [...best.values()];
}

/* Quarter values for one concept: direct three-month facts, then quarters
   recovered from consecutive year-to-date facts with the same start. */
function conceptQuarters(rows, cumulative) {
  const out = new Map();   // end -> { val, derived }
  for (const r of rows) {
    if (isQuarter(days(r.start, r.end))) out.set(r.end, { val: r.val, derived: false, filed: r.filed });
  }
  if (!cumulative) return out;
  const byStart = new Map();
  for (const r of rows) {
    const d = days(r.start, r.end);
    if (d < 70 || d > 380) continue;
    if (!byStart.has(r.start)) byStart.set(r.start, []);
    byStart.get(r.start).push(r);
  }
  for (const list of byStart.values()) {
    list.sort((a, b) => a.end.localeCompare(b.end));
    for (let i = 1; i < list.length; i++) {
      const prev = list[i - 1], cur = list[i];
      if (out.has(cur.end)) continue;
      if (!isQuarter(days(prev.end, cur.end))) continue;
      out.set(cur.end, { val: cur.val - prev.val, derived: true, filed: cur.filed });
    }
  }
  /* Some filers give only three-month figures in their 10-Qs (no
     year-to-date). Then Q4 is the full year less the three quarters inside it. */
  for (const r of rows) {
    const d = days(r.start, r.end);
    if (d < 340 || d > 380 || out.has(r.end)) continue;
    const inside = [...out.entries()].filter(([end]) => end > r.start && end < r.end);
    if (inside.length !== 3) continue;
    out.set(r.end, { val: r.val - inside.reduce((s, [, v]) => s + v.val, 0), derived: true, filed: r.filed });
  }
  return out;
}

function metricQuarters(facts, spec) {
  const perConcept = spec.concepts.map(c => conceptQuarters(conceptRows(facts, c, spec.units), spec.cumulative));
  const merged = new Map();
  const ends = new Set();
  perConcept.forEach(m => m.forEach((_, end) => ends.add(end)));
  for (const end of ends) {
    if (spec.pick === "max") {
      let best = null;
      perConcept.forEach(m => { const v = m.get(end); if (v && (!best || v.val > best.val)) best = v; });
      if (best) merged.set(end, best);
    } else {
      for (const m of perConcept) { const v = m.get(end); if (v) { merged.set(end, v); break; } }
    }
  }
  return merged;
}

/* The same fiscal quarter can carry end dates a day or two apart across tags
   (52/53-week calendars). Snap ends within 6 days of each other together. */
function canonicalEnds(maps) {
  const all = [...new Set(maps.flatMap(m => [...m.keys()]))].sort();
  const canon = new Map();
  let anchor = null;
  for (const e of all) {
    if (anchor && days(anchor, e) <= 6) canon.set(e, anchor);
    else { anchor = e; canon.set(e, e); }
  }
  return canon;
}

function calendarLabel(end) {
  const d = new Date(end + "T00:00:00Z");
  /* A quarter that closes in the first few days of a month belongs to the
     month before (e.g. Apple's 52/53-week quarters ending Dec 28 or Jan 1). */
  const shifted = new Date(d.getTime() - 10 * DAY);
  const q = Math.floor(shifted.getUTCMonth() / 3) + 1;
  return { q, year: shifted.getUTCFullYear(), label: "Q" + q + " " + shifted.getUTCFullYear() };
}

function buildQuarterlyHistory(facts, { maxQuarters = 44 } = {}) {
  const series = {};
  for (const [key, spec] of Object.entries(METRICS)) series[key] = metricQuarters(facts, spec);
  const canon = canonicalEnds([series.revenue, series.netIncome, series.operatingCashFlow, series.eps]);
  const snapped = {};
  for (const [key, m] of Object.entries(series)) {
    const s = new Map();
    m.forEach((v, end) => {
      const c = canon.get(end) || end;
      if (!s.has(c)) s.set(c, v);
    });
    snapped[key] = s;
  }
  const ends = [...new Set([...snapped.revenue.keys(), ...snapped.netIncome.keys()])].sort();
  const rows = ends.map(end => {
    const g = k => snapped[k].get(end);
    const val = k => (g(k) ? g(k).val : null);
    const rev = val("revenue");
    let gp = val("grossProfit");
    let gpDerived = !!(g("grossProfit") && g("grossProfit").derived);
    if (gp == null && rev != null && val("costOfRevenue") != null) { gp = rev - val("costOfRevenue"); gpDerived = true; }
    const ocf = val("operatingCashFlow"), capex = val("capex");
    const cal = calendarLabel(end);
    const derived = [];
    for (const k of Object.keys(METRICS)) if (g(k) && g(k).derived) derived.push(k);
    if (gpDerived && !derived.includes("grossProfit")) derived.push("grossProfit");
    return {
      end, label: cal.label, q: cal.q, year: cal.year,
      revenue: rev, grossProfit: gp, operatingIncome: val("operatingIncome"), netIncome: val("netIncome"),
      eps: val("eps"), operatingCashFlow: ocf, capex: capex == null ? null : Math.abs(capex),
      freeCashFlow: ocf != null && capex != null ? ocf - Math.abs(capex) : null,
      shares: val("shares"), price: null, derived,
    };
  });

  /* Keep only an unbroken run of quarters ending at the latest one: a gap
     would make trailing-twelve-month sums and growth rates wrong. */
  let start = rows.length - 1;
  while (start > 0 && isQuarter(days(rows[start - 1].end, rows[start].end))) start--;
  const run = rows.slice(start).slice(-maxQuarters);

  adjustForSplits(run);

  /* Weighted diluted shares are not reported for Q4 by most filers and can't
     be subtracted out of the annual figure; carry the nearest reported
     quarter across a single-quarter gap. */
  for (let i = 0; i < run.length; i++) {
    if (run[i].shares != null) continue;
    const prev = run[i - 1] && run[i - 1].shares, next = run[i + 1] && run[i + 1].shares;
    if (prev != null && next != null) run[i].shares = Math.sqrt(prev * next);
    else if (prev != null) run[i].shares = prev;
    else if (next != null) run[i].shares = next;
    if (run[i].shares != null) run[i].derived.push("shares");
  }
  return run;
}

/* Older quarters keep the share count and EPS of the filing they came from;
   only the last two or three years get restated after a stock split. Left
   alone, NVIDIA's EPS falls 10x and its share count rises 10x overnight in
   2024. A quarter-on-quarter jump in diluted shares that lands on a whole
   split ratio is treated as a split: earlier shares are scaled up and earlier
   per-share figures down by the same ratio. Prices from Yahoo are already
   split-adjusted. */
function adjustForSplits(rows) {
  const splits = [];
  for (let i = rows.length - 1; i > 0; i--) {
    const b = rows[i].shares;
    let p = i - 1;
    while (p >= 0 && !(rows[p].shares > 0)) p--;       // skip gaps (e.g. Q4)
    if (p < 0 || !(b > 0)) continue;
    const a = rows[p].shares;
    const r = b / a;
    let ratio = null;
    if (r >= 1.8) { const n = Math.round(r); if (Math.abs(r - n) / n < 0.06) ratio = n; else if (Math.abs(r - 1.5) < 0.05) ratio = 1.5; }
    else if (r <= 0.56) { const n = Math.round(1 / r); if (Math.abs(1 / r - n) / n < 0.06) ratio = 1 / n; }
    if (!ratio) continue;
    splits.push({ end: rows[i].end, ratio });
    /* Per-share figures in the gap quarter(s) come from the same older filings. */
    for (let j = 0; j < i; j++) {
      if (rows[j].shares != null) rows[j].shares *= ratio;
      if (rows[j].eps != null) rows[j].eps /= ratio;
      if (rows[j].price != null) rows[j].price /= ratio;
    }
  }
  rows.splits = splits;
  return rows;
}

/* Close on or before each quarter end, from a price series [{time, close}]. */
function attachPrices(rows, prices) {
  if (!Array.isArray(prices) || !prices.length) return rows;
  const sorted = prices.filter(p => p && finite(p.close) && finite(p.time)).sort((a, b) => a.time - b.time);
  for (const row of rows) {
    const t = Date.parse(row.end + "T23:59:59Z") / 1000;
    let lo = 0, hi = sorted.length - 1, hit = -1;
    while (lo <= hi) { const mid = (lo + hi) >> 1; if (sorted[mid].time <= t) { hit = mid; lo = mid + 1; } else hi = mid - 1; }
    if (hit >= 0 && t - sorted[hit].time <= 12 * 86400) row.price = sorted[hit].close;
  }
  return rows;
}

module.exports = { METRICS, buildQuarterlyHistory, attachPrices, adjustForSplits, conceptQuarters, calendarLabel };

"use strict";
/* ═══════════════════════════════════════════════════════════════════════════
   LensScore factor grades.

   Five questions every investor asks, each answered against the company's
   own sector so a bank is not judged like a chipmaker:

     Value          Is the price reasonable for what you get?
     Growth         Is the business getting bigger?
     Profitability  Does it turn sales into profit and returns?
     Health         Can it survive a bad year?
     Momentum       Is the market already rewarding it?

   Every metric is a percentile among sector peers (0 = worst, 100 = best).
   A factor's percentile is the mean of its metrics; its letter grade comes
   from that percentile. The LensScore (0–10) is where the weighted blend of
   the five factors ranks across every company we cover, with caps so one
   failing area can never hide behind four good ones.

   Pure functions; the route supplies the subject's metrics and the peers.
   ═══════════════════════════════════════════════════════════════════════════ */

const VERSION = "2.0.0";

const SECTOR_NAMES = {
  "Tech": "Technology", "Comm.": "Communication", "Health": "Healthcare", "Finance": "Financials",
  "Staples": "Consumer Staples", "Cons.Disc": "Consumer Discretionary", "Energy": "Energy",
  "Materials": "Materials", "Industrials": "Industrials", "Real Est.": "Real Estate", "Utilities": "Utilities",
};

/* dir: +1 higher is better, -1 lower is better.
   worst: "nonpositive" → zero or negative counts as the worst possible reading
          (a P/E on losses), "negative" → only negative values are worst
          (negative equity in debt/equity). */
const FACTORS = [
  {
    key: "value", label: "Value", question: "Is the price reasonable?",
    learn: "Valuation compares the price you pay with what the business produces. A low multiple can mean a bargain or a business in trouble, so read it next to Growth and Profitability.",
    metrics: [
      { k: "peTTM", label: "P/E (last 12 months)", dir: -1, worst: "nonpositive", fmt: "x",
        why: "Share price divided by the last year of earnings per share. Lower means you pay less for each dollar of profit." },
      { k: "forwardPE", label: "P/E (next 12 months)", dir: -1, worst: "nonpositive", fmt: "x",
        why: "Price divided by the profit analysts expect next year. Much lower than the trailing P/E means profits are expected to grow into the price." },
      { k: "pegTTM", label: "PEG ratio", dir: -1, worst: "nonpositive", fmt: "x",
        why: "P/E divided by earnings growth. A high P/E can still be fair when earnings grow fast; around 1 or below is traditionally seen as reasonable." },
      { k: "psTTM", label: "Price / sales", dir: -1, worst: "nonpositive", fmt: "x",
        why: "Company value per dollar of yearly sales. Useful when profits are small or negative." },
      { k: "pfcfShareTTM", label: "Price / free cash flow", dir: -1, worst: "nonpositive", fmt: "x", skip: ["Finance"],
        why: "Price per dollar of cash the business actually keeps after investing. Cash is harder to dress up than earnings." },
      { k: "evEbitdaTTM", label: "EV / EBITDA", dir: -1, worst: "nonpositive", fmt: "x", skip: ["Finance", "Real Est."],
        why: "Whole-company value (including debt) per dollar of operating profit before depreciation. Lets you compare companies with different amounts of debt." },
      { k: "pbQuarterly", label: "Price / book value", dir: -1, worst: "nonpositive", fmt: "x", only: ["Finance", "Real Est."],
        why: "Price per dollar of net assets. The standard yardstick for banks, insurers and property companies." },
    ],
  },
  {
    key: "growth", label: "Growth", question: "Is the business getting bigger?",
    learn: "Growth in sales and earnings is what lets a company's value rise over time. Recent growth tells you about now; three-year growth tells you whether it lasts.",
    metrics: [
      { k: "revenueGrowthTTMYoy", label: "Revenue growth (last 12 months)", dir: 1, fmt: "%",
        why: "How much more the company sold over the last year than the year before." },
      { k: "revenueGrowthQuarterlyYoy", label: "Revenue growth (latest quarter)", dir: 1, fmt: "%",
        why: "Latest quarter versus the same quarter a year ago. Shows whether growth is speeding up or slowing down." },
      { k: "epsGrowthTTMYoy", label: "Earnings-per-share growth", dir: 1, fmt: "%",
        why: "Growth in profit per share. This is what ultimately supports the share price." },
      { k: "revenueGrowth3Y", label: "Revenue growth (3-year average)", dir: 1, fmt: "%",
        why: "Average yearly sales growth over three years. Filters out one lucky year." },
      { k: "epsGrowth3Y", label: "EPS growth (3-year average)", dir: 1, fmt: "%",
        why: "Average yearly growth in profit per share over three years." },
    ],
  },
  {
    key: "profitability", label: "Profitability", question: "Does it make good money?",
    learn: "Profitable businesses fund their own growth instead of borrowing or issuing shares. Margins show how much of each sales dollar is kept; returns show how well invested money is used.",
    metrics: [
      { k: "grossMarginTTM", label: "Gross margin", dir: 1, fmt: "%", skip: ["Finance"],
        why: "Share of each sales dollar left after the direct cost of the product. High gross margins usually signal pricing power." },
      { k: "operatingMarginTTM", label: "Operating margin", dir: 1, fmt: "%",
        why: "Share of sales left after running the whole business, before interest and tax." },
      { k: "netProfitMarginTTM", label: "Net profit margin", dir: 1, fmt: "%",
        why: "Share of sales that ends up as profit for shareholders." },
      { k: "roeTTM", label: "Return on equity", dir: 1, fmt: "%",
        why: "Profit earned per dollar of shareholders' money in the business." },
      { k: "roiTTM", label: "Return on invested capital", dir: 1, fmt: "%", skip: ["Finance"],
        why: "Profit per dollar of all capital invested, debt included. Investors such as Buffett treat a high, steady figure as the mark of a great business." },
    ],
  },
  {
    key: "health", label: "Financial health", question: "Can it survive a bad year?",
    learn: "A strong balance sheet means a company can ride out a recession, keep investing and avoid selling new shares at bad prices. Debt is not bad by itself; too much of it is.",
    metrics: [
      { k: "totalDebt/totalEquityQuarterly", label: "Debt / equity", dir: -1, worst: "negative", fmt: "x",
        why: "Borrowings compared with shareholders' money. Lower means less pressure from lenders in a downturn." },
      { k: "currentRatioQuarterly", label: "Current ratio", dir: 1, fmt: "x", skip: ["Finance"],
        why: "Assets that turn into cash within a year divided by bills due within a year. Above 1 means short-term bills are covered." },
      { k: "netInterestCoverageTTM", label: "Interest coverage", dir: 1, fmt: "x", skip: ["Finance"],
        why: "Operating profit divided by interest owed. A high number means debt payments are easy to meet." },
      { k: "beta", label: "Volatility vs market (beta)", dir: -1, fmt: "num",
        why: "How much the stock has moved compared with the market. 1 moves with the market; 2 swings twice as hard." },
    ],
  },
  {
    key: "momentum", label: "Momentum", question: "Is the market rewarding it?",
    learn: "Stocks that have beaten the market tend to keep doing so for a while, and stocks near their highs attract buyers. Momentum is about timing and sentiment, not about the business itself.",
    metrics: [
      { k: "priceRelativeToS&P50013Week", label: "vs S&P 500, 3 months", dir: 1, fmt: "pp",
        why: "How much the stock beat or lagged the S&P 500 over the last three months." },
      { k: "priceRelativeToS&P50026Week", label: "vs S&P 500, 6 months", dir: 1, fmt: "pp",
        why: "How much the stock beat or lagged the S&P 500 over the last six months." },
      { k: "priceRelativeToS&P50052Week", label: "vs S&P 500, 12 months", dir: 1, fmt: "pp",
        why: "How much the stock beat or lagged the S&P 500 over the last year." },
      { k: "fromHigh", label: "Distance from 52-week high", dir: 1, fmt: "%",
        why: "How far the price sits below its highest point of the past year. Leaders tend to trade near their highs." },
    ],
  },
];

const WEIGHTS = { value: 0.20, growth: 0.20, profitability: 0.25, health: 0.15, momentum: 0.20 };
const CAP_BELOW = { value: 13, profitability: 13, health: 20, growth: 27, momentum: 27 };
const MIN_PEERS = 8;           // fewer sector peers than this → rank against everyone
const MIN_METRIC_PEERS = 5;

const finite = v => v !== null && v !== undefined && v !== "" && Number.isFinite(Number(v));
const round = (v, p = 1) => finite(v) ? Math.round(Number(v) * 10 ** p) / 10 ** p : null;

/* Add derived fields to a metric object (copy). */
function derive(metric = {}, price) {
  const m = { ...metric };
  const hi = Number(m["52WeekHigh"]);
  if (finite(price) && hi > 0) m.fromHigh = (Number(price) / hi - 1) * 100;
  return m;
}

function sortKey(spec, value) {
  if (!finite(value)) return null;
  const v = Number(value);
  if (spec.worst === "nonpositive" && v <= 0) return -Infinity;
  if (spec.worst === "negative" && v < 0) return -Infinity;
  return spec.dir > 0 ? v : -v;
}

function percentileOf(spec, value, peerValues) {
  const x = sortKey(spec, value);
  if (x === null) return null;
  const keys = peerValues.map(v => sortKey(spec, v)).filter(k => k !== null);
  if (keys.length < MIN_METRIC_PEERS) return null;
  let below = 0, equal = 0;
  for (const k of keys) { if (k < x) below++; else if (k === x) equal++; }
  return ((below + equal * 0.5) / keys.length) * 100;
}

function median(values) {
  const v = values.filter(finite).map(Number).sort((a, b) => a - b);
  if (!v.length) return null;
  const mid = Math.floor(v.length / 2);
  return v.length % 2 ? v[mid] : (v[mid - 1] + v[mid]) / 2;
}

const GRADES = [
  [90, "A+"], [80, "A"], [73, "A-"], [67, "B+"], [60, "B"], [53, "B-"],
  [47, "C+"], [40, "C"], [33, "C-"], [27, "D+"], [20, "D"], [13, "D-"], [0, "F"],
];
function gradeFor(pct) {
  if (!finite(pct)) return null;
  for (const [min, g] of GRADES) if (pct >= min) return g;
  return "F";
}
function toneFor(pct) {
  if (!finite(pct)) return "unknown";
  return pct >= 67 ? "strong" : pct >= 47 ? "neutral" : pct >= 27 ? "weak" : "severe";
}
function labelFor(score) {
  if (!finite(score)) return "Not rated";
  if (score >= 8) return "Top-rated";
  if (score >= 6.5) return "Above average";
  if (score >= 4.5) return "Middle of the pack";
  if (score >= 3) return "Below average";
  return "Bottom-rated";
}

function applies(spec, sector) {
  if (spec.only && !spec.only.includes(sector)) return false;
  if (spec.skip && spec.skip.includes(sector)) return false;
  return true;
}

/* Grade one company's metrics against a peer list (rows with .m and .px). */
function gradeAgainst(metric, price, sector, peerRows) {
  const m = derive(metric, price);
  const peerMetrics = peerRows.map(r => derive(r.m || {}, r.px));
  const factors = FACTORS.map(f => {
    const metrics = f.metrics.filter(spec => applies(spec, sector)).map(spec => {
      const peerVals = peerMetrics.map(pm => pm[spec.k]);
      const value = finite(m[spec.k]) ? Number(m[spec.k]) : null;
      const pct = percentileOf(spec, value, peerVals);
      return {
        key: spec.k, label: spec.label, fmt: spec.fmt, why: spec.why, better: spec.dir > 0 ? "higher" : "lower",
        value: round(value, 2), percentile: round(pct, 0), peerMedian: round(median(peerVals.filter(v => sortKey(spec, v) !== null && sortKey(spec, v) !== -Infinity)), 2),
        peers: peerVals.filter(finite).length,
      };
    });
    const scored = metrics.filter(x => finite(x.percentile));
    const pct = scored.length >= 2 ? scored.reduce((s, x) => s + x.percentile, 0) / scored.length : null;
    return { key: f.key, label: f.label, question: f.question, learn: f.learn, percentile: round(pct, 0), grade: gradeFor(pct), tone: toneFor(pct), metrics };
  });
  const usable = factors.filter(f => finite(f.percentile));
  let composite = null;
  if (usable.length >= 4) {
    const w = usable.reduce((s, f) => s + WEIGHTS[f.key], 0);
    composite = usable.reduce((s, f) => s + f.percentile * WEIGHTS[f.key], 0) / w;
  }
  return { factors, composite };
}

function peerGroup(sector, ticker, universe) {
  const same = universe.filter(r => r.s === sector && r.t !== ticker);
  if (same.length >= MIN_PEERS) return { rows: same, basis: "sector" };
  return { rows: universe.filter(r => r.t !== ticker), basis: "all" };
}

/* Caps: a failing factor limits the overall score however good the rest is. */
function caps(factors, metric) {
  const out = [];
  let cap = 100;
  /* Thresholds follow the convention of factor-rating services: weak growth
     or momentum caps sooner than a merely expensive price, because great
     businesses rarely look cheap. */
  const low = factors.filter(f => finite(f.percentile) && f.percentile < (CAP_BELOW[f.key] ?? 20));
  if (low.length >= 2) { cap = Math.min(cap, 50); out.push(`${low.map(f => f.label).join(" and ")} are both failing grades, so the score is held at 5.0 or below.`); }
  else if (low.length === 1) { cap = Math.min(cap, 68); out.push(`${low[0].label} grades ${low[0].grade}, so the score is held at 6.8 or below until it improves.`); }
  const prof = factors.find(f => f.key === "profitability"), health = factors.find(f => f.key === "health");
  if (prof && health && finite(prof.percentile) && finite(health.percentile) && prof.percentile < 15 && health.percentile < 25) {
    cap = Math.min(cap, 40); out.push("Weak profits combined with a weak balance sheet hold the score at 4.0 or below.");
  }
  if (finite(metric?.["totalDebt/totalEquityQuarterly"]) && Number(metric["totalDebt/totalEquityQuarterly"]) < 0) {
    cap = Math.min(cap, 45); out.push("Shareholders' equity is negative (liabilities exceed assets), so the score is held at 4.5 or below.");
  }
  return { cap, notes: out };
}

const fmtNum = (v, fmt) => {
  if (!finite(v)) return "n/a";
  const n = Number(v);
  if (fmt === "%") return `${n >= 0 ? "" : "−"}${Math.abs(n) >= 100 ? Math.abs(n).toFixed(0) : Math.abs(n).toFixed(1)}%`;
  if (fmt === "pp") return `${n >= 0 ? "+" : "−"}${Math.abs(n).toFixed(1)} pts`;
  if (fmt === "x") return `${n < 0 ? "−" : ""}${Math.abs(n) >= 100 ? Math.abs(n).toFixed(0) : Math.abs(n).toFixed(1)}×`;
  return n.toFixed(2);
};

function metricSentence(m, sectorName, basis) {
  const group = basis === "sector" ? `${sectorName} peers` : "companies we cover";
  const pct = Math.round(m.percentile);
  const med = finite(m.peerMedian) ? ` (median ${fmtNum(m.peerMedian, m.fmt)})` : "";
  const head = `${m.label} ${fmtNum(m.value, m.fmt)}`;
  if (pct >= 99) return `${head}: the best among ${group}${med}.`;
  if (pct <= 1) return `${head}: the weakest among ${group}${med}.`;
  if (pct >= 50) return `${head}: better than ${pct}% of ${group}${med}.`;
  return `${head}: weaker than ${100 - pct}% of ${group}${med}.`;
}

function verdictFor(name, factors, metric) {
  const by = Object.fromEntries(factors.map(f => [f.key, f]));
  const p = k => (by[k] && finite(by[k].percentile) ? by[k].percentile : null);
  const parts = [];
  const nm = Number(metric?.netProfitMarginTTM);
  const prof = p("profitability");
  if (finite(nm) && nm < 0) parts.push("is not yet profitable");
  else if (prof !== null) parts.push(prof >= 67 ? "is more profitable than most of its peers" : prof >= 40 ? "is about as profitable as its peers" : "earns thinner profits than its peers");
  const rg = Number(metric?.revenueGrowthTTMYoy), gr = p("growth");
  if (finite(rg) && rg < 0) parts.push("its sales are shrinking");
  else if (gr !== null) parts.push(gr >= 67 ? "it is growing faster than most" : gr >= 40 ? "it is growing at a typical pace" : "it is growing more slowly than its peers");
  const first = parts.length ? `${name} ${parts[0]}${parts[1] ? ` and ${parts[1]}` : ""}.` : "";
  const v = p("value"), h = p("health"), mo = p("momentum");
  const second = [];
  if (v !== null) second.push(v >= 67 ? "the shares look cheap next to similar companies" : v >= 40 ? "the shares are priced roughly in line with similar companies" : "you pay a premium price compared with similar companies");
  if (h !== null) second.push(h >= 67 ? "the balance sheet is strong" : h >= 33 ? "the balance sheet is adequate" : "the balance sheet is a weak spot");
  const sent2 = second.length ? ` ${second[0].charAt(0).toUpperCase()}${second[0].slice(1)}${second[1] ? `, and ${second[1]}` : ""}.` : "";
  const sent3 = mo === null ? "" : mo >= 67 ? " The stock has been beating the market." : mo >= 40 ? " The stock has moved roughly with the market." : " The stock has been lagging the market.";
  return `${first}${sent2}${sent3}`.trim();
}

/* Grade a company. subject: { ticker, name, sector, metric, price }.
   universe: peer rows from lib/peer-universe ({ t, n, s, m, px, mc }). */
function gradeCompany(subject, universe) {
  const ticker = String(subject.ticker || "").toUpperCase();
  const sector = subject.sector || null;
  const sectorName = SECTOR_NAMES[sector] || "all sectors";
  const pool = universe.filter(r => r && r.m && r.t !== ticker);
  if (!sector || pool.length < 20) {
    return { status: "not-rated", version: VERSION, reason: !sector ? "The company's sector is unknown, so it cannot be compared with peers." : "The peer universe is still loading. Try again in a few minutes.", ticker };
  }
  const group = peerGroup(sector, ticker, pool);
  const mine = gradeAgainst(subject.metric || {}, subject.price, sector, group.rows);
  if (!finite(mine.composite)) {
    return { status: "not-rated", version: VERSION, ticker, sector, sectorName, factors: mine.factors,
      reason: "Not enough reported data to grade at least four of the five factors." };
  }

  /* Composite for every company we cover, each against its own sector, so
     the final score is a rank across the whole universe. */
  const composites = [];
  const peerScores = [];
  for (const r of pool) {
    const g = peerGroup(r.s, r.t, pool.concat([{ t: ticker, s: sector, m: subject.metric || {}, px: subject.price }]));
    const res = gradeAgainst(r.m, r.px, r.s, g.rows);
    if (!finite(res.composite)) continue;
    const c = caps(res.factors, r.m);
    composites.push(res.composite);
    if (r.s === sector) peerScores.push({ ticker: r.t, name: r.n, marketCap: r.mc, composite: res.composite, cap: c.cap,
      grades: Object.fromEntries(res.factors.map(f => [f.key, f.grade])) });
  }
  const rankPct = comp => composites.length >= 30
    ? (composites.filter(c => c < comp).length + 0.5 * composites.filter(c => c === comp).length) / composites.length * 100
    : Math.max(0, Math.min(100, 50 + (comp - 50) * 1.6));
  const capInfo = caps(mine.factors, subject.metric);
  const raw = rankPct(mine.composite);
  const score100 = Math.min(raw, capInfo.cap);
  /* Never print a perfect 10 or a flat 0: a rank is relative to the set we
     cover, not a certainty. */
  const clampScore = v => Math.max(0.1, Math.min(9.9, v));
  const score = round(clampScore(score100 / 10), 1);
  peerScores.forEach(p => { p.score = round(clampScore(Math.min(rankPct(p.composite), p.cap) / 10), 1); });
  const ranked = peerScores.concat([{ ticker, name: subject.name || ticker, marketCap: subject.marketCap || null, score, self: true,
    grades: Object.fromEntries(mine.factors.map(f => [f.key, f.grade])) }])
    .sort((a, b) => b.score - a.score || (b.marketCap || 0) - (a.marketCap || 0));
  const position = ranked.findIndex(p => p.self) + 1;

  const allMetrics = mine.factors.flatMap(f => f.metrics.filter(m => finite(m.percentile)).map(m => ({ ...m, factor: f.label })));
  const strengths = allMetrics.filter(m => m.percentile >= 75).sort((a, b) => b.percentile - a.percentile).slice(0, 4)
    .map(m => ({ factor: m.factor, text: metricSentence(m, sectorName, group.basis) }));
  const watch = allMetrics.filter(m => m.percentile <= 25).sort((a, b) => a.percentile - b.percentile).slice(0, 4)
    .map(m => ({ factor: m.factor, text: metricSentence(m, sectorName, group.basis) }));

  return {
    status: "graded",
    version: VERSION,
    ticker,
    sector,
    sectorName,
    basis: group.basis,
    peerCount: group.rows.length,
    universeCount: composites.length,
    score,
    label: labelFor(score),
    tone: score >= 8 ? "strong" : score >= 6.5 ? "positive" : score >= 4.5 ? "neutral" : score >= 3 ? "weak" : "severe",
    uncapped: round(raw / 10, 1),
    caps: capInfo.notes,
    rank: { position, of: ranked.length, sectorName },
    verdict: verdictFor(subject.name || ticker, mine.factors, subject.metric),
    factors: mine.factors,
    weights: WEIGHTS,
    strengths,
    watch,
    peers: ranked.slice(0, 12).concat(position > 12 ? [ranked[position - 1]] : [])
      .map(p => ({ ticker: p.ticker, name: p.name, score: p.score, grades: p.grades, self: !!p.self, rank: ranked.indexOf(p) + 1 })),
  };
}

/* Grade every company in the universe at once (screener, leaderboard,
   history). Each company is graded against its own sector, then ranked
   across the whole set exactly as gradeCompany ranks a single company. */
function gradeUniverse(universe) {
  const pool = universe.filter(r => r && r.m && r.s);
  const rows = [];
  for (const r of pool) {
    const g = peerGroup(r.s, r.t, pool);
    const res = gradeAgainst(r.m, r.px, r.s, g.rows);
    if (!finite(res.composite)) continue;
    rows.push({ r, res, cap: caps(res.factors, r.m).cap });
  }
  const composites = rows.map(x => x.res.composite);
  const rankPct = comp => composites.length >= 30
    ? (composites.filter(c => c < comp).length + 0.5 * composites.filter(c => c === comp).length) / composites.length * 100
    : Math.max(0, Math.min(100, 50 + (comp - 50) * 1.6));
  const out = rows.map(({ r, res, cap }) => {
    const score = round(Math.max(0.1, Math.min(9.9, Math.min(rankPct(res.composite), cap) / 10)), 1);
    return {
      ticker: r.t, name: r.n, sector: r.s, sectorName: SECTOR_NAMES[r.s] || r.s, price: r.px || null, marketCap: r.mc || null,
      score, label: labelFor(score),
      grades: Object.fromEntries(res.factors.map(f => [f.key, f.grade])),
      percentiles: Object.fromEntries(res.factors.map(f => [f.key, f.percentile])),
    };
  });
  const bySector = {};
  out.forEach(o => { (bySector[o.sector] = bySector[o.sector] || []).push(o); });
  Object.values(bySector).forEach(list => {
    list.sort((a, b) => b.score - a.score || (b.marketCap || 0) - (a.marketCap || 0));
    list.forEach((o, i) => { o.sectorRank = i + 1; o.sectorCount = list.length; });
  });
  return out.sort((a, b) => b.score - a.score);
}

const GRADE_ORDER = ["F", "D-", "D", "D+", "C-", "C", "C+", "B-", "B", "B+", "A-", "A", "A+"];
const gradeAtLeast = (g, min) => !min || (g && GRADE_ORDER.indexOf(g) >= GRADE_ORDER.indexOf(min));

module.exports = { gradeUniverse, gradeAtLeast, GRADE_ORDER, VERSION, FACTORS, WEIGHTS, gradeCompany, gradeAgainst, percentileOf, gradeFor, labelFor, derive, fmtNum, SECTOR_NAMES };

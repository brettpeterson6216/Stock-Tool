"use strict";
/* ═══════════════════════════════════════════════════════════════════════════
   Company fundamentals from SEC EDGAR, for LensScore and the stock pages.

   SEC filings are public and free to use commercially. This module turns a
   company's XBRL facts (data.sec.gov companyfacts) and its filing index
   (data.sec.gov submissions) into:

     · a profile: name, SIC industry code → sector, fiscal year end;
     · a snapshot of reported figures: trailing-twelve-month revenue, profit,
       cash flow, the latest balance sheet, growth rates (no price needed);
     · metrics in the keys the grades already use (peTTM, grossMarginTTM,
       priceRelativeToS&P50013Week…), once a price history is supplied.

   SEC asks for at most 10 requests a second with a contact in the
   User-Agent; requests here are spaced to stay well under that.
   ═══════════════════════════════════════════════════════════════════════════ */

const { buildQuarterlyHistory, adjustForSplits } = require("./fundamentals-history");

const SEC_USER_AGENT = process.env.SEC_USER_AGENT || "ImpliedLens/1.2 support@impliedlens.com";
const MIN_GAP_MS = 150;                       // ≤ ~7 requests a second
const finite = v => v !== null && v !== undefined && v !== "" && Number.isFinite(Number(v));
const num = v => (finite(v) ? Number(v) : null);
const pct = (a, b) => (finite(a) && finite(b) && Number(b) !== 0 ? (Number(a) / Number(b)) * 100 : null);
const growth = (now, then) => (finite(now) && finite(then) && Number(then) > 0 ? (Number(now) / Number(then) - 1) * 100 : null);

/* ── polite SEC fetch ──────────────────────────────────────────────────── */
let nextSlot = 0;
async function secJson(url, timeoutMs = 15000) {
  const wait = Math.max(0, nextSlot - Date.now());
  nextSlot = Math.max(Date.now(), nextSlot) + MIN_GAP_MS;
  if (wait) await new Promise(r => setTimeout(r, wait));
  const r = await fetch(url, { headers: { "User-Agent": SEC_USER_AGENT, Accept: "application/json" }, signal: AbortSignal.timeout(timeoutMs) });
  if (!r.ok) throw Object.assign(new Error(`SEC returned ${r.status}`), { status: r.status });
  return r.json();
}
async function secText(url, timeoutMs = 12000) {
  const wait = Math.max(0, nextSlot - Date.now());
  nextSlot = Math.max(Date.now(), nextSlot) + MIN_GAP_MS;
  if (wait) await new Promise(r => setTimeout(r, wait));
  const r = await fetch(url, { headers: { "User-Agent": SEC_USER_AGENT, Accept: "text/xml,application/xml,text/plain,*/*" }, signal: AbortSignal.timeout(timeoutMs) });
  if (!r.ok) throw Object.assign(new Error(`SEC returned ${r.status}`), { status: r.status });
  return r.text();
}

/* ── ticker → CIK ──────────────────────────────────────────────────────── */
let tickerMap = null, tickerMapAt = 0;
async function cikFor(ticker) {
  if (!tickerMap || Date.now() - tickerMapAt > 24 * 3600 * 1000) {
    const data = await secJson("https://www.sec.gov/files/company_tickers.json");
    tickerMap = new Map(Object.values(data || {}).map(e => [String(e.ticker || "").toUpperCase(), { cik: String(e.cik_str || "").padStart(10, "0"), name: e.title }]));
    tickerMapAt = Date.now();
  }
  const t = String(ticker || "").toUpperCase();
  return tickerMap.get(t) || tickerMap.get(t.replace(".", "-")) || tickerMap.get(t.replace("-", ".")) || null;
}

/* ── submissions (filing index) ────────────────────────────────────────── */
const subCache = new Map();
/* `cache: false` for the background pass over the graded universe: a big
   filer's index is ~1MB, and keeping a thousand of them would crowd out the
   ones people are actually reading. */
async function submissions(ticker, { cache = true } = {}) {
  const id = await cikFor(ticker);
  if (!id) throw new Error("No SEC filer for this ticker.");
  const hit = subCache.get(id.cik);
  if (hit && Date.now() - hit.at < 6 * 3600 * 1000) return hit.data;
  const data = await secJson(`https://data.sec.gov/submissions/CIK${id.cik}.json`);
  if (!cache) return data;
  subCache.set(id.cik, { at: Date.now(), data });
  if (subCache.size > 600) subCache.delete(subCache.keys().next().value);
  return data;
}

/* Pure: the recent-filings table as rows. */
function recentFilings(sub) {
  const r = sub?.filings?.recent || {};
  const n = Array.isArray(r.form) ? r.form.length : 0;
  const out = [];
  for (let i = 0; i < n; i += 1) {
    out.push({
      form: r.form[i], filingDate: r.filingDate?.[i], reportDate: r.reportDate?.[i] || null,
      accession: r.accessionNumber?.[i], primaryDocument: r.primaryDocument?.[i] || null,
      items: String(r.items?.[i] || ""), acceptance: r.acceptanceDateTime?.[i] || null,
    });
  }
  return out;
}

/* SIC industry code → our sector buckets (GICS-like). A handful of large
   companies whose SIC code puts them in the wrong bucket are pinned. */
const SECTOR_PINS = {
  GOOGL: "Comm.", GOOG: "Comm.", META: "Comm.", NFLX: "Comm.", DIS: "Comm.", CMCSA: "Comm.", T: "Comm.", VZ: "Comm.", TMUS: "Comm.",
  CHTR: "Comm.", EA: "Comm.", TTWO: "Comm.", WBD: "Comm.", PARA: "Comm.", SPOT: "Comm.", RDDT: "Comm.", PINS: "Comm.", SNAP: "Comm.",
  AMZN: "Cons.Disc", TSLA: "Cons.Disc", HD: "Cons.Disc", LOW: "Cons.Disc", MCD: "Cons.Disc", SBUX: "Cons.Disc", NKE: "Cons.Disc", BKNG: "Cons.Disc",
  WMT: "Staples", COST: "Staples", KR: "Staples", DG: "Staples", DLTR: "Staples", TGT: "Staples", BJ: "Staples", SYY: "Staples", ACI: "Staples",
  V: "Finance", MA: "Finance", PYPL: "Finance", AXP: "Finance", SOFI: "Finance", HOOD: "Finance", COIN: "Finance", AFRM: "Finance",
  UBER: "Industrials", LYFT: "Industrials", ADP: "Industrials", PAYX: "Industrials",
  PLTR: "Tech", CRM: "Tech", ORCL: "Tech", ADBE: "Tech", NOW: "Tech", IBM: "Tech", ACN: "Tech",
  AMT: "Real Est.", PLD: "Real Est.", CCI: "Real Est.", EQIX: "Real Est.",
  LIN: "Materials", HIMS: "Health",
  /* SIC files these under business services or water transport; GICS puts
     them in Consumer Discretionary (travel, delivery, marketplaces) or
     Industrials. */
  ABNB: "Cons.Disc", EXPE: "Cons.Disc", DASH: "Cons.Disc", EBAY: "Cons.Disc", ETSY: "Cons.Disc", CPNG: "Cons.Disc",
  RCL: "Cons.Disc", CCL: "Cons.Disc", NCLH: "Cons.Disc", CVNA: "Cons.Disc", CPRT: "Industrials",
};
function sectorFromSic(sic, ticker) {
  const t = String(ticker || "").toUpperCase();
  if (SECTOR_PINS[t]) return SECTOR_PINS[t];
  const s = Number(sic);
  if (!finite(s) || s <= 0) return null;
  const between = (a, b) => s >= a && s <= b;
  if (between(2830, 2836) || between(3841, 3851) || between(8000, 8099) || s === 5122 || s === 5047) return "Health";
  if (between(6798, 6798) || between(6500, 6553)) return "Real Est.";
  if (between(6000, 6799)) return "Finance";
  if (between(4900, 4991)) return "Utilities";
  if (between(4800, 4899) || between(2710, 2799) || between(7800, 7849)) return "Comm.";
  if (between(1300, 1389) || between(2900, 2999) || between(4610, 4619) || between(1200, 1241)) return "Energy";
  if (between(3570, 3579) || between(3600, 3699) || between(3810, 3829) || between(7370, 7379) || between(3661, 3679)) return "Tech";
  if (between(2000, 2199) || between(2840, 2844) || between(5400, 5499) || between(5140, 5149) || between(5180, 5182) || s === 5912 || s === 5331) return "Staples";
  if (between(1000, 1099) || between(1400, 1499) || between(2600, 2699) || between(2800, 2829) || between(2850, 2899) || between(3200, 3299) || between(3300, 3399) || between(2400, 2499)) return "Materials";
  if (between(3710, 3716) || between(3750, 3751) || between(2200, 2399) || between(3140, 3199) || between(5200, 5999) || between(7000, 7099) || between(5800, 5899) || between(7900, 7999) || between(1520, 1531) || s === 3630 || s === 3944 || s === 3949) return "Cons.Disc";
  if (between(1500, 1799) || between(3400, 3569) || between(3580, 3599) || between(3700, 3799) || between(3800, 3899) || between(4000, 4799) || between(7300, 7369) || between(7380, 7399) || between(8700, 8799) || between(5000, 5099) || between(3900, 3999)) return "Industrials";
  return null;
}

/* ── company facts → snapshot (pure) ───────────────────────────────────── */
function factRows(facts, concepts, units = ["USD"]) {
  const out = [];
  for (const tax of ["us-gaap", "ifrs-full", "dei"]) {
    const t = facts?.facts?.[tax] || {};
    for (const c of concepts) {
      const u = t[c]?.units || {};
      const unit = units.find(x => Array.isArray(u[x]));
      if (!unit) continue;
      u[unit].forEach(f => { if (finite(f.val) && f.end && f.filed) out.push({ ...f, concept: c }); });
    }
  }
  return out;
}
/* Latest value of a balance-sheet (instant) concept, from 10-K/10-Q. */
function latestInstant(facts, concepts, units = ["USD"]) {
  const rows = factRows(facts, concepts, units).filter(f => !f.start && /^(10-K|10-Q|20-F|40-F)/.test(f.form || ""));
  if (!rows.length) return null;
  rows.sort((a, b) => a.end.localeCompare(b.end) || a.filed.localeCompare(b.filed));
  const end = rows.at(-1).end;
  for (const c of concepts) {
    const hit = rows.filter(r => r.end === end && r.concept === c).at(-1);
    if (hit) return { val: Number(hit.val), end, filed: hit.filed };
  }
  return null;
}
/* Full-year values of a duration concept (10-K), newest last. */
function annualValues(facts, concepts, units = ["USD"]) {
  const rows = factRows(facts, concepts, units).filter(f => f.start && /^(10-K|20-F|40-F)/.test(f.form || ""))
    .filter(f => { const d = (Date.parse(f.end) - Date.parse(f.start)) / 864e5; return d >= 340 && d <= 380; });
  const byEnd = new Map();
  for (const c of concepts) {
    rows.filter(r => r.concept === c).forEach(r => {
      const prev = byEnd.get(r.end);
      if (!prev || (prev.concept === c && r.filed > prev.filed)) byEnd.set(r.end, r);
    });
  }
  return [...byEnd.values()].sort((a, b) => a.end.localeCompare(b.end)).map(r => ({ end: r.end, val: Number(r.val) }));
}

const C = {
  equity: ["StockholdersEquity", "StockholdersEquityIncludingPortionAttributableToNoncontrollingInterest"],
  assets: ["Assets"],
  cash: ["CashAndCashEquivalentsAtCarryingValue", "CashCashEquivalentsRestrictedCashAndRestrictedCashEquivalents", "Cash"],
  currentAssets: ["AssetsCurrent"],
  currentLiabilities: ["LiabilitiesCurrent"],
  debtTotal: ["LongTermDebt", "DebtLongtermAndShorttermCombinedAmount"],
  debtNoncurrent: ["LongTermDebtNoncurrent", "LongTermDebtAndCapitalLeaseObligations", "LongTermDebtAndFinanceLeaseObligationsNoncurrent"],
  debtCurrent: ["LongTermDebtCurrent", "LongTermDebtAndCapitalLeaseObligationsCurrent", "DebtCurrent"],
  shortTerm: ["ShortTermBorrowings", "CommercialPaper"],
  interest: ["InterestExpense", "InterestExpenseNonoperating", "InterestExpenseDebt", "InterestPaidNet"],
  da: ["DepreciationDepletionAndAmortization", "DepreciationAndAmortization", "DepreciationAmortizationAndAccretionNet", "Depreciation"],
  sharesOut: ["EntityCommonStockSharesOutstanding", "CommonStockSharesOutstanding"],
  dps: ["CommonStockDividendsPerShareDeclared", "CommonStockDividendsPerShareCashPaid"],
  tax: ["IncomeTaxExpenseBenefit"],
  pretax: ["IncomeLossFromContinuingOperationsBeforeIncomeTaxesExtraordinaryItemsNoncontrollingInterest", "IncomeLossFromContinuingOperationsBeforeIncomeTaxesMinorityInterestAndIncomeLossFromEquityMethodInvestments", "IncomeLossFromContinuingOperationsBeforeIncomeTaxesDomestic"],
};

/* Pure: the company's facts as they stood on `day` — every figure filed after
   it removed. Each SEC fact carries the date it was filed, so this rebuilds
   exactly what an investor could have known then (the point-in-time view the
   LensScore backtest uses; restated figures appear only once restated). */
function factsAsOf(facts, day) {
  const cut = String(day || "");
  if (!cut || !facts?.facts) return facts;
  const out = { ...facts, facts: {} };
  for (const [tax, concepts] of Object.entries(facts.facts)) {
    const t = {};
    for (const [name, c] of Object.entries(concepts || {})) {
      const units = {};
      for (const [u, list] of Object.entries(c?.units || {})) {
        const kept = (list || []).filter(f => f && f.filed && f.filed <= cut);
        if (kept.length) units[u] = kept;
      }
      if (Object.keys(units).length) t[name] = { ...c, units };
    }
    out.facts[tax] = t;
  }
  return out;
}

function snapshotFromFacts(facts) {
  let q = buildQuarterlyHistory(facts, { maxQuarters: 20 });
  try { q = adjustForSplits(q) || q; } catch (_) { /* keep unadjusted */ }
  const sum = (rows, k) => (rows.length === 4 && rows.every(r => finite(r[k])) ? rows.reduce((s, r) => s + Number(r[k]), 0) : null);
  const last4 = q.slice(-4), prev4 = q.slice(-8, -4);
  const lastQ = q.at(-1) || null, yearAgoQ = q.length >= 5 ? q.at(-5) : null;
  const ttm = {
    revenue: sum(last4, "revenue"), grossProfit: sum(last4, "grossProfit"), operatingIncome: sum(last4, "operatingIncome"),
    netIncome: sum(last4, "netIncome"), eps: sum(last4, "eps"), operatingCashFlow: sum(last4, "operatingCashFlow"),
    capex: sum(last4, "capex"), freeCashFlow: sum(last4, "freeCashFlow"),
  };
  const prevTtm = { revenue: sum(prev4, "revenue"), eps: sum(prev4, "eps"), netIncome: sum(prev4, "netIncome") };

  const annRev = annualValues(facts, ["Revenues", "RevenueFromContractWithCustomerExcludingAssessedTax", "SalesRevenueNet", "RevenuesNetOfInterestExpense"]);
  const annEps = annualValues(facts, ["EarningsPerShareDiluted", "EarningsPerShareBasicAndDiluted", "EarningsPerShareBasic"], ["USD/shares"]);
  const cagr = (rows) => {
    if (rows.length < 4) return null;
    const a = rows.at(-4).val, b = rows.at(-1).val;
    return a > 0 && b > 0 ? (Math.pow(b / a, 1 / 3) - 1) * 100 : null;
  };

  const inst = k => latestInstant(facts, C[k]);
  /* LongTermDebt already includes its current portion; short-term
     borrowings and commercial paper sit outside it. */
  const debtTotal = inst("debtTotal");
  const shortTerm = num(inst("shortTerm")?.val) || 0;
  const parts = (num(inst("debtNoncurrent")?.val) || 0) + (num(inst("debtCurrent")?.val) || 0);
  const debt = debtTotal ? debtTotal.val + shortTerm : (parts + shortTerm) || (inst("equity") ? 0 : null);
  const sharesOut = latestInstant(facts, C.sharesOut, ["shares"]);
  const interestA = annualValues(facts, C.interest).at(-1);
  const daA = annualValues(facts, C.da).at(-1);
  const dpsA = annualValues(facts, C.dps, ["USD/shares"]).at(-1);
  /* Effective tax rate from the last annual report, for after-tax operating
     profit (ROIC). Held to 0-35%; 21% (the US federal rate) when not
     reported or not meaningful (a pre-tax loss). */
  const taxA = annualValues(facts, C.tax).at(-1), preA = annualValues(facts, C.pretax).at(-1);
  const taxRate = taxA && preA && preA.val > 0 && taxA.end === preA.end ? Math.max(0, Math.min(0.35, taxA.val / preA.val)) : 0.21;
  const filed = Object.values(facts?.facts || {}).flatMap(t => Object.values(t || {})).flatMap(c => Object.values(c?.units || {})).flat()
    .map(f => f?.filed).filter(Boolean).sort().at(-1) || null;

  return {
    name: facts?.entityName || null,
    asOf: filed,
    quarterEnd: lastQ?.end || null,
    quarters: q.length,
    ttm, prevTtm,
    lastQuarterRevenue: lastQ?.revenue ?? null,
    yearAgoQuarterRevenue: yearAgoQ?.revenue ?? null,
    revenueCagr3Y: cagr(annRev), epsCagr3Y: cagr(annEps),
    equity: num(inst("equity")?.val), assets: num(inst("assets")?.val), cash: num(inst("cash")?.val),
    currentAssets: num(inst("currentAssets")?.val), currentLiabilities: num(inst("currentLiabilities")?.val),
    debt: finite(debt) ? Number(debt) : null,
    interestExpense: interestA ? Math.abs(interestA.val) : null,
    depreciation: daA ? Math.abs(daA.val) : null,
    dividendsPerShare: dpsA ? dpsA.val : null,
    taxRate,
    /* The cover-page share count is occasionally filed for one class only or
       in the wrong unit (Simon Property: a few thousand shares, so a $1.7M
       market cap). When it is under a fifth of the diluted weighted count,
       the weighted count is the better figure. */
    sharesOutstanding: (() => {
      const cover = num(sharesOut?.val), weighted = num(lastQ?.shares);
      if (cover && weighted && cover < weighted * 0.2) return weighted;
      return cover || weighted;
    })(),
  };
}

/* ── price-based figures (pure) ────────────────────────────────────────── */
function closeOnOrBefore(rows, day) {
  for (let i = rows.length - 1; i >= 0; i -= 1) if (rows[i].day <= day) return rows[i].close;
  return null;
}
function returnOver(rows, weeks) {
  if (!rows?.length) return null;
  const last = rows.at(-1);
  const from = new Date(Date.parse(last.day + "T12:00:00Z") - weeks * 7 * 864e5).toISOString().slice(0, 10);
  if (rows[0].day > from) return null;
  const then = closeOnOrBefore(rows, from);
  return growth(last.close, then);
}
/* Weekly-return beta against the benchmark over up to two years. */
function betaOf(rows, bench) {
  if (!rows?.length || !bench?.length) return null;
  const weekly = list => {
    const out = new Map();
    list.forEach(r => { const d = new Date(r.day + "T12:00:00Z"); const k = new Date(d - ((d.getUTCDay() + 6) % 7) * 864e5).toISOString().slice(0, 10); out.set(k, r.close); });
    return out;
  };
  const a = weekly(rows), b = weekly(bench);
  const keys = [...a.keys()].filter(k => b.has(k)).sort();
  const ra = [], rb = [];
  for (let i = 1; i < keys.length; i += 1) {
    const x0 = a.get(keys[i - 1]), x1 = a.get(keys[i]), y0 = b.get(keys[i - 1]), y1 = b.get(keys[i]);
    if (x0 > 0 && y0 > 0) { ra.push(x1 / x0 - 1); rb.push(y1 / y0 - 1); }
  }
  if (ra.length < 26) return null;
  const mean = v => v.reduce((s, x) => s + x, 0) / v.length;
  const ma = mean(ra), mb = mean(rb);
  let cov = 0, varb = 0;
  for (let i = 0; i < ra.length; i += 1) { cov += (ra[i] - ma) * (rb[i] - mb); varb += (rb[i] - mb) ** 2; }
  return varb > 0 ? cov / varb : null;
}

/* ── share basis (pure) ────────────────────────────────────────────────
   SEC figures are per the issuer's reporting share; the quote is for the
   class that trades. For most companies they are the same. Berkshire files
   EPS and share counts in Class A equivalents, while BRK.B trades at 1/1500
   of a Class A share, so the quoted price must be paired with A-equivalent
   shares x 1500 and EPS / 1500 (10-Q Note 18). Without this the market cap
   came out near $0.5B and every value ratio near zero. */
const QUOTED_CLASS_RATIO = { "BRK.B": 1500, "BRK-B": 1500, "BRK/B": 1500 };
function quoteBasis(snap, { ticker = "", price = null } = {}) {
  const s = snap || {}, t = s.ttm || {};
  const ratio = QUOTED_CLASS_RATIO[String(ticker || "").toUpperCase()] || 1;
  /* The share count the income statement used: earnings over EPS. */
  const implied = finite(t.netIncome) && finite(t.eps) && Math.abs(t.eps) > 0.01 ? Math.abs(t.netIncome / t.eps) : null;
  let reporting = finite(s.sharesOutstanding) && implied && s.sharesOutstanding < implied * 0.2 ? implied : s.sharesOutstanding;
  if (ratio !== 1 && implied) reporting = implied;
  const shares = finite(reporting) ? reporting * ratio : null;
  const eps = finite(t.eps) ? t.eps / ratio : null;
  const px = finite(price) ? Number(price) : null;
  const mcap = finite(px) && finite(shares) ? px * shares : null;
  /* Plausibility: a listed company valued at under 2% of a year's sales,
     or at under one year of earnings, is a share-basis error, not a
     bargain. Such figures are kept out of grading and display. */
  const ps = finite(mcap) && finite(t.revenue) && t.revenue > 0 ? mcap / t.revenue : null;
  const pe = finite(px) && finite(eps) && eps > 0 ? px / eps : null;
  const plausible = !(ps !== null && ps < 0.02) && !(pe !== null && pe < 1);
  return { ratio, shares, eps, mcap, plausible };
}

/* Snapshot + prices → metrics in the keys lib/lens-factors.js grades.
   `rows` and `bench` are daily closes [{ day, close, high }] oldest first. */
function metricsFrom(snap, { price = null, rows = [], bench = [], ticker = "" } = {}) {
  const m = {};
  const set = (k, v) => { if (finite(v)) m[k] = Number(v); };
  const s = snap || {};
  const t = s.ttm || {};
  const px = finite(price) ? Number(price) : (rows.at(-1)?.close ?? null);
  const basis = quoteBasis(s, { ticker, price: px });
  const mcap = basis.plausible ? basis.mcap : null;
  const qEps = basis.eps;

  // Growth
  set("revenueGrowthTTMYoy", growth(t.revenue, s.prevTtm?.revenue));
  set("revenueGrowthQuarterlyYoy", growth(s.lastQuarterRevenue, s.yearAgoQuarterRevenue));
  set("epsGrowthTTMYoy", growth(t.eps, s.prevTtm?.eps));
  set("revenueGrowth3Y", s.revenueCagr3Y);
  set("epsGrowth3Y", s.epsCagr3Y);
  // Profitability
  set("grossMarginTTM", pct(t.grossProfit, t.revenue));
  set("operatingMarginTTM", pct(t.operatingIncome, t.revenue));
  set("netProfitMarginTTM", pct(t.netIncome, t.revenue));
  if (finite(s.equity) && s.equity > 0) set("roeTTM", pct(t.netIncome, s.equity));
  /* Return on invested capital: after-tax operating profit over the capital
     the business uses (debt + equity − cash). */
  const invested = (finite(s.debt) ? s.debt : 0) + (finite(s.equity) ? s.equity : 0) - (finite(s.cash) ? s.cash : 0);
  const nopat = finite(t.operatingIncome) ? t.operatingIncome * (1 - (finite(s.taxRate) ? s.taxRate : 0.21)) : null;
  if (invested > 0 && finite(nopat)) set("roiTTM", pct(nopat, invested));
  /* Capital ratio: the standard solvency yardstick for banks and insurers,
     whose debt and current ratios mean something else. */
  if (finite(s.equity) && finite(s.assets) && s.assets > 0) set("equityToAssetsQuarterly", pct(s.equity, s.assets));
  // Health
  if (finite(s.equity) && s.equity !== 0 && finite(s.debt)) set("totalDebt/totalEquityQuarterly", s.debt / s.equity);
  if (finite(s.currentAssets) && finite(s.currentLiabilities) && s.currentLiabilities > 0) set("currentRatioQuarterly", s.currentAssets / s.currentLiabilities);
  if (finite(t.operatingIncome) && finite(s.interestExpense) && s.interestExpense > 0) set("netInterestCoverageTTM", t.operatingIncome / s.interestExpense);
  set("beta", betaOf(rows, bench));
  // Value
  if (finite(px)) {
    if (basis.plausible && finite(qEps) && qEps !== 0) set("peTTM", px / qEps);
    if (finite(mcap)) {
      set("marketCapitalization", mcap / 1e6);
      if (finite(t.revenue) && t.revenue > 0) set("psTTM", mcap / t.revenue);
      if (finite(t.freeCashFlow) && t.freeCashFlow !== 0) set("pfcfShareTTM", mcap / t.freeCashFlow);
      if (finite(s.equity) && s.equity !== 0) set("pbQuarterly", mcap / s.equity);
      const ebitda = finite(t.operatingIncome) ? t.operatingIncome + (finite(s.depreciation) ? s.depreciation : 0) : null;
      const ev = mcap + (finite(s.debt) ? s.debt : 0) - (finite(s.cash) ? s.cash : 0);
      if (finite(ebitda) && ebitda !== 0) set("evEbitdaTTM", ev / ebitda);
    }
    const g = finite(m.epsGrowth3Y) ? m.epsGrowth3Y : m.epsGrowthTTMYoy;
    if (finite(m.peTTM) && m.peTTM > 0 && finite(g) && g > 0) set("pegTTM", m.peTTM / g);
    if (finite(s.dividendsPerShare) && s.dividendsPerShare > 0) set("dividendYieldIndicatedAnnual", (s.dividendsPerShare / px) * 100);
  }
  // Momentum and range
  if (rows.length) {
    const year = rows.filter(r => r.day >= new Date(Date.parse(rows.at(-1).day + "T12:00:00Z") - 365 * 864e5).toISOString().slice(0, 10));
    const hi = Math.max(...year.map(r => Number(r.high ?? r.close)).filter(finite));
    const lo = Math.min(...year.map(r => Number(r.low ?? r.close)).filter(finite));
    if (finite(hi)) set("52WeekHigh", hi);
    if (finite(lo)) set("52WeekLow", lo);
    for (const [w, k] of [[13, "13Week"], [26, "26Week"], [52, "52Week"]]) {
      const own = returnOver(rows, w);
      set(`${k}PriceReturnDaily`, own);
      const b = returnOver(bench, w);
      if (finite(own) && finite(b)) set(`priceRelativeToS&P500${k}`, own - b);
    }
  }
  return m;
}

module.exports = {
  submissions, recentFilings, cikFor, sectorFromSic, snapshotFromFacts, metricsFrom, quoteBasis, betaOf, returnOver,
  secJson, secText, SEC_USER_AGENT, factsAsOf,
};

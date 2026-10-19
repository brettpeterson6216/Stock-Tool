// ============================================================
//  Financials routes — all Pro-gated
//    GET /api/financials/:ticker
//    GET /api/earnings/:ticker
//    GET /api/calls/:ticker
//    GET /api/calls/:ticker/:id
//    GET /api/metrics/:ticker
//    GET /api/me/limit              (free — quota info)
//    GET /api/sec/:ticker
//    GET /api/estimates/:ticker
//    GET /api/analyst/:ticker
//    GET /api/institutional/:ticker
//    GET /api/darkpool/:ticker (legacy path; returns FINRA OTC activity)
// ============================================================
const { ttmFromFacts, matchedTtm, latestDilutedShares, latestSharesFromFacts } = require("../lib/ttm");
const express = require("express");

const { FINNHUB_KEY }  = require("../lib/config");
const { db }           = require("../lib/db");
const { requirePro, requireAccount, reconcileEffectivePlan, normalizeTicker, FREE_DAILY_LIMIT, GUEST_DAILY_LIMIT } = require("../lib/plan");
const { deriveEarnings, loadCompanyFacts, loadFinnhubResearch, loadPriceHistory } = require("../lib/stock-research");

const { buildQuarterlyHistory, attachPrices } = require("../lib/fundamentals-history");
const secUniverse = require("../lib/sec-universe");
const secFilings = require("../lib/sec-filings");
const sec13f = require("../lib/sec-13f");
const secEarnings = require("../lib/sec-earnings");
const prices = require("../lib/prices");
const router = express.Router();
const UA     = "ImpliedLens/1.0 brettpeterson6216@gmail.com";

function requestTicker(req, res) {
  const ticker = normalizeTicker(req.params.ticker);
  if (!ticker) res.status(400).json({ error: "Invalid ticker." });
  return ticker;
}

/* Discount rate for the DCF tools. Cost of equity from a Blume-adjusted beta
   (raw betas overstate the extremes), a 4.3% risk-free rate and a 5% equity
   premium, blended with an after-tax cost of debt by a debt/equity ratio.
   The old formula used the raw beta alone and gave NVDA 16.9%. */
function suggestDiscountRate(beta, debtToEquityPct) {
  const b = Number(beta);
  if (!Number.isFinite(b) || b <= 0) return null;
  const adj = 0.67 * b + 0.33;
  const costEquity = 4.3 + adj * 5;
  const de = Number(debtToEquityPct);
  // Capped at 1:1 so a bank's deposit funding cannot drag it to the floor.
  const d = Number.isFinite(de) && de > 0 ? Math.min(de / 100, 1) : 0;
  const wE = 1 / (1 + d), wD = d / (1 + d);
  const costDebtAfterTax = 5.5 * (1 - 0.21);
  const wacc = wE * costEquity + wD * costDebtAfterTax;
  return Math.round(Math.max(6, Math.min(12, wacc)) * 10) / 10;   // capped at 12%: a raw CAPM rate for a high-beta megacap (NVDA ~13.5%) is harsher than practitioners use
}

function sourceMeta(source, { asOf = null, status = "available", note = null } = {}) {
  return {
    source,
    retrievedAt: new Date().toISOString(),
    asOf,
    status,
    synthetic: false,
    note,
  };
}

// ---- Fetch with timeout helper ----
async function fetchWithTimeout(url, options = {}, timeoutMs = 5000) {
  const ctrl  = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, { ...options, signal: ctrl.signal });
    clearTimeout(timer);
    return res;
  } catch (e) {
    clearTimeout(timer);
    throw e;
  }
}

// ============================================================
//  GET /api/me/limit  (free — shows quota to any user)
// ============================================================
router.get("/me/limit", async (req, res) => {
  const today = new Date().toISOString().slice(0, 10);
  if (!req.session.userId) {
    try {
      const usage = await db.execute({
        sql: "SELECT COUNT(*) AS cnt FROM analysis_usage WHERE subject_id = ? AND usage_date = ?",
        args: [`g:${req.guestId || req.sessionID}`, today],
      });
      const used = Number(usage.rows[0]?.cnt || 0);
      return res.json({ plan: "guest", used, limit: GUEST_DAILY_LIMIT, remaining: Math.max(0, GUEST_DAILY_LIMIT - used) });
    } catch (e) {
      return res.status(503).json({ error: "Analysis limit service unavailable." });
    }
  }
  try {
    const r   = await db.execute({ sql: "SELECT id, email, plan, trial_ends_at, stripe_customer_id, stripe_subscription_id FROM users WHERE id = ?", args: [req.session.userId] });
    const row = r.rows[0];
    if (!row) return res.json({ plan: "free", used: 0, limit: FREE_DAILY_LIMIT, remaining: FREE_DAILY_LIMIT });
    const plan = await reconcileEffectivePlan(row);
    if (plan === "pro" || plan === "trial") return res.json({ plan, used: 0, limit: null, remaining: null });
    const usage = await db.execute({
      sql: "SELECT COUNT(*) AS cnt FROM analysis_usage WHERE subject_id = ? AND usage_date = ?",
      args: [`u:${req.session.userId}`, today],
    });
    const used = Number(usage.rows[0]?.cnt || 0);
    res.json({ plan, used, limit: FREE_DAILY_LIMIT, remaining: Math.max(0, FREE_DAILY_LIMIT - used) });
  } catch (e) {
    res.status(503).json({ error: "Analysis limit service unavailable." });
  }
});

// ============================================================
//  GET /api/financials/:ticker  (Pro)
// ============================================================
router.get("/financials/:ticker", requireAccount, async (req, res) => {
  const ticker = requestTicker(req, res);
  if (!ticker) return;

  try {
    // Step 1: Resolve CIK from SEC authoritative ticker map
    let cik = null;
    try {
      const r = await fetchWithTimeout("https://www.sec.gov/files/company_tickers.json", { headers: { "User-Agent": UA } }, 6000);
      if (r.ok) {
        const data  = await r.json();
        const entry = Object.values(data).find(e => e.ticker?.toUpperCase() === ticker);
        if (entry) cik = String(entry.cik_str).padStart(10, "0");
      }
    } catch (_) {}

    // Fallback: EDGAR full-text search
    if (!cik) {
      try {
        const r = await fetchWithTimeout(
          `https://efts.sec.gov/LATEST/search-index?q=%22${encodeURIComponent(ticker)}%22&forms=10-K`,
          { headers: { "User-Agent": UA, "Accept": "application/json" } }, 5000
        );
        if (r.ok) {
          const d   = await r.json();
          const hit = (d?.hits?.hits || [])[0];
          if (hit?._source?.entity_id) cik = String(hit._source.entity_id).padStart(10, "0");
        }
      } catch (_) {}
    }

    if (!cik) {
      console.log(`[financials] ${ticker}: CIK not found (ETF/fund)`);
      return res.json({
        noStatements: true,
        reason: "SEC EDGAR does not provide company statements for this instrument.",
        impliedLens: { synthetic: false, source: "SEC EDGAR", retrievedAt: new Date().toISOString(), asOf: null },
        quoteSummary: { result: [{ defaultKeyStatistics:{}, financialData:{} }] },
      });
    }

    console.log(`[financials] ${ticker}: CIK=${cik}`);

    // Step 2: XBRL company facts
    const factsResp = await fetchWithTimeout(
      `https://data.sec.gov/api/xbrl/companyfacts/CIK${cik}.json`,
      { headers: { "User-Agent": UA } }, 15000
    );
    if (!factsResp.ok) throw new Error(`companyfacts ${factsResp.status}`);
    const facts = await factsResp.json();
    const gaap  = facts.facts?.["us-gaap"] || {};

    // Step 3: Extract annual (10-K) series for a concept list.
    // Facts are grouped by PERIOD END year (u.end), not filing fiscal year —
    // a 10-K reports prior-year comparatives under the same fy, which used to
    // collapse the history into a single wrong year. EPS facts live under the
    // "USD/shares" unit. Duration facts must span a full year (skips quarters).
    function annualSeries(concepts, { pickMax = false } = {}) {
      // MERGE facts across all synonym concepts: companies change XBRL tags
      // over time (e.g. Apple moved Revenues -> RevenueFromContractWithCustomer
      // in 2018), so per-year we take the best fact from any listed concept.
      const byYear = {};
      for (const concept of concepts) {
        const unitMap = gaap[concept]?.units || {};
        const units   = unitMap.USD || unitMap["USD/shares"] || unitMap.shares || [];
        for (const u of units) {
          if (u.form !== "10-K" && u.form !== "10-K/A") continue;
          if (!u.end) continue;
          if (u.start) {
            const days = (new Date(u.end) - new Date(u.start)) / 86400000;
            if (days < 300 || days > 400) continue; // annual duration only
          }
          const yr = u.end.slice(0, 4);
          const cur = byYear[yr];
          /* Revenue: the largest figure for the year (total, not a subset tag). */
          if (!cur || (pickMax && Number(u.val) > Number(cur.val) && u.end >= cur.end) || (!pickMax && (u.filed || "") > (cur.filed || ""))
              || (pickMax && u.end > cur.end)) byYear[yr] = u;
        }
      }
      return Object.values(byYear)
        .sort((a, b) => a.end < b.end ? 1 : -1)   // newest first
        .slice(0, 4);
    }

    const ttmValue = concepts => ttmFromFacts(gaap, concepts);
    const latestShares = () => latestSharesFromFacts(facts);

    const revSeries    = annualSeries(["Revenues","RevenueFromContractWithCustomerExcludingAssessedTax","SalesRevenueNet","RevenueFromContractWithCustomerIncludingAssessedTax","RevenuesNetOfInterestExpense"], { pickMax: true });
    const cogsSeries   = annualSeries(["CostOfGoodsAndServicesSold","CostOfRevenue","CostOfGoodsSold"]);
    const gpSeries     = annualSeries(["GrossProfit"]);
    const opexSeries   = annualSeries(["OperatingExpenses","CostsAndExpenses"]);
    const opinSeries   = annualSeries(["OperatingIncomeLoss"]);
    const niSeries     = annualSeries(["NetIncomeLoss","ProfitLoss"]);
    const epsBasSeries = annualSeries(["EarningsPerShareBasic"]);
    const epsDilSeries = annualSeries(["EarningsPerShareDiluted"]);
    const cashSeries   = annualSeries(["CashAndCashEquivalentsAtCarryingValue","Cash"]);
    const stiSeries    = annualSeries(["ShortTermInvestments","AvailableForSaleSecuritiesCurrent"]);
    const tcaSeries    = annualSeries(["AssetsCurrent"]);
    const tclSeries    = annualSeries(["LiabilitiesCurrent"]);
    const invSeries    = annualSeries(["InventoryNet","InventoryFinishedGoodsNetOfAllowancesCustomerAdvancesAndProgressBillings"]);
    const tasSeries    = annualSeries(["Assets"]);
    const ltdSeries    = annualSeries(["LongTermDebt","LongTermDebtNoncurrent"]);
    const tlbSeries    = annualSeries(["Liabilities"]);
    const equSeries    = annualSeries(["StockholdersEquity","StockholdersEquityIncludingPortionAttributableToNoncontrollingInterest"]);
    const ocfSeries    = annualSeries(["NetCashProvidedByUsedInOperatingActivities"]);
    const capexSeries  = annualSeries(["PaymentsToAcquirePropertyPlantAndEquipment","PaymentsToAcquireProductiveAssets","CapitalExpenditures"]);
    const icfSeries    = annualSeries(["NetCashProvidedByUsedInInvestingActivities"]);
    const fcfSeries    = annualSeries(["NetCashProvidedByUsedInFinancingActivities"]);
    const cchSeries    = annualSeries(["CashAndCashEquivalentsPeriodIncreaseDecrease","NetIncreaseDecreaseInCashAndCashEquivalents"]);
    const shareSeries  = annualSeries(["WeightedAverageNumberOfDilutedSharesOutstanding","CommonStockSharesOutstanding"]);
    const intSeries    = annualSeries(["InterestExpenseNonOperating","InterestExpense"]);

    const backbone = revSeries.length ? revSeries : (niSeries.length ? niSeries : opinSeries);
    if (!backbone.length) {
      console.log(`[financials] ${ticker}: no annual XBRL data (ETF?)`);
      return res.json({
        noStatements: true,
        reason: "No annual SEC XBRL statements were available for this company.",
        impliedLens: { synthetic: false, source: "SEC EDGAR XBRL", retrievedAt: new Date().toISOString(), asOf: null },
        quoteSummary: { result: [{ defaultKeyStatistics:{}, financialData:{} }] },
      });
    }

    const years = backbone.map(b => String(b.end.slice(0, 4)));

    function pickVal(series, yr) {
      const e = series.find(s => String(s.end?.slice(0, 4)) === yr);
      return e ? { raw: e.val } : null;
    }

    const incS = years.map(yr => ({
      endDate:               { fmt: yr, raw: Math.floor(new Date(`${yr}-12-31`).getTime() / 1000) },
      totalRevenue:          pickVal(revSeries,    yr),
      costOfRevenue:         pickVal(cogsSeries,   yr),
      grossProfit:           pickVal(gpSeries,     yr),
      totalOperatingExpenses:pickVal(opexSeries,   yr),
      operatingIncome:       pickVal(opinSeries,   yr),
      netIncome:             pickVal(niSeries,     yr),
      basicEps:              pickVal(epsBasSeries, yr),
      dilutedEps:            pickVal(epsDilSeries, yr),
    }));

    const balS = years.map(yr => ({
      endDate:               { fmt: yr, raw: Math.floor(new Date(`${yr}-12-31`).getTime() / 1000) },
      cash:                  pickVal(cashSeries, yr),
      shortTermInvestments:  pickVal(stiSeries,  yr),
      totalCurrentAssets:    pickVal(tcaSeries,  yr),
      totalAssets:           pickVal(tasSeries,  yr),
      longTermDebt:          pickVal(ltdSeries,  yr),
      totalLiab:             pickVal(tlbSeries,  yr),
      totalStockholderEquity:pickVal(equSeries,  yr),
    }));

    const cfS = years.map(yr => {
      const capexEntry = capexSeries.find(s => String(s.end?.slice(0, 4)) === yr);
      return {
        endDate:               { fmt: yr, raw: Math.floor(new Date(`${yr}-12-31`).getTime() / 1000) },
        totalCashFromOperatingActivities:      pickVal(ocfSeries,  yr),
        capitalExpenditures:                   capexEntry ? { raw: -Math.abs(capexEntry.val) } : null,
        totalCashflowsFromInvestingActivities: pickVal(icfSeries,  yr),
        totalCashFromFinancingActivities:      pickVal(fcfSeries,  yr),
        changeInCash:                          pickVal(cchSeries,  yr),
      };
    });

    // Augment with Finnhub metric ratios
    let m = {}, shares = null, marketPrice = null;
    try {
      const [mr, pr] = await Promise.all([
        fetchWithTimeout(`https://finnhub.io/api/v1/stock/metric?symbol=${ticker}&metric=all&token=${FINNHUB_KEY}`, {}, 5000),
        fetchWithTimeout(`https://finnhub.io/api/v1/stock/profile2?symbol=${ticker}&token=${FINNHUB_KEY}`,          {}, 5000),
      ]);
      const [md, pd] = await Promise.all([mr.json().catch(()=>({})), pr.json().catch(()=>({}))]);
      m      = md.metric || {};
      shares = pd.shareOutstanding ? pd.shareOutstanding * 1e6 : null;
    } catch (_) {}
    try {
      const market = await loadPriceHistory(ticker, { range: "1y", interval: "1d" });
      marketPrice = market.bars.at(-1)?.close || null;
    } catch (_) {}

    const seriesValue = (series, index = 0) => {
      const value = series[index]?.val;
      return value != null && !isNaN(value) ? Number(value) : null;
    };
    const currentYear = years[0];
    const currentValue = series => {
      const row = series.find(item => String(item.end || "").slice(0, 4) === currentYear);
      return row?.val != null && !isNaN(row.val) ? Number(row.val) : null;
    };
    const safeRatio = (a, b) => a != null && b != null && Number(b) !== 0 ? Number(a) / Number(b) : null;
    shares = shares || currentValue(shareSeries);
    const latestRevenue = currentValue(revSeries);
    const priorRevenue = seriesValue(revSeries, 1);
    const latestNetIncome = currentValue(niSeries);
    const latestGrossProfit = currentValue(gpSeries);
    const latestOperatingIncome = currentValue(opinSeries);
    const latestEquity = currentValue(equSeries);
    const latestAssets = currentValue(tasSeries);
    const latestCurrentAssets = currentValue(tcaSeries);
    const latestCurrentLiabilities = currentValue(tclSeries);
    const latestInventory = currentValue(invSeries);
    const latestDebt = currentValue(ltdSeries);
    const latestCash = currentValue(cashSeries);
    const latestShortTermInvestments = currentValue(stiSeries);
    const latestOcf = currentValue(ocfSeries);
    const latestCapex = currentValue(capexSeries);
    const latestEps = currentValue(epsDilSeries);
    const priorEps = seriesValue(epsDilSeries, 1);
    const latestInterest = Math.abs(currentValue(intSeries) || 0) || null;
    const freeCashFlow = latestOcf != null && latestCapex != null
      ? latestOcf - Math.abs(latestCapex)
      : null;
    const marketCap = marketPrice != null && shares != null ? marketPrice * shares : null;
    const enterpriseValue = marketCap != null
      ? marketCap + Number(latestDebt || 0) - Number(latestCash || 0)
      : null;
    const investedCapital = latestDebt != null && latestEquity != null && latestCash != null
      ? latestDebt + latestEquity - latestCash
      : null;

    /* Latest quarter vs the same quarter a year earlier, from the company's
       own SEC filings. Finnhub's quarterly growth uses its own revenue
       definition and was off by miles for lenders (SoFi showed +185% when the
       filings say about +42%). */
    let secQuarterYoy = null;
    try {
      const qh = buildQuarterlyHistory(facts, { maxQuarters: 8 });
      const last = qh.at(-1), prev = qh.length >= 5 ? qh.at(-5) : null;
      const gap = last && prev ? (Date.parse(last.end) - Date.parse(prev.end)) / 86400000 : 0;
      if (last && prev && gap > 330 && gap < 400 && last.revenue > 0 && prev.revenue > 0) secQuarterYoy = last.revenue / prev.revenue - 1;
    } catch (_) { /* fall back to Finnhub */ }
    const n   = v => (v != null && !isNaN(v)) ? { raw: v } : null;
    const pct = v => (v != null && !isNaN(v)) ? { raw: v / 100 } : null;

    const defaultKeyStatistics = {
      trailingPE:                   n(m.peBasicExclExtraTTM ?? m.peNormalizedAnnual ?? safeRatio(marketPrice, latestEps)),
      forwardPE:                    null,
      priceToBook:                  n(m.pbQuarterly ?? (marketCap != null ? safeRatio(marketCap, latestEquity) : null)),
      priceToSalesTrailing12Months: n(m.psTTM ?? (marketCap != null ? safeRatio(marketCap, latestRevenue) : null)),
      enterpriseToEbitda:           n(m.evEbitdaTTM ?? safeRatio(enterpriseValue, latestOperatingIncome)),
      enterpriseToRevenue:          n(safeRatio(enterpriseValue, latestRevenue)),
      sharesOutstanding:            n(shares),
      bookValuePerShare:            n(m.bookValuePerShareQuarterly),
    };
    const financialData = {
      grossMargins:     m.grossMarginAnnual != null || m.grossMarginTTM != null
        ? pct(m.grossMarginAnnual ?? m.grossMarginTTM)
        : n(safeRatio(latestGrossProfit, latestRevenue)),
      operatingMargins: m.operatingProfitMarginAnnual != null || m.operatingProfitMarginTTM != null
        ? pct(m.operatingProfitMarginAnnual ?? m.operatingProfitMarginTTM)
        : n(safeRatio(latestOperatingIncome, latestRevenue)),
      profitMargins:    m.netProfitMarginAnnual != null || m.netProfitMarginTTM != null
        ? pct(m.netProfitMarginAnnual ?? m.netProfitMarginTTM)
        : n(safeRatio(latestNetIncome, latestRevenue)),
      returnOnEquity:   m.roeTTM != null || m.roeRfy != null
        ? pct(m.roeTTM ?? m.roeRfy)
        : n(safeRatio(latestNetIncome, latestEquity)),
      returnOnAssets:   m.roaTTM != null || m.roaRfy != null
        ? pct(m.roaTTM ?? m.roaRfy)
        : n(safeRatio(latestNetIncome, latestAssets)),
      roic:            n(latestOperatingIncome != null && investedCapital > 0
        ? latestOperatingIncome * 0.79 / investedCapital
        : null),
      revenueGrowth:    secQuarterYoy != null ? n(secQuarterYoy)
        : m.revenueGrowthQuarterlyYoy != null || m.revenueGrowth3Y != null
        ? pct(m.revenueGrowthQuarterlyYoy ?? m.revenueGrowth3Y)
        : n(priorRevenue ? safeRatio(latestRevenue - priorRevenue, Math.abs(priorRevenue)) : null),
      earningsGrowth:   m.epsGrowthTTMYoy != null || m.epsGrowth3Y != null
        ? pct(m.epsGrowthTTMYoy ?? m.epsGrowth3Y)
        : n(priorEps ? safeRatio(latestEps - priorEps, Math.abs(priorEps)) : null),
      debtToEquity:     m.totalDebt2EquityQuarterly != null || m.totalDebt2EquityAnnual != null
        ? pct(m.totalDebt2EquityQuarterly ?? m.totalDebt2EquityAnnual)
        : n(safeRatio(latestDebt, latestEquity)),
      currentRatio:     n(m.currentRatioQuarterly ?? m.currentRatioAnnual ?? safeRatio(latestCurrentAssets, latestCurrentLiabilities)),
      quickRatio:       n(m.quickRatioQuarterly ?? m.quickRatioAnnual ?? (
        latestCurrentAssets != null && latestInventory != null
          ? safeRatio(latestCurrentAssets - latestInventory, latestCurrentLiabilities)
          : null
      )),
      freeCashflow:     (m.fcfPerShareTTM != null && shares) ? n(m.fcfPerShareTTM * shares) : n(freeCashFlow),
      totalCash:        n(latestCash),
      interestCoverage: n(latestInterest ? safeRatio(latestOperatingIncome, latestInterest) : null),
    };

    console.log(`[financials] ${ticker}: EDGAR OK — years: ${years.join(", ")}`);
    const hasFinnhubMetrics = Object.keys(m).length > 0;
    return res.json({
      impliedLens: {
        synthetic: false,
        source: hasFinnhubMetrics ? "SEC EDGAR XBRL + Finnhub metrics" : "SEC EDGAR XBRL",
        retrievedAt: new Date().toISOString(),
        asOf: [...revSeries, ...niSeries].map(row => row.filed).filter(Boolean).sort().at(-1) || null,
      },
      quoteSummary: { result: [{
        incomeStatementHistory:            { incomeStatementHistory:  incS },
        balanceSheetHistory:               { balanceSheetStatements:  balS },
        cashflowStatementHistory:          { cashflowStatements:      cfS  },
        incomeStatementHistoryQuarterly:   { incomeStatementHistory:  []   },
        balanceSheetHistoryQuarterly:      { balanceSheetStatements:  []   },
        cashflowStatementHistoryQuarterly: { cashflowStatements:      []   },
        defaultKeyStatistics,
        financialData,
        trailingTwelveMonths: (() => {
          const REV = ["Revenues","RevenueFromContractWithCustomerExcludingAssessedTax","SalesRevenueNet","RevenueFromContractWithCustomerIncludingAssessedTax","RevenuesNetOfInterestExpense"];
          const NI = ["NetIncomeLoss","ProfitLoss"];
          // Revenue and net income from the same twelve months, never one of each.
          const both = matchedTtm(gaap, REV, NI);
          const rev = both ? both.revenue : ttmValue(REV);
          const ni = both ? both.netIncome : null;
          const sh = latestShares();
          const dil = latestDilutedShares(facts);
          return {
            revenue: rev ? { raw: rev.val } : null,
            netIncome: ni ? { raw: ni.val } : null,
            asOf: rev ? rev.asOf : null,
            basis: rev ? rev.basis : null,
            sharesOutstanding: sh ? { raw: sh.val } : null,
            dilutedShares: dil ? { raw: dil.val, asOf: dil.asOf, cagr3: dil.cagr3 } : null,
            // The last annual report the TTM was built from, with its real end
            // date (statement endDate is a Dec-31 placeholder for every company).
            annualRevenue: rev && rev.annual ? { raw: rev.annual.val, asOf: rev.annual.asOf } : null,
          };
        })(),
      }]},
    });

  } catch (e) {
    console.error("[financials] error:", e.message);
    res.status(503).json({ error: "Reported SEC financials are currently unavailable.", synthetic: false });
  }
});

// ============================================================
//  GET /api/earnings/:ticker  (Pro)
// ============================================================
/* Quarterly fundamentals history for the growth charts: one row per fiscal
   quarter from SEC XBRL, with the share price at each quarter end. */
const historyCache = new Map();
function hasOnlyAnnualForeignReports(facts) {
  const g = facts?.facts?.["us-gaap"] || {}, ifrs = facts?.facts?.["ifrs-full"] || {};
  const forms = new Set();
  for (const tax of [g, ifrs]) for (const c of Object.values(tax).slice(0, 40)) for (const u of Object.values(c.units || {})) for (const f of u) forms.add(f.form);
  return [...forms].some(f => /^(20-F|40-F)/.test(f)) && ![...forms].some(f => /^10-Q/.test(f));
}
router.get("/fundamentals/history/:ticker", requireAccount, async (req, res) => {
  const ticker = requestTicker(req, res);
  if (!ticker) return;
  const hit = historyCache.get(ticker);
  if (hit && Date.now() - hit.at < 6 * 3600 * 1000) return res.json(hit.body);
  try {
    const company = await loadCompanyFacts(ticker);
    /* Prices first: Yahoo's split events are what restate older per-share
       figures (SEC filings only restate the last two or three years). */
    let prices = null, priceNote = null;
    try { prices = await loadPriceHistory(ticker, { range: "10y", interval: "1wk" }); }
    catch (e) { priceNote = "Price history unavailable; valuation ratios are hidden."; }
    const quarters = buildQuarterlyHistory(company.facts, { splits: prices ? prices.splits : [] });
    if (quarters.length < 4) {
      const foreign = hasOnlyAnnualForeignReports(company.facts);
      return res.status(404).json({
        error: foreign
          ? "This company files annual reports (Form 20-F) with the SEC, so quarterly figures aren't available here. The Financials tables below show its annual numbers."
          : "Quarterly statements are not available for this company.",
        noHistory: true,
      });
    }
    if (prices) attachPrices(quarters, prices.bars);
    // Each quarter's 10-Q/10-K, for the quarterly statement tables' links.
    const filings = await secEarnings.filingLinks(ticker, quarters.map(q => q.end)).catch(() => ({}));
    const body = {
      ticker,
      name: company.name || ticker,
      quarters,
      filings,
      splits: quarters.splits || [],
      calendar: "Quarters that line up with the calendar are labelled Q1–Q4; others by the month they end.",
      priceNote,
      impliedLens: company.provenance || null,
    };
    if (historyCache.size > 400) historyCache.clear();
    historyCache.set(ticker, { at: Date.now(), body });
    res.json(body);
  } catch (e) {
    const missing = /identifier unavailable/i.test(String(e && e.message));
    res.status(missing ? 404 : 502).json({
      error: missing ? "SEC statements are not available for this ticker (it may be an ETF or a foreign filer)." : "SEC data is temporarily unavailable. Try again shortly.",
      noHistory: missing,
    });
  }
});

router.get("/earnings/:ticker", requireAccount, async (req, res) => {
  const ticker = requestTicker(req, res);
  if (!ticker) return;
  try {
    const [factsResult, finnhubResult] = await Promise.allSettled([
      loadCompanyFacts(ticker),
      loadFinnhubResearch(ticker),
    ]);
    const finnhub = finnhubResult.status === "fulfilled"
      ? finnhubResult.value
      : { earnings: [], estimates: null };
    if (factsResult.status !== "fulfilled" && !finnhub.earnings?.length) {
      return res.status(503).json({
        error: "Reported earnings are unavailable from SEC EDGAR and Finnhub.",
        synthetic: false,
      });
    }
    const earnings = deriveEarnings(
      factsResult.status === "fulfilled" ? factsResult.value : null,
      finnhub
    );
    if (!earnings.length) {
      return res.status(404).json({ error: "No reported earnings history is available for this ticker.", synthetic: false });
    }
    res.setHeader("X-Data-Source", earnings[0].source);
    res.setHeader("X-Data-As-Of", earnings[0].asOf || "");
    res.json(earnings);
  } catch (e) {
    console.error("earnings proxy error:", e.message);
    res.status(503).json({ error: "Failed to fetch reported earnings.", synthetic: false });
  }
});

// ============================================================
//  GET /api/calls/:ticker and /api/calls/:ticker/:id  (Pro)
// ============================================================
/* Earnings materials from SEC filings (lib/sec-earnings.js): each quarter's
   results release (8-K Item 2.02, Exhibit 99.1), the quarter's reported
   numbers and the 10-Q/10-K that followed. Transcripts need a licensed
   provider the site does not have; the response keeps an empty list. */
router.get("/calls/:ticker", requirePro, async (req, res) => {
  const ticker = requestTicker(req, res);
  if (!ticker) return;
  try {
    const data = await secEarnings.releasesFor(ticker);
    res.json({
      ...data,
      transcripts: [], transcriptProvider: null,
      links: { sec: data.filingsUrl, website: data.website },
      impliedLens: sourceMeta("SEC EDGAR 8-K (Item 2.02), 10-Q and 10-K filings", { asOf: data.releases[0]?.date || null }),
    });
  } catch (error) {
    if (error.status === 404) return res.status(404).json({ error: "No SEC earnings releases for this ticker (it may be an ETF or a foreign filer)." });
    console.error("[calls] releases error:", error.message);
    // SEC unreachable: keep the page usable (scorecard, EDGAR search link).
    res.json({
      ticker, releases: [], transcripts: [], transcriptProvider: null, unavailable: true,
      error: "SEC filings are temporarily unavailable. Try again shortly.",
      links: { sec: `https://www.sec.gov/edgar/search/#/q=${encodeURIComponent(ticker)}&forms=8-K` },
    });
  }
});

router.get("/calls/:ticker/:id", requirePro, async (req, res) => {
  const ticker = requestTicker(req, res);
  if (!ticker) return;
  try {
    res.json({ ticker, kind: "release", ...(await secEarnings.releaseText(ticker, String(req.params.id || ""))) });
  } catch (error) {
    if (error.status) return res.status(error.status).json({ error: error.message });
    console.error("[calls] release text error:", error.message);
    res.status(503).json({ error: "Could not load this release from the SEC. Try again shortly." });
  }
});

// ============================================================
//  GET /api/metrics/:ticker  (Pro)
// ============================================================
router.get("/metrics/:ticker", requirePro, async (req, res) => {
  const ticker = requestTicker(req, res);
  if (!ticker) return;
  try {
    const co = await secUniverse.forTicker(ticker);
    res.json({ symbol: ticker, metric: co.metric, metricType: "all", impliedLens: sourceMeta(`SEC filings + ${prices.sourceLabel()}`, { asOf: co.snap?.asOf || null }) });
  } catch (e) {
    console.error("metrics error:", e.message);
    res.status(503).json({ error: "Company metrics are unavailable for this ticker (no SEC filings found).", synthetic: false });
  }
});

// ============================================================
//  GET /api/sec/:ticker  (Pro)
// ============================================================
router.get("/sec/:ticker", requirePro, async (req, res) => {
  const ticker = requestTicker(req, res);
  if (!ticker) return;
  try {
    let entityId = null, entityName = ticker;

    // Strategy 1: EDGAR full-text search
    try {
      const cikUrl  = `https://efts.sec.gov/LATEST/search-index?q=%22${encodeURIComponent(ticker)}%22&forms=10-K,10-Q,8-K`;
      const cikResp = await fetchWithTimeout(cikUrl, { headers: { "User-Agent": UA, "Accept": "application/json" } });
      if (cikResp.ok) {
        const cikData = await cikResp.json();
        const hits    = cikData?.hits?.hits || [];
        if (hits.length) {
          entityId   = hits[0]?._source?.entity_id;
          entityName = hits[0]?._source?.entity_name || ticker;
        }
      }
    } catch (_) {}

    // Strategy 2: authoritative ticker→CIK map
    if (!entityId) {
      try {
        const tcResp = await fetchWithTimeout("https://www.sec.gov/files/company_tickers.json", { headers: { "User-Agent": UA } });
        if (tcResp.ok) {
          const tcData = await tcResp.json();
          const entry  = Object.values(tcData).find(e => e.ticker?.toUpperCase() === ticker);
          if (entry) { entityId = entry.cik_str; entityName = entry.title || ticker; }
        }
      } catch (_) {}
    }

    if (!entityId) {
      return res.status(404).json({
        error: "No SEC registrant identifier was found for this ticker.",
        filings: [],
        entity: ticker,
        synthetic: false,
      });
    }

    const paddedCik = String(entityId).padStart(10, "0");
    const subUrl    = `https://data.sec.gov/submissions/CIK${paddedCik}.json`;
    const subResp   = await fetchWithTimeout(subUrl, { headers: { "User-Agent": UA } });
    if (!subResp.ok) {
      return res.status(503).json({
        error: "SEC filing history is currently unavailable.",
        filings: [],
        entity: ticker,
        synthetic: false,
      });
    }
    const sub = await subResp.json();

    const recent  = sub.filings?.recent;
    const filings = [];
    const TYPES   = new Set(["10-K","10-Q","8-K","DEF 14A","S-1","10-K/A","10-Q/A"]);
    if (recent && recent.form) {
      for (let i = 0; i < recent.form.length && filings.length < 40; i++) {
        if (!TYPES.has(recent.form[i])) continue;
        const accDashes   = recent.accessionNumber[i];
        const accNoDashes = accDashes.replace(/-/g, "");
        filings.push({
          form:        recent.form[i],
          date:        recent.filingDate[i],
          description: recent.primaryDocDescription?.[i] || "",
          primaryDoc:  recent.primaryDocument?.[i]       || "",
          accession:   accDashes,
          viewerUrl:   `https://www.sec.gov/Archives/edgar/data/${parseInt(entityId)}/${accNoDashes}/${recent.primaryDocument?.[i] || ""}`,
          indexUrl:    `https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&CIK=${paddedCik}&type=${encodeURIComponent(recent.form[i])}&dateb=&owner=include&count=10`,
        });
      }
    }
    res.json({
      entity: sub.name || ticker,
      cik: paddedCik,
      filings,
      impliedLens: sourceMeta("SEC EDGAR submissions", {
        asOf: filings.map(row => row.date).filter(Boolean).sort().at(-1) || null,
      }),
    });
  } catch (e) {
    console.error("SEC proxy error:", e.message);
    res.status(503).json({ error: "Failed to fetch SEC filing data.", synthetic: false });
  }
});

// ============================================================
//  GET /api/estimates/:ticker  (Pro)
// ============================================================
/* Consensus estimates and price targets need a licensed feed the site does
   not have. The route still answers with what can be worked out from SEC
   filings and prices (margin trend, a suggested discount rate) so the
   valuation tools keep their defaults. */
router.get("/estimates/:ticker", requirePro, async (req, res) => {
  const ticker = requestTicker(req, res);
  if (!ticker) return;
  try {
    const co = await secUniverse.forTicker(ticker);
    const m = co.metric || {};
    const marginTrend = "flat";
    return res.json({
      ticker,
      revenueGrowth: null, epsGrowth: null, forwardPE: null, marginTrend, priceTarget: null, nextYearEPS: null, fwdQuarterly: [],
      suggestedWACC: suggestDiscountRate(m.beta, Number.isFinite(m["totalDebt/totalEquityQuarterly"]) ? m["totalDebt/totalEquityQuarterly"] * 100 : null),
      estimatesAvailable: false,
      upstream: { revenueEstimates: false, epsEstimates: false, priceTarget: false },
      impliedLens: sourceMeta("SEC filings", {
        asOf: co.snap?.asOf || null, status: "unavailable",
        note: "Analyst estimates and price targets are not part of this site's licensed data.",
      }),
    });
  } catch (e) {
    return res.status(503).json({ error: "Estimates are not available for this ticker.", synthetic: false });
  }
});

// ============================================================
//  GET /api/analyst/:ticker  (Pro)
// ============================================================
// Finnhub profiles carry an industry ("Semiconductors", "Banking"); the
// sector benchmarks are keyed by sector. Map the one onto the other.
const INDUSTRY_SECTORS = [
  [/semiconductor|software|technology|hardware|electronic|it services|internet|computer/i, "Technology"],
  [/pharma|biotech|health|medical|life science/i, "Healthcare"],
  [/bank|financial|insurance|capital market|credit|asset management/i, "Financial Services"],
  [/retail|automobile|auto |hotel|restaurant|leisure|textile|apparel|consumer products|homebuild|e-commerce/i, "Consumer Cyclical"],
  [/food|beverage|tobacco|household|personal products|consumer staples/i, "Consumer Defensive"],
  [/aerospace|defense|machinery|industrial|logistics|airline|construction|transport|electrical equipment|building/i, "Industrials"],
  [/energy|oil|gas|coal/i, "Energy"],
  [/utilit/i, "Utilities"],
  [/real estate|reit/i, "Real Estate"],
  [/media|telecom|communication|entertainment/i, "Communication"],
  [/chemical|metal|mining|material|packaging|paper|steel/i, "Basic Materials"],
];
function sectorForIndustry(industry) {
  if (!industry) return null;
  const hit = INDUSTRY_SECTORS.find(([re]) => re.test(industry));
  return hit ? hit[1] : null;
}

/* Kept for the pages that read company basics from it (Valuation Lab,
   Projection Lab, Compare). Analyst ratings and price targets are no longer
   included: they need a licensed feed. Everything here is from SEC filings
   and the licensed price provider. */
const SECTOR_LONG = {
  "Tech": "Technology", "Health": "Healthcare", "Finance": "Financial Services", "Cons.Disc": "Consumer Cyclical",
  "Staples": "Consumer Defensive", "Industrials": "Industrials", "Energy": "Energy", "Utilities": "Utilities",
  "Real Est.": "Real Estate", "Comm.": "Communication", "Materials": "Basic Materials",
};
router.get("/analyst/:ticker", requirePro, async (req, res) => {
  const ticker = requestTicker(req, res);
  if (!ticker) return;
  try {
    const co = await secUniverse.forTicker(ticker);
    const m = co.metric || {};
    res.json({
      priceTarget: { targetMean: null, targetHigh: null, targetLow: null, targetMedian: null, numberOfAnalysts: null, lastUpdated: null, symbol: ticker },
      recommendations: [],
      analystDataAvailable: false,
      industry: co.industry || null,
      sector: SECTOR_LONG[co.sector] || null,
      yahooFd: {
        targetMeanPrice: null, targetHighPrice: null, targetLowPrice: null, targetMedianPrice: null,
        numberOfAnalystOpinions: null, recommendationMean: null, recommendationKey: null,
        priceToBook: m.pbQuarterly || null,
        trailingPE: m.peTTM > 0 ? m.peTTM : null,
        forwardPE: null,
        priceToSales: m.psTTM || null,
        marketCap: m.marketCapitalization ? m.marketCapitalization * 1e6 : null,
        enterpriseValue: null,
        currentPrice: co.price || null,
      },
      impliedLens: sourceMeta(`SEC filings + ${prices.sourceLabel()}`, { asOf: co.snap?.asOf || null }),
    });
  } catch (e) {
    console.error("analyst (company basics) error:", e.message);
    res.status(503).json({ error: "Company data is unavailable for this ticker.", synthetic: false });
  }
});

// ============================================================
//  GET /api/institutional/:ticker  (Pro)
// ============================================================
/* Insider buying and selling, parsed from the insiders' own SEC Form 4
   filings (lib/sec-filings.js). Institutional holders (13F) are not shown. */
router.get("/institutional/:ticker", requirePro, async (req, res) => {
  const ticker = requestTicker(req, res);
  if (!ticker) return;
  try {
    const [ins, co] = await Promise.all([
      secFilings.insiderTrades(ticker),
      secUniverse.forTicker(ticker).catch(() => null),
    ]);
    res.json({
      ownership: [], ownershipAvailable: false,
      sharesOutstanding: co?.snap?.sharesOutstanding || null,
      insiders: ins.insiders.slice(0, 40).map(t => ({ name: t.name || "—", role: t.role, change: t.change, shares: t.share, price: t.price, date: t.date, filed: t.filed, code: t.code, url: t.source })),
      insiderSummary: ins.insiderSummary,
      impliedLens: sourceMeta("SEC EDGAR Form 4 filings", { asOf: ins.insiders[0]?.filed || null, note: ins.truncated ? "Based on the 40 most recent Form 4 filings." : null }),
    });
  } catch (e) {
    console.error("insider (Form 4) error:", e.message);
    res.status(503).json({ error: "Insider filings are unavailable for this ticker.", synthetic: false });
  }
});

// ============================================================
//  GET /api/funds/:ticker  (everyone; public SEC data)
// ============================================================
/* Which well-known investors held the stock at the last quarter end, and
   whether they bought or sold in that quarter (lib/sec-13f.js, SEC 13F). */
router.get("/funds/:ticker", async (req, res) => {
  const ticker = requestTicker(req, res);
  if (!ticker) return;
  try {
    const data = await sec13f.forTicker(ticker);
    res.setHeader("Cache-Control", "public, max-age=900");
    res.json({ ...data, impliedLens: sourceMeta("SEC EDGAR Form 13F filings", { asOf: data.latestPeriod }) });
  } catch (e) {
    res.status(404).json({ error: "No 13F holdings for this ticker.", holders: [], soldOut: [] });
  }
});

// ============================================================
//  GET /api/darkpool/:ticker  (Pro; legacy route name for FINRA OTC activity)
// ============================================================
router.get("/darkpool/:ticker", requirePro, async (req, res) => {
  const ticker = requestTicker(req, res);
  if (!ticker) return;
  try {
    const finraDataUrl = "https://api.finra.org/data/group/OTCMarket/name/weeklySummary";
    const partitionUrl = "https://api.finra.org/partitions/group/OTCMarket/name/weeklySummary";
    const finraHeaders = {
      Accept: "application/json",
      "Content-Type": "application/json",
      "User-Agent": UA,
    };
    const fetchPartition = async (weekStartDate, tierIdentifier) => {
      const body = {
        compareFilters: [
          { fieldName: "weekStartDate", compareType: "EQUAL", fieldValue: weekStartDate },
          { fieldName: "tierIdentifier", compareType: "EQUAL", fieldValue: tierIdentifier },
          { fieldName: "issueSymbolIdentifier", compareType: "EQUAL", fieldValue: ticker },
        ],
        fields: [
          "weekStartDate",
          "issueSymbolIdentifier",
          "totalWeeklyShareQuantity",
          "totalWeeklyTradeCount",
          "totalNotionalSum",
          "summaryTypeCode",
        ],
        limit: 5000,
      };
      const response = await fetchWithTimeout(finraDataUrl, {
        method: "POST",
        headers: finraHeaders,
        body: JSON.stringify(body),
      }, 10000);
      if (!response.ok) return [];
      const rows = await response.json().catch(() => []);
      return Array.isArray(rows) ? rows : [];
    };

    const [partitionResp, metricResp] = await Promise.all([
      fetchWithTimeout(partitionUrl, { headers: finraHeaders }, 10000).catch(() => null),
      fetchWithTimeout(`https://finnhub.io/api/v1/stock/metric?symbol=${ticker}&metric=all&token=${FINNHUB_KEY}`).catch(() => null),
    ]);

    const partitionData = partitionResp?.ok ? await partitionResp.json().catch(() => null) : null;
    const availablePartitions = Array.isArray(partitionData?.availablePartitions)
      ? partitionData.availablePartitions.map(row => row.partitions).filter(parts => Array.isArray(parts) && parts.length >= 2)
      : [];
    const tierDates = tier => [...new Set(
      availablePartitions.filter(parts => parts[1] === tier).map(parts => parts[0])
    )].sort().reverse();
    const t1Dates = tierDates("T1");
    const t2Dates = tierDates("T2");
    const [t1Probe, t2Probe] = await Promise.all([
      t1Dates[0] ? fetchPartition(t1Dates[0], "T1") : [],
      t2Dates[0] ? fetchPartition(t2Dates[0], "T2") : [],
    ]);
    const selectedTier = t1Probe.length ? "T1" : t2Probe.length ? "T2" : null;
    const selectedDates = selectedTier === "T1" ? t1Dates.slice(0, 8) : selectedTier === "T2" ? t2Dates.slice(0, 8) : [];
    const weeklyRows = selectedTier
      ? await Promise.all(selectedDates.map((date, index) => {
          if (index === 0) return selectedTier === "T1" ? t1Probe : t2Probe;
          return fetchPartition(date, selectedTier);
        }))
      : [];
    const finraData = weeklyRows.map((rows, index) => {
      const shares = rows.reduce((sum, row) => sum + Number(row.totalWeeklyShareQuantity || 0), 0);
      const trades = rows.reduce((sum, row) => sum + Number(row.totalWeeklyTradeCount || 0), 0);
      const notional = rows.reduce((sum, row) => sum + Number(row.totalNotionalSum || 0), 0);
      return {
        weekStartDate: selectedDates[index],
        totalWeeklyShareQuantity: shares,
        totalWeeklyTradeCount: trades,
        totalNotionalSum: notional,
        averageReportedPrice: shares > 0 ? notional / shares : null,
        venuesReported: rows.length,
        tierIdentifier: selectedTier,
      };
    }).filter(row => row.totalWeeklyShareQuantity > 0 || row.totalWeeklyTradeCount > 0);
    const metricData = (metricResp?.ok) ? await metricResp.json().catch(()=>({})) : {};
    const m          = metricData.metric || {};

    const siData = {
      sharesShort: null, shortRatio: null, shortPercentOfFloat: null,
      dateShortInterest: null, sharesOutstanding: m.sharesOutstanding || null, floatShares: null,
    };
    if (!finraData.length && !metricResp?.ok) {
      return res.status(503).json({
        error: "FINRA OTC activity and short-interest context are currently unavailable.",
        synthetic: false,
      });
    }
    const otcActivity = Array.isArray(finraData) ? finraData : [];
    const otcSources = [
      otcActivity.length ? "FINRA OTC Transparency" : null,
      metricResp?.ok ? "Finnhub metrics" : null,
    ].filter(Boolean).join(" + ");
    res.json({
      otcActivity,
      darkpool: otcActivity,
      shortInterest: siData,
      impliedLens: {
        ...sourceMeta(otcSources || "FINRA OTC Transparency", {
          asOf: otcActivity.map(row => row.weekStartDate).filter(Boolean).sort().at(-1) || null,
          note: "FINRA weekly OTC transparency is delayed aggregate activity, not venue-level dark-pool order flow.",
        }),
        finraAvailable: finraData.length > 0,
        finnhubAvailable: Boolean(metricResp?.ok),
      },
    });
  } catch (e) {
    console.error("darkpool proxy error:", e.message);
    res.status(503).json({ error: "Failed to fetch FINRA OTC activity.", synthetic: false });
  }
});

router.suggestDiscountRate = suggestDiscountRate;
module.exports = router;

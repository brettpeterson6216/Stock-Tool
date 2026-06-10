// ============================================================
//  Financials routes — all Pro-gated
//    GET /api/financials/:ticker
//    GET /api/earnings/:ticker
//    GET /api/metrics/:ticker
//    GET /api/me/limit              (free — quota info)
//    GET /api/sec/:ticker
//    GET /api/estimates/:ticker
//    GET /api/analyst/:ticker
//    GET /api/institutional/:ticker
//    GET /api/darkpool/:ticker
// ============================================================
const express = require("express");

const { FINNHUB_KEY }  = require("../lib/config");
const { db }           = require("../lib/db");
const { requirePro, getEffectivePlan, FREE_DAILY_LIMIT, GUEST_DAILY_LIMIT } = require("../lib/plan");

const router = express.Router();
const UA     = "ImpliedLens/1.0 brettpeterson6216@gmail.com";

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
    const r   = await db.execute({ sql: "SELECT email, plan, trial_ends_at FROM users WHERE id = ?", args: [req.session.userId] });
    const row = r.rows[0];
    if (!row) return res.json({ plan: "free", used: 0, limit: FREE_DAILY_LIMIT, remaining: FREE_DAILY_LIMIT });
    const plan = getEffectivePlan(row);
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
router.get("/financials/:ticker", requirePro, async (req, res) => {
  const ticker = req.params.ticker.toUpperCase().replace(/[^A-Z0-9.]/g, "");

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
      return res.json({ noStatements: true, quoteSummary: { result: [{ defaultKeyStatistics:{}, financialData:{} }] } });
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

    // Step 3: Extract annual (10-K) series for a concept list
    function annualSeries(concepts) {
      for (const concept of concepts) {
        const units  = gaap[concept]?.units?.USD || gaap[concept]?.units?.shares || [];
        const byYear = {};
        for (const u of units) {
          if (u.form !== "10-K") continue;
          const yr = u.fy || u.end?.slice(0, 4);
          if (!yr) continue;
          if (!byYear[yr] || u.filed > byYear[yr].filed) byYear[yr] = u;
        }
        const sorted = Object.values(byYear)
          .sort((a, b) => (b.fy || b.end) > (a.fy || a.end) ? 1 : -1)
          .slice(0, 4);
        if (sorted.length) return sorted;
      }
      return [];
    }

    const revSeries    = annualSeries(["Revenues","RevenueFromContractWithCustomerExcludingAssessedTax","SalesRevenueNet","RevenueFromContractWithCustomerIncludingAssessedTax"]);
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
    const tasSeries    = annualSeries(["Assets"]);
    const ltdSeries    = annualSeries(["LongTermDebt","LongTermDebtNoncurrent"]);
    const tlbSeries    = annualSeries(["Liabilities"]);
    const equSeries    = annualSeries(["StockholdersEquity","StockholdersEquityIncludingPortionAttributableToNoncontrollingInterest"]);
    const ocfSeries    = annualSeries(["NetCashProvidedByUsedInOperatingActivities"]);
    const capexSeries  = annualSeries(["PaymentsToAcquirePropertyPlantAndEquipment","CapitalExpenditures"]);
    const icfSeries    = annualSeries(["NetCashProvidedByUsedInInvestingActivities"]);
    const fcfSeries    = annualSeries(["NetCashProvidedByUsedInFinancingActivities"]);
    const cchSeries    = annualSeries(["CashAndCashEquivalentsPeriodIncreaseDecrease","NetIncreaseDecreaseInCashAndCashEquivalents"]);

    const backbone = revSeries.length ? revSeries : (niSeries.length ? niSeries : opinSeries);
    if (!backbone.length) {
      console.log(`[financials] ${ticker}: no annual XBRL data (ETF?)`);
      return res.json({ noStatements: true, quoteSummary: { result: [{ defaultKeyStatistics:{}, financialData:{} }] } });
    }

    const years = backbone.map(b => String(b.fy || b.end?.slice(0, 4)));

    function pickVal(series, yr) {
      const e = series.find(s => String(s.fy || s.end?.slice(0, 4)) === yr);
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
      const capexEntry = capexSeries.find(s => String(s.fy || s.end?.slice(0, 4)) === yr);
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
    let m = {}, shares = null;
    try {
      const [mr, pr] = await Promise.all([
        fetchWithTimeout(`https://finnhub.io/api/v1/stock/metric?symbol=${ticker}&metric=all&token=${FINNHUB_KEY}`, {}, 5000),
        fetchWithTimeout(`https://finnhub.io/api/v1/stock/profile2?symbol=${ticker}&token=${FINNHUB_KEY}`,          {}, 5000),
      ]);
      const [md, pd] = await Promise.all([mr.json().catch(()=>({})), pr.json().catch(()=>({}))]);
      m      = md.metric || {};
      shares = pd.shareOutstanding ? pd.shareOutstanding * 1e6 : null;
    } catch (_) {}

    const n   = v => (v != null && !isNaN(v)) ? { raw: v } : null;
    const pct = v => (v != null && !isNaN(v)) ? { raw: v / 100 } : null;

    const defaultKeyStatistics = {
      trailingPE:                   n(m.peNormalizedAnnual || m.peBasicExclExtraTTM),
      forwardPE:                    null,
      priceToBook:                  n(m.pbQuarterly),
      priceToSalesTrailing12Months: n(m.psTTM),
      enterpriseToEbitda:           n(m.evEbitdaTTM),
      enterpriseToRevenue:          null,
      sharesOutstanding:            n(shares),
      bookValuePerShare:            n(m.bookValuePerShareQuarterly),
    };
    const financialData = {
      grossMargins:     pct(m.grossMarginAnnual    ?? m.grossMarginTTM),
      operatingMargins: pct(m.operatingProfitMarginAnnual ?? m.operatingProfitMarginTTM),
      profitMargins:    pct(m.netProfitMarginAnnual ?? m.netProfitMarginTTM),
      returnOnEquity:   pct(m.roeTTM  ?? m.roeRfy),
      returnOnAssets:   pct(m.roaTTM  ?? m.roaRfy),
      revenueGrowth:    pct(m.revenueGrowthQuarterlyYoy ?? m.revenueGrowth3Y),
      earningsGrowth:   pct(m.epsGrowthTTMYoy ?? m.epsGrowth3Y),
      debtToEquity:     n(m.totalDebt2EquityQuarterly ?? m.totalDebt2EquityAnnual),
      currentRatio:     n(m.currentRatioQuarterly  ?? m.currentRatioAnnual),
      quickRatio:       n(m.quickRatioQuarterly    ?? m.quickRatioAnnual),
      freeCashflow:     (m.fcfPerShareTTM != null && shares) ? n(m.fcfPerShareTTM * shares) : null,
    };

    console.log(`[financials] ${ticker}: EDGAR OK — years: ${years.join(", ")}`);
    return res.json({
      quoteSummary: { result: [{
        incomeStatementHistory:            { incomeStatementHistory:  incS },
        balanceSheetHistory:               { balanceSheetStatements:  balS },
        cashflowStatementHistory:          { cashflowStatements:      cfS  },
        incomeStatementHistoryQuarterly:   { incomeStatementHistory:  []   },
        balanceSheetHistoryQuarterly:      { balanceSheetStatements:  []   },
        cashflowStatementHistoryQuarterly: { cashflowStatements:      []   },
        defaultKeyStatistics,
        financialData,
      }]},
    });

  } catch (e) {
    console.error("[financials] error:", e.message);
    res.status(500).json({ error: "Failed to fetch financials: " + e.message });
  }
});

// ============================================================
//  GET /api/earnings/:ticker  (Pro)
// ============================================================
router.get("/earnings/:ticker", requirePro, async (req, res) => {
  try {
    const ticker = req.params.ticker.toUpperCase();
    const url    = `https://finnhub.io/api/v1/stock/earnings?symbol=${ticker}&limit=20&token=${FINNHUB_KEY}`;
    const r      = await fetchWithTimeout(url);
    if (!r.ok) return res.status(r.status).json({ error: "Finnhub returned " + r.status });
    res.json(await r.json());
  } catch (e) {
    console.error("earnings proxy error:", e.message);
    res.status(500).json({ error: "Failed to fetch earnings." });
  }
});

// ============================================================
//  GET /api/metrics/:ticker  (Pro)
// ============================================================
router.get("/metrics/:ticker", requirePro, async (req, res) => {
  try {
    const ticker = req.params.ticker.toUpperCase();
    const url    = `https://finnhub.io/api/v1/stock/metric?symbol=${ticker}&metric=all&token=${FINNHUB_KEY}`;
    const r      = await fetchWithTimeout(url);
    if (!r.ok) return res.status(r.status).json({ error: "Finnhub returned " + r.status });
    res.json(await r.json());
  } catch (e) {
    console.error("metrics proxy error:", e.message);
    res.status(500).json({ error: "Failed to fetch metrics." });
  }
});

// ============================================================
//  GET /api/sec/:ticker  (Pro)
// ============================================================
router.get("/sec/:ticker", requirePro, async (req, res) => {
  const ticker = req.params.ticker.toUpperCase().replace(/[^A-Z0-9.]/g, "");
  if (!ticker) return res.status(400).json({ error: "No ticker" });
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

    if (!entityId) return res.json({ filings: [], entity: ticker });

    const paddedCik = String(entityId).padStart(10, "0");
    const subUrl    = `https://data.sec.gov/submissions/CIK${paddedCik}.json`;
    const subResp   = await fetchWithTimeout(subUrl, { headers: { "User-Agent": UA } });
    if (!subResp.ok) return res.json({ filings: [], entity: ticker });
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
    res.json({ entity: sub.name || ticker, cik: paddedCik, filings });
  } catch (e) {
    console.error("SEC proxy error:", e.message);
    res.status(500).json({ error: "Failed to fetch SEC data." });
  }
});

// ============================================================
//  GET /api/estimates/:ticker  (Pro)
// ============================================================
router.get("/estimates/:ticker", requirePro, async (req, res) => {
  const ticker = req.params.ticker.toUpperCase().replace(/[^A-Z0-9.]/g, "");
  if (!ticker) return res.status(400).json({ error: "No ticker" });
  try {
    const FH = FINNHUB_KEY;
    const [revResp, epsResp, metResp, ptResp] = await Promise.allSettled([
      fetchWithTimeout(`https://finnhub.io/api/v1/stock/revenue-estimate?symbol=${ticker}&freq=annual&token=${FH}`),
      fetchWithTimeout(`https://finnhub.io/api/v1/stock/eps-estimate?symbol=${ticker}&freq=annual&token=${FH}`),
      fetchWithTimeout(`https://finnhub.io/api/v1/stock/metric?symbol=${ticker}&metric=all&token=${FH}`),
      fetchWithTimeout(`https://finnhub.io/api/v1/stock/price-target?symbol=${ticker}&token=${FH}`),
    ]);

    const safe = async (p) => {
      try { if (p.status === "fulfilled" && p.value.ok) return await p.value.json(); } catch (_) {}
      return null;
    };
    const [rev, eps, met, pt] = await Promise.all([safe(revResp), safe(epsResp), safe(metResp), safe(ptResp)]);

    const currentYear = String(new Date().getUTCFullYear());
    const nextEstimatePair = (rows, field) => {
      const future = [...(rows || [])]
        .filter(row => row.period >= currentYear && Number(row[field]) > 0)
        .sort((a, b) => a.period.localeCompare(b.period));
      return [future[0] || null, future[1] || null];
    };

    let revenueGrowth = null;
    if (rev?.data?.length >= 2) {
      const [cur, nxt] = nextEstimatePair(rev.data, "revenueAvg");
      if (cur && nxt && cur.revenueAvg > 0) revenueGrowth = Math.round(((nxt.revenueAvg / cur.revenueAvg) - 1) * 1000) / 10;
    }

    let epsGrowth = null;
    if (eps?.data?.length >= 2) {
      const [cur, nxt] = nextEstimatePair(eps.data, "epsAvg");
      if (cur && nxt && cur.epsAvg > 0) epsGrowth = Math.round(((nxt.epsAvg / cur.epsAvg) - 1) * 1000) / 10;
    }

    const m         = met?.metric || {};
    const forwardPE = m["peNormalizedAnnual"] || m["peBasicExclExtraTTM"] || null;

    const marginTrend = (() => {
      const mg3   = m["netProfitMargin3Y"]   || null;
      const mgTTM = m["netProfitMarginTTM"]  || m["netProfitMarginAnnual"] || null;
      if (mg3 && mgTTM) {
        const diff = mgTTM - mg3;
        if (diff >  1.5) return "expand";
        if (diff < -1.5) return "compress";
      }
      return "flat";
    })();

    const priceTarget = pt?.targetMean || pt?.targetHigh ? {
      mean: pt.targetMean || null, high: pt.targetHigh || null, low: pt.targetLow || null,
    } : null;

    let nextYearEPS = null;
    if (eps?.data?.length) {
      const future = [...eps.data]
        .filter(d => d.period >= currentYear && d.epsAvg != null && d.epsAvg > 0)
        .sort((a, b) => a.period.localeCompare(b.period));
      if (future.length) nextYearEPS = future[0].epsAvg;
    }

    let fwdQuarterly = [];
    try {
      const qEpsResp = await fetchWithTimeout(`https://finnhub.io/api/v1/stock/eps-estimate?symbol=${ticker}&freq=quarterly&token=${FH}`);
      if (qEpsResp.ok) {
        const qEps = await qEpsResp.json();
        if (qEps?.data?.length) {
          const now = new Date().toISOString().slice(0, 7);
          fwdQuarterly = qEps.data
            .filter(d => d.period >= now && d.epsAvg != null)
            .sort((a, b) => a.period.localeCompare(b.period))
            .slice(0, 4)
            .map(d => ({ period: d.period, epsAvg: d.epsAvg, epsHigh: d.epsHigh, epsLow: d.epsLow, numberAnalysts: d.numberAnalysts }));
        }
      }
    } catch (_) {}

    const beta = m["beta"] || m["betaAnnual"] || null;
    let suggestedWACC = null;
    if (beta) {
      suggestedWACC = Math.round((4.5 + Number(beta) * 5.5) * 10) / 10;
      suggestedWACC = Math.max(6, Math.min(20, suggestedWACC));
    }

    return res.json({ ticker, revenueGrowth, epsGrowth, forwardPE, marginTrend, priceTarget, nextYearEPS, fwdQuarterly, suggestedWACC });
  } catch (e) {
    console.error("estimates error", e.message);
    return res.status(500).json({ error: "Could not fetch estimates" });
  }
});

// ============================================================
//  GET /api/analyst/:ticker  (Pro)
// ============================================================
router.get("/analyst/:ticker", requirePro, async (req, res) => {
  const ticker = req.params.ticker.toUpperCase();
  try {
    const [ptResp, recResp] = await Promise.all([
      fetchWithTimeout(`https://finnhub.io/api/v1/stock/price-target?symbol=${ticker}&token=${FINNHUB_KEY}`),
      fetchWithTimeout(`https://finnhub.io/api/v1/stock/recommendation?symbol=${ticker}&token=${FINNHUB_KEY}`),
    ]);
    const [pt, rec] = await Promise.all([ptResp.json(), recResp.json()]);

    let yahooFd = {};
    try {
      const [metricResp, quoteResp] = await Promise.all([
        fetchWithTimeout(`https://finnhub.io/api/v1/stock/metric?symbol=${ticker}&metric=all&token=${FINNHUB_KEY}`),
        fetchWithTimeout(`https://finnhub.io/api/v1/quote?symbol=${ticker}&token=${FINNHUB_KEY}`),
      ]);
      const [metricData, quoteData] = await Promise.all([metricResp.json(), quoteResp.json()]);
      const m = metricData.metric || {};
      yahooFd = {
        targetMeanPrice: null, targetHighPrice: null, targetLowPrice: null, targetMedianPrice: null,
        numberOfAnalystOpinions: null, recommendationMean: null, recommendationKey: null,
        priceToBook:  m.pbQuarterly || null,
        trailingPE:   m.peNormalizedAnnual || m.peBasicExclExtraTTM || null,
        forwardPE:    null,
        priceToSales: m.psTTM || null,
        marketCap:    m.marketCapitalization ? m.marketCapitalization * 1e6 : null,
        enterpriseValue: null,
        currentPrice: quoteData.c || null,
      };
    } catch (_) {}

    const merged = {
      targetMean:  pt.targetMean   || yahooFd.targetMeanPrice   || null,
      targetHigh:  pt.targetHigh   || yahooFd.targetHighPrice   || null,
      targetLow:   pt.targetLow    || yahooFd.targetLowPrice    || null,
      targetMedian:pt.targetMedian || yahooFd.targetMedianPrice || null,
      numberOfAnalysts: pt.numberOfAnalysts || yahooFd.numberOfAnalystOpinions || null,
      lastUpdated: pt.lastUpdated || null,
      symbol: ticker,
    };
    res.json({ priceTarget: merged, recommendations: rec, yahooFd });
  } catch (e) {
    console.error("analyst proxy error:", e.message);
    res.status(500).json({ error: "Failed to fetch analyst data." });
  }
});

// ============================================================
//  GET /api/institutional/:ticker  (Pro)
// ============================================================
router.get("/institutional/:ticker", requirePro, async (req, res) => {
  const ticker = req.params.ticker.toUpperCase();
  try {
    const r    = await fetchWithTimeout(`https://finnhub.io/api/v1/stock/ownership?symbol=${ticker}&limit=10&token=${FINNHUB_KEY}`);
    const data = await r.json();
    res.json(data);
  } catch (e) {
    console.error("institutional proxy error:", e.message);
    res.status(500).json({ error: "Failed to fetch institutional data." });
  }
});

// ============================================================
//  GET /api/darkpool/:ticker  (Pro)
// ============================================================
router.get("/darkpool/:ticker", requirePro, async (req, res) => {
  const ticker = req.params.ticker.toUpperCase();
  try {
    const compareFilters = encodeURIComponent(JSON.stringify([
      { fieldName: "issueSymbolIdentifier", compareType: "equal", fieldValue: ticker },
    ]));
    const sortFields = encodeURIComponent(JSON.stringify([{ fieldName: "weekStartDate", sortType: "DESC" }]));
    const finraUrl   = `https://api.finra.org/data/group/OTCMarket/name/weeklySummary?compareFilters=${compareFilters}&fields=weekStartDate,totalWeeklyShareQuantity,totalWeeklyTradeCount,lastSalePrice&limit=8&sortFields=${sortFields}`;

    const [finraResp, metricResp] = await Promise.all([
      fetchWithTimeout(finraUrl, { headers: { "Accept": "application/json", "User-Agent": UA } }).catch(() => null),
      fetchWithTimeout(`https://finnhub.io/api/v1/stock/metric?symbol=${ticker}&metric=all&token=${FINNHUB_KEY}`).catch(() => null),
    ]);

    const finraData  = (finraResp?.ok)  ? await finraResp.json().catch(()=>[])    : [];
    const metricData = (metricResp?.ok) ? await metricResp.json().catch(()=>({})) : {};
    const m          = metricData.metric || {};

    const siData = {
      sharesShort: null, shortRatio: null, shortPercentOfFloat: null,
      dateShortInterest: null, sharesOutstanding: m.sharesOutstanding || null, floatShares: null,
    };
    res.json({ darkpool: Array.isArray(finraData) ? finraData : [], shortInterest: siData });
  } catch (e) {
    console.error("darkpool proxy error:", e.message);
    res.status(500).json({ error: "Failed to fetch dark pool data." });
  }
});

module.exports = router;

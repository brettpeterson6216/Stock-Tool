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
const express = require("express");

const { FINNHUB_KEY }  = require("../lib/config");
const { db }           = require("../lib/db");
const { requirePro, reconcileEffectivePlan, normalizeTicker, FREE_DAILY_LIMIT, GUEST_DAILY_LIMIT } = require("../lib/plan");
const { deriveEarnings, loadCompanyFacts, loadFinnhubResearch, loadPriceHistory } = require("../lib/stock-research");

const router = express.Router();
const UA     = "ImpliedLens/1.0 brettpeterson6216@gmail.com";

function requestTicker(req, res) {
  const ticker = normalizeTicker(req.params.ticker);
  if (!ticker) res.status(400).json({ error: "Invalid ticker." });
  return ticker;
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
router.get("/financials/:ticker", requirePro, async (req, res) => {
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
    function annualSeries(concepts) {
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
          if (!byYear[yr] || (u.filed || "") > (byYear[yr].filed || "")) byYear[yr] = u;
        }
      }
      return Object.values(byYear)
        .sort((a, b) => a.end < b.end ? 1 : -1)   // newest first
        .slice(0, 4);
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

    const n   = v => (v != null && !isNaN(v)) ? { raw: v } : null;
    const pct = v => (v != null && !isNaN(v)) ? { raw: v / 100 } : null;

    const defaultKeyStatistics = {
      trailingPE:                   n(m.peNormalizedAnnual ?? m.peBasicExclExtraTTM ?? safeRatio(marketPrice, latestEps)),
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
      revenueGrowth:    m.revenueGrowthQuarterlyYoy != null || m.revenueGrowth3Y != null
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
router.get("/earnings/:ticker", requirePro, async (req, res) => {
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
router.get("/calls/:ticker", requirePro, async (req, res) => {
  const ticker = requestTicker(req, res);
  if (!ticker) return;
  try {
    const [listResult, profileResult] = await Promise.allSettled([
      fetchWithTimeout(`https://finnhub.io/api/v1/stock/transcripts/list?symbol=${ticker}&token=${FINNHUB_KEY}`, {}, 7000),
      fetchWithTimeout(`https://finnhub.io/api/v1/stock/profile2?symbol=${ticker}&token=${FINNHUB_KEY}`, {}, 5000),
    ]);
    const read = async result => {
      if (result.status !== "fulfilled" || !result.value.ok) return null;
      return result.value.json().catch(() => null);
    };
    const [listData, profile] = await Promise.all([read(listResult), read(profileResult)]);
    const rows = Array.isArray(listData) ? listData : Array.isArray(listData?.transcripts) ? listData.transcripts : Array.isArray(listData?.data) ? listData.data : [];
    const transcripts = rows.slice(0, 24).map(row => ({
      id: String(row.id || ""),
      symbol: String(row.symbol || ticker),
      year: Number(row.year) || null,
      quarter: Number(row.quarter) || null,
      time: row.time || row.date || null,
      title: String(row.title || `${ticker} earnings call`).slice(0, 200),
    })).filter(row => row.id);
    res.json({
      ticker,
      company: profile?.name || ticker,
      companyWebsite: /^https?:\/\//.test(profile?.weburl || "") ? profile.weburl : null,
      transcripts,
      transcriptProvider: transcripts.length ? "Finnhub" : null,
      links: {
        sec: `https://www.sec.gov/edgar/browse/?CIK=${encodeURIComponent(ticker)}&owner=exclude&action=getcompany`,
        investorRelationsSearch: `https://www.google.com/search?q=${encodeURIComponent(`${ticker} investor relations earnings call`)}`,
        earnings: `https://finance.yahoo.com/quote/${encodeURIComponent(ticker)}/earnings/`,
      },
    });
  } catch (error) {
    console.error("[calls] list error:", error.message);
    res.status(500).json({ error: "Could not load earnings-call research." });
  }
});

router.get("/calls/:ticker/:id", requirePro, async (req, res) => {
  const ticker = requestTicker(req, res);
  const id = String(req.params.id || "");
  if (!ticker) return;
  if (!/^[A-Za-z0-9_.:-]{1,200}$/.test(id)) return res.status(400).json({ error: "Invalid transcript request." });
  try {
    const response = await fetchWithTimeout(`https://finnhub.io/api/v1/stock/transcripts?id=${encodeURIComponent(id)}&token=${FINNHUB_KEY}`, {}, 12000);
    if (!response.ok) return res.status(response.status).json({ error: "Transcript is unavailable from the current data provider." });
    const data = await response.json();
    const transcript = Array.isArray(data?.transcript) ? data.transcript.slice(0, 800).map(item => ({
      name: String(item.name || item.speaker || "Speaker").slice(0, 160),
      speech: String(item.speech || item.text || "").slice(0, 30000),
    })).filter(item => item.speech) : [];
    res.json({
      id,
      ticker,
      year: Number(data?.year) || null,
      quarter: Number(data?.quarter) || null,
      audio: /^https?:\/\//.test(data?.audio || "") ? data.audio : null,
      participants: Array.isArray(data?.participant) ? data.participant.slice(0, 100) : [],
      transcript,
    });
  } catch (error) {
    console.error("[calls] transcript error:", error.message);
    res.status(500).json({ error: "Could not load this transcript." });
  }
});

// ============================================================
//  GET /api/metrics/:ticker  (Pro)
// ============================================================
router.get("/metrics/:ticker", requirePro, async (req, res) => {
  const ticker = requestTicker(req, res);
  if (!ticker) return;
  try {
    const url    = `https://finnhub.io/api/v1/stock/metric?symbol=${ticker}&metric=all&token=${FINNHUB_KEY}`;
    const r      = await fetchWithTimeout(url);
    if (!r.ok) return res.status(503).json({ error: "Provider metrics are currently unavailable.", synthetic: false });
    const data = await r.json();
    res.json({ ...data, impliedLens: sourceMeta("Finnhub metrics") });
  } catch (e) {
    console.error("metrics proxy error:", e.message);
    res.status(503).json({ error: "Failed to fetch provider metrics.", synthetic: false });
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
router.get("/estimates/:ticker", requirePro, async (req, res) => {
  const ticker = requestTicker(req, res);
  if (!ticker) return;
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

    const available = Boolean(rev || eps || met || pt || fwdQuarterly.length);
    if (!available) {
      return res.status(503).json({
        error: "Analyst estimates are unavailable from the configured provider.",
        synthetic: false,
      });
    }
    return res.json({
      ticker,
      revenueGrowth,
      epsGrowth,
      forwardPE,
      marginTrend,
      priceTarget,
      nextYearEPS,
      fwdQuarterly,
      suggestedWACC,
      impliedLens: sourceMeta("Finnhub analyst estimates", {
        asOf: null,
        note: "Estimate periods are forecast periods, not source freshness dates.",
      }),
    });
  } catch (e) {
    console.error("estimates error", e.message);
    return res.status(503).json({ error: "Could not fetch analyst estimates.", synthetic: false });
  }
});

// ============================================================
//  GET /api/analyst/:ticker  (Pro)
// ============================================================
router.get("/analyst/:ticker", requirePro, async (req, res) => {
  const ticker = requestTicker(req, res);
  if (!ticker) return;
  try {
    const [ptResp, recResp] = await Promise.all([
      fetchWithTimeout(`https://finnhub.io/api/v1/stock/price-target?symbol=${ticker}&token=${FINNHUB_KEY}`),
      fetchWithTimeout(`https://finnhub.io/api/v1/stock/recommendation?symbol=${ticker}&token=${FINNHUB_KEY}`),
    ]);
    if (!ptResp.ok && !recResp.ok) {
      return res.status(503).json({ error: "Analyst data is unavailable from the configured provider.", synthetic: false });
    }
    const [pt, rec] = await Promise.all([
      ptResp.ok ? ptResp.json() : {},
      recResp.ok ? recResp.json() : [],
    ]);

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
    res.json({
      priceTarget: merged,
      recommendations: rec,
      yahooFd,
      impliedLens: sourceMeta("Finnhub analyst data", { asOf: merged.lastUpdated }),
    });
  } catch (e) {
    console.error("analyst proxy error:", e.message);
    res.status(503).json({ error: "Failed to fetch analyst data.", synthetic: false });
  }
});

// ============================================================
//  GET /api/institutional/:ticker  (Pro)
// ============================================================
router.get("/institutional/:ticker", requirePro, async (req, res) => {
  const ticker = requestTicker(req, res);
  if (!ticker) return;
  try {
    const r    = await fetchWithTimeout(`https://finnhub.io/api/v1/stock/ownership?symbol=${ticker}&limit=10&token=${FINNHUB_KEY}`);
    if (!r.ok) return res.status(503).json({ error: "Institutional ownership is currently unavailable.", synthetic: false });
    const data = await r.json();
    res.json({ ...data, impliedLens: sourceMeta("Finnhub institutional ownership") });
  } catch (e) {
    console.error("institutional proxy error:", e.message);
    res.status(503).json({ error: "Failed to fetch institutional data.", synthetic: false });
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

module.exports = router;

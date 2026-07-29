"use strict";

const { FINNHUB_KEY } = require("./config");
const { normalizeTicker } = require("./plan");
const { recordProvider } = require("./provider-health");

const SEC_USER_AGENT = process.env.SEC_USER_AGENT || "ImpliedLens/1.2 support@impliedlens.com";
const cache = new Map();
const CACHE_LIMIT = 300;
const MARKET_MAX_AGE_MS = 12 * 24 * 60 * 60 * 1000;
const FUNDAMENTAL_MAX_AGE_MS = 400 * 24 * 60 * 60 * 1000;
const ANNUAL_FORMS = new Set(["10-K", "10-K/A", "20-F", "20-F/A", "40-F", "40-F/A"]);
const REPORTED_FORMS = new Set([...ANNUAL_FORMS, "10-Q", "10-Q/A", "6-K", "6-K/A"]);

function finite(value) {
  return value !== null && value !== undefined && value !== "" && Number.isFinite(Number(value));
}

function number(value) {
  return finite(value) ? Number(value) : null;
}

function clamp(value, min, max) {
  return Math.min(max, Math.max(min, Number(value)));
}

function ratio(numerator, denominator) {
  return finite(numerator) && finite(denominator) && Number(denominator) !== 0
    ? Number(numerator) / Number(denominator)
    : null;
}

function researchTicker(value) {
  const normalized = normalizeTicker(value);
  if (!normalized) return null;
  // Yahoo and the SEC use a dash for US share classes (BRK.B -> BRK-B).
  return /^[A-Z]{1,5}\.[A-Z]$/.test(normalized)
    ? normalized.replace(".", "-")
    : normalized;
}

function ageMs(value, now = Date.now()) {
  const timestamp = Date.parse(value || "");
  return Number.isFinite(timestamp) ? Math.max(0, now - timestamp) : null;
}

function freshness(value, maxAgeMs, now = Date.now()) {
  const elapsed = ageMs(value, now);
  return {
    asOf: value || null,
    ageDays: elapsed === null ? null : Math.floor(elapsed / 86400000),
    status: elapsed === null ? "unavailable" : elapsed <= maxAgeMs ? "current" : "stale",
  };
}

function getCached(key, ttlMs) {
  const entry = cache.get(key);
  if (!entry || Date.now() - entry.storedAt > ttlMs) {
    if (entry) cache.delete(key);
    return null;
  }
  return entry.value;
}

function setCached(key, value) {
  if (cache.size >= CACHE_LIMIT) cache.delete(cache.keys().next().value);
  cache.set(key, { storedAt: Date.now(), value });
  return value;
}

async function fetchWithTimeout(url, options = {}, timeoutMs = 9000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

async function fetchJson(url, options = {}, timeoutMs = 9000) {
  const response = await fetchWithTimeout(url, options, timeoutMs);
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return response.json();
}

function provider(name, sourceUrl, retrievedAt, extra = {}) {
  return {
    name,
    sourceUrl,
    retrievedAt,
    asOf: extra.asOf || null,
    status: extra.status || "available",
    fallback: Boolean(extra.fallback),
    delayed: extra.delayed ?? null,
    note: extra.note || null,
  };
}

let tickerMapCache = null;
let tickerMapStoredAt = 0;

async function loadTickerMap() {
  if (tickerMapCache && Date.now() - tickerMapStoredAt < 24 * 60 * 60 * 1000) {
    return tickerMapCache;
  }
  const started = Date.now();
  const url = "https://www.sec.gov/files/company_tickers.json";
  const data = await fetchJson(url, {
    headers: { "User-Agent": SEC_USER_AGENT, Accept: "application/json" },
  }, 10000);
  tickerMapCache = new Map(
    Object.values(data || {}).map(entry => [
      String(entry.ticker || "").toUpperCase(),
      {
        cik: String(entry.cik_str || "").padStart(10, "0"),
        name: String(entry.title || entry.ticker || ""),
      },
    ])
  );
  tickerMapStoredAt = Date.now();
  recordProvider("SEC EDGAR", true, Date.now() - started, "Ticker map available");
  return tickerMapCache;
}

async function resolveCompany(ticker) {
  const normalized = researchTicker(ticker);
  if (!normalized) throw new Error("Invalid ticker.");
  const map = await loadTickerMap();
  const company = map.get(normalized);
  if (!company) throw new Error("SEC company identifier unavailable for this ticker.");
  return { ticker: normalized, ...company };
}

function parseYahooChart(payload, ticker, source, fallback = false) {
  const result = payload?.chart?.result?.[0];
  const quote = result?.indicators?.quote?.[0];
  const timestamps = result?.timestamp || [];
  if (!timestamps.length || !quote) throw new Error("Price history was empty.");
  const bars = timestamps.map((time, index) => ({
    time: Number(time),
    open: number(quote.open?.[index]),
    high: number(quote.high?.[index]),
    low: number(quote.low?.[index]),
    close: number(quote.close?.[index]),
    volume: number(quote.volume?.[index]) || 0,
  })).filter(bar =>
    finite(bar.time) && finite(bar.open) && finite(bar.high) &&
    finite(bar.low) && finite(bar.close) && bar.close > 0
  );
  if (bars.length < 60) throw new Error("Fewer than 60 valid price observations were returned.");
  const latest = bars[bars.length - 1];
  const marketAsOf = new Date(latest.time * 1000).toISOString();
  const marketFreshness = freshness(marketAsOf, MARKET_MAX_AGE_MS);
  if (marketFreshness.status === "stale") {
    throw new Error(
      `Latest market observation is stale (${marketAsOf.slice(0, 10)}). ` +
      "LensScore requires a current price series."
    );
  }
  const retrievedAt = new Date().toISOString();
  return {
    ticker,
    bars,
    meta: {
      symbol: result.meta?.symbol || ticker,
      name: result.meta?.longName || result.meta?.shortName || ticker,
      currency: result.meta?.currency || "USD",
      exchange: result.meta?.exchangeName || null,
      instrumentType: result.meta?.instrumentType || null,
      price: number(result.meta?.regularMarketPrice) || latest.close,
      previousClose: number(result.meta?.previousClose) || number(result.meta?.chartPreviousClose),
    },
    provenance: provider(source, "https://finance.yahoo.com/", retrievedAt, {
      asOf: marketAsOf,
      fallback,
      delayed: true,
      note: "Latest available provider observation; not represented as a real-time exchange feed.",
    }),
    freshness: marketFreshness,
  };
}

async function loadPriceHistory(ticker, { range = "5y", interval = "1d" } = {}) {
  const normalized = researchTicker(ticker);
  if (!normalized) throw new Error("Invalid ticker.");
  const cacheKey = `price:${normalized}:${range}:${interval}`;
  const cached = getCached(cacheKey, 60 * 1000);
  if (cached) return cached;

  const started = Date.now();
  const headers = {
    "User-Agent": "Mozilla/5.0 (compatible; ImpliedLens/1.2)",
    Accept: "application/json,text/plain,*/*",
  };
  const hosts = ["query2.finance.yahoo.com", "query1.finance.yahoo.com"];
  let lastError = null;
  for (let index = 0; index < hosts.length; index += 1) {
    const host = hosts[index];
    const url = `https://${host}/v8/finance/chart/${encodeURIComponent(normalized)}?interval=${encodeURIComponent(interval)}&range=${encodeURIComponent(range)}&includePrePost=false&events=div%2Csplits`;
    try {
      const payload = await fetchJson(url, { headers }, 9000);
      const parsed = parseYahooChart(payload, normalized, "Yahoo Finance chart", index > 0);
      recordProvider("Yahoo Finance", true, Date.now() - started, `${normalized} ${range} history`);
      return setCached(cacheKey, parsed);
    } catch (error) {
      lastError = error;
    }
  }
  recordProvider("Yahoo Finance", false, Date.now() - started, lastError?.message || "Price history unavailable");
  if (/stale/i.test(String(lastError?.message || ""))) throw lastError;
  throw new Error("Live price history is unavailable. No synthetic series was substituted.");
}

async function loadCompanyFacts(ticker) {
  const company = await resolveCompany(ticker);
  const cacheKey = `facts:${company.cik}`;
  const cached = getCached(cacheKey, 30 * 60 * 1000);
  if (cached) return cached;
  const started = Date.now();
  const url = `https://data.sec.gov/api/xbrl/companyfacts/CIK${company.cik}.json`;
  try {
    const facts = await fetchJson(url, {
      headers: { "User-Agent": SEC_USER_AGENT, Accept: "application/json" },
    }, 15000);
    const retrievedAt = new Date().toISOString();
    const latestFiled = Object.values(facts?.facts || {})
      .flatMap(taxonomy => Object.values(taxonomy || {}))
      .flatMap(concept => Object.values(concept?.units || {}))
      .flat()
      .map(row => row?.filed)
      .filter(Boolean)
      .sort()
      .at(-1) || null;
    recordProvider("SEC EDGAR", true, Date.now() - started, `${company.ticker} company facts`);
    return setCached(cacheKey, {
      ...company,
      facts,
      provenance: provider("SEC EDGAR XBRL", url, retrievedAt, {
        asOf: latestFiled,
        delayed: false,
        note: "Company-reported facts; each observation retains its filing date.",
      }),
    });
  } catch (error) {
    recordProvider("SEC EDGAR", false, Date.now() - started, error.message);
    throw error;
  }
}

function conceptFacts(companyFacts, concepts, preferredUnits = ["USD", "USD/shares", "shares", "pure"]) {
  const rows = [];
  const taxonomies = [
    ["us-gaap", companyFacts?.facts?.facts?.["us-gaap"] || {}],
    ["ifrs-full", companyFacts?.facts?.facts?.["ifrs-full"] || {}],
    ["dei", companyFacts?.facts?.facts?.dei || {}],
  ];
  for (const [taxonomyName, taxonomy] of taxonomies) {
    for (const concept of concepts) {
      const units = taxonomy[concept]?.units || {};
      const selectedUnit = preferredUnits.find(unit => Array.isArray(units[unit]) && units[unit].length)
        || Object.keys(units).find(unit => Array.isArray(units[unit]) && units[unit].length);
      if (!selectedUnit) continue;
      for (const fact of units[selectedUnit] || []) {
        if (!finite(fact.val) || !fact.end || !fact.filed) continue;
        rows.push({ ...fact, concept, taxonomy: taxonomyName, unit: selectedUnit });
      }
    }
  }
  return rows;
}

function consistentSeries(rows) {
  const groups = new Map();
  for (const row of rows || []) {
    const key = `${row.taxonomy || ""}:${row.concept || ""}:${row.unit || ""}`;
    if (!groups.has(key)) groups.set(key, new Map());
    const byEnd = groups.get(key);
    const existing = byEnd.get(row.end);
    if (!existing || row.filed > existing.filed) byEnd.set(row.end, row);
  }
  const candidates = [...groups.values()]
    .map(byEnd => [...byEnd.values()].sort((a, b) => a.end.localeCompare(b.end)))
    .filter(series => series.length)
    .sort((a, b) => {
      const latestEnd = String(b.at(-1).end).localeCompare(String(a.at(-1).end));
      if (latestEnd) return latestEnd;
      if (b.length !== a.length) return b.length - a.length;
      const aUsd = /^USD(?:\/|$)/.test(a[0].unit || "") ? 1 : 0;
      const bUsd = /^USD(?:\/|$)/.test(b[0].unit || "") ? 1 : 0;
      if (bUsd !== aUsd) return bUsd - aUsd;
      return String(b.at(-1).filed).localeCompare(String(a.at(-1).filed));
    });
  return candidates[0] || [];
}

function annualSeries(companyFacts, concepts, { duration = true } = {}) {
  const rows = conceptFacts(companyFacts, concepts)
    .filter(row => ANNUAL_FORMS.has(row.form))
    .filter(row => {
      if (!duration || !row.start) return true;
      const days = (new Date(row.end) - new Date(row.start)) / 86400000;
      return days >= 300 && days <= 400;
    });
  return consistentSeries(rows);
}

function quarterlySeries(companyFacts, concepts) {
  const rows = conceptFacts(companyFacts, concepts)
    .filter(row => REPORTED_FORMS.has(row.form))
    .filter(row => {
      if (!row.start) return false;
      const days = (new Date(row.end) - new Date(row.start)) / 86400000;
      return days >= 70 && days <= 120;
    });
  return consistentSeries(rows);
}

function instantSeries(companyFacts, concepts) {
  const rows = conceptFacts(companyFacts, concepts)
    .filter(row => REPORTED_FORMS.has(row.form));
  return consistentSeries(rows);
}

const CONCEPTS = Object.freeze({
  revenue: [
    "RevenueFromContractWithCustomerExcludingAssessedTax", "Revenues", "SalesRevenueNet",
    "Revenue", "RevenueFromContractsWithCustomers",
  ],
  netIncome: ["NetIncomeLoss", "ProfitLoss"],
  dilutedEps: ["EarningsPerShareDiluted", "DilutedEarningsLossPerShare"],
  operatingIncome: ["OperatingIncomeLoss", "ProfitLossFromOperatingActivities"],
  interestExpense: ["InterestExpenseNonOperating", "InterestExpense", "FinanceCosts", "InterestExpenseOnBorrowings"],
  operatingCashFlow: ["NetCashProvidedByUsedInOperatingActivities", "CashFlowsFromUsedInOperatingActivities"],
  capex: [
    "PaymentsToAcquirePropertyPlantAndEquipment", "PaymentsToAcquireProductiveAssets", "CapitalExpenditures",
    "PurchaseOfPropertyPlantAndEquipmentClassifiedAsInvestingActivities",
  ],
  cash: [
    "CashAndCashEquivalentsAtCarryingValue", "CashCashEquivalentsRestrictedCashAndRestrictedCashEquivalents",
    "CashAndCashEquivalents",
  ],
  assets: ["Assets"],
  debt: [
    "LongTermDebtAndFinanceLeaseObligationsCurrent", "LongTermDebtCurrent", "LongTermDebtNoncurrent", "LongTermDebt",
    "CurrentPortionOfLongtermBorrowings", "LongtermBorrowings", "ShorttermBorrowings",
  ],
  equity: [
    "StockholdersEquity", "StockholdersEquityIncludingPortionAttributableToNoncontrollingInterest", "Equity",
  ],
  shares: [
    "WeightedAverageNumberOfDilutedSharesOutstanding", "CommonStockSharesOutstanding",
    "AdjustedWeightedAverageShares", "WeightedAverageShares", "EntityCommonStockSharesOutstanding",
  ],
});

function latestPair(series) {
  const clean = (series || []).filter(row => finite(row.val));
  return [clean.at(-1) || null, clean.at(-2) || null];
}

function latestValue(series) {
  return latestPair(series)[0]?.val ?? null;
}

function valueAtEnd(series, end) {
  return [...(series || [])]
    .filter(row => row.end === end && finite(row.val))
    .sort((a, b) => String(a.filed).localeCompare(String(b.filed)))
    .at(-1)?.val ?? null;
}

function latestDebtAtEnd(companyFacts, end) {
  const aggregate = instantSeries(companyFacts, ["LongTermDebt"]);
  const aggregateValue = valueAtEnd(aggregate, end);
  if (finite(aggregateValue)) return aggregateValue;
  const current = valueAtEnd(
    instantSeries(companyFacts, [
      "LongTermDebtAndFinanceLeaseObligationsCurrent", "LongTermDebtCurrent",
      "CurrentPortionOfLongtermBorrowings", "ShorttermBorrowings",
    ]),
    end
  );
  const noncurrent = valueAtEnd(
    instantSeries(companyFacts, [
      "LongTermDebtAndFinanceLeaseObligationsNoncurrent", "LongTermDebtNoncurrent", "LongtermBorrowings",
    ]),
    end
  );
  if (!finite(current) && !finite(noncurrent)) return null;
  return Number(current || 0) + Number(noncurrent || 0);
}

async function loadFinnhubResearch(ticker) {
  if (!FINNHUB_KEY) {
    return {
      estimates: null,
      metrics: null,
      profile: null,
      earnings: [],
      provenance: provider("Finnhub", "https://finnhub.io/", new Date().toISOString(), {
        status: "unavailable",
        note: "FINNHUB_KEY is not configured.",
      }),
    };
  }
  const normalized = normalizeTicker(ticker);
  const cacheKey = `finnhub:${normalized}`;
  const cached = getCached(cacheKey, 10 * 60 * 1000);
  if (cached) return cached;
  const started = Date.now();
  const base = "https://finnhub.io/api/v1";
  const endpoints = {
    revenue: `${base}/stock/revenue-estimate?symbol=${normalized}&freq=annual&token=${FINNHUB_KEY}`,
    eps: `${base}/stock/eps-estimate?symbol=${normalized}&freq=annual&token=${FINNHUB_KEY}`,
    metrics: `${base}/stock/metric?symbol=${normalized}&metric=all&token=${FINNHUB_KEY}`,
    profile: `${base}/stock/profile2?symbol=${normalized}&token=${FINNHUB_KEY}`,
    earnings: `${base}/stock/earnings?symbol=${normalized}&limit=20&token=${FINNHUB_KEY}`,
  };
  const entries = await Promise.all(Object.entries(endpoints).map(async ([key, url]) => {
    try {
      return [key, await fetchJson(url, {}, 8000)];
    } catch (_) {
      return [key, null];
    }
  }));
  const data = Object.fromEntries(entries);
  const successCount = entries.filter(([, value]) => value).length;
  recordProvider("Finnhub", successCount > 0, Date.now() - started, `${successCount}/${entries.length} research feeds available`);
  const result = {
    estimates: { revenue: data.revenue, eps: data.eps },
    metrics: data.metrics?.metric || null,
    profile: data.profile || null,
    earnings: Array.isArray(data.earnings) ? data.earnings : [],
    provenance: provider("Finnhub", "https://finnhub.io/", new Date().toISOString(), {
      status: successCount ? "available" : "unavailable",
      delayed: null,
      note: `${successCount} of ${entries.length} requested research datasets were available.`,
    }),
  };
  return setCached(cacheKey, result);
}

function nextEstimate(rows, field) {
  const today = new Date().toISOString().slice(0, 10);
  return [...(rows || [])]
    .filter(row => String(row.period || "") >= today.slice(0, 4) && finite(row[field]) && Number(row[field]) > 0)
    .sort((a, b) => String(a.period).localeCompare(String(b.period)))[0] || null;
}

function trailingFourQuarterEps(rows) {
  const uniquePeriods = new Map();
  for (const row of rows || []) {
    const period = String(row?.period || "").slice(0, 10);
    if (!/^\d{4}-\d{2}-\d{2}$/.test(period) || !finite(row?.actual)) continue;
    if (!uniquePeriods.has(period)) {
      uniquePeriods.set(period, { period, actual: Number(row.actual) });
    }
  }
  const quarters = [...uniquePeriods.values()]
    .sort((a, b) => b.period.localeCompare(a.period))
    .slice(0, 4);
  if (quarters.length !== 4) return null;
  const newest = Date.parse(`${quarters[0].period}T12:00:00Z`);
  const oldest = Date.parse(`${quarters[3].period}T12:00:00Z`);
  const spanDays = (newest - oldest) / 86_400_000;
  if (!Number.isFinite(spanDays) || spanDays < 240 || spanDays > 420) return null;
  const cadenceDays = quarters.slice(0, -1).map((quarter, index) => {
    const newer = Date.parse(`${quarter.period}T12:00:00Z`);
    const older = Date.parse(`${quarters[index + 1].period}T12:00:00Z`);
    return (newer - older) / 86_400_000;
  });
  if (cadenceDays.some(days => !Number.isFinite(days) || days < 60 || days > 130)) return null;
  const value = Number(quarters.reduce((sum, quarter) => sum + quarter.actual, 0).toFixed(6));
  if (!Number.isFinite(value) || value <= 0) return null;
  return {
    value,
    basis: "Trailing four-quarter actual EPS",
    asOf: quarters[0].period,
    quarters: quarters.map(quarter => quarter.period),
  };
}

function selectReferenceEps({ estimatedEps = null, reportedAnnualEps = null, earnings = [] } = {}) {
  if (finite(estimatedEps?.epsAvg) && Number(estimatedEps.epsAvg) > 0) {
    return {
      value: Number(estimatedEps.epsAvg),
      basis: "Forward annual consensus EPS",
      asOf: estimatedEps.period || null,
      quarters: [],
    };
  }
  const trailing = trailingFourQuarterEps(earnings);
  if (trailing) return trailing;
  if (finite(reportedAnnualEps?.val) && Number(reportedAnnualEps.val) > 0) {
    return {
      value: Number(reportedAnnualEps.val),
      basis: "Latest annual reported diluted EPS",
      asOf: reportedAnnualEps.end || reportedAnnualEps.filed || null,
      quarters: [],
    };
  }
  return { value: null, basis: "Unavailable", asOf: null, quarters: [] };
}

function metricNumber(metrics, keys) {
  for (const key of keys) {
    if (finite(metrics?.[key])) return Number(metrics[key]);
  }
  return null;
}

function metricRate(metrics, keys) {
  const value = metricNumber(metrics, keys);
  return finite(value) ? Number(value) / 100 : null;
}

function deriveFundamentals(companyFacts, price, finnhub = {}, market = {}) {
  const revenueSeries = annualSeries(companyFacts, CONCEPTS.revenue);
  const epsSeries = annualSeries(companyFacts, CONCEPTS.dilutedEps);
  const ocfSeries = annualSeries(companyFacts, CONCEPTS.operatingCashFlow);
  const capexSeries = annualSeries(companyFacts, CONCEPTS.capex);
  const operatingIncomeSeries = annualSeries(companyFacts, CONCEPTS.operatingIncome);
  const netIncomeSeries = annualSeries(companyFacts, CONCEPTS.netIncome);
  const interestSeries = annualSeries(companyFacts, CONCEPTS.interestExpense);
  const equitySeries = instantSeries(companyFacts, CONCEPTS.equity);
  const cashSeries = instantSeries(companyFacts, CONCEPTS.cash);
  const assetSeries = instantSeries(companyFacts, CONCEPTS.assets);
  const shareSeries = annualSeries(companyFacts, CONCEPTS.shares);
  const metrics = finnhub.metrics || {};

  const [revenue, priorRevenue] = latestPair(revenueSeries);
  const [eps, priorEps] = latestPair(epsSeries);
  const [shares, priorShares] = latestPair(shareSeries);
  const latestInstantEnd = [equitySeries.at(-1), cashSeries.at(-1), assetSeries.at(-1)]
    .filter(Boolean)
    .map(row => row.end)
    .sort()
    .at(-1) || null;
  const operatingEnd = revenue?.end || eps?.end || null;
  const balanceEnd = latestInstantEnd || operatingEnd;
  const operatingCashFlow = valueAtEnd(ocfSeries, operatingEnd);
  const capex = valueAtEnd(capexSeries, operatingEnd);
  const operatingIncome = valueAtEnd(operatingIncomeSeries, operatingEnd);
  const netIncome = valueAtEnd(netIncomeSeries, operatingEnd);
  const interestExpenseRaw = valueAtEnd(interestSeries, operatingEnd);
  const interestExpense = finite(interestExpenseRaw) ? Math.abs(Number(interestExpenseRaw)) : null;
  const equity = valueAtEnd(equitySeries, balanceEnd);
  const cash = valueAtEnd(cashSeries, balanceEnd);
  const assets = valueAtEnd(assetSeries, balanceEnd);
  const debt = latestDebtAtEnd(companyFacts, balanceEnd);
  const freeCashFlow = finite(operatingCashFlow) && finite(capex)
    ? Number(operatingCashFlow) - Math.abs(Number(capex))
    : null;

  const reportedRevenueGrowth = revenue && priorRevenue ? ratio(revenue.val - priorRevenue.val, Math.abs(priorRevenue.val)) : null;
  const reportedEpsGrowth = eps && priorEps && Number(priorEps.val) !== 0
    ? ratio(eps.val - priorEps.val, Math.abs(priorEps.val))
    : null;
  const providerRevenueGrowth = metricRate(metrics, [
    "revenueGrowthQuarterlyYoy", "revenueGrowthTTMYoy", "revenueGrowth3Y",
  ]);
  const providerEpsGrowth = metricRate(metrics, [
    "epsGrowthTTMYoy", "epsGrowthQuarterlyYoy", "epsGrowth3Y",
  ]);
  const estimatedRevenue = nextEstimate(finnhub.estimates?.revenue?.data, "revenueAvg");
  const estimatedEps = nextEstimate(finnhub.estimates?.eps?.data, "epsAvg");
  const reportedQuarterlyEps = quarterlySeries(companyFacts, CONCEPTS.dilutedEps).map(row => ({
    period: row.end,
    actual: row.val,
  }));
  const estimatedRevenuePrior = [...(finnhub.estimates?.revenue?.data || [])]
    .filter(row => finite(row.revenueAvg) && Number(row.revenueAvg) > 0)
    .sort((a, b) => String(a.period).localeCompare(String(b.period)))
    .find(row => estimatedRevenue && String(row.period) < String(estimatedRevenue.period));
  const forwardRevenueGrowth = estimatedRevenue && estimatedRevenuePrior
    ? ratio(estimatedRevenue.revenueAvg - estimatedRevenuePrior.revenueAvg, estimatedRevenuePrior.revenueAvg)
    : null;

  const revenueGrowth = finite(forwardRevenueGrowth)
    ? forwardRevenueGrowth
    : finite(providerRevenueGrowth) ? providerRevenueGrowth : reportedRevenueGrowth;
  const derivedEpsGrowth = estimatedEps && eps && Number(eps.val) > 0
    ? ratio(estimatedEps.epsAvg - eps.val, Math.abs(eps.val))
    : reportedEpsGrowth;
  const epsGrowth = finite(derivedEpsGrowth) ? derivedEpsGrowth : providerEpsGrowth;
  const providerFcfMargin = (() => {
    const direct = metricRate(metrics, ["freeCashFlowMarginTTM", "freeCashFlowMarginAnnual"]);
    if (finite(direct)) return direct;
    const fcfPerShare = metricNumber(metrics, ["fcfPerShareTTM", "fcfPerShareAnnual"]);
    const revenuePerShare = metricNumber(metrics, ["revenuePerShareTTM", "revenuePerShareAnnual"]);
    return finite(fcfPerShare) && finite(revenuePerShare) && revenuePerShare !== 0
      ? fcfPerShare / revenuePerShare
      : null;
  })();
  const fcfMargin = revenue && finite(freeCashFlow)
    ? ratio(freeCashFlow, revenue.val)
    : providerFcfMargin;
  const investedCapital = finite(debt) && finite(equity) && finite(cash)
    ? Number(debt) + Number(equity) - Number(cash)
    : null;
  const derivedRoic = finite(operatingIncome) && finite(investedCapital) && investedCapital > 0
    ? Number(operatingIncome) * 0.79 / investedCapital
    : null;
  const providerRoic = metricRate(metrics, ["roiTTM", "roiAnnual", "roicTTM", "roicAnnual"]);
  const roic = finite(derivedRoic)
    ? derivedRoic
    : providerRoic;
  const providerProfitMargin = metricRate(metrics, ["netProfitMarginTTM", "netProfitMarginAnnual"]);
  const profitMargin = revenue && finite(netIncome)
    ? ratio(netIncome, revenue.val)
    : providerProfitMargin;
  const derivedReturnOnEquity = finite(netIncome) && finite(equity) && Number(equity) > 0
    ? Number(netIncome) / Number(equity)
    : null;
  const providerReturnOnEquity = metricRate(metrics, ["roeTTM", "roeRfy", "roeAnnual"]);
  const returnOnEquity = finite(derivedReturnOnEquity)
    ? derivedReturnOnEquity
    : providerReturnOnEquity;
  const capitalRatio = finite(equity) && finite(assets) && Number(assets) > 0
    ? Number(equity) / Number(assets)
    : null;
  const netDebt = finite(debt) && finite(cash) ? Number(debt) - Number(cash) : null;
  const derivedNetDebtEbitda = finite(netDebt) && finite(operatingIncome) && Number(operatingIncome) > 0
    ? Number(netDebt) / Number(operatingIncome)
    : null;
  const providerNetDebt = metricNumber(metrics, ["netDebtAnnual", "netDebtQuarterly"]);
  const providerEbitda = metricNumber(metrics, ["ebitdaTTM", "ebitdaAnnual"]);
  const providerNetDebtEbitda = finite(providerNetDebt) && finite(providerEbitda) && providerEbitda > 0
    ? providerNetDebt / providerEbitda
    : metricNumber(metrics, ["netDebtToEbitdaTTM", "netDebtToEbitdaAnnual"]);
  const netDebtEbitda = finite(derivedNetDebtEbitda)
    ? derivedNetDebtEbitda
    : providerNetDebtEbitda;
  const derivedInterestCoverage = finite(operatingIncome) && finite(interestExpense) && interestExpense > 0
    ? Number(operatingIncome) / interestExpense
    : null;
  const providerInterestCoverage = metricNumber(metrics, ["interestCoverageTTM", "interestCoverageAnnual"]);
  const interestCoverage = finite(derivedInterestCoverage)
    ? derivedInterestCoverage
    : providerInterestCoverage;
  const providerDilution = metricRate(metrics, ["shareGrowthTTMYoy", "shareGrowthAnnual"]);
  const dilution = shares && priorShares && Number(priorShares.val) > 0
    ? ratio(shares.val - priorShares.val, priorShares.val)
    : providerDilution;

  const secEvidenceRows = [
    revenue, eps, shares,
    equitySeries.at(-1), cashSeries.at(-1), assetSeries.at(-1),
    operatingIncomeSeries.at(-1), netIncomeSeries.at(-1),
    ocfSeries.at(-1), capexSeries.at(-1), interestSeries.at(-1),
  ].filter(Boolean);
  const secAsOf = secEvidenceRows.map(row => row.filed).filter(Boolean).sort().at(-1) || null;
  const secFreshness = freshness(secAsOf, FUNDAMENTAL_MAX_AGE_MS);
  const providerAsOf = finnhub.provenance?.retrievedAt || null;
  const secIsCurrent = secFreshness.status === "current";

  const effectiveRevenueGrowth = finite(forwardRevenueGrowth)
    ? forwardRevenueGrowth
    : finite(providerRevenueGrowth) ? providerRevenueGrowth
      : secIsCurrent ? reportedRevenueGrowth : null;
  const effectiveEpsGrowth = secIsCurrent && finite(derivedEpsGrowth)
    ? derivedEpsGrowth
    : providerEpsGrowth;
  const effectiveFcfMargin = secIsCurrent && revenue && finite(freeCashFlow)
    ? fcfMargin
    : providerFcfMargin;
  const effectiveRoic = secIsCurrent && finite(derivedRoic) ? derivedRoic : providerRoic;
  const effectiveProfitMargin = secIsCurrent && revenue && finite(netIncome)
    ? profitMargin
    : providerProfitMargin;
  const effectiveReturnOnEquity = secIsCurrent && finite(derivedReturnOnEquity)
    ? derivedReturnOnEquity
    : providerReturnOnEquity;
  const effectiveCapitalRatio = secIsCurrent ? capitalRatio : null;
  const effectiveNetDebtEbitda = secIsCurrent && finite(derivedNetDebtEbitda)
    ? derivedNetDebtEbitda
    : providerNetDebtEbitda;
  const effectiveInterestCoverage = secIsCurrent && finite(derivedInterestCoverage)
    ? derivedInterestCoverage
    : providerInterestCoverage;
  const effectiveDilution = secIsCurrent && shares && priorShares
    ? dilution
    : providerDilution;

  const providerPE = number(finnhub.metrics?.peNormalizedAnnual || finnhub.metrics?.peBasicExclExtraTTM);
  const marketCurrency = String(market.currency || "").toUpperCase();
  const companyCurrency = String(finnhub.profile?.currency || "").toUpperCase();
  const earningsCurrencyMismatch = Boolean(
    marketCurrency && companyCurrency && marketCurrency !== companyCurrency
  );
  const rawReferenceEpsSelection = selectReferenceEps({
    estimatedEps,
    reportedAnnualEps: secIsCurrent ? eps : null,
    earnings: [...(finnhub.earnings || []), ...reportedQuarterlyEps],
  });
  const rawReferencePE = finite(rawReferenceEpsSelection.value) && rawReferenceEpsSelection.value > 0 && finite(price)
    ? Number(price) / Number(rawReferenceEpsSelection.value)
    : null;
  const perShareBasisMismatch = finite(providerPE) && providerPE > 0 && finite(rawReferencePE)
    ? rawReferencePE / providerPE < 0.4 || rawReferencePE / providerPE > 2.5
    : false;
  const normalizePerShareBasis = (earningsCurrencyMismatch || perShareBasisMismatch)
    && finite(providerPE) && providerPE > 0 && finite(price);
  const referenceEpsSelection = normalizePerShareBasis
    ? {
      value: Number(price) / Number(providerPE),
      basis: "Provider-normalized earnings multiple",
      asOf: providerAsOf,
      quarters: [],
    }
    : rawReferenceEpsSelection;
  const referenceEps = referenceEpsSelection.value;
  const forwardPE = finite(referenceEps) && Number(referenceEps) > 0 && finite(price)
    ? Number(price) / Number(referenceEps)
    : providerPE;
  const supportedGrowth = clamp(
    [effectiveRevenueGrowth, effectiveEpsGrowth].filter(finite).reduce((sum, value) => sum + Number(value), 0) /
      Math.max(1, [effectiveRevenueGrowth, effectiveEpsGrowth].filter(finite).length),
    -0.2,
    0.35
  );
  const fairMultiple = finite(effectiveRoic)
    ? clamp(11 + supportedGrowth * 55 + Math.max(0, Number(effectiveRoic)) * 28, 8, 36)
    : clamp(12 + supportedGrowth * 60, 8, 32);
  const modeledValue = finite(referenceEps) && Number(referenceEps) > 0
    ? Number(referenceEps) * fairMultiple
    : null;
  const bearValue = finite(referenceEps) && Number(referenceEps) > 0
    ? Number(referenceEps) * 0.8 * Math.max(8, fairMultiple * 0.62)
    : null;
  const modeledUpside = finite(modeledValue) && finite(price) ? ratio(modeledValue - price, price) : null;
  const bearDownside = finite(bearValue) && finite(price) ? ratio(bearValue - price, price) : null;
  const marketImpliedGrowth = finite(forwardPE) && Number(forwardPE) > 0
    ? Math.pow(Math.max(0.05, Number(forwardPE)) / 18, 1 / 5) - 1
    : null;
  const impliedGrowthGap = finite(marketImpliedGrowth) ? marketImpliedGrowth - supportedGrowth : null;

  const providerEvidenceUsed = [
    providerRevenueGrowth, providerEpsGrowth, providerFcfMargin, providerRoic,
    providerProfitMargin, providerReturnOnEquity, providerNetDebtEbitda,
    providerInterestCoverage, providerDilution,
  ].some(finite);
  const asOf = secIsCurrent ? secAsOf : providerEvidenceUsed ? providerAsOf : secAsOf;
  const fundamentalFreshness = secIsCurrent
    ? secFreshness
    : providerEvidenceUsed
      ? { ...freshness(providerAsOf, 24 * 60 * 60 * 1000), basis: "provider-snapshot" }
      : secFreshness;
  const values = {
    revenueGrowth: effectiveRevenueGrowth,
    epsGrowth: effectiveEpsGrowth,
    fcfMargin: effectiveFcfMargin,
    roic: effectiveRoic,
    profitMargin: effectiveProfitMargin,
    returnOnEquity: effectiveReturnOnEquity,
    capitalRatio: effectiveCapitalRatio,
    netDebtEbitda: effectiveNetDebtEbitda,
    interestCoverage: effectiveInterestCoverage,
    dilution: effectiveDilution,
    forwardPE,
    dcfUpside: modeledUpside,
    impliedGrowthGap,
    bearDownside,
  };
  const fields = {
    revenueGrowth: {
      value: effectiveRevenueGrowth,
      source: finite(forwardRevenueGrowth) ? "Finnhub consensus"
        : finite(providerRevenueGrowth) ? "Finnhub provider metric" : "SEC filing",
      asOf: finite(forwardRevenueGrowth) || finite(providerRevenueGrowth) ? providerAsOf : secAsOf,
    },
    epsGrowth: {
      value: effectiveEpsGrowth,
      source: secIsCurrent && finite(derivedEpsGrowth)
        ? estimatedEps ? "Finnhub consensus + SEC filing" : "SEC filing"
        : "Finnhub provider metric",
      asOf: secIsCurrent && finite(derivedEpsGrowth)
        ? estimatedEps ? providerAsOf : secAsOf
        : providerAsOf,
    },
    fcfMargin: {
      value: effectiveFcfMargin,
      source: finite(effectiveFcfMargin) && !(secIsCurrent && revenue && finite(freeCashFlow))
        ? "Finnhub provider metric" : "SEC filing",
      asOf: finite(effectiveFcfMargin) && !(secIsCurrent && revenue && finite(freeCashFlow)) ? providerAsOf : secAsOf,
    },
    roic: { value: effectiveRoic, source: finite(derivedRoic) && secIsCurrent ? "Derived from SEC filing" : "Finnhub provider metric", asOf: finite(derivedRoic) && secIsCurrent ? secAsOf : providerAsOf },
    profitMargin: { value: effectiveProfitMargin, source: finite(profitMargin) && secIsCurrent ? "Derived from SEC filing" : "Finnhub provider metric", asOf: finite(profitMargin) && secIsCurrent ? secAsOf : providerAsOf },
    returnOnEquity: { value: effectiveReturnOnEquity, source: finite(derivedReturnOnEquity) && secIsCurrent ? "Derived from SEC filing" : "Finnhub provider metric", asOf: finite(derivedReturnOnEquity) && secIsCurrent ? secAsOf : providerAsOf },
    capitalRatio: { value: effectiveCapitalRatio, source: "Derived from SEC filing", asOf: secAsOf },
    netDebtEbitda: { value: effectiveNetDebtEbitda, source: finite(derivedNetDebtEbitda) && secIsCurrent ? "Derived SEC operating-income proxy" : "Finnhub provider metric", asOf: finite(derivedNetDebtEbitda) && secIsCurrent ? secAsOf : providerAsOf },
    interestCoverage: { value: effectiveInterestCoverage, source: finite(derivedInterestCoverage) && secIsCurrent ? "Derived from SEC filing" : "Finnhub provider metric", asOf: finite(derivedInterestCoverage) && secIsCurrent ? secAsOf : providerAsOf },
    dilution: { value: effectiveDilution, source: shares && priorShares && secIsCurrent ? "SEC filing" : "Finnhub provider metric", asOf: shares && priorShares && secIsCurrent ? secAsOf : providerAsOf },
    forwardPE: {
      value: forwardPE,
      source: `Price / ${referenceEpsSelection.basis.charAt(0).toLowerCase()}${referenceEpsSelection.basis.slice(1)}`,
      asOf: referenceEpsSelection.asOf || asOf,
    },
    dcfUpside: { value: modeledUpside, source: "Implied Lens normalized earnings-value model", asOf },
    impliedGrowthGap: { value: impliedGrowthGap, source: "Implied Lens price-expectations model", asOf },
    bearDownside: { value: bearDownside, source: "Implied Lens conservative earnings-value model", asOf },
  };
  return {
    values,
    fields,
    asOf,
    coverage: Object.values(fields).filter(field => finite(field.value)).length / Object.keys(fields).length,
    modeledValue,
    bearValue,
    fairMultiple,
    referenceEps,
    referenceEpsBasis: referenceEpsSelection.basis,
    referenceEpsAsOf: referenceEpsSelection.asOf,
    referenceEpsQuarters: referenceEpsSelection.quarters,
    freshness: fundamentalFreshness,
    reportedAsOf: secAsOf,
    earningsCurrencyMismatch,
    perShareBasisMismatch,
  };
}

function deriveEarnings(companyFacts, finnhub = {}) {
  if (Array.isArray(finnhub.earnings) && finnhub.earnings.length) {
    return finnhub.earnings.slice(0, 20).map(row => ({
      period: row.period || null,
      quarter: row.quarter || null,
      year: row.year || null,
      actual: number(row.actual),
      estimate: number(row.estimate),
      surprise: number(row.surprise),
      surprisePercent: number(row.surprisePercent),
      source: "Finnhub",
      asOf: row.period || null,
    }));
  }
  return quarterlySeries(companyFacts, CONCEPTS.dilutedEps).slice(-20).reverse().map(row => ({
    period: row.end,
    quarter: row.fp || null,
    year: row.fy || Number(row.end.slice(0, 4)),
    actual: number(row.val),
    estimate: null,
    surprise: null,
    surprisePercent: null,
    source: "SEC EDGAR XBRL",
    asOf: row.filed,
  }));
}

async function buildResearchBundle(ticker, options = {}) {
  const normalized = researchTicker(ticker);
  if (!normalized) throw new Error("Invalid ticker.");
  const [priceResult, factsResult, finnhubResult] = await Promise.allSettled([
    loadPriceHistory(normalized, { range: options.range || "5y", interval: options.interval || "1d" }),
    loadCompanyFacts(normalized),
    loadFinnhubResearch(normalized),
  ]);
  if (priceResult.status !== "fulfilled") throw priceResult.reason;

  const price = priceResult.value;
  const companyFacts = factsResult.status === "fulfilled" ? factsResult.value : null;
  const finnhub = finnhubResult.status === "fulfilled" ? finnhubResult.value : {
    estimates: null, metrics: null, profile: null, earnings: [],
    provenance: provider("Finnhub", "https://finnhub.io/", new Date().toISOString(), {
      status: "unavailable",
      note: "Research feeds were unavailable.",
    }),
  };
  const latestPrice = price.bars.at(-1)?.close;
  const fundamentals = deriveFundamentals(companyFacts, latestPrice, finnhub, {
    currency: price.meta.currency,
  });
  const retrievedAt = new Date().toISOString();
  const secProvenance = companyFacts?.provenance || provider(
    "SEC EDGAR XBRL",
    "https://data.sec.gov/",
    retrievedAt,
    {
      status: "unavailable",
      note: `No compatible company filing was available${factsResult.reason?.message ? `: ${factsResult.reason.message}` : "."}`,
    }
  );
  const warnings = [];
  if (price.freshness?.status !== "current") warnings.push("Market history is not current.");
  if (fundamentals.freshness?.status === "stale") {
    warnings.push(`Company evidence is stale${fundamentals.reportedAsOf ? ` (${fundamentals.reportedAsOf})` : ""} and was excluded where no current provider metric was available.`);
  }
  if (fundamentals.earningsCurrencyMismatch) {
    warnings.push("Raw per-share earnings used a different currency than the traded security; valuation was normalized through the provider P/E instead.");
  } else if (fundamentals.perShareBasisMismatch) {
    warnings.push("Raw per-share earnings did not match the traded share class; valuation was normalized through the provider P/E instead.");
  }
  if (!companyFacts) warnings.push("SEC company facts were unavailable; LensValue uses only verified provider metrics that were returned.");
  return {
    schemaVersion: "1.0.0",
    ticker: normalized,
    company: finnhub.profile?.name || companyFacts?.name || price.meta.name || normalized,
    market: price,
    fundamentals,
    earnings: deriveEarnings(companyFacts, finnhub),
    provenance: {
      retrievedAt,
      asOf: {
        market: price.provenance.asOf,
        fundamentals: fundamentals.asOf,
      },
      freshness: {
        market: price.freshness || freshness(price.provenance.asOf, MARKET_MAX_AGE_MS),
        fundamentals: fundamentals.freshness,
      },
      sources: [price.provenance, secProvenance, finnhub.provenance],
      synthetic: false,
      warnings,
      unavailableFields: Object.entries(fundamentals.values)
        .filter(([, value]) => !finite(value))
        .map(([key]) => key),
    },
  };
}

module.exports = {
  CONCEPTS,
  annualSeries,
  buildResearchBundle,
  deriveEarnings,
  deriveFundamentals,
  freshness,
  instantSeries,
  loadCompanyFacts,
  loadFinnhubResearch,
  loadPriceHistory,
  parseYahooChart,
  quarterlySeries,
  researchTicker,
  resolveCompany,
  selectReferenceEps,
  trailingFourQuarterEps,
};

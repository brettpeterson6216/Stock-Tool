"use strict";

const { FINNHUB_KEY } = require("./config");
const { normalizeTicker } = require("./plan");
const { recordProvider } = require("./provider-health");

const SEC_USER_AGENT = process.env.SEC_USER_AGENT || "ImpliedLens/1.2 support@impliedlens.com";
const cache = new Map();
const CACHE_LIMIT = 300;

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
  const normalized = normalizeTicker(ticker);
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
      asOf: new Date(latest.time * 1000).toISOString(),
      fallback,
      delayed: true,
      note: "Latest available provider observation; not represented as a real-time exchange feed.",
    }),
  };
}

async function loadPriceHistory(ticker, { range = "5y", interval = "1d" } = {}) {
  const normalized = normalizeTicker(ticker);
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
    const latestFiled = Object.values(facts?.facts?.["us-gaap"] || {})
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
  const gaap = companyFacts?.facts?.facts?.["us-gaap"] || {};
  const rows = [];
  for (const concept of concepts) {
    const units = gaap[concept]?.units || {};
    for (const unit of preferredUnits) {
      for (const fact of units[unit] || []) {
        if (!finite(fact.val) || !fact.end || !fact.filed) continue;
        rows.push({ ...fact, concept, unit });
      }
    }
  }
  return rows;
}

function annualSeries(companyFacts, concepts, { duration = true } = {}) {
  const rows = conceptFacts(companyFacts, concepts)
    .filter(row => row.form === "10-K" || row.form === "10-K/A")
    .filter(row => {
      if (!duration || !row.start) return true;
      const days = (new Date(row.end) - new Date(row.start)) / 86400000;
      return days >= 300 && days <= 400;
    });
  const byEnd = new Map();
  for (const row of rows) {
    const existing = byEnd.get(row.end);
    if (!existing || row.filed > existing.filed) byEnd.set(row.end, row);
  }
  return [...byEnd.values()].sort((a, b) => a.end.localeCompare(b.end));
}

function quarterlySeries(companyFacts, concepts) {
  const rows = conceptFacts(companyFacts, concepts)
    .filter(row => ["10-Q", "10-Q/A", "10-K", "10-K/A"].includes(row.form))
    .filter(row => {
      if (!row.start) return false;
      const days = (new Date(row.end) - new Date(row.start)) / 86400000;
      return days >= 70 && days <= 120;
    });
  const byEnd = new Map();
  for (const row of rows) {
    const existing = byEnd.get(row.end);
    if (!existing || row.filed > existing.filed) byEnd.set(row.end, row);
  }
  return [...byEnd.values()].sort((a, b) => a.end.localeCompare(b.end));
}

const CONCEPTS = Object.freeze({
  revenue: ["RevenueFromContractWithCustomerExcludingAssessedTax", "Revenues", "SalesRevenueNet"],
  netIncome: ["NetIncomeLoss", "ProfitLoss"],
  dilutedEps: ["EarningsPerShareDiluted"],
  operatingIncome: ["OperatingIncomeLoss"],
  interestExpense: ["InterestExpenseNonOperating", "InterestExpense"],
  operatingCashFlow: ["NetCashProvidedByUsedInOperatingActivities"],
  capex: ["PaymentsToAcquirePropertyPlantAndEquipment", "PaymentsToAcquireProductiveAssets", "CapitalExpenditures"],
  cash: ["CashAndCashEquivalentsAtCarryingValue", "CashCashEquivalentsRestrictedCashAndRestrictedCashEquivalents"],
  assets: ["Assets"],
  debt: ["LongTermDebtAndFinanceLeaseObligationsCurrent", "LongTermDebtCurrent", "LongTermDebtNoncurrent", "LongTermDebt"],
  equity: ["StockholdersEquity", "StockholdersEquityIncludingPortionAttributableToNoncontrollingInterest"],
  shares: ["WeightedAverageNumberOfDilutedSharesOutstanding", "CommonStockSharesOutstanding"],
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
  const aggregate = annualSeries(companyFacts, ["LongTermDebt"], { duration: false });
  const aggregateValue = valueAtEnd(aggregate, end);
  if (finite(aggregateValue)) return aggregateValue;
  const current = valueAtEnd(
    annualSeries(companyFacts, ["LongTermDebtAndFinanceLeaseObligationsCurrent", "LongTermDebtCurrent"], { duration: false }),
    end
  );
  const noncurrent = valueAtEnd(
    annualSeries(companyFacts, ["LongTermDebtAndFinanceLeaseObligationsNoncurrent", "LongTermDebtNoncurrent"], { duration: false }),
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

function deriveFundamentals(companyFacts, price, finnhub = {}) {
  const revenueSeries = annualSeries(companyFacts, CONCEPTS.revenue);
  const epsSeries = annualSeries(companyFacts, CONCEPTS.dilutedEps);
  const ocfSeries = annualSeries(companyFacts, CONCEPTS.operatingCashFlow);
  const capexSeries = annualSeries(companyFacts, CONCEPTS.capex);
  const operatingIncomeSeries = annualSeries(companyFacts, CONCEPTS.operatingIncome);
  const netIncomeSeries = annualSeries(companyFacts, CONCEPTS.netIncome);
  const interestSeries = annualSeries(companyFacts, CONCEPTS.interestExpense);
  const equitySeries = annualSeries(companyFacts, CONCEPTS.equity, { duration: false });
  const cashSeries = annualSeries(companyFacts, CONCEPTS.cash, { duration: false });
  const assetSeries = annualSeries(companyFacts, CONCEPTS.assets, { duration: false });
  const shareSeries = annualSeries(companyFacts, CONCEPTS.shares);

  const [revenue, priorRevenue] = latestPair(revenueSeries);
  const [eps, priorEps] = latestPair(epsSeries);
  const [shares, priorShares] = latestPair(shareSeries);
  const measurementEnd = revenue?.end || eps?.end || null;
  const operatingCashFlow = valueAtEnd(ocfSeries, measurementEnd);
  const capex = valueAtEnd(capexSeries, measurementEnd);
  const operatingIncome = valueAtEnd(operatingIncomeSeries, measurementEnd);
  const netIncome = valueAtEnd(netIncomeSeries, measurementEnd);
  const interestExpenseRaw = valueAtEnd(interestSeries, measurementEnd);
  const interestExpense = finite(interestExpenseRaw) ? Math.abs(Number(interestExpenseRaw)) : null;
  const equity = valueAtEnd(equitySeries, measurementEnd);
  const cash = valueAtEnd(cashSeries, measurementEnd);
  const assets = valueAtEnd(assetSeries, measurementEnd);
  const debt = latestDebtAtEnd(companyFacts, measurementEnd);
  const freeCashFlow = finite(operatingCashFlow) && finite(capex)
    ? Number(operatingCashFlow) - Math.abs(Number(capex))
    : null;

  const reportedRevenueGrowth = revenue && priorRevenue ? ratio(revenue.val - priorRevenue.val, Math.abs(priorRevenue.val)) : null;
  const reportedEpsGrowth = eps && priorEps && Number(priorEps.val) !== 0
    ? ratio(eps.val - priorEps.val, Math.abs(priorEps.val))
    : null;
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

  const revenueGrowth = finite(forwardRevenueGrowth) ? forwardRevenueGrowth : reportedRevenueGrowth;
  const epsGrowth = estimatedEps && eps && Number(eps.val) > 0
    ? ratio(estimatedEps.epsAvg - eps.val, Math.abs(eps.val))
    : reportedEpsGrowth;
  const fcfMargin = revenue && finite(freeCashFlow) ? ratio(freeCashFlow, revenue.val) : null;
  const investedCapital = finite(debt) && finite(equity) && finite(cash)
    ? Number(debt) + Number(equity) - Number(cash)
    : null;
  const roic = finite(operatingIncome) && finite(investedCapital) && investedCapital > 0
    ? Number(operatingIncome) * 0.79 / investedCapital
    : null;
  const profitMargin = revenue && finite(netIncome) ? ratio(netIncome, revenue.val) : null;
  const returnOnEquity = finite(netIncome) && finite(equity) && Number(equity) > 0
    ? Number(netIncome) / Number(equity)
    : null;
  const capitalRatio = finite(equity) && finite(assets) && Number(assets) > 0
    ? Number(equity) / Number(assets)
    : null;
  const netDebt = finite(debt) && finite(cash) ? Number(debt) - Number(cash) : null;
  const netDebtEbitda = finite(netDebt) && finite(operatingIncome) && Number(operatingIncome) > 0
    ? Number(netDebt) / Number(operatingIncome)
    : null;
  const interestCoverage = finite(operatingIncome) && finite(interestExpense) && interestExpense > 0
    ? Number(operatingIncome) / interestExpense
    : null;
  const dilution = shares && priorShares && Number(priorShares.val) > 0
    ? ratio(shares.val - priorShares.val, priorShares.val)
    : null;

  const referenceEpsSelection = selectReferenceEps({
    estimatedEps,
    reportedAnnualEps: eps,
    earnings: [...(finnhub.earnings || []), ...reportedQuarterlyEps],
  });
  const referenceEps = referenceEpsSelection.value;
  const forwardPE = finite(referenceEps) && Number(referenceEps) > 0 && finite(price)
    ? Number(price) / Number(referenceEps)
    : number(finnhub.metrics?.peNormalizedAnnual || finnhub.metrics?.peBasicExclExtraTTM);
  const supportedGrowth = clamp(
    [revenueGrowth, epsGrowth].filter(finite).reduce((sum, value) => sum + Number(value), 0) /
      Math.max(1, [revenueGrowth, epsGrowth].filter(finite).length),
    -0.2,
    0.35
  );
  const fairMultiple = finite(roic)
    ? clamp(11 + supportedGrowth * 55 + Math.max(0, Number(roic)) * 28, 8, 36)
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

  const asOf = [revenue, eps, shares].filter(Boolean).map(row => row.filed).sort().at(-1) || null;
  const values = {
    revenueGrowth,
    epsGrowth,
    fcfMargin,
    roic,
    profitMargin,
    returnOnEquity,
    capitalRatio,
    netDebtEbitda,
    interestCoverage,
    dilution,
    forwardPE,
    dcfUpside: modeledUpside,
    impliedGrowthGap,
    bearDownside,
  };
  const fields = {
    revenueGrowth: { value: revenueGrowth, source: finite(forwardRevenueGrowth) ? "Finnhub consensus" : "SEC filing", asOf },
    epsGrowth: { value: epsGrowth, source: estimatedEps ? "Finnhub consensus + SEC filing" : "SEC filing", asOf },
    fcfMargin: { value: fcfMargin, source: "SEC filing", asOf },
    roic: { value: roic, source: "Derived from SEC filing", asOf },
    profitMargin: { value: profitMargin, source: "Derived from SEC filing", asOf },
    returnOnEquity: { value: returnOnEquity, source: "Derived from SEC filing", asOf },
    capitalRatio: { value: capitalRatio, source: "Derived from SEC filing", asOf },
    netDebtEbitda: { value: netDebtEbitda, source: "Derived SEC operating-income proxy", asOf },
    interestCoverage: { value: interestCoverage, source: "Derived from SEC filing", asOf },
    dilution: { value: dilution, source: "SEC filing", asOf },
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
  const normalized = normalizeTicker(ticker);
  if (!normalized) throw new Error("Invalid ticker.");
  const [priceResult, factsResult, finnhubResult] = await Promise.allSettled([
    loadPriceHistory(normalized, { range: options.range || "5y", interval: options.interval || "1d" }),
    loadCompanyFacts(normalized),
    loadFinnhubResearch(normalized),
  ]);
  if (priceResult.status !== "fulfilled") throw priceResult.reason;
  if (factsResult.status !== "fulfilled") throw new Error(
    `Reported company financials are unavailable: ${factsResult.reason?.message || "SEC EDGAR request failed"}.`
  );

  const price = priceResult.value;
  const companyFacts = factsResult.value;
  const finnhub = finnhubResult.status === "fulfilled" ? finnhubResult.value : {
    estimates: null, metrics: null, profile: null, earnings: [],
    provenance: provider("Finnhub", "https://finnhub.io/", new Date().toISOString(), {
      status: "unavailable",
      note: "Research feeds were unavailable.",
    }),
  };
  const latestPrice = price.bars.at(-1)?.close;
  const fundamentals = deriveFundamentals(companyFacts, latestPrice, finnhub);
  const retrievedAt = new Date().toISOString();
  return {
    schemaVersion: "1.0.0",
    ticker: normalized,
    company: finnhub.profile?.name || companyFacts.name || price.meta.name || normalized,
    market: price,
    fundamentals,
    earnings: deriveEarnings(companyFacts, finnhub),
    provenance: {
      retrievedAt,
      asOf: {
        market: price.provenance.asOf,
        fundamentals: fundamentals.asOf,
      },
      sources: [price.provenance, companyFacts.provenance, finnhub.provenance],
      synthetic: false,
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
  loadCompanyFacts,
  loadFinnhubResearch,
  loadPriceHistory,
  quarterlySeries,
  resolveCompany,
  selectReferenceEps,
  trailingFourQuarterEps,
};

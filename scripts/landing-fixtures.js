// Synthetic fixtures shaped like the live API responses (NVDA-like numbers).
function rng(seed) { let s = seed; return () => (s = (s * 16807) % 2147483647) / 2147483647; }

function quote(range, tk) {
  const seed = [...String(tk||'NVDA')].reduce((a,c)=>a*31+c.charCodeAt(0),7)%2147483646+1;
  const r = rng(seed);
  const day = 86400;
  let n, step, startPx;
  if (range === "1d") { n = 78; step = 300; } else if (range === "5d") { n = 65; step = 1800; }
  else if (range === "5y") { n = 260; step = 7 * day; } else if (range === "max") { n = 320; step = 30 * day; } else { n = 503; step = day; }
  const end = 1793367000;
  const ts = [], o = [], hh = [], l = [], c = [], v = [];
  let px = range === "max" ? 1 : range === "5y" ? 20 : range === "1d" || range === "5d" ? 213 : 135;
  const target = 204.64;
  for (let i = 0; i < n; i++) {
    const t = end - (n - 1 - i) * step;
    const drift = Math.log(target / px) / (n - i);
    const ch = drift + (r() - 0.5) * (range === "1d" ? 0.004 : 0.045);
    const open = px; px = px * Math.exp(ch);
    ts.push(t); o.push(+open.toFixed(2)); c.push(+px.toFixed(2));
    hh.push(+(Math.max(open, px) * (1 + r() * 0.012)).toFixed(2)); l.push(+(Math.min(open, px) * (1 - r() * 0.012)).toFixed(2));
    v.push(Math.round(120e6 + r() * 150e6));
  }
  c[c.length - 1] = target;
  return {
    chart: { result: [{ meta: { currency: "USD", symbol: "NVDA", fullExchangeName: "NasdaqGS", regularMarketPrice: 204.64, chartPreviousClose: 213.66, longName: "NVIDIA Corporation", shortName: "NVIDIA Corporation", marketCap: 4931824000000, trailingPE: 25.87, beta: 2.06, sector: "Technology", industry: "Semiconductors & Related Devices" }, timestamp: ts, indicators: { quote: [{ open: o, high: hh, low: l, close: c, volume: v }] } }] },
    impliedLens: { source: "Marketstack", asOf: "2026-10-30T13:30:00.000Z", latestTimestamp: end, interval: "1d", range, marketSession: "closed", fallback: false },
  };
}

const lens = {
  ticker: "NVDA", company: "NVIDIA CORP", score: { status: "graded", technical: {} },
  grades: {
    status: "graded", score: 9.9, label: "Top-rated", tone: "strong", sectorName: "Technology",
    rank: { position: 1, of: 63, sectorName: "Technology" },
    verdict: "NVIDIA is more profitable than most of its peers and it is growing faster than most. The shares are priced roughly in line with similar companies, and the balance sheet is strong.",
    factors: [
      { key: "value", label: "Value", grade: "B-", percentile: 58 }, { key: "growth", label: "Growth", grade: "A+", percentile: 93 },
      { key: "profitability", label: "Profitability", grade: "A+", percentile: 92 }, { key: "health", label: "Financial health", grade: "B+", percentile: 68 },
      { key: "momentum", label: "Momentum", grade: "B-", percentile: 56 },
    ],
    strengths: [{ factor: "Profitability", text: "Return on invested capital 73.5%: the best among Technology peers (median 10.3%)." }, { factor: "Growth", text: "Revenue growth (3-year average) 86%: far ahead of peers (median 9%)." }],
    watch: [{ factor: "Value", text: "Price to sales of 24× is higher than 70% of Technology peers." }],
    peers: ["MU", "PLTR", "MSFT"],
    street: { nextEarnings: { date: "2026-11-18", days: 18, estimated: true } },
  },
  provenance: { asOf: { fundamentals: "2026-08-27" } },
};

function hist() {
  const quarters = [];
  let rev = 6.7e9;
  const ends = [];
  for (let y = 2022; y <= 2026; y++) for (const m of ["01-31", "04-30", "07-31", "10-31"]) ends.push(`${y}-${m}`);
  const use = ends.filter(e => e <= "2026-07-31").slice(-16);
  use.forEach((end, i) => {
    rev = rev * (i < 4 ? 1.02 : i < 10 ? 1.32 : 1.12);
    const gp = rev * 0.72, op = rev * 0.6, ni = rev * 0.53, sh = 24.5e9 - i * 3e7;
    const ocf = ni * 1.05, capex = rev * 0.03;
    quarters.push({ end, label: ["Jan", "Apr", "Jul", "Oct"][["01", "04", "07", "10"].indexOf(end.slice(5, 7))] + " " + end.slice(0, 4), revenue: rev, grossProfit: gp, operatingIncome: op, netIncome: ni, eps: ni / sh, operatingCashFlow: ocf, capex, freeCashFlow: ocf - capex, shares: sh, derived: i % 4 === 3 ? ["revenue"] : [] });
  });
  return { ticker: "NVDA", name: "NVIDIA CORP", quarters, filings: { "2026-07-31": { form: "10-Q", filed: "2026-08-27", url: "https://www.sec.gov/" } }, calendar: "Quarters that line up with the calendar are labelled Q1–Q4; others by the month they end." };
}

function annual() {
  const yrs = ["2021", "2022", "2023", "2024", "2025", "2026"];
  const rev = [16.7e9, 26.9e9, 27e9, 60.9e9, 130.5e9, 216e9];
  const row = (fn) => yrs.map((y, i) => ({ endDate: { fmt: y, raw: Date.UTC(+y, 11, 31) / 1000 }, ...fn(i) }));
  return {
    impliedLens: { source: "SEC EDGAR XBRL" },
    quoteSummary: { result: [{
      incomeStatementHistory: { incomeStatementHistory: row(i => ({ totalRevenue: { raw: rev[i] }, grossProfit: { raw: rev[i] * 0.7 }, operatingIncome: { raw: rev[i] * 0.55 }, netIncome: { raw: rev[i] * 0.5 }, dilutedEps: { raw: rev[i] * 0.5 / 24.6e9 } })) },
      balanceSheetHistory: { balanceSheetStatements: row(i => ({ cash: { raw: rev[i] * 0.1 }, shortTermInvestments: { raw: rev[i] * 0.2 }, totalCurrentAssets: { raw: rev[i] * 0.6 }, totalAssets: { raw: rev[i] * 0.9 }, longTermDebt: { raw: 8.5e9 }, totalLiab: { raw: rev[i] * 0.25 }, totalStockholderEquity: { raw: rev[i] * 0.65 } })) },
      cashflowStatementHistory: { cashflowStatements: row(i => ({ totalCashFromOperatingActivities: { raw: rev[i] * 0.5 }, capitalExpenditures: { raw: -rev[i] * 0.03 }, totalCashflowsFromInvestingActivities: { raw: -rev[i] * 0.15 }, totalCashFromFinancingActivities: { raw: -rev[i] * 0.3 } })) },
    }] },
  };
}

const calls = {
  releases: [
    { id: "0001045810-26-000101", date: "2026-08-26", title: "Fiscal Q2 2027 results", pending: false, indexUrl: "https://www.sec.gov/", quarter: { label: "Fiscal Q2 2027", calendarLabel: "Jul 2026", revenue: 96.2e9, eps: 2.46, revenueYoY: 106, epsYoY: 112 }, report: { form: "10-Q", url: "https://www.sec.gov/" } },
    { id: "0001045810-26-000077", date: "2026-05-27", title: "Fiscal Q1 2027 results", pending: false, indexUrl: "https://www.sec.gov/", quarter: { label: "Fiscal Q1 2027", calendarLabel: "Apr 2026", revenue: 81.1e9, eps: 2.02, revenueYoY: 85, epsYoY: 90 }, report: { form: "10-Q", url: "https://www.sec.gov/" } },
    { id: "0001045810-26-000010", date: "2026-02-25", title: "Latest results", pending: true, indexUrl: "https://www.sec.gov/", quarter: null },
  ],
};
const funds = {
  holders: [
    { fund: "Tiger Global", who: "Chase Coleman", period: "2026-06-30", url: "https://www.sec.gov/", shares: 12e6, value: 2.4e9, weight: 7.1, change: "reduced", changePct: -18 },
    { fund: "Appaloosa", who: "David Tepper", period: "2026-06-30", shares: 4.1e6, value: 0.8e9, weight: 11.2, change: "added", changePct: 24 },
    { fund: "ARK Invest", who: "Cathie Wood", period: "2026-06-30", shares: 2.2e6, value: 0.44e9, weight: 2.1, change: "added", changePct: 9 },
    { fund: "Duquesne Family Office", who: "Stanley Druckenmiller", period: "2026-06-30", shares: 1.5e6, value: 0.3e9, weight: 6, change: "new" },
  ],
  soldOut: [{ fund: "Scion", who: "Michael Burry", period: "2026-06-30", prevShares: 900000 }],
  managersTracked: 28, loading: false, latestPeriod: "2026-06-30",
  note: "13F filings show positions at quarter end and are filed up to 45 days later. They list US-listed shares only; short positions are not reported.",
};
const news = [
  { headline: "NVIDIA announces financial results for second quarter fiscal 2027", summary: "Record revenue of $96.2 billion, up 106% from a year ago.", source: "SEC 8-K", url: "https://www.sec.gov/", datetime: 1787750000, category: "filing" },
  { headline: "Director change", summary: "The board appointed a new independent director.", source: "SEC 8-K", url: "https://www.sec.gov/", datetime: 1786000000, category: "filing" },
];
const sec = { filings: [
  { form: "10-Q", date: "2026-08-27", description: "Quarterly report", viewerUrl: "https://www.sec.gov/" },
  { form: "8-K", date: "2026-08-26", description: "Results of operations", viewerUrl: "https://www.sec.gov/" },
  { form: "4", date: "2026-08-20", description: "4", viewerUrl: "https://www.sec.gov/" },
  { form: "DEF 14A", date: "2026-05-10", description: "Proxy statement", viewerUrl: "https://www.sec.gov/" },
  { form: "10-K", date: "2026-02-26", description: "Annual report", viewerUrl: "https://www.sec.gov/" },
] };
const ins = { insiders: [
  { name: "Jensen Huang", role: "CEO", change: -75000, shares: 75000, price: 210.1, date: "2026-09-12", code: "S", url: "https://www.sec.gov/" },
  { name: "Mark Stevens", role: "Director", change: 20000, shares: 20000, price: 188.2, date: "2026-08-02", code: "P", url: "https://www.sec.gov/" },
  { name: "Colette Kress", role: "CFO", change: 40000, shares: 40000, price: 0, date: "2026-07-20", code: "M" },
], insiderSummary: { buys: 1, sells: 6, buyValue: 3.7e6, sellValue: 410e6, since: "2026-05-01" } };
const dark = { otcActivity: [{ weekStartDate: "2026-10-12", totalWeeklyShareQuantity: 210e6, totalWeeklyTradeCount: 2.1e6, averageReportedPrice: 215.2 }, { weekStartDate: "2026-10-05", totalWeeklyShareQuantity: 190e6, totalWeeklyTradeCount: 1.9e6, averageReportedPrice: 218.9 }] };
const peers = { grades: {
  AAPL: { score: 6.7, change: -0.6, grades: { value: "C", growth: "B-", profitability: "A", health: "B", momentum: "C+" } },
  COST: { score: 7.9, change: 0.3, grades: { value: "D", growth: "B", profitability: "B+", health: "A-", momentum: "B" } },
  NVDA: { score: 9.9, grades: { value: "B-", growth: "A+", profitability: "A+", health: "B+", momentum: "B-" } },
  MU: { score: 8.1, grades: { value: "A-", growth: "A", profitability: "B", health: "B", momentum: "B+" } },
  PLTR: { score: 6.2, grades: { value: "D", growth: "A", profitability: "B+", health: "A", momentum: "C" } },
  MSFT: { score: 7.4, grades: { value: "C", growth: "B", profitability: "A", health: "A-", momentum: "C+" } },
} };
const leaders = { universe: 279, top: [{ ticker: "NVDA", name: "NVIDIA CORP", score: 9.9, sectorName: "Technology", sectorRank: 1, sectorCount: 63, grades: { value: "B-", growth: "A+", profitability: "A+", health: "B+", momentum: "B-" } }, { ticker: "LLY", name: "ELI LILLY", score: 9.1, sectorName: "Health care", sectorRank: 1, sectorCount: 40, grades: { value: "C", growth: "A+", profitability: "A", health: "B", momentum: "A" } }], historyStarts: "2026-10-27", trackRecord: { startDay: "2026-10-27", endDay: "2026-10-30", companies: 268, allAverage: -1.9, bands: [{ key: "top", label: "Top-rated (8.0+)", count: 41, averageReturn: -0.8, beatAll: 1.1 }, { key: "above", label: "Above average (6.5–7.9)", count: 70, averageReturn: -1.5, beatAll: 0.4 }, { key: "middle", label: "Middle (4.5–6.4)", count: 90, averageReturn: -2.2, beatAll: -0.3 }, { key: "below", label: "Below average (3.0–4.4)", count: 47, averageReturn: -2.6, beatAll: -0.7 }, { key: "bottom", label: "Bottom-rated (under 3.0)", count: 20, averageReturn: -3.4, beatAll: -1.5 }] }, movers: { since: "2026-10-27", up: [{ ticker: "REGN", name: "Regeneron", then: 6.1, now: 7.4, change: 1.3 }], down: [{ ticker: "INTC", name: "Intel", then: 4.2, now: 3.1, change: -1.1 }] }, sectors: [
  { sector: "tech", sectorName: "Technology", count: 63, top: [{ ticker: "NVDA", name: "NVIDIA", score: 9.9, grades: peers.grades.NVDA.grades }, { ticker: "MU", score: 8.1 }, { ticker: "AVGO", score: 8 }] },
  { sector: "health", sectorName: "Health care", count: 40, top: [{ ticker: "LLY", name: "Eli Lilly", score: 9.1, grades: { value: "C", growth: "A+", profitability: "A", health: "B", momentum: "A" } }, { ticker: "REGN", score: 8.4 }] },
] };
const search = { results: [{ symbol: "NVDA", name: "NVIDIA Corp" }, { symbol: "NVO", name: "Novo Nordisk" }] };

module.exports = function route(path, user) {
  const plan = user ? user.plan : "guest";
  const pro = plan === "pro" || plan === "trial";
  const need = (lvl) => (lvl === "account" && !user) ? { status: 401, body: { error: "Create a free account to see this.", requiresLogin: true } }
    : (lvl === "pro" && !pro) ? (user ? { status: 403, body: { error: "Pro plan required.", requiresPro: true } } : { status: 401, body: { error: "Login required.", requiresLogin: true } }) : null;
  const p = path.split("?")[0];
  const q = new URLSearchParams(path.split("?")[1] || "");
  const ok = (b) => ({ status: 200, body: b });
  if (p === "/api/auth/me") return user ? ok({ user }) : { status: 401, body: { error: "Not logged in" } };
  if (p === "/api/csrf") return ok({ token: "t" });
  if (p.startsWith("/api/quote/")) return ok(quote(q.get("range") || "1y", p.split("/")[3]));
  if (p.startsWith("/api/lens-score/")) return ok(lens);
  if (p.startsWith("/api/fundamentals/history/")) return need("account") || ok(hist());
  if (p.startsWith("/api/financials/")) return need("account") || ok(annual());
  if (p.startsWith("/api/funds/")) return ok(funds);
  if (p.startsWith("/api/news/")) return ok(news);
  if (/^\/api\/calls\/[^/]+\/.+/.test(p)) return need("pro") || ok({ paragraphs: ["NVIDIA reported record revenue of $96.2 billion for the second quarter.", "Data Center revenue was a record, up strongly from a year ago."] });
  if (p.startsWith("/api/calls/")) return need("pro") || ok(calls);
  if (p.startsWith("/api/sec/")) return need("pro") || ok(sec);
  if (p.startsWith("/api/institutional/")) return need("pro") || ok(ins);
  if (p.startsWith("/api/darkpool/")) return need("pro") || ok(dark);
  if (p.startsWith("/api/lens-grades")) return ok(peers);
  if (p === "/api/screener") { if (!pro) return need("pro"); const T=["NVDA","AAPL","MSFT","AMZN","GOOGL","META","TSLA","COST","JPM","LLY","AVGO","NFLX","AMD","INTC","WMT","KO","PEP","XOM","CVX","UNH","V","MA","HD","PG","MU","PLTR","REGN","WEC","VLO","BAC"]; const S=["Technology","Technology","Technology","Consumer","Communication","Communication","Consumer","Consumer","Financials","Health care","Technology","Communication","Technology","Technology","Consumer","Staples","Staples","Energy","Energy","Health care","Financials","Financials","Consumer","Staples","Technology","Technology","Health care","Utilities","Energy","Financials"]; const G=["A+","A","A-","B+","B","B-","C+","C","D","F"]; return ok(T.map((t,i)=>({ ticker:t, name:t+" CORP", sector:S[i], price:50+i*13.7, change1D:((i*7)%9-4)/2, change1Y:((i*37)%120)-40, revenueGrowth:((i*17)%70)-10, marketCap:(i%7+1)*1.3e11, pe:12+(i*11)%60, dividendYield:(i%4)*0.9, beta:0.6+(i%5)*0.3, lensScore:+(9.9-i*0.29).toFixed(1), grades:{value:G[(i*3)%10],growth:G[(i*5)%10],profitability:G[(i*2)%10],health:G[(i*7)%10],momentum:G[(i)%10]} }))); }
  if (p.startsWith("/api/lens-leaders")) return ok(leaders);
  if (p.startsWith("/api/search")) return ok(search);
  if (p.startsWith("/api/workspace/watchlist")) return need("account") || ok(["NVDA","AAPL","MSFT","PLTR","COST"].map((t,i) => ({ id:i+1, ticker: t, note: i===0?"Buy more under $180 if data-center growth holds":"", target_price: i===0?180:(i===2?150:null) })));
  if (p.startsWith("/api/market/snapshot")) return ok({ quotes: (q.get("tickers")||"").split(",").map((t,i) => ({ symbol: t, name: t + " INC", price: 100 + i * 37.3, chgPct: (i % 2 ? -1 : 1) * (0.4 + i), asOf: "2026-10-30" })) });
  if (p.startsWith("/api/market/landing-summary")) { const ser=(b,d)=>Array.from({length:30},(_,i)=>+(b*(1+d*i/30+Math.sin(i/3)*0.01)).toFixed(2)); return ok({ window:"1M", indexes:[{symbol:"^GSPC",name:"S&P 500 (SPY)",price:684.2,changePct:0.42,closes:ser(660,0.035)},{symbol:"^IXIC",name:"Nasdaq (QQQ)",price:612.8,changePct:0.87,closes:ser(580,0.05)},{symbol:"^DJI",name:"Dow Jones (DIA)",price:471.3,changePct:-0.18,closes:ser(468,0.006)}], sectors:[{symbol:"XLK",name:"Technology",changePct:1.12},{symbol:"XLC",name:"Comm. Services",changePct:0.64},{symbol:"XLI",name:"Industrials",changePct:-0.21},{symbol:"XLF",name:"Financials",changePct:0.33},{symbol:"XLE",name:"Energy",changePct:-0.92},{symbol:"XLRE",name:"Real Estate",changePct:0.08}], breadth:67, advancing:4, measured:6, asOf:"2026-11-02T19:00:00Z" }); }
  if (p.startsWith("/api/market/movers")) return ok([["REGN",13.3],["SMCI",7.1],["PLTR",5.2],["TSLA",4.4],["AMD",3.9],["MU",3.1]].map(([s,c]) => ({ symbol: s, name: s + " CORP", price: 100, chgPct: q.get("type")==="losers" ? -c : c, asOf: "2026-10-30" })));
  if (p === "/api/alerts") return ok({ alerts: [{ id: 1, ticker: "NVDA", kind: "below", level: 180, active: true }, { id: 2, ticker: "AAPL", kind: "score", level: null, active: true }, { id: 3, ticker: "MSFT", kind: "above", level: 450, active: false, triggeredAt: "2026-10-20" }], limit: 50, plan: "pro" });
  if (p.startsWith("/api/alerts")) return ok({ ok: true });
  if (p === "/api/saves") return ok([{ id: 9, ticker: "NVDA", type: "implied", label: "Base case, 25x exit", created_at: "2026-10-31 12:00:00" }, { id: 4, ticker: "COST", type: "valuation", label: "", created_at: "2026-10-05 12:00:00" }]);
  return { status: 404, body: { error: "fixture missing " + p } };
};

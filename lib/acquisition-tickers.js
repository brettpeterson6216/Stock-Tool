"use strict";

// Curated, high-interest acquisition pages. Arbitrary /stock/:ticker routes still
// work, but only this reviewed set is indexable and included in the sitemap.
const ACQUISITION_TICKERS = [
  "AAPL", "MSFT", "NVDA", "AMZN", "GOOGL", "META", "TSLA", "BRK.B", "JPM", "V",
  "MA", "AVGO", "LLY", "WMT", "XOM", "UNH", "COST", "ORCL", "HD", "PG",
  "NFLX", "JNJ", "ABBV", "BAC", "KO", "CRM", "AMD", "CVX", "MRK", "PEP",
  "TMO", "ADBE", "CSCO", "MCD", "ACN", "IBM", "GE", "CAT", "QCOM", "NOW",
  "INTU", "TXN", "AMAT", "DIS", "NKE", "UBER", "PLTR", "SHOP", "SQ", "PYPL",
  "COIN", "ROKU", "SNAP", "BA", "GS", "MS", "C", "BLK", "SCHW", "SOFI",
  "RIVN", "LCID", "F", "GM", "TM", "NVO", "PFE", "BMY", "GILD", "ISRG",
  "ABT", "DHR", "LOW", "TGT", "SBUX", "CMG", "DE", "LMT", "RTX", "NOC",
  "UPS", "FDX", "SPY", "QQQ", "DIA", "IWM", "VTI", "VOO", "ARKK", "GLD",
  "SLV", "TLT", "HYG", "USO", "SMH", "XLK", "XLF", "XLE", "XLV", "XLY",
  "XLP", "XLI", "XLU",
];

const ACQUISITION_TICKER_SET = new Set(ACQUISITION_TICKERS);

function buildSitemapXml(baseUrl = "https://impliedlens.com") {
  const root = String(baseUrl || "https://impliedlens.com").replace(/\/$/, "");
  const staticPages = [
    ["", "daily", "1.0"],
    ["/about", "monthly", "0.7"],
    ["/blog", "weekly", "0.6"],
    ["/privacy", "yearly", "0.3"],
    ["/terms", "yearly", "0.3"],
    ["/data-sources", "monthly", "0.5"],
    ["/research-process", "monthly", "0.7"],
    ["/compound-calculator", "monthly", "0.7"],
    ["/lens-score", "weekly", "0.8"],
  ];
  const entries = [
    ...staticPages.map(([pagePath, changefreq, priority]) => ({ loc: root + pagePath, changefreq, priority })),
    ...ACQUISITION_TICKERS.map(ticker => ({
      loc: `${root}/stock/${ticker}`,
      changefreq: "daily",
      priority: "0.8",
    })),
  ];

  return `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${entries.map(entry => `  <url>
    <loc>${entry.loc}</loc>
    <changefreq>${entry.changefreq}</changefreq>
    <priority>${entry.priority}</priority>
  </url>`).join("\n")}
</urlset>
`;
}

function relatedTickers(ticker, count = 10) {
  const clean = String(ticker || "").toUpperCase();
  const candidates = ACQUISITION_TICKERS.filter(item => item !== clean);
  const start = Math.max(0, ACQUISITION_TICKERS.indexOf(clean));
  return [...candidates.slice(start, start + count), ...candidates].slice(0, count);
}

module.exports = {
  ACQUISITION_TICKERS,
  ACQUISITION_TICKER_SET,
  buildSitemapXml,
  relatedTickers,
};

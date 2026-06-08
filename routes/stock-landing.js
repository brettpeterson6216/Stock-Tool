// ============================================================
//  Stock landing pages — /stock/:ticker
//
//  SEO-friendly server-rendered page for each ticker.
//  Fetches a lightweight quote snapshot from Finnhub for meta
//  tags and the hero card; all heavy analysis happens in the
//  SPA after the user clicks through.
//
//  Also handles the ?ticker= homepage param (index.html picks
//  it up client-side; this module only handles /stock/:ticker).
// ============================================================
const express  = require("express");
const { FINNHUB_KEY, APP_URL } = require("../lib/config");

const router = express.Router();

// ── Helpers ───────────────────────────────────────────────────
function esc(s) {
  return String(s || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function fmtPrice(n) {
  if (!n && n !== 0) return "—";
  return "$" + Number(n).toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 });
}

function fmtPct(n) {
  if (!n && n !== 0) return "";
  const sign = n >= 0 ? "+" : "";
  return sign + Number(n).toFixed(2) + "%";
}

function fmtBig(n) {
  if (!n) return "—";
  if (n >= 1e12) return "$" + (n / 1e12).toFixed(2) + "T";
  if (n >= 1e9)  return "$" + (n / 1e9).toFixed(2) + "B";
  if (n >= 1e6)  return "$" + (n / 1e6).toFixed(2) + "M";
  return "$" + Number(n).toLocaleString();
}

async function fetchQuickQuote(ticker) {
  if (!FINNHUB_KEY) return null;
  try {
    const [qRes, pRes] = await Promise.all([
      fetch(`https://finnhub.io/api/v1/quote?symbol=${ticker}&token=${FINNHUB_KEY}`,           { signal: AbortSignal.timeout(4000) }),
      fetch(`https://finnhub.io/api/v1/stock/profile2?symbol=${ticker}&token=${FINNHUB_KEY}`,  { signal: AbortSignal.timeout(4000) }),
    ]);
    const q = qRes.ok  ? await qRes.json()  : null;
    const p = pRes.ok  ? await pRes.json()  : null;
    if (!q || !q.c) return null;
    const chgPct = q.pc ? ((q.c - q.pc) / q.pc) * 100 : 0;
    return {
      price:     q.c,
      change:    q.c - (q.pc || q.c),
      changePct: chgPct,
      high:      q.h,
      low:       q.l,
      open:      q.o,
      prevClose: q.pc,
      name:      p?.name    || ticker,
      exchange:  p?.exchange || "",
      industry:  p?.finnhubIndustry || "",
      country:   p?.country  || "",
      logo:      p?.logo     || "",
      weburl:    p?.weburl   || "",
      marketCap: p?.marketCapitalization ? p.marketCapitalization * 1e6 : null,
      currency:  p?.currency || "USD",
    };
  } catch (_) {
    return null;
  }
}

function renderPage(ticker, q) {
  const name      = q ? esc(q.name)      : ticker;
  const price     = q ? fmtPrice(q.price)   : "—";
  const chgPct    = q ? fmtPct(q.changePct) : "";
  const isUp      = q ? q.changePct >= 0    : true;
  const chgColor  = isUp ? "#52d18a" : "#e05a5a";
  const chgSign   = isUp ? "▲" : "▼";
  const mktCap    = q ? fmtBig(q.marketCap) : "—";
  const industry  = q ? esc(q.industry) : "";
  const exchange  = q ? esc(q.exchange) : "";

  const metaTitle = q
    ? `${ticker} Stock Analysis — ${name} ${price} (${chgPct}) | ImpliedLens`
    : `${ticker} Stock Analysis | ImpliedLens`;

  const metaDesc = q
    ? `${name} (${ticker}) is trading at ${price} (${chgPct} today). Run a full DCF valuation, financial statement analysis, analyst targets, and more — free on ImpliedLens.`
    : `Analyze ${ticker} with ImpliedLens — DCF valuation, financials, analyst targets, earnings history, and institutional data.`;

  const canonicalUrl = `${APP_URL}/stock/${ticker}`;
  const analyzeUrl   = `${APP_URL}/?ticker=${ticker}`;

  // Schema.org FinancialProduct structured data
  const schema = JSON.stringify({
    "@context": "https://schema.org",
    "@type":    "WebPage",
    "name":     metaTitle,
    "description": metaDesc,
    "url":      canonicalUrl,
    "breadcrumb": {
      "@type": "BreadcrumbList",
      "itemListElement": [
        { "@type": "ListItem", "position": 1, "name": "Home",   "item": APP_URL },
        { "@type": "ListItem", "position": 2, "name": ticker,   "item": canonicalUrl },
      ],
    },
  });

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>${esc(metaTitle)}</title>
  <meta name="description" content="${esc(metaDesc)}">
  <link rel="canonical" href="${esc(canonicalUrl)}">

  <!-- Open Graph -->
  <meta property="og:type"        content="website">
  <meta property="og:url"         content="${esc(canonicalUrl)}">
  <meta property="og:title"       content="${esc(metaTitle)}">
  <meta property="og:description" content="${esc(metaDesc)}">
  <meta property="og:site_name"   content="ImpliedLens">

  <!-- Twitter Card -->
  <meta name="twitter:card"        content="summary">
  <meta name="twitter:site"        content="@ImpliedLens">
  <meta name="twitter:title"       content="${esc(metaTitle)}">
  <meta name="twitter:description" content="${esc(metaDesc)}">

  <!-- Structured data -->
  <script type="application/ld+json">${schema}</script>

  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Playfair+Display:ital,wght@0,400;0,600;1,400&family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
  <style>
    *{margin:0;padding:0;box-sizing:border-box}
    body{font-family:'Inter',sans-serif;background:#08090D;color:rgba(220,225,232,.88);min-height:100vh}
    a{text-decoration:none;color:inherit}

    /* top bar */
    .top-bar{background:rgba(255,255,255,.03);border-bottom:1px solid rgba(255,255,255,.06);
      padding:.8rem 2rem;display:flex;align-items:center;gap:1rem}
    .logo{font-family:'Playfair Display',serif;font-size:1.2rem;color:#fff}
    .logo em{color:#C8882A;font-style:italic}
    .top-bar .back{font-size:.78rem;color:rgba(220,225,232,.35);margin-left:auto}
    .top-bar .back:hover{color:#C8882A}

    /* hero */
    .hero{max-width:820px;margin:0 auto;padding:3rem 2rem 2rem}
    .breadcrumb{font-size:.72rem;color:rgba(220,225,232,.35);margin-bottom:1.25rem}
    .breadcrumb a{color:rgba(220,225,232,.35)}
    .breadcrumb a:hover{color:#C8882A}
    .ticker-badge{display:inline-block;font-family:monospace;font-size:.75rem;font-weight:700;
      letter-spacing:.08em;background:rgba(200,136,42,.12);color:#C8882A;
      border:1px solid rgba(200,136,42,.25);border-radius:5px;padding:.2rem .6rem;margin-bottom:.75rem}
    h1{font-family:'Playfair Display',serif;font-size:2rem;color:#fff;line-height:1.2;margin-bottom:.5rem}
    .exchange-tag{font-size:.75rem;color:rgba(220,225,232,.35);margin-bottom:2rem}

    /* quote card */
    .quote-card{background:rgba(255,255,255,.035);border:1px solid rgba(255,255,255,.08);
      border-radius:14px;padding:1.75rem 2rem;margin-bottom:2rem;
      display:flex;flex-wrap:wrap;gap:1.5rem;align-items:flex-start}
    .q-main{flex:1;min-width:180px}
    .q-price{font-size:2.4rem;font-weight:700;color:#fff;line-height:1;margin-bottom:.25rem}
    .q-chg{font-size:1rem;font-weight:600}
    .q-label{font-size:.7rem;color:rgba(220,225,232,.4);text-transform:uppercase;letter-spacing:.07em;margin-top:.5rem}
    .q-stats{display:flex;flex-wrap:wrap;gap:1.25rem}
    .q-stat{min-width:90px}
    .q-stat-val{font-size:.95rem;font-weight:600;color:#fff}
    .q-stat-lbl{font-size:.68rem;color:rgba(220,225,232,.4);text-transform:uppercase;letter-spacing:.06em;margin-top:.15rem}

    /* CTA */
    .cta-section{text-align:center;margin-bottom:3rem}
    .cta-btn{display:inline-block;background:#C8882A;color:#08090D;
      padding:1rem 2.5rem;border-radius:11px;font-size:1rem;font-weight:700;
      transition:opacity .15s;cursor:pointer}
    .cta-btn:hover{opacity:.85}
    .cta-note{font-size:.78rem;color:rgba(220,225,232,.35);margin-top:.65rem}

    /* what you get */
    .features{max-width:820px;margin:0 auto;padding:0 2rem 3rem}
    h2{font-family:'Playfair Display',serif;font-size:1.3rem;color:#fff;margin-bottom:1rem}
    .feat-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:.75rem}
    .feat{background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.06);
      border-radius:10px;padding:1rem 1.1rem}
    .feat-icon{font-size:1.1rem;margin-bottom:.4rem}
    .feat-title{font-size:.85rem;font-weight:600;color:#fff;margin-bottom:.2rem}
    .feat-desc{font-size:.75rem;color:rgba(220,225,232,.45);line-height:1.5}

    /* related tickers */
    .related{max-width:820px;margin:0 auto;padding:0 2rem 4rem}
    .pill-row{display:flex;flex-wrap:wrap;gap:.5rem;margin-top:.75rem}
    .ticker-pill{display:inline-block;padding:.35rem .85rem;border-radius:100px;
      background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.08);
      font-size:.78rem;font-family:monospace;font-weight:600;color:rgba(220,225,232,.7);
      transition:all .15s}
    .ticker-pill:hover{background:rgba(200,136,42,.1);border-color:rgba(200,136,42,.3);color:#C8882A}

    /* footer */
    footer{border-top:1px solid rgba(255,255,255,.06);padding:1.25rem 2rem;
      display:flex;gap:1.25rem;flex-wrap:wrap;justify-content:center;font-size:.75rem}
    footer a{color:rgba(220,225,232,.3)}
    footer a:hover{color:#C8882A}

    @media(max-width:600px){
      h1{font-size:1.5rem}
      .q-price{font-size:1.8rem}
      .hero,.features,.related{padding-left:1rem;padding-right:1rem}
    }
  </style>
</head>
<body>
  <div class="top-bar">
    <a href="/" class="logo">Implied<em>Lens</em></a>
    <a href="/" class="back">← All analysis</a>
  </div>

  <div class="hero">
    <div class="breadcrumb">
      <a href="/">ImpliedLens</a> › <a href="/stock/${esc(ticker)}">${esc(ticker)}</a>
    </div>
    <div class="ticker-badge">${esc(ticker)}</div>
    <h1>${esc(name)} Stock Analysis</h1>
    ${exchange || industry ? `<div class="exchange-tag">${[exchange, industry].filter(Boolean).join(" · ")}</div>` : ""}

    ${q ? `
    <div class="quote-card">
      <div class="q-main">
        <div class="q-price">${price}</div>
        <div class="q-chg" style="color:${chgColor}">${chgSign} ${chgPct}</div>
        <div class="q-label">Live quote · 15 min delay</div>
      </div>
      <div class="q-stats">
        <div class="q-stat">
          <div class="q-stat-val">${fmtPrice(q.open)}</div>
          <div class="q-stat-lbl">Open</div>
        </div>
        <div class="q-stat">
          <div class="q-stat-val">${fmtPrice(q.high)}</div>
          <div class="q-stat-lbl">High</div>
        </div>
        <div class="q-stat">
          <div class="q-stat-val">${fmtPrice(q.low)}</div>
          <div class="q-stat-lbl">Low</div>
        </div>
        <div class="q-stat">
          <div class="q-stat-val">${fmtPrice(q.prevClose)}</div>
          <div class="q-stat-lbl">Prev close</div>
        </div>
        <div class="q-stat">
          <div class="q-stat-val">${mktCap}</div>
          <div class="q-stat-lbl">Market cap</div>
        </div>
      </div>
    </div>` : `
    <div class="quote-card" style="justify-content:center;padding:2rem">
      <div style="color:rgba(220,225,232,.4);font-size:.9rem">Live quote unavailable — open the analyzer for full data.</div>
    </div>`}

    <div class="cta-section">
      <a href="${esc(analyzeUrl)}" class="cta-btn">Analyze ${esc(ticker)} in depth →</a>
      <div class="cta-note">Free · No account required for your first analyses</div>
    </div>
  </div>

  <div class="features">
    <h2>What you get with ImpliedLens</h2>
    <div class="feat-grid">
      <div class="feat"><div class="feat-icon">📊</div><div class="feat-title">Financial statements</div><div class="feat-desc">Income, balance sheet, cash flow from SEC filings with 30+ calculated ratios.</div></div>
      <div class="feat"><div class="feat-icon">🧮</div><div class="feat-title">DCF valuation</div><div class="feat-desc">Customizable discounted cash flow model with live inputs.</div></div>
      <div class="feat"><div class="feat-icon">🎯</div><div class="feat-title">Analyst targets</div><div class="feat-desc">Price targets, recommendation breakdowns, earnings surprises.</div></div>
      <div class="feat"><div class="feat-icon">🏦</div><div class="feat-title">Institutional data</div><div class="feat-desc">13F ownership, dark pool prints, insider transactions.</div></div>
      <div class="feat"><div class="feat-icon">📋</div><div class="feat-title">SEC filings</div><div class="feat-desc">Direct links to 10-K, 10-Q, 8-K, and proxy statements.</div></div>
      <div class="feat"><div class="feat-icon">📈</div><div class="feat-title">Projection models</div><div class="feat-desc">Bull/base/bear scenario modeling with editable assumptions.</div></div>
    </div>
  </div>

  <div class="related">
    <h2>Analyze another ticker</h2>
    <div class="pill-row">
      ${["AAPL","MSFT","NVDA","TSLA","AMZN","META","GOOGL","JPM","BRK.B","SPY","QQQ","NFLX"]
        .filter(t => t !== ticker)
        .slice(0, 10)
        .map(t => `<a href="/stock/${t}" class="ticker-pill">${t}</a>`)
        .join("")}
    </div>
  </div>

  <footer>
    <a href="/privacy">Privacy</a>
    <a href="/terms">Terms</a>
    <a href="/data-sources">Data Sources</a>
    <a href="/about">About</a>
    <a href="/">ImpliedLens</a>
  </footer>

  <script>
    // Auto-redirect to full analyzer after a short delay on CTA click
    // (also handle ?autoload=1 for programmatic deep links)
    if (new URLSearchParams(window.location.search).get('autoload') === '1') {
      window.location.href = ${JSON.stringify(analyzeUrl)};
    }
  </script>
</body>
</html>`;
}

// ── Route ─────────────────────────────────────────────────────
router.get("/stock/:ticker", async (req, res) => {
  const raw    = (req.params.ticker || "").toUpperCase().replace(/[^A-Z0-9.\-^]/g, "").slice(0, 10);
  if (!raw) return res.redirect("/");

  // Fetch live quote data (best-effort — page renders without it)
  const q = await fetchQuickQuote(raw);

  const html = renderPage(raw, q);
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  // Cache for 5 minutes on CDN, 60s stale-while-revalidate
  res.setHeader("Cache-Control", "public, max-age=300, stale-while-revalidate=60");
  res.send(html);
});

module.exports = router;

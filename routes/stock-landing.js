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
const {
  ACQUISITION_TICKER_SET,
  relatedTickers,
} = require("../lib/acquisition-tickers");
const { loadPriceHistory } = require("../lib/stock-research");

const router = express.Router();
const TICKER_RE = /^[A-Z0-9.^-]{1,15}$/;

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

function researchQuestions(name, ticker, industry) {
  const label = name && name !== ticker ? name : ticker;
  const category = String(industry || "").toLowerCase();
  let tailored = `What assumptions does the current ${ticker} price require to deliver an attractive return?`;
  if (/software|technology|semiconductor|computer|electronic/.test(category)) {
    tailored = `Can ${label} sustain growth and margins as its technology market matures?`;
  } else if (/bank|financial|insurance|capital markets/.test(category)) {
    tailored = `How sensitive are ${label}'s earnings and balance sheet to rates, credit losses, and liquidity?`;
  } else if (/drug|biotech|health|medical|pharma/.test(category)) {
    tailored = `Which products and pipeline milestones drive ${label}'s next five years of cash flow?`;
  } else if (/retail|consumer|restaurant|beverage|food/.test(category)) {
    tailored = `Does ${label} have enough pricing power and unit growth to protect margins?`;
  } else if (/energy|oil|gas/.test(category)) {
    tailored = `How resilient is ${label}'s free cash flow across a full commodity-price cycle?`;
  } else if (/aerospace|defense|industrial|machinery/.test(category)) {
    tailored = `How durable are ${label}'s backlog, margins, and capital-return plans?`;
  }
  return [
    tailored,
    `Which risks would invalidate the investment thesis for ${ticker}?`,
    `How does ${ticker}'s valuation compare with its growth, quality, and closest alternatives?`,
  ];
}

async function fetchQuickQuote(ticker) {
  if (FINNHUB_KEY) {
    try {
      const [qRes, pRes] = await Promise.all([
        fetch(`https://finnhub.io/api/v1/quote?symbol=${ticker}&token=${FINNHUB_KEY}`,           { signal: AbortSignal.timeout(4000) }),
        fetch(`https://finnhub.io/api/v1/stock/profile2?symbol=${ticker}&token=${FINNHUB_KEY}`,  { signal: AbortSignal.timeout(4000) }),
      ]);
      const q = qRes.ok  ? await qRes.json()  : null;
      const p = pRes.ok  ? await pRes.json()  : null;
      if (q?.c) {
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
          asOf:      q.t ? new Date(Number(q.t) * 1000).toISOString() : null,
          source:    "Finnhub",
        };
      }
    } catch (_) {
      // Continue to the canonical Yahoo chart fallback below.
    }
  }
  try {
    const history = await loadPriceHistory(ticker, { range: "1y", interval: "1d" });
    const latest = history.bars.at(-1);
    const previous = history.bars.at(-2);
    if (!latest) return null;
    const priorClose = previous?.close || history.meta.previousClose || latest.close;
    const change = latest.close - priorClose;
    return {
      price: latest.close,
      change,
      changePct: priorClose ? (change / priorClose) * 100 : 0,
      high: latest.high,
      low: latest.low,
      open: latest.open,
      prevClose: priorClose,
      name: history.meta.name || ticker,
      exchange: history.meta.exchange || "",
      industry: "",
      country: "",
      logo: "",
      weburl: "",
      marketCap: null,
      currency: history.meta.currency || "USD",
      asOf: history.provenance.asOf,
      source: history.provenance.name,
    };
  } catch (_) {
    return null;
  }
}

function renderPage(ticker, q) {
  const name      = q ? String(q.name || ticker) : ticker;
  const price     = q ? fmtPrice(q.price)   : "—";
  const chgPct    = q ? fmtPct(q.changePct) : "";
  const isUp      = q ? q.changePct >= 0    : true;
  const chgSign   = isUp ? "▲" : "▼";
  const mktCap    = q ? fmtBig(q.marketCap) : "—";
  const industry  = q ? esc(q.industry) : "";
  const exchange  = q ? esc(q.exchange) : "";
  const indexable = ACQUISITION_TICKER_SET.has(ticker);
  const questions = researchQuestions(name, ticker, q?.industry);
  const related   = relatedTickers(ticker);
  const quoteTiming = q?.asOf
    ? `${q.source || "Provider"} quote · as of ${new Date(q.asOf).toLocaleString("en-US", { dateStyle: "medium", timeStyle: "short", timeZone: "America/New_York" })} ET`
    : "Latest available provider quote";

  const metaTitle = q
    ? `${ticker} Stock Analysis — ${name} ${price} (${chgPct}) | ImpliedLens`
    : `${ticker} Stock Analysis | ImpliedLens`;

  const metaDesc = q
    ? `${name} (${ticker}) is trading at ${price} (${chgPct} today). Run a full DCF valuation, financial statement analysis, analyst targets, and more — free on ImpliedLens.`
    : `Analyze ${ticker} with ImpliedLens — DCF valuation, financials, analyst targets, earnings history, and institutional data.`;

  const canonicalUrl = `${APP_URL}/stock/${ticker}`;
  const analyzeUrl   = `/?ticker=${ticker}&source=stock_landing`;
  const signupNext   = `/?view=tool&section=analyze&ticker=${ticker}&resume_analysis=1&source=stock_landing_signup`;
  const signupUrl    = `/signup?next=${encodeURIComponent(signupNext)}&source=stock_landing&ticker=${encodeURIComponent(ticker)}`;
  const analyzeUrlJson = JSON.stringify(analyzeUrl).replace(/</g, "\\u003c");
  const landingContextJson = JSON.stringify({
    ticker,
    quote_available: !!q,
    industry: q?.industry || null,
  }).replace(/</g, "\\u003c");

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
  }).replace(/</g, "\\u003c");

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <script>(function(){if(localStorage.getItem('il-theme')==='dark')document.documentElement.setAttribute('data-theme','dark')})();</script>
  <title>${esc(metaTitle)}</title>
  <meta name="description" content="${esc(metaDesc)}">
  <meta name="robots" content="${indexable ? "index,follow" : "noindex,follow"}">
  <link rel="canonical" href="${esc(canonicalUrl)}">

  <!-- Open Graph -->
  <meta property="og:type"        content="website">
  <meta property="og:url"         content="${esc(canonicalUrl)}">
  <meta property="og:title"       content="${esc(metaTitle)}">
  <meta property="og:description" content="${esc(metaDesc)}">
  <meta property="og:image"       content="${APP_URL}/social-card.png">
  <meta property="og:image:type"  content="image/png">
  <meta property="og:image:width" content="1200">
  <meta property="og:image:height" content="630">
  <meta property="og:image:alt"   content="ImpliedLens stock research workspace preview">
  <meta property="og:site_name"   content="ImpliedLens">

  <!-- Twitter Card -->
  <meta name="twitter:card"        content="summary_large_image">
  <meta name="twitter:site"        content="@ImpliedLens">
  <meta name="twitter:title"       content="${esc(metaTitle)}">
  <meta name="twitter:description" content="${esc(metaDesc)}">
  <meta name="twitter:image"       content="${APP_URL}/social-card.png">
  <meta name="twitter:image:alt"   content="ImpliedLens stock research workspace preview">

  <!-- Structured data -->
  <script type="application/ld+json">${schema}</script>

  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=DM+Serif+Display:ital@0;1&family=DM+Sans:wght@300;400;500;600;700&family=DM+Mono:wght@400;500&display=swap" rel="stylesheet">
  <style>
    *{margin:0;padding:0;box-sizing:border-box}
    body{font-family:'DM Sans',sans-serif;background:#08090D;color:rgba(220,225,232,.88);min-height:100vh}
    a{text-decoration:none;color:inherit}

    /* top bar */
    .top-bar{background:rgba(255,255,255,.03);border-bottom:1px solid rgba(255,255,255,.06);
      padding:.8rem 2rem;display:flex;align-items:center;gap:1rem}
    .logo{font-family:'DM Serif Display',serif;font-size:1.2rem;color:#fff}
    .logo em{color:#C8882A;font-style:italic}
    .top-bar .back{font-size:.78rem;color:rgba(220,225,232,.35);margin-left:auto}
    .top-bar .back:hover{color:#C8882A}

    /* hero */
    .hero{max-width:820px;margin:0 auto;padding:3rem 2rem 2rem}
    .breadcrumb{font-size:.72rem;color:rgba(220,225,232,.35);margin-bottom:1.25rem}
    .breadcrumb a{color:rgba(220,225,232,.35)}
    .breadcrumb a:hover{color:#C8882A}
    .ticker-badge{display:inline-block;font-family:'DM Mono',monospace;font-size:.75rem;font-weight:700;
      letter-spacing:.08em;background:rgba(200,136,42,.12);color:#C8882A;
      border:1px solid rgba(200,136,42,.25);border-radius:5px;padding:.2rem .6rem;margin-bottom:.75rem}
    h1{font-family:'DM Serif Display',serif;font-size:2rem;color:#fff;line-height:1.2;margin-bottom:.5rem}
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
    .cta-note a{color:#C8882A;font-weight:600}

    /* what you get */
    .features{max-width:820px;margin:0 auto;padding:0 2rem 3rem}
    h2{font-family:'DM Serif Display',serif;font-size:1.3rem;color:#fff;margin-bottom:1rem}
    .feat-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:.75rem}
    .feat{background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.06);
      border-radius:10px;padding:1rem 1.1rem}
    .feat-icon{font-size:1.1rem;margin-bottom:.4rem}
    .feat-title{font-size:.85rem;font-weight:600;color:#fff;margin-bottom:.2rem}
    .feat-desc{font-size:.75rem;color:rgba(220,225,232,.45);line-height:1.5}

    .research{max-width:820px;margin:0 auto;padding:0 2rem 3rem}
    .research-list{display:grid;gap:.65rem}
    .research-item{background:rgba(200,136,42,.06);border:1px solid rgba(200,136,42,.16);
      border-radius:10px;padding:.9rem 1rem;font-size:.82rem;line-height:1.5;color:rgba(220,225,232,.72)}
    .research-item strong{color:#C8882A;margin-right:.4rem}

    /* related tickers */
    .related{max-width:820px;margin:0 auto;padding:0 2rem 4rem}
    .pill-row{display:flex;flex-wrap:wrap;gap:.5rem;margin-top:.75rem}
    .ticker-pill{display:inline-block;padding:.35rem .85rem;border-radius:100px;
      background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.08);
      font-size:.78rem;font-family:'DM Mono',monospace;font-weight:600;color:rgba(220,225,232,.7);
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
      .hero,.features,.research,.related{padding-left:1rem;padding-right:1rem}
    }
    html:not([data-theme="dark"]) body{background:#f7f1e6;color:#25231f}
    html:not([data-theme="dark"]) .top-bar{background:rgba(255,255,255,.7);border-color:rgba(42,35,24,.12)}
    html:not([data-theme="dark"]) .logo,
    html:not([data-theme="dark"]) h1,
    html:not([data-theme="dark"]) h2,
    html:not([data-theme="dark"]) .q-price,
    html:not([data-theme="dark"]) .q-stat-val,
    html:not([data-theme="dark"]) .feat-title{color:#171510}
    html:not([data-theme="dark"]) .top-bar .back,
    html:not([data-theme="dark"]) .breadcrumb,
    html:not([data-theme="dark"]) .breadcrumb a,
    html:not([data-theme="dark"]) .exchange-tag,
    html:not([data-theme="dark"]) .q-label,
    html:not([data-theme="dark"]) .q-stat-lbl,
    html:not([data-theme="dark"]) .feat-desc,
    html:not([data-theme="dark"]) .cta-note,
    html:not([data-theme="dark"]) footer a{color:rgba(37,35,31,.62)}
    html:not([data-theme="dark"]) .quote-card,
    html:not([data-theme="dark"]) .feat,
    html:not([data-theme="dark"]) .ticker-pill{background:rgba(255,255,255,.58);border-color:rgba(42,35,24,.12)}
    html:not([data-theme="dark"]) .research-item{color:#3e392f;background:rgba(200,136,42,.08)}
    html:not([data-theme="dark"]) footer{border-color:rgba(42,35,24,.12)}
  </style>
  <link rel="stylesheet" href="/static-polish.css?v=20260725-2">
  <link rel="stylesheet" href="/visual-refresh.css?v=20260730-10">
  <link rel="stylesheet" href="/site-shell.css?v=20260730-24">
</head>
<body>
  <a class="il-skip-link" href="#public-main">Skip to content</a>
  <nav class="il-global-nav" aria-label="Primary navigation">
    <a class="il-global-brand" href="/"><img src="/logo.svg" alt=""><span>Implied<em>Lens</em></span></a>
    <div class="il-global-links">
      <a class="il-global-tab" href="/">Home</a>
      <a class="il-global-tab" href="/?view=home&amp;market=1">Market</a>
      <a class="il-global-tab active" href="/?view=tool&amp;section=analyze">Research</a>
      <a class="il-global-tab" href="/lens-score">LensScore</a>
      <a class="il-global-tab" href="/?view=tool&amp;section=projection">Projections</a>
      <a class="il-global-tab" href="/?view=tool&amp;section=wealth">Planner</a>
      <a class="il-global-tab" href="/?view=tool&amp;section=education">Learn</a>
      <a class="il-global-tab" href="/?view=tool&amp;section=reports">Saved</a>
      <a class="il-global-tab" href="/about">About</a>
    </div>
    <form class="il-global-search" action="/" method="get" role="search"><input type="hidden" name="view" value="tool"><input type="hidden" name="section" value="analyze"><span aria-hidden="true">⌕</span><input name="symbol" type="text" placeholder="Search ticker…" autocomplete="off" autocapitalize="characters" spellcheck="false" aria-label="Search for a ticker"></form>
    <div class="il-global-actions">
      <button class="static-theme-toggle" type="button" aria-label="Switch theme"><span class="static-theme-thumb"></span></button>
      <span class="il-global-live" title="ImpliedLens is live">Live</span>
      <a class="il-global-login" href="/login">Log in</a>
      <a class="il-global-trial" href="/signup">Start trial</a>
    </div>
  </nav>
  <div class="top-bar" hidden>
    <a href="/" class="logo">Implied<em>Lens</em></a>
    <a href="/" class="back">← All analysis</a>
    <button class="static-theme-toggle" type="button" aria-label="Switch theme"><span class="static-theme-thumb"></span></button>
  </div>

  <main id="public-main">
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
        <div class="q-chg ${isUp ? "up" : "dn"}">${chgSign} ${chgPct}</div>
        <div class="q-label">${esc(quoteTiming)} · no synthetic replacement</div>
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
      <div style="color:rgba(220,225,232,.4);font-size:.9rem">Open the analyzer for the latest available market context.</div>
    </div>`}

    <div class="cta-section">
      <a id="analyze-cta" href="${esc(analyzeUrl)}" class="cta-btn">Analyze ${esc(ticker)} in depth →</a>
      <div class="cta-note">Guests get 2 analyses/day. <a id="landing-signup-cta" href="${esc(signupUrl)}">Create a free account for 5/day</a>.</div>
    </div>
  </div>

  <div class="features">
    <h2>What you get with ImpliedLens</h2>
    <div class="feat-grid">
      <div class="feat"><div class="feat-icon">📊</div><div class="feat-title">Financial statements</div><div class="feat-desc">Income, balance sheet, cash flow from SEC filings with 30+ calculated ratios.</div></div>
      <div class="feat"><div class="feat-icon">🧮</div><div class="feat-title">DCF valuation</div><div class="feat-desc">Customizable discounted cash flow model with live inputs.</div></div>
      <div class="feat"><div class="feat-icon">🎯</div><div class="feat-title">Analyst targets</div><div class="feat-desc">Price targets, recommendation breakdowns, earnings surprises.</div></div>
      <div class="feat"><div class="feat-icon">🏦</div><div class="feat-title">Institutional context</div><div class="feat-desc">Ownership data and aggregated FINRA OTC activity.</div></div>
      <div class="feat"><div class="feat-icon">📋</div><div class="feat-title">SEC filings</div><div class="feat-desc">Direct links to 10-K, 10-Q, 8-K, and proxy statements.</div></div>
      <div class="feat"><div class="feat-icon">📈</div><div class="feat-title">Projection models</div><div class="feat-desc">Bull/base/bear scenario modeling with editable assumptions.</div></div>
    </div>
  </div>

  <div class="research">
    <h2>Questions to answer before investing in ${esc(ticker)}</h2>
    <div class="research-list">
      ${questions.map((question, index) => `<div class="research-item"><strong>0${index + 1}</strong>${esc(question)}</div>`).join("")}
    </div>
  </div>

  <div class="related">
    <h2>Analyze another ticker</h2>
    <div class="pill-row">
      ${related
        .map(t => `<a href="/stock/${t}" class="ticker-pill">${t}</a>`)
        .join("")}
    </div>
  </div>
  </main>

  <footer>
    <a href="/privacy">Privacy</a>
    <a href="/terms">Terms</a>
    <a href="/data-sources">Data Sources</a>
    <a href="/about">About</a>
    <a href="/">ImpliedLens</a>
  </footer>

  <script src="/static-theme.js?v=20260609"></script>
  <script>
    const landingContext = ${landingContextJson};
    function trackLanding(event, properties) {
      let referrerHost = '';
      try { referrerHost = document.referrer ? new URL(document.referrer).hostname : ''; } catch (_) {}
      const params = new URLSearchParams(window.location.search);
      fetch('/api/track', {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({
          event,
          properties: {
            ...landingContext,
            ...properties,
            referrer_host: referrerHost || null,
            utm_source: params.get('utm_source'),
            utm_medium: params.get('utm_medium'),
            utm_campaign: params.get('utm_campaign'),
          },
        }),
        keepalive: true,
      }).catch(() => {});
    }
    const acquisitionParams = new URLSearchParams(window.location.search);
    const acquisition = {
      source: 'stock_landing',
      utm_source: acquisitionParams.get('utm_source'),
      utm_medium: acquisitionParams.get('utm_medium'),
      utm_campaign: acquisitionParams.get('utm_campaign'),
    };
    try {
      sessionStorage.setItem('ilAcquisitionContext', JSON.stringify(
        Object.fromEntries(Object.entries(acquisition).filter(([, value]) => value))
      ));
    } catch (_) {}
    ['analyze-cta','landing-signup-cta'].forEach(id => {
      const link = document.getElementById(id);
      if (!link) return;
      const url = new URL(link.href, window.location.origin);
      ['utm_source','utm_medium','utm_campaign'].forEach(key => {
        if (acquisition[key]) url.searchParams.set(key, acquisition[key]);
      });
      link.href = url.toString();
    });
    trackLanding('landing_page_view', {});
    document.getElementById('analyze-cta').addEventListener('click', () => {
      trackLanding('landing_cta_clicked', { destination: 'analyzer' });
    });
    document.getElementById('landing-signup-cta').addEventListener('click', () => {
      trackLanding('guest_signup_started', { source: 'stock_landing' });
    });

    // Auto-redirect to full analyzer after a short delay on CTA click
    // (also handle ?autoload=1 for programmatic deep links)
    if (new URLSearchParams(window.location.search).get('autoload') === '1') {
      window.location.href = ${analyzeUrlJson};
    }
  </script>
</body>
</html>`;
}

// ── Route ─────────────────────────────────────────────────────
router.get("/stock/:ticker", async (req, res) => {
  const raw = String(req.params.ticker || "").trim().toUpperCase();
  if (!TICKER_RE.test(raw)) return res.status(404).type("text/plain").send("Ticker page not found.");

  // Fetch live quote data (best-effort — page renders without it)
  const q = await fetchQuickQuote(raw);

  const html = renderPage(raw, q);
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  // Cache for 5 minutes on CDN, 60s stale-while-revalidate
  res.setHeader("Cache-Control", "public, max-age=300, stale-while-revalidate=60");
  res.send(html);
});

module.exports = router;

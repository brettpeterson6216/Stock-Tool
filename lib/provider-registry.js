"use strict";

/*
 * Canonical, public-safe inventory of the external providers used by
 * ImpliedLens. This module deliberately contains no network or environment
 * access so routes and templates can consume it without triggering a provider.
 *
 * `status` describes the integration, not current uptime. Runtime observations
 * remain the responsibility of provider-health.js.
 */

const CATEGORIES = {
  MARKET_RESEARCH: "market-research",
  INFRASTRUCTURE_PROCESSOR: "infrastructure-processor",
};

const FRESHNESS_VOCABULARY = {
  "latest-provider-observation": {
    label: "Latest provider observation",
    definition: "The newest observation returned by the named provider; it is not a guarantee of real-time exchange data.",
  },
  "latest-completed-market-bar": {
    label: "Latest completed market bar",
    definition: "The newest completed OHLCV interval returned by the provider, with timing determined by the market, instrument, and interval.",
  },
  "provider-as-of": {
    label: "Provider as-of",
    definition: "The effective date or timestamp supplied by the provider when one is available.",
  },
  "provider-schedule": {
    label: "Provider schedule",
    definition: "The dataset changes on the provider's own publication or refresh schedule; no fixed real-time claim is made.",
  },
  "filing-date": {
    label: "Filing date",
    definition: "The date an issuer filing or reported fact was filed with the regulator.",
  },
  "delayed-weekly-aggregate": {
    label: "Delayed weekly aggregate",
    definition: "A weekly aggregate published after the covered activity, not venue-level or live order-flow data.",
  },
  "retrieved-at": {
    label: "Retrieved at",
    definition: "When ImpliedLens retrieved a response; retrieval time is not necessarily the observation's effective time.",
  },
  "generated-on-request": {
    label: "Generated on request",
    definition: "Generated when requested from already-computed inputs; it is not an independently refreshed market dataset.",
  },
  "not-market-data": {
    label: "Not market data",
    definition: "Freshness terminology does not apply because this service supplies application infrastructure, processing, or software rather than market observations.",
  },
};

const PROVIDERS = [
  {
    id: "yahoo-finance",
    name: "Yahoo Finance",
    category: CATEGORIES.MARKET_RESEARCH,
    kind: "market-data",
    officialUrl: "https://finance.yahoo.com/",
    purpose: "Supplies price history, OHLCV bars, quote context, market benchmarks, movers, and the primary screener universe.",
    features: [
      "Price and index charts",
      "Technical-analysis and LensSetup inputs",
      "Quote and market-session context",
      "Landing-market summary and movers",
      "Screener universe",
    ],
    freshness: {
      terms: ["latest-provider-observation", "latest-completed-market-bar", "provider-as-of", "retrieved-at"],
      guidance: "Show the observation timestamp returned by the provider when available. Do not describe Yahoo responses as a direct or guaranteed real-time exchange feed.",
    },
    attribution: "Market data source: Yahoo Finance.",
    disclosure: "Timing can vary by exchange, instrument, market session, endpoint, and cache state. Missing fields remain unavailable rather than being inferred.",
    status: "active",
    optional: false,
    role: "primary",
    aliases: ["Yahoo Finance chart", "Yahoo Finance charts", "Yahoo Finance historical CSV", "Yahoo Finance screener"],
  },
  {
    id: "finnhub",
    name: "Finnhub",
    category: CATEGORIES.MARKET_RESEARCH,
    kind: "market-and-research-data",
    officialUrl: "https://finnhub.io/",
    purpose: "Supplies supplemental quotes and company profiles plus news, estimates, price targets, recommendations, metrics, earnings, transcripts, and ownership data.",
    features: [
      "Company and general market news",
      "Analyst estimates, targets, and recommendations",
      "Company metrics and profiles",
      "Reported earnings and transcript availability",
      "Institutional ownership",
      "Supplemental quote context",
    ],
    freshness: {
      terms: ["provider-schedule", "provider-as-of", "retrieved-at"],
      guidance: "Use a provider-supplied effective date when present; otherwise show retrieval time and state that the dataset follows Finnhub's schedule.",
    },
    attribution: "Research and supplemental market data source: Finnhub.",
    disclosure: "Coverage and update timing vary by dataset and account entitlement. A configured FINNHUB_KEY is required for the production integration.",
    status: "active",
    optional: false,
    role: "supplemental",
    aliases: ["Finnhub metrics", "Finnhub analyst estimates", "Finnhub analyst data", "Finnhub institutional ownership", "Finnhub earnings history", "Finnhub consensus"],
  },
  {
    id: "sec-edgar",
    name: "SEC EDGAR",
    category: CATEGORIES.MARKET_RESEARCH,
    kind: "regulatory-primary-source",
    officialUrl: "https://www.sec.gov/edgar/",
    purpose: "Supplies the authoritative ticker-to-CIK map, issuer-filed XBRL company facts, filing history, and links to original filings.",
    features: [
      "Annual financial statements",
      "Reported GAAP earnings history",
      "LensValue reported inputs",
      "10-K, 10-Q, 8-K, DEF 14A, and related filing links",
      "Issuer identity and filing metadata",
    ],
    freshness: {
      terms: ["filing-date", "provider-as-of", "retrieved-at"],
      guidance: "Retain the filing date for each reported fact. Retrieval time does not replace the reporting period or filing date.",
    },
    attribution: "Regulatory filing source: SEC EDGAR.",
    disclosure: "These are issuer-reported filings and facts. Amendments, restatements, taxonomy differences, and reporting lags can affect comparability; critical figures should be checked against the original filing.",
    status: "active",
    optional: false,
    role: "primary",
    aliases: ["SEC EDGAR XBRL", "SEC EDGAR submissions", "SEC filing", "SEC filing data"],
  },
  {
    id: "finra-otc",
    name: "FINRA OTC Transparency",
    category: CATEGORIES.MARKET_RESEARCH,
    kind: "regulatory-market-transparency",
    officialUrl: "https://www.finra.org/filing-reporting/otc-transparency-data",
    purpose: "Supplies weekly OTC share-volume, trade-count, and notional aggregates used in the institutional research surface.",
    features: [
      "Weekly OTC share volume",
      "Weekly OTC trade counts",
      "Weekly aggregate notional activity",
      "Reported venue-count context",
    ],
    freshness: {
      terms: ["delayed-weekly-aggregate", "provider-as-of", "retrieved-at"],
      guidance: "Label the covered week and describe the result as delayed, aggregated OTC activity.",
    },
    attribution: "OTC activity source: FINRA OTC Transparency.",
    disclosure: "The route's legacy name is not a description of the data. FINRA weekly OTC aggregates are not venue-level dark-pool order flow and are not a live short-interest feed.",
    status: "active",
    optional: false,
    role: "primary",
    aliases: ["FINRA OTC", "FINRA weekly OTC transparency"],
  },
  {
    id: "stooq",
    name: "Stooq",
    category: CATEGORIES.MARKET_RESEARCH,
    kind: "historical-market-data",
    officialUrl: "https://stooq.com/",
    purpose: "Supplies daily historical prices only when the primary Yahoo chart and download paths do not return usable history.",
    features: ["Daily historical-price fallback"],
    freshness: {
      terms: ["latest-completed-market-bar", "provider-as-of", "retrieved-at"],
      guidance: "Identify Stooq as a fallback and show the latest completed daily observation; do not present it as an intraday or real-time quote.",
    },
    attribution: "Fallback historical-price source: Stooq.",
    disclosure: "Stooq is a conditional fallback, not the primary quote provider. The application may supplement its last daily close with separately attributed Finnhub quote context.",
    status: "optional",
    optional: true,
    role: "fallback",
    aliases: ["Stooq historical prices", "Stooq historical prices + Finnhub snapshot"],
  },
  {
    id: "turso",
    name: "Turso / libSQL",
    category: CATEGORIES.INFRASTRUCTURE_PROCESSOR,
    kind: "database-hosting",
    officialUrl: "https://turso.tech/",
    purpose: "Hosts the production libSQL database used for accounts, sessions, saved research and workspace records, usage controls, subscription identifiers, and application events.",
    features: [
      "Account and session persistence",
      "Saved analyses, theses, positions, and watchlists",
      "Plan, usage, and billing-event records",
    ],
    freshness: {
      terms: ["not-market-data"],
      guidance: "Describe database timestamps as application-record timestamps, not market-data as-of times.",
    },
    attribution: "Application database service: Turso / libSQL.",
    disclosure: "Turso is an infrastructure provider, not a market-data source. Local development can use the same libSQL client with a local file database.",
    status: "active",
    optional: false,
    role: "processor",
    aliases: ["Turso", "libSQL"],
  },
  {
    id: "stripe",
    name: "Stripe",
    category: CATEGORIES.INFRASTRUCTURE_PROCESSOR,
    kind: "billing-processor",
    officialUrl: "https://stripe.com/",
    purpose: "Provides hosted checkout, promotion-code support, subscription billing, billing-portal access, webhook events, and entitlement reconciliation.",
    features: [
      "Checkout and payment-method collection",
      "Subscription and trial lifecycle",
      "Promotion codes",
      "Customer billing portal",
      "Signed webhook delivery",
    ],
    freshness: {
      terms: ["not-market-data"],
      guidance: "Subscription state is operational account data and must not be described with market-data freshness terms.",
    },
    attribution: "Payment and subscription processor: Stripe.",
    disclosure: "Payment details are collected by Stripe Checkout. ImpliedLens stores Stripe customer and subscription identifiers and processes signed billing events; Stripe does not supply research data.",
    status: "active",
    optional: false,
    role: "processor",
    aliases: ["Stripe Checkout", "Stripe Billing"],
  },
  {
    id: "render",
    name: "Render",
    category: CATEGORIES.INFRASTRUCTURE_PROCESSOR,
    kind: "application-hosting",
    officialUrl: "https://render.com/",
    purpose: "Hosts the production application runtime and its public HTTP service.",
    features: ["Application hosting", "Deployment runtime", "Service health checks"],
    freshness: {
      terms: ["not-market-data"],
      guidance: "Build and service timestamps are operational metadata, not market observations.",
    },
    attribution: "Application hosting provider: Render.",
    disclosure: "Render operates the deployed server infrastructure and therefore handles requests reaching the application; it does not supply market or research data.",
    status: "active",
    optional: false,
    role: "processor",
    aliases: ["Render hosting"],
  },
  {
    id: "resend",
    name: "Resend",
    category: CATEGORIES.INFRASTRUCTURE_PROCESSOR,
    kind: "transactional-email-processor",
    officialUrl: "https://resend.com/",
    purpose: "Delivers transactional account email, including verification, password-reset, account, and scheduled review messages.",
    features: ["Email verification", "Password-reset email", "Transactional account email", "Review reminders"],
    freshness: {
      terms: ["not-market-data"],
      guidance: "Delivery identifiers and send times are message-operation metadata, not research-data timestamps.",
    },
    attribution: "Transactional email provider: Resend.",
    disclosure: "Resend receives the destination email address and message content needed to deliver a transaction. The integration does not provide market data and reports a send only when Resend returns a delivery identifier.",
    status: "active",
    optional: false,
    role: "processor",
    aliases: ["Resend email"],
  },
  {
    id: "anthropic",
    name: "Anthropic (Claude)",
    category: CATEGORIES.INFRASTRUCTURE_PROCESSOR,
    kind: "optional-ai-processor",
    officialUrl: "https://www.anthropic.com/",
    purpose: "Optionally rewrites already-computed technical signals into a short plain-language technical read.",
    features: ["Optional technical-signal narration"],
    freshness: {
      terms: ["generated-on-request", "not-market-data"],
      guidance: "Label model narration as generated on request from the displayed, already-computed signal set.",
    },
    attribution: "Optional technical-read narration provider: Anthropic (Claude).",
    disclosure: "When configured and requested, Anthropic receives the ticker, timeframe, as-of value, price, and computed signal facts—not raw price history. Claude narrates those inputs; it does not calculate the signals. A deterministic local summary is used when the integration is absent or fails.",
    status: "optional",
    optional: true,
    role: "processor",
    aliases: ["Anthropic", "Claude", "model"],
  },
  {
    id: "tradingview-lightweight-charts",
    name: "TradingView Lightweight Charts",
    category: CATEGORIES.INFRASTRUCTURE_PROCESSOR,
    kind: "self-hosted-charting-library",
    officialUrl: "https://www.tradingview.com/lightweight-charts/",
    purpose: "Renders interactive price and index charts in the browser from data supplied by the named market providers.",
    features: ["Interactive price charts", "Index comparison charts"],
    freshness: {
      terms: ["not-market-data"],
      guidance: "Attribute chart data to its market provider; the charting library is not the source of those observations.",
    },
    attribution: "Charts use TradingView Lightweight Charts under the Apache License 2.0.",
    disclosure: "The charting bundle is served by ImpliedLens. TradingView Lightweight Charts renders data but does not supply the displayed quotes or fundamentals.",
    status: "active",
    optional: false,
    role: "software",
    aliases: ["Lightweight Charts", "TradingView"],
  },
  {
    id: "jsdelivr",
    name: "jsDelivr",
    category: CATEGORIES.INFRASTRUCTURE_PROCESSOR,
    kind: "content-delivery-network",
    officialUrl: "https://www.jsdelivr.com/",
    purpose: "Delivers the world-atlas geography JSON requested by the browser for the decorative portfolio globe.",
    features: ["World-atlas geography asset delivery"],
    freshness: {
      terms: ["not-market-data"],
      guidance: "The geography asset is static presentation data and must not be described as investment or market data.",
    },
    attribution: "Static geography asset delivery: jsDelivr.",
    disclosure: "The browser fetches a public world-atlas file from jsDelivr. The request does not include an ImpliedLens account identifier or portfolio payload.",
    status: "active",
    optional: false,
    role: "processor",
    aliases: ["cdn.jsdelivr.net"],
  },
  {
    id: "cdnjs",
    name: "cdnjs (Cloudflare)",
    category: CATEGORIES.INFRASTRUCTURE_PROCESSOR,
    kind: "content-delivery-network",
    officialUrl: "https://cdnjs.com/",
    purpose: "Delivers the Chart.js browser bundle used by the administrator analytics page.",
    features: ["Administrator analytics chart-library delivery"],
    freshness: {
      terms: ["not-market-data"],
      guidance: "The delivered script is application software, not a source of analytics or market observations.",
    },
    attribution: "Administrator chart-library delivery: cdnjs (Cloudflare).",
    disclosure: "Only the charting library is fetched from cdnjs; application analytics records are retrieved from ImpliedLens, not from the CDN.",
    status: "active",
    optional: false,
    role: "processor",
    aliases: ["cdnjs.cloudflare.com", "Cloudflare cdnjs"],
  },
];

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  Object.values(value).forEach(deepFreeze);
  return Object.freeze(value);
}

deepFreeze(CATEGORIES);
deepFreeze(FRESHNESS_VOCABULARY);
deepFreeze(PROVIDERS);

const providerLookup = new Map();
for (const provider of PROVIDERS) {
  for (const key of [provider.id, provider.name, ...provider.aliases]) {
    providerLookup.set(String(key).trim().toLowerCase(), provider);
  }
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function resolveProvider(identifier) {
  if (typeof identifier !== "string") return null;
  return providerLookup.get(identifier.trim().toLowerCase()) || null;
}

function getProvider(identifier) {
  const provider = resolveProvider(identifier);
  return provider ? clone(provider) : null;
}

function listProviders({ category = null, status = null, includeOptional = true } = {}) {
  return PROVIDERS
    .filter(provider => !category || provider.category === category)
    .filter(provider => !status || provider.status === status)
    .filter(provider => includeOptional || !provider.optional)
    .map(clone);
}

function providerName(identifier) {
  return resolveProvider(identifier)?.name || null;
}

function providerSummary(identifier) {
  const provider = resolveProvider(identifier);
  if (!provider) return null;
  return `${provider.name}: ${provider.purpose} ${provider.disclosure}`;
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// These helpers never echo an unknown identifier. Their output is assembled
// only from the canonical registry and is safe to place in an HTML template.
function renderProviderNameHtml(identifier) {
  return escapeHtml(providerName(identifier) || "");
}

function renderProviderSummaryHtml(identifier) {
  return escapeHtml(providerSummary(identifier) || "");
}

function publicProvider(provider) {
  return {
    id: provider.id,
    name: provider.name,
    category: provider.category,
    kind: provider.kind,
    officialUrl: provider.officialUrl,
    purpose: provider.purpose,
    features: [...provider.features],
    freshness: {
      terms: [...provider.freshness.terms],
      guidance: provider.freshness.guidance,
    },
    attribution: provider.attribution,
    disclosure: provider.disclosure,
    status: provider.status,
    optional: provider.optional,
    role: provider.role,
  };
}

function getPublicProviderRegistry(options = {}) {
  const providers = listProviders(options).map(publicProvider);
  const usedTerms = new Set(providers.flatMap(provider => provider.freshness.terms));
  const freshnessVocabulary = Object.fromEntries(
    Object.entries(FRESHNESS_VOCABULARY)
      .filter(([term]) => usedTerms.has(term))
      .map(([term, description]) => [term, clone(description)])
  );
  return {
    schemaVersion: 1,
    categories: [
      { id: CATEGORIES.MARKET_RESEARCH, label: "Market & research providers" },
      { id: CATEGORIES.INFRASTRUCTURE_PROCESSOR, label: "Infrastructure & processors" },
    ],
    freshnessVocabulary,
    providers,
  };
}

module.exports = {
  CATEGORIES,
  FRESHNESS_VOCABULARY,
  PROVIDERS,
  getProvider,
  listProviders,
  providerName,
  providerSummary,
  renderProviderNameHtml,
  renderProviderSummaryHtml,
  getPublicProviderRegistry,
};

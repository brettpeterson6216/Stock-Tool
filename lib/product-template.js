"use strict";

// Server-side presentation helpers for product promises that must agree across
// marketing, billing, limits, and policy pages. HTML files keep their existing
// structure and use small {{TOKEN}} placeholders; this module is the only place
// that turns the canonical product/provider registries into public copy.

const {
  PRODUCT_CONFIG,
  getPublicProductConfig,
  serializePublicProductConfig,
} = require("./product-config");
const { CATEGORIES, listProviders } = require("./provider-registry");

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, char => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[char]);
}

function stripCurrency(formatted) {
  return String(formatted).replace(/^\$/, "");
}

function annualEquivalent(config) {
  return `$${(config.pricing.annual.unitAmountCents / 1200).toFixed(2)}`;
}

function annualSavingsPercent(config) {
  const monthlyYear = config.pricing.monthly.unitAmountCents * 12;
  return Math.max(0, Math.round((1 - config.pricing.annual.unitAmountCents / monthlyYear) * 100));
}

function renderProviderCards() {
  return listProviders({ category: CATEGORIES.MARKET_RESEARCH }).map(provider => {
    const tags = provider.features
      .map((feature, index) => `<span class="tag${index < 2 ? " gold" : ""}">${escapeHtml(feature)}</span>`)
      .join("");
    const host = new URL(provider.officialUrl).hostname.replace(/^www\./, "");
    return `<article class="source-card" data-provider="${escapeHtml(provider.id)}">
      <div class="src-head">
        <div class="src-icon"><i class="ti ti-database" aria-hidden="true"></i></div>
        <div>
          <div class="src-name">${escapeHtml(provider.name)}</div>
          <div class="src-url"><a href="${escapeHtml(provider.officialUrl)}" rel="noopener">${escapeHtml(host)}</a></div>
        </div>
      </div>
      <p class="src-desc">${escapeHtml(provider.purpose)} ${escapeHtml(provider.disclosure)}</p>
      <p class="src-desc"><strong>Freshness:</strong> ${escapeHtml(provider.freshness.guidance)}</p>
      <div class="src-tags">${tags}</div>
    </article>`;
  }).join("\n");
}

function renderHomepageProviderBadges() {
  const icons = {
    "sec-edgar": "ti-file-certificate",
    "yahoo-finance": "ti-chart-line",
    finnhub: "ti-broadcast",
    "finra-otc": "ti-building-bank",
  };
  return ["sec-edgar", "yahoo-finance", "finnhub", "finra-otc"]
    .map(id => listProviders({ category: CATEGORIES.MARKET_RESEARCH }).find(provider => provider.id === id))
    .filter(Boolean)
    .map(provider => `<span><i class="ti ${icons[provider.id] || "ti-database"}"></i>${escapeHtml(provider.name)}</span>`)
    .join("\n        ");
}

function renderProcessorList() {
  return listProviders({ category: CATEGORIES.INFRASTRUCTURE_PROCESSOR })
    .filter(provider => ["turso", "stripe", "render", "resend", "anthropic"].includes(provider.id))
    .map(provider => `<li><strong>${escapeHtml(provider.name)}</strong> — ${escapeHtml(provider.purpose)}</li>`)
    .join("\n      ");
}

function productOffersJsonLd(config) {
  const offer = (name, cents, unitCode, description) => {
    const amount = (cents / 100).toFixed(2);
    const out = {
      "@type": "Offer",
      name,
      price: amount,
      priceCurrency: config.currency.toUpperCase(),
      availability: "https://schema.org/InStock",
      url: "https://impliedlens.com/pricing",
    };
    if (description) out.description = description;
    if (unitCode) {
      out.priceSpecification = {
        "@type": "UnitPriceSpecification",
        price: amount,
        priceCurrency: config.currency.toUpperCase(),
        referenceQuantity: { "@type": "QuantitativeValue", value: 1, unitCode },
      };
    }
    return out;
  };
  const trial = config.trial.requiresCard
    ? `${config.trial.days}-day free trial; a payment method is required to start it.`
    : `${config.trial.days}-day free trial; no payment method required.`;
  return JSON.stringify([
    offer("Free", 0, null,
      `${config.analysisLimits.registeredFreeDaily} stock analyses per day with a free account.`),
    offer("Pro, billed monthly", config.pricing.monthly.unitAmountCents, "MON", trial),
    offer("Pro, billed annually", config.pricing.annual.unitAmountCents, "ANN", trial),
  ], null, 2).replace(/</g, "\\u003c");
}

function renderProductTemplate(html, config = PRODUCT_CONFIG) {
  const publicConfig = getPublicProductConfig(config);
  const replacements = {
    PLAN_MONTHLY_PRICE: publicConfig.pricing.monthly.formatted,
    PLAN_MONTHLY_AMOUNT: stripCurrency(publicConfig.pricing.monthly.formatted),
    PLAN_ANNUAL_PRICE: publicConfig.pricing.annual.formatted,
    PLAN_ANNUAL_AMOUNT: stripCurrency(publicConfig.pricing.annual.formatted),
    PLAN_ANNUAL_EQUIVALENT: annualEquivalent(publicConfig),
    PLAN_ANNUAL_SAVINGS_PERCENT: String(annualSavingsPercent(publicConfig)),
    /* The same numbers, for the in-app pricing toggle. Embedding them is what
       keeps app-legacy.js from carrying a second, silently stale copy of the
       price -- which is how the advertised price drifted from Stripe before.
       It rides on a meta attribute rather than an inline <script> on purpose:
       the homepage CSP has no 'unsafe-inline' in script-src, so an inline
       block would be silently dropped by the browser and the fallback numbers
       would be the ones on screen. JSON.stringify then HTML-escaping is what
       makes the value safe inside a quoted attribute. */
    PUBLIC_PRODUCT_CONFIG_ATTR: escapeHtml(JSON.stringify(publicConfig)),
    /* The homepage's schema.org block declared `"price": "0"`. That is a
       financial claim about the product, made to Google, and it was false:
       there is a free tier, but Pro is charged. A rich result reading "Free"
       for a product that asks for a card is the kind of thing that gets a
       site a manual action, and it is exactly what the SEO plan means by
       "do not mark up financial claims that are not supported by the page".
       Both halves of the offer are declared here, from the same catalog the
       pricing page reads, so the markup cannot drift from the charge. */
    PRODUCT_OFFERS_JSONLD: productOffersJsonLd(publicConfig),
    /* Empty unless GOOGLE_SITE_VERIFICATION is set, so no page ever ships an
       empty verification tag. */
    GOOGLE_SITE_VERIFICATION_TAG: (() => {
      const token = require("./config").GOOGLE_SITE_VERIFICATION;
      return token
        ? `<meta name="google-site-verification" content="${escapeHtml(token)}">`
        : "";
    })(),
    TRIAL_DAYS: String(publicConfig.trial.days),
    TRIAL_CARD_COPY: publicConfig.trial.requiresCard
      ? "A valid payment method is required. You will not be charged during the trial."
      : "No payment method is required to begin the trial.",
    TRIAL_CARD_SHORT: publicConfig.trial.requiresCard ? "Card required" : "No card required",
    GUEST_DAILY_LIMIT: String(publicConfig.analysisLimits.guestDaily),
    FREE_DAILY_LIMIT: String(publicConfig.analysisLimits.registeredFreeDaily),
    PROMOTION_COPY: publicConfig.checkout.allowPromotionCodes
      ? "Promotion codes, when available, can be entered in Stripe Checkout."
      : "Promotion codes are not currently accepted.",
    MARKET_PROVIDER_NAMES: listProviders({ category: CATEGORIES.MARKET_RESEARCH })
      .map(provider => provider.name).join(", "),
    HOMEPAGE_PROVIDER_BADGES: renderHomepageProviderBadges(),
    DATA_PROVIDER_CARDS: renderProviderCards(),
    INFRASTRUCTURE_PROVIDER_LIST: renderProcessorList(),
  };

  return Object.entries(replacements).reduce(
    (output, [token, value]) => output.replaceAll(`{{${token}}}`, value),
    String(html)
  );
}

module.exports = {
  annualEquivalent,
  productOffersJsonLd,
  annualSavingsPercent,
  renderHomepageProviderBadges,
  renderProcessorList,
  renderProductTemplate,
  renderProviderCards,
};

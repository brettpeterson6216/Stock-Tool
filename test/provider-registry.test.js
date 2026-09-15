"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const {
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
} = require("../lib/provider-registry");

const ROOT = path.join(__dirname, "..");

test("registry covers every current public data source and named operating service", () => {
  const expected = [
    "yahoo-finance",
    "finnhub",
    "sec-edgar",
    "finra-otc",
    "stooq",
    "turso",
    "stripe",
    "render",
    "resend",
    "anthropic",
    "tradingview-lightweight-charts",
    "jsdelivr",
    "cdnjs",
  ];
  const ids = PROVIDERS.map(provider => provider.id);
  assert.deepEqual([...ids].sort(), [...expected].sort());
  assert.equal(ids.some(id => /fred/i.test(id)), false, "FRED is not used by the backend and must not be claimed");
});

test("registry entries expose a complete and consistent public disclosure shape", () => {
  const ids = new Set();
  for (const provider of PROVIDERS) {
    assert.match(provider.id, /^[a-z0-9]+(?:-[a-z0-9]+)*$/);
    assert.equal(ids.has(provider.id), false, `duplicate provider id: ${provider.id}`);
    ids.add(provider.id);

    assert.ok(Object.values(CATEGORIES).includes(provider.category), `${provider.id} has an unknown category`);
    assert.match(provider.officialUrl, /^https:\/\//);
    assert.ok(provider.name.length > 1);
    assert.ok(provider.purpose.length > 20);
    assert.ok(Array.isArray(provider.features) && provider.features.length > 0);
    assert.ok(Array.isArray(provider.freshness.terms) && provider.freshness.terms.length > 0);
    assert.ok(provider.freshness.guidance.length > 20);
    assert.ok(provider.attribution.length > 10);
    assert.ok(provider.disclosure.length > 20);
    assert.ok(["active", "optional"].includes(provider.status));
    assert.equal(provider.optional, provider.status === "optional");

    for (const term of provider.freshness.terms) {
      assert.ok(FRESHNESS_VOCABULARY[term], `${provider.id} uses an undefined freshness term: ${term}`);
    }
  }
});

test("market and research providers stay separate from infrastructure and processors", () => {
  const marketIds = listProviders({ category: CATEGORIES.MARKET_RESEARCH }).map(provider => provider.id);
  const infrastructureIds = listProviders({ category: CATEGORIES.INFRASTRUCTURE_PROCESSOR }).map(provider => provider.id);

  assert.deepEqual(marketIds, ["yahoo-finance", "finnhub", "sec-edgar", "finra-otc", "stooq"]);
  assert.ok(infrastructureIds.includes("turso"));
  assert.ok(infrastructureIds.includes("stripe"));
  assert.ok(infrastructureIds.includes("render"));
  assert.ok(infrastructureIds.includes("resend"));
  assert.ok(infrastructureIds.includes("anthropic"));
  assert.equal(new Set([...marketIds, ...infrastructureIds]).size, PROVIDERS.length);
});

test("status and role describe real conditional behavior without claiming provider uptime", () => {
  assert.equal(getProvider("yahoo-finance").role, "primary");
  assert.equal(getProvider("stooq").role, "fallback");
  assert.equal(getProvider("stooq").status, "optional");
  assert.equal(getProvider("anthropic").status, "optional");
  assert.equal(getProvider("finnhub").status, "active");
  assert.equal(listProviders({ includeOptional: false }).some(provider => provider.optional), false);
});

test("actual route and library integrations named by the registry remain present", () => {
  const market = fs.readFileSync(path.join(ROOT, "routes", "market-data.js"), "utf8");
  const financials = fs.readFileSync(path.join(ROOT, "routes", "financials.js"), "utf8");
  const analysis = fs.readFileSync(path.join(ROOT, "routes", "analysis.js"), "utf8");
  const database = fs.readFileSync(path.join(ROOT, "lib", "db.js"), "utf8");
  const email = fs.readFileSync(path.join(ROOT, "lib", "email.js"), "utf8");
  const billing = fs.readFileSync(path.join(ROOT, "routes", "billing.js"), "utf8");
  const buildInfo = fs.readFileSync(path.join(ROOT, "lib", "build-info.js"), "utf8");

  assert.match(market, /finance\.yahoo\.com/);
  assert.match(market, /finnhub\.io/);
  assert.match(market, /stooq\.com/);
  assert.match(financials, /data\.sec\.gov/);
  assert.match(financials, /api\.finra\.org/);
  assert.match(database, /@libsql\/client/);
  assert.match(email, /require\(["']resend["']\)/);
  assert.match(billing, /require\(["']stripe["']\)/);
  assert.match(buildInfo, /RENDER_SERVICE_NAME/);
  assert.match(analysis, /api\.anthropic\.com\/v1\/messages/);
});

test("lookup and HTML helpers resolve aliases without reflecting untrusted input", () => {
  assert.equal(providerName("SEC EDGAR XBRL"), "SEC EDGAR");
  assert.match(providerSummary("Finnhub metrics"), /^Finnhub:/);
  assert.equal(renderProviderNameHtml("TradingView"), "TradingView Lightweight Charts");
  assert.match(renderProviderSummaryHtml("stripe"), /Stripe:/);

  const attack = '<img src=x onerror="alert(1)">';
  assert.equal(providerName(attack), null);
  assert.equal(providerSummary(attack), null);
  assert.equal(renderProviderNameHtml(attack), "");
  assert.equal(renderProviderSummaryHtml(attack), "");
});

test("public JSON view omits internal aliases and cannot mutate the canonical registry", () => {
  const first = getPublicProviderRegistry();
  assert.equal(first.schemaVersion, 1);
  assert.equal(first.categories.length, 2);
  assert.ok(first.providers.length === PROVIDERS.length);
  assert.equal(Object.hasOwn(first.providers[0], "aliases"), false);

  const originalName = PROVIDERS[0].name;
  first.providers[0].name = "changed";
  first.providers[0].features.push("changed");
  const second = getPublicProviderRegistry();
  assert.equal(second.providers[0].name, originalName);
  assert.equal(second.providers[0].features.includes("changed"), false);
});

test("canonical registry and freshness vocabulary are deeply immutable", () => {
  assert.equal(Object.isFrozen(PROVIDERS), true);
  assert.equal(Object.isFrozen(PROVIDERS[0]), true);
  assert.equal(Object.isFrozen(PROVIDERS[0].features), true);
  assert.equal(Object.isFrozen(FRESHNESS_VOCABULARY), true);
  assert.equal(Object.isFrozen(FRESHNESS_VOCABULARY["provider-as-of"]), true);
});

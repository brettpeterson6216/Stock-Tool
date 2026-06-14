"use strict";

const providers = new Map();

function recordProvider(name, ok, latencyMs, message = "") {
  const previous = providers.get(name) || { successes: 0, failures: 0 };
  providers.set(name, {
    name,
    status: ok ? "operational" : "degraded",
    successes: previous.successes + (ok ? 1 : 0),
    failures: previous.failures + (ok ? 0 : 1),
    latencyMs: Number.isFinite(latencyMs) ? Math.round(latencyMs) : null,
    message: String(message || "").slice(0, 160),
    checkedAt: new Date().toISOString(),
  });
}

function snapshot() {
  const items = [...providers.values()].sort((a, b) => a.name.localeCompare(b.name));
  const degraded = items.filter(item => item.status !== "operational").length;
  const latestObservation = items.map(item => item.checkedAt).filter(Boolean).sort().at(-1) || null;
  const stale = latestObservation ? Date.now() - new Date(latestObservation).getTime() > 15 * 60 * 1000 : true;
  return {
    status: degraded ? "degraded" : items.length ? "operational" : "observing",
    observedProviders: items.length,
    degradedProviders: degraded,
    latestObservation,
    stale,
    message: items.length
      ? stale ? "Provider observations are older than 15 minutes." : "Status reflects recent observed market requests."
      : "No market-provider request has been observed by this service instance yet.",
    providers: items,
  };
}

module.exports = { recordProvider, snapshot };

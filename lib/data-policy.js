"use strict";
/* ═══════════════════════════════════════════════════════════════════════════
   Data policy: which outside data sources the site may call.

   Finnhub's free plan is for personal use only and forbids sharing its data
   or anything derived from it. Yahoo Finance forbids automated collection and
   commercial use. Both are therefore switched off here, at the one place every
   outbound request passes through, rather than at each of the thirty call
   sites:

     · finnhub.io           blocked unless FINNHUB_ENABLED=1 (set it only with
                            a commercial licence from Finnhub);
     · *.finance.yahoo.com  allowed only while no licensed price provider is
                            configured (lib/prices.js), so prices keep working
                            until the Marketstack key is added, and never after;
     · stooq.com            blocked (no licence for commercial display).

   A blocked call gets a 403 JSON answer immediately, which every caller
   already treats as "this source is unavailable". SEC EDGAR, FINRA and the
   licensed price provider pass straight through.
   ═══════════════════════════════════════════════════════════════════════════ */

let realFetch = null;
const stats = { blocked: {} };

function finnhubAllowed() { return process.env.FINNHUB_ENABLED === "1"; }
function licensedPrices() { return Boolean(process.env.MARKETSTACK_API_KEY); }
function yahooAllowed() { return !licensedPrices() && process.env.YAHOO_ENABLED !== "0"; }

function hostOf(url) {
  try { return new URL(typeof url === "string" ? url : url.url).hostname; } catch (_) { return ""; }
}

/* Pure: may this host be called right now? */
function allowed(host) {
  if (/(^|\.)finnhub\.io$/.test(host)) return finnhubAllowed();
  if (/(^|\.)finance\.yahoo\.com$/.test(host)) return yahooAllowed();
  if (/(^|\.)stooq\.(com|pl)$/.test(host)) return false;
  return true;
}

function blocked(host) {
  stats.blocked[host] = (stats.blocked[host] || 0) + 1;
  return new Response(JSON.stringify({ error: "This data source is not licensed for use on this site." }), {
    status: 403, headers: { "content-type": "application/json", "x-data-policy": "blocked" },
  });
}

function install() {
  if (realFetch) return;
  realFetch = global.fetch;
  global.fetch = function policyFetch(input, init) {
    const host = hostOf(input);
    if (!allowed(host)) return Promise.resolve(blocked(host));
    return realFetch(input, init);
  };
}

function snapshot() {
  return {
    finnhub: finnhubAllowed() ? "enabled (licensed)" : "off",
    yahoo: yahooAllowed() ? "legacy fallback until a licensed price provider is set" : "off",
    prices: licensedPrices() ? "Marketstack" : "Yahoo (legacy)",
    blockedCalls: stats.blocked,
  };
}

module.exports = { install, allowed, snapshot, finnhubAllowed, yahooAllowed, licensedPrices };

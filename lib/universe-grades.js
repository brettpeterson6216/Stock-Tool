"use strict";
/* Cached LensScore grades for every company in the peer universe. Grading the
   whole set takes a fraction of a second; it is redone when the peer set has
   changed and the last pass is at least two minutes old. */
const peers = require("./peer-universe");
const { gradeUniverse } = require("./lens-factors");

let cache = { version: -1, at: 0, rows: [], byTicker: new Map() };

function current({ maxAgeMs = 2 * 60 * 1000 } = {}) {
  const v = peers.getVersion();
  if (cache.version === v || (cache.rows.length && Date.now() - cache.at < maxAgeMs)) return cache;
  const rows = gradeUniverse(peers.all());
  cache = { version: v, at: Date.now(), rows, byTicker: new Map(rows.map(r => [r.ticker, r])) };
  return cache;
}

function get(ticker) { return current().byTicker.get(String(ticker || "").toUpperCase()) || null; }
function _reset() { cache = { version: -1, at: 0, rows: [], byTicker: new Map() }; }

module.exports = { current, get, _reset };

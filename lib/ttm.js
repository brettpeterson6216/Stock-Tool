"use strict";
/* Trailing-twelve-month figures from SEC XBRL company facts.

   The annual statements stop at the last 10-K, which can be close to a year
   old. A 10-Q reports fiscal year-to-date, so
     TTM = last fiscal year + this year-to-date - the same period a year ago.
   Each XBRL concept is tried on its own (tags are never mixed inside one
   sum) and the freshest complete answer wins. With no newer 10-Q, the
   annual figure is returned with basis "annual". */

const DAY = 86400000;
const dur = u => (new Date(u.end) - new Date(u.start)) / DAY;
const newestFirst = (a, b) => (a.end < b.end ? 1 : a.end > b.end ? -1 : ((a.filed || "") < (b.filed || "") ? 1 : -1));

function ttmFromFacts(gaap, concepts) {
  let best = null;
  for (const concept of concepts) {
    const units = ((gaap && gaap[concept] && gaap[concept].units && gaap[concept].units.USD) || [])
      .filter(u => u.start && u.end && Number.isFinite(Number(u.val)));
    const annual = units.filter(u => /^10-K/.test(u.form || "") && dur(u) >= 300 && dur(u) <= 400).sort(newestFirst)[0];
    if (!annual) continue;
    let out = { val: Number(annual.val), asOf: annual.end, basis: "annual" };
    const fyStart = new Date(annual.end).getTime() + DAY;
    const ytd = units.filter(u => /^10-Q/.test(u.form || "") && u.end > annual.end &&
        Math.abs(new Date(u.start).getTime() - fyStart) <= 10 * DAY && dur(u) >= 80 && dur(u) < 300)
      .sort(newestFirst)[0];
    if (ytd) {
      const target = new Date(ytd.end).getTime() - 365 * DAY;
      const prior = units.filter(u => Math.abs(new Date(u.end).getTime() - target) <= 15 * DAY && Math.abs(dur(u) - dur(ytd)) <= 12)
        .sort((a, b) => ((a.filed || "") < (b.filed || "") ? 1 : -1))[0];
      if (prior) out = { val: Number(annual.val) + Number(ytd.val) - Number(prior.val), asOf: ytd.end, basis: "ttm" };
    }
    if (!best || out.asOf > best.asOf) best = out;
  }
  return best;
}

// Newest share count from any filing's cover page.
function latestSharesFromFacts(facts) {
  const rows = (facts && facts.facts && facts.facts.dei && facts.facts.dei.EntityCommonStockSharesOutstanding &&
    facts.facts.dei.EntityCommonStockSharesOutstanding.units && facts.facts.dei.EntityCommonStockSharesOutstanding.units.shares) || [];
  const row = rows.filter(u => Number(u.val) > 0).sort((a, b) => (a.end < b.end ? 1 : -1))[0];
  return row ? { val: Number(row.val), asOf: row.end } : null;
}

module.exports = { ttmFromFacts, latestSharesFromFacts };

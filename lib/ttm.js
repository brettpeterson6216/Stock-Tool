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

/* Every TTM (or annual) value a concept can produce, newest period first. */
function ttmCandidates(gaap, concepts) {
  const out = [];
  for (const concept of concepts) {
    const units = ((gaap && gaap[concept] && gaap[concept].units && gaap[concept].units.USD) || [])
      .filter(u => u.start && u.end && Number.isFinite(Number(u.val)));
    const annuals = units.filter(u => /^10-K/.test(u.form || "") && dur(u) >= 300 && dur(u) <= 400).sort(newestFirst);
    const annual = annuals[0];
    if (!annual) continue;
    out.push({ val: Number(annual.val), asOf: annual.end, basis: "annual", concept });
    const fyStart = new Date(annual.end).getTime() + DAY;
    const ytd = units.filter(u => /^10-Q/.test(u.form || "") && u.end > annual.end &&
        Math.abs(new Date(u.start).getTime() - fyStart) <= 10 * DAY && dur(u) >= 80 && dur(u) < 300)
      .sort(newestFirst)[0];
    if (ytd) {
      const target = new Date(ytd.end).getTime() - 365 * DAY;
      const prior = units.filter(u => Math.abs(new Date(u.end).getTime() - target) <= 15 * DAY && Math.abs(dur(u) - dur(ytd)) <= 12)
        .sort((a, b) => ((a.filed || "") < (b.filed || "") ? 1 : -1))[0];
      if (prior) out.push({ val: Number(annual.val) + Number(ytd.val) - Number(prior.val), asOf: ytd.end, basis: "ttm", concept });
    }
  }
  // Newest period first; for the same period, the concept listed first wins.
  return out.sort((a, b) => (a.asOf < b.asOf ? 1 : a.asOf > b.asOf ? -1 : concepts.indexOf(a.concept) - concepts.indexOf(b.concept)));
}

function ttmFromFacts(gaap, concepts) {
  const c = ttmCandidates(gaap, concepts)[0];
  return c ? { val: c.val, asOf: c.asOf, basis: c.basis } : null;
}

/* Revenue and net income for the SAME twelve months. Looked up separately,
   JPM paired FY2025 revenue with net income to June 2026 (its 10-Q revenue
   uses a tag the list did not have), inflating the margin by several points.
   Takes the newest period both figures can be built for. */
function matchedTtm(gaap, revConcepts, niConcepts) {
  const revs = ttmCandidates(gaap, revConcepts), nis = ttmCandidates(gaap, niConcepts);
  for (const r of revs) {
    const n = nis.find(x => x.asOf === r.asOf);
    if (n) return { revenue: { val: r.val, asOf: r.asOf, basis: r.basis }, netIncome: { val: n.val, asOf: n.asOf, basis: n.basis }, asOf: r.asOf, basis: r.basis };
  }
  return null;
}

/* Diluted weighted-average shares for the newest quarter (falls back to the
   newest annual figure). The cover-page count is basic shares on one date. */
function latestDilutedShares(facts) {
  const rows = (facts && facts.facts && facts.facts["us-gaap"] && facts.facts["us-gaap"].WeightedAverageNumberOfDilutedSharesOutstanding &&
    facts.facts["us-gaap"].WeightedAverageNumberOfDilutedSharesOutstanding.units && facts.facts["us-gaap"].WeightedAverageNumberOfDilutedSharesOutstanding.units.shares) || [];
  const ok = rows.filter(u => Number(u.val) > 0 && u.start && u.end);
  const q = ok.filter(u => dur(u) >= 80 && dur(u) <= 100).sort(newestFirst)[0];
  const a = ok.filter(u => dur(u) >= 300 && dur(u) <= 400).sort(newestFirst)[0];
  const row = q && (!a || q.end >= a.end) ? q : a;
  if (!row) return null;
  // 3-year compound change of the annual diluted count: buybacks negative.
  const annual = ok.filter(u => /^10-K/.test(u.form || "") && dur(u) >= 300 && dur(u) <= 400).sort(newestFirst);
  const byEnd = []; annual.forEach(u => { if (!byEnd.some(x => x.end === u.end)) byEnd.push(u); });
  let cagr3 = null;
  if (byEnd.length >= 4) {
    const now = Number(byEnd[0].val), then = Number(byEnd[3].val);
    if (now > 0 && then > 0) cagr3 = Math.pow(now / then, 1 / 3) - 1;
  }
  return { val: Number(row.val), asOf: row.end, cagr3 };
}

// Newest share count from any filing's cover page.
function latestSharesFromFacts(facts) {
  const rows = (facts && facts.facts && facts.facts.dei && facts.facts.dei.EntityCommonStockSharesOutstanding &&
    facts.facts.dei.EntityCommonStockSharesOutstanding.units && facts.facts.dei.EntityCommonStockSharesOutstanding.units.shares) || [];
  const row = rows.filter(u => Number(u.val) > 0).sort((a, b) => (a.end < b.end ? 1 : -1))[0];
  return row ? { val: Number(row.val), asOf: row.end } : null;
}

module.exports = { ttmFromFacts, ttmCandidates, matchedTtm, latestDilutedShares, latestSharesFromFacts };

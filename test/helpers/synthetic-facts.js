"use strict";
/* A synthetic SEC companyfacts document shaped like the real thing:
   - revenue and income reported as three-month facts in 10-Qs and as a
     full year in the 10-K (no Q4 fact);
   - cash flows reported only year-to-date (3, 6, 9, 12 months);
   - revenue tagged "Revenues" until 2018, then RevenueFromContract…;
   - a 10-for-1 stock split in mid-2024 that only restates recent filings. */
function iso(d) { return d.toISOString().slice(0, 10); }
function addMonths(d, m) { const x = new Date(d); x.setUTCMonth(x.getUTCMonth() + m); return x; }

function buildFacts({ startYear = 2015, endYear = 2025, quartersIntoLast = 2, splitYear = 2024 } = {}) {
  const facts = {};
  const put = (concept, unit, row) => {
    facts[concept] = facts[concept] || { units: {} };
    (facts[concept].units[unit] = facts[concept].units[unit] || []).push(row);
  };
  let q = 0;
  for (let fy = startYear; fy <= endYear; fy++) {
    const fyStart = new Date(Date.UTC(fy, 0, 1));
    let ytdOcf = 0, ytdCapex = 0, ytdRev = 0, ytdNi = 0, ytdEps = 0;
    const nq = fy === endYear ? quartersIntoLast : 4;
    for (let k = 0; k < nq; k++) {
      q++;
      const qs = addMonths(fyStart, 3 * k), qe = new Date(addMonths(fyStart, 3 * (k + 1)) - 86400000);
      const rev = 1e9 * Math.pow(1.03, q);
      const ni = rev * 0.2;
      const ocf = rev * 0.25, capex = rev * 0.05;
      /* Pre-split filings report 10x fewer shares and 10x higher EPS. */
      const restated = fy >= splitYear - 1;
      const sharesTrue = 1e9 * Math.pow(0.995, q);
      const shares = restated ? sharesTrue : sharesTrue / 10;
      const eps = ni / shares;
      ytdOcf += ocf; ytdCapex += capex; ytdRev += rev; ytdNi += ni; ytdEps += eps;
      const filed = iso(addMonths(qe, 1));
      const form = k === 3 ? "10-K" : "10-Q";
      const revTag = fy < 2018 ? "Revenues" : "RevenueFromContractWithCustomerExcludingAssessedTax";
      if (k < 3) {
        put(revTag, "USD", { start: iso(qs), end: iso(qe), val: rev, form, filed });
        put("NetIncomeLoss", "USD", { start: iso(qs), end: iso(qe), val: ni, form, filed });
        put("EarningsPerShareDiluted", "USD/shares", { start: iso(qs), end: iso(qe), val: eps, form, filed });
        put("WeightedAverageNumberOfDilutedSharesOutstanding", "shares", { start: iso(qs), end: iso(qe), val: shares, form, filed });
        if (k > 0) {
          put(revTag, "USD", { start: iso(fyStart), end: iso(qe), val: ytdRev, form, filed });
        }
      } else {
        put(revTag, "USD", { start: iso(fyStart), end: iso(qe), val: ytdRev, form, filed });
        put("NetIncomeLoss", "USD", { start: iso(fyStart), end: iso(qe), val: ytdNi, form, filed });
        put("EarningsPerShareDiluted", "USD/shares", { start: iso(fyStart), end: iso(qe), val: ytdEps, form, filed });
        put("NetIncomeLoss", "USD", { start: iso(addMonths(fyStart, 0)), end: iso(new Date(addMonths(fyStart, 9) - 86400000)), val: ytdNi - ni, form: "10-Q", filed: iso(addMonths(fyStart, 10)) });
        put("EarningsPerShareDiluted", "USD/shares", { start: iso(fyStart), end: iso(new Date(addMonths(fyStart, 9) - 86400000)), val: ytdEps - eps, form: "10-Q", filed: iso(addMonths(fyStart, 10)) });
      }
      put("NetCashProvidedByUsedInOperatingActivities", "USD", { start: iso(fyStart), end: iso(qe), val: ytdOcf, form, filed });
      put("PaymentsToAcquirePropertyPlantAndEquipment", "USD", { start: iso(fyStart), end: iso(qe), val: ytdCapex, form, filed });
    }
  }
  return { cik: 1, entityName: "Synthetic Co", facts: { "us-gaap": facts } };
}

module.exports = { buildFacts };

"use strict";
/* What Wall Street thinks, from Finnhub's free feeds: the analyst rating mix
   now and three months ago, and the last four earnings reports against the
   estimate. Price targets and estimate revisions need a premium feed. */
function summarizeStreet(rec, earnings) {
  const out = {};
  const rows = Array.isArray(rec) ? rec.filter(r => r && r.period).sort((a, b) => String(b.period).localeCompare(String(a.period))) : [];
  const mix = r => {
    if (!r) return null;
    const n = ["strongBuy", "buy", "hold", "sell", "strongSell"].reduce((t, k) => t + (Number(r[k]) || 0), 0);
    if (!n) return null;
    const mean = ((r.strongBuy || 0) * 5 + (r.buy || 0) * 4 + (r.hold || 0) * 3 + (r.sell || 0) * 2 + (r.strongSell || 0)) / n;
    return { period: r.period, strongBuy: r.strongBuy || 0, buy: r.buy || 0, hold: r.hold || 0, sell: r.sell || 0, strongSell: r.strongSell || 0, total: n,
      mean: Math.round(mean * 100) / 100,
      label: mean >= 4.3 ? "Strong buy" : mean >= 3.6 ? "Buy" : mean >= 2.6 ? "Hold" : mean >= 1.8 ? "Sell" : "Strong sell" };
  };
  const now = mix(rows[0]);
  const then = mix(rows[3] || rows[rows.length - 1]);
  if (now) out.ratings = { ...now, threeMonthsAgo: then && then.period !== now.period ? then : null };
  const eps = (Array.isArray(earnings) ? earnings : []).filter(e => Number.isFinite(Number(e.actual)) && Number.isFinite(Number(e.estimate)))
    .sort((a, b) => String(b.period).localeCompare(String(a.period))).slice(0, 4)
    .map(e => ({ period: e.period, actual: Number(e.actual), estimate: Number(e.estimate),
      surprisePct: Number.isFinite(Number(e.surprisePercent)) ? Math.round(Number(e.surprisePercent) * 10) / 10 : null,
      beat: Number(e.actual) >= Number(e.estimate) }));
  if (eps.length) out.earnings = { quarters: eps, beats: eps.filter(e => e.beat).length };
  return Object.keys(out).length ? out : null;
}
/* Next scheduled earnings report from Finnhub's earnings calendar. hour is
   "bmo" (before the open), "amc" (after the close) or "dmh"/"" (unknown). */
function nextEarnings(cal, today = new Date().toISOString().slice(0, 10)) {
  const rows = Array.isArray(cal?.earningsCalendar) ? cal.earningsCalendar : [];
  const next = rows.filter(r => r && /^\d{4}-\d{2}-\d{2}$/.test(String(r.date)) && r.date >= today)
    .sort((a, b) => a.date.localeCompare(b.date))[0];
  if (!next) return null;
  const when = { bmo: "before the open", amc: "after the close" }[String(next.hour || "").toLowerCase()] || null;
  const days = Math.round((Date.parse(next.date + "T12:00:00Z") - Date.parse(today + "T12:00:00Z")) / 86400000);
  return { date: next.date, when, days, quarter: next.quarter || null, year: next.year || null,
    epsEstimate: Number.isFinite(Number(next.epsEstimate)) && next.epsEstimate !== null ? Number(next.epsEstimate) : null };
}
module.exports = { summarizeStreet, nextEarnings };

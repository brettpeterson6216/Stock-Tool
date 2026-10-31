/* ═══════════════════════════════════════════════════════════════════════════
   What the price implies — the valuation math behind the Valuation tab.

   Deliberately small and transparent, so every number on the page can be
   explained in a sentence:

     value in N years  = revenue × (1+g)^N × net margin × exit P/E ÷ shares
     annual return     = (value in N years ÷ price today)^(1/N) − 1
     value today       = value in N years ÷ (1 + required return)^N

   impliedGrowth() runs the first line backwards: the yearly revenue growth
   that makes value today equal the price, holding margin, exit P/E and the
   required return fixed. That is the "implied" in ImpliedLens.
   ═══════════════════════════════════════════════════════════════════════════ */
(function (root) {
  "use strict";

  function finite(v) { return typeof v === "number" && isFinite(v); }

  /* inputs: { price, revenue, shares, years, growth, margin, exitPE, shareChange, required }
     rates are decimals (0.12 = 12%). */
  function project(i) {
    var n = i.years || 5;
    if (!(i.price > 0 && i.revenue > 0 && i.shares > 0 && finite(i.growth) && finite(i.margin) && i.exitPE > 0)) return null;
    var rev = [], eps = [];
    var shares = i.shares;
    for (var y = 1; y <= n; y++) {
      var r = i.revenue * Math.pow(1 + i.growth, y);
      shares = shares * (1 + (i.shareChange || 0));
      rev.push(r);
      eps.push(r * i.margin / shares);
    }
    var future = eps[n - 1] * i.exitPE;
    var annual = future > 0 ? Math.pow(future / i.price, 1 / n) - 1 : -1;
    var today = future / Math.pow(1 + (i.required || 0.1), n);
    return {
      years: n, revenue: rev, eps: eps, sharesEnd: shares,
      futurePrice: future, annualReturn: annual, valueToday: today,
      upside: today / i.price - 1,
    };
  }

  function impliedGrowth(i) {
    var n = i.years || 5;
    if (!(i.price > 0 && i.revenue > 0 && i.shares > 0 && i.margin > 0 && i.exitPE > 0)) return null;
    var sharesEnd = i.shares * Math.pow(1 + (i.shareChange || 0), n);
    var needed = i.price * Math.pow(1 + (i.required || 0.1), n) * sharesEnd / (i.exitPE * i.margin * i.revenue);
    return Math.pow(needed, 1 / n) - 1;
  }

  /* Compound yearly growth between the first and last of a list of yearly
     values (oldest first). Null when the start is not positive. */
  function cagr(start, end, years) {
    if (!(start > 0) || !(end > 0) || !(years > 0)) return null;
    return Math.pow(end / start, 1 / years) - 1;
  }

  function clamp(v, lo, hi) { return Math.max(lo, Math.min(hi, v)); }
  function round(v, step) { return Math.round(v / step) * step; }

  /* Sensible starting assumptions from what the company has actually done. */
  function defaults(ctx) {
    var hist = finite(ctx.growth3y) ? ctx.growth3y : finite(ctx.growth1y) ? ctx.growth1y : 0.06;
    var base = clamp(round(hist * 0.7, 0.005), -0.05, 0.3);
    var m = finite(ctx.margin) && ctx.margin > 0.01 ? clamp(ctx.margin, 0.02, 0.6) : 0.1;
    var pe = finite(ctx.pe) && ctx.pe > 0 ? clamp(round(ctx.pe * 0.8, 1), 10, 35) : 18;
    return {
      bear: { growth: round(base - 0.08, 0.005), margin: round(m * 0.8, 0.005), exitPE: Math.max(8, round(pe * 0.75, 1)) },
      base: { growth: base, margin: round(m, 0.005), exitPE: pe },
      bull: { growth: round(base + 0.08, 0.005), margin: round(Math.min(0.65, m * 1.15), 0.005), exitPE: round(pe * 1.2, 1) },
      required: 0.1, years: 5, shareChange: 0, unprofitable: !(ctx.margin > 0.01),
    };
  }

  var api = { project: project, impliedGrowth: impliedGrowth, cagr: cagr, defaults: defaults };
  if (typeof module === "object" && module.exports) module.exports = api;
  else { root.IL = root.IL || {}; root.IL.valuation = api; }
})(typeof window !== "undefined" ? window : globalThis);

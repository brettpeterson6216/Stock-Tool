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

  /* A rate given by the user: a valid number is kept as is, zero included.
     Only a missing or non-numeric value takes the default. */
  function rate(v, dflt) { return finite(v) ? v : dflt; }

  /* Check the inputs before any math. Returns null when they are usable,
     or { field, message } naming the first problem in plain words. */
  function validate(i) {
    var n = i.years == null ? 5 : i.years;
    if (!(finite(n) && n >= 1 && n <= 30 && Math.round(n) === n)) return { field: "years", message: "Years must be a whole number from 1 to 30." };
    if (!(i.price > 0)) return { field: "price", message: "A price above zero is needed." };
    if (!(i.revenue > 0)) return { field: "revenue", message: "Revenue above zero is needed." };
    if (!(i.shares > 0)) return { field: "shares", message: "A share count above zero is needed." };
    if ("growth" in i && !(finite(i.growth) && i.growth > -1)) return { field: "growth", message: "Revenue growth must be above \u2212100% a year." };
    if (!finite(i.margin)) return { field: "margin", message: "Enter a net margin." };
    if (!(i.exitPE > 0)) return { field: "exitPE", message: "The P/E in the final year must be above zero." };
    if (i.shareChange != null && !(finite(i.shareChange) && i.shareChange > -1)) return { field: "shareChange", message: "The yearly share-count change must be above \u2212100%; at \u2212100% no shares would be left." };
    if (i.required != null && !(finite(i.required) && i.required > -1)) return { field: "required", message: "The return you require must be above \u2212100%." };
    return null;
  }

  /* inputs: { price, revenue, shares, years, growth, margin, exitPE, shareChange, required }
     rates are decimals (0.12 = 12%). Returns null for unusable inputs
     (see validate) or when any result is not a finite number. */
  function project(i) {
    if (validate(i) || !("growth" in i)) return null;
    var n = i.years == null ? 5 : i.years, req = rate(i.required, 0.1), dil = rate(i.shareChange, 0);
    var rev = [], eps = [];
    var shares = i.shares;
    for (var y = 1; y <= n; y++) {
      var r = i.revenue * Math.pow(1 + i.growth, y);
      shares = shares * (1 + dil);
      rev.push(r);
      eps.push(r * i.margin / shares);
    }
    var future = eps[n - 1] * i.exitPE;
    var annual = future > 0 ? Math.pow(future / i.price, 1 / n) - 1 : -1;
    var today = future / Math.pow(1 + req, n);
    var out = {
      years: n, revenue: rev, eps: eps, sharesEnd: shares,
      futurePrice: future, annualReturn: annual, valueToday: today,
      upside: today / i.price - 1,
    };
    return [future, annual, today, out.upside, shares].every(finite) ? out : null;
  }

  function impliedGrowth(i) {
    if (validate(i) || !(i.margin > 0)) return null;
    var n = i.years == null ? 5 : i.years, req = rate(i.required, 0.1), dil = rate(i.shareChange, 0);
    var sharesEnd = i.shares * Math.pow(1 + dil, n);
    var needed = i.price * Math.pow(1 + req, n) * sharesEnd / (i.exitPE * i.margin * i.revenue);
    var g = Math.pow(needed, 1 / n) - 1;
    return finite(g) ? g : null;
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

  var api = { project: project, impliedGrowth: impliedGrowth, cagr: cagr, defaults: defaults, validate: validate };
  if (typeof module === "object" && module.exports) module.exports = api;
  else { root.IL = root.IL || {}; root.IL.valuation = api; }
})(typeof window !== "undefined" ? window : globalThis);

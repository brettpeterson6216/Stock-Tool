/* ═══════════════════════════════════════════════════════════════════════════
   The Projection Lab's math: what the price implies, and what each case is
   worth. Deliberately small and transparent, so every number on the page can
   be explained in a sentence:

     revenue in year y = revenue × Π(1 + growth that year)
                         growth fades in a straight line from the starting
                         rate to the final-year rate
     net margin        = moves in a straight line from today's to the target
     EPS in year y     = revenue × margin ÷ shares (shares change each year)
     price in year N   = EPS in year N × the P/E you expect then
     annual return     = (price in year N ÷ price today)^(1/N) − 1
     worth today       = price in year N ÷ (1 + the return you require)^N

   impliedGrowth() runs it backwards with one steady growth rate: the yearly
   revenue growth that makes "worth today" equal the price. That is the
   "implied" in ImpliedLens.

   defaults() seeds the three cases from what the company has actually done,
   and says in plain words where each number came from. Recent quarters lead,
   because a full-year rate can be inflated by an acquisition (Celsius's
   +49% in 2025 was mostly Alani Nu, bought that April).
   ═══════════════════════════════════════════════════════════════════════════ */
(function (root) {
  "use strict";

  function finite(v) { return typeof v === "number" && isFinite(v); }
  /* A rate given by the user: a valid number is kept as is, zero included.
     Only a missing or non-numeric value takes the default. */
  function rate(v, dflt) { return finite(v) ? v : dflt; }
  function clamp(v, lo, hi) { return Math.max(lo, Math.min(hi, v)); }
  function round(v, step) { return Number((Math.round(v / step) * step).toFixed(6)); }

  /* Check the inputs before any math. Returns null when they are usable,
     or { field, message } naming the first problem in plain words. */
  function validate(i) {
    var n = i.years == null ? 5 : i.years;
    if (!(finite(n) && n >= 1 && n <= 30 && Math.round(n) === n)) return { field: "years", message: "Years must be a whole number from 1 to 30." };
    if (!(i.price > 0)) return { field: "price", message: "A price above zero is needed." };
    if (!(i.revenue > 0)) return { field: "revenue", message: "Revenue above zero is needed." };
    if (!(i.shares > 0)) return { field: "shares", message: "A share count above zero is needed." };
    if ("growth" in i && !(finite(i.growth) && i.growth > -1)) return { field: "growth", message: "Revenue growth must be above −100% a year." };
    if (i.growthEnd != null && !(finite(i.growthEnd) && i.growthEnd > -1)) return { field: "growthEnd", message: "Final-year growth must be above −100% a year." };
    if (!finite(i.margin)) return { field: "margin", message: "Enter a net margin." };
    if (!(i.exitPE > 0)) return { field: "exitPE", message: "The P/E in the final year must be above zero." };
    if (i.shareChange != null && !(finite(i.shareChange) && i.shareChange > -1)) return { field: "shareChange", message: "The yearly share-count change must be above −100%; at −100% no shares would be left." };
    if (i.required != null && !(finite(i.required) && i.required > -1)) return { field: "required", message: "The return you require must be above −100%." };
    return null;
  }

  /* Growth in year y of n: a straight line from `start` (year 1) to `end`
     (year n). Without `end`, the same rate every year. */
  function growthIn(start, end, y, n) {
    if (!finite(end) || n <= 1) return start;
    return start + (end - start) * (y - 1) / (n - 1);
  }

  /* inputs: { price, revenue, shares, years, growth, growthEnd?, margin,
     margin0?, exitPE, shareChange, required } (rates as decimals, 0.12 = 12%).
     Returns null for unusable inputs or any non-finite result. */
  function project(i) {
    if (validate(i) || !("growth" in i)) return null;
    var n = i.years == null ? 5 : i.years, req = rate(i.required, 0.1), dil = rate(i.shareChange, 0);
    var m0 = finite(i.margin0) ? i.margin0 : i.margin;
    var rev = [], eps = [], growth = [], margin = [], shares = [], price = [];
    var r = i.revenue, sh = i.shares;
    for (var y = 1; y <= n; y++) {
      var g = growthIn(i.growth, i.growthEnd, y, n);
      r = r * (1 + g);
      sh = sh * (1 + dil);
      var m = m0 + (i.margin - m0) * y / n;
      growth.push(g); rev.push(r); margin.push(m); shares.push(sh);
      eps.push(r * m / sh);
      price.push(r * m / sh * i.exitPE);
    }
    var future = price[n - 1];
    var annual = future > 0 ? Math.pow(future / i.price, 1 / n) - 1 : -1;
    var today = future / Math.pow(1 + req, n);
    var out = {
      years: n, revenue: rev, eps: eps, growth: growth, margin: margin, shares: shares, pricePath: price,
      sharesEnd: sh, futurePrice: future, annualReturn: annual, valueToday: today, upside: today / i.price - 1,
    };
    return [future, annual, today, out.upside, sh].every(finite) ? out : null;
  }

  /* The steady yearly revenue growth at which the price earns exactly the
     required return, holding margin, exit P/E and share change fixed. */
  function impliedGrowth(i) {
    if (validate(i) || !(i.margin > 0)) return null;
    var n = i.years == null ? 5 : i.years, req = rate(i.required, 0.1), dil = rate(i.shareChange, 0);
    var sharesEnd = i.shares * Math.pow(1 + dil, n);
    var needed = i.price * Math.pow(1 + req, n) * sharesEnd / (i.exitPE * i.margin * i.revenue);
    var g = Math.pow(needed, 1 / n) - 1;
    return finite(g) ? g : null;
  }

  /* Probability-weighted outcome of the three cases. weights sum to 1. */
  function weighted(outs, weights, price) {
    var keys = ["bear", "base", "bull"], sum = 0, value = 0;
    for (var k = 0; k < keys.length; k++) {
      var o = outs[keys[k]], w = weights[keys[k]];
      if (!o || !finite(w) || w < 0) return null;
      sum += w; value += w * o.futurePrice;
    }
    if (!(sum > 0)) return null;
    value /= sum;
    var n = outs.base.years;
    return { futurePrice: value, annualReturn: value > 0 ? Math.pow(value / price, 1 / n) - 1 : -1 };
  }

  function cagr(start, end, years) {
    if (!(start > 0) || !(end > 0) || !(years > 0)) return null;
    return Math.pow(end / start, 1 / years) - 1;
  }

  /* Pure: what the reported quarters say about growth and the share count.
     quarters: [{ end, revenue, netIncome, shares }] oldest first. */
  function history(quarters) {
    var q = (quarters || []).filter(function (x) { return x && finite(x.revenue) && x.revenue > 0; });
    var out = { recent: null, recentNote: null, jump: null, shareTrend: null, shareJump: null };
    var yoy = [];
    for (var i = Math.max(4, q.length - 2); i < q.length; i++) {
      if (q[i - 4] && q[i - 4].revenue > 0) yoy.push({ end: q[i].end, g: q[i].revenue / q[i - 4].revenue - 1 });
    }
    if (yoy.length) {
      out.recent = yoy.reduce(function (s, x) { return s + x.g; }, 0) / yoy.length;
      out.recentNote = yoy.length === 2 ? "the last two quarters against the same quarters a year earlier" : "the latest quarter against the same quarter a year earlier";
    }
    /* A single quarter of revenue more than 40% above the one before, within
       the last two years, is almost always an acquisition (or a one-off). */
    for (var j = Math.max(1, q.length - 8); j < q.length; j++) {
      var step = q[j].revenue / q[j - 1].revenue - 1;
      if (step > 0.4 && (!out.jump || step > out.jump.step)) out.jump = { end: q[j].end, step: step };
    }
    var s = (quarters || []).filter(function (x) { return x && finite(x.shares) && x.shares > 0; });
    if (s.length >= 5) {
      var last = s[s.length - 1].shares, yearAgo = s[s.length - 5].shares;
      out.shareTrend = last / yearAgo - 1;
      for (var k = Math.max(1, s.length - 4); k < s.length; k++) {
        var d = s[k].shares / s[k - 1].shares - 1;
        if (Math.abs(d) > 0.08) out.shareJump = { end: s[k].end, step: d };
      }
    }
    return out;
  }

  function quarterLabel(end) {
    var d = new Date(String(end) + "T12:00:00Z");
    if (isNaN(d)) return "one quarter";
    return "the quarter to " + d.toLocaleDateString("en-US", { month: "short", year: "numeric", timeZone: "UTC" });
  }
  function pct(v) { return (v >= 0 ? "+" : "−") + Math.abs(Math.round(v * 1000) / 10) + "%"; }

  /* Starting assumptions from what the company has actually done, with a
     plain sentence for each saying where it came from.
     ctx: { price, pe, margin, growth1y, growth3y, quarters? } */
  function defaults(ctx) {
    var notes = [];
    var h = history(ctx.quarters);
    var g1 = finite(ctx.growth1y) ? ctx.growth1y : null, g3 = finite(ctx.growth3y) ? ctx.growth3y : null;
    var start, src;
    if (finite(h.recent)) {
      start = h.recent; src = "Starting growth " + pct(h.recent) + ": " + h.recentNote + ".";
      if (h.jump) src += " Revenue rose " + pct(h.jump.step) + " in " + quarterLabel(h.jump.end) + " alone, which usually means an acquisition, so the full-year " + (g1 !== null ? pct(g1) : "rate") + " is not used.";
      else if (g1 !== null && g1 - h.recent > 0.12) src += " Growth has slowed from " + pct(g1) + " over the full year.";
    } else if (g3 !== null) { start = g3; src = "Starting growth " + pct(g3) + ": the 3-year average."; }
    else if (g1 !== null) { start = g1; src = "Starting growth " + pct(g1) + ": the last 12 months."; }
    else { start = 0.06; src = "Starting growth 6%: no reported history, so a typical rate."; }
    var raw = start;
    start = clamp(round(start, 0.005), -0.1, 0.45);
    if (raw > 0.45) src += " Held to 45% for the first year: few companies keep up more than that.";
    else if (raw < -0.1) src += " Held to −10% for the first year.";
    notes.push(src + " It fades to 4% a year by the final year, because fast growth rarely lasts.");

    var unprofitable = !(finite(ctx.margin) && ctx.margin > 0.01);
    var m = unprofitable ? 0.08 : clamp(ctx.margin, 0.02, 0.6);
    notes.push(unprofitable ? "Net margin target 8%: the company is not profitable yet, so the final-year margin is an assumption, not today's figure." : "Net margin " + pct(m).replace("+", "") + ": the last 12 months, held steady in the base case.");

    var pe0 = finite(ctx.pe) && ctx.pe > 0 ? ctx.pe : null;
    var pe = pe0 ? clamp(round((pe0 + 20) / 2, 1), 10, 40) : 18;
    notes.push(pe0 ? "Final-year P/E " + pe + "×: halfway from today's " + Math.round(pe0) + "× toward a long-run 20×" + (pe0 > 60 ? ", capped at 40×" : "") + "." : "Final-year P/E 18×: no meaningful P/E today, so a market-typical multiple.");

    var shareChange = 0;
    if (finite(h.shareTrend)) {
      if (h.shareJump) notes.push("Share count: held flat. It moved " + pct(h.shareJump.step) + " in " + quarterLabel(h.shareJump.end) + ", a one-off (often an acquisition or a big buyback), so last year's trend is not used.");
      else { shareChange = clamp(round(h.shareTrend, 0.005), -0.05, 0.05); notes.push("Share count " + pct(shareChange) + " a year: the change over the last four quarters" + (shareChange < 0 ? " (buybacks)." : shareChange > 0 ? " (new shares issued)." : ".")); }
    }

    var bearStart = start > 0 ? start * 0.6 : start - 0.05, bullStart = start > 0 ? Math.min(0.6, start * 1.3) : start + 0.05;
    return {
      bear: { growth: round(bearStart, 0.005), growthEnd: 0.02, margin: round(unprofitable ? 0.04 : m * 0.85, 0.005), exitPE: Math.max(6, round(pe * 0.8, 1)) },
      base: { growth: start, growthEnd: 0.04, margin: round(m, 0.001), exitPE: pe },
      bull: { growth: round(bullStart, 0.005), growthEnd: 0.06, margin: round(unprofitable ? 0.12 : Math.min(0.65, m * 1.12), 0.005), exitPE: round(pe * 1.2, 1) },
      weights: { bear: 0.25, base: 0.5, bull: 0.25 },
      required: 0.1, years: 5, shareChange: shareChange, unprofitable: unprofitable,
      notes: notes, history: h,
    };
  }

  /* Pure: the stock's own P/E at each quarter end — price at that date
     over the four quarters of diluted EPS reported up to it. A Value grade
     says cheap or dear against peers; this says cheap or dear against the
     stock's own history, so a whole sector priced high does not pass as
     "cheap". Last five years by default. quarters: [{ end, eps, price? }]
     (price is the history API's close at the quarter end; without it the
     bars are used); bars: [{ time (s), close }]. */
  function peHistory(quarters, bars, years) {
    var q = (quarters || []).filter(function (x) { return x && x.end; });
    var b = (bars || []).filter(function (x) { return x && finite(x.close) && x.close > 0; });
    if (q.length < 5) return null;
    function closeOn(day) {
      if (b.length < 60) return null;
      var t = Date.parse(day + "T23:59:59Z") / 1000, hit = null;
      if (t < b[0].time) return null;
      for (var i = 0; i < b.length; i++) { if (b[i].time <= t) hit = b[i].close; else break; }
      return hit;
    }
    var cutoff = Date.parse(q[q.length - 1].end) - (years || 5) * 365.25 * 86400000;
    var pts = [];
    for (var k = 3; k < q.length; k++) {
      if (Date.parse(q[k].end) <= cutoff) continue;
      var e = [q[k], q[k - 1], q[k - 2], q[k - 3]].map(function (x) { return x.eps; });
      if (!e.every(finite)) continue;
      var ttm = e.reduce(function (s, x) { return s + x; }, 0);
      if (!(ttm > 0)) continue;
      var px = finite(q[k].price) && q[k].price > 0 ? q[k].price : closeOn(q[k].end);
      if (px) pts.push({ end: q[k].end, pe: px / ttm });
    }
    if (pts.length < 4) return null;
    var v = pts.map(function (p) { return p.pe; }).sort(function (x, y) { return x - y; });
    var mid = Math.floor(v.length / 2), med = v.length % 2 ? v[mid] : (v[mid - 1] + v[mid]) / 2;
    return { points: pts, median: med, low: v[0], high: v[v.length - 1], since: pts[0].end };
  }


  /* Discounted cash flow on a case's revenue path.
     o: { revenuePath: [year 1..n], fcfMargin0 (today), fcfMargin (final
     year), rate (discount rate), terminal (growth after year n), netCash
     (cash and investments less debt), shares, price }
     Free cash flow each year is revenue times a margin moving in a straight
     line from today's to the final year's; after year n it grows at
     `terminal` for ever (Gordon growth). Value per share is the present value
     of all of it, plus net cash, over today's diluted shares. */
  function dcfProblem(o) {
    if (!o || !Array.isArray(o.revenuePath) || !o.revenuePath.length || !o.revenuePath.every(function (v) { return finite(v) && v > 0; })) return "The cases above need to be valid first.";
    if (!(o.shares > 0) || !(o.price > 0)) return "A price and share count are needed.";
    if (!finite(o.fcfMargin) || !finite(o.fcfMargin0)) return "Enter a free-cash-flow margin for each case.";
    if (!(finite(o.rate) && o.rate > 0 && o.rate < 0.3)) return "The discount rate must be between 0% and 30%.";
    if (!(finite(o.terminal) && o.terminal >= -0.03 && o.terminal <= 0.05)) return "Growth after the final year must be between −3% and 5%; no company outgrows the economy for ever.";
    if (!(o.rate - o.terminal >= 0.01)) return "The discount rate must be at least 1 point above the growth after the final year, or the value is infinite.";
    if (o.netCash != null && !finite(o.netCash)) return "Net cash must be a number.";
    return null;
  }
  function dcf(o) {
    if (dcfProblem(o)) return null;
    var n = o.revenuePath.length, fcf = [], pv = [], sum = 0;
    for (var i = 0; i < n; i++) {
      var m = n === 1 ? o.fcfMargin : o.fcfMargin0 + (o.fcfMargin - o.fcfMargin0) * (i + 1) / n;
      var f = o.revenuePath[i] * m, d = Math.pow(1 + o.rate, i + 1);
      fcf.push(f); pv.push(f / d); sum += f / d;
    }
    var tv = fcf[n - 1] * (1 + o.terminal) / (o.rate - o.terminal), pvTv = tv / Math.pow(1 + o.rate, n);
    var ops = sum + pvTv, equity = ops + (o.netCash || 0), value = equity / o.shares;
    var out = { fcf: fcf, pv: pv, sumPv: sum, terminalValue: tv, pvTerminal: pvTv, terminalShare: ops > 0 ? pvTv / ops : null, equity: equity, value: value, upside: value / o.price - 1 };
    return [value, sum, pvTv].every(finite) ? out : null;
  }
  /* The final-year free-cash-flow margin at which the DCF value equals
     today's price. Value is linear in that margin, so two runs solve it. */
  function impliedFcfMargin(o) {
    var a = dcf(Object.assign({}, o, { fcfMargin: 0 })), b = dcf(Object.assign({}, o, { fcfMargin: 0.1 }));
    if (!a || !b || b.value === a.value) return null;
    var m = (o.price - a.value) / ((b.value - a.value) / 0.1);
    return finite(m) ? Math.round(m * 1e6) / 1e6 : null;
  }

  /* Pure: risk-adjusted figures from a year of daily closes.
     closes: oldest first. rf: yearly cash rate (0.039 = 3.9%).
     Sharpe: yearly return above cash per unit of yearly volatility.
     Sortino: the same, with only the falls below cash counted as risk.
     VaR 95%: the daily loss exceeded on 1 day in 20 (historical, not a
     normal-curve guess); CVaR: the average loss on those days. */
  function riskStats(closes, rf) {
    var c = (closes || []).filter(function (x) { return finite(x) && x > 0; });
    if (c.length < 120) return null;
    var r = [];
    for (var i = 1; i < c.length; i++) r.push(c[i] / c[i - 1] - 1);
    var n = r.length, rfD = (finite(rf) ? rf : 0) / 252;
    var mean = r.reduce(function (s, x) { return s + x; }, 0) / n;
    var sd = Math.sqrt(r.reduce(function (s, x) { return s + (x - mean) * (x - mean); }, 0) / (n - 1));
    var down = Math.sqrt(r.reduce(function (s, x) { var d = Math.min(0, x - rfD); return s + d * d; }, 0) / n);
    var sorted = r.slice().sort(function (a, b) { return a - b; });
    var k = Math.max(1, Math.floor(n * 0.05)), tail = sorted.slice(0, k);
    var out = {
      sharpe: sd > 0 ? (mean - rfD) / sd * Math.sqrt(252) : null,
      sortino: down > 0 ? (mean - rfD) / down * Math.sqrt(252) : null,
      var95: -sorted[k - 1],
      cvar95: -tail.reduce(function (s, x) { return s + x; }, 0) / k,
      days: n,
    };
    return out;
  }

  var api = { riskStats: riskStats, dcf: dcf, dcfProblem: dcfProblem, impliedFcfMargin: impliedFcfMargin, peHistory: peHistory, project: project, impliedGrowth: impliedGrowth, weighted: weighted, cagr: cagr, defaults: defaults, history: history, validate: validate, growthIn: growthIn };
  if (typeof module === "object" && module.exports) module.exports = api;
  else { root.IL = root.IL || {}; root.IL.valuation = api; }
})(typeof window !== "undefined" ? window : globalThis);

/* ═══════════════════════════════════════════════════════════════════════════
   The Lens Report: plain-English findings computed from a company's filings,
   its grades and its price history. Pure functions, shared by the stock page,
   Compare and the dashboard, and tested in node.

   Every flag states the number behind it. No flag is raised on a figure we do
   not have: a missing quarter means fewer flags, never a guessed one.
   ═══════════════════════════════════════════════════════════════════════════ */
(function (root) {
  "use strict";

  function num(v) {
    if (v && typeof v === "object" && "raw" in v) v = v.raw;
    if (v === null || v === undefined || v === "") return null;
    var n = Number(v);
    return isFinite(n) ? n : null;
  }
  function pct(a, b) { return a !== null && b !== null && b > 0 ? (a / b - 1) * 100 : null; }
  function r1(v) { return Math.round(v * 10) / 10; }
  function money(v) {
    var a = Math.abs(v), s = v < 0 ? "−" : "";
    if (a >= 1e12) return s + "$" + (a / 1e12).toFixed(2) + "T";
    if (a >= 1e9) return s + "$" + (a / 1e9).toFixed(a >= 1e11 ? 0 : 1) + "B";
    if (a >= 1e6) return s + "$" + (a / 1e6).toFixed(0) + "M";
    return s + "$" + Math.round(a).toLocaleString("en-US");
  }
  function p0(v) { return (v < 0 ? "−" : "") + Math.abs(v).toFixed(Math.abs(v) < 10 ? 1 : 0) + "%"; }

  /* Quarters oldest → newest, only rows with an end date. */
  function quarters(hist) {
    var q = (hist && hist.quarters ? hist.quarters.slice() : []).filter(function (x) { return x && x.end; });
    q.sort(function (a, b) { return a.end < b.end ? -1 : a.end > b.end ? 1 : 0; });
    return q;
  }
  /* Sum of `key` over n quarters ending `offset` quarters before the latest. */
  function sum(q, key, n, offset) {
    offset = offset || 0;
    var end = q.length - offset, start = end - n;
    if (start < 0) return null;
    var s = 0;
    for (var i = start; i < end; i++) { var v = num(q[i][key]); if (v === null) return null; s += v; }
    return s;
  }

  /* Twelve-month figures now and a year earlier. */
  function fundamentals(hist) {
    var q = quarters(hist);
    if (q.length < 4) return null;
    var last = q[q.length - 1];
    var f = {
      quarters: q.length, latest: last,
      revenue: sum(q, "revenue", 4), revenuePrev: sum(q, "revenue", 4, 4), revenue3y: sum(q, "revenue", 4, 12),
      netIncome: sum(q, "netIncome", 4), netIncomePrev: sum(q, "netIncome", 4, 4),
      opIncome: sum(q, "operatingIncome", 4), opIncomePrev: sum(q, "operatingIncome", 4, 4),
      grossProfit: sum(q, "grossProfit", 4),
      ocf: sum(q, "operatingCashFlow", 4), fcf: sum(q, "freeCashFlow", 4),
      eps: sum(q, "eps", 4), epsPrev: sum(q, "eps", 4, 4),
      shares: num(last.shares), sharesPrev: q.length >= 5 ? num(q[q.length - 5].shares) : null,
    };
    f.growth1y = pct(f.revenue, f.revenuePrev);
    f.growth3y = f.revenue3y > 0 && f.revenue > 0 ? (Math.pow(f.revenue / f.revenue3y, 1 / 3) - 1) * 100 : null;
    f.netMargin = f.revenue > 0 && f.netIncome !== null ? f.netIncome / f.revenue * 100 : null;
    f.opMargin = f.revenue > 0 && f.opIncome !== null ? f.opIncome / f.revenue * 100 : null;
    f.opMarginPrev = f.revenuePrev > 0 && f.opIncomePrev !== null ? f.opIncomePrev / f.revenuePrev * 100 : null;
    f.grossMargin = f.revenue > 0 && f.grossProfit !== null ? f.grossProfit / f.revenue * 100 : null;
    f.fcfMargin = f.revenue > 0 && f.fcf !== null ? f.fcf / f.revenue * 100 : null;
    f.shareChange = pct(f.shares, f.sharesPrev);
    /* Quarter-on-year-ago growth for the last two quarters: is growth speeding up? */
    var yoy = function (i) { var a = q[q.length - 1 - i], b = q[q.length - 5 - i]; return a && b ? pct(num(a.revenue), num(b.revenue)) : null; };
    f.qGrowth = yoy(0); f.qGrowthPrev = yoy(1);
    f.series = q.map(function (x) { return { end: x.end, revenue: num(x.revenue), netIncome: num(x.netIncome), shares: num(x.shares) }; });
    return f;
  }

  /* Price facts from daily bars [{time, close, high, low}] oldest → newest. */
  function priceFacts(bars, meta) {
    if (!bars || bars.length < 2) return null;
    meta = meta || {};
    var last = bars[bars.length - 1];
    var price = num(meta.regularMarketPrice) || last.close;
    /* "Past year" = 52 weeks back to the close on or before (audit F04);
       the same rule as IL.yearReturn and lib/sec-fundamentals.js. */
    var from = last.time - 364 * 86400, at = 0;
    for (var yi = bars.length - 1; yi >= 0; yi--) if (bars[yi].time <= from) { at = yi; break; }
    var fullYear = bars[0].time <= from + 4 * 86400;
    var year = bars.slice(at);
    var rets = [];
    for (var i = 1; i < year.length; i++) rets.push(Math.log(year[i].close / year[i - 1].close));
    var mean = rets.reduce(function (s, x) { return s + x; }, 0) / (rets.length || 1);
    var vol = Math.sqrt(rets.reduce(function (s, x) { return s + (x - mean) * (x - mean); }, 0) / Math.max(1, rets.length - 1)) * Math.sqrt(252) * 100;
    var peak = -Infinity, dd = 0;
    year.forEach(function (b) { peak = Math.max(peak, b.close); dd = Math.min(dd, b.close / peak - 1); });
    var ma = function (n) { if (bars.length < n) return null; var s = 0; for (var j = bars.length - n; j < bars.length; j++) s += bars[j].close; return s / n; };
    var prev = bars[bars.length - 2].close;
    return {
      price: price, prev: prev, chg: price - prev, chgPct: (price / prev - 1) * 100,
      hi: Math.max.apply(null, year.map(function (b) { return b.high || b.close; })),
      lo: Math.min.apply(null, year.map(function (b) { return b.low || b.close; })),
      vol: vol, drawdown: dd * 100, fromHigh: (price / Math.max.apply(null, year.map(function (b) { return b.close; })) - 1) * 100,
      worstDay: rets.length ? (Math.exp(Math.min.apply(null, rets)) - 1) * 100 : null,
      ma50: ma(50), ma200: ma(200), yearReturn: year.length && fullYear ? (last.close / year[0].close - 1) * 100 : null,
      lastTime: last.time,
    };
  }

  /* What growth the price implies, with the default assumptions the
     Valuation tab starts from (so the two always agree until edited). */
  function valuation(f, p, pe, V) {
    V = V || (root.IL && root.IL.valuation);
    if (!f || !p || !V || !(f.revenue > 0) || !(f.shares > 0)) return null;
    /* The same inputs the Projection Lab starts from, so the overview's
       "what the price implies" and the lab agree until someone edits. */
    var eps = f.netIncome !== null && f.shares > 0 ? f.netIncome / f.shares : null;
    var ctx = {
      price: p.price, revenue: f.revenue, shares: f.shares,
      margin: f.netIncome !== null ? f.netIncome / f.revenue : null,
      pe: eps > 0 ? p.price / eps : pe, growth1y: f.growth1y !== null ? f.growth1y / 100 : null, growth3y: f.growth3y !== null ? f.growth3y / 100 : null,
      quarters: f.series || null,
    };
    var d = V.defaults(ctx);
    var implied = V.impliedGrowth({ price: ctx.price, revenue: ctx.revenue, shares: ctx.shares, years: 5, margin: d.base.margin, exitPE: d.base.exitPE, shareChange: d.shareChange, required: d.required });
    var delivered = d.history && d.history.recent !== null ? d.history.recent : ctx.growth3y !== null ? ctx.growth3y : ctx.growth1y;
    var verdict = null;
    if (implied !== null && delivered !== null) {
      var gap = (implied - delivered) * 100;
      verdict = gap > 15 ? { key: "rich", label: "Priced for perfection", tone: "bad" }
        : gap > 5 ? { key: "full", label: "Priced for more than it has done", tone: "mid" }
        : gap < -5 ? { key: "cheap", label: "Priced for less than it has done", tone: "good" }
        : { key: "fair", label: "Priced for what it has done", tone: "mid" };
    }
    return { ctx: ctx, defaults: d, implied: implied, delivered: delivered, verdict: verdict };
  }

  /* Green and red flags. Each: { tone: "good"|"bad", key, title, detail }. */
  function flags(input) {
    var f = input.fundamentals, p = input.price, g = input.grades, v = input.valuation, out = [];
    function add(tone, key, title, detail) { out.push({ tone: tone, key: key, title: title, detail: detail }); }
    if (f) {
      if (f.growth1y !== null) {
        if (f.growth1y >= 15) add("good", "growth", "Sales growing fast", "Revenue up " + p0(f.growth1y) + " over the last 12 months, to " + money(f.revenue) + ".");
        else if (f.growth1y < 0) add("bad", "shrinking", "Sales shrinking", "Revenue down " + p0(-f.growth1y) + " over the last 12 months.");
      }
      if (f.qGrowth !== null && f.qGrowthPrev !== null && f.qGrowthPrev > 0 && f.qGrowth < f.qGrowthPrev - 10)
        add("bad", "slowing", "Growth is slowing", "Last quarter grew " + p0(f.qGrowth) + " on a year ago, down from " + p0(f.qGrowthPrev) + " the quarter before.");
      else if (f.qGrowth !== null && f.qGrowthPrev !== null && f.qGrowth > f.qGrowthPrev + 10 && f.qGrowth > 0)
        add("good", "accelerating", "Growth is speeding up", "Last quarter grew " + p0(f.qGrowth) + " on a year ago, up from " + p0(f.qGrowthPrev) + ".");
      if (f.netIncome !== null && f.netIncome < 0) add("bad", "loss", "Losing money", "Net loss of " + money(-f.netIncome) + " over the last 12 months.");
      else if (f.netMargin !== null && f.netMargin >= 20) add("good", "margin", "Very profitable", "Keeps " + p0(f.netMargin) + " of every sales dollar as profit.");
      if (f.opMargin !== null && f.opMarginPrev !== null) {
        var dm = f.opMargin - f.opMarginPrev;
        if (dm >= 3) add("good", "margins-up", "Margins widening", "Operating margin " + p0(f.opMarginPrev) + " → " + p0(f.opMargin) + " over a year.");
        else if (dm <= -3) add("bad", "margins-down", "Margins shrinking", "Operating margin " + p0(f.opMarginPrev) + " → " + p0(f.opMargin) + " over a year.");
      }
      if (f.fcf !== null) {
        if (f.fcf < 0) add("bad", "burn", "Burning cash", "Free cash flow of " + money(f.fcf) + " over 12 months: it spends more than it brings in.");
        else if (f.fcfMargin !== null && f.fcfMargin >= 15) add("good", "cash", "Strong cash generation", money(f.fcf) + " of free cash flow, " + p0(f.fcfMargin) + " of sales.");
      }
      if (f.netIncome > 0 && f.ocf !== null && f.ocf < f.netIncome * 0.7)
        add("bad", "quality", "Profit not turning into cash", "Operating cash flow " + money(f.ocf) + " vs net income " + money(f.netIncome) + ".");
      if (f.shareChange !== null) {
        if (f.shareChange >= 3) add("bad", "dilution", "Share count rising", "Diluted shares up " + p0(f.shareChange) + " in a year, so each share owns less.");
        else if (f.shareChange <= -1.5) add("good", "buybacks", "Buying back shares", "Diluted shares down " + p0(-f.shareChange) + " in a year.");
      }
    }
    /* What the full report card says, so the summary never contradicts it.
       Its watch-outs always count; its strengths stand in when the
       statement checks above could not run (guests, missing filings). */
    function fromCard(item) {
      var t = String(item && (item.text || item) || "").trim(), i = t.indexOf(":");
      return i > 0 ? { title: t.slice(0, i), detail: t.slice(i + 1).trim().replace(/^./, function (c) { return c.toUpperCase(); }) } : { title: t.replace(/\.$/, ""), detail: "From the LensScore report card." };
    }
    if (g && g.watch) g.watch.slice(0, 2).forEach(function (w, i) { var c = fromCard(w); if (c.title) add("bad", "card-watch-" + i, c.title, c.detail); });
    if (!f && g && g.strengths) g.strengths.slice(0, 3).forEach(function (w, i) { var c = fromCard(w); if (c.title) add("good", "card-strength-" + i, c.title, c.detail); });
    if (g && g.factors) {
      var health = g.factors.filter(function (x) { return x.key === "health"; })[0];
      if (health && /^[DF]/.test(health.grade || "")) add("bad", "health", "Weak balance sheet", "Financial health graded " + health.grade + " against sector peers.");
      else if (health && /^A/.test(health.grade || "")) add("good", "health", "Strong balance sheet", "Financial health graded " + health.grade + " against sector peers.");
    }
    if (v && v.verdict && v.implied !== null && v.delivered !== null) {
      var detail = "The price needs about " + p0(v.implied * 100) + " yearly revenue growth; it has delivered " + p0(v.delivered * 100) + ".";
      if (v.verdict.key === "rich") add("bad", "valuation", "Priced for perfection", detail);
      else if (v.verdict.key === "cheap") add("good", "valuation", "Price asks for less than it has done", detail);
    }
    if (p) {
      if (p.ma200 && p.price < p.ma200 * 0.97 && p.ma50 && p.ma50 < p.ma200) add("bad", "downtrend", "In a downtrend", "Price is below its 200-day average and the 50-day is below the 200-day.");
      else if (p.ma200 && p.ma50 && p.price > p.ma50 && p.ma50 > p.ma200) add("good", "uptrend", "In an uptrend", "Price is above its 50-day average, which is above the 200-day.");
      if (p.fromHigh !== null && p.fromHigh <= -30) add("bad", "drawdown", "Far below its high", "Down " + p0(-p.fromHigh) + " from its 52-week high.");
      if (p.vol >= 60) add("bad", "volatile", "Very volatile", "Typical yearly swing of " + p0(p.vol) + "; expect big moves both ways.");
    }
    if (input.insiders && input.insiders.buys > 0)
      add("good", "insider-buys", "Insiders buying", input.insiders.buys + " open-market purchase" + (input.insiders.buys === 1 ? "" : "s") + " by executives or directors in the last year.");
    return out;
  }

  /* Three or four sentences that a beginner can read in ten seconds. */
  function story(input) {
    var f = input.fundamentals, g = input.grades, v = input.valuation, name = input.name || input.ticker, s = [];
    if (f && f.revenue) {
      var line = name + " brought in " + money(f.revenue) + " of revenue over the last 12 months";
      if (f.growth1y !== null) line += ", " + (f.growth1y >= 0 ? "up " : "down ") + p0(Math.abs(f.growth1y)) + " on the year before";
      if (f.netMargin !== null) line += f.netMargin >= 0 ? ", and kept " + p0(f.netMargin) + " of it as profit." : ", and lost money doing it.";
      else line += ".";
      s.push(line);
    }
    if (g && g.status === "graded") {
      s.push("Against " + (g.sectorName || "sector") + " peers it rates " + Number(g.score).toFixed(1) + " out of 10" + (g.rank ? ", #" + g.rank.position + " of " + g.rank.of : "") + ", strongest on " + best(g.factors) + " and weakest on " + worst(g.factors) + ".");
    }
    if (v && v.implied !== null) {
      var t = "At today’s price, investors are paying for about " + p0(v.implied * 100) + " yearly revenue growth over five years";
      if (v.delivered !== null) t += ", against " + p0(v.delivered * 100) + " a year delivered recently";
      s.push(t + ".");
    }
    if (g && g.watch && g.watch[0] && g.watch[0].text) s.push("Watch: " + g.watch[0].text);
    return s;
  }
  var LABEL = { value: "value", growth: "growth", profitability: "profitability", health: "financial health", momentum: "momentum" };
  var RANK = function (grade) { var m = { "A+": 13, "A": 12, "A-": 11, "B+": 10, "B": 9, "B-": 8, "C+": 7, "C": 6, "C-": 5, "D+": 4, "D": 3, "D-": 2, "F": 1 }; return m[String(grade || "").replace("−", "-")] || 0; };
  function best(fs) { var b = (fs || []).slice().sort(function (a, c) { return RANK(c.grade) - RANK(a.grade); })[0]; return b ? LABEL[b.key] || b.label : "—"; }
  function worst(fs) { var b = (fs || []).slice().sort(function (a, c) { return RANK(a.grade) - RANK(c.grade); })[0]; return b ? LABEL[b.key] || b.label : "—"; }

  /* Which checks actually ran. A check that could not run is "not
     checked", never "nothing found". */
  function coverage(input) {
    return { statements: !!input.fundamentals, prices: !!input.price, grades: !!(input.grades && input.grades.factors) };
  }

  var api = { coverage: coverage, num: num, quarters: quarters, fundamentals: fundamentals, priceFacts: priceFacts, valuation: valuation, flags: flags, story: story, gradeRank: RANK };
  if (typeof module === "object" && module.exports) module.exports = api;
  else { root.IL = root.IL || {}; root.IL.analysis = api; }
})(typeof window !== "undefined" ? window : globalThis);

/* ═══════════════════════════════════════════════════════════════════════════
   ImpliedLens — growth math

   Turns the quarterly rows from /api/fundamentals/history into chart series:
   quarterly or trailing-twelve-month values, per-share figures, margins and
   valuation multiples, plus the summary numbers and the plain-English read
   shown above each chart. Pure functions; loaded in the browser and in tests.
   ═══════════════════════════════════════════════════════════════════════════ */
(function (root, factory) {
  var api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.ILGrowthMath = api;
}(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  var GROUPS = [
    { id: "growth", label: "Growth", color: "#E3A945" },
    { id: "cash", label: "Cash", color: "#3FCB9B" },
    { id: "owners", label: "Shareholders", color: "#7FB2E5" },
    { id: "margins", label: "Margins", color: "#B48CF0" },
    { id: "value", label: "Valuation", color: "#F0A35E" }
  ];

  /* kind: money | perShare | shares | pct | multiple
     agg:  how a trailing-twelve-month value is formed */
  var METRICS = {
    revenue: { group: "growth", label: "Revenue", short: "Revenue", kind: "money", agg: "sum",
      what: "Everything customers paid the company in the period, before any costs." },
    grossProfit: { group: "growth", label: "Gross profit", short: "Gross profit", kind: "money", agg: "sum",
      what: "Revenue minus the direct cost of what was sold." },
    operatingIncome: { group: "growth", label: "Operating income", short: "Op. income", kind: "money", agg: "sum",
      what: "Profit from running the business, before interest and taxes." },
    netIncome: { group: "growth", label: "Net income", short: "Net income", kind: "money", agg: "sum",
      what: "The bottom line: profit left for shareholders after every cost, interest and tax." },
    eps: { group: "growth", label: "Earnings per share (diluted)", short: "EPS", kind: "perShare", agg: "sum",
      what: "Net income divided by the number of shares. What each share earned." },
    operatingCashFlow: { group: "cash", label: "Operating cash flow", short: "Op. cash flow", kind: "money", agg: "sum",
      what: "Cash the business actually brought in from operations." },
    freeCashFlow: { group: "cash", label: "Free cash flow", short: "Free cash flow", kind: "money", agg: "sum",
      what: "Operating cash flow minus spending on equipment and buildings. Cash the company could hand back to owners." },
    fcfPerShare: { group: "cash", label: "Free cash flow per share", short: "FCF / share", kind: "perShare", agg: "derived",
      what: "Free cash flow divided by shares. Rising FCF per share is one of the clearest signs a stock is compounding." },
    capex: { group: "cash", label: "Capital spending", short: "Capex", kind: "money", agg: "sum",
      what: "Money spent on equipment, data centres, stores and other long-lived assets." },
    shares: { group: "owners", label: "Shares outstanding (diluted)", short: "Shares", kind: "shares", agg: "last",
      what: "How many slices the company is cut into. Falling means buybacks; rising means dilution." },
    grossMargin: { group: "margins", label: "Gross margin", short: "Gross margin", kind: "pct", agg: "derived",
      what: "Gross profit as a share of revenue. Pricing power shows up here." },
    operatingMargin: { group: "margins", label: "Operating margin", short: "Op. margin", kind: "pct", agg: "derived",
      what: "Operating income as a share of revenue." },
    netMargin: { group: "margins", label: "Net margin", short: "Net margin", kind: "pct", agg: "derived",
      what: "Net income as a share of revenue: cents of profit per dollar of sales." },
    fcfMargin: { group: "margins", label: "Free cash flow margin", short: "FCF margin", kind: "pct", agg: "derived",
      what: "Free cash flow as a share of revenue." },
    pe: { group: "value", label: "P/E ratio (trailing)", short: "P/E", kind: "multiple", agg: "derived", ttmOnly: true,
      what: "Share price divided by the last twelve months of earnings per share. What you pay for each $1 of profit." },
    ps: { group: "value", label: "Price to sales (trailing)", short: "P/S", kind: "multiple", agg: "derived", ttmOnly: true,
      what: "Market value divided by the last twelve months of revenue." },
    pfcf: { group: "value", label: "Price to free cash flow", short: "P/FCF", kind: "multiple", agg: "derived", ttmOnly: true,
      what: "Market value divided by the last twelve months of free cash flow." }
  };
  var ORDER = ["revenue", "grossProfit", "operatingIncome", "netIncome", "eps",
    "operatingCashFlow", "freeCashFlow", "fcfPerShare", "capex", "shares",
    "grossMargin", "operatingMargin", "netMargin", "fcfMargin", "pe", "ps", "pfcf"];

  function num(v) { return typeof v === "number" && isFinite(v) ? v : null; }

  /* Sum of the four quarters ending at i, or null if any is missing. */
  function ttmAt(rows, i, key) {
    if (i < 3) return null;
    var s = 0;
    for (var k = i - 3; k <= i; k++) { var v = num(rows[k][key]); if (v == null) return null; s += v; }
    return s;
  }
  function ratio(a, b) { return a != null && b != null && b !== 0 ? a / b : null; }

  function valueAt(rows, i, id, period) {
    var r = rows[i], ttm = period === "ttm";
    var get = function (key) { return ttm ? ttmAt(rows, i, key) : num(r[key]); };
    switch (id) {
      case "shares": return num(r.shares);
      case "fcfPerShare": return ratio(get("freeCashFlow"), num(r.shares));
      case "grossMargin": return pct(ratio(get("grossProfit"), get("revenue")));
      case "operatingMargin": return pct(ratio(get("operatingIncome"), get("revenue")));
      case "netMargin": return pct(ratio(get("netIncome"), get("revenue")));
      case "fcfMargin": return pct(ratio(get("freeCashFlow"), get("revenue")));
      case "pe": {
        var eps = ttmAt(rows, i, "eps");
        return r.price != null && eps != null && eps > 0 ? r.price / eps : null;
      }
      case "ps": {
        var rev = ttmAt(rows, i, "revenue");
        return r.price != null && r.shares && rev > 0 ? r.price * r.shares / rev : null;
      }
      case "pfcf": {
        var f = ttmAt(rows, i, "freeCashFlow");
        return r.price != null && r.shares && f > 0 ? r.price * r.shares / f : null;
      }
      default: return get(id);
    }
  }
  function pct(v) { return v == null ? null : v * 100; }

  /* Points for a metric. `years` trims to the most recent N years (0 = all). */
  function series(rows, id, period, years) {
    var out = [];
    for (var i = 0; i < rows.length; i++) {
      var v = valueAt(rows, i, id, METRICS[id] && METRICS[id].ttmOnly ? "ttm" : period);
      out.push({ end: rows[i].end, label: rows[i].label, q: rows[i].q, year: rows[i].year, value: v,
                 derived: (rows[i].derived || []).length > 0 });
    }
    /* Drop leading quarters with no value (e.g. the first three in TTM mode). */
    while (out.length && out[0].value == null) out.shift();
    if (years > 0 && out.length > years * 4 + 1) out = out.slice(out.length - (years * 4 + 1));
    return out;
  }

  function available(rows, id, period) {
    var s = series(rows, id, period, 0);
    var n = 0;
    s.forEach(function (p) { if (p.value != null) n++; });
    return n >= 4;
  }

  function stats(points, id) {
    var vals = points.filter(function (p) { return p.value != null; });
    if (!vals.length) return null;
    var last = vals[vals.length - 1], first = vals[0];
    var yearAgo = null;
    for (var i = points.length - 1; i >= 0; i--) {
      if (points[i] === last) { yearAgo = points[i - 4] || null; break; }
    }
    var kind = METRICS[id] ? METRICS[id].kind : "money";
    var change = function (a, b) {
      if (a == null || b == null) return null;
      if (kind === "pct") return a - b;                      // percentage points
      if (b <= 0) return null;                               // growth from a loss is undefined
      return (a / b - 1) * 100;
    };
    var yrs = (points.indexOf(last) - points.indexOf(first)) / 4;
    var cagr = null;
    if (kind !== "pct" && kind !== "multiple" && yrs >= 1 && first.value > 0 && last.value > 0) {
      cagr = (Math.pow(last.value / first.value, 1 / yrs) - 1) * 100;
    }
    var hi = vals[0], lo = vals[0];
    vals.forEach(function (p) { if (p.value > hi.value) hi = p; if (p.value < lo.value) lo = p; });
    var total = kind === "pct" || kind === "multiple" ? last.value - first.value : change(last.value, first.value);
    return {
      last: last, first: first, years: yrs, yoy: change(last.value, yearAgo && yearAgo.value),
      cagr: cagr, total: total, high: hi, low: lo, avg: vals.reduce(function (s, p) { return s + p.value; }, 0) / vals.length
    };
  }

  /* ── formatting ─────────────────────────────────────────────────────────── */
  function money(v, digits) {
    if (v == null) return "—";
    var a = Math.abs(v), s = v < 0 ? "−$" : "$";
    if (a >= 1e12) return s + (a / 1e12).toFixed(digits != null ? digits : 2) + "T";
    if (a >= 1e9) return s + (a / 1e9).toFixed(digits != null ? digits : a >= 1e11 ? 0 : 1) + "B";
    if (a >= 1e6) return s + (a / 1e6).toFixed(digits != null ? digits : a >= 1e8 ? 0 : 1) + "M";
    if (a >= 1e3) return s + (a / 1e3).toFixed(0) + "K";
    return s + a.toFixed(0);
  }
  function format(v, id, opts) {
    if (v == null) return "—";
    var kind = METRICS[id] ? METRICS[id].kind : "money";
    var compact = opts && opts.compact;
    switch (kind) {
      case "perShare": return (v < 0 ? "−$" : "$") + Math.abs(v).toFixed(Math.abs(v) >= 100 ? 0 : 2);
      case "shares": {
        var a = Math.abs(v);
        return a >= 1e9 ? (v / 1e9).toFixed(2) + "B" : a >= 1e6 ? (v / 1e6).toFixed(compact ? 0 : 1) + "M" : Math.round(v).toLocaleString("en-US");
      }
      case "pct": return v.toFixed(compact ? 0 : 1).replace("-", "−") + "%";
      case "multiple": return v.toFixed(v >= 100 ? 0 : 1) + "×";
      default: return money(v, compact ? (Math.abs(v) >= 1e11 ? 0 : 1) : null);
    }
  }
  function signedPct(v, digits) {
    if (v == null) return "—";
    return (v >= 0 ? "+" : "−") + Math.abs(v).toFixed(digits == null ? (Math.abs(v) >= 100 ? 0 : 1) : digits) + "%";
  }
  function changeText(v, id) {
    if (v == null) return "—";
    if (METRICS[id] && METRICS[id].kind === "pct") return (v >= 0 ? "+" : "−") + Math.abs(v).toFixed(1) + " pts";
    return signedPct(v);
  }

  /* ── the plain-English read ─────────────────────────────────────────────── */
  function read(rows, id, period, years, name) {
    var pts = series(rows, id, period, years), st = stats(pts, id);
    if (!st) return "";
    var m = METRICS[id], who = name || "The company";
    var span = st.years >= 1 ? (Math.round(st.years) === 1 ? "the past year" : "the past " + Math.round(st.years) + " years") : "the period shown";
    var basis = m.ttmOnly ? "" : period === "ttm" ? " (trailing twelve months)" : " (latest quarter)";
    var last = format(st.last.value, id), first = format(st.first.value, id);
    if (m.kind === "pct") {
      var dir = st.total > 1 ? "widened" : st.total < -1 ? "narrowed" : "held roughly steady";
      return who + "'s " + m.label.toLowerCase() + " " + dir + " over " + span + ", from " + first + " to " + last + basis + ".";
    }
    if (m.kind === "multiple") {
      var avg = format(st.avg, id);
      var cheap = st.last.value < st.avg * 0.85 ? " That is below its average of " + avg + " over this stretch, so the market is paying less for each dollar than it usually has."
        : st.last.value > st.avg * 1.15 ? " That is above its average of " + avg + " over this stretch, so the market is paying more than it usually has."
        : " That is close to its average of " + avg + " over this stretch.";
      return who + " trades at " + last + " " + m.short + " today, versus " + first + " at the start of " + span + "." + cheap;
    }
    if (id === "shares") {
      var chg = st.total;
      if (chg == null) return "";
      if (chg < -2) return who + " has bought back stock: the share count fell " + Math.abs(chg).toFixed(1) + "% over " + span + ", so each remaining share owns more of the company.";
      if (chg > 2) return "The share count rose " + chg.toFixed(1) + "% over " + span + " (dilution), so each share owns a little less of the company.";
      return "The share count barely moved over " + span + " (" + signedPct(chg) + ").";
    }
    if (st.first.value <= 0 || st.last.value <= 0) {
      if (st.last.value > 0 && st.first.value <= 0) return who + " turned " + m.label.toLowerCase() + " positive over " + span + ": from " + first + " to " + last + basis + ".";
      if (st.last.value <= 0 && st.first.value > 0) return who + "'s " + m.label.toLowerCase() + " went from " + first + " to " + last + basis + " over " + span + ".";
      return who + "'s " + m.label.toLowerCase() + " has been negative through " + span + " (" + last + basis + ").";
    }
    var times = st.last.value / st.first.value;
    var mult = times >= 1.9 ? " — " + (times >= 10 ? Math.round(times) : times.toFixed(1)) + "× in " + span : "";
    var line = m.label + " went from " + first + " to " + last + basis + mult + (st.cagr != null ? ", about " + signedPct(st.cagr) + " a year" : "") + ".";
    if (id === "netIncome" || id === "eps" || id === "netMargin") {
      var li = rows.length - 1;
      var ni = valueAt(rows, li, "netIncome", period), oi = valueAt(rows, li, "operatingIncome", period);
      if (ni != null && oi != null && oi > 0 && ni > oi * 1.3) {
        line += " Net income is well above operating income, so much of it came from outside the core business (investment gains or one-off items). Operating income is the cleaner trend here.";
      }
    }
    if (id === "fcfPerShare" || id === "eps") {
      var price = priceChange(rows, pts);
      if (price != null && st.cagr != null) {
        line += price < st.total * 0.6
          ? " The share price rose less than that (" + signedPct(price) + "), so the stock got cheaper relative to what it produces."
          : price > st.total * 1.4
            ? " The share price rose faster (" + signedPct(price) + "), so investors now pay more for each dollar it produces."
            : " The share price moved roughly in step (" + signedPct(price) + ").";
      }
    }
    return line;
  }
  function priceChange(rows, pts) {
    if (!pts.length) return null;
    var a = null, b = null;
    rows.forEach(function (r) { if (r.end === pts[0].end) a = r.price; if (r.end === pts[pts.length - 1].end) b = r.price; });
    return a > 0 && b > 0 ? (b / a - 1) * 100 : null;
  }

  return {
    GROUPS: GROUPS, METRICS: METRICS, ORDER: ORDER,
    series: series, stats: stats, available: available, read: read,
    format: format, signedPct: signedPct, changeText: changeText, ttmAt: ttmAt
  };
}));

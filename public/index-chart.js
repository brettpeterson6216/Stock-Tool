/* ═══════════════════════════════════════════════════════════════════════════
   Overlaid index comparison, drawn with Lens Charts (public/lens-charts.js).

   It ran on TradingView's Lightweight Charts, which put TradingView's logo on
   the first chart a member sees. It is ImpliedLens's own line chart now: the
   same SVG kit as the Financials and valuation charts, with the value and
   name of each index written at the end of its line instead of in a legend.

   Each series is shown as percent change from its first point in the window,
   which is the only way three indexes on very different price levels (the
   Dow near 41,000, the S&P near 5,800) can share one axis.

   Public shape is unchanged - window.ilRenderIndexChart(host, indexes) - so
   home-member.js and the timeframe control did not have to move.
   ═══════════════════════════════════════════════════════════════════════════ */
(function () {
  "use strict";

  var SLOTS = ["--ilx-a", "--ilx-b", "--ilx-c"];

  /* A close of zero is not a price, it is a bar that has not printed. Yahoo
     sends null for those and Number(null) is 0, which is finite - so they have
     to be rejected explicitly or they plot as a -100% cliff. Timestamps are
     forced ascending and unique so a repeated bar cannot fold the line back. */
  function toPoints(s) {
    var out = [], lastAt = -Infinity, base = null;
    for (var i = 0; i < s.closes.length; i += 1) {
      var c = Number(s.closes[i]);
      var at = Number(s.stamps[i]);
      if (!Number.isFinite(c) || c <= 0) continue;
      if (!Number.isFinite(at) || at <= 0 || at <= lastAt) continue;
      lastAt = at;
      if (base == null) base = c;
      out.push([at * 1000, (c / base - 1) * 100]);
    }
    return out;
  }

  window.ilRenderIndexChart = function (host, indexes) {
    if (!host) return null;

    // One chart per host: tearing the old one down is what stops a timeframe
    // click from stacking a second chart on top of the first.
    if (host.ilxChart) {
      try { host.ilxChart.remove(); } catch (e) {}
      host.ilxChart = null;
    }
    host.innerHTML = "";

    var usable = (indexes || []).filter(function (s) {
      return s && Array.isArray(s.closes) && Array.isArray(s.stamps) &&
        s.closes.length > 1 && s.closes.length === s.stamps.length;
    });
    if (!usable.length) return fail(host, "Index history is unavailable right now.");
    if (!window.LensCharts) return fail(host, "The chart did not load.");

    var series = usable.map(function (s, i) {
      return { name: s.name || s.symbol, color: "var(" + SLOTS[i % SLOTS.length] + ")", points: toPoints(s), emphasis: i === 0 };
    }).filter(function (s) { return s.points.length > 1; });
    if (!series.length) return fail(host, "Index history is unavailable right now.");

    var plot = document.createElement("div");
    plot.className = "ilx-plot";
    host.appendChild(plot);

    /* Bars less than a day apart are intraday: space them by position so the
       hours the market is shut take no width. */
    var first = series[0].points, gaps = [];
    for (var g = 1; g < first.length; g++) gaps.push(first[g][0] - first[g - 1][0]);
    gaps.sort(function (a, b) { return a - b; });
    var intraday = gaps.length && gaps[gaps.length >> 1] < 20 * 3600 * 1000;

    var api = window.LensCharts.lines(plot, {
      series: series, zero: true, ordinal: intraday,
      height: Math.max(200, plot.clientHeight || 360),
      format: function (v) { return (v > 0 ? "+" : "") + v.toFixed(2) + "%"; },
      axisFormat: function (v) { return (v > 0 ? "+" : "") + (Math.abs(v) >= 1 || v === 0 ? v.toFixed(0) : v.toFixed(1)) + "%"; },
      label: "Percent change of " + series.map(function (s) { return s.name; }).join(", ") + " over the selected window"
    });

    host.ilxChart = { remove: function () { if (api) api.destroy(); } };
    return { chart: api, series: series };
  };

  function fail(host, message) {
    var msg = document.createElement("p");
    msg.className = "ilx-empty";
    msg.textContent = message;
    host.appendChild(msg);
    return null;
  }
}());

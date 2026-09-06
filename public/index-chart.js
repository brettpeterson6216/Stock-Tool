/* ═══════════════════════════════════════════════════════════════════════════
   Overlaid index comparison, drawn with TradingView Lightweight Charts.

   This was a hand-rolled SVG renderer until it turned out the library was
   already vendored and already driving the Analysis page - which meant the
   dashboard was paying for a second, worse chart engine that shipped no
   additional bytes' worth of benefit. It renders through the same engine as
   the rest of the site now, so the two pages look like one product and this
   file is a thin adapter rather than a plotting library.

   Two things the library does better than the code it replaced:

     · Percentage price-scale mode normalises every series against the left
       edge of the *visible* range and re-normalises as you pan, so a
       comparison stays a comparison at any zoom. The old code normalised
       once, against the first point in the payload, and a zoomed view then
       measured from a moment off screen.
     · The time scale is session-aware, so closed hours take no width without
       anyone having to build an ordinal axis by hand.

   What it still is not: candlesticks, indicators or drawing tools. Those live
   on the Analysis page, where they belong.

   Public shape is unchanged - window.ilRenderIndexChart(host, indexes) - so
   home-member.js and the timeframe control did not have to move.
   ═══════════════════════════════════════════════════════════════════════════ */
(function () {
  "use strict";

  var SLOTS = ["--ilx-a", "--ilx-b", "--ilx-c"];

  function fmtPct(v) {
    if (!Number.isFinite(v)) return "—";
    return (v > 0 ? "+" : "") + v.toFixed(2) + "%";
  }

  function token(host, name, fallback) {
    var v = getComputedStyle(host).getPropertyValue(name);
    v = v && v.trim();
    return v || fallback;
  }

  /* A close of zero is not a price, it is a bar that has not printed. Yahoo
     sends null for those and Number(null) is 0, which is finite - so they have
     to be rejected explicitly or they plot as a -100% cliff. Lightweight
     Charts also requires strictly ascending, unique timestamps per series and
     drops the whole series if it gets anything else. */
  function toPoints(s) {
    var out = [], lastAt = -Infinity;
    for (var i = 0; i < s.closes.length; i += 1) {
      var c = Number(s.closes[i]);
      var at = Number(s.stamps[i]);
      if (!Number.isFinite(c) || c <= 0) continue;
      if (!Number.isFinite(at) || at <= lastAt) continue;
      lastAt = at;
      out.push({ time: at, value: c });
    }
    return out;
  }

  window.ilRenderIndexChart = function (host, indexes) {
    if (!host) return null;

    // One chart per host: tearing the old one down is what stops a timeframe
    // click from stacking a second canvas on top of the first.
    if (host.ilxChart) {
      try { host.ilxChart.remove(); } catch (e) {}
      host.ilxChart = null;
    }
    host.innerHTML = "";

    var LWC = window.LightweightCharts;
    var usable = (indexes || []).filter(function (s) {
      return s && Array.isArray(s.closes) && Array.isArray(s.stamps) &&
        s.closes.length > 1 && s.closes.length === s.stamps.length;
    });

    if (!usable.length) {
      return fail(host, "Index history is unavailable right now.");
    }
    if (!LWC || !LWC.createChart) {
      // The vendor file is the only thing that draws this now, so say so
      // rather than leaving an empty box that reads as a loading state.
      return fail(host, "The charting library did not load.");
    }

    var series = usable.map(function (s, i) {
      return {
        symbol: s.symbol,
        name: s.name || s.symbol,
        colour: token(host, SLOTS[i % SLOTS.length], "#3987e5"),
        points: toPoints(s),
        on: true
      };
    }).filter(function (s) { return s.points.length > 1; });

    if (!series.length) return fail(host, "Index history is unavailable right now.");

    var plot = document.createElement("div");
    plot.className = "ilx-plot";
    host.appendChild(plot);

    var grid = token(host, "--lp-border", "rgba(176,160,126,.16)");
    var text = token(host, "--lp-muted", "#929c9c");

    var chart = LWC.createChart(plot, {
      autoSize: true,
      layout: {
        background: { type: "solid", color: "transparent" },
        textColor: text,
        fontFamily: '"JetBrains Mono", ui-monospace, monospace',
        fontSize: 11,
        attributionLogo: true
      },
      grid: { vertLines: { color: grid }, horzLines: { color: grid } },
      rightPriceScale: {
        borderVisible: false,
        scaleMargins: { top: 0.12, bottom: 0.12 },
        /* Percentage mode is the whole reason three indexes can share an axis:
           the Dow near 41,000 and the S&P near 5,800 have no common scale in
           absolute terms, and two of the three lines would sit flat against an
           edge. The library measures each series from the left edge of the
           visible range, so the comparison survives panning. */
        mode: LWC.PriceScaleMode.Percentage
      },
      timeScale: { borderVisible: false, rightOffset: 2, fixLeftEdge: true, fixRightEdge: true },
      crosshair: { mode: LWC.CrosshairMode.Normal },
      /* Drag to pan and pinch to zoom, but the wheel is left to the page.
         A dashboard chart that swallows scroll traps the reader halfway down
         the page, which is a worse failure than not having wheel zoom. */
      handleScroll: { mouseWheel: false, pressedMouseMove: true, horzTouchDrag: true, vertTouchDrag: false },
      handleScale: { mouseWheel: false, pinch: true, axisPressedMouseMove: true, axisDoubleClickReset: true }
    });

    series.forEach(function (s) {
      s.line = chart.addSeries(LWC.LineSeries, {
        color: s.colour,
        lineWidth: 2,
        priceLineVisible: false,
        lastValueVisible: false,
        crosshairMarkerVisible: true,
        crosshairMarkerRadius: 4
      });
      s.line.setData(s.points);
    });
    chart.timeScale().fitContent();

    // Legend doubles as the crosshair readout: the pointer never has to land
    // on a line to get its value, and every series answers at once.
    var legend = document.createElement("div");
    legend.className = "ilx-legend";
    series.forEach(function (s) {
      var b = document.createElement("button");
      b.type = "button";
      b.className = "ilx-key is-on";
      b.setAttribute("aria-pressed", "true");
      b.innerHTML = '<span class="ilx-swatch"></span>' +
        '<span class="ilx-key-name"></span><span class="ilx-key-val"></span>';
      b.querySelector(".ilx-swatch").style.background = s.colour;
      b.querySelector(".ilx-key-name").textContent = s.name;
      b.addEventListener("click", function () {
        s.on = !s.on;
        b.classList.toggle("is-on", s.on);
        b.setAttribute("aria-pressed", String(s.on));
        s.line.applyOptions({ visible: s.on });
      });
      s.key = b;
      legend.appendChild(b);
    });
    host.appendChild(legend);

    // Percent change against the first point of the series, which is what the
    // axis is showing; the crosshair then reports the same measure it does.
    function pctAt(s, value) {
      var base = s.points[0] && s.points[0].value;
      if (!(base > 0) || !Number.isFinite(value)) return NaN;
      return ((value - base) / base) * 100;
    }

    function showLatest() {
      series.forEach(function (s) {
        var last = s.points[s.points.length - 1];
        s.key.querySelector(".ilx-key-val").textContent =
          s.on && last ? fmtPct(pctAt(s, last.value)) : "—";
      });
    }

    chart.subscribeCrosshairMove(function (param) {
      if (!param || !param.time || !param.seriesData) return showLatest();
      series.forEach(function (s) {
        var d = param.seriesData.get(s.line);
        var v = d && (d.value != null ? d.value : d.close);
        s.key.querySelector(".ilx-key-val").textContent =
          s.on && v != null ? fmtPct(pctAt(s, v)) : "—";
      });
    });

    showLatest();
    host.ilxChart = chart;
    return { chart: chart, series: series };
  };

  function fail(host, message) {
    var msg = document.createElement("p");
    msg.className = "ilx-empty";
    msg.textContent = message;
    host.appendChild(msg);
    return null;
  }
}());

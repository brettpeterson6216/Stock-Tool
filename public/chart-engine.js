/* ═══════════════════════════════════════════════════════════════════════════
   Implied Lens — price chart engine

   Replaces the Chart.js price chart with TradingView Lightweight Charts while
   keeping every existing entry point intact. app-legacy.js still calls
   buildPriceChart(result, closes, timestamps); this module takes that call over
   and renders panes, indicators, and a scrub readout instead.

   Deliberate compatibility guarantees:
     · #price-chart stays a real <canvas> and keeps receiving a mirrored frame,
       so workspace-system.js's toDataURL report export still produces an image.
     · S.charts['price-chart'] keeps a shim exposing destroy/zoom/resetZoom so
       existing callers do not throw.
     · setChartType / toggleInd / changeRange keep their current signatures and
       state; this module only re-renders from S.
   ═══════════════════════════════════════════════════════════════════════════ */
(function () {
  "use strict";

  var LWC = window.LightweightCharts;
  if (!LWC || !LWC.createChart) return;                 // vendor missing → keep Chart.js

  /* ── indicator math (self-contained; no load-order dependency) ─────────── */
  var TA = {
    sma: function (v, p) {
      var out = new Array(v.length).fill(null), sum = 0;
      for (var i = 0; i < v.length; i++) {
        sum += v[i];
        if (i >= p) sum -= v[i - p];
        if (i >= p - 1) out[i] = sum / p;
      }
      return out;
    },
    ema: function (v, p) {
      var out = new Array(v.length).fill(null), k = 2 / (p + 1), prev = null;
      for (var i = 0; i < v.length; i++) {
        if (i === p - 1) {
          var s = 0; for (var j = 0; j < p; j++) s += v[j];
          prev = s / p; out[i] = prev;
        } else if (i >= p) { prev = v[i] * k + prev * (1 - k); out[i] = prev; }
      }
      return out;
    },
    bollinger: function (v, p, mult) {
      p = p || 20; mult = mult || 2;
      var mid = TA.sma(v, p), up = [], lo = [];
      for (var i = 0; i < v.length; i++) {
        if (mid[i] == null) { up.push(null); lo.push(null); continue; }
        var s = 0;
        for (var j = i - p + 1; j <= i; j++) s += Math.pow(v[j] - mid[i], 2);
        var sd = Math.sqrt(s / p);
        up.push(mid[i] + mult * sd); lo.push(mid[i] - mult * sd);
      }
      return { mid: mid, upper: up, lower: lo };
    },
    rsi: function (v, p) {
      p = p || 14;
      var out = new Array(v.length).fill(null), g = 0, l = 0, i;
      for (i = 1; i <= p && i < v.length; i++) {
        var d = v[i] - v[i - 1];
        if (d >= 0) g += d; else l -= d;
      }
      g /= p; l /= p;
      if (v.length > p) out[p] = l === 0 ? 100 : 100 - 100 / (1 + g / l);
      for (i = p + 1; i < v.length; i++) {
        var ch = v[i] - v[i - 1];
        g = (g * (p - 1) + (ch > 0 ? ch : 0)) / p;
        l = (l * (p - 1) + (ch < 0 ? -ch : 0)) / p;
        out[i] = l === 0 ? 100 : 100 - 100 / (1 + g / l);
      }
      return out;
    },
    macd: function (v, f, s, sig) {
      f = f || 12; s = s || 26; sig = sig || 9;
      var ef = TA.ema(v, f), es = TA.ema(v, s);
      var line = v.map(function (_, i) {
        return ef[i] == null || es[i] == null ? null : ef[i] - es[i];
      });
      var compact = line.filter(function (x) { return x != null; });
      var sigC = TA.ema(compact, sig);
      var signal = new Array(line.length).fill(null), k = 0;
      for (var i = 0; i < line.length; i++) if (line[i] != null) signal[i] = sigC[k++];
      var hist = line.map(function (x, i) {
        return x == null || signal[i] == null ? null : x - signal[i];
      });
      return { line: line, signal: signal, hist: hist };
    },
    vwap: function (h, l, c, vol) {
      var out = [], pv = 0, cv = 0;
      for (var i = 0; i < c.length; i++) {
        var tp = ((h[i] != null ? h[i] : c[i]) + (l[i] != null ? l[i] : c[i]) + c[i]) / 3;
        var vv = vol[i] || 0;
        pv += tp * vv; cv += vv;
        out.push(cv ? pv / cv : null);
      }
      return out;
    }
  };
  window.ILTA = TA;

  /* ── theme ─────────────────────────────────────────────────────────────── */
  function isDark() { return document.documentElement.getAttribute("data-theme") === "dark"; }

  function palette() {
    var d = isDark();
    return {
      text: d ? "#9A968D" : "#6B6F78",
      textStrong: d ? "#F2F0EB" : "#14161A",
      grid: d ? "rgba(255,255,255,.045)" : "rgba(24,22,18,.06)",
      border: d ? "rgba(255,255,255,.08)" : "rgba(24,22,18,.10)",
      crosshair: d ? "rgba(214,172,100,.55)" : "rgba(150,109,43,.5)",
      up: d ? "#2FD98C" : "#0B7A4C",
      down: d ? "#F05C6A" : "#BE3A4B",
      upFill: d ? "rgba(47,217,140,.5)" : "rgba(11,122,76,.45)",
      downFill: d ? "rgba(240,92,106,.5)" : "rgba(190,58,75,.45)",
      gold: d ? "#D6AC64" : "#966D2B",
      ma50: d ? "#7FB2E5" : "#2F6FA8",
      ma200: d ? "#C79BE8" : "#6D46A0",
      ema: d ? "#EDCB84" : "#B8892F",
      vwap: d ? "#7ED9C8" : "#127C6C",
      band: d ? "rgba(214,172,100,.42)" : "rgba(150,109,43,.4)",
      volUp: d ? "rgba(47,217,140,.34)" : "rgba(11,122,76,.3)",
      volDown: d ? "rgba(240,92,106,.34)" : "rgba(190,58,75,.28)"
    };
  }

  /* ── state ─────────────────────────────────────────────────────────────── */
  var view = {
    scale: "normal",       // normal | log | percent
    volume: true,
    osc: "rsi",            // rsi | macd | none
    ema21: false,
    vwap: false,
    pins: { earnings: false, news: false }
  };
  try {
    var saved = JSON.parse(localStorage.getItem("il-chart-view") || "{}");
    Object.keys(saved).forEach(function (k) { if (k in view) view[k] = saved[k]; });
  } catch (e) {}
  function persist() {
    try { localStorage.setItem("il-chart-view", JSON.stringify(view)); } catch (e) {}
  }
  window.ILChartView = view;

  var inst = null;          // active main-chart instance
  var lastFrame = null;     // { rows, meta } for readout + re-render

  /* ── helpers ───────────────────────────────────────────────────────────── */
  function fmtPrice(v) {
    if (v == null || !isFinite(v)) return "—";
    var a = Math.abs(v);
    return "$" + v.toFixed(a >= 1000 ? 0 : a >= 1 ? 2 : 4);
  }
  function fmtVol(v) {
    if (!v) return "—";
    if (v >= 1e9) return (v / 1e9).toFixed(2) + "B";
    if (v >= 1e6) return (v / 1e6).toFixed(1) + "M";
    if (v >= 1e3) return (v / 1e3).toFixed(0) + "K";
    return String(v);
  }
  function intraday() { return window.S && (S.range === "1d" || S.range === "5d"); }

  /* ── build ─────────────────────────────────────────────────────────────── */
  function buildInstance(host, rows, opts) {
    opts = opts || {};
    var p = palette();
    var type = (window.S && S.chartType) || "candle";
    /* Candles need physical room or the bodies collapse into a smear. Lines can
       run much tighter. These two numbers are what stop "squished candles". */
    var seed = type === "candle" ? 8 : 4;
    var floorSpacing = type === "candle" ? 3.5 : 1;
    var chart = LWC.createChart(host, {
      layout: {
        background: { type: "solid", color: "transparent" },
        textColor: p.text,
        fontFamily: '"DM Mono", ui-monospace, monospace',
        fontSize: 10,
        panes: { separatorColor: p.border, separatorHoverColor: p.crosshair, enableResize: true }
      },
      grid: { vertLines: { color: p.grid }, horzLines: { color: p.grid } },
      rightPriceScale: {
        borderColor: p.border,
        scaleMargins: { top: 0.12, bottom: 0.12 },
        mode: view.scale === "log" ? 1 : view.scale === "percent" ? 2 : 0
      },
      timeScale: {
        borderColor: p.border,
        timeVisible: intraday(),
        secondsVisible: false,
        rightOffset: 6,
        barSpacing: seed,
        minBarSpacing: floorSpacing,
        shiftVisibleRangeOnNewBar: true,
        lockVisibleTimeRangeOnResize: true
      },
      crosshair: {
        mode: opts.magnet === false ? 0 : 1,
        vertLine: { color: p.crosshair, width: 1, style: 2, labelBackgroundColor: p.gold },
        horzLine: { color: p.crosshair, width: 1, style: 2, labelBackgroundColor: p.gold }
      },
      handleScroll: true,
      handleScale: true,
      autoSize: true
    });

    var series = {};

    /* price series */
    if (type === "candle") {
      series.price = chart.addSeries(LWC.CandlestickSeries, {
        upColor: p.up, downColor: p.down,
        borderUpColor: p.up, borderDownColor: p.down,
        wickUpColor: p.up, wickDownColor: p.down,
        priceLineVisible: true, priceLineColor: p.gold, priceLineStyle: 2, priceLineWidth: 1
      }, 0);
      series.price.setData(rows.map(function (r) {
        return { time: r.time, open: r.open, high: r.high, low: r.low, close: r.close };
      }));
    } else {
      /* Robinhood reading: the line is green or red against where the visible
         period opened, not against the previous bar. */
      var base = rows.length ? rows[0].close : 0;
      var last = rows.length ? rows[rows.length - 1].close : 0;
      var rising = last >= base;
      var stroke = rising ? p.up : p.down;

      if (type === "area") {
        series.price = chart.addSeries(LWC.AreaSeries, {
          lineColor: stroke, lineWidth: 2,
          topColor: rising ? p.upFill : p.downFill,
          bottomColor: "rgba(0,0,0,0)",
          priceLineVisible: true, priceLineColor: stroke, priceLineStyle: 2, priceLineWidth: 1,
          crosshairMarkerRadius: 4, crosshairMarkerBorderWidth: 2,
          crosshairMarkerBorderColor: isDark() ? "#0B0D11" : "#FFFFFF",
          crosshairMarkerBackgroundColor: stroke
        }, 0);
      } else {
        series.price = chart.addSeries(LWC.LineSeries, {
          color: stroke, lineWidth: 2,
          priceLineVisible: true, priceLineColor: stroke, priceLineStyle: 2, priceLineWidth: 1,
          crosshairMarkerRadius: 4, crosshairMarkerBorderWidth: 2,
          crosshairMarkerBorderColor: isDark() ? "#0B0D11" : "#FFFFFF",
          crosshairMarkerBackgroundColor: stroke
        }, 0);
      }
      series.price.setData(rows.map(function (r) { return { time: r.time, value: r.close }; }));
    }

    var closes = rows.map(function (r) { return r.close; });
    var line = function (color, width, style) {
      return chart.addSeries(LWC.LineSeries, {
        color: color, lineWidth: width || 1, lineStyle: style || 0,
        priceLineVisible: false, lastValueVisible: false, crosshairMarkerVisible: false
      }, 0);
    };
    var pair = function (vals) {
      return rows.map(function (r, i) {
        return vals[i] == null ? null : { time: r.time, value: vals[i] };
      }).filter(Boolean);
    };

    var S_ = window.S || { inds: {} };
    if (S_.inds && S_.inds.ma50) { series.ma50 = line(p.ma50, 1.5); series.ma50.setData(pair(TA.sma(closes, 50))); }
    if (S_.inds && S_.inds.ma200) { series.ma200 = line(p.ma200, 1.5); series.ma200.setData(pair(TA.sma(closes, 200))); }
    if (view.ema21) { series.ema21 = line(p.ema, 1.5); series.ema21.setData(pair(TA.ema(closes, 21))); }
    if (view.vwap) {
      series.vwap = line(p.vwap, 1.5, 2);
      series.vwap.setData(pair(TA.vwap(
        rows.map(function (r) { return r.high; }),
        rows.map(function (r) { return r.low; }),
        closes,
        rows.map(function (r) { return r.volume; })
      )));
    }
    if (S_.inds && S_.inds.bb) {
      var bb = TA.bollinger(closes, 20, 2);
      series.bbU = line(p.band, 1, 2); series.bbU.setData(pair(bb.upper));
      series.bbL = line(p.band, 1, 2); series.bbL.setData(pair(bb.lower));
      series.bbM = line(p.band, 1, 3); series.bbM.setData(pair(bb.mid));
    }

    /* analyst target lines, carried over from the previous chart */
    if (S_.analystTarget && S_.analystTarget.mean && rows.length) {
      series.price.createPriceLine({
        price: S_.analystTarget.mean, color: p.gold, lineWidth: 1, lineStyle: 2,
        axisLabelVisible: true, title: "Analyst target"
      });
    }

    var paneIdx = 1;

    /* volume pane */
    if (view.volume && !opts.compact) {
      series.volume = chart.addSeries(LWC.HistogramSeries, {
        priceFormat: { type: "volume" }, priceLineVisible: false, lastValueVisible: false
      }, paneIdx);
      series.volume.setData(rows.map(function (r, i) {
        var up = i === 0 ? r.close >= r.open : r.close >= rows[i - 1].close;
        return { time: r.time, value: r.volume || 0, color: up ? p.volUp : p.volDown };
      }));
      paneIdx++;
    }

    /* oscillator pane */
    if (view.osc === "rsi" && !opts.compact) {
      series.rsi = chart.addSeries(LWC.LineSeries, {
        color: p.gold, lineWidth: 1.5, priceLineVisible: false,
        priceFormat: { type: "price", precision: 1, minMove: 0.1 }
      }, paneIdx);
      series.rsi.setData(pair(TA.rsi(closes, 14)));
      [70, 30].forEach(function (lvl) {
        series.rsi.createPriceLine({
          price: lvl, color: lvl === 70 ? p.down : p.up,
          lineWidth: 1, lineStyle: 2, axisLabelVisible: true, title: String(lvl)
        });
      });
      paneIdx++;
    } else if (view.osc === "macd" && !opts.compact) {
      var m = TA.macd(closes);
      series.macdHist = chart.addSeries(LWC.HistogramSeries, { priceLineVisible: false }, paneIdx);
      series.macdHist.setData(rows.map(function (r, i) {
        return m.hist[i] == null ? null : {
          time: r.time, value: m.hist[i], color: m.hist[i] >= 0 ? p.volUp : p.volDown
        };
      }).filter(Boolean));
      series.macdLine = chart.addSeries(LWC.LineSeries, {
        color: p.gold, lineWidth: 1.5, priceLineVisible: false, lastValueVisible: false
      }, paneIdx);
      series.macdLine.setData(pair(m.line));
      series.macdSignal = chart.addSeries(LWC.LineSeries, {
        color: p.ma50, lineWidth: 1.5, priceLineVisible: false, lastValueVisible: false
      }, paneIdx);
      series.macdSignal.setData(pair(m.signal));
      paneIdx++;
    }

    /* Pane proportions: price dominates. Height must be measured after layout,
       not during construction, or a 0-height host collapses the sub-panes. */
    function sizePanes() {
      try {
        var panes = chart.panes();
        if (panes.length < 2) return;
        var h = host.clientHeight;
        if (!h) return;
        var axis = 26;                        // time axis lives inside the last pane
        var usable = h - axis;
        var extra = panes.length - 1;
        /* 44px was not enough for an oscillator: the 30/50/70 axis labels
           collided with each other and with the pane separator. */
        var small = Math.max(58, Math.min(104, Math.round(usable * 0.18)));
        for (var i = 1; i < panes.length; i++) panes[i].setHeight(small);
        panes[0].setHeight(Math.max(140, usable - small * extra));
      } catch (e) {}
    }
    requestAnimationFrame(function () { requestAnimationFrame(sizePanes); });

    if (typeof ResizeObserver === "function") {
      var ro = new ResizeObserver(function () { sizePanes(); });
      ro.observe(host);
      chart._ilResizeObserver = ro;
    }

    /* fitContent() crushes every bar in the series into the viewport, which is
       exactly the "candles get squished" complaint: a 5y daily series is 1250
       bars in 900px, i.e. 0.7px per candle. Instead pick a bar count that keeps
       each candle legible at the current width and show the most recent slice
       of the series. Panning left still reaches the whole history. */
    function applyInitialView() {
      var width = host.clientWidth || 900;
      var target = type === "candle" ? 9 : 4.5;   // px per bar we want to see
      var gutter = 64;                            // price axis + right offset
      var visible = Math.max(24, Math.min(rows.length, Math.floor((width - gutter) / target)));
      var ts = chart.timeScale();
      try {
        ts.applyOptions({ barSpacing: Math.max(floorSpacing, (width - gutter) / visible) });
        ts.setVisibleLogicalRange({ from: rows.length - visible, to: rows.length + 3 });
      } catch (e) { try { ts.fitContent(); } catch (e2) {} }
    }
    /* Run once now (so the first paint is right) and once after layout settles
       (so autoSize has the real width). The second pass must stand down if the
       caller has meanwhile restored a saved viewport, or flipping candle→line
       would silently throw the user's zoom away. */
    requestAnimationFrame(function () {
      requestAnimationFrame(function () { if (!chart._ilViewLocked) applyInitialView(); });
    });
    applyInitialView();

    return {
      chart: chart, series: series, rows: rows, host: host,
      sizePanes: sizePanes, applyInitialView: applyInitialView,
      barType: type, floorSpacing: floorSpacing
    };
  }

  /* ── scrub readout ─────────────────────────────────────────────────────── */
  function buildReadout(wrap) {
    var scope = wrap.parentElement || wrap;
    var el = scope.querySelector(".il-chart-readout");
    if (el) return el;
    el = document.createElement("div");
    el.className = "il-chart-readout";
    el.innerHTML =
      '<div class="ilr-main"><span class="ilr-price">—</span><span class="ilr-chg">—</span></div>' +
      '<div class="ilr-ohlc">' +
      '<span><i>O</i><b data-k="o">—</b></span><span><i>H</i><b data-k="h">—</b></span>' +
      '<span><i>L</i><b data-k="l">—</b></span><span><i>C</i><b data-k="c">—</b></span>' +
      '<span><i>Vol</i><b data-k="v">—</b></span></div>' +
      '<div class="ilr-date">—</div>';
    /* Sit ABOVE the plot, not on top of it. As a floating overlay this box
       covered the top-left of every chart — which is exactly where the last
       few months of a rising series live. */
    /* Sit ABOVE the plot, not on top of it. As a floating overlay this box
       covered the top-left of every chart — which is exactly where the last
       few months of a rising series live. `wrap` is the fixed-height plot
       slot, so the strip goes in its parent, immediately before it. */
    var parent = wrap.parentElement;
    if (parent) parent.insertBefore(el, wrap); else wrap.appendChild(el);
    return el;
  }

  function wireReadout(instance, wrap) {
    var el = buildReadout(wrap);
    var rows = instance.rows;
    var byTime = {};
    rows.forEach(function (r) { byTime[r.time] = r; });
    var base = rows.length ? rows[0].close : 0;

    function paint(r, isLive) {
      if (!r) return;
      var chg = r.close - base;
      var pct = base ? (chg / base) * 100 : 0;
      var pos = chg >= 0;
      el.querySelector(".ilr-price").textContent = fmtPrice(r.close);
      var c = el.querySelector(".ilr-chg");
      c.textContent = (pos ? "▲ " : "▼ ") + fmtPrice(Math.abs(chg)).replace("$", "$") +
        "  (" + (pos ? "+" : "−") + Math.abs(pct).toFixed(2) + "%)";
      c.className = "ilr-chg " + (pos ? "pos" : "neg");
      el.querySelector('[data-k="o"]').textContent = fmtPrice(r.open);
      el.querySelector('[data-k="h"]').textContent = fmtPrice(r.high);
      el.querySelector('[data-k="l"]').textContent = fmtPrice(r.low);
      el.querySelector('[data-k="c"]').textContent = fmtPrice(r.close);
      el.querySelector('[data-k="v"]').textContent = fmtVol(r.volume);
      var d = new Date(r.time * 1000);
      el.querySelector(".ilr-date").textContent = intraday()
        ? d.toLocaleString("en-US", { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" })
        : d.toLocaleDateString("en-US", { weekday: "short", month: "short", day: "numeric", year: "numeric" });
      el.classList.toggle("live", !!isLive);
    }

    paint(rows[rows.length - 1], true);

    instance.chart.subscribeCrosshairMove(function (param) {
      if (!param || param.time == null) return;      // leave handled by mouseleave
      paint(byTime[param.time] || rows[rows.length - 1], false);
    });

    /* The crosshair subscription only reports when the pointer is over a
       series point. Drive the readout from raw pointer position as well so
       scrubbing is continuous across gaps, sub-panes, and the axis gutter. */
    var ts = instance.chart.timeScale();
    var host = instance.host;
    var frame = null;
    host.addEventListener("mousemove", function (ev) {
      if (frame) return;
      frame = requestAnimationFrame(function () {
        frame = null;
        var rect = host.getBoundingClientRect();
        var x = ev.clientX - rect.left;
        var idx = null;
        try {
          var logical = ts.coordinateToLogical(x);
          if (logical != null) idx = Math.round(logical);
        } catch (e) {}
        if (idx == null) return;
        idx = Math.max(0, Math.min(rows.length - 1, idx));
        paint(rows[idx], false);
      });
    }, { passive: true });

    host.addEventListener("mouseleave", function () {
      paint(rows[rows.length - 1], true);
    }, { passive: true });

    return el;
  }

  /* ── canvas mirror so the PDF report export keeps working ──────────────── */
  function mirrorToCanvas(instance) {
    var canvas = document.getElementById("price-chart");
    if (!canvas || !canvas.getContext) return;
    try {
      var shot = instance.chart.takeScreenshot();
      if (!shot) return;
      canvas.width = shot.width; canvas.height = shot.height;
      canvas.getContext("2d").drawImage(shot, 0, 0);
    } catch (e) {}
  }

  /* ── markers: earnings + news ──────────────────────────────────────────── */
  var markerCache = {};
  function applyMarkers(instance) {
    if (!window.S || !S.ticker) return;
    if (!view.pins.earnings && !view.pins.news) {
      if (instance._markers) { instance._markers.setMarkers([]); }
      return;
    }
    var ticker = S.ticker;
    var wants = [];
    if (view.pins.earnings) wants.push("earnings");
    if (view.pins.news) wants.push("news");

    Promise.all(wants.map(function (kind) {
      var key = kind + ":" + ticker;
      if (markerCache[key]) return Promise.resolve(markerCache[key]);
      var url = kind === "earnings" ? "/api/earnings/" + encodeURIComponent(ticker)
                                    : "/api/news/" + encodeURIComponent(ticker);
      return fetch(url, { credentials: "same-origin" })
        .then(function (r) { return r.ok ? r.json() : null; })
        .then(function (j) {
          var out = [];
          if (!j) return (markerCache[key] = out);
          var list = kind === "earnings"
            ? (j.earnings || j.history || j.data || (Array.isArray(j) ? j : []))
            : (j.news || j.articles || (Array.isArray(j) ? j : []));
          (list || []).slice(0, 60).forEach(function (item) {
            var raw = item.period || item.date || item.datetime || item.publishedAt || item.time;
            if (!raw) return;
            var t = typeof raw === "number" ? (raw > 1e11 ? Math.floor(raw / 1000) : raw)
                                            : Math.floor(new Date(raw).getTime() / 1000);
            if (!isFinite(t)) return;
            out.push({
              time: t, kind: kind,
              text: kind === "earnings"
                ? ("EPS " + (item.actual != null ? item.actual : "—") +
                   (item.estimate != null ? " vs " + item.estimate + " est" : ""))
                : String(item.headline || item.title || "News").slice(0, 70)
            });
          });
          return (markerCache[key] = out);
        })
        .catch(function () { return (markerCache[key] = []); });
    })).then(function (sets) {
      var rows = instance.rows;
      if (!rows.length) return;
      var times = rows.map(function (r) { return r.time; });
      var first = times[0], last = times[times.length - 1];
      var p = palette();
      var markers = [];
      sets.flat().forEach(function (m) {
        if (m.time < first || m.time > last) return;
        // snap to the nearest bar the chart actually has
        var best = null, bestD = Infinity;
        for (var i = 0; i < times.length; i++) {
          var d = Math.abs(times[i] - m.time);
          if (d < bestD) { bestD = d; best = times[i]; }
        }
        if (best == null) return;
        markers.push({
          time: best,
          position: m.kind === "earnings" ? "belowBar" : "aboveBar",
          color: m.kind === "earnings" ? p.gold : p.ma50,
          shape: m.kind === "earnings" ? "arrowUp" : "circle",
          text: m.kind === "earnings" ? "E" : "N",
          size: 1,
          _tip: m.text
        });
      });
      markers.sort(function (a, b) { return a.time - b.time; });
      try {
        if (instance._markers) instance._markers.setMarkers(markers);
        else instance._markers = LWC.createSeriesMarkers(instance.series.price, markers);
      } catch (e) {}
    });
  }

  /* ── mount ─────────────────────────────────────────────────────────────── */
  function hostFor() {
    var canvas = document.getElementById("price-chart");
    if (!canvas) return null;
    var slot = canvas.parentElement;                  // .h240
    if (!slot) return null;
    slot.classList.add("il-chart-slot");
    var host = slot.querySelector(".il-chart-host");
    if (!host) {
      host = document.createElement("div");
      host.className = "il-chart-host";
      slot.insertBefore(host, canvas);
      canvas.classList.add("il-chart-mirror");        // kept for toDataURL only
    }
    return host;
  }

  function rowsFrom(result, closes, timestamps) {
    var q = (result && result.indicators && result.indicators.quote && result.indicators.quote[0]) || {};
    var ts = timestamps || result.timestamp || [];
    var cl = closes || q.close || [];
    var n = Math.min(ts.length, cl.length);
    var rows = [], seen = {};
    for (var i = 0; i < n; i++) {
      var c = Number(cl[i]);
      if (!isFinite(c)) continue;
      var t = Math.floor(Number(ts[i]));
      if (!isFinite(t) || seen[t]) continue;           // LWC requires strictly ascending unique times
      seen[t] = 1;
      rows.push({
        time: t,
        open: isFinite(Number(q.open && q.open[i])) ? Number(q.open[i]) : c,
        high: isFinite(Number(q.high && q.high[i])) ? Number(q.high[i]) : c,
        low: isFinite(Number(q.low && q.low[i])) ? Number(q.low[i]) : c,
        close: c,
        volume: isFinite(Number(q.volume && q.volume[i])) ? Number(q.volume[i]) : 0
      });
    }
    rows.sort(function (a, b) { return a.time - b.time; });
    return rows;
  }

  function render(result, closes, timestamps) {
    var host = hostFor();
    if (!host) return;
    var rows = rowsFrom(result, closes, timestamps);
    if (!rows.length) return;

    var keepRange = null;
    var prevLength = inst ? inst._ilLength : null;
    if (inst && inst.chart) {
      try { keepRange = inst.chart.timeScale().getVisibleLogicalRange(); } catch (e) {}
      try { if (inst.chart._ilResizeObserver) inst.chart._ilResizeObserver.disconnect(); } catch (e) {}
      try { inst.chart.remove(); } catch (e) {}
      inst = null;
    }
    host.innerHTML = "";

    inst = buildInstance(host, rows);
    lastFrame = { rows: rows, result: result };
    wireReadout(inst, host.parentElement);
    applyMarkers(inst);
    if (zonesOn) fetchZones(function () { if (inst) applyZones(inst); });

    /* Restore the user's zoom ONLY when the underlying bar count is unchanged —
       i.e. they flipped candle→line or toggled an indicator. Changing timeframe
       changes the bar count, and reusing the old logical range there is what made
       the candle size appear frozen across timeframes. */
    if (keepRange && prevLength === rows.length) {
      inst.chart._ilViewLocked = true;
      try { inst.chart.timeScale().setVisibleLogicalRange(keepRange); } catch (e) {}
      requestAnimationFrame(function () {
        requestAnimationFrame(function () {
          try { inst.chart.timeScale().setVisibleLogicalRange(keepRange); } catch (e) {}
        });
      });
    }
    inst._ilLength = rows.length;
    window.__ilChart = inst;   // debug + integration handle

    setTimeout(function () { mirrorToCanvas(inst); }, 260);

    /* keep existing callers alive */
    if (window.S) {
      S.charts = S.charts || {};
      S.charts["price-chart"] = {
        _il: true,
        destroy: function () { try { inst && inst.chart.remove(); } catch (e) {} inst = null; },
        resetZoom: function () { try { inst.applyInitialView(); } catch (e) { try { inst.chart.timeScale().fitContent(); } catch (e2) {} } },
        zoom: function (f) {
          try {
            var ts = inst.chart.timeScale();
            var r = ts.getVisibleLogicalRange();
            if (!r) return;
            var span = r.to - r.from;
            var next = span / f;
            /* Clamp both ends: never fewer than 12 bars (you lose all context)
               and never so many that a candle drops under its legibility floor. */
            var width = (inst.host.clientWidth || 900) - 64;
            var maxBars = Math.max(40, Math.floor(width / inst.floorSpacing));
            next = Math.max(12, Math.min(maxBars, next));
            var mid = (r.from + r.to) / 2, half = next / 2;
            ts.setVisibleLogicalRange({ from: mid - half, to: mid + half });
          } catch (e) {}
        },
        update: function () {},
        resize: function () {},
        toBase64Image: function () {
          try { return inst.chart.takeScreenshot().toDataURL("image/png"); } catch (e) { return ""; }
        }
      };
    }
    document.dispatchEvent(new CustomEvent("il-chart-rendered", { detail: { rows: rows } }));
  }

  /* ── LensScore zones drawn onto the price pane ─────────────────────────── */
  var zonesOn = false;
  try { zonesOn = localStorage.getItem("il-chart-zones") === "1"; } catch (e) {}

  function clearZones(instance) {
    (instance._ilZoneLines || []).forEach(function (ln) {
      try { instance.series.price.removePriceLine(ln); } catch (e) {}
    });
    instance._ilZoneLines = [];
    if (instance._ilZoneMarkers) {
      try { instance._ilZoneMarkers.setMarkers([]); } catch (e) {}
      instance._ilZoneMarkers = null;
    }
  }

  function applyZones(instance) {
    if (!instance || !instance.series || !instance.series.price) return;
    clearZones(instance);
    if (!zonesOn) return;
    var setup = window.__ilLensZones;
    if (!setup || !setup.ok) return;
    var p = palette();
    var lines = [];

    function add(price, color, title, style, width) {
      if (price == null || !isFinite(Number(price))) return;
      try {
        lines.push(instance.series.price.createPriceLine({
          price: Number(price), color: color, lineWidth: width || 1,
          lineStyle: style == null ? 2 : style,
          axisLabelVisible: true, title: title
        }));
      } catch (e) {}
    }

    var z = setup.zones || {};
    (z.buyer || []).slice(0, 3).forEach(function (g, i) {
      add(g.price, p.up, i === 0 ? "Buyers" : "Buyers " + (i + 1), 2, i === 0 ? 2 : 1);
    });
    (z.seller || []).slice(0, 3).forEach(function (g, i) {
      add(g.price, p.down, i === 0 ? "Sellers" : "Sellers " + (i + 1), 2, i === 0 ? 2 : 1);
    });

    var fib = setup.retracement;
    if (fib) {
      add(fib.upper, p.band, "0.5", 3);
      add(fib.lower, p.band, "0.618", 3);
    }
    instance._ilZoneLines = lines;

    /* Divergence gets a marker on the swing that formed it, not a price line. */
    var div = setup.divergence || {};
    var rows = instance.rows || [];
    var marks = [];
    /* Server and client series can differ by a bar or two at the edges, but
       both end on the same session — so anchor from the right. */
    var srvBars = (setup.inputs && setup.inputs.bars) || rows.length;
    function markAt(idx, kind) {
      var fromEnd = srvBars - 1 - idx;
      var row = rows[rows.length - 1 - fromEnd];
      if (!row) return;
      marks.push({
        time: row.time,
        position: kind === "bullish" ? "belowBar" : "aboveBar",
        color: kind === "bullish" ? p.up : p.down,
        shape: kind === "bullish" ? "arrowUp" : "arrowDown",
        text: kind === "bullish" ? "Bull div" : "Bear div"
      });
    }
    if (div.bullish) markAt(div.bullish.toIndex, "bullish");
    if (div.bearish) markAt(div.bearish.toIndex, "bearish");
    if (marks.length && window.LWC && LWC.createSeriesMarkers) {
      try { instance._ilZoneMarkers = LWC.createSeriesMarkers(instance.series.price, marks); } catch (e) {}
    }
  }

  var zoneCache = {};
  function fetchZones(then) {
    if (!window.S || !S.ticker) return;
    var key = S.ticker + ":" + (S.range || "1y");
    if (zoneCache[key]) { window.__ilLensZones = zoneCache[key]; then && then(); return; }
    fetch("/api/analysis/" + encodeURIComponent(S.ticker) + "?range=" + encodeURIComponent(S.range || "1y"),
          { credentials: "same-origin" })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (j) {
        var z = j && j.lensSetup && j.lensSetup.ok ? j.lensSetup : null;
        if (!z) return;
        zoneCache[key] = z;
        window.__ilLensZones = z;
        then && then();
      })
      .catch(function () {});
  }

  window.ilToggleZones = function (btn) {
    zonesOn = !zonesOn;
    try { localStorage.setItem("il-chart-zones", zonesOn ? "1" : "0"); } catch (e) {}
    if (btn) { btn.classList.toggle("on", zonesOn); btn.setAttribute("aria-pressed", String(zonesOn)); }
    document.querySelectorAll("[data-il-zones]").forEach(function (b) {
      b.classList.toggle("on", zonesOn);
      b.setAttribute("aria-pressed", String(zonesOn));
    });
    function paint() {
      if (inst) applyZones(inst);
      var modal = document.getElementById("chart-expand-modal");
      if (modal && modal._ilExpanded) applyZones(modal._ilExpanded);
    }
    if (zonesOn && !window.__ilLensZones) fetchZones(paint); else paint();
  };

  /* ── full-screen control strip ─────────────────────────────────────────── */
  var TF = [["1d","1D"],["5d","5D"],["1mo","1M"],["3mo","3M"],["6mo","6M"],
            ["ytd","YTD"],["1y","1Y"],["2y","2Y"],["5y","5Y"],["max","Max"]];
  var CT = [["candle","Candle"],["line","Line"],["area","Area"]];

  function buildExpandedControls(modal, syncOnly) {
    var strip = modal.querySelector(".il-cex-controls");
    if (!strip) {
      if (syncOnly) return;
      strip = document.createElement("div");
      strip.className = "il-cex-controls";
      strip.innerHTML =
        '<div class="ilcx-group" role="group" aria-label="Timeframe">' +
          TF.map(function (t) {
            return '<button type="button" class="ilcx-chip" data-il-range="' + t[0] + '">' + t[1] + "</button>";
          }).join("") +
        "</div>" +
        '<div class="ilcx-group" role="group" aria-label="Chart type">' +
          CT.map(function (t) {
            return '<button type="button" class="ilcx-chip" data-il-ctype="' + t[0] + '">' + t[1] + "</button>";
          }).join("") +
        "</div>" +
        '<div class="ilcx-group" role="group" aria-label="Price scale">' +
          '<button type="button" class="ilcx-chip" data-il-scale="log" title="Logarithmic price scale">Log</button>' +
          '<button type="button" class="ilcx-chip" data-il-scale="percent" title="Percent-change scale">%</button>' +
        "</div>" +
        '<div class="ilcx-group" role="group" aria-label="Studies">' +
          '<button type="button" class="ilcx-chip" data-il-vol="1" title="Volume pane">Vol</button>' +
          '<button type="button" class="ilcx-chip" data-il-osc="rsi" title="RSI pane">RSI</button>' +
          '<button type="button" class="ilcx-chip" data-il-osc="macd" title="MACD pane">MACD</button>' +
          '<button type="button" class="ilcx-chip" data-il-ov="ema21" title="21-period EMA">21 EMA</button>' +
          '<button type="button" class="ilcx-chip" data-il-ov="vwap" title="Volume-weighted average price">VWAP</button>' +
        "</div>" +
        '<div class="ilcx-group" role="group" aria-label="Overlays">' +
          '<button type="button" class="ilcx-chip" data-il-zones="1" title="LensScore supply and demand zones">Zones</button>' +
          '<button type="button" class="ilcx-chip" data-il-pin="earnings" title="Earnings markers">Earnings</button>' +
          '<button type="button" class="ilcx-chip" data-il-pin="news" title="News markers">News</button>' +
        "</div>";

      strip.addEventListener("click", function (ev) {
        var b = ev.target.closest ? ev.target.closest(".ilcx-chip") : null;
        if (!b) return;
        var v;
        if ((v = b.getAttribute("data-il-range")) && typeof window.changeRange === "function") return window.changeRange(v);
        if ((v = b.getAttribute("data-il-ctype")) && typeof window.setChartType === "function") return window.setChartType(v);
        if ((v = b.getAttribute("data-il-scale"))) return window.ilSetScale(v);
        if (b.hasAttribute("data-il-vol")) return window.ilToggleVolume();
        if ((v = b.getAttribute("data-il-osc"))) return window.ilSetOscillator(v);
        if ((v = b.getAttribute("data-il-ov"))) return window.ilToggleOverlay(v);
        if (b.hasAttribute("data-il-zones")) return window.ilToggleZones(b);
        if ((v = b.getAttribute("data-il-pin"))) {
          window.ilTogglePins(v, b);
          var mm = document.getElementById("chart-expand-modal");
          if (mm && mm._ilExpanded) applyMarkers(mm._ilExpanded);
          return;
        }
      });

      var head = modal.querySelector(".cex-header");
      var box = modal.querySelector(".cex-box") || modal;
      if (head && head.nextSibling) box.insertBefore(strip, head.nextSibling);
      else box.appendChild(strip);
    }

    var range = (window.S && S.range) || "1y";
    var ctype = (window.S && S.chartType) || "candle";
    function set(sel, on) {
      var b = strip.querySelector(sel);
      if (!b) return;
      b.classList.toggle("on", !!on);
      b.setAttribute("aria-pressed", String(!!on));
    }
    TF.forEach(function (t) { set('[data-il-range="' + t[0] + '"]', t[0] === range); });
    CT.forEach(function (t) { set('[data-il-ctype="' + t[0] + '"]', t[0] === ctype); });
    set('[data-il-scale="log"]', view.scale === "log");
    set('[data-il-scale="percent"]', view.scale === "percent");
    set("[data-il-vol]", view.volume);
    set('[data-il-osc="rsi"]', view.osc === "rsi");
    set('[data-il-osc="macd"]', view.osc === "macd");
    set('[data-il-ov="ema21"]', view.ema21);
    set('[data-il-ov="vwap"]', view.vwap);
    set("[data-il-zones]", zonesOn);
    set('[data-il-pin="earnings"]', view.pins.earnings);
    set('[data-il-pin="news"]', view.pins.news);
  }

  /* ── take over the global entry points ─────────────────────────────────── */
  function install() {
    if (window.__ilChartEngine) return;
    window.__ilChartEngine = true;

    var prevBuild = window.buildPriceChart;
    window.buildPriceChart = function (result, closes, timestamps) {
      try { if (typeof window.syncIndicatorAvailability === "function") window.syncIndicatorAvailability(); } catch (e) {}
      try { render(result, closes, timestamps); }
      catch (e) {
        console.warn("[chart-engine] falling back to Chart.js:", e && e.message);
        if (typeof prevBuild === "function") {
          var c = document.getElementById("price-chart");
          if (c) c.classList.remove("il-chart-mirror");
          return prevBuild.apply(this, arguments);
        }
      }
    };

    window.zoomPriceChart = function (factor) {
      if (factor < 1 && typeof window.chartAtFullHistory === "function") {
        try {
          var ts = inst && inst.chart.timeScale();
          var r = ts && ts.getVisibleLogicalRange();
          if (r && r.from <= 0.5 && typeof window.loadMorePriceHistory === "function") {
            return window.loadMorePriceHistory();
          }
        } catch (e) {}
      }
      if (window.S && S.charts && S.charts["price-chart"]) S.charts["price-chart"].zoom(factor);
    };
    window.resetPriceZoom = function () {
      if (window.S && S.charts && S.charts["price-chart"]) S.charts["price-chart"].resetZoom();
    };

    /* the expanded modal gets its own full-height instance */
    var prevExpand = window.expandChart;
    window.expandChart = function (chartId, title) {
      if (chartId !== "price-chart" || !lastFrame) {
        return typeof prevExpand === "function" ? prevExpand.apply(this, arguments) : undefined;
      }
      var modal = document.getElementById("chart-expand-modal");
      if (!modal) return;
      modal.dataset.chartId = chartId;
      modal.dataset.chartTitle = title || "Price Chart";
      /* Flags the modal as owned by the Lightweight-Charts engine. The CSS then
         hides the legacy Chart.js canvases and the markup toolbar that operates
         on them — they were still occupying layout and pushing the real chart
         host below the fold, which is why full screen came up blank. */
      modal.classList.add("il-lwc", "open");
      var t = document.getElementById("cex-title");
      if (t) t.textContent = modal.dataset.chartTitle;
      document.body.style.overflow = "hidden";

      buildExpandedControls(modal);
      mountExpanded(modal);
      document.dispatchEvent(new CustomEvent("il-chart-expanded"));
    };

    function mountExpanded(modal) {
      var slot = modal.querySelector(".cex-workspace") || modal.querySelector(".cex-body") || modal;
      if (modal._ilExpanded) {
        try { modal._ilExpanded.chart.remove(); } catch (e) {}
        modal._ilExpanded = null;
      }
      var old = slot.querySelector(".il-chart-host-expanded");
      if (old) old.remove();
      var host = document.createElement("div");
      host.className = "il-chart-host-expanded";
      slot.appendChild(host);

      /* The modal is display:none until .open lands, so the host measures 0x0
         on this frame. Building an LWC chart into a zero box produces a chart
         that never draws. Wait two frames for layout to settle. */
      requestAnimationFrame(function () {
        requestAnimationFrame(function () {
          if (!document.body.contains(host)) return;
          var ex = buildInstance(host, lastFrame.rows);
          wireReadout(ex, host);
          applyMarkers(ex);
          applyZones(ex);
          modal._ilExpanded = ex;
          try { ex.sizePanes(); ex.applyInitialView(); } catch (e) {}
        });
      });
    }

    /* Keep the expanded chart in step with the toolbar: any main-chart re-render
       (new range, new type, indicator toggled) rebuilds it from the new frame. */
    document.addEventListener("il-chart-rendered", function () {
      var modal = document.getElementById("chart-expand-modal");
      if (modal && modal.classList.contains("open") && modal.classList.contains("il-lwc")) {
        buildExpandedControls(modal, true);
        mountExpanded(modal);
      }
    });

    var prevClose = window.closeExpandModal;
    window.closeExpandModal = function () {
      var modal = document.getElementById("chart-expand-modal");
      if (modal && modal._ilExpanded) {
        try { modal._ilExpanded.chart.remove(); } catch (e) {}
        modal._ilExpanded = null;
        var h = modal.querySelector(".il-chart-host-expanded");
        if (h) h.remove();
      }
      if (modal) modal.classList.remove("il-lwc");
      if (typeof prevClose === "function") return prevClose.apply(this, arguments);
      if (modal) { modal.classList.remove("open"); document.body.style.overflow = ""; }
    };

    /* Zoom / reset inside the modal must drive the modal's own instance. */
    var prevZoomEx = window.zoomExpandedChart;
    window.zoomExpandedChart = function (f) {
      var modal = document.getElementById("chart-expand-modal");
      var ex = modal && modal._ilExpanded;
      if (!ex) return typeof prevZoomEx === "function" ? prevZoomEx.apply(this, arguments) : undefined;
      try {
        var ts = ex.chart.timeScale();
        var r = ts.getVisibleLogicalRange();
        if (!r) return;
        var next = (r.to - r.from) / f;
        var width = (ex.host.clientWidth || 1200) - 64;
        next = Math.max(12, Math.min(Math.max(40, Math.floor(width / ex.floorSpacing)), next));
        var mid = (r.from + r.to) / 2;
        ts.setVisibleLogicalRange({ from: mid - next / 2, to: mid + next / 2 });
      } catch (e) {}
    };
    var prevResetEx = window.resetExpandZoom;
    window.resetExpandZoom = function () {
      var modal = document.getElementById("chart-expand-modal");
      var ex = modal && modal._ilExpanded;
      if (!ex) return typeof prevResetEx === "function" ? prevResetEx.apply(this, arguments) : undefined;
      try { ex.applyInitialView(); } catch (e) {}
    };

    /* re-render on theme flip so colours follow the surface */
    var mo = new MutationObserver(function (muts) {
      for (var i = 0; i < muts.length; i++) {
        if (muts[i].attributeName === "data-theme" && lastFrame) {
          render(lastFrame.result, null, null);
          return;
        }
      }
    });
    mo.observe(document.documentElement, { attributes: true });

    wireToolbar();
  }

  /* ── new toolbar controls (Log / % / Vol / RSI / MACD / EMA / VWAP) ─────── */
  function rerender() {
    if (lastFrame) render(lastFrame.result, null, null);
  }

  window.ilSetScale = function (mode, btn) {
    view.scale = view.scale === mode ? "normal" : mode;
    persist();
    syncToggleStates();
    rerender();
  };
  window.ilToggleVolume = function () {
    view.volume = !view.volume; persist();
    syncToggleStates();
    rerender();
  };
  window.ilSetOscillator = function (which, btn) {
    view.osc = view.osc === which ? "none" : which; persist();
    syncToggleStates();
    rerender();
  };
  window.ilToggleOverlay = function (key, btn) {
    view[key] = !view[key]; persist();
    if (btn) { btn.classList.toggle("on", view[key]); btn.setAttribute("aria-pressed", String(view[key])); }
    rerender();
  };
  window.ilTogglePins = function (kind, btn) {
    view.pins[kind] = !view.pins[kind]; persist();
    if (btn) { btn.classList.toggle("on", view.pins[kind]); btn.setAttribute("aria-pressed", String(view.pins[kind])); }
    if (inst) applyMarkers(inst);
  };

  function syncToggleStates() {
    document.querySelectorAll("[data-il-scale]").forEach(function (b) {
      var on = b.getAttribute("data-il-scale") === view.scale;
      b.classList.toggle("on", on);
      b.setAttribute("aria-pressed", on ? "true" : "false");
    });
    document.querySelectorAll("[data-il-vol]").forEach(function (b) {
      b.classList.toggle("on", view.volume);
      b.setAttribute("aria-pressed", String(view.volume));
    });
    document.querySelectorAll("[data-il-osc]").forEach(function (b) {
      var on = b.getAttribute("data-il-osc") === view.osc;
      b.classList.toggle("on", on);
      b.setAttribute("aria-pressed", on ? "true" : "false");
    });
  }

  function wireToolbar() {
    /* The Earnings / News buttons were decorative stubs — make them real. */
    var e = document.getElementById("epins-btn");
    if (e) e.setAttribute("onclick", "ilTogglePins('earnings',this)");
    var n = document.getElementById("npins-btn");
    if (n) n.setAttribute("onclick", "ilTogglePins('news',this)");

    var bar = document.getElementById("app-chart-toolbar");
    if (!bar || bar.querySelector("[data-il-osc]")) return;
    var right = bar.querySelector(".act-right");

    function mk(html, attrs) {
      var b = document.createElement("button");
      b.type = "button";
      b.className = "act-btn";
      b.innerHTML = html;
      Object.keys(attrs || {}).forEach(function (k) { b.setAttribute(k, attrs[k]); });
      if (right) bar.insertBefore(b, right); else bar.appendChild(b);
      return b;
    }
    var sep = document.createElement("div");
    sep.className = "act-sep";
    if (right) bar.insertBefore(sep, right); else bar.appendChild(sep);

    mk('<span class="chart-key key-ema"></span>21 EMA',
       { onclick: "ilToggleOverlay('ema21',this)", "data-mobile-label": "EMA",
         "aria-pressed": String(view.ema21), title: "21-period exponential moving average" })
      .classList.toggle("on", view.ema21);
    mk('<span class="chart-key key-vwap"></span>VWAP',
       { onclick: "ilToggleOverlay('vwap',this)", "data-mobile-label": "VWAP",
         "aria-pressed": String(view.vwap), title: "Volume-weighted average price" })
      .classList.toggle("on", view.vwap);
    mk("RSI", { onclick: "ilSetOscillator('rsi',this)", "data-il-osc": "rsi",
                "aria-pressed": String(view.osc === "rsi"), title: "Relative strength index pane" })
      .classList.toggle("on", view.osc === "rsi");
    mk("MACD", { onclick: "ilSetOscillator('macd',this)", "data-il-osc": "macd",
                 "aria-pressed": String(view.osc === "macd"), title: "MACD pane" })
      .classList.toggle("on", view.osc === "macd");
    mk("Zones", { onclick: "ilToggleZones(this)", "data-il-zones": "1", "data-mobile-label": "Zones",
                  "aria-pressed": String(zonesOn),
                  title: "LensScore supply and demand zones, retracement band and divergence" })
      .classList.toggle("on", zonesOn);

    syncToggleStates();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", install);
  } else { install(); }
  setTimeout(install, 900);   // matches workspace-system.js's late-install fallback
})();

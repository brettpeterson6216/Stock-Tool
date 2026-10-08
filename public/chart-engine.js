/* ═══════════════════════════════════════════════════════════════════════════
   ImpliedLens — price chart engine

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
    var css = getComputedStyle(document.documentElement);
    function token(name, fallback) { return css.getPropertyValue(name).trim() || fallback; }
    return {
      text: token("--rp-muted", d ? "#9A968D" : "#6B6F78"),
      textStrong: token("--rp-ink", d ? "#F2F0EB" : "#14161A"),
      grid: d ? "rgba(255,255,255,.045)" : "rgba(24,22,18,.06)",
      border: d ? "rgba(255,255,255,.08)" : "rgba(24,22,18,.10)",
      crosshair: d ? "rgba(214,172,100,.55)" : "rgba(150,109,43,.5)",
      up: token("--rp-green", d ? "#2FD98C" : "#0B7A4C"),
      down: token("--rp-red", d ? "#F05C6A" : "#BE3A4B"),
      upFill: d ? "rgba(47,217,140,.5)" : "rgba(11,122,76,.45)",
      downFill: d ? "rgba(240,92,106,.5)" : "rgba(190,58,75,.45)",
      gold: token("--rp-gold", d ? "#D6AC64" : "#966D2B"),
      /* The 50-day takes the product's gold on candles, where nothing else
         is gold; on the line and area views the price itself is gold, so the
         average steps to orange there. The 200-day is blue either way. */
      ma50: ((window.S && S.chartType) || "candle") === "candle"
        ? token("--rp-gold", d ? "#F0BE5A" : "#87590C")
        : (d ? "#E8794A" : "#C4561F"),
      ma200: d ? "#7FB2E5" : "#2F6FA8",
      rsi: d ? "#C79BE8" : "#6D46A0",
      ema: d ? "#EDCB84" : "#B8892F",
      vwap: d ? "#7ED9C8" : "#127C6C",
      band: d ? "rgba(214,172,100,.42)" : "rgba(150,109,43,.4)",
      volUp: d ? "rgba(47,217,140,.34)" : "rgba(11,122,76,.3)",
      volDown: d ? "rgba(240,92,106,.34)" : "rgba(190,58,75,.28)"
    };
  }

  // The indicator charts (Chart.js, app-legacy.js) read this so every chart
  // on the page shares one palette.
  window.ILChartPalette = palette;

  /* ── state ─────────────────────────────────────────────────────────────── */
  var view = {
    scale: "normal",       // normal | log | percent
    volume: true,
    osc: "rsi",            // rsi | macd | timing | none
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
  /* ── time & interval ───────────────────────────────────────────────────── */
  var INTERVAL_LABEL = { "1m": "1 min", "2m": "2 min", "5m": "5 min", "15m": "15 min", "30m": "30 min",
    "60m": "Hourly", "90m": "90 min", "1h": "Hourly", "1d": "Daily", "5d": "5 day", "1wk": "Weekly",
    "1mo": "Monthly", "3mo": "Quarterly" };
  var AUTO_INTERVAL = { "1d": "5m", "5d": "30m", "1mo": "1d", "3mo": "1d", "6mo": "1d", "ytd": "1d",
    "1y": "1d", "2y": "1d", "5y": "1wk", "10y": "1wk", "max": "1mo" };
  function frameInterval(result) {
    var g = String((result && result.meta && result.meta.dataGranularity) || "").toLowerCase();
    if (INTERVAL_LABEL[g]) return g;
    return AUTO_INTERVAL[(window.S && S.range) || "1y"] || "1d";
  }
  function isIntraInterval(iv) { return /^\d+(m|h)$/.test(iv || ""); }
  function currentInterval() { return lastFrame ? lastFrame.interval : AUTO_INTERVAL[(window.S && S.range) || "1y"]; }
  function intraday() { return isIntraInterval(currentInterval()); }
  function exchangeTz() {
    var m = lastFrame && lastFrame.result && lastFrame.result.meta;
    return (m && m.exchangeTimezoneName) || "America/New_York";
  }
  var dtfCache = {};
  function dtf(opts) {
    var k = JSON.stringify(opts);
    if (!dtfCache[k]) {
      try { dtfCache[k] = new Intl.DateTimeFormat("en-US", opts); }
      catch (e) { var o = Object.assign({}, opts); delete o.timeZone; dtfCache[k] = new Intl.DateTimeFormat("en-US", o); }
    }
    return dtfCache[k];
  }
  /* Bars carry UTC timestamps. Lightweight Charts prints them in UTC, which put
     the NYSE open at "13:30" on the axis. Format every label in the exchange's
     own time zone instead. */
  function fmtBarTime(t, long) {
    var d = new Date(t * 1000), tz = exchangeTz();
    if (intraday()) {
      return dtf({ timeZone: tz, weekday: "short", month: "short", day: "numeric", hour: "numeric", minute: "2-digit" }).format(d);
    }
    return dtf(long
      ? { timeZone: tz, weekday: "short", month: "short", day: "numeric", year: "numeric" }
      : { timeZone: tz, month: "short", day: "numeric", year: "2-digit" }).format(d);
  }
  function tickLabel(time, type) {
    if (typeof time !== "number") return null;
    var d = new Date(time * 1000), tz = exchangeTz();
    if (type === 0) return dtf({ timeZone: tz, year: "numeric" }).format(d);
    if (type === 1) return dtf({ timeZone: tz, month: "short" }).format(d);
    if (type === 2) return intraday() ? dtf({ timeZone: tz, month: "short", day: "numeric" }).format(d)
                                      : dtf({ timeZone: tz, day: "numeric" }).format(d);
    return dtf({ timeZone: tz, hour: "2-digit", minute: "2-digit", hourCycle: "h23" }).format(d);
  }

  /* Moving averages on a short range need bars from before the range starts:
     a 50-day average on a one-month chart is otherwise blank for its first 49
     days. app-legacy.js keeps two years of daily closes in S.maLookback; when
     the chart is daily, prepend the older ones for the maths only. */
  function extendedCloses(rows) {
    var closes = rows.map(function (r) { return r.close; });
    var lb = window.S && S.maLookback;
    if (!lb || !lb.ts || lb.ticker !== S.ticker || rows.length < 2 || isIntraInterval(currentInterval())) return { pre: 0, closes: closes };
    var gaps = [];
    for (var i = 1; i < Math.min(rows.length, 30); i++) gaps.push(rows[i].time - rows[i - 1].time);
    gaps.sort(function (a, b) { return a - b; });
    var med = gaps[gaps.length >> 1] || 0;
    if (!(med > 0 && med < 86400 * 2.5)) return { pre: 0, closes: closes };
    var first = rows[0].time - 3600, pre = [];
    for (var j = 0; j < lb.ts.length; j++) if (lb.ts[j] < first) pre.push(lb.close[j]);
    return { pre: pre.length, closes: pre.concat(closes) };
  }
  function trim(ext, arr) { return ext.pre ? arr.slice(ext.pre) : arr; }

  /* ── build ─────────────────────────────────────────────────────────────── */
  var MIN_SPACING = 0.5;     // px per bar at the widest zoom-out

  function buildInstance(host, rows, opts) {
    opts = opts || {};
    var p = palette();
    var type = (window.S && S.chartType) || "candle";
    /* Candles open at a legible width; the user can zoom out as far as half a
       pixel per bar, the way every desktop charting tool lets you. */
    var seed = type === "candle" ? 8 : 4;
    var chart = LWC.createChart(host, {
      layout: {
        background: { type: "solid", color: "transparent" },
        textColor: p.text,
        fontFamily: '"IBM Plex Sans", "Plus Jakarta Sans", -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
        fontSize: 12,
        panes: { separatorColor: p.border, separatorHoverColor: p.crosshair, enableResize: true }
      },
      localization: {
        locale: "en-US",
        timeFormatter: function (t) { return typeof t === "number" ? fmtBarTime(t, false) : String(t); }
      },
      grid: { vertLines: { visible: false }, horzLines: { color: p.grid } },
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
        minBarSpacing: MIN_SPACING,
        fixLeftEdge: true,
        shiftVisibleRangeOnNewBar: true,
        lockVisibleTimeRangeOnResize: true,
        tickMarkFormatter: tickLabel
      },
      crosshair: {
        mode: opts.magnet === false ? 0 : 1,
        vertLine: { color: p.crosshair, width: 1, style: 2, labelBackgroundColor: p.gold },
        horzLine: { color: p.crosshair, width: 1, style: 2, labelBackgroundColor: p.gold }
      },
      /* Wheel zooms and trackpads pan. On the research page the chart only takes
         the wheel once it has been clicked (see the guard in workspace-system.js)
         so scrolling the page past it still works. */
      handleScroll: { mouseWheel: true, pressedMouseMove: true, horzTouchDrag: true, vertTouchDrag: false },
      handleScale: { mouseWheel: true, pinch: true, axisPressedMouseMove: { time: true, price: true }, axisDoubleClickReset: true },
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
    } else if (type === "area") {
      series.price = chart.addSeries(LWC.AreaSeries, {
        lineColor: p.gold, lineWidth: 2,
        topColor: isDark() ? "rgba(224,186,104,.16)" : "rgba(132,96,24,.12)",
        bottomColor: "rgba(0,0,0,0)",
        priceLineVisible: true, priceLineColor: p.gold, priceLineStyle: 2, priceLineWidth: 1,
        crosshairMarkerRadius: 4, crosshairMarkerBorderWidth: 2,
        crosshairMarkerBorderColor: isDark() ? "#0B0D11" : "#FFFFFF",
        crosshairMarkerBackgroundColor: p.gold
      }, 0);
    } else {
      series.price = chart.addSeries(LWC.LineSeries, {
        color: p.gold, lineWidth: 2,
        priceLineVisible: true, priceLineColor: p.gold, priceLineStyle: 2, priceLineWidth: 1,
        crosshairMarkerRadius: 4, crosshairMarkerBorderWidth: 2,
        crosshairMarkerBorderColor: isDark() ? "#0B0D11" : "#FFFFFF",
        crosshairMarkerBackgroundColor: p.gold
      }, 0);
    }

    var line = function (color, width, style) {
      return chart.addSeries(LWC.LineSeries, {
        color: color, lineWidth: width || 1, lineStyle: style || 0,
        priceLineVisible: false, lastValueVisible: false, crosshairMarkerVisible: false
      }, 0);
    };

    var S_ = window.S || { inds: {} };
    if (S_.inds && S_.inds.ma50) series.ma50 = line(p.ma50, 1.5);
    if (S_.inds && S_.inds.ma200) series.ma200 = line(p.ma200, 1.5);
    if (view.ema21) series.ema21 = line(p.ema, 1.5);
    if (view.vwap) series.vwap = line(p.vwap, 1.5, 2);
    if (S_.inds && S_.inds.bb) {
      series.bbU = line(p.band, 1, 2);
      series.bbL = line(p.band, 1, 2);
      series.bbM = line(p.band, 1, 3);
    }

    /* analyst target line */
    if (S_.analystTarget && S_.analystTarget.mean && rows.length) {
      series.price.createPriceLine({
        price: S_.analystTarget.mean, color: p.gold, lineWidth: 1, lineStyle: 2,
        axisLabelVisible: true, title: "Analyst target"
      });
    }

    var paneIdx = 1;
    if (view.volume && !opts.compact) {
      series.volume = chart.addSeries(LWC.HistogramSeries, {
        priceFormat: { type: "volume" }, priceLineVisible: false, lastValueVisible: false
      }, paneIdx);
      paneIdx++;
    }
    if (view.osc === "rsi" && !opts.compact) {
      series.rsi = chart.addSeries(LWC.LineSeries, {
        color: p.rsi, lineWidth: 1.5, priceLineVisible: false,
        priceFormat: { type: "price", precision: 1, minMove: 0.1 }
      }, paneIdx);
      [70, 30].forEach(function (lvl) {
        series.rsi.createPriceLine({
          price: lvl, color: lvl === 70 ? p.down : p.up,
          lineWidth: 1, lineStyle: 2, axisLabelVisible: true, title: String(lvl)
        });
      });
      paneIdx++;
    } else if (view.osc === "timing" && !opts.compact && LWC.BaselineSeries) {
      /* Lens Timing: 10 = pulled back hard, 0 = stretched. Green above 5,
         red below, with the extreme bands marked. */
      series.timing = chart.addSeries(LWC.BaselineSeries, {
        baseValue: { type: "price", price: 5 },
        topLineColor: p.up, topFillColor1: isDark() ? "rgba(46,204,140,.30)" : "rgba(10,122,67,.22)", topFillColor2: "rgba(46,204,140,.02)",
        bottomLineColor: p.down, bottomFillColor1: "rgba(255,90,100,.02)", bottomFillColor2: isDark() ? "rgba(255,90,100,.30)" : "rgba(192,40,58,.22)",
        lineWidth: 2, lineType: 2, priceLineVisible: false,
        autoscaleInfoProvider: function () { return { priceRange: { minValue: 0, maxValue: 10 } }; },
        priceFormat: { type: "price", precision: 1, minMove: 0.1 }
      }, paneIdx);
      [[7.5, p.up, "Pulled back"], [2.5, p.down, "Stretched"]].forEach(function (l) {
        series.timing.createPriceLine({ price: l[0], color: l[1], lineWidth: 1, lineStyle: 2, axisLabelVisible: true, title: l[2] });
      });
      paneIdx++;
    } else if (view.osc === "macd" && !opts.compact) {
      series.macdHist = chart.addSeries(LWC.HistogramSeries, { priceLineVisible: false }, paneIdx);
      series.macdLine = chart.addSeries(LWC.LineSeries, {
        color: p.gold, lineWidth: 1.5, priceLineVisible: false, lastValueVisible: false
      }, paneIdx);
      series.macdSignal = chart.addSeries(LWC.LineSeries, {
        color: p.ma200, lineWidth: 1.5, priceLineVisible: false, lastValueVisible: false
      }, paneIdx);
      paneIdx++;
    }

    /* Everything that depends on the bars lives here, so older history can be
       prepended in place without rebuilding the chart (a rebuild would drop a
       drag that is still in progress). */
    function fill(rs) {
      var ext = extendedCloses(rs);
      var closes = rs.map(function (r) { return r.close; });
      var pair = function (vals) {
        var out = [];
        for (var i = 0; i < rs.length; i++) if (vals[i] != null && isFinite(vals[i])) out.push({ time: rs[i].time, value: vals[i] });
        return out;
      };
      if (type === "candle") {
        series.price.setData(rs.map(function (r) {
          return { time: r.time, open: r.open, high: r.high, low: r.low, close: r.close };
        }));
      } else {
        series.price.setData(rs.map(function (r) { return { time: r.time, value: r.close }; }));
      }
      if (series.ma50) series.ma50.setData(pair(trim(ext, TA.sma(ext.closes, 50))));
      if (series.ma200) series.ma200.setData(pair(trim(ext, TA.sma(ext.closes, 200))));
      if (series.ema21) series.ema21.setData(pair(trim(ext, TA.ema(ext.closes, 21))));
      if (series.vwap) {
        series.vwap.setData(pair(TA.vwap(
          rs.map(function (r) { return r.high; }), rs.map(function (r) { return r.low; }),
          closes, rs.map(function (r) { return r.volume; })
        )));
      }
      if (series.bbU) {
        var bb = TA.bollinger(ext.closes, 20, 2);
        series.bbU.setData(pair(trim(ext, bb.upper)));
        series.bbL.setData(pair(trim(ext, bb.lower)));
        series.bbM.setData(pair(trim(ext, bb.mid)));
      }
      if (series.volume) {
        series.volume.setData(rs.map(function (r, i) {
          var up = i === 0 ? r.close >= r.open : r.close >= rs[i - 1].close;
          return { time: r.time, value: r.volume || 0, color: up ? p.volUp : p.volDown };
        }));
      }
      if (series.rsi) series.rsi.setData(pair(trim(ext, TA.rsi(ext.closes, 14))));
      if (series.timing && window.LensScoreEngine && LensScoreEngine.calculateLensTiming) {
        try {
          var lt = LensScoreEngine.calculateLensTiming(rs.map(function (r) {
            return { time: r.time, open: r.open, high: r.high, low: r.low, close: r.close, volume: r.volume || 0 };
          }));
          series.timing.setData((lt.series || []).map(function (pt) { return { time: pt.time, value: pt.timingScore }; }));
        } catch (e) {}
      }
      if (series.macdHist) {
        var m = TA.macd(ext.closes);
        var hist = trim(ext, m.hist);
        series.macdHist.setData(rs.map(function (r, i) {
          return hist[i] == null ? null : { time: r.time, value: hist[i], color: hist[i] >= 0 ? p.volUp : p.volDown };
        }).filter(Boolean));
        series.macdLine.setData(pair(trim(ext, m.line)));
        series.macdSignal.setData(pair(trim(ext, m.signal)));
      }
    }
    fill(rows);

    /* A faint ticker watermark: the plot always says what it is, including
       in screenshots and exports. */
    if (LWC.createTextWatermark && window.S && S.ticker) {
      try {
        var wm = isDark() ? "rgba(242,240,235,.045)" : "rgba(20,22,26,.05)";
        LWC.createTextWatermark(chart.panes()[0], {
          horzAlign: "center", vertAlign: "center",
          lines: [{ text: S.ticker, color: wm, fontSize: 84, fontStyle: "700",
                    fontFamily: '"Plus Jakarta Sans", "IBM Plex Sans", sans-serif' }]
        });
      } catch (e) {}
    }

    /* Pane proportions: price dominates. Height must be measured after layout,
       not during construction, or a 0-height host collapses the sub-panes. */
    function sizePanes() {
      try {
        var panes = chart.panes();
        if (panes.length < 2) return;
        var h = host.clientHeight;
        if (!h) return;
        var axis = 26;
        var usable = h - axis;
        var extra = panes.length - 1;
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

    var instance = {
      chart: chart, series: series, rows: rows, host: host,
      sizePanes: sizePanes, barType: type, floorSpacing: MIN_SPACING
    };

    /* Open on the most recent slice at a legible candle width rather than
       crushing the whole range into the viewport. */
    function applyInitialView() {
      var rs = instance.rows;
      var width = host.clientWidth || 900;
      var target = type === "candle" ? 9 : 4.5;
      var gutter = 64;
      var visible = Math.max(24, Math.min(rs.length, Math.floor((width - gutter) / target)));
      var ts = chart.timeScale();
      try {
        ts.applyOptions({ barSpacing: Math.max(MIN_SPACING, (width - gutter) / visible) });
        ts.setVisibleLogicalRange({ from: rs.length - visible, to: rs.length + 3 });
      } catch (e) { try { ts.fitContent(); } catch (e2) {} }
      try {
        host.dataset.ilVisibleBars = String(Math.min(visible, rs.length));
        host.dataset.ilTotalBars = String(rs.length);
        document.dispatchEvent(new CustomEvent("il:chart-view", {
          detail: { visible: Math.min(visible, rs.length), total: rs.length }
        }));
      } catch (e) {}
    }
    instance.applyInitialView = applyInitialView;

    /* Replace the bars in place. `prepended` older bars keep the same view. */
    instance.setRows = function (rs, prepended) {
      var ts = chart.timeScale();
      var before = null;
      try { before = ts.getVisibleLogicalRange(); } catch (e) {}
      instance.rows = rs;
      fill(rs);
      if (before && prepended) {
        try {
          var now = ts.getVisibleLogicalRange();
          var want = { from: before.from + prepended, to: before.to + prepended };
          if (!now || Math.abs(now.from - want.from) > 0.5) ts.setVisibleLogicalRange(want);
        } catch (e) {}
      }
      try { host.dataset.ilTotalBars = String(rs.length); } catch (e) {}
      if (instance.onRows) instance.onRows(rs);
    };

    requestAnimationFrame(function () {
      requestAnimationFrame(function () { if (!chart._ilViewLocked) applyInitialView(); });
    });
    applyInitialView();

    /* Reaching the left edge loads the next block of older bars at the same
       interval: pan back from a 1D chart and yesterday's candles appear. */
    var edgeFrame = null;
    chart.timeScale().subscribeVisibleLogicalRangeChange(function (r) {
      if (!r || edgeFrame || instance.disposed) return;
      /* A timer, not requestAnimationFrame: rAF is paused in background tabs,
         and a range change made while hidden would never load its history. */
      edgeFrame = setTimeout(function () {
        edgeFrame = null;
        if (r.from < 10 && instance.frame) loadOlder(instance.frame);
      }, 30);
    });

    return instance;
  }

  /* ── scrub readout + legend ────────────────────────────────────────────── */
  function buildReadout(wrap) {
    var scope = wrap.parentElement || wrap;
    var el = scope.querySelector(".il-chart-readout");
    if (el) return el;
    el = document.createElement("div");
    el.className = "il-chart-readout";
    el.innerHTML =
      '<div class="ilr-sym"><b class="ilr-tk"></b><span class="ilr-nm"></span><span class="ilr-meta"></span></div>' +
      '<div class="ilr-main"><span class="ilr-price">—</span><span class="ilr-chg">—</span></div>' +
      '<div class="ilr-ohlc">' +
      '<span><i>O</i><b data-k="o">—</b></span><span><i>H</i><b data-k="h">—</b></span>' +
      '<span><i>L</i><b data-k="l">—</b></span><span><i>C</i><b data-k="c">—</b></span>' +
      '<span><i>Vol</i><b data-k="v">—</b></span></div>' +
      '<div class="ilr-date">—</div>';
    /* A strip above the plot, not a box on top of it: as an overlay it hid the
       top-left of the series, where the last few months of a riser live. */
    var parent = wrap.parentElement;
    if (parent) parent.insertBefore(el, wrap); else wrap.appendChild(el);
    return el;
  }

  function companyName() {
    var n = document.getElementById("r-name");
    var t = (n && n.textContent || "").trim();
    return t && window.S && t !== S.ticker ? t : "";
  }
  function exchangeName() {
    var m = lastFrame && lastFrame.result && lastFrame.result.meta;
    var x = (m && (m.fullExchangeName || m.exchangeName)) || "";
    return { NMS: "NASDAQ", NGM: "NASDAQ", NCM: "NASDAQ", NYQ: "NYSE", ASE: "NYSE American", PCX: "NYSE Arca", BTS: "Cboe" }[x] || x;
  }
  function rangeLabel() {
    var r = (window.S && S.range) || "1y";
    return r === "max" ? "Max" : r === "ytd" ? "YTD" : r.toUpperCase();
  }
  function legendText() {
    return {
      ticker: (window.S && S.ticker) || "",
      name: companyName(),
      meta: [exchangeName(), rangeLabel(), INTERVAL_LABEL[currentInterval()] || ""].filter(Boolean).join(" · ")
    };
  }
  window.ILChartLegend = legendText;

  function wireReadout(instance, wrap) {
    var el = buildReadout(wrap);
    var lg = legendText();
    el.querySelector(".ilr-tk").textContent = lg.ticker;
    el.querySelector(".ilr-nm").textContent = lg.name;
    el.querySelector(".ilr-meta").textContent = lg.meta;
    el.querySelector(".ilr-sym").title = [lg.ticker, lg.name, lg.meta].filter(Boolean).join(" · ");

    var byTime = null, byRows = null;
    function at(t) {
      if (byRows !== instance.rows) {
        byTime = {}; byRows = instance.rows;
        byRows.forEach(function (r) { byTime[r.time] = r; });
      }
      return byTime[t];
    }
    function latest() { return instance.rows[instance.rows.length - 1]; }

    function paint(r, isLive) {
      if (!r) return;
      var base = (instance.frame && instance.frame.base) || (instance.rows[0] && instance.rows[0].close) || 0;
      var chg = r.close - base;
      var pct = base ? (chg / base) * 100 : 0;
      var pos = chg >= 0;
      el.querySelector(".ilr-price").textContent = fmtPrice(r.close);
      var c = el.querySelector(".ilr-chg");
      c.textContent = (pos ? "▲ " : "▼ ") + fmtPrice(Math.abs(chg)) +
        "  (" + (pos ? "+" : "−") + Math.abs(pct).toFixed(2) + "%)";
      c.className = "ilr-chg " + (pos ? "pos" : "neg");
      c.title = "Change from the first bar of the " + rangeLabel() + " range";
      el.querySelector('[data-k="o"]').textContent = fmtPrice(r.open);
      el.querySelector('[data-k="h"]').textContent = fmtPrice(r.high);
      el.querySelector('[data-k="l"]').textContent = fmtPrice(r.low);
      el.querySelector('[data-k="c"]').textContent = fmtPrice(r.close);
      el.querySelector('[data-k="v"]').textContent = fmtVol(r.volume);
      el.querySelector(".ilr-date").textContent = fmtBarTime(r.time, true) + (intraday() ? " ET" : "");
      el.classList.toggle("live", !!isLive);
    }

    paint(latest(), true);

    instance.chart.subscribeCrosshairMove(function (param) {
      if (!param || param.time == null) return;
      paint(at(param.time) || latest(), false);
    });

    /* Drive the readout from raw pointer position as well so scrubbing is
       continuous across gaps, sub-panes and the axis gutter. */
    var ts = instance.chart.timeScale();
    var host = instance.host;
    var frame = null;
    function onMove(ev) {
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
        var rows = instance.rows;
        idx = Math.max(0, Math.min(rows.length - 1, idx));
        paint(rows[idx], false);
      });
    }
    host.addEventListener("mousemove", onMove, { passive: true });

    function onLeave() {
      if (frame) { cancelAnimationFrame(frame); frame = null; }
      paint(latest(), true);
    }
    host.addEventListener("mouseleave", onLeave, { passive: true });
    instance.paintReadout = function (r) { paint(r || latest(), !r); };
    instance.disposeReadout = function () {
      if (frame) cancelAnimationFrame(frame);
      host.removeEventListener("mousemove", onMove);
      host.removeEventListener("mouseleave", onLeave);
      el.remove();
    };

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

  /* Golden and death crosses: where the 50-day average crosses the 200-day.
     Shown when both averages are on, so the marker always sits on the two
     lines it describes. ILChartCrosses is also read by chart-reads.js. */
  function findCrosses(rows, useLookback) {
    var ext = useLookback ? extendedCloses(rows) : { pre: 0, closes: rows.map(function (r) { return r.close; }) };
    var a = trim(ext, TA.sma(ext.closes, 50)), b = trim(ext, TA.sma(ext.closes, 200)), out = [];
    for (var i = 1; i < rows.length; i++) {
      if (a[i - 1] == null || b[i - 1] == null || a[i] == null || b[i] == null) continue;
      if (a[i - 1] <= b[i - 1] && a[i] > b[i]) out.push({ time: rows[i].time, kind: "golden", index: i });
      else if (a[i - 1] >= b[i - 1] && a[i] < b[i]) out.push({ time: rows[i].time, kind: "death", index: i });
    }
    return out;
  }
  window.ILChartCrosses = findCrosses;
  function crossMarkers(instance) {
    var S_ = window.S || {};
    if (!S_.inds || !S_.inds.ma50 || !S_.inds.ma200 || !instance.rows) return [];
    var p = palette();
    return findCrosses(instance.rows, true).map(function (c) {
      return {
        time: c.time, position: c.kind === "golden" ? "belowBar" : "aboveBar",
        color: c.kind === "golden" ? p.up : p.down, shape: "circle", size: 1,
        text: c.kind === "golden" ? "Golden cross" : "Death cross"
      };
    });
  }
  function setMarkers(instance, markers) {
    markers.sort(function (a, b) { return a.time - b.time; });
    try {
      if (instance._markers) instance._markers.setMarkers(markers);
      else if (markers.length) instance._markers = LWC.createSeriesMarkers(instance.series.price, markers);
    } catch (e) {}
  }

  function applyMarkers(instance) {
    if (!window.S || !S.ticker) return;
    if (!view.pins.earnings && !view.pins.news) {
      setMarkers(instance, crossMarkers(instance));
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
      if (instance.disposed) return;
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
          color: m.kind === "earnings" ? p.gold : p.ma200,
          shape: m.kind === "earnings" ? "arrowUp" : "circle",
          text: m.kind === "earnings" ? "E" : "N",
          size: 1,
          _tip: m.text
        });
      });
      setMarkers(instance, markers.concat(crossMarkers(instance)));
    });
  }

  /* Zoom by a factor, keeping the latest bar pinned to the right the way
     charting desktops do. Shared by the toolbar buttons in both views. */
  function zoomInstance(instance, f) {
    if (!instance) return;
    try {
      var ts = instance.chart.timeScale();
      var r = ts.getVisibleLogicalRange();
      if (!r) return;
      var width = Math.max(200, (instance.host.clientWidth || 900) - 64);
      var next = (r.to - r.from) / f;
      next = Math.max(12, Math.min(Math.floor(width / MIN_SPACING), next));
      var to = Math.min(r.to, instance.rows.length + 6);
      ts.setVisibleLogicalRange({ from: to - next, to: to });
      if (f < 1 && to - next < 10 && instance.frame) loadOlder(instance.frame);
    } catch (e) {}
  }

  /* ── older history on demand ───────────────────────────────────────────── */
  /* Each interval steps through longer Yahoo ranges at the SAME bar size, so a
     5-minute chart backfills with 5-minute bars rather than switching to daily.
     Yahoo keeps about 60 days of 5/30-minute bars and two years of hourly. */
  var LADDER = {
    "1m": ["1d", "5d"], "2m": ["1d", "5d", "1mo"], "5m": ["1d", "5d", "1mo"], "15m": ["1d", "5d", "1mo"],
    "30m": ["5d", "1mo"], "90m": ["5d", "1mo"],
    "60m": ["5d", "1mo", "3mo", "6mo", "1y", "2y"], "1h": ["5d", "1mo", "3mo", "6mo", "1y", "2y"],
    "1d": ["1mo", "3mo", "6mo", "1y", "2y", "5y", "10y", "max"],
    "1wk": ["1y", "2y", "5y", "10y", "max"], "1mo": ["max"], "3mo": ["max"]
  };
  var SPAN_DAYS = { "1d": 1, "5d": 5, "1mo": 31, "3mo": 92, "6mo": 183, "1y": 366, "2y": 731, "5y": 1827, "10y": 3653, "max": 1e9 };

  function liveInstances(frame) {
    var out = [];
    if (inst && inst.frame === frame && !inst.disposed) out.push(inst);
    var modal = document.getElementById("chart-expand-modal");
    var ex = modal && modal._ilExpanded;
    if (ex && ex.frame === frame && !ex.disposed) out.push(ex);
    return out;
  }
  function setLoading(frame, on) {
    liveInstances(frame).forEach(function (i) {
      var slot = i.host.parentElement;
      if (!slot) return;
      var pill = slot.querySelector(".ilc-loading");
      if (!pill) {
        pill = document.createElement("div");
        pill.className = "ilc-loading";
        pill.innerHTML = '<span></span>Loading earlier bars…';
        slot.appendChild(pill);
      }
      pill.classList.toggle("on", !!on);
    });
  }

  function loadOlder(frame) {
    if (!frame || frame.loading || frame.exhausted || !frame.rows.length) return;
    var ladder = LADDER[frame.interval] || [];
    var covered = (Date.now() / 1000 - frame.rows[0].time) / 86400;
    var next = null;
    for (var i = 0; i < ladder.length; i++) {
      if (SPAN_DAYS[ladder[i]] > covered + 1 && frame.tried.indexOf(ladder[i]) < 0) { next = ladder[i]; break; }
    }
    if (!next) {
      frame.exhausted = true;
      if (!frame.toldEnd && isIntraInterval(frame.interval)) {
        frame.toldEnd = true;
        if (typeof window.toast === "function") {
          window.toast("That is all the " + (INTERVAL_LABEL[frame.interval] || "intraday").toLowerCase() +
            " history available. Pick 1M or longer for daily bars.", "ok");
        }
      }
      return;
    }
    frame.loading = true;
    frame.tried.push(next);
    setLoading(frame, true);
    var preview = /^(127\.0\.0\.1|localhost)$/.test(location.hostname) ? "&preview=1" : "";
    fetch("/api/quote/" + encodeURIComponent(frame.ticker) + "?range=" + next + "&interval=" + frame.interval + preview,
          { credentials: "same-origin" })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (d) {
        var res = d && d.chart && d.chart.result && d.chart.result[0];
        var got = res ? rowsFrom(res) : [];
        if (lastFrame !== frame) return;              // the user moved on
        var first = frame.rows[0].time;
        var older = got.filter(function (r) { return r.time < first - 30; });
        frame.loading = false;
        setLoading(frame, false);
        if (!older.length) { loadOlder(frame); return; }  // try the next rung
        frame.rows = older.concat(frame.rows);
        liveInstances(frame).forEach(function (i) { i.setRows(frame.rows, older.length); });
        document.dispatchEvent(new CustomEvent("il:chart-history", { detail: { added: older.length, total: frame.rows.length } }));
      })
      .catch(function () {
        frame.loading = false;
        setLoading(frame, false);
      });
  }
  window.ilLoadOlderBars = function () { if (lastFrame) loadOlder(lastFrame); };

  /* Hook for chart-tools.js (drawings, legend refresh). */
  function attachTools(instance, mode) {
    instance.mode = mode;
    instance.onRows = function () {
      applyMarkers(instance);
      if (zonesOn) applyZones(instance);
      if (instance.toolsOnRows) instance.toolsOnRows();
    };
    if (window.ILChartTools && window.ILChartTools.attach) {
      try { window.ILChartTools.attach(instance, mode); } catch (e) { console.warn("[chart-tools]", e && e.message); }
    }
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
    function price(value, fallback) {
      return value != null && value !== "" && Number.isFinite(Number(value)) && Number(value) > 0 ? Number(value) : fallback;
    }
    for (var i = 0; i < n; i++) {
      var c = price(cl[i], NaN);
      if (!Number.isFinite(c)) continue;
      var t = Math.floor(Number(ts[i]));
      if (!Number.isFinite(t) || t <= 0 || seen[t]) continue;
      seen[t] = 1;
      var o = price(q.open && q.open[i], c);
      rows.push({
        time: t,
        open: o,
        high: Math.max(price(q.high && q.high[i], c), o, c),
        low: Math.min(price(q.low && q.low[i], c), o, c),
        close: c,
        volume: isFinite(Number(q.volume && q.volume[i])) ? Number(q.volume[i]) : 0
      });
    }
    rows.sort(function (a, b) { return a.time - b.time; });
    return rows;
  }

  function dispose(instance) {
    if (!instance || instance.disposed) return;
    instance.disposed = true;
    if (instance.disposeReadout) instance.disposeReadout();
    if (instance.disposeTools) instance.disposeTools();
    if (instance.chart._ilResizeObserver) instance.chart._ilResizeObserver.disconnect();
    try { instance.chart.remove(); } catch (_) {}
  }

  function render(result, closes, timestamps) {
    var host = hostFor();
    if (!host) return;
    var rows = rowsFrom(result, closes, timestamps);
    if (!rows.length) {
      dispose(inst); inst = null; lastFrame = null;
      host.textContent = "Price history is unavailable for this company.";
      return;
    }

    var interval = frameInterval(result);
    var chartKey = window.S ? S.ticker + ":" + S.range + ":" + interval : "";
    var frame = { rows: rows, result: result, base: rows[0].close, interval: interval,
                  ticker: window.S ? S.ticker : "", key: chartKey, tried: [], loading: false, exhausted: false };
    /* Re-rendering the same series (type flip, indicator toggle, theme) keeps
       the older bars the user already panned back through. */
    if (lastFrame && lastFrame.key === chartKey && lastFrame.rows.length) {
      var firstNew = rows[0].time;
      var older = lastFrame.rows.filter(function (r) { return r.time < firstNew - 30; });
      if (older.length) frame.rows = rows = older.concat(rows);
      frame.base = lastFrame.base;
      frame.tried = lastFrame.tried.slice();
      frame.exhausted = lastFrame.exhausted;
    }

    var keepRange = null;
    var prevLength = inst ? inst._ilLength : null;
    var prevKey = inst ? inst._ilKey : null;
    if (inst && inst.chart) {
      try { keepRange = inst.chart.timeScale().getVisibleLogicalRange(); } catch (e) {}
      dispose(inst);
      inst = null;
    }
    host.innerHTML = "";
    lastFrame = frame;

    inst = buildInstance(host, rows);
    inst.frame = frame;
    var rendered = inst;
    wireReadout(inst, host.parentElement);
    attachTools(inst, "inline");
    applyMarkers(inst);
    if (zonesOn) fetchZones(function () { if (inst) applyZones(inst); });

    /* Restore the user's zoom only when the bars are the same — they flipped
       candle→line or toggled an indicator. A new timeframe opens fresh. */
    if (keepRange && prevLength === rows.length && prevKey === chartKey) {
      inst.chart._ilViewLocked = true;
      try { inst.chart.timeScale().setVisibleLogicalRange(keepRange); } catch (e) {}
      requestAnimationFrame(function () {
        requestAnimationFrame(function () {
          try { if (!rendered.disposed) rendered.chart.timeScale().setVisibleLogicalRange(keepRange); } catch (e) {}
        });
      });
    }
    inst._ilLength = rows.length;
    inst._ilKey = chartKey;
    window.__ilChart = inst;   // debug + integration handle

    setTimeout(function () { if (!rendered.disposed) mirrorToCanvas(rendered); }, 260);

    /* keep existing callers alive */
    if (window.S) {
      S.charts = S.charts || {};
      S.charts["price-chart"] = {
        _il: true,
        destroy: function () { dispose(rendered); if (inst === rendered) inst = null; },
        resetZoom: function () { try { inst.applyInitialView(); } catch (e) { try { inst.chart.timeScale().fitContent(); } catch (e2) {} } },
        zoom: function (f) { zoomInstance(inst, f); },
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
    if (instance._ilZonePrim) {
      try { instance.series.price.detachPrimitive(instance._ilZonePrim); } catch (e) {}
      instance._ilZonePrim = null;
    }
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

    function tint(hex, a) {
      var m = String(hex || "").match(/^#?([0-9a-f]{6})$/i);
      if (!m) return hex;
      var n = parseInt(m[1], 16);
      return "rgba(" + (n >> 16 & 255) + "," + (n >> 8 & 255) + "," + (n & 255) + "," + a + ")";
    }
    function add(price, color, title, style, width, label) {
      if (price == null || !isFinite(Number(price))) return;
      try {
        lines.push(instance.series.price.createPriceLine({
          price: Number(price), color: color, lineWidth: width || 1,
          lineStyle: style == null ? 2 : style,
          axisLabelVisible: !!label, title: label ? title : ""
        }));
      } catch (e) {}
    }

    /* Only the nearest buy and sell zones are labelled; deeper levels and the
       retracement band are faint guides, so the chart stays readable. */
    var z = setup.zones || {};
    (z.buyer || []).slice(0, 3).forEach(function (g, i) {
      add(g.price, i === 0 ? p.up : tint(p.up, .38), "Buy zone", 2, 1, i === 0);
    });
    (z.seller || []).slice(0, 3).forEach(function (g, i) {
      add(g.price, i === 0 ? p.down : tint(p.down, .38), "Sell zone", 2, 1, i === 0);
    });

    var fib = setup.retracement;
    if (fib) {
      add(fib.upper, tint(p.gold, .35), "", 3, 1, false);
      add(fib.lower, tint(p.gold, .35), "", 3, 1, false);
    }
    instance._ilZoneLines = lines;

    /* Shaded bands: each zone is a price shelf, not a single line, so paint
       its width (half the clustering tolerance either side). */
    var band = Number(z.band) || 0;
    if (band > 0) {
      var rects = [];
      (z.buyer || []).slice(0, 3).forEach(function (g, i) { rects.push({ lo: g.price - band, hi: g.price + band, color: p.up, a: i === 0 ? .16 : .07 }); });
      (z.seller || []).slice(0, 3).forEach(function (g, i) { rects.push({ lo: g.price - band, hi: g.price + band, color: p.down, a: i === 0 ? .16 : .07 }); });
      var req = null;
      var renderer = { draw: function (target) {
        target.useMediaCoordinateSpace(function (scope) {
          var ctx = scope.context, w = scope.mediaSize.width;
          rects.forEach(function (r) {
            var y1 = instance.series.price.priceToCoordinate(r.hi), y2 = instance.series.price.priceToCoordinate(r.lo);
            if (y1 == null || y2 == null) return;
            ctx.fillStyle = tint(r.color, r.a);
            ctx.fillRect(0, Math.min(y1, y2), w, Math.max(2, Math.abs(y2 - y1)));
          });
        });
      } };
      var view_ = { zOrder: function () { return "bottom"; }, renderer: function () { return renderer; } };
      var prim = {
        attached: function (q) { req = q.requestUpdate; }, detached: function () { req = null; },
        updateAllViews: function () {}, paneViews: function () { return [view_]; }
      };
      try { instance.series.price.attachPrimitive(prim); instance._ilZonePrim = prim; } catch (e) {}
    }

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
        text: kind === "bullish" ? "Div" : "Div"
      });
    }
    if (div.bullish) markAt(div.bullish.toIndex, "bullish");
    if (div.bearish) markAt(div.bearish.toIndex, "bearish");
    if (marks.length && window.LWC && LWC.createSeriesMarkers) {
      try { instance._ilZoneMarkers = LWC.createSeriesMarkers(instance.series.price, marks); } catch (e) {}
    }
  }

  var zoneCache = {};
  var zonesKey = null;
  function fetchZones(then) {
    if (!window.S || !S.ticker) return;
    var key = S.ticker + ":" + (S.range || "1y");
    if (zonesKey !== key) { window.__ilLensZones = null; zonesKey = key; }
    if (zoneCache[key]) { window.__ilLensZones = zoneCache[key]; then && then(); return; }
    fetch("/api/analysis/" + encodeURIComponent(S.ticker) + "?range=" + encodeURIComponent(S.range || "1y"),
          { credentials: "same-origin" })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (j) {
        var z = j && j.lensSetup && j.lensSetup.ok ? j.lensSetup : null;
        if (!z) return;
        zoneCache[key] = z;
        if (!window.S || S.ticker + ":" + (S.range || "1y") !== key) return;
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
    if (zonesOn) fetchZones(paint); else paint();
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

  /* The full-screen header names the company, not "Price Chart". */
  function setExpandedTitle(modal) {
    var t = document.getElementById("cex-title");
    if (!t) return;
    var lg = legendText();
    if (!lg.ticker) { t.textContent = modal.dataset.chartTitle || "Price chart"; return; }
    t.innerHTML = "";
    var b = document.createElement("b"); b.className = "ilc-title-tk"; b.textContent = lg.ticker;
    var n = document.createElement("span"); n.className = "ilc-title-nm"; n.textContent = lg.name || "Price chart";
    var m = document.createElement("span"); m.className = "ilc-title-meta"; m.textContent = lg.meta;
    t.appendChild(b); t.appendChild(n); t.appendChild(m);
    t.title = [lg.ticker, lg.name, lg.meta].filter(Boolean).join(" · ");
  }

  /* ── take over the global entry points ─────────────────────────────────── */
  function install() {
    // A slow connection can fire the fallback timer before the legacy script
    // arrives. Installing then is overwritten by its function declarations.
    if (!window.S || typeof window.buildPriceChart !== "function") return;
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
      if (inst) return zoomInstance(inst, factor);
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
      /* Above the site navigation (z 2147482000), which otherwise covered the
         modal header — and its Close button — on phones. Inline !important is
         what outranks the bundled layers. */
      modal.style.setProperty("z-index", "2147483050", "important");
      setExpandedTitle(modal);
      document.body.style.overflow = "hidden";

      if (window.ILChartTools && window.ILChartTools.mountFullBar) window.ILChartTools.mountFullBar(modal);
      else buildExpandedControls(modal);
      mountExpanded(modal);
      document.dispatchEvent(new CustomEvent("il-chart-expanded"));
    };

    function mountExpanded(modal) {
      var slot = modal.querySelector(".cex-workspace") || modal.querySelector(".cex-body") || modal;
      if (modal._ilExpanded) {
        dispose(modal._ilExpanded);
        modal._ilExpanded = null;
      }
      var oldStage = slot.querySelector(".il-chart-stage");
      if (oldStage) oldStage.remove();
      var old = slot.querySelector(".il-chart-host-expanded");
      if (old) old.remove();
      var stage = document.createElement("div");
      stage.className = "il-chart-stage";
      var host = document.createElement("div");
      host.className = "il-chart-host-expanded";
      stage.appendChild(host);
      slot.appendChild(stage);

      /* The modal is display:none until .open lands, so the host measures 0x0
         on this frame. Building an LWC chart into a zero box produces a chart
         that never draws. Wait two frames for layout to settle. */
      requestAnimationFrame(function () {
        requestAnimationFrame(function () {
          if (!document.body.contains(host) || !lastFrame) return;
          var ex = buildInstance(host, lastFrame.rows);
          ex.frame = lastFrame;
          wireReadout(ex, stage);
          attachTools(ex, "full");
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
        if (window.ILChartTools && window.ILChartTools.syncBars) window.ILChartTools.syncBars();
        else buildExpandedControls(modal, true);
        setExpandedTitle(modal);
        mountExpanded(modal);
      }
    });

    var prevClose = window.closeExpandModal;
    window.closeExpandModal = function () {
      var modal = document.getElementById("chart-expand-modal");
      if (modal && modal._ilExpanded) {
        dispose(modal._ilExpanded);
        modal._ilExpanded = null;
        var h = modal.querySelector(".il-chart-stage") || modal.querySelector(".il-chart-host-expanded");
        if (h) h.remove();
      }
      if (modal) modal.classList.remove("il-lwc");
      if (window.ILChartTools && window.ILChartTools.releaseFull) window.ILChartTools.releaseFull(modal);
      if (typeof prevClose === "function") return prevClose.apply(this, arguments);
      if (modal) { modal.classList.remove("open"); document.body.style.overflow = ""; }
    };

    /* Zoom / reset inside the modal must drive the modal's own instance. */
    var prevZoomEx = window.zoomExpandedChart;
    window.zoomExpandedChart = function (f) {
      var modal = document.getElementById("chart-expand-modal");
      var ex = modal && modal._ilExpanded;
      if (!ex) return typeof prevZoomEx === "function" ? prevZoomEx.apply(this, arguments) : undefined;
      zoomInstance(ex, f);
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
    liveInstances(lastFrame).forEach(applyMarkers);
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

  /* Integration surface for chart-tools.js and share-studio.js. */
  window.ILChartEngine = {
    instances: function () { return liveInstances(lastFrame); },
    frame: function () { return lastFrame; },
    legend: legendText,
    palette: palette,
    zoom: function (instance, f) { zoomInstance(instance, f); },
    reset: function (instance) { try { instance.applyInitialView(); } catch (e) {} },
    loadOlder: function () { if (lastFrame) loadOlder(lastFrame); },
    fmtTime: fmtBarTime,
    intraday: intraday,
    intervalLabel: function () { return INTERVAL_LABEL[currentInterval()] || ""; },
    rangeLabel: rangeLabel,
    sma: function (rows, p) { var ext = extendedCloses(rows); return trim(ext, TA.sma(ext.closes, p)); },
    ema: function (rows, p) { var ext = extendedCloses(rows); return trim(ext, TA.ema(ext.closes, p)); },
    view: view,
    zonesOn: function () { return zonesOn; }
  };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", install);
  } else { install(); }
  setTimeout(install, 900);   // matches workspace-system.js's late-install fallback
})();

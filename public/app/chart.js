/* ═══════════════════════════════════════════════════════════════════════════
   Price chart for the stock page, drawn by the site's own engine (ilchart.js).

   One component, no globals beyond window.IL.PriceChart. Daily ranges share a
   single two-year daily series so switching between 1M, 6M, YTD and 1Y is
   instant and the 50- and 200-day averages are correct at the left edge of
   every view. 1D and 5D load intraday bars; 5Y uses weekly bars and Max
   monthly bars, where the averages are hidden because they would mean
   something different.

   A range button is a starting window into the loaded bars, not a hard cut:
   drag to move back through them, zoom in or out, and the figure above the
   chart follows what is in view. Double-click returns to the range.
   ═══════════════════════════════════════════════════════════════════════════ */
(function () {
  "use strict";
  var IL = window.IL;
  var RANGES = [
    { key: "1D", fetch: "1d", intraday: true },
    { key: "5D", fetch: "5d", intraday: true },
    { key: "1M", fetch: "2y", days: 31 },
    { key: "6M", fetch: "2y", days: 183 },
    { key: "YTD", fetch: "2y", ytd: true },
    { key: "1Y", fetch: "2y", days: 364 },
    { key: "5Y", fetch: "5y", weekly: true },
    { key: "Max", fetch: "max", monthly: true },
  ];

  function css(name) { return getComputedStyle(document.documentElement).getPropertyValue(name).trim(); }
  /* A token colour at a given opacity, whatever form the token is written in. */
  function alpha(color, a) {
    var m = /^#([0-9a-f]{3}|[0-9a-f]{6})$/i.exec(color);
    if (m) {
      var x = m[1].length === 3 ? m[1].replace(/./g, "$&$&") : m[1];
      return "rgba(" + parseInt(x.slice(0, 2), 16) + "," + parseInt(x.slice(2, 4), 16) + "," + parseInt(x.slice(4, 6), 16) + "," + a + ")";
    }
    m = /^rgba?\(\s*([\d.]+)[\s,]+([\d.]+)[\s,]+([\d.]+)/i.exec(color);
    return m ? "rgba(" + m[1] + "," + m[2] + "," + m[3] + "," + a + ")" : color;
  }
  IL.alpha = alpha;

  function seriesFrom(json) {
    var r = json && json.chart && json.chart.result && json.chart.result[0];
    if (!r || !r.timestamp) return { bars: [], meta: {} };
    var q = (r.indicators && r.indicators.quote && r.indicators.quote[0]) || {};
    var bars = [];
    var last = -1;
    for (var i = 0; i < r.timestamp.length; i++) {
      var c = Number(q.close && q.close[i]);
      if (!(c > 0)) continue;
      var t = r.timestamp[i];
      if (t <= last) continue;
      last = t;
      var o = Number(q.open && q.open[i]), h = Number(q.high && q.high[i]), l = Number(q.low && q.low[i]);
      bars.push({
        time: t, close: c,
        open: o > 0 ? o : c, high: h > 0 ? h : c, low: l > 0 ? l : c,
        volume: Number(q.volume && q.volume[i]) || 0,
      });
    }
    return { bars: bars, meta: r.meta || {} };
  }
  function sma(bars, n) {
    var out = [], sum = 0;
    for (var i = 0; i < bars.length; i++) {
      sum += bars[i].close;
      if (i >= n) sum -= bars[i - n].close;
      if (i >= n - 1) out.push({ time: bars[i].time, value: sum / n });
    }
    return out;
  }
  function rsi(bars, n) {
    n = n || 14;
    var out = [], gain = 0, loss = 0;
    for (var i = 1; i < bars.length; i++) {
      var d = bars[i].close - bars[i - 1].close;
      var g = d > 0 ? d : 0, l = d < 0 ? -d : 0;
      if (i <= n) { gain += g; loss += l; if (i === n) { gain /= n; loss /= n; } }
      else { gain = (gain * (n - 1) + g) / n; loss = (loss * (n - 1) + l) / n; }
      if (i >= n) out.push({ time: bars[i].time, value: loss === 0 ? 100 : 100 - 100 / (1 + gain / loss) });
    }
    return out;
  }
  IL.sma = sma;
  IL.seriesFrom = seriesFrom;

  var ET = "America/New_York";
  function fmtTime(t, intraday) {
    var d = new Date(t * 1000);
    return intraday
      ? d.toLocaleString("en-US", { month: "short", day: "numeric", hour: "numeric", minute: "2-digit", timeZone: ET }) + " ET"
      : d.toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric", timeZone: ET });
  }
  /* Whole dollars when the gridlines are whole dollars, cents otherwise. */
  function fmtAxis(p, step) {
    var d = step >= 1 && step % 1 === 0 ? 0 : 2;
    return "$" + p.toLocaleString("en-US", { minimumFractionDigits: d, maximumFractionDigits: d });
  }
  /* An average or an RSI as one value per bar, blank until there is enough history. */
  function aligned(points, bars) {
    var out = new Array(bars.length).fill(NaN), at = bars.length - points.length;
    for (var i = 0; i < points.length; i++) out[at + i] = points[i].value;
    return out;
  }
  function vol(v) { var a = Math.abs(v), s = v < 0 ? "−" : ""; return s + (a >= 1e9 ? (a / 1e9).toFixed(2) + "B" : a >= 1e6 ? (a / 1e6).toFixed(1) + "M" : a >= 1e3 ? (a / 1e3).toFixed(0) + "K" : String(Math.round(a))); }
  function n2(v) { return isFinite(v) ? v.toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 }) : "—"; }
  function n0(v) { return isFinite(v) ? v.toFixed(0) : "—"; }

  /* ── Indicators ─────────────────────────────────────────────────────────
     Overlays sit on the price and use daily bars (their names say "day").
     Panes sit below the price and work on any bars except intraday. Each has
     a one-line explanation for someone who has never seen it. The maths is
     in indicators.js (IL.ind), tested on its own. */
  var OVERLAYS = [
    { k: "ma20", label: "20-day average", color: "--chart-s3", tip: "Average close over the last 20 trading days (about a month). Short-term trend: price above it is climbing faster than its recent norm." },
    { k: "ma50", label: "50-day average", color: "--text2", tip: "Average close over the last 50 trading days. Price above it is a sign of a short-term uptrend." },
    { k: "ma200", label: "200-day average", color: "--blue", tip: "Average close over roughly the last year. Many investors treat price above it as a long-term uptrend; the 50-day crossing above it is called a golden cross, below it a death cross." },
    { k: "ema9", label: "9-day EMA", color: "--chart-s4", tip: "Exponential moving average: like an average, but recent days count more, so it turns sooner. Traders use the 9-day for very short-term direction." },
    { k: "ema21", label: "21-day EMA", color: "--chart-s4", dash: [5, 4], tip: "Exponential average over about a month of trading. Pullbacks to it in an uptrend are a common place traders look for entries." },
    { k: "bb", label: "Bollinger Bands (20, 2)", color: "--text3", tip: "A band two standard deviations either side of the 20-day average. It widens when the price swings more and narrows when it is calm; a close outside the band is unusual." },
  ];
  var PANES = [
    { k: "rsi", label: "RSI (14)", tip: "Relative Strength Index, 0–100: how strong recent gains are against recent losses. Above 70 has risen fast (overbought); below 30 has fallen fast (oversold)." },
    { k: "macd", label: "MACD (12, 26, 9)", tip: "The gap between a 12-day and a 26-day exponential average, with a 9-day signal line. The bars show the gap minus the signal: growing bars mean momentum is building in that direction." },
    { k: "stoch", label: "Stochastic (14, 3, 3)", tip: "Where the close sits within the last 14 days' high–low range, 0–100, smoothed. Above 80 is near the top of its range, below 20 near the bottom." },
    { k: "atr", label: "ATR (14)", tip: "Average True Range: how far the price typically moves in a day, in dollars, including gaps between days. Useful for sizing a stop-loss or a position." },
    { k: "adx", label: "ADX (14)", tip: "Average Directional Index: how strong the trend is, not its direction. Above 25 is a trending market, below 20 a sideways one. +DI above −DI means buyers lead." },
    { k: "obv", label: "On-balance volume", tip: "A running total of volume, added on up days and taken away on down days. Rising OBV while the price is flat can mean buyers are quietly accumulating." },
  ];

  IL.PriceChart = function (root, opts) {
    opts = opts || {};
    var ticker = opts.ticker;
    var store = {};          // fetch key → {bars, meta}
    var state = {
      range: opts.range || "1Y", type: "area",
      show: { ma50: true, ma200: true, volume: true },
    };
    try {
      var saved = JSON.parse(localStorage.getItem("il-chart") || "null");
      if (saved && saved.show) state.show = Object.assign(state.show, saved.show);
      if (saved && saved.type) state.type = saved.type;
      if (saved && saved.range && RANGES.some(function (r) { return r.key === saved.range; })) state.range = saved.range;
    } catch (_) {}
    function persist() { try { localStorage.setItem("il-chart", JSON.stringify({ show: state.show, type: state.type, range: state.range })); } catch (_) {} }

    root.innerHTML =
      '<div class="pc-bar">' +
        '<div class="seg" role="group" aria-label="Time range">' + RANGES.map(function (r) {
          return '<button type="button" data-range="' + r.key + '" aria-pressed="' + (r.key === state.range) + '">' + r.key + "</button>";
        }).join("") + "</div>" +
        '<div class="pc-tools">' +
          '<span class="pc-legend" id="pc-legend"></span>' +
          '<div class="seg" role="group" aria-label="Chart type"><button type="button" data-type="area" aria-pressed="' + (state.type === "area") + '">Line</button><button type="button" data-type="candles" aria-pressed="' + (state.type === "candles") + '">Candles</button></div>' +
          '<div class="pc-ind"><button type="button" class="btn sm" id="pc-ind-btn" aria-haspopup="true" aria-expanded="false">Indicators</button>' +
            '<div class="il-menu pc-ind-menu" id="pc-ind-menu" hidden>' +
              '<div class="pc-ind-h">On the price</div>' +
              OVERLAYS.map(function (o) { return ind(o.k, o.label, o.tip, o.color, o.dash); }).join("") +
              ind("volume", "Volume", "Shares traded each day. Big moves on heavy volume carry more weight.") +
              '<div class="pc-ind-h">Below the chart</div>' +
              PANES.map(function (o) { return ind(o.k, o.label, o.tip); }).join("") +
              '<button type="button" class="pc-ind-clear" id="pc-ind-clear">Clear indicators</button>' +
            "</div></div>" +
        "</div>" +
      "</div>" +
      '<div class="pc-head" id="pc-head"></div>' +
      '<div class="pc-canvas" id="pc-canvas"><div class="pc-loading"><span class="sk" style="height:100%"></span></div></div>' +
      '<p class="note pc-note" id="pc-note"></p>';

    function ind(key, label, tip, color, dash) {
      var sw = color ? '<i class="pc-sw' + (dash ? " dash" : "") + '" style="--sw:var(' + color + ')"></i>' : "";
      return '<label class="pc-check"><input type="checkbox" data-ind="' + key + '"' + (state.show[key] ? " checked" : "") + "><span>" + sw + label + "</span>" + IL.tip(tip) + "</label>";
    }

    var canvas = root.querySelector("#pc-canvas");
    var chart = null, current = null, drawn = null;      // drawn: what the chart holds now
    var view = null, at = null;                          // the window in view; the bar being read

    function build() {
      if (chart || !IL.Chart) return;
      chart = IL.Chart(canvas, {
        label: ticker + " price chart. Arrow keys read each bar; plus and minus zoom; zero resets.",
        onView: function (v) {
          view = v;
          root.querySelectorAll("[data-range]").forEach(function (x) { x.setAttribute("aria-pressed", String(v.atHome && x.getAttribute("data-range") === state.range)); });
          header();
        },
        onCross: function (i) { at = i; header(); legend(); },
        describe: function (i) {
          var b = current && current.bars[i]; if (!b) return "";
          return fmtTime(b.time, spec().intraday) + ": " + IL.fmt.price(b.close);
        },
      });
    }

    function spec() { return RANGES.filter(function (r) { return r.key === state.range; })[0] || RANGES[5]; }

    /* The first bar of the range: anchored on the close on or before the
       start, like every "past year" figure on the site. */
    function startOf(all, r) {
      if (!all.length || !(r.days || r.ytd)) return 0;
      if (!r.ytd) return IL.windowStart(all, r.days);
      var start = Date.UTC(new Date(all[all.length - 1].time * 1000).getUTCFullYear(), 0, 1) / 1000;
      for (var i = 0; i < all.length; i++) if (all[i].time >= start) return i;
      return 0;
    }

    /* keep: same bars, only the look changed (type or an indicator), so the
       window stays where the reader left it. */
    function draw(keep) {
      if (!current || !chart) return;
      var r = spec(), all = current.bars;
      if (!all.length) return;
      var daily = !!(r.days || r.ytd), candles = state.type === "candles";
      var close = all.map(function (b) { return b.close; }), series = [], panes = [], lines = [];
      if (state.show.volume) {
        /* Candles colour volume by the day's direction, like the candles
           themselves. The line view keeps it neutral: colour there would be a
           second, unlabelled encoding under a single gold line. */
        var gs = alpha(css("--gain"), 0.4), ls = alpha(css("--loss"), 0.4), ns = alpha(css("--text3"), 0.32);
        series.push({ id: "vol", kind: "hist", v: all.map(function (b) { return b.volume; }),
          colors: function (i) { return !candles ? ns : all[i].close >= (i ? all[i - 1].close : all[i].open) ? gs : ls; } });
      }
      var I = IL.ind, phone = root.clientWidth < 560, PH = phone ? 78 : 92;
      if (daily && I) {
        if (state.show.bb) {
          var bb = I.bollinger(all, 20, 2);
          series.push({ id: "bb", kind: "band", v: bb.upper, lo: bb.lower, color: "--text3", wash: 0.08 });
          series.push({ id: "bbu", kind: "line", v: bb.upper, color: "--text3", width: 1 }, { id: "bbl", kind: "line", v: bb.lower, color: "--text3", width: 1 });
        }
        if (state.show.ma200) series.push({ id: "ma200", kind: "line", v: I.sma(all, 200), color: "--blue", width: 1.5 });
        if (state.show.ma50) series.push({ id: "ma50", kind: "line", v: I.sma(all, 50), color: "--text2", width: 1.5 });
        if (state.show.ma20) series.push({ id: "ma20", kind: "line", v: I.sma(all, 20), color: "--chart-s3", width: 1.5 });
        if (state.show.ema21) series.push({ id: "ema21", kind: "line", v: I.ema(all, 21), color: "--chart-s4", width: 1.5, dash: [5, 4] });
        if (state.show.ema9) series.push({ id: "ema9", kind: "line", v: I.ema(all, 9), color: "--chart-s4", width: 1.5 });
      }
      if (candles) {
        series.push({ id: "px", kind: "candles", v: close, tag: true, fmt: IL.fmt.price,
          o: all.map(function (b) { return b.open; }), h: all.map(function (b) { return b.high; }), l: all.map(function (b) { return b.low; }) });
      } else {
        /* The brand line over one flat tint (rulebook 4: no gradients on
           data). Up or down shows in the header, not the fill. */
        series.push({ id: "px", kind: "area", v: close, color: css("--chart-brand") ? "--chart-brand" : "--gold", width: 2, wash: 0.09, tag: true, marker: true, fmt: IL.fmt.price });
      }
      var paneOn = !r.intraday && I, pct0 = function (v) { return v.toFixed(0); };
      if (paneOn && state.show.rsi) {
        var rs = I.rsi(all, 14);
        panes.push({ id: "rsi", height: PH, min: 0, max: 100, ticks: [30, 70], fmt: pct0, label: function (i) { return "RSI 14  " + n0(rs[i]); } });
        series.push({ id: "rsi", pane: "rsi", kind: "line", v: rs, color: "--text2", width: 1.5, tag: true, fmt: pct0 });
        lines.push({ pane: "rsi", value: 70, dash: [3, 3] }, { pane: "rsi", value: 30, dash: [3, 3] });
      }
      if (paneOn && state.show.macd) {
        var m = I.macd(all), gp = alpha(css("--gain"), 0.55), lp = alpha(css("--loss"), 0.55);
        panes.push({ id: "macd", height: PH, fmt: function (v) { return v.toFixed(Math.abs(v) < 1 ? 2 : 1); },
          label: function (i) { return "MACD 12, 26, 9  " + n2(m.macd[i]) + "  signal " + n2(m.signal[i]) + "  bars " + n2(m.hist[i]); } });
        series.push({ id: "macdh", pane: "macd", kind: "bars", v: m.hist, colors: function (i) { return m.hist[i] >= 0 ? gp : lp; } });
        series.push({ id: "macd", pane: "macd", kind: "line", v: m.macd, color: "--text", width: 1.5 });
        series.push({ id: "macds", pane: "macd", kind: "line", v: m.signal, color: "--chart-s3", width: 1.25 });
        lines.push({ pane: "macd", value: 0 });
      }
      if (paneOn && state.show.stoch) {
        var st = I.stochastic(all);
        panes.push({ id: "stoch", height: PH, min: 0, max: 100, ticks: [20, 80], fmt: pct0, label: function (i) { return "Stochastic 14, 3, 3  %K " + n0(st.k[i]) + "  %D " + n0(st.d[i]); } });
        series.push({ id: "stk", pane: "stoch", kind: "line", v: st.k, color: "--text", width: 1.5, tag: true, fmt: pct0 });
        series.push({ id: "std", pane: "stoch", kind: "line", v: st.d, color: "--chart-s3", width: 1.25, dash: [4, 3] });
        lines.push({ pane: "stoch", value: 80, dash: [3, 3] }, { pane: "stoch", value: 20, dash: [3, 3] });
      }
      if (paneOn && state.show.atr) {
        var at14 = I.atr(all, 14);
        panes.push({ id: "atr", height: PH, fmt: function (v) { return "$" + n2(v); },
          label: function (i) { return "ATR 14  $" + n2(at14[i]) + (all[i] && all[i].close ? "  (" + (at14[i] / all[i].close * 100).toFixed(1) + "% of price)" : ""); } });
        series.push({ id: "atr", pane: "atr", kind: "line", v: at14, color: "--text2", width: 1.5 });
      }
      if (paneOn && state.show.adx) {
        var ax = I.adx(all, 14);
        panes.push({ id: "adx", height: PH, min: 0, max: 70, ticks: [20, 40], fmt: pct0,
          label: function (i) { return "ADX 14  " + n0(ax.adx[i]) + "  +DI " + n0(ax.plusDI[i]) + "  −DI " + n0(ax.minusDI[i]); } });
        series.push({ id: "adx", pane: "adx", kind: "line", v: ax.adx, color: "--text", width: 1.75, tag: true, fmt: pct0 });
        series.push({ id: "pdi", pane: "adx", kind: "line", v: ax.plusDI, color: "--chart-s2", width: 1.1 });
        series.push({ id: "mdi", pane: "adx", kind: "line", v: ax.minusDI, color: "--chart-s3", width: 1.1 });
        lines.push({ pane: "adx", value: 25, dash: [3, 3] });
      }
      if (paneOn && state.show.obv) {
        var ob = I.obv(all);
        panes.push({ id: "obv", height: PH, fmt: function (v) { return vol(v); }, label: function (i) { return "On-balance volume  " + vol(ob[i]); } });
        series.push({ id: "obv", pane: "obv", kind: "line", v: ob, color: "--text2", width: 1.5 });
      }
      /* The chart grows with each pane, so the price keeps its height. */
      canvas.style.height = ((phone ? 280 : 360) + panes.reduce(function (t, p) { return t + p.height + 1; }, 0)) + "px";
      var same = keep && drawn === current;
      drawn = current; at = null;
      chart.set({ times: all.map(function (b) { return b.time; }), series: series, panes: panes, lines: lines,
        floor: 0, fmtY: fmtAxis, fmtTime: function (t) { return fmtTime(t, r.intraday); } },
        same ? { keep: true } : { show: startOf(all, r) });
      legend();
      source(r);
    }

    /* What the bars are and where they came from. Written on every draw, so it
       stays right when a range comes from the cache or the chart type changes. */
    function source(r) {
      var note = root.querySelector("#pc-note"), pv = current && current.provenance;
      if (!note) return;
      var unit = state.type === "candles" ? "bars" : "closes";
      var what = r.intraday ? "Intraday " + (state.type === "candles" ? "bars" : "prices") + ", times in Eastern Time."
        : (r.monthly ? "Monthly " : r.weekly ? "Weekly " : "Daily ") + unit + ".";
      var touch = window.matchMedia && window.matchMedia("(hover: none)").matches;
      note.textContent = "Prices: " + ((pv && pv.source) || "market data") + ". " + what + " Delayed at least 15 minutes during market hours. " +
        (touch ? "Drag to move, pinch to zoom, double-tap to reset." : "Drag to move, scroll or pinch to zoom, double-click to reset.");
    }

    function legend() {
      var el = root.querySelector("#pc-legend"), r = spec();
      var daily = !!(r.days || r.ytd), parts = [];
      if (daily) OVERLAYS.forEach(function (o) {
        if (!state.show[o.k]) return;
        var v = NaN, txt = "";
        if (at !== null && chart) {
          if (o.k === "bb") { var u = chart.val("bbu", at), l = chart.val("bbl", at); if (isFinite(u) && isFinite(l)) txt = IL.fmt.price(l) + "–" + IL.fmt.price(u); }
          else { v = chart.val(o.k, at); if (isFinite(v)) txt = IL.fmt.price(v); }
        }
        parts.push('<span class="pc-key"><i class="pc-sw' + (o.dash ? " dash" : "") + '" style="--sw:var(' + o.color + ')"></i>' + o.label.replace(" average", " avg") + (txt ? ' <b class="num">' + txt + "</b>" : "") + "</span>");
      });
      el.innerHTML = parts.join("");
    }

    /* The line above the chart: the change over whatever is in view, or the
       bar being read. At the range's own window it uses the range's name and
       base, so "Past year" here equals "Past year" everywhere else. */
    function header() {
      var el = root.querySelector("#pc-head"), r = spec();
      if (!current || !view || !current.bars.length) { el.innerHTML = ""; return; }
      var all = current.bars, first = all[view.i0], last = all[view.i1], h = IL.h, F = IL.fmt;
      if (!first || !last) { el.innerHTML = ""; return; }
      if (at !== null && all[at]) {
        var b = all[at], chg = b.close - first.close, n2 = function (v) { return v.toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 }); };
        /* A phone has one line for this, so it gets the short form and the chart does not jump. */
        if (root.clientWidth < 560) {
          el.innerHTML = state.type === "candles"
            ? '<span class="faint">' + h(fmtTime(b.time, r.intraday).replace(/, \d{4}$/, "")) + '</span><span class="num pc-ohlc">O ' + n2(b.open) + " H " + n2(b.high) + " L " + n2(b.low) + " C " + n2(b.close) + "</span>"
            : '<span class="num pc-px">' + F.price(b.close) + '</span><span class="num ' + F.cls(chg) + '">' + F.spct(chg / first.close * 100) + '</span><span class="faint">' + h(fmtTime(b.time, r.intraday)) + "</span>";
          return;
        }
        el.innerHTML = '<span class="num pc-px">' + F.price(b.close) + '</span><span class="num ' + F.cls(chg) + '">' + F.spct(chg / first.close * 100) + " since " + h(fmtTime(first.time, r.intraday)) + '</span><span class="faint">' + h(fmtTime(b.time, r.intraday)) + "</span>" +
          (state.type === "candles" ? '<span class="faint num pc-ohlc">O ' + F.price(b.open) + " · H " + F.price(b.high) + " · L " + F.price(b.low) + " · C " + F.price(b.close) + "</span>" : "") +
          (state.show.volume && b.volume ? '<span class="faint num">Vol ' + vol(b.volume) + "</span>" : "");
        return;
      }
      var name, base = first.close;
      if (view.atHome) {
        name = r.key === "Max" ? "All time" : r.key === "YTD" ? "Year to date" : "Past " + ({ "1D": "day", "5D": "5 days", "1M": "month", "6M": "6 months", "1Y": "year", "5Y": "5 years" }[r.key]);
        if (r.key === "1D" && current.meta && current.meta.chartPreviousClose) base = Number(current.meta.chartPreviousClose);
      } else name = fmtTime(first.time, r.intraday) + " to " + fmtTime(last.time, r.intraday);
      var d = last.close - base;
      el.innerHTML = '<span class="faint">' + h(name) + '</span><span class="num ' + F.cls(d) + '">' + F.schg(d) + " (" + F.spct(d / base * 100, 2) + ")</span>";
    }

    function load() {
      var r = spec();
      var key = r.fetch;
      if (store[key]) { current = store[key]; build(); draw(); return Promise.resolve(); }
      return IL.api("/api/quote/" + encodeURIComponent(ticker) + "?range=" + key).then(function (res) {
        if (!res.ok) {
          if (opts.onError) opts.onError(res);
          if (chart) { chart.destroy(); chart = null; drawn = null; }
          canvas.innerHTML = '<div class="empty">' + (res.gate ? "" : "Price history is unavailable for this range right now.") + "</div>";
          if (res.gate) canvas.innerHTML = IL.gate(res.gate, null, { center: true });
          root.querySelector("#pc-head").innerHTML = "";
          return;
        }
        store[key] = seriesFrom(res.data);
        store[key].provenance = res.data.impliedLens || null;
        if (spec().fetch !== key) return;               // another range was picked while this one loaded
        current = store[key];
        if (!chart) build();
        if (!chart) { canvas.innerHTML = '<div class="empty">The chart did not load. Refresh to try again.</div>'; return; }
        draw();
      });
    }

    root.addEventListener("click", function (e) {
      var b = e.target.closest("[data-range]");
      if (b) {
        var was = spec();
        state.range = b.getAttribute("data-range"); persist();
        root.querySelectorAll("[data-range]").forEach(function (x) { x.setAttribute("aria-pressed", String(x === b)); });
        /* Ranges that share bars glide from one window to the next. */
        var r = spec();
        if (chart && drawn && drawn === store[r.fetch] && was.fetch === r.fetch) { chart.show(startOf(drawn.bars, r), { animate: true }); header(); return; }
        load();
        return;
      }
      var t = e.target.closest("[data-type]");
      if (t) {
        state.type = t.getAttribute("data-type"); persist();
        root.querySelectorAll("[data-type]").forEach(function (x) { x.setAttribute("aria-pressed", String(x === t)); });
        draw(true);
        return;
      }
      if (e.target.closest("#pc-ind-btn")) {
        var m = root.querySelector("#pc-ind-menu");
        m.hidden = !m.hidden;
        root.querySelector("#pc-ind-btn").setAttribute("aria-expanded", String(!m.hidden));
        e.stopPropagation();
      }
    });
    root.addEventListener("click", function (e) {
      if (!e.target.closest("#pc-ind-clear")) return;
      Object.keys(state.show).forEach(function (k) { state.show[k] = k === "volume" ? state.show[k] : false; });
      root.querySelectorAll("[data-ind]").forEach(function (x) { x.checked = !!state.show[x.getAttribute("data-ind")]; });
      persist(); draw(true);
    });
    root.addEventListener("change", function (e) {
      var k = e.target.getAttribute && e.target.getAttribute("data-ind");
      if (!k) return;
      state.show[k] = e.target.checked; persist(); draw(true);
    });
    document.addEventListener("click", function (e) {
      var m = root.querySelector("#pc-ind-menu");
      if (m && !m.hidden && !e.target.closest(".pc-ind")) { m.hidden = true; root.querySelector("#pc-ind-btn").setAttribute("aria-expanded", "false"); }
    });

    /* Seed with data the page already fetched (the 2y daily series). */
    if (opts.seed) { store["2y"] = opts.seed; }
    load();

    return {
      daily: function () { return store["2y"] || null; },
      setRange: function (k) { var b = root.querySelector('[data-range="' + k + '"]'); if (b) b.click(); },
    };
  };
})();

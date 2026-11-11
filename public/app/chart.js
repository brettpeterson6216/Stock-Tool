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
  function vol(v) { return v >= 1e9 ? (v / 1e9).toFixed(2) + "B" : v >= 1e6 ? (v / 1e6).toFixed(1) + "M" : v >= 1e3 ? (v / 1e3).toFixed(0) + "K" : String(Math.round(v)); }

  IL.PriceChart = function (root, opts) {
    opts = opts || {};
    var ticker = opts.ticker;
    var store = {};          // fetch key → {bars, meta}
    var state = {
      range: opts.range || "1Y", type: "area",
      show: { ma50: true, ma200: true, volume: true, rsi: false },
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
              ind("ma50", "50-day average", "Average closing price over the last 50 trading days. Price above it is a sign of a short-term uptrend.") +
              ind("ma200", "200-day average", "Average close over roughly the last year. Many investors treat price above it as a long-term uptrend.") +
              ind("volume", "Volume", "Shares traded each day. Big moves on heavy volume carry more weight.") +
              ind("rsi", "RSI (14)", "Relative Strength Index. Above 70 means it has risen fast (overbought); below 30 means it has fallen fast (oversold).") +
            "</div></div>" +
        "</div>" +
      "</div>" +
      '<div class="pc-head" id="pc-head"></div>' +
      '<div class="pc-canvas" id="pc-canvas"><div class="pc-loading"><span class="sk" style="height:100%"></span></div></div>' +
      '<p class="note pc-note" id="pc-note"></p>';

    function ind(key, label, tip) {
      return '<label class="pc-check"><input type="checkbox" data-ind="' + key + '"' + (state.show[key] ? " checked" : "") + "><span>" + label + "</span>" + IL.tip(tip) + "</label>";
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
      if (daily && state.show.ma200) series.push({ id: "ma200", kind: "line", v: aligned(sma(all, 200), all), color: "--blue", width: 1.5 });
      if (daily && state.show.ma50) series.push({ id: "ma50", kind: "line", v: aligned(sma(all, 50), all), color: "--text2", width: 1.5 });
      if (candles) {
        series.push({ id: "px", kind: "candles", v: close, tag: true, fmt: IL.fmt.price,
          o: all.map(function (b) { return b.open; }), h: all.map(function (b) { return b.high; }), l: all.map(function (b) { return b.low; }) });
      } else {
        /* The brand line over one flat tint (rulebook 4: no gradients on
           data). Up or down shows in the header, not the fill. */
        series.push({ id: "px", kind: "area", v: close, color: css("--chart-brand") ? "--chart-brand" : "--gold", width: 2, wash: 0.09, tag: true, marker: true, fmt: IL.fmt.price });
      }
      var rsiOn = state.show.rsi && !r.intraday;
      if (rsiOn) {
        panes.push({ id: "rsi", height: 92, min: 0, max: 100, ticks: [30, 70], label: "RSI 14", fmt: function (v) { return v.toFixed(0); } });
        series.push({ id: "rsi", pane: "rsi", kind: "line", v: aligned(rsi(all, 14), all), color: "--text2", width: 1.5, tag: true, fmt: function (v) { return v.toFixed(0); } });
        lines.push({ pane: "rsi", value: 70, dash: [3, 3] }, { pane: "rsi", value: 30, dash: [3, 3] });
      }
      canvas.classList.toggle("pc-rsi", rsiOn);
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
      function key(id, color, label) {
        var v = at !== null && chart ? chart.val(id, at) : NaN;
        parts.push('<span class="pc-key"><i style="background:var(' + color + ')"></i>' + label + (isFinite(v) ? ' <b class="num">' + IL.fmt.price(v) + "</b>" : "") + "</span>");
      }
      if (daily && state.show.ma50) key("ma50", "--text2", "50-day avg");
      if (daily && state.show.ma200) key("ma200", "--blue", "200-day avg");
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

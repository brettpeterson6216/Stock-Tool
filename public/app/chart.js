/* ═══════════════════════════════════════════════════════════════════════════
   Price chart for the rebuilt stock page (Lightweight Charts v5).

   One component, no globals beyond window.IL.PriceChart. Daily ranges share a
   single two-year daily series so switching between 1M, 6M, YTD and 1Y is
   instant and the 50- and 200-day averages are correct at the left edge of
   every view. 1D and 5D load intraday bars; 5Y uses weekly bars and Max
   monthly bars, where the averages are hidden because they would mean
   something different.
   ═══════════════════════════════════════════════════════════════════════════ */
(function () {
  "use strict";
  var IL = window.IL;
  var LWC = function () { return window.LightweightCharts; };

  var RANGES = [
    { key: "1D", fetch: "1d", intraday: true },
    { key: "5D", fetch: "5d", intraday: true },
    { key: "1M", fetch: "2y", days: 31 },
    { key: "6M", fetch: "2y", days: 183 },
    { key: "YTD", fetch: "2y", ytd: true },
    { key: "1Y", fetch: "2y", days: 366 },
    { key: "5Y", fetch: "5y", weekly: true },
    { key: "Max", fetch: "max", monthly: true },
  ];

  function css(name) { return getComputedStyle(document.documentElement).getPropertyValue(name).trim(); }

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
    var chart = null, main = null, vol = null, ma50 = null, ma200 = null, rsiS = null;
    var current = null;

    function build() {
      if (chart || !LWC()) return;
      var L = LWC();
      canvas.innerHTML = "";
      chart = L.createChart(canvas, {
        autoSize: true,
        layout: { background: { type: "solid", color: "transparent" }, textColor: css("--text3"), fontFamily: "IBM Plex Sans, Inter, sans-serif", fontSize: 11, attributionLogo: true, panes: { separatorColor: css("--line"), enableResize: false } },
        grid: { vertLines: { visible: false }, horzLines: { color: css("--chart-grid") } },
        rightPriceScale: { borderVisible: false, scaleMargins: { top: 0.08, bottom: 0.2 } },
        timeScale: { borderVisible: false, rightOffset: 2, fixLeftEdge: true, fixRightEdge: true, lockVisibleTimeRangeOnResize: true },
        crosshair: { mode: 0, vertLine: { color: css("--line3"), labelBackgroundColor: css("--raised") }, horzLine: { color: css("--line3"), labelBackgroundColor: css("--raised") } },
        handleScroll: { vertTouchDrag: false },
        localization: { priceFormatter: function (p) { return "$" + (p >= 1000 ? p.toFixed(0) : p.toFixed(2)); } },
      });
      chart.subscribeCrosshairMove(onCross);
    }

    function themeColors() {
      if (!chart) return;
      chart.applyOptions({
        layout: { textColor: css("--text3"), panes: { separatorColor: css("--line") } },
        grid: { horzLines: { color: css("--chart-grid") } },
        crosshair: { vertLine: { color: css("--line3"), labelBackgroundColor: css("--raised") }, horzLine: { color: css("--line3"), labelBackgroundColor: css("--raised") } },
      });
      draw();
    }
    document.addEventListener("il:theme", themeColors);

    function clearSeries() {
      [main, vol, ma50, ma200, rsiS].forEach(function (s) { if (s) chart.removeSeries(s); });
      main = vol = ma50 = ma200 = rsiS = null;
      while (chart.panes().length > 1) chart.removePane(1);
    }

    function spec() { return RANGES.filter(function (r) { return r.key === state.range; })[0] || RANGES[5]; }

    function visibleBars(all, r) {
      if (!all.length) return all;
      if (r.days || r.ytd) {
        var end = all[all.length - 1].time;
        var start = r.ytd ? Date.UTC(new Date(end * 1000).getUTCFullYear(), 0, 1) / 1000 : end - r.days * 86400;
        return all.filter(function (b) { return b.time >= start; });
      }
      return all;
    }

    function draw() {
      if (!current || !chart) return;
      var L = LWC(), r = spec();
      var all = current.bars, view = visibleBars(all, r);
      clearSeries();
      if (!view.length) return;
      var up = view[view.length - 1].close >= view[0].close;
      var lineColor = css("--chart-line");
      var gold = css("--gold");
      if (state.type === "candles") {
        main = chart.addSeries(L.CandlestickSeries, {
          upColor: css("--gain"), downColor: css("--loss"), wickUpColor: css("--gain"), wickDownColor: css("--loss"), borderVisible: false,
          priceLineVisible: false, lastValueVisible: true,
        });
        main.setData(view.map(function (b) { return { time: b.time, open: b.open, high: b.high, low: b.low, close: b.close }; }));
      } else {
        main = chart.addSeries(L.AreaSeries, {
          lineColor: lineColor, lineWidth: 2,
          topColor: up ? "rgba(76,195,138,0.16)" : "rgba(240,123,123,0.14)", bottomColor: "rgba(0,0,0,0)",
          priceLineVisible: false, lastValueVisible: true, crosshairMarkerRadius: 4,
          crosshairMarkerBorderColor: css("--surface"), crosshairMarkerBackgroundColor: lineColor,
        });
        main.setData(view.map(function (b) { return { time: b.time, value: b.close }; }));
      }
      var daily = !!(r.days || r.ytd);
      var start = view[0].time;
      if (daily && state.show.ma50) {
        ma50 = chart.addSeries(L.LineSeries, { color: gold, lineWidth: 1.5, priceLineVisible: false, lastValueVisible: false, crosshairMarkerVisible: false });
        ma50.setData(sma(all, 50).filter(function (p) { return p.time >= start; }));
      }
      if (daily && state.show.ma200) {
        ma200 = chart.addSeries(L.LineSeries, { color: css("--blue"), lineWidth: 1.5, priceLineVisible: false, lastValueVisible: false, crosshairMarkerVisible: false });
        ma200.setData(sma(all, 200).filter(function (p) { return p.time >= start; }));
      }
      if (state.show.volume) {
        vol = chart.addSeries(L.HistogramSeries, { priceScaleId: "vol", priceFormat: { type: "volume" }, priceLineVisible: false, lastValueVisible: false });
        chart.priceScale("vol").applyOptions({ scaleMargins: { top: 0.84, bottom: 0 }, visible: false });
        var gs = css("--gain"), ls = css("--loss");
        vol.setData(view.map(function (b, i) {
          var prev = i ? view[i - 1].close : b.open;
          return { time: b.time, value: b.volume, color: (b.close >= prev ? gs : ls) + "55" };
        }));
      }
      if (state.show.rsi && !r.intraday) {
        rsiS = chart.addSeries(L.LineSeries, { color: css("--text2"), lineWidth: 1.5, priceLineVisible: false, lastValueVisible: true, priceFormat: { type: "custom", formatter: function (v) { return v.toFixed(0); } } }, 1);
        rsiS.setData(rsi(all, 14).filter(function (p) { return p.time >= start; }));
        rsiS.createPriceLine({ price: 70, color: css("--line3"), lineWidth: 1, lineStyle: 2, axisLabelVisible: false });
        rsiS.createPriceLine({ price: 30, color: css("--line3"), lineWidth: 1, lineStyle: 2, axisLabelVisible: false });
        var panes = chart.panes();
        if (panes[1]) panes[1].setHeight(90);
      }
      chart.applyOptions({
        timeScale: { timeVisible: !!r.intraday, secondsVisible: false },
        localization: {
          timeFormatter: function (t) { return fmtTime(t, r.intraday); },
          priceFormatter: function (p) { return "$" + (p >= 1000 ? p.toFixed(0) : p.toFixed(2)); },
        },
      });
      chart.timeScale().fitContent();
      header(view, null);
      legend(r);
    }

    function legend(r) {
      var el = root.querySelector("#pc-legend");
      var daily = !!(r.days || r.ytd), parts = [];
      if (daily && state.show.ma50) parts.push('<span class="pc-key"><i style="background:var(--gold)"></i>50-day avg</span>');
      if (daily && state.show.ma200) parts.push('<span class="pc-key"><i style="background:var(--blue)"></i>200-day avg</span>');
      el.innerHTML = parts.join("");
    }

    function header(view, point) {
      var el = root.querySelector("#pc-head"), r = spec();
      if (!view.length) { el.innerHTML = ""; return; }
      var first = view[0], last = view[view.length - 1];
      if (point) {
        var chg = point.close - first.close;
        el.innerHTML = '<span class="num pc-px">' + IL.fmt.price(point.close) + '</span><span class="num ' + IL.fmt.cls(chg) + '">' + IL.fmt.spct(chg / first.close * 100) + " since " + IL.h(fmtTime(first.time, r.intraday)) + '</span><span class="faint">' + IL.h(fmtTime(point.time, r.intraday)) + "</span>";
        return;
      }
      var base = r.intraday && current.meta && current.meta.chartPreviousClose ? Number(current.meta.chartPreviousClose) : first.close;
      if (r.key === "5D") base = first.close;
      var d = last.close - base;
      el.innerHTML = '<span class="faint">' + IL.h(r.key === "Max" ? "All time" : r.key === "YTD" ? "Year to date" : "Past " + ({ "1D": "day", "5D": "5 days", "1M": "month", "6M": "6 months", "1Y": "year", "5Y": "5 years" }[r.key])) + '</span><span class="num ' + IL.fmt.cls(d) + '">' + IL.fmt.schg(d) + " (" + IL.fmt.spct(d / base * 100, 2) + ")</span>";
    }

    function onCross(p) {
      if (!current) return;
      var view = visibleBars(current.bars, spec());
      if (!p || !p.time || !main) { header(view, null); return; }
      var d = p.seriesData.get(main);
      if (!d) { header(view, null); return; }
      header(view, { time: p.time, close: d.close != null ? d.close : d.value });
    }

    function load() {
      var r = spec();
      var key = r.fetch;
      var note = root.querySelector("#pc-note");
      if (store[key]) { current = store[key]; build(); draw(); return Promise.resolve(); }
      return IL.api("/api/quote/" + encodeURIComponent(ticker) + "?range=" + key).then(function (res) {
        if (!res.ok) {
          if (opts.onError) opts.onError(res);
          canvas.innerHTML = '<div class="empty">' + (res.gate ? "" : "Price history is unavailable for this range right now.") + "</div>";
          if (res.gate) canvas.innerHTML = IL.gate(res.gate, null, { center: true });
          chart = null; main = vol = ma50 = ma200 = rsiS = null;
          return;
        }
        store[key] = seriesFrom(res.data);
        store[key].provenance = res.data.impliedLens || null;
        current = store[key];
        if (!chart) build();
        if (!chart) { canvas.innerHTML = '<div class="empty">The chart library did not load. Refresh to try again.</div>'; return; }
        draw();
        var pv = current.provenance;
        if (note && pv) {
          note.textContent = "Prices: " + (pv.source || "market data") + (pv.fallback ? "" : "") + ". " + (r.intraday ? "Intraday bars, times in Eastern Time." : "Daily closes.") + " Delayed at least 15 minutes during market hours.";
        }
      });
    }

    root.addEventListener("click", function (e) {
      var b = e.target.closest("[data-range]");
      if (b) {
        state.range = b.getAttribute("data-range"); persist();
        root.querySelectorAll("[data-range]").forEach(function (x) { x.setAttribute("aria-pressed", String(x === b)); });
        load();
        return;
      }
      var t = e.target.closest("[data-type]");
      if (t) {
        state.type = t.getAttribute("data-type"); persist();
        root.querySelectorAll("[data-type]").forEach(function (x) { x.setAttribute("aria-pressed", String(x === t)); });
        draw();
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
      state.show[k] = e.target.checked; persist(); draw();
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

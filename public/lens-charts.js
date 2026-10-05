/* Lens Charts: ImpliedLens's own small-chart kit.

   Four chart forms, drawn as SVG, styled by the site's tokens so they follow
   the theme without redrawing:

     LensCharts.bars(host,  { items: [{ label, value, highlight }], format, height })
     LensCharts.lines(host, { series: [{ name, points: [[time, value], …], emphasis }], format, zero, height })
     LensCharts.range(host, { rows: [{ name, lo, mid, hi, muted }], marker: { value, label }, format })
     LensCharts.spark(host, { values: [ … ], label })

   Each call replaces whatever the host held, redraws when the host changes
   width, and returns { update(opts), destroy() }. Gold marks the thing being
   studied; every number carries a plain label; no legends where a direct
   label fits. Replaces Chart.js (≈80KB) for these forms at a few KB. */
(function () {
  "use strict";

  var NS = "http://www.w3.org/2000/svg";
  var CSS = [
    ".lc-host{position:relative;width:100%}",
    ".lc-svg{display:block;width:100%;overflow:visible;font-family:var(--rp-num,'IBM Plex Sans',system-ui,sans-serif)}",
    ".lc-grid{stroke:var(--rp-line,rgba(70,52,22,.12));stroke-width:1;fill:none}",
    ".lc-axis{stroke:var(--rp-line-strong,rgba(70,52,22,.24));stroke-width:1;fill:none}",
    ".lc-zero{stroke:var(--rp-line-strong,rgba(70,52,22,.3));stroke-width:1;stroke-dasharray:3 4;fill:none}",
    ".lc-tick{fill:var(--rp-muted,#6f6758);font-size:11px}",
    ".lc-cat{fill:var(--rp-muted,#6f6758);font-size:11px;font-family:var(--rp-sans,'Plus Jakarta Sans',system-ui,sans-serif)}",
    ".lc-val{fill:var(--rp-copy,#4d463b);font-size:11.5px;font-weight:500}",
    ".lc-val-hi{fill:var(--rp-gold,#87590c);font-weight:700}",
    ".lc-bar{fill:var(--lc-bar-soft)}",
    ".lc-bar-hi{fill:var(--lc-gold-mark)}",
    ".lc-bar-neg{fill:var(--rp-red,#b42f33);fill-opacity:.55}",
    ".lc-line{fill:none;stroke-width:1.7;stroke-linejoin:round;stroke-linecap:round}",
    ".lc-line-em{stroke-width:2.4}",
    ".lc-end-v{font-size:13px;font-weight:600}",
    ".lc-end-n{fill:var(--rp-copy,#4d463b);font-size:11px;font-family:var(--rp-sans,'Plus Jakarta Sans',system-ui,sans-serif)}",
    ".lc-range{fill:var(--lc-range)}",
    ".lc-range-muted{fill:var(--lc-range-muted)}",
    ".lc-mid{stroke:var(--lc-mid);stroke-width:2}",
    ".lc-marker{stroke:var(--rp-gold,#87590c);stroke-width:1.5;stroke-dasharray:4 3}",
    ".lc-marker-t{fill:var(--rp-gold,#87590c);font-size:11px;font-weight:600}",
    ".lc-name{fill:var(--rp-ink,#1b1712);font-size:12.5px;font-weight:500;font-family:var(--rp-sans,'Plus Jakarta Sans',system-ui,sans-serif)}",
    ".lc-spark-a{fill:var(--lc-spark-fill)}",
    ".lc-spark-l{fill:none;stroke:var(--lc-gold-mark);stroke-width:1.8;stroke-linejoin:round;stroke-linecap:round}",
    ".lc-dot{fill:var(--rp-gold,#87590c)}",
    ".lc-cross{stroke:var(--rp-muted,#6f6758);stroke-width:1;stroke-dasharray:3 3}",
    ".lc-hit{fill:transparent;cursor:crosshair}",
    ".lc-tip{position:absolute;pointer-events:none;z-index:5;min-width:120px;padding:8px 10px;border-radius:9px;",
    "background:var(--rp-raised,#fff);border:1px solid var(--rp-line-strong,rgba(70,52,22,.24));",
    "box-shadow:0 12px 28px -14px rgba(0,0,0,.45);font-size:12px;color:var(--rp-ink,#1b1712);",
    "font-family:var(--rp-sans,'Plus Jakarta Sans',system-ui,sans-serif);display:none}",
    ".lc-tip b{display:block;font-weight:600;margin-bottom:4px}",
    ".lc-tip span{display:flex;justify-content:space-between;gap:14px;align-items:center}",
    ".lc-tip i{font-style:normal;font-family:var(--rp-num,'IBM Plex Sans',sans-serif);font-weight:600}",
    ".lc-sw{display:inline-block;width:9px;height:3px;border-radius:2px;margin-right:6px;vertical-align:middle}",
    ".lc-sr{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}",
    ":root{--lc-gold-mark:#b07d1e;--lc-bar-soft:#e7d4a6;--lc-range:rgba(227,180,72,.42);--lc-range-muted:rgba(70,52,22,.13);",
    "--lc-mid:#6e470d;--lc-spark-fill:rgba(176,125,30,.12);--lc-s1:#b07d1e;--lc-s2:#2a78d6;--lc-s3:#1b8a5f;--lc-s4:#c4561f}",
    "html[data-theme=\"dark\"]{--lc-gold-mark:#e9b44c;--lc-bar-soft:rgba(233,180,76,.28);--lc-range:rgba(233,180,76,.30);",
    "--lc-range-muted:rgba(240,214,160,.12);--lc-mid:#f8dc95;--lc-spark-fill:rgba(233,180,76,.13);",
    "--lc-s1:#f0be5a;--lc-s2:#5b9be8;--lc-s3:#3fbf8a;--lc-s4:#e8794a}"
  ].join("");

  function injectCss() {
    if (document.getElementById("lc-style")) return;
    var s = document.createElement("style");
    s.id = "lc-style";
    s.textContent = CSS;
    (document.head || document.documentElement).appendChild(s);
  }

  function svgEl(tag, attrs, parent) {
    var e = document.createElementNS(NS, tag);
    for (var k in attrs) if (attrs[k] != null) e.setAttribute(k, attrs[k]);
    if (parent) parent.appendChild(e);
    return e;
  }
  function text(parent, x, y, str, cls, anchor) {
    var t = svgEl("text", { x: r1(x), y: r1(y), "class": cls, "text-anchor": anchor || "start" }, parent);
    t.textContent = str;
    return t;
  }
  function r1(n) { return Math.round(n * 10) / 10; }
  function esc(s) { return String(s == null ? "" : s).replace(/[&<>"]/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]; }); }

  function niceTicks(lo, hi, count) {
    if (!(hi > lo)) { hi = lo + 1; }
    var raw = (hi - lo) / (count || 4);
    var mag = Math.pow(10, Math.floor(Math.log10(raw)));
    var step = [1, 2, 2.5, 5, 10].map(function (m) { return m * mag; }).filter(function (m) { return m >= raw; })[0] || mag * 10;
    var start = Math.floor(lo / step) * step, end = Math.ceil(hi / step) * step, out = [];
    for (var v = start; v <= end + step * 1e-6; v += step) out.push(Math.round(v / step) * step);
    return out;
  }

  var compact = function (v) {
    var a = Math.abs(v);
    if (a >= 1e12) return (v / 1e12).toFixed(a >= 1e13 ? 0 : 1) + "T";
    if (a >= 1e9) return (v / 1e9).toFixed(a >= 1e10 ? 0 : 1) + "B";
    if (a >= 1e6) return (v / 1e6).toFixed(a >= 1e7 ? 0 : 1) + "M";
    if (a >= 1e3) return (v / 1e3).toFixed(0) + "K";
    return String(Math.round(v * 100) / 100);
  };

  /* ── shared mount: one svg + tooltip per host, redraw on width change ── */
  function mount(host, draw, opts) {
    injectCss();
    if (host.__lc) host.__lc.destroy();
    host.classList.add("lc-host");
    var state = { opts: opts, width: 0, ro: null };
    function render() {
      var w = Math.round(host.clientWidth || (opts && opts.width) || 0);
      if (!w) return;
      state.width = w;
      host.innerHTML = "";
      var tip = document.createElement("div");
      tip.className = "lc-tip";
      draw(host, w, state.opts, tip);
      host.appendChild(tip);
    }
    render();
    if ("ResizeObserver" in window) {
      /* A redraw can toggle a page scrollbar, which changes the width, which
         asks for a redraw: skip a width we just left (that is the loop) and
         coalesce bursts into one frame. */
      var prevW = 0, queued = false;
      state.ro = new ResizeObserver(function () {
        if (queued) return;
        queued = true;
        (window.requestAnimationFrame || setTimeout)(function () {
          queued = false;
          var w = Math.round(host.clientWidth);
          if (!w || Math.abs(w - state.width) <= 1 || Math.abs(w - prevW) <= 1) return;
          prevW = state.width;
          render();
        });
      });
      state.ro.observe(host);
    }
    var api = {
      update: function (next) { state.opts = next; render(); },
      destroy: function () { if (state.ro) state.ro.disconnect(); host.innerHTML = ""; host.__lc = null; }
    };
    host.__lc = api;
    return api;
  }

  function baseSvg(host, w, h, label) {
    var svg = svgEl("svg", { "class": "lc-svg", width: w, height: h, viewBox: "0 0 " + w + " " + h, role: "img", "aria-label": label || "Chart" }, host);
    return svg;
  }
  function srSummary(host, lines) {
    var p = document.createElement("p");
    p.className = "lc-sr";
    p.textContent = lines.join(". ");
    host.appendChild(p);
  }
  function showTip(tip, host, html, x, y) {
    tip.innerHTML = html;
    tip.style.display = "block";
    var hw = host.clientWidth, tw = tip.offsetWidth;
    var left = x + 14;
    if (left + tw > hw) left = x - tw - 14;
    tip.style.left = Math.max(0, left) + "px";
    tip.style.top = Math.max(0, y - 10) + "px";
  }

  /* ── bars ─────────────────────────────────────────────────────────────── */
  function drawBars(host, w, o, tip) {
    var items = (o.items || []).filter(function (d) { return Number.isFinite(d.value); });
    var h = o.height || 220, fmt = o.format || compact;
    var L = 46, R = 6, T = 22, B = 26;
    var svg = baseSvg(host, w, h, o.label);
    if (!items.length) return;
    var vals = items.map(function (d) { return d.value; });
    var ticks = niceTicks(Math.min(0, Math.min.apply(null, vals)), Math.max(0, Math.max.apply(null, vals)), 4);
    var lo = ticks[0], hi = ticks[ticks.length - 1];
    var PH = h - T - B, PW = w - L - R;
    function y(v) { return T + (hi - v) / (hi - lo) * PH; }
    ticks.forEach(function (t) {
      var Y = y(t);
      if (t !== 0) svgEl("path", { d: "M" + L + " " + r1(Y) + "H" + (w - R), "class": "lc-grid" }, svg);
      text(svg, L - 8, Y + 4, (o.axisFormat || fmt)(t), "lc-tick", "end");
    });
    svgEl("path", { d: "M" + L + " " + r1(y(0)) + "H" + (w - R), "class": "lc-axis" }, svg);
    var slot = PW / items.length, bw = Math.min(46, slot * 0.62), showAll = slot >= 46;
    items.forEach(function (d, i) {
      var cx = L + slot * (i + 0.5), x0 = cx - bw / 2, y0 = y(Math.max(0, d.value)), y1 = y(Math.min(0, d.value));
      var hgt = Math.max(1, y1 - y0), rad = Math.min(4, hgt / 2, bw / 2);
      var pos = d.value >= 0;
      var path = pos
        ? "M" + r1(x0) + " " + r1(y1) + "V" + r1(y0 + rad) + "Q" + r1(x0) + " " + r1(y0) + " " + r1(x0 + rad) + " " + r1(y0) + "H" + r1(x0 + bw - rad) + "Q" + r1(x0 + bw) + " " + r1(y0) + " " + r1(x0 + bw) + " " + r1(y0 + rad) + "V" + r1(y1) + "Z"
        : "M" + r1(x0) + " " + r1(y0) + "V" + r1(y1 - rad) + "Q" + r1(x0) + " " + r1(y1) + " " + r1(x0 + rad) + " " + r1(y1) + "H" + r1(x0 + bw - rad) + "Q" + r1(x0 + bw) + " " + r1(y1) + " " + r1(x0 + bw) + " " + r1(y1 - rad) + "V" + r1(y0) + "Z";
      svgEl("path", { d: path, "class": !pos ? "lc-bar-neg" : d.highlight ? "lc-bar-hi" : "lc-bar" }, svg);
      if (showAll || d.highlight) text(svg, cx, pos ? y0 - 7 : y1 + 14, fmt(d.value), d.highlight ? "lc-val lc-val-hi" : "lc-val", "middle");
      text(svg, cx, h - 7, d.label, "lc-cat", "middle");
      var hit = svgEl("rect", { x: r1(L + slot * i), y: T, width: r1(slot), height: PH, "class": "lc-hit" }, svg);
      hit.addEventListener("pointerenter", function () {
        showTip(tip, host, "<b>" + esc(d.label) + "</b><span>" + esc(o.valueName || "Value") + " <i>" + esc(fmt(d.value)) + "</i></span>" + (d.note ? "<span>" + esc(d.note) + "</span>" : ""), cx, y0);
      });
      hit.addEventListener("pointerleave", function () { tip.style.display = "none"; });
    });
    srSummary(host, items.map(function (d) { return d.label + ": " + fmt(d.value); }));
  }

  /* ── lines ────────────────────────────────────────────────────────────── */
  var MON = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  function pctAxis(step) { return function (v) { return (v > 0 ? "+" : "") + v.toFixed(step >= 1 ? 0 : 1) + "%"; }; }
  function drawLines(host, w, o, tip) {
    var series = (o.series || []).map(function (s, i) {
      return { name: s.name, emphasis: !!s.emphasis, color: s.color || "var(--lc-s" + ((i % 4) + 1) + ")",
        points: (s.points || []).filter(function (p) { return p && Number.isFinite(p[0]) && Number.isFinite(p[1]); }) };
    }).filter(function (s) { return s.points.length > 1; });
    var h = o.height || 230, fmt = o.format || function (v) { return (v > 0 ? "+" : "") + v.toFixed(1) + "%"; };
    var narrow = w < 420;
    var L = 46, R = o.endLabels === false ? 8 : (narrow ? 70 : 100), T = 10, B = 24;
    var svg = baseSvg(host, w, h, o.label);
    if (!series.length) return;
    var t0 = Infinity, t1 = -Infinity, v0 = o.zero ? 0 : Infinity, v1 = o.zero ? 0 : -Infinity;
    series.forEach(function (s) { s.points.forEach(function (p) { t0 = Math.min(t0, p[0]); t1 = Math.max(t1, p[0]); v0 = Math.min(v0, p[1]); v1 = Math.max(v1, p[1]); }); });
    var ticks = niceTicks(v0, v1, 4), lo = ticks[0], hi = ticks[ticks.length - 1];
    var PW = w - L - R, PH = h - T - B;
    /* ordinal: bars are spaced by position, not by clock time, so the hours
       a market is closed take no width (intraday and multi-day hourly data). */
    var ord = null, pos = null;
    if (o.ordinal) {
      var seen = {};
      series.forEach(function (s) { s.points.forEach(function (p) { seen[p[0]] = 1; }); });
      ord = Object.keys(seen).map(Number).sort(function (a, b) { return a - b; });
      pos = {};
      ord.forEach(function (t, i) { pos[t] = i; });
    }
    function ordIndex(t) {
      if (pos[t] != null) return pos[t];
      var lo = 0, hi = ord.length - 1;
      while (hi - lo > 1) { var m = (lo + hi) >> 1; if (ord[m] < t) lo = m; else hi = m; }
      return Math.abs(ord[lo] - t) <= Math.abs(ord[hi] - t) ? lo : hi;
    }
    function x(t) {
      if (ord) return L + ordIndex(t) / ((ord.length - 1) || 1) * PW;
      return L + (t - t0) / ((t1 - t0) || 1) * PW;
    }
    function y(v) { return T + (hi - v) / (hi - lo) * PH; }
    ticks.forEach(function (t) {
      svgEl("path", { d: "M" + L + " " + r1(y(t)) + "H" + (L + PW), "class": t === 0 && o.zero ? "lc-zero" : "lc-grid" }, svg);
      text(svg, L - 8, y(t) + 4, (o.axisFormat || (o.format ? fmt : pctAxis(ticks[1] - ticks[0])))(t), "lc-tick", "end");
    });
    // time labels, by span: hours inside two days, days inside ~2.5 months,
    // then month starts (years on long spans); thinned to fit the width
    var span = t1 - t0, labels = [], HOUR = 36e5, DAY = 864e5;
    var maxLabels = Math.max(2, Math.floor(PW / 70));
    function thin(list) { while (list.length > maxLabels) list = list.filter(function (_, i) { return i % 2 === 0; }); return list; }
    if (ord) {
      var oneDay = new Date(t0).toDateString() === new Date(t1).toDateString();
      var prevKey = null;
      ord.forEach(function (t) {
        var d = new Date(t), key = oneDay ? d.getHours() : d.toDateString();
        if (prevKey !== null && key !== prevKey) labels.push(t);
        prevKey = key;
      });
      thin(labels).forEach(function (t) {
        var d = new Date(t), hr = d.getHours();
        text(svg, x(t), h - 6, oneDay ? (hr % 12 || 12) + (hr < 12 ? " AM" : " PM") : MON[d.getMonth()] + " " + d.getDate(), "lc-cat", "middle");
      });
    } else if (span <= 2 * DAY) {
      var stepH = [1, 2, 3, 4, 6, 12].filter(function (h) { return span / (h * HOUR) <= maxLabels; })[0] || 12;
      var h0 = new Date(t0); h0.setMinutes(0, 0, 0);
      for (var th = h0.getTime() + HOUR; th <= t1; th += HOUR) if (new Date(th).getHours() % stepH === 0) labels.push(th);
      thin(labels).forEach(function (t) {
        var hr = new Date(t).getHours();
        text(svg, x(t), h - 6, (hr % 12 || 12) + (hr < 12 ? " AM" : " PM"), "lc-cat", "middle");
      });
    } else if (span <= 75 * DAY) {
      var stepD = [1, 2, 7, 14].filter(function (d) { return span / (d * DAY) <= maxLabels; })[0] || 14;
      var d0 = new Date(t0); d0.setHours(0, 0, 0, 0);
      var k = 0;
      for (var td = d0.getTime() + DAY; td <= t1; td += DAY) {
        var dd = new Date(td), wd = dd.getDay();
        if (wd === 0 || wd === 6) continue;
        if (stepD === 7 || stepD === 14) { if (wd === 1 && (stepD === 7 || k++ % 2 === 0)) labels.push(td); }
        else if (k++ % stepD === 0) labels.push(td);
      }
      thin(labels).forEach(function (t) { var dt = new Date(t); text(svg, x(t), h - 6, MON[dt.getMonth()] + " " + dt.getDate(), "lc-cat", "middle"); });
    } else {
      var stepMonths = span > 4 * 365 * DAY ? 12 : span > 400 * DAY ? 3 : span > 150 * DAY ? 2 : 1;
      var dm = new Date(t0);
      dm = new Date(Date.UTC(dm.getUTCFullYear(), dm.getUTCMonth() + 1, 1));
      while (dm.getTime() <= t1) {
        if (dm.getUTCMonth() % stepMonths === 0) labels.push(dm.getTime());
        dm = new Date(Date.UTC(dm.getUTCFullYear(), dm.getUTCMonth() + 1, 1));
      }
      thin(labels).forEach(function (t) {
        var dt = new Date(t), m = dt.getUTCMonth();
        text(svg, x(t), h - 6, (m === 0 || stepMonths === 12) ? String(dt.getUTCFullYear()) : MON[m], "lc-cat", "middle");
      });
    }
    // lines, emphasised last so it sits on top
    var order = series.slice().sort(function (a, b) { return (a.emphasis ? 1 : 0) - (b.emphasis ? 1 : 0); });
    order.forEach(function (s) {
      var dstr = svgCurve(s.points.map(function (p) { return [x(p[0]), y(p[1])]; }));
      svgEl("path", { d: dstr, "class": "lc-line" + (s.emphasis ? " lc-line-em" : ""), style: "stroke:" + s.color }, svg);
      var last = s.points[s.points.length - 1];
      svgEl("circle", { cx: r1(x(last[0])), cy: r1(y(last[1])), r: 3.5, style: "fill:" + s.color }, svg);
    });
    // end labels, nudged apart
    if (o.endLabels !== false) {
      var tags = series.map(function (s) { var last = s.points[s.points.length - 1]; return { s: s, v: last[1], y: y(last[1]) }; })
        .sort(function (a, b) { return a.y - b.y; });
      var gap = narrow ? 16 : 28;
      for (var pass = 0; pass < 20; pass++) {
        for (var i = 1; i < tags.length; i++) {
          var over = tags[i - 1].y + gap - tags[i].y;
          if (over > 0) { tags[i - 1].y -= over / 2; tags[i].y += over / 2; }
        }
      }
      tags.forEach(function (t) {
        var yy = Math.max(T + 8, Math.min(h - B - (narrow ? 2 : 14), t.y));
        var tv = text(svg, L + PW + 10, yy + 4, fmt(t.v), "lc-end-v");
        tv.setAttribute("style", "fill:" + t.s.color);
        if (!narrow) text(svg, L + PW + 10, yy + 18, t.s.name, "lc-end-n");
      });
    }
    // hover
    var cross = svgEl("path", { d: "", "class": "lc-cross", style: "display:none" }, svg);
    var hit = svgEl("rect", { x: L, y: T, width: PW, height: PH, "class": "lc-hit" }, svg);
    var base = series[0].points;
    hit.addEventListener("pointermove", function (e) {
      var rect = svg.getBoundingClientRect();
      var px = (e.clientX - rect.left) * (w / rect.width);
      var bt;
      if (ord) bt = ord[Math.max(0, Math.min(ord.length - 1, Math.round((px - L) / PW * (ord.length - 1))))];
      else {
        var t = t0 + (px - L) / PW * (t1 - t0), best = 0;
        for (var i = 1; i < base.length; i++) if (Math.abs(base[i][0] - t) < Math.abs(base[best][0] - t)) best = i;
        bt = base[best][0];
      }
      var X = x(bt);
      cross.setAttribute("d", "M" + r1(X) + " " + T + "V" + (T + PH));
      cross.style.display = "";
      var dt = new Date(bt), hh = dt.getHours(), mm = dt.getMinutes();
      var when = span <= 2 * DAY ? MON[dt.getMonth()] + " " + dt.getDate() + ", " + (hh % 12 || 12) + ":" + (mm < 10 ? "0" : "") + mm + (hh < 12 ? " AM" : " PM")
                                 : MON[dt.getMonth()] + " " + dt.getDate() + ", " + dt.getFullYear();
      var html = "<b>" + when + "</b>";
      series.forEach(function (s) {
        var pt = s.points.reduce(function (a, p) { return Math.abs(p[0] - bt) < Math.abs(a[0] - bt) ? p : a; }, s.points[0]);
        html += "<span><span><em class=\"lc-sw\" style=\"background:" + s.color + "\"></em>" + esc(s.name) + "</span><i>" + esc(fmt(pt[1])) + "</i></span>";
      });
      showTip(tip, host, html, X, T + 6);
    });
    hit.addEventListener("pointerleave", function () { cross.style.display = "none"; tip.style.display = "none"; });
    srSummary(host, series.map(function (s) { return s.name + " " + fmt(s.points[s.points.length - 1][1]); }));
  }

  /* ── range (a "football field") ──────────────────────────────────────── */
  function drawRange(host, w, o, tip) {
    var rows = (o.rows || []).filter(function (r) { return Number.isFinite(r.lo) && Number.isFinite(r.hi); });
    var fmt = o.format || function (v) { return "$" + Math.round(v); };
    var narrow = w < 460;
    // Narrow: each name sits on its own line above its bar, so the bars get
    // the full width instead of a third of it.
    var rowH = narrow ? 58 : 44, T = o.marker ? 22 : 8, B = 26, h = T + rows.length * rowH + B;
    var nameW = narrow ? 0 : 150, padL = narrow ? 46 : 50, padR = 46;
    var svg = baseSvg(host, w, h, o.label);
    if (!rows.length) return;
    var vals = [];
    rows.forEach(function (r) { vals.push(r.lo, r.hi); });
    if (o.marker && Number.isFinite(o.marker.value)) vals.push(o.marker.value);
    var vmin = Math.min.apply(null, vals), vmax = Math.max.apply(null, vals), span = (vmax - vmin) || Math.abs(vmax) || 1;
    var lo = vmin - span * 0.04, hi = vmax + span * 0.04;
    var X0 = nameW + padL, X1 = w - padR;
    function x(v) { return X0 + (v - lo) / (hi - lo) * (X1 - X0); }
    var ticks = niceTicks(lo, hi, Math.max(2, Math.floor((X1 - X0) / 70))).filter(function (t) { return t >= lo && t <= hi; });
    ticks.forEach(function (t) {
      svgEl("path", { d: "M" + r1(x(t)) + " " + (T - 4) + "V" + (h - B + 2), "class": "lc-grid" }, svg);
      text(svg, x(t), h - 6, fmt(t), "lc-tick", "middle");
    });
    rows.forEach(function (r, i) {
      var y0 = T + i * rowH + (narrow ? 26 : 10), bh = 22;
      text(svg, 0, narrow ? y0 - 8 : y0 + 15, r.name, "lc-name");
      svgEl("rect", { x: r1(x(r.lo)), y: y0, width: r1(Math.max(2, x(r.hi) - x(r.lo))), height: bh, rx: 5, "class": r.muted ? "lc-range-muted" : "lc-range" }, svg);
      if (Number.isFinite(r.mid)) svgEl("path", { d: "M" + r1(x(r.mid)) + " " + (y0 - 3) + "V" + (y0 + bh + 3), "class": "lc-mid" }, svg);
      text(svg, x(r.lo) - 6, y0 + 15, fmt(r.lo), "lc-val", "end");
      text(svg, x(r.hi) + 6, y0 + 15, fmt(r.hi), "lc-val");
      var hit = svgEl("rect", { x: 0, y: y0 - 8, width: w, height: rowH - 4, "class": "lc-hit" }, svg);
      hit.style.cursor = "default";
      hit.addEventListener("pointerenter", function () {
        showTip(tip, host, "<b>" + esc(r.name) + "</b><span>Low <i>" + esc(fmt(r.lo)) + "</i></span>" +
          (Number.isFinite(r.mid) ? "<span>Middle <i>" + esc(fmt(r.mid)) + "</i></span>" : "") +
          "<span>High <i>" + esc(fmt(r.hi)) + "</i></span>" + (r.note ? "<span>" + esc(r.note) + "</span>" : ""), x(r.hi), y0);
      });
      hit.addEventListener("pointerleave", function () { tip.style.display = "none"; });
    });
    if (o.marker && Number.isFinite(o.marker.value)) {
      var mx = x(o.marker.value);
      svgEl("path", { d: "M" + r1(mx) + " " + (T - 2) + "V" + (h - B), "class": "lc-marker" }, svg);
      var anchor = mx > w - 90 ? "end" : mx < X0 + 40 ? "start" : "middle";
      text(svg, mx, T - 8, (o.marker.label || "Now") + " " + fmt(o.marker.value), "lc-marker-t", anchor);
    }
    srSummary(host, rows.map(function (r) { return r.name + " " + fmt(r.lo) + " to " + fmt(r.hi); }));
  }


  /* ── smooth curves ───────────────────────────────────────────────────────
     Monotone cubic interpolation (Fritsch–Carlson). The curve passes through
     every real point and never bends above a peak or below a trough between
     two of them, so it reads smooth without inventing values the data does
     not have. Returns cubic Bézier segments; svgCurve and canvasCurve draw them. */
  function curveSegs(pts) {
    var n = pts.length, segs = [];
    if (n < 2) return segs;
    var dx = [], m = [], t = [];
    for (var i = 0; i < n - 1; i++) { dx[i] = pts[i + 1][0] - pts[i][0]; m[i] = dx[i] ? (pts[i + 1][1] - pts[i][1]) / dx[i] : 0; }
    t[0] = m[0]; t[n - 1] = m[n - 2];
    for (var j = 1; j < n - 1; j++) t[j] = m[j - 1] * m[j] <= 0 ? 0 : (m[j - 1] + m[j]) / 2;
    for (var k = 0; k < n - 1; k++) {
      if (m[k] === 0) { t[k] = 0; t[k + 1] = 0; continue; }
      var a = t[k] / m[k], b = t[k + 1] / m[k], q = a * a + b * b;
      if (q > 9) { var r = 3 / Math.sqrt(q); t[k] = r * a * m[k]; t[k + 1] = r * b * m[k]; }
    }
    for (var s = 0; s < n - 1; s++) {
      var h = dx[s] / 3;
      segs.push([pts[s][0] + h, pts[s][1] + t[s] * h, pts[s + 1][0] - h, pts[s + 1][1] - t[s + 1] * h, pts[s + 1][0], pts[s + 1][1]]);
    }
    return segs;
  }
  // SVG path data; `cont` continues an existing path with L instead of M.
  function svgCurve(pts, cont) {
    if (!pts.length) return "";
    var d = (cont ? "L" : "M") + r1(pts[0][0]) + " " + r1(pts[0][1]);
    if (pts.length > 160) return d + pts.slice(1).map(function (p) { return "L" + r1(p[0]) + " " + r1(p[1]); }).join("");
    curveSegs(pts).forEach(function (c) { d += "C" + r1(c[0]) + " " + r1(c[1]) + " " + r1(c[2]) + " " + r1(c[3]) + " " + r1(c[4]) + " " + r1(c[5]); });
    return d;
  }
  function canvasCurve(g, pts, cont) {
    if (!pts.length) return;
    if (cont) g.lineTo(pts[0][0], pts[0][1]); else g.moveTo(pts[0][0], pts[0][1]);
    curveSegs(pts).forEach(function (c) { g.bezierCurveTo(c[0], c[1], c[2], c[3], c[4], c[5]); });
  }

  /* ── sparkline ───────────────────────────────────────────────────────── */
  function drawSpark(host, w, o) {
    var vals = (o.values || []).filter(Number.isFinite);
    var h = o.height || 56, pad = 5;
    var svg = baseSvg(host, w, h, o.label || "Trend");
    if (vals.length < 2) return;
    var mn = Math.min.apply(null, vals), mx = Math.max.apply(null, vals);
    var pts = vals.map(function (v, i) { return [pad + i / (vals.length - 1) * (w - pad * 2), h - pad - (v - mn) / ((mx - mn) || 1) * (h - pad * 2)]; });
    var line = svgCurve(pts);
    svgEl("path", { d: line + "L" + r1(pts[pts.length - 1][0]) + " " + h + "L" + r1(pts[0][0]) + " " + h + "Z", "class": "lc-spark-a" }, svg);
    svgEl("path", { d: line, "class": "lc-spark-l" }, svg);
    var e = pts[pts.length - 1];
    svgEl("circle", { cx: r1(e[0]), cy: r1(e[1]), r: 3.2, "class": "lc-dot" }, svg);
  }

  window.LensCharts = {
    curve: curveSegs, svgCurve: svgCurve, canvasCurve: canvasCurve,
    bars: function (host, opts) { return host ? mount(host, drawBars, opts || {}) : null; },
    lines: function (host, opts) { return host ? mount(host, drawLines, opts || {}) : null; },
    range: function (host, opts) { return host ? mount(host, drawRange, opts || {}) : null; },
    spark: function (host, opts) { return host ? mount(host, drawSpark, opts || {}) : null; },
    compact: compact,
    niceTicks: niceTicks
  };
})();

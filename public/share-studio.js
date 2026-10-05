/* ═══════════════════════════════════════════════════════════════════════════
   ImpliedLens — chart Share Studio

   Turns the chart you are looking at into a post-ready image. The chart is
   drawn from the price data itself, not screenshotted from the live chart, so
   the image carries none of the interface: no axis badges, no crosshair, no
   library watermark, just the series, the averages you have on, your own
   drawings, and the brand frame.

   Five colour schemes, three sizes (16:9 for X, square, 4:5 portrait), an
   editable headline, and Download / Copy / Share plus suggested post text.
   ═══════════════════════════════════════════════════════════════════════════ */
(function () {
  "use strict";

  var SIZES = {
    wide: { w: 1600, h: 900, label: "Landscape", note: "1600 × 900 · best for X and LinkedIn" },
    square: { w: 1080, h: 1080, label: "Square", note: "1080 × 1080 · X, Instagram, LinkedIn" },
    tall: { w: 1080, h: 1350, label: "Portrait", note: "1080 × 1350 · Instagram feed" }
  };
  /* Each scheme is a complete palette, not just an accent swap, so light and
     dark images are both deliberate. */
  var SCHEMES = {
    onyx: { label: "Onyx", bg: "#0C0B09", bg2: "#14120E", panel: "rgba(243,238,227,.035)", line: "rgba(243,238,227,.09)",
            grid: "rgba(243,238,227,.06)", ink: "#F3EEE3", dim: "rgba(243,238,227,.62)", faint: "rgba(243,238,227,.40)",
            accent: "#E3A945", glow: "rgba(227,169,69,.16)", up: "#4FC48A", down: "#E5735F", ma50: "#E3A945", ma200: "#7FB2E5", dark: true },
    ivory: { label: "Ivory", bg: "#F7F2E8", bg2: "#EFE7D8", panel: "rgba(255,255,255,.62)", line: "rgba(40,30,12,.10)",
             grid: "rgba(40,30,12,.07)", ink: "#17140E", dim: "rgba(23,20,14,.66)", faint: "rgba(23,20,14,.45)",
             accent: "#9C6C17", glow: "rgba(156,108,23,.10)", up: "#0B8A55", down: "#C23447", ma50: "#A6741F", ma200: "#2F6FA8", dark: false },
    midnight: { label: "Midnight", bg: "#080D18", bg2: "#0E1626", panel: "rgba(226,236,255,.04)", line: "rgba(226,236,255,.10)",
                grid: "rgba(226,236,255,.06)", ink: "#EAF0FA", dim: "rgba(234,240,250,.64)", faint: "rgba(234,240,250,.42)",
                accent: "#8DB8F2", glow: "rgba(110,160,240,.16)", up: "#4FD1A1", down: "#F07383", ma50: "#E3A945", ma200: "#8DB8F2", dark: true },
    emerald: { label: "Emerald", bg: "#07110D", bg2: "#0D1A14", panel: "rgba(224,245,235,.04)", line: "rgba(224,245,235,.10)",
               grid: "rgba(224,245,235,.06)", ink: "#EAF5EF", dim: "rgba(234,245,239,.64)", faint: "rgba(234,245,239,.42)",
               accent: "#5FD49A", glow: "rgba(95,212,154,.14)", up: "#5FD49A", down: "#EF7A6E", ma50: "#E3C26A", ma200: "#8DB8F2", dark: true },
    graphite: { label: "Graphite", bg: "#111214", bg2: "#18191C", panel: "rgba(255,255,255,.035)", line: "rgba(255,255,255,.09)",
                grid: "rgba(255,255,255,.055)", ink: "#F2F2F0", dim: "rgba(242,242,240,.62)", faint: "rgba(242,242,240,.40)",
                accent: "#ECE7DA", glow: "rgba(255,255,255,.07)", up: "#7FD8A8", down: "#F08A8A", ma50: "#E3A945", ma200: "#9DB8DA", dark: true }
  };
  var F = {
    sans: '"Plus Jakarta Sans", "Segoe UI", Arial, sans-serif',
    serif: '"Instrument Serif", Georgia, serif',
    num: '"IBM Plex Sans", "Plus Jakarta Sans", Arial, sans-serif'
  };

  var state = { size: "wide", scheme: "onyx", headline: "", drawings: true, averages: true, stats: true };
  try {
    var saved = JSON.parse(localStorage.getItem("il-share-studio") || "{}");
    ["size", "scheme"].forEach(function (k) { if (saved[k]) state[k] = saved[k]; });
    ["drawings", "averages", "stats"].forEach(function (k) { if (typeof saved[k] === "boolean") state[k] = saved[k]; });
    if (!SIZES[state.size]) state.size = "wide";
    if (!SCHEMES[state.scheme]) state.scheme = "onyx";
  } catch (e) {}
  function persist() {
    try { localStorage.setItem("il-share-studio", JSON.stringify({ size: state.size, scheme: state.scheme, drawings: state.drawings, averages: state.averages, stats: state.stats })); } catch (e) {}
  }

  var root = null, canvas = null, fontsReady = null, logo = null, data = null;

  /* ── data from the chart on screen ─────────────────────────────────────── */
  function engine() { return window.ILChartEngine; }
  function activeInstance() {
    var e = engine();
    if (!e) return null;
    var list = e.instances();
    for (var i = 0; i < list.length; i++) if (list[i].mode === "full") return list[i];
    return list[0] || null;
  }
  function collect() {
    var e = engine(), inst = activeInstance();
    if (!e || !inst || !inst.rows || inst.rows.length < 2) return null;
    var rows = inst.rows, n = rows.length;
    /* Export what is on screen: the visible window of the active chart. */
    var from = 0, to = n - 1;
    try {
      var r = inst.chart.timeScale().getVisibleLogicalRange();
      if (r) { from = Math.max(0, Math.floor(r.from)); to = Math.min(n - 1, Math.ceil(r.to)); }
    } catch (err) {}
    if (to - from < 10) { from = Math.max(0, n - 60); to = n - 1; }
    var S = window.S || {};
    var ma = {};
    if (S.inds && S.inds.ma50) ma.ma50 = e.sma(rows, 50);
    if (S.inds && S.inds.ma200) ma.ma200 = e.sma(rows, 200);
    var lg = e.legend();
    var meta = (e.frame() && e.frame().result && e.frame().result.meta) || {};
    return {
      rows: rows, from: from, to: to, ma: ma, legend: lg,
      type: S.chartType || "candle",
      intraday: e.intraday(),
      interval: e.intervalLabel(),
      tz: meta.exchangeTimezoneName || "America/New_York",
      source: ((document.getElementById("quote-source") || {}).innerText || "").replace(/\s+/g, " ").trim(),
      drawings: window.ILChartTools ? window.ILChartTools.drawings().items : []
    };
  }

  /* ── formatting ────────────────────────────────────────────────────────── */
  function money(v) {
    if (!isFinite(v)) return "—";
    var a = Math.abs(v), d = a >= 1000 ? 0 : a >= 1 ? 2 : 4;
    return (v < 0 ? "−$" : "$") + a.toLocaleString("en-US", { minimumFractionDigits: d, maximumFractionDigits: d });
  }
  function signedPct(v) { return (v >= 0 ? "+" : "−") + Math.abs(v).toFixed(Math.abs(v) >= 100 ? 0 : 2) + "%"; }
  function signedMoney(v) { return (v >= 0 ? "+" : "−") + money(Math.abs(v)).replace("−", ""); }
  function vol(v) {
    if (!v) return "—";
    if (v >= 1e9) return (v / 1e9).toFixed(2) + "B";
    if (v >= 1e6) return (v / 1e6).toFixed(1) + "M";
    if (v >= 1e3) return Math.round(v / 1e3) + "K";
    return String(Math.round(v));
  }
  var dtfCache = {};
  function fmt(t, opts) {
    var key = JSON.stringify(opts);
    if (!dtfCache[key]) { try { dtfCache[key] = new Intl.DateTimeFormat("en-US", opts); } catch (e) { delete opts.timeZone; dtfCache[key] = new Intl.DateTimeFormat("en-US", opts); } }
    return dtfCache[key].format(new Date(t * 1000));
  }
  function windowWords(d) {
    var a = d.rows[d.from].time, b = d.rows[d.to].time, days = (b - a) / 86400;
    if (d.intraday && days < 1.2) return "today";
    if (days < 8) return "over the past " + Math.max(2, Math.round(days)) + " days";
    if (days < 45) return "over the past month";
    if (days < 120) return "over the past " + Math.round(days / 30.4) + " months";
    if (days < 330) return "over the past " + Math.round(days / 30.4) + " months";
    if (days < 420) return "over the past year";
    return "over the past " + Math.round(days / 365.25) + " years";
  }
  function stats(d) {
    var slice = d.rows.slice(d.from, d.to + 1);
    var first = slice[0], last = slice[slice.length - 1];
    var hi = -Infinity, lo = Infinity, hiT = 0, loT = 0, v = 0;
    slice.forEach(function (r) {
      if (r.high > hi) { hi = r.high; hiT = r.time; }
      if (r.low < lo) { lo = r.low; loT = r.time; }
      v += r.volume || 0;
    });
    var chg = last.close - first.close;
    return {
      first: first, last: last, hi: hi, lo: lo, hiT: hiT, loT: loT,
      chg: chg, pct: first.close ? chg / first.close * 100 : 0,
      avgVol: v / slice.length, offHigh: hi ? (last.close / hi - 1) * 100 : 0
    };
  }
  function shortName(n) { return String(n || "").replace(/,? (Inc|Corp|Corporation|Incorporated|Ltd|plc|Co|Holdings|Company)\.?$/i, ""); }
  function defaultHeadline(d, st) {
    var who = shortName(d.legend.name) || d.legend.ticker;
    var w = windowWords(d);
    var dir = st.pct >= 0 ? "up " : "down ";
    return who + " is " + dir + Math.abs(st.pct).toFixed(Math.abs(st.pct) >= 10 ? 0 : 1) + "% " + w;
  }

  /* ── canvas helpers ────────────────────────────────────────────────────── */
  /* The brand sans has a very narrow word space (about 0.17em, rounded down
     at small sizes), which made short labels read as one word on the image. */
  function font(g, weight, size, family) {
    g.font = weight + " " + Math.round(size) + "px " + family;
    if ("wordSpacing" in g) g.wordSpacing = size < 30 ? Math.round(size * 0.12) + "px" : Math.round(size * 0.04) + "px";
  }
  function rr(g, x, y, w, h, r) {
    r = Math.min(r, w / 2, h / 2);
    g.beginPath(); g.moveTo(x + r, y); g.arcTo(x + w, y, x + w, y + h, r); g.arcTo(x + w, y + h, x, y + h, r);
    g.arcTo(x, y + h, x, y, r); g.arcTo(x, y, x + w, y, r); g.closePath();
  }
  function fitFont(g, text, weight, size, family, maxW, min) {
    var s = size; font(g, weight, s, family);
    while (g.measureText(text).width > maxW && s > (min || 10)) { s -= 1; font(g, weight, s, family); }
    return s;
  }
  function wrap(g, text, maxW, maxLines) {
    var words = String(text).split(/\s+/), lines = [], line = "";
    words.forEach(function (w) {
      var t = line ? line + " " + w : w;
      if (g.measureText(t).width > maxW && line) { lines.push(line); line = w; } else line = t;
    });
    if (line) lines.push(line);
    if (lines.length > maxLines) {
      lines = lines.slice(0, maxLines);
      var l = lines[maxLines - 1];
      while (g.measureText(l + "…").width > maxW && l.length) l = l.slice(0, -1);
      lines[maxLines - 1] = l + "…";
    }
    return lines;
  }
  function hexA(hex, a) {
    var m = /^#?([0-9a-f]{6})$/i.exec(hex || "");
    if (!m) return hex;
    var n = parseInt(m[1], 16);
    return "rgba(" + (n >> 16 & 255) + "," + (n >> 8 & 255) + "," + (n & 255) + "," + a + ")";
  }
  function niceStep(range, target) {
    var raw = range / Math.max(1, target), mag = Math.pow(10, Math.floor(Math.log10(raw))), f = raw / mag;
    return (f < 1.5 ? 1 : f < 3 ? 2 : f < 7 ? 5 : 10) * mag;
  }

  /* ── the brand frame ───────────────────────────────────────────────────── */
  function brand(g, x, y, u, C) {
    var s = 40 * u;
    if (logo && logo.complete && logo.naturalWidth) g.drawImage(logo, x, y, s, s);
    g.textBaseline = "middle";
    font(g, 700, 24 * u, F.sans); g.fillStyle = C.ink;
    g.fillText("Implied", x + s + 12 * u, y + s / 2 + 1 * u);
    var iw = g.measureText("Implied").width;
    font(g, 700, 24 * u, F.sans); g.fillStyle = "#D9A441";
    if (!C.dark) g.fillStyle = "#9C6C17";
    g.fillText("Lens", x + s + 12 * u + iw, y + s / 2 + 1 * u);
    g.textBaseline = "alphabetic";
  }

  /* ── the chart ─────────────────────────────────────────────────────────── */
  function plot(g, box, d, C, u) {
    var rows = d.rows, from = d.from, to = d.to, n = to - from + 1;
    var axisW = 86 * u, axisH = 34 * u;
    var px = box.x + 4 * u, py = box.y + 10 * u, pw = box.w - axisW - 8 * u, ph = box.h - axisH - 14 * u;
    var lo = Infinity, hi = -Infinity, i;
    for (i = from; i <= to; i++) { lo = Math.min(lo, rows[i].low); hi = Math.max(hi, rows[i].high); }
    if (state.averages) Object.keys(d.ma).forEach(function (k) {
      for (var j = from; j <= to; j++) { var v = d.ma[k][j]; if (v != null && isFinite(v)) { lo = Math.min(lo, v); hi = Math.max(hi, v); } }
    });
    var pad = (hi - lo) * 0.08 || hi * 0.02 || 1;
    lo -= pad; hi += pad;
    var bw = pw / n;
    function X(idx) { return px + (idx - from + 0.5) * bw; }
    function Y(v) { return py + (1 - (v - lo) / (hi - lo)) * ph; }

    /* grid + price axis (labels give way to the last-price marker) */
    var lastY = Math.max(py + 10 * u, Math.min(py + ph - 10 * u, Y(rows[to].close)));
    var step = niceStep(hi - lo, ph > 420 * u ? 6 : 5);
    font(g, 500, 15 * u, F.num); g.textBaseline = "middle";
    for (var t = Math.ceil(lo / step) * step; t <= hi; t += step) {
      var yy = Y(t);
      g.strokeStyle = C.grid; g.lineWidth = 1;
      g.beginPath(); g.moveTo(px, Math.round(yy) + .5); g.lineTo(px + pw, Math.round(yy) + .5); g.stroke();
      g.fillStyle = C.faint; g.textAlign = "left";
      if (Math.abs(yy - lastY) > 24 * u) g.fillText(money(t).replace(".00", ""), px + pw + 14 * u, yy);
    }
    g.textAlign = "left"; g.textBaseline = "alphabetic";

    /* time axis: about five evenly spaced labels */
    var spanDays = (rows[to].time - rows[from].time) / 86400;
    var tfmt = d.intraday ? (spanDays < 1.5 ? { timeZone: d.tz, hour: "numeric", minute: "2-digit" } : { timeZone: d.tz, month: "short", day: "numeric" })
             : spanDays > 900 ? { timeZone: d.tz, month: "short", year: "numeric" }
             : { timeZone: d.tz, month: "short", day: "numeric" };
    var labels = Math.max(3, Math.min(6, Math.floor(pw / (170 * u))));
    font(g, 500, 15 * u, F.num); g.fillStyle = C.faint;
    for (var k = 0; k < labels; k++) {
      var idx = Math.round(from + (n - 1) * (k + 0.5) / labels);
      var tx = X(idx), label = fmt(rows[idx].time, tfmt);
      g.textAlign = "center";
      g.fillText(label, tx, py + ph + 26 * u);
    }
    g.textAlign = "left";

    g.save();
    rr(g, px, py - 4 * u, pw, ph + 8 * u, 0); g.clip();

    var type = d.type;
    if (type === "candle" && n > 320) type = "area";   // thousands of candles read as noise in a still image
    if (type === "candle") {
      var body = Math.max(1, Math.min(bw * 0.64, 18 * u));
      for (i = from; i <= to; i++) {
        var r = rows[i], up = r.close >= r.open, c = up ? C.up : C.down, x = X(i);
        g.strokeStyle = c; g.lineWidth = Math.max(1, 1.2 * u);
        g.beginPath(); g.moveTo(Math.round(x) + .5, Y(r.high)); g.lineTo(Math.round(x) + .5, Y(r.low)); g.stroke();
        var y1 = Y(Math.max(r.open, r.close)), y2 = Y(Math.min(r.open, r.close));
        g.fillStyle = c;
        g.fillRect(x - body / 2, y1, body, Math.max(1.2 * u, y2 - y1));
      }
    } else {
      var grad = g.createLinearGradient(0, py, 0, py + ph);
      grad.addColorStop(0, hexA(C.accent, C.dark ? .26 : .20));
      grad.addColorStop(1, hexA(C.accent, 0));
      g.beginPath();
      for (i = from; i <= to; i++) { var lx = X(i), ly = Y(rows[i].close); if (i === from) g.moveTo(lx, ly); else g.lineTo(lx, ly); }
      g.lineTo(X(to), py + ph); g.lineTo(X(from), py + ph); g.closePath();
      g.fillStyle = grad; g.fill();
      g.beginPath();
      for (i = from; i <= to; i++) { var mx = X(i), my = Y(rows[i].close); if (i === from) g.moveTo(mx, my); else g.lineTo(mx, my); }
      g.strokeStyle = C.accent; g.lineWidth = 3 * u; g.lineJoin = "round"; g.lineCap = "round"; g.stroke();
    }

    /* moving averages */
    if (state.averages) {
      [["ma50", C.ma50], ["ma200", C.ma200]].forEach(function (m) {
        var vals = d.ma[m[0]];
        if (!vals) return;
        g.beginPath();
        var started = false;
        for (var j = from; j <= to; j++) {
          var v = vals[j];
          if (v == null || !isFinite(v)) continue;
          if (!started) { g.moveTo(X(j), Y(v)); started = true; } else g.lineTo(X(j), Y(v));
        }
        g.strokeStyle = hexA(m[1], .95); g.lineWidth = 2.2 * u; g.lineJoin = "round"; g.stroke();
      });
    }

    /* the user's drawings, pinned to time and price exactly as on the chart */
    if (state.drawings && d.drawings.length && window.ILChartTools) {
      var tToL = window.ILChartTools.tToL;
      var P = function (pt) { return { x: px + (tToL(rows, pt.t) - from + 0.5) * bw, y: Y(pt.p) }; };
      var colr = function (k) {
        var map = { gold: ["#E2B65C", "#A6741F"], green: ["#34D48C", "#0B8A55"], red: ["#F0606E", "#C23447"],
                    blue: ["#72A9F2", "#2F6FC4"], violet: ["#B790F0", "#7446B8"], ink: ["#EDE9DF", "#1A1C20"] }[k] || ["#E2B65C", "#A6741F"];
        return C.dark ? map[0] : map[1];
      };
      d.drawings.forEach(function (it) {
        var c = colr(it.color), a = P(it.pts[0]), b = P(it.pts[1] || it.pts[0]);
        g.save(); g.lineCap = "round"; g.lineJoin = "round";
        if (it.type === "trend" || it.type === "ray") {
          var x2 = b.x, y2 = b.y;
          if (it.type === "ray" && b.x !== a.x) { var kx = (px + pw + 40 - a.x) / (b.x - a.x); if (kx > 1) { x2 = a.x + (b.x - a.x) * kx; y2 = a.y + (b.y - a.y) * kx; } }
          g.strokeStyle = c; g.lineWidth = 3 * u; g.beginPath(); g.moveTo(a.x, a.y); g.lineTo(x2, y2); g.stroke();
        } else if (it.type === "hline") {
          g.strokeStyle = c; g.lineWidth = 2.2 * u; g.setLineDash([10 * u, 7 * u]);
          g.beginPath(); g.moveTo(px, a.y); g.lineTo(px + pw, a.y); g.stroke();
        } else if (it.type === "rect") {
          var rx = Math.min(a.x, b.x), ry = Math.min(a.y, b.y), rw = Math.abs(b.x - a.x), rh = Math.abs(b.y - a.y);
          g.fillStyle = hexA(c, C.dark ? .16 : .14); g.fillRect(rx, ry, rw, rh);
          g.strokeStyle = hexA(c, .75); g.lineWidth = 1.5 * u; g.strokeRect(rx, ry, rw, rh);
        } else if (it.type === "fib") {
          var pA = it.pts[0].p, pB = (it.pts[1] || it.pts[0]).p, left = Math.min(a.x, b.x), right = Math.max(a.x, b.x, left + 60 * u);
          font(g, 600, 14 * u, F.num);
          [0, .236, .382, .5, .618, .786, 1].forEach(function (lv) {
            var pr = pB - (pB - pA) * lv, yy = Y(pr);
            g.strokeStyle = hexA(c, lv === 0 || lv === 1 ? .95 : .6); g.lineWidth = (lv === .618 ? 2.2 : 1.4) * u;
            g.beginPath(); g.moveTo(left, yy); g.lineTo(right, yy); g.stroke();
            g.fillStyle = hexA(c, .95); g.fillText((lv * 100).toFixed(lv === 0 || lv === 1 || lv === .5 ? 0 : 1) + "%  " + money(pr), left + 6 * u, yy - 6 * u);
          });
        } else if (it.type === "pen" || it.type === "marker") {
          var mk = it.type === "marker";
          g.strokeStyle = mk ? hexA(c, C.dark ? .34 : .38) : c; g.lineWidth = (mk ? 18 : 3) * u;
          g.beginPath();
          it.pts.forEach(function (pt, j) { var q = P(pt); if (j) g.lineTo(q.x, q.y); else g.moveTo(q.x, q.y); });
          g.stroke();
        }
        g.restore();
      });
    }
    g.restore();

    /* last price marker on the axis */
    var last = rows[to], ly2 = Math.max(py + 10 * u, Math.min(py + ph - 10 * u, Y(last.close)));
    var lc = last.close >= rows[from].close ? C.up : C.down;
    g.setLineDash([4 * u, 5 * u]); g.strokeStyle = hexA(lc, .7); g.lineWidth = 1.4 * u;
    g.beginPath(); g.moveTo(px, ly2); g.lineTo(px + pw, ly2); g.stroke(); g.setLineDash([]);
    font(g, 700, 15 * u, F.num);
    var label = money(last.close), lw = g.measureText(label).width + 16 * u;
    rr(g, px + pw + 6 * u, ly2 - 13 * u, lw, 26 * u, 7 * u); g.fillStyle = lc; g.fill();
    g.fillStyle = C.dark ? "#0B0A08" : "#FFFFFF"; g.textBaseline = "middle";
    g.fillText(label, px + pw + 14 * u, ly2 + 1 * u);
    g.textBaseline = "alphabetic";
  }

  /* ── composition ───────────────────────────────────────────────────────── */
  function draw(target) {
    var sz = SIZES[state.size], cv = target || canvas;
    if (!cv || !data) return;
    cv.width = sz.w; cv.height = sz.h;
    var g = cv.getContext("2d"), W = sz.w, H = sz.h, C = SCHEMES[state.scheme];
    var wide = W / H > 1.4, u = wide ? 1 : W / 1180;
    var d = data, st = stats(d);
    var P = (wide ? 64 : 60) * u;

    /* background */
    var bg = g.createLinearGradient(0, 0, 0, H);
    bg.addColorStop(0, C.bg2); bg.addColorStop(1, C.bg);
    g.fillStyle = bg; g.fillRect(0, 0, W, H);
    var glow = g.createRadialGradient(W * 0.88, -H * 0.08, 10, W * 0.88, -H * 0.08, Math.max(W, H) * 0.75);
    glow.addColorStop(0, C.glow); glow.addColorStop(1, hexA(C.bg, 0));
    g.fillStyle = glow; g.fillRect(0, 0, W, H);

    /* header: brand left, symbol context right */
    brand(g, P, P - 6 * u, u, C);
    g.textAlign = "right"; g.textBaseline = "middle";
    font(g, 600, 15 * u, F.sans); g.fillStyle = C.faint;
    var exch = String(d.legend.meta || "").split(" · ")[0];
    var span = d.intraday && (d.rows[d.to].time - d.rows[d.from].time) < 86400 * 1.2
      ? fmt(d.rows[d.to].time, { timeZone: d.tz, month: "short", day: "numeric", year: "numeric" })
      : fmt(d.rows[d.from].time, { timeZone: d.tz, month: "short", day: "numeric", year: "numeric" }) + " – " +
        fmt(d.rows[d.to].time, { timeZone: d.tz, month: "short", day: "numeric", year: "numeric" });
    var ctx = [d.legend.ticker, exch, span, d.interval].filter(Boolean).join("  ·  ");
    g.fillText(ctx, W - P, P + 14 * u);
    g.textAlign = "left"; g.textBaseline = "alphabetic";

    /* title block */
    var y = P + 92 * u;
    var chipText = d.legend.ticker || "";
    font(g, 700, 17 * u, F.num);
    var chipW = g.measureText(chipText).width + 22 * u;
    rr(g, P, y - 24 * u, chipW, 34 * u, 8 * u);
    g.fillStyle = hexA(C.accent, C.dark ? .14 : .12); g.fill();
    g.strokeStyle = hexA(C.accent, .4); g.lineWidth = 1.2 * u; g.stroke();
    g.fillStyle = C.accent; g.textBaseline = "middle";
    g.fillText(chipText, P + 11 * u, y - 7 * u);
    font(g, 600, 21 * u, F.sans); g.fillStyle = C.dim;
    g.fillText(d.legend.name || "", P + chipW + 14 * u, y - 7 * u);
    g.textBaseline = "alphabetic";

    var priceBlockW = wide ? 380 * u : 0;
    var headline = state.headline || defaultHeadline(d, st);
    var headSize = wide ? 50 * u : 56 * u;
    font(g, 700, headSize, F.sans);
    var maxW = W - P * 2 - priceBlockW - (wide ? 40 * u : 0);
    var lines = wrap(g, headline, maxW, 2);
    if (lines.length === 2 && g.measureText(lines[1]).width < maxW * 0.25) {
      headSize *= 0.9; font(g, 700, headSize, F.sans); lines = wrap(g, headline, maxW, 2);
    }
    var hy = y + 58 * u;
    lines.forEach(function (ln, i) {
      g.fillStyle = C.ink;
      g.fillText(ln, P, hy + i * headSize * 1.14);
    });
    var afterHead = hy + (lines.length - 1) * headSize * 1.14;

    /* price block: right column on landscape, under the headline otherwise */
    var up = st.chg >= 0, chgC = up ? C.up : C.down;
    var priceTxt = money(st.last.close);
    var chgTxt = (up ? "▲ " : "▼ ") + signedMoney(st.chg) + "  " + signedPct(st.pct);
    if (wide) {
      g.textAlign = "right";
      font(g, 600, 58 * u, F.num); g.fillStyle = C.ink;
      g.fillText(priceTxt, W - P, y + 50 * u);
      font(g, 700, 20 * u, F.num); g.fillStyle = chgC;
      g.fillText(chgTxt, W - P, y + 84 * u);
      g.textAlign = "left";
    } else {
      afterHead += 64 * u;
      font(g, 600, 54 * u, F.num); g.fillStyle = C.ink;
      g.fillText(priceTxt, P, afterHead);
      var pw0 = g.measureText(priceTxt).width;
      font(g, 700, 21 * u, F.num); g.fillStyle = chgC;
      g.fillText(chgTxt, P + pw0 + 18 * u, afterHead - 6 * u);
    }

    /* stats row */
    var footerH = 64 * u;
    var statsH = state.stats ? 92 * u : 0;
    var chartTop = (wide ? Math.max(afterHead, y + 84 * u) : afterHead) + (wide ? 38 * u : 30 * u);
    var chartBottom = H - P - footerH - (state.stats ? statsH + 18 * u : 0);
    var box = { x: P, y: chartTop, w: W - P * 2, h: chartBottom - chartTop };
    rr(g, box.x - 14 * u, box.y - 8 * u, box.w + 28 * u, box.h + 16 * u, 18 * u);
    g.fillStyle = C.panel; g.fill();
    g.strokeStyle = C.line; g.lineWidth = 1; g.stroke();
    plot(g, { x: box.x + 6 * u, y: box.y, w: box.w - 6 * u, h: box.h }, d, C, u);

    if (state.stats) {
      var tiles = [
        ["Period return", signedPct(st.pct), chgC],
        ["Period high", money(st.hi), null],
        ["Period low", money(st.lo), null],
        [d.intraday ? "Avg volume / bar" : "Avg daily volume", vol(st.avgVol), null]
      ];
      if (!/daily|min|hour/i.test(d.interval || "")) tiles[3][0] = "Avg volume / bar";
      var gap = 14 * u, tw = (W - P * 2 - gap * 3) / 4, ty = chartBottom + 18 * u;
      tiles.forEach(function (t, i) {
        var tx = P + i * (tw + gap);
        rr(g, tx, ty, tw, statsH, 14 * u);
        g.fillStyle = C.panel; g.fill(); g.strokeStyle = C.line; g.lineWidth = 1; g.stroke();
        font(g, 600, 16 * u, F.sans); g.fillStyle = C.faint;
        g.fillText(t[0], tx + 18 * u, ty + 32 * u);
        fitFont(g, t[1], 600, 30 * u, F.num, tw - 36 * u, 14);
        g.fillStyle = t[2] || C.ink;
        g.fillText(t[1], tx + 18 * u, ty + 70 * u);
      });
    }

    /* footer */
    var fy = H - P - 6 * u;
    g.strokeStyle = C.line; g.lineWidth = 1;
    g.beginPath(); g.moveTo(P, fy - 34 * u); g.lineTo(W - P, fy - 34 * u); g.stroke();
    font(g, 500, 15 * u, F.sans); g.fillStyle = C.faint;
    var asOf = fmt(st.last.time, d.intraday
      ? { timeZone: d.tz, month: "short", day: "numeric", year: "numeric", hour: "numeric", minute: "2-digit" }
      : { timeZone: d.tz, month: "short", day: "numeric", year: "numeric" });
    var src = "Price data: Yahoo Finance · as of " + asOf + (d.intraday ? " ET" : "") + " · Educational, not investment advice";
    fitFont(g, src, 500, 15 * u, F.sans, W - P * 2 - 220 * u, 10);
    g.fillText(src, P, fy);
    font(g, 700, 18 * u, F.sans); g.fillStyle = C.dark ? "#D9A441" : "#9C6C17";
    g.textAlign = "right"; g.fillText("impliedlens.com", W - P, fy); g.textAlign = "left";
  }

  /* ── post text and file actions ────────────────────────────────────────── */
  function postText() {
    var d = data, st = stats(d), t = d.legend.ticker;
    var link = "impliedlens.com/stock/" + encodeURIComponent(t);
    return "$" + t + " " + windowWords(d) + ": " + signedPct(st.pct) + " (" + money(st.first.close) + " → " + money(st.last.close) + ").\n" +
      "Range " + money(st.lo) + " – " + money(st.hi) + ", now " + Math.abs(st.offHigh).toFixed(1) + "% " + (st.offHigh < -0.05 ? "below" : "at") + " the high.\n\n" +
      "Chart and full research:\n" + link;
  }
  function fileName() {
    var d = data;
    return (d.legend.ticker || "chart") + "-" + String(d.legend.meta || "").split(" · ").slice(-2).join("-").replace(/\s+/g, "").toLowerCase() + "-" + state.size + ".png";
  }
  function blob() { return new Promise(function (res) { canvas.toBlob(res, "image/png"); }); }
  function note(msg, ok) { if (typeof window.toast === "function") window.toast(msg, ok === false ? "red" : "green"); }
  function download() {
    blob().then(function (b) {
      var url = URL.createObjectURL(b), a = document.createElement("a");
      a.href = url; a.download = fileName(); document.body.appendChild(a); a.click();
      setTimeout(function () { a.remove(); URL.revokeObjectURL(url); }, 200);
      note("Image saved");
    });
  }
  function copyImage() {
    if (!navigator.clipboard || !window.ClipboardItem) return note("Copying images isn't supported in this browser. Use Download.", false);
    navigator.clipboard.write([new ClipboardItem({ "image/png": blob() })])
      .then(function () { note("Image copied. Paste it into your post."); }, function () { note("Couldn't copy. Use Download instead.", false); });
  }
  function share() {
    blob().then(function (b) {
      var file = new File([b], fileName(), { type: "image/png" });
      var payload = { files: [file], text: postText() };
      if (navigator.canShare && navigator.canShare(payload)) navigator.share(payload).catch(function () {});
      else download();
    });
  }
  function copyText() {
    var t = root.querySelector(".ilss-post");
    (navigator.clipboard ? navigator.clipboard.writeText(t.value) : Promise.reject()).then(function () { note("Post text copied"); },
      function () { t.select(); document.execCommand("copy"); note("Post text copied"); });
  }

  /* ── UI ────────────────────────────────────────────────────────────────── */
  function ico(body) {
    return '<svg viewBox="0 0 24 24" width="17" height="17" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">' + body + "</svg>";
  }
  var I = {
    download: ico('<path d="M12 4v11M7.5 10.5L12 15l4.5-4.5M5 19.5h14"/>'),
    copy: ico('<rect x="8.5" y="8.5" width="11" height="11" rx="2"/><path d="M15.5 8.5V6.5a2 2 0 00-2-2h-7a2 2 0 00-2 2v7a2 2 0 002 2h2"/>'),
    share: ico('<path d="M12 15V4M7.5 8.5L12 4l4.5 4.5"/><path d="M5 13v5a2 2 0 002 2h10a2 2 0 002-2v-5"/>'),
    text: ico('<path d="M5 6h14M5 11h14M5 16h9"/>'),
    x: ico('<path d="M6 6l12 12M18 6L6 18"/>')
  };

  var CSS =
    "html.ilss-open{overflow:hidden}" +
    ".ilss[hidden]{display:none}.ilss{position:fixed;inset:0;z-index:2147483300;display:flex;align-items:center;justify-content:center;padding:24px;font-family:'Plus Jakarta Sans',-apple-system,sans-serif}" +
    ".ilss-back{position:absolute;inset:0;background:rgba(6,5,4,.74);backdrop-filter:blur(6px);-webkit-backdrop-filter:blur(6px)}" +
    ".ilss-sheet{--k-ink:#F3EEE3;--k-dim:rgba(243,238,227,.66);--k-faint:rgba(243,238,227,.45);--k-line:rgba(243,238,227,.12);--k-bg:#14120F;--k-well:#0D0C0A;--k-gold:#E3A945;position:relative;width:min(1280px,100%);max-height:calc(100dvh - 48px);overflow:auto;background:var(--k-bg);color:var(--k-ink);border:1px solid var(--k-line);border-radius:20px;box-shadow:0 30px 80px rgba(0,0,0,.5);outline:none}" +
    "html:not([data-theme='dark']) .ilss-sheet{--k-ink:#17140E;--k-dim:rgba(23,20,14,.68);--k-faint:rgba(23,20,14,.48);--k-line:rgba(23,20,14,.12);--k-bg:#FFFDF9;--k-well:#F4EFE5;--k-gold:#9C6C17}" +
    ".ilss-head{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;padding:22px 26px 6px}" +
    ".ilss-kicker{font:700 12px/1 'Plus Jakarta Sans',sans-serif;color:var(--k-gold);letter-spacing:.06em;text-transform:uppercase}" +
    ".ilss-head h2{margin:8px 0 0;font:700 24px/1.2 'Plus Jakarta Sans',sans-serif;color:var(--k-ink)}" +
    ".ilss-x{width:40px;height:40px;border-radius:12px;border:1px solid var(--k-line);background:transparent;color:inherit;cursor:pointer;display:grid;place-items:center}" +
    ".ilss-body{display:grid;grid-template-columns:290px minmax(0,1fr);grid-template-areas:'c s' 'c a';gap:18px 24px;padding:16px 26px 26px}" +
    ".ilss-body>*{min-width:0}.ilss-controls{grid-area:c;display:flex;flex-direction:column;gap:18px}" +
    ".ilss-stage{grid-area:s;background:var(--k-well);border:1px solid var(--k-line);border-radius:14px;padding:14px;display:flex;align-items:center;justify-content:center;min-height:240px}" +
    ".ilss-canvas{display:block;max-width:100%;max-height:min(58vh,620px);width:auto;height:auto;border-radius:8px;box-shadow:0 10px 40px rgba(0,0,0,.4)}" +
    ".ilss-actions{grid-area:a;display:flex;flex-wrap:wrap;gap:10px;align-items:flex-start}" +
    ".ilss-group{display:flex;flex-direction:column;gap:8px;margin:0;border:0;padding:0}" +
    ".ilss-lbl{font:600 13px/1.2 'Plus Jakarta Sans',sans-serif;color:var(--k-dim)}.ilss-lbl em{font-style:normal;font-weight:500;opacity:.65}" +
    ".ilss-schemes{display:grid;grid-template-columns:repeat(5,1fr);gap:8px}" +
    ".ilss-scheme{display:flex;flex-direction:column;align-items:center;gap:6px;padding:0;border:0;background:none;color:var(--k-dim);font:600 11.5px/1 'Plus Jakarta Sans',sans-serif;cursor:pointer}" +
    ".ilss-scheme i{display:block;width:100%;aspect-ratio:1;border-radius:12px;border:1px solid var(--k-line);position:relative;overflow:hidden}" +
    ".ilss-scheme i::after{content:'';position:absolute;left:18%;right:18%;bottom:30%;height:3px;border-radius:2px;background:var(--a);box-shadow:0 -7px 0 -1px var(--a2)}" +
    ".ilss-scheme[aria-pressed=true]{color:var(--k-ink)}.ilss-scheme[aria-pressed=true] i{box-shadow:0 0 0 2px var(--k-bg),0 0 0 4px var(--k-gold)}" +
    ".ilss-seg{display:flex;padding:3px;border-radius:12px;border:1px solid var(--k-line);gap:3px}" +
    ".ilss-seg button{flex:1;min-height:38px;border:0;border-radius:9px;background:transparent;color:var(--k-dim);font:600 13.5px/1 'Plus Jakarta Sans',sans-serif;cursor:pointer}" +
    ".ilss-seg button[aria-pressed=true]{background:var(--k-gold);color:#17130C}" +
    ".ilss-note{font:500 12.5px/1.3 'Plus Jakarta Sans',sans-serif;color:var(--k-faint)}" +
    ".ilss-toggles{display:flex;flex-direction:column;gap:2px}" +
    ".ilss-tog{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:8px 2px;border:0;background:none;color:var(--k-ink);font:500 14px/1.2 'Plus Jakarta Sans',sans-serif;cursor:pointer;text-align:left}" +
    ".ilss-tog span:last-child{width:36px;height:20px;border-radius:999px;background:var(--k-line);position:relative;flex:0 0 auto;transition:background .15s}" +
    ".ilss-tog span:last-child::after{content:'';position:absolute;top:2px;left:2px;width:16px;height:16px;border-radius:50%;background:#fff;transition:transform .15s}" +
    ".ilss-tog[aria-pressed=true] span:last-child{background:var(--k-gold)}.ilss-tog[aria-pressed=true] span:last-child::after{transform:translateX(16px)}" +
    ".ilss-tog[disabled]{opacity:.45;cursor:default}" +
    ".ilss-head-in,.ilss-post{width:100%;box-sizing:border-box;border-radius:10px;border:1px solid var(--k-line);background:var(--k-well);color:inherit;font:500 14px/1.45 'Plus Jakarta Sans',sans-serif;padding:10px 12px}" +
    ".ilss-post{resize:vertical;min-height:110px}.ilss-postwrap{flex:1 1 100%}" +
    ".ilss-btn{min-height:42px;padding:0 16px;border-radius:11px;border:1px solid var(--k-line);background:transparent;color:inherit;font:600 14px/1 'Plus Jakarta Sans',sans-serif;display:inline-flex;align-items:center;gap:8px;cursor:pointer}" +
    ".ilss-btn.is-gold{background:var(--k-gold);border-color:transparent;color:#17130C}" +
    ".ilss-btn:focus-visible,.ilss-scheme:focus-visible,.ilss-seg button:focus-visible,.ilss-x:focus-visible,.ilss-tog:focus-visible{outline:2px solid var(--k-gold);outline-offset:2px}" +
    "@media (max-width:860px){.ilss{padding:0;align-items:flex-end}.ilss-sheet{max-height:94dvh;border-radius:20px 20px 0 0}" +
    ".ilss-body{grid-template-columns:1fr;grid-template-areas:'s' 'c' 'a';padding:10px 16px 24px}.ilss-head{padding:18px 16px 4px}" +
    ".ilss-stage{padding:8px;min-height:0}.ilss-canvas{max-height:46vh}.ilss-head-in,.ilss-post{font-size:16px}.ilss-btn{flex:1 1 auto;justify-content:center}}";

  function build() {
    if (!document.getElementById("ilss-style")) {
      var st = document.createElement("style"); st.id = "ilss-style"; st.textContent = CSS; document.head.appendChild(st);
    }
    root = document.createElement("div");
    root.className = "ilss"; root.hidden = true;
    root.innerHTML =
      '<div class="ilss-back" data-close></div>' +
      '<div class="ilss-sheet" role="dialog" aria-modal="true" aria-labelledby="ilss-title" tabindex="-1">' +
        '<header class="ilss-head"><div><span class="ilss-kicker">Share Studio</span><h2 id="ilss-title">Make a post-ready chart image</h2></div>' +
        '<button type="button" class="ilss-x" data-close aria-label="Close">' + I.x + "</button></header>" +
        '<div class="ilss-body">' +
          '<div class="ilss-controls">' +
            '<div class="ilss-group"><span class="ilss-lbl">Style</span><div class="ilss-schemes">' +
              Object.keys(SCHEMES).map(function (k) {
                var C = SCHEMES[k];
                return '<button type="button" class="ilss-scheme" data-ilss="scheme:' + k + '"><i style="background:linear-gradient(160deg,' + C.bg2 + "," + C.bg + ");--a:" + C.accent + ";--a2:" + C.up + '"></i>' + C.label + "</button>";
              }).join("") +
            "</div></div>" +
            '<div class="ilss-group"><span class="ilss-lbl">Size</span><div class="ilss-seg">' +
              Object.keys(SIZES).map(function (k) { return '<button type="button" data-ilss="size:' + k + '">' + SIZES[k].label + "</button>"; }).join("") +
            '</div><span class="ilss-note ilss-size-note"></span></div>' +
            '<label class="ilss-group"><span class="ilss-lbl">Headline <em>optional</em></span><input class="ilss-head-in" type="text" maxlength="90" autocomplete="off"></label>' +
            '<div class="ilss-group"><span class="ilss-lbl">Include</span><div class="ilss-toggles">' +
              '<button type="button" class="ilss-tog" data-tog="drawings"><span>Your drawings</span><span></span></button>' +
              '<button type="button" class="ilss-tog" data-tog="averages"><span>Moving averages</span><span></span></button>' +
              '<button type="button" class="ilss-tog" data-tog="stats"><span>Stats row</span><span></span></button>' +
            "</div></div>" +
            '<span class="ilss-note">The image shows the stretch of chart that is on your screen. Pan or zoom the chart first to frame it.</span>' +
          "</div>" +
          '<div class="ilss-stage"><canvas class="ilss-canvas" aria-label="Preview of the chart image"></canvas></div>' +
          '<div class="ilss-actions">' +
            '<button type="button" class="ilss-btn is-gold" data-act="download">' + I.download + " Download PNG</button>" +
            '<button type="button" class="ilss-btn" data-act="copy">' + I.copy + " Copy image</button>" +
            '<button type="button" class="ilss-btn ilss-share" data-act="share" hidden>' + I.share + " Share</button>" +
            '<label class="ilss-group ilss-postwrap"><span class="ilss-lbl">Suggested post</span><textarea class="ilss-post" rows="4"></textarea></label>' +
            '<button type="button" class="ilss-btn" data-act="text">' + I.text + " Copy post text</button>" +
          "</div>" +
        "</div>" +
      "</div>";
    document.body.appendChild(root);
    canvas = root.querySelector(".ilss-canvas");
    if (navigator.canShare && window.File) {
      try { if (navigator.canShare({ files: [new File([""], "x.png", { type: "image/png" })] })) root.querySelector(".ilss-share").hidden = false; } catch (e) {}
    }
    root.addEventListener("click", function (e) {
      if (e.target.closest("[data-close]")) return close();
      var b = e.target.closest("[data-ilss]");
      if (b) { var p = b.getAttribute("data-ilss").split(":"); state[p[0]] = p[1]; persist(); render(); return; }
      var t = e.target.closest("[data-tog]");
      if (t && !t.disabled) { var k = t.getAttribute("data-tog"); state[k] = !state[k]; persist(); render(); return; }
      var a = e.target.closest("[data-act]");
      if (!a) return;
      var act = a.getAttribute("data-act");
      if (act === "download") download(); else if (act === "copy") copyImage(); else if (act === "share") share(); else if (act === "text") copyText();
    });
    root.querySelector(".ilss-head-in").addEventListener("input", function (e) { state.headline = e.target.value.trim(); draw(); });
    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape" && root && !root.hidden) { e.stopImmediatePropagation(); close(); }
    }, true);
  }

  function render() {
    if (!root || !data) return;
    root.querySelectorAll("[data-ilss]").forEach(function (b) {
      var p = b.getAttribute("data-ilss").split(":");
      b.setAttribute("aria-pressed", String(state[p[0]] === p[1]));
    });
    root.querySelectorAll("[data-tog]").forEach(function (b) {
      var k = b.getAttribute("data-tog");
      var avail = k === "drawings" ? data.drawings.length > 0 : k === "averages" ? Object.keys(data.ma).length > 0 : true;
      b.disabled = !avail;
      b.setAttribute("aria-pressed", String(avail && !!state[k]));
    });
    root.querySelector(".ilss-size-note").textContent = SIZES[state.size].note;
    root.querySelector(".ilss-head-in").placeholder = defaultHeadline(data, stats(data));
    root.querySelector(".ilss-post").value = postText();
    draw();
  }

  function ensureAssets() {
    if (!logo) {
      logo = new Image();
      logo.src = "/logo-mark.png";
    }
    var logoReady = logo.complete ? Promise.resolve() : new Promise(function (res) { logo.onload = logo.onerror = res; });
    if (!fontsReady) {
      fontsReady = !document.fonts || !document.fonts.load ? Promise.resolve() : Promise.all([
        document.fonts.load('700 40px "Plus Jakarta Sans"'), document.fonts.load('600 20px "Plus Jakarta Sans"'),
        document.fonts.load('500 20px "Plus Jakarta Sans"'), document.fonts.load('600 40px "IBM Plex Sans"'),
        document.fonts.load('700 20px "IBM Plex Sans"'), document.fonts.load('500 16px "IBM Plex Sans"')
      ]).catch(function () {});
    }
    return Promise.all([logoReady, fontsReady]);
  }

  function open() {
    var d = collect();
    if (!d || !d.legend.ticker) {
      note("Load a company chart first", false);
      var input = document.getElementById("main-ticker");
      if (input) input.focus();
      return;
    }
    if (!root) build();
    data = d;
    state.headline = "";
    root.querySelector(".ilss-head-in").value = "";
    root.hidden = false;
    document.documentElement.classList.add("ilss-open");
    root.querySelector(".ilss-sheet").focus({ preventScroll: true });
    render();
    ensureAssets().then(render);
  }
  function close() {
    if (!root) return;
    root.hidden = true;
    document.documentElement.classList.remove("ilss-open");
  }

  function install() {
    window.openShareStudio = open;
    window.closeShareStudio = close;
    window.renderShareStudio = function () { if (root && !root.hidden) render(); };
    window.downloadShareStudio = function () { if (root && !root.hidden) download(); };
    window.exportExpandedChart = open;
  }
  window.ILShareStudio = { open: open, close: close, _draw: draw, _state: state, _collect: collect, _setData: function (d) { data = d; } };

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", install);
  else install();
  /* app-legacy.js defines its own exportExpandedChart; keep ours. */
  setTimeout(install, 1400);
}());

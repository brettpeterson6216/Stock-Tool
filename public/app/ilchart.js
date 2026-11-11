/* ═══════════════════════════════════════════════════════════════════════════
   IL.Chart: the site's own chart engine. One canvas, no library.

   Time runs on bar positions, not clock time, so nights, weekends and
   holidays take no room. The view is a window [from, to] in bar positions:

     drag                       move through time, with a glide on release
     wheel after a click        zoom at the pointer (Ctrl/⌘ + wheel always zooms)
     trackpad pinch / swipe     zoom / move
     two fingers                pinch to zoom; one finger drags; a tap reads a bar
     double-click, double-tap   back to the view the page asked for
     keyboard                   ← → read bars, Shift + ← → move, + − zoom, 0 reset

   The price scale fits whatever is in view and eases to it. Everything is
   drawn from the theme tokens in lens.css and redrawn on a theme switch.

     var ch = IL.Chart(host, { label, onCross(i, how), onView(view), describe(i) });
     ch.set({ times, series, panes, lines, rebase, intraday, fmtY, fmtTime }, { show: i0 | keep: true });
     ch.show(i0, { animate: true });      // from bar i0 to the latest bar; becomes "home"
     ch.val(id, i);  ch.view();  ch.destroy();

   Series: { id, kind: "line" | "area" | "candles" | "hist", v: [], o, h, l,
             pane, color, width, smooth, tag, marker, auto, colors(i), fmt }
   ═══════════════════════════════════════════════════════════════════════════ */
(function () {
  "use strict";
  var IL = window.IL = window.IL || {};
  var ET = "America/New_York", MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  var AXIS_H = 26, FONT = '"IBM Plex Sans", Inter, system-ui, sans-serif';

  function css(n) { return getComputedStyle(document.documentElement).getPropertyValue(n).trim(); }
  function clamp(v, a, b) { return v < a ? a : v > b ? b : v; }
  function fin(v) { return typeof v === "number" && isFinite(v); }
  function rgba(color, a) {
    var m = /^#([0-9a-f]{3}|[0-9a-f]{6})$/i.exec(color);
    if (m) {
      var x = m[1].length === 3 ? m[1].replace(/./g, "$&$&") : m[1];
      return "rgba(" + parseInt(x.slice(0, 2), 16) + "," + parseInt(x.slice(2, 4), 16) + "," + parseInt(x.slice(4, 6), 16) + "," + a + ")";
    }
    m = /^rgba?\(\s*([\d.]+)[\s,]+([\d.]+)[\s,]+([\d.]+)/i.exec(color);
    return m ? "rgba(" + m[1] + "," + m[2] + "," + m[3] + "," + a + ")" : color;
  }
  /* Dark ink on a light tag, white on a dark one. */
  function inkOn(color) {
    var m = /rgba\((\d+),(\d+),(\d+)/.exec(rgba(color, 1));
    if (!m) return "#fff";
    return (0.2126 * m[1] + 0.7152 * m[2] + 0.0722 * m[3]) / 255 > 0.55 ? "#17130A" : "#fff";
  }

  /* Calendar parts in Eastern Time for each bar, and how big a boundary each
     bar starts: a year (70), a quarter (65), a month (60), a week (50), a day
     (40), an hour (30), a half hour (20). The time axis labels the biggest
     boundaries first and fills in smaller ones where there is room. */
  var partsFmt = null;
  function calendar(times) {
    if (!partsFmt) partsFmt = new Intl.DateTimeFormat("en-US", { timeZone: ET, year: "numeric", month: "numeric", day: "numeric", hour: "numeric", minute: "numeric", hourCycle: "h23" });
    var P = new Array(times.length), W = new Array(times.length), prev = null;
    for (var i = 0; i < times.length; i++) {
      var o = {}, parts = partsFmt.formatToParts(new Date(times[i] * 1000));
      for (var k = 0; k < parts.length; k++) o[parts[k].type] = parts[k].value;
      var p = { y: +o.year, m: +o.month, d: +o.day, h: +o.hour % 24, mi: +o.minute, t: times[i] };
      p.dow = new Date(Date.UTC(p.y, p.m - 1, p.d)).getUTCDay();
      var w = 10;
      if (prev) {
        if (p.y !== prev.y) w = 70;
        else if (p.m !== prev.m) w = (p.m - 1) % 3 === 0 ? 65 : 60;
        else if (p.d !== prev.d) w = p.dow < prev.dow || times[i] - prev.t > 6 * 86400 ? 50 : 40;
        else if (p.h !== prev.h) w = 30;
        else if (p.mi % 30 === 0) w = 20;
      }
      P[i] = p; W[i] = w; prev = p;
    }
    return { p: P, w: W };
  }
  /* Label sets from coarse to fine. The axis uses the finest one whose labels
     still have room, so a view never mixes "Apr" with "Feb 8". */
  var SETS = [
    function (p, w) { return w >= 70 && p.y % 10 === 0; }, function (p, w) { return w >= 70 && p.y % 5 === 0; },
    function (p, w) { return w >= 70 && p.y % 2 === 0; }, function (p, w) { return w >= 70; },
    function (p, w) { return w >= 60 && (p.m === 1 || p.m === 7); }, function (p, w) { return w >= 60 && (p.m - 1) % 3 === 0; },
    function (p, w) { return w >= 60 && p.m % 2 === 1; }, function (p, w) { return w >= 60; },
    function (p, w) { return w >= 50; }, function (p, w) { return w >= 40; },
    function (p, w) { return w >= 40 || (w >= 30 && p.h % 4 === 0); }, function (p, w) { return w >= 40 || (w >= 30 && p.h % 2 === 0); },
    function (p, w) { return w >= 30; },
    function (p, w) { return w >= 20; }, function () { return true; },
  ];
  function tickText(p, w) {
    if (w >= 70) return String(p.y);
    if (w >= 60) return MONTHS[p.m - 1];
    if (w >= 40) return MONTHS[p.m - 1] + " " + p.d;
    var h = p.h % 12 || 12, ap = p.h < 12 ? "AM" : "PM";
    return w >= 30 && p.mi === 0 ? h + " " + ap : h + ":" + (p.mi < 10 ? "0" : "") + p.mi;
  }

  function niceStep(raw) {
    var p = Math.pow(10, Math.floor(Math.log10(raw))), f = raw / p;
    return (f <= 1 ? 1 : f <= 2 ? 2 : f <= 2.5 ? 2.5 : f <= 5 ? 5 : 10) * p;
  }

  /* A smooth line through every point that never overshoots one (monotone
     cubic), drawn straight once the points are closer than the eye can tell. */
  function trace(ctx, xs, ys, a, b) {
    var n = b - a + 1, k;
    ctx.moveTo(xs[a], ys[a]);
    if (n < 3 || xs[a + 1] - xs[a] < 2.5) { for (k = a + 1; k <= b; k++) ctx.lineTo(xs[k], ys[k]); return; }
    var d = new Array(n - 1), m = new Array(n);
    for (k = 0; k < n - 1; k++) d[k] = (ys[a + k + 1] - ys[a + k]) / (xs[a + k + 1] - xs[a + k]);
    m[0] = d[0]; m[n - 1] = d[n - 2];
    for (k = 1; k < n - 1; k++) m[k] = d[k - 1] * d[k] <= 0 ? 0 : (d[k - 1] + d[k]) / 2;
    for (k = 0; k < n - 1; k++) {
      if (d[k] === 0) { m[k] = 0; m[k + 1] = 0; continue; }
      var A = m[k] / d[k], B = m[k + 1] / d[k], s = A * A + B * B;
      if (s > 9) { var t = 3 / Math.sqrt(s); m[k] = t * A * d[k]; m[k + 1] = t * B * d[k]; }
    }
    for (k = 0; k < n - 1; k++) {
      var x0 = xs[a + k], x1 = xs[a + k + 1], h = (x1 - x0) / 3;
      ctx.bezierCurveTo(x0 + h, ys[a + k] + m[k] * h, x1 - h, ys[a + k + 1] - m[k + 1] * h, x1, ys[a + k + 1]);
    }
  }

  IL.Chart = function (host, opts) {
    opts = opts || {};
    var still = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    host.innerHTML = "";
    host.classList.add("ilc");
    var cv = document.createElement("canvas");
    cv.tabIndex = 0; cv.setAttribute("role", "img"); cv.setAttribute("aria-label", opts.label || "Chart");
    var ctl = document.createElement("div"); ctl.className = "ilc-ctl";
    ctl.innerHTML = '<button type="button" class="ilc-z" data-z="in" aria-label="Zoom in" title="Zoom in">+</button>' +
      '<button type="button" class="ilc-z" data-z="out" aria-label="Zoom out" title="Zoom out">−</button>' +
      '<button type="button" class="ilc-reset" data-z="reset" hidden>Reset</button>';
    var hint = document.createElement("div"); hint.className = "ilc-hint"; hint.setAttribute("aria-hidden", "true");
    var live = document.createElement("p"); live.className = "ilc-live"; live.setAttribute("aria-live", "polite");
    host.appendChild(cv); host.appendChild(ctl); host.appendChild(hint); host.appendChild(live);
    var ctx = cv.getContext("2d");

    var D = { times: [], n: 0, series: [], panes: [], lines: [], cal: { p: [], w: [] } };
    var V = { from: -0.5, to: 0.5 }, home = null, sent = "";
    var W = 0, H = 0, dpr = 1, G = 56, plotW = 0, rects = {};
    var cross = null;             // { i, y, pane, how }
    var yNow = {}, bases = {};
    var raf = 0, lastT = 0, anim = null, glide = null, dead = false;
    var T = {};

    function theme() {
      T = { text: css("--text"), t2: css("--text2"), t3: css("--text3"), grid: css("--chart-grid"), line: css("--line"), line3: css("--line3"),
        raised: css("--raised"), surface: css("--surface"), gain: css("--gain"), loss: css("--loss") };
      T.cache = {};
    }
    function col(c) { if (!c) return T.t2; if (c.indexOf("--") !== 0) return c; return T.cache[c] || (T.cache[c] = css(c) || T.t2); }

    /* ── The window ─────────────────────────────────────────────────────── */
    function pad(span) { return Math.max(1.5, span * 0.012); }
    function minSpan() { return Math.min(D.n, 10); }
    function fix(from, to) {
      var span = clamp(to - from, minSpan(), D.n + pad(D.n) + 0.01);
      var lo = -0.5, hi = D.n - 0.5 + pad(span);
      if (span >= hi - lo) return { from: lo, to: hi };
      if (from < lo) from = lo;
      if (from + span > hi) from = hi - span;
      return { from: from, to: from + span };
    }
    function setView(from, to) { V = fix(from, to); request(); }
    function idxAt(x) { return V.from + x / plotW * (V.to - V.from); }
    function X(i) { return (i - V.from) / (V.to - V.from) * plotW; }
    function first() { return clamp(Math.ceil(V.from), 0, D.n - 1); }
    function last() { return clamp(Math.floor(V.to), 0, D.n - 1); }
    function atHome() { return !!home && Math.abs(V.from - home[0]) < 0.01 && Math.abs(V.to - home[1]) < 0.01; }
    function viewInfo() { return { from: V.from, to: V.to, i0: first(), i1: last(), atHome: atHome() }; }
    function zoomAt(factor, x) {
      var span = V.to - V.from, next = clamp(span * factor, minSpan(), D.n + pad(D.n));
      var at = x === undefined ? (V.to >= D.n - 0.5 ? V.to : (V.from + V.to) / 2) : idxAt(x);
      var k = (at - V.from) / span;
      stop(); setView(at - k * next, at - k * next + next);
    }
    function stop() { anim = null; glide = null; }
    function animateTo(from, to) {
      var b = fix(from, to);
      if (still) { V = b; request(); return; }
      anim = { a: { from: V.from, to: V.to }, b: b, t: 0, ms: 280 }; glide = null; request();
    }
    function show(i0, o) {
      var span = D.n - i0, from = i0 - 0.5, to = D.n - 0.5 + pad(span + 0.5);
      var b = fix(from, to); home = [b.from, b.to];
      if (o && o.animate) animateTo(b.from, b.to); else { stop(); V = b; request(); }
    }

    /* ── Data ───────────────────────────────────────────────────────────── */
    function set(d, o) {
      o = o || {};
      var same = o.keep && D.n === (d.times || []).length;
      D.times = d.times || []; D.n = D.times.length;
      D.series = d.series || []; D.panes = d.panes || []; D.lines = d.lines || [];
      D.rebase = !!d.rebase; D.floor = d.floor; D.fmtY = d.fmtY || function (v) { return String(Math.round(v * 100) / 100); };
      D.fmtTime = d.fmtTime || function (t) { return new Date(t * 1000).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric", timeZone: ET }); };
      D.cal = calendar(D.times);
      cross = null; stop();
      if (!same) { yNow = {}; V = fix(-0.5, D.n - 0.5 + pad(D.n)); home = [V.from, V.to]; if (typeof o.show === "number") show(o.show); }
      sent = "";
      request();
    }
    function paneOf(s) { return s.pane || "main"; }
    function val(s, i) {
      var v = s.v[i];
      if (!D.rebase) return v;
      var b = bases[s.id];
      return fin(v) && b ? (v / b - 1) * 100 : NaN;
    }
    function rebase(i0) {
      bases = {};
      if (!D.rebase) return;
      D.series.forEach(function (s) { for (var i = i0; i < D.n; i++) if (fin(s.v[i]) && s.v[i] > 0) { bases[s.id] = s.v[i]; break; } });
    }

    /* ── Scales ─────────────────────────────────────────────────────────── */
    function fit(pane, i0, i1) {
      if (pane.min != null) return { min: pane.min, max: pane.max };
      var lo = Infinity, hi = -Infinity, hist = false;
      D.series.forEach(function (s) {
        if (paneOf(s) !== pane.id) return;
        if (s.kind === "hist") { hist = true; return; }
        if (s.auto === false) return;
        for (var i = i0; i <= i1; i++) {
          var a = s.kind === "candles" ? s.l[i] : val(s, i), b = s.kind === "candles" ? s.h[i] : a;
          if (fin(a) && a < lo) lo = a;
          if (fin(b) && b > hi) hi = b;
        }
      });
      D.lines.forEach(function (l) { if ((l.pane || "main") === pane.id && l.fit) { if (l.value < lo) lo = l.value; if (l.value > hi) hi = l.value; } });
      if (!fin(lo) || !fin(hi)) return null;
      if (hi === lo) { var e = Math.abs(lo) * 0.01 || 1; lo -= e; hi += e; }
      var pt = 0.1, pb = hist ? 0.24 : 0.1, r = (hi - lo) / (1 - pt - pb);
      return { min: lo - r * pb, max: hi + r * pt };
    }
    function ease(id, target, dt) {
      var c = yNow[id];
      if (!target) return false;
      if (!c || still || !dt) { yNow[id] = { min: target.min, max: target.max }; return false; }
      var k = 1 - Math.exp(-dt / 70), span = target.max - target.min || 1;
      c.min += (target.min - c.min) * k; c.max += (target.max - c.max) * k;
      if (Math.abs(target.min - c.min) + Math.abs(target.max - c.max) < span * 0.002) { c.min = target.min; c.max = target.max; return false; }
      return true;
    }
    function ticksFor(pane, r) {
      if (pane.ticks) return { list: pane.ticks, step: 1 };
      var sc = yNow[pane.id]; if (!sc) return { list: [], step: 1 };
      var step = niceStep((sc.max - sc.min) / Math.max(2, Math.floor(r.h / 54)) * 0.7), out = [];
      for (var v = Math.ceil(sc.min / step) * step; v <= sc.max; v += step) out.push(Math.abs(v) < step / 1e6 ? 0 : v);
      return { list: out, step: step };
    }

    /* ── Drawing ────────────────────────────────────────────────────────── */
    function size() {
      var w = host.clientWidth, h = host.clientHeight, r = window.devicePixelRatio || 1;
      if (w === W && h === H && r === dpr) return;
      W = w; H = h; dpr = r;
      cv.width = Math.max(1, Math.round(W * dpr)); cv.height = Math.max(1, Math.round(H * dpr));
    }
    function layout() {
      var sub = 0; D.panes.forEach(function (p) { sub += p.height + 1; });
      rects = { main: { id: "main", y: 0, h: Math.max(40, H - AXIS_H - sub) } };
      var y = rects.main.h + 1;
      D.panes.forEach(function (p) { rects[p.id] = { id: p.id, y: y, h: p.height, pane: p }; y += p.height + 1; });
      ctl.style.bottom = (H - rects.main.h + 8) + "px";
    }
    function Y(id, v) { var r = rects[id], s = yNow[id]; return r.y + r.h * (1 - (v - s.min) / (s.max - s.min)); }
    function px(v) { return Math.round(v) + 0.5; }

    function draw(dt) {
      size();
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, W, H);
      if (!D.n || W < 40 || H < 60) return false;
      layout();
      var i0 = first(), i1 = last(), moving = false;
      rebase(i0);
      var panes = [{ id: "main" }].concat(D.panes);
      panes.forEach(function (p) { if (ease(p.id, fit(p, i0, i1), dt)) moving = true; });
      if (!yNow.main) return false;

      /* The price gutter is as wide as its widest label, in steps so it does not twitch. */
      ctx.font = "500 11px " + FONT;
      var mt = ticksFor(panes[0], rects.main), widest = 0;
      mt.list.forEach(function (v) { widest = Math.max(widest, ctx.measureText(D.fmtY(v, mt.step)).width); });
      D.series.forEach(function (s) { if (s.tag && fin(val(s, i1))) widest = Math.max(widest, ctx.measureText((s.fmt || D.fmtY)(val(s, i1), mt.step)).width + 8); });
      G = Math.max(44, Math.ceil((widest + 20) / 6) * 6);
      plotW = Math.max(40, W - G);

      var a = Math.max(0, i0 - 2), b = Math.min(D.n - 1, i1 + 2), barW = plotW / (V.to - V.from);
      var xs = new Array(D.n); for (var i = a; i <= b; i++) xs[i] = X(i);

      var tags = [];
      D.series.forEach(function (s) {
        var id = paneOf(s), v = val(s, i1); if (!s.tag || !fin(v) || !yNow[id]) return;
        tags.push({ id: id, v: v, y: clamp(Y(id, v), rects[id].y + 9, rects[id].y + rects[id].h - 9), text: (s.fmt || D.fmtY)(v, mt.step),
          bg: s.kind === "candles" ? (s.v[i1] >= s.o[i1] ? T.gain : T.loss) : col(s.color) });
      });

      panes.forEach(function (p) {
        var r = rects[p.id], tk = p.id === "main" ? mt : ticksFor(p, r), fmt = p.fmt || D.fmtY;
        if (!yNow[p.id]) return;
        ctx.lineWidth = 1; ctx.strokeStyle = T.grid; ctx.fillStyle = T.t3; ctx.textBaseline = "middle"; ctx.textAlign = "left"; ctx.font = "500 11px " + FONT;
        tk.list.forEach(function (v) {
          var y = Y(p.id, v); if (y < r.y + 7 || y > r.y + r.h - 5 || (D.floor != null && p.id === "main" && v < D.floor)) return;
          ctx.beginPath(); ctx.moveTo(0, px(y)); ctx.lineTo(plotW, px(y)); ctx.stroke();
          if (!tags.some(function (t) { return t.id === p.id && Math.abs(t.y - y) < 15; })) ctx.fillText(fmt(v, tk.step), plotW + 8, y);
        });
        if (p.id !== "main") { ctx.strokeStyle = T.line; ctx.beginPath(); ctx.moveTo(0, r.y - 0.5); ctx.lineTo(W, r.y - 0.5); ctx.stroke(); }
        ctx.save(); ctx.beginPath(); ctx.rect(0, r.y, plotW, r.h); ctx.clip();
        D.lines.forEach(function (l) {
          if ((l.pane || "main") !== p.id) return;
          var y = px(Y(p.id, l.value));
          ctx.strokeStyle = col(l.color || "--line3"); ctx.setLineDash(l.dash || []); ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(plotW, y); ctx.stroke(); ctx.setLineDash([]);
        });
        D.series.forEach(function (s) { if (paneOf(s) === p.id && s.kind === "hist") drawHist(s, r, i0, i1, xs, barW); });
        D.series.forEach(function (s) { if (paneOf(s) === p.id && (s.kind === "line" || s.kind === "area")) drawLine(s, p.id, r, a, b, xs); });
        D.series.forEach(function (s) { if (paneOf(s) === p.id && s.kind === "candles") drawCandles(s, p.id, i0, i1, xs, barW); });
        if (p.label) { ctx.fillStyle = T.t3; ctx.font = "500 10.5px " + FONT; ctx.textAlign = "left"; ctx.textBaseline = "top"; ctx.fillText(p.label, 8, r.y + 6); }
        ctx.restore();
      });

      var reading = cross && cross.i >= i0 && cross.i <= i1 ? dateBox() : null;
      timeAxis(i0, i1, xs, reading ? [reading.x - 22, reading.x + reading.w + 22] : null);
      tags.forEach(function (t) { tag(t.id, t.v, t.text, t.bg, true); });
      if (reading) drawCross(reading);
      return moving;
    }

    function drawLine(s, id, r, a, b, xs) {
      var ys = new Array(b + 1), i, c = col(s.color);
      for (i = a; i <= b; i++) { var v = val(s, i); ys[i] = fin(v) ? Y(id, v) : NaN; }
      var runs = [], st = -1;
      for (i = a; i <= b + 1; i++) {
        var ok = i <= b && ys[i] === ys[i];
        if (ok && st < 0) st = i;
        if (!ok && st >= 0) { runs.push([st, i - 1]); st = -1; }
      }
      runs.forEach(function (run) {
        if (s.kind === "area" && run[1] > run[0]) {
          ctx.beginPath(); trace(ctx, xs, ys, run[0], run[1]);
          ctx.lineTo(xs[run[1]], r.y + r.h); ctx.lineTo(xs[run[0]], r.y + r.h); ctx.closePath();
          ctx.fillStyle = rgba(c, s.wash || 0.09); ctx.fill();
        }
        ctx.beginPath();
        if (run[1] === run[0]) ctx.arc(xs[run[0]], ys[run[0]], (s.width || 2) / 2 + 0.5, 0, 6.2832);
        else if (s.smooth === false) { ctx.moveTo(xs[run[0]], ys[run[0]]); for (var k = run[0] + 1; k <= run[1]; k++) ctx.lineTo(xs[k], ys[k]); }
        else trace(ctx, xs, ys, run[0], run[1]);
        ctx.lineWidth = s.width || 2; ctx.lineJoin = "round"; ctx.lineCap = "round"; ctx.strokeStyle = c;
        if (run[1] === run[0]) { ctx.fillStyle = c; ctx.fill(); } else ctx.stroke();
      });
    }
    /* Candles and volume bars are laid out in whole device pixels, so they
       stay sharp on every screen. */
    function drawCandles(s, id, i0, i1, xs, barW) {
      var q = 1 / dpr, bw = barW * dpr, body = bw >= 3 ? Math.max(1, Math.floor(bw * 0.7)) : 1, wick = Math.max(1, Math.round(dpr * 0.75));
      if (body % 2 !== wick % 2) body = Math.max(wick, body - 1);
      for (var i = i0; i <= i1; i++) {
        var o = s.o[i], c = s.v[i]; if (!fin(o) || !fin(c)) continue;
        var cx = Math.round(xs[i] * dpr), yo = Math.round(Y(id, o) * dpr), yc = Math.round(Y(id, c) * dpr);
        var yh = Math.round(Y(id, s.h[i]) * dpr), yl = Math.round(Y(id, s.l[i]) * dpr), top = Math.min(yo, yc);
        ctx.fillStyle = c >= o ? T.gain : T.loss;
        ctx.fillRect((cx - Math.floor(wick / 2)) * q, yh * q, wick * q, Math.max(1, yl - yh) * q);
        if (body > wick) ctx.fillRect((cx - Math.floor(body / 2)) * q, top * q, body * q, Math.max(1, Math.abs(yo - yc)) * q);
      }
    }
    function drawHist(s, r, i0, i1, xs, barW) {
      var max = 0, i, band = r.h * (s.band || 0.16), c = s.color ? col(s.color) : null, q = 1 / dpr, bw = barW * dpr;
      for (i = i0; i <= i1; i++) if (s.v[i] > max) max = s.v[i];
      if (!max) return;
      var w = Math.max(1, Math.floor(bw) - (bw >= 4 ? Math.max(1, Math.round(dpr)) : 0)), base = Math.round((r.y + r.h) * dpr);
      for (i = i0; i <= i1; i++) {
        var v = s.v[i]; if (!(v > 0)) continue;
        var ht = Math.max(1, Math.round(v / max * band * dpr));
        ctx.fillStyle = s.colors ? col(s.colors(i)) : c;
        ctx.fillRect((Math.round(xs[i] * dpr) - Math.floor(w / 2)) * q, (base - ht) * q, w * q, ht * q);
      }
    }
    function timeAxis(i0, i1, xs, skip) {
      var y = H - AXIS_H, gap = plotW < 420 ? 56 : 74, P = D.cal.p, Wt = D.cal.w, i, k, pick = SETS[0];
      var perBar = plotW / (V.to - V.from);
      for (k = SETS.length - 1; k >= 0; k--) {
        var n = 0; for (i = i0; i <= i1; i++) if (SETS[k](P[i], Wt[i])) n++;
        if (!n || (i1 - i0 + 1) * perBar / n >= gap) { pick = SETS[k]; break; }
      }
      var taken = new Uint8Array(Math.ceil(plotW) + 2), picks = [];
      for (i = i0; i <= i1; i++) if (pick(P[i], Wt[i])) picks.push(i);
      picks.sort(function (p, q) { return Wt[q] - Wt[p] || p - q; });
      ctx.textBaseline = "middle"; ctx.textAlign = "center";
      var room = Math.round(gap * 0.6);
      picks.forEach(function (c) {
        var x = Math.round(xs[c]); if (x < 20 || x > plotW - 20 || taken[x] || (skip && x > skip[0] && x < skip[1])) return;
        for (var j = Math.max(0, x - room); j <= Math.min(plotW, x + room); j++) taken[j] = 1;
        var w = Wt[c], big = w >= 70;
        ctx.font = (big ? "600" : "500") + " 11px " + FONT; ctx.fillStyle = big ? T.t2 : T.t3;
        ctx.fillText(tickText(P[c], w), x, y + AXIS_H / 2 + 1);
      });
    }
    function tag(id, v, text, bg, solid) {
      var r = rects[id], y = clamp(Y(id, v), r.y + 9, r.y + r.h - 9);
      ctx.font = "600 11px " + FONT;
      var w = Math.min(G - 2, ctx.measureText(text).width + 12);
      ctx.fillStyle = bg; rr(plotW + 2, y - 9, w, 18, 3); ctx.fill();
      if (!solid) { ctx.strokeStyle = T.line3; ctx.lineWidth = 1; rr(plotW + 2.5, y - 8.5, w - 1, 17, 3); ctx.stroke(); }
      ctx.fillStyle = solid ? inkOn(bg) : T.text; ctx.textAlign = "left"; ctx.textBaseline = "middle"; ctx.fillText(text, plotW + 8, y + 0.5);
    }
    function rr(x, y, w, h, r) {
      ctx.beginPath(); ctx.moveTo(x + r, y); ctx.arcTo(x + w, y, x + w, y + h, r); ctx.arcTo(x + w, y + h, x, y + h, r); ctx.arcTo(x, y + h, x, y, r); ctx.arcTo(x, y, x + w, y, r); ctx.closePath();
    }
    function dateBox() {
      var text = D.fmtTime(D.times[cross.i]);
      ctx.font = "600 11px " + FONT;
      var w = ctx.measureText(text).width + 14;
      return { text: text, w: w, x: clamp(X(cross.i) - w / 2, 0, Math.max(0, plotW - w)) };
    }
    function drawCross(box) {
      var x = px(X(cross.i)), bottom = H - AXIS_H;
      ctx.lineWidth = 1; ctx.strokeStyle = T.line3;
      ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, bottom); ctx.stroke();
      D.series.forEach(function (s) {
        if (!s.marker) return; var v = val(s, cross.i); if (!fin(v)) return;
        var id = paneOf(s); if (!yNow[id]) return;
        ctx.beginPath(); ctx.arc(X(cross.i), Y(id, v), 4.5, 0, 6.2832);
        ctx.fillStyle = col(s.color); ctx.fill(); ctx.lineWidth = 2; ctx.strokeStyle = T.surface; ctx.stroke();
      });
      /* The level under the pointer, for a mouse. A finger or the keyboard reads bars, not levels. */
      if (cross.how === "mouse" && cross.pane && yNow[cross.pane]) {
        var r = rects[cross.pane], s = yNow[cross.pane], y = px(cross.y), fmt = (r.pane && r.pane.fmt) || D.fmtY;
        ctx.lineWidth = 1; ctx.strokeStyle = T.line3; ctx.setLineDash([3, 3]);
        ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(plotW, y); ctx.stroke(); ctx.setLineDash([]);
        tag(cross.pane, s.min + (1 - (cross.y - r.y) / r.h) * (s.max - s.min), fmt(s.min + (1 - (cross.y - r.y) / r.h) * (s.max - s.min), 0.01), T.raised, false);
      }
      var w = box.w, lx = box.x;
      ctx.font = "600 11px " + FONT;
      ctx.fillStyle = T.raised; rr(lx, bottom + 3, w, 19, 3); ctx.fill();
      ctx.strokeStyle = T.line3; ctx.lineWidth = 1; rr(lx + 0.5, bottom + 3.5, w - 1, 18, 3); ctx.stroke();
      ctx.fillStyle = T.text; ctx.textAlign = "center"; ctx.textBaseline = "middle"; ctx.fillText(box.text, lx + w / 2, bottom + 13);
    }

    /* ── The loop ───────────────────────────────────────────────────────── */
    function request() { if (!raf && !dead) raf = requestAnimationFrame(frame); }
    function frame(now) {
      raf = 0; if (dead) return;
      var dt = lastT ? Math.min(64, now - lastT) : 16, again = false;
      lastT = now;
      if (anim) {
        anim.t += dt;
        var k = Math.min(1, anim.t / anim.ms), e = 1 - Math.pow(1 - k, 3);
        V = { from: anim.a.from + (anim.b.from - anim.a.from) * e, to: anim.a.to + (anim.b.to - anim.a.to) * e };
        if (k >= 1) anim = null; else again = true;
      }
      if (glide) {
        var span = V.to - V.from, was = V.from;
        V = fix(V.from - glide.v * dt, V.from - glide.v * dt + span);
        glide.v *= Math.exp(-dt / 320);
        if (Math.abs(glide.v) * plotW / span < 0.02 || V.from === was) glide = null; else again = true;
      }
      if (draw(dt)) again = true;
      var key = V.from.toFixed(3) + "|" + V.to.toFixed(3) + "|" + D.n;
      if (key !== sent) { sent = key; ctl.querySelector(".ilc-reset").hidden = atHome(); if (opts.onView) opts.onView(viewInfo()); }
      if (again) request(); else lastT = 0;
    }

    /* ── Reading a bar ──────────────────────────────────────────────────── */
    function setCross(c) {
      var was = cross ? cross.i : null;
      cross = c;
      if (opts.onCross && (c ? c.i : null) !== was) opts.onCross(c ? c.i : null, c ? c.how : null);
      if (c && c.how === "keys" && opts.describe) live.textContent = opts.describe(c.i);
      request();
    }
    function crossAt(x, y, how) {
      if (!D.n || x < 0 || x > plotW) return setCross(null);
      var i = clamp(Math.round(idxAt(x)), first(), last()), pane = null;
      Object.keys(rects).forEach(function (id) { var r = rects[id]; if (y >= r.y && y <= r.y + r.h) pane = id; });
      setCross({ i: i, y: y, pane: pane, how: how });
    }

    /* ── Pointer, wheel, keys ───────────────────────────────────────────── */
    var pts = {}, count = 0, drag = null, pinch = null, engaged = false, press = 0, lastTap = null, hinted = false;
    function pos(e) { var r = cv.getBoundingClientRect(); return { x: e.clientX - r.left, y: e.clientY - r.top }; }
    function pair() { var k = Object.keys(pts); return [pts[k[0]], pts[k[1]]]; }
    function startDrag(p, type) { drag = { x: p.x, from: V.from, to: V.to, moved: false, scrub: false, type: type, trail: [{ x: p.x, t: performance.now() }] }; }
    cv.addEventListener("pointerdown", function (e) {
      if (e.pointerType === "mouse" && e.button !== 0) return;
      var p = pos(e); pts[e.pointerId] = p; count = Object.keys(pts).length;
      try { cv.setPointerCapture(e.pointerId); } catch (_) {}
      stop(); engaged = true; clearTimeout(press);
      if (count === 2) {
        var two = pair(), cx = (two[0].x + two[1].x) / 2;
        pinch = { d: Math.max(20, Math.hypot(two[0].x - two[1].x, two[0].y - two[1].y)), at: idxAt(cx), span: V.to - V.from }; drag = null; setCross(null);
        return;
      }
      if (p.x > plotW) return;
      startDrag(p, e.pointerType);
      if (e.pointerType !== "mouse") press = setTimeout(function () { if (drag && !drag.moved) { drag.scrub = true; crossAt(drag.x, p.y, "touch"); } }, 380);
    });
    cv.addEventListener("pointermove", function (e) {
      var p = pos(e);
      if (pts[e.pointerId]) pts[e.pointerId] = p;
      if (pinch && count >= 2) {
        var two = pair(), cx = (two[0].x + two[1].x) / 2, d = Math.max(20, Math.hypot(two[0].x - two[1].x, two[0].y - two[1].y));
        var span = clamp(pinch.span * pinch.d / d, minSpan(), D.n + pad(D.n)), from = pinch.at - cx / plotW * span;
        setView(from, from + span); return;
      }
      if (drag && pts[e.pointerId]) {
        if (drag.scrub) { crossAt(p.x, p.y, "touch"); return; }
        var dx = p.x - drag.x;
        if (!drag.moved && Math.abs(dx) < 4) return;
        if (!drag.moved) { drag.moved = true; clearTimeout(press); host.classList.add("grab"); setCross(null); }
        var sp = drag.to - drag.from, f = drag.from - dx / plotW * sp;
        setView(f, f + sp);
        drag.trail.push({ x: p.x, t: performance.now() }); if (drag.trail.length > 6) drag.trail.shift();
        return;
      }
      if (e.pointerType === "mouse") crossAt(p.x, p.y, "mouse");
    });
    function release(e) {
      var had = pts[e.pointerId]; delete pts[e.pointerId]; count = Object.keys(pts).length;
      clearTimeout(press); host.classList.remove("grab");
      if (pinch) { pinch = null; drag = null; if (count === 1) startDrag(pts[Object.keys(pts)[0]], "touch"), drag.moved = true; return; }
      if (!drag || !had) return;
      var d = drag; drag = null;
      if (e.type === "pointercancel") return;
      if (d.moved) {
        var a = d.trail[0], b = d.trail[d.trail.length - 1], ms = b.t - a.t;
        if (!still && ms > 0 && performance.now() - b.t < 80) {
          var v = (b.x - a.x) / ms * (V.to - V.from) / plotW;      // bars per millisecond
          if (Math.abs((b.x - a.x) / ms) > 0.15) { glide = { v: v }; request(); }
        }
        return;
      }
      if (d.scrub) return;
      if (d.type !== "mouse") {
        var now = performance.now(), p = pos(e);
        if (lastTap && now - lastTap.t < 320 && Math.abs(p.x - lastTap.x) < 30) { lastTap = null; reset(); return; }
        lastTap = { t: now, x: p.x };
        if (cross && cross.i === clamp(Math.round(idxAt(p.x)), first(), last())) setCross(null); else crossAt(p.x, p.y, "touch");
      }
    }
    cv.addEventListener("pointerup", release);
    cv.addEventListener("pointercancel", release);
    cv.addEventListener("pointerleave", function (e) { if (e.pointerType === "mouse" && !drag) { setCross(null); engaged = false; } });
    cv.addEventListener("dblclick", function (e) { e.preventDefault(); reset(); });
    cv.addEventListener("wheel", function (e) {
      if (!D.n) return;
      var unit = e.deltaMode === 1 ? 16 : e.deltaMode === 2 ? 400 : 1, dx = e.deltaX * unit, dy = e.deltaY * unit, p = pos(e);
      if (e.ctrlKey || e.metaKey) { e.preventDefault(); zoomAt(Math.exp(clamp(dy, -60, 60) * 0.012), p.x); return; }
      if (Math.abs(dx) > Math.abs(dy)) { e.preventDefault(); stop(); var sp = V.to - V.from, f = V.from + dx / plotW * sp; setView(f, f + sp); return; }
      if (engaged) { e.preventDefault(); zoomAt(Math.exp(clamp(dy, -240, 240) * 0.0016), p.x); return; }
      if (!hinted) { hinted = true; say(/Mac|iPhone|iPad/.test(navigator.platform || "") ? "Click the chart, or hold ⌘, to zoom with the wheel" : "Click the chart, or hold Ctrl, to zoom with the wheel"); }
    }, { passive: false });
    cv.addEventListener("keydown", function (e) {
      if (!D.n) return;
      var k = e.key, span = V.to - V.from, i;
      if (k === "ArrowLeft" || k === "ArrowRight") {
        var dir = k === "ArrowLeft" ? -1 : 1;
        if (e.shiftKey) { stop(); setView(V.from + dir * span * 0.12, V.to + dir * span * 0.12); }
        else {
          i = clamp((cross ? cross.i : last() + (dir < 0 ? 1 : 0)) + dir, 0, D.n - 1);
          if (i < first()) setView(i - 0.5, i - 0.5 + span); else if (i > last()) setView(i + 0.5 - span + pad(span), i + 0.5 + pad(span));
          setCross({ i: i, how: "keys" });
        }
      } else if (k === "+" || k === "=") zoomAt(0.8);
      else if (k === "-" || k === "_") zoomAt(1.25);
      else if (k === "0") reset();
      else if (k === "Home") { setView(-0.5, -0.5 + span); setCross({ i: 0, how: "keys" }); }
      else if (k === "End") { setView(D.n - 0.5 + pad(span) - span, D.n - 0.5 + pad(span)); setCross({ i: D.n - 1, how: "keys" }); }
      else if (k === "Escape") setCross(null);
      else return;
      e.preventDefault();
    });
    cv.addEventListener("blur", function () { if (cross && cross.how === "keys") setCross(null); });
    ctl.addEventListener("click", function (e) {
      var b = e.target.closest("[data-z]"); if (!b) return;
      var z = b.getAttribute("data-z");
      if (z === "reset") reset(); else zoomAt(z === "in" ? 0.7 : 1 / 0.7);
    });
    function reset() { if (home) animateTo(home[0], home[1]); setCross(null); }
    var hintT = 0;
    function say(text) { hint.textContent = text; hint.classList.add("on"); clearTimeout(hintT); hintT = setTimeout(function () { hint.classList.remove("on"); }, 2600); }

    var ro = window.ResizeObserver ? new ResizeObserver(function () { request(); }) : null;
    if (ro) ro.observe(host); else window.addEventListener("resize", request);
    function onTheme() { theme(); request(); }
    document.addEventListener("il:theme", onTheme);
    if (document.fonts && document.fonts.ready) document.fonts.ready.then(request);
    theme();

    return {
      set: set, show: show,
      view: viewInfo,
      val: function (id, i) { var s = D.series.filter(function (x) { return x.id === id; })[0]; return s ? val(s, i) : NaN; },
      redraw: request,
      destroy: function () { dead = true; cancelAnimationFrame(raf); if (ro) ro.disconnect(); document.removeEventListener("il:theme", onTheme); clearTimeout(press); clearTimeout(hintT); host.innerHTML = ""; host.classList.remove("ilc", "grab"); },
    };
  };
})();

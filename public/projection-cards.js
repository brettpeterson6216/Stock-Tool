/* Valuation Lab card studio.

   Turns the projection a member has built into a branded image they can post:
   three card types (price range, bear/base/bull, how the price is built) in
   three sizes (X landscape, square, portrait). Every number comes from
   ImpliedLensMath.plCalculateOutlook, the same calculation as the page, so a
   card can never show something the model does not say.

   projection-lab.js calls ILProjectionCards.open(model). */
(function () {
  "use strict";

  var SIZES = {
    wide: { w: 1600, h: 900, label: "Landscape", note: "1600 × 900 · best for X" },
    square: { w: 1080, h: 1080, label: "Square", note: "1080 × 1080 · X, Instagram, LinkedIn" },
    tall: { w: 1080, h: 1350, label: "Portrait", note: "1080 × 1350 · Instagram feed" },
  };
  var TYPES = {
    range: { label: "Price range", note: "Where the model lands, with the path there" },
    scenarios: { label: "Bear · Base · Bull", note: "Three outcomes side by side" },
    build: { label: "How it's built", note: "Revenue to price, step by step" },
  };
  var SCEN = { bear: "Bear", base: "Base", bull: "Bull" };
  var C = {
    bg: "#0C0B09", panel: "#15130F", line: "rgba(241,237,227,.10)", lineStrong: "rgba(241,237,227,.22)",
    cream: "#F3EEE3", dim: "rgba(243,238,227,.62)", faint: "rgba(243,238,227,.40)",
    gold: "#E3A945", goldSoft: "rgba(227,169,69,.16)", goldLine: "rgba(227,169,69,.45)",
    bear: "#E5735F", base: "#E3A945", bull: "#4FC48A",
  };
  var F = {
    sans: '"Plus Jakarta Sans", "Segoe UI", Arial, sans-serif',
    serif: '"Instrument Serif", Georgia, serif',
    num: '"IBM Plex Sans", "Plus Jakarta Sans", Arial, sans-serif',
  };

  var state = { type: "range", size: "wide", scenario: "base", headline: "", model: null, outlook: null };
  var root = null, canvas = null, fontsReady = null;

  /* ── formatting ─────────────────────────────────────────────────────────── */
  function price(v) {
    if (!Number.isFinite(v)) return "—";
    var a = Math.abs(v), d = a >= 1000 ? 0 : a >= 100 ? 0 : 2;
    return (v < 0 ? "−$" : "$") + a.toLocaleString("en-US", { minimumFractionDigits: d, maximumFractionDigits: d });
  }
  function priceExact(v) { return Number.isFinite(v) ? "$" + v.toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 }) : "—"; }
  function big(v) {
    if (!Number.isFinite(v)) return "—";
    var a = Math.abs(v), s = v < 0 ? "−$" : "$";
    if (a >= 1e12) return s + (a / 1e12).toFixed(2) + "T";
    if (a >= 1e9) return s + (a / 1e9).toFixed(a >= 1e11 ? 0 : 1) + "B";
    if (a >= 1e6) return s + (a / 1e6).toFixed(1) + "M";
    return s + Math.round(a).toLocaleString("en-US");
  }
  function count(v) {
    if (!Number.isFinite(v)) return "—";
    if (v >= 1e9) return (v / 1e9).toFixed(2) + "B";
    if (v >= 1e6) return (v / 1e6).toFixed(1) + "M";
    return Math.round(v).toLocaleString("en-US");
  }
  function pct(v, d) { return Number.isFinite(v) ? (v * 100).toFixed(d == null ? 0 : d).replace(/^-/, "−") + "%" : "—"; }
  function pe(v) { return Number.isFinite(v) ? (+v.toFixed(1)) + "×" : "—"; }
  function cagrRange(t) { return pct(t.cagrLow) + " to " + pct(t.cagrHigh) + " a year"; }
  function avg(arr) { var s = 0, n = 0; arr.forEach(function (v) { if (Number.isFinite(v)) { s += v; n++; } }); return n ? s / n : NaN; }
  function name() { var m = state.model; return (m.companyName || m.ticker || "This company").replace(/,? (Inc|Corp|Corporation|Incorporated|Ltd|plc|Co)\.?$/i, ""); }

  /* ── canvas helpers ─────────────────────────────────────────────────────── */
  function font(g, weight, size, family) { g.font = weight + " " + Math.round(size) + "px " + family; }
  function rr(g, x, y, w, h, r) {
    r = Math.min(r, w / 2, h / 2);
    g.beginPath(); g.moveTo(x + r, y); g.arcTo(x + w, y, x + w, y + h, r); g.arcTo(x + w, y + h, x, y + h, r);
    g.arcTo(x, y + h, x, y, r); g.arcTo(x, y, x + w, y, r); g.closePath();
  }
  function box(g, x, y, w, h, r, fill, stroke) { rr(g, x, y, w, h, r); if (fill) { g.fillStyle = fill; g.fill(); } if (stroke) { g.strokeStyle = stroke; g.lineWidth = 1.5; g.stroke(); } }
  /* Mixed-style text with word wrap. runs = [{t, w, s, f, c}] */
  function runs(g, list, x, y, maxW, lineH) {
    var words = [];
    list.forEach(function (r) { r.t.split(/(\s+)/).forEach(function (p) { if (p) words.push({ t: p, r: r }); }); });
    var cx = x, cy = y;
    words.forEach(function (wd) {
      font(g, wd.r.w, wd.r.s, wd.r.f);
      var ww = g.measureText(wd.t).width;
      if (/^\s+$/.test(wd.t)) { if (cx > x) cx += ww; return; }
      if (cx + ww > x + maxW && cx > x) { cx = x; cy += lineH; }
      g.fillStyle = wd.r.c; g.fillText(wd.t, cx, cy); cx += ww;
    });
    return cy;
  }
  function fit(g, text, weight, size, family, maxW) {
    var s = size; font(g, weight, s, family);
    while (g.measureText(text).width > maxW && s > 10) { s -= 2; font(g, weight, s, family); }
    return s;
  }
  function mark(g, x, y, s) {
    g.save(); g.translate(x, y);
    g.strokeStyle = C.gold; g.lineWidth = s * 0.09;
    g.beginPath(); g.arc(s / 2, s / 2, s * 0.42, 0, Math.PI * 2); g.stroke();
    g.fillStyle = C.gold;
    [0.28, 0.46, 0.64].forEach(function (fx, i) { var hh = s * (0.16 + i * 0.12); g.fillRect(s * fx - s * 0.05, s * 0.68 - hh, s * 0.1, hh); });
    g.restore();
  }

  /* ── shared frame ───────────────────────────────────────────────────────── */
  function frame(g, W, H, u, kicker) {
    g.fillStyle = C.bg; g.fillRect(0, 0, W, H);
    var glow = g.createRadialGradient(W * 0.85, -H * 0.1, 10, W * 0.85, -H * 0.1, Math.max(W, H) * 0.75);
    glow.addColorStop(0, "rgba(227,169,69,.17)"); glow.addColorStop(1, "rgba(227,169,69,0)");
    g.fillStyle = glow; g.fillRect(0, 0, W, H);
    var low = g.createRadialGradient(0, H, 10, 0, H, Math.max(W, H) * 0.6);
    low.addColorStop(0, "rgba(227,169,69,.06)"); low.addColorStop(1, "rgba(227,169,69,0)");
    g.fillStyle = low; g.fillRect(0, 0, W, H);
    var P = 64 * u;
    mark(g, P, P - 4 * u, 34 * u);
    g.textBaseline = "middle";
    font(g, 700, 25 * u, F.sans); g.fillStyle = C.cream; g.fillText("Implied", P + 46 * u, P + 13 * u);
    var iw = g.measureText("Implied").width;
    font(g, 400, 29 * u, F.serif); g.fillStyle = C.gold; g.fillText("Lens", P + 46 * u + iw + 3 * u, P + 12 * u);
    font(g, 700, 15 * u, F.sans); g.fillStyle = C.dim; g.textAlign = "right";
    g.fillText(kicker.toUpperCase(), W - P, P + 13 * u);
    g.textAlign = "left";
    // footer
    g.strokeStyle = C.line; g.lineWidth = 1; g.beginPath(); g.moveTo(P, H - P - 30 * u); g.lineTo(W - P, H - P - 30 * u); g.stroke();
    font(g, 500, 15 * u, F.sans); g.fillStyle = C.faint;
    g.fillText("Educational model with the author's assumptions. Not investment advice.", P, H - P + 2 * u);
    font(g, 700, 17 * u, F.sans); g.fillStyle = C.gold; g.textAlign = "right";
    g.fillText("impliedlens.com", W - P, H - P + 2 * u);
    g.textAlign = "left"; g.textBaseline = "alphabetic";
    return { P: P, top: P + 64 * u, bottom: H - P - 52 * u };
  }

  function title(g, x, y, maxW, u, plain, accent, size) {
    var s = (size || 56) * u;
    // A title that just misses one line is shrunk to fit rather than leaving
    // one word stranded on the second.
    function width(sz) { font(g, 700, sz, F.sans); var w = g.measureText(plain + " ").width; font(g, 400, sz * 1.12, F.serif); return w + g.measureText(accent).width; }
    var w0 = width(s);
    if (w0 > maxW && w0 < maxW * 1.25) s = s * maxW / w0 * 0.98;
    return runs(g, [{ t: plain + " ", w: 700, s: s, f: F.sans, c: C.cream }, { t: accent, w: 400, s: s * 1.12, f: F.serif, c: C.gold }], x, y, maxW, s * 1.18);
  }

  function statRow(g, x, y, w, u, items) {
    var gap = 14 * u, cols = items.length, cw = (w - gap * (cols - 1)) / cols, h = 92 * u;
    items.forEach(function (it, i) {
      var bx = x + i * (cw + gap);
      box(g, bx, y, cw, h, 14 * u, "rgba(243,238,227,.035)", C.line);
      font(g, 600, 14 * u, F.sans); g.fillStyle = C.dim; g.fillText(it[0], bx + 18 * u, y + 32 * u);
      fit(g, it[1], 600, 30 * u, F.num, cw - 36 * u); g.fillStyle = it[2] || C.cream; g.fillText(it[1], bx + 18 * u, y + 70 * u);
    });
    return y + h;
  }

  /* Band chart: start price, then low–high band and midpoint per year. */
  function bandChart(g, x, y, w, h, u, proj, startPrice, color) {
    /* The card draws the compound path from today's price to the modelled
       range: one point a month at the annual return each end implies. It lands
       exactly on the model's low, midpoint and high, and reads as the smooth
       fan it is, instead of a first-year jump while the multiple re-rates. */
    var t = proj.terminal;
    if (t.negativeEarnings || !(t.priceLow > 0)) return;
    var yrs = proj.rows.length, months = yrs * 12, pts = [];
    for (var mo = 0; mo <= months; mo++) {
      var f = mo / months;
      pts.push({
        year: proj.baseYear + mo / 12,
        low: startPrice * Math.pow(t.priceLow / startPrice, f),
        high: startPrice * Math.pow(t.priceHigh / startPrice, f),
        mid: startPrice * Math.pow(t.priceMid / startPrice, f),
      });
    }
    var lo = Infinity, hi = -Infinity;
    pts.forEach(function (p) { lo = Math.min(lo, p.low); hi = Math.max(hi, p.high); });
    var span = hi - lo || hi * 0.2 || 1; lo = Math.max(0, lo - span * 0.12); hi += span * 0.1;
    var padL = 0, padR = 118 * u, padB = 38 * u;
    var pw = w - padL - padR, ph = h - padB;
    var x0 = pts[0].year, x1 = pts[pts.length - 1].year;
    function X(yr) { return x + padL + (yr - x0) / (x1 - x0 || 1) * pw; }
    function Y(v) { return y + (1 - (v - lo) / (hi - lo)) * ph; }
    // grid
    g.textBaseline = "middle";
    for (var i = 0; i <= 3; i++) {
      var v = lo + (hi - lo) * i / 3, yy = Y(v);
      g.strokeStyle = C.line; g.lineWidth = 1; g.beginPath(); g.moveTo(x, yy); g.lineTo(x + pw, yy); g.stroke();
    }
    // band
    var grad = g.createLinearGradient(0, y, 0, y + ph);
    grad.addColorStop(0, hexA(color, 0.34)); grad.addColorStop(1, hexA(color, 0.08));
    var top = pts.map(function (p) { return [X(p.year), Y(p.high)]; });
    var bot = pts.map(function (p) { return [X(p.year), Y(p.low)]; });
    var mid = pts.map(function (p) { return [X(p.year), Y(p.mid)]; });
    g.beginPath(); curve(g, top); curve(g, bot.slice().reverse(), true);
    g.closePath(); g.fillStyle = grad; g.fill();
    g.strokeStyle = hexA(color, 0.55); g.lineWidth = 1.5 * u;
    g.beginPath(); curve(g, top); g.stroke();
    g.beginPath(); curve(g, bot); g.stroke();
    // today line
    g.setLineDash([6 * u, 6 * u]); g.strokeStyle = C.lineStrong; g.lineWidth = 1.5 * u;
    g.beginPath(); g.moveTo(x, Y(startPrice)); g.lineTo(x + pw, Y(startPrice)); g.stroke(); g.setLineDash([]);
    // midpoint
    g.strokeStyle = color; g.lineWidth = 3.5 * u; g.lineJoin = "round";
    g.beginPath(); curve(g, mid); g.stroke();
    // only the end point is marked: dots on every year made the curve read as steps
    var em = mid[mid.length - 1];
    g.beginPath(); g.arc(em[0], em[1], 12 * u, 0, Math.PI * 2); g.fillStyle = hexA(color, 0.18); g.fill();
    g.beginPath(); g.arc(em[0], em[1], 6.5 * u, 0, Math.PI * 2); g.fillStyle = color; g.fill();
    // end labels (kept apart)
    var e = pts[pts.length - 1], lx = X(e.year) + 16 * u;
    var ys = [Y(e.high), Y(e.mid), Y(e.low)];
    if (ys[1] - ys[0] < 26 * u) ys[0] = ys[1] - 26 * u;
    if (ys[2] - ys[1] < 26 * u) ys[2] = ys[1] + 26 * u;
    font(g, 500, 16 * u, F.num); g.fillStyle = C.dim; g.fillText(price(e.high), lx, ys[0]);
    font(g, 700, 19 * u, F.num); g.fillStyle = C.cream; g.fillText(price(e.mid), lx, ys[1]);
    font(g, 500, 16 * u, F.num); g.fillStyle = C.dim; g.fillText(price(e.low), lx, ys[2]);
    // today label
    var ty = Y(startPrice);
    if (Math.abs(ty - ys[2]) > 22 * u && Math.abs(ty - ys[1]) > 22 * u) {
      font(g, 600, 14 * u, F.sans); g.fillStyle = C.faint; g.fillText("Today " + price(startPrice), lx, ty);
    } else {
      font(g, 600, 14 * u, F.sans); g.fillStyle = C.faint; g.fillText("Today " + price(startPrice), x + 6 * u, ty - 14 * u);
    }
    // x axis
    g.textAlign = "center"; font(g, 500, 15 * u, F.num); g.fillStyle = C.faint;
    var step = yrs > 6 ? 2 : 1;
    for (var yi = 0; yi <= yrs; yi++) if (yi % step === 0 || yi === yrs) g.fillText(String(proj.baseYear + yi), X(proj.baseYear + yi), y + ph + 24 * u);
    g.textAlign = "left"; g.textBaseline = "alphabetic";
  }
  function curve(g, pts, cont) {
    if (window.LensCharts && window.LensCharts.canvasCurve) return window.LensCharts.canvasCurve(g, pts, cont);
    pts.forEach(function (p, i) { (i || cont) ? g.lineTo(p[0], p[1]) : g.moveTo(p[0], p[1]); });
  }
  function hexA(hex, a) {
    var n = parseInt(hex.slice(1), 16);
    return "rgba(" + (n >> 16 & 255) + "," + (n >> 8 & 255) + "," + (n & 255) + "," + a + ")";
  }

  /* ── card 1: price range ───────────────────────────────────────────────── */
  function drawRange(g, W, H, u, wide) {
    var m = state.model, o = state.outlook, k = state.scenario, proj = o.scenarios[k], t = proj.terminal, col = C[k];
    var f = frame(g, W, H, u, "Valuation Lab · " + m.ticker), P = f.P;
    var textW = wide ? W * 0.44 : W - 2 * P;
    var y = f.top + 8 * u;
    // scenario chip
    font(g, 700, 15 * u, F.sans);
    var chip = SCEN[k].toUpperCase() + " CASE · " + o.horizonYears + " YEARS", cw = g.measureText(chip).width + 44 * u;
    box(g, P, y, cw, 34 * u, 17 * u, hexA(col, 0.14), hexA(col, 0.5));
    g.beginPath(); g.arc(P + 17 * u, y + 17 * u, 5 * u, 0, Math.PI * 2); g.fillStyle = col; g.fill();
    g.fillStyle = C.cream; g.textBaseline = "middle"; g.fillText(chip, P + 30 * u, y + 18 * u); g.textBaseline = "alphabetic";
    y += 34 * u + 68 * u;
    var head = state.headline || ("What could " + name() + " be worth by");
    var tail = state.headline ? "" : t.year + "?";
    y = title(g, P, y, textW, u, head, tail, wide ? 54 : 52);
    y += 100 * u;
    if (t.negativeEarnings) {
      font(g, 700, 44 * u, F.num); g.fillStyle = C.cream; g.fillText("No profit by " + t.year, P, y);
      font(g, 500, 20 * u, F.sans); g.fillStyle = C.dim; g.fillText("A P/E-based price is not meaningful for this case.", P, y + 38 * u);
      y += 60 * u;
    } else {
      var rangeTxt = price(t.priceLow) + " – " + price(t.priceHigh);
      fit(g, rangeTxt, 600, (wide ? 82 : 88) * u, F.num, textW);
      g.fillStyle = C.cream; g.fillText(rangeTxt, P, y);
      y += 52 * u;
      font(g, 500, 22 * u, F.sans); g.fillStyle = C.dim;
      runs(g, [{ t: "Per share in " + t.year + ", from ", w: 500, s: 22 * u, f: F.sans, c: C.dim }, { t: priceExact(m.startPrice), w: 700, s: 22 * u, f: F.num, c: C.cream }, { t: " today", w: 500, s: 22 * u, f: F.sans, c: C.dim }], P, y, textW, 30 * u);
      y += 36 * u;
      runs(g, [{ t: "That is ", w: 500, s: 22 * u, f: F.sans, c: C.dim }, { t: cagrRange(t), w: 700, s: 22 * u, f: F.sans, c: col }], P, y, textW, 30 * u);
      y += 20 * u;
    }
    var stats = [
      ["Revenue growth", pct(avg(proj.rows.map(function (r) { return r.revGrowth; })), 0) + " / yr"],
      ["Net margin " + t.year, pct(t.netMargin, 1)],
      ["EPS " + t.year, priceExact(t.eps)],
      ["Exit P/E", pe(t.peLow) + "–" + pe(t.peHigh)],
    ];
    if (wide) {
      bandChart(g, W * 0.53, f.top + 70 * u, W - P - W * 0.53, f.bottom - f.top - 220 * u, u, proj, m.startPrice, col);
      statRow(g, P, f.bottom - 112 * u, W - 2 * P, u, stats);
    } else {
      var statsY = f.bottom - (W < H * 0.9 ? 212 : 112) * u;
      var chartTop = y + 50 * u;
      bandChart(g, P, chartTop, W - 2 * P, statsY - chartTop - 40 * u, u, proj, m.startPrice, col);
      if (W < H * 0.9) { statRow(g, P, statsY, W - 2 * P, u, stats.slice(0, 2)); statRow(g, P, statsY + 106 * u, W - 2 * P, u, stats.slice(2)); }
      else statRow(g, P, statsY, W - 2 * P, u, stats);
    }
  }

  /* ── card 2: bear / base / bull ────────────────────────────────────────── */
  function drawScenarios(g, W, H, u, wide) {
    var m = state.model, o = state.outlook;
    var f = frame(g, W, H, u, "Valuation Lab · " + m.ticker), P = f.P;
    var yr = o.terminalYear;
    var y = f.top + 52 * u;
    y = title(g, P, y, W - 2 * P, u, state.headline || (name() + " in " + yr + ":"), state.headline ? "" : "three ways it could go", wide ? 54 : 52);
    y += 52 * u;
    var keys = ["bear", "base", "bull"].filter(function (k) { return !o.scenarios[k].terminal.negativeEarnings; });
    var all = [m.startPrice];
    keys.forEach(function (k) { var t = o.scenarios[k].terminal; all.push(t.priceLow, t.priceHigh); });
    var lo = Math.min.apply(null, all), hi = Math.max.apply(null, all), span = hi - lo || 1;
    lo = Math.max(0, lo - span * 0.08); hi += span * 0.08;
    var labelW = 110 * u, cx = P + labelW, cwid = W - 2 * P - labelW - 20 * u;
    function X(v) { return cx + (v - lo) / (hi - lo) * cwid; }
    var avail = f.bottom - y - (o.expected ? 70 : 0) * u;
    var rowH = wide ? 74 * u : Math.min(120 * u, avail * 0.42 / 3), chartH = rowH * 3;
    // today line
    var tx = X(m.startPrice);
    g.setLineDash([6 * u, 6 * u]); g.strokeStyle = C.lineStrong; g.lineWidth = 1.5 * u;
    g.beginPath(); g.moveTo(tx, y - 10 * u); g.lineTo(tx, y + chartH); g.stroke(); g.setLineDash([]);
    font(g, 600, 14 * u, F.sans); g.fillStyle = C.faint; g.textAlign = "center";
    g.fillText("Today " + price(m.startPrice), tx, y + chartH + 26 * u); g.textAlign = "left";
    ["bear", "base", "bull"].forEach(function (k, i) {
      var t = o.scenarios[k].terminal, ry = y + i * rowH + rowH / 2, col = C[k];
      g.beginPath(); g.arc(P + 8 * u, ry, 6 * u, 0, Math.PI * 2); g.fillStyle = col; g.fill();
      font(g, 700, 20 * u, F.sans); g.fillStyle = C.cream; g.textBaseline = "middle"; g.fillText(SCEN[k], P + 24 * u, ry);
      if (t.negativeEarnings) { font(g, 500, 17 * u, F.sans); g.fillStyle = C.dim; g.fillText("No profit by " + yr, cx, ry); g.textBaseline = "alphabetic"; return; }
      var bh = Math.max(22 * u, rowH * 0.26), x1 = X(t.priceLow), x2 = X(t.priceHigh);
      box(g, x1, ry - bh / 2, Math.max(x2 - x1, 6 * u), bh, bh / 2, hexA(col, 0.32), hexA(col, 0.8));
      g.beginPath(); g.arc(X(t.priceMid), ry, 7 * u, 0, Math.PI * 2); g.fillStyle = col; g.fill(); g.strokeStyle = C.bg; g.lineWidth = 2.5 * u; g.stroke();
      font(g, 500, 16 * u, F.num); g.fillStyle = C.dim;
      g.textAlign = "right"; g.fillText(price(t.priceLow), x1 - 10 * u, ry);
      g.textAlign = "left"; g.fillText(price(t.priceHigh), x2 + 10 * u, ry);
      g.textBaseline = "alphabetic";
    });
    y += chartH + 64 * u;
    // three columns of detail
    var gap = 16 * u, cols = wide ? 3 : 1, colW = (W - 2 * P - gap * (cols - 1)) / cols;
    var cardH = wide ? 150 * u : Math.min(150 * u, (f.bottom - y - (o.expected ? 80 : 10) * u - 24 * u) / 3);
    ["bear", "base", "bull"].forEach(function (k, i) {
      var t = o.scenarios[k].terminal, proj = o.scenarios[k], col = C[k];
      var bx = wide ? P + i * (colW + gap) : P, by = wide ? y : y + i * (cardH + 12 * u);
      if (by + cardH > f.bottom - (o.expected ? 70 : 0) * u) return;
      box(g, bx, by, colW, cardH, 14 * u, k === state.scenario ? hexA(col, 0.08) : "rgba(243,238,227,.03)", k === state.scenario ? hexA(col, 0.55) : C.line);
      var growth = pct(avg(proj.rows.map(function (r) { return r.revGrowth; }))) + " growth";
      var margin = pct(t.netMargin, 1) + " margin";
      var mult = pe(t.peLow) + "–" + pe(t.peHigh) + " P/E";
      if (wide) {
        font(g, 700, 15 * u, F.sans); g.fillStyle = col; g.fillText(SCEN[k].toUpperCase(), bx + 20 * u, by + 34 * u);
        font(g, 600, 30 * u, F.num); g.fillStyle = C.cream;
        g.fillText(t.negativeEarnings ? "No profit" : price(t.priceMid), bx + 20 * u, by + 76 * u);
        font(g, 500, 15 * u, F.sans); g.fillStyle = C.dim;
        if (!t.negativeEarnings) g.fillText("midpoint · " + pct((t.cagrLow + t.cagrHigh) / 2) + " a year", bx + 20 * u, by + 104 * u);
        g.fillText(growth + " · " + margin + " · " + mult, bx + 20 * u, by + 130 * u);
      } else {
        font(g, 700, 15 * u, F.sans); g.fillStyle = col; g.fillText(SCEN[k].toUpperCase(), bx + 20 * u, by + 36 * u);
        font(g, 600, 28 * u, F.num); g.fillStyle = C.cream; g.textAlign = "right";
        g.fillText(t.negativeEarnings ? "No profit" : price(t.priceMid), bx + colW - 20 * u, by + 42 * u); g.textAlign = "left";
        font(g, 500, 15 * u, F.sans); g.fillStyle = C.dim;
        if (cardH > 120 * u && !t.negativeEarnings) { g.fillText(price(t.priceLow) + "–" + price(t.priceHigh) + " · " + cagrRange(t), bx + 20 * u, by + 72 * u); g.fillText(growth + " · " + margin + " · " + mult, bx + 20 * u, by + 102 * u); }
        else g.fillText(growth + " · " + margin + " · " + mult, bx + 20 * u, by + 70 * u);
      }
    });
    if (o.expected) {
      var ey = f.bottom - 20 * u, w = o.expected.weights;
      runs(g, [
        { t: "Probability-weighted (" + w.bear + "/" + w.base + "/" + w.bull + "): ", w: 500, s: 19 * u, f: F.sans, c: C.dim },
        { t: priceExact(o.expected.price), w: 700, s: 21 * u, f: F.num, c: C.gold },
        { t: " · " + pct(o.expected.cagr, 1) + " a year", w: 500, s: 19 * u, f: F.sans, c: C.dim },
      ], P, ey, W - 2 * P, 26 * u);
    }
  }

  /* ── card 3: how the price is built ────────────────────────────────────── */
  function drawBuild(g, W, H, u, wide) {
    var m = state.model, o = state.outlook, k = state.scenario, proj = o.scenarios[k], t = proj.terminal, col = C[k];
    var f = frame(g, W, H, u, "Valuation Lab · " + m.ticker), P = f.P;
    var y = f.top + 52 * u;
    y = title(g, P, y, W - 2 * P, u, state.headline || ("How the " + t.year + " " + SCEN[k].toLowerCase() + " case for " + m.ticker), state.headline ? "" : "is built", wide ? 52 : 50);
    y += 30 * u;
    runs(g, [{ t: "Every price target is earnings times a multiple. Here is the math.", w: 500, s: 20 * u, f: F.sans, c: C.dim }], P, y + 14 * u, W - 2 * P, 28 * u);
    y += (wide ? 52 : 80) * u;
    var growth = avg(proj.rows.map(function (r) { return r.revGrowth; }));
    var tiles = [
      { op: "", label: "Revenue " + t.year, value: big(t.revenue), note: pct(growth) + " a year from " + big(proj.base.revenue) },
      { op: "×", label: "Net margin", value: pct(t.netMargin, 1), note: "today " + pct(proj.base.netMargin, 1) },
      { op: "=", label: "Net income", value: big(t.netIncome), note: "profit after every cost" },
      { op: "÷", label: "Diluted shares", value: count(t.shares), note: "held flat in this model" },
      { op: "=", label: "Earnings per share", value: priceExact(t.eps), note: "today " + priceExact(proj.base.eps) },
      { op: "×", label: "Exit P/E", value: pe(t.peLow) + "–" + pe(t.peHigh), note: "what the market pays per $1 of EPS" },
    ];
    var cols = wide ? 3 : 2, gap = 16 * u;
    var resultH = 128 * u;
    var rows = Math.ceil(tiles.length / cols);
    var availH = f.bottom - y - resultH - 24 * u;
    var th = Math.min((wide ? 160 : 210) * u, (availH - gap * (rows - 1)) / rows), tw = (W - 2 * P - gap * (cols - 1)) / cols;
    tiles.forEach(function (it, i) {
      var bx = P + (i % cols) * (tw + gap), by = y + Math.floor(i / cols) * (th + gap);
      box(g, bx, by, tw, th, 16 * u, "rgba(243,238,227,.035)", C.line);
      var tx = bx + 22 * u;
      if (it.op) {
        var r = 17 * u;
        g.beginPath(); g.arc(bx + 22 * u + r, by + 22 * u + r, r, 0, Math.PI * 2); g.fillStyle = C.goldSoft; g.fill();
        g.strokeStyle = C.goldLine; g.lineWidth = 1.2 * u; g.stroke();
        font(g, 600, 22 * u, F.num); g.fillStyle = C.gold; g.textAlign = "center"; g.textBaseline = "middle";
        g.fillText(it.op, bx + 22 * u + r, by + 22 * u + r + 1 * u); g.textAlign = "left"; g.textBaseline = "alphabetic";
        tx = bx + 22 * u + 2 * r + 14 * u;
      }
      font(g, 600, 16 * u, F.sans); g.fillStyle = C.dim; g.fillText(it.label, tx, by + 46 * u);
      var hasNote = th >= 150 * u;
      fit(g, it.value, 600, 38 * u, F.num, tw - 44 * u); g.fillStyle = C.cream;
      g.fillText(it.value, bx + 22 * u, by + (hasNote ? th - 54 * u : th - 24 * u));
      font(g, 500, 14 * u, F.sans); g.fillStyle = C.faint;
      if (hasNote) g.fillText(it.note, bx + 22 * u, by + th - 22 * u);
    });
    var ry = Math.max(y + rows * (th + gap) + 8 * u, f.bottom - resultH - (wide ? 10 : 0) * u);
    box(g, P, ry, W - 2 * P, resultH, 18 * u, hexA(col, 0.1), hexA(col, 0.6));
    font(g, 700, 16 * u, F.sans); g.fillStyle = col; g.fillText("= PRICE PER SHARE IN " + t.year, P + 26 * u, ry + 40 * u);
    var v = t.negativeEarnings ? "No profit, no P/E price" : price(t.priceLow) + " – " + price(t.priceHigh);
    fit(g, v, 600, 50 * u, F.num, (W - 2 * P) * 0.6); g.fillStyle = C.cream; g.fillText(v, P + 26 * u, ry + 98 * u);
    if (!t.negativeEarnings) {
      font(g, 500, 18 * u, F.sans); g.fillStyle = C.dim; g.textAlign = "right";
      g.fillText("from " + priceExact(m.startPrice) + " today", W - P - 26 * u, ry + 56 * u);
      font(g, 700, 20 * u, F.sans); g.fillStyle = col;
      g.fillText(cagrRange(t), W - P - 26 * u, ry + 90 * u); g.textAlign = "left";
    }
  }

  /* ── render + actions ───────────────────────────────────────────────────── */
  function ensureFonts() {
    if (fontsReady) return fontsReady;
    if (!document.fonts || !document.fonts.load) return (fontsReady = Promise.resolve());
    fontsReady = Promise.all([
      document.fonts.load('700 40px "Plus Jakarta Sans"'), document.fonts.load('500 20px "Plus Jakarta Sans"'),
      document.fonts.load('400 40px "Instrument Serif"'),
      document.fonts.load('600 40px "IBM Plex Sans"'), document.fonts.load('500 20px "IBM Plex Sans"'),
    ]).catch(function () {});
    return fontsReady;
  }

  function draw(target) {
    var sz = SIZES[state.size], cv = target || canvas;
    cv.width = sz.w; cv.height = sz.h;
    var g = cv.getContext("2d"), wide = sz.w / sz.h > 1.4;
    var u = wide ? 1 : sz.w / 1000;
    if (state.type === "scenarios") drawScenarios(g, sz.w, sz.h, u, wide);
    else if (state.type === "build") drawBuild(g, sz.w, sz.h, u, wide);
    else drawRange(g, sz.w, sz.h, u, wide);
  }

  function render() {
    if (!root || !state.model) return;
    var o = window.ImpliedLensMath.plCalculateOutlook(state.model);
    var err = root.querySelector(".ilpc-err");
    if (!o.ok) { err.textContent = "Fix the model first: " + o.error; err.hidden = false; return; }
    err.hidden = true; state.outlook = o;
    /* A card publishes the model. If the selected case implies a return far
       outside anything a stock sustains for years, say so before it is shared. */
    var tt = o.scenarios[state.scenario].terminal, warn = root.querySelector(".ilpc-warn");
    var midCagr = tt.negativeEarnings ? null : Math.pow(tt.priceMid / state.model.startPrice, 1 / o.horizonYears) - 1;
    warn.hidden = !(midCagr != null && (midCagr > 0.35 || midCagr < -0.25));
    if (!warn.hidden) warn.textContent = "This case implies " + Math.round(midCagr * 100) + "% a year for " + o.horizonYears + " years, far outside what stocks usually sustain. Check the inputs before posting.";
    root.querySelectorAll("[data-ilpc]").forEach(function (b) {
      var p = b.getAttribute("data-ilpc").split(":");
      b.setAttribute("aria-pressed", String(state[p[0]] === p[1]));
    });
    root.querySelector(".ilpc-scen").hidden = state.type === "scenarios";
    root.querySelector(".ilpc-size-note").textContent = SIZES[state.size].note;
    root.querySelector(".ilpc-post").value = postText();
    var ph = root.querySelector(".ilpc-head-in");
    ph.placeholder = defaultHeadline();
    draw();
  }

  function defaultHeadline() {
    var t = state.outlook ? state.outlook.terminalYear : "";
    if (state.type === "scenarios") return name() + " in " + t + ": three ways it could go";
    if (state.type === "build") return "How the " + t + " " + SCEN[state.scenario].toLowerCase() + " case for " + state.model.ticker + " is built";
    return "What could " + name() + " be worth by " + t + "?";
  }

  function postText() {
    var m = state.model, o = state.outlook, t = o.scenarios[state.scenario].terminal, link = "impliedlens.com/stock/" + encodeURIComponent(m.ticker);
    if (state.type === "scenarios") {
      var b = o.scenarios.bear.terminal, u = o.scenarios.bull.terminal;
      return "$" + m.ticker + " by " + o.terminalYear + ", three ways:\n\nBear " + (b.negativeEarnings ? "no profit" : price(b.priceMid)) +
        "\nBase " + price(o.scenarios.base.terminal.priceMid) + "\nBull " + (u.negativeEarnings ? "no profit" : price(u.priceMid)) +
        "\n\nToday " + priceExact(m.startPrice) + ". Every assumption is editable. Build your own:\n" + link;
    }
    if (t.negativeEarnings) return "$" + m.ticker + " " + SCEN[state.scenario].toLowerCase() + " case: no profit by " + t.year + ". Build your own model:\n" + link;
    if (state.type === "build") {
      return "How a " + t.year + " price for $" + m.ticker + " is built:\n\nRevenue " + big(t.revenue) + "\n× " + pct(t.netMargin, 1) + " margin\n÷ " + count(t.shares) +
        " shares\n= " + priceExact(t.eps) + " EPS\n× " + pe(t.peLow) + "–" + pe(t.peHigh) + " P/E\n= " + price(t.priceLow) + "–" + price(t.priceHigh) + "\n\nChange any input and see it move:\n" + link;
    }
    return "What could $" + m.ticker + " be worth by " + t.year + "?\n\nMy " + SCEN[state.scenario].toLowerCase() + " case: " + price(t.priceLow) + "–" + price(t.priceHigh) +
      " (" + cagrRange(t) + " from " + priceExact(m.startPrice) + ").\n\nEvery assumption is editable. Build your own:\n" + link;
  }

  function fileName() {
    var m = state.model;
    return (m.ticker || "projection") + "-" + state.type + "-" + (state.type === "scenarios" ? "" : state.scenario + "-") + state.outlook.terminalYear + "-" + state.size + ".png";
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
      var data = { files: [file], text: postText() };
      if (navigator.canShare && navigator.canShare(data)) navigator.share(data).catch(function () {});
      else download();
    });
  }
  function copyText() {
    var t = root.querySelector(".ilpc-post");
    (navigator.clipboard ? navigator.clipboard.writeText(t.value) : Promise.reject()).then(function () { note("Post text copied"); }, function () { t.select(); document.execCommand("copy"); note("Post text copied"); });
  }

  /* Unlayered on purpose: it beats the site's layered button and input rules
     without !important. */
  var CSS =
    "html.ilpc-open{overflow:hidden}" +
    ".ilpc[hidden]{display:none}.ilpc{position:fixed;inset:0;z-index:2147483000;display:flex;align-items:center;justify-content:center;padding:24px}" +
    ".ilpc-back{position:absolute;inset:0;background:rgba(6,5,4,.72);backdrop-filter:blur(6px);-webkit-backdrop-filter:blur(6px)}" +
    ".ilpc-sheet{position:relative;width:min(1240px,100%);max-height:calc(100dvh - 48px);overflow:auto;background:var(--rp-surface,#14120f);color:var(--rp-text,#f3eee3);border:1px solid var(--rp-border,rgba(243,238,227,.12));border-radius:20px;box-shadow:0 30px 80px rgba(0,0,0,.5);outline:none}" +
    ".ilpc-head{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;padding:22px 26px 6px}" +
    ".ilpc-kicker{font:600 12px/1 var(--rp-sans,sans-serif);color:var(--rp-gold,#e3a945);letter-spacing:.02em}" +
    ".ilpc-head h2{margin:8px 0 0;font:700 24px/1.2 var(--rp-sans,sans-serif);color:var(--rp-text,#f3eee3)}" +
    ".ilpc-x{width:40px;height:40px;border-radius:12px;border:1px solid var(--rp-border,rgba(243,238,227,.14));background:transparent;color:inherit;font-size:18px;cursor:pointer;display:grid;place-items:center}" +
    ".ilpc-body{display:grid;grid-template-columns:300px minmax(0,1fr);grid-template-areas:'c s' 'c a';gap:18px 24px;padding:16px 26px 26px}" +
    ".ilpc-body>*{min-width:0}.ilpc-controls{grid-area:c;display:flex;flex-direction:column;gap:18px}" +
    ".ilpc-stage{grid-area:s;background:#080706;border:1px solid var(--rp-border,rgba(243,238,227,.1));border-radius:14px;padding:14px;display:flex;align-items:center;justify-content:center;min-height:240px}" +
    ".ilpc-canvas{display:block;max-width:100%;max-height:min(58vh,620px);width:auto;height:auto;border-radius:8px;box-shadow:0 10px 40px rgba(0,0,0,.45)}" +
    ".ilpc-actions{grid-area:a;display:flex;flex-wrap:wrap;gap:10px;align-items:flex-start}" +
    ".ilpc-group{display:flex;flex-direction:column;gap:8px;margin:0}" +
    ".ilpc-lbl{font:600 13px/1.2 var(--rp-sans,sans-serif);color:var(--rp-text-2,rgba(243,238,227,.7))}.ilpc-lbl em{font-style:normal;font-weight:500;opacity:.6}" +
    ".ilpc-types{display:flex;flex-direction:column;gap:8px}" +
    ".ilpc-type{display:flex;flex-direction:column;gap:3px;text-align:left;padding:12px 14px;border-radius:12px;border:1px solid var(--rp-border,rgba(243,238,227,.12));background:transparent;color:inherit;cursor:pointer;font:inherit}" +
    ".ilpc-type b{font:600 15px/1.2 var(--rp-sans,sans-serif)}.ilpc-type span{font:500 12.5px/1.35 var(--rp-sans,sans-serif);color:var(--rp-text-3,rgba(243,238,227,.55))}" +
    ".ilpc-type[aria-pressed=true]{border-color:var(--rp-gold,#e3a945);background:rgba(227,169,69,.09)}" +
    ".ilpc-seg{display:flex;padding:3px;border-radius:12px;border:1px solid var(--rp-border,rgba(243,238,227,.12));gap:3px}" +
    ".ilpc-seg button{flex:1;min-height:38px;border:0;border-radius:9px;background:transparent;color:var(--rp-text-2,rgba(243,238,227,.75));font:600 13.5px/1 var(--rp-sans,sans-serif);cursor:pointer;display:flex;align-items:center;justify-content:center;gap:6px}" +
    ".ilpc-seg button[aria-pressed=true]{background:var(--rp-gold,#e3a945);color:#17130c}" +
    ".ilpc-dot{width:8px;height:8px;border-radius:50%;display:inline-block}.ilpc-dot.is-bear{background:#e5735f}.ilpc-dot.is-base{background:#e3a945}.ilpc-dot.is-bull{background:#4fc48a}" +
    ".ilpc-seg button[aria-pressed=true] .ilpc-dot{box-shadow:0 0 0 1.5px #17130c}" +
    ".ilpc-size-note{font:500 12.5px/1.3 var(--rp-sans,sans-serif);color:var(--rp-text-3,rgba(243,238,227,.55))}" +
    ".ilpc-head-in,.ilpc-post{width:100%;box-sizing:border-box;border-radius:10px;border:1px solid var(--rp-border,rgba(243,238,227,.14));background:var(--rp-bg,#0d0c0a);color:inherit;font:500 14px/1.45 var(--rp-sans,sans-serif);padding:10px 12px}" +
    ".ilpc-post{resize:vertical;min-height:110px}" +
    ".ilpc-postwrap{flex:1 1 100%}" +
    ".ilpc-btn{min-height:42px;padding:0 16px;border-radius:11px;border:1px solid var(--rp-border,rgba(243,238,227,.16));background:transparent;color:inherit;font:600 14px/1 var(--rp-sans,sans-serif);display:inline-flex;align-items:center;gap:8px;cursor:pointer}" +
    ".ilpc-btn.is-gold{background:var(--rp-gold,#e3a945);border-color:transparent;color:#17130c}" +
    ".ilpc-btn:focus-visible,.ilpc-type:focus-visible,.ilpc-seg button:focus-visible,.ilpc-x:focus-visible{outline:2px solid var(--rp-gold,#e3a945);outline-offset:2px}" +
    ".ilpc-err{margin:0;color:#e5735f;font:500 13px/1.4 var(--rp-sans,sans-serif)}" +
    ".ilpc-warn{margin:0;padding:10px 12px;border-radius:10px;border:1px solid rgba(227,169,69,.45);background:rgba(227,169,69,.08);color:var(--rp-text,#f3eee3);font:500 13px/1.45 var(--rp-sans,sans-serif)}" +
    "@media (max-width:860px){.ilpc{padding:0;align-items:flex-end}.ilpc-sheet{max-height:94dvh;border-radius:20px 20px 0 0}" +
    ".ilpc-body{grid-template-columns:1fr;grid-template-areas:'s' 'c' 'a';padding:10px 16px 24px}.ilpc-head{padding:18px 16px 4px}" +
    ".ilpc-types{flex-direction:row}.ilpc-type{flex:1 1 0;min-width:0;padding:10px}.ilpc-type b{font-size:13.5px}.ilpc-type span{display:none}.ilpc-stage{padding:8px;min-height:0}.ilpc-canvas{max-height:46vh}" +
    ".ilpc-head-in,.ilpc-post{font-size:16px}.ilpc-btn{flex:1 1 auto;justify-content:center}}";

  function build() {
    if (!document.getElementById("ilpc-style")) {
      var st = document.createElement("style"); st.id = "ilpc-style"; st.textContent = CSS; document.head.appendChild(st);
    }
    root = document.createElement("div");
    root.className = "ilpc"; root.hidden = true;
    root.innerHTML =
      '<div class="ilpc-back" data-close></div>' +
      '<div class="ilpc-sheet" role="dialog" aria-modal="true" aria-labelledby="ilpc-title" tabindex="-1">' +
        '<header class="ilpc-head"><div><span class="ilpc-kicker">Share your model</span><h2 id="ilpc-title">Make a post-ready image</h2></div>' +
        '<button type="button" class="ilpc-x" data-close aria-label="Close"><i class="ti ti-x" aria-hidden="true"></i></button></header>' +
        '<div class="ilpc-body">' +
          '<div class="ilpc-controls">' +
            '<div class="ilpc-group"><span class="ilpc-lbl">Card</span><div class="ilpc-types">' +
              Object.keys(TYPES).map(function (k) { return '<button type="button" class="ilpc-type" data-ilpc="type:' + k + '"><b>' + TYPES[k].label + '</b><span>' + TYPES[k].note + '</span></button>'; }).join("") +
            '</div></div>' +
            '<div class="ilpc-group ilpc-scen"><span class="ilpc-lbl">Scenario</span><div class="ilpc-seg">' +
              Object.keys(SCEN).map(function (k) { return '<button type="button" data-ilpc="scenario:' + k + '"><i class="ilpc-dot is-' + k + '"></i>' + SCEN[k] + '</button>'; }).join("") +
            '</div></div>' +
            '<div class="ilpc-group"><span class="ilpc-lbl">Size</span><div class="ilpc-seg">' +
              Object.keys(SIZES).map(function (k) { return '<button type="button" data-ilpc="size:' + k + '">' + SIZES[k].label + '</button>'; }).join("") +
            '</div><span class="ilpc-size-note"></span></div>' +
            '<label class="ilpc-group"><span class="ilpc-lbl">Headline <em>optional</em></span><input class="ilpc-head-in" type="text" maxlength="80" autocomplete="off"></label>' +
            '<p class="ilpc-err" role="alert" hidden></p>' +
            '<p class="ilpc-warn" role="status" hidden></p>' +
          '</div>' +
          '<div class="ilpc-stage"><canvas class="ilpc-canvas" aria-label="Preview of the image"></canvas></div>' +
          '<div class="ilpc-actions">' +
            '<button type="button" class="ilpc-btn is-gold" data-act="download"><i class="ti ti-download" aria-hidden="true"></i> Download PNG</button>' +
            '<button type="button" class="ilpc-btn" data-act="copy"><i class="ti ti-copy" aria-hidden="true"></i> Copy image</button>' +
            '<button type="button" class="ilpc-btn ilpc-share" data-act="share" hidden><i class="ti ti-share" aria-hidden="true"></i> Share</button>' +
            '<label class="ilpc-group ilpc-postwrap"><span class="ilpc-lbl">Suggested post</span><textarea class="ilpc-post" rows="4"></textarea></label>' +
            '<button type="button" class="ilpc-btn" data-act="text"><i class="ti ti-clipboard-text" aria-hidden="true"></i> Copy post text</button>' +
          '</div>' +
        '</div>' +
      '</div>';
    document.body.appendChild(root);
    canvas = root.querySelector(".ilpc-canvas");
    if (navigator.canShare && window.File) {
      try { if (navigator.canShare({ files: [new File([""], "x.png", { type: "image/png" })] })) root.querySelector(".ilpc-share").hidden = false; } catch (e) {}
    }
    root.addEventListener("click", function (e) {
      if (e.target.closest("[data-close]")) return close();
      var b = e.target.closest("[data-ilpc]");
      if (b) { var p = b.getAttribute("data-ilpc").split(":"); state[p[0]] = p[1]; if (p[0] === "type") { state.headline = ""; root.querySelector(".ilpc-head-in").value = ""; } render(); return; }
      var a = e.target.closest("[data-act]");
      if (!a) return;
      var act = a.getAttribute("data-act");
      if (act === "download") download(); else if (act === "copy") copyImage(); else if (act === "share") share(); else if (act === "text") copyText();
    });
    root.querySelector(".ilpc-head-in").addEventListener("input", function (e) { state.headline = e.target.value.trim(); draw(); });
    document.addEventListener("keydown", function (e) { if (e.key === "Escape" && root && !root.hidden) close(); });
  }

  function open(model) {
    if (!model || !window.ImpliedLensMath) return;
    if (!root) build();
    state.model = model;
    state.scenario = model.selectedScenario || "base";
    root.hidden = false;
    document.documentElement.classList.add("ilpc-open");
    root.querySelector(".ilpc-sheet").focus({ preventScroll: true });
    render();
    ensureFonts().then(render);
  }
  function close() {
    if (!root) return;
    root.hidden = true;
    document.documentElement.classList.remove("ilpc-open");
  }

  window.ILProjectionCards = { open: open, close: close, _draw: draw, _state: state };
})();

/* ═══════════════════════════════════════════════════════════════════════════
   ImpliedLens — Growth over time

   Quarter-by-quarter charts of what a company produces: revenue, profit, EPS,
   cash flow, free cash flow per share, share count, margins and valuation
   multiples, from SEC filings. Trailing-twelve-month or quarterly, 3/5/10
   years or everything. Each chart carries the headline number, its growth
   rate, a plain-English read and a one-line definition, and can be turned
   into a post-ready image in Share Studio.

   Data: /api/fundamentals/history/:ticker   Maths: growth-math.js
   ═══════════════════════════════════════════════════════════════════════════ */
(function () {
  "use strict";

  var M = function () { return window.ILGrowthMath; };
  var state = { ticker: null, data: null, metric: "revenue", period: "ttm", years: 5, loading: false, error: null };
  try {
    var saved = JSON.parse(localStorage.getItem("il-growth") || "{}");
    if (saved.metric) state.metric = saved.metric;
    if (saved.period === "q" || saved.period === "ttm") state.period = saved.period;
    if ([3, 5, 10, 0].indexOf(saved.years) >= 0) state.years = saved.years;
  } catch (e) {}
  function persist() {
    try { localStorage.setItem("il-growth", JSON.stringify({ metric: state.metric, period: state.period, years: state.years })); } catch (e) {}
  }

  function isDark() { return document.documentElement.getAttribute("data-theme") === "dark"; }
  var COLORS = {
    growth: { d: "#E3A945", l: "#A6741F" },
    cash: { d: "#3FCB9B", l: "#0E8A63" },
    owners: { d: "#7FB2E5", l: "#2F6FA8" },
    margins: { d: "#B48CF0", l: "#7446B8" },
    value: { d: "#F0A35E", l: "#B8661F" }
  };
  function colorFor(id) {
    var g = M().METRICS[id].group;
    return (COLORS[g] || COLORS.growth)[isDark() ? "d" : "l"];
  }
  function negColor() { return isDark() ? "#F0606E" : "#C23447"; }
  function esc(s) { return String(s == null ? "" : s).replace(/[&<>"]/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]; }); }
  function shortName() {
    var n = (state.data && state.data.name) || state.ticker || "";
    n = String(n).replace(/\b(inc|corp|corporation|incorporated|ltd|plc|co|company|holdings)\.?$/i, "").replace(/[,\s]+$/, "");
    if (n === n.toUpperCase() && n.length > 4) n = n.toLowerCase().replace(/\b\w/g, function (c) { return c.toUpperCase(); });
    return n || state.ticker;
  }

  /* ── styles ─────────────────────────────────────────────────────────────── */
  var CSS = [
    ".ilg{--g-ink:#F1EDE4;--g-dim:rgba(241,237,228,.64);--g-faint:rgba(241,237,228,.42);--g-line:rgba(241,237,228,.09);--g-line2:rgba(241,237,228,.16);--g-panel:rgba(241,237,228,.028);--g-hover:rgba(241,237,228,.06);--g-gold:#E3A945;--g-tip:#15130F;margin:4px 0 22px;font-family:'Plus Jakarta Sans',-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;color:var(--g-ink)}",
    "html:not([data-theme='dark']) .ilg{--g-ink:#17191D;--g-dim:rgba(23,25,29,.66);--g-faint:rgba(23,25,29,.46);--g-line:rgba(23,25,29,.09);--g-line2:rgba(23,25,29,.16);--g-panel:rgba(255,255,255,.7);--g-hover:rgba(23,25,29,.05);--g-gold:#9C6C17;--g-tip:#FFFFFF}",
    ".ilg[hidden]{display:none}",
    ".ilg-card{border:1px solid var(--g-line);border-radius:18px;background:var(--g-panel);padding:20px 22px 16px}",
    ".ilg-head{display:flex;flex-wrap:wrap;align-items:flex-end;justify-content:space-between;gap:12px 20px;margin-bottom:14px}",
    ".ilg-kicker{display:block;font:700 11.5px/1 'Plus Jakarta Sans',sans-serif;letter-spacing:.09em;text-transform:uppercase;color:var(--g-gold);margin-bottom:8px}",
    ".ilg-head h3{margin:0;font:700 22px/1.2 'Plus Jakarta Sans',sans-serif;color:var(--g-ink);letter-spacing:-.01em}",
    ".ilg-head h3 em{font-family:'Instrument Serif',Georgia,serif;font-style:italic;font-weight:400;color:var(--g-gold);font-size:1.12em}",
    ".ilg-sub{margin:6px 0 0;font:500 13px/1.4 'Plus Jakarta Sans',sans-serif;color:var(--g-dim)}",
    ".ilg-ctrl{display:flex;flex-wrap:wrap;gap:8px}",
    ".ilg-seg{display:inline-flex;gap:2px;padding:3px;border-radius:11px;border:1px solid var(--g-line);background:var(--g-hover)}",
    ".ilg-seg button,.ilg-chip{appearance:none;border:0;background:transparent;color:var(--g-dim);font:600 12.5px/1 'Plus Jakarta Sans',sans-serif;height:30px;padding:0 11px;border-radius:8px;cursor:pointer;white-space:nowrap;transition:background .14s,color .14s}",
    ".ilg-seg button:hover,.ilg-chip:hover{color:var(--g-ink);background:var(--g-hover)}",
    ".ilg-seg button[aria-pressed=true]{background:var(--g-gold);color:#17130C}",
    ".ilg-metrics{display:flex;flex-wrap:wrap;gap:6px 14px;margin:0 0 16px;padding:0 0 14px;border-bottom:1px solid var(--g-line)}",
    ".ilg-group{display:flex;flex-wrap:wrap;align-items:center;gap:2px}",
    ".ilg-group>span{font:700 10.5px/1 'Plus Jakarta Sans',sans-serif;letter-spacing:.08em;text-transform:uppercase;color:var(--g-faint);margin-right:6px}",
    ".ilg-chip[aria-pressed=true]{color:var(--c);background:color-mix(in srgb,var(--c) 15%,transparent);box-shadow:inset 0 0 0 1px color-mix(in srgb,var(--c) 40%,transparent)}",
    ".ilg-chip[disabled]{opacity:.35;cursor:default;background:none}",
    ".ilg-select{display:none}",
    ".ilg-select{position:relative}.ilg-select::after{content:'';position:absolute;right:17px;bottom:18px;width:7px;height:7px;border-right:1.7px solid var(--g-dim);border-bottom:1.7px solid var(--g-dim);transform:rotate(45deg);pointer-events:none}",
    ".ilg-select span{display:block;font:700 10.5px/1 'Plus Jakarta Sans',sans-serif;letter-spacing:.08em;text-transform:uppercase;color:var(--g-faint);margin-bottom:6px}",
    ".ilg-select select{width:100%;height:44px;padding:0 38px 0 12px;border-radius:11px;border:1px solid var(--g-line2);background:var(--g-hover) url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12'%3E%3Cpath d='M2 4l4 4 4-4' fill='none' stroke='%23999' stroke-width='1.6'/%3E%3C/svg%3E\") no-repeat right 14px center;color:var(--g-ink);font:600 16px/1 'Plus Jakarta Sans',sans-serif;appearance:none;-webkit-appearance:none}",
    ".ilg-top{display:flex;flex-wrap:wrap;align-items:flex-end;justify-content:space-between;gap:10px 18px}",
    ".ilg-big{font:600 34px/1 'IBM Plex Sans','Plus Jakarta Sans',sans-serif;letter-spacing:-.01em;color:var(--g-ink)}",
    ".ilg-big small{display:block;margin-top:7px;font:600 12.5px/1.2 'Plus Jakarta Sans',sans-serif;color:var(--g-dim);letter-spacing:0}",
    ".ilg-stats{display:flex;flex-wrap:wrap;gap:8px}",
    ".ilg-stat{display:flex;flex-direction:column;gap:5px;padding:9px 12px;border-radius:11px;border:1px solid var(--g-line);min-width:96px}",
    ".ilg-stat span{font:600 11px/1 'Plus Jakarta Sans',sans-serif;color:var(--g-faint)}",
    ".ilg-stat b{font:600 16px/1 'IBM Plex Sans',sans-serif;color:var(--g-ink)}",
    ".ilg-stat b.up{color:#3FCB9B}.ilg-stat b.down{color:#F0606E}",
    "html:not([data-theme='dark']) .ilg-stat b.up{color:#0B8A55}html:not([data-theme='dark']) .ilg-stat b.down{color:#C23447}",
    ".ilg-share{appearance:none;display:inline-flex;align-items:center;gap:7px;height:36px;padding:0 14px;border-radius:10px;border:1px solid var(--g-line2);background:transparent;color:var(--g-ink);font:600 13px/1 'Plus Jakarta Sans',sans-serif;cursor:pointer}",
    ".ilg-share:hover{border-color:var(--g-gold);color:var(--g-gold)}",
    ".ilg-read{margin:14px 0 2px;font:500 15px/1.55 'Plus Jakarta Sans',sans-serif;color:var(--g-ink);max-width:880px}",
    ".ilg-chart{position:relative;margin-top:12px;height:300px;touch-action:pan-y}",
    ".ilg-chart svg{display:block;width:100%;height:100%;overflow:visible}",
    ".ilg-tip{position:absolute;z-index:3;pointer-events:none;padding:8px 10px;border-radius:9px;background:var(--g-tip);border:1px solid var(--g-line2);box-shadow:0 10px 28px rgba(0,0,0,.35);font:500 12px/1.45 'Plus Jakarta Sans',sans-serif;color:var(--g-dim);white-space:nowrap;transform:translate(-50%,-100%);opacity:0;transition:opacity .1s}",
    ".ilg-tip b{display:block;font:600 15px/1.2 'IBM Plex Sans',sans-serif;color:var(--g-ink)}",
    ".ilg-tip.on{opacity:1}",
    ".ilg-what{margin:10px 0 0;font:500 12.5px/1.5 'Plus Jakarta Sans',sans-serif;color:var(--g-faint)}",
    ".ilg-what b{color:var(--g-dim);font-weight:700}",
    ".ilg-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin-top:14px}",
    ".ilg-mini{appearance:none;text-align:left;display:flex;flex-direction:column;gap:8px;padding:14px 14px 10px;border-radius:14px;border:1px solid var(--g-line);background:var(--g-panel);color:inherit;cursor:pointer;font:inherit;transition:border-color .14s,transform .14s}",
    ".ilg-mini:hover{border-color:var(--g-line2);transform:translateY(-1px)}",
    ".ilg-mini[aria-pressed=true]{border-color:color-mix(in srgb,var(--c) 55%,transparent)}",
    ".ilg-mini-h{display:flex;justify-content:space-between;align-items:baseline;gap:8px}",
    ".ilg-mini-h span{font:600 12.5px/1.2 'Plus Jakarta Sans',sans-serif;color:var(--g-dim)}",
    ".ilg-mini-h em{font:600 12px/1 'IBM Plex Sans',sans-serif;font-style:normal;color:var(--g-faint)}",
    ".ilg-mini-h em.up{color:#3FCB9B}.ilg-mini-h em.down{color:#F0606E}",
    "html:not([data-theme='dark']) .ilg-mini-h em.up{color:#0B8A55}html:not([data-theme='dark']) .ilg-mini-h em.down{color:#C23447}",
    ".ilg-mini b{font:600 21px/1 'IBM Plex Sans',sans-serif;color:var(--g-ink)}",
    ".ilg-mini .ilg-spark{height:64px}",
    ".ilg-foot{margin:12px 2px 0;font:500 11.5px/1.5 'Plus Jakarta Sans',sans-serif;color:var(--g-faint)}",
    ".ilg-empty{padding:28px 0;text-align:center;font:500 14px/1.5 'Plus Jakarta Sans',sans-serif;color:var(--g-dim)}",
    ".ilg-skel{height:300px;border-radius:12px;background:linear-gradient(90deg,var(--g-hover),transparent,var(--g-hover));background-size:200% 100%;animation:ilg-sh 1.4s linear infinite}",
    "@keyframes ilg-sh{to{background-position:-200% 0}}",
    "@media (max-width:860px){.ilg-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}",
    "@media (max-width:640px){.ilg-card{padding:16px 14px 12px;border-radius:16px}.ilg-head h3{font-size:19px}.ilg-big{font-size:28px}.ilg-chart{height:240px}.ilg-read{font-size:14px}.ilg-metrics{display:none}.ilg-select{display:block;margin:0 0 16px}.ilg-ctrl{flex-wrap:nowrap;width:100%}.ilg-seg button{padding:0 9px;font-size:12px}.ilg-grid{gap:8px}.ilg-mini{padding:11px 11px 8px}.ilg-mini b{font-size:17px}.ilg-mini .ilg-spark{height:48px}.ilg-mini-h{flex-direction:column;align-items:flex-start;gap:4px}.ilg-stats{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));width:100%}.ilg-stat{min-width:0;padding:8px 9px}.ilg-stat b{font-size:14.5px}.ilg-stat span{font-size:10.5px}.ilg-share{grid-column:1/-1;justify-content:center}}"
  ].join("\n");
  function injectCss() {
    if (document.getElementById("ilg-style")) return;
    var st = document.createElement("style"); st.id = "ilg-style"; st.textContent = CSS;
    document.head.appendChild(st);
  }

  /* ── SVG bars ───────────────────────────────────────────────────────────── */
  var SVGNS = "http://www.w3.org/2000/svg";
  function niceStep(span, target) {
    var raw = span / Math.max(1, target), mag = Math.pow(10, Math.floor(Math.log10(raw || 1))), f = raw / mag;
    return (f < 1.5 ? 1 : f < 3 ? 2 : f < 7 ? 5 : 10) * mag;
  }
  var gid = 0;
  function bars(host, points, id, opts) {
    opts = opts || {};
    var W = Math.max(120, host.clientWidth || 600), H = Math.max(40, host.clientHeight || (opts.mini ? 64 : 300));
    var mini = !!opts.mini, color = colorFor(id), neg = negColor();
    var axisW = mini ? 0 : 62, axisH = mini ? 0 : 26, padT = mini ? 4 : 26;
    var pw = W - axisW, ph = H - axisH - padT;
    var vals = points.map(function (p) { return p.value; }).filter(function (v) { return v != null; });
    var lo = Math.min(0, Math.min.apply(null, vals)), hi = Math.max(0, Math.max.apply(null, vals));
    if (hi === lo) hi = lo + 1;
    var step = niceStep(hi - lo, mini ? 2 : 4);
    var top = Math.ceil(hi / step) * step, bottom = Math.floor(lo / step) * step;
    if (!mini && top - hi < step * 0.18) top += step * 0.5;   // room for the value label
    function Y(v) { return padT + (top - v) / (top - bottom) * ph; }
    var n = points.length, slot = pw / n, bw = Math.max(1.5, Math.min(slot * (mini ? 0.62 : 0.66), 46));
    var M_ = M();
    var g = "ilg" + (++gid);
    var parts = [];
    parts.push('<defs><linearGradient id="' + g + 'p" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="' + color + '"/><stop offset="1" stop-color="' + color + '" stop-opacity=".55"/></linearGradient>' +
      '<linearGradient id="' + g + 'n" x1="0" y1="1" x2="0" y2="0"><stop offset="0" stop-color="' + neg + '"/><stop offset="1" stop-color="' + neg + '" stop-opacity=".55"/></linearGradient></defs>');
    if (!mini) {
      for (var t = bottom; t <= top + 1e-9; t += step) {
        var yy = Math.round(Y(t)) + 0.5;
        parts.push('<line x1="0" x2="' + pw + '" y1="' + yy + '" y2="' + yy + '" stroke="' + (Math.abs(t) < 1e-9 ? "var(--g-line2)" : "var(--g-line)") + '" stroke-width="1"/>');
        parts.push('<text x="' + (pw + 10) + '" y="' + (yy + 4) + '" fill="var(--g-faint)" font-family="IBM Plex Sans, sans-serif" font-size="11.5">' + esc(M_.format(t, id, { compact: true })) + "</text>");
      }
    }
    var zero = Y(0);
    points.forEach(function (p, i) {
      if (p.value == null) return;
      var x = i * slot + (slot - bw) / 2, y = Y(p.value), h = Math.abs(zero - y), r = Math.min(mini ? 1.5 : 3.5, bw / 2, h);
      var last = i === n - 1;
      var up = p.value >= 0, yTop = up ? y : zero, op = last ? 1 : mini ? 0.82 : 0.86;
      var d = up
        ? "M" + x + "," + (yTop + h) + "V" + (yTop + r) + "Q" + x + "," + yTop + " " + (x + r) + "," + yTop + "H" + (x + bw - r) + "Q" + (x + bw) + "," + yTop + " " + (x + bw) + "," + (yTop + r) + "V" + (yTop + h) + "Z"
        : "M" + x + "," + yTop + "V" + (yTop + h - r) + "Q" + x + "," + (yTop + h) + " " + (x + r) + "," + (yTop + h) + "H" + (x + bw - r) + "Q" + (x + bw) + "," + (yTop + h) + " " + (x + bw) + "," + (yTop + h - r) + "V" + yTop + "Z";
      parts.push('<path d="' + d + '" fill="url(#' + g + (up ? "p" : "n") + ')" opacity="' + op + '"' + (last && !mini ? ' stroke="' + (up ? color : neg) + '" stroke-width="1.2"' : "") + "/>");
    });
    if (!mini) {
      /* Value label on the latest bar. */
      var lp = points[n - 1];
      if (lp && lp.value != null) {
        var lx = (n - 1) * slot + slot / 2, ly = lp.value >= 0 ? Y(lp.value) - 8 : Y(lp.value) + 16;
        var anchor = lx > pw - 40 ? "end" : "middle";
        parts.push('<text x="' + Math.min(lx, pw) + '" y="' + ly + '" text-anchor="' + anchor + '" fill="var(--g-ink)" font-family="IBM Plex Sans, sans-serif" font-weight="600" font-size="12.5">' + esc(M_.format(lp.value, id)) + "</text>");
      }
      /* Years along the bottom, with a tick where each calendar year starts. */
      var years = [];
      points.forEach(function (p, i) {
        if (!years.length || years[years.length - 1].year !== p.year) years.push({ year: p.year, from: i, to: i });
        else years[years.length - 1].to = i;
      });
      var minGap = 34, lastX = -999;
      years.forEach(function (y, k) {
        var x0 = y.from * slot, x1 = (y.to + 1) * slot, cx = (x0 + x1) / 2;
        if (k > 0) parts.push('<line x1="' + Math.round(x0) + '.5" x2="' + Math.round(x0) + '.5" y1="' + (padT + ph) + '" y2="' + (padT + ph + 6) + '" stroke="var(--g-line2)"/>');
        var label = y.to - y.from >= 2 || years.length < 4 ? String(y.year) : "";
        if (label && cx - lastX >= minGap) {
          parts.push('<text x="' + cx + '" y="' + (padT + ph + 19) + '" text-anchor="middle" fill="var(--g-faint)" font-family="IBM Plex Sans, sans-serif" font-size="11.5">' + (years.length > 8 && pw < 560 ? "’" + String(y.year).slice(2) : y.year) + "</text>");
          lastX = cx;
        }
      });
    }
    host.innerHTML = '<svg viewBox="0 0 ' + W + " " + H + '" preserveAspectRatio="none" role="img" aria-label="' + esc(M_.METRICS[id].label) + ' by quarter">' + parts.join("") + "</svg>";

    if (!mini) {
      var tip = document.createElement("div");
      tip.className = "ilg-tip";
      host.appendChild(tip);
      var svgEl = host.querySelector("svg");
      var show = function (ev) {
        var rect = svgEl.getBoundingClientRect();
        var x = (ev.clientX - rect.left) * (W / rect.width);
        var i = Math.max(0, Math.min(n - 1, Math.floor(x / slot)));
        var p = points[i];
        if (!p || p.value == null) { tip.classList.remove("on"); return; }
        var prev = points[i - 4];
        var yoy = prev && prev.value != null ? (M_.METRICS[id].kind === "pct" ? p.value - prev.value : prev.value > 0 ? (p.value / prev.value - 1) * 100 : null) : null;
        tip.innerHTML = "<b>" + esc(M_.format(p.value, id)) + "</b>" + esc(p.label) + (yoy != null ? " · " + esc(M_.changeText(yoy, id)) + " vs a year earlier" : "") + (p.derived ? "<br>Part derived from the annual report" : "");
        tip.style.left = ((i + 0.5) * slot) * (rect.width / W) + "px";
        tip.style.top = (Math.min(Y(Math.max(0, p.value)), Y(p.value)) - 10) * (rect.height / H) + "px";
        tip.classList.add("on");
      };
      svgEl.addEventListener("pointermove", show);
      svgEl.addEventListener("pointerdown", show);
      svgEl.addEventListener("pointerleave", function () { tip.classList.remove("on"); });
    }
  }

  /* ── rendering ─────────────────────────────────────────────────────────── */
  var root = null;
  var MINIS = ["revenue", "netIncome", "eps", "freeCashFlow", "shares", "pe"];

  function ensureRoot() {
    if (root && document.body.contains(root)) return root;
    var anchor = document.getElementById("fin-glance");
    var parent = anchor ? anchor.parentElement : document.getElementById("fin-content");
    if (!parent) return null;
    injectCss();
    root = document.createElement("section");
    root.className = "ilg";
    root.id = "il-growth";
    root.setAttribute("aria-labelledby", "ilg-title");
    /* Generic section rules in the bundled sheets pad every <section> with
       !important; only an inline !important outranks those. */
    ["padding", "border", "background", "box-shadow"].forEach(function (k) { root.style.setProperty(k, k === "padding" ? "0" : "none", "important"); });
    if (anchor) anchor.insertAdjacentElement("afterend", root); else parent.insertBefore(root, parent.firstChild);
    root.addEventListener("click", onClick);
    root.addEventListener("change", function (e) {
      if (e.target && e.target.matches(".ilg-select select")) { state.metric = e.target.value; persist(); render(); }
    });
    if (typeof ResizeObserver === "function") {
      var last = 0;
      new ResizeObserver(function () {
        var w = root.clientWidth;
        if (Math.abs(w - last) > 4) { last = w; if (state.data) drawCharts(); }
      }).observe(root);
    }
    return root;
  }

  function onClick(e) {
    var b = e.target.closest("button");
    if (!b || !root.contains(b)) return;
    var v;
    if ((v = b.getAttribute("data-metric"))) { if (!b.disabled) { state.metric = v; persist(); render(); } return; }
    if ((v = b.getAttribute("data-period"))) { state.period = v; persist(); render(); return; }
    if ((v = b.getAttribute("data-years")) != null && b.hasAttribute("data-years")) { state.years = Number(v); persist(); render(); return; }
    if (b.hasAttribute("data-share")) shareImage();
  }

  function statusHtml(html) {
    return '<div class="ilg-card"><div class="ilg-head"><div><span class="ilg-kicker">Growth over time</span><h3 id="ilg-title">' + esc(state.ticker || "") + " fundamentals</h3></div></div>" + html + "</div>";
  }

  function render() {
    var el = ensureRoot();
    if (!el) return;
    el.hidden = false;
    if (state.loading) { el.innerHTML = statusHtml('<div class="ilg-skel" aria-label="Loading quarterly history"></div>'); return; }
    if (state.error) { el.innerHTML = statusHtml('<div class="ilg-empty">' + esc(state.error) + "</div>"); return; }
    if (!state.data) { el.hidden = true; return; }
    var MM = M(), rows = state.data.quarters, name = shortName();
    if (!MM.available(rows, state.metric, state.period)) state.metric = "revenue";
    var id = state.metric, meta = MM.METRICS[id];
    var pts = MM.series(rows, id, state.period, state.years);
    var st = MM.stats(pts, id);
    var firstLabel = rows.length ? rows[0].label : "";
    var color = colorFor(id);

    var groups = MM.GROUPS.map(function (g) {
      var chips = MM.ORDER.filter(function (k) { return MM.METRICS[k].group === g.id; }).map(function (k) {
        var ok = MM.available(rows, k, state.period);
        return '<button type="button" class="ilg-chip" data-metric="' + k + '" aria-pressed="' + (k === id) + '"' + (ok ? "" : " disabled title=\"Not reported for this company\"") +
          ' style="--c:' + colorFor(k) + '">' + esc(MM.METRICS[k].short) + "</button>";
      }).join("");
      return '<div class="ilg-group" role="group" aria-label="' + g.label + '"><span>' + g.label + "</span>" + chips + "</div>";
    }).join("");

    var basis = meta.ttmOnly ? "trailing twelve months" : state.period === "ttm" ? "trailing twelve months" : "latest quarter, " + (st ? st.last.label : "");
    var yoyCls = st && st.yoy != null ? (st.yoy >= 0 ? "up" : "down") : "";
    var cagrCls = st && st.cagr != null ? (st.cagr >= 0 ? "up" : "down") : "";
    var flip = meta.kind === "multiple" || id === "shares";   // lower is not bad here; keep neutral
    if (flip) { yoyCls = ""; cagrCls = ""; }
    var statBlocks = st ? [
      ["vs a year ago", MM.changeText(st.yoy, id), yoyCls],
      meta.kind === "pct" || meta.kind === "multiple"
        ? ["Range shown", MM.format(st.low.value, id) + " – " + MM.format(st.high.value, id), ""]
        : ["Per year, " + Math.max(1, Math.round(st.years)) + "y", st.cagr != null ? MM.signedPct(st.cagr) : "—", cagrCls],
      ["Since " + st.first.label, meta.kind === "pct" ? MM.changeText(st.total, id) : meta.kind === "multiple" ? MM.format(st.first.value, id) + " → " + MM.format(st.last.value, id) : MM.signedPct(st.total, 0), flip ? "" : st.total != null ? (st.total >= 0 ? "up" : "down") : ""]
    ] : [];

    var html =
      '<div class="ilg-card">' +
        '<div class="ilg-head"><div><span class="ilg-kicker">Growth over time</span>' +
          '<h3 id="ilg-title">How ' + esc(name) + " has <em>grown</em></h3>" +
          '<p class="ilg-sub">Every quarter since ' + esc(firstLabel) + ", straight from SEC filings.</p></div>" +
          '<div class="ilg-ctrl">' +
            '<div class="ilg-seg" role="group" aria-label="Period">' +
              '<button type="button" data-period="ttm" aria-pressed="' + (state.period === "ttm") + '" title="Each bar is the sum of the last four quarters: smooths out seasonality">TTM</button>' +
              '<button type="button" data-period="q" aria-pressed="' + (state.period === "q") + '" title="Each bar is a single quarter">Quarterly</button></div>' +
            '<div class="ilg-seg" role="group" aria-label="Years shown">' +
              [[3, "3Y"], [5, "5Y"], [10, "10Y"], [0, "All"]].map(function (y) {
                return '<button type="button" data-years="' + y[0] + '" aria-pressed="' + (state.years === y[0]) + '">' + y[1] + "</button>";
              }).join("") + "</div>" +
          "</div></div>" +
        '<div class="ilg-metrics" role="navigation" aria-label="Metric">' + groups + "</div>" +
        '<label class="ilg-select"><span>Metric</span><select aria-label="Metric">' + MM.GROUPS.map(function (g) {
          return '<optgroup label="' + g.label + '">' + MM.ORDER.filter(function (k) { return MM.METRICS[k].group === g.id; }).map(function (k) {
            return '<option value="' + k + '"' + (k === id ? " selected" : "") + (MM.available(rows, k, state.period) ? "" : " disabled") + ">" + esc(MM.METRICS[k].label) + "</option>";
          }).join("") + "</optgroup>";
        }).join("") + "</select></label>" +
        '<div class="ilg-top"><div class="ilg-big" style="color:' + color + '">' + (st ? esc(MM.format(st.last.value, id)) : "—") +
          "<small>" + esc(meta.label) + " · " + esc(basis) + "</small></div>" +
          '<div class="ilg-stats">' + statBlocks.map(function (s) {
            return '<div class="ilg-stat"><span>' + esc(s[0]) + '</span><b class="' + s[2] + '">' + esc(s[1]) + "</b></div>";
          }).join("") +
          '<button type="button" class="ilg-share" data-share title="Make a branded image of this chart"><svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3.5" y="5" width="17" height="14" rx="2.2"/><path d="M3.5 15.5l4.6-4.4 3.6 3.4 2.8-2.6 6 5.6"/></svg>Share image</button></div></div>' +
        '<p class="ilg-read">' + esc(MM.read(rows, id, state.period, state.years, name)) + "</p>" +
        '<div class="ilg-chart" id="ilg-main"></div>' +
        '<p class="ilg-what"><b>What it is:</b> ' + esc(meta.what) + "</p>" +
      "</div>" +
      '<div class="ilg-grid">' + MINIS.map(function (k) {
        if (!MM.available(rows, k, "ttm")) k = k === "pe" ? "operatingMargin" : k;
        var p = MM.series(rows, k, "ttm", state.years), s = MM.stats(p, k);
        var neutral = MM.METRICS[k].kind === "multiple" || k === "shares";
        var ch = s && s.yoy != null ? '<em class="' + (neutral ? "" : s.yoy >= 0 ? "up" : "down") + '">' + esc(MM.changeText(s.yoy, k)) + " y/y</em>" : "";
        return '<button type="button" class="ilg-mini" data-metric="' + k + '" aria-pressed="' + (k === id) + '" style="--c:' + colorFor(k) + '">' +
          '<span class="ilg-mini-h"><span>' + esc(MM.METRICS[k].short) + (MM.METRICS[k].agg === "sum" ? " (TTM)" : "") + "</span>" + ch + "</span>" +
          "<b>" + (s ? esc(MM.format(s.last.value, k)) : "—") + "</b>" +
          '<span class="ilg-spark" data-spark="' + k + '"></span></button>';
      }).join("") + "</div>" +
      '<p class="ilg-foot">' + esc(state.data.calendar || "") +
        (state.period === "q" ? " Fourth-quarter figures and quarterly cash flows are worked out from the annual and year-to-date reports." : "") +
        (state.data.splits && state.data.splits.length ? " Share counts and per-share figures are adjusted for stock splits." : "") +
        (state.data.priceNote ? " " + esc(state.data.priceNote) : "") + " Source: SEC EDGAR XBRL; prices from Yahoo Finance.</p>";
    el.innerHTML = html;
    drawCharts();

    /* The annual revenue card above is now a subset of this; keep its tiles. */
    var oldCard = document.querySelector("#fin-glance .il-fg-card");
    if (oldCard) oldCard.style.display = "none";
  }

  function drawCharts() {
    if (!root || !state.data) return;
    var MM = M(), rows = state.data.quarters;
    var main = root.querySelector("#ilg-main");
    if (main) bars(main, MM.series(rows, state.metric, state.period, state.years), state.metric);
    root.querySelectorAll("[data-spark]").forEach(function (h) {
      var k = h.getAttribute("data-spark");
      bars(h, MM.series(rows, k, "ttm", state.years), k, { mini: true });
    });
  }

  function shareImage() {
    if (!window.ILShareStudio || !window.ILShareStudio.openSeries || !state.data) return;
    var MM = M(), rows = state.data.quarters, id = state.metric, meta = MM.METRICS[id];
    var pts = MM.series(rows, id, state.period, state.years);
    window.ILShareStudio.openSeries({
      ticker: state.ticker, name: state.data.name, short: shortName(),
      metric: id, label: meta.label, period: meta.ttmOnly ? "Trailing 12 months" : meta.agg === "last" ? "By quarter" : state.period === "ttm" ? "TTM" : "Quarterly",
      color: COLORS[meta.group], points: pts, stats: MM.stats(pts, id),
      read: MM.read(rows, id, state.period, state.years, shortName()),
      format: function (v) { return MM.format(v, id); },
      formatCompact: function (v) { return MM.format(v, id, { compact: true }); },
      changeText: function (v) { return MM.changeText(v, id); },
      kind: meta.kind
    });
  }

  /* ── loading ───────────────────────────────────────────────────────────── */
  var inflight = null;
  function load(ticker) {
    ticker = String(ticker || "").toUpperCase();
    if (!ticker || !M()) return;
    if (state.ticker === ticker && (state.data || state.loading)) { render(); return; }
    state.ticker = ticker; state.data = null; state.error = null; state.loading = true;
    render();
    var req = inflight = fetch("/api/fundamentals/history/" + encodeURIComponent(ticker), { credentials: "same-origin" })
      .then(function (r) { return r.json().then(function (j) { return { ok: r.ok, status: r.status, body: j }; }); })
      .then(function (res) {
        if (req !== inflight) return;
        state.loading = false;
        if (res.ok && res.body && res.body.quarters && res.body.quarters.length >= 4) state.data = res.body;
        else if (res.status === 401 || res.status === 403) { state.error = null; state.data = null; if (root) root.hidden = true; return; }
        else state.error = (res.body && res.body.error) || "Quarterly history is not available for this company.";
        render();
      })
      .catch(function () {
        if (req !== inflight) return;
        state.loading = false;
        state.error = "Couldn't load the quarterly history. Check your connection and try again.";
        render();
      });
  }

  /* Recolour on theme change. */
  new MutationObserver(function (m) {
    for (var i = 0; i < m.length; i++) if (m[i].attributeName === "data-theme" && state.data) { render(); return; }
  }).observe(document.documentElement, { attributes: true });

  window.ILGrowth = { load: load, render: render, _state: state };
})();

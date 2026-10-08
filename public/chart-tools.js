/* ═══════════════════════════════════════════════════════════════════════════
   ImpliedLens — chart tools

   Sits on top of chart-engine.js and gives the price chart, in the page and in
   full screen alike:
     · one compact toolbar that wraps instead of scrolling (timeframe, chart
       type, indicators menu, scale, zoom, share, full screen, more);
     · technical-analysis drawings — trend line, ray, horizontal level,
       highlight zone, Fibonacci retracement, measure, pen, highlighter,
       eraser, colours, undo / redo / clear.

   Drawings are stored as (time, price) pairs, not pixels, so they stay pinned
   to the bars through pan, zoom, timeframe changes, older-history backfill and
   the jump to full screen. They are painted by a Lightweight Charts series
   primitive, which means they are part of the chart's own canvas and appear in
   its screenshots. They are kept per ticker in this browser.
   ═══════════════════════════════════════════════════════════════════════════ */
(function () {
  "use strict";

  /* ── icons (24-unit stroke set, drawn to match the product's line weight) ── */
  function svg(body, fill) {
    return '<svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true" focusable="false" fill="' + (fill || "none") +
      '" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">' + body + "</svg>";
  }
  var DOT = function (cx, cy) { return '<circle cx="' + cx + '" cy="' + cy + '" r="1.9" fill="currentColor" stroke="none"/>'; };
  var ICON = {
    cursor: svg('<path d="M6 3.5l12.5 7.3-5.6 1.5-2.6 5.4z"/>'),
    trend: svg('<path d="M5 18.5L19 5.5"/>' + DOT(5, 18.5) + DOT(19, 5.5)),
    ray: svg('<path d="M4.5 18L21 6.5"/>' + DOT(4.5, 18) + DOT(11, 13.5)),
    hline: svg('<path d="M3 12h18"/>' + DOT(12, 12) + '<path d="M3 7.5h3M3 16.5h3" opacity=".45"/>'),
    rect: svg('<rect x="4" y="6.5" width="16" height="11" rx="1.5" fill="currentColor" fill-opacity=".2"/>'),
    fib: svg('<path d="M4 5h16"/><path d="M4 9.5h16" opacity=".7"/><path d="M4 14.5h16" opacity=".7"/><path d="M4 19h16"/>'),
    measure: svg('<path d="M5 4h14M5 20h14"/><path d="M12 7v10M9 9.8L12 7l3 2.8M9 14.2L12 17l3-2.8"/>'),
    pen: svg('<path d="M4.5 19.5l1.1-4.3L16.2 4.6a1.6 1.6 0 012.2 0l1 1a1.6 1.6 0 010 2.2L8.8 18.4z"/><path d="M14.3 6.5l3.2 3.2"/>'),
    marker: svg('<path d="M14.5 4.5l5 5-7.2 7.2H7.3v-5z"/><path d="M7.3 16.7L5 19"/><path d="M4 20.5h9" stroke-width="3" opacity=".55"/>'),
    eraser: svg('<path d="M9 20h11"/><path d="M4.6 15.4l8.9-8.9a2 2 0 012.8 0l2.2 2.2a2 2 0 010 2.8L11 19H8.2z"/><path d="M9.2 10.8l4.9 4.9" opacity=".6"/>'),
    undo: svg('<path d="M9 14.5L4 9.5l5-5"/><path d="M4 9.5h10.5a5.5 5.5 0 010 11H11"/>'),
    redo: svg('<path d="M15 14.5l5-5-5-5"/><path d="M20 9.5H9.5a5.5 5.5 0 000 11H13"/>'),
    trash: svg('<path d="M4.5 7h15M10 11v6M14 11v6M6 7l.9 11.5A2 2 0 008.9 20.4h6.2a2 2 0 002-1.9L18 7M9.5 7V4.5h5V7"/>'),
    zoomIn: svg('<circle cx="10.5" cy="10.5" r="6"/><path d="M20 20l-5.2-5.2M8 10.5h5M10.5 8v5"/>'),
    zoomOut: svg('<circle cx="10.5" cy="10.5" r="6"/><path d="M20 20l-5.2-5.2M8 10.5h5"/>'),
    fit: svg('<path d="M4 9V5.5A1.5 1.5 0 015.5 4H9M15 4h3.5A1.5 1.5 0 0120 5.5V9M20 15v3.5a1.5 1.5 0 01-1.5 1.5H15M9 20H5.5A1.5 1.5 0 014 18.5V15"/><path d="M8 14.5l3-3 2 2 3-3.5"/>'),
    expand: svg('<path d="M4 9V4h5M20 9V4h-5M4 15v5h5M20 15v5h-5"/>'),
    collapse: svg('<path d="M9 4v5H4M15 4v5h5M9 20v-5H4M15 20v-5h5"/>'),
    share: svg('<rect x="3.5" y="5" width="17" height="14" rx="2.2"/><path d="M3.5 15.5l4.6-4.4 3.6 3.4 2.8-2.6 6 5.6"/><circle cx="15.8" cy="9" r="1.3"/>'),
    more: svg(DOT(5.5, 12) + DOT(12, 12) + DOT(18.5, 12)),
    studies: svg('<path d="M3 15.5c2.2 0 3-7 5.5-7s3 9 5.5 9 3-6 6.5-6"/><path d="M3 20.5h18" opacity=".4"/>'),
    candle: svg('<path d="M7.5 3.5v3.5M7.5 17v3.5M16.5 3v3M16.5 15v5.5"/><rect x="5.5" y="7" width="4" height="10" rx="1"/><rect x="14.5" y="6" width="4" height="9" rx="1" fill="currentColor" fill-opacity=".35"/>'),
    line: svg('<path d="M3.5 17l5-5.5 4 3L20.5 6"/>'),
    area: svg('<path d="M3.5 17l5-5.5 4 3L20.5 6"/><path d="M3.5 17l5-5.5 4 3L20.5 6V20h-17z" fill="currentColor" fill-opacity=".2" stroke="none"/>'),
    check: svg('<path d="M5 12.5l4.5 4.5L19 7.5"/>'),
    chev: '<svg viewBox="0 0 12 12" width="10" height="10" aria-hidden="true"><path d="M3 4.5l3 3 3-3" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>'
  };

  /* ── styles (unlayered so they sit above the bundled layers) ─────────────── */
  var CSS = [
    ".ilc-scope{--ilc-ink:#F1EDE4;--ilc-dim:rgba(241,237,228,.62);--ilc-faint:rgba(241,237,228,.38);--ilc-line:rgba(241,237,228,.09);--ilc-line2:rgba(241,237,228,.16);--ilc-panel:#121417;--ilc-hover:rgba(241,237,228,.065);--ilc-well:rgba(241,237,228,.035);--ilc-gold:#E2B65C;--ilc-gold-soft:rgba(226,182,92,.15);--ilc-gold-line:rgba(226,182,92,.38);--ilc-shadow:0 18px 44px rgba(0,0,0,.5),0 2px 8px rgba(0,0,0,.35);font-family:'Plus Jakarta Sans',-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif}",
    "html:not([data-theme='dark']) .ilc-scope{--ilc-ink:#17191D;--ilc-dim:rgba(23,25,29,.64);--ilc-faint:rgba(23,25,29,.42);--ilc-line:rgba(23,25,29,.10);--ilc-line2:rgba(23,25,29,.18);--ilc-panel:#FFFFFF;--ilc-hover:rgba(23,25,29,.055);--ilc-well:rgba(23,25,29,.03);--ilc-gold:#9C6C17;--ilc-gold-soft:rgba(156,108,23,.11);--ilc-gold-line:rgba(156,108,23,.34);--ilc-shadow:0 18px 44px rgba(30,24,12,.16),0 2px 8px rgba(30,24,12,.08)}",
    /* toolbar */
    ".ilc-bar{display:flex;flex-wrap:wrap;align-items:center;gap:8px 8px;padding:8px 2px 10px;min-width:0}",
    ".ilc-g{display:inline-flex;align-items:center;gap:2px;padding:3px;border-radius:11px;background:var(--ilc-well);border:1px solid var(--ilc-line);flex:0 0 auto}",
    ".ilc-g.ilc-plain{background:none;border-color:transparent;padding:3px 0}",
    ".ilc-spacer{flex:1 1 0;min-width:0}",
    ".ilc-b{appearance:none;-webkit-appearance:none;display:inline-flex;align-items:center;justify-content:center;gap:6px;height:28px;min-width:28px;padding:0 9px;border:0;border-radius:8px;background:transparent;color:var(--ilc-dim);font:600 12px/1 'Plus Jakarta Sans',-apple-system,sans-serif;letter-spacing:.01em;white-space:nowrap;cursor:pointer;transition:background .14s ease,color .14s ease,box-shadow .14s ease}",
    ".ilc-b.ilc-ico{padding:0;width:30px}",
    ".ilc-b:hover{background:var(--ilc-hover);color:var(--ilc-ink)}",
    ".ilc-b:focus-visible{outline:2px solid var(--ilc-gold);outline-offset:1px}",
    ".ilc-b.on{background:var(--ilc-gold-soft);color:var(--ilc-gold);box-shadow:inset 0 0 0 1px var(--ilc-gold-line)}",
    ".ilc-b[disabled]{opacity:.35;cursor:default;background:none}",
    ".ilc-b svg{flex:0 0 auto}",
    ".ilc-tf .ilc-b{padding:0 8px;min-width:32px;font-family:'IBM Plex Sans','Plus Jakarta Sans',sans-serif;font-weight:600}",
    ".ilc-count{display:inline-grid;place-items:center;min-width:17px;height:17px;padding:0 4px;border-radius:9px;background:var(--ilc-gold-soft);color:var(--ilc-gold);font:700 10px/1 'IBM Plex Sans',sans-serif}",
    ".ilc-b .ilc-chev{opacity:.6;margin-left:-2px}",
    /* popover menus */
    ".ilc-pop{position:fixed;z-index:2147483100;min-width:236px;max-width:min(320px,calc(100vw - 24px));max-height:min(70vh,560px);overflow:auto;padding:6px;border-radius:14px;background:var(--ilc-panel);border:1px solid var(--ilc-line2);box-shadow:var(--ilc-shadow);color:var(--ilc-ink)}",
    ".ilc-pop[hidden]{display:none}",
    ".ilc-pop h6{margin:8px 10px 4px;font:700 10.5px/1.2 'Plus Jakarta Sans',sans-serif;letter-spacing:.09em;text-transform:uppercase;color:var(--ilc-faint)}",
    ".ilc-mi{display:flex;align-items:center;gap:10px;width:100%;padding:8px 10px;border:0;border-radius:9px;background:none;color:var(--ilc-ink);font:500 13px/1.25 'Plus Jakarta Sans',sans-serif;text-align:left;cursor:pointer}",
    ".ilc-mi:hover,.ilc-mi:focus-visible{background:var(--ilc-hover);outline:none}",
    ".ilc-mi .ilc-key{width:14px;height:3px;border-radius:2px;flex:0 0 auto;background:var(--k,var(--ilc-dim))}",
    ".ilc-mi .ilc-mi-t{flex:1 1 auto;min-width:0}",
    ".ilc-mi .ilc-mi-t small{display:block;margin-top:2px;color:var(--ilc-faint);font-size:11.5px;font-weight:500}",
    ".ilc-mi .ilc-tick{width:18px;height:18px;border-radius:6px;display:grid;place-items:center;border:1px solid var(--ilc-line2);color:transparent;flex:0 0 auto}",
    ".ilc-mi.on .ilc-tick{background:var(--ilc-gold);border-color:var(--ilc-gold);color:var(--ilc-panel)}",
    ".ilc-mi .ilc-tick svg{width:13px;height:13px}",
    ".ilc-mi[disabled]{opacity:.42;cursor:default}",
    ".ilc-sep{height:1px;margin:6px 4px;background:var(--ilc-line)}",
    ".ilc-cmp{display:flex;gap:6px;padding:6px 6px 4px}",
    ".ilc-cmp input{flex:1 1 auto;min-width:0;height:32px;padding:0 10px;border-radius:9px;border:1px solid var(--ilc-line2);background:var(--ilc-well);color:var(--ilc-ink);font:600 13px 'IBM Plex Sans',sans-serif;text-transform:uppercase}",
    ".ilc-cmp button{height:32px;padding:0 12px;border-radius:9px;border:0;background:var(--ilc-gold);color:#17130A;font:700 12px 'Plus Jakarta Sans',sans-serif;cursor:pointer}",
    /* drawing rail */
    ".ilc-has-rail>.il-chart-host,.ilc-has-rail>.il-chart-host-expanded{left:46px!important;width:auto!important;right:0}",
    ".ilc-rail{position:absolute;left:0;top:0;bottom:0;width:38px;display:flex;flex-direction:column;flex-wrap:wrap;align-content:flex-start;gap:2px;padding:4px;border-radius:12px;background:var(--ilc-well);border:1px solid var(--ilc-line);z-index:4;box-sizing:content-box}",
    ".ilc-rail .ilc-b{width:30px;height:30px;padding:0}",
    ".ilc-rail .ilc-rsep{width:22px;height:1px;margin:4px;background:var(--ilc-line2)}",
    ".ilc-rail .ilc-toolpick{display:none}",
    "@media (max-width:760px),(pointer:coarse){.ilc-rail .ilc-toolpick{display:inline-flex}.ilc-rail [data-tool]{display:none}.ilc-rail{flex-wrap:nowrap}.ilc-rail .ilc-b{width:32px;height:32px;min-height:0!important;min-width:0!important}}",
    ".ilc-swatch{width:14px;height:14px;border-radius:50%;background:var(--sw);box-shadow:0 0 0 2px var(--ilc-panel),0 0 0 3px var(--ilc-line2)}",
    ".ilc-colors{display:grid;grid-template-columns:repeat(6,28px);gap:6px;padding:8px}",
    ".ilc-colors button{width:28px;height:28px;border-radius:50%;border:0;background:var(--sw);cursor:pointer;box-shadow:inset 0 0 0 1px rgba(0,0,0,.18)}",
    ".ilc-colors button.on{box-shadow:0 0 0 2px var(--ilc-panel),0 0 0 4px var(--ilc-gold)}",
    ".ilc-layer{position:absolute;left:0;top:0;z-index:3;touch-action:none;cursor:crosshair;pointer-events:none}",
    ".ilc-layer.on{pointer-events:auto}",
    ".ilc-layer.ilc-erase{cursor:cell}",
    /* hints and loading pill */
    ".ilc-hint,.ilc-loading{position:absolute;left:50%;top:14px;transform:translate(-50%,-6px);z-index:6;padding:7px 12px;border-radius:999px;background:var(--ilc-panel);border:1px solid var(--ilc-line2);box-shadow:var(--ilc-shadow);color:var(--ilc-ink);font:600 12px/1 'Plus Jakarta Sans',sans-serif;white-space:nowrap;opacity:0;pointer-events:none;transition:opacity .18s ease,transform .18s ease}",
    ".ilc-hint.on,.ilc-loading.on{opacity:1;transform:translate(-50%,0)}",
    ".ilc-loading span{display:inline-block;width:10px;height:10px;margin-right:8px;vertical-align:-1px;border-radius:50%;border:2px solid var(--ilc-gold-line);border-top-color:var(--ilc-gold);animation:ilc-spin .8s linear infinite}",
    "@keyframes ilc-spin{to{transform:rotate(360deg)}}",
    ".il-chart-slot.ilc-has-rail .ilc-hint,.il-chart-slot.ilc-has-rail .ilc-loading,.ilc-has-rail>.ilc-hint,.ilc-has-rail>.ilc-loading{left:calc(50% + 23px)}",
    /* legend on the readout strip */
    ".il-chart-readout{flex-wrap:wrap;row-gap:4px}",
    ".il-chart-readout .ilr-sym{order:0}.il-chart-readout .ilr-date{order:1;margin-left:auto}",
    ".il-chart-readout::before{content:'';order:2;flex-basis:100%;height:0}",
    ".il-chart-readout .ilr-main{order:3}.il-chart-readout .ilr-ohlc{order:4}",
    "#chart-expand-modal .il-chart-readout::before{display:none}#chart-expand-modal .il-chart-readout .ilr-date{order:5}",
    ".il-chart-readout .ilr-sym{display:flex;align-items:baseline;gap:8px;min-width:0;max-width:100%;flex:0 1 auto;margin-right:14px}",
    ".il-chart-readout .ilr-tk{font:700 13px/1 'IBM Plex Sans',sans-serif;letter-spacing:.04em;color:var(--ilc-gold,#E2B65C);padding:4px 7px;border-radius:6px;background:rgba(226,182,92,.13);box-shadow:inset 0 0 0 1px rgba(226,182,92,.3)}",
    "html:not([data-theme='dark']) .il-chart-readout .ilr-tk{color:#8A5E12;background:rgba(156,108,23,.10);box-shadow:inset 0 0 0 1px rgba(156,108,23,.28)}",
    ".il-chart-readout .ilr-nm{font:600 14px/1.2 'Plus Jakarta Sans',sans-serif;color:inherit;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;min-width:0}",
    ".il-chart-readout .ilr-meta{font:500 12px/1.2 'Plus Jakarta Sans',sans-serif;opacity:.6;white-space:nowrap}",
    ".il-chart-readout .ilr-tk:empty,.il-chart-readout .ilr-nm:empty,.il-chart-readout .ilr-meta:empty{display:none}",
    /* the stage that holds the full-screen chart */
    ".il-chart-stage{position:relative;flex:1 1 auto;min-height:320px;width:100%}",
    ".il-chart-stage>.il-chart-host-expanded{position:absolute!important;inset:0;height:auto!important;min-height:0!important;width:auto!important}",
    "#il-chart-dock.ilc-on>#app-chart-toolbar,#il-chart-dock.ilc-on>#app-tf-strip{display:none!important}",
    "#chart-expand-modal.il-lwc .il-cex-controls{display:none!important}",
    "#chart-expand-modal.il-lwc .ilc-bar{padding:8px 16px;border-bottom:1px solid var(--ilc-line);flex:0 0 auto}",
    "#chart-expand-modal.il-lwc .cex-hint,#chart-expand-modal.il-lwc .cex-icon-btn,#chart-expand-modal.il-lwc .cex-controls .cex-btn[onclick^='resetExpandZoom']{display:none!important}",
    "#chart-expand-modal.il-lwc .cex-share{display:none!important}",
    "#chart-expand-modal .il-chart-readout .ilr-sym{display:none}",
    "#cex-title{display:flex;align-items:baseline;gap:10px;min-width:0;overflow:hidden}",
    "#cex-title .ilc-title-tk{font:700 13px/1 'IBM Plex Sans',sans-serif;letter-spacing:.04em;color:#E2B65C;padding:5px 8px;border-radius:7px;background:rgba(226,182,92,.13);box-shadow:inset 0 0 0 1px rgba(226,182,92,.3);align-self:center}",
    "html:not([data-theme='dark']) #cex-title .ilc-title-tk{color:#8A5E12;background:rgba(156,108,23,.10)}",
    "#cex-title .ilc-title-nm{font:700 17px/1.2 'Plus Jakarta Sans',sans-serif;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;min-width:0}",
    "#cex-title .ilc-title-meta{font:500 12.5px/1.2 'Plus Jakarta Sans',sans-serif;opacity:.58;white-space:nowrap}",
    "@media (max-width:760px){.ilc-bar{gap:6px}.ilc-b{height:30px}.ilc-tf .ilc-b{min-width:30px;padding:0 6px}.ilc-b .ilc-lbl{display:none}#cex-title .ilc-title-meta{display:none}.il-chart-readout .ilr-meta{display:none}#chart-expand-modal.il-lwc .ilc-bar{padding:8px 10px}}",
    "@media (max-width:420px){.ilc-tf .ilc-b{min-width:28px;padding:0 4px;font-size:11.5px}.ilc-rail{width:34px}.ilc-rail .ilc-b{width:28px;height:28px}.ilc-has-rail>.il-chart-host,.ilc-has-rail>.il-chart-host-expanded{left:42px!important}}"
  ].join("\n");
  function injectCss() {
    if (document.getElementById("ilc-style")) return;
    var st = document.createElement("style");
    st.id = "ilc-style";
    st.textContent = CSS;
    (document.head || document.documentElement).appendChild(st);
  }

  function isDark() { return document.documentElement.getAttribute("data-theme") === "dark"; }
  function toast(msg, kind) { if (typeof window.toast === "function") window.toast(msg, kind || "ok"); }
  function E() { return window.ILChartEngine; }

  /* ════════════════════════════════════════════════════════════════════════
     DRAWINGS
     ════════════════════════════════════════════════════════════════════════ */
  var COLORS = {
    gold:   { d: "#E2B65C", l: "#A6741F", n: "Gold" },
    green:  { d: "#34D48C", l: "#0B8A55", n: "Green" },
    red:    { d: "#F0606E", l: "#C23447", n: "Red" },
    blue:   { d: "#72A9F2", l: "#2F6FC4", n: "Blue" },
    violet: { d: "#B790F0", l: "#7446B8", n: "Violet" },
    ink:    { d: "#EDE9DF", l: "#1A1C20", n: "White / ink" }
  };
  function col(k) { var c = COLORS[k] || COLORS.gold; return isDark() ? c.d : c.l; }
  function rgba(hex, a) {
    var m = /^#?([0-9a-f]{6})$/i.exec(hex || "");
    if (!m) return hex;
    var n = parseInt(m[1], 16);
    return "rgba(" + (n >> 16 & 255) + "," + (n >> 8 & 255) + "," + (n & 255) + "," + a + ")";
  }

  var TOOLS = [
    { k: "cursor", n: "Cursor — pan and zoom", key: "Esc" },
    { k: "trend", n: "Trend line", key: "T" },
    { k: "ray", n: "Ray — trend line extended right", key: "R" },
    { k: "hline", n: "Horizontal level", key: "H" },
    { k: "rect", n: "Highlight zone", key: "Z" },
    { k: "fib", n: "Fibonacci retracement", key: "F" },
    { k: "measure", n: "Measure — price change, % and bars", key: "M" },
    { k: "pen", n: "Pen", key: "P" },
    { k: "marker", n: "Highlighter", key: "L" },
    { k: "eraser", n: "Eraser — click a drawing to remove it", key: "E" }
  ];
  var TWO_POINT = { trend: 1, ray: 1, rect: 1, fib: 1, measure: 1 };
  var STICKY = { pen: 1, marker: 1, eraser: 1 };
  var FIB = [0, 0.236, 0.382, 0.5, 0.618, 0.786, 1];

  var D = {
    tool: "cursor", color: "gold", ticker: null,
    items: [], undo: [], redo: [], draft: null, measure: null, hover: null
  };
  try { var savedColor = localStorage.getItem("il-draw-color"); if (COLORS[savedColor]) D.color = savedColor; } catch (e) {}

  var live = [];   // { inst, prim, layer, rail, stage }

  function storeKey(t) { return "il-draw:v1:" + t; }
  function loadFor(ticker) {
    if (D.ticker === ticker) return;
    D.ticker = ticker; D.items = []; D.undo = []; D.redo = []; D.draft = null; D.measure = null;
    if (!ticker) return;
    try {
      var raw = JSON.parse(localStorage.getItem(storeKey(ticker)) || "[]");
      if (Array.isArray(raw)) D.items = raw.filter(function (it) { return it && it.type && Array.isArray(it.pts); });
    } catch (e) {}
  }
  function save() {
    if (!D.ticker) return;
    try {
      if (D.items.length) localStorage.setItem(storeKey(D.ticker), JSON.stringify(D.items));
      else localStorage.removeItem(storeKey(D.ticker));
    } catch (e) {}
  }
  function snapshot() { return JSON.stringify(D.items); }
  function mutate(fn) {
    D.undo.push(snapshot());
    if (D.undo.length > 80) D.undo.shift();
    D.redo = [];
    fn();
    save();
    refresh();
  }
  function undo() {
    if (!D.undo.length) return;
    D.redo.push(snapshot());
    D.items = JSON.parse(D.undo.pop());
    save(); refresh();
  }
  function redo() {
    if (!D.redo.length) return;
    D.undo.push(snapshot());
    D.items = JSON.parse(D.redo.pop());
    save(); refresh();
  }
  function clearAll() {
    if (!D.items.length) return;
    mutate(function () { D.items = []; });
    toast("Drawings cleared. Undo brings them back.");
  }
  function uid() { return Date.now().toString(36) + Math.random().toString(36).slice(2, 6); }

  function refresh() {
    live.forEach(function (rec) { if (rec.prim) rec.prim.update(); });
    syncRails();
  }

  /* ── time ↔ logical index ────────────────────────────────────────────── */
  function medianStep(rows, fromEnd) {
    var gaps = [], n = rows.length;
    for (var i = 1; i < Math.min(n, 24); i++) {
      var a = fromEnd ? n - i - 1 : i - 1, b = a + 1;
      if (a >= 0 && b < n) gaps.push(rows[b].time - rows[a].time);
    }
    gaps.sort(function (x, y) { return x - y; });
    return gaps[gaps.length >> 1] || 86400;
  }
  function tToL(rows, t) {
    var n = rows.length;
    if (!n) return null;
    if (t <= rows[0].time) return (t - rows[0].time) / medianStep(rows, false);
    if (t >= rows[n - 1].time) return n - 1 + (t - rows[n - 1].time) / medianStep(rows, true);
    var lo = 0, hi = n - 1;
    while (hi - lo > 1) { var mid = (lo + hi) >> 1; if (rows[mid].time <= t) lo = mid; else hi = mid; }
    var span = rows[hi].time - rows[lo].time;
    return lo + (span ? (t - rows[lo].time) / span : 0);
  }
  function lToT(rows, l) {
    var n = rows.length;
    if (!n) return 0;
    if (l <= 0) return Math.round(rows[0].time + l * medianStep(rows, false));
    if (l >= n - 1) return Math.round(rows[n - 1].time + (l - (n - 1)) * medianStep(rows, true));
    var i = Math.floor(l), f = l - i;
    return Math.round(rows[i].time + f * (rows[i + 1].time - rows[i].time));
  }
  function toPx(rec, pt) {
    var inst = rec.inst;
    var l = tToL(inst.rows, pt.t);
    var x = l == null ? null : inst.chart.timeScale().logicalToCoordinate(l);
    var y = inst.series.price.priceToCoordinate(pt.p);
    return (x == null || y == null) ? null : { x: x, y: y };
  }
  function fromPx(rec, x, y) {
    var inst = rec.inst;
    var l = inst.chart.timeScale().coordinateToLogical(x);
    var p = inst.series.price.coordinateToPrice(y);
    if (l == null || p == null) return null;
    return { t: lToT(inst.rows, l), p: p };
  }

  /* ── painting ─────────────────────────────────────────────────────────── */
  function fmtP(v) {
    var a = Math.abs(v);
    return (a >= 1000 ? v.toFixed(0) : a >= 1 ? v.toFixed(2) : v.toFixed(4));
  }
  function inkColor() { return isDark() ? "#F1EDE4" : "#17191D"; }
  function panelColor() { return isDark() ? "rgba(18,20,23,.92)" : "rgba(255,255,255,.94)"; }

  function pill(ctx, x, y, lines, color, align) {
    ctx.font = "600 11.5px 'IBM Plex Sans', 'Plus Jakarta Sans', sans-serif";
    var w = 0;
    lines.forEach(function (s) { w = Math.max(w, ctx.measureText(s).width); });
    var pad = 8, lh = 15, h = lines.length * lh + 8;
    w += pad * 2;
    var bx = align === "center" ? x - w / 2 : x;
    var by = y - h / 2;
    ctx.save();
    ctx.fillStyle = panelColor();
    ctx.strokeStyle = rgba(color, .55);
    ctx.lineWidth = 1;
    ctx.beginPath();
    if (ctx.roundRect) ctx.roundRect(bx, by, w, h, 7); else ctx.rect(bx, by, w, h);
    ctx.fill(); ctx.stroke();
    ctx.fillStyle = inkColor();
    ctx.textBaseline = "middle";
    lines.forEach(function (s, i) { ctx.fillText(s, bx + pad, by + 4 + lh * i + lh / 2); });
    ctx.restore();
  }

  function paintItem(rec, ctx, size, it, opts) {
    opts = opts || {};
    var c = col(it.color);
    var pts = it.pts.map(function (p) { return toPx(rec, p); });
    if (pts.some(function (p) { return !p; })) return;
    var hot = opts.hot;
    ctx.save();
    ctx.lineCap = "round"; ctx.lineJoin = "round";
    if (hot) { ctx.shadowColor = rgba(col("red"), .9); ctx.shadowBlur = 10; }
    var a = pts[0], b = pts[1] || pts[0];
    switch (it.type) {
      case "trend":
      case "ray": {
        var x2 = b.x, y2 = b.y;
        if (it.type === "ray" && (b.x !== a.x || b.y !== a.y)) {
          var dx = b.x - a.x, dy = b.y - a.y;
          var k = dx > 0 ? (size.width + 50 - a.x) / dx : dx < 0 ? (-50 - a.x) / dx : 0;
          if (dx === 0) { y2 = dy > 0 ? size.height + 50 : -50; }
          else { x2 = a.x + dx * Math.max(1, k); y2 = a.y + dy * Math.max(1, k); }
        }
        ctx.strokeStyle = c; ctx.lineWidth = 2;
        ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(x2, y2); ctx.stroke();
        if (opts.draft || hot) {
          [a, b].forEach(function (p) {
            ctx.beginPath(); ctx.arc(p.x, p.y, 4, 0, Math.PI * 2);
            ctx.fillStyle = panelColor(); ctx.fill(); ctx.lineWidth = 1.5; ctx.stroke();
          });
        }
        break;
      }
      case "hline": {
        ctx.strokeStyle = c; ctx.lineWidth = 1.5;
        ctx.beginPath(); ctx.moveTo(0, a.y); ctx.lineTo(size.width, a.y); ctx.stroke();
        break;
      }
      case "rect": {
        var x = Math.min(a.x, b.x), y = Math.min(a.y, b.y), w = Math.abs(b.x - a.x), h = Math.abs(b.y - a.y);
        ctx.fillStyle = rgba(c, isDark() ? .14 : .12);
        ctx.fillRect(x, y, w, h);
        ctx.strokeStyle = rgba(c, .7); ctx.lineWidth = 1;
        ctx.strokeRect(x + .5, y + .5, w, h);
        break;
      }
      case "fib": {
        var pA = it.pts[0].p, pB = (it.pts[1] || it.pts[0]).p;
        var left = Math.min(a.x, b.x), right = Math.max(a.x, b.x);
        if (right - left < 40) right = left + 40;
        var ys = FIB.map(function (lv) { return rec.inst.series.price.priceToCoordinate(pB - (pB - pA) * lv); });
        for (var i = 0; i < FIB.length - 1; i++) {
          if (ys[i] == null || ys[i + 1] == null) continue;
          ctx.fillStyle = rgba(c, i % 2 ? .05 : .09);
          ctx.fillRect(left, Math.min(ys[i], ys[i + 1]), right - left, Math.abs(ys[i + 1] - ys[i]));
        }
        ctx.font = "600 11px 'IBM Plex Sans', sans-serif";
        ctx.textBaseline = "bottom";
        FIB.forEach(function (lv, j) {
          var yy = ys[j];
          if (yy == null) return;
          ctx.strokeStyle = rgba(c, lv === 0 || lv === 1 ? .95 : lv === 0.5 || lv === 0.618 ? .8 : .55);
          ctx.lineWidth = lv === 0.618 ? 1.6 : 1;
          ctx.beginPath(); ctx.moveTo(left, yy); ctx.lineTo(right, yy); ctx.stroke();
          ctx.fillStyle = rgba(c, .95);
          ctx.fillText((lv * 100).toFixed(lv === 0 || lv === 1 || lv === 0.5 ? 0 : 1) + "%  " + fmtP(pB - (pB - pA) * lv), left + 4, yy - 2);
        });
        ctx.setLineDash([3, 4]);
        ctx.strokeStyle = rgba(c, .5);
        ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke();
        break;
      }
      case "measure": {
        var up = it.pts[1].p >= it.pts[0].p;
        var mc = col(up ? "green" : "red");
        var mx = Math.min(a.x, b.x), my = Math.min(a.y, b.y), mw = Math.abs(b.x - a.x), mh = Math.abs(b.y - a.y);
        ctx.fillStyle = rgba(mc, .12);
        ctx.fillRect(mx, my, mw, mh);
        ctx.strokeStyle = rgba(mc, .85); ctx.lineWidth = 1.5;
        var cx = mx + mw / 2;
        ctx.beginPath(); ctx.moveTo(cx, a.y); ctx.lineTo(cx, b.y); ctx.stroke();
        var dir = b.y < a.y ? 1 : -1;
        ctx.beginPath(); ctx.moveTo(cx - 5, b.y + 6 * dir); ctx.lineTo(cx, b.y); ctx.lineTo(cx + 5, b.y + 6 * dir); ctx.stroke();
        var d = it.pts[1].p - it.pts[0].p;
        var pct = it.pts[0].p ? d / it.pts[0].p * 100 : 0;
        var bars = Math.round(Math.abs(tToL(rec.inst.rows, it.pts[1].t) - tToL(rec.inst.rows, it.pts[0].t)));
        var secs = Math.abs(it.pts[1].t - it.pts[0].t);
        var span = secs >= 86400 * 1.5 ? Math.round(secs / 86400) + " days" : secs >= 3600 ? (secs / 3600).toFixed(1) + " hours" : Math.round(secs / 60) + " min";
        pill(ctx, cx, b.y + (dir > 0 ? -22 : 22),
          [(d >= 0 ? "+" : "−") + "$" + fmtP(Math.abs(d)) + "  (" + (d >= 0 ? "+" : "−") + Math.abs(pct).toFixed(2) + "%)",
           bars + " bars · " + span], mc, "center");
        break;
      }
      case "pen":
      case "marker": {
        var marker = it.type === "marker";
        ctx.strokeStyle = marker ? rgba(c, isDark() ? .32 : .36) : c;
        ctx.lineWidth = marker ? 14 : 2;
        ctx.beginPath();
        pts.forEach(function (p, i) { if (i) ctx.lineTo(p.x, p.y); else ctx.moveTo(p.x, p.y); });
        if (pts.length === 1) ctx.lineTo(pts[0].x + 0.1, pts[0].y);
        ctx.stroke();
        break;
      }
    }
    ctx.restore();
  }

  function paintAll(rec, ctx, size) {
    D.items.forEach(function (it) { paintItem(rec, ctx, size, it, { hot: D.tool === "eraser" && D.hover === it.id }); });
    if (D.draft && D.draft.owner === rec) paintItem(rec, ctx, size, D.draft, { draft: true });
    if (D.measure && D.measure.owner === rec) paintItem(rec, ctx, size, D.measure, { draft: true });
    syncLayer(rec);
  }

  function makePrimitive(rec) {
    var requestUpdate = null;
    var renderer = {
      draw: function (target) {
        target.useMediaCoordinateSpace(function (scope) {
          try { paintAll(rec, scope.context, scope.mediaSize); } catch (e) {}
        });
      }
    };
    var paneView = { zOrder: function () { return "top"; }, renderer: function () { return renderer; } };
    function axisViews() {
      var out = [];
      var list = D.items.slice();
      if (D.draft && D.draft.owner === rec && D.draft.type === "hline") list.push(D.draft);
      list.forEach(function (it) {
        if (it.type !== "hline") return;
        var y = rec.inst.series.price.priceToCoordinate(it.pts[0].p);
        if (y == null) return;
        var c = col(it.color);
        out.push({
          coordinate: function () { return y; },
          text: function () { return fmtP(it.pts[0].p); },
          textColor: function () { return it.color === "ink" && !isDark() ? "#FFFFFF" : "#101114"; },
          backColor: function () { return c; },
          visible: function () { return true; },
          tickVisible: function () { return true; }
        });
      });
      return out;
    }
    return {
      attached: function (p) { requestUpdate = p.requestUpdate; },
      detached: function () { requestUpdate = null; },
      updateAllViews: function () {},
      paneViews: function () { return [paneView]; },
      priceAxisViews: axisViews,
      update: function () { if (requestUpdate) requestUpdate(); }
    };
  }

  /* The pointer layer covers exactly the price pane's plot area. */
  function syncLayer(rec) {
    try {
      var w = rec.inst.chart.timeScale().width();
      var h = rec.inst.chart.panes()[0].getHeight();
      if (w !== rec.lw || h !== rec.lh) {
        rec.lw = w; rec.lh = h;
        rec.layer.style.width = w + "px";
        rec.layer.style.height = h + "px";
      }
    } catch (e) {}
  }

  /* ── hit testing (pixels) ─────────────────────────────────────────────── */
  function distSeg(px, py, a, b) {
    var dx = b.x - a.x, dy = b.y - a.y, L = dx * dx + dy * dy;
    var t = L ? Math.max(0, Math.min(1, ((px - a.x) * dx + (py - a.y) * dy) / L)) : 0;
    var x = a.x + t * dx, y = a.y + t * dy;
    return Math.hypot(px - x, py - y);
  }
  function hitTest(rec, x, y) {
    var best = null, bestD = 9;
    var w = rec.lw || 2000;
    D.items.forEach(function (it) {
      var pts = it.pts.map(function (p) { return toPx(rec, p); });
      if (pts.some(function (p) { return !p; })) return;
      var a = pts[0], b = pts[1] || pts[0], d = Infinity;
      if (it.type === "hline") d = Math.abs(y - a.y);
      else if (it.type === "trend") d = distSeg(x, y, a, b);
      else if (it.type === "ray") {
        var dx = b.x - a.x, dy = b.y - a.y, k = dx ? Math.max(1, (w + 50 - a.x) / dx) : 1;
        d = distSeg(x, y, a, dx > 0 ? { x: a.x + dx * k, y: a.y + dy * k } : b);
      } else if (it.type === "rect" || it.type === "fib") {
        var l = Math.min(a.x, b.x), r = Math.max(a.x, b.x, l + (it.type === "fib" ? 40 : 0));
        var t = Math.min(a.y, b.y), bo = Math.max(a.y, b.y);
        if (x >= l - 4 && x <= r + 4 && y >= t - 4 && y <= bo + 4) d = 0;
      } else if (it.type === "pen" || it.type === "marker") {
        for (var i = 1; i < pts.length; i++) d = Math.min(d, distSeg(x, y, pts[i - 1], pts[i]));
        if (pts.length === 1) d = Math.hypot(x - a.x, y - a.y);
        if (it.type === "marker") d -= 6;
      }
      if (d < bestD) { bestD = d; best = it; }
    });
    return best;
  }

  /* ── pointer interaction ──────────────────────────────────────────────── */
  function localXY(rec, e) {
    var r = rec.layer.getBoundingClientRect();
    return { x: e.clientX - r.left, y: e.clientY - r.top };
  }
  function syncCrosshair(rec, pt) {
    try {
      var rows = rec.inst.rows;
      var i = Math.max(0, Math.min(rows.length - 1, Math.round(tToL(rows, pt.t))));
      rec.inst.chart.setCrosshairPosition(pt.p, rows[i].time, rec.inst.series.price);
      if (rec.inst.paintReadout) rec.inst.paintReadout(rows[i]);
    } catch (e) {}
  }
  function finishDraft(rec) {
    var d = D.draft;
    D.draft = null;
    if (!d) return;
    if (d.type === "measure") {
      d.owner = rec;
      D.measure = d;
      refresh();
    } else {
      delete d.owner; delete d.awaiting; delete d.start;
      mutate(function () { D.items.push(d); });
    }
    if (!STICKY[D.tool]) setTool("cursor");
  }

  function wireLayer(rec) {
    var layer = rec.layer, down = false;
    layer.addEventListener("pointerdown", function (e) {
      if (D.tool === "cursor" || e.button > 0) return;
      e.preventDefault();
      try { layer.setPointerCapture(e.pointerId); } catch (_) {}
      var xy = localXY(rec, e), pt = fromPx(rec, xy.x, xy.y);
      if (!pt) return;
      down = true;
      D.measure = null;
      var tool = D.tool;
      if (tool === "eraser") {
        var hit = hitTest(rec, xy.x, xy.y);
        if (hit) mutate(function () { D.items = D.items.filter(function (it) { return it !== hit; }); });
        return;
      }
      if (tool === "hline") {
        mutate(function () { D.items.push({ id: uid(), type: "hline", color: D.color, pts: [pt] }); });
        setTool("cursor");
        down = false;
        return;
      }
      if (TWO_POINT[tool]) {
        if (D.draft && D.draft.awaiting && D.draft.owner === rec) {
          D.draft.pts[1] = pt;
          finishDraft(rec);
          down = false;
          return;
        }
        D.draft = { id: uid(), type: tool, color: D.color, pts: [pt, pt], owner: rec, start: xy };
        refresh();
        return;
      }
      if (tool === "pen" || tool === "marker") {
        D.draft = { id: uid(), type: tool, color: D.color, pts: [pt], owner: rec, last: xy };
        refresh();
      }
    });
    layer.addEventListener("pointermove", function (e) {
      if (D.tool === "cursor") return;
      var xy = localXY(rec, e), pt = fromPx(rec, xy.x, xy.y);
      if (!pt) return;
      syncCrosshair(rec, pt);
      if (D.tool === "eraser") {
        var hit = hitTest(rec, xy.x, xy.y);
        var id = hit ? hit.id : null;
        if (down && hit) { mutate(function () { D.items = D.items.filter(function (it) { return it !== hit; }); }); return; }
        if (id !== D.hover) { D.hover = id; refresh(); }
        return;
      }
      var d = D.draft;
      if (!d || d.owner !== rec) return;
      if (TWO_POINT[d.type]) { d.pts[1] = pt; rec.prim.update(); return; }
      if ((d.type === "pen" || d.type === "marker") && down) {
        if (Math.hypot(xy.x - d.last.x, xy.y - d.last.y) >= 2.5) { d.pts.push(pt); d.last = xy; rec.prim.update(); }
      }
    });
    function up(e) {
      if (!down) return;
      down = false;
      var d = D.draft;
      if (!d || d.owner !== rec) return;
      if (TWO_POINT[d.type]) {
        var xy = localXY(rec, e);
        if (Math.hypot(xy.x - d.start.x, xy.y - d.start.y) < 5) { d.awaiting = true; return; }   // click, click
        finishDraft(rec);
        return;
      }
      if (d.type === "pen" || d.type === "marker") {
        D.draft = null;
        delete d.owner; delete d.last;
        if (d.pts.length >= 1) mutate(function () { D.items.push(d); });
      }
    }
    layer.addEventListener("pointerup", up);
    layer.addEventListener("pointercancel", up);
    layer.addEventListener("pointerleave", function () { if (D.hover) { D.hover = null; refresh(); } });
    /* Zoom still works while a drawing tool is armed. */
    layer.addEventListener("wheel", function (e) {
      if (D.tool === "cursor") return;
      e.preventDefault();
      if (E()) E().zoom(rec.inst, e.deltaY > 0 ? 0.88 : 1.14);
    }, { passive: false });
  }

  function setTool(k) {
    if (!TOOLS.some(function (t) { return t.k === k; })) return;
    if (D.draft && k !== D.tool) D.draft = null;
    D.tool = k;
    D.hover = null;
    live.forEach(function (rec) {
      rec.layer.classList.toggle("on", k !== "cursor");
      rec.layer.classList.toggle("ilc-erase", k === "eraser");
    });
    refresh();
  }
  function setColor(k) {
    if (!COLORS[k]) return;
    D.color = k;
    try { localStorage.setItem("il-draw-color", k); } catch (e) {}
    syncRails();
  }

  /* ── rail ─────────────────────────────────────────────────────────────── */
  function buildRail() {
    var rail = document.createElement("div");
    rail.className = "ilc-rail ilc-scope";
    rail.setAttribute("role", "toolbar");
    rail.setAttribute("aria-label", "Drawing tools");
    rail.setAttribute("aria-orientation", "vertical");
    var html = '<button type="button" class="ilc-b ilc-ico ilc-toolpick" data-act="tools" title="Drawing tools" aria-label="Drawing tools" aria-haspopup="true">' + ICON.cursor + "</button>";
    html += TOOLS.map(function (t) {
      return '<button type="button" class="ilc-b ilc-ico" data-tool="' + t.k + '" title="' + t.n + " (" + t.key + ')" aria-label="' + t.n + '">' + ICON[t.k] + "</button>";
    }).join("");
    html += '<span class="ilc-rsep" aria-hidden="true"></span>' +
      '<button type="button" class="ilc-b ilc-ico" data-act="color" title="Drawing colour" aria-label="Drawing colour" aria-haspopup="true"><span class="ilc-swatch"></span></button>' +
      '<button type="button" class="ilc-b ilc-ico" data-act="undo" title="Undo (Ctrl+Z)" aria-label="Undo drawing">' + ICON.undo + "</button>" +
      '<button type="button" class="ilc-b ilc-ico" data-act="redo" title="Redo (Ctrl+Shift+Z)" aria-label="Redo drawing">' + ICON.redo + "</button>" +
      '<button type="button" class="ilc-b ilc-ico" data-act="clear" title="Clear all drawings on this ticker" aria-label="Clear all drawings">' + ICON.trash + "</button>";
    rail.innerHTML = html;
    rail.addEventListener("click", function (e) {
      var b = e.target.closest("button");
      if (!b) return;
      var t = b.getAttribute("data-tool");
      if (t) { setTool(D.tool === t && t !== "cursor" ? "cursor" : t); return; }
      var a = b.getAttribute("data-act");
      if (a === "undo") undo();
      else if (a === "redo") redo();
      else if (a === "clear") clearAll();
      else if (a === "color") openColors(b);
      else if (a === "tools") openToolPicker(b);
    });
    return rail;
  }
  function syncRails() {
    live.forEach(function (rec) {
      if (!rec.rail) return;
      rec.rail.querySelectorAll("[data-tool]").forEach(function (b) {
        var on = b.getAttribute("data-tool") === D.tool;
        b.classList.toggle("on", on);
        b.setAttribute("aria-pressed", String(on));
      });
      var pick = rec.rail.querySelector(".ilc-toolpick");
      if (pick) {
        pick.innerHTML = ICON[D.tool] || ICON.cursor;
        pick.classList.toggle("on", D.tool !== "cursor");
      }
      var sw = rec.rail.querySelector(".ilc-swatch");
      if (sw) sw.style.setProperty("--sw", col(D.color));
      var u = rec.rail.querySelector('[data-act="undo"]'), r = rec.rail.querySelector('[data-act="redo"]'), c = rec.rail.querySelector('[data-act="clear"]');
      if (u) u.disabled = !D.undo.length;
      if (r) r.disabled = !D.redo.length;
      if (c) c.disabled = !D.items.length;
    });
  }

  /* ════════════════════════════════════════════════════════════════════════
     POPOVERS
     ════════════════════════════════════════════════════════════════════════ */
  var pop = null, popAnchor = null;
  function closePop() {
    if (pop) { pop.remove(); pop = null; }
    if (popAnchor) { popAnchor.setAttribute("aria-expanded", "false"); popAnchor = null; }
  }
  function openPop(anchor, html, onClick, side) {
    if (popAnchor === anchor) { closePop(); return null; }
    closePop();
    pop = document.createElement("div");
    pop.className = "ilc-pop ilc-scope";
    pop.setAttribute("role", "menu");
    pop.innerHTML = html;
    document.body.appendChild(pop);
    popAnchor = anchor;
    anchor.setAttribute("aria-expanded", "true");
    var r = anchor.getBoundingClientRect(), pw = pop.offsetWidth, ph = pop.offsetHeight;
    var vw = window.innerWidth, vh = window.innerHeight;
    var left, top;
    if (side === "right") { left = r.right + 8; top = r.top; }
    else { left = r.left; top = r.bottom + 6; }
    if (left + pw > vw - 12) left = Math.max(12, (side === "right" ? r.left - pw - 8 : r.right - pw));
    if (top + ph > vh - 12) top = Math.max(12, vh - ph - 12);
    pop.style.left = left + "px";
    pop.style.top = top + "px";
    pop.addEventListener("click", function (e) { onClick(e); });
    var first = pop.querySelector("button,input");
    if (first && first.tagName === "INPUT") first.focus();
    return pop;
  }
  document.addEventListener("pointerdown", function (e) {
    if (!pop) return;
    if (pop.contains(e.target) || (popAnchor && popAnchor.contains(e.target))) return;
    closePop();
  }, true);
  window.addEventListener("resize", closePop);
  document.addEventListener("scroll", function (e) { if (pop && !pop.contains(e.target)) closePop(); }, true);

  /* Phones: one button opens the full tool list instead of a tall rail. */
  function openToolPicker(anchor) {
    var html = "<h6>Draw</h6>" + TOOLS.map(function (t) {
      return '<button type="button" class="ilc-mi' + (t.k === D.tool ? " on" : "") + '" data-pick="' + t.k + '"><span style="display:inline-flex;color:var(--ilc-gold)">' + ICON[t.k] + '</span><span class="ilc-mi-t">' + t.n.split(" — ")[0] + "</span></button>";
    }).join("");
    openPop(anchor, html, function (e) {
      var b = e.target.closest("[data-pick]");
      if (!b) return;
      setTool(b.getAttribute("data-pick"));
      closePop();
    }, "right");
  }

  function openColors(anchor) {
    var html = '<h6>Drawing colour</h6><div class="ilc-colors">' + Object.keys(COLORS).map(function (k) {
      return '<button type="button" data-color="' + k + '" class="' + (k === D.color ? "on" : "") + '" style="--sw:' + col(k) + '" title="' + COLORS[k].n + '" aria-label="' + COLORS[k].n + '"></button>';
    }).join("") + "</div>";
    openPop(anchor, html, function (e) {
      var b = e.target.closest("[data-color]");
      if (!b) return;
      setColor(b.getAttribute("data-color"));
      closePop();
    }, "right");
  }

  /* ════════════════════════════════════════════════════════════════════════
     TOOLBAR
     ════════════════════════════════════════════════════════════════════════ */
  var TF = [["1d", "1D"], ["5d", "5D"], ["1mo", "1M"], ["3mo", "3M"], ["6mo", "6M"],
            ["ytd", "YTD"], ["1y", "1Y"], ["2y", "2Y"], ["5y", "5Y"], ["max", "Max"]];
  var TF_TITLE = { "1d": "Today, 5-minute bars", "5d": "5 days, 30-minute bars", "1mo": "1 month, daily", "3mo": "3 months, daily",
    "6mo": "6 months, daily", "ytd": "Year to date, daily", "1y": "1 year, daily", "2y": "2 years, daily", "5y": "5 years, weekly", "max": "All history, monthly" };
  var bars = [];

  function S() { return window.S || {}; }
  function view() { return (E() && E().view) || {}; }

  function studies() {
    var s = S(), v = view(), inds = s.inds || {};
    var pal = E() ? E().palette() : {};
    var read = document.getElementById("il-read-toggle");
    return [
      { h: "Overlays" },
      { id: "ma50", n: "50-day moving average", on: !!inds.ma50, key: pal.ma50 },
      { id: "ma200", n: "200-day moving average", on: !!inds.ma200, key: pal.ma200 },
      { id: "bb", n: "Bollinger Bands (20, 2)", on: !!inds.bb, key: pal.band },
      { id: "ema21", n: "21-period EMA", on: !!v.ema21, key: pal.ema },
      { id: "vwap", n: "VWAP", sub: "Volume-weighted average price", on: !!v.vwap, key: pal.vwap },
      { h: "Panes" },
      { id: "vol", n: "Volume", on: !!v.volume, key: pal.volUp },
      { id: "rsi", n: "RSI (14)", sub: "Momentum, 0 to 100", on: v.osc === "rsi", key: pal.rsi },
      { id: "macd", n: "MACD (12, 26, 9)", on: v.osc === "macd", key: pal.gold },
      { id: "timing", n: "Lens Timing (0\u201310)", sub: "Stretched or pulled back, from four momentum gauges", on: v.osc === "timing", key: pal.up },
      { h: "On the chart" },
      { id: "zones", n: "Lens Zones", sub: "Shaded buy and sell zones, retracement, divergence", on: !!(E() && E().zonesOn()) },
      { id: "earnings", n: "Earnings markers", on: !!(v.pins && v.pins.earnings) },
      { id: "news", n: "News markers", on: !!(v.pins && v.pins.news) },
      read ? { id: "read", n: "Technical read below the chart", on: read.classList.contains("on") } : null
    ].filter(Boolean);
  }
  function activeCount() {
    return studies().filter(function (x) { return x.id && x.on && x.id !== "read"; }).length;
  }
  function toggleStudy(id) {
    var s = S();
    switch (id) {
      case "ma50": case "ma200": case "bb":
        if (typeof window.toggleInd === "function") {
          var btn = document.querySelector('[data-ind="' + id + '"]') || document.getElementById("ind-" + id + "-btn") || document.createElement("button");
          window.toggleInd(btn, id);
        }
        break;
      case "ema21": case "vwap": if (window.ilToggleOverlay) window.ilToggleOverlay(id); break;
      case "vol": if (window.ilToggleVolume) window.ilToggleVolume(); break;
      case "rsi": case "macd": case "timing": if (window.ilSetOscillator) window.ilSetOscillator(id); break;
      case "zones": if (window.ilToggleZones) window.ilToggleZones(); break;
      case "earnings": case "news": if (window.ilTogglePins) window.ilTogglePins(id); break;
      case "read": if (window.ilToggleRead) window.ilToggleRead(); break;
    }
    void s;
    setTimeout(syncBars, 0);
  }
  function studiesHtml() {
    return studies().map(function (x) {
      if (x.h) return "<h6>" + x.h + "</h6>";
      return '<button type="button" role="menuitemcheckbox" aria-checked="' + x.on + '" class="ilc-mi' + (x.on ? " on" : "") + '" data-study="' + x.id + '">' +
        '<span class="ilc-key" style="--k:' + (x.key || "transparent") + '"></span>' +
        '<span class="ilc-mi-t">' + x.n + (x.sub ? "<small>" + x.sub + "</small>" : "") + "</span>" +
        '<span class="ilc-tick">' + ICON.check + "</span></button>";
    }).join("");
  }
  function openStudies(anchor) {
    var p = openPop(anchor, studiesHtml(), function (e) {
      var b = e.target.closest("[data-study]");
      if (!b) return;
      toggleStudy(b.getAttribute("data-study"));
      setTimeout(function () { if (pop) pop.innerHTML = studiesHtml(); }, 60);
    });
    void p;
  }

  function moreHtml() {
    var dash = document.getElementById("il-dash-toggle");
    var out = '<h6>Compare</h6><div class="ilc-cmp"><input id="ilc-cmp-in" maxlength="8" placeholder="vs TICKER" aria-label="Ticker to compare against"><button type="button" data-more="compare">Compare</button></div>';
    out += '<div class="ilc-sep"></div><h6>Layout</h6>';
    if (document.getElementById("il-save-layout")) {
      out += '<button type="button" class="ilc-mi" data-more="save"><span class="ilc-mi-t">Save this chart layout<small>Timeframe, chart type and studies for this ticker</small></span></button>';
      out += '<button type="button" class="ilc-mi" data-more="restore"><span class="ilc-mi-t">Restore saved layout</span></button>';
    }
    if (dash) {
      out += '<button type="button" class="ilc-mi' + (dash.classList.contains("on") ? " on" : "") + '" data-more="dash"><span class="ilc-mi-t">Dashboard mode<small>Drag, resize and collapse the panels</small></span><span class="ilc-tick">' + ICON.check + "</span></button>";
      out += '<button type="button" class="ilc-mi" data-more="dashreset"><span class="ilc-mi-t">Reset dashboard layout</span></button>';
    }
    out += '<div class="ilc-sep"></div><button type="button" class="ilc-mi" data-more="older"><span class="ilc-mi-t">Load earlier bars<small>Or just drag the chart to the left</small></span></button>';
    return out;
  }
  function openMore(anchor) {
    var p = openPop(anchor, moreHtml(), function (e) {
      var b = e.target.closest("[data-more]");
      if (!b) return;
      var k = b.getAttribute("data-more");
      var proxy = { save: "il-save-layout", restore: "il-restore-layout", dash: "il-dash-toggle", dashreset: "il-dash-reset" }[k];
      if (proxy) { var el = document.getElementById(proxy); if (el) el.click(); closePop(); setTimeout(syncBars, 50); return; }
      if (k === "older") { if (E()) E().loadOlder(); closePop(); return; }
      if (k === "compare") runCompare();
    });
    if (p) {
      var input = p.querySelector("#ilc-cmp-in");
      if (input) input.addEventListener("keydown", function (e) { if (e.key === "Enter") runCompare(); });
    }
  }
  function runCompare() {
    var input = document.getElementById("ilc-cmp-in");
    var v = (input && input.value || "").trim().toUpperCase().replace(/[^A-Z0-9.^-]/g, "");
    if (!v) { if (input) input.focus(); return; }
    var legacy = document.getElementById("il-compare-ticker"), go = document.getElementById("il-run-compare");
    closePop();
    if (legacy && go) { legacy.value = v; go.click(); return; }
    var a = document.getElementById("cmp1"), b = document.getElementById("cmp2");
    if (a && b && window.openSection && window.runCompare) { a.value = S().ticker || ""; b.value = v; window.openSection("compare"); window.runCompare(); }
  }

  function instFor(mode) {
    var list = E() ? E().instances() : [];
    for (var i = 0; i < list.length; i++) if (list[i].mode === mode) return list[i];
    return list[0] || null;
  }

  function buildBar(mode) {
    var bar = document.createElement("div");
    bar.className = "ilc-bar ilc-scope";
    bar.setAttribute("role", "toolbar");
    bar.setAttribute("aria-label", "Chart controls");
    bar.dataset.mode = mode;
    var tf = '<div class="ilc-g ilc-tf" role="group" aria-label="Timeframe">' + TF.map(function (t) {
      return '<button type="button" class="ilc-b" data-range="' + t[0] + '" title="' + TF_TITLE[t[0]] + '">' + t[1] + "</button>";
    }).join("") + "</div>";
    var type = '<div class="ilc-g" role="group" aria-label="Chart type">' +
      '<button type="button" class="ilc-b ilc-ico" data-ctype="candle" title="Candles" aria-label="Candles">' + ICON.candle + "</button>" +
      '<button type="button" class="ilc-b ilc-ico" data-ctype="line" title="Line" aria-label="Line">' + ICON.line + "</button>" +
      '<button type="button" class="ilc-b ilc-ico" data-ctype="area" title="Area" aria-label="Area">' + ICON.area + "</button></div>";
    var st = '<div class="ilc-g"><button type="button" class="ilc-b" data-act="studies" aria-haspopup="true" aria-expanded="false" title="Indicators, panes and markers">' +
      ICON.studies + '<span class="ilc-lbl">Indicators</span><span class="ilc-count"></span><span class="ilc-chev">' + ICON.chev + "</span></button></div>";
    var scale = '<div class="ilc-g" role="group" aria-label="Price scale">' +
      '<button type="button" class="ilc-b" data-scale="log" title="Logarithmic price scale">Log</button>' +
      '<button type="button" class="ilc-b" data-scale="percent" title="Percent change from the first bar on screen">%</button></div>';
    var zoom = '<div class="ilc-g" role="group" aria-label="Zoom">' +
      '<button type="button" class="ilc-b ilc-ico" data-act="zoomout" title="Zoom out (or scroll down on the chart)" aria-label="Zoom out">' + ICON.zoomOut + "</button>" +
      '<button type="button" class="ilc-b ilc-ico" data-act="reset" title="Reset view" aria-label="Reset view">' + ICON.fit + "</button>" +
      '<button type="button" class="ilc-b ilc-ico" data-act="zoomin" title="Zoom in (or scroll up on the chart)" aria-label="Zoom in">' + ICON.zoomIn + "</button></div>";
    var right = '<div class="ilc-g ilc-plain">' +
      '<button type="button" class="ilc-b" data-act="share" title="Make a branded image of this chart">' + ICON.share + '<span class="ilc-lbl">Share image</span></button>' +
      (mode === "inline"
        ? '<button type="button" class="ilc-b ilc-ico" data-act="more" aria-haspopup="true" aria-expanded="false" title="Compare, layouts and more" aria-label="More chart options">' + ICON.more + "</button>" +
          '<button type="button" class="ilc-b ilc-ico" data-act="full" title="Full screen" aria-label="Open full screen chart">' + ICON.expand + "</button>"
        : "") +
      "</div>";
    bar.innerHTML = tf + type + st + scale + '<span class="ilc-spacer"></span>' + zoom + right;

    bar.addEventListener("click", function (e) {
      var b = e.target.closest("button");
      if (!b || !bar.contains(b)) return;
      var v;
      if ((v = b.getAttribute("data-range"))) {
        if (typeof window.changeRange === "function") {
          var pill = Array.prototype.find.call(document.querySelectorAll(".tf-pill"), function (p) { return (p.getAttribute("onclick") || "").indexOf("'" + v + "'") >= 0; });
          window.changeRange(v, pill);
        }
        syncBars();
        return;
      }
      if ((v = b.getAttribute("data-ctype"))) {
        if (typeof window.setChartType === "function") window.setChartType(v, document.getElementById("ct-" + v));
        syncBars();
        return;
      }
      if ((v = b.getAttribute("data-scale"))) { if (window.ilSetScale) window.ilSetScale(v); syncBars(); return; }
      var a = b.getAttribute("data-act");
      var target = instFor(mode);
      if (a === "studies") openStudies(b);
      else if (a === "more") openMore(b);
      else if (a === "zoomin") { if (E() && target) E().zoom(target, 1.25); }
      else if (a === "zoomout") { if (E() && target) E().zoom(target, 0.8); }
      else if (a === "reset") { if (E() && target) E().reset(target); }
      else if (a === "share") { if (window.openShareStudio) window.openShareStudio(); }
      else if (a === "full") { if (window.expandChart) window.expandChart("price-chart", "Price chart"); }
      else if (a === "exit") { if (window.closeExpandModal) window.closeExpandModal(); }
    });
    bars.push(bar);
    return bar;
  }

  function syncBars() {
    var s = S(), v = view();
    var count = activeCount();
    bars = bars.filter(function (b) { return document.body.contains(b); });
    bars.forEach(function (bar) {
      function set(sel, on) {
        bar.querySelectorAll(sel).forEach(function (b) { b.classList.toggle("on", !!on); b.setAttribute("aria-pressed", String(!!on)); });
      }
      TF.forEach(function (t) { set('[data-range="' + t[0] + '"]', (s.range || "1y") === t[0]); });
      ["candle", "line", "area"].forEach(function (t) { set('[data-ctype="' + t + '"]', (s.chartType || "candle") === t); });
      set('[data-scale="log"]', v.scale === "log");
      set('[data-scale="percent"]', v.scale === "percent");
      var c = bar.querySelector(".ilc-count");
      if (c) { c.textContent = count ? String(count) : ""; c.style.display = count ? "" : "none"; }
    });
  }
  window.ILChartToolsSync = syncBars;

  function mountInlineBar() {
    var dock = document.getElementById("il-chart-dock");
    if (dock) {
      if (dock.querySelector(".ilc-bar")) return true;
      dock.insertBefore(buildBar("inline"), dock.firstChild);
      dock.classList.add("ilc-on");
      /* The old two-row toolbar stays in the DOM (other modules read and
         toggle its buttons) but is parked in a hidden box: app-legacy.js sets
         its display directly on section changes, so hiding it by style alone
         does not stick. */
      var park = document.getElementById("ilc-legacy-park");
      if (!park) {
        park = document.createElement("div");
        park.id = "ilc-legacy-park";
        park.hidden = true;
        park.setAttribute("aria-hidden", "true");
        park.style.setProperty("display", "none", "important");
        dock.appendChild(park);
      }
      ["app-chart-toolbar", "app-tf-strip"].forEach(function (id) {
        var el = document.getElementById(id);
        if (el && el.parentElement !== park) park.appendChild(el);
      });
      syncBars();
      return true;
    }
    var header = document.querySelector("#body-analyze .chart-wrap .chart-header");
    if (header && !header.parentElement.querySelector(".ilc-bar")) {
      header.insertAdjacentElement("afterend", buildBar("inline"));
      syncBars();
      return true;
    }
    return false;
  }

  function mountFullBar(modal) {
    if (!modal) return;
    var box = modal.querySelector(".cex-box") || modal;
    /* The header's own zoom, reset, hint and share buttons duplicate the bar. */
    modal._ilcHidden = Array.prototype.slice.call(
      box.querySelectorAll(".cex-hint,.cex-icon-btn,.cex-share,.cex-controls [onclick^='resetExpandZoom'],.il-cex-controls"));
    modal._ilcHidden.forEach(function (el) { el.style.setProperty("display", "none", "important"); });
    var bar = box.querySelector(".ilc-bar");
    if (!bar) {
      bar = buildBar("full");
      var head = box.querySelector(".cex-header");
      if (head && head.nextSibling) box.insertBefore(bar, head.nextSibling); else box.appendChild(bar);
    }
    bar.style.display = "";
    syncBars();
  }
  /* The same modal also expands the Chart.js indicator charts, which still
     use the header controls. */
  function releaseFull(modal) {
    if (!modal) return;
    (modal._ilcHidden || []).forEach(function (el) { el.style.removeProperty("display"); });
    modal._ilcHidden = null;
    var bar = modal.querySelector(".ilc-bar");
    if (bar) bar.style.display = "none";
    modal.style.removeProperty("z-index");
    closePop();
    if (D.tool !== "cursor") setTool("cursor");
  }

  /* ════════════════════════════════════════════════════════════════════════
     ATTACH TO A CHART INSTANCE
     ════════════════════════════════════════════════════════════════════════ */
  function attach(inst, mode) {
    injectCss();
    var stage = inst.host.parentElement;
    if (!stage) return;
    loadFor(S().ticker || null);

    var rec = { inst: inst, stage: stage, mode: mode };
    var old = stage.querySelector(":scope > .ilc-rail");
    if (old) old.remove();
    rec.rail = buildRail();
    stage.insertBefore(rec.rail, stage.firstChild);
    stage.classList.add("ilc-has-rail");

    rec.layer = document.createElement("div");
    rec.layer.className = "ilc-layer" + (D.tool !== "cursor" ? " on" : "") + (D.tool === "eraser" ? " ilc-erase" : "");
    inst.host.appendChild(rec.layer);
    wireLayer(rec);

    rec.prim = makePrimitive(rec);
    try { inst.series.price.attachPrimitive(rec.prim); } catch (e) {}
    live.push(rec);

    inst.toolsOnRows = function () { rec.prim.update(); };
    inst.disposeTools = function () {
      live = live.filter(function (r) { return r !== rec; });
      if (D.draft && D.draft.owner === rec) D.draft = null;
      if (D.measure && D.measure.owner === rec) D.measure = null;
      try { rec.layer.remove(); } catch (e) {}
      /* the rail is reused by the next instance on the same stage */
    };

    /* Cursor mode: a click anywhere on the chart clears a finished measure. */
    inst.host.addEventListener("pointerdown", function () {
      if (D.tool === "cursor" && D.measure) { D.measure = null; refresh(); }
    }, true);

    if (mode === "inline") wireEngagement(stage);
    syncRails();
  }

  /* Cooperative wheel on the research page (see workspace-system.js). */
  function wireEngagement(slot) {
    if (slot.dataset.ilcEngage) return;
    slot.dataset.ilcEngage = "1";
    slot.addEventListener("pointerdown", function () { slot.classList.add("il-engaged"); });
    slot.addEventListener("pointerleave", function () { slot.classList.remove("il-engaged"); });
    slot.addEventListener("il:wheel-hint", function () {
      var hint = slot.querySelector(".ilc-hint");
      if (!hint) {
        hint = document.createElement("div");
        hint.className = "ilc-hint ilc-scope";
        hint.textContent = "Click the chart, then scroll to zoom · drag to pan";
        slot.appendChild(hint);
      }
      hint.classList.add("on");
      clearTimeout(hint._t);
      hint._t = setTimeout(function () { hint.classList.remove("on"); }, 1900);
    });
  }

  /* ── keyboard ─────────────────────────────────────────────────────────── */
  var KEYS = {};
  TOOLS.forEach(function (t) { if (t.key.length === 1) KEYS[t.key.toLowerCase()] = t.k; });
  document.addEventListener("keydown", function (e) {
    var t = e.target;
    if (t && (t.tagName === "INPUT" || t.tagName === "TEXTAREA" || t.tagName === "SELECT" || t.isContentEditable)) return;
    var modal = document.getElementById("chart-expand-modal");
    var full = modal && modal.classList.contains("open");
    var engaged = document.querySelector(".il-chart-slot.il-engaged");
    if (!full && !engaged) return;
    if (e.key === "Escape") {
      if (pop) { closePop(); return; }
      if (D.draft || D.tool !== "cursor" || D.measure) {
        D.draft = null; D.measure = null; setTool("cursor");
        e.stopImmediatePropagation();
      }
      return;
    }
    var mod = e.ctrlKey || e.metaKey;
    if (mod && (e.key === "z" || e.key === "Z")) { e.preventDefault(); if (e.shiftKey) redo(); else undo(); return; }
    if (mod && (e.key === "y" || e.key === "Y")) { e.preventDefault(); redo(); return; }
    if (mod || e.altKey) return;
    var k = KEYS[(e.key || "").toLowerCase()];
    if (k) { e.preventDefault(); setTool(D.tool === k ? "cursor" : k); }
  }, true);

  /* ── public surface ───────────────────────────────────────────────────── */
  window.ILChartTools = {
    attach: attach,
    mountFullBar: mountFullBar,
    releaseFull: releaseFull,
    syncBars: syncBars,
    setTool: setTool,
    drawings: function () { return { ticker: D.ticker, items: D.items.slice() }; },
    color: col,
    tToL: tToL,
    _reload: function () { var t = D.ticker; D.ticker = null; loadFor(t || S().ticker); refresh(); }
  };

  function boot() {
    injectCss();
    if (!mountInlineBar()) return false;
    /* The chart may have rendered before this script ran: attach to it now. */
    var list = E() ? E().instances() : [];
    list.forEach(function (i) { if (!i.disposeTools) attach(i, i.mode || "inline"); });
    return true;
  }
  document.addEventListener("il-chart-rendered", function () { mountInlineBar(); syncBars(); });
  document.addEventListener("click", function (e) {
    if (e.target.closest && e.target.closest(".tf-pill,.rpill,#app-chart-toolbar,[data-ind]")) setTimeout(syncBars, 30);
  });
  function tryBoot(n) { if (!boot() && n > 0) setTimeout(function () { tryBoot(n - 1); }, 400); }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", function () { tryBoot(10); });
  else tryBoot(10);
})();

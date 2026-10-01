/* Signed-out landing: ticker search, popular chips, and the live LensScore
   demo. Every number painted here is read from /api/lens-score/:ticker with
   preview=1 — the curated preview tickers cost a visitor no daily credit
   (lib/plan.js PREVIEW_QUOTE_TICKERS). If the request fails the card says so;
   it never paints a placeholder number. */
(function () {
  "use strict";

  var cache = {};
  var current = null;

  function $(id) { return document.getElementById(id); }

  function openTicker(t) {
    t = String(t || "").trim().toUpperCase().replace(/[^A-Z0-9.\-^]/g, "").slice(0, 12);
    if (!t) { var i = $("landing-search"); if (i) i.focus(); return; }
    if (typeof window.heroLoadTicker === "function") window.heroLoadTicker(t);
    else window.location.href = "/?view=tool&section=analyze&symbol=" + encodeURIComponent(t);
  }

  function wireSearch() {
    var input = $("landing-search");
    var go = $("landing-search-go");
    if (input) input.addEventListener("keydown", function (e) { if (e.key === "Enter") { e.preventDefault(); openTicker(input.value); } });
    if (go) go.addEventListener("click", function () { openTicker(input && input.value); });
    document.querySelectorAll("[data-lx-ticker]").forEach(function (b) {
      b.addEventListener("click", function () { openTicker(b.getAttribute("data-lx-ticker")); });
    });
    var demoLink = $("il-hero-primary");
    if (demoLink) demoLink.addEventListener("click", function (e) {
      var target = $("lx-demo");
      if (!target) return;
      e.preventDefault();
      target.scrollIntoView({ behavior: "smooth", block: "start" });
    });
  }

  function fmtPrice(n) {
    if (!Number.isFinite(n)) return "";
    return "$" + n.toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  }
  function ten(v) { return Number.isFinite(v) ? (v / 10).toFixed(1) : "–"; }
  function setText(id, v) { var el = $(id); if (el) el.textContent = v; }
  function setBar(id, pct) {
    var el = $(id); if (!el) return;
    var p = Number.isFinite(pct) ? Math.max(0, Math.min(100, pct)) : 0;
    el.style.width = p + "%";
    el.dataset.tone = p >= 70 ? "good" : p >= 45 ? "mid" : "weak";
  }
  function list(id, items, empty) {
    var el = $(id); if (!el) return;
    el.textContent = "";
    var rows = (items || []).slice(0, 4);
    if (!rows.length) rows = [empty];
    rows.forEach(function (t) { var li = document.createElement("li"); li.textContent = t; el.appendChild(li); });
  }

  function drawChart(bars) {
    var closes = (bars || []).map(function (b) { return Number(b && b.close); }).filter(Number.isFinite);
    closes = closes.slice(-252);
    var line = $("lx-demo-line"), area = $("lx-demo-area");
    if (!line || !area) return null;
    if (closes.length < 2) { line.setAttribute("d", ""); area.setAttribute("d", ""); return null; }
    var min = Math.min.apply(null, closes), max = Math.max.apply(null, closes);
    var span = max - min || 1, W = 600, H = 150, pad = 8;
    var pts = closes.map(function (c, i) {
      var x = (i / (closes.length - 1)) * W;
      var y = pad + (1 - (c - min) / span) * (H - pad * 2);
      return x.toFixed(1) + " " + y.toFixed(1);
    });
    line.setAttribute("d", "M" + pts.join(" L"));
    area.setAttribute("d", "M" + pts.join(" L") + " L" + W + " " + H + " L0 " + H + " Z");
    var change = (closes[closes.length - 1] / closes[0] - 1) * 100;
    var card = $("lx-demo-card");
    if (card) card.dataset.dir = change >= 0 ? "up" : "down";
    return change;
  }

  function render(t, d) {
    var card = $("lx-demo-card");
    if (card) { card.setAttribute("aria-busy", "false"); card.classList.remove("is-error"); }
    var s = d && d.score;
    if (!s || s.status !== "graded" || !Number.isFinite(Number(s.score))) return renderError(t, "LensScore is not available for " + t + " right now.");
    var lenses = s.lenses || {};
    var comps = s.components || {};
    setText("lx-demo-sym", t);
    setText("lx-demo-name", d.company || t);
    var yr = drawChart(s.technical && s.technical.bars);
    var price = Number(s.price);
    setText("lx-demo-price", fmtPrice(price) + (Number.isFinite(yr) ? "  ·  " + (yr >= 0 ? "+" : "") + yr.toFixed(1) + "% over 1 year" : ""));
    setText("lx-demo-score", Number(s.score).toFixed(1));
    var dial = $("lx-dial"); if (dial) dial.style.setProperty("--lx-score", String(Number(s.score) * 10));
    setText("lx-demo-label", (s.label || "") + (s.confidence ? " · " + s.confidence + " confidence" : ""));
    var v = lenses.value && Number(lenses.value.score), st = lenses.setup && Number(lenses.setup.score);
    setText("lx-lens-value", Number.isFinite(v) ? v.toFixed(1) : "–"); setBar("lx-bar-value", v * 10);
    setText("lx-lens-setup", Number.isFinite(st) ? st.toFixed(1) : "–"); setBar("lx-bar-setup", st * 10);
    setText("lx-comp-fund", ten(comps.fundamentals)); setBar("lx-bar-fund", comps.fundamentals);
    setText("lx-comp-val", ten(comps.valuation)); setBar("lx-bar-val", comps.valuation);
    setText("lx-comp-risk", ten(comps.risk)); setBar("lx-bar-risk", comps.risk);
    list("lx-demo-strengths", s.strengths, "No standout strengths on the current evidence.");
    list("lx-demo-concerns", (s.concerns || []).concat(s.caps || []).map(function (c) { return typeof c === "string" ? c : (c && (c.reason || c.label)) || ""; }).filter(Boolean), "No active warnings on the current evidence.");
    var open = $("lx-demo-open"); if (open) open.href = "/?view=tool&section=analyze&symbol=" + encodeURIComponent(t);
    setText("lx-demo-asof", "Live data · " + new Date().toLocaleDateString("en-US", { month: "short", day: "numeric" }) + " · Educational research, not a recommendation.");
  }

  function renderError(t, msg) {
    var card = $("lx-demo-card");
    if (card) { card.setAttribute("aria-busy", "false"); card.classList.add("is-error"); }
    setText("lx-demo-sym", t);
    setText("lx-demo-name", msg || "Live data is unavailable right now.");
    setText("lx-demo-price", "Try again in a moment, or open the full analysis.");
    setText("lx-demo-score", "–");
    var dial = $("lx-dial"); if (dial) dial.style.setProperty("--lx-score", "0");
    list("lx-demo-strengths", [], "–"); list("lx-demo-concerns", [], "–");
    var open = $("lx-demo-open"); if (open) open.href = "/?view=tool&section=analyze&symbol=" + encodeURIComponent(t);
  }

  function load(t) {
    current = t;
    document.querySelectorAll("[data-demo]").forEach(function (b) {
      b.setAttribute("aria-selected", String(b.getAttribute("data-demo") === t));
    });
    var card = $("lx-demo-card"); if (card) card.setAttribute("aria-busy", "true");
    if (cache[t]) return render(t, cache[t]);
    fetch("/api/lens-score/" + encodeURIComponent(t) + "?preview=1", { credentials: "same-origin" })
      .then(function (r) { if (!r.ok) throw new Error(String(r.status)); return r.json(); })
      .then(function (d) { cache[t] = d; if (current === t) render(t, d); })
      .catch(function () { if (current === t) renderError(t); });
  }

  function wireDemo() {
    var section = $("lx-demo");
    if (!section) return;
    document.querySelectorAll("[data-demo]").forEach(function (b) {
      b.addEventListener("click", function () { load(b.getAttribute("data-demo")); });
    });
    var started = false;
    function start() { if (started) return; started = true; load("NVDA"); }
    if ("IntersectionObserver" in window) {
      var io = new IntersectionObserver(function (entries) {
        if (entries.some(function (e) { return e.isIntersecting; })) { start(); io.disconnect(); }
      }, { rootMargin: "400px 0px" });
      io.observe(section);
    } else start();
  }

  function init() { wireSearch(); wireDemo(); }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();

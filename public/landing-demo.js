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

  var reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  function countUp(el, to) {
    if (!el) return;
    if (reduce || !Number.isFinite(to)) { el.textContent = Number.isFinite(to) ? to.toFixed(1) : "–"; return; }
    var start = performance.now(), dur = 900;
    (function step(now) {
      var k = Math.min(1, (now - start) / dur), e = 1 - Math.pow(1 - k, 3);
      el.textContent = (to * e).toFixed(1);
      if (k < 1) requestAnimationFrame(step);
    })(start);
  }

  function wireReveal() {
    var targets = document.querySelectorAll("#landing-page > .lx-section, #landing-page > .il-market-strip");
    if (!targets.length || !("IntersectionObserver" in window) || reduce) return;
    document.documentElement.classList.add("js-reveal");
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) { if (e.isIntersecting) { e.target.classList.add("lx-in"); io.unobserve(e.target); } });
    }, { rootMargin: "0px 0px -8% 0px", threshold: 0.05 });
    targets.forEach(function (t) { io.observe(t); });
    // Anything already on screen, or reached by an anchor jump, shows at once.
    setTimeout(function () { targets.forEach(function (t) { if (t.getBoundingClientRect().top < innerHeight) t.classList.add("lx-in"); }); }, 50);
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
    countUp(document.getElementById("lx-demo-score"), Number(s.score));
    if (card) { card.classList.remove("is-drawing"); void card.offsetWidth; card.classList.add("is-drawing"); }
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
    setText("lx-demo-asof", (d.servedStale ? "Most recent read · " : "Live data · ") + new Date().toLocaleDateString("en-US", { month: "short", day: "numeric" }) + " · Educational research, not a recommendation.");
  }

  function renderError(t, msg) {
    var card = $("lx-demo-card");
    if (card) { card.setAttribute("aria-busy", "false"); card.classList.add("is-error"); }
    setText("lx-demo-sym", t);
    setText("lx-demo-name", msg || "Live data is taking longer than usual.");
    var price = $("lx-demo-price");
    if (price) {
      price.textContent = "";
      var retry = document.createElement("button");
      retry.type = "button";
      retry.className = "lx-demo-retry";
      retry.textContent = "Try again";
      retry.addEventListener("click", function () { delete cache[t]; load(t); });
      price.appendChild(retry);
    }
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
    setText("lx-demo-sym", t);
    setText("lx-demo-name", "Loading a live read…");
    fetchScore(t, 0);
  }

  // A cold server or a provider blip should never leave the card spinning:
  // every attempt times out, and we retry twice before showing "Try again".
  function fetchScore(t, attempt) {
    var ctrl = "AbortController" in window ? new AbortController() : null;
    var timer = setTimeout(function () { if (ctrl) ctrl.abort(); }, 20000);
    fetch("/api/lens-score/" + encodeURIComponent(t) + "?preview=1&card=1", { credentials: "same-origin", signal: ctrl ? ctrl.signal : undefined })
      .then(function (r) { if (!r.ok) throw new Error(String(r.status)); return r.json(); })
      .then(function (d) {
        clearTimeout(timer);
        if (!d || !d.score || d.score.status !== "graded") throw new Error("not graded");
        cache[t] = d;
        if (current === t) render(t, d);
      })
      .catch(function () {
        clearTimeout(timer);
        if (current !== t) return;
        if (attempt < 2) return setTimeout(function () { if (current === t) fetchScore(t, attempt + 1); }, attempt ? 4000 : 1500);
        renderError(t);
      });
  }

  function wireDemo() {
    var section = $("lx-demo");
    if (!section) return;
    document.querySelectorAll("[data-demo]").forEach(function (b) {
      b.addEventListener("click", function () { load(b.getAttribute("data-demo")); });
    });
    var started = false;
    // index.html holds the app views too; only fetch when the homepage itself
    // is on screen, not behind the research or dashboard views.
    function landingShown() {
      var lp = document.getElementById("landing-page");
      return !!(lp && lp.getClientRects().length);
    }
    function start() { if (started || !landingShown()) return; started = true; load("NVDA"); }
    window.addEventListener("il:viewchange", function () { setTimeout(start, 600); });
    document.addEventListener("visibilitychange", function () { if (!document.hidden) start(); });
    // The demo is the next section down, so fetch early rather than relying
    // only on the scroll observer (which some browsers delay or skip).
    setTimeout(start, 2500);
    if ("IntersectionObserver" in window) {
      var io = new IntersectionObserver(function (entries) {
        if (entries.some(function (e) { return e.isIntersecting; })) { start(); io.disconnect(); }
      }, { rootMargin: "400px 0px" });
      io.observe(section);
    } else start();
  }

  function init() { wireSearch(); wireDemo(); wireReveal(); }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();

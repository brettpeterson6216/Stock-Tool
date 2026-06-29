/* ════════════════════════════════════════════════════════════════════════════
   ImpliedLens — Dashboard System
   Adds a TradingView-style draggable / resizable / collapsible widget layout to
   the panels inside the Analyze view. Fully additive: it enhances existing
   .panel-box / .chart-wrap elements without touching navigation or data loading.
   Layout (order, sizes, collapsed state) persists per-user in localStorage.
   ════════════════════════════════════════════════════════════════════════════ */
(function () {
  "use strict";

  var LS_KEY = "il-dashboard-layout-v1";
  var ENABLED_KEY = "il-dashboard-enabled-v1";

  function analyzeBody() { return document.getElementById("body-analyze"); }

  function widgets() {
    var body = analyzeBody();
    if (!body) return [];
    return Array.prototype.slice.call(
      body.querySelectorAll(".panel-box, .chart-wrap")
    ).filter(function (el) { return !el.closest(".il-widget-skip"); });
  }

  function readLayout() {
    try { return JSON.parse(localStorage.getItem(LS_KEY) || "{}"); }
    catch (e) { return {}; }
  }
  function writeLayout(layout) {
    try { localStorage.setItem(LS_KEY, JSON.stringify(layout)); } catch (e) {}
  }
  function isEnabled() { return localStorage.getItem(ENABLED_KEY) === "1"; }
  function setEnabled(on) { localStorage.setItem(ENABLED_KEY, on ? "1" : "0"); }

  function keyFor(el, idx) {
    var t = el.querySelector(".panel-box-title, .chart-title, .chart-header");
    var label = (t && t.textContent.trim()) || ("panel-" + idx);
    return label.toLowerCase().replace(/[^a-z0-9]+/g, "-").slice(0, 40) || ("panel-" + idx);
  }

  function applyLayout() {
    if (!isEnabled()) return;
    var body = analyzeBody();
    if (!body) return;
    var layout = readLayout();
    var ws = widgets();
    var withKeys = ws.map(function (el, i) {
      var k = keyFor(el, i);
      el.dataset.ilKey = k;
      return { el: el, key: k, order: (layout[k] && layout[k].order != null) ? layout[k].order : i };
    });
    withKeys.sort(function (a, b) { return a.order - b.order; });
    withKeys.forEach(function (w) {
      body.appendChild(w.el);
      var saved = layout[w.key];
      if (saved) {
        if (saved.h) w.el.style.height = saved.h + "px";
        if (saved.collapsed) w.el.classList.add("il-collapsed");
      }
    });
  }

  function saveOrder() {
    var layout = readLayout();
    widgets().forEach(function (el, i) {
      var k = el.dataset.ilKey || keyFor(el, i);
      layout[k] = layout[k] || {};
      layout[k].order = i;
      layout[k].h = Math.round(el.getBoundingClientRect().height);
      layout[k].collapsed = el.classList.contains("il-collapsed");
    });
    writeLayout(layout);
  }

  var dragEl = null, placeholder = null, startY = 0;

  function onPointerDown(e) {
    if (!isEnabled()) return;
    var handle = e.target.closest(".il-drag-handle");
    if (!handle) return;
    var widget = handle.closest(".panel-box, .chart-wrap");
    if (!widget) return;
    e.preventDefault();
    dragEl = widget;
    dragEl.classList.add("il-dragging");
    placeholder = document.createElement("div");
    placeholder.className = "il-drop-placeholder";
    placeholder.style.height = dragEl.getBoundingClientRect().height + "px";
    dragEl.parentNode.insertBefore(placeholder, dragEl.nextSibling);
    startY = e.clientY;
    document.addEventListener("pointermove", onPointerMove);
    document.addEventListener("pointerup", onPointerUp, { once: true });
  }

  function onPointerMove(e) {
    if (!dragEl) return;
    dragEl.style.transform = "translateY(" + (e.clientY - startY) + "px)";
    var body = analyzeBody();
    var siblings = widgets().filter(function (w) { return w !== dragEl; });
    var after = null;
    for (var i = 0; i < siblings.length; i++) {
      var r = siblings[i].getBoundingClientRect();
      if (e.clientY < r.top + r.height / 2) { after = siblings[i]; break; }
    }
    if (after) body.insertBefore(placeholder, after);
    else body.appendChild(placeholder);
  }

  function onPointerUp() {
    if (!dragEl) return;
    document.removeEventListener("pointermove", onPointerMove);
    dragEl.style.transform = "";
    dragEl.classList.remove("il-dragging");
    if (placeholder && placeholder.parentNode) {
      placeholder.parentNode.insertBefore(dragEl, placeholder);
      placeholder.parentNode.removeChild(placeholder);
    }
    placeholder = null;
    dragEl = null;
    saveOrder();
  }

  function enhance() {
    widgets().forEach(function (el, i) {
      if (el.dataset.ilWidget) return;
      el.dataset.ilWidget = "1";
      el.dataset.ilKey = keyFor(el, i);
      var bar = document.createElement("div");
      bar.className = "il-widget-bar";
      bar.innerHTML =
        '<button class="il-drag-handle" type="button" title="Drag to reorder" aria-label="Drag to reorder panel"><i class="ti ti-grip-vertical"></i></button>' +
        '<span class="il-widget-spacer"></span>' +
        '<button class="il-widget-min" type="button" title="Collapse / expand" aria-label="Collapse or expand panel"><i class="ti ti-minus"></i></button>';
      el.insertBefore(bar, el.firstChild);
      bar.querySelector(".il-widget-min").addEventListener("click", function (ev) {
        ev.stopPropagation();
        var collapsed = el.classList.toggle("il-collapsed");
        this.innerHTML = collapsed ? '<i class="ti ti-plus"></i>' : '<i class="ti ti-minus"></i>';
        saveOrder();
      });
      el.addEventListener("mouseup", function () { if (isEnabled()) saveOrder(); });
    });
    if (isEnabled()) document.body.classList.add("il-dashboard-on");
    else document.body.classList.remove("il-dashboard-on");
    applyLayout();
  }

  function injectToggle() {
    var toolbar = document.getElementById("app-chart-toolbar");
    if (!toolbar || document.getElementById("il-dash-toggle")) return;
    var right = toolbar.querySelector(".act-right") || toolbar;
    var btn = document.createElement("button");
    btn.id = "il-dash-toggle";
    btn.type = "button";
    btn.className = "act-btn";
    btn.title = "Toggle dashboard layout (drag, resize, collapse panels)";
    btn.setAttribute("aria-pressed", isEnabled() ? "true" : "false");
    btn.innerHTML = '<i class="ti ti-layout-dashboard"></i>';
    if (isEnabled()) btn.classList.add("on");
    btn.addEventListener("click", function () {
      var on = !isEnabled();
      setEnabled(on);
      btn.classList.toggle("on", on);
      btn.setAttribute("aria-pressed", on ? "true" : "false");
      document.body.classList.toggle("il-dashboard-on", on);
      if (on) { enhance(); window.toast && window.toast("Dashboard mode on — drag, resize, and collapse panels", "ok"); }
      else { window.toast && window.toast("Dashboard mode off", "ok"); }
    });
    right.insertBefore(btn, right.firstChild);
    var reset = document.createElement("button");
    reset.id = "il-dash-reset";
    reset.type = "button";
    reset.className = "act-btn";
    reset.title = "Reset dashboard layout";
    reset.setAttribute("aria-label", "Reset dashboard layout");
    reset.innerHTML = '<i class="ti ti-rotate"></i>';
    reset.addEventListener("click", function () {
      writeLayout({});
      widgets().forEach(function (el) { el.style.height = ""; el.classList.remove("il-collapsed"); });
      window.toast && window.toast("Dashboard layout reset", "ok");
    });
    right.insertBefore(reset, btn.nextSibling);
  }

  function init() {
    injectToggle();
    enhance();
    document.addEventListener("pointerdown", onPointerDown);
    var body = analyzeBody();
    if (body) {
      var mo = new MutationObserver(function () {
        clearTimeout(window._ilDashT);
        window._ilDashT = setTimeout(function () { injectToggle(); enhance(); }, 150);
      });
      mo.observe(body, { childList: true, subtree: true });
    }
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();

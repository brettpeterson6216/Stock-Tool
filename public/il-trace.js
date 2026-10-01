/* IL Trace: the ImpliedLens signature line.

   One clean gold price line that draws itself once when it comes into
   view, settles, and keeps a single breathing "last price" dot. It is a
   component, not wallpaper: drop <div class="il-trace"></div> anywhere
   (or let this script add one under a page hero) and it renders an SVG
   sized to its box.

     data-seed="7"        same seed, same shape (deterministic)
     data-trend="up"      up | down | flat
     data-points="90"     resolution
     data-size="hero"     hero | compact (height and weight)

   SVG + CSS only: no canvas, no animation loop. The draw-in and the dot
   are CSS animations, disabled under prefers-reduced-motion. Colours are
   the theme tokens, so light and dark both work. */
(function () {
  "use strict";
  var NS = "http://www.w3.org/2000/svg";
  var uid = 0;

  function rng(seed) {
    var s = (seed >>> 0) || 1;
    return function () { s = (s * 16807) % 2147483647; return (s - 1) / 2147483646; };
  }

  // A seeded random walk with drift, lightly smoothed: reads like a real
  // price series rather than a sine wave.
  function series(seed, n, trend) {
    var r = rng(seed), v = 0, out = [], drift = trend === "down" ? -0.055 : trend === "flat" ? 0 : 0.06;
    for (var i = 0; i < n; i++) {
      var shock = (r() - 0.5) * 1.1 + (r() - 0.5) * 0.6;
      v += drift + shock * 0.55;
      out.push(v);
    }
    // three-point smoothing keeps the character without the jitter
    var sm = out.map(function (_, i) {
      var a = out[Math.max(0, i - 1)], b = out[i], c = out[Math.min(n - 1, i + 1)];
      return (a + 2 * b + c) / 4;
    });
    var min = Math.min.apply(null, sm), max = Math.max.apply(null, sm), span = max - min || 1;
    return sm.map(function (y) { return (y - min) / span; });
  }

  // Catmull-Rom through the points, as cubic Béziers.
  function pathFor(pts) {
    var d = "M" + pts[0][0].toFixed(1) + " " + pts[0][1].toFixed(1);
    for (var i = 0; i < pts.length - 1; i++) {
      var p0 = pts[Math.max(0, i - 1)], p1 = pts[i], p2 = pts[i + 1], p3 = pts[Math.min(pts.length - 1, i + 2)];
      var c1x = p1[0] + (p2[0] - p0[0]) / 6, c1y = p1[1] + (p2[1] - p0[1]) / 6;
      var c2x = p2[0] - (p3[0] - p1[0]) / 6, c2y = p2[1] - (p3[1] - p1[1]) / 6;
      d += "C" + c1x.toFixed(1) + " " + c1y.toFixed(1) + " " + c2x.toFixed(1) + " " + c2y.toFixed(1) + " " + p2[0].toFixed(1) + " " + p2[1].toFixed(1);
    }
    return d;
  }

  function el(name, attrs) {
    var e = document.createElementNS(NS, name);
    for (var k in attrs) e.setAttribute(k, attrs[k]);
    return e;
  }

  function render(host) {
    if (host.__ilTrace) return;
    host.__ilTrace = true;
    var W = 1000, H = host.getAttribute("data-size") === "compact" ? 70 : 120;
    var seed = parseInt(host.getAttribute("data-seed") || "7", 10);
    var n = parseInt(host.getAttribute("data-points") || "90", 10);
    var trend = host.getAttribute("data-trend") || "up";
    var ys = series(seed, n, trend);
    var top = 10, bottom = H - 8;
    var pts = ys.map(function (y, i) { return [i / (n - 1) * W, bottom - y * (bottom - top)]; });
    var id = "ilt" + (++uid);

    var svg = el("svg", { viewBox: "0 0 " + W + " " + H, preserveAspectRatio: "none", "aria-hidden": "true", focusable: "false" });
    var defs = el("defs", {});
    var grad = el("linearGradient", { id: id + "f", x1: "0", y1: "0", x2: "0", y2: "1" });
    grad.appendChild(el("stop", { offset: "0", "class": "il-trace-fill-a" }));
    grad.appendChild(el("stop", { offset: "1", "class": "il-trace-fill-b" }));
    defs.appendChild(grad);
    svg.appendChild(defs);

    // quiet chart furniture: three guide lines and the opening level
    [0.25, 0.5, 0.75].forEach(function (f) {
      svg.appendChild(el("line", { x1: 0, x2: W, y1: (top + (bottom - top) * f).toFixed(1), y2: (top + (bottom - top) * f).toFixed(1), "class": "il-trace-grid" }));
    });
    svg.appendChild(el("line", { x1: 0, x2: W, y1: pts[0][1].toFixed(1), y2: pts[0][1].toFixed(1), "class": "il-trace-open" }));

    var line = pathFor(pts);
    svg.appendChild(el("path", { d: line + "L" + W + " " + H + "L0 " + H + "Z", fill: "url(#" + id + "f)", "class": "il-trace-area" }));
    svg.appendChild(el("path", { d: line, "class": "il-trace-line", pathLength: "1" }));
    host.appendChild(svg);

    // The dot lives outside the stretched SVG so it stays round.
    var last = pts[pts.length - 1];
    var dot = document.createElement("span");
    dot.className = "il-trace-dot";
    dot.style.top = (last[1] / H * 100).toFixed(2) + "%";
    host.appendChild(dot);
    host.style.setProperty("--il-trace-h", H + "px");
    host.classList.add("is-ready");

    if ("IntersectionObserver" in window) {
      var io = new IntersectionObserver(function (e) {
        if (e[0].isIntersecting) { host.classList.add("is-drawn"); io.disconnect(); }
      }, { threshold: 0.25 });
      io.observe(host);
    } else host.classList.add("is-drawn");
  }

  // Under every page hero that does not already carry one.
  var HEROES = "#landing-page .il-landing-hero, .il-static-page .hero, .il-static-page section.hero, .il-static-page section.intro, .lxp-hero, .lxl:not(.lxl-lesson) .lxl-hero, #public-main > .hero";
  function init() {
    document.querySelectorAll(HEROES).forEach(function (h, i) {
      if (h.querySelector(".il-trace")) return;
      var t = document.createElement("div");
      t.className = "il-trace il-trace-hero";
      t.setAttribute("data-seed", String(11 + (location.pathname.length * 7 + i * 13) % 97));
      t.setAttribute("data-size", h.matches("#landing-page .il-landing-hero") ? "hero" : "compact");
      h.appendChild(t);
    });
    document.querySelectorAll(".il-trace").forEach(render);
  }
  window.ILTrace = { render: render, init: init };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();

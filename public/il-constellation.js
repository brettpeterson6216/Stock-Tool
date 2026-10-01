/* IL Constellation: the ImpliedLens hero field.

   A slow 3D constellation of gold nodes joined by hairlines, with a few
   nodes tagged by the things a researcher actually weighs (EPS, FCF,
   ROIC...). It sits behind a hero, spans the full viewport width, and
   keeps clear of the copy: nodes fade out where the text is.

   Reusable: <div class="il-constellation" data-seed="7" data-labels="EPS,FCF"
   data-density="60" data-clear="center|left|none"></div> inside any
   position:relative box. This script also adds one behind each page hero.

   Lightweight by design: Canvas 2D, ~60 nodes, 30fps cap, stops when off
   screen or in a background tab, one static frame under reduced motion.
   Colours come from the theme tokens, so light and dark both work. */
(function () {
  "use strict";

  var LABELS = ["EPS", "FREE CASH FLOW", "ROIC", "P/E", "MARGINS", "MOAT", "DCF", "GUIDANCE", "10-K", "INSIDERS", "DEBT / EQUITY", "RSI", "REVENUE", "BUYBACKS"];
  var reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var theme = {};

  function readTheme() {
    var cs = getComputedStyle(document.documentElement);
    theme.gold = parseColor(cs.getPropertyValue("--rp-gold-accent").trim() || "#c9a24a");
    theme.mono = (cs.getPropertyValue("--rp-mono").trim() || "ui-monospace, SFMono-Regular, Menlo, monospace");
    theme.dark = document.documentElement.getAttribute("data-theme") === "dark";
  }
  function parseColor(c) {
    var m = c.match(/^#([0-9a-f]{3}|[0-9a-f]{6})$/i);
    if (m) {
      var h = m[1].length === 3 ? m[1].replace(/./g, "$&$&") : m[1];
      return [parseInt(h.slice(0, 2), 16), parseInt(h.slice(2, 4), 16), parseInt(h.slice(4, 6), 16)];
    }
    m = c.match(/rgba?\(([^)]+)\)/);
    if (m) return m[1].split(",").slice(0, 3).map(function (v) { return parseFloat(v); });
    return [201, 162, 74];
  }
  function rgba(a) { return "rgba(" + theme.gold[0] + "," + theme.gold[1] + "," + theme.gold[2] + "," + a.toFixed(3) + ")"; }

  function rng(seed) {
    var s = (seed >>> 0) || 1;
    return function () { s = (s * 16807) % 2147483647; return (s - 1) / 2147483646; };
  }
  function smooth(a, b, x) { var t = Math.max(0, Math.min(1, (x - a) / (b - a))); return t * t * (3 - 2 * t); }

  function build(seed, n, labels) {
    var r = rng(seed), nodes = [], i, j;
    // A wide, shallow cloud: reads as a field, not a ball.
    for (i = 0; i < n; i++) {
      var u = r() * Math.PI * 2, v = Math.acos(2 * r() - 1), rad = Math.pow(r(), 0.45);
      nodes.push({
        x: Math.cos(u) * Math.sin(v) * rad * 1.45,
        y: Math.cos(v) * rad * 0.62,
        z: Math.sin(u) * Math.sin(v) * rad * 1.1,
        s: 0.7 + r() * 0.8
      });
    }
    // Hairlines: each node to its two nearest neighbours.
    var edges = [], seen = {};
    for (i = 0; i < n; i++) {
      var d = [];
      for (j = 0; j < n; j++) if (j !== i) {
        var dx = nodes[i].x - nodes[j].x, dy = nodes[i].y - nodes[j].y, dz = nodes[i].z - nodes[j].z;
        d.push([dx * dx + dy * dy + dz * dz, j]);
      }
      d.sort(function (a, b) { return a[0] - b[0]; });
      for (var k = 0; k < 3; k++) {
        var a = Math.min(i, d[k][1]), b = Math.max(i, d[k][1]), key = a + ":" + b;
        if (!seen[key] && d[k][0] < (k < 2 ? 0.45 : 0.14)) { seen[key] = 1; edges.push([a, b]); }
      }
    }
    // Labels go on well-spread nodes, plus one "live" accent node.
    var order = nodes.map(function (_, idx) { return idx; }).sort(function () { return r() - 0.5; });
    var tagged = [];
    for (i = 0; i < order.length && tagged.length < labels.length; i++) {
      var p = nodes[order[i]], ok = Math.abs(p.y) < 0.45;
      for (j = 0; j < tagged.length && ok; j++) {
        var q = nodes[tagged[j]];
        if (Math.abs(q.x - p.x) < 0.55 && Math.abs(q.z - p.z) < 0.55) ok = false;
      }
      if (ok) { p.label = labels[tagged.length]; tagged.push(order[i]); }
    }
    nodes[order[order.length - 1]].accent = true;
    return { nodes: nodes, edges: edges };
  }

  function mount(host) {
    if (host.__ilc) return;
    host.__ilc = true;
    var seed = parseInt(host.getAttribute("data-seed") || "7", 10);
    var density = parseInt(host.getAttribute("data-density") || "60", 10);
    var clear = host.getAttribute("data-clear") || "center";
    var labels = (host.getAttribute("data-labels") || "").split(",").map(function (s) { return s.trim(); }).filter(Boolean);
    if (!labels.length) {
      var lr = rng(seed * 31), pool = LABELS.slice();
      for (var i = 0; i < 5; i++) labels.push(pool.splice(Math.floor(lr() * pool.length), 1)[0]);
    }
    var scene = build(seed, density, labels);
    var canvas = document.createElement("canvas");
    canvas.setAttribute("aria-hidden", "true");
    host.appendChild(canvas);
    var ctx = canvas.getContext("2d");
    var W = 0, H = 0, dpr = 1, visible = true, raf = 0, last = 0, t0 = performance.now();
    var proj = new Array(scene.nodes.length);

    function size() {
      var full = host.classList.contains("il-constellation-hero");
      if (full) {
        // Bleed to the viewport edges whatever container the hero sits in.
        var parentLeft = host.parentElement.getBoundingClientRect().left;
        host.style.left = (-parentLeft) + "px";
        host.style.width = document.documentElement.clientWidth + "px";
      }
      var rect = host.getBoundingClientRect();
      dpr = Math.min(window.devicePixelRatio || 1, 1.5);
      W = Math.max(1, rect.width); H = Math.max(1, rect.height);
      canvas.width = Math.round(W * dpr); canvas.height = Math.round(H * dpr);
      canvas.style.width = W + "px"; canvas.style.height = H + "px";
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      draw(performance.now());
    }

    // How much a point at (x, y) is allowed to show, keeping the copy clear.
    function clearance(x, y) {
      var edge = smooth(0, H * 0.18, y) * smooth(H, H * 0.82, y);
      if (clear === "none") return edge;
      if (W < 700) return edge * 0.38; // phones: copy fills the width, so the whole field stays faint
      if (clear === "left") {
        var cx = W < 760 ? 0.2 : 0.42;
        return edge * (0.12 + 0.88 * smooth(W * cx, W * (cx + 0.26), x));
      }
      var nx = (x - W / 2) / (Math.min(W, 1100) * 0.42), ny = (y - H * 0.5) / (H * 0.5);
      var d = Math.sqrt(nx * nx + ny * ny * 0.35);
      return edge * (0.1 + 0.9 * smooth(0.55, 1.1, d));
    }

    function draw(now) {
      var t = (now - t0) / 1000;
      // About one full turn every five minutes: you notice it, it never pulls focus.
      var rot = (reduce ? 0.6 : 0.6 + t * 0.021) + (window.scrollY || 0) * 0.00025;
      var tilt = 0.32, cr = Math.cos(rot), sr = Math.sin(rot), ct = Math.cos(tilt), st = Math.sin(tilt);
      var scale = Math.min(W * 0.36, 620), cx = W / 2, cy = H * 0.5;
      var nodes = scene.nodes, i;
      ctx.clearRect(0, 0, W, H);
      for (i = 0; i < nodes.length; i++) {
        var p = nodes[i];
        var x = p.x * cr - p.z * sr, z = p.x * sr + p.z * cr;
        var y = p.y * ct - z * st; z = p.y * st + z * ct;
        var f = 3 / (3 + z);
        var sx = cx + x * f * scale, sy = cy + y * f * scale * 0.9;
        var depth = (1 - z) / 2; // 0 back .. 1 front
        proj[i] = { x: sx, y: sy, d: depth, k: clearance(sx, sy) };
      }
      var base = theme.dark ? 1 : 0.85;
      ctx.lineWidth = 0.7;
      for (i = 0; i < scene.edges.length; i++) {
        var a = proj[scene.edges[i][0]], b = proj[scene.edges[i][1]];
        var al = (0.05 + 0.13 * (a.d + b.d) / 2) * Math.min(a.k, b.k) * base;
        if (al < 0.006) continue;
        ctx.strokeStyle = rgba(al);
        ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke();
      }
      for (i = 0; i < nodes.length; i++) {
        var q = proj[i], n = nodes[i];
        var alpha = (0.18 + 0.55 * q.d) * q.k * base;
        if (alpha < 0.01) continue;
        var r = (0.8 + 1.3 * q.d) * n.s;
        if (n.accent) {
          var pulse = reduce ? 0.5 : 0.5 + 0.5 * Math.sin(t * (Math.PI * 2 / 4.5));
          ctx.fillStyle = rgba(0.10 * pulse * q.k);
          ctx.beginPath(); ctx.arc(q.x, q.y, r + 6 + 4 * pulse, 0, Math.PI * 2); ctx.fill();
          ctx.fillStyle = rgba(Math.min(1, alpha + 0.3));
          ctx.beginPath(); ctx.arc(q.x, q.y, r + 1.2, 0, Math.PI * 2); ctx.fill();
          continue;
        }
        ctx.fillStyle = rgba(alpha);
        ctx.beginPath(); ctx.arc(q.x, q.y, r, 0, Math.PI * 2); ctx.fill();
        if (n.label && W > 560) {
          // Labels only read when their node swings to the front.
          var la = smooth(0.45, 0.8, q.d) * q.k * (theme.dark ? 0.62 : 0.72);
          if (la < 0.02) continue;
          ctx.strokeStyle = rgba(la * 0.7);
          ctx.lineWidth = 0.8;
          ctx.beginPath(); ctx.arc(q.x, q.y, r + 3.5, 0, Math.PI * 2); ctx.stroke();
          ctx.lineWidth = 0.7;
          ctx.font = "500 10px " + theme.mono;
          ctx.fillStyle = rgba(la);
          ctx.fillText(n.label, q.x + r + 8, q.y - r - 5);
        }
      }
    }

    function loop(now) {
      raf = 0;
      if (!visible || document.hidden) return;
      if (now - last >= 33) { last = now; draw(now); }
      raf = requestAnimationFrame(loop);
    }
    function start() { if (!reduce && !raf && visible && !document.hidden) raf = requestAnimationFrame(loop); }

    if ("IntersectionObserver" in window) {
      new IntersectionObserver(function (e) { visible = e[0].isIntersecting; if (visible) start(); }, { rootMargin: "80px" }).observe(host);
    }
    document.addEventListener("visibilitychange", start);
    if (reduce) window.addEventListener("scroll", function () { requestAnimationFrame(function () { draw(performance.now()); }); }, { passive: true });
    if ("ResizeObserver" in window) new ResizeObserver(function () { size(); }).observe(host.parentElement);
    window.addEventListener("resize", size);
    host.__ilcRedraw = function () { draw(performance.now()); };
    size();
    host.classList.add("is-ready");
    start();
  }

  var HEROES = "#landing-page .il-landing-hero, .il-static-page .hero, .il-static-page section.hero, .il-static-page section.intro, .lxp-hero, .lxl:not(.lxl-lesson) .lxl-hero, #public-main > .hero";
  function init() {
    readTheme();
    document.querySelectorAll(HEROES).forEach(function (h, i) {
      if (h.querySelector(".il-constellation")) return;
      var c = document.createElement("div");
      var ta = getComputedStyle(h).textAlign;
      c.className = "il-constellation il-constellation-hero";
      c.setAttribute("data-seed", String(17 + (location.pathname.length * 11 + i * 7) % 89));
      c.setAttribute("data-clear", ta === "center" ? "center" : "left");
      c.setAttribute("data-density", h.matches("#landing-page .il-landing-hero") ? "96" : "60");
      h.classList.add("il-has-constellation");
      h.insertBefore(c, h.firstChild);
    });
    document.querySelectorAll(".il-constellation").forEach(mount);
    new MutationObserver(function () {
      readTheme();
      document.querySelectorAll(".il-constellation").forEach(function (c) { if (c.__ilcRedraw) c.__ilcRedraw(); });
    }).observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
  }
  window.ILConstellation = { init: init, mount: mount };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();

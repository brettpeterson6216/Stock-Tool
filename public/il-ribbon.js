/* IL Ribbon: the ImpliedLens hero object.

   One glowing gold wireframe tube with a square cross-section that
   snakes through 3D space behind a hero: four continuous rails, evenly
   spaced square frames, a slow twist, and frames that drift along its
   length. On first view it draws itself in from one end.

   Composition is chosen per hero: "flanks" (two asymmetric ribbons that
   drop from the top and leave off either side of centred copy), "cradle"
   (one big U around it) or "sweep" (a swoop right of left-aligned copy). Reusable anywhere:
     <div class="il-ribbon" data-path="flanks|cradle|sweep" data-seed="3"></div>
   inside a position:relative box.

   Canvas 2D, 30fps cap, pauses off screen and in background tabs, a
   single still frame under prefers-reduced-motion. Gold comes from the
   theme tokens; additive glow in dark mode, crisp ink lines in light. */
(function () {
  "use strict";
  var reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var theme = { dark: true, gold: [214, 168, 82] };

  function readTheme() {
    theme.dark = document.documentElement.getAttribute("data-theme") === "dark";
    var c = getComputedStyle(document.documentElement).getPropertyValue("--rp-gold-accent").trim();
    var m = c.match(/^#([0-9a-f]{6})$/i);
    if (m) theme.gold = [0, 2, 4].map(function (i) { return parseInt(m[1].slice(i, i + 2), 16); });
  }
  function col(rgb, a) { return "rgba(" + rgb[0] + "," + rgb[1] + "," + rgb[2] + "," + a.toFixed(3) + ")"; }
  function mix(a, b, k) { return [0, 1, 2].map(function (i) { return Math.round(a[i] + (b[i] - a[i]) * k); }); }
  function smooth(a, b, x) { var t = Math.max(0, Math.min(1, (x - a) / (b - a))); return t * t * (3 - 2 * t); }

  // Compositions. Each ribbon: control points in normalised hero space
  // (x, y in -1..1, y down; z is depth), a size factor and a start delay.
  var LEFT = [[-0.5, -1.4, 0.25], [-0.6, -0.8, -0.45], [-0.84, -0.12, -0.05], [-0.72, 0.42, 0.45], [-0.98, 0.84, -0.25], [-1.55, 1.02, 0.05]];
  var RIGHT = [[0.6, -1.4, -0.2], [0.64, -0.86, 0.35], [0.8, -0.3, -0.3], [0.7, 0.18, 0.2], [0.9, 0.52, 0.4], [1.55, 0.74, 0]];
  var PATHS = {
    flanks: [{ pts: LEFT, size: 1, delay: 0, twist: 1.5 }, { pts: RIGHT, size: 0.78, delay: 0.7, twist: -1.3 }],
    cradle: [{ pts: [[1.55, -1.25, 0.1], [1.06, -0.78, -0.5], [0.86, 0.02, -0.15], [0.66, 0.74, 0.5], [0.02, 1.02, 0.7], [-0.66, 0.86, 0.25], [-0.98, 0.25, -0.35], [-0.86, -0.5, -0.6], [-1.25, -1.35, -0.25]], size: 1, delay: 0, twist: 2.4 }],
    sweep: [{ pts: [[1.4, -1.35, 0.2], [0.95, -0.72, -0.5], [0.5, -0.02, 0.35], [0.58, 0.66, -0.4], [1.05, 1.0, 0.2], [1.5, 1.35, -0.1]], size: 1, delay: 0, twist: 2.4 }],
    // Phones: the copy fills the width, so two bands cross above and below it.
    phone: [{ pts: [[-1.7, -0.48, 0], [-0.6, -0.6, -0.3], [0.35, -0.86, 0.25], [1.0, -1.15, -0.1], [1.6, -1.4, 0]], size: 1, delay: 0, twist: 1.6 },
            { pts: [[-1.7, 0.42, 0], [-0.7, 0.58, -0.3], [0.15, 0.8, 0.3], [0.85, 1.08, -0.2], [1.5, 1.45, 0]], size: 0.85, delay: 0.6, twist: -1.4 }]
  };

  function catmull(p0, p1, p2, p3, t) {
    var t2 = t * t, t3 = t2 * t;
    return [0, 1, 2].map(function (i) {
      return 0.5 * (2 * p1[i] + (-p0[i] + p2[i]) * t + (2 * p0[i] - 5 * p1[i] + 4 * p2[i] - p3[i]) * t2 + (-p0[i] + 3 * p1[i] - 3 * p2[i] + p3[i]) * t3);
    });
  }
  function sub(a, b) { return [a[0] - b[0], a[1] - b[1], a[2] - b[2]]; }
  function add(a, b) { return [a[0] + b[0], a[1] + b[1], a[2] + b[2]]; }
  function mul(a, k) { return [a[0] * k, a[1] * k, a[2] * k]; }
  function dot(a, b) { return a[0] * b[0] + a[1] * b[1] + a[2] * b[2]; }
  function cross(a, b) { return [a[1] * b[2] - a[2] * b[1], a[2] * b[0] - a[0] * b[2], a[0] * b[1] - a[1] * b[0]]; }
  function norm(a) { var l = Math.sqrt(dot(a, a)) || 1; return [a[0] / l, a[1] / l, a[2] / l]; }

  function mount(host) {
    if (host.__ilr) return;
    host.__ilr = true;
    var pathName = host.getAttribute("data-path") || "flanks";
    var seed = parseInt(host.getAttribute("data-seed") || "3", 10);
    var canvas = document.createElement("canvas");
    canvas.setAttribute("aria-hidden", "true");
    host.appendChild(canvas);
    var ctx = canvas.getContext("2d");
    var W = 0, H = 0, dpr = 1, visible = true, raf = 0, last = 0, born = 0;

    function size() {
      if (host.classList.contains("il-ribbon-hero")) {
        host.style.left = (-host.parentElement.getBoundingClientRect().left) + "px";
        host.style.width = document.documentElement.clientWidth + "px";
      }
      var r = host.getBoundingClientRect();
      dpr = Math.min(window.devicePixelRatio || 1, 1.75);
      W = Math.max(1, r.width); H = Math.max(1, r.height);
      canvas.width = Math.round(W * dpr); canvas.height = Math.round(H * dpr);
      canvas.style.width = W + "px"; canvas.style.height = H + "px";
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      draw(performance.now());
    }

    function geometry(t, cps, salt) {
      var sx = W / 2, sy = H / 2, sz = Math.min(W, H) / 2;
      // Each control point breathes a little, so the whole body slowly flexes.
      var pts = cps.map(function (p, i) {
        var a = 0.035, ph = i * 1.9 + seed + salt * 2.7;
        return [(p[0] + a * Math.sin(t * 0.11 + ph)) * sx, (p[1] + a * Math.cos(t * 0.09 + ph * 1.3)) * sy, (p[2] + 0.12 * Math.sin(t * 0.07 + ph)) * sz];
      });
      var samples = [], steps = 26;
      for (var i = 0; i < pts.length - 1; i++) {
        var p0 = pts[Math.max(0, i - 1)], p1 = pts[i], p2 = pts[i + 1], p3 = pts[Math.min(pts.length - 1, i + 2)];
        for (var s = 0; s < steps; s++) samples.push(catmull(p0, p1, p2, p3, s / steps));
      }
      samples.push(pts[pts.length - 1]);
      // Arc length, tangents and a parallel-transported frame (no flips).
      var len = [0], T = [], N = [], B = [];
      for (i = 0; i < samples.length; i++) {
        if (i) len.push(len[i - 1] + Math.sqrt(dot(sub(samples[i], samples[i - 1]), sub(samples[i], samples[i - 1]))));
        T.push(norm(sub(samples[Math.min(samples.length - 1, i + 1)], samples[Math.max(0, i - 1)])));
      }
      var n0 = cross(T[0], [0, 0, 1]);
      if (dot(n0, n0) < 1e-6) n0 = cross(T[0], [0, 1, 0]);
      N.push(norm(n0)); B.push(cross(T[0], N[0]));
      for (i = 1; i < samples.length; i++) {
        var n = sub(N[i - 1], mul(T[i], dot(N[i - 1], T[i])));
        N.push(norm(n)); B.push(cross(T[i], N[i]));
      }
      return { p: samples, T: T, N: N, B: B, len: len, total: len[len.length - 1] };
    }

    function at(g, d) {
      var lo = 0, hi = g.len.length - 1;
      while (hi - lo > 1) { var mid = (lo + hi) >> 1; if (g.len[mid] < d) lo = mid; else hi = mid; }
      var k = (d - g.len[lo]) / ((g.len[hi] - g.len[lo]) || 1);
      return {
        p: add(g.p[lo], mul(sub(g.p[hi], g.p[lo]), k)),
        N: norm(add(g.N[lo], mul(sub(g.N[hi], g.N[lo]), k))),
        B: norm(add(g.B[lo], mul(sub(g.B[hi], g.B[lo]), k))),
        u: d / g.total
      };
    }

    function project(v) {
      var D = Math.max(W, H) * 1.05, f = D / (D + v[2]);
      return [W / 2 + v[0] * f, H / 2 + v[1] * f, v[2]];
    }

    function corners(fr, half, twist) {
      var out = [];
      for (var k = 0; k < 4; k++) {
        var a = twist + k * Math.PI / 2 + Math.PI / 4;
        out.push(project(add(fr.p, add(mul(fr.N, Math.cos(a) * half), mul(fr.B, Math.sin(a) * half)))));
      }
      return out;
    }

    // Copy stays readable: lines thin out where the text block sits.
    function keep(x, y) {
      var edge = smooth(-40, H * 0.1, y) * smooth(H + 40, H * 0.9, y) * smooth(-60, W * 0.04, x) * smooth(W + 60, W * 0.96, x);
      var nx = (x - W / 2) / Math.min(W * 0.36, 520), ny = (y - H * 0.46) / (H * 0.42);
      if (pathName === "sweep") { nx = (x - W * 0.32) / (W * 0.3); ny = (y - H * 0.5) / (H * 0.45); }
      var d = Math.sqrt(nx * nx + ny * ny);
      return edge * (W < 700 ? 0.5 + 0.5 * smooth(0.55, 1.0, d) : 0.32 + 0.68 * smooth(0.7, 1.15, d));
    }

    function stroke(segs, dark) {
      // segs: [x1,y1,x2,y2,alpha,depth]
      var gold = theme.gold, hot = mix(gold, [255, 244, 214], 0.55), ink = mix(gold, [70, 48, 12], 0.35);
      if (dark) {
        ctx.globalCompositeOperation = "lighter";
        var passes = [[11, 0.045, gold], [3.4, 0.2, gold], [1.25, 0.9, hot]];
        passes.forEach(function (ps) {
          ctx.lineWidth = ps[0];
          for (var i = 0; i < segs.length; i++) {
            var s = segs[i], a = s[4] * ps[1];
            if (a < 0.004) continue;
            ctx.strokeStyle = col(ps[2], a);
            ctx.beginPath(); ctx.moveTo(s[0], s[1]); ctx.lineTo(s[2], s[3]); ctx.stroke();
          }
        });
        ctx.globalCompositeOperation = "source-over";
      } else {
        [[4, 0.07, gold], [1.15, 0.62, ink]].forEach(function (ps) {
          ctx.lineWidth = ps[0];
          for (var i = 0; i < segs.length; i++) {
            var s = segs[i], a = s[4] * ps[1];
            if (a < 0.004) continue;
            ctx.strokeStyle = col(ps[2], a);
            ctx.beginPath(); ctx.moveTo(s[0], s[1]); ctx.lineTo(s[2], s[3]); ctx.stroke();
          }
        });
      }
    }

    function draw(now) {
      var t = (now - born) / 1000;
      ctx.clearRect(0, 0, W, H);
      var key = W < 700 && pathName !== "sweep" ? "phone" : pathName;
      var ribbons = PATHS[key] || PATHS.flanks;
      var base = Math.max(24, Math.min(58, Math.min(W, H) * 0.058)) * (W < 700 ? 0.85 : 1);
      var segs = [];
      function depthA(z) { return 0.4 + 0.6 * smooth(Math.min(W, H) * 0.35, -Math.min(W, H) * 0.3, z); }

      ribbons.forEach(function (rb, ri) {
        var g = geometry(reduce ? 4 : t, rb.pts, ri);
        var half = base * rb.size;
        var reveal = reduce ? 1 : smooth(rb.delay, rb.delay + 2.6, t);
        if (reveal <= 0) return;
        var twistAt = function (u) { return u * rb.twist + (reduce ? 0 : t * 0.05 * (ri ? -1 : 1)); };

        // Four continuous rails.
        var step = 7, prev = null, maxD = g.total * reveal, d, k;
        for (d = 0; d <= maxD; d += step) {
          var fr = at(g, d), cs = corners(fr, half, twistAt(fr.u));
          if (prev) for (k = 0; k < 4; k++) {
            var a = cs[k], b = prev[k];
            segs.push([b[0], b[1], a[0], a[1], keep((a[0] + b[0]) / 2, (a[1] + b[1]) / 2) * depthA(a[2]) * 0.85, a[2]]);
          }
          prev = cs;
        }
        // Square frames, evenly spaced, drifting slowly along the body.
        var gap = half * 2.05, flow = reduce ? 0 : (t * 9) % gap;
        for (d = flow; d <= maxD; d += gap) {
          var f2 = at(g, d), q = corners(f2, half, twistAt(f2.u));
          var tip = smooth(maxD, maxD - gap * 2, d); // frames near the drawing tip fade in
          for (k = 0; k < 4; k++) {
            var p1 = q[k], p2 = q[(k + 1) % 4];
            segs.push([p1[0], p1[1], p2[0], p2[1], keep((p1[0] + p2[0]) / 2, (p1[1] + p2[1]) / 2) * depthA(p1[2]) * tip, p1[2]]);
          }
        }
      });
      stroke(segs, theme.dark);
    }

    function loop(now) {
      raf = 0;
      if (!visible || document.hidden) return;
      if (now - last >= 33) { last = now; draw(now); }
      raf = requestAnimationFrame(loop);
    }
    function start() { if (!reduce && !raf && visible && !document.hidden) raf = requestAnimationFrame(loop); }

    born = performance.now();
    if ("IntersectionObserver" in window) {
      new IntersectionObserver(function (e) { visible = e[0].isIntersecting; if (visible) start(); }, { rootMargin: "80px" }).observe(host);
    }
    document.addEventListener("visibilitychange", start);
    if ("ResizeObserver" in window) new ResizeObserver(size).observe(host.parentElement);
    window.addEventListener("resize", size);
    host.__ilrRedraw = function () { draw(performance.now()); };
    size();
    host.classList.add("is-ready");
    start();
  }

  var HEROES = "#landing-page .il-landing-hero, .il-static-page .hero, .il-static-page section.hero, .il-static-page section.intro, .lxp-hero, .lxl:not(.lxl-lesson) .lxl-hero, #public-main > .hero";
  function init() {
    readTheme();
    document.querySelectorAll(HEROES).forEach(function (h, i) {
      if (h.querySelector(".il-ribbon")) return;
      var r = document.createElement("div");
      r.className = "il-ribbon il-ribbon-hero";
      r.setAttribute("data-path", getComputedStyle(h).textAlign === "center" ? "flanks" : "sweep");
      r.setAttribute("data-seed", String((location.pathname.length + i * 5) % 11));
      h.classList.add("il-has-ribbon");
      h.insertBefore(r, h.firstChild);
    });
    document.querySelectorAll(".il-ribbon").forEach(mount);
    new MutationObserver(function () {
      readTheme();
      document.querySelectorAll(".il-ribbon").forEach(function (c) { if (c.__ilrRedraw) c.__ilrRedraw(); });
    }).observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
  }
  window.ILRibbon = { init: init, mount: mount };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();

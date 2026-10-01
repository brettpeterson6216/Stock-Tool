/* Ambient background: "market silk".

   A field of thin gold price lines drifting across the top of the page,
   layered by depth like strands of silk. One line is brighter and carries
   a glowing head, like the last tick on a live chart. It sits behind the
   content on every public page (homepage, pricing, Academy, sign-in,
   stock pages, info pages, member dashboard) so the site shares one
   living backdrop, and it is never shown in the research workspace,
   where the charts are the point.

   Canvas 2D, ~20fps, devicePixelRatio capped at 1.5, paused in background
   tabs and while the top of the page is scrolled away, one still frame
   under prefers-reduced-motion, colours read from the theme tokens. */
(function () {
  "use strict";
  if (window.__ilAmbient) return;
  window.__ilAmbient = true;

  var reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var canvas = document.createElement("canvas");
  if (!canvas.getContext) return;
  canvas.id = "il-ambient";
  canvas.setAttribute("aria-hidden", "true");
  var ctx = canvas.getContext("2d");
  if (!ctx) return;

  // Deterministic pseudo-random so every visit draws the same composition.
  var seed = 7;
  function rnd() { seed = (seed * 16807) % 2147483647; return (seed - 1) / 2147483646; }

  // Each strand is a sum of a few slow travelling waves plus a gentle drift,
  // which reads as a price path rather than a sine.
  var STRANDS = 16;
  var strands = [];
  for (var i = 0; i < STRANDS; i++) {
    var depth = i / (STRANDS - 1);                 // 0 = far, 1 = near
    var waves = [];
    for (var k = 0; k < 4; k++) {
      waves.push({
        f: (0.0016 + rnd() * 0.004) * (1 + k * 0.9),
        a: (0.04 + rnd() * 0.05) / (1 + k * 0.8),
        p: rnd() * Math.PI * 2,
        s: (0.000025 + rnd() * 0.00005) * (k % 2 ? -1 : 1)   // radians per ms: one swell every 1.5–4 minutes
      });
    }
    strands.push({
      base: 0.18 + 0.55 * (i / STRANDS) + (rnd() - 0.5) * 0.06,
      trend: (rnd() - 0.5) * 0.12,
      waves: waves,
      depth: depth,
      width: 0.6 + depth * 0.9,
      alpha: 0.07 + depth * 0.22
    });
  }
  var hero = strands[Math.floor(STRANDS * 0.62)];
  hero.width = 1.7; hero.alpha = 0.7; hero.hero = true;

  var W = 0, H = 0, dpr = 1, gold = "233,180,76", dark = true;
  function hexToRgb(v) {
    var m = /^#?([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})$/i.exec(String(v).trim());
    return m ? parseInt(m[1], 16) + "," + parseInt(m[2], 16) + "," + parseInt(m[3], 16) : null;
  }
  function readTheme() {
    var cs = getComputedStyle(document.documentElement);
    gold = hexToRgb(cs.getPropertyValue("--rp-gold-accent")) || gold;
    dark = document.documentElement.getAttribute("data-theme") === "dark";
  }
  function resize() {
    dpr = Math.min(1.5, window.devicePixelRatio || 1);
    W = window.innerWidth; H = Math.max(520, Math.min(window.innerHeight * 1.05, 980));
    canvas.width = Math.round(W * dpr); canvas.height = Math.round(H * dpr);
    canvas.style.height = H + "px";
  }

  function yAt(s, x, t) {
    var v = s.base + s.trend * (x / W - 0.5);
    for (var k = 0; k < s.waves.length; k++) {
      var w = s.waves[k];
      v += w.a * Math.sin(x * w.f + w.p + t * w.s);
    }
    return v * H;
  }

  function draw(t) {
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, W, H);
    var mult = dark ? 1 : 0.8;
    var step = Math.max(5, W / 260);

    for (var i = 0; i < strands.length; i++) {
      var s = strands[i];
      var g = ctx.createLinearGradient(0, 0, W, 0);
      var a = s.alpha * mult;
      g.addColorStop(0, "rgba(" + gold + ",0)");
      g.addColorStop(0.18, "rgba(" + gold + "," + (a * 0.6).toFixed(3) + ")");
      g.addColorStop(0.62, "rgba(" + gold + "," + a.toFixed(3) + ")");
      g.addColorStop(1, "rgba(" + gold + ",0)");
      ctx.strokeStyle = g;
      ctx.lineWidth = s.width;
      ctx.beginPath();
      for (var x = -step; x <= W + step; x += step) {
        var y = yAt(s, x, t);
        if (x < 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
      }
      ctx.stroke();

      if (s.hero) {
        // A soft area under the brightest strand, and a live "last tick".
        var fill = ctx.createLinearGradient(0, 0, 0, H);
        fill.addColorStop(0, "rgba(" + gold + "," + (0.07 * mult).toFixed(3) + ")");
        fill.addColorStop(1, "rgba(" + gold + ",0)");
        ctx.lineTo(W + step, H); ctx.lineTo(-step, H); ctx.closePath();
        ctx.save();
        ctx.globalCompositeOperation = "source-over";
        ctx.fillStyle = fill;
        ctx.globalAlpha = 0.9;
        ctx.fill();
        ctx.restore();

        var hx = W * 0.72, hy = yAt(s, hx, t);
        var pulse = (t % 4200) / 4200;
        var glow = ctx.createRadialGradient(hx, hy, 0, hx, hy, 26);
        glow.addColorStop(0, "rgba(" + gold + "," + (0.45 * mult).toFixed(3) + ")");
        glow.addColorStop(1, "rgba(" + gold + ",0)");
        ctx.fillStyle = glow;
        ctx.beginPath(); ctx.arc(hx, hy, 26, 0, Math.PI * 2); ctx.fill();
        ctx.fillStyle = "rgba(" + gold + "," + (0.95 * mult).toFixed(3) + ")";
        ctx.beginPath(); ctx.arc(hx, hy, 2.6, 0, Math.PI * 2); ctx.fill();
        ctx.strokeStyle = "rgba(" + gold + "," + ((1 - pulse) * 0.5 * mult).toFixed(3) + ")";
        ctx.lineWidth = 1;
        ctx.beginPath(); ctx.arc(hx, hy, 3 + pulse * 14, 0, Math.PI * 2); ctx.stroke();
      }
    }
  }

  var running = false, raf = 0, last = 0, clock = 0, onScreen = true;
  function loop(now) {
    raf = 0;
    if (!running) return;
    if (now - last >= 50) {                       // 20fps is plenty for a drift this slow
      clock += Math.min(100, last ? now - last : 50);
      last = now;
      draw(clock);
    }
    raf = requestAnimationFrame(loop);
  }
  function update() {
    var inTool = document.body.classList.contains("il-tool-active");
    canvas.style.display = inTool ? "none" : "";
    var want = !reduce && !document.hidden && onScreen && !inTool;
    if (want === running) return;
    running = want; last = 0;
    if (want && !raf) raf = requestAnimationFrame(loop);
  }

  function start() {
    document.body.insertBefore(canvas, document.body.firstChild);
    readTheme(); resize(); draw(4000);
    update();
    window.addEventListener("resize", function () { resize(); draw(clock || 4000); });
    document.addEventListener("visibilitychange", update);
    window.addEventListener("scroll", function () {
      var vis = window.scrollY < H * 0.95;
      if (vis !== onScreen) { onScreen = vis; update(); }
    }, { passive: true });
    new MutationObserver(function () { readTheme(); draw(clock || 4000); update(); })
      .observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
    new MutationObserver(update).observe(document.body, { attributes: true, attributeFilter: ["class"] });
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start);
  else start();
})();

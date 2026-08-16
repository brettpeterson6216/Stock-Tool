/* Implied Lens — premium motion layer.
   Progressive enhancement only. Nothing here is required for the page to
   function; if it never runs, every element is visible and interactive.
   Restrained by design: state on scroll, one reveal per element, no loops. */
(function () {
  "use strict";

  var reduced = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var root = document.documentElement;

  /* ── Nav condenses once the page leaves the top ─────────────────────────── */
  function initNavState() {
    var nav = document.querySelector("nav#main-nav, nav.il-global-nav");
    if (!nav) return;
    var ticking = false;
    function apply() {
      nav.classList.toggle("il-nav-scrolled", window.scrollY > 12);
      ticking = false;
    }
    window.addEventListener("scroll", function () {
      if (ticking) return;
      ticking = true;
      window.requestAnimationFrame(apply);
    }, { passive: true });
    apply();
  }

  /* ── Reveal on first scroll into view ───────────────────────────────────── */
  var REVEAL_GROUPS = [
    ["#landing-page .il-cap-head", 0],
    ["#landing-page .il-cap-card", 1],
    ["#landing-page .il-workflow-copy", 0],
    ["#landing-page .il-wf-panel", 1],
    ["#landing-page .il-landing-band", 0],
    ["#landing-page .il-landing-pricing", 0],
    [".il-page-hero", 0],
    [".il-static-card", 1]
  ];

  function initReveal() {
    if (reduced || !("IntersectionObserver" in window)) return;

    var targets = [];
    REVEAL_GROUPS.forEach(function (group) {
      var nodes = document.querySelectorAll(group[0]);
      for (var i = 0; i < nodes.length; i++) {
        if (nodes[i].hasAttribute("data-il-reveal")) continue;
        nodes[i].setAttribute("data-il-reveal", "");
        if (group[1]) {
          nodes[i].style.setProperty("--il-reveal-delay", Math.min(i, 5) * 0.07 + "s");
        }
        targets.push(nodes[i]);
      }
    });
    if (!targets.length) return;

    root.classList.add("il-motion");

    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (!entry.isIntersecting) return;
        entry.target.classList.add("il-revealed");
        io.unobserve(entry.target);
      });
    }, { rootMargin: "0px 0px -8% 0px", threshold: 0.08 });

    targets.forEach(function (el) {
      // Anything already on screen at load reveals immediately, so the first
      // paint is never blank.
      var box = el.getBoundingClientRect();
      if (box.top < window.innerHeight * 0.92) {
        el.classList.add("il-revealed");
      } else {
        io.observe(el);
      }
    });

    // Failsafe: content must never stay hidden. If anything is still waiting
    // after 4s (observer wedged, print, headless capture, odd scroll
    // container), reveal it unconditionally.
    window.setTimeout(function () {
      targets.forEach(function (el) { el.classList.add("il-revealed"); });
      io.disconnect();
    }, 4000);

    window.addEventListener("beforeprint", function () {
      targets.forEach(function (el) { el.classList.add("il-revealed"); });
    });
  }

  /* ── Hero mock follows the pointer, gently ──────────────────────────────── */
  function initHeroTilt() {
    if (reduced) return;
    if (window.matchMedia && window.matchMedia("(pointer: coarse)").matches) return;

    var stage = document.querySelector("#landing-page .il-landing-preview");
    var mock = stage && stage.querySelector(".il-hero-mock");
    if (!mock) return;

    var frame = null;
    function move(ev) {
      if (frame) return;
      frame = window.requestAnimationFrame(function () {
        frame = null;
        var box = stage.getBoundingClientRect();
        var dx = (ev.clientX - (box.left + box.width / 2)) / box.width;
        var dy = (ev.clientY - (box.top + box.height / 2)) / box.height;
        mock.style.transition = "transform .32s cubic-bezier(.16,1,.3,1)";
        mock.style.transform =
          "perspective(1800px) rotateY(" + (-3 + dx * 5).toFixed(2) + "deg) rotateX(" +
          (1 - dy * 4).toFixed(2) + "deg) translateY(-6px)";
      });
    }

    function leave() {
      mock.style.transition = "";
      mock.style.transform = "";
    }

    stage.addEventListener("mousemove", move);
    stage.addEventListener("mouseleave", leave);
  }

  function init() {
    try { initNavState(); } catch (e) {}
    try { initReveal(); } catch (e) {}
    try { initHeroTilt(); } catch (e) {}
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();

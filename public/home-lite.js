/* Signed-out home page without the application (see lib/home-lite.js).

   The landing page itself needs none of the app. What does need it is the
   handful of in-page routes into the app - the nav tabs, the mobile menu, the
   nav search - which on the full page switch views without a reload. Here
   they become real navigations to URLs that get the full page.

   Once the landing page has settled, the held-back scripts are prefetched at
   idle priority, so the first move into the app comes from the cache. */
(function () {
  "use strict";

  document.documentElement.setAttribute("data-il-lite", "1");

  function go(url) { window.location.href = url; }
  function toSection(id) {
    id = String(id || "analyze").replace(/[^a-z]/gi, "") || "analyze";
    go("/?view=tool&section=" + encodeURIComponent(id));
  }
  function toTicker(t) {
    t = String(t || "").trim().toUpperCase().replace(/[^A-Z0-9.\-^]/g, "").slice(0, 12);
    if (!t) return toSection("analyze");
    go("/?view=tool&section=analyze&symbol=" + encodeURIComponent(t));
  }

  var homeNav = window.navGoTo;
  window.navGoTo = function (id) {
    if (id === "home") return typeof homeNav === "function" ? homeNav("home") : undefined;
    toSection(id === "adveducation" ? "education" : id);
  };
  window.openSection = function (id) { toSection(id); };
  window.showMarketPage = function () { go("/?market=1"); };
  window.heroLoadTicker = toTicker;
  window.mobileTickerGo = function () {
    var el = document.getElementById("mmenu-ticker");
    toTicker(el && el.value);
  };
  // Without navSearchGo, site-nav.js lets the nav search form submit natively
  // to /?view=tool&section=analyze&symbol=…, which is the full page.
  try { delete window.navSearchGo; } catch (e) { window.navSearchGo = undefined; }
  if (typeof window._setMobileNav !== "function") window._setMobileNav = function () {};

  /* ── warm the cache ─────────────────────────────────────────────────── */
  function bundle() {
    try { return JSON.parse((document.getElementById("il-home-lite") || { dataset: {} }).dataset.bundle || "[]"); }
    catch (e) { return []; }
  }
  function frugal() {
    var c = navigator.connection;
    return !!(c && (c.saveData || /(^|-)2g$/.test(c.effectiveType || "")));
  }
  var warmed = false;
  function warm() {
    if (warmed || frugal()) return;
    warmed = true;
    bundle().forEach(function (href) {
      var l = document.createElement("link");
      l.rel = "prefetch";
      l.as = "script";
      l.href = href;
      document.head.appendChild(l);
    });
  }
  function later() {
    var idle = window.requestIdleCallback || function (fn) { return setTimeout(fn, 1); };
    setTimeout(function () { idle(warm, { timeout: 3000 }); }, 2500);
  }
  if (document.readyState === "complete") later();
  else window.addEventListener("load", later, { once: true });

  // A visitor reaching for the app should not wait for the idle timer.
  function intent(e) {
    var a = e.target && e.target.closest && e.target.closest('a[href*="view=tool"], #nav-search, #landing-search, [data-lx-ticker], .mobile-bottom-nav, #lx-demo-open');
    if (a) warm();
  }
  document.addEventListener("pointerover", intent, { passive: true });
  document.addEventListener("focusin", intent);
  document.addEventListener("touchstart", intent, { passive: true });
})();

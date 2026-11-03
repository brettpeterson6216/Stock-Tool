/* Signed-out home page without the application (see lib/home-lite.js).

   The landing page itself needs none of the app. What does need it is the
   handful of in-page routes into the app - the nav tabs, the mobile menu, the
   nav search - which on the full page switch views without a reload. Here
   they become real navigations to URLs that get the full page.

   When a visitor reaches for search or a stock, the rebuilt research page's
   few files are prefetched so the first move into the app is quick. */
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
    go(t ? "/research/" + encodeURIComponent(t) : "/research");
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

  /* ── warm the cache, on intent only (audit F08) ─────────────────────────
     The old version prefetched ~1.2 MB of the legacy application at idle on
     every visit. The likely next page is the rebuilt research page, whose
     whole set is a few small files; fetch those only once a visitor reaches
     for search, a stock or a research link. */
  var NEXT = [
    ["/app/lens.css", "style"], ["/app/stock.css", "style"],
    ["/app/core.js", "script"], ["/app/stock.js", "script"], ["/app/chart.js", "script"],
    ["/app/analysis.js", "script"], ["/app/valuation.js", "script"],
    ["/vendor/lightweight-charts.standalone.production.js", "script"],
  ];
  function frugal() {
    var c = navigator.connection;
    return !!(c && (c.saveData || /(^|-)2g$/.test(c.effectiveType || "")));
  }
  var warmed = false;
  function warm() {
    if (warmed || frugal()) return;
    warmed = true;
    NEXT.forEach(function (f) {
      var l = document.createElement("link");
      l.rel = "prefetch";
      l.as = f[1];
      l.href = f[0];
      document.head.appendChild(l);
    });
  }
  function intent(e) {
    var a = e.target && e.target.closest && e.target.closest('a[href^="/research"], a[href*="view=tool"], #nav-search, #landing-search, [data-lx-ticker], #lx-demo-open, il-top');
    if (a) warm();
  }
  document.addEventListener("pointerover", intent, { passive: true });
  document.addEventListener("focusin", intent);
  document.addEventListener("touchstart", intent, { passive: true });
})();

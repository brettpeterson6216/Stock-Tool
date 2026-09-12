/* ═══════════════════════════════════════════════════════════════════════════
   ONE HEADER, EVERY PAGE.

   The site had three different top bars. The landing page ran #main-nav at
   63px fixed; six static pages ran .il-global-nav at 60px sticky; the three
   auth pages ran a bare <nav> at 60px static with no tabs, no search and no
   account control; and the research terminal hid the bar altogether. So the
   bar changed height, changed positioning mode, lost half its controls and
   then vanished, depending on where you were.

   The markup is now identical on every page - byte for byte, which
   test/header-contract.test.js enforces - and this file supplies the behaviour
   that used to be spread across inline onclick attributes that only resolved
   on the landing page.

   It defers to the product implementations wherever they exist. On the SPA,
   app-navigation.js defines navGoTo / navSearchGo / navGoLensScore and
   app-legacy.js owns the theme toggle; this file must load after them and
   only fills in what is missing. Nothing here overwrites a function that is
   already defined.
   ═══════════════════════════════════════════════════════════════════════════ */
(function () {
  "use strict";

  var root = document.documentElement;
  var nav = document.getElementById("main-nav");
  if (!nav) return;

  // A pricing visit opens the existing plan chooser. It never starts checkout.
  // Capture the request before the application normalizes its initial URL.
  var pricingRequested = new URLSearchParams(location.search).get("pricing") === "1";
  function openPricing() {
    if (typeof window.showUpgradeModal !== "function") return false;
    window.showUpgradeModal(false, "pricing_navigation");
    return true;
  }
  if (pricingRequested && location.pathname === "/") {
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", openPricing, { once: true });
    } else openPricing();
  }

  /* ── active tab, derived from the URL rather than hand-marked per page ──
     Six copies of the markup meant six chances to mark the wrong tab, and
     several pages marked none. */
  function markActiveTab() {
    var path = location.pathname.replace(/\/+$/, "") || "/";
    var params = new URLSearchParams(location.search);
    var section = params.get("section") || "";
    var view = params.get("view") || "";

    /* No tab is the right answer on /login, /signup, /reset-password and the
       admin page - marking Dashboard there pointed at a page you were not on. */
    var want = "";
    if (path === "/" && view === "tool") {
      if (section === "reports" || section === "workspace") want = "reports";
      else want = "research";
    } else if (path === "/") want = "home";
    else if (path === "/lens-score") want = "lens-score";
    /* /blog keeps working and keeps lighting the Learn tab, because the tab's
       data-nav moved from "blog" to "learn" when it started pointing at the
       lessons — a reader who lands on the blog from a link should still see
       where they are. */
    else if (path === "/learn" || path.indexOf("/learn/") === 0 || path === "/blog") want = "learn";
    else if (path === "/pricing") want = "pricing";

    var tabs = nav.querySelectorAll(".nav-tab");
    for (var i = 0; i < tabs.length; i++) {
      var on = tabs[i].getAttribute("data-nav") === want;
      tabs[i].classList.toggle("active-tab", on);
      tabs[i].classList.toggle("active", on);
      if (on) tabs[i].setAttribute("aria-current", "page");
      else tabs[i].removeAttribute("aria-current");
    }
  }
  markActiveTab();
  window.addEventListener("popstate", markActiveTab);
  window.addEventListener("il:viewchange", function () { queueMicrotask(markActiveTab); });

  /* ── tabs ──────────────────────────────────────────────────────────────
     On the SPA, hand the click to navGoTo so the view switches without a
     document load. Anywhere else the href is a real URL and the browser
     handles it, which is why the markup no longer carries inline onclick
     attributes that referenced functions six of the pages never loaded. */
  var SECTION_FOR = { research: "analyze", screener: "screener", reports: "workspace" };
  nav.addEventListener("click", function (e) {
    // Preserve the browser's open-in-new-tab and open-in-new-window actions.
    if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
    var tab = e.target.closest ? e.target.closest(".nav-tab, .nav-logo") : null;
    if (!tab || !nav.contains(tab)) return;
    var key = tab.getAttribute("data-nav");
    if (!key) return;

    /* Pricing used to be intercepted here and turned into a modal over the
       landing page. A top tab that opens a modal cannot be marked active -
       markActiveTab derives the active tab from the URL, and the URL had not
       changed - which is why the Dashboard stayed lit while the pricing modal
       was open. It is a real page at /pricing now, so the link is left alone
       and the active state follows from the path like every other tab. */
    if (key === "reports" && typeof window.openWorkspaceWatchlist === "function") {
      e.preventDefault();
      window.openWorkspaceWatchlist();
      markActiveTab();
      return;
    }
    if (key === "lens-score" && typeof window.navGoLensScore === "function") {
      if (window.navGoLensScore(tab, e) === false) e.preventDefault();
      return;
    }
    if (typeof window.navGoTo !== "function") return;      // static page: follow the href
    if (key === "home" && location.pathname === "/") { e.preventDefault(); window.navGoTo("home"); markActiveTab(); return; }
    if (SECTION_FOR[key] && location.pathname === "/") { e.preventDefault(); window.navGoTo(SECTION_FOR[key]); markActiveTab(); return; }
  });

  /* ── search ────────────────────────────────────────────────────────────
     The form has a real action and hidden inputs, so it works with no
     JavaScript at all. navSearchGo takes over on the SPA. */
  var form = document.getElementById("nav-search");
  if (form) {
    form.addEventListener("submit", function (e) {
      if (typeof window.navSearchGo === "function") {
        var r = window.navSearchGo(e);
        if (r === false) e.preventDefault();
        return;
      }
      var input = document.getElementById("nav-ticker-input");
      var v = input && input.value ? input.value.trim().toUpperCase() : "";
      if (!v) { e.preventDefault(); return; }
      if (input) input.value = v;
    });
  }

  /* ── theme ─────────────────────────────────────────────────────────────
     app-legacy.js owns toggleTheme on the SPA (it also has charts to recolour).
     Everywhere else this is the implementation. Either way the choice is
     written to the same key theme-bootstrap.js reads before first paint. */
  var btn = document.getElementById("theme-toggle-btn");

  function isDark() { return root.getAttribute("data-theme") === "dark"; }

  function syncToggle() {
    if (!btn) return;
    var dark = isDark();
    var next = dark ? "light" : "dark";
    btn.setAttribute("aria-pressed", String(dark));
    btn.setAttribute("aria-label", "Switch to " + next + " mode");
    btn.title = "Switch to " + next + " mode";
  }

  if (btn && typeof window.toggleTheme !== "function") {
    window.toggleTheme = function () {
      var dark = !isDark();
      if (dark) root.setAttribute("data-theme", "dark");
      else root.removeAttribute("data-theme");
      try { localStorage.setItem("il-theme", dark ? "dark" : "light"); } catch (e) {}
      if (typeof window.syncBrowserChrome === "function") window.syncBrowserChrome();
      syncToggle();
    };
    btn.addEventListener("click", window.toggleTheme);
  }
  syncToggle();

  /* ── mobile affordances ────────────────────────────────────────────────
     _toggleMobileMenu and navAccountTap live in app-legacy.js. The markup is
     shared, so the buttons exist on pages that never load it; without these
     fallbacks they threw ReferenceError on tap. */
  if (typeof window._toggleMobileMenu !== "function") {
    window._toggleMobileMenu = function () {
      var toggle = nav.querySelector(".lp-static-menu-toggle");
      if (toggle) toggle.click();
    };
  }
  // The application drawer is a disclosure, so focus may leave it normally.
  // Keep every trigger in sync, including when navigation closes the drawer.
  var appDrawer = document.getElementById("mobile-more-menu");
  if (appDrawer) {
    var triggers = document.querySelectorAll(".prime-nav-menu, .prime-mobile-appbar button, #mbn-more");
    var lastTrigger = null;
    var wasOpen = false;
    appDrawer.setAttribute("role", "region");
    appDrawer.setAttribute("aria-label", "Research navigation");
    function syncAppDrawer() {
      var open = appDrawer.classList.contains("open");
      appDrawer.setAttribute("aria-hidden", String(!open));
      triggers.forEach(function (trigger) {
        trigger.setAttribute("aria-controls", "mobile-more-menu");
        trigger.setAttribute("aria-expanded", String(open));
      });
      if (open && !wasOpen) {
        lastTrigger = document.activeElement;
        var input = appDrawer.querySelector('input:not([type="hidden"]), a[href], button');
        if (input) input.focus();
      }
      wasOpen = open;
    }
    syncAppDrawer();
    new MutationObserver(syncAppDrawer).observe(appDrawer, { attributes: true, attributeFilter: ["class"] });
    document.addEventListener("keydown", function (event) {
      if (event.key !== "Escape" || !appDrawer.classList.contains("open")) return;
      event.preventDefault();
      appDrawer.classList.remove("open");
      if (lastTrigger && typeof lastTrigger.focus === "function") lastTrigger.focus();
    });
    document.addEventListener("focusin", function (event) {
      if (!appDrawer.classList.contains("open") || appDrawer.contains(event.target)) return;
      if (Array.prototype.indexOf.call(triggers, event.target) === -1) appDrawer.classList.remove("open");
    });
    window.addEventListener("resize", function () {
      if (window.innerWidth > 900) appDrawer.classList.remove("open");
    });
  }
  if (typeof window.navAccountTap !== "function") {
    window.navAccountTap = function () {
      var acct = nav.querySelector(".il-global-account");
      location.href = acct ? acct.getAttribute("href") : "/login";
    };
  }
}());

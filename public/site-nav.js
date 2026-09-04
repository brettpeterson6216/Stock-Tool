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
      else if (section === "screener") want = "screener";
      else want = "screener";
    } else if (path === "/") want = "home";
    else if (path === "/lens-score") want = "lens-score";
    else if (path === "/blog") want = "blog";
    else if (path === "/signup" || path === "/pricing") want = "pricing";

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

  /* ── tabs ──────────────────────────────────────────────────────────────
     On the SPA, hand the click to navGoTo so the view switches without a
     document load. Anywhere else the href is a real URL and the browser
     handles it, which is why the markup no longer carries inline onclick
     attributes that referenced functions six of the pages never loaded. */
  var SECTION_FOR = { screener: "screener", reports: "reports" };
  nav.addEventListener("click", function (e) {
    var tab = e.target.closest ? e.target.closest(".nav-tab, .nav-logo") : null;
    if (!tab || !nav.contains(tab)) return;
    var key = tab.getAttribute("data-nav");
    if (!key) return;

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
    window._toggleMobileMenu = function () { nav.classList.toggle("il-nav-open"); };
  }
  if (typeof window.navAccountTap !== "function") {
    window.navAccountTap = function () {
      var acct = nav.querySelector(".il-global-account");
      location.href = acct ? acct.getAttribute("href") : "/login";
    };
  }
}());

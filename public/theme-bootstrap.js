(function () {
  "use strict";

  /* Lens Prime is a deliberately dark, graphite-and-gold product surface, so
     dark is the default for a first visit. It was also the ONLY outcome: this
     line used to set data-theme="dark" unconditionally on every page load and
     never read the preference that toggleTheme() and static-theme.js both
     write to localStorage under "il-theme". Choosing light and then clicking
     any tab put you straight back into dark, on every page, forever - which
     made the toggle look broken rather than ignored.

     Read the stored choice here, in the blocking <head> script, so the first
     frame is already correct and there is no flash of the wrong theme. Light
     is expressed by removing the attribute, which is the convention
     toggleTheme() already uses. */
  try {
    var savedTheme = localStorage.getItem("il-theme");
    if (savedTheme === "light") document.documentElement.removeAttribute("data-theme");
    else document.documentElement.setAttribute("data-theme", "dark");
  } catch (e) {
    document.documentElement.setAttribute("data-theme", "dark");
  }

  window.syncBrowserChrome = function () {
    var dark = document.documentElement.getAttribute("data-theme") === "dark";
    var color = document.querySelector('meta[name="theme-color"]');
    var status = document.querySelector('meta[name="apple-mobile-web-app-status-bar-style"]');
    if (color) color.setAttribute("content", dark ? "#07080B" : "#F6F4EF");
    if (status) status.setAttribute("content", dark ? "black-translucent" : "default");
  };

  window.syncBrowserChrome();

  /* ── session hint, stamped before first paint ────────────────────────────
     The static pages resolve the session with a fetch in static-auth.js, which
     is `defer`red — so it cannot run until after the document has parsed and
     painted. That meant a signed-in visitor saw "Log in / Start trial" for a
     frame on every static page, which is most of why the LensScore tab looked
     like it had signed them out.

     This script is a blocking <head> script, so it runs before anything is
     painted. It cannot touch the nav (no <body> yet), but it can stamp the
     root element, and CSS keys off that. static-auth.js still does the real
     check and corrects this if the hint turns out to be wrong. */
  try {
    var hint = JSON.parse(localStorage.getItem("il-auth-hint") || "null");
    var fresh = hint && typeof hint.in === "boolean" && (Date.now() - (hint.at || 0)) < 864e5;
    document.documentElement.classList.add(
      fresh ? (hint.in ? "il-hint-in" : "il-hint-out") : "il-hint-unknown"
    );
  } catch (e) {
    document.documentElement.classList.add("il-hint-unknown");
  }

  /* ── which view and section, resolved before first paint ─────────────────
     Measured on a cold load of /?view=tool&section=screener:

       +443ms   nothing laid out yet, document 4222px tall
       +1082ms  the Research chart section is on screen, sidebar showing all
                18 items
       +1361ms  it is replaced by Screener and the sidebar drops to 8

     So the answer to "why are the research tab and the screener tab open at
     the same time" is that they are not open at the same time - the wrong one
     paints first for about a third of a second and then swaps. Same reason
     the page "completely changes" on a refresh: the tab row starts at x=200
     and lands at 266.5 while the document height falls from 4795 to 3158.

     app-navigation.js resolves all of this correctly, but it is a deferred
     script, so it cannot run until the document has parsed. This runs in the
     head, before anything is painted, and stamps the answer on <html> for CSS
     to key off. app-navigation.js still does the real work and corrects this
     if it disagrees. */
  try {
    var GROUPS = {
      research: ["analyze", "financials", "advmetrics", "earnings", "calls", "secfilings", "institutional", "screener"],
      projections: ["projection", "dcf"],
      comparison: ["compare"],
      planner: ["wealth"],
      learn: ["education", "adveducation"],
      saved: ["reports", "workspace"]
    };
    var params = new URLSearchParams(window.location.search);
    var view = params.get("view") === "tool" ? "tool" : "home";
    var section = (params.get("section") || "").replace(/[^a-z]/gi, "");
    if (view === "tool") {
      if (!section) section = "analyze";
      var group = "research";
      for (var key in GROUPS) if (GROUPS[key].indexOf(section) !== -1) { group = key; break; }
      document.documentElement.setAttribute("data-boot-view", "tool");
      document.documentElement.setAttribute("data-boot-section", section);
      document.documentElement.setAttribute("data-boot-group", group);

      /* Written as a stylesheet rather than as attribute selectors in
         clean-pass.css, because the section and the group are known here and
         enumerating every combination in a static sheet would be sixty
         selectors that have to stay in step with NAV_GROUPS by hand.
         app-navigation.js removes this element once it has done the real
         work, so nothing here can outlive the load. */
      var css =
        "#view-home{display:none!important}" +
        "#view-tool{display:flex!important;flex-direction:column!important}" +
        "#view-tool .app-section>.acc-body{display:none!important}" +
        '#view-tool #sec-' + section + ">.acc-body{display:block!important}" +
        ".app-sidebar .sb-item{display:none!important}" +
        GROUPS[group].map(function (s) {
          return '.app-sidebar .sb-item[data-sec="' + s + '"]{display:flex!important}';
        }).join("");
      var style = document.createElement("style");
      style.id = "il-boot-view";
      style.textContent = css;
      document.head.appendChild(style);
    } else {
      document.documentElement.setAttribute("data-boot-view", "home");
    }
  } catch (e) {
    document.documentElement.setAttribute("data-boot-view", "home");
  }
})();

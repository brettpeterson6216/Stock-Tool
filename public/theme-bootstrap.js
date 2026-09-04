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
})();

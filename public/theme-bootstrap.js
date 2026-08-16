(function () {
  "use strict";

  // Dark is the default surface for the product. Light stays available and is
  // honoured whenever the visitor has explicitly chosen it.
  var storedTheme = localStorage.getItem("il-theme");
  if (storedTheme !== "light") document.documentElement.setAttribute("data-theme", "dark");

  window.syncBrowserChrome = function () {
    var dark = document.documentElement.getAttribute("data-theme") === "dark";
    var color = document.querySelector('meta[name="theme-color"]');
    var status = document.querySelector('meta[name="apple-mobile-web-app-status-bar-style"]');
    if (color) color.setAttribute("content", dark ? "#07080B" : "#F6F4EF");
    if (status) status.setAttribute("content", dark ? "black-translucent" : "default");
  };

  window.syncBrowserChrome();
})();

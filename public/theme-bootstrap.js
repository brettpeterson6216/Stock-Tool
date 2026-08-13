(function () {
  "use strict";

  var storedTheme = localStorage.getItem("il-theme");
  if (storedTheme === "dark") document.documentElement.setAttribute("data-theme", "dark");

  window.syncBrowserChrome = function () {
    var dark = document.documentElement.getAttribute("data-theme") === "dark";
    var color = document.querySelector('meta[name="theme-color"]');
    var status = document.querySelector('meta[name="apple-mobile-web-app-status-bar-style"]');
    if (color) color.setAttribute("content", dark ? "#12100D" : "#f9f8f5");
    if (status) status.setAttribute("content", dark ? "black-translucent" : "default");
  };

  window.syncBrowserChrome();
})();

/* The not-found page names what was asked for, so a mistyped ticker is
   explained rather than silently dropped (audit F17). */
(function () {
  "use strict";
  var m = location.pathname.match(/^\/(?:research|stock)\/([^/]+)/i);
  if (!m) return;
  var raw = decodeURIComponent(m[1]).slice(0, 24);
  var title = document.getElementById("nf-title"), text = document.getElementById("nf-text");
  if (title) title.textContent = "“" + raw + "” isn’t a ticker we recognise.";
  if (text) text.textContent = "Tickers are letters and numbers, like NVDA or BRK.B. Search by company name above, or try one of these.";
  document.title = "Ticker not found · ImpliedLens";
})();

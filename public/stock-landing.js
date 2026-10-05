/* Stock landing pages (/stock/:ticker): analytics and acquisition context.
   This used to be an inline <script>, which the site's Content-Security-Policy
   blocks, so no landing view or CTA click was ever recorded. */
(function () {
  "use strict";
  var ctx = {};
  try { ctx = JSON.parse(document.getElementById("il-landing-context").textContent) || {}; } catch (_) {}
  var analyzeUrl = ctx.analyzeUrl; delete ctx.analyzeUrl;
  var params = new URLSearchParams(window.location.search);

  function track(event, properties) {
    var referrerHost = "";
    try { referrerHost = document.referrer ? new URL(document.referrer).hostname : ""; } catch (_) {}
    var props = Object.assign({}, ctx, properties || {}, {
      referrer_host: referrerHost || null,
      utm_source: params.get("utm_source"),
      utm_medium: params.get("utm_medium"),
      utm_campaign: params.get("utm_campaign"),
    });
    try {
      fetch("/api/track", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ event: event, properties: props }), keepalive: true }).catch(function () {});
    } catch (_) {}
  }

  var acquisition = { source: "stock_landing" };
  ["utm_source", "utm_medium", "utm_campaign"].forEach(function (k) { if (params.get(k)) acquisition[k] = params.get(k); });
  try { sessionStorage.setItem("ilAcquisitionContext", JSON.stringify(acquisition)); } catch (_) {}

  ["analyze-cta", "landing-signup-cta"].forEach(function (id) {
    var link = document.getElementById(id);
    if (!link) return;
    var url = new URL(link.href, window.location.origin);
    ["utm_source", "utm_medium", "utm_campaign"].forEach(function (k) { if (acquisition[k]) url.searchParams.set(k, acquisition[k]); });
    link.href = url.toString();
  });

  track("landing_page_view", {});
  var a = document.getElementById("analyze-cta");
  if (a) a.addEventListener("click", function () { track("landing_cta_clicked", { destination: "analyzer" }); });
  var s = document.getElementById("landing-signup-cta");
  if (s) s.addEventListener("click", function () { track("guest_signup_started", { source: "stock_landing" }); });

  if (params.get("autoload") === "1" && analyzeUrl && analyzeUrl.charAt(0) === "/") window.location.href = analyzeUrl;
})();

/* ImpliedLens icon set.

   One family drawn for this product: a 24px grid, a single 1.5px stroke,
   round caps and joins, no fills. It replaces the stock icon font in the
   places that carry the brand (the side menus, the section headers and the
   tool cards). Everything else keeps the icon font.

   The swap is non-destructive: the original <i class="ti ti-…"> stays in the
   DOM (other code sets its className, e.g. the section header), and the SVG
   is drawn inside it. A MutationObserver picks up markup that other scripts
   build later (Call Research and Wealth Planner menu items, section intros,
   the header icon that changes on every navigation). */
(function () {
  "use strict";

  var P = {
    chart: '<path d="M6 4v3M6 15v5M12 3v4M12 13v8M18 6v3M18 16v3"/><rect x="4.25" y="7" width="3.5" height="8" rx=".75"/><rect x="10.25" y="7" width="3.5" height="6" rx=".75"/><rect x="16.25" y="9" width="3.5" height="7" rx=".75"/>',
    financials: '<path d="M4 20h16"/><path d="M6.5 20v-7M11 20V8M15.5 20v-5M20 20V5"/>',
    metrics: '<path d="M4.5 16.5a7.5 7.5 0 1 1 15 0"/><path d="M12 16.5l3.4-4.2"/><circle cx="12" cy="16.5" r="1.2"/>',
    earnings: '<rect x="4" y="5" width="16" height="15" rx="2.5"/><path d="M4 9.5h16M8.5 3v4M15.5 3v4"/><path d="m9 14.5 2 2 4-4"/>',
    calls: '<path d="M4 12h1M7.5 8.5v7M10.5 5.5v13M13.5 9v6M16.5 7v10M19.5 11v2"/>',
    filings: '<path d="M14 3.5H7a1 1 0 0 0-1 1v15a1 1 0 0 0 1 1h10a1 1 0 0 0 1-1V7.5Z"/><path d="M14 3.5v4h4M9.5 12h5M9.5 15.5h5"/>',
    ownership: '<path d="M12 4a8 8 0 1 0 8 8h-8Z"/><path d="M15 3.6a8 8 0 0 1 5.4 5.4H15Z"/>',
    screener: '<path d="M4 6h16M7 12h10M10 18h4"/>',
    compare: '<path d="M8 4v16M16 4v16"/><path d="M4 9h8M12 15h8"/>',
    valuation: '<path d="M12 4v16M8 20h8M5 7.5h14"/><path d="M5 7.5 2.5 13a2.5 2.5 0 0 0 5 0Zm14 0L16.5 13a2.5 2.5 0 0 0 5 0Z"/>',
    scenarios: '<path d="M4 16c5 0 8.5-2 16-9M4 16c5 0 9.5-.5 16-2M4 16c5 0 9.5 1 16 4"/>',
    wealth: '<path d="M4 19c6 0 10-4 15-13"/><path d="M14.5 6H19v4.5"/>',
    lessons: '<path d="M3.5 6.5c3-1.3 5.8-1.3 8.5.5 2.7-1.8 5.5-1.8 8.5-.5V19c-3-1.3-5.8-1.3-8.5.5-2.7-1.8-5.5-1.8-8.5-.5Z"/><path d="M12 7v12.5"/>',
    glossary: '<path d="M4.5 18 9 6l4.5 12M6.2 14h5.6"/><path d="M16.5 10h3M16.5 14h3M16.5 18h3"/>',
    saved: '<path d="M7 3.5h10a.5.5 0 0 1 .5.5v16l-5.5-3.6L6.5 20V4a.5.5 0 0 1 .5-.5Z"/>',
    thesis: '<path d="M4 20h7"/><path d="M15.5 4.5l4 4L9 19H5v-4Z"/>',
    portfolio: '<circle cx="12" cy="12" r="8"/><circle cx="12" cy="12" r="3.5"/><path d="M12 4v4.5M19.4 14.6l-4.1-1.4M6.5 17.6l3-3.1"/>',
    watchlist: '<path d="M12 4.2l2.3 4.8 5.2.7-3.8 3.6.9 5.2-4.6-2.5-4.6 2.5.9-5.2-3.8-3.6 5.2-.7Z"/>',
    overview: '<circle cx="12" cy="12" r="8"/><path d="M4 12h16M12 4c2.4 2.3 3.5 5 3.5 8s-1.1 5.7-3.5 8c-2.4-2.3-3.5-5-3.5-8s1.1-5.7 3.5-8Z"/>',
    breadth: '<path d="M3 12h4l2.5-6 5 12 2.5-6h4"/>',
    movers: '<path d="M8 19V5M4.5 8.5 8 5l3.5 3.5M16 5v14M12.5 15.5 16 19l3.5-3.5"/>',
    insights: '<path d="M9.5 17.5h5M10.5 20.5h3"/><path d="M8.6 14.6a5.5 5.5 0 1 1 6.8 0c-.7.5-.9 1.2-.9 1.9v1h-5v-1c0-.7-.2-1.4-.9-1.9Z"/>',
    lens: '<circle cx="12" cy="12" r="8"/><circle cx="12" cy="12" r="3.75"/><path d="M12 2.5v3M12 18.5v3M2.5 12h3M18.5 12h3"/>',
    dashboard: '<rect x="4" y="4" width="7" height="9" rx="1.25"/><rect x="13" y="4" width="7" height="5" rx="1.25"/><rect x="13" y="11" width="7" height="9" rx="1.25"/><rect x="4" y="15" width="7" height="5" rx="1.25"/>',
    news: '<rect x="4" y="5" width="13" height="14" rx="1.5"/><path d="M17 9h2.5v8.5a1.5 1.5 0 0 1-3 0M7.5 9h6M7.5 12.5h6M7.5 16h3.5"/>'
  };

  // Stock icon class -> ImpliedLens icon, for the branded places only.
  var MAP = {
    "chart-candle": "chart", "table": "financials", "report-money": "financials",
    "report-analytics": "metrics", "trending-up": "earnings", "chart-arrows-vertical": "earnings",
    "calendar-check": "earnings", "headphones": "calls", "file-text": "filings", "file-search": "filings",
    "file-certificate": "filings", "file-description": "filings", "building-bank": "ownership",
    "adjustments-horizontal": "compare", "arrows-diff": "compare", "filter": "screener",
    "focus-2": "lens", "target": "lens", "calculator": "valuation", "adjustments": "scenarios",
    "chart-dots-3": "wealth", "route": "wealth", "school": "lessons", "book-2": "glossary",
    "bookmark": "saved", "notes": "thesis", "chart-donut-3": "portfolio", "star": "watchlist",
    "globe": "overview", "activity": "breadth", "flame": "movers", "bulb": "insights",
    "layout-dashboard": "dashboard", "layout": "dashboard", "news": "news", "chart-line": "scenarios"
  };

  var SCOPE = [
    ".sb-item i.ti", ".hsb-item i.ti", ".prime-dash-nav i.ti", "i#ash-icon",
    ".il-sec-kicker i.ti", ".ihm-tool i.ti", ".lx-feats i.ti", ".lx-path-tag i.ti",
    ".il-up-feats i.ti", ".il-static-page .feat i.ti", ".il-static-page .research-item i.ti"
  ].join(",");

  function svg(name) {
    return '<svg class="il-ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" ' +
      'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">' + P[name] + "</svg>";
  }

  function nameFor(el) {
    for (var i = 0; i < el.classList.length; i++) {
      var c = el.classList[i];
      if (c.indexOf("ti-") === 0 && MAP[c.slice(3)]) return MAP[c.slice(3)];
    }
    return null;
  }

  function upgrade(el) {
    var name = nameFor(el);
    if (!name) {
      if (el.dataset.ilIcon) { if (el.classList.contains("il-ic-host")) el.classList.remove("il-ic-host"); el.innerHTML = ""; delete el.dataset.ilIcon; }
      return;
    }
    // classList.add() rewrites the attribute even when the class is already
    // there, which queues a mutation and would wake the observer forever.
    if (!el.classList.contains("il-ic-host")) el.classList.add("il-ic-host");
    if (el.dataset.ilIcon === name && el.firstElementChild) return;
    el.dataset.ilIcon = name;
    el.innerHTML = svg(name);
  }

  function scan(root) {
    var list = (root || document).querySelectorAll ? (root || document).querySelectorAll(SCOPE) : [];
    for (var i = 0; i < list.length; i++) upgrade(list[i]);
    if (root && root.matches && root.matches(SCOPE)) upgrade(root);
  }

  window.ILIcons = { svg: function (name) { return P[name] ? svg(name) : ""; }, names: Object.keys(P), scan: scan };

  function start() {
    scan(document);
    if (!("MutationObserver" in window)) return;
    var queued = false;
    new MutationObserver(function (records) {
      var added = false;
      for (var i = 0; i < records.length; i++) {
        var r = records[i];
        if (r.type === "attributes") {
          // The section header swaps its icon class on every navigation.
          if (r.target.matches && r.target.matches(SCOPE)) upgrade(r.target);
        } else if (r.addedNodes.length && !(r.target.classList && r.target.classList.contains("il-ic-host"))) {
          added = true; // ignore our own writes into an icon host
        }
      }
      if (!added || queued) return;
      queued = true;
      (window.requestAnimationFrame || setTimeout)(function () { queued = false; scan(document); });
    }).observe(document.body, { childList: true, subtree: true, attributes: true, attributeFilter: ["class"] });
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start);
  else start();
})();

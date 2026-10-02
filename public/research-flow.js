/* Research flow: the Chart & Analysis page as one reading order.

   The legacy markup is a two-column dashboard (charts left, a long rail
   right), which left the centre empty below the fold and shrank every
   indicator to a thumbnail. This module rearranges the SAME elements — ids
   untouched, so every renderer keeps working — into:

     price chart (full width, tall)
     insights row: analyst target · plain-English read · risk
     indicators: one large chart, tabbed (RSI, MACD, Volume, OBV, ATR, Returns)
     news (wide, two columns)  |  tools (Quick EPS, research coverage)

   No data logic lives here. */
(function () {
  "use strict";

  var TABS = [
    { id: "rsi-chart", label: "RSI" },
    { id: "macd-chart", label: "MACD" },
    { id: "vol-chart", label: "Volume" },
    { id: "obv-chart", label: "OBV" },
    { id: "atr-chart", label: "ATR" },
    { id: "dist-chart", label: "Returns" }
  ];
  var KEY = "il-ind-tab";

  function el(tag, cls, html) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (html != null) e.innerHTML = html;
    return e;
  }

  function resizeChart(canvas) {
    try {
      var c = window.Chart && Chart.getChart ? Chart.getChart(canvas) : null;
      if (c) c.resize();
    } catch (e) {}
  }

  function buildIndicators(main) {
    var panes = [];
    TABS.forEach(function (t) {
      var canvas = document.getElementById(t.id);
      var wrap = canvas && canvas.closest(".chart-wrap");
      if (wrap) panes.push({ tab: t, wrap: wrap, canvas: canvas });
    });
    if (!panes.length) return;
    var firstGrid = panes[0].wrap.closest(".g2");
    var panel = el("section", "il-ind-panel");
    panel.setAttribute("aria-label", "Indicators");
    var head = el("div", "il-ind-head");
    head.appendChild(el("div", "il-ind-title", "Indicators"));
    var tabs = el("div", "il-ind-tabs");
    tabs.setAttribute("role", "tablist");
    head.appendChild(tabs);
    panel.appendChild(head);
    var body = el("div", "il-ind-body");
    panel.appendChild(body);

    var saved = null;
    try { saved = localStorage.getItem(KEY); } catch (e) {}

    function select(id) {
      panes.forEach(function (p) {
        var on = p.tab.id === id;
        p.wrap.hidden = !on;
        p.button.classList.toggle("on", on);
        p.button.setAttribute("aria-selected", String(on));
        if (on) requestAnimationFrame(function () { resizeChart(p.canvas); });
      });
      try { localStorage.setItem(KEY, id); } catch (e) {}
    }

    panes.forEach(function (p) {
      var b = el("button", "il-ind-tab", p.tab.label);
      b.type = "button";
      b.setAttribute("role", "tab");
      b.addEventListener("click", function () { select(p.tab.id); });
      p.button = b;
      tabs.appendChild(b);
      p.wrap.classList.add("il-ind-pane");
      body.appendChild(p.wrap);
    });

    if (firstGrid) firstGrid.before(panel); else main.appendChild(panel);
    main.querySelectorAll(".g2").forEach(function (g) { if (!g.querySelector(".chart-wrap")) g.remove(); });
    var start = panes.some(function (p) { return p.tab.id === saved; }) ? saved : panes[0].tab.id;
    select(start);
  }


  /* ── Landing-style section intros ─────────────────────────────────────
     Every section opens the way the homepage does: a gold label, a big
     headline with a serif-italic accent, and one line of context. */
  var INTROS = {
    financials:   ["ti-report-money", "Financials", "What the business", "actually earns.", "Four years of income, balance sheet and cash flow, straight from SEC filings."],
    advmetrics:   ["ti-report-analytics", "Metrics", "Quality, price and", "the balance sheet.", "Valuation multiples, margins, returns and leverage in one view."],
    earnings:     ["ti-chart-arrows-vertical", "Earnings", "Promises versus", "results.", "Consensus estimates against reported earnings, quarter by quarter."],
    secfilings:   ["ti-file-search", "SEC filings", "Read the source,", "not the summary.", "Annual, quarterly and current reports direct from SEC EDGAR."],
    institutional:["ti-building-bank", "Ownership", "Who owns it,", "and who is moving.", "The largest institutional holders and weekly off-exchange volume."],
    compare:      ["ti-arrows-diff", "Compare", "Side by side,", "on equal terms.", "Up to four companies with normalized performance and fundamentals."],
    screener:     ["ti-filter", "Screener", "Find the candidates", "worth a closer look.", "Filter the market by value, size, income and momentum."],
    projection:   ["ti-calculator", "Valuation Lab", "What could it", "be worth?", "Bear, Base and Bull projections with every assumption editable."],
    dcf:          ["ti-calculator", "Valuation Lab", "What could it", "be worth?", "A discounted-cash-flow model with every assumption editable."],
    reports:      ["ti-bookmark", "Saved research", "Everything you have", "worked on.", "Saved analyses, models and notes, ready to pick back up."],
    education:    ["ti-school", "Academy", "Learn the method,", "one lesson at a time.", "Short, plain-English lessons with real examples and quick checks."]
  };
  // Sections that already open with their own headline get the serif accent.
  var ACCENTS = [
    ["#sec-calls .il-research-hero h2", "Listen for changes,", "not confidence."],
    ["#sec-wealth .il-research-hero h2", "Model the range,", "not a fantasy."],
    ["#sec-workspace .il-ws-intro h2", "Turn research into", "a reviewable decision."]
  ];

  function tickerNow() {
    try { return (window.S && S.ticker) || (window.IL_STATE && IL_STATE.ticker) || ""; } catch (e) { return ""; }
  }

  function intros() {
    Object.keys(INTROS).forEach(function (id) {
      var sec = document.getElementById("sec-" + id);
      if (!sec) return;
      var c = INTROS[id], hero = sec.querySelector(":scope > .il-sec-hero");
      if (!hero) {
        hero = el("header", "il-sec-hero");
        hero.innerHTML = '<span class="il-sec-kicker"><i class="ti ' + c[0] + '" aria-hidden="true"></i><span class="il-sec-label"></span></span>' +
          '<h2 class="il-sec-title">' + c[2] + ' <em>' + c[3] + '</em></h2><p class="il-sec-sub">' + c[4] + '</p>';
        sec.insertBefore(hero, sec.firstChild);
      }
      var t = tickerNow();
      hero.querySelector(".il-sec-label").textContent = c[1] + (t && id !== "screener" && id !== "reports" && id !== "education" ? " \u00b7 " + t : "");
    });
    ACCENTS.forEach(function (a) {
      var h = document.querySelector(a[0]);
      if (h && !h.querySelector("em")) h.innerHTML = a[1] + " <em>" + a[2] + "</em>";
    });
  }

  function build() {
    var layout = document.querySelector("#stock-result .dash-layout");
    if (!layout || layout.classList.contains("il-flow")) return;
    var main = layout.querySelector(".dash-main");
    var rail = layout.querySelector(".dash-sidebar");
    if (!main || !rail) return;
    layout.classList.add("il-flow");

    var price = main.querySelector(".chart-wrap");
    // Insights row. #il-plain-read is created later right after
    // #analyst-sidebar, so it lands in this row on its own.
    var insights = el("div", "il-insights");
    ["analyst-sidebar", "sidebar-risk"].forEach(function (id) {
      var n = document.getElementById(id);
      if (n) insights.appendChild(n);
    });
    var plain = document.getElementById("il-plain-read");
    if (plain) insights.insertBefore(plain, document.getElementById("sidebar-risk"));
    if (price) price.after(insights); else main.prepend(insights);

    buildIndicators(main);

    // News gets the wide column; the rail keeps the tools.
    var news = rail.querySelector(".news-section");
    var newsBox = news && news.closest(".panel-box");
    if (newsBox) {
      var col = el("div", "il-news-col");
      newsBox.classList.add("il-news-card");
      col.appendChild(newsBox);
      rail.before(col);
    }
    rail.classList.add("il-tools-col");

    // Research coverage is appended to the rail later; it reads better under
    // the news, so the two columns finish at similar heights.
    var newsCol = layout.querySelector(".il-news-col");
    function moveCoverage() {
      var cov = document.getElementById("il-coverage");
      if (cov && newsCol && cov.parentElement !== newsCol) newsCol.appendChild(cov);
    }
    moveCoverage();
    if (newsCol && "MutationObserver" in window) new MutationObserver(moveCoverage).observe(rail, { childList: true });
  }

  function init() {
    build();
    intros();
    var tool = document.getElementById("view-tool");
    if (tool && "MutationObserver" in window) {
      new MutationObserver(function () { intros(); }).observe(tool, { attributes: true, attributeFilter: ["data-active-section"] });
    }
    // A defensive second pass for late-built markup.
    setTimeout(function () { build(); intros(); }, 1500);
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();

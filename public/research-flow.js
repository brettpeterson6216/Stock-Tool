/* Research flow: the Chart & Analysis page as one reading order.

   The legacy markup is a two-column dashboard (charts left, a long rail
   right). This module rearranges the SAME elements — ids untouched, so every
   renderer keeps working — into one order a beginner can follow and a pro
   can skim (audit fix 6, Oct 2026):

     report card (stock-report-card.js) and key numbers
     price chart (full width; RSI and volume are panes inside it)
     read the chart (trend, momentum, volume in plain English)
     what is it worth (one valuation view, one link to the Valuation Lab)
     risk (five plain lines by default, every measure one click away)
     filings and research coverage
     more indicators (MACD, OBV, ATR, returns), folded away

   Removed from view, still rendered for the scripts that read them: the
   second RSI and volume charts, the plain-English bullet card (it repeated
   "Read the chart"), the mini risk card (it repeated the risk panel), the
   Quick EPS calculator and the Bear/Base/Bull teaser (the Valuation Lab does
   both, properly).

   No data logic lives here. */
(function () {
  "use strict";

  var TABS = [
    { id: "macd-chart", label: "MACD" },
    { id: "obv-chart", label: "OBV" },
    { id: "atr-chart", label: "ATR" },
    { id: "dist-chart", label: "Returns" }
  ];
  // Already panes of the main chart; their legacy copies are parked.
  var DUPLICATES = ["rsi-chart", "vol-chart"];
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

    var parked = parking(main);
    DUPLICATES.forEach(function (id) {
      var c = document.getElementById(id), w = c && c.closest(".chart-wrap");
      if (w) parked.appendChild(w);
    });
    // Folded away at the end of the page: useful to traders, noise to a beginner.
    var more = el("details", "il-ind-more");
    var sum = el("summary", "il-ind-more-sum", '<span>More indicators</span><small>MACD, on-balance volume, ATR, daily returns</small><b class="il-ind-chev" aria-hidden="true"></b>');
    more.appendChild(sum);
    more.appendChild(panel);
    more.addEventListener("toggle", function () {
      if (!more.open) return;
      panes.forEach(function (p) { if (!p.wrap.hidden) requestAnimationFrame(function () { resizeChart(p.canvas); }); });
    });
    var layout = main.closest(".dash-layout");
    (layout || main).appendChild(more);
    main.querySelectorAll(".g2").forEach(function (g) { if (!g.querySelector(".chart-wrap")) g.remove(); });
    var start = panes.some(function (p) { return p.tab.id === saved; }) ? saved : panes[0].tab.id;
    select(start);
  }

  /* A hidden holder for elements other scripts still fill or read. */
  function parking(scope) {
    var p = document.getElementById("il-flow-parked");
    if (!p) {
      p = el("div", "il-flow-parked");
      p.id = "il-flow-parked";
      p.hidden = true;
      p.setAttribute("aria-hidden", "true");
      (document.getElementById("stock-result") || scope).appendChild(p);
    }
    return p;
  }


  /* ── Landing-style section intros ─────────────────────────────────────
     Every section opens the way the homepage does: a gold label, a big
     headline with a serif-italic accent, and one line of context. */
  var INTROS = {
    financials:   ["ti-report-money", "Financials", "What the business", "actually earns.", "Four years of income, balance sheet and cash flow, straight from SEC filings."],
    advmetrics:   ["ti-report-analytics", "Metrics", "Quality, price and", "the balance sheet.", "Valuation multiples, margins, returns and leverage in one view."],
    earnings:     ["ti-chart-arrows-vertical", "Earnings", "Promises versus", "results.", "Reported earnings quarter by quarter, straight from SEC filings."],
    secfilings:   ["ti-file-search", "SEC filings", "Read the source,", "not the summary.", "Annual, quarterly and current reports direct from SEC EDGAR."],
    institutional:["ti-building-bank", "Ownership", "Who owns it,", "and who is moving.", "Famous investors' positions, insider buying and selling, and weekly off-exchange volume."],
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
    var parked = parking(main);

    var price = main.querySelector(".chart-wrap");
    // Analyst consensus shows only when a licensed feed supplies it; the row
    // disappears when the slot is empty.
    var insights = el("div", "il-insights");
    var analyst = document.getElementById("analyst-sidebar");
    if (analyst) insights.appendChild(analyst);
    if (price) price.after(insights); else main.prepend(insights);
    function tidyInsights() {
      ["il-plain-read", "sidebar-risk"].forEach(function (id) {
        var n = document.getElementById(id);
        if (n && n.parentElement !== parked) parked.appendChild(n);
      });
      insights.hidden = !analyst || !analyst.children.length;
    }
    tidyInsights();
    if ("MutationObserver" in window) {
      new MutationObserver(tidyInsights).observe(insights, { childList: true, subtree: true });
      new MutationObserver(tidyInsights).observe(rail, { childList: true });
    }

    // One valuation view, then risk, straight after the chart.
    var worth = document.getElementById("il-worth");
    var reads = document.getElementById("il-chart-reads");
    var risk = document.getElementById("risk-panel");
    if (reads) insights.after(reads);
    if (worth) (reads || insights).after(worth);
    if (risk) (worth || reads || insights).after(risk);
    ["il-quick-eps"].forEach(function (id) { var n = document.getElementById(id); if (n) parked.appendChild(n); });
    var lab = document.querySelector("#stock-result .il-lab-cta");
    if (lab) parked.appendChild(lab);

    buildIndicators(main);

    // Filings and news get the wide column; research coverage sits beside them.
    var news = rail.querySelector(".news-section");
    var newsBox = news && news.closest(".panel-box");
    if (newsBox) {
      var col = el("div", "il-news-col");
      newsBox.classList.add("il-news-card");
      col.appendChild(newsBox);
      rail.before(col);
    }
    rail.classList.add("il-tools-col");
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

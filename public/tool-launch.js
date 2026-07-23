/* ImpliedLens — tool empty-state enhancers: live market strip, tool launchpad,
   and a "continue where you left off" row. Keeps the no-ticker workspace from
   feeling blank. Self-contained; degrades gracefully if data/functions absent. */
(function () {
  "use strict";
  var IDX = [
    { t: "^GSPC", label: "S&P 500" },
    { t: "^IXIC", label: "Nasdaq" },
    { t: "^DJI", label: "Dow Jones" },
  ];
  function metaOf(j) { try { return j.chart.result[0].meta; } catch (e) { return null; } }
  function cell(label, valHtml, chgHtml) {
    return '<div class="twm-cell"><span class="twm-lbl">' + label + '</span><span class="twm-val">' + valHtml + '</span>' + (chgHtml || "") + "</div>";
  }
  async function loadMarketStrip() {
    var el = document.getElementById("tw-market");
    if (!el) return;
    el.innerHTML = IDX.map(function (i) { return cell(i.label, "—", ""); }).join("");
    try {
      var res = await Promise.allSettled(IDX.map(function (i) {
        return fetch("/api/quote/" + encodeURIComponent(i.t) + "?range=1d&preview=1", { credentials: "same-origin" }).then(function (r) { return r.ok ? r.json() : null; }).catch(function () { return null; });
      }));
      el.innerHTML = res.map(function (r, i) {
        var meta = r.status === "fulfilled" ? metaOf(r.value) : null;
        if (!meta) return cell(IDX[i].label, "—", "");
        var p = meta.regularMarketPrice != null ? meta.regularMarketPrice : meta.chartPreviousClose;
        var prev = meta.chartPreviousClose || p, chg = p - prev, pct = prev ? (chg / prev) * 100 : 0, up = chg >= 0;
        var val = Number(p).toLocaleString("en-US", { maximumFractionDigits: p >= 1000 ? 0 : 2 });
        var chgHtml = '<span class="twm-chg ' + (up ? "up" : "dn") + '">' + (up ? "▲" : "▼") + " " + Math.abs(pct).toFixed(2) + "%</span>";
        return cell(IDX[i].label, val, chgHtml);
      }).join("");
    } catch (e) { /* leave placeholders */ }
  }
  function renderLaunch() {
    var el = document.getElementById("tw-launch");
    if (!el) return;
    var tools = [
      ["projection", "ti-timeline", "Projection Lab", "Year-by-year Bear / Base / Bull revenue-to-price model."],
      ["dcf", "ti-calculator", "Valuation Lab", "DCF, exit P/E and EV/EBITDA with scenarios."],
      ["compare", "ti-arrows-split-2", "Compare", "Four stocks side by side, normalized."],
      ["screener", "ti-filter", "Screener", "Filter the market by value, size and momentum."],
    ];
    el.innerHTML = '<div class="tw-sec-lbl">Jump into a tool</div><div class="tw-launch-grid">' +
      tools.map(function (t) {
        return '<a class="tw-tool" href="#" onclick="if(typeof navGoTo===\'function\')navGoTo(\'' + t[0] + '\');return false;"><i class="ti ' + t[1] + '"></i><strong>' + t[2] + "</strong><span>" + t[3] + "</span></a>";
      }).join("") + "</div>";
  }
  function esc(s) { return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) { return ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]; }); }
  function renderContinue() {
    var el = document.getElementById("tw-continue");
    if (!el) return;
    var saved = [];
    try { if (typeof window.getSavedAnalyses === "function") saved = window.getSavedAnalyses() || []; } catch (e) {}
    var withTicker = saved.filter(function (a) { return a && a.ticker; }).slice(0, 4);
    if (!withTicker.length) { el.innerHTML = ""; return; }
    el.innerHTML = '<div class="tw-sec-lbl">Continue where you left off</div><div class="tw-recent-grid">' +
      withTicker.map(function (a) {
        var ttl = esc((a.title || a.type || "Saved analysis")).slice(0, 44);
        return '<a class="tw-recent-card" href="#" onclick="if(typeof heroLoadTicker===\'function\')heroLoadTicker(\'' + esc(a.ticker) + "');return false;\"><span class=\"tw-recent-tk\">" + esc(a.ticker) + '</span><span class="tw-recent-ttl">' + ttl + "</span></a>";
      }).join("") + "</div>";
  }
  var _stripLoaded = false;
  function render() {
    if (!document.getElementById("tw-market") && !document.getElementById("tw-launch")) return;
    // Only fetch the index strip when the tool view is actually visible — never on the
    // hidden landing page, where #tw-market exists but isn't shown. (audit P1-01)
    var vt = document.getElementById("view-tool");
    var toolVisible = vt && vt.style.display !== "none";
    if (toolVisible && !_stripLoaded) { _stripLoaded = true; loadMarketStrip(); }
    renderLaunch(); renderContinue();
  }
  window.renderToolLaunch = render;
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", render); else render();
})();

/* Under the research chart: "Read the chart" (plain-English reads of trend,
   momentum, volume and any recent golden/death cross) and "What is it
   worth?" (a Lens Charts range comparing four ways to value the company).

   Both are computed in the browser from data the page already has: the
   price rows chart-engine.js draws (it fires il-chart-rendered), the quote
   meta, the analyst targets and the consensus estimates. */
(function () {
  "use strict";

  var MON = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  function esc(s) { return String(s == null ? "" : s).replace(/[&<>"]/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]; }); }
  function day(t) { var d = new Date(t * 1000); return MON[d.getUTCMonth()] + " " + d.getUTCDate() + ", " + d.getUTCFullYear(); }
  function last(arr) { for (var i = arr.length - 1; i >= 0; i--) if (arr[i] != null) return arr[i]; return null; }

  var lastRows = null;

  /* ── Read the chart ───────────────────────────────────────────────────── */
  function reads(rows) {
    var host = document.getElementById("il-reads-grid"), wrap = document.getElementById("il-chart-reads");
    var TA = window.ILTA;
    if (!host || !wrap || !TA || !rows || rows.length < 30) { if (wrap) wrap.hidden = true; return; }
    var closes = rows.map(function (r) { return r.close; });
    var price = closes[closes.length - 1];
    var ma50 = last(TA.sma(closes, 50)), ma200 = last(TA.sma(closes, 200)), rsi = last(TA.rsi(closes, 14));
    var cards = [];

    // Trend
    if (ma50 != null) {
      var a50 = price > ma50, a200 = ma200 == null ? null : price > ma200, title, body, tone;
      if (a200 === null) {
        title = a50 ? "Above its 50-day average" : "Below its 50-day average";
        body = a50 ? "Over the last 50 sessions buyers have had the upper hand. Pick a longer range to see the 200-day."
                   : "Price is under where it has averaged for 50 sessions. Pick a longer range to see the 200-day.";
        tone = a50 ? "up" : "down";
      } else if (a50 && a200) {
        title = "Above both moving averages"; tone = "up";
        body = "Price sits over its 50-day and 200-day averages: buyers have been in control on both time frames.";
      } else if (!a50 && !a200) {
        title = "Below both moving averages"; tone = "down";
        body = "Price is under its 50-day and 200-day averages: sellers have had control. Watch whether it reclaims them.";
      } else if (a200) {
        title = "Dipped below the 50-day"; tone = "neutral";
        body = "Still above the long-run 200-day average, but the short-term trend has cooled.";
      } else {
        title = "Back above the 50-day"; tone = "neutral";
        body = "A short-term recovery, but price is still under its long-run 200-day average.";
      }
      cards.push({ kicker: "Trend", tone: tone, title: title, body: body });
    }

    // Momentum
    if (rsi != null) {
      var r0 = Math.round(rsi);
      cards.push({
        kicker: "Momentum", tone: "rsi",
        title: "RSI " + r0 + " · " + (rsi >= 70 ? "stretched" : rsi <= 30 ? "washed out" : "neutral"),
        body: rsi >= 70 ? "Above 70 means the run has been fast. Pullbacks are common from here, though strong trends can stay stretched."
            : rsi <= 30 ? "Below 30 means selling has been heavy. Bounces are common from here, though weak trends can stay washed out."
            : "Between 30 and 70: no extreme either way, so the trend matters more than momentum right now."
      });
    }

    // Volume
    var vols = rows.map(function (r) { return r.volume || 0; });
    var recent = vols.slice(-64, -1).filter(function (v) { return v > 0; });
    var lv = vols[vols.length - 1];
    if (recent.length >= 20 && lv > 0) {
      var avg = recent.reduce(function (s, v) { return s + v; }, 0) / recent.length, x = lv / avg;
      cards.push({
        kicker: "Volume", tone: "gold",
        title: x.toFixed(1) + "× its 3-month average",
        body: x >= 1.5 ? "Much heavier trading than usual: the latest move has real conviction behind it."
            : x >= 1.15 ? "Busier than usual: a little more conviction behind the latest move."
            : x <= 0.6 ? "Quiet trading. Moves on light volume are easier to reverse."
            : "Ordinary trading volume: no sign of a crowd rushing in or out."
      });
    }

    // The most recent cross, when it is recent enough to matter
    var crosses = typeof window.ILChartCrosses === "function" ? window.ILChartCrosses(rows) : [];
    var c = crosses[crosses.length - 1];
    if (c && rows.length - c.index <= 130) {
      var golden = c.kind === "golden";
      cards.push({
        kicker: "Learn · " + (golden ? "Golden cross" : "Death cross"), tone: golden ? "up" : "down", learn: true,
        title: (golden ? "Golden cross on " : "Death cross on ") + day(c.time),
        body: golden ? "The 50-day average crossed above the 200-day. Traders read it as a shift from downtrend to uptrend. It is a signal, not a guarantee."
                     : "The 50-day average crossed below the 200-day. Traders read it as a shift from uptrend to downtrend. It is a signal, not a guarantee."
      });
    }

    if (!cards.length) { wrap.hidden = true; return; }
    host.innerHTML = cards.map(function (k) {
      return '<div class="il-read' + (k.learn ? " is-learn" : "") + '">' +
        '<span class="il-read-kicker"><i class="il-read-dot is-' + k.tone + '" aria-hidden="true"></i>' + esc(k.kicker) + '</span>' +
        '<b class="il-read-title">' + esc(k.title) + '</b>' +
        '<span class="il-read-body">' + esc(k.body) + '</span></div>';
    }).join("");
    wrap.hidden = false;
  }

  /* ── What is it worth? ────────────────────────────────────────────────── */
  function worth() {
    var wrap = document.getElementById("il-worth"), host = document.getElementById("il-worth-chart");
    if (!wrap || !host || !window.LensCharts) return;
    var S = window.S || {}, meta = S.meta || {}, est = S.estimates || {};
    var price = Number(meta.regularMarketPrice);
    if (!(price > 0) && lastRows && lastRows.length) price = lastRows[lastRows.length - 1].close;
    var rows = [];

    // An EPS-based cash-flow model with cautious and hopeful growth around the consensus
    var eps = Number(est.nextYearEPS), g = Number(est.epsGrowth), wacc = Number(est.suggestedWACC) || 10;
    var M = window.ImpliedLensMath;
    if (eps > 0 && Number.isFinite(g) && M && M.epsDcf) {
      var run = function (g1, w) {
        g1 = Math.max(0, Math.min(50, g1));
        var res = M.epsDcf({ eps: eps, growth1: g1 / 100, growth2: g1 * 0.55 / 100, terminalGrowth: 0.03, discountRate: Math.max(5, w) / 100 });
        return res && res.ok ? res.intrinsic : null;
      };
      var mid = run(g, wacc), lo = run(g * 0.5, wacc + 1), hi = run(g * 1.4, wacc - 1);
      if (mid && lo && hi && hi < price * 6) rows.push({ name: "Cash-flow model", lo: Math.min(lo, hi), mid: mid, hi: Math.max(lo, hi),
        note: "10-year EPS model around consensus growth of " + g.toFixed(0) + "%" });
    }
    /* Earnings at a multiple between today's and a long-run norm (13x for
       financials, 20x otherwise), +-15%. A fixed 15-25x gave a bank and a
       chipmaker the same multiple. Uses next-year EPS when consensus exists,
       otherwise trailing EPS implied by the TTM P/E. */
    var pe = Number(meta.trailingPE), ttmEps = pe > 0 && price > 0 ? price / pe : NaN;
    var useEps = eps > 0 ? eps : ttmEps;
    if (useEps > 0) {
      var norm = /financ|bank|insur/i.test(S.sector || "") ? 13 : 20;
      var mid = pe > 0 ? Math.max(8, Math.min(40, 0.5 * Math.min(pe, 80) + 0.5 * norm)) : norm;
      rows.push({ name: "Earnings × " + Math.round(mid * 0.85) + "–" + Math.round(mid * 1.15) + " P/E", lo: useEps * mid * 0.85, mid: useEps * mid, hi: useEps * mid * 1.15,
        note: (eps > 0 ? "Next-year" : "Trailing") + " EPS $" + useEps.toFixed(2) + " at a multiple halfway from today's to a long-run " + norm + "×" });
    }
    // Wall Street price targets
    var at = S.analystTarget;
    if (at && at.low > 0 && at.high > 0) rows.push({ name: "Analyst targets", lo: at.low, mid: at.mean || null, hi: at.high });
    // Where it has actually traded
    if (meta.fiftyTwoWeekLow > 0 && meta.fiftyTwoWeekHigh > 0) rows.push({ name: "52-week range", lo: meta.fiftyTwoWeekLow, hi: meta.fiftyTwoWeekHigh, muted: true, note: "Lowest and highest price in the past year" });

    if (rows.length < 2 || !(price > 0)) { wrap.hidden = true; return; }
    wrap.hidden = false;
    window.LensCharts.range(host, {
      rows: rows, marker: { value: price, label: "Price" },
      format: function (v) { return "$" + (v >= 10 ? Math.round(v).toLocaleString("en-US") : v.toFixed(2)); },
      label: "Valuation ranges for " + (S.ticker || "this company") + " compared with today's price"
    });
  }

  /* On a phone the time-range strip scrolls sideways; keep the selected range
     in view (1Y, the default, otherwise sits off the right edge). */
  function centerRange() {
    var strip = document.getElementById("app-tf-strip");
    var on = strip && (strip.querySelector('.tf-pill[aria-pressed="true"]') || strip.querySelector(".tf-pill.active"));
    if (!strip || !on || strip.scrollWidth <= strip.clientWidth) return;
    var sr = strip.getBoundingClientRect(), ar = on.getBoundingClientRect();
    strip.scrollLeft = Math.max(0, strip.scrollLeft + (ar.left - sr.left) - (sr.width - ar.width) / 2);
  }

  document.addEventListener("il-chart-rendered", function (e) {
    try { centerRange(); } catch (err) {}
    lastRows = e.detail && e.detail.rows;
    try { reads(lastRows); } catch (err) {}
    try { worth(); } catch (err) {}
  });
  document.addEventListener("il-estimates", function () { try { worth(); } catch (err) {} });
})();

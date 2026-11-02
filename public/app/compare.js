/* ═══════════════════════════════════════════════════════════════════════════
   Compare: up to four stocks side by side. /compare?t=NVDA,AMD,AVGO

   Grades, valuation (including what growth each price implies), growth,
   margins, risk and the Lens Report's flags, with the best value in each row
   marked, and a one-year performance chart rebased to 0%.
   ═══════════════════════════════════════════════════════════════════════════ */
(function () {
  "use strict";
  var IL = window.IL, F = IL.fmt, h = IL.h, A = function () { return IL.analysis; };
  var MAX = 4;
  var COLORS = ["#E5B65A", "#6EA8FE", "#3CC9A0", "#F08A4B"];
  var PRESETS = [
    { label: "Chip makers", t: ["NVDA", "AMD", "AVGO", "INTC"] },
    { label: "Big tech", t: ["AAPL", "MSFT", "GOOGL", "AMZN"] },
    { label: "Retail", t: ["COST", "WMT", "TGT"] },
    { label: "Banks", t: ["JPM", "BAC", "WFC"] },
    { label: "Streaming", t: ["NFLX", "DIS", "SPOT"] },
  ];
  var tickers = [], data = {}, chart = null;

  function readUrl() {
    var q = new URLSearchParams(location.search).get("t") || "";
    tickers = q.split(",").map(function (x) { return x.trim().toUpperCase(); }).filter(function (x, i, a) { return /^[A-Z0-9.^-]{1,15}$/.test(x) && a.indexOf(x) === i; }).slice(0, MAX);
  }
  function writeUrl() {
    history.replaceState(null, "", "/compare" + (tickers.length ? "?t=" + tickers.join(",") : ""));
    document.title = (tickers.length ? tickers.join(" vs ") + " · " : "") + "Compare stocks · ImpliedLens";
  }

  function load(t) {
    if (data[t]) return data[t].ready;
    var d = data[t] = { t: t };
    d.ready = Promise.all([
      IL.api("/api/quote/" + t + "?range=2y"),
      IL.api("/api/lens-score/" + t + "?card=1"),
      IL.api("/api/fundamentals/history/" + t),
    ]).then(function (r) {
      d.quoteRes = r[0]; d.lensRes = r[1]; d.histRes = r[2];
      var s = r[0].ok ? IL.seriesFrom(r[0].data) : null;
      d.series = s;
      d.meta = s ? s.meta : {};
      d.p = s ? A().priceFacts(s.bars, s.meta) : null;
      d.g = r[1].ok && r[1].data.grades && r[1].data.grades.status === "graded" ? r[1].data.grades : null;
      d.f = r[2].ok ? A().fundamentals(r[2].data) : null;
      d.v = A().valuation(d.f, d.p, IL.n(d.meta.trailingPE));
      d.flags = A().flags({ fundamentals: d.f, price: d.p, grades: d.g, valuation: d.v });
      d.name = shortName(d.meta.shortName || d.meta.longName || (r[1].data && r[1].data.company) || t);
    });
    return d.ready;
  }
  function shortName(n) {
    n = String(n || "");
    if (n === n.toUpperCase()) n = n.toLowerCase().replace(/\b([a-z])/g, function (m) { return m.toUpperCase(); });
    return n.replace(/,? (Inc|Corp|Corporation|Co|Company|Ltd|Plc|Holdings|Group)\.?$/i, "");
  }

  /* Rows: label, value getter, formatter, which way is better, tip. */
  function grade(k) { return function (d) { var f = d.g && (d.g.factors || []).filter(function (x) { return x.key === k; })[0]; return f ? f.grade : null; }; }
  var GROUPS = [
    { title: "At a glance", rows: [
      { k: "Price", get: function (d) { return d.p && d.p.price; }, f: F.price },
      { k: "Today", get: function (d) { return d.p && d.p.chgPct; }, f: function (v) { return F.spct(v, 2); }, color: true },
      { k: "Market cap", get: function (d) { return IL.n(d.meta.marketCap); }, f: F.money },
      { k: "Past year", get: function (d) { return d.p && d.p.yearReturn; }, f: F.spct, color: true, better: "high" },
      { k: "LensScore", get: function (d) { return d.g ? Number(d.g.score) : null; }, f: function (v) { return v == null ? "—" : '<span class="pill ' + IL.scoreTone(v) + '">' + F.num(v, 1) + "</span>"; }, better: "high", html: true, tip: "0–10 grade against sector peers on value, growth, profitability, financial health and momentum." },
      { k: "Sector rank", withRow: true, get: function (d) { return d.g && d.g.rank ? d.g.rank.position / d.g.rank.of : null; }, f: function (v, d) { return d.g && d.g.rank ? "#" + d.g.rank.position + " of " + d.g.rank.of + " " + h(d.g.rank.sectorName || "") : "—"; }, html: true },
    ] },
    { title: "Grades against sector peers", rows: ["value", "growth", "profitability", "health", "momentum"].map(function (k) {
      return { k: { value: "Value", growth: "Growth", profitability: "Profitability", health: "Financial health", momentum: "Momentum" }[k], get: grade(k), rank: true, better: "high",
        f: function (v) { return IL.gchip(v); }, html: true };
    }) },
    { title: "Valuation", rows: [
      { k: "P/E (trailing)", get: function (d) { var v = IL.n(d.meta.trailingPE); return v > 0 ? v : null; }, f: F.mult, better: "low", tip: "Price divided by the last 12 months of earnings per share." },
      { k: "Price / sales", get: function (d) { var m = IL.n(d.meta.marketCap); return m && d.f && d.f.revenue ? m / d.f.revenue : null; }, f: F.mult, better: "low", tip: "Market cap divided by the last 12 months of revenue." },
      { k: "Growth the price needs", get: function (d) { return d.v && d.v.implied !== null ? d.v.implied * 100 : null; }, f: F.spct, better: "low", tip: "Yearly revenue growth over five years that today’s price assumes, at the base-case margin and P/E and a 10% return." },
      { k: "Growth delivered", get: function (d) { return d.v && d.v.delivered !== null ? d.v.delivered * 100 : null; }, f: F.spct, better: "high", color: true, tip: "Average yearly revenue growth over the last three years (or the last year when three are not available)." },
      { k: "Verdict", get: function (d) { return d.v && d.v.verdict ? d.v.verdict : null; }, f: function (v) { return v ? '<span class="tag ' + (v.tone === "good" ? "good" : v.tone === "bad" ? "bad" : "gold") + '">' + h(v.label) + "</span>" : "—"; }, html: true },
    ] },
    { title: "Growth and profit, last 12 months", rows: [
      { k: "Revenue", get: function (d) { return d.f && d.f.revenue; }, f: F.money },
      { k: "Revenue growth", get: function (d) { return d.f && d.f.growth1y; }, f: F.spct, color: true, better: "high" },
      { k: "Gross margin", get: function (d) { return d.f && d.f.grossMargin; }, f: F.pct, better: "high" },
      { k: "Operating margin", get: function (d) { return d.f && d.f.opMargin; }, f: F.pct, better: "high" },
      { k: "Net margin", get: function (d) { return d.f && d.f.netMargin; }, f: F.pct, better: "high" },
      { k: "Free cash flow margin", get: function (d) { return d.f && d.f.fcfMargin; }, f: F.pct, better: "high" },
      { k: "Share count, 1 year", get: function (d) { return d.f && d.f.shareChange; }, f: F.spct, better: "low", tip: "Change in diluted shares. Falling means buybacks; rising means each share owns less." },
    ] },
    { title: "Risk, past year", rows: [
      { k: "Typical yearly swing", get: function (d) { return d.p && d.p.vol; }, f: F.pct, better: "low" },
      { k: "Worst drop from a high", get: function (d) { return d.p && d.p.drawdown; }, f: F.spct, better: "high" },
      { k: "Beta", get: function (d) { var b = IL.n(d.meta.beta); return b; }, f: function (v) { return F.num(v, 2); } },
    ] },
  ];

  function render() {
    var main = document.getElementById("main");
    main.innerHTML =
      '<div class="cmp-head hero-band card prime" id="cmp-hero"><div class="stack" style="gap:10px">' + IL.eyebrow("Compare", "research") + '<h1 class="display">Side by side, <em>honestly.</em></h1><p class="muted">Up to four companies side by side: grades, what each price assumes, growth, margins and risk.</p></div></div>' +
      '<div class="cmp-pick card">' +
        '<div class="cmp-chips" id="cmp-chips">' + tickers.map(function (t, i) {
          return '<span class="cmp-chip"><i style="background:' + COLORS[i] + '"></i><a href="/research/' + h(t) + '">' + h(t) + '</a><button type="button" data-rm="' + h(t) + '" aria-label="Remove ' + h(t) + '">×</button></span>';
        }).join("") +
        (tickers.length < MAX ? '<div class="il-search cmp-add" role="search"><label class="il-search-box">' + IL.icon("search") + '<input id="cmp-q" type="search" autocomplete="off" placeholder="' + (tickers.length ? "Add a company" : "Add a company or ticker") + '" aria-label="Add a company to compare" role="combobox" aria-expanded="false" aria-controls="cmp-sugg"></label><div class="il-sugg" id="cmp-sugg" role="listbox" hidden></div></div>' : "") +
        "</div>" +
        '<div class="row wrap cmp-presets"><span class="faint">Try:</span>' + PRESETS.map(function (p, i) { return '<button class="tag" type="button" data-preset="' + i + '">' + h(p.label) + "</button>"; }).join("") + "</div>" +
      "</div>" +
      (tickers.length < 2
        ? '<div class="gate center"><div class="gate-t">Pick at least two companies</div><div class="gate-s">Search above, or try one of the groups. Tip: compare a company with its closest rivals, not with the whole market.</div></div>'
        : '<section class="card"><div class="card-h"><h2 class="card-t">Performance, past year</h2><span class="card-sub">Rebased to 0% a year ago</span></div><div class="cmp-legend" id="cmp-legend"></div><div class="cmp-chart" id="cmp-chart"></div></section>' +
          '<section class="card flush"><div class="tbl-wrap"><table class="tbl cmp-tbl" id="cmp-tbl"><tbody><tr><td>' + '<span class="sk" style="height:200px"></span>' + "</td></tr></tbody></table></div></section>" +
          '<div class="grid-2" id="cmp-flags"></div>' +
          '<p class="note">Best value in each row is marked. Grades compare each company with its own sector. Figures from SEC filings and a year of prices; not investment advice.</p>');
    IL.wireSearchPick(IL.$("#cmp-q"), IL.$("#cmp-sugg"), add);
    IL.ribbon(IL.$("#cmp-hero"), "sweep", 8);
    writeUrl();
    if (tickers.length >= 2) Promise.all(tickers.map(load)).then(paint);
  }

  function add(sym) {
    sym = String(sym || "").trim().toUpperCase();
    if (!/^[A-Z0-9.^-]{1,15}$/.test(sym) || tickers.indexOf(sym) >= 0 || tickers.length >= MAX) return;
    tickers.push(sym); render();
    var q = IL.$("#cmp-q"); if (q) q.focus();
  }
  document.addEventListener("click", function (e) {
    var rm = e.target.closest("[data-rm]");
    if (rm) { var t = rm.getAttribute("data-rm"); tickers = tickers.filter(function (x) { return x !== t; }); render(); return; }
    var pr = e.target.closest("[data-preset]");
    if (pr) { tickers = PRESETS[+pr.getAttribute("data-preset")].t.slice(0, MAX); render(); }
  });

  function paint() {
    var list = tickers.map(function (t) { return data[t]; });
    var gate = list.filter(function (d) { return d.quoteRes.gate; })[0];
    var tbl = IL.$("#cmp-tbl"); if (!tbl) return;
    if (gate) { tbl.parentNode.innerHTML = '<div style="padding:16px">' + IL.gate(gate.quoteRes.gate) + "</div>"; return; }
    var histGate = list.filter(function (d) { return d.histRes.gate; })[0];
    var head = "<thead><tr><th></th>" + list.map(function (d, i) {
      return '<th><a class="cmp-th" href="/research/' + h(d.t) + '"><b><i style="background:' + COLORS[i] + '"></i>' + h(d.t) + '</b><span>' + h(d.name) + "</span></a></th>";
    }).join("") + "</tr></thead>";
    var body = GROUPS.map(function (gr) {
      var rows = gr.rows.map(function (r) {
        var vals = list.map(function (d) { var v = r.get(d); return v === undefined ? null : v; });
        var nums = vals.map(function (v) { return r.rank ? A().gradeRank(v) || null : typeof v === "number" && isFinite(v) ? v : null; });
        var best = -1;
        if (r.better && nums.filter(function (v) { return v !== null; }).length >= 2) {
          var pick = r.better === "high" ? Math.max.apply(null, nums.filter(function (v) { return v !== null; })) : Math.min.apply(null, nums.filter(function (v) { return v !== null; }));
          if (nums.filter(function (v) { return v === pick; }).length === 1) best = nums.indexOf(pick);
        }
        return "<tr><td>" + h(r.k) + (r.tip ? " " + IL.tip(r.tip) : "") + "</td>" + vals.map(function (v, i) {
          var txt = r.withRow ? r.f(v, list[i]) : r.f(v);
          var cls = (i === best ? "best " : "") + (r.color && typeof v === "number" ? F.cls(v) : "");
          return '<td class="' + cls + '">' + (i === best ? '<span class="best-dot" aria-label="Best"></span>' : "") + txt + "</td>";
        }).join("") + "</tr>";
      }).join("");
      return '<tr class="cmp-group"><td colspan="' + (list.length + 1) + '">' + h(gr.title) + "</td></tr>" + rows;
    }).join("");
    tbl.innerHTML = head + "<tbody>" + body + "</tbody>";
    if (histGate) tbl.parentNode.insertAdjacentHTML("afterend", '<p class="lr-gate" style="margin:12px 20px">' + IL.icon("lock", 14) + ' <span>Revenue, margins, price/sales and the growth each price needs use SEC statements, which need a free account. <a href="' + IL.signupHref() + '">Create one</a> · no card.</span></p>');
    IL.$("#cmp-flags").className = list.length === 3 ? "grid-3" : "grid-2";
    IL.$("#cmp-flags").innerHTML = list.map(function (d, i) {
      var good = d.flags.filter(function (x) { return x.tone === "good"; }), bad = d.flags.filter(function (x) { return x.tone === "bad"; });
      return '<section class="card"><div class="card-h"><h3 class="card-t"><i class="cmp-dot" style="background:' + COLORS[i] + '"></i>' + h(d.t) + ' <span class="muted" style="font-weight:500">' + h(d.name) + '</span></h3><span class="card-sub"><span class="up">' + good.length + ' working</span> · <span class="down">' + bad.length + " warning" + (bad.length === 1 ? "" : "s") + "</span></span></div>" +
        '<ul class="lr-flags good">' + good.slice(0, 3).map(function (x) { return '<li><span class="lr-ico">+</span><div><b>' + h(x.title) + "</b><span>" + h(x.detail) + "</span></div></li>"; }).join("") + "</ul>" +
        '<ul class="lr-flags bad">' + bad.slice(0, 3).map(function (x) { return '<li><span class="lr-ico">!</span><div><b>' + h(x.title) + "</b><span>" + h(x.detail) + "</span></div></li>"; }).join("") + "</ul>" +
        '<a class="card-foot" href="/research/' + h(d.t) + '">Open the full report →</a></section>';
    }).join("");
    drawChart(list);
  }

  function drawChart(list) {
    var el = IL.$("#cmp-chart"), L = window.LightweightCharts;
    if (!el || !L) return;
    el.innerHTML = "";
    var css = function (n) { return getComputedStyle(document.documentElement).getPropertyValue(n).trim(); };
    chart = L.createChart(el, {
      autoSize: true,
      layout: { background: { type: "solid", color: "transparent" }, textColor: css("--text3"), fontFamily: "IBM Plex Sans, Inter, sans-serif", fontSize: 11 },
      grid: { vertLines: { visible: false }, horzLines: { color: css("--chart-grid") } },
      rightPriceScale: { borderVisible: false }, timeScale: { borderVisible: false, fixLeftEdge: true, fixRightEdge: true },
      localization: { priceFormatter: function (v) { return (v > 0 ? "+" : v < 0 ? "−" : "") + Math.abs(v).toFixed(0) + "%"; } },
      crosshair: { mode: 0 },
      handleScroll: false, handleScale: false,
    });
    var legend = [];
    list.forEach(function (d, i) {
      if (!d.series || !d.series.bars.length) return;
      var bars = d.series.bars, end = bars[bars.length - 1].time;
      var year = bars.filter(function (b) { return b.time >= end - 366 * 86400; });
      if (!year.length) return;
      var base = year[0].close;
      var s = chart.addSeries(L.LineSeries, { color: COLORS[i], lineWidth: 2.5, lineType: 2, priceLineVisible: false, lastValueVisible: true, crosshairMarkerRadius: 3 });
      s.setData(year.map(function (b) { return { time: b.time, value: (b.close / base - 1) * 100 }; }));
      var last = (year[year.length - 1].close / base - 1) * 100;
      legend.push('<span class="cmp-key"><i style="background:' + COLORS[i] + '"></i>' + h(d.t) + ' <b class="num ' + F.cls(last) + '">' + F.spct(last) + "</b></span>");
    });
    chart.timeScale().fitContent();
    IL.$("#cmp-legend").innerHTML = legend.join("");
  }

  function boot() {
    IL.shell("research");
    readUrl();
    render();
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot); else boot();
})();

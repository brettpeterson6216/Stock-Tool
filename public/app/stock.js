/* ═══════════════════════════════════════════════════════════════════════════
   The stock page: /research/:ticker[/tab]

   Overview · Financials · Valuation · Earnings · Ownership · Filings

   Every tab is drawn from the existing APIs. What a visitor cannot see is
   replaced with a clear gate (free account or Pro), never a blank panel.
   ═══════════════════════════════════════════════════════════════════════════ */
(function () {
  "use strict";
  var IL = window.IL, F = IL.fmt, h = IL.h, N = IL.n;

  var TABS = [
    { key: "overview", label: "Overview" },
    { key: "financials", label: "Financials" },
    { key: "valuation", label: "Valuation" },
    { key: "earnings", label: "Earnings" },
    { key: "ownership", label: "Ownership" },
    { key: "filings", label: "Filings" },
  ];
  var FACTOR_LABEL = { value: "Value", growth: "Growth", profitability: "Profit", health: "Health", momentum: "Momentum" };
  var FACTOR_HELP = {
    value: "How cheap the stock is next to its sector peers, on price compared with sales, earnings and cash flow.",
    growth: "How fast sales and earnings have grown compared with sector peers.",
    profitability: "How much of each dollar of sales the company keeps as profit, compared with peers.",
    health: "Debt, cash and the ability to pay bills, compared with peers.",
    momentum: "How the share price has moved over the past year compared with peers.",
  };

  var S = { t: null, tab: "overview", quote: null, lens: null, hist: null, annual: null, chart: null };

  function parsePath() {
    var parts = location.pathname.replace(/\/+$/, "").split("/").filter(Boolean);
    var t = parts[1] ? decodeURIComponent(parts[1]).toUpperCase() : null;
    var tab = parts[2] ? parts[2].toLowerCase() : "overview";
    if (!TABS.some(function (x) { return x.key === tab; })) tab = "overview";
    if (t && !/^[A-Z0-9.^-]{1,15}$/.test(t)) t = null;
    return { t: t, tab: tab };
  }

  /* ── Data, fetched once per page and shared by the tabs ─────────────── */
  var once = {};
  function get(key, path) {
    if (!once[key]) once[key] = IL.api(path);
    return once[key];
  }
  var D = {
    quote: function () { return get("quote", "/api/quote/" + S.t + "?range=2y"); },
    lens: function () { return get("lens", "/api/lens-score/" + S.t + "?card=1"); },
    hist: function () { return get("hist", "/api/fundamentals/history/" + S.t); },
    annual: function () { return get("annual", "/api/financials/" + S.t); },
    funds: function () { return get("funds", "/api/funds/" + S.t); },
    news: function () { return get("news", "/api/news/" + S.t); },
    calls: function () { return get("calls", "/api/calls/" + S.t); },
    sec: function () { return get("sec", "/api/sec/" + S.t); },
    insiders: function () { return get("ins", "/api/institutional/" + S.t); },
    dark: function () { return get("dark", "/api/darkpool/" + S.t); },
    watchlist: function () { return get("wl", "/api/workspace/watchlist"); },
  };

  /* ── Small render helpers ────────────────────────────────────────────── */
  function main() { return document.getElementById("main"); }
  function sk(hgt, w) { return '<span class="sk" style="height:' + (hgt || 14) + "px" + (w ? ";width:" + w : "") + '"></span>'; }
  function scoreRing(score, size) {
    size = size || 92;
    var r = size / 2 - 6, c = 2 * Math.PI * r, pct = Math.max(0, Math.min(1, Number(score) / 10));
    var tone = IL.scoreTone(score), col = tone === "good" ? "var(--gain)" : tone === "mid" ? "var(--amber)" : "var(--loss)";
    return '<svg width="' + size + '" height="' + size + '" viewBox="0 0 ' + size + " " + size + '" role="img" aria-label="LensScore ' + h(F.num(score, 1)) + ' out of 10">' +
      '<circle cx="' + size / 2 + '" cy="' + size / 2 + '" r="' + r + '" fill="none" stroke="var(--line2)" stroke-width="8"/>' +
      '<circle cx="' + size / 2 + '" cy="' + size / 2 + '" r="' + r + '" fill="none" stroke="' + col + '" stroke-width="8" stroke-linecap="round" stroke-dasharray="' + (c * pct).toFixed(1) + " " + c.toFixed(1) + '" transform="rotate(-90 ' + size / 2 + " " + size / 2 + ')"/>' +
      '<text x="50%" y="50%" dy="0.35em" text-anchor="middle" font-family="IBM Plex Sans, sans-serif" font-weight="700" font-size="' + Math.round(size * 0.26) + '" fill="var(--text)">' + h(F.num(score, 1)) + "</text></svg>";
  }
  function quarterly(hist) {
    var q = (hist && hist.quarters ? hist.quarters.slice() : []).filter(function (x) { return x && x.end; });
    q.sort(function (a, b) { return a.end < b.end ? -1 : 1; });
    return q;
  }
  function sumLast(q, key, n, offset) {
    offset = offset || 0;
    var slice = q.slice(Math.max(0, q.length - n - offset), q.length - offset);
    if (slice.length < n) return null;
    var s = 0;
    for (var i = 0; i < slice.length; i++) { var v = N(slice[i][key]); if (v === null) return null; s += v; }
    return s;
  }
  function growth(cur, prev) { return cur !== null && prev !== null && prev > 0 ? (cur / prev - 1) * 100 : null; }

  /* ── Price figures from the 2y daily quote ───────────────────────────── */
  function priceFacts() {
    var q = S.quote; if (!q || !q.bars.length) return null;
    var bars = q.bars, meta = q.meta || {}, last = bars[bars.length - 1];
    var price = N(meta.regularMarketPrice) || last.close;
    var prev = bars.length > 1 ? bars[bars.length - 2].close : N(meta.previousClose);
    var year = bars.filter(function (b) { return b.time >= last.time - 366 * 86400; });
    var hi = Math.max.apply(null, year.map(function (b) { return b.high || b.close; }));
    var lo = Math.min.apply(null, year.map(function (b) { return b.low || b.close; }));
    var rets = [];
    for (var i = 1; i < year.length; i++) rets.push(Math.log(year[i].close / year[i - 1].close));
    var mean = rets.reduce(function (s, x) { return s + x; }, 0) / (rets.length || 1);
    var vol = Math.sqrt(rets.reduce(function (s, x) { return s + (x - mean) * (x - mean); }, 0) / Math.max(1, rets.length - 1)) * Math.sqrt(252) * 100;
    var peak = -Infinity, dd = 0;
    year.forEach(function (b) { peak = Math.max(peak, b.close); dd = Math.min(dd, b.close / peak - 1); });
    var worst = rets.length ? (Math.exp(Math.min.apply(null, rets)) - 1) * 100 : null;
    var ma = function (n) { if (bars.length < n) return null; var s = 0; for (var j = bars.length - n; j < bars.length; j++) s += bars[j].close; return s / n; };
    var yr = year.length ? (last.close / year[0].close - 1) * 100 : null;
    return {
      price: price, prev: prev, chg: prev ? price - prev : null, chgPct: prev ? (price / prev - 1) * 100 : null,
      hi: hi, lo: lo, vol: vol, drawdown: dd * 100, worstDay: worst, ma50: ma(50), ma200: ma(200), yearReturn: yr,
      lastTime: last.time, meta: meta, provenance: q.provenance,
    };
  }
  /* SEC names are filed in capitals ("NVIDIA CORP"). Prefer a mixed-case
     name when one exists, otherwise soften the capitals ("Apple Inc"). */
  function displayName() {
    var names = Array.prototype.slice.call(arguments).filter(function (n) { return n && String(n).trim() && String(n).toUpperCase() !== S.t; });
    var mixed = names.filter(function (n) { return n !== n.toUpperCase(); })[0];
    if (mixed) return mixed;
    var n = names[0];
    if (!n) return S.t;
    return n.toLowerCase().replace(/\b([a-z])/g, function (m) { return m.toUpperCase(); })
      .replace(/\b(Inc|Corp|Co|Ltd|Plc|Llc|Lp|Sa|Nv|Ag)\b\.?/g, function (m) { return m; })
      .replace(/\b(Ii|Iii|Iv|Usa|Us|Etf|Reit|Ai)\b/g, function (m) { return m.toUpperCase(); });
  }
  function riskWord(vol) { return vol == null ? "—" : vol < 22 ? "Steady" : vol < 40 ? "Bumpy" : "Wild"; }

  /* ═════════════════════════════════════════════════════════════════════
     Research landing (no ticker)
     ═════════════════════════════════════════════════════════════════════ */
  function renderLanding() {
    document.title = "Research a stock · ImpliedLens";
    var popular = ["NVDA", "AAPL", "MSFT", "AMZN", "GOOGL", "META", "TSLA", "COST", "JPM", "LLY", "AVGO", "NFLX"];
    main().innerHTML =
      '<section class="rl-hero">' +
        '<h1>Research any US stock</h1>' +
        '<p class="muted">A plain-English report card, the full financials, what the price is assuming, earnings releases and who owns it. Straight from SEC filings.</p>' +
        '<div class="il-search rl-search" role="search"><label class="il-search-box">' + IL.icon("search", 18) +
          '<input id="rl-q" type="search" autocomplete="off" spellcheck="false" placeholder="Company name or ticker, e.g. Apple or AAPL" aria-label="Search a company or ticker" role="combobox" aria-expanded="false" aria-controls="rl-sugg"></label>' +
          '<div class="il-sugg" id="rl-sugg" role="listbox" hidden></div></div>' +
        '<div class="row wrap rl-pop"><span class="faint">Popular:</span>' + popular.map(function (t) { return '<a class="tag" href="/research/' + t + '">' + t + "</a>"; }).join("") + "</div>" +
      "</section>" +
      '<div class="grid-3 rl-tools">' +
        '<a class="card" href="/?view=tool&section=screener"><span class="card-t">Screener</span><span class="card-sub">Filter about 290 US stocks by grade, value, size and momentum.</span></a>' +
        '<a class="card" href="/lens-score"><span class="card-t">LensToolkit</span><span class="card-sub">Trend, timing, buy zones and alerts for any stock.</span></a>' +
        '<a class="card" href="/?view=tool&section=projection"><span class="card-t">Valuation Lab</span><span class="card-sub">A full five-year model with saved versions.</span></a>' +
      "</div>" +
      '<div class="section-h"><h2 class="section-t">Top-rated in each sector</h2><span class="card-sub">Highest LensScore among the companies we grade</span></div>' +
      '<div class="card flush" id="rl-leaders"><div style="padding:20px">' + sk(16) + "</div></div>";
    IL.wireSearch(IL.$("#rl-q"), IL.$("#rl-sugg"));
    IL.api("/api/lens-leaders").then(function (res) {
      var box = IL.$("#rl-leaders");
      var d = res.data || {};
      var rows = (d.sectors || []).filter(function (s) { return s.top && s.top.length; });
      rows.sort(function (a, b) { return (b.count || 0) - (a.count || 0); });
      if (!res.ok || !rows.length) { box.innerHTML = '<div class="empty">Grades are still loading. Search for a company above.</div>'; return; }
      var keys = ["value", "growth", "profitability", "health", "momentum"];
      box.innerHTML = '<div class="tbl-wrap"><table class="tbl"><thead><tr><th>Sector</th><th style="text-align:left">Top-rated</th><th>LensScore</th>' + keys.map(function (k) { return "<th>" + FACTOR_LABEL[k] + "</th>"; }).join("") + '<th style="text-align:left">Runners-up</th></tr></thead><tbody>' +
        rows.map(function (r) {
          var top = r.top[0];
          return '<tr class="click" data-go="' + h(top.ticker) + '"><td>' + h(r.sectorName || r.sector) + ' <span class="faint num">(' + (r.count || "") + ')</span></td><td style="text-align:left;font-family:var(--sans)"><b>' + h(top.ticker) + '</b> <span class="muted">' + h(top.name || "") + '</span></td><td><span class="pill ' + IL.scoreTone(top.score) + '">' + F.num(top.score, 1) + "</span></td>" +
            keys.map(function (k) { var gr = top.grades && top.grades[k]; return '<td style="color:' + IL.gradeTone(gr) + ';font-weight:650">' + h(gr || "—") + "</td>"; }).join("") +
            '<td style="text-align:left;font-family:var(--sans)">' + r.top.slice(1, 3).map(function (x) { return '<a href="/research/' + h(x.ticker) + '">' + h(x.ticker) + ' <span class="num faint">' + F.num(x.score, 1) + "</span></a>"; }).join(" · ") + "</td></tr>";
        }).join("") + "</tbody></table></div>";
    });
    main().addEventListener("click", function (e) { var r = e.target.closest("[data-go]"); if (r) IL.go(r.getAttribute("data-go")); });
  }

  /* ═════════════════════════════════════════════════════════════════════
     Stock page frame: header, actions, tabs
     ═════════════════════════════════════════════════════════════════════ */
  function renderFrame() {
    main().innerHTML =
      '<section class="sh" id="sh">' +
        '<div class="sh-id">' +
          '<div class="sh-meta"><span class="sh-sym">' + h(S.t) + '</span><span id="sh-sector" class="muted"></span></div>' +
          '<h1 class="sh-name" id="sh-name">' + sk(26, "260px") + "</h1>" +
          '<div class="sh-px" id="sh-px">' + sk(30, "220px") + "</div>" +
        "</div>" +
        '<div class="sh-actions">' +
          '<button class="btn" type="button" id="act-watch" aria-pressed="false">' + IL.icon("star") + '<span>Watch</span></button>' +
          '<button class="btn" type="button" id="act-alert">' + IL.icon("bell") + "<span>Alert</span></button>" +
          '<a class="btn primary" href="/research/' + h(S.t) + '/valuation" data-tab="valuation">Build a valuation</a>' +
        "</div>" +
      "</section>" +
      '<nav class="tabs" aria-label="Stock sections">' + TABS.map(function (t) {
        return '<a href="/research/' + h(S.t) + (t.key === "overview" ? "" : "/" + t.key) + '" data-tab="' + t.key + '"' + (t.key === S.tab ? ' aria-current="page"' : "") + ">" + t.label + "</a>";
      }).join("") + "</nav>" +
      '<div id="tab"></div>';
    wireActions();
  }

  function fillHeader() {
    var p = priceFacts(), meta = p ? p.meta : {}, lens = S.lens || {};
    var name = displayName(meta.longName, meta.shortName, lens.company);
    IL.$("#sh-name").textContent = name;
    document.title = S.t + " " + (p ? F.price(p.price) + " " : "") + "· " + name + " · ImpliedLens";
    var bits = [meta.fullExchangeName || meta.exchangeName, meta.sector, meta.industry].filter(Boolean);
    IL.$("#sh-sector").textContent = bits.join(" · ");
    if (!p) { IL.$("#sh-px").innerHTML = '<span class="muted">Price unavailable</span>'; return; }
    var session = p.provenance && p.provenance.marketSession;
    var when = session === "regular"
      ? "Delayed price · " + new Date().toLocaleTimeString("en-US", { hour: "numeric", minute: "2-digit", timeZone: "America/New_York" }) + " ET"
      : "Close · " + F.date(p.lastTime, { year: undefined, timeZone: "America/New_York" });
    IL.$("#sh-px").innerHTML =
      '<span class="num sh-price">' + F.price(p.price) + "</span>" +
      '<span class="num sh-chg ' + F.cls(p.chg) + '">' + F.schg(p.chg) + " (" + F.spct(p.chgPct, 2) + ")</span>" +
      '<span class="faint sh-when">' + h(when) + "</span>";
  }

  /* ── Watch and Alert ─────────────────────────────────────────────────── */
  function wireActions() {
    var watch = IL.$("#act-watch"), alert = IL.$("#act-alert");
    IL.me().then(function (u) {
      if (!u) return;
      D.watchlist().then(function (res) {
        var on = res.ok && Array.isArray(res.data) && res.data.some(function (r) { return String(r.ticker).toUpperCase() === S.t; });
        setWatch(on);
      });
    });
    function setWatch(on) {
      watch.setAttribute("aria-pressed", String(on));
      watch.classList.toggle("on", on);
      watch.querySelector("span").textContent = on ? "Watching" : "Watch";
    }
    watch.addEventListener("click", function () {
      if (!IL.user) { location.href = IL.signupHref(); return; }
      var on = watch.getAttribute("aria-pressed") === "true";
      watch.disabled = true;
      IL.api("/api/workspace/watchlist/" + S.t, on ? { method: "DELETE" } : { method: "PUT", body: {} }).then(function (res) {
        watch.disabled = false;
        if (!res.ok) { IL.toast((res.data && res.data.error) || "Could not update your watchlist."); return; }
        setWatch(!on);
        IL.toast(on ? S.t + " removed from your watchlist" : S.t + " added to your watchlist");
      });
    });
    alert.addEventListener("click", function () {
      if (!IL.user) { location.href = IL.signupHref(); return; }
      var p = priceFacts(), px = p ? p.price : null;
      IL.dialog(
        "<h2>Alert me about " + h(S.t) + "</h2>" +
        '<p class="muted" style="font-size:13.5px">We email you once when it happens' + (px ? ". It is " + F.price(px) + " now." : ".") + "</p>" +
        '<label class="field">When<select class="input" id="al-kind"><option value="below">Price falls to or below</option><option value="above">Price rises to or above</option><option value="score">Its LensScore grade changes</option></select></label>' +
        '<label class="field" id="al-level-f">Price<input class="input num" id="al-level" inputmode="decimal" value="' + (px ? (px * 0.9).toFixed(2) : "") + '"></label>' +
        '<p class="note" id="al-err" role="alert"></p>' +
        '<div class="row" style="justify-content:flex-end"><button class="btn ghost" type="button" data-close>Cancel</button><button class="btn primary" type="button" id="al-save">Save alert</button></div>',
        function (d) {
          var kind = d.querySelector("#al-kind"), lvl = d.querySelector("#al-level");
          kind.addEventListener("change", function () {
            d.querySelector("#al-level-f").style.display = kind.value === "score" ? "none" : "";
            if (px && kind.value !== "score") lvl.value = (px * (kind.value === "above" ? 1.1 : 0.9)).toFixed(2);
          });
          d.querySelector("#al-save").addEventListener("click", function () {
            var body = { ticker: S.t, kind: kind.value };
            if (kind.value !== "score") body.level = Number(String(lvl.value).replace(/[$,\s]/g, ""));
            IL.api("/api/alerts", { method: "POST", body: body }).then(function (res) {
              if (!res.ok) {
                var msg = (res.data && res.data.error) || "Could not save the alert.";
                d.querySelector("#al-err").innerHTML = h(msg) + (res.data && res.data.upgrade ? ' <a href="/pricing">See Pro</a>' : "");
                return;
              }
              d.close(); IL.toast("Alert saved. We’ll email you.");
            });
          });
        });
    });
  }

  /* ── Tab switching without reloads ───────────────────────────────────── */
  function go(tab, push) {
    S.tab = tab;
    IL.$$(".tabs a").forEach(function (a) { if (a.getAttribute("data-tab") === tab) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current"); });
    if (push) history.pushState({ tab: tab }, "", "/research/" + S.t + (tab === "overview" ? "" : "/" + tab));
    var box = IL.$("#tab");
    box.innerHTML = "";
    ({ overview: tabOverview, financials: tabFinancials, valuation: tabValuation, earnings: tabEarnings, ownership: tabOwnership, filings: tabFilings }[tab])(box);
    if (push) {
      var tabs = IL.$(".tabs");
      if (tabs && tabs.getBoundingClientRect().top < 0) window.scrollTo({ top: tabs.offsetTop - 70 });
    }
  }
  document.addEventListener("click", function (e) {
    var a = e.target.closest("a[data-tab]");
    if (!a || e.metaKey || e.ctrlKey || e.shiftKey || !S.t) return;
    e.preventDefault();
    go(a.getAttribute("data-tab"), true);
    var anchor = a.getAttribute("data-anchor");
    if (anchor) setTimeout(function () { var el = document.getElementById(anchor); if (el) el.scrollIntoView({ behavior: "smooth", block: "start" }); }, 60);
    else if (a.closest(".tabs") === null) window.scrollTo({ top: 0, behavior: "smooth" });
  });
  window.addEventListener("popstate", function () { var p = parsePath(); if (p.t === S.t) go(p.tab, false); else location.reload(); });

  /* ═════════════════════════════════════════════════════════════════════
     Overview
     ═════════════════════════════════════════════════════════════════════ */
  function tabOverview(box) {
    box.innerHTML =
      '<div class="ov">' +
        '<div class="ov-main">' +
          '<section class="card pc" aria-label="Price chart" id="ov-chart"></section>' +
          '<section class="kv" aria-label="Key numbers" id="ov-kv">' + Array(8).join('<div><span class="k">' + sk(10, "60%") + '</span><span class="v">' + sk(16, "50%") + "</span></div>") + "</section>" +
          '<div class="grid-3">' +
            '<section class="card" id="ov-q"><h2 class="card-t">Latest quarter</h2>' + sk(60) + "</section>" +
            '<section class="card" id="ov-f"><h2 class="card-t">Famous investors</h2>' + sk(60) + "</section>" +
            '<section class="card" id="ov-r"><h2 class="card-t">How risky has it been?</h2>' + sk(60) + "</section>" +
          "</div>" +
        "</div>" +
        '<aside class="card rc" aria-label="LensScore report card" id="ov-rc">' + sk(220) + "</aside>" +
      "</div>" +
      '<div class="section-h" id="report"><h2 class="section-t">Full report card</h2><span class="card-sub" id="rep-sub"></span></div>' +
      '<div class="grid-2" id="ov-rep"><section class="card">' + sk(140) + '</section><section class="card">' + sk(140) + "</section></div>" +
      '<div class="section-h" id="peers"><h2 class="section-t">Compared with peers</h2><span class="card-sub">Same sector, graded the same way</span></div>' +
      '<section class="card flush" id="ov-peers"><div style="padding:20px">' + sk(80) + "</div></section>" +
      '<div class="section-h"><h2 class="section-t">Latest from the company</h2><a class="link" href="/research/' + h(S.t) + '/filings" data-tab="filings">All filings →</a></div>' +
      '<section class="card flush" id="ov-news"><div style="padding:20px">' + sk(60) + "</div></section>";

    S.chart = IL.PriceChart(IL.$("#ov-chart"), { ticker: S.t, seed: S.quote || undefined });
    paintKeyNumbers();
    paintRisk();
    D.lens().then(function () { paintReportCard(); paintKeyNumbers(); paintReport(); paintPeers(); });
    paintLatestQuarter();
    paintFunds(IL.$("#ov-f"), true);
    paintNews(IL.$("#ov-news"), 6);
  }

  function nextEarnings() {
    var g = S.lens && S.lens.grades;
    return g && g.street && g.street.nextEarnings ? g.street.nextEarnings : null;
  }
  function nextEarningsText(ne, long) {
    if (!ne || !ne.date) return "—";
    var d = F.date(ne.date, long ? {} : { year: undefined });
    return (ne.estimated ? "~" : "") + d;
  }

  function paintKeyNumbers() {
    var box = IL.$("#ov-kv"); if (!box) return;
    var p = priceFacts(); if (!p) return;
    var meta = p.meta, ne = nextEarnings();
    var pos = p.hi > p.lo ? (p.price - p.lo) / (p.hi - p.lo) * 100 : 50;
    function rel(ma) { if (!ma) return ""; var d = (p.price / ma - 1) * 100; return "Price is " + F.pct(Math.abs(d)) + (d >= 0 ? " above" : " below"); }
    box.innerHTML =
      '<div><span class="k">Market cap ' + IL.tip("What the whole company is worth at today’s price: share price times shares outstanding.") + '</span><span class="v">' + F.money(meta.marketCap) + "</span></div>" +
      '<div><span class="k">P/E (trailing) ' + IL.tip("Price divided by the last 12 months of earnings per share. How many dollars you pay for each $1 of yearly profit. Blank when the company lost money.") + '</span><span class="v">' + F.mult(meta.trailingPE) + "</span></div>" +
      '<div><span class="k">Past year ' + IL.tip("How much the share price changed over the last 12 months, not counting dividends.") + '</span><span class="v ' + F.cls(p.yearReturn) + '">' + F.spct(p.yearReturn) + "</span></div>" +
      '<div><span class="k">Next earnings ' + IL.tip("When the company is expected to report its next quarter. A ~ means the date is estimated from its past pattern.") + '</span><span class="v">' + h(nextEarningsText(ne)) + "</span>" + (ne && ne.days != null && ne.days >= 0 ? '<span class="n">in ' + ne.days + " day" + (ne.days === 1 ? "" : "s") + "</span>" : "") + "</div>" +
      '<div class="kv-wide"><span class="k">52-week range</span><div class="range"><span class="num">' + F.price(p.lo) + '</span><div class="range-track"><span class="range-dot" style="left:' + Math.max(0, Math.min(100, pos)).toFixed(1) + '%"></span></div><span class="num">' + F.price(p.hi) + "</span></div></div>" +
      '<div><span class="k">50-day avg</span><span class="v">' + F.price(p.ma50) + '</span><span class="n">' + rel(p.ma50) + "</span></div>" +
      '<div><span class="k">200-day avg</span><span class="v">' + F.price(p.ma200) + '</span><span class="n">' + rel(p.ma200) + "</span></div>";
  }

  function paintRisk() {
    var box = IL.$("#ov-r"); if (!box) return;
    var p = priceFacts();
    if (!p) { box.innerHTML = '<h2 class="card-t">How risky has it been?</h2><p class="muted">Needs price history.</p>'; return; }
    var beta = N(p.meta.beta);
    box.innerHTML = '<div class="card-h"><h2 class="card-t">How risky has it been?</h2><span class="tag ' + (p.vol < 22 ? "good" : p.vol < 40 ? "gold" : "bad") + '">' + riskWord(p.vol) + "</span></div>" +
      '<span class="card-sub">Past year</span>' +
      '<div><div class="stat"><span class="k">Typical yearly swing ' + IL.tip("Annualized volatility: how far the price usually moves in a year, up or down. The S&P 500 is usually around 15%.") + '</span><span class="v">' + F.pct(p.vol) + "</span></div>" +
      '<div class="stat"><span class="k">Worst drop from a high ' + IL.tip("The largest fall from a peak to a later low over the past year (maximum drawdown).") + '</span><span class="v down">' + F.spct(p.drawdown) + "</span></div>" +
      '<div class="stat"><span class="k">Worst single day</span><span class="v down">' + F.spct(p.worstDay) + "</span></div>" +
      (beta !== null ? '<div class="stat"><span class="k">Beta ' + IL.tip("How much the stock tends to move when the whole market moves 1%. Above 1 means it swings more than the market.") + '</span><span class="v">' + F.num(beta, 2) + "</span></div>" : "") +
      "</div>";
  }

  function paintReportCard() {
    var box = IL.$("#ov-rc"); if (!box) return;
    var res = S.lensRes, g = S.lens && S.lens.grades;
    if (res && res.gate) { box.innerHTML = '<h2 class="card-t">LensScore</h2>' + IL.gate(res.gate); return; }
    if (!g || g.status !== "graded") {
      box.innerHTML = '<h2 class="card-t">LensScore</h2><p class="muted" style="font-size:13.5px">' +
        h((g && g.reason) || "We grade US companies that file with the SEC against their sector peers. This one is not graded yet, often because it is a fund, a foreign listing or too new.") + "</p>";
      return;
    }
    var f = g.factors || [];
    var checks = [];
    var valueF = f.filter(function (x) { return x.key === "value"; })[0];
    if (valueF && /^[C-F]/.test(valueF.grade || "")) checks.push({ text: "Is the price already assuming the growth?", tab: "valuation" });
    else checks.push({ text: "What does today’s price assume?", tab: "valuation" });
    var ne = nextEarnings();
    if (ne && ne.date) checks.push({ text: "Read the last release before " + nextEarningsText(ne), tab: "earnings" });
    if (g.watch && g.watch[0]) checks.push({ text: "Watch: " + String(g.watch[0].text || "").replace(/\.$/, ""), anchor: "report" });
    box.innerHTML =
      '<div class="card-h"><h2 class="card-t">LensScore ' + IL.tip("A 0–10 grade of the business against its sector peers on five things, from SEC filings and price history. It describes the company today; it is not a price prediction.") + "</h2>" +
        (g.rank ? '<span class="card-sub">#' + g.rank.position + " of " + g.rank.of + " in " + h(g.rank.sectorName || g.sectorName || "its sector") + "</span>" : "") + "</div>" +
      '<div class="rc-top">' + scoreRing(g.score) +
        '<div class="rc-lab"><span class="rc-label">' + h(g.label || "") + '</span><span class="muted">Graded against ' + h(g.sectorName || "sector") + " peers on five things.</span></div></div>" +
      '<div class="grades">' + f.map(function (x) {
        return '<div class="grade"><span>' + h(FACTOR_LABEL[x.key] || x.label) + '</span><div class="bar"><i style="width:' + IL.gradeFill(x.grade) + "%;background:" + IL.gradeTone(x.grade) + '"></i></div><span class="g" style="color:' + IL.gradeTone(x.grade) + '">' + h(x.grade || "—") + "</span></div>";
      }).join("") + "</div>" +
      (g.verdict ? '<p class="rc-verdict">' + h(g.verdict) + "</p>" : "") +
      '<div class="rc-next"><span class="rc-next-h">What to check next</span>' + checks.slice(0, 3).map(function (c) {
        return '<a href="/research/' + h(S.t) + (c.tab ? "/" + c.tab : "") + '" data-tab="' + (c.tab || "overview") + '"' + (c.anchor ? ' data-anchor="' + c.anchor + '"' : "") + "><span>" + h(c.text) + "</span>" + IL.icon("arrow", 14) + "</a>";
      }).join("") + "</div>" +
      '<div class="rc-foot"><a class="btn sm" href="#report" data-scroll="report">Full report card</a><a class="btn sm ghost" href="#peers" data-scroll="peers">Compare peers</a></div>';
  }
  document.addEventListener("click", function (e) {
    var a = e.target.closest("[data-scroll]"); if (!a) return;
    e.preventDefault();
    var el = document.getElementById(a.getAttribute("data-scroll"));
    if (el) el.scrollIntoView({ behavior: "smooth", block: "start" });
  });

  function paintReport() {
    var box = IL.$("#ov-rep"); if (!box) return;
    var g = S.lens && S.lens.grades;
    if (!g || g.status !== "graded") {
      box.innerHTML = '<section class="card"><p class="muted">The report card appears for companies we grade.</p></section>';
      IL.$("#rep-sub").textContent = "";
      return;
    }
    IL.$("#rep-sub").textContent = "Percentile = share of " + (g.sectorName || "sector") + " peers it beats";
    var rows = (g.factors || []).map(function (x) {
      var pct = N(x.percentile);
      return '<div class="rep-f"><div class="rep-f-h"><span class="rep-f-n">' + h(FACTOR_LABEL[x.key] || x.label) + '</span><span class="num" style="color:' + IL.gradeTone(x.grade) + ';font-weight:700">' + h(x.grade || "—") + "</span></div>" +
        '<div class="rep-bar"><i style="width:' + (pct === null ? 0 : Math.max(2, Math.min(100, pct))) + "%;background:" + IL.gradeTone(x.grade) + '"></i></div>' +
        '<div class="rep-f-s"><span>' + h(FACTOR_HELP[x.key] || "") + '</span><span class="num faint">' + (pct === null ? "" : "Beats " + Math.round(pct) + "%") + "</span></div></div>";
    }).join("");
    function list(items, cls) {
      if (!items || !items.length) return '<p class="muted" style="font-size:13.5px">Nothing stands out.</p>';
      return '<ul class="rep-list ' + cls + '">' + items.map(function (s) { return "<li>" + h(s.text || s) + "</li>"; }).join("") + "</ul>";
    }
    box.innerHTML =
      '<section class="card"><h3 class="card-t">The five grades</h3>' + rows + "</section>" +
      '<section class="card"><h3 class="card-t">Strengths</h3>' + list(g.strengths, "good") +
        '<h3 class="card-t" style="margin-top:8px">Things to watch</h3>' + list(g.watch, "bad") +
        '<p class="note">Grades compare the company with its sector using SEC filings and a year of prices. ' + (S.lens.provenance && S.lens.provenance.asOf && S.lens.provenance.asOf.fundamentals ? "Filings as of " + F.date(S.lens.provenance.asOf.fundamentals) + ". " : "") + '<a href="/learn/lens-score">How the LensScore works</a></p></section>';
  }

  function paintPeers() {
    var box = IL.$("#ov-peers"); if (!box) return;
    var g = S.lens && S.lens.grades;
    var peers = (g && g.peers) || [];
    if (!g || g.status !== "graded" || !peers.length) { box.innerHTML = '<div class="empty">No graded peers to compare with.</div>'; return; }
    var list = [S.t].concat(peers.filter(function (p) { return p !== S.t; })).slice(0, 6);
    IL.api("/api/lens-grades?tickers=" + list.join(",")).then(function (res) {
      var gg = (res.data && res.data.grades) || {};
      var keys = ["value", "growth", "profitability", "health", "momentum"];
      box.innerHTML = '<div class="tbl-wrap"><table class="tbl"><thead><tr><th>Company</th><th>LensScore</th>' + keys.map(function (k) { return "<th>" + FACTOR_LABEL[k] + "</th>"; }).join("") + "</tr></thead><tbody>" +
        list.map(function (t) {
          var x = gg[t]; if (!x) return "";
          var me = t === S.t;
          return '<tr class="' + (me ? "em" : "click") + '"' + (me ? "" : ' data-go="' + h(t) + '"') + "><td><b>" + h(t) + "</b>" + (me ? ' <span class="tag gold">This stock</span>' : "") + '</td><td><span class="pill ' + IL.scoreTone(x.score) + '">' + F.num(x.score, 1) + "</span></td>" +
            keys.map(function (k) { var gr = x.grades && x.grades[k]; return '<td style="color:' + IL.gradeTone(gr) + ';font-weight:650">' + h(gr || "—") + "</td>"; }).join("") + "</tr>";
        }).join("") + "</tbody></table></div>";
    });
  }
  document.addEventListener("click", function (e) { var r = e.target.closest("tr[data-go]"); if (r) IL.go(r.getAttribute("data-go")); });

  function paintLatestQuarter() {
    var box = IL.$("#ov-q"); if (!box) return;
    D.hist().then(function (res) {
      if (res.gate) { box.innerHTML = '<h2 class="card-t">Latest quarter</h2>' + IL.gate(res.gate, "See the latest quarter", { why: "Free accounts see every quarter’s revenue, profit and cash flow, straight from SEC filings." }); return; }
      var q = quarterly(res.data);
      if (!res.ok || !q.length) { box.innerHTML = '<h2 class="card-t">Latest quarter</h2><p class="muted" style="font-size:13.5px">' + h((res.data && res.data.error) || "Quarterly figures are not available for this company.") + "</p>"; return; }
      var last = q[q.length - 1], ago = q.length >= 5 ? q[q.length - 5] : null;
      var rg = ago ? growth(N(last.revenue), N(ago.revenue)) : null;
      var eg = ago && N(ago.eps) > 0 ? growth(N(last.eps), N(ago.eps)) : null;
      var filing = res.data.filings && res.data.filings[last.end];
      box.innerHTML = '<h2 class="card-t">Latest quarter</h2><span class="card-sub">' + h(last.label) + " · ended " + F.date(last.end) + (filing && filing.filed ? " · filed " + F.date(filing.filed, { year: undefined }) : "") + "</span>" +
        '<div><div class="stat"><span class="k">Revenue</span><span class="v">' + F.money(last.revenue) + (rg !== null ? ' <span class="' + F.cls(rg) + '">' + F.spct(rg, 0) + "</span>" : "") + "</span></div>" +
        '<div class="stat"><span class="k">EPS (diluted)</span><span class="v">' + F.eps(last.eps) + (eg !== null ? ' <span class="' + F.cls(eg) + '">' + F.spct(eg, 0) + "</span>" : "") + "</span></div>" +
        '<div class="stat"><span class="k">Free cash flow</span><span class="v">' + F.money(last.freeCashFlow) + "</span></div></div>" +
        '<a class="card-foot" href="/research/' + h(S.t) + '/earnings" data-tab="earnings">Earnings and releases →</a>';
    });
  }

  function changeTag(x) {
    var c = x.change;
    if (c === "new") return '<span class="tag good">New position</span>';
    if (c === "added") return '<span class="tag good">Bought more</span>';
    if (c === "reduced") return '<span class="tag bad">Sold some</span>';
    if (c === "unchanged") return '<span class="tag">No change</span>';
    return '<span class="tag">Held</span>';
  }
  function paintFunds(box, compact) {
    D.funds().then(function (res) {
      var d = res.data || {};
      var holders = d.holders || [], sold = d.soldOut || [];
      if (compact) {
        if (d.loading && !holders.length) { box.innerHTML = '<h2 class="card-t">Famous investors</h2><p class="muted" style="font-size:13.5px">Loading the latest 13F filings from the SEC. Check back in a minute.</p>'; return; }
        if (!res.ok && !holders.length) { box.innerHTML = '<h2 class="card-t">Famous investors</h2><p class="muted" style="font-size:13.5px">No 13F holdings for this company.</p>'; return; }
        box.innerHTML = '<h2 class="card-t">Famous investors</h2><span class="card-sub">' + (holders.length ? holders.length + " of " + (d.managersTracked || "the") + " we follow hold it" : "None of the " + (d.managersTracked || "") + " we follow hold it") + "</span>" +
          '<div>' + holders.slice(0, 3).map(function (x) { return '<div class="stat"><span class="k">' + h(x.who || x.fund) + "</span>" + changeTag(x) + "</div>"; }).join("") +
          (sold[0] && holders.length < 3 ? '<div class="stat"><span class="k">' + h(sold[0].who || sold[0].fund) + '</span><span class="tag bad">Sold out</span></div>' : "") + "</div>" +
          '<a class="card-foot" href="/research/' + h(S.t) + '/ownership" data-tab="ownership">See all holders →</a>';
        return;
      }
      if (d.loading && !holders.length) { box.innerHTML = '<div class="empty">Loading the latest 13F filings from the SEC. This takes about a minute after an update; refresh shortly.</div>'; return; }
      if (!holders.length && !sold.length) { box.innerHTML = '<div class="empty">None of the ' + h(d.managersTracked || "") + " well-known investors we follow reported owning " + h(S.t) + " last quarter.</div>"; return; }
      box.innerHTML = '<div class="tbl-wrap"><table class="tbl"><thead><tr><th>Investor</th><th>Shares</th><th>Value</th><th>Of their portfolio ' + IL.tip("How much of the investor’s reported US stock portfolio this position is. Bigger means more conviction.") + "</th><th>Last quarter</th><th>As of</th></tr></thead><tbody>" +
        holders.map(function (x) {
          return "<tr><td><b>" + h(x.who || x.fund) + '</b><div class="faint" style="font-size:12px">' + h(x.who && x.fund !== x.who ? x.fund : "") + "</div></td><td>" + F.count(x.shares) + "</td><td>" + F.money(x.value) + "</td><td>" + F.pct(x.weight) + "</td><td>" + changeTag(x) + (N(x.changePct) !== null && x.change !== "new" && x.change !== "unchanged" ? ' <span class="num faint">' + F.spct(x.changePct, 0) + "</span>" : "") + '</td><td class="sub">' + (x.url ? '<a href="' + h(x.url) + '" target="_blank" rel="noopener">' + F.date(x.period) + "</a>" : F.date(x.period)) + "</td></tr>";
        }).join("") +
        sold.map(function (x) {
          return "<tr><td><b>" + h(x.who || x.fund) + '</b></td><td class="sub">' + F.count(x.prevShares) + ' before</td><td></td><td></td><td><span class="tag bad">Sold out</span></td><td class="sub">' + F.date(x.period) + "</td></tr>";
        }).join("") + "</tbody></table></div>" +
        '<p class="note" style="padding:12px 20px">' + h(d.note || "") + "</p>";
    });
  }

  function paintNews(box, limit) {
    D.news().then(function (res) {
      var items = Array.isArray(res.data) ? res.data : (res.data && res.data.items) || [];
      if (!items.length) { box.innerHTML = '<div class="empty">No recent company announcements.</div>'; return; }
      box.innerHTML = '<ul class="feed">' + items.slice(0, limit || 10).map(function (n) {
        return '<li><a href="' + h(n.url) + '" target="_blank" rel="noopener"><span class="feed-t">' + h(n.headline) + '</span><span class="feed-s">' + h(n.summary || "") + '</span></a><span class="feed-m"><span class="tag">' + h(n.source || "") + '</span><span class="num faint">' + F.date(n.datetime) + "</span></span></li>";
      }).join("") + "</ul>";
    });
  }

  /* ═════════════════════════════════════════════════════════════════════
     Financials
     ═════════════════════════════════════════════════════════════════════ */
  var finView = "quarterly";
  function tabFinancials(box) {
    box.innerHTML =
      '<div class="section-h"><div><h2 class="section-t">Financial statements</h2><p class="card-sub">From the company’s 10-Q and 10-K filings with the SEC.</p></div>' +
        '<div class="row"><div class="seg" role="group" aria-label="Period"><button type="button" data-fv="quarterly" aria-pressed="' + (finView === "quarterly") + '">Quarterly</button><button type="button" data-fv="annual" aria-pressed="' + (finView === "annual") + '">Annual</button></div>' +
        '<button class="btn sm" type="button" id="fin-csv">Download CSV</button></div></div>' +
      '<div id="fin-body"><section class="card">' + sk(260) + "</section></div>";
    box.querySelectorAll("[data-fv]").forEach(function (b) {
      b.addEventListener("click", function () {
        finView = b.getAttribute("data-fv");
        box.querySelectorAll("[data-fv]").forEach(function (x) { x.setAttribute("aria-pressed", String(x === b)); });
        paintFin();
      });
    });
    IL.$("#fin-csv").addEventListener("click", downloadCsv);
    paintFin();
  }

  var lastTables = [];
  function paintFin() {
    var body = IL.$("#fin-body"); if (!body) return;
    body.innerHTML = '<section class="card">' + sk(260) + "</section>";
    if (finView === "quarterly") {
      D.hist().then(function (res) {
        if (res.gate) { body.innerHTML = IL.gate(res.gate, "Create a free account to see the financial statements", { center: true }); return; }
        var q = quarterly(res.data);
        if (!res.ok || !q.length) { body.innerHTML = '<div class="gate center"><div class="gate-t">Quarterly statements are not available</div><div class="gate-s">' + h((res.data && res.data.error) || "") + '</div><button class="btn" type="button" data-fv2="annual">Show annual</button></div>'; wireFv2(body); return; }
        var cols = q.slice(-12);
        var yoy = function (key) {
          return cols.map(function (c) {
            var i = q.indexOf(c), ago = i >= 4 ? q[i - 4] : null;
            return ago ? growth(N(c[key]), N(ago[key])) : null;
          });
        };
        var margin = function (key) { return cols.map(function (c) { var r = N(c.revenue), v = N(c[key]); return r && v !== null ? v / r * 100 : null; }); };
        var tables = [
          { title: "Income", rows: [
            { k: "Revenue", tip: "Everything customers paid the company in the quarter.", v: cols.map(function (c) { return c.revenue; }), f: F.money, em: true },
            { k: "Growth vs a year ago", v: yoy("revenue"), f: F.spct, sub: true, color: true },
            { k: "Gross profit", tip: "Revenue minus the direct cost of what was sold.", v: cols.map(function (c) { return c.grossProfit; }), f: F.money },
            { k: "Gross margin", v: margin("grossProfit"), f: F.pct, sub: true },
            { k: "Operating income", tip: "Profit from running the business, before interest and taxes.", v: cols.map(function (c) { return c.operatingIncome; }), f: F.money },
            { k: "Operating margin", v: margin("operatingIncome"), f: F.pct, sub: true },
            { k: "Net income", tip: "What is left for shareholders after every cost, interest and tax.", v: cols.map(function (c) { return c.netIncome; }), f: F.money, em: true },
            { k: "Net margin", v: margin("netIncome"), f: F.pct, sub: true },
            { k: "EPS (diluted)", tip: "Net income divided by the number of shares, counting options that could become shares.", v: cols.map(function (c) { return c.eps; }), f: F.eps },
            { k: "Diluted shares", v: cols.map(function (c) { return c.shares; }), f: F.count },
          ] },
          { title: "Cash flow", rows: [
            { k: "Operating cash flow", tip: "Cash the business actually brought in from operations. Harder to dress up than profit.", v: cols.map(function (c) { return c.operatingCashFlow; }), f: F.money },
            { k: "Capital spending", flow: true, tip: "Cash spent on buildings, equipment and other long-lived assets.", v: cols.map(function (c) { var x = N(c.capex); return x === null ? null : -Math.abs(x); }), f: F.money },
            { k: "Free cash flow", tip: "Operating cash flow minus capital spending: the cash left to pay dividends, buy back shares or pay down debt.", v: cols.map(function (c) { return c.freeCashFlow; }), f: F.money, em: true },
          ] },
        ];
        var heads = cols.map(function (c) { return c.label; });
        lastTables = { heads: heads, tables: tables, name: "quarterly" };
        body.innerHTML = finChart(cols.map(function (c) { return { label: c.label, a: N(c.revenue), b: N(c.netIncome) }; }), "Revenue", "Net income") +
          tables.map(function (t) { return finTable(t, heads); }).join("") +
          '<p class="note">' + h(res.data.calendar || "") + (q.some(function (c) { return c.derived && c.derived.length; }) ? " Fourth-quarter and some cash-flow figures are worked out from year-to-date totals in the filings." : "") + "</p>";
        scrollTablesRight(body);
      });
    } else {
      D.annual().then(function (res) {
        if (res.gate) { body.innerHTML = IL.gate(res.gate, "Create a free account to see the financial statements", { center: true }); return; }
        var r = res.data && res.data.quoteSummary && res.data.quoteSummary.result && res.data.quoteSummary.result[0];
        if (!res.ok || !r) { body.innerHTML = '<div class="empty">Annual statements are not available for this company.</div>'; return; }
        var inc = (r.incomeStatementHistory && r.incomeStatementHistory.incomeStatementHistory) || [];
        var bal = (r.balanceSheetHistory && r.balanceSheetHistory.balanceSheetStatements) || [];
        var cf = (r.cashflowStatementHistory && r.cashflowStatementHistory.cashflowStatements) || [];
        var order = function (arr) { return arr.slice().sort(function (a, b) { return N(a.endDate) - N(b.endDate); }); };
        inc = order(inc).slice(-8); bal = order(bal).slice(-8); cf = order(cf).slice(-8);
        var heads = inc.map(function (x) { return "FY " + (x.endDate && x.endDate.fmt); });
        var col = function (arr, key) { return arr.map(function (x) { return N(x[key]); }); };
        var rev = col(inc, "totalRevenue");
        var yoy = rev.map(function (v, i) { return i ? growth(v, rev[i - 1]) : null; });
        var pctOf = function (arr) { return arr.map(function (v, i) { return v !== null && rev[i] ? v / rev[i] * 100 : null; }); };
        var gp = col(inc, "grossProfit"), op = col(inc, "operatingIncome"), ni = col(inc, "netIncome");
        var ocf = col(cf, "totalCashFromOperatingActivities"), capex = col(cf, "capitalExpenditures");
        var fcf = ocf.map(function (v, i) { return v !== null && capex[i] !== null ? v + capex[i] : null; });
        var assets = col(bal, "totalAssets"), liab = col(bal, "totalLiab"), eq = col(bal, "totalStockholderEquity");
        var tables = [
          { title: "Income", rows: [
            { k: "Revenue", v: rev, f: F.money, em: true },
            { k: "Growth vs prior year", v: yoy, f: F.spct, sub: true, color: true },
            { k: "Gross profit", v: gp, f: F.money }, { k: "Gross margin", v: pctOf(gp), f: F.pct, sub: true },
            { k: "Operating income", v: op, f: F.money }, { k: "Operating margin", v: pctOf(op), f: F.pct, sub: true },
            { k: "Net income", v: ni, f: F.money, em: true }, { k: "Net margin", v: pctOf(ni), f: F.pct, sub: true },
            { k: "EPS (diluted)", v: col(inc, "dilutedEps"), f: F.eps },
          ] },
          { title: "Balance sheet", note: "At the end of each fiscal year", rows: [
            { k: "Cash", tip: "Cash and cash equivalents.", v: col(bal, "cash"), f: F.money },
            { k: "Short-term investments", v: col(bal, "shortTermInvestments"), f: F.money },
            { k: "Current assets", tip: "Assets expected to turn into cash within a year.", v: col(bal, "totalCurrentAssets"), f: F.money },
            { k: "Total assets", v: assets, f: F.money, em: true },
            { k: "Long-term debt", v: col(bal, "longTermDebt"), f: F.money },
            { k: "Total liabilities", v: liab, f: F.money },
            { k: "Shareholders’ equity", tip: "Assets minus liabilities: the book value that belongs to shareholders.", v: eq, f: F.money, em: true },
            { k: "Liabilities to equity", tip: "How much the company owes for each $1 of shareholder equity. Lower is safer.", v: liab.map(function (v, i) { return v !== null && eq[i] > 0 ? v / eq[i] : null; }), f: function (v) { return F.num(v, 2); }, sub: true },
          ] },
          { title: "Cash flow", rows: [
            { k: "Operating cash flow", v: ocf, f: F.money },
            { k: "Capital spending", v: capex, f: F.money, flow: true },
            { k: "Free cash flow", v: fcf, f: F.money, em: true },
            { k: "Investing cash flow", flow: true, v: col(cf, "totalCashflowsFromInvestingActivities"), f: F.money },
            { k: "Financing cash flow", flow: true, tip: "Cash from borrowing and issuing shares, minus debt repaid, buybacks and dividends.", v: col(cf, "totalCashFromFinancingActivities"), f: F.money },
          ] },
        ];
        lastTables = { heads: heads, tables: tables, name: "annual" };
        body.innerHTML = finChart(inc.map(function (x, i) { return { label: heads[i], a: rev[i], b: ni[i] }; }), "Revenue", "Net income") +
          tables.map(function (t) { return finTable(t, heads); }).join("") +
          '<p class="note">Fiscal years are labelled by the calendar year they end in. Source: ' + h((res.data.impliedLens && res.data.impliedLens.source) || "SEC EDGAR") + ".</p>";
        scrollTablesRight(body);
      });
    }
  }
  function wireFv2(body) {
    var b = body.querySelector("[data-fv2]"); if (!b) return;
    b.addEventListener("click", function () { var t = IL.$('[data-fv="annual"]'); if (t) t.click(); });
  }
  function scrollTablesRight(body) {
    requestAnimationFrame(function () { body.querySelectorAll(".tbl-wrap").forEach(function (w) { w.scrollLeft = w.scrollWidth; }); });
  }
  function finTable(t, heads) {
    return '<section class="card flush fin"><div class="card-h"><h3 class="card-t">' + h(t.title) + "</h3>" + (t.note ? '<span class="card-sub">' + h(t.note) + "</span>" : "") + "</div>" +
      '<div class="tbl-wrap"><table class="tbl"><thead><tr><th class="sticky"></th>' + heads.map(function (x) { return "<th>" + h(x) + "</th>"; }).join("") + "</tr></thead><tbody>" +
      t.rows.map(function (r) {
        return '<tr class="' + (r.em ? "em" : "") + '"><td class="sticky' + (r.sub ? " sub" : "") + '">' + (r.sub ? '<span style="padding-left:12px">' + h(r.k) + "</span>" : h(r.k)) + (r.tip ? " " + IL.tip(r.tip) : "") + "</td>" +
          r.v.map(function (v) { var n = N(v); return '<td class="' + (r.sub ? "sub " : "") + (r.color && n !== null ? F.cls(n) : n !== null && n < 0 && !r.flow ? "down" : "") + '">' + r.f(v) + "</td>"; }).join("") + "</tr>";
      }).join("") + "</tbody></table></div></section>";
  }
  function finChart(points, aLabel, bLabel) {
    var pts = points.filter(function (p) { return p.a !== null; });
    if (pts.length < 2) return "";
    var W = 760, H = 170, pad = 10, n = pts.length;
    var max = Math.max.apply(null, pts.map(function (p) { return Math.max(p.a || 0, p.b || 0); }));
    var min = Math.min(0, Math.min.apply(null, pts.map(function (p) { return Math.min(p.a || 0, p.b || 0); })));
    var span = max - min || 1, zero = pad + (max / span) * (H - pad * 2);
    var slot = W / n, bw = Math.min(26, slot * 0.32);
    var y = function (v) { return pad + ((max - v) / span) * (H - pad * 2); };
    var bars = pts.map(function (p, i) {
      var x = i * slot + slot / 2;
      var a = '<rect x="' + (x - bw - 1).toFixed(1) + '" y="' + Math.min(y(p.a), zero).toFixed(1) + '" width="' + bw.toFixed(1) + '" height="' + Math.max(1, Math.abs(zero - y(p.a))).toFixed(1) + '" rx="3" fill="var(--text3)"><title>' + h(p.label + " " + aLabel + ": " + F.money(p.a)) + "</title></rect>";
      var b = p.b === null ? "" : '<rect x="' + (x + 1).toFixed(1) + '" y="' + Math.min(y(p.b), zero).toFixed(1) + '" width="' + bw.toFixed(1) + '" height="' + Math.max(1, Math.abs(zero - y(p.b))).toFixed(1) + '" rx="3" fill="' + (p.b < 0 ? "var(--loss)" : "var(--gold)") + '"><title>' + h(p.label + " " + bLabel + ": " + F.money(p.b)) + "</title></rect>";
      return a + b;
    }).join("");
    var labels = '<div class="bars-x" aria-hidden="true">' + pts.map(function (p, i) { return "<span>" + ((n <= 8 || i % 2 === (n - 1) % 2) ? h(p.label.replace(/^FY /, "")) : "") + "</span>"; }).join("") + "</div>";
    return '<section class="card fin-chart"><div class="card-h"><h3 class="card-t">' + h(aLabel) + " and " + h(bLabel.toLowerCase()) + '</h3><span class="row" style="gap:14px;font-size:12.5px"><span class="pc-key"><i style="background:var(--text3)"></i>' + h(aLabel) + '</span><span class="pc-key"><i style="background:var(--gold)"></i>' + h(bLabel) + "</span></span></div>" +
      '<svg viewBox="0 0 ' + W + " " + H + '" width="100%" preserveAspectRatio="none" style="height:170px" role="img" aria-label="' + h(aLabel + " and " + bLabel + " by period") + '"><line x1="0" x2="' + W + '" y1="' + zero.toFixed(1) + '" y2="' + zero.toFixed(1) + '" stroke="var(--line2)"/>' + bars + "</svg>" + labels + "</section>";
  }
  function downloadCsv() {
    if (!IL.user) { location.href = IL.signupHref(); return; }
    if (!IL.isPro()) { IL.dialog('<h2>CSV downloads are part of Pro</h2><p class="muted">Pro lets you download every statement, plus unlimited lookups, the Valuation Lab, alerts and every tab.</p><div class="row" style="justify-content:flex-end"><button class="btn ghost" data-close type="button">Not now</button><a class="btn primary" href="/pricing">Start the free trial</a></div>'); return; }
    if (!lastTables || !lastTables.tables) return;
    var lines = [["", ].concat(lastTables.heads)];
    lastTables.tables.forEach(function (t) {
      lines.push([t.title]);
      t.rows.forEach(function (r) { lines.push([r.k].concat(r.v.map(function (v) { var n = N(v); return n === null ? "" : String(n); }))); });
    });
    var csv = lines.map(function (l) { return l.map(function (c) { c = String(c); return /[",\n]/.test(c) ? '"' + c.replace(/"/g, '""') + '"' : c; }).join(","); }).join("\n");
    var a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([csv], { type: "text/csv" }));
    a.download = S.t + "-" + lastTables.name + "-financials.csv";
    document.body.appendChild(a); a.click(); a.remove();
  }

  /* ═════════════════════════════════════════════════════════════════════
     Valuation — what the price implies
     ═════════════════════════════════════════════════════════════════════ */
  function tabValuation(box) {
    box.innerHTML = '<section class="card">' + sk(240) + "</section>";
    Promise.all([D.hist(), D.quote()]).then(function (all) {
      var res = all[0];
      if (res.gate) { box.innerHTML = IL.gate(res.gate, "Create a free account to value " + S.t, { center: true, why: "See what growth today’s price is assuming, and build bear, base and bull cases from the company’s real numbers. Free, no card needed." }); return; }
      var q = quarterly(res.data), p = priceFacts();
      var rev = sumLast(q, "revenue", 4), ni = sumLast(q, "netIncome", 4);
      var shares = q.length ? N(q[q.length - 1].shares) : null;
      if (!res.ok || !p || !rev || !shares) {
        box.innerHTML = '<div class="gate center"><div class="gate-t">Not enough data to value ' + h(S.t) + ' here</div><div class="gate-s">This needs four quarters of revenue and a share count from SEC filings. Funds and foreign listings usually do not have them.</div><a class="btn" href="/?view=tool&section=projection&symbol=' + h(S.t) + '">Open the Valuation Lab</a></div>';
        return;
      }
      var ctx = {
        price: p.price, revenue: rev, shares: shares, netIncome: ni,
        margin: ni !== null ? ni / rev : null,
        pe: N(p.meta.trailingPE),
        growth1y: growth(rev, sumLast(q, "revenue", 4, 4)) / 100,
        growth3y: (function () { var old = sumLast(q, "revenue", 4, 12); return old ? IL.valuation.cagr(old, rev, 3) : null; })(),
      };
      if (!isFinite(ctx.growth1y)) ctx.growth1y = null;
      var key = "il-val-" + S.t, saved = null;
      try { saved = JSON.parse(localStorage.getItem(key) || "null"); } catch (_) {}
      var def = IL.valuation.defaults(ctx);
      var M = saved && saved.v === 1 ? saved.m : def;
      renderValuation(box, ctx, M, def, key);
    });
  }

  function renderValuation(box, ctx, M, def, key) {
    var V = IL.valuation;
    var cases = ["bear", "base", "bull"], label = { bear: "Bear case", base: "Base case", bull: "Bull case" };
    function pctIn(v) { return (Math.round(v * 1000) / 10).toString(); }
    box.innerHTML =
      '<section class="card val-hero" id="val-hero"></section>' +
      '<div class="section-h"><div><h2 class="section-t">Build your own cases</h2><p class="card-sub">Five years out. Start from what the company has done; change any number.</p></div><div class="row"><button class="btn sm ghost" type="button" id="val-reset">Reset</button></div></div>' +
      '<section class="card flush"><div class="tbl-wrap"><table class="tbl val-tbl"><thead><tr><th></th>' + cases.map(function (c) { return '<th class="val-' + c + '">' + label[c] + "</th>"; }).join("") + "</tr></thead><tbody>" +
        valRow("growth", "Revenue growth per year", "%", "How fast sales grow each year for the next five years.") +
        valRow("margin", "Net profit margin", "%", "Share of revenue kept as profit in year five. " + (ctx.margin !== null ? "Last 12 months: " + F.pct(ctx.margin * 100) + "." : "")) +
        valRow("exitPE", "P/E in five years", "×", "What investors pay for each $1 of earnings in year five. Fast growers usually get higher multiples; mature companies lower. " + (ctx.pe ? "Today: " + F.mult(ctx.pe) + "." : "")) +
        '<tr class="val-out"><td>Price in five years</td>' + cases.map(function (c) { return '<td id="o-fp-' + c + '"></td>'; }).join("") + "</tr>" +
        '<tr class="val-out"><td>Yearly return from today ' + IL.tip("The compound yearly return if you buy at today’s price and the case plays out. Dividends are not included.") + "</td>" + cases.map(function (c) { return '<td id="o-ar-' + c + '"></td>'; }).join("") + "</tr>" +
        '<tr class="val-out"><td>Worth today at your return ' + IL.tip("The year-five price discounted back at the yearly return you require. If this is above today’s price, the case beats your hurdle.") + "</td>" + cases.map(function (c) { return '<td id="o-vt-' + c + '"></td>'; }).join("") + "</tr>" +
      "</tbody></table></div>" +
      '<div class="val-foot"><label class="field" style="flex-direction:row;align-items:center;gap:10px">Return you require <input class="input num val-in" style="width:84px" id="v-req" inputmode="decimal" value="' + pctIn(M.required) + '"> %</label>' +
        '<label class="field" style="flex-direction:row;align-items:center;gap:10px">Share count change per year ' + IL.tip("Negative if the company buys back shares; positive if it issues new ones (for example to pay staff).") + ' <input class="input num val-in" style="width:84px" id="v-sh" inputmode="decimal" value="' + pctIn(M.shareChange) + '"> %</label></div></section>' +
      '<div class="grid-2">' +
        '<section class="card"><h3 class="card-t">Starting point</h3><div>' +
          '<div class="stat"><span class="k">Price</span><span class="v">' + F.price(ctx.price) + "</span></div>" +
          '<div class="stat"><span class="k">Revenue, last 12 months</span><span class="v">' + F.money(ctx.revenue) + "</span></div>" +
          '<div class="stat"><span class="k">Net margin, last 12 months</span><span class="v">' + (ctx.margin !== null ? F.pct(ctx.margin * 100) : "—") + "</span></div>" +
          '<div class="stat"><span class="k">Revenue growth, last year</span><span class="v ' + F.cls(ctx.growth1y) + '">' + (ctx.growth1y !== null ? F.spct(ctx.growth1y * 100) : "—") + "</span></div>" +
          '<div class="stat"><span class="k">Revenue growth, 3-year average</span><span class="v ' + F.cls(ctx.growth3y) + '">' + (ctx.growth3y !== null ? F.spct(ctx.growth3y * 100) : "—") + "</span></div>" +
          '<div class="stat"><span class="k">Diluted shares</span><span class="v">' + F.count(ctx.shares) + "</span></div>" +
        "</div></section>" +
        '<section class="card"><h3 class="card-t">How to read this</h3><p class="muted" style="font-size:13.5px">A stock price is a bet on the future. Instead of guessing a “fair value”, start with what the price already assumes, then ask whether the company can beat it. If the growth it needs is well above anything it has done, the stock is priced for perfection. If it is below, the market may be too gloomy.</p>' +
          '<p class="muted" style="font-size:13.5px">For a full discounted-cash-flow model with year-by-year margins, reinvestment and saved versions, open the Valuation Lab.</p>' +
          '<a class="card-foot" href="/?view=tool&section=projection&symbol=' + h(S.t) + '">Open the Valuation Lab →</a></section>' +
      "</div>";

    function valRow(field, text, unit, tip) {
      return "<tr><td>" + h(text) + " " + IL.tip(tip) + "</td>" + cases.map(function (c) {
        var v = M[c][field];
        return '<td><span class="val-cell"><input class="input num val-in" data-case="' + c + '" data-field="' + field + '" inputmode="decimal" aria-label="' + h(label[c] + " " + text) + '" value="' + (unit === "%" ? pctIn(v) : String(v)) + '"><span class="faint">' + unit + "</span></span></td>";
      }).join("") + "</tr>";
    }

    function read() {
      box.querySelectorAll("[data-case]").forEach(function (inp) {
        var c = inp.getAttribute("data-case"), f = inp.getAttribute("data-field");
        var n = Number(String(inp.value).replace(/[%x×,\s]/g, ""));
        if (!isFinite(n)) return;
        M[c][f] = f === "exitPE" ? n : n / 100;
      });
      var r = Number(IL.$("#v-req").value), s = Number(IL.$("#v-sh").value);
      if (isFinite(r)) M.required = r / 100;
      if (isFinite(s)) M.shareChange = s / 100;
    }
    function compute() {
      cases.forEach(function (c) {
        var out = V.project({ price: ctx.price, revenue: ctx.revenue, shares: ctx.shares, years: 5, growth: M[c].growth, margin: M[c].margin, exitPE: M[c].exitPE, shareChange: M.shareChange, required: M.required });
        IL.$("#o-fp-" + c).innerHTML = out ? '<b class="num">' + F.price(out.futurePrice) + "</b>" : "—";
        IL.$("#o-ar-" + c).innerHTML = out ? '<b class="num ' + F.cls(out.annualReturn) + '">' + F.spct(out.annualReturn * 100) + "</b>" : "—";
        IL.$("#o-vt-" + c).innerHTML = out ? '<span class="num">' + F.price(out.valueToday) + '</span> <span class="num ' + F.cls(out.upside) + '" style="font-size:12px">' + F.spct(out.upside * 100, 0) + "</span>" : "—";
      });
      hero();
      try { localStorage.setItem(key, JSON.stringify({ v: 1, m: M })); } catch (_) {}
    }
    function hero() {
      var m = M.base.margin, pe = M.base.exitPE;
      var g = V.impliedGrowth({ price: ctx.price, revenue: ctx.revenue, shares: ctx.shares, years: 5, margin: m, exitPE: pe, shareChange: M.shareChange, required: M.required });
      var past = ctx.growth3y !== null ? ctx.growth3y : ctx.growth1y;
      var verdict = "", tone = "";
      if (g !== null && past !== null) {
        var gap = g - past;
        if (gap > 0.05) { verdict = "The price asks for faster growth than the company has delivered."; tone = "bad"; }
        else if (gap < -0.05) { verdict = "The price asks for slower growth than the company has delivered."; tone = "good"; }
        else { verdict = "The price asks for roughly the growth the company has delivered."; tone = "gold"; }
      }
      IL.$("#val-hero").innerHTML =
        '<div class="val-h"><div><span class="card-sub">What the price implies ' + IL.tip("Solved backwards from today’s price: the yearly revenue growth that, with the base-case margin and P/E, earns exactly your required return.") + "</span>" +
          '<div class="val-big num">' + (g === null ? "—" : F.spct(g * 100)) + '<span class="val-unit">revenue growth a year</span></div>' +
          '<p class="muted val-sent">At ' + F.price(ctx.price) + ", " + h(S.t) + " earns a " + F.pct(M.required * 100, 0) + " yearly return if revenue grows about " + (g === null ? "—" : F.pct(g * 100)) + " a year for five years, it keeps a " + F.pct(m * 100) + " net margin, and investors still pay " + F.mult(pe) + " earnings in year five.</p></div>" +
          '<div class="val-cmp">' +
            '<div><span class="card-sub">Priced in</span><span class="num val-mid">' + (g === null ? "—" : F.spct(g * 100)) + "</span></div>" +
            '<div><span class="card-sub">Delivered, ' + (ctx.growth3y !== null ? "3 years" : "last year") + '</span><span class="num val-mid ' + F.cls(past) + '">' + (past === null ? "—" : F.spct(past * 100)) + "</span></div>" +
            (verdict ? '<span class="tag ' + tone + '" style="white-space:normal">' + h(verdict) + "</span>" : "") +
          "</div></div>" +
        (def.unprofitable ? '<p class="callout">' + IL.icon("info") + "<span><b>Not profitable yet.</b> The margin here is a target for year five, not today’s figure.</span></p>" : "");
    }
    box.addEventListener("input", function (e) { if (e.target.classList.contains("val-in")) { read(); compute(); } });
    IL.$("#val-reset").addEventListener("click", function () {
      try { localStorage.removeItem(key); } catch (_) {}
      M = JSON.parse(JSON.stringify(def));
      renderValuation(box, ctx, M, def, key);
    });
    compute();
  }

  /* ═════════════════════════════════════════════════════════════════════
     Earnings
     ═════════════════════════════════════════════════════════════════════ */
  function tabEarnings(box) {
    box.innerHTML =
      '<div class="grid-3 earn-top">' +
        '<section class="card" id="e-next"><h2 class="card-t">Next report</h2>' + sk(40) + "</section>" +
        '<section class="card" id="e-last"><h2 class="card-t">Last quarter</h2>' + sk(40) + "</section>" +
        '<section class="card" id="e-trend"><h2 class="card-t">Trend</h2>' + sk(40) + "</section>" +
      "</div>" +
      '<div id="e-chart"></div>' +
      '<div class="section-h"><h2 class="section-t">Earnings releases</h2><span class="card-sub">Each quarter’s press release (8-K) and the numbers from its 10-Q or 10-K</span></div>' +
      '<section class="card flush" id="e-rel"><div style="padding:20px">' + sk(120) + "</div></section>";

    D.lens().then(function () {
      var ne = nextEarnings(), el = IL.$("#e-next"); if (!el) return;
      el.innerHTML = '<h2 class="card-t">Next report</h2>' + (ne && ne.date
        ? '<div class="big-num num">' + h(nextEarningsText(ne, true)) + "</div><span class=\"card-sub\">" + (ne.days != null && ne.days >= 0 ? "In " + ne.days + " day" + (ne.days === 1 ? "" : "s") + ". " : "") + h(ne.estimated ? "Estimated from the company’s past reporting pattern; confirm on its investor site." : "Confirmed date.") + "</span>"
        : '<p class="muted">No date yet.</p>');
    });
    D.hist().then(function (res) {
      var last = IL.$("#e-last"), trend = IL.$("#e-trend"), chart = IL.$("#e-chart");
      if (!last) return;
      if (res.gate) {
        last.innerHTML = '<h2 class="card-t">Last quarter</h2><p class="muted" style="font-size:13.5px">Free account required.</p>';
        trend.innerHTML = '<h2 class="card-t">Trend</h2><p class="muted" style="font-size:13.5px">Free account required.</p>';
        chart.innerHTML = IL.gate(res.gate, "Create a free account to see every quarter", { why: "Revenue, profit and earnings per share for the last three years, from SEC filings." });
        return;
      }
      var q = quarterly(res.data);
      if (!res.ok || q.length < 2) { last.innerHTML = '<h2 class="card-t">Last quarter</h2><p class="muted">Not available.</p>'; trend.innerHTML = ""; chart.innerHTML = ""; return; }
      var l = q[q.length - 1], ago = q.length >= 5 ? q[q.length - 5] : null;
      var rg = ago ? growth(N(l.revenue), N(ago.revenue)) : null;
      last.innerHTML = '<h2 class="card-t">Last quarter</h2><div class="big-num num">' + F.money(l.revenue) + ' <span class="' + F.cls(rg) + '" style="font-size:15px">' + F.spct(rg, 0) + "</span></div><span class=\"card-sub\">Revenue, quarter ended " + F.date(l.end) + " · EPS " + F.eps(l.eps) + "</span>";
      var ups = 0, tot = 0;
      for (var i = Math.max(4, q.length - 8); i < q.length; i++) { var g = growth(N(q[i].revenue), N(q[i - 4].revenue)); if (g !== null) { tot++; if (g > 0) ups++; } }
      var accel = (function () {
        var a = q.length >= 5 ? growth(N(q[q.length - 1].revenue), N(q[q.length - 5].revenue)) : null;
        var b = q.length >= 6 ? growth(N(q[q.length - 2].revenue), N(q[q.length - 6].revenue)) : null;
        return a !== null && b !== null ? a - b : null;
      })();
      trend.innerHTML = '<h2 class="card-t">Trend</h2><div class="big-num num">' + ups + " of " + tot + '</div><span class="card-sub">quarters with revenue up on a year earlier' + (accel === null ? "." : Math.abs(accel) < 1 ? ". Growth held steady last quarter." : ". Growth " + (accel > 0 ? "sped up" : "slowed") + " by " + F.num(Math.abs(accel), 0) + " percentage points last quarter.") + "</span>";
      var cols = q.slice(-12);
      chart.innerHTML = '<div class="grid-2">' +
        finChart(cols.map(function (c) { return { label: c.label, a: N(c.revenue), b: N(c.netIncome) }; }), "Revenue", "Net income") +
        epsChart(cols) + "</div>";
    });
    D.calls().then(function (res) {
      var box2 = IL.$("#e-rel"); if (!box2) return;
      if (res.gate) {
        box2.innerHTML = '<div style="padding:16px">' + IL.gate(res.gate, "Earnings releases are part of Pro", { why: "Read every quarterly press release in plain text, with the headline numbers and links to the 10-Q, without leaving the page. Pro is $7.99 a month after a 30-day free trial." }) + "</div>";
        return;
      }
      var rel = (res.data && res.data.releases) || [];
      if (!rel.length) { box2.innerHTML = '<div class="empty">' + h((res.data && res.data.error) || "No earnings releases found in SEC filings.") + "</div>"; return; }
      box2.innerHTML = '<ul class="rel">' + rel.slice(0, 12).map(function (r) {
        var q = r.quarter || {};
        return '<li class="rel-i"><div class="rel-h"><div><div class="rel-t">' + h(r.title || "Results") + '</div><div class="faint" style="font-size:12.5px">Released ' + F.date(r.date) + (q.calendarLabel && q.calendarLabel !== q.label ? " · calendar " + h(q.calendarLabel) : "") + "</div></div>" +
          '<div class="rel-n">' + (r.pending ? '<span class="faint" style="font-size:12.5px">Numbers once the 10-Q is filed</span>' :
            '<span><span class="faint">Revenue</span> <b class="num">' + F.money(q.revenue) + '</b> <span class="num ' + F.cls(q.revenueYoY) + '">' + F.spct(q.revenueYoY, 0) + "</span></span>" +
            '<span><span class="faint">EPS</span> <b class="num">' + F.eps(q.eps) + '</b> <span class="num ' + F.cls(q.epsYoY) + '">' + F.spct(q.epsYoY, 0) + "</span></span>") + "</div></div>" +
          '<div class="row wrap"><button class="btn sm" type="button" data-rel="' + h(r.id) + '">Read the release</button>' +
            (r.indexUrl ? '<a class="btn sm ghost" href="' + h(r.indexUrl) + '" target="_blank" rel="noopener">8-K on SEC.gov ' + IL.icon("ext", 13) + "</a>" : "") +
            (r.report && r.report.url ? '<a class="btn sm ghost" href="' + h(r.report.url) + '" target="_blank" rel="noopener">' + h(r.report.form || "Report") + " " + IL.icon("ext", 13) + "</a>" : "") + "</div>" +
          '<div class="rel-body" id="rel-' + h(r.id) + '" hidden></div></li>';
      }).join("") + "</ul>";
      box2.addEventListener("click", function (e) {
        var b = e.target.closest("[data-rel]"); if (!b) return;
        var id = b.getAttribute("data-rel"), body = document.getElementById("rel-" + id);
        if (!body) return;
        if (!body.hidden) { body.hidden = true; b.textContent = "Read the release"; return; }
        body.hidden = false; b.textContent = "Hide the release";
        if (body.getAttribute("data-loaded")) return;
        body.innerHTML = sk(80);
        IL.api("/api/calls/" + S.t + "/" + encodeURIComponent(id)).then(function (r2) {
          var paras = (r2.data && r2.data.paragraphs) || [];
          body.setAttribute("data-loaded", "1");
          body.innerHTML = paras.length ? paras.slice(0, 60).map(function (p) { return "<p>" + h(p) + "</p>"; }).join("") : '<p class="muted">' + h((r2.data && r2.data.error) || "The release text could not be read.") + "</p>";
        });
      });
    });
  }
  function epsChart(cols) {
    var pts = cols.map(function (c) { return { label: c.label, v: N(c.eps) }; }).filter(function (p) { return p.v !== null; });
    if (pts.length < 2) return "";
    var W = 760, H = 170, pad = 10, n = pts.length;
    var max = Math.max(0, Math.max.apply(null, pts.map(function (p) { return p.v; })));
    var min = Math.min(0, Math.min.apply(null, pts.map(function (p) { return p.v; })));
    var span = max - min || 1, zero = pad + (max / span) * (H - pad * 2), slot = W / n, bw = Math.min(30, slot * 0.5);
    var y = function (v) { return pad + ((max - v) / span) * (H - pad * 2); };
    return '<section class="card fin-chart"><div class="card-h"><h3 class="card-t">Earnings per share</h3><span class="card-sub">Diluted, each quarter</span></div><svg viewBox="0 0 ' + W + " " + H + '" width="100%" preserveAspectRatio="none" style="height:170px" role="img" aria-label="Earnings per share by quarter"><line x1="0" x2="' + W + '" y1="' + zero.toFixed(1) + '" y2="' + zero.toFixed(1) + '" stroke="var(--line2)"/>' +
      pts.map(function (p, i) {
        var x = i * slot + slot / 2;
        return '<rect x="' + (x - bw / 2).toFixed(1) + '" y="' + Math.min(y(p.v), zero).toFixed(1) + '" width="' + bw.toFixed(1) + '" height="' + Math.max(1, Math.abs(zero - y(p.v))).toFixed(1) + '" rx="3" fill="' + (p.v < 0 ? "var(--loss)" : "var(--gold)") + '"><title>' + h(p.label + ": " + F.eps(p.v)) + "</title></rect>" +
          "";
      }).join("") + '</svg><div class="bars-x" aria-hidden="true">' + pts.map(function (p, i) { return "<span>" + ((n <= 8 || i % 2 === (n - 1) % 2) ? h(p.label) : "") + "</span>"; }).join("") + "</div></section>";
  }

  /* ═════════════════════════════════════════════════════════════════════
     Ownership
     ═════════════════════════════════════════════════════════════════════ */
  function tabOwnership(box) {
    box.innerHTML =
      '<div class="section-h"><div><h2 class="section-t">Famous investors</h2><p class="card-sub">Well-known fund managers who reported owning ' + h(S.t) + " in their latest 13F filing</p></div></div>" +
      '<section class="card flush" id="o-funds"><div style="padding:20px">' + sk(120) + "</div></section>" +
      '<div class="section-h"><div><h2 class="section-t">Insider trades</h2><p class="card-sub">Executives and directors buying or selling, from SEC Form 4</p></div></div>' +
      '<div id="o-ins"><section class="card">' + sk(120) + "</section></div>" +
      '<div class="section-h"><div><h2 class="section-t">Off-exchange trading</h2><p class="card-sub">Weekly volume traded away from the exchanges, from FINRA</p></div></div>' +
      '<div id="o-otc"><section class="card">' + sk(80) + "</section></div>";
    paintFunds(IL.$("#o-funds"), false);
    D.insiders().then(function (res) {
      var el = IL.$("#o-ins"); if (!el) return;
      if (res.gate) { el.innerHTML = IL.gate(res.gate, "Insider trades are part of Pro", { why: "See every executive and director purchase and sale, with the price paid and a link to the filing." }); return; }
      var d = res.data || {}, rows = d.insiders || [], sm = d.insiderSummary || {};
      if (!rows.length) { el.innerHTML = '<section class="card"><p class="muted">No insider trades reported recently.</p></section>'; return; }
      el.innerHTML = '<section class="card flush">' +
        '<div class="card-h"><span class="card-sub">Since ' + F.date(sm.since) + '</span><span class="row" style="gap:16px;font-size:13px"><span>Buys <b class="num up">' + (sm.buys || 0) + "</b> " + (sm.buyValue ? '<span class="num faint">' + F.money(sm.buyValue) + "</span>" : "") + '</span><span>Sells <b class="num down">' + (sm.sells || 0) + "</b> " + (sm.sellValue ? '<span class="num faint">' + F.money(sm.sellValue) + "</span>" : "") + "</span></span></div>" +
        '<div class="tbl-wrap"><table class="tbl"><thead><tr><th>Insider</th><th>Trade</th><th>Shares</th><th>Price</th><th>Value</th><th>Date</th></tr></thead><tbody>' +
        rows.slice(0, 25).map(function (x) {
          var sh = N(x.change) !== null ? N(x.change) : N(x.shares);
          var buy = x.code === "P" || (sh !== null && sh > 0 && x.code !== "S");
          var what = x.code === "P" ? "Bought" : x.code === "S" ? "Sold" : x.code === "M" ? "Exercised options" : x.code === "A" ? "Granted" : x.code === "F" ? "Tax withholding" : x.code === "G" ? "Gift" : buy ? "Acquired" : "Disposed";
          return "<tr><td><b>" + h(x.name) + '</b><div class="faint" style="font-size:12px">' + h(x.role || "") + '</div></td><td><span class="tag ' + (x.code === "P" ? "good" : x.code === "S" ? "bad" : "") + '">' + what + "</span></td><td>" + F.count(sh !== null ? Math.abs(sh) : null) + "</td><td>" + F.price(x.price) + "</td><td>" + (N(x.price) && sh ? F.money(Math.abs(sh) * N(x.price)) : "—") + '</td><td class="sub">' + (x.url ? '<a href="' + h(x.url) + '" target="_blank" rel="noopener">' + F.date(x.date) + "</a>" : F.date(x.date)) + "</td></tr>";
        }).join("") + "</tbody></table></div>" +
        '<p class="note" style="padding:12px 20px">Option exercises, grants and tax withholding are routine pay, not a view on the stock. Open-market buys (“Bought”) are the ones investors watch.</p></section>';
    });
    D.dark().then(function (res) {
      var el = IL.$("#o-otc"); if (!el) return;
      if (res.gate) { el.innerHTML = IL.gate(res.gate, "Off-exchange trading is part of Pro", { slim: true }); return; }
      var rows = ((res.data && res.data.otcActivity) || []).slice(0, 8);
      if (!rows.length) { el.innerHTML = '<section class="card"><p class="muted">No off-exchange activity reported for this ticker.</p></section>'; return; }
      el.innerHTML = '<section class="card flush"><div class="tbl-wrap"><table class="tbl"><thead><tr><th>Week of</th><th>Shares</th><th>Trades</th><th>Average price</th></tr></thead><tbody>' +
        rows.map(function (r) { return "<tr><td>" + F.date(r.weekStartDate) + "</td><td>" + F.count(r.totalWeeklyShareQuantity) + "</td><td>" + F.count(r.totalWeeklyTradeCount) + "</td><td>" + F.price(r.averageReportedPrice) + "</td></tr>"; }).join("") +
        '</tbody></table></div><p class="note" style="padding:12px 20px">FINRA publishes these figures with a delay of two to four weeks.</p></section>';
    });
  }

  /* ═════════════════════════════════════════════════════════════════════
     Filings
     ═════════════════════════════════════════════════════════════════════ */
  var FILING_HELP = {
    "10-K": "Annual report", "10-Q": "Quarterly report", "8-K": "Major event or results", "DEF 14A": "Proxy: pay and shareholder votes",
    "4": "Insider trade", "S-1": "Registration", "SC 13G": "5%+ owner", "SC 13G/A": "5%+ owner update", "SC 13D": "Activist 5%+ owner",
    "144": "Planned insider sale", "3": "New insider", "10-K/A": "Annual report amendment", "10-Q/A": "Quarterly report amendment", "20-F": "Annual report (foreign)", "6-K": "Foreign issuer report",
  };
  function tabFilings(box) {
    box.innerHTML =
      '<div class="section-h"><div><h2 class="section-t">SEC filings</h2><p class="card-sub">Everything the company files with the SEC, newest first</p></div>' +
        '<div class="seg" role="group" aria-label="Filter filings" id="fl-f"><button type="button" data-ff="all" aria-pressed="true">All</button><button type="button" data-ff="reports" aria-pressed="false">10-K and 10-Q</button><button type="button" data-ff="8-K" aria-pressed="false">8-K</button><button type="button" data-ff="insider" aria-pressed="false">Insider</button><button type="button" data-ff="proxy" aria-pressed="false">Proxy</button></div></div>' +
      '<section class="card flush" id="fl-list"><div style="padding:20px">' + sk(160) + "</div></section>";
    D.sec().then(function (res) {
      var el = IL.$("#fl-list"); if (!el) return;
      if (res.gate) {
        IL.$("#fl-f").style.display = "none";
        el.innerHTML = '<div style="padding:16px">' + IL.gate(res.gate, "The full filing history is part of Pro", { why: "Every 10-K, 10-Q, 8-K, proxy and insider filing with a plain-English label and a direct link. Below are the latest company announcements, free." }) + '</div><div class="card-h" style="border-top:1px solid var(--line)"><h3 class="card-t">Latest announcements</h3></div><div id="fl-news"></div>';
        paintNews(IL.$("#fl-news"), 10);
        return;
      }
      var all = (res.data && res.data.filings) || [];
      if (!all.length) { el.innerHTML = '<div class="empty">No SEC filings found for this ticker.</div>'; return; }
      var filter = "all";
      function keep(f) {
        var form = String(f.form || "");
        if (filter === "reports") return /^10-[KQ]/.test(form);
        if (filter === "8-K") return /^8-K/.test(form);
        if (filter === "insider") return /^(3|4|5|144)(\/A)?$/.test(form);
        if (filter === "proxy") return /14A/.test(form);
        return true;
      }
      function paint() {
        var rows = all.filter(keep).slice(0, 80);
        el.innerHTML = rows.length ? '<div class="tbl-wrap"><table class="tbl"><thead><tr><th>Form</th><th style="text-align:left">What it is</th><th>Filed</th><th></th></tr></thead><tbody>' +
          rows.map(function (f) {
            var url = f.viewerUrl || f.indexUrl;
            return "<tr><td><b>" + h(f.form) + '</b></td><td style="text-align:left;font-family:var(--sans);white-space:normal">' + h(FILING_HELP[f.form] || "") + (f.description && f.description !== f.form ? ' <span class="faint">' + h(f.description) + "</span>" : "") + '</td><td class="sub">' + F.date(f.date) + "</td><td>" + (url ? '<a href="' + h(url) + '" target="_blank" rel="noopener">Open ' + IL.icon("ext", 13).replace("<svg", '<svg style="display:inline;vertical-align:-2px"') + "</a>" : "") + "</td></tr>";
          }).join("") + "</tbody></table></div>" : '<div class="empty">No filings of this type.</div>';
      }
      IL.$("#fl-f").addEventListener("click", function (e) {
        var b = e.target.closest("[data-ff]"); if (!b) return;
        filter = b.getAttribute("data-ff");
        IL.$$("#fl-f [data-ff]").forEach(function (x) { x.setAttribute("aria-pressed", String(x === b)); });
        paint();
      });
      paint();
    });
  }

  /* ═════════════════════════════════════════════════════════════════════
     Boot
     ═════════════════════════════════════════════════════════════════════ */
  function notFound(msg) {
    main().innerHTML = '<div class="gate center" style="margin-top:40px"><div class="gate-t">We could not find ' + h(S.t) + '</div><div class="gate-s">' + h(msg || "Check the ticker, or search by company name.") + '</div><a class="btn primary" href="/research">Search for a company</a></div>';
  }

  function boot() {
    IL.shell("research");
    var p = parsePath();
    if (!p.t) { renderLanding(); return; }
    S.t = p.t; S.tab = p.tab;
    renderFrame();
    IL.me();
    D.quote().then(function (res) {
      if (res.gate) {
        IL.$("#sh-px").innerHTML = "";
        IL.$("#sh-name").textContent = S.t;
        IL.$("#tab").innerHTML = IL.gate(res.gate, null, { center: true });
        IL.$(".tabs").style.display = "none";
        return;
      }
      if (!res.ok) {
        if (res.status === 404 || res.status === 400) { notFound(res.data && res.data.error); return; }
        IL.$("#sh-px").innerHTML = '<span class="muted">Prices are unavailable right now.</span>';
      } else {
        S.quote = IL.seriesFrom(res.data);
        S.quote.provenance = res.data.impliedLens || null;
      }
      fillHeader();
      go(S.tab, false);
      D.lens().then(function (lr) {
        S.lensRes = lr;
        S.lens = lr.ok ? lr.data : null;
        fillHeader();
      });
    });
  }
  /* Overview paints the report card once lens data lands; make sure the
     shared promise resolves S.lens before those painters run. */
  var lensRaw = D.lens;
  D.lens = function () {
    return lensRaw().then(function (lr) { S.lensRes = lr; S.lens = lr.ok ? lr.data : null; return lr; });
  };

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot);
  else boot();
})();

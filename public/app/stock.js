/* ═══════════════════════════════════════════════════════════════════════════
   The stock page: /research/:ticker[/tab]

   Overview · Financials · Projection Lab · Earnings · Ownership · Filings

   Every tab is drawn from the existing APIs. What a visitor cannot see is
   replaced with a clear gate (free account or Pro), never a blank panel.
   ═══════════════════════════════════════════════════════════════════════════ */
(function () {
  "use strict";
  var IL = window.IL, F = IL.fmt, h = IL.h, N = IL.n;

  var TABS = [
    { key: "overview", label: "Overview" },
    { key: "financials", label: "Financials" },
    { key: "projection", label: "Projection Lab" },
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
    if (tab === "valuation") tab = "projection";      // the tab's old address keeps working
    if (!TABS.some(function (x) { return x.key === tab; })) tab = "overview";
    if (t && !/^[A-Z0-9.^-]{1,15}$/.test(t)) t = null;
    return { t: t, tab: tab, lab: parts[0] === "projection" };
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
    hist: function () { return get("hist", "/api/fundamentals/history/" + S.t).then(function (r) { S.histRes = r; return r; }); },
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
    var r = size / 2 - 7, c = 2 * Math.PI * r, pct = Math.max(0, Math.min(1, Number(score) / 10));
    /* Gold, flat, no glow: the score is the brand's number, not a gain or a
       loss, so it does not take green or red (rulebook 3, 4). */
    var mid = size / 2;
    return '<svg class="ring" width="' + size + '" height="' + size + '" viewBox="0 0 ' + size + " " + size + '" role="img" aria-label="LensScore ' + h(F.num(score, 1)) + ' out of 10">' +
      '<circle cx="' + mid + '" cy="' + mid + '" r="' + r + '" fill="none" stroke="var(--line2)" stroke-width="9"/>' +
      '<circle cx="' + mid + '" cy="' + mid + '" r="' + r + '" fill="none" stroke="var(--gold)" stroke-width="9" stroke-linecap="round" stroke-dasharray="' + (c * pct).toFixed(1) + " " + c.toFixed(1) + '" transform="rotate(-90 ' + mid + " " + mid + ')"/>' +
      '<text x="50%" y="50%" dy="0.36em" text-anchor="middle" font-family="IBM Plex Sans, sans-serif" font-weight="700" font-size="' + Math.round(size * 0.28) + '" fill="var(--text)">' + h(F.num(score, 1)) + "</text></svg>";
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
    var year = bars.slice(IL.windowStart(bars, IL.YEAR_DAYS));
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
    var yr = IL.yearReturn(bars);
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
  function tile(href, plate, pos, title, sub) {
    return '<a class="card lift tile" href="' + href + '"><span class="tile-art" style="--plate:url(' + IL.plateSrc(plate) + ');--plate-pos:' + pos + '" aria-hidden="true"></span>' +
      '<span class="tile-body"><span class="card-t">' + title + ' <span class="tile-go">' + IL.icon("arrow", 14) + '</span></span><span class="card-sub">' + sub + "</span></span></a>";
  }
  /* /projection: the Projection Lab's front door. Pick a company; the lab
     opens on its own page with its filings already loaded. */
  function renderProjectionLanding() {
    document.title = "Projection Lab · ImpliedLens";
    var popular = ["NVDA", "AMD", "AAPL", "MSFT", "AMZN", "META", "TSLA", "CELH", "COST", "PLTR"];
    main().innerHTML =
      '<section class="rl-hero pj-landing">' +
        IL.eyebrow("Projection Lab") +
        '<h1 class="display">What does the price already assume?</h1>' +
        '<p class="muted">Pick a company. The lab loads its revenue, margins and share count from SEC filings, solves for the growth today\u2019s price needs, and builds bear, base and bull cases you can change line by line.</p>' +
        '<div class="il-search rl-search" role="search"><label class="il-search-box">' + IL.icon("search", 18) +
          '<input id="pj-q" type="search" autocomplete="off" spellcheck="false" placeholder="Company name or ticker, e.g. AMD or Celsius" aria-label="Search a company to project" role="combobox" aria-expanded="false" aria-controls="pj-sugg"></label>' +
          '<div class="il-sugg" id="pj-sugg" role="listbox" hidden></div></div>' +
        '<div class="row wrap rl-pop"><span class="faint">Try:</span>' + popular.map(function (t) { return '<a class="tag" href="/research/' + t + '/projection">' + t + "</a>"; }).join("") + "</div>" +
      "</section>" +
      '<div class="grid-3 pj-how">' +
        '<section class="card"><h2 class="card-t">1. What the price implies</h2><p class="muted">The yearly revenue growth that, at today\u2019s price, earns your required return. Compare it with what the company is actually delivering.</p></section>' +
        '<section class="card"><h2 class="card-t">2. Three cases from real numbers</h2><p class="muted">Growth starts from recent quarters and fades toward 4%. Acquisitions and one-off share changes are spotted and left out, and every starting number says where it came from.</p></section>' +
        '<section class="card"><h2 class="card-t">3. Your odds, one answer</h2><p class="muted">Weight the cases by how likely you think each is, see the expected yearly return, then save the version or share it as an image.</p></section>' +
      "</div>";
    IL.plate(IL.$(".rl-hero"), "engraved", "70% 60%");
    IL.wireSearch(IL.$("#pj-q"), IL.$("#pj-sugg"), function (t) { location.href = "/research/" + encodeURIComponent(t) + "/projection"; });
  }

  function renderLanding() {
    document.title = "Research a stock · ImpliedLens";
    var popular = ["NVDA", "AAPL", "MSFT", "AMZN", "GOOGL", "META", "TSLA", "COST", "JPM", "LLY", "AVGO", "NFLX"];
    main().innerHTML =
      '<section class="rl-hero">' +
        IL.eyebrow("Stock research for every level", "research") +
        '<h1 class="display">Research any stock like a <em>professional.</em></h1>' +
        '<p class="muted">A plain-English report card, the full financials, what the price is assuming, earnings releases and who owns it. Straight from SEC filings.</p>' +
        '<div class="il-search rl-search" role="search"><label class="il-search-box">' + IL.icon("search", 18) +
          '<input id="rl-q" type="search" autocomplete="off" spellcheck="false" placeholder="Company name or ticker, e.g. Apple or AAPL" aria-label="Search a company or ticker" role="combobox" aria-expanded="false" aria-controls="rl-sugg"></label>' +
          '<div class="il-sugg" id="rl-sugg" role="listbox" hidden></div></div>' +
        '<div class="row wrap rl-pop"><span class="faint">Popular:</span>' + popular.map(function (t) { return '<a class="tag" href="/research/' + t + '">' + t + "</a>"; }).join("") + "</div>" +
      "</section>" +
      '<div class="grid-3 rl-tools">' +
        tile("/compare", "atlas", "52% 70%", "Compare", "Up to four stocks side by side, with the best in each row marked.") +
        tile("/screener", "ledger", "60% 40%", "Screener", "Filter the <span data-graded>~280</span> US stocks we grade by grade, value, size and momentum.") +
        tile("/lens-score", "dial", "75% 45%", "LensToolkit", "Trend, timing, buy zones and alerts for any stock.") +
        tile("/projection", "engraved", "70% 70%", "Projection Lab", "Bear, base and bull cases from any company\u2019s filings, and what its price already assumes.") +
      "</div>" +
      '<div class="section-h"><h2 class="section-t">Top-rated in each <em>sector</em></h2><span class="card-sub">Highest LensScore among the companies we grade</span></div>' +
      '<div class="card flush" id="rl-leaders" data-w="expand,csv" data-w-title="Top-rated by sector"><div style="padding:20px">' + sk(16) + "</div></div>" +
      '<div class="grid-2">' +
        '<section class="card flush" id="rl-track" data-w="expand" data-w-title="Track record"><div class="card-h"><h2 class="card-t">Does the LensScore work?</h2><span class="card-sub">Our public track record</span></div><div style="padding:20px">' + sk(80) + "</div></section>" +
        '<section class="card flush" id="rl-movers" data-w="expand" data-w-title="Grade changes"><div class="card-h"><h2 class="card-t">Biggest grade changes this week</h2></div><div style="padding:20px">' + sk(80) + "</div></section>" +
      "</div>";
    IL.wireSearch(IL.$("#rl-q"), IL.$("#rl-sugg"));
    IL.plate(IL.$(".rl-hero"), "globe", "62% 30%");
    IL.widgets(main());
    IL.api("/api/lens-leaders").then(function (res) {
      var box = IL.$("#rl-leaders");
      var d = res.data || {};
      paintTrack(d); paintGradeMovers(d);
      var rows = (d.sectors || []).filter(function (s) { return s.top && s.top.length; });
      rows.sort(function (a, b) { return (b.count || 0) - (a.count || 0); });
      if (!res.ok || !rows.length) { box.innerHTML = '<div class="empty">Grades are still loading. Search for a company above.</div>'; return; }
      var keys = ["value", "growth", "profitability", "health", "momentum"];
      var head = IL.$("#peers"); if (head && !head.querySelector(".link")) head.insertAdjacentHTML("beforeend", '<a class="link" href="/compare?t=' + list.slice(0, 4).join(",") + '">Compare side by side \u2192</a>');
      box.innerHTML = '<div class="tbl-wrap"><table class="tbl"><thead><tr><th>Sector</th><th style="text-align:left">Top-rated</th><th>LensScore</th>' + keys.map(function (k) { return "<th>" + FACTOR_LABEL[k] + "</th>"; }).join("") + '<th style="text-align:left">Runners-up</th></tr></thead><tbody>' +
        rows.map(function (r) {
          var top = r.top[0];
          return '<tr class="click" data-go="' + h(top.ticker) + '"><td>' + h(r.sectorName || r.sector) + ' <span class="faint num">(' + (r.count || "") + ')</span></td><td style="text-align:left;font-family:var(--sans)"><span class="cell-co">' + IL.mono(top.ticker, r.sectorName, "sm") + '<span><a href="/research/' + h(top.ticker) + '"><b>' + h(top.ticker) + '</b></a> <span class="muted">' + h(IL.cleanName(top.name || "")) + '</span></span></span></td><td><span class="pill score ' + IL.scoreTone(top.score) + '">' + F.num(top.score, 1) + "</span></td>" +
            keys.map(function (k) { return "<td>" + IL.gchip(top.grades && top.grades[k]) + "</td>"; }).join("") +
            '<td style="text-align:left;font-family:var(--sans)">' + r.top.slice(1, 3).map(function (x) { return '<a href="/research/' + h(x.ticker) + '">' + h(x.ticker) + ' <span class="num faint">' + F.num(x.score, 1) + "</span></a>"; }).join(" · ") + "</td></tr>";
        }).join("") + "</tbody></table></div>";
    });
    main().addEventListener("click", function (e) { var r = e.target.closest("[data-go]"); if (r && !e.target.closest("a,button,input")) IL.go(r.getAttribute("data-go")); });
  }

  /* The score's own record: how each score band has done since the first
     daily snapshot, against the average of every graded company. */
  function paintTrack(d) {
    var box = IL.$("#rl-track"); if (!box) return;
    var tr = d && d.trackRecord, start = d && d.historyStarts;
    if (!tr || !tr.bands || !tr.companies) {
      box.innerHTML = '<div class="card-h"><h2 class="card-t">Does the LensScore work?</h2></div><p class="muted" style="padding:16px 20px">' +
        (start ? "We save every grade each trading day, starting " + h(F.date(start)) + ". Results by score band appear here as the record grows, good or bad." : "The daily record of every grade starts soon. Results appear here as they build up.") + "</p>";
      return;
    }
    var days = tr.startDay && tr.endDay ? Math.round((Date.parse(tr.endDay) - Date.parse(tr.startDay)) / 864e5) : null;
    box.innerHTML = '<div class="card-h"><h2 class="card-t">Does the LensScore work?</h2><span class="card-sub">Price change since ' + h(F.date(tr.startDay)) + ", by starting score</span></div>" +
      '<div class="tbl-wrap"><table class="tbl"><thead><tr><th>Score on day one</th><th>Companies</th><th>Average change</th><th>vs all graded</th></tr></thead><tbody>' +
      tr.bands.filter(function (b) { return b.count; }).map(function (b) {
        return "<tr><td>" + h(b.label) + "</td><td>" + b.count + '</td><td class="' + F.cls(b.averageReturn) + '">' + F.spct(b.averageReturn) + '</td><td class="' + F.cls(b.beatAll) + '">' + F.spct(b.beatAll) + "</td></tr>";
      }).join("") + '<tr class="em"><td>All graded</td><td>' + tr.companies + '</td><td class="' + F.cls(tr.allAverage) + '">' + F.spct(tr.allAverage) + "</td><td></td></tr></tbody></table></div>" +
      '<p class="note" style="padding:10px 20px 14px">' + (days !== null && days < 90 ? "Only " + days + " days so far: far too short to judge. " : "") + "Price change only, no dividends. Past results do not predict future ones; we publish them either way.</p>";
  }
  function paintGradeMovers(d) {
    var box = IL.$("#rl-movers"); if (!box) return;
    var m = d && d.movers;
    if (!m || (!m.up.length && !m.down.length)) { box.innerHTML = '<div class="card-h"><h2 class="card-t">Biggest grade changes this week</h2></div><p class="muted" style="padding:16px 20px">No score changes yet this week.</p>'; return; }
    var row = function (x) { return '<li><a href="/research/' + h(x.ticker) + '"><b>' + h(x.ticker) + '</b><span class="faint">' + h(IL.cleanName(x.name || "")) + '</span></a><span class="num"><span class="faint">' + F.num(x.then, 1) + ' \u2192 </span><b class="' + F.cls(x.change) + '">' + F.num(x.now, 1) + "</b></span></li>"; };
    box.innerHTML = '<div class="card-h"><h2 class="card-t">Biggest grade changes this week</h2><span class="card-sub">LensScore since ' + h(F.date(m.since, { year: undefined })) + "</span></div>" +
      '<ul class="mini">' + m.up.slice(0, 4).map(row).join("") + m.down.slice(0, 3).map(row).join("") + "</ul>";
  }

  /* ═════════════════════════════════════════════════════════════════════
     Stock page frame: header, actions, tabs
     ═════════════════════════════════════════════════════════════════════ */
  function renderFrame() {
    main().innerHTML =
      '<section class="sh card prime hero-band" id="sh">' +
        '<div class="sh-id">' +
          '<div class="sh-top"><span id="sh-mono">' + IL.mono(S.t, "", "lg") + '</span><div><div class="sh-meta"><span class="sh-sym">' + h(S.t) + '</span><span id="sh-sector" class="muted"></span></div>' +
          '<h1 class="sh-name" id="sh-name">' + sk(26, "260px") + "</h1></div></div>" +
          '<div class="sh-px" id="sh-px">' + sk(30, "220px") + "</div>" +
        "</div>" +
        '<div class="sh-actions">' +
          '<button class="btn" type="button" id="act-watch" aria-pressed="false">' + IL.icon("star") + '<span>Watch</span></button>' +
          '<button class="btn" type="button" id="act-alert">' + IL.icon("bell") + "<span>Alert</span></button>" +
          '<a class="btn primary" href="/research/' + h(S.t) + '/projection" data-tab="projection">Open the Projection Lab</a>' +
        "</div>" +
      "</section>" +
      '<nav class="tabs" aria-label="Stock sections">' + TABS.map(function (t) {
        return '<a href="/research/' + h(S.t) + (t.key === "overview" ? "" : "/" + t.key) + '" data-tab="' + t.key + '"' + (t.key === S.tab ? ' aria-current="page"' : "") + ">" + t.label + "</a>";
      }).join("") + "</nav>" +
      '<div id="tab"></div>';
    wireActions();
    IL.plate(IL.$("#sh"), "engraved", "right 32%");
  }

  /* A one-year sparkline with a gold wash, top right of the header. */
  /* The header used to carry a small unlabelled sparkline and its own
     "past year" figure. The full chart with axes sits just below and the
     key numbers give the past year, so the header keeps to identity, price
     and actions (rulebook 6). */


  function fillHeader() {
    var p = priceFacts(), meta = p ? p.meta : {}, lens = S.lens || {};
    var name = displayName(meta.longName, meta.shortName, lens.company);
    IL.$("#sh-name").textContent = name;
    document.title = S.t + " " + (p ? F.price(p.price) + " " : "") + "· " + name + " · ImpliedLens";
    var bits = [meta.fullExchangeName || meta.exchangeName, meta.sector, meta.industry].filter(Boolean);
    IL.$("#sh-sector").textContent = bits.join(" · ");
    var mono = IL.$("#sh-mono"); if (mono) mono.innerHTML = IL.mono(S.t, meta.sector || (lens.grades && lens.grades.sectorName), "lg");
    if (!p) { IL.$("#sh-px").innerHTML = '<span class="muted">Price unavailable</span>'; return; }
    var session = p.provenance && p.provenance.marketSession;
    var when = session === "regular"
      /* The provider's own quote time when it sends one; never the bar's
         start-of-day stamp, and never just "now" (audit F15). */
      ? "Delayed price · " + new Date((p.provenance.quoteTime || p.provenance.asOf || p.provenance.retrievedAt) || Date.now()).toLocaleTimeString("en-US", { hour: "numeric", minute: "2-digit", timeZone: "America/New_York" }) + " ET"
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
    ({ overview: tabOverview, financials: tabFinancials, projection: tabProjection, earnings: tabEarnings, ownership: tabOwnership, filings: tabFilings }[tab])(box);
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
          '<section class="card prime lr" aria-label="Lens Report" id="ov-lr" data-w="share,expand" data-w-title="The Lens Report"><div class="lr-h"><h2 class="card-t">The Lens Report</h2></div>' + sk(90) + "</section>" +
          '<section class="card pc" aria-label="Price chart" id="ov-chart"></section>' +
          '<section class="kv" aria-label="Key numbers" id="ov-kv">' + Array(8).join('<div><span class="k">' + sk(10, "60%") + '</span><span class="v">' + sk(16, "50%") + "</span></div>") + "</section>" +
          '<div class="grid-3">' +
            '<section class="card" id="ov-q" data-w="expand" data-w-title="Latest quarter"><h2 class="card-t">Latest quarter</h2>' + sk(60) + "</section>" +
            '<section class="card" id="ov-f" data-w="expand" data-w-title="Famous investors"><h2 class="card-t">Famous investors</h2>' + sk(60) + "</section>" +
            '<section class="card" id="ov-r" data-w="expand" data-w-title="Risk"><h2 class="card-t">How risky has it been?</h2>' + sk(60) + "</section>" +
          "</div>" +
        "</div>" +
        '<aside class="card prime rc" aria-label="LensScore report card" id="ov-rc" data-w="share,expand" data-w-title="LensScore">' + sk(220) + "</aside>" +
      "</div>" +
      '<div class="section-h" id="report"><h2 class="section-t">Full report <em>card</em></h2><span class="card-sub" id="rep-sub"></span></div>' +
      '<div class="grid-2" id="ov-rep"><section class="card">' + sk(140) + '</section><section class="card">' + sk(140) + "</section></div>" +
      '<div class="section-h" id="peers"><h2 class="section-t">Compared with <em>peers</em></h2><span class="card-sub">Same sector, graded the same way</span></div>' +
      '<section class="card flush" id="ov-peers"><div style="padding:20px">' + sk(80) + "</div></section>" +
      '<div class="section-h"><h2 class="section-t">Latest from the company</h2><a class="link" href="/research/' + h(S.t) + '/filings" data-tab="filings">All filings →</a></div>' +
      '<section class="card flush" id="ov-news"><div style="padding:20px">' + sk(60) + "</div></section>";

    S.chart = IL.PriceChart(IL.$("#ov-chart"), { ticker: S.t, seed: S.quote || undefined });
    IL.widgetShare["ov-lr"] = IL.widgetShare["ov-rc"] = function () { var inp = reportInputs(); shareCard(inp, IL.analysis.flags(inp)); };
    IL.widgets(box);
    paintKeyNumbers();
    paintRisk();
    D.lens().then(function () { paintReportCard(); paintKeyNumbers(); paintReport(); paintPeers(); paintLensReport(); });
    D.hist().then(paintLensReport);
    paintLatestQuarter();
    paintFunds(IL.$("#ov-f"), true);
    paintNews(IL.$("#ov-news"), 6);
  }

  /* ── The Lens Report: verdict, story, green and red flags ─────────────── */
  function reportInputs() {
    var A = IL.analysis;
    var f = S.histRes && S.histRes.ok ? A.fundamentals(S.histRes.data) : null;
    var p = S.quote ? A.priceFacts(S.quote.bars, S.quote.meta) : null;
    var g = S.lens && S.lens.grades && S.lens.grades.status === "graded" ? S.lens.grades : null;
    var v = A.valuation(f, p, S.quote ? N(S.quote.meta.trailingPE) : null);
    var meta = S.quote ? S.quote.meta : {};
    return { ticker: S.t, name: IL.$("#sh-name") ? IL.$("#sh-name").textContent : S.t, fundamentals: f, price: p, grades: g, valuation: v, meta: meta };
  }
  function paintLensReport() {
    var box = IL.$("#ov-lr"); if (!box) return;
    if (!S.histRes && once.hist) return;   // the history request is still on its way
    var inp = reportInputs(), A = IL.analysis;
    var fl = A.flags(inp), st = A.story(inp), cov = A.coverage(inp);
    var notRun = S.histRes && S.histRes.gate ? "Not checked: the sales, margin, cash-flow and dilution checks need a free account." : "Not checked: SEC filings for these checks aren’t available for this company.";
    var good = fl.filter(function (x) { return x.tone === "good"; }), bad = fl.filter(function (x) { return x.tone === "bad"; });
    var v = inp.valuation;
    var verdict = v && v.verdict
      ? '<span class="tag">' + h(v.verdict.label) + "</span>"     /* a reading, not a gain or loss: neutral (rulebook 3) */
      : "";
    function list(items, cls, empty) {
      if (!items.length) return '<p class="muted lr-empty">' + h(empty) + "</p>";
      return '<ul class="lr-flags ' + cls + '">' + items.slice(0, 5).map(function (x) {
        return '<li><span class="lr-ico" aria-hidden="true"></span><div><b>' + h(x.title) + '</b><span>' + h(x.detail) + "</span></div></li>";
      }).join("") + "</ul>";
    }
    var gated = S.histRes && S.histRes.gate;
    box.innerHTML =
      '<div class="lr-h"><h2 class="card-t lr-title">The Lens <em>Report</em> ' + IL.tip("Written automatically from the company’s SEC filings, its grades against sector peers and a year of prices. Every point shows the number behind it. Not investment advice.") + "</h2>" + verdict + "</div>" +
      (st.length ? '<p class="lr-story">' + st.map(h).join(" ") + "</p>" : '<p class="muted">Not enough data to write a report for this company yet.</p>') +
      '<div class="lr-cols">' +
        '<div><h3 class="lr-sub good">What’s working</h3>' + list(good, "good", cov.statements ? "Nothing stands out in the checks we ran." : notRun) + "</div>" +
        '<div><h3 class="lr-sub bad">Warning signs</h3>' + list(bad, "bad", cov.statements ? "No warning signs in the checks we ran." : notRun) + "</div>" +
      "</div>" +
      (gated ? '<p class="lr-gate">' + IL.icon("lock", 14) + ' <span>Sales, margin, cash-flow and dilution checks need a free account. <a href="' + IL.signupHref() + '">Create one</a> · no card.</span></p>' : "") +
      '<div class="lr-foot"><a class="link" href="/research/' + h(S.t) + '/projection" data-tab="projection">Test the price in the Projection Lab →</a><button class="link" type="button" id="lr-share">Share this report</button></div>';
    var sh = IL.$("#lr-share"); if (sh) sh.addEventListener("click", function () { shareCard(inp, fl); });
  }

  /* ── Share card: a 1200×630 image of the report, made in the browser ──
     A fixed engraved plate (the same for every stock) lit in the middle,
     with the live data in two darkened side columns: the stock and its
     implied-vs-delivered growth on the left, the LensScore and grades on the
     right. No panels. Two plates; the sharer picks, and the pick is
     remembered. */
  var PLATES = {
    engraved: { src: "/share/engraved-v1.webp", label: "Engraved" },
    atlas: { src: "/share/atlas-v1.webp", label: "Atlas" },
    globe: { src: "/share/globe-v1.webp", label: "Globe" },
    ledger: { src: "/share/ledger-v1.webp", label: "Ledger" },
    dial: { src: "/share/dial-v1.webp", label: "Dial", draw: function (i, f, p) { return drawDialCard(i, f, p); } },
    plain: { src: null, label: "Plain", draw: function (i, f) { return drawPlainCard(i, f); } }
  };
  function renderCard(style, inp, fl, plate) { var P = PLATES[style] || PLATES.engraved; return P.draw ? P.draw(inp, fl, plate) : drawShareCard(inp, fl, plate); }
  function shareCard(inp, fl) {
    var v = inp.valuation, g = inp.grades, url = location.origin + "/research/" + S.t;
    IL.shareImage({
      title: "Share the " + S.t + " report", file: S.t + "-lens-report",
      text: S.t + ": " + (v && v.verdict ? v.verdict.label + ". " : "") + (g ? "LensScore " + Number(g.score).toFixed(1) + "/10. " : "") + url,
      styles: Object.keys(PLATES),
      render: function (style, plate) { return renderCard(style, inp, fl, plate); }
    });
  }
  var EXCHANGE = { nasdaqgs: "NASDAQ", nasdaqgm: "NASDAQ", nasdaqcm: "NASDAQ", nasdaq: "NASDAQ", nms: "NASDAQ", ngm: "NASDAQ", ncm: "NASDAQ", nyse: "NYSE", nyq: "NYSE", "nyse arca": "NYSE ARCA", nysearca: "NYSE ARCA", pcx: "NYSE ARCA", "nyse american": "NYSE AMERICAN", ase: "NYSE AMERICAN", bats: "CBOE", cboe: "CBOE" };
  /* Monotone cubic (Fritsch-Carlson) through the real points: smooth, but it
     never overshoots or invents peaks, so highs and lows stay true. */
  function monotonePath(x, P) {
    var n = P.length; if (n < 2) return;
    var d = [], m = [];
    for (var i = 0; i < n - 1; i++) d.push((P[i + 1][1] - P[i][1]) / ((P[i + 1][0] - P[i][0]) || 1));
    m[0] = d[0]; m[n - 1] = d[n - 2];
    for (i = 1; i < n - 1; i++) m[i] = d[i - 1] * d[i] <= 0 ? 0 : (d[i - 1] + d[i]) / 2;
    for (i = 0; i < n - 1; i++) {
      if (d[i] === 0) { m[i] = 0; m[i + 1] = 0; continue; }
      var a = m[i] / d[i], b = m[i + 1] / d[i], s = a * a + b * b;
      if (s > 9) { var tt = 3 / Math.sqrt(s); m[i] = tt * a * d[i]; m[i + 1] = tt * b * d[i]; }
    }
    x.moveTo(P[0][0], P[0][1]);
    for (i = 0; i < n - 1; i++) {
      var h = (P[i + 1][0] - P[i][0]) / 3;
      x.bezierCurveTo(P[i][0] + h, P[i][1] + m[i] * h, P[i + 1][0] - h, P[i + 1][1] - m[i + 1] * h, P[i + 1][0], P[i + 1][1]);
    }
  }
  function drawShareCard(inp, fl, plate) {
    var W = 1200, H = 630, c = document.createElement("canvas");
    c.width = W; c.height = H;
    var x = c.getContext("2d");
    var C = { bg: "#10110F", text: "#F3F0E7", t2: "#B9B6AB", t3: "#8C897F", gold: "#E5B65A", gain: "#4CC38A", gradeB: "#8FD0A4", amber: "#E5B65A", loss: "#F07B7B", rule: "rgba(243,240,231,0.12)" };
    var sans = "Inter, system-ui, sans-serif", nums = "'IBM Plex Sans', Inter, sans-serif";
    var hasLS = "letterSpacing" in x, DASH = "—";
    function font(w, px, fam) { return w + " " + px + "px " + fam; }
    function width(str, f, track) { x.font = f; if (hasLS) x.letterSpacing = (track || 0) + "px"; var w = x.measureText(str).width; if (hasLS) x.letterSpacing = "0px"; return w; }
    /* Draw text inside a box (top-left x,y and height): the ink is centred
       vertically in the box using the font's real cap and descender metrics. */
    function box(str, X, Y, w, h, f, color, align, track) {
      x.font = f; x.fillStyle = color; x.textAlign = align || "left"; x.textBaseline = "alphabetic";
      if (hasLS) x.letterSpacing = (track || 0) + "px";
      var m = x.measureText("Hg0"), asc = m.actualBoundingBoxAscent, desc = m.actualBoundingBoxDescent;
      var base = Y + (h - (asc + desc)) / 2 + asc;
      var ax = align === "center" ? X + w / 2 : align === "right" ? X + w : X;
      x.fillText(str, ax, base);
      var tw = x.measureText(str).width;
      if (hasLS) x.letterSpacing = "0px";
      return { w: tw, base: base };
    }
    function fit(str, wt, fam, max, min, maxW, track) { var px = max; while (px > min && width(str, font(wt, px, fam), track) > maxW) px -= 1; return px; }
    function ellipsize(str, f, maxW) { if (width(str, f) <= maxW) return str; while (str.length > 1 && width(str + "…", f) > maxW) str = str.slice(0, -1); return str.replace(/\s+$/, "") + "…"; }
    function wrap2(str, f, maxW) {
      var words = String(str).split(" "), lines = [""];
      words.forEach(function (wd) { var t = lines[lines.length - 1] ? lines[lines.length - 1] + " " + wd : wd; if (width(t, f) > maxW && lines[lines.length - 1]) lines.push(wd); else lines[lines.length - 1] = t; });
      if (lines.length > 2) { lines = [lines[0], ellipsize(lines.slice(1).join(" "), f, maxW)]; }
      return lines;
    }
    function gradeCol(gr) { gr = String(gr || "").charAt(0); return gr === "A" ? C.gain : gr === "B" ? C.gradeB : gr === "C" ? C.amber : gr ? C.loss : C.t3; }
    function signed(v, d) { return F.spct(v, d); }

    var p = inp.price, g = inp.grades, v = inp.valuation, f = inp.fundamentals, meta = inp.meta || {};
    var sector = meta.sector || (g && (g.sectorName || (g.rank && g.rank.sectorName))) || "";
    var exRaw = String(meta.fullExchangeName || meta.exchangeName || "").trim();
    var ex = EXCHANGE[exRaw.toLowerCase()] || exRaw.toUpperCase();
    var asOf = p && p.lastTime ? new Date(p.lastTime * 1000) : new Date();

    /* Background: the fixed folio, or plain ground if it fails to load. */
    x.fillStyle = C.bg; x.fillRect(0, 0, W, H);
    if (plate) x.drawImage(plate, 0, 0, W, H);
    /* Feathered veils so the text columns read and the globe stays lit. */
    var vl = x.createLinearGradient(0, 0, 600, 0);
    vl.addColorStop(0, "rgba(16,17,15,0.86)"); vl.addColorStop(0.62, "rgba(16,17,15,0.72)"); vl.addColorStop(0.86, "rgba(16,17,15,0.28)"); vl.addColorStop(1, "rgba(16,17,15,0)");
    x.fillStyle = vl; x.fillRect(0, 0, 600, H);
    var vr = x.createLinearGradient(740, 0, W, 0);
    vr.addColorStop(0, "rgba(16,17,15,0)"); vr.addColorStop(0.3, "rgba(16,17,15,0.6)"); vr.addColorStop(0.55, "rgba(16,17,15,0.8)"); vr.addColorStop(1, "rgba(16,17,15,0.86)");
    x.fillStyle = vr; x.fillRect(740, 0, W - 740, H);
    var vb = x.createLinearGradient(0, 540, 0, H);
    vb.addColorStop(0, "rgba(16,17,15,0)"); vb.addColorStop(0.45, "rgba(16,17,15,0.8)"); vb.addColorStop(1, "rgba(16,17,15,0.92)");
    x.fillStyle = vb; x.fillRect(0, 540, W, H - 540);

    /* Header: brand and the report date (the date of the data shown). */
    var bw = box("Implied", 48, 32, 240, 28, font(700, 23, sans), C.text).w;
    box("Lens", 48 + bw, 32, 240, 28, font(700, 23, sans), C.gold);
    box("LENS REPORT  ·  " + asOf.toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric", timeZone: "America/New_York" }).toUpperCase(), 792, 38, 360, 20, font(500, 13, sans), C.t2, "right", 1);

    /* Identity: exchange and sector, the ticker, the company. */
    box([ex, sector].filter(Boolean).join("  ·  ").toUpperCase(), 48, 76, 400, 16, font(500, 12, sans), C.t2, "left", 1.2);
    var tpx = fit(S.t, 700, sans, 72, 52, 392, -1.5);
    box(S.t, 48, 94, 392, 80, font(700, tpx, sans), C.text, "left", -1.5);
    var npx = fit(String(inp.name || ""), 500, sans, 24, 19, 392);
    box(ellipsize(String(inp.name || ""), font(500, npx, sans), 392), 48, 180, 392, 30, font(500, npx, sans), C.t2);

    /* Price and today's move. */
    var cur = meta.currency && meta.currency !== "USD" ? meta.currency + " " : "";
    var priceStr = p ? (cur ? cur + F.num(p.price, 2) : F.price(p.price)) : DASH;
    var ppx = fit(priceStr, 600, nums, 40, 32, 224);
    var pr = box(priceStr, 48, 220, 224, 48, font(600, ppx, nums), C.text);
    if (p && isFinite(p.chgPct)) box(signed(p.chgPct, 2) + " today", 48 + pr.w + 18, 235, 360, 26, font(500, 20, nums), p.chg >= 0 ? C.gain : C.loss);

    /* The signature comparison: growth the price implies vs growth delivered.
       When neither figure exists (a visitor, or a company without the
       filings), the slot shows the year's trading range instead of two big
       empty dashes (audit F14). Nothing is ever estimated to fill it. */
    var impVal = v && isFinite(v.implied) ? v.implied : null;
    var delivered = v && v.delivered !== null && v.delivered !== undefined && isFinite(v.delivered) ? v.delivered : null;
    function growth(val, X, w, color) {
      if (val === null || val === undefined || !isFinite(val)) {
        box(DASH, X, 349, w, 60, font(600, 48, nums), C.t3);
        return false;
      }
      var main = signed(val * 100, 0), px = 48;
      while (px > 34 && width(main, font(600, px, nums)) + 5 + width("/yr", font(500, 18, nums)) > w) px -= 1;
      var r = box(main, X, 349, w, 60, font(600, px, nums), color);
      x.font = font(500, 18, nums); x.fillStyle = C.t2; x.textAlign = "left"; x.fillText("/yr", X + r.w + 5, r.base);
      return true;
    }
    if (impVal === null && delivered === null && p && isFinite(p.lo) && isFinite(p.hi)) {
      box("52-WEEK RANGE", 48, 291, 392, 18, font(600, 13, sans), C.t2, "left", 1.1);
      box("Low", 48, 324, 190, 21, font(500, 17, sans), C.t2);
      box("High", 252, 324, 190, 21, font(500, 17, sans), C.t2);
      [[p.lo, 48], [p.hi, 252]].forEach(function (c) {
        var s0 = F.price(c[0]), px = 44;
        while (px > 30 && width(s0, font(600, px, nums)) > 190) px -= 1;
        box(s0, c[1], 352, 190, 56, font(600, px, nums), C.text);
      });
      var off = p.hi > 0 ? (p.price / p.hi - 1) * 100 : null;
      box(off !== null && isFinite(off) ? (off >= -0.05 ? "At its 52-week high" : signed(off, 1) + " below the high") : "", 48, 414, 392, 16, font(400, 13, sans), C.t3);
      if (isFinite(p.drawdown)) box("Worst drop from a high: " + signed(p.drawdown, 1), 48, 431, 392, 16, font(400, 13, sans), C.t3);
    } else {
      box("ANNUAL SALES GROWTH", 48, 291, 392, 18, font(600, 13, sans), C.t2, "left", 1.1);
      box("Implied by price", 48, 324, 190, 21, font(500, 17, sans), C.t2);
      box("Delivered", 252, 324, 190, 21, font(500, 17, sans), C.t2);
      var hasImp = growth(impVal, 48, 190, C.gold);
      var hasDel = growth(delivered, 252, 190, C.text);
      var impBasis = hasImp ? ["Model estimate", "next 5 years"] : ["Not available"];
      var delBasis = hasDel ? ["Reported", f && f.growth3y !== null ? "3-year annual rate" : "last 12 months vs prior"] : ["Not available"];
      [[impBasis, 48], [delBasis, 252]].forEach(function (b) { b[0].forEach(function (ln, i) { box(ln, b[1], 414 + i * 17, 190, 16, font(400, 13, sans), C.t3); }); });
    }

    /* Price over the past year: the real daily closes, no axes or fill. */
    box("PRICE  ·  PAST YEAR", 48, 468, 180, 18, font(500, 12, sans), C.t2, "left", 1);
    var yrRet = p && p.yearReturn !== null && isFinite(p.yearReturn) ? p.yearReturn : null;
    if (yrRet !== null) box(signed(yrRet, 1), 242, 464, 198, 25, font(500, 20, nums), yrRet >= 0 ? C.gain : C.loss, "right");
    if (S.quote && S.quote.bars.length > 1) {
      var bars = S.quote.bars.filter(function (b) { return b && isFinite(b.time) && isFinite(b.close) && b.close > 0; }).slice().sort(function (a, b) { return a.time - b.time; });
      var yr = bars.slice(IL.windowStart(bars, IL.YEAR_DAYS));      // the same year as the figure beside it
      if (yr.length > 1) {
        var t0 = yr[0].time, t1 = yr[yr.length - 1].time, lo = Infinity, hi = -Infinity;
        yr.forEach(function (b) { lo = Math.min(lo, b.close); hi = Math.max(hi, b.close); });
        var cx0 = 48, cx1 = 440, cy0 = 498, cy1 = 544;
        var Xt = function (t) { return cx0 + (cx1 - cx0) * (t - t0) / ((t1 - t0) || 1); };
        var Yv = function (val) { return hi === lo ? (cy0 + cy1) / 2 : cy1 - (val - lo) / (hi - lo) * (cy1 - cy0); };
        /* Break the line at real gaps in the data (more than 10 days). */
        /* Plot each week's real closing price (the last trading day of the
           week, plus the year's high and low days) so day-to-day noise
           doesn't read as jagged at this size; highs and lows stay true. */
        var wk = {}, keep = [];
        yr.forEach(function (b) { wk[Math.floor((b.time + 3 * 86400) / (7 * 86400))] = b; });
        Object.keys(wk).forEach(function (k) { keep.push(wk[k]); });
        yr.forEach(function (b) { if (b.close === lo || b.close === hi) keep.push(b); });
        keep.push(yr[0]); keep.push(yr[yr.length - 1]);
        keep = keep.sort(function (a, b) { return a.time - b.time; }).filter(function (b, i, arr) { return !i || b.time !== arr[i - 1].time; });
        var seg = [], segs = [seg];
        keep.forEach(function (b, i) { if (i && b.time - keep[i - 1].time > 14 * 86400) { seg = []; segs.push(seg); } seg.push([Xt(b.time), Yv(b.close)]); });
        x.strokeStyle = C.gold; x.lineWidth = 2.5; x.lineJoin = "round"; x.lineCap = "round";
        segs.forEach(function (sg) { if (sg.length < 2) return; x.beginPath(); monotonePath(x, sg); x.stroke(); });
        var last = segs[segs.length - 1], lp = last[last.length - 1];
        x.fillStyle = C.gold; x.beginPath(); x.arc(lp[0], lp[1], 3.5, 0, Math.PI * 2); x.fill();
      }
    }

    /* The LensScore: an unframed number, always gold; words carry the meaning. */
    box("LENSSCORE", 840, 118, 312, 20, font(600, 14, sans), C.t2, "center", 2);
    if (g && isFinite(Number(g.score))) {
      var sc = Number(g.score).toFixed(1), fN = font(600, 112, nums), fU = font(500, 22, nums);
      var wN = width(sc, fN), wU = width("/10", fU), gx0 = 840 + (312 - (wN + 8 + wU)) / 2;
      var sr = box(sc, gx0, 146, wN, 128, fN, C.gold);
      x.font = fU; x.fillStyle = C.t2; x.textAlign = "left"; x.fillText("/10", gx0 + wN + 8, sr.base);
      if (g.label) box(g.label, 840, 286, 312, 26, font(500, 21, sans), C.text, "center");
      if (g.rank) {
        var rk = "#" + g.rank.position + " of " + g.rank.of + "  ·  " + (g.rank.sectorName || g.sectorName || sector || "");
        var lines = wrap2(rk.replace(/\s+·\s+$/, ""), font(400, 17, sans), 312);
        lines.forEach(function (ln, i) { box(ln, 840, 318 + i * 22, 312, 22, font(400, 17, sans), C.t2, "center"); });
      }
    } else {
      box(DASH, 840, 146, 312, 128, font(600, 112, nums), C.t3, "center");
      box("Not graded", 840, 286, 312, 26, font(500, 21, sans), C.t2, "center");
    }
    x.fillStyle = C.rule; x.fillRect(840, 384, 312, 1);
    var fs = g && g.factors ? g.factors.slice(0, 5) : [];
    ["value", "growth", "profitability", "health", "momentum"].forEach(function (key, i) {
      var fc = fs.filter(function (z) { return z.key === key; })[0] || fs[i] || null;
      var X0 = 840 + 62.4 * i;
      box(FACTOR_LABEL[key], X0, 400, 62.4, 16, font(500, 11, sans), C.t2, "center");
      var gr = fc && fc.grade ? fc.grade : DASH;
      box(gr, X0, 424, 62.4, 40, font(600, 30, nums), fc && fc.grade ? gradeCol(fc.grade) : C.t3, "center");
    });

    /* Footer. */
    x.fillStyle = C.rule; x.fillRect(48, 566, 1104, 1);
    box("impliedlens.com/research/" + S.t, 48, 586, 690, 23, font(600, 18, sans), C.text);
    box("Educational research · not investment advice", 792, 590, 360, 18, font(400, 13, sans), C.t3, "right");
    return c;
  }
  /* "Plain": the first data-first card, no picture behind it. */
  function drawPlainCard(inp, fl) {
    var W = 1200, H = 630, c = document.createElement("canvas");
    c.width = W; c.height = H;
    var x = c.getContext("2d");
    var C = { bg: "#0F1012", line: "#24272C", grid: "#1C1F23", text: "#ECEDEF", t2: "#A1A7AF", t3: "#6F767F", gold: "#E5B65A", gain: "#4CC38A", gradeB: "#8FD0A4", amber: "#D9A441", loss: "#F07B7B" };
    var sans = "Inter, system-ui, sans-serif", nums = "'IBM Plex Sans', Inter, sans-serif";
    function t(str, X, Y, font, color, align) { x.font = font; x.fillStyle = color; x.textAlign = align || "left"; x.fillText(str, X, Y); return x.measureText(str).width; }
    function hline(X0, X1, Y, col) { x.fillStyle = col || C.line; x.fillRect(X0, Math.round(Y), X1 - X0, 1); }
    function gradeCol(gr) { gr = String(gr || "").charAt(0); return gr === "A" ? C.gain : gr === "B" ? C.gradeB : gr === "C" ? C.amber : gr ? C.loss : C.t3; }
    var p = inp.price, g = inp.grades, v = inp.valuation, f = inp.fundamentals, meta = inp.meta || {};
    var sector = meta.sector || (g && (g.sectorName || (g.rank && g.rank.sectorName))) || "";
    var L = 56, R = W - 56;

    x.fillStyle = C.bg; x.fillRect(0, 0, W, H);

    /* Header: ticker and name left, price and moves right. */
    var tw = t(S.t, L, 92, "700 40px " + sans, C.text);
    t(String(inp.name || "").slice(0, 36), L + tw + 16, 92, "500 24px " + sans, C.t2);
    t([meta.fullExchangeName || meta.exchangeName, sector].filter(Boolean).join("  ·  "), L, 124, "500 17px " + sans, C.t3);
    if (p) {
      t(F.price(p.price), R, 92, "600 40px " + nums, C.text, "right");
      var yrRet = p.yearReturn;
      x.font = "500 18px " + nums;
      var s1 = F.spct(p.chgPct, 2) + " today", s2 = yrRet !== null && isFinite(yrRet) ? F.spct(yrRet, 1) + " past year" : "";
      var w2 = s2 ? x.measureText(s2).width : 0;
      if (s2) t(s2, R, 124, "500 18px " + nums, yrRet >= 0 ? C.gain : C.loss, "right");
      t(s1 + (s2 ? "   " : ""), R - w2, 124, "500 18px " + nums, p.chg >= 0 ? C.gain : C.loss, "right");
    }

    /* The chart: one year of closes, lightly smoothed, with real axes. */
    var cx0 = L, cx1 = 790, cy0 = 172, cy1 = 432;
    if (S.quote && S.quote.bars.length > 20) {
      var bars = S.quote.bars, yr = bars.slice(IL.windowStart(bars, IL.YEAR_DAYS));
      var sm = yr.map(function (b, i) { var a = yr.slice(Math.max(0, i - 2), i + 3), s = 0; a.forEach(function (z) { s += z.close; }); return s / a.length; });
      sm[sm.length - 1] = yr[yr.length - 1].close;
      var pts = [], step = Math.max(1, Math.round(yr.length / 90));
      for (var i = 0; i < yr.length; i += step) pts.push([i, sm[i]]);
      if (pts[pts.length - 1][0] !== yr.length - 1) pts.push([yr.length - 1, sm[yr.length - 1]]);
      var lo = Math.min.apply(null, sm), hi = Math.max.apply(null, sm);
      var raw = (hi - lo) / 4 || 1, mag = Math.pow(10, Math.floor(Math.log10(raw))), nice = [1, 2, 2.5, 5, 10].map(function (k) { return k * mag; }).filter(function (k) { return k >= raw; })[0];
      var gLo = Math.floor(lo / nice) * nice, gHi = Math.ceil(hi / nice) * nice;
      var plotR = cx1 - 64;
      var X = function (i) { return cx0 + (plotR - cx0) * i / (yr.length - 1); };
      var Y = function (val) { return cy1 - (val - gLo) / ((gHi - gLo) || 1) * (cy1 - cy0); };
      for (var gv = gLo; gv <= gHi + nice / 2; gv += nice) {
        hline(cx0, plotR + 8, Y(gv), C.grid);
        t(F.price(gv).replace(/\.00$/, ""), cx1, Y(gv) + 5, "500 14px " + nums, C.t3, "right");
      }
      var lastMonth = -1;
      yr.forEach(function (b, i) {
        var d = new Date(b.time * 1000), m = d.getUTCMonth();
        if (m !== lastMonth && i > 3 && m % 2 === 0) t(d.toLocaleString("en-US", { month: "short", timeZone: "UTC" }), X(i), cy1 + 26, "500 14px " + sans, C.t3, "center");
        if (m !== lastMonth) lastMonth = m;
      });
      var P = pts.map(function (q) { return [X(q[0]), Y(q[1])]; });
      function curve() { x.moveTo(P[0][0], P[0][1]); for (var k = 0; k < P.length - 1; k++) { var a0 = P[k - 1] || P[k], a1 = P[k], a2 = P[k + 1], a3 = P[k + 2] || a2; x.bezierCurveTo(a1[0] + (a2[0] - a0[0]) / 6, a1[1] + (a2[1] - a0[1]) / 6, a2[0] - (a3[0] - a1[0]) / 6, a2[1] - (a3[1] - a1[1]) / 6, a2[0], a2[1]); } }
      var wash = x.createLinearGradient(0, cy0, 0, cy1); wash.addColorStop(0, "rgba(229,182,90,0.14)"); wash.addColorStop(1, "rgba(229,182,90,0)");
      x.beginPath(); curve(); x.lineTo(P[P.length - 1][0], cy1); x.lineTo(P[0][0], cy1); x.closePath(); x.fillStyle = wash; x.fill();
      x.beginPath(); curve(); x.strokeStyle = C.gold; x.lineWidth = 2.5; x.lineJoin = "round"; x.lineCap = "round"; x.stroke();
      var lp = P[P.length - 1];
      x.fillStyle = C.gold; x.beginPath(); x.arc(lp[0], lp[1], 4.5, 0, Math.PI * 2); x.fill();
    }

    /* The LensScore column: the number, the rank, the five grades as rows. */
    var rx = 846;
    x.fillStyle = C.line; x.fillRect(rx - 28, 172, 1, 262);
    t("LENSSCORE", rx, 186, "600 14px " + sans, C.t3);
    if (g) {
      var sc = Number(g.score), sw = t(sc.toFixed(1), rx, 250, "600 60px " + nums, C.text);
      t("/ 10", rx + sw + 10, 250, "500 20px " + nums, C.t3);
      t([g.label, g.rank ? "#" + g.rank.position + " of " + g.rank.of : ""].filter(Boolean).join("  ·  "), rx, 282, "500 17px " + sans, C.t2);
      var gy = 322;
      (g.factors || []).slice(0, 5).forEach(function (fc) {
        var col = gradeCol(fc.grade), fill = IL.gradeFill(fc.grade) / 100;
        t(FACTOR_LABEL[fc.key] || fc.label, rx, gy, "500 16px " + sans, C.t2);
        x.fillStyle = C.grid; x.fillRect(rx + 104, gy - 6, 150, 4);
        x.fillStyle = col; x.fillRect(rx + 104, gy - 6, Math.max(4, 150 * fill), 4);
        t(fc.grade || "—", R, gy, "600 16px " + nums, col, "right");
        gy += 26;
      });
    } else {
      t("Not graded", rx, 240, "600 26px " + sans, C.t2);
      t("Funds and foreign listings", rx, 272, "500 16px " + sans, C.t3);
      t("aren’t compared with peers.", rx, 296, "500 16px " + sans, C.t3);
    }

    /* The numbers behind the call. */
    hline(L, R, 468);
    var cells = [
      ["Market cap", meta.marketCap ? F.money(meta.marketCap) : "—", C.text],
      ["P/E", N(meta.trailingPE) ? N(meta.trailingPE).toFixed(1) : "—", C.text],
      ["Sales growth", f && f.growth1y !== null ? F.spct(f.growth1y, 0) : "—", f && f.growth1y !== null ? (f.growth1y >= 0 ? C.gain : C.loss) : C.text],
      ["Net margin", f && f.netMargin !== null ? f.netMargin.toFixed(0) + "%" : "—", C.text],
      ["Growth priced in", v && v.implied !== null ? F.spct(v.implied * 100, 0) + "/yr" : "—", C.text],
      ["Growth delivered", v && v.delivered !== null ? F.spct(v.delivered * 100, 0) + "/yr" : "—", v && v.delivered !== null && v.implied !== null ? (v.delivered >= v.implied ? C.gain : C.loss) : C.text]
    ];
    var cw = (R - L) / cells.length;
    cells.forEach(function (cl, i) {
      var X0 = L + i * cw;
      if (i) { x.fillStyle = C.line; x.fillRect(Math.round(X0) - 16, 488, 1, 56); }
      t(cl[0], X0, 506, "500 15px " + sans, C.t3);
      t(cl[1], X0, 540, "600 26px " + nums, cl[2]);
    });

    /* Footer. */
    hline(L, R, 568);
    var ww = t("Implied", L, 604, "700 19px " + sans, C.text);
    t("Lens", L + ww, 604, "700 19px " + sans, C.gold);
    t("impliedlens.com/research/" + S.t + "   ·   Not investment advice", R, 604, "500 15px " + sans, C.t3, "right");
    return c;
  }
  /* "Dial": the first plate (an engraved chart-book page with a lens dial)
     with frosted widgets and the LensScore set inside the dial. */
  function drawDialCard(inp, fl, plate) {
    var DIAL = { x: 900, y: 300 };
    var W = 1200, H = 630, c = document.createElement("canvas");
    c.width = W; c.height = H;
    var x = c.getContext("2d");
    var C = { text: "#F1EEE8", t2: "#B9B2A6", t3: "#8A8378", gold: "#E5B65A", gain: "#4CC38A", gradeB: "#8FD0A4", amber: "#D9A441", loss: "#F07B7B" };
    var sans = "Inter, system-ui, sans-serif", nums = "'IBM Plex Sans', Inter, sans-serif";
    var hasLS = "letterSpacing" in x;
    function t(str, X, Y, font, color, align, track) {
      x.font = font; x.fillStyle = color; x.textAlign = align || "left";
      if (hasLS) x.letterSpacing = track ? track + "px" : "0px";
      x.fillText(str, X, Y); var w = x.measureText(str).width;
      if (hasLS) x.letterSpacing = "0px";
      return w;
    }
    function gradeCol(gr) { gr = String(gr || "").charAt(0); return gr === "A" ? C.gain : gr === "B" ? C.gradeB : gr === "C" ? C.amber : gr ? C.loss : C.t3; }
    /* A widget: frosted glass over the plate, a thin gold edge. */
    function widget(X, Y, w, hh) {
      x.save(); roundRect(x, X, Y, w, hh, 14); x.clip();
      if (plate && "filter" in x) { x.filter = "blur(10px)"; x.drawImage(plate, 0, 0, W, H); x.filter = "none"; }
      x.fillStyle = "rgba(10,9,7,0.62)"; x.fillRect(X, Y, w, hh);
      var sh = x.createLinearGradient(0, Y, 0, Y + 60); sh.addColorStop(0, "rgba(229,182,90,0.07)"); sh.addColorStop(1, "rgba(229,182,90,0)"); x.fillStyle = sh; x.fillRect(X, Y, w, 60);
      x.restore();
      x.strokeStyle = "rgba(229,182,90,0.26)"; x.lineWidth = 1; roundRect(x, X + 0.5, Y + 0.5, w - 1, hh - 1, 14); x.stroke();
    }
    var p = inp.price, g = inp.grades, v = inp.valuation, f = inp.fundamentals, meta = inp.meta || {};
    var sector = meta.sector || (g && (g.sectorName || (g.rank && g.rank.sectorName))) || "";

    /* The plate. */
    if (plate) x.drawImage(plate, 0, 0, W, H); else { x.fillStyle = "#0C0A07"; x.fillRect(0, 0, W, H); }

    /* Top line: the wordmark and the report date, in small tracked capitals. */
    var ww = t("Implied", 56, 52, "700 20px " + sans, C.text);
    t("Lens", 56 + ww, 52, "700 20px " + sans, C.gold);
    t("LENS REPORT  ·  " + new Date().toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" }).toUpperCase(), W - 56, 50, "600 13px " + sans, C.t3, "right", 2.2);

    /* Identity: ticker, company, price. Straight on the plate. */
    var tw = t(S.t, 56, 140, "700 64px " + sans, C.text, "left", -1.5);
    t(String(inp.name || "").slice(0, 28), 56 + tw + 18, 138, "500 22px " + sans, C.t2);
    t([meta.fullExchangeName || meta.exchangeName, sector].filter(Boolean).join("  ·  ").toUpperCase(), 56 + tw + 18, 112, "600 12px " + sans, C.t3, "left", 1.8);
    if (p) {
      var pw = t(F.price(p.price), 56, 200, "600 40px " + nums, C.text);
      t(F.spct(p.chgPct, 2) + " today", 56 + pw + 18, 198, "500 19px " + nums, p.chg >= 0 ? C.gain : C.loss);
    }

    /* Widget: one year of price. */
    var wx = 56, wy = 232, wW = 560, wH = 176;
    widget(wx, wy, wW, wH);
    t("PAST YEAR", wx + 20, wy + 30, "600 12px " + sans, C.t3, "left", 2);
    if (p && p.yearReturn !== null && isFinite(p.yearReturn)) t(F.spct(p.yearReturn, 1), wx + wW - 20, wy + 31, "600 17px " + nums, p.yearReturn >= 0 ? C.gain : C.loss, "right");
    if (S.quote && S.quote.bars.length > 20) {
      var bars = S.quote.bars, yr = bars.slice(IL.windowStart(bars, IL.YEAR_DAYS));
      var sm = yr.map(function (b, i) { var a = yr.slice(Math.max(0, i - 2), i + 3), s = 0; a.forEach(function (z) { s += z.close; }); return s / a.length; });
      sm[sm.length - 1] = yr[yr.length - 1].close;
      var step = Math.max(1, Math.round(yr.length / 80)), pts = [];
      for (var i = 0; i < yr.length; i += step) pts.push([i, sm[i]]);
      if (pts[pts.length - 1][0] !== yr.length - 1) pts.push([yr.length - 1, sm[yr.length - 1]]);
      var lo = Math.min.apply(null, sm), hi = Math.max.apply(null, sm);
      var cx0 = wx + 20, cx1 = wx + wW - 26, cy0 = wy + 50, cy1 = wy + wH - 20;
      var P = pts.map(function (q) { return [cx0 + (cx1 - cx0) * q[0] / (yr.length - 1), cy1 - (q[1] - lo) / ((hi - lo) || 1) * (cy1 - cy0)]; });
      function curve() { x.moveTo(P[0][0], P[0][1]); for (var k = 0; k < P.length - 1; k++) { var a0 = P[k - 1] || P[k], a1 = P[k], a2 = P[k + 1], a3 = P[k + 2] || a2; x.bezierCurveTo(a1[0] + (a2[0] - a0[0]) / 6, a1[1] + (a2[1] - a0[1]) / 6, a2[0] - (a3[0] - a1[0]) / 6, a2[1] - (a3[1] - a1[1]) / 6, a2[0], a2[1]); } }
      var wash = x.createLinearGradient(0, cy0, 0, cy1); wash.addColorStop(0, "rgba(229,182,90,0.20)"); wash.addColorStop(1, "rgba(229,182,90,0)");
      x.beginPath(); curve(); x.lineTo(P[P.length - 1][0], cy1); x.lineTo(P[0][0], cy1); x.closePath(); x.fillStyle = wash; x.fill();
      x.beginPath(); curve(); x.strokeStyle = C.gold; x.lineWidth = 2.5; x.lineJoin = "round"; x.lineCap = "round"; x.stroke();
      var lp = P[P.length - 1]; x.fillStyle = C.gold; x.beginPath(); x.arc(lp[0], lp[1], 4.5, 0, Math.PI * 2); x.fill();
    }

    /* Widget: the numbers behind the call. */
    var sx = 56, sy = 424, sW = 560, sH = 120;
    widget(sx, sy, sW, sH);
    var cells = [
      ["MARKET CAP", meta.marketCap ? F.money(meta.marketCap) : "—", C.text],
      ["P/E", N(meta.trailingPE) ? N(meta.trailingPE).toFixed(1) : "—", C.text],
      ["IMPLIED GROWTH", v && v.implied !== null ? F.spct(v.implied * 100, 0) + "/yr" : "—", C.text],
      ["DELIVERED", v && v.delivered !== null ? F.spct(v.delivered * 100, 0) + "/yr" : (f && f.growth1y !== null ? F.spct(f.growth1y, 0) : "—"), v && v.delivered !== null && v.implied !== null ? (v.delivered >= v.implied ? C.gain : C.loss) : C.text]
    ];
    var cws = [118, 86, 168, 148], cx = sx + 20;
    cells.forEach(function (cl, i) {
      var X0 = cx; cx += cws[i];
      if (i) { x.fillStyle = "rgba(229,182,90,0.16)"; x.fillRect(Math.round(X0) - 12, sy + 24, 1, sH - 48); }
      t(cl[0], X0, sy + 46, "600 11px " + sans, C.t3, "left", 1.6);
      t(cl[1], X0, sy + 84, "600 25px " + nums, cl[2]);
    });

    /* The LensScore, set inside the plate's dial like a watch face. */
    var dx = DIAL.x, dy = DIAL.y;
    var face = x.createRadialGradient(dx, dy, 0, dx, dy, 186);
    face.addColorStop(0, "rgba(10,9,7,0.9)"); face.addColorStop(0.8, "rgba(10,9,7,0.84)"); face.addColorStop(1, "rgba(10,9,7,0.2)");
    x.fillStyle = face; x.beginPath(); x.arc(dx, dy, 190, 0, Math.PI * 2); x.fill();
    t("LENSSCORE", dx, dy - 104, "600 13px " + sans, C.t3, "center", 3);
    if (g) {
      var sc = Number(g.score), tone = IL.scoreTone(sc), arcCol = tone === "good" ? C.gain : tone === "mid" ? C.gold : C.loss;
      /* The score as an arc on the dial's inner ring. */
      x.strokeStyle = "rgba(229,182,90,0.14)"; x.lineWidth = 3; x.beginPath(); x.arc(dx, dy, 190, 0, Math.PI * 2); x.stroke();
      x.strokeStyle = arcCol; x.lineCap = "round"; x.beginPath(); x.arc(dx, dy, 190, -Math.PI / 2, -Math.PI / 2 + Math.PI * 2 * Math.max(0.02, Math.min(1, sc / 10))); x.stroke(); x.lineCap = "butt";
      t(sc.toFixed(1), dx, dy - 6, "600 100px " + nums, C.gold, "center", -2);
      t([g.label, g.rank ? "#" + g.rank.position + " of " + g.rank.of + " in " + (g.rank.sectorName || g.sectorName || "sector") : ""].filter(Boolean).join("  ·  "), dx, dy + 32, "500 16px " + sans, C.t2, "center");
      var fs = (g.factors || []).slice(0, 5), gw = 58, gap = 5, gx0 = dx - (fs.length * gw + (fs.length - 1) * gap) / 2, gy = dy + 52;
      fs.forEach(function (fc, i) {
        var X0 = gx0 + i * (gw + gap), col = gradeCol(fc.grade);
        x.strokeStyle = "rgba(229,182,90,0.22)"; x.lineWidth = 1; roundRect(x, X0 + 0.5, gy + 0.5, gw - 1, 52, 10); x.stroke();
        t(fc.grade || "—", X0 + gw / 2, gy + 25, "600 19px " + nums, col, "center");
        t((FACTOR_LABEL[fc.key] || fc.label || "").toUpperCase(), X0 + gw / 2, gy + 42, "600 8.5px " + sans, C.t3, "center", 0.6);
      });
    } else {
      t("Not graded", dx, dy + 6, "600 30px " + sans, C.t2, "center");
      t("Funds and foreign listings aren’t compared with peers.", dx, dy + 38, "500 15px " + sans, C.t3, "center");
    }

    /* Footer: the link and the small print. */
    t("impliedlens.com/research/" + S.t, 56, 594, "600 17px " + sans, C.text);
    t("FROM SEC FILINGS AND A YEAR OF PRICES  ·  NOT INVESTMENT ADVICE", W - 56, 593, "600 11px " + sans, C.t3, "right", 1.4);
    return c;
  }

  /* Valuation share image: what the price implies on the left, the
     sharer's own bear / base / bull cases on the right. */
  function drawValuationCard(d, plate) {
    var W = 1200, H = 630, c = document.createElement("canvas"); c.width = W; c.height = H;
    var x = c.getContext("2d"), K = IL.cardKit(x), C = K.C, font = K.font, box = K.box, sans = K.sans, nums = K.nums;
    var meta = S.quote ? S.quote.meta : {}, name = IL.$("#sh-name") ? IL.$("#sh-name").textContent : S.t;
    var exRaw = String(meta.fullExchangeName || meta.exchangeName || "").trim(), ex = EXCHANGE[exRaw.toLowerCase()] || exRaw.toUpperCase();
    K.plate(plate, W, H);
    K.brand("PROJECTION LAB  ·  " + new Date().toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" }).toUpperCase());
    box([ex, meta.sector].filter(Boolean).join("  ·  ").toUpperCase(), 48, 76, 400, 16, font(500, 12, sans), C.t2, "left", 1.2);
    var tpx = K.fit(S.t, 700, sans, 72, 52, 392, -1.5);
    box(S.t, 48, 94, 392, 80, font(700, tpx, sans), C.text, "left", -1.5);
    var npx = K.fit(name, 500, sans, 24, 19, 392);
    box(K.ellipsize(name, font(500, npx, sans), 392), 48, 180, 392, 30, font(500, npx, sans), C.t2);
    box(F.price(d.price) + " today", 48, 220, 392, 30, font(600, 26, nums), C.text);

    box("WHAT THE PRICE IMPLIES", 48, 284, 392, 18, font(600, 13, sans), C.t2, "left", 1.1);
    if (d.implied === null || !isFinite(d.implied)) box(K.DASH, 48, 306, 392, 70, font(600, 60, nums), C.t3);
    else {
      var main = F.spct(d.implied * 100), r = box(main, 48, 306, 392, 70, font(600, 60, nums), C.gold);
      x.font = font(500, 20, nums); x.fillStyle = C.t2; x.textAlign = "left"; x.fillText("/yr", 48 + r.w + 6, r.base);
    }
    box("Revenue growth a year for " + d.M.years + " years, at a " + F.pct(d.M.required * 100, 0) + " return", 48, 380, 392, 18, font(400, 14, sans), C.t3);
    var dl = box("Delivered ", 48, 414, 120, 26, font(500, 18, sans), C.t2);
    box(d.past === null ? K.DASH : F.spct(d.past * 100) + "/yr", 48 + dl.w + 4, 412, 200, 28, font(600, 24, nums), C.text);
    box("Reported · " + d.pastLabel, 48, 446, 392, 16, font(400, 13, sans), C.t3);
    box("Base case: " + F.pct(d.M.base.margin * 100, 0) + " net margin, " + F.mult(d.M.base.exitPE) + " P/E in year " + d.M.years, 48, 476, 392, 16, font(400, 13, sans), C.t3);

    box("MY " + (d.M.years === 10 ? "TEN" : d.M.years === 3 ? "THREE" : "FIVE") + "-YEAR CASES", 840, 96, 312, 18, font(600, 13, sans), C.t2, "left", 1.6);
    var rows = [["bear", "Bear case", C.loss], ["base", "Base case", C.text], ["bull", "Bull case", C.gain]];
    rows.forEach(function (rw, i) {
      var y = 132 + i * 128, o = d.outs[rw[0]], m = d.M[rw[0]];
      if (i) { x.fillStyle = C.rule; x.fillRect(840, y - 14, 312, 1); }
      box(rw[1], 840, y, 160, 20, font(600, 15, sans), rw[2]);
      box(F.spct(m.growth * 100, 0) + (m.growthEnd != null && Math.abs(m.growthEnd - m.growth) > 0.004 ? "\u2192" + F.pct(m.growthEnd * 100, 0) : "") + " growth · " + F.pct(m.margin * 100, 0) + " margin · " + F.mult(m.exitPE), 840, y + 24, 312, 16, font(400, 13, sans), C.t3);
      box(o ? F.price(o.futurePrice) : K.DASH, 840, y + 46, 200, 40, font(600, 32, nums), C.text);
      if (o) box(F.spct(o.annualReturn * 100) + "/yr", 952, y + 54, 200, 28, font(600, 22, nums), o.annualReturn >= 0 ? C.gain : C.loss, "right");
      box("price in " + d.M.years + " years", 840, y + 88, 200, 14, font(400, 12, sans), C.t3);
      box("yearly return", 952, y + 88, 200, 14, font(400, 12, sans), C.t3, "right");
    });
    K.footer("impliedlens.com/research/" + S.t + "/projection");
    return c;
  }
  function roundRect(x, X, Y, w, hh, r) {
    x.beginPath(); x.moveTo(X + r, Y); x.arcTo(X + w, Y, X + w, Y + hh, r); x.arcTo(X + w, Y + hh, X, Y + hh, r); x.arcTo(X, Y + hh, X, Y, r); x.arcTo(X, Y, X + w, Y, r); x.closePath();
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
    box.innerHTML = '<div class="card-h"><h2 class="card-t">How risky has it been?</h2><span class="tag">' + riskWord(p.vol) + "</span></div>" +
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
    if (valueF && /^[C-F]/.test(valueF.grade || "")) checks.push({ text: "Is the price already assuming the growth?", tab: "projection" });
    else checks.push({ text: "What does today’s price assume?", tab: "projection" });
    var ne = nextEarnings();
    if (ne && ne.date) checks.push({ text: "Read the last release before " + nextEarningsText(ne), tab: "earnings" });
    if (g.watch && g.watch[0]) checks.push({ text: "Watch: " + String(g.watch[0].text || "").replace(/\.$/, ""), anchor: "report" });
    box.innerHTML =
      '<div class="card-h"><h2 class="card-t">LensScore ' + IL.tip("A 0–10 grade of the business against its sector peers on five things, from SEC filings and price history. It describes the company today; it is not a price prediction.") + "</h2>" +
        (g.rank ? '<span class="card-sub">#' + g.rank.position + " of " + g.rank.of + " in " + h(g.rank.sectorName || g.sectorName || "its sector") + "</span>" : "") + "</div>" +
      '<div class="rc-top">' + scoreRing(g.score, 104) +
        '<div class="rc-lab"><span class="rc-label">' + h(g.label || "") + '</span><span class="muted">Graded against ' + h(g.groupName || g.sectorName || "sector") + " peers on five things.</span></div></div>" +
      '<div class="grades">' + f.map(function (x) {
        return '<div class="grade"><span>' + h(FACTOR_LABEL[x.key] || x.label) + '</span><div class="bar"><i style="width:' + IL.gradeFill(x.grade) + "%;background:" + IL.gradeTone(x.grade) + '"></i></div><span class="g">' + IL.gchip(x.grade) + "</span></div>";
      }).join("") + "</div>" +
      (g.verdict ? '<p class="rc-verdict">' + h(g.verdict) + "</p>" : "") +
      '<div class="rc-next"><span class="rc-next-h">What to check next</span>' + checks.slice(0, 3).map(function (c) {
        return '<a href="/research/' + h(S.t) + (c.tab ? "/" + c.tab : "") + '" data-tab="' + (c.tab || "overview") + '"' + (c.anchor ? ' data-anchor="' + c.anchor + '"' : "") + "><span>" + h(c.text) + "</span>" + IL.icon("arrow", 14) + "</a>";
      }).join("") + "</div>" +
      '<div class="rc-foot"><a class="btn sm" href="#report" data-scroll="report">Full report card</a><a class="btn sm ghost" href="/compare?t=' + [S.t].concat((g.peers || []).filter(function (x) { return x !== S.t; })).slice(0, 4).join(",") + '">Compare peers</a></div>';
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
    IL.$("#rep-sub").textContent = "Percentile = share of " + (g.groupName || g.sectorName || "sector") + " peers it beats";
    var rows = (g.factors || []).map(function (x) {
      var pct = N(x.percentile);
      return '<div class="rep-f"><div class="rep-f-h"><span class="rep-f-n">' + h(FACTOR_LABEL[x.key] || x.label) + '</span>' + IL.gchip(x.grade) + "</div>" +
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
        '<p class="note">The five grades compare the company with its own industry (or sector, when we grade too few of its industry); the 0–10 LensScore combines them and ranks it across the graded universe. Entry timing on the chart is separate and not part of the score. ' + (S.lens.provenance && S.lens.provenance.asOf && S.lens.provenance.asOf.fundamentals ? "Filings as of " + F.date(S.lens.provenance.asOf.fundamentals) + ". " : "") + '<a href="/learn/lens-score">How to read it</a> \u00b7 <a href="/methodology">Method and test results</a></p></section>';
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
          return '<tr class="' + (me ? "em" : "click") + '"' + (me ? "" : ' data-go="' + h(t) + '"') + '><td><span class="cell-co">' + IL.mono(t, x.sectorName, "sm") + (me ? "<b>" + h(t) + "</b>" : '<a href="/research/' + h(t) + '"><b>' + h(t) + "</b></a>") + "</span>" + (me ? ' <span class="tag gold">This stock</span>' : "") + '</td><td><span class="pill score ' + IL.scoreTone(x.score) + '">' + F.num(x.score, 1) + "</span></td>" +
            keys.map(function (k) { var gr = x.grades && x.grades[k]; return "<td>" + IL.gchip(gr) + "</td>"; }).join("") + "</tr>";
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
    if (!IL.isPro()) { IL.dialog('<h2>CSV downloads are part of Pro</h2><p class="muted">Pro lets you download every statement, plus 10-year projections, unlimited lookups, alerts and every tab.</p><div class="row" style="justify-content:flex-end"><button class="btn ghost" data-close type="button">Not now</button><a class="btn primary" href="/pricing">Start the free trial</a></div>'); return; }
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
     Projection Lab — what the price implies, and what each case is worth.
     One model for the whole site (public/app/valuation.js): the overview's
     "what the price implies" line and the share card read the same numbers.
     ═════════════════════════════════════════════════════════════════════ */
  var CASES = ["bear", "base", "bull"], CASE_LABEL = { bear: "Bear case", base: "Base case", bull: "Bull case" };

  /* Saved models from before fading growth and horizons (v1) become v2. */
  function migrateModel(m, def) {
    if (!m || !m.base) return null;
    var out = JSON.parse(JSON.stringify(m));
    CASES.forEach(function (c) { if (out[c] && out[c].growthEnd == null) out[c].growthEnd = out[c].growth; });
    if (!out.weights) out.weights = JSON.parse(JSON.stringify(def.weights));
    if (!out.years) out.years = 5;
    if (out.shareChange == null) out.shareChange = def.shareChange;
    if (out.required == null) out.required = def.required;
    return out;
  }

  function tabProjection(box) {
    box.innerHTML = '<section class="card">' + sk(240) + "</section>";
    /* Nothing is computed until the company's filings and price are both in:
       a projection drawn from stand-in numbers looks real and is not. */
    Promise.all([D.hist(), D.quote()]).then(function (all) {
      var res = all[0];
      if (res.gate) { box.innerHTML = IL.gate(res.gate, "Create a free account to open the Projection Lab for " + S.t, { center: true, why: "See what growth today’s price is assuming, then build bear, base and bull cases from the company’s real numbers. Free, no card needed." }); return; }
      var q = quarterly(res.data), p = priceFacts();
      var rev = sumLast(q, "revenue", 4), ni = sumLast(q, "netIncome", 4);
      var shares = q.length ? N(q[q.length - 1].shares) : null;
      if (!res.ok || !p || !rev || !shares) {
        box.innerHTML = '<div class="gate center"><div class="gate-t">Not enough data to project ' + h(S.t) + '</div><div class="gate-s">The Projection Lab needs four quarters of revenue and a share count from SEC filings. Funds and foreign listings usually do not have them.</div></div>';
        return;
      }
      var eps = ni !== null ? ni / shares : null;
      var ctx = {
        price: p.price, revenue: rev, shares: shares, netIncome: ni,
        margin: ni !== null ? ni / rev : null,
        pe: eps > 0 ? p.price / eps : null,
        growth1y: growth(rev, sumLast(q, "revenue", 4, 4)) / 100,
        growth3y: (function () { var old = sumLast(q, "revenue", 4, 12); return old ? IL.valuation.cagr(old, rev, 3) : null; })(),
        quarters: q.map(function (x) { return { end: x.end, revenue: N(x.revenue), netIncome: N(x.netIncome), shares: N(x.shares) }; }),
        asOf: q.length ? q[q.length - 1].end : null,
      };
      if (!isFinite(ctx.growth1y)) ctx.growth1y = null;
      var key = "il-proj-" + S.t, saved = null;
      try { saved = JSON.parse(localStorage.getItem(key) || "null"); } catch (_) {}
      var def = IL.valuation.defaults(ctx);
      var M = (saved && saved.v === 2 && migrateModel(saved.m, def)) || JSON.parse(JSON.stringify(stripNotes(def)));
      renderProjection(box, ctx, M, def, key);
    });
  }
  function stripNotes(d) { var o = {}; Object.keys(d).forEach(function (k) { if (k !== "notes" && k !== "history") o[k] = d[k]; }); return o; }

  function renderProjection(box, ctx, M, def, key) {
    var V = IL.valuation;
    if (!IL.isPro() && M.years > 5) M.years = 5;
    function pctIn(v) { return (Math.round(v * 1000) / 10).toString(); }
    var N_ = function () { return M.years; };
    var horizons = [3, 5, 10];
    box.innerHTML =
      '<section class="card prime val-hero hero-band plate" id="val-hero" data-w="share" data-w-title="your projection" style="--plate:url(/share/ledger-v1.webp);--plate-pos:right 40%"></section>' +
      '<p class="callout val-err" id="val-err" role="alert" hidden></p>' +
      '<div class="section-h"><div><h2 class="section-t">Projection Lab</h2><p class="card-sub">Bear, base and bull cases from the company’s own filings. Change any number; everything recalculates.</p></div>' +
        '<div class="row wrap"><div class="seg" role="group" aria-label="Years ahead" id="pj-years">' + horizons.map(function (n) { return '<button type="button" data-years="' + n + '" aria-pressed="' + (M.years === n) + '">' + n + " years" + (n === 10 && !IL.isPro() ? ' <span class="tag gold" style="margin-left:4px">Pro</span>' : "") + "</button>"; }).join("") + "</div>" +
        '<select class="input val-versions" id="val-versions" aria-label="Saved versions"><option value="">Saved versions</option></select><button class="btn sm" type="button" id="val-save">Save version</button><button class="btn sm ghost" type="button" id="val-reset">Reset</button></div></div>' +
      '<section class="card flush" id="val-cases" data-w="csv" data-w-title="Projection cases"><div class="tbl-wrap"><table class="tbl val-tbl"><thead><tr><th></th>' + CASES.map(function (c) { return '<th class="val-' + c + '">' + CASE_LABEL[c] + "</th>"; }).join("") + "</tr></thead><tbody>" +
        valRow("growth", "Revenue growth, first year", "%", "How fast sales grow next year." + (ctx.growth1y !== null ? " Last 12 months: " + F.spct(ctx.growth1y * 100) + "." : "")) +
        valRow("growthEnd", "Revenue growth, final year", "%", "Growth moves in a straight line from the first-year rate to this one. Few companies keep growing fast for long; most settle at 2–6%.") +
        valRow("margin", "Net profit margin, final year", "%", "Share of revenue kept as profit by the final year. It moves in a straight line from today’s. " + (ctx.margin !== null ? "Last 12 months: " + F.pct(ctx.margin * 100) + "." : "")) +
        valRow("exitPE", "P/E in the final year", "×", "What investors pay for each $1 of earnings at the end. Fast growers usually get higher multiples; mature companies lower. " + (ctx.pe ? "Today: " + F.mult(ctx.pe) + "." : "")) +
        '<tr class="val-out"><td id="o-fp-h">Price in ' + M.years + " years</td>" + CASES.map(function (c) { return '<td id="o-fp-' + c + '"></td>'; }).join("") + "</tr>" +
        '<tr class="val-out"><td>Yearly return from today ' + IL.tip("The compound yearly return if you buy at today’s price and the case plays out. Dividends are not included.") + "</td>" + CASES.map(function (c) { return '<td id="o-ar-' + c + '"></td>'; }).join("") + "</tr>" +
        '<tr class="val-out"><td>Worth today at your return ' + IL.tip("The final-year price discounted back at the yearly return you require. If this is above today’s price, the case beats your hurdle.") + "</td>" + CASES.map(function (c) { return '<td id="o-vt-' + c + '"></td>'; }).join("") + "</tr>" +
        "<tr><td>How likely you think it is " + IL.tip("Your own odds for each case. They are used to blend the three outcomes into one expected value below. They do not have to add up to 100; they are scaled.") + "</td>" + CASES.map(function (c) { return '<td><span class="val-cell"><input class="input num val-in" data-w-case="' + c + '" inputmode="decimal" aria-label="' + h(CASE_LABEL[c]) + ' likelihood" value="' + Math.round(M.weights[c] * 100) + '"><span class="faint">%</span></span></td>'; }).join("") + "</tr>" +
      "</tbody></table></div>" +
      '<div class="pj-expected" id="pj-expected"></div>' +
      '<div class="val-foot"><label class="field" style="flex-direction:row;align-items:center;gap:10px">Return you require <input class="input num val-in" style="width:84px" id="v-req" inputmode="decimal" value="' + pctIn(M.required) + '"> %</label>' +
        '<label class="field" style="flex-direction:row;align-items:center;gap:10px">Share count change per year ' + IL.tip("Negative if the company buys back shares; positive if it issues new ones (for example to pay staff or buy a company).") + ' <input class="input num val-in" style="width:84px" id="v-sh" inputmode="decimal" value="' + pctIn(M.shareChange) + '"> %</label></div></section>' +
      '<section class="card flush" id="pj-chart-card" data-w="expand" data-w-title="Price path"><div class="card-h"><h3 class="card-t">Where each case takes the price</h3><span class="card-sub">Each year’s earnings at the final-year P/E, against today’s price</span></div><div class="pj-chart" id="pj-chart"></div></section>' +
      '<section class="card" id="pj-seeds"><h3 class="card-t">Where the starting numbers come from</h3><ul class="pj-notes">' + def.notes.map(function (n) { return "<li>" + h(n) + "</li>"; }).join("") + "</ul>" +
        '<p class="note">From SEC filings' + (ctx.asOf ? " through the quarter to " + F.date(ctx.asOf) : "") + '. Bear and bull start from the same history: bear grows at 60% of the base rate, keeps 85% of the margin and gets a 20% lower P/E; bull the reverse. <a class="link" href="/learn/priced-in">How to use this</a></p></section>' +
      '<section class="card flush" id="val-years" data-w="expand,csv" data-w-title="Year by year"><div class="card-h"><h3 class="card-t">Year by year</h3><div class="seg" role="group" aria-label="Case" id="val-yr-seg"><button type="button" data-yr="bear" aria-pressed="false">Bear</button><button type="button" data-yr="base" aria-pressed="true">Base</button><button type="button" data-yr="bull" aria-pressed="false">Bull</button></div></div><div class="tbl-wrap"><table class="tbl" id="val-yr"></table></div><p class="note" style="padding:10px 20px 14px">Growth and the margin each move in a straight line from the first year to the last. “Price at the final P/E” shows what each year’s earnings would be worth at that multiple.</p></section>' +
      '<section class="card flush" id="val-whatif" data-w="expand,csv" data-w-title="What if"><div class="card-h"><h3 class="card-t">What if? Yearly return from today ' + IL.tip("Base case, with first-year growth and the final-year P/E changed. Green beats the return you require; amber makes money but less than that; red loses money.") + '</h3><span class="card-sub">Base-case margin and fade; rows = first-year growth, columns = final-year P/E</span></div><div class="tbl-wrap"><table class="tbl val-sens" id="val-sens"></table></div></section>' +
      '<div class="grid-2">' +
        '<section class="card"><h3 class="card-t">Starting point</h3><div>' +
          '<div class="stat"><span class="k">Price</span><span class="v">' + F.price(ctx.price) + "</span></div>" +
          '<div class="stat"><span class="k">Revenue, last 12 months</span><span class="v">' + F.money(ctx.revenue) + "</span></div>" +
          '<div class="stat"><span class="k">Net margin, last 12 months</span><span class="v">' + (ctx.margin !== null ? F.pct(ctx.margin * 100) : "—") + "</span></div>" +
          '<div class="stat"><span class="k">P/E, last 12 months</span><span class="v">' + (ctx.pe ? F.mult(ctx.pe) : "—") + "</span></div>" +
          '<div class="stat"><span class="k">Revenue growth, last year</span><span class="v ' + F.cls(ctx.growth1y) + '">' + (ctx.growth1y !== null ? F.spct(ctx.growth1y * 100) : "—") + "</span></div>" +
          '<div class="stat"><span class="k">Revenue growth, last two quarters</span><span class="v ' + F.cls(def.history.recent) + '">' + (def.history.recent !== null ? F.spct(def.history.recent * 100) : "—") + "</span></div>" +
          '<div class="stat"><span class="k">Revenue growth, 3-year average</span><span class="v ' + F.cls(ctx.growth3y) + '">' + (ctx.growth3y !== null ? F.spct(ctx.growth3y * 100) : "—") + "</span></div>" +
          '<div class="stat"><span class="k">Diluted shares</span><span class="v">' + F.count(ctx.shares) + "</span></div>" +
        "</div></section>" +
        '<section class="card"><h3 class="card-t">How to read this</h3><p class="muted" style="font-size:13.5px">A stock price is a bet on the future. Instead of guessing a “fair value”, start with what the price already assumes, then ask whether the company can beat it. If the growth it needs is well above anything it has done, the stock is priced for perfection. If it is below, the market may be too gloomy.</p>' +
          '<p class="muted" style="font-size:13.5px">This is a model of your assumptions, not a price target. Want a discounted-cash-flow model with reinvestment and a cost of capital instead? The classic DCF is still available.</p>' +
          '<a class="card-foot" href="/?view=tool&section=dcf&symbol=' + h(S.t) + '">Open the classic DCF model →</a></section>' +
      "</div>";

    function valRow(field, text, unit, tip) {
      return "<tr><td>" + h(text) + " " + IL.tip(tip) + "</td>" + CASES.map(function (c) {
        var v = M[c][field];
        return '<td><span class="val-cell"><input class="input num val-in" data-case="' + c + '" data-field="' + field + '" inputmode="decimal" aria-label="' + h(CASE_LABEL[c] + " " + text) + '" value="' + (unit === "%" ? pctIn(v) : String(v)) + '"><span class="faint">' + unit + "</span></span></td>";
      }).join("") + "</tr>";
    }
    function inputs(c, over) {
      var x = M[c], o = over || {};
      return { price: ctx.price, revenue: ctx.revenue, shares: ctx.shares, years: M.years, growth: o.growth != null ? o.growth : x.growth, growthEnd: x.growthEnd,
        margin: x.margin, margin0: ctx.margin !== null && ctx.margin > 0 ? ctx.margin : x.margin, exitPE: o.exitPE != null ? o.exitPE : x.exitPE, shareChange: M.shareChange, required: M.required };
    }
    function read() {
      box.querySelectorAll("[data-case]").forEach(function (inp) {
        var c = inp.getAttribute("data-case"), f = inp.getAttribute("data-field");
        var n = Number(String(inp.value).replace(/[%x×,\s]/g, ""));
        if (!isFinite(n) || String(inp.value).trim() === "") return;
        M[c][f] = f === "exitPE" ? n : n / 100;
      });
      box.querySelectorAll("[data-w-case]").forEach(function (inp) {
        var n = Number(String(inp.value).replace(/[%,\s]/g, ""));
        if (isFinite(n) && n >= 0) M.weights[inp.getAttribute("data-w-case")] = n / 100;
      });
      var r = Number(IL.$("#v-req").value), s = Number(IL.$("#v-sh").value);
      if (isFinite(r) && IL.$("#v-req").value.trim() !== "") M.required = r / 100;
      if (isFinite(s) && IL.$("#v-sh").value.trim() !== "") M.shareChange = s / 100;
    }
    function problem() {
      for (var k = 0; k < CASES.length; k++) {
        var bad = V.validate(inputs(CASES[k]));
        if (bad) return (bad.field === "shareChange" || bad.field === "required" ? "" : CASE_LABEL[CASES[k]] + ": ") + bad.message;
      }
      var w = M.weights.bear + M.weights.base + M.weights.bull;
      if (!(w > 0)) return "Give at least one case a likelihood above zero.";
      return null;
    }
    var outs = {};
    function compute() {
      var msg = problem(), err = IL.$("#val-err");
      if (err) { err.hidden = !msg; err.textContent = msg || ""; }
      IL.$("#o-fp-h").textContent = "Price in " + M.years + " years";
      CASES.forEach(function (c) {
        var out = outs[c] = V.project(inputs(c));
        IL.$("#o-fp-" + c).innerHTML = out ? '<b class="num">' + F.price(out.futurePrice) + "</b>" : "—";
        IL.$("#o-ar-" + c).innerHTML = out ? '<b class="num ' + F.cls(out.annualReturn) + '">' + F.spct(out.annualReturn * 100) + "</b>" : "—";
        IL.$("#o-vt-" + c).innerHTML = out ? '<span class="num">' + F.price(out.valueToday) + '</span> <span class="num ' + F.cls(out.upside) + '" style="font-size:12px">' + F.spct(out.upside * 100, 0) + "</span>" : "—";
      });
      var ex = outs.base && outs.bear && outs.bull ? V.weighted(outs, M.weights, ctx.price) : null, wsum = M.weights.bear + M.weights.base + M.weights.bull;
      IL.$("#pj-expected").innerHTML = ex
        ? '<span class="card-sub">Weighted by your odds (' + CASES.map(function (c) { return Math.round(M.weights[c] / wsum * 100) + "% " + c; }).join(", ") + ")</span>" +
          '<span><b class="num">' + F.price(ex.futurePrice) + '</b> <span class="faint">in ' + M.years + ' years</span></span><span><b class="num ' + F.cls(ex.annualReturn) + '">' + F.spct(ex.annualReturn * 100) + '</b> <span class="faint">a year from ' + F.price(ctx.price) + "</span></span>"
        : "";
      hero(); chart(); years(); sensitivity();
      try { localStorage.setItem(key, JSON.stringify({ v: 2, m: M })); } catch (_) {}
    }

    /* The price path for each case, as smooth curves through each year’s
       value (monotone, so a curve never overshoots its own points). */
    function chart() {
      var el = IL.$("#pj-chart"); if (!el) return;
      if (!outs.base || !outs.bear || !outs.bull) { el.innerHTML = '<div class="empty">Fix the inputs above to draw the cases.</div>'; return; }
      var n = M.years, W = Math.max(320, Math.round(el.clientWidth || 720)), H = W < 560 ? 240 : 300, L = W < 560 ? 52 : 64, R = W < 560 ? 84 : 108, T = 18, B = 34;
      var series = CASES.map(function (c) { return { c: c, pts: [ctx.price].concat(outs[c].pricePath) }; });
      var all = series.reduce(function (a, s) { return a.concat(s.pts); }, []);
      var lo = Math.min.apply(null, all), hi = Math.max.apply(null, all);
      lo = Math.max(0, lo - (hi - lo) * 0.08); hi = hi + (hi - lo) * 0.06;
      var step = niceStep((hi - lo) / 4), y0 = Math.floor(lo / step) * step, y1 = Math.ceil(hi / step) * step;
      var X = function (i) { return L + (W - L - R) * i / n; }, Y = function (v) { return T + (H - T - B) * (1 - (v - y0) / (y1 - y0)); };
      var ticks = []; for (var v = y0; v <= y1 + step / 2; v += step) ticks.push(v);
      var year0 = new Date().getUTCFullYear();
      var labelEvery = n > 5 ? 2 : 1;
      var svg = '<svg viewBox="0 0 ' + W + " " + H + '" role="img" aria-label="Projected price path for the bear, base and bull cases over ' + n + ' years">' +
        ticks.map(function (t) { return '<line x1="' + L + '" x2="' + (W - R) + '" y1="' + Y(t) + '" y2="' + Y(t) + '" class="pj-grid"/><text x="' + (L - 10) + '" y="' + (Y(t) + 4) + '" class="pj-ax" text-anchor="end">' + h(axisPrice(t)) + "</text>"; }).join("") +
        Array.from({ length: n + 1 }, function (_, i) { return i % labelEvery && i !== n ? "" : '<text x="' + X(i) + '" y="' + (H - 10) + '" class="pj-ax" text-anchor="middle">' + (i === 0 ? "Today" : year0 + i) + "</text>"; }).join("") +
        '<line x1="' + L + '" x2="' + (W - R) + '" y1="' + Y(ctx.price) + '" y2="' + Y(ctx.price) + '" class="pj-now"/>' +
        series.map(function (s) {
          return '<path d="' + smooth(s.pts.map(function (v, i) { return [X(i), Y(v)]; })) + '" class="pj-line pj-' + s.c + '"/>' +
            s.pts.map(function (v, i) { return i ? '<circle cx="' + X(i) + '" cy="' + Y(v) + '" r="' + (s.c === "base" ? 3 : 2.25) + '" class="pj-dot pj-' + s.c + '"><title>' + CASE_LABEL[s.c] + ", " + (year0 + i) + ": " + F.price(v) + "</title></circle>" : ""; }).join("");
        }).join("") +
        endLabels(series.map(function (s) { return { c: s.c, y: Y(s.pts[n]), v: s.pts[n] }; }), W - R + 10, T + 6, H - B) +
        "</svg>" +
        '<p class="note pj-legend"><span class="pj-key pj-key-now"></span>Today\u2019s price, ' + h(F.price(ctx.price)) + ". Hover a point for its value.</p>";
      el.innerHTML = svg;
    }
    function endLabels(items, x, top, bottom) {
      items.sort(function (a, b) { return a.y - b.y; });
      for (var i = 1; i < items.length; i++) if (items[i].y - items[i - 1].y < 30) items[i].y = items[i - 1].y + 30;
      var over = items[items.length - 1].y - bottom; if (over > 0) items.forEach(function (it) { it.y -= over; });
      if (items[0].y < top) { var d = top - items[0].y; items.forEach(function (it) { it.y += d; }); }
      return items.map(function (it) { return '<text x="' + x + '" y="' + (it.y - 2) + '" class="pj-end pj-' + it.c + '">' + (it.c === "base" ? "Base" : it.c === "bear" ? "Bear" : "Bull") + '</text><text x="' + x + '" y="' + (it.y + 13) + '" class="pj-endv">' + h(F.price(it.v)) + "</text>"; }).join("");
    }
    var yrCase = "base";
    function years() {
      var c = M[yrCase], o = outs[yrCase], t = IL.$("#val-yr"); if (!t) return;
      if (!o) { t.innerHTML = ""; return; }
      var m0 = ctx.margin !== null && ctx.margin > 0 ? ctx.margin : c.margin, year0 = new Date().getUTCFullYear();
      var rows = [{ y: "Today", rev: ctx.revenue, g: null, m: ctx.margin !== null ? ctx.margin : m0, ni: ctx.netIncome, sh: ctx.shares, eps: ctx.netIncome !== null ? ctx.netIncome / ctx.shares : null, px: null }];
      for (var i = 0; i < o.years; i++) rows.push({ y: String(year0 + i + 1), rev: o.revenue[i], g: o.growth[i], m: o.margin[i], ni: o.revenue[i] * o.margin[i], sh: o.shares[i], eps: o.eps[i], px: o.pricePath[i] });
      var line = function (label, fn, cls) { return "<tr" + (cls ? ' class="' + cls + '"' : "") + "><td>" + label + "</td>" + rows.map(function (r, i) { return "<td>" + fn(r, i) + "</td>"; }).join("") + "</tr>"; };
      t.innerHTML = "<thead><tr><th></th>" + rows.map(function (r) { return "<th>" + r.y + "</th>"; }).join("") + "</tr></thead><tbody>" +
        line("Revenue", function (r) { return F.money(r.rev); }, "em") +
        line("Growth", function (r) { return r.g === null ? "" : F.spct(r.g * 100); }) +
        line("Net margin", function (r) { return r.m === null ? "—" : F.pct(r.m * 100); }) +
        line("Net income", function (r) { return r.ni === null ? "—" : F.money(r.ni); }) +
        line("Diluted shares", function (r) { return F.count(r.sh); }) +
        line("Earnings per share", function (r) { return r.eps === null ? "—" : F.eps(r.eps); }, "em") +
        line("Price at the final P/E", function (r, i) { return i === 0 ? '<span class="faint">' + F.price(ctx.price) + " now</span>" : F.price(r.px); }) +
        "</tbody>";
    }
    function sensitivity() {
      var b = M.base, gs = [-0.08, -0.04, 0, 0.04, 0.08].map(function (d) { return b.growth + d; }), pes = [0.6, 0.8, 1, 1.2, 1.4].map(function (k) { return Math.max(3, Math.round(b.exitPE * k)); });
      IL.$("#val-sens").innerHTML = "<thead><tr><th>First-year growth ↓ / final P/E →</th>" + pes.map(function (pe) { return "<th>" + pe + "×</th>"; }).join("") + "</tr></thead><tbody>" +
        gs.map(function (g, gi) {
          return "<tr><td" + (gi === 2 ? ' class="em"' : "") + ">" + F.spct(g * 100) + "</td>" + pes.map(function (pe, pi) {
            var out = V.project(inputs("base", { growth: g, exitPE: pe }));
            var r = out ? out.annualReturn : null;
            var tone = r === null ? "" : r >= M.required ? "s-good" : r >= 0 ? "s-mid" : "s-bad";
            return '<td class="' + tone + (gi === 2 && pi === 2 ? " s-base" : "") + '">' + (r === null ? "—" : F.spct(r * 100, 0)) + "</td>";
          }).join("") + "</tr>";
        }).join("") + "</tbody>";
    }
    function implied() {
      return V.impliedGrowth({ price: ctx.price, revenue: ctx.revenue, shares: ctx.shares, years: M.years, margin: M.base.margin, exitPE: M.base.exitPE, shareChange: M.shareChange, required: M.required });
    }
    function delivered() {
      var r = def.history.recent;
      if (r !== null) return { v: r, label: "last two quarters" };
      return ctx.growth3y !== null ? { v: ctx.growth3y, label: "3 years" } : { v: ctx.growth1y, label: "last year" };
    }
    function hero() {
      var m = M.base.margin, pe = M.base.exitPE, g = implied(), past = delivered();
      var verdict = "";
      if (g !== null && past.v !== null) {
        var gap = g - past.v;
        verdict = gap > 0.05 ? "The price asks for faster growth than the company is delivering." : gap < -0.05 ? "The price asks for slower growth than the company is delivering." : "The price asks for roughly the growth the company is delivering.";
      }
      IL.$("#val-hero").innerHTML =
        '<div class="val-h"><div><span class="card-sub">What the price implies ' + IL.tip("Solved backwards from today’s price: the steady yearly revenue growth that, with the base-case margin and final P/E, earns exactly your required return.") + "</span>" +
          '<div class="val-big num">' + (g === null ? "—" : F.spct(g * 100)) + '<span class="val-unit">revenue growth a year</span></div>' +
          '<p class="muted val-sent">At ' + F.price(ctx.price) + ", " + h(S.t) + " earns a " + F.pct(M.required * 100, 0) + " yearly return if revenue grows about " + (g === null ? "—" : F.pct(g * 100)) + " a year for " + M.years + " years, it keeps a " + F.pct(m * 100) + " net margin, and investors still pay " + F.mult(pe) + " earnings at the end.</p></div>" +
          '<div class="val-cmp">' +
            '<div><span class="card-sub">Priced in</span><span class="num val-mid">' + (g === null ? "—" : F.spct(g * 100)) + "</span></div>" +
            '<div><span class="card-sub">Delivering, ' + past.label + '</span><span class="num val-mid ' + F.cls(past.v) + '">' + (past.v === null ? "—" : F.spct(past.v * 100)) + "</span></div>" +
            (verdict ? '<span class="tag" style="white-space:normal">' + h(verdict) + "</span>" : "") +
          "</div></div>" +
        (def.unprofitable ? '<p class="callout">' + IL.icon("info") + "<span><b>Not profitable yet.</b> The margin here is a target for the final year, not today’s figure.</span></p>" : "");
    }
    if (!box.__valWired) {
      box.__valWired = true;
      box.addEventListener("input", function (e) { if (e.target.classList.contains("val-in")) { box.__read(); box.__compute(); } });
    }
    box.__read = read; box.__compute = compute;
    IL.widgetShare["val-hero"] = function () {
      var msg = problem(); if (msg) { IL.toast("Fix the inputs first: " + msg); return; }
      var g = implied(), past = delivered();
      var d = { implied: g, past: past.v, pastLabel: past.label, price: ctx.price, M: M, outs: outs };
      var fr = function (o) { return o ? F.spct(o.annualReturn * 100) + "/yr" : "—"; };
      IL.shareImage({
        title: "Share your " + S.t + " projection", file: S.t + "-projection",
        text: S.t + ": the price implies " + (g === null ? "—" : F.spct(g * 100)) + " a year revenue growth" + (past.v !== null ? "; it is delivering " + F.spct(past.v * 100) + "." : ".") + " My " + M.years + "-year cases: bear " + fr(outs.bear) + ", base " + fr(outs.base) + ", bull " + fr(outs.bull) + ". " + location.origin + "/research/" + S.t + "/projection",
        styles: ["engraved", "atlas", "globe", "ledger"],
        render: function (style, plate) { return drawValuationCard(d, plate); }
      });
    };
    IL.widgets(box);
    IL.$("#val-yr-seg").addEventListener("click", function (e) {
      var b = e.target.closest("[data-yr]"); if (!b) return;
      yrCase = b.getAttribute("data-yr");
      IL.$$("#val-yr-seg [data-yr]").forEach(function (x) { x.setAttribute("aria-pressed", String(x === b)); });
      years();
    });
    if (!box.__pjResize) { box.__pjResize = true; var rt; window.addEventListener("resize", function () { clearTimeout(rt); rt = setTimeout(function () { if (box.__chart) box.__chart(); }, 150); }); }
    box.__chart = chart;
    IL.$("#pj-years").addEventListener("click", function (e) {
      var b = e.target.closest("[data-years]"); if (!b) return;
      var n = Number(b.getAttribute("data-years"));
      if (n > 5 && !IL.isPro()) {
        IL.dialog('<h2>10-year projections are part of Pro</h2><p class="muted">Pro adds the 10-year horizon, CSV downloads, unlimited lookups, alerts and every tab.</p><div class="row" style="justify-content:flex-end"><button class="btn ghost" data-close type="button">Not now</button><a class="btn primary" href="/pricing" data-checkout="monthly">Start the free trial</a></div>');
        return;
      }
      M.years = n;
      IL.$$("#pj-years [data-years]").forEach(function (x) { x.setAttribute("aria-pressed", String(x === b)); });
      compute();
    });
    var versions = [];
    function loadVersions(selectId) {
      if (!IL.user) { var s0 = IL.$("#val-versions"); if (s0) s0.innerHTML = '<option value="">No saved versions</option>'; return; }
      IL.api("/api/saves", { fresh: true }).then(function (res) {
        versions = (res.ok && Array.isArray(res.data) ? res.data : []).filter(function (x) { return x.type === "implied" && x.ticker === S.t && x.data && x.data.m; });
        var sel = IL.$("#val-versions"); if (!sel) return;
        sel.innerHTML = '<option value="">' + (versions.length ? "Saved versions (" + versions.length + ")" : "No saved versions") + "</option>" +
          versions.map(function (v) { return '<option value="' + v.id + '">' + h(v.label || "Version") + " · " + h(F.date(v.created_at, { year: undefined })) + "</option>"; }).join("");
        if (selectId) sel.value = String(selectId);
        var want = new URLSearchParams(location.search).get("save");
        if (want && !box.__loadedSave) { box.__loadedSave = true; var hit = versions.filter(function (v) { return String(v.id) === want; })[0]; if (hit) useVersion(hit); }
      });
    }
    function useVersion(v) {
      var m = migrateModel(v.data.m, def); if (!m) return;
      renderProjection(box, ctx, m, def, key);
      IL.toast("Loaded “" + (v.label || "version") + "”");
    }
    IL.$("#val-versions").addEventListener("change", function (e) {
      var v = versions.filter(function (x) { return String(x.id) === e.target.value; })[0];
      if (v) useVersion(v);
    });
    IL.$("#val-save").addEventListener("click", function () {
      if (!IL.user) { location.href = IL.signupHref(); return; }
      IL.dialog('<h2>Save this version</h2><label class="field">Name<input class="input" id="vs-label" maxlength="80" value="' + h("Base " + F.spct(M.base.growth * 100, 0) + " fading to " + F.pct(M.base.growthEnd * 100, 0) + ", " + M.base.exitPE + "×, " + M.years + "y") + '"></label><p class="note" id="vs-err"></p><div class="row" style="justify-content:flex-end"><button class="btn ghost" type="button" data-close>Cancel</button><button class="btn primary" type="button" id="vs-go">Save</button></div>', function (d) {
        d.querySelector("#vs-go").addEventListener("click", function () {
          IL.api("/api/saves", { method: "POST", body: { ticker: S.t, type: "implied", label: d.querySelector("#vs-label").value, data: { v: 2, m: M, price: ctx.price } } }).then(function (res) {
            if (!res.ok) { d.querySelector("#vs-err").textContent = (res.data && res.data.error) || "Could not save."; return; }
            d.close(); IL.toast("Saved. Find it on your Saved page too."); loadVersions(res.data.id);
          });
        });
      });
    });
    loadVersions();
    IL.$("#val-reset").addEventListener("click", function () {
      try { localStorage.removeItem(key); } catch (_) {}
      renderProjection(box, ctx, JSON.parse(JSON.stringify(stripNotes(def))), def, key);
    });
    compute();
  }
  function axisPrice(v) {
    if (v === 0) return "$0";
    return v >= 1000 ? "$" + Math.round(v).toLocaleString("en-US") : v >= 10 ? "$" + (Math.round(v * 10) / 10).toString() : "$" + (Math.round(v * 100) / 100).toString();
  }
  function niceStep(raw) {
    var p = Math.pow(10, Math.floor(Math.log10(Math.max(raw, 1e-9)))), f = raw / p;
    return (f <= 1 ? 1 : f <= 2 ? 2 : f <= 2.5 ? 2.5 : f <= 5 ? 5 : 10) * p;
  }
  /* Monotone cubic path (Fritsch–Carlson): smooth, and never bends past the
     points it joins, so a curve cannot invent a peak the model does not have. */
  function smooth(pts) {
    var n = pts.length; if (n < 2) return "";
    var dx = [], dy = [], m = [], t = [];
    for (var i = 0; i < n - 1; i++) { dx.push(pts[i + 1][0] - pts[i][0]); dy.push(pts[i + 1][1] - pts[i][1]); m.push(dy[i] / dx[i]); }
    t.push(m[0]);
    for (var j = 1; j < n - 1; j++) t.push(m[j - 1] * m[j] <= 0 ? 0 : 3 * (dx[j - 1] + dx[j]) / ((2 * dx[j] + dx[j - 1]) / m[j - 1] + (dx[j] + 2 * dx[j - 1]) / m[j]));
    t.push(m[n - 2]);
    var d = "M" + pts[0][0].toFixed(1) + "," + pts[0][1].toFixed(1);
    for (var k = 0; k < n - 1; k++) {
      var h3 = dx[k] / 3;
      d += "C" + (pts[k][0] + h3).toFixed(1) + "," + (pts[k][1] + t[k] * h3).toFixed(1) + " " + (pts[k + 1][0] - h3).toFixed(1) + "," + (pts[k + 1][1] - t[k + 1] * h3).toFixed(1) + " " + pts[k + 1][0].toFixed(1) + "," + pts[k + 1][1].toFixed(1);
    }
    return d;
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
    if (!p.t && p.lab) { renderProjectionLanding(); return; }
    if (!p.t) { renderLanding(); return; }
    if (/\/valuation\/?$/.test(location.pathname)) history.replaceState(null, "", location.pathname.replace(/valuation\/?$/, "projection") + location.search);
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

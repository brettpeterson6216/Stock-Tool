/* ═══════════════════════════════════════════════════════════════════════════
   The member dashboard: what changed on your stocks, and where to look next.

   Watchlist with last close, day change, LensScore and its weekly change;
   grade changes since your last visit (remembered in this browser); the
   market's biggest movers; top-rated by sector; your next lesson.
   ═══════════════════════════════════════════════════════════════════════════ */
(function () {
  "use strict";
  var IL = window.IL, F = IL.fmt, h = IL.h;
  var KEYS = ["value", "growth", "profitability", "health", "momentum"];
  var SHORT = { value: "V", growth: "G", profitability: "P", health: "H", momentum: "M" };
  var LAST = "il-dash-last";

  function greet() {
    var hr = new Date().getHours();
    return hr < 12 ? "Good morning" : hr < 18 ? "Good afternoon" : "Good evening";
  }
  function sk(hh) { return '<span class="sk" style="height:' + hh + 'px"></span>'; }

  function displayName(user) {
    var n = String((user && (user.displayName || user.firstName || user.username)) || "").trim();
    if (!n || /@/.test(n)) return "";
    return n.charAt(0).toUpperCase() + n.slice(1);
  }
  /* A tool card with its engraved plate: the four ways into the product,
     first thing under the greeting. */
  function tile(href, plate, pos, title, sub) {
    return '<a class="card lift tile" href="' + href + '"><span class="tile-art" style="--plate:url(' + IL.plateSrc(plate) + ');--plate-pos:' + pos + '" aria-hidden="true"></span>' +
      '<span class="tile-body"><span class="card-t">' + title + ' <span class="tile-go">' + IL.icon("arrow", 14) + '</span></span><span class="card-sub">' + sub + "</span></span></a>";
  }

  function render(user) {
    var main = document.getElementById("main"), name = displayName(user);
    main.innerHTML =
      '<div class="dh hero-band card prime" id="dh"><div class="stack" style="gap:10px"><h1 class="display">' + h(greet()) + (name ? ', <em>' + h(name) + '.</em>' : ".") + '</h1><p class="muted" id="dh-sum">Here is what changed on your stocks.</p></div>' +
        '</div>' +
      '<nav class="grid-3 rl-tools d-tools" aria-label="Tools">' +
        tile("/research", "globe", "62% 40%", "Research a stock", "A plain-English report card, the financials and what the price assumes.") +
        tile("/screener", "ledger", "60% 40%", "Screener", "Filter about 290 US stocks by grade, value, size and momentum.") +
        tile("/compare", "atlas", "52% 70%", "Compare", "Up to four stocks side by side, with the best in each row marked.") +
        tile("/lens-score", "engraved", "70% 70%", "LensToolkit", "Trend, timing, buy zones and alerts for any stock.") +
      "</nav>" +
      '<div class="dcols">' +
      '<div class="dcol dcol-main">' +
        '<section class="card flush dash-wl" id="w-wl" data-w="expand,csv" data-w-title="Your watchlist" aria-label="Your watchlist"><div class="card-h"><h2 class="card-t">Your watchlist</h2><a class="link" href="/watchlist">Manage →</a></div><div id="d-wl"><div style="padding:20px">' + sk(140) + "</div></div></section>" +
        '<div class="dpair">' +
        '<section class="card flush" id="w-since" data-w="expand" data-w-title="Since your last visit" aria-label="Since your last visit"><div class="card-h"><h2 class="card-t">Since your last visit</h2></div><div id="d-since" class="d-pad">' + sk(90) + "</div></section>" +
        '<section class="card flush" id="w-chg" data-w="expand" data-w-title="Grade changes this week"><div class="card-h"><h2 class="card-t">Grade changes this week</h2><a class="link" href="/research">More →</a></div><div id="d-chg"><div style="padding:20px">' + sk(120) + "</div></div></section>" +
        "</div>" +
        '<section class="card flush" id="w-top" data-w="expand,csv" data-w-title="Top-rated by sector"><div class="card-h"><h2 class="card-t">Top-rated in each sector</h2><a class="link" href="/research">All sectors →</a></div><div id="d-top"><div style="padding:20px">' + sk(160) + "</div></div></section>" +
      "</div>" +
      '<div class="dcol dcol-side">' +
        '<section class="card flush dmkt" id="w-mkt" data-w="expand" data-w-title="Market today" aria-label="Market today"><div class="card-h"><h2 class="card-t">Market today</h2><span class="card-sub" id="d-mkt-st"></span></div><div id="d-mkt"><div style="padding:20px">' + sk(150) + "</div></div></section>" +
        '<section class="card flush" id="w-mv" data-w="expand" data-w-title="Biggest movers"><div class="card-h"><h2 class="card-t">Biggest movers</h2><div class="seg" role="group" aria-label="Movers"><button type="button" data-mv="gainers" aria-pressed="true">Up</button><button type="button" data-mv="losers" aria-pressed="false">Down</button></div></div><div id="d-mv"><div style="padding:20px">' + sk(120) + "</div></div></section>" +
        '<section class="card flush dlearn" id="d-learn"><div class="d-pad">' + sk(90) + "</div></section>" +
      "</div>" +
      "</div>";
    IL.plate(IL.$("#dh"), "engraved", "right 30%");
    loadWatchlist();
    loadMarket();
    loadMovers("gainers");
    loadLeaders();
    paintLearn();
    IL.widgets(main);
    main.addEventListener("click", function (e) {
      var b = e.target.closest("[data-mv]");
      if (b) { IL.$$("[data-mv]").forEach(function (x) { x.setAttribute("aria-pressed", String(x === b)); }); loadMovers(b.getAttribute("data-mv")); }
      var w = e.target.closest("[data-watch]");
      if (w) {
        e.preventDefault(); w.disabled = true;
        IL.api("/api/workspace/watchlist/" + w.getAttribute("data-watch"), { method: "PUT", body: {} }).then(function (res) {
          if (res.ok) { IL.toast(w.getAttribute("data-watch") + " added to your watchlist"); loadWatchlist(); } else { w.disabled = false; IL.toast("Could not add it. Try again."); }
        });
        return;
      }
      var r = e.target.closest("tr[data-go]"); if (r && !e.target.closest("a,button")) IL.go(r.getAttribute("data-go"));
    });
  }

  /* Market today: the three index trackers and the sector funds, as numbers.
     Day is today against the previous close; 1 month is the first close in
     the returned month against the latest. No lines: a 120px sparkline with
     no axis said less than the number beside it. */
  function monthPct(closes) {
    if (!closes || closes.length < 2 || !(closes[0] > 0)) return null;
    return (closes[closes.length - 1] / closes[0] - 1) * 100;
  }
  function loadMarket() {
    IL.marketSummary().then(function (d) {
      var box = IL.$("#d-mkt"); if (!box) return;
      if (!d || !(d.indexes || []).length) { box.innerHTML = '<div class="empty">Market data is updating. Check back in a minute.</div>'; return; }
      var sectors = (d.sectors || []).filter(function (x) { return x.changePct != null; })
        .sort(function (a, b) { return b.changePct - a.changePct; });
      box.innerHTML =
        '<table class="tbl d-mkt-t"><thead><tr><th>Index</th><th>Last</th><th>Day</th><th>1 month</th></tr></thead><tbody>' +
        d.indexes.map(function (x) {
          var nm = String(x.name || x.symbol).replace(/\s*\((\w+)\)$/, ""), etf = (String(x.name || "").match(/\((\w+)\)$/) || [])[1];
          var m = monthPct(x.closes);
          return "<tr><td><b>" + h(nm) + "</b>" + (etf ? ' <span class="faint">' + h(etf) + "</span>" : "") + '</td><td class="num">' + F.price(x.price) + '</td><td class="num ' + F.cls(x.changePct) + '">' + F.spct(x.changePct, 2) + '</td><td class="num ' + F.cls(m) + '">' + (m == null ? "\u2014" : F.spct(m, 1)) + "</td></tr>";
        }).join("") + "</tbody></table>" +
        (sectors.length
          ? '<table class="tbl d-mkt-t d-sec-t"><thead><tr><th>Sector</th><th>Day</th></tr></thead><tbody>' +
            sectors.map(function (x) { return "<tr><td>" + h(x.name) + '</td><td class="num ' + F.cls(x.changePct) + '">' + F.spct(x.changePct, 2) + "</td></tr>"; }).join("") +
            "</tbody></table>"
          : "");
      var st = IL.$("#d-mkt-st");
      if (st && d.measured) st.textContent = d.advancing + " of " + d.measured + " sectors up";
    });
  }

  function loadWatchlist() {
    IL.api("/api/workspace/watchlist").then(function (res) {
      var box = IL.$("#d-wl"), since = IL.$("#d-since");
      var rows = res.ok && Array.isArray(res.data) ? res.data : [];
      if (!res.ok) { box.innerHTML = '<div class="empty">We could not load your watchlist. Refresh to try again.</div>'; since.innerHTML = ""; return; }
      if (!rows.length) {
        var picks = ["NVDA", "AAPL", "MSFT", "COST", "LLY", "JPM"];
        box.innerHTML = '<div class="dash-empty"><p><b>Start your watchlist.</b> Follow a few companies and this fills with their prices, grades and what changed.</p><div class="d-picks" id="d-picks">' +
          picks.map(function (t) { return '<div class="d-pick"><a href="/research/' + t + '">' + IL.mono(t, "", "") + '<span class="d-li-t"><b>' + t + '</b><span class="faint" data-pn="' + t + '">LensScore \u2014</span></span></a><button class="btn sm" type="button" data-watch="' + t + '">Watch</button></div>'; }).join("") + "</div>" +
          '<ul class="d-tips"><li><span><b>Write why you follow it</b> and the price you would act at.</span></li><li><span><b>Get an alert</b> when the price hits your level or a grade changes.</span></li><li><span><b>A weekly email</b> every Saturday with what moved on your stocks.</span></li></ul></div>';
        IL.api("/api/lens-grades?tickers=" + picks.join(",")).then(function (r) {
          var g = (r.data && r.data.grades) || {};
          picks.forEach(function (t) { var el = box.querySelector('[data-pn="' + t + '"]'); if (el && g[t]) el.innerHTML = 'LensScore <b class="num" style="color:var(--text)">' + F.num(g[t].score, 1) + "</b>"; });
        });
        since.innerHTML = '<p class="muted" style="font-size:13.5px">Once you follow a few stocks, grade changes on them show up here.</p><a class="card-foot" style="margin-top:auto" href="/screener">Find ideas in the Screener \u2192</a>';
        var sum = IL.$("#dh-sum"); if (sum) sum.textContent = "Here is the market today and a few places to start.";
        return;
      }
      var tickers = rows.map(function (r) { return String(r.ticker).toUpperCase(); }).slice(0, 40);
      Promise.all([
        IL.api("/api/market/snapshot?tickers=" + tickers.join(",")),
        IL.api("/api/lens-grades?tickers=" + tickers.join(",")),
      ]).then(function (r) {
        var q = {}; ((r[0].data && r[0].data.quotes) || []).forEach(function (x) { q[x.symbol] = x; });
        var g = (r[1].data && r[1].data.grades) || {};
        box.innerHTML = '<div class="tbl-wrap"><table class="tbl"><thead><tr><th>Company</th><th>Last close</th><th>Day</th><th>LensScore</th><th>Week</th><th class="dash-grades" title="Value, Growth, Profitability, Health, Momentum">V &nbsp;G &nbsp;P &nbsp;H &nbsp;M</th></tr></thead><tbody>' +
          tickers.map(function (t) {
            var x = q[t] || {}, s = g[t];
            return '<tr class="click" data-go="' + h(t) + '"><td><span class="cell-co">' + IL.mono(t, s && s.sectorName, "sm") + '<span><a href="/research/' + h(t) + '"><b>' + h(t) + '</b></a><div class="faint dash-name">' + h(IL.cleanName(x.name || "")) + "</div></span></span></td>" +
              "<td>" + F.price(x.price) + '</td><td class="' + F.cls(x.chgPct) + '">' + F.spct(x.chgPct, 2) + "</td>" +
              "<td>" + (s ? '<span class="pill ' + IL.scoreTone(s.score) + '">' + F.num(s.score, 1) + "</span>" : '<span class="faint">—</span>') + "</td>" +
              '<td class="' + F.cls(s && s.change) + '">' + (s && s.change ? F.schg(s.change).replace(/\.?0+$/, "") : "—") + "</td>" +
              '<td class="dash-grades">' + (s && s.grades ? KEYS.map(function (k) { return IL.gchip(s.grades[k]); }).join("") : "") + "</td></tr>";
          }).join("") + "</tbody></table></div>" +
          '<p class="note" style="padding:10px 20px">Prices are daily closes and update after each trading day. Week = change in LensScore over about five trading days.</p>';
        paintSince(tickers, g);
        var ups = tickers.filter(function (t) { return (q[t] || {}).chgPct > 0; }).length, downs = tickers.filter(function (t) { return (q[t] || {}).chgPct < 0; }).length;
        var sum = IL.$("#dh-sum"); if (sum) sum.innerHTML = "Your " + tickers.length + " stock" + (tickers.length === 1 ? "" : "s") + ' at the last close: <b class="up">' + ups + " up</b> \u00b7 <b class=\"down\">" + downs + " down</b>.";
      });
    });
  }
  function nice(n) {
    n = String(n || "");
    return n === n.toUpperCase() ? n.toLowerCase().replace(/\b([a-z])/g, function (m) { return m.toUpperCase(); }) : n;
  }

  /* Grade changes since this browser last opened the dashboard. */
  function paintSince(tickers, grades) {
    var box = IL.$("#d-since"), prev = null;
    try { prev = JSON.parse(localStorage.getItem(LAST) || "null"); } catch (_) {}
    var items = [];
    tickers.forEach(function (t) {
      var now = grades[t]; if (!now) return;
      var was = prev && prev.g && prev.g[t];
      if (was && was.grades && now.grades) {
        KEYS.forEach(function (k) {
          if (was.grades[k] && now.grades[k] && was.grades[k] !== now.grades[k]) {
            var up = IL.analysis ? IL.analysis.gradeRank(now.grades[k]) > IL.analysis.gradeRank(was.grades[k]) : true;
            items.push({ tone: up ? "good" : "bad", text: "<b>" + h(t) + "</b> " + h({ value: "Value", growth: "Growth", profitability: "Profitability", health: "Health", momentum: "Momentum" }[k]) + " " + h(was.grades[k]) + " → " + h(now.grades[k]), t: t });
          }
        });
      } else if (now.change && Math.abs(now.change) >= 0.5) {
        items.push({ tone: now.change > 0 ? "good" : "bad", text: "<b>" + h(t) + "</b> LensScore " + (now.change > 0 ? "up " : "down ") + F.num(Math.abs(now.change), 1) + " this week", t: t });
      }
    });
    var when = prev && prev.at ? new Date(prev.at).toLocaleDateString("en-US", { month: "short", day: "numeric" }) : null;
    box.innerHTML = (items.length
      ? '<ul class="since">' + items.slice(0, 8).map(function (x) { return '<li><a href="/research/' + h(x.t) + '">' + x.text + "</a></li>"; }).join("") + "</ul>"
      : '<p class="muted" style="font-size:13.5px">No grade changes on your stocks' + (when ? " since " + h(when) : " yet") + ".</p>") +
      '<p class="note">' + (when ? "Compared with your visit on " + h(when) + "." : "We’ll compare against today next time you visit.") + "</p>" +
      '<a class="card-foot" style="margin-top:auto" href="/watchlist">Open your watchlist \u2192</a>';
    try {
      var snap = { at: Date.now(), g: {} };
      tickers.forEach(function (t) { if (grades[t]) snap.g[t] = { score: grades[t].score, grades: grades[t].grades }; });
      localStorage.setItem(LAST, JSON.stringify(snap));
    } catch (_) {}
  }

  function loadMovers(type) {
    IL.api("/api/market/movers?type=" + type).then(function (res) {
      var box = IL.$("#d-mv"); if (!box) return;
      var rows = Array.isArray(res.data) ? res.data : [];
      if (!rows.length) { box.innerHTML = '<div class="empty">Movers appear once today’s closes are in.</div>'; return; }
      box.innerHTML = '<ul class="d-list">' + rows.slice(0, 5).map(function (r) {
        return '<li><a href="/research/' + h(r.symbol) + '">' + IL.mono(r.symbol, "", "sm") + '<span class="d-li-t"><b>' + h(r.symbol) + '</b><span class="faint">' + h(IL.cleanName(r.name || "")) + '</span></span></a><span class="num ' + F.cls(r.chgPct) + '">' + F.spct(r.chgPct) + "</span></li>";
      }).join("") + "</ul>" + (rows[0] && rows[0].asOf ? '<p class="note d-note">Among the ~280 stocks we grade \u00b7 close of ' + F.date(rows[0].asOf, { year: undefined }) + "</p>" : "");
    });
  }

  function loadLeaders() {
    IL.api("/api/lens-leaders").then(function (res) {
      var box = IL.$("#d-top"), chg = IL.$("#d-chg"); if (!box) return;
      var d = res.data || {}, s = (d.sectors || []).filter(function (x) { return x.top && x.top.length; });
      if (!s.length) { box.innerHTML = '<div class="empty">Grades are loading.</div>'; }
      else {
        s.sort(function (a, b) { return Number(b.top[0].score) - Number(a.top[0].score); });
        box.innerHTML = '<div class="tbl-wrap"><table class="tbl"><thead><tr><th>Company</th><th style="text-align:left">Sector</th><th>LensScore</th>' + KEYS.map(function (k) { return '<th class="dash-grades">' + SHORT[k] + "</th>"; }).join("") + "</tr></thead><tbody>" +
          s.slice(0, 8).map(function (x) {
            var t = x.top[0];
            return '<tr class="click" data-go="' + h(t.ticker) + '"><td><span class="cell-co">' + IL.mono(t.ticker, x.sectorName, "sm") + '<span><a href="/research/' + h(t.ticker) + '"><b>' + h(t.ticker) + '</b></a><div class="faint dash-name">' + h(IL.cleanName(t.name || "")) + '</div></span></span></td><td style="text-align:left;font-family:var(--sans)" class="muted">' + h(x.sectorName || x.sector) + '</td><td><span class="pill ' + IL.scoreTone(t.score) + '">' + F.num(t.score, 1) + "</span></td>" +
              KEYS.map(function (k) { return '<td class="dash-grades">' + IL.gchip(t.grades && t.grades[k]) + "</td>"; }).join("") + "</tr>";
          }).join("") + "</tbody></table></div>";
      }
      if (!chg) return;
      var m = d.movers;
      if (!m || (!m.up.length && !m.down.length)) { chg.innerHTML = '<p class="muted d-pad" style="font-size:13.5px">No score changes yet this week.</p>'; return; }
      var row = function (x) { return '<li><a href="/research/' + h(x.ticker) + '">' + IL.mono(x.ticker, "", "sm") + '<span class="d-li-t"><b>' + h(x.ticker) + '</b><span class="faint">' + h(IL.cleanName(x.name || "")) + '</span></span></a><span class="num"><span class="faint">' + F.num(x.then, 1) + ' \u2192 </span><b class="' + F.cls(x.change) + '">' + F.num(x.now, 1) + "</b></span></li>"; };
      chg.innerHTML = '<ul class="d-list">' + m.up.slice(0, 3).map(row).join("") + m.down.slice(0, 3).map(row).join("") + '</ul><p class="note d-note">LensScore since ' + h(F.date(m.since, { year: undefined })) + "</p>";
    });
  }

  function paintLearn() {
    var box = IL.$("#d-learn .d-pad"), done = [];
    try { done = JSON.parse(localStorage.getItem("il-academy-done") || "[]"); } catch (_) {}
    var lessons = (window.IL_LESSONS && window.IL_LESSONS.lessons) || [];
    var next = lessons.filter(function (l) { return done.indexOf(l.slug) < 0; })[0];
    if (!lessons.length) { box.innerHTML = '<h2 class="card-t">Keep learning</h2><a class="card-foot" href="/learn">Open the Academy →</a>'; return; }
    var pct = Math.round(done.length / lessons.length * 100);
    box.innerHTML = '<h2 class="card-t">Keep learning</h2><span class="card-sub">' + done.length + " of " + lessons.length + " lessons done</span>" +
      '<div class="rep-bar"><i style="width:' + Math.max(2, pct) + '%;background:var(--gold)"></i></div>' +
      (next ? '<div><span class="faint" style="font-size:12.5px">Next · ' + h(next.minutes || "") + ' min</span><div style="font-weight:650;margin-top:2px">' + h(next.title) + '</div><p class="muted" style="font-size:13px;margin-top:4px">' + h(next.summary || "") + "</p></div>" +
        '<a class="card-foot" href="/learn/' + h(next.slug) + '">' + (done.length ? "Continue" : "Start") + " →</a>"
        : '<p class="muted">You finished every lesson. Put it to work: compare two companies you own.</p><a class="card-foot" href="/compare">Compare stocks →</a>');
  }

  function boot() {
    IL.shell("home");
    IL.me().then(function (u) {
      if (!u) { location.replace("/login?next=%2F"); return; }
      render(u);
    });
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot); else boot();
})();

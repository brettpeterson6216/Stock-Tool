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

  function greet(name) {
    var hr = new Date().getHours();
    return (hr < 12 ? "Good morning" : hr < 18 ? "Good afternoon" : "Good evening") + (name ? ", " + name : "");
  }
  function sk(hh) { return '<span class="sk" style="height:' + hh + 'px"></span>'; }

  function render(user) {
    var main = document.getElementById("main");
    main.innerHTML =
      '<div class="dh"><div><h1 class="dh-t">' + h(greet(user && user.username)) + '</h1><p class="muted">Here is what changed on your stocks.</p></div>' +
        '<div class="row wrap"><a class="btn" href="/compare">Compare stocks</a><a class="btn primary" href="/?view=tool&section=screener">Find new ideas</a></div></div>' +
      '<div class="dash">' +
        '<section class="card flush dash-wl" aria-label="Your watchlist"><div class="card-h"><h2 class="card-t">Your watchlist</h2><a class="link" href="/?view=tool&section=workspace&workspace_tab=watchlist">Manage →</a></div><div id="d-wl"><div style="padding:20px">' + sk(140) + "</div></div></section>" +
        '<section class="card dash-since" aria-label="Since your last visit"><h2 class="card-t">Since your last visit</h2><div id="d-since">' + sk(90) + "</div></section>" +
      "</div>" +
      '<div class="grid-3">' +
        '<section class="card flush"><div class="card-h"><h2 class="card-t">Biggest movers</h2><div class="seg" role="group" aria-label="Movers"><button type="button" data-mv="gainers" aria-pressed="true">Up</button><button type="button" data-mv="losers" aria-pressed="false">Down</button></div></div><div id="d-mv"><div style="padding:20px">' + sk(120) + "</div></div></section>" +
        '<section class="card flush"><div class="card-h"><h2 class="card-t">Top-rated by sector</h2><a class="link" href="/research">All →</a></div><div id="d-top"><div style="padding:20px">' + sk(120) + "</div></div></section>" +
        '<section class="card" id="d-learn"><h2 class="card-t">Keep learning</h2>' + sk(90) + "</section>" +
      "</div>";
    loadWatchlist();
    loadMovers("gainers");
    loadLeaders();
    paintLearn();
    main.addEventListener("click", function (e) {
      var b = e.target.closest("[data-mv]");
      if (b) { IL.$$("[data-mv]").forEach(function (x) { x.setAttribute("aria-pressed", String(x === b)); }); loadMovers(b.getAttribute("data-mv")); }
      var r = e.target.closest("tr[data-go]"); if (r && !e.target.closest("a,button")) IL.go(r.getAttribute("data-go"));
    });
  }

  function loadWatchlist() {
    IL.api("/api/workspace/watchlist").then(function (res) {
      var box = IL.$("#d-wl"), since = IL.$("#d-since");
      var rows = res.ok && Array.isArray(res.data) ? res.data : [];
      if (!res.ok) { box.innerHTML = '<div class="empty">We could not load your watchlist. Refresh to try again.</div>'; since.innerHTML = ""; return; }
      if (!rows.length) {
        box.innerHTML = '<div class="dash-empty"><p><b>Your watchlist is empty.</b> Open any stock and press Watch to follow it here, with its grade and price.</p>' +
          '<div class="row wrap">' + ["NVDA", "AAPL", "MSFT", "COST", "LLY"].map(function (t) { return '<a class="tag" href="/research/' + t + '">' + t + "</a>"; }).join("") + "</div></div>";
        since.innerHTML = '<p class="muted" style="font-size:13.5px">Add stocks to your watchlist and we’ll show grade changes here.</p>';
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
            return '<tr class="click" data-go="' + h(t) + '"><td><a href="/research/' + h(t) + '"><b>' + h(t) + '</b></a><div class="faint dash-name">' + h(nice(x.name || "")) + "</div></td>" +
              "<td>" + F.price(x.price) + '</td><td class="' + F.cls(x.chgPct) + '">' + F.spct(x.chgPct, 2) + "</td>" +
              "<td>" + (s ? '<span class="pill ' + IL.scoreTone(s.score) + '">' + F.num(s.score, 1) + "</span>" : '<span class="faint">—</span>') + "</td>" +
              '<td class="' + F.cls(s && s.change) + '">' + (s && s.change ? F.schg(s.change).replace(/\.?0+$/, "") : "—") + "</td>" +
              '<td class="dash-grades">' + (s && s.grades ? KEYS.map(function (k) { var gr = s.grades[k]; return '<span title="' + k + '" style="color:' + IL.gradeTone(gr) + '">' + h(gr || "—") + "</span>"; }).join("") : "") + "</td></tr>";
          }).join("") + "</tbody></table></div>" +
          '<p class="note" style="padding:10px 20px">Prices are daily closes and update after each trading day. Week = change in LensScore over about five trading days.</p>';
        paintSince(tickers, g);
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
      ? '<ul class="since">' + items.slice(0, 8).map(function (x) { return '<li><span class="since-dot ' + x.tone + '"></span><a href="/research/' + h(x.t) + '">' + x.text + "</a></li>"; }).join("") + "</ul>"
      : '<p class="muted" style="font-size:13.5px">No grade changes on your stocks' + (when ? " since " + h(when) : " yet") + ".</p>") +
      '<p class="note">' + (when ? "Compared with your visit on " + h(when) + "." : "We’ll compare against today next time you visit.") + "</p>";
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
      box.innerHTML = '<ul class="mini">' + rows.map(function (r) {
        return '<li><a href="/research/' + h(r.symbol) + '"><b>' + h(r.symbol) + '</b><span class="faint">' + h(nice(r.name || "")) + '</span></a><span class="num ' + F.cls(r.chgPct) + '">' + F.spct(r.chgPct) + "</span></li>";
      }).join("") + "</ul>" + (rows[0] && rows[0].asOf ? '<p class="note" style="padding:0 20px 14px">Among the ~280 stocks we grade · close of ' + F.date(rows[0].asOf, { year: undefined }) + "</p>" : "");
    });
  }

  function loadLeaders() {
    IL.api("/api/lens-leaders").then(function (res) {
      var box = IL.$("#d-top"); if (!box) return;
      var s = (res.data && res.data.sectors) || [];
      if (!s.length) { box.innerHTML = '<div class="empty">Grades are loading.</div>'; return; }
      box.innerHTML = '<ul class="mini">' + s.slice(0, 7).map(function (x) {
        var t = x.top[0];
        return '<li><a href="/research/' + h(t.ticker) + '"><b>' + h(t.ticker) + '</b><span class="faint">' + h(x.sectorName || x.sector) + '</span></a><span class="pill ' + IL.scoreTone(t.score) + '">' + F.num(t.score, 1) + "</span></li>";
      }).join("") + "</ul>";
    });
  }

  function paintLearn() {
    var box = IL.$("#d-learn"), done = [];
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

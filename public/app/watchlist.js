/* ═══════════════════════════════════════════════════════════════════════════
   Watchlist: the companies you follow, why you follow them, and the price you
   would act at. /watchlist

   Each row keeps a note and a target price (saved to your account), shows
   the last close, how far it is from your target, the LensScore and grades,
   and its alerts. Below: every alert.

   /saved is the other half, kept apart on purpose: the work you saved
   (valuations, comparisons, notes), not the companies you follow.
   ═══════════════════════════════════════════════════════════════════════════ */
(function () {
  "use strict";
  var IL = window.IL, F = IL.fmt, h = IL.h;
  var KEYS = ["value", "growth", "profitability", "health", "momentum"];
  var items = [], quotes = {}, grades = {}, alerts = [], alertLimit = null;

  function sk(hh) { return '<span class="sk" style="height:' + hh + 'px"></span>'; }
  function nice(n) { return IL.cleanName(n); }
  var SAVED = /^\/saved/.test(location.pathname);

  function shell() {
    document.getElementById("main").innerHTML =
      '<div class="dh hero-band card prime" id="wl-hero"><div class="stack" style="gap:10px">' + IL.eyebrow("Watchlist", "star") + '<h1 class="display">The companies you <em>follow.</em></h1><p class="muted">Write down why you follow each company and the price you would act at. We’ll keep the numbers current.</p></div>' +
        '<div class="row wrap"><div class="il-search wl-add" role="search"><label class="il-search-box">' + IL.icon("search") + '<input id="wl-q" type="search" autocomplete="off" placeholder="Add a company" aria-label="Add a company to your watchlist" role="combobox" aria-expanded="false" aria-controls="wl-sugg"></label><div class="il-sugg" id="wl-sugg" role="listbox" hidden></div></div><a class="btn" id="wl-compare" href="/compare">Compare</a></div></div>' +
      '<section class="card flush prime"><div class="tbl-wrap"><table class="tbl wl-tbl" id="wl-tbl"><tbody><tr><td>' + sk(160) + "</td></tr></tbody></table></div></section>" +
      '<label class="wl-digest card" id="wl-digest" hidden><input type="checkbox" id="wl-digest-on"><span><b>Weekly grade email</b><span class="muted">Every Saturday morning: your watchlist\u2019s LensScores, what changed and the week\u2019s biggest movers.</span></span></label>' +
      '<div class="section-h"><h2 class="section-t">Alerts</h2><span class="card-sub" id="al-sub"></span></div>' +
      '<section class="card flush" id="al-box"><div style="padding:20px">' + sk(60) + "</div></section>" +
      '<p class="note wl-pointer">Valuations, comparisons and notes you save live in <a href="/saved">Saved</a>.</p>';
    IL.wireSearchPick(IL.$("#wl-q"), IL.$("#wl-sugg"), add);
    IL.plate(IL.$("#wl-hero"), "atlas", "right 30%");
  }

  /* ── Saved work page ─────────────────────────────────────────────────── */
  function savedShell() {
    document.getElementById("main").innerHTML =
      '<div class="dh hero-band card prime" id="sv-hero"><div class="stack" style="gap:10px">' + IL.eyebrow("Saved") + '<h1 class="display">Your saved <em>work.</em></h1>' +
        '<p class="muted">The valuations, comparisons and notes you kept, newest first. The companies you follow are on your <a href="/watchlist">Watchlist</a>.</p></div></div>' +
      '<div id="sv-box">' + '<section class="card"><div style="padding:4px">' + sk(80) + "</div></section></div>" +
      '<p class="note">Older theses and positions from the classic workspace are <a href="/?view=tool&section=workspace">here</a>.</p>';
    IL.plate(IL.$("#sv-hero"), "ledger", "right 30%");
  }
  var SAVE_TYPE = { implied: "Projection Lab", valuation: "Valuation Lab (classic)", projection: "Projection (classic)", dcf: "DCF (classic)", compare: "Comparison", note: "Note", lensscore: "LensToolkit", price: "Analysis" };
  var SAVE_GROUP = [
    ["Valuations", ["implied", "valuation", "projection", "dcf"]],
    ["Comparisons", ["compare"]],
    ["Notes and analyses", ["note", "lensscore", "price"]],
  ];
  function saveHref(s) {
    if (s.type === "implied") return "/research/" + encodeURIComponent(s.ticker) + "/projection?save=" + s.id;
    if (s.type === "compare" && s.ticker) return "/compare?t=" + encodeURIComponent(s.ticker);
    return "/?view=tool&section=reports";
  }
  function savedRows(list) {
    return '<ul class="mini">' + list.map(function (s) {
      return '<li><a href="' + saveHref(s) + '"><b>' + h(s.ticker) + " · " + h(s.label || SAVE_TYPE[s.type] || "Saved") + '</b><span class="faint">' + h(SAVE_TYPE[s.type] || s.type) + " · " + h(F.date(s.created_at)) + '</span></a><button class="btn sm ghost" type="button" data-del-save="' + s.id + '">Delete</button></li>';
    }).join("") + "</ul>";
  }

  function load() {
    return IL.api("/api/workspace/watchlist", { fresh: true }).then(function (res) {
      if (!res.ok) { IL.$("#wl-tbl").innerHTML = '<tbody><tr><td><div class="empty">We could not load your watchlist. Refresh to try again.</div></td></tr></tbody>'; return; }
      items = res.data || [];
      var t = items.map(function (r) { return r.ticker; });
      IL.$("#wl-compare").href = "/compare" + (t.length ? "?t=" + t.slice(0, 4).join(",") : "");
      if (!t.length) { paint(); return; }
      return Promise.all([
        IL.api("/api/market/snapshot?tickers=" + t.join(","), { fresh: true }),
        IL.api("/api/lens-grades?tickers=" + t.join(","), { fresh: true }),
      ]).then(function (r) {
        quotes = {}; ((r[0].data && r[0].data.quotes) || []).forEach(function (q) { quotes[q.symbol] = q; });
        grades = (r[1].data && r[1].data.grades) || {};
        paint();
      });
    });
  }

  function paint() {
    var tbl = IL.$("#wl-tbl");
    if (!items.length) {
      tbl.innerHTML = '<tbody><tr><td><div class="dash-empty"><p><b>Nothing here yet.</b> Search above to add a company, or press Watch on any stock page.</p><div class="row wrap">' +
        ["NVDA", "AAPL", "MSFT", "COST", "LLY"].map(function (t) { return '<button class="tag" type="button" data-add="' + t + '">+ ' + t + "</button>"; }).join("") + "</div></div></td></tr></tbody>";
      return;
    }
    tbl.innerHTML = "<thead><tr><th>Company</th><th>Last close</th><th>Day</th><th>Your target</th><th>From target</th><th>LensScore</th><th class=\"wl-gr\" title=\"Value, growth, profitability, health, momentum\">Grades</th><th>Why you follow it</th><th></th></tr></thead><tbody>" +
      items.map(function (r, i) {
        var t = r.ticker, q = quotes[t] || {}, g = grades[t], tgt = r.target_price;
        var gap = q.price && tgt ? (q.price / tgt - 1) * 100 : null;
        var al = alerts.filter(function (a) { return a.ticker === t && a.active; }).length;
        return "<tr>" +
          '<td><span class="cell-co">' + IL.mono(t, g && g.sectorName, "sm") + '<span><a href="/research/' + h(t) + '"><b>' + h(t) + '</b></a><div class="faint wl-name">' + h(nice(q.name || "")) + (al ? ' · <span class="wl-bell">' + IL.icon("bell", 11) + " " + al + "</span>" : "") + "</div></span></span></td>" +
          "<td>" + F.price(q.price) + '</td><td class="' + F.cls(q.chgPct) + '">' + F.spct(q.chgPct, 2) + "</td>" +
          '<td><input class="input num wl-in" inputmode="decimal" data-target="' + h(t) + '" value="' + (tgt ? Number(tgt).toFixed(2) : "") + '" placeholder="$" aria-label="Target price for ' + h(t) + '"></td>' +
          '<td class="' + (gap === null ? "" : gap <= 0 ? "up" : "") + '">' + (gap === null ? "—" : gap <= 0 ? "At or below" : F.pct(gap) + " above") + "</td>" +
          "<td>" + (g ? '<span class="pill score ' + IL.scoreTone(g.score) + '">' + F.num(g.score, 1) + "</span>" + (g.change ? ' <span class="num ' + F.cls(g.change) + '" style="font-size:12px">' + F.schg(g.change).replace(/\.?0+$/, "") + "</span>" : "") : "—") + "</td>" +
          '<td class="wl-gr">' + (g && g.grades ? KEYS.map(function (k) { return IL.gchip(g.grades[k]); }).join("") : "") + "</td>" +
          '<td class="wl-note-td"><input class="input wl-note" data-note="' + h(t) + '" value="' + h(r.note || "") + '" maxlength="500" placeholder="' + (i ? "Add a note" : "e.g. Buy under $180 if margins hold") + '" aria-label="Note for ' + h(t) + '"></td>' +
          '<td class="wl-act"><button class="btn sm ghost" type="button" data-alert="' + h(t) + '" aria-label="Alert for ' + h(t) + '">' + IL.icon("bell", 14) + '</button><button class="btn sm ghost" type="button" data-rm="' + h(t) + '" aria-label="Remove ' + h(t) + '">×</button></td></tr>';
      }).join("") + "</tbody>";
  }

  function add(t) {
    t = String(t || "").toUpperCase();
    if (!/^[A-Z0-9.^-]{1,15}$/.test(t)) return;
    if (items.some(function (r) { return r.ticker === t; })) { IL.toast(t + " is already on your watchlist"); return; }
    IL.api("/api/workspace/watchlist/" + t, { method: "PUT", body: {} }).then(function (res) {
      if (!res.ok) { IL.toast((res.data && res.data.error) || "Could not add " + t); return; }
      IL.toast(t + " added"); load();
    });
  }
  function saveRow(t) {
    var row = items.filter(function (r) { return r.ticker === t; })[0]; if (!row) return;
    var note = IL.$('[data-note="' + t + '"]'), tgt = IL.$('[data-target="' + t + '"]');
    var price = tgt && tgt.value.trim() ? Number(tgt.value.replace(/[$,\s]/g, "")) : null;
    if (tgt && tgt.value.trim() && !(price > 0)) { IL.toast("Enter a target price above zero"); return; }
    var body = { note: note ? note.value : row.note, target_price: price };
    IL.api("/api/workspace/watchlist/" + t, { method: "PUT", body: body }).then(function (res) {
      if (!res.ok) { IL.toast("Could not save " + t); return; }
      row.note = body.note; row.target_price = price; paint(); IL.toast("Saved");
    });
  }

  function loadAlerts() {
    return IL.api("/api/alerts", { fresh: true }).then(function (res) {
      var box = IL.$("#al-box");
      if (!res.ok) { box.innerHTML = '<div class="empty">Alerts are unavailable right now.</div>'; return; }
      alerts = res.data.alerts || []; alertLimit = res.data.limit;
      var active = alerts.filter(function (a) { return a.active; });
      IL.$("#al-sub").textContent = active.length + " active of " + (alertLimit || "—") + " allowed on your plan";
      if (!alerts.length) { box.innerHTML = '<p class="muted" style="padding:16px 20px;font-size:13.5px">No alerts yet. Press the bell on a row to get an email when a price is reached or a grade changes.</p>'; paint(); return; }
      box.innerHTML = '<div class="tbl-wrap"><table class="tbl"><thead><tr><th>Company</th><th style="text-align:left">When</th><th>Status</th><th></th></tr></thead><tbody>' +
        alerts.map(function (a) {
          var what = a.kind === "above" ? "Price at or above " + F.price(a.level) : a.kind === "below" ? "Price at or below " + F.price(a.level) : a.kind === "buy_zone" ? "Reaches the buy zone (" + F.price(a.level) + ")" : "LensScore grade changes";
          return '<tr><td><a href="/research/' + h(a.ticker) + '"><b>' + h(a.ticker) + '</b></a></td><td style="text-align:left;font-family:var(--sans)">' + h(what) + "</td><td>" +
            (a.active ? '<span class="tag gold">Watching</span>' : '<span class="tag">Sent ' + h(a.triggeredAt ? F.date(a.triggeredAt, { year: undefined }) : "") + "</span>") +
            '</td><td><button class="btn sm ghost" type="button" data-del-alert="' + a.id + '">Delete</button></td></tr>';
        }).join("") + "</tbody></table></div>";
      paint();
    });
  }

  function loadSaves() {
    IL.api("/api/saves", { fresh: true }).then(function (res) {
      var box = IL.$("#sv-box"); if (!box) return;
      var list = res.ok && Array.isArray(res.data) ? res.data : [];
      if (!list.length) {
        box.innerHTML = '<section class="card"><div class="dash-empty"><p><b>Nothing saved yet.</b> Save a valuation from any stock’s Valuation tab, or a set of companies from Compare, and it appears here.</p><div class="row wrap"><a class="btn" href="/research/NVDA/valuation">Value a stock</a><a class="btn ghost" href="/compare">Compare stocks</a></div></div></section>';
        return;
      }
      var known = {};
      box.innerHTML = SAVE_GROUP.map(function (g) {
        var rows = list.filter(function (s) { return g[1].indexOf(s.type) >= 0; });
        rows.forEach(function (s) { known[s.id] = 1; });
        return rows.length ? '<div class="section-h"><h2 class="section-t">' + g[0] + '</h2><span class="card-sub">' + rows.length + "</span></div>" + '<section class="card flush">' + savedRows(rows) + "</section>" : "";
      }).join("") + (function () {
        var rest = list.filter(function (s) { return !known[s.id]; });
        return rest.length ? '<div class="section-h"><h2 class="section-t">Other</h2></div><section class="card flush">' + savedRows(rest) + "</section>" : "";
      })();
      return;

    });
  }

  function alertDialog(t) {
    var q = quotes[t] || {}, px = q.price;
    IL.dialog("<h2>Alert me about " + h(t) + "</h2>" +
      '<label class="field">When<select class="input" id="al-kind"><option value="below">Price falls to or below</option><option value="above">Price rises to or above</option><option value="score">Its LensScore grade changes</option></select></label>' +
      '<label class="field" id="al-level-f">Price<input class="input num" id="al-level" inputmode="decimal" value="' + (px ? (px * 0.9).toFixed(2) : "") + '"></label>' +
      '<p class="note" id="al-err" role="alert"></p><div class="row" style="justify-content:flex-end"><button class="btn ghost" type="button" data-close>Cancel</button><button class="btn primary" type="button" id="al-save">Save alert</button></div>',
      function (d) {
        var kind = d.querySelector("#al-kind"), lvl = d.querySelector("#al-level");
        kind.addEventListener("change", function () { d.querySelector("#al-level-f").style.display = kind.value === "score" ? "none" : ""; if (px && kind.value !== "score") lvl.value = (px * (kind.value === "above" ? 1.1 : 0.9)).toFixed(2); });
        d.querySelector("#al-save").addEventListener("click", function () {
          var body = { ticker: t, kind: kind.value };
          if (kind.value !== "score") body.level = Number(String(lvl.value).replace(/[$,\s]/g, ""));
          IL.api("/api/alerts", { method: "POST", body: body }).then(function (res) {
            if (!res.ok) { d.querySelector("#al-err").innerHTML = h((res.data && res.data.error) || "Could not save the alert.") + (res.data && res.data.upgrade ? ' <a href="/pricing">See Pro</a>' : ""); return; }
            d.close(); IL.toast("Alert saved"); loadAlerts();
          });
        });
      });
  }

  function wire() {
    var main = document.getElementById("main");
    main.addEventListener("change", function (e) {
      var t = e.target.getAttribute("data-note") || e.target.getAttribute("data-target");
      if (t) saveRow(t);
    });
    main.addEventListener("keydown", function (e) { if (e.key === "Enter" && e.target.classList.contains("input") && (e.target.dataset.note || e.target.dataset.target)) e.target.blur(); });
    main.addEventListener("click", function (e) {
      var b;
      if ((b = e.target.closest("[data-add]"))) { add(b.getAttribute("data-add")); return; }
      if ((b = e.target.closest("[data-rm]"))) {
        var t = b.getAttribute("data-rm");
        IL.api("/api/workspace/watchlist/" + t, { method: "DELETE" }).then(function (res) { if (res.ok) { IL.toast(t + " removed"); load(); } else IL.toast("Could not remove " + t); });
        return;
      }
      if ((b = e.target.closest("[data-alert]"))) { alertDialog(b.getAttribute("data-alert")); return; }
      if ((b = e.target.closest("[data-del-alert]"))) {
        IL.api("/api/alerts/" + b.getAttribute("data-del-alert"), { method: "DELETE" }).then(function (res) { if (res.ok) { IL.toast("Alert deleted"); loadAlerts(); } });
        return;
      }
      if ((b = e.target.closest("[data-del-save]"))) {
        if (!window.confirm("Delete this saved item? This cannot be undone.")) return;
        IL.api("/api/saves/" + b.getAttribute("data-del-save"), { method: "DELETE" }).then(function (res) { if (res.ok) { IL.toast("Deleted"); loadSaves(); } });
      }
    });
  }

  function boot() {
    IL.shell(SAVED ? "saved" : "watchlist");
    IL.me().then(function (u) {
      if (!u && SAVED) {
        document.getElementById("main").innerHTML = '<div class="dh"><div><h1 class="dh-t">Saved work</h1><p class="muted">Valuations, comparisons and notes you keep.</p></div></div>' +
          IL.gate("login", "Create a free account to save your work", { why: "Free accounts keep the valuations you build and the companies you compare, so you can come back to them." });
        return;
      }
      if (SAVED) { savedShell(); wire(); loadSaves(); return; }
      if (!u) {
        document.getElementById("main").innerHTML = '<div class="dh"><div><h1 class="dh-t">Watchlist</h1><p class="muted">Follow companies, note why, set a target price and get an email when it’s reached.</p></div></div>' +
          IL.gate("login", "Create a free account to keep a watchlist", { why: "Free accounts keep a watchlist with notes and target prices, see grade changes on the dashboard and get 3 email alerts. No card needed.", center: true });
        return;
      }
      shell(); wire();
      IL.api("/api/workspace/digest", { fresh: true }).then(function (res) {
        if (!res.ok) return;
        var box = IL.$("#wl-digest"), cb = IL.$("#wl-digest-on");
        box.hidden = false; cb.checked = !!res.data.on;
        cb.addEventListener("change", function () {
          IL.api("/api/workspace/digest", { method: "PUT", body: { on: cb.checked } }).then(function (r) {
            if (r.ok) IL.toast(cb.checked ? "Weekly email on" : "Weekly email off"); else { cb.checked = !cb.checked; IL.toast("Could not save"); }
          });
        });
      });
      Promise.all([load(), loadAlerts()]);
    });
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot); else boot();
})();

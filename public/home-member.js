/* ═══════════════════════════════════════════════════════════════════════════
   The signed-in half of the home page.

   One URL serves two audiences. theme-bootstrap.js resolves the cached session
   hint before first paint, so a member never sees the pitch and a first-time
   visitor never sees an empty workspace. This script fills the member side and
   reconciles the hint against the server.

   Same honesty rule as everywhere else on this site: every number here is a
   count the API returned. When a request fails, the tile says so rather than
   showing a zero, because "0 watchlist items" and "we could not reach your
   watchlist" are different facts.
   ═══════════════════════════════════════════════════════════════════════════ */
(function () {
  "use strict";

  var root = document.getElementById("il-home-member");
  if (!root) return;

  var TILES = [
    { key: "watchlist", label: "Watchlist", href: "/?view=tool&section=workspace", unit: "item" },
    { key: "theses", label: "Theses", href: "/?view=tool&section=workspace", unit: "thesis", plural: "theses" },
    { key: "saves", label: "Saved analyses", href: "/?view=tool&section=reports", unit: "analysis", plural: "analyses" },
    { key: "dueReviews", label: "Reviews due", href: "/?view=tool&section=workspace", unit: "review" }
  ];

  function esc(value) {
    return String(value == null ? "" : value).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  function plural(n, one, many) {
    return n === 1 ? one : (many || one + "s");
  }

  function greet(name) {
    var hour = new Date().getHours();
    var part = hour < 12 ? "Good morning" : hour < 18 ? "Good afternoon" : "Good evening";
    return name ? part + ", " + name + "." : part + ".";
  }

  function renderTiles(counts, failed) {
    var wrap = document.getElementById("ihm-tiles");
    if (!wrap) return;
    var total = TILES.reduce(function (sum, t) {
      return sum + (Number.isFinite(counts[t.key]) ? counts[t.key] : 0);
    }, 0);

    // Nothing saved yet is the new-account case, and a list of zeroes is a
    // worse answer for that person than being told what to do first.
    var start = document.getElementById("ihm-start");
    if (!failed && total === 0) {
      wrap.hidden = true;
      if (start) start.hidden = false;
      return;
    }
    if (start) start.hidden = true;
    wrap.hidden = false;

    wrap.innerHTML = TILES.map(function (t) {
      var n = counts[t.key];
      var has = Number.isFinite(n);
      var value = has ? String(n) : "&mdash;";
      var sub = has ? plural(n, t.unit, t.plural) : "unavailable";
      return '<a class="ihm-tile' + (has && n > 0 && t.key === "dueReviews" ? " is-due" : "") + '" href="' + t.href + '">' +
        '<span class="ihm-tile-n">' + value + "</span>" +
        '<span class="ihm-tile-l">' + esc(t.label) + "</span>" +
        '<span class="ihm-tile-s">' + esc(sub) + "</span></a>";
    }).join("");
  }

  function renderRecent(saves) {
    var wrap = document.getElementById("ihm-recent");
    var list = document.getElementById("ihm-recent-list");
    if (!wrap || !list) return;
    var rows = (Array.isArray(saves) ? saves : []).slice(0, 5);
    if (!rows.length) { wrap.hidden = true; return; }
    wrap.hidden = false;
    list.innerHTML = rows.map(function (row) {
      var when = "";
      var t = Date.parse(row.created_at || "");
      if (Number.isFinite(t)) {
        var days = Math.floor((Date.now() - t) / 86400000);
        when = days <= 0 ? "today" : days === 1 ? "yesterday" : days + " days ago";
      }
      return '<a class="ihm-recent-row" href="/?view=tool&section=reports">' +
        '<b>' + esc(row.ticker || "&mdash;") + "</b>" +
        '<span class="ihm-recent-label">' + esc(row.label || row.type || "Saved analysis") + "</span>" +
        '<span class="ihm-recent-when">' + esc(when) + "</span></a>";
    }).join("");
  }

  function json(url) {
    return fetch(url, { credentials: "same-origin", headers: { Accept: "application/json" } })
      .then(function (r) { return r.ok ? r.json() : Promise.reject(new Error(String(r.status))); });
  }

  function load(user) {
    var name = "";
    var label = String((user && (user.username || user.email)) || "").split("@")[0].trim();
    if (label) {
      var first = label.split(/[._\-\s]+/)[0];
      name = first ? first.charAt(0).toUpperCase() + first.slice(1) : "";
    }
    var g = document.getElementById("ihm-greeting");
    if (g) g.textContent = greet(name);

    Promise.allSettled([json("/api/workspace/summary"), json("/api/saves")])
      .then(function (results) {
        var summary = results[0].status === "fulfilled" ? results[0].value : null;
        var saves = results[1].status === "fulfilled" ? results[1].value : null;
        var counts = {
          watchlist: summary && Number.isFinite(Number(summary.watchlist)) ? Number(summary.watchlist) : NaN,
          theses: summary && Number.isFinite(Number(summary.theses)) ? Number(summary.theses) : NaN,
          dueReviews: summary && Number.isFinite(Number(summary.dueReviews)) ? Number(summary.dueReviews) : NaN,
          saves: Array.isArray(saves) ? saves.length : NaN
        };
        renderTiles(counts, !summary && !saves);
        renderRecent(saves);
      });
  }

  /* The hint decides the first paint; this decides the truth. */
  json("/api/auth/me")
    .then(function (data) {
      var user = data && data.user;
      var html = document.documentElement;
      html.classList.remove("il-hint-unknown");
      html.classList.toggle("il-hint-in", !!user);
      html.classList.toggle("il-hint-out", !user);
      if (user) load(user);
    })
    .catch(function () {
      // Session unresolvable: fall back to the visitor page rather than an
      // empty workspace.
      document.documentElement.classList.remove("il-hint-unknown", "il-hint-in");
      document.documentElement.classList.add("il-hint-out");
    });
}());

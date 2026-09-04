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

  /* Four wide tiles across the top pushed everything else below the fold and
     said very little; they are a short list in the left rail now. The three
     numbered "how to use this site" steps that replaced them on an empty
     account are gone entirely - they told someone who had already signed up
     and logged in to search for a ticker, which is the one thing the box
     directly beside them already invited them to do. */
  function renderTiles(counts, failed) {
    var wrap = document.getElementById("ihm-tiles");
    if (!wrap) return;
    wrap.hidden = false;
    wrap.innerHTML = TILES.map(function (t) {
      var n = counts[t.key];
      var has = Number.isFinite(n);
      return '<a class="ihm-stat' + (has && n > 0 && t.key === "dueReviews" ? " is-due" : "") +
        (has && n === 0 ? " is-zero" : "") + '" href="' + t.href + '">' +
        '<span class="ihm-stat-l">' + esc(t.label) + "</span>" +
        '<span class="ihm-stat-n">' + (has ? String(n) : "&mdash;") + "</span></a>";
    }).join("") + (failed ? '<span class="ihm-none">Your counts are unavailable right now.</span>' : "");
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


  /* ── The working half of the dashboard ─────────────────────────────────
     The page was a greeting, a search box, four tiles and a list, which left
     the footer occupying half the viewport. These panels fill it with things
     that are actually useful to someone already signed in: where the market
     is, what moved, and what they follow. */

  var INDEXES = [
    { t: "^IXIC", label: "Nasdaq" },
    { t: "^DJI", label: "Dow Jones" },
    { t: "^VIX", label: "Volatility" }
  ];
  var POPULAR = ["AAPL", "NVDA", "MSFT", "AMZN", "META", "TSLA"];

  function num(value, digits) {
    return Number.isFinite(Number(value))
      ? Number(value).toLocaleString("en-US", { minimumFractionDigits: digits, maximumFractionDigits: digits })
      : "\u2014";
  }
  function pct(value) {
    if (!Number.isFinite(Number(value))) return "\u2014";
    var n = Number(value);
    return (n >= 0 ? "+" : "") + n.toFixed(2) + "%";
  }
  function dirClass(v) {
    return Number.isFinite(Number(v)) ? (Number(v) >= 0 ? " is-up" : " is-dn") : "";
  }
  function linePath(values, w, h) {
    var nums = (Array.isArray(values) ? values : []).map(Number).filter(Number.isFinite);
    if (nums.length < 2) return "";
    var min = Math.min.apply(Math, nums), max = Math.max.apply(Math, nums);
    var span = max - min || 1;
    return nums.map(function (v, i) {
      var x = (i / (nums.length - 1)) * w;
      var y = h - 3 - ((v - min) / span) * (h - 7);
      return (i ? "L" : "M") + x.toFixed(2) + " " + y.toFixed(2);
    }).join(" ");
  }

  /* A sparkline is a shape, not a number: no axis, no labels, nothing that a
     horizontal stretch could distort. The stroke is pinned to screen pixels
     so it stays one weight whatever width the card ends up. Fewer than two
     real closes draws nothing rather than a straight line implying calm. */
  function spark(closes, up) {
    var d = linePath(closes, 100, 30);
    if (!d) return "";
    return '<svg class="ihm-spark' + (up ? " is-up" : " is-dn") + '" viewBox="0 0 100 30" ' +
      'preserveAspectRatio="none" aria-hidden="true" focusable="false"><path d="' + d + '"/></svg>';
  }

  /* One quote call per symbol, on the preview path so it costs no analysis
     quota. Anything that does not answer is left out rather than guessed at. */
  function quote(symbol) {
    return json("/api/quote/" + encodeURIComponent(symbol) + "?range=1d&preview=1")
      .then(function (d) {
        var meta = d && d.chart && d.chart.result && d.chart.result[0] && d.chart.result[0].meta;
        if (!meta) return null;
        var price = Number(meta.regularMarketPrice != null ? meta.regularMarketPrice : meta.chartPreviousClose);
        var prev = Number(meta.chartPreviousClose || meta.previousClose || price);
        if (!Number.isFinite(price)) return null;
        // A close of null is a bar that has not printed. Number(null) is 0 and
        // 0 is finite, so the null has to be rejected before the conversion or
        // it becomes a price of zero and the sparkline falls off its own floor.
        var raw = d.chart.result[0].indicators && d.chart.result[0].indicators.quote &&
                  d.chart.result[0].indicators.quote[0] && d.chart.result[0].indicators.quote[0].close;
        var closes = [];
        (Array.isArray(raw) ? raw : []).forEach(function (v) {
          if (v == null) return;
          var n = Number(v);
          if (Number.isFinite(n) && n > 0) closes.push(n);
        });
        return { symbol: symbol, price: price, closes: closes,
                 changePct: prev > 0 ? ((price - prev) / prev) * 100 : NaN };
      })
      .catch(function () { return null; });
  }

  function renderMarket(data) {
    var overview = data && data.overview;
    var host = document.getElementById("il-home-member");
    var chartHost = document.getElementById("ihm-chart");

    if (!overview || !Number.isFinite(Number(overview.price))) {
      if (chartHost) chartHost.innerHTML = '<p class="ilx-empty">Market data is unavailable right now.</p>';
      if (host) host.classList.add("mkt-empty");
    } else {
      if (host) {
        host.classList.remove("mkt-empty");
        host.classList.toggle("is-up", Number(overview.changePct) >= 0);
        host.classList.toggle("is-dn", Number(overview.changePct) < 0);
      }
      var priceEl = document.getElementById("ihm-mkt-price");
      var chgEl = document.getElementById("ihm-mkt-change");
      if (priceEl) priceEl.textContent = num(overview.price, 2);
      if (chgEl) {
        chgEl.textContent = pct(overview.changePct);
        chgEl.className = dirClass(overview.changePct).trim();
      }

      /* Three indexes overlaid and normalised, drawn by index-chart.js. The
         note under the title reports the interval the server actually got, so
         the resolution of the line is stated rather than assumed. */
      var indexes = Array.isArray(data.indexes) ? data.indexes : [];
      if (chartHost && typeof window.ilRenderIndexChart === "function") {
        var drawn = window.ilRenderIndexChart(chartHost, indexes);
        var note = document.getElementById("ihm-mkt-note");
        if (note) {
          var lead = indexes[0] || {};
          // The server reports which rung of the ladder answered, so the note
          // states the resolution that was actually drawn rather than the one
          // that was asked for.
          var span = data && data.windowLabel ? data.windowLabel : "30 days";
          var res = lead.interval === "1d" ? "daily closes"
                  : lead.interval === "1wk" ? "weekly closes"
                  : lead.interval + " bars";
          note.textContent = Number.isFinite(Number(lead.points))
            ? "percent change \u00b7 " + span + " \u00b7 " + lead.points + " " + res
            : "percent change";
        }
      } else if (chartHost) {
        chartHost.innerHTML = '<p class="ilx-empty">Index history is unavailable right now.</p>';
      }
    }

    var sectors = Array.isArray(data.sectors) ? data.sectors : [];
    var wrap = document.getElementById("ihm-sectors");
    if (wrap) {
      wrap.innerHTML = sectors.length
        ? sectors.map(function (s) {
            return '<span class="ihm-sector' + dirClass(s.changePct) + '"><b>' + esc(s.name || s.symbol) +
              "</b><i>" + pct(s.changePct) + "</i></span>";
          }).join("")
        : '<span class="ihm-none">Sector data unavailable.</span>';
    }
    var breadth = document.getElementById("ihm-breadth");
    if (breadth) {
      breadth.textContent = Number.isFinite(Number(data.measured)) && Number(data.measured) > 0
        ? Number(data.advancing || 0) + " of " + Number(data.measured) + " advancing"
        : "\u2014";
    }
    var news = document.getElementById("ihm-news");
    if (news) {
      var items = Array.isArray(data.news) ? data.news.slice(0, 4) : [];
      news.innerHTML = items.length
        ? items.map(function (n) {
            var href = n.url ? ' href="' + esc(n.url) + '" target="_blank" rel="noopener"' : "";
            return "<a class=\"ihm-news-row\"" + href + "><span>" + esc(n.headline) +
              '</span><i>' + esc(n.source || "") + "</i></a>";
          }).join("")
        : '<span class="ihm-none">No market news available right now.</span>';
    }
  }

  function renderIndexes(rows) {
    var wrap = document.getElementById("ihm-indexes");
    if (!wrap) return;
    var have = rows.filter(Boolean);
    wrap.innerHTML = have.length
      ? have.map(function (r) {
          var label = (INDEXES.filter(function (i) { return i.t === r.symbol; })[0] || {}).label || r.symbol;
          return '<div class="ihm-index' + dirClass(r.changePct) + '">' +
            '<div class="ihm-index-txt"><span>' + esc(label) + "</span><b>" + num(r.price, 2) +
            "</b><i>" + pct(r.changePct) + "</i></div>" +
            spark(r.closes, Number(r.changePct) >= 0) + "</div>";
        }).join("")
      : '<span class="ihm-none">Index data unavailable.</span>';
  }

  function renderPopulars(rows) {
    var wrap = document.getElementById("ihm-populars");
    if (!wrap) return;
    var have = rows.filter(Boolean);
    wrap.innerHTML = have.length
      ? have.map(function (r) {
          return '<a class="ihm-pop' + dirClass(r.changePct) + '" href="/?view=tool&section=analyze&symbol=' +
            encodeURIComponent(r.symbol) + '">' + spark(r.closes, Number(r.changePct) >= 0) +
            '<div class="ihm-pop-txt"><b>' + esc(r.symbol) + "</b><span>" + num(r.price, 2) +
            "</span><i>" + pct(r.changePct) + "</i></div></a>";
        }).join("")
      : '<span class="ihm-none">Quotes unavailable right now.</span>';
  }

  function renderFavourites(items, quotes) {
    var wrap = document.getElementById("ihm-favs");
    var empty = document.getElementById("ihm-favs-empty");
    if (!wrap || !empty) return;
    if (!Array.isArray(items) || !items.length) {
      wrap.innerHTML = "";
      empty.hidden = false;
      return;
    }
    empty.hidden = true;
    var byTicker = {};
    (quotes || []).forEach(function (q) { if (q) byTicker[q.symbol] = q; });
    wrap.innerHTML = items.slice(0, 10).map(function (item) {
      var q = byTicker[item.ticker];
      var right = q
        ? '<b>' + num(q.price, 2) + "</b><i>" + pct(q.changePct) + "</i>"
        : '<b>&mdash;</b><i class="ihm-na">no quote</i>';
      // Number(null) is 0, and 0 is finite - so a row with no target rendered
      // "target 0.00", which reads as a real price of zero.
      var hasTarget = item.target_price != null && item.target_price !== "" &&
        Number.isFinite(Number(item.target_price)) && Number(item.target_price) > 0;
      var target = hasTarget
        ? '<span class="ihm-fav-note">target ' + num(item.target_price, 2) + "</span>"
        : item.note ? '<span class="ihm-fav-note">' + esc(String(item.note).slice(0, 40)) + "</span>" : "";
      return '<a class="ihm-fav' + (q ? dirClass(q.changePct) : "") +
        '" href="/?view=tool&section=analyze&symbol=' + encodeURIComponent(item.ticker) + '">' +
        '<span class="ihm-fav-sym">' + esc(item.ticker) + target + "</span>" +
        '<span class="ihm-fav-q">' + right + "</span></a>";
    }).join("");
  }

  /* The timeframe picks the resolution, not just the span: a day is drawn from
     five-minute bars and a month from daily closes, which is what every
     finance site does and the reason a month of hourly bars read as noise -
     over the same range the S&P changes direction 81 times hourly and 12
     times daily. The server owns that mapping; this only asks for a window. */
  var WINDOWS = ["1D", "1W", "1M", "3M", "1Y"];
  var DEFAULT_WINDOW = "1M";
  var currentWindow = DEFAULT_WINDOW;

  function rememberedWindow() {
    try {
      var v = window.localStorage.getItem("il-mkt-window");
      return WINDOWS.indexOf(v) >= 0 ? v : DEFAULT_WINDOW;
    } catch (_) { return DEFAULT_WINDOW; }
  }

  function loadMarket(key) {
    currentWindow = WINDOWS.indexOf(key) >= 0 ? key : DEFAULT_WINDOW;
    try { window.localStorage.setItem("il-mkt-window", currentWindow); } catch (_) {}

    var buttons = document.querySelectorAll("#ihm-tfs .ihm-tf");
    for (var i = 0; i < buttons.length; i += 1) {
      buttons[i].setAttribute("aria-pressed", String(buttons[i].getAttribute("data-window") === currentWindow));
    }
    var chartHost = document.getElementById("ihm-chart");
    if (chartHost) chartHost.classList.add("is-loading");

    var asked = currentWindow;
    return json("/api/market/landing-summary?window=" + encodeURIComponent(currentWindow))
      .then(function (data) {
        // A slow answer for a window the reader has already moved off must not
        // overwrite the one they are looking at.
        if (asked !== currentWindow) return;
        if (chartHost) chartHost.classList.remove("is-loading");
        renderMarket(data);
      })
      .catch(function () {
        if (asked !== currentWindow) return;
        if (chartHost) chartHost.classList.remove("is-loading");
        renderMarket(null);
      });
  }

  function wireTimeframes() {
    var group = document.getElementById("ihm-tfs");
    if (!group || group.ilWired) return;
    group.ilWired = true;
    group.addEventListener("click", function (e) {
      var btn = e.target && e.target.closest ? e.target.closest(".ihm-tf") : null;
      if (!btn) return;
      var key = btn.getAttribute("data-window");
      if (!key || key === currentWindow) return;
      loadMarket(key);
    });
  }

  function loadDashboard() {
    wireTimeframes();
    loadMarket(rememberedWindow());

    Promise.all(INDEXES.map(function (i) { return quote(i.t); })).then(renderIndexes);
    Promise.all(POPULAR.map(quote)).then(renderPopulars);

    json("/api/workspace/watchlist")
      .then(function (items) {
        var list = Array.isArray(items) ? items : [];
        return Promise.all(list.slice(0, 10).map(function (i) { return quote(i.ticker); }))
          .then(function (quotes) { renderFavourites(list, quotes); });
      })
      .catch(function () { renderFavourites([], []); });
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
    loadDashboard();
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

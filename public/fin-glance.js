/* Financials at a glance: revenue bars and four key-number tiles, drawn with
   Lens Charts from the same SEC statements as the tables underneath.
   app-legacy.js calls ILFinGlance.render(result) after it builds the tables. */
(function () {
  "use strict";

  function raw(v) { return v == null ? null : (v.raw != null ? v.raw : (typeof v === "number" ? v : null)); }
  function year(s) { var d = s && s.endDate; return d ? (d.fmt ? d.fmt.slice(0, 4) : String(d).slice(0, 4)) : ""; }
  function money(n) {
    if (!Number.isFinite(n)) return "—";
    var a = Math.abs(n), sign = n < 0 ? "−" : "";
    if (a >= 1e12) return sign + "$" + (a / 1e12).toFixed(2) + "T";
    if (a >= 1e9) return sign + "$" + (a / 1e9).toFixed(a >= 1e11 ? 0 : 1) + "B";
    if (a >= 1e6) return sign + "$" + (a / 1e6).toFixed(a >= 1e8 ? 0 : 1) + "M";
    return sign + "$" + Math.round(a).toLocaleString("en-US");
  }
  function esc(s) { return String(s == null ? "" : s).replace(/[&<>"]/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]; }); }

  function annual(r, histKey, listKey) {
    var h = r && r[histKey] && r[histKey][listKey];
    return Array.isArray(h) ? h.slice().filter(function (s) { return s && s.endDate; })
      .sort(function (a, b) { return year(a) < year(b) ? -1 : 1; }) : [];
  }

  function render(r) {
    var host = document.getElementById("fin-glance");
    if (!host || !window.LensCharts) return;
    var inc = annual(r, "incomeStatementHistory", "incomeStatementHistory");
    var cf = annual(r, "cashflowStatementHistory", "cashflowStatements");
    var revs = inc.map(function (s) { return { y: year(s), v: raw(s.totalRevenue) }; }).filter(function (d) { return Number.isFinite(d.v) && d.v > 0; });
    if (revs.length < 2) { host.hidden = true; return; }
    host.hidden = false;

    /* Revenue by year, plus trailing twelve months when a 10-Q is newer than
       the last annual report. */
    var items = revs.map(function (d) { return { label: "FY" + d.y.slice(2), value: d.v }; });
    var ttm = r.trailingTwelveMonths || {};
    var lastEnd = inc.length ? String((inc[inc.length - 1].endDate || {}).fmt || inc[inc.length - 1].endDate || "") : "";
    var hasTtm = ttm.basis === "ttm" && raw(ttm.revenue) > 0 && ttm.asOf && ttm.asOf > lastEnd;
    if (hasTtm) items.push({ label: "TTM", value: raw(ttm.revenue), note: "Last 12 months to " + ttm.asOf });
    items[items.length - 1].highlight = true;
    var a = revs[revs.length - 1].v, b = revs[revs.length - 2].v, g = (a / b - 1) * 100;
    var chip = document.getElementById("fin-glance-growth");
    if (chip) {
      chip.textContent = (g >= 0 ? "+" : "−") + Math.abs(g).toFixed(0) + "% in FY" + revs[revs.length - 1].y;
      chip.classList.toggle("is-down", g < 0);
    }


    /* Four key numbers, each with its trend across the annual reports. */
    function series(list, fn) { return list.map(function (s) { var v = fn(s); return Number.isFinite(v) ? v : null; }); }
    var gm = series(inc, function (s) { var rv = raw(s.totalRevenue), gp = raw(s.grossProfit); return rv > 0 && gp != null ? gp / rv * 100 : null; });
    var om = series(inc, function (s) { var rv = raw(s.totalRevenue), oi = raw(s.operatingIncome); return rv > 0 && oi != null ? oi / rv * 100 : null; });
    var ni = series(inc, function (s) { return raw(s.netIncome); });
    var fcf = series(cf, function (s) {
      var op = raw(s.totalCashFromOperatingActivities), cx = raw(s.capitalExpenditures);
      return op != null && cx != null ? op - Math.abs(cx) : null;
    });
    function lastTwo(arr) { var v = arr.filter(function (x) { return x != null; }); return v.length ? [v[v.length - 1], v.length > 1 ? v[v.length - 2] : null] : [null, null]; }
    function pctTile(label, arr, note) {
      var lt = lastTwo(arr), now = lt[0], prev = lt[1];
      if (now == null) return null;
      var d = prev == null ? null : now - prev;
      return { label: label, value: now.toFixed(1) + "%", values: arr,
        delta: d == null ? "" : (d >= 0 ? "▲ " : "▼ ") + Math.abs(d).toFixed(1) + " pts vs. prior year", up: d == null || d >= 0, note: note(now) };
    }
    function moneyTile(label, arr, note) {
      var lt = lastTwo(arr), now = lt[0], prev = lt[1];
      if (now == null) return null;
      var d = prev == null || prev === 0 ? null : (now - prev) / Math.abs(prev) * 100;
      return { label: label, value: money(now), values: arr,
        delta: d == null ? "" : (d >= 0 ? "▲ " : "▼ ") + Math.abs(d).toFixed(0) + "% vs. prior year", up: d == null || d >= 0, note: note(now) };
    }
    var tiles = [
      pctTile("Gross margin", gm, function (v) { return "Keeps about " + Math.round(v) + "¢ of every sales dollar after the cost of what it sells."; }),
      pctTile("Operating margin", om, function (v) { return v >= 0 ? Math.round(v) + "¢ of each dollar is left after running the business." : "Running the business costs more than it brings in."; }),
      moneyTile("Net income", ni, function (v) { return v >= 0 ? "Profit after every cost, interest and tax." : "A loss after every cost, interest and tax."; }),
      moneyTile("Free cash flow", fcf, function (v) { return v >= 0 ? "Cash left after running and investing in the business." : "Spent more cash than the business brought in."; })
    ].filter(Boolean);

    var wrap = document.getElementById("fin-glance-tiles");
    if (!wrap) return;
    wrap.innerHTML = tiles.map(function (t, i) {
      return '<div class="il-fg-tile">' +
        '<span class="il-fg-label">' + esc(t.label) + '</span>' +
        '<span class="il-fg-value">' + esc(t.value) + '</span>' +
        (t.delta ? '<span class="il-fg-delta' + (t.up ? "" : " is-down") + '">' + esc(t.delta) + '</span>' : "") +
        '<div class="il-fg-spark" id="fin-glance-spark-' + i + '"></div>' +
        '<span class="il-fg-note">' + esc(t.note) + '</span></div>';
    }).join("");
    tiles.forEach(function (t, i) {
      window.LensCharts.spark(document.getElementById("fin-glance-spark-" + i), {
        values: t.values.filter(function (v) { return v != null; }), height: 44, label: t.label + " trend by fiscal year"
      });
    });

    /* Drawn last: beside the tiles, the bars take the height the tiles give
       the row, so the card has no dead space under the chart. */
    function barHeight() {
      var card = host.querySelector(".il-fg-card"), head = host.querySelector(".il-fg-head");
      var tilesEl = document.getElementById("fin-glance-tiles");
      var side = card && tilesEl && card.getBoundingClientRect().top === tilesEl.getBoundingClientRect().top;
      if (!side) return 220;
      var avail = tilesEl.getBoundingClientRect().height - (head ? head.getBoundingClientRect().height : 24) - 44;
      return Math.max(220, Math.min(380, Math.round(avail)));
    }
    window.LensCharts.bars(document.getElementById("fin-glance-bars"), {
      items: items, format: money, valueName: "Revenue", height: barHeight(),
      label: "Revenue by fiscal year" + (hasTtm ? " and trailing twelve months" : "")
    });
  }

  window.ILFinGlance = { render: render };
})();

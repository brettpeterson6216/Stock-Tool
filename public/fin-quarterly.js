/* Quarterly statements on the Financials page.

   An Annual | Quarterly switch next to the statement tabs. Quarterly shows the
   last eight quarters of the income and cash-flow statements from SEC XBRL
   (/api/fundamentals/history, the same rows the growth charts use), each
   column linked to the 10-Q or 10-K that reported it. Cells carry data-raw,
   so the CSV button exports exact numbers. The quarterly balance sheet is
   not built yet; that tab says so and points back to Annual. */
(function () {
  "use strict";

  var KEY = "il-fin-period";
  var QUARTERS = 8;
  var cache = {};
  var period = "a";
  try { period = localStorage.getItem(KEY) === "q" ? "q" : "a"; } catch (e) {}

  function esc(v) { return String(v == null ? "" : v).replace(/[&<>"']/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]; }); }
  function ticker() { try { return (window.S && S.ticker) || ""; } catch (e) { return ""; } }
  function money(n) {
    if (n == null || !isFinite(n)) return "—";
    var a = Math.abs(n), s = n < 0 ? "-" : "";
    if (a >= 1e9) return s + "$" + (a / 1e9).toFixed(2) + "B";
    if (a >= 1e6) return s + "$" + (a / 1e6).toFixed(1) + "M";
    if (a >= 1e3) return s + "$" + (a / 1e3).toFixed(0) + "K";
    return s + "$" + a.toFixed(2);
  }
  function shares(n) { return n == null || !isFinite(n) ? "—" : n >= 1e9 ? (n / 1e9).toFixed(2) + "B" : (n / 1e6).toFixed(1) + "M"; }
  function pct(n) { return n == null || !isFinite(n) ? "—" : n.toFixed(1) + "%"; }
  function ratio(a, b) { return a != null && b ? (a / b) * 100 : null; }

  var INCOME = [
    { label: "Revenue", get: function (q) { return q.revenue; }, key: "revenue" },
    { label: "Revenue growth (vs a year earlier)", get: function (q, all, i) { var p = all[i - 4]; return p && p.revenue > 0 && q.revenue != null ? (q.revenue / p.revenue - 1) * 100 : null; }, fmt: pct, signed: true },
    { label: "Gross profit", get: function (q) { return q.grossProfit; }, key: "grossProfit", strong: true },
    { label: "Gross margin", get: function (q) { return ratio(q.grossProfit, q.revenue); }, fmt: pct },
    { label: "Operating income", get: function (q) { return q.operatingIncome; }, key: "operatingIncome", strong: true },
    { label: "Operating margin", get: function (q) { return ratio(q.operatingIncome, q.revenue); }, fmt: pct, signed: true },
    { label: "Net income", get: function (q) { return q.netIncome; }, key: "netIncome", strong: true },
    { label: "Net margin", get: function (q) { return ratio(q.netIncome, q.revenue); }, fmt: pct, signed: true },
    { label: "EPS (diluted)", get: function (q) { return q.eps; }, key: "eps", fmt: function (v) { return v == null ? "—" : (v < 0 ? "-$" : "$") + Math.abs(v).toFixed(2); } },
    { label: "Diluted shares", get: function (q) { return q.shares; }, key: "shares", fmt: shares }
  ];
  var CASH = [
    { label: "Operating cash flow", get: function (q) { return q.operatingCashFlow; }, key: "operatingCashFlow", strong: true },
    { label: "Capital expenditures", get: function (q) { return q.capex == null ? null : -q.capex; }, key: "capex" },
    { label: "Free cash flow", get: function (q) { return q.freeCashFlow; }, strong: true },
    { label: "Free cash flow margin", get: function (q) { return ratio(q.freeCashFlow, q.revenue); }, fmt: pct, signed: true }
  ];

  function table(rows, data, filings) {
    var all = data.quarters || [];
    var idx = all.map(function (_, i) { return i; }).slice(-QUARTERS).reverse();
    var head = '<tr><th>Item</th>' + idx.map(function (i) {
      var q = all[i], f = filings[q.end];
      return '<th><span class="il-fq-lbl">' + esc(q.label) + '</span>' +
        (f ? '<a class="il-fq-doc" href="' + esc(f.url) + '" target="_blank" rel="noopener noreferrer" title="Open the ' + esc(f.form) + ' filed ' + esc(f.filed) + '">' + esc(f.form) + '</a>' : '') + '</th>';
    }).join("") + '</tr>';
    var derivedSeen = false;
    var body = rows.map(function (r) {
      return '<tr' + (r.strong ? ' class="il-fq-strong"' : '') + '><td>' + esc(r.label) + '</td>' + idx.map(function (i) {
        var q = all[i], v = r.get(q, all, i);
        var derived = r.key && r.key !== "shares" && (q.derived || []).indexOf(r.key) >= 0;
        if (derived) derivedSeen = true;
        var cls = v != null && v < 0 && (r.signed || !r.fmt) ? "fin-negative" : "";
        return '<td' + (cls ? ' class="' + cls + '"' : '') + (v != null && isFinite(v) ? ' data-raw="' + v + '"' : '') +
          (derived ? ' title="Fourth quarter: the full year less the first nine months, as filed"' : '') + '>' +
          (r.fmt ? r.fmt(v) : money(v)) + (derived ? '<sup class="il-fq-mark">†</sup>' : '') + '</td>';
      }).join("") + '</tr>';
    }).join("");
    return '<div style="overflow-x:auto;"><table class="fin-table il-fq-table"><thead>' + head + '</thead><tbody>' + body + '</tbody></table></div>' +
      '<p class="il-fq-foot">' + (derivedSeen ? '† Companies report the full year, not the fourth quarter; that quarter is the full year less the first nine months. ' : '') +
      'From SEC XBRL filings, newest first. ' + esc(data.calendar || "") + '</p>';
  }

  function holders() {
    ["income", "balance", "cashflow"].forEach(function (name) {
      var base = document.getElementById("fin-" + name);
      if (base && !document.getElementById("fin-" + name + "-q")) {
        var d = document.createElement("div");
        d.id = "fin-" + name + "-q"; d.className = "fin-subtab"; d.style.display = "none";
        base.after(d);
      }
    });
  }

  function currentTab() {
    var b = document.querySelector(".fin-tab-btn.active");
    var m = b && /showFinTab\('(\w+)'/.exec(b.getAttribute("onclick") || "");
    return m ? m[1] : "income";
  }
  function showCurrent() {
    var name = currentTab();
    document.querySelectorAll(".fin-subtab").forEach(function (d) { d.style.display = "none"; });
    var el = document.getElementById("fin-" + name + (period === "q" ? "-q" : ""));
    if (el) el.style.display = "block";
  }

  function load(t) {
    if (!t) return;
    holders();
    var inc = document.getElementById("fin-income-q"), cf = document.getElementById("fin-cashflow-q"), bal = document.getElementById("fin-balance-q");
    if (bal) bal.innerHTML = '<div class="il-fq-empty">The quarterly balance sheet isn’t built yet. Switch to <button type="button" class="il-fq-link" data-fq-period="a">Annual</button> for the year-end balance sheet.</div>';
    if (cache[t] && cache[t].ticker === t) return paint(cache[t]);
    [inc, cf].forEach(function (el) { if (el) el.innerHTML = '<div class="il-fq-empty">Loading quarterly statements from SEC filings…</div>'; });
    fetch("/api/fundamentals/history/" + encodeURIComponent(t), { credentials: "same-origin" })
      .then(function (r) { return r.json().then(function (j) { return { ok: r.ok, j: j }; }); })
      .then(function (res) {
        if (ticker() && ticker() !== t) return;
        if (!res.ok || !res.j || !(res.j.quarters || []).length) {
          var msg = esc((res.j && res.j.error) || "Quarterly statements are not available for this company.");
          [inc, cf].forEach(function (el) { if (el) el.innerHTML = '<div class="il-fq-empty">' + msg + '</div>'; });
          return;
        }
        cache[t] = res.j;
        paint(res.j);
      })
      .catch(function () { [inc, cf].forEach(function (el) { if (el) el.innerHTML = '<div class="il-fq-empty">SEC data is temporarily unavailable. Try again shortly.</div>'; }); });
  }
  function paint(data) {
    var filings = data.filings || {};
    var inc = document.getElementById("fin-income-q"), cf = document.getElementById("fin-cashflow-q");
    if (inc) inc.innerHTML = table(INCOME, data, filings);
    if (cf) cf.innerHTML = table(CASH, data, filings);
  }

  function setPeriod(p) {
    period = p === "q" ? "q" : "a";
    try { localStorage.setItem(KEY, period); } catch (e) {}
    document.querySelectorAll(".fin-period-btn").forEach(function (b) { b.setAttribute("aria-pressed", String(b.dataset.period === period)); });
    if (period === "q") load(ticker());
    showCurrent();
  }

  function mount() {
    var bar = document.querySelector(".fin-tab-btn") && document.querySelector(".fin-tab-btn").parentElement;
    if (!bar || document.getElementById("fin-period")) return;
    holders();
    var seg = document.createElement("div");
    seg.id = "fin-period"; seg.className = "il-fq-period"; seg.setAttribute("role", "group"); seg.setAttribute("aria-label", "Statement period");
    seg.innerHTML = '<button type="button" class="fin-period-btn" data-period="a">Annual</button><button type="button" class="fin-period-btn" data-period="q">Quarterly</button>';
    bar.after(seg);
    seg.addEventListener("click", function (e) { var b = e.target.closest(".fin-period-btn"); if (b) setPeriod(b.dataset.period); });
    document.addEventListener("click", function (e) { var b = e.target.closest && e.target.closest("[data-fq-period]"); if (b) setPeriod(b.dataset.fqPeriod); });

    // Tabs keep working in either period.
    var origTab = window.showFinTab;
    if (typeof origTab === "function") {
      window.showFinTab = function (name, btn) { var out = origTab.apply(this, arguments); showCurrent(); return out; };
    }
    // A new company: annual tables reload; quarterly follows.
    var origLoad = window.loadFinancials;
    if (typeof origLoad === "function") {
      window.loadFinancials = function (t) {
        var p = origLoad.apply(this, arguments);
        Promise.resolve(p).then(function () { if (period === "q") { load(t); showCurrent(); } });
        return p;
      };
    }
    setPeriod(period);
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", mount); else mount();
  window.ILFinQuarterly = { setPeriod: setPeriod, _table: table, _rows: { income: INCOME, cash: CASH } };
})();

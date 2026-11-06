/* ═══════════════════════════════════════════════════════════════════════════
   Screener: about 280 US stocks, filtered by grade, valuation, size, growth
   and momentum. /screener[?preset=fast]

   The data is Pro (/api/screener). Free visitors see the ten highest-rated
   companies and what Pro unlocks, so the page is never empty.
   ═══════════════════════════════════════════════════════════════════════════ */
(function () {
  "use strict";
  var IL = window.IL, F = IL.fmt, h = IL.h;
  var KEYS = ["value", "growth", "profitability", "health", "momentum"];
  var KLABEL = { value: "Value", growth: "Growth", profitability: "Profitability", health: "Health", momentum: "Momentum" };
  var GRADES = ["A+", "A", "A-", "B+", "B", "B-", "C+", "C", "C-", "D+", "D", "D-", "F"];
  function rank(g) { var i = GRADES.indexOf(String(g || "").replace("−", "-")); return i < 0 ? 0 : GRADES.length - i; }

  var PRESETS = [
    { key: "quality", label: "Quality at a fair price", why: "Profitability B or better, Value C or better.", f: { minG: { profitability: "B", value: "C" } } },
    { key: "fast", label: "Fast growers", why: "Growth A− or better and revenue up 20%+.", f: { minG: { growth: "A-" }, minRev: 20 } },
    { key: "fortress", label: "Fortress balance sheet", why: "Financial health A− or better.", f: { minG: { health: "A-" } } },
    { key: "leaders", label: "Market leaders", why: "LensScore 8 or higher.", f: { minScore: 8 } },
    { key: "cheap", label: "Cheap and improving", why: "Value B or better and Momentum B or better.", f: { minG: { value: "B", momentum: "B" } } },
    { key: "beaten", label: "Beaten-down quality", why: "Profitability B+ or better, down 20%+ over the year.", f: { minG: { profitability: "B+" }, max1Y: -20 } },
    { key: "income", label: "Dividend payers", why: "Pays a dividend of 2%+ with Health C or better.", f: { minDiv: 2, minG: { health: "C" } } },
  ];
  var DEFAULT = { q: "", sector: "", minScore: 0, minG: {}, maxPE: "", minCap: "", minRev: "", max1Y: "", minDiv: "", maxBeta: "", sort: "lensScore", dir: -1 };
  var st = JSON.parse(JSON.stringify(DEFAULT)), rows = [], picked = [], preset = null;

  function applyPreset(key) {
    var p = PRESETS.filter(function (x) { return x.key === key; })[0];
    st = JSON.parse(JSON.stringify(DEFAULT));
    preset = p ? p.key : null;
    if (p) Object.keys(p.f).forEach(function (k) { st[k] = JSON.parse(JSON.stringify(p.f[k])); });
  }

  function filtered() {
    var q = st.q.trim().toUpperCase();
    return rows.filter(function (r) {
      if (q && r.ticker.indexOf(q) !== 0 && String(r.name || "").toUpperCase().indexOf(q) < 0) return false;
      if (st.sector && r.sector !== st.sector) return false;
      if (st.minScore && !(r.lensScore >= st.minScore)) return false;
      for (var k in st.minG) { if (st.minG[k] && !(r.grades && rank(r.grades[k]) >= rank(st.minG[k]))) return false; }
      if (st.maxPE !== "" && !(r.pe > 0 && r.pe <= +st.maxPE)) return false;
      if (st.minCap !== "" && !(r.marketCap >= +st.minCap)) return false;
      if (st.minRev !== "" && !(r.revenueGrowth >= +st.minRev)) return false;
      if (st.max1Y !== "" && !(r.change1Y <= +st.max1Y)) return false;
      if (st.minDiv !== "" && !(r.dividendYield >= +st.minDiv)) return false;
      if (st.maxBeta !== "" && !(r.beta <= +st.maxBeta)) return false;
      return true;
    }).sort(function (a, b) {
      var x = val(a, st.sort), y = val(b, st.sort);
      if (x === null && y === null) return 0; if (x === null) return 1; if (y === null) return -1;
      return (x < y ? -1 : x > y ? 1 : 0) * st.dir;
    });
  }
  function val(r, k) {
    if (k === "ticker") return r.ticker;
    if (KEYS.indexOf(k) >= 0) return r.grades ? rank(r.grades[k]) || null : null;
    var v = r[k];
    return typeof v === "number" && isFinite(v) ? v : null;
  }

  var COLS = [
    { k: "ticker", label: "Company", left: true },
    { k: "lensScore", label: "LensScore" },
    { k: "value", label: "Value", tip: "Value grade" }, { k: "growth", label: "Growth", tip: "Growth grade" }, { k: "profitability", label: "Profit", tip: "Profitability grade" }, { k: "health", label: "Health", tip: "Financial health grade" }, { k: "momentum", label: "Mom.", tip: "Momentum grade" },
    { k: "price", label: "Price" }, { k: "change1D", label: "Day" }, { k: "change1Y", label: "1 year" },
    { k: "revenueGrowth", label: "Rev growth" }, { k: "pe", label: "P/E" }, { k: "marketCap", label: "Mkt cap" }, { k: "dividendYield", label: "Yield" },
  ];

  function shell() {
    var main = document.getElementById("main");
    main.innerHTML =
      '<div class="sc-head hero-band card prime" id="sc-hero"><div class="stack" style="gap:10px">' + IL.eyebrow("Screener") + '<h1 class="display">Find your next <em>idea.</em></h1><p class="muted">Every company graded against its own industry. Pick a starting idea, then narrow it down.</p></div><div class="row" id="sc-actions"></div></div>' +
      '<div class="sc-presets" id="sc-presets">' + PRESETS.map(function (p) {
        return '<button type="button" class="sc-preset" data-preset="' + p.key + '" aria-pressed="false"><b>' + h(p.label) + "</b><span>" + h(p.why) + "</span></button>";
      }).join("") + "</div>" +
      '<div id="sc-body"><section class="card">' + '<span class="sk" style="height:300px"></span>' + "</section></div>";
  }

  function filtersHtml(sectors) {
    function sel(id, label, opts, cur) {
      return '<label class="field">' + label + '<select class="input" data-f="' + id + '">' + opts.map(function (o) { return '<option value="' + h(o[0]) + '"' + (String(cur) === String(o[0]) ? " selected" : "") + ">" + h(o[1]) + "</option>"; }).join("") + "</select></label>";
    }
    var gradeOpts = [["", "Any"]].concat(["A", "A-", "B+", "B", "B-", "C", "D"].map(function (g) { return [g, g + " or better"]; }));
    return '<section class="card sc-filters">' +
      '<div class="sc-frow">' +
        '<label class="field sc-q">Search<input class="input" data-f="q" value="' + h(st.q) + '" placeholder="Ticker or company" autocomplete="off"></label>' +
        sel("sector", "Sector", [["", "All sectors"]].concat(sectors.map(function (s) { return [s, s]; })), st.sector) +
        sel("minScore", "Min LensScore", [[0, "Any"], [5, "5+"], [6, "6+"], [7, "7+"], [8, "8+"], [9, "9+"]], st.minScore) +
        sel("minCap", "Size", [["", "Any size"], [2e9, "Over $2B"], [10e9, "Over $10B"], [100e9, "Over $100B"], [1e12, "Over $1T"]], st.minCap) +
      "</div>" +
      '<div class="sc-frow">' + KEYS.map(function (k) { return sel("g:" + k, KLABEL[k], gradeOpts, st.minG[k] || ""); }).join("") + "</div>" +
      '<div class="sc-frow">' +
        sel("maxPE", "Max P/E", [["", "Any"], [15, "15×"], [20, "20×"], [30, "30×"], [50, "50×"]], st.maxPE) +
        sel("minRev", "Revenue growth", [["", "Any"], [0, "Growing"], [10, "10%+"], [20, "20%+"], [40, "40%+"]], st.minRev) +
        sel("max1Y", "1-year change", [["", "Any"], [0, "Down on the year"], [-20, "Down 20%+"], [-40, "Down 40%+"]], st.max1Y) +
        sel("minDiv", "Dividend", [["", "Any"], [0.01, "Pays one"], [2, "2%+"], [4, "4%+"]], st.minDiv) +
        sel("maxBeta", "Beta", [["", "Any"], [0.8, "Under 0.8 (calm)"], [1.2, "Under 1.2"], [2, "Under 2"]], st.maxBeta) +
      "</div>" +
      '<div class="row sc-fbar"><span class="muted" id="sc-count"></span><span class="spacer"></span><button class="btn sm ghost" type="button" id="sc-reset">Reset filters</button></div>' +
    "</section>";
  }

  function paintTable() {
    var list = filtered();
    IL.$("#sc-count").textContent = list.length + " of " + rows.length + " companies";
    var tb = IL.$("#sc-tbl");
    tb.innerHTML = "<thead><tr><th></th>" + COLS.map(function (c) {
      var on = st.sort === c.k;
      return '<th class="' + (c.left ? "l" : "") + '"><button type="button" class="sc-sort' + (on ? " on" : "") + '" data-sort="' + c.k + '"' + (c.tip ? ' title="' + h(c.tip) + '"' : "") + ">" + h(c.label) + (on ? (st.dir < 0 ? " ↓" : " ↑") : "") + "</button></th>";
    }).join("") + "</tr></thead><tbody>" +
      (list.length ? list.slice(0, 300).map(function (r) {
        var g = r.grades || {}, chk = picked.indexOf(r.ticker) >= 0;
        return '<tr class="click" data-go="' + h(r.ticker) + '"><td class="sc-pick"><input type="checkbox" aria-label="Pick ' + h(r.ticker) + ' to compare" data-pick="' + h(r.ticker) + '"' + (chk ? " checked" : "") + "></td>" +
          '<td class="l"><span class="cell-co">' + IL.mono(r.ticker, r.sector, "sm") + '<span><a href="/research/' + h(r.ticker) + '"><b>' + h(r.ticker) + '</b></a><div class="faint sc-name">' + h(nice(r.name)) + " · " + h(r.sector || "") + "</div></span></span></td>" +
          "<td>" + (r.lensScore != null ? '<span class="pill score ' + IL.scoreTone(r.lensScore) + '">' + F.num(r.lensScore, 1) + "</span>" : "—") + "</td>" +
          KEYS.map(function (k) { return '<td class="sc-g">' + IL.gchip(g[k]) + "</td>"; }).join("") +
          "<td>" + F.price(r.price) + '</td><td class="' + F.cls(r.change1D) + '">' + F.spct(r.change1D) + '</td><td class="' + F.cls(r.change1Y) + '">' + F.spct(r.change1Y, 0) + "</td>" +
          '<td class="' + F.cls(r.revenueGrowth) + '">' + F.spct(r.revenueGrowth, 0) + "</td><td>" + F.mult(r.pe) + "</td><td>" + F.money(r.marketCap) + "</td><td>" + (r.dividendYield >= 0.05 ? F.pct(r.dividendYield) : r.dividendYield > 0 ? "<0.1%" : "—") + "</td></tr>";
      }).join("") : '<tr><td colspan="' + (COLS.length + 1) + '"><div class="empty">No company passes every filter. Loosen one, or reset.</div></td></tr>') +
      "</tbody>";
    paintActions();
  }
  function nice(n) { return IL.cleanName(n); }

  function paintActions() {
    var a = IL.$("#sc-actions"); if (!a) return;
    a.innerHTML = (picked.length ? '<a class="btn" href="/compare?t=' + picked.join(",") + '">Compare ' + picked.length + " picked</a>" : "") +
      '<button class="btn" type="button" id="sc-csv">Download CSV</button>';
  }

  function wire() {
    var body = IL.$("#sc-body");
    body.addEventListener("input", onFilter);
    body.addEventListener("change", onFilter);
    function onFilter(e) {
      var k = e.target.getAttribute && e.target.getAttribute("data-f");
      if (k) {
        var v = e.target.value;
        if (k.indexOf("g:") === 0) st.minG[k.slice(2)] = v;
        else if (k === "minScore") st.minScore = +v;
        else st[k] = v;
        preset = null; markPreset(); save(); paintTable(); return;
      }
      var p = e.target.getAttribute && e.target.getAttribute("data-pick");
      if (p) {
        if (e.target.checked) { if (picked.length >= 4) { e.target.checked = false; IL.toast("Compare takes up to 4 stocks"); return; } picked.push(p); }
        else picked = picked.filter(function (x) { return x !== p; });
        paintActions();
      }
    }
    document.addEventListener("click", function (e) {
      var s = e.target.closest("[data-sort]");
      if (s) { var k = s.getAttribute("data-sort"); if (st.sort === k) st.dir = -st.dir; else { st.sort = k; st.dir = k === "ticker" || k === "pe" ? 1 : -1; } save(); paintTable(); return; }
      if (e.target.closest("#sc-reset")) { applyPreset(null); save(); renderData(); return; }
      if (e.target.closest("#sc-csv")) { csv(); return; }
      var r = e.target.closest("tr[data-go]");
      if (r && !e.target.closest("a,button,input")) IL.go(r.getAttribute("data-go"));
    });
  }
  function markPreset() { IL.$$("[data-preset]").forEach(function (b) { b.setAttribute("aria-pressed", String(b.getAttribute("data-preset") === preset)); }); }
  function save() { try { localStorage.setItem("il-screener", JSON.stringify({ st: st, preset: preset })); } catch (_) {} }

  function csv() {
    if (!IL.isPro()) { location.href = "/pricing"; return; }
    var list = filtered();
    var head = ["Ticker", "Name", "Sector", "LensScore"].concat(KEYS.map(function (k) { return KLABEL[k]; }), ["Price", "Day %", "1 year %", "Revenue growth %", "P/E", "Market cap", "Dividend yield %"]);
    var lines = [head].concat(list.map(function (r) {
      var g = r.grades || {};
      return [r.ticker, r.name, r.sector, r.lensScore].concat(KEYS.map(function (k) { return g[k] || ""; }), [r.price, r.change1D, r.change1Y, r.revenueGrowth, r.pe, r.marketCap, r.dividendYield]);
    }));
    var text = lines.map(function (l) { return l.map(function (c) { c = c == null ? "" : String(c); if (/^[=+\-@]/.test(c) && isNaN(Number(c))) c = "'" + c; return /[",\n]/.test(c) ? '"' + c.replace(/"/g, '""') + '"' : c; }).join(","); }).join("\n");
    var a = document.createElement("a");
    a.href = "data:text/csv;charset=utf-8," + encodeURIComponent(text);
    a.download = "impliedlens-screener.csv"; document.body.appendChild(a); a.click(); a.remove();
  }

  function renderData() {
    var sectors = rows.map(function (r) { return r.sector; }).filter(function (s, i, a) { return s && a.indexOf(s) === i; }).sort();
    IL.$("#sc-body").innerHTML = filtersHtml(sectors) +
      '<section class="card flush"><div class="tbl-wrap"><table class="tbl sc-tbl" id="sc-tbl"></table></div></section>' +
      '<p class="note">Grades compare each company with its own sector, from SEC filings and a year of prices. Prices are daily closes. Not investment advice.</p>';
    markPreset();
    paintTable();
  }

  /* Free and guest visitors: the ten highest-rated and what Pro unlocks. */
  function renderTeaser(gate) {
    IL.$("#sc-actions").innerHTML = "";
    IL.api("/api/lens-leaders").then(function (res) {
      var top = (res.data && res.data.top) || [];
      IL.$("#sc-body").innerHTML =
        IL.gate("pro", "Filter every stock we grade with Pro", { why: "Set minimum grades, P/E, size, growth, dividends and risk, sort any column, pick stocks to compare and download the results. Pro is $7.99 a month after a 30-day free trial." }) +
        '<div class="section-h"><h2 class="section-t">The ten highest-rated right now</h2><span class="card-sub">Free for everyone</span></div>' +
        '<section class="card flush"><div class="tbl-wrap"><table class="tbl"><thead><tr><th class="l">Company</th><th>LensScore</th>' + KEYS.map(function (k) { return "<th>" + KLABEL[k].charAt(0) + "</th>"; }).join("") + "<th>Sector rank</th></tr></thead><tbody>" +
        top.map(function (r) {
          var g = r.grades || {};
          return '<tr class="click" data-go="' + h(r.ticker) + '"><td class="l"><a href="/research/' + h(r.ticker) + '"><b>' + h(r.ticker) + '</b></a><div class="faint sc-name">' + h(nice(r.name)) + "</div></td><td>" + '<span class="pill score ' + IL.scoreTone(r.score) + '">' + F.num(r.score, 1) + "</span></td>" +
            KEYS.map(function (k) { return '<td class="sc-g">' + IL.gchip(g[k]) + "</td>"; }).join("") +
            "<td>" + (r.sectorRank ? "#" + r.sectorRank + " of " + r.sectorCount + " " + h(r.sectorName || "") : h(r.sectorName || "")) + "</td></tr>";
        }).join("") + "</tbody></table></div></section>";
    });
    IL.$$("[data-preset]").forEach(function (b) { b.disabled = true; b.title = "Part of Pro"; });
  }

  function boot() {
    IL.shell("screener");
    shell();
    IL.plate(IL.$("#sc-hero"), "ledger", "right 35%");
    try { var s = JSON.parse(localStorage.getItem("il-screener") || "null"); if (s && s.st) { st = Object.assign(JSON.parse(JSON.stringify(DEFAULT)), s.st); preset = s.preset || null; } } catch (_) {}
    var qp = new URLSearchParams(location.search).get("preset");
    if (qp) applyPreset(qp);
    wire();
    IL.$("#sc-presets").addEventListener("click", function (e) {
      var b = e.target.closest("[data-preset]"); if (!b || b.disabled) return;
      var k = b.getAttribute("data-preset");
      applyPreset(preset === k ? null : k); save(); renderData();
    });
    IL.me().then(function () {
      IL.api("/api/screener").then(function (res) {
        if (res.gate) { renderTeaser(res.gate); return; }
        if (!res.ok || !Array.isArray(res.data)) { IL.$("#sc-body").innerHTML = '<div class="empty">' + h((res.data && res.data.error) || "The screener is warming up. Try again in a minute.") + "</div>"; return; }
        rows = res.data;
        renderData();
      });
    });
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot); else boot();
})();

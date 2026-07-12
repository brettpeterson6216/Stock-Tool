/* ImpliedLens — Projection Lab
   Year-by-year revenue → EPS → price projection with editable Bear/Base/Bull
   assumptions, live recalculation, auto-seeding from loaded financials,
   local save, and CSV / image export. Self-contained (injects its own CSS). */
(function () {
  "use strict";

  var SCEN = ["bear", "base", "bull"];
  var SCEN_LABEL = { bear: "Bear", base: "Base", bull: "Bull" };
  var YEAR_OPTIONS = [3, 5, 10];
  var LS_PREFIX = "il-projlab:";

  var PL = { state: null, container: null };

  /* ---------- helpers ---------- */
  function M() { return window.ImpliedLensMath; }
  function el(tag, cls, html) { var n = document.createElement(tag); if (cls) n.className = cls; if (html != null) n.innerHTML = html; return n; }
  function num(v) { var n = Number(v); return Number.isFinite(n) ? n : NaN; }
  function clamp(v, lo, hi) { return Math.max(lo, Math.min(hi, v)); }

  function fmtBig(n) {
    if (!Number.isFinite(n)) return "—";
    var neg = n < 0 ? "-" : ""; n = Math.abs(n);
    if (n >= 1e12) return neg + "$" + (n / 1e12).toFixed(2) + "T";
    if (n >= 1e9) return neg + "$" + (n / 1e9).toFixed(2) + "B";
    if (n >= 1e6) return neg + "$" + (n / 1e6).toFixed(1) + "M";
    if (n >= 1e3) return neg + "$" + (n / 1e3).toFixed(0) + "K";
    return neg + "$" + n.toFixed(0);
  }
  function fmtPrice(n) { if (!Number.isFinite(n)) return "—"; return "$" + n.toLocaleString("en-US", { maximumFractionDigits: n < 10 ? 2 : 0 }); }
  function fmtEps(n) { return Number.isFinite(n) ? "$" + n.toFixed(2) : "—"; }
  function fmtPct(x) { if (x == null || !Number.isFinite(x)) return "—"; return (x * 100).toFixed(0) + "%"; }
  function fmtShares(n) { if (!Number.isFinite(n)) return "—"; return Math.round(n).toLocaleString("en-US"); }

  /* ---------- state ---------- */
  function presetScenarios(seed) {
    var pe = Number.isFinite(seed.currentPE) && seed.currentPE > 0 ? seed.currentPE : 25;
    var g = Number.isFinite(seed.histGrowth) ? clamp(seed.histGrowth, -0.2, 1.5) : 0.15;
    var margin = Number.isFinite(seed.baseMargin) ? clamp(seed.baseMargin, -0.5, 0.6) : 0.15;
    // Whole-number percents for the input fields.
    function scn(gm, mm, plo, phi) {
      return { revGrowth: +(g * gm * 100).toFixed(1), netMargin: +(clamp(margin * mm, -0.5, 0.6) * 100).toFixed(1), peLow: Math.max(1, Math.round(pe * plo)), peHigh: Math.max(2, Math.round(pe * phi)), shareChange: 0 };
    }
    return {
      bear: scn(0.5, 0.8, 0.5, 0.75),
      base: scn(1.0, 1.0, 0.8, 1.2),
      bull: scn(1.45, 1.2, 1.1, 1.7),
    };
  }

  function expandScenario(s, years) {
    // Turn single seed values into per-year arrays (editable independently later).
    function arr(v) { var a = []; for (var i = 0; i < years; i++) a.push(v); return a; }
    return {
      revGrowth: Array.isArray(s.revGrowth) ? s.revGrowth.slice(0, years) : arr(s.revGrowth),
      netMargin: Array.isArray(s.netMargin) ? s.netMargin.slice(0, years) : arr(s.netMargin),
      peLow: Array.isArray(s.peLow) ? s.peLow.slice(0, years) : arr(s.peLow),
      peHigh: Array.isArray(s.peHigh) ? s.peHigh.slice(0, years) : arr(s.peHigh),
      shareChange: s.shareChange || 0,
    };
  }

  function defaultState(seed) {
    seed = seed || {};
    var years = YEAR_OPTIONS.indexOf(seed.years) >= 0 ? seed.years : 5;
    var presets = presetScenarios(seed);
    var scenarios = {};
    SCEN.forEach(function (k) { scenarios[k] = expandScenario(presets[k], years); });
    var baseMargin = Number.isFinite(seed.baseMargin) ? seed.baseMargin : (M() ? M().asDecimalRate(presets.base.netMargin) : 0.15);
    var baseRevenue = Number.isFinite(seed.baseRevenue) && seed.baseRevenue > 0 ? seed.baseRevenue : 1e9;
    return {
      ticker: seed.ticker || "—",
      startPrice: Number.isFinite(seed.startPrice) && seed.startPrice > 0 ? seed.startPrice : 100,
      startShares: Number.isFinite(seed.startShares) && seed.startShares > 0 ? seed.startShares : 1e9,
      baseRevenue: baseRevenue,
      baseMargin: baseMargin,
      baseYear: seed.baseYear || new Date().getFullYear(),
      years: years,
      active: "base",
      scenarios: scenarios,
      seeded: !!seed.seeded,
    };
  }

  function ensureYears(years) {
    // Re-shape per-year arrays when the horizon changes, keeping existing values.
    SCEN.forEach(function (k) {
      var s = PL.state.scenarios[k];
      ["revGrowth", "netMargin", "peLow", "peHigh"].forEach(function (f) {
        var a = s[f];
        var last = a.length ? a[a.length - 1] : 0;
        while (a.length < years) a.push(last);
        a.length = years;
      });
    });
    PL.state.years = years;
  }

  /* ---------- compute ---------- */
  function activeModel() {
    var st = PL.state, s = st.scenarios[st.active];
    return M().projectRevenueModel({
      baseYear: st.baseYear, years: st.years, startPrice: st.startPrice, startShares: st.startShares, baseRevenue: st.baseRevenue,
      revGrowth: s.revGrowth, netMargin: s.netMargin, peLow: s.peLow, peHigh: s.peHigh, shareChange: s.shareChange,
    });
  }
  function allScenarios() {
    var st = PL.state;
    return M().projectRevenueScenarios({
      baseYear: st.baseYear, years: st.years, startPrice: st.startPrice, startShares: st.startShares, baseRevenue: st.baseRevenue,
      scenarios: st.scenarios,
    });
  }

  /* ---------- render ---------- */
  var METRIC_ROWS = [
    { key: "revenue", label: "Revenue", type: "out", fmt: fmtBig },
    { key: "revGrowth", label: "Rev Growth", type: "in", suffix: "%" },
    { key: "netIncome", label: "Net Income", type: "out", fmt: fmtBig },
    { key: "netMargin", label: "Net Margin", type: "in", suffix: "%" },
    { key: "eps", label: "EPS", type: "out", fmt: fmtEps },
    { key: "peLow", label: "P/E Low", type: "in", suffix: "x" },
    { key: "peHigh", label: "P/E High", type: "in", suffix: "x" },
    { key: "priceLow", label: "Share Price Low", type: "out", fmt: fmtPrice, band: "low" },
    { key: "priceHigh", label: "Share Price High", type: "out", fmt: fmtPrice, band: "high" },
    { key: "cagrLow", label: "CAGR Low", type: "out", fmt: fmtPct, band: "low" },
    { key: "cagrHigh", label: "CAGR High", type: "out", fmt: fmtPct, band: "high" },
  ];

  function render() {
    injectCSS();
    var st = PL.state;
    var root = el("div", "plab");

    /* header */
    var head = el("div", "plab-head");
    head.innerHTML =
      '<div class="plab-title"><span class="plab-tk" id="plab-ticker">' + st.ticker + '</span>' +
      '<span class="plab-sub">Projection Lab</span></div>' +
      '<div class="plab-meta">' +
      '<label>Start price <input type="number" id="plab-price" step="0.01" min="0.01" value="' + st.startPrice + '"></label>' +
      '<label>Shares out <input type="number" id="plab-shares" step="1" min="1" value="' + Math.round(st.startShares) + '"></label>' +
      '<label>Base yr revenue <input type="number" id="plab-rev" step="1000000" min="1" value="' + Math.round(st.baseRevenue) + '"></label>' +
      '</div>';
    root.appendChild(head);

    /* controls: scenario tabs + horizon */
    var ctrl = el("div", "plab-ctrl");
    var tabs = el("div", "plab-tabs");
    SCEN.forEach(function (k) {
      var b = el("button", "plab-tab plab-tab-" + k + (st.active === k ? " active" : ""), SCEN_LABEL[k]);
      b.setAttribute("data-scen", k);
      b.onclick = function () { switchScenario(k); };
      tabs.appendChild(b);
    });
    ctrl.appendChild(tabs);
    var horiz = el("div", "plab-horizon");
    horiz.innerHTML = '<span>Horizon</span>';
    YEAR_OPTIONS.forEach(function (y) {
      var b = el("button", "plab-yr" + (st.years === y ? " active" : ""), y + "y");
      b.onclick = function () { setYears(y); };
      horiz.appendChild(b);
    });
    ctrl.appendChild(horiz);
    root.appendChild(ctrl);

    /* table */
    var wrap = el("div", "plab-table-wrap");
    var table = el("table", "plab-table");
    var years = [];
    for (var i = 1; i <= st.years; i++) years.push(st.baseYear + i);

    var thead = el("thead");
    var hr = el("tr");
    hr.appendChild(el("th", "plab-rowlbl", "Year"));
    hr.appendChild(el("th", "plab-basecol", '<span class="plab-basetag">' + st.baseYear + '</span><small>base</small>'));
    years.forEach(function (y) { hr.appendChild(el("th", null, String(y))); });
    thead.appendChild(hr);
    table.appendChild(thead);

    var tbody = el("tbody");
    METRIC_ROWS.forEach(function (row) {
      var tr = el("tr", "plab-r plab-r-" + row.key + (row.band ? " plab-band-" + row.band : ""));
      tr.appendChild(el("td", "plab-rowlbl", row.label));
      // base-year column
      tr.appendChild(el("td", "plab-basecol", baseCell(row)));
      // projected years
      for (var yi = 0; yi < st.years; yi++) {
        var td = el("td");
        if (row.type === "in") {
          var inp = el("input", "plab-cell-in");
          inp.type = "number";
          inp.value = st.scenarios[st.active][row.key][yi];
          inp.setAttribute("data-field", row.key);
          inp.setAttribute("data-yi", yi);
          inp.step = row.suffix === "x" ? "0.5" : "0.5";
          inp.oninput = onCellInput;
          var span = el("span", "plab-suffix", row.suffix || "");
          td.appendChild(inp); td.appendChild(span);
        } else {
          td.className = "plab-out";
          td.setAttribute("data-out", row.key + ":" + yi);
          td.textContent = "—";
        }
        tr.appendChild(td);
      }
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    wrap.appendChild(table);
    root.appendChild(wrap);

    /* summary */
    root.appendChild(buildSummary());

    /* actions */
    var actions = el("div", "plab-actions");
    actions.innerHTML =
      '<button class="plab-btn plab-btn-ghost" id="plab-reseed"><i class="ti ti-wand"></i> Re-seed from data</button>' +
      '<span class="plab-spacer"></span>' +
      '<button class="plab-btn plab-btn-ghost" id="plab-save"><i class="ti ti-bookmark"></i> Save</button>' +
      '<button class="plab-btn plab-btn-ghost" id="plab-csv"><i class="ti ti-table-export"></i> CSV</button>' +
      '<button class="plab-btn plab-btn-gold" id="plab-img"><i class="ti ti-photo-down"></i> Export image</button>';
    root.appendChild(actions);

    var note = el("div", "plab-note", 'Editable cells are highlighted. Growth and margins accept whole percents. Projections are educational, not investment advice.');
    root.appendChild(note);

    PL.container.innerHTML = "";
    PL.container.appendChild(root);

    // wire header inputs
    root.querySelector("#plab-price").oninput = function () { PL.state.startPrice = num(this.value) || PL.state.startPrice; recompute(); };
    root.querySelector("#plab-shares").oninput = function () { PL.state.startShares = num(this.value) || PL.state.startShares; recompute(); };
    root.querySelector("#plab-rev").oninput = function () { PL.state.baseRevenue = num(this.value) || PL.state.baseRevenue; recompute(); };
    root.querySelector("#plab-reseed").onclick = function () { seedFromApp(true); };
    root.querySelector("#plab-save").onclick = saveModel;
    root.querySelector("#plab-csv").onclick = exportCSV;
    root.querySelector("#plab-img").onclick = exportImage;

    recompute();
  }

  function baseCell(row) {
    var st = PL.state;
    var rev = st.baseRevenue, sh = st.startShares, mg = Number.isFinite(st.baseMargin) ? st.baseMargin : 0.15;
    switch (row.key) {
      case "revenue": return fmtBig(rev);
      case "netMargin": return fmtPct(mg);
      case "netIncome": return fmtBig(rev * mg);
      case "eps": return fmtEps(rev * mg / sh);
      case "priceLow": case "priceHigh": return fmtPrice(st.startPrice);
      default: return "—";
    }
  }

  function buildSummary() {
    var box = el("div", "plab-summary");
    box.id = "plab-summary";
    return box;
  }

  /* ---------- recompute (updates derived cells only, keeps focus) ---------- */
  function recompute() {
    var model = activeModel();
    var root = PL.container;
    if (!model.ok) {
      METRIC_ROWS.forEach(function (row) {
        if (row.type === "out") for (var yi = 0; yi < PL.state.years; yi++) { var c = root.querySelector('[data-out="' + row.key + ":" + yi + '"]'); if (c) c.textContent = "—"; }
      });
      var err = root.querySelector("#plab-summary");
      if (err) err.innerHTML = '<div class="plab-err">' + (model.error || "Check your assumptions.") + "</div>";
      return;
    }
    model.rows.forEach(function (r, yi) {
      setOut("revenue", yi, fmtBig(r.revenue));
      setOut("netIncome", yi, fmtBig(r.netIncome));
      setOut("eps", yi, fmtEps(r.eps));
      setOut("priceLow", yi, fmtPrice(r.priceLow));
      setOut("priceHigh", yi, fmtPrice(r.priceHigh));
      setOut("cagrLow", yi, fmtPct(r.cagrLow));
      setOut("cagrHigh", yi, fmtPct(r.cagrHigh));
    });
    renderSummary();
  }
  function setOut(key, yi, txt) { var c = PL.container.querySelector('[data-out="' + key + ":" + yi + '"]'); if (c) c.textContent = txt; }

  function renderSummary() {
    var all = allScenarios();
    var box = PL.container.querySelector("#plab-summary");
    if (!box) return;
    if (!all.ok) { box.innerHTML = '<div class="plab-err">' + (all.error || "Check assumptions.") + "</div>"; return; }
    var st = PL.state;
    var cards = SCEN.map(function (k) {
      var t = all.scenarios[k].terminal;
      return '<div class="plab-scard plab-scard-' + k + (st.active === k ? " active" : "") + '" data-scen="' + k + '">' +
        '<div class="plab-scard-h">' + SCEN_LABEL[k] + '</div>' +
        '<div class="plab-scard-px">' + fmtPrice(t.priceLow) + ' – ' + fmtPrice(t.priceHigh) + '</div>' +
        '<div class="plab-scard-cagr">' + fmtPct(t.cagrLow) + ' → ' + fmtPct(t.cagrHigh) + ' <small>CAGR</small></div>' +
        '</div>';
    }).join("");
    var exp = all.expected;
    var expHtml = '<div class="plab-exp"><div class="plab-exp-l">Expected (' + fmtPct(all.expected.weights.bear) + '/' + fmtPct(all.expected.weights.base) + '/' + fmtPct(all.expected.weights.bull) + ')</div>' +
      '<div class="plab-exp-v">' + fmtPrice(exp.price) + ' <span>' + fmtPct(exp.cagr) + ' CAGR by ' + exp.year + '</span></div></div>';
    box.innerHTML = '<div class="plab-summary-title">' + st.years + '-year outlook &middot; from ' + fmtPrice(st.startPrice) + '</div>' +
      '<div class="plab-scards">' + cards + '</div>' + expHtml;
    Array.prototype.forEach.call(box.querySelectorAll(".plab-scard"), function (c) {
      c.onclick = function () { switchScenario(c.getAttribute("data-scen")); };
    });
  }

  /* ---------- interactions ---------- */
  function onCellInput() {
    var f = this.getAttribute("data-field"), yi = +this.getAttribute("data-yi");
    PL.state.scenarios[PL.state.active][f][yi] = this.value;
    recompute();
  }
  function switchScenario(k) {
    if (PL.state.active === k) return;
    PL.state.active = k;
    // update inputs in place, tabs, then recompute
    Array.prototype.forEach.call(PL.container.querySelectorAll(".plab-tab"), function (t) { t.classList.toggle("active", t.getAttribute("data-scen") === k); });
    var s = PL.state.scenarios[k];
    Array.prototype.forEach.call(PL.container.querySelectorAll(".plab-cell-in"), function (inp) {
      var f = inp.getAttribute("data-field"), yi = +inp.getAttribute("data-yi");
      inp.value = s[f][yi];
    });
    PL.container.querySelector(".plab-table").setAttribute("data-scen", k);
    recompute();
  }
  function setYears(y) { ensureYears(y); render(); }

  /* ---------- persistence + export ---------- */
  function saveModel() {
    try {
      localStorage.setItem(LS_PREFIX + (PL.state.ticker || "GEN"), JSON.stringify(PL.state));
      toastPL("Projection saved for " + PL.state.ticker);
    } catch (e) { toastPL("Could not save (storage unavailable)"); }
  }
  function loadSaved(ticker) {
    try { var raw = localStorage.getItem(LS_PREFIX + ticker); if (raw) return JSON.parse(raw); } catch (e) {}
    return null;
  }
  function exportCSV() {
    var st = PL.state, model = activeModel();
    if (!model.ok) return;
    var years = model.rows.map(function (r) { return r.year; });
    var lines = [];
    lines.push([PL.state.ticker + " — " + SCEN_LABEL[st.active] + " case", st.baseYear].concat(years).join(","));
    lines.push(["Revenue", Math.round(st.baseRevenue)].concat(model.rows.map(function (r) { return Math.round(r.revenue); })).join(","));
    lines.push(["Rev Growth %", ""].concat(model.rows.map(function (r) { return (r.revGrowth * 100).toFixed(1); })).join(","));
    lines.push(["Net Income", ""].concat(model.rows.map(function (r) { return Math.round(r.netIncome); })).join(","));
    lines.push(["Net Margin %", ""].concat(model.rows.map(function (r) { return (r.netMargin * 100).toFixed(1); })).join(","));
    lines.push(["EPS", ""].concat(model.rows.map(function (r) { return r.eps.toFixed(2); })).join(","));
    lines.push(["P/E Low", ""].concat(model.rows.map(function (r) { return r.peLow; })).join(","));
    lines.push(["P/E High", ""].concat(model.rows.map(function (r) { return r.peHigh; })).join(","));
    lines.push(["Share Price Low", st.startPrice.toFixed(2)].concat(model.rows.map(function (r) { return r.priceLow.toFixed(2); })).join(","));
    lines.push(["Share Price High", st.startPrice.toFixed(2)].concat(model.rows.map(function (r) { return r.priceHigh.toFixed(2); })).join(","));
    lines.push(["CAGR Low %", ""].concat(model.rows.map(function (r) { return r.cagrLow == null ? "" : (r.cagrLow * 100).toFixed(1); })).join(","));
    lines.push(["CAGR High %", ""].concat(model.rows.map(function (r) { return r.cagrHigh == null ? "" : (r.cagrHigh * 100).toFixed(1); })).join(","));
    downloadBlob(lines.join("\n"), "text/csv", (PL.state.ticker || "projection") + "_" + st.active + ".csv");
  }
  function downloadBlob(text, mime, filename) {
    var blob = new Blob([text], { type: mime });
    var url = URL.createObjectURL(blob);
    var a = document.createElement("a"); a.href = url; a.download = filename; document.body.appendChild(a); a.click();
    setTimeout(function () { document.body.removeChild(a); URL.revokeObjectURL(url); }, 100);
  }

  /* image export — draws an on-brand summary card to a canvas */
  function exportImage() {
    var all = allScenarios();
    if (!all.ok) { toastPL("Fix assumptions before exporting."); return; }
    var st = PL.state;
    var W = 1000, H = 560, sc = 2;
    var cv = document.createElement("canvas"); cv.width = W * sc; cv.height = H * sc;
    var g = cv.getContext("2d"); g.scale(sc, sc);
    // bg
    var grad = g.createLinearGradient(0, 0, W, H);
    grad.addColorStop(0, "#14181d"); grad.addColorStop(1, "#0a0c0f");
    g.fillStyle = grad; g.fillRect(0, 0, W, H);
    g.fillStyle = "#d9b35e"; g.font = "700 15px DM Sans, Arial"; g.fillText("IMPLIED LENS · PROJECTION LAB", 40, 50);
    g.fillStyle = "#f5ebd7"; g.font = "800 46px Space Grotesk, DM Sans, Arial"; g.fillText(st.ticker, 40, 108);
    g.fillStyle = "rgba(245,235,215,.72)"; g.font = "500 16px DM Sans, Arial";
    g.fillText("Start " + fmtPrice(st.startPrice) + "   ·   " + st.years + "-year outlook to " + (st.baseYear + st.years), 40, 138);
    // scenario columns
    var x0 = 40, colW = (W - 80) / 3, y0 = 190;
    SCEN.forEach(function (k, i) {
      var t = all.scenarios[k].terminal;
      var x = x0 + i * colW;
      g.fillStyle = k === "bear" ? "rgba(169,79,85,.16)" : k === "bull" ? "rgba(36,119,87,.16)" : "rgba(217,179,94,.16)";
      roundRect(g, x, y0, colW - 16, 250, 14); g.fill();
      g.fillStyle = k === "bear" ? "#e08a8f" : k === "bull" ? "#4fd39a" : "#e9c877";
      g.font = "700 18px DM Sans, Arial"; g.fillText(SCEN_LABEL[k] + " case", x + 22, y0 + 40);
      g.fillStyle = "#f5ebd7"; g.font = "800 30px Space Grotesk, DM Sans, Arial";
      g.fillText(fmtPrice(t.priceLow) + "–" + fmtPrice(t.priceHigh), x + 22, y0 + 92);
      g.fillStyle = "rgba(245,235,215,.6)"; g.font = "500 14px DM Sans, Arial"; g.fillText("Target price " + (st.baseYear + st.years), x + 22, y0 + 118);
      g.fillStyle = "#f5ebd7"; g.font = "700 22px DM Sans, Arial";
      g.fillText(fmtPct(t.cagrLow) + " → " + fmtPct(t.cagrHigh), x + 22, y0 + 168);
      g.fillStyle = "rgba(245,235,215,.6)"; g.font = "500 14px DM Sans, Arial"; g.fillText("Annualized return (CAGR)", x + 22, y0 + 192);
    });
    g.fillStyle = "rgba(245,235,215,.5)"; g.font = "500 13px DM Sans, Arial";
    g.fillText("Educational model · not investment advice · impliedlens.com", 40, H - 28);
    cv.toBlob(function (blob) {
      var url = URL.createObjectURL(blob);
      var a = document.createElement("a"); a.href = url; a.download = (st.ticker || "projection") + "_projection.png";
      document.body.appendChild(a); a.click(); setTimeout(function () { document.body.removeChild(a); URL.revokeObjectURL(url); }, 100);
    });
  }
  function roundRect(g, x, y, w, h, r) { g.beginPath(); g.moveTo(x + r, y); g.arcTo(x + w, y, x + w, y + h, r); g.arcTo(x + w, y + h, x, y + h, r); g.arcTo(x, y + h, x, y, r); g.arcTo(x, y, x + w, y, r); g.closePath(); }

  function toastPL(msg) { if (typeof window.toast === "function") { window.toast(msg); return; } var t = el("div", "plab-toast", msg); document.body.appendChild(t); setTimeout(function () { t.classList.add("show"); }, 10); setTimeout(function () { t.remove(); }, 2600); }

  /* ---------- seeding from the app ---------- */
  function rawNum(v) { if (v == null) return NaN; if (typeof v === "number") return v; if (typeof v === "object" && v.raw != null) return Number(v.raw); return Number(v); }

  function readSeedFromApp() {
    var S = window.S || {};
    var meta = (S.data && S.data.meta) || {};
    var seed = { ticker: S.ticker || meta.symbol || "—", seeded: false };
    var price = rawNum(meta.regularMarketPrice);
    if (Number.isFinite(price) && price > 0) seed.startPrice = price;
    var pe = rawNum(meta.trailingPE);
    if (Number.isFinite(pe) && pe > 0) seed.currentPE = pe;
    // financials raw (cached by loadFinancials when available)
    var r = window.S && S.financialsRaw;
    if (r) {
      var inc = (r.incomeStatementHistory && r.incomeStatementHistory.incomeStatementHistory) || [];
      var ks = r.defaultKeyStatistics || {};
      if (inc.length) {
        var rev0 = rawNum(inc[0].totalRevenue);
        var ni0 = rawNum(inc[0].netIncome);
        if (Number.isFinite(rev0) && rev0 > 0) { seed.baseRevenue = rev0; seed.seeded = true; }
        if (Number.isFinite(ni0) && Number.isFinite(rev0) && rev0 > 0) seed.baseMargin = ni0 / rev0;
        if (inc.length > 1) {
          var rev1 = rawNum(inc[1].totalRevenue);
          if (Number.isFinite(rev1) && rev1 > 0 && Number.isFinite(rev0)) seed.histGrowth = rev0 / rev1 - 1;
        }
      }
      var sh = rawNum(ks.sharesOutstanding);
      if (Number.isFinite(sh) && sh > 0) seed.startShares = sh;
    }
    if (!Number.isFinite(seed.startShares) && Number.isFinite(rawNum(meta.marketCap)) && Number.isFinite(seed.startPrice)) {
      seed.startShares = rawNum(meta.marketCap) / seed.startPrice;
    }
    seed.baseYear = new Date().getFullYear();
    return seed;
  }

  function applySeed(seed, force) {
    // Preserve horizon + saved edits unless forced.
    var years = PL.state ? PL.state.years : 5;
    seed.years = years;
    if (!force) {
      var saved = loadSaved(seed.ticker);
      if (saved && saved.scenarios) { PL.state = saved; PL.state.ticker = seed.ticker; render(); return; }
    }
    PL.state = defaultState(seed);
    render();
  }

  function seedFromApp(force) {
    var seed = readSeedFromApp();
    // If financials not yet loaded, try to load them then re-seed.
    if (!seed.seeded && window.S && window.S.ticker && typeof window.loadFinancials === "function" && !window._plabLoadingFin) {
      window._plabLoadingFin = true;
      applySeed(seed, force); // seed with what we have now (price/PE)
      Promise.resolve(window.loadFinancials(window.S.ticker)).then(function () {
        window._plabLoadingFin = false;
        var s2 = readSeedFromApp();
        if (s2.seeded) applySeed(s2, true);
      }).catch(function () { window._plabLoadingFin = false; });
      return;
    }
    applySeed(seed, force);
  }

  /* ---------- mount ---------- */
  function mount(container, seed) {
    PL.container = typeof container === "string" ? document.getElementById(container) : container;
    if (!PL.container) return;
    if (!M() || typeof M().projectRevenueModel !== "function") {
      PL.container.innerHTML = '<div style="color:#e0a6a9;font:600 .85rem sans-serif;padding:1rem;">Projection engine unavailable. Please reload.</div>';
      return;
    }
    try {
      if (seed) { PL.state = defaultState(seed); render(); }
      else if (window.S && window.S.ticker) { seedFromApp(false); }
      else { PL.state = defaultState({}); render(); }
    } catch (e) {
      if (window.console) console.error("ProjectionLab mount error", e);
      PL.container.innerHTML = '<div style="color:#e0a6a9;font:600 .85rem sans-serif;padding:1rem;">Could not build the projection. ' + (e && e.message ? e.message : "") + '</div>';
    }
  }

  window.ProjectionLab = { mount: mount, seedFromApp: seedFromApp, render: render, _state: function () { return PL.state; } };

  /* ---------- styles ---------- */
  function injectCSS() {
    if (document.getElementById("plab-css")) return;
    var css =
      ".plab{--plab-line:rgba(230,188,99,.16);--plab-in:rgba(217,179,94,.09);color:var(--lens-text,#f5ebd7);font-family:var(--sans,'DM Sans',Arial);}" +
      ".plab-head{display:flex;flex-wrap:wrap;justify-content:space-between;align-items:flex-end;gap:14px;margin-bottom:14px;}" +
      ".plab-title{display:flex;align-items:baseline;gap:10px;}" +
      ".plab-tk{font:800 1.9rem/1 var(--serif,'Space Grotesk',DM Sans);color:var(--lens-gold,#d9b35e);letter-spacing:.01em;}" +
      ".plab-sub{font:600 .72rem var(--sans);letter-spacing:.14em;text-transform:uppercase;color:rgba(245,235,215,.5);}" +
      ".plab-meta{display:flex;flex-wrap:wrap;gap:10px;}" +
      ".plab-meta label{display:flex;flex-direction:column;gap:3px;font:600 .58rem var(--sans);letter-spacing:.08em;text-transform:uppercase;color:rgba(245,235,215,.55);}" +
      ".plab-meta input{width:130px;background:#0c0e10;border:1px solid var(--plab-line);border-radius:7px;color:var(--lens-text,#f5ebd7);font:700 .82rem var(--sans);padding:.4rem .5rem;}" +
      ".plab-ctrl{display:flex;flex-wrap:wrap;justify-content:space-between;gap:12px;margin-bottom:12px;}" +
      ".plab-tabs{display:inline-flex;background:#0c0e10;border:1px solid var(--plab-line);border-radius:10px;padding:3px;gap:3px;}" +
      ".plab-tab{border:0;background:transparent;color:rgba(245,235,215,.66);font:700 .8rem var(--sans);padding:.45rem 1.1rem;border-radius:8px;cursor:pointer;transition:.14s;}" +
      ".plab-tab.active{color:#17130c;}" +
      ".plab-tab-bear.active{background:#c76b70;color:#fff;}.plab-tab-base.active{background:var(--lens-gold,#d9b35e);}.plab-tab-bull.active{background:#2f9c6a;color:#fff;}" +
      ".plab-horizon{display:inline-flex;align-items:center;gap:6px;font:600 .62rem var(--sans);letter-spacing:.1em;text-transform:uppercase;color:rgba(245,235,215,.5);}" +
      ".plab-yr{border:1px solid var(--plab-line);background:#0c0e10;color:rgba(245,235,215,.7);border-radius:7px;padding:.35rem .6rem;font:700 .74rem var(--sans);cursor:pointer;}" +
      ".plab-yr.active{background:var(--lens-gold,#d9b35e);color:#17130c;border-color:var(--lens-gold,#d9b35e);}" +
      ".plab-table-wrap{overflow-x:auto;-webkit-overflow-scrolling:touch;border:1px solid var(--plab-line);border-radius:12px;background:#0d0f12;}" +
      ".plab-table{border-collapse:collapse;width:100%;min-width:max-content;font-variant-numeric:tabular-nums;}" +
      ".plab-table th,.plab-table td{padding:.5rem .7rem;text-align:right;white-space:nowrap;border-bottom:1px solid rgba(230,188,99,.08);}" +
      ".plab-table thead th{position:sticky;top:0;background:#12151a;font:700 .72rem var(--sans);color:var(--lens-gold,#d9b35e);border-bottom:1px solid var(--plab-line);}" +
      ".plab-rowlbl{text-align:left!important;font:600 .68rem var(--sans);letter-spacing:.06em;text-transform:uppercase;color:rgba(245,235,215,.62);position:sticky;left:0;background:#0c0e10;z-index:1;}" +
      ".plab-table thead .plab-rowlbl{background:#12151a;z-index:2;}" +
      ".plab-basecol{background:rgba(255,255,255,.02);color:rgba(245,235,215,.6);}" +
      ".plab-basetag{font-weight:800;color:rgba(245,235,215,.85);}.plab-basecol small{display:block;font-size:.56rem;letter-spacing:.1em;text-transform:uppercase;opacity:.6;}" +
      ".plab-r-revenue td,.plab-r-eps td{font-weight:700;}" +
      ".plab-r-priceLow,.plab-r-priceHigh{background:rgba(217,179,94,.05);}" +
      ".plab-out{color:var(--lens-text,#f5ebd7);}" +
      ".plab-band-low .plab-out{color:#e0a6a9;}.plab-band-high .plab-out{color:#7fd3a6;}" +
      ".plab-r-cagrLow .plab-out,.plab-r-cagrHigh .plab-out{font-weight:800;}" +
      ".plab-cell-in{width:62px;background:var(--plab-in);border:1px solid var(--plab-line);border-radius:6px;color:var(--lens-text,#f5ebd7);font:700 .8rem var(--sans);padding:.3rem .1rem;text-align:right;}" +
      ".plab-cell-in:focus{outline:0;border-color:var(--lens-gold,#d9b35e);box-shadow:0 0 0 2px rgba(217,179,94,.2);}" +
      ".plab-suffix{font:600 .62rem var(--sans);color:rgba(245,235,215,.4);margin-left:2px;}" +
      ".plab-summary{margin-top:16px;}" +
      ".plab-summary-title{font:600 .66rem var(--sans);letter-spacing:.1em;text-transform:uppercase;color:rgba(245,235,215,.5);margin-bottom:8px;}" +
      ".plab-scards{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;}" +
      ".plab-scard{border:1px solid var(--plab-line);border-radius:12px;padding:.8rem .9rem;cursor:pointer;transition:.14s;background:#0c0e10;}" +
      ".plab-scard.active{border-color:var(--lens-gold,#d9b35e);box-shadow:0 0 0 1px var(--lens-gold,#d9b35e) inset;}" +
      ".plab-scard-h{font:700 .74rem var(--sans);letter-spacing:.04em;margin-bottom:6px;}" +
      ".plab-scard-bear .plab-scard-h{color:#e08a8f;}.plab-scard-base .plab-scard-h{color:#e9c877;}.plab-scard-bull .plab-scard-h{color:#4fd39a;}" +
      ".plab-scard-px{font:800 1.15rem var(--serif,'Space Grotesk',DM Sans);color:var(--lens-text,#f5ebd7);}" +
      ".plab-scard-cagr{font:700 .8rem var(--sans);color:rgba(245,235,215,.75);margin-top:3px;}.plab-scard-cagr small{font-weight:600;opacity:.5;}" +
      ".plab-exp{display:flex;justify-content:space-between;align-items:center;margin-top:10px;padding:.7rem .9rem;border:1px dashed var(--plab-line);border-radius:10px;}" +
      ".plab-exp-l{font:600 .64rem var(--sans);letter-spacing:.06em;text-transform:uppercase;color:rgba(245,235,215,.55);}" +
      ".plab-exp-v{font:800 1.1rem var(--serif,'Space Grotesk',DM Sans);color:var(--lens-gold,#d9b35e);}.plab-exp-v span{font:600 .72rem var(--sans);color:rgba(245,235,215,.6);margin-left:6px;}" +
      ".plab-actions{display:flex;flex-wrap:wrap;align-items:center;gap:8px;margin-top:16px;}.plab-spacer{flex:1;}" +
      ".plab-btn{display:inline-flex;align-items:center;gap:6px;border:1px solid var(--plab-line);background:#0c0e10;color:var(--lens-text,#f5ebd7);font:700 .76rem var(--sans);padding:.5rem .9rem;border-radius:8px;cursor:pointer;}" +
      ".plab-btn-gold{background:var(--lens-gold,#d9b35e);color:#17130c;border-color:var(--lens-gold,#d9b35e);}" +
      ".plab-btn:hover{border-color:var(--lens-gold,#d9b35e);}" +
      ".plab-note{margin-top:10px;font:500 .66rem var(--sans);color:rgba(245,235,215,.4);line-height:1.5;}" +
      ".plab-err{padding:.8rem;border:1px solid rgba(201,107,112,.4);background:rgba(201,107,112,.08);border-radius:10px;color:#e0a6a9;font:600 .8rem var(--sans);}" +
      ".plab-toast{position:fixed;left:50%;bottom:80px;transform:translateX(-50%) translateY(10px);background:#12151a;color:#f5ebd7;border:1px solid var(--plab-line);padding:.6rem 1rem;border-radius:10px;font:600 .8rem var(--sans);opacity:0;transition:.2s;z-index:99999;}.plab-toast.show{opacity:1;transform:translateX(-50%) translateY(0);}" +
      "html:not([data-theme='dark']) .plab-meta input,html:not([data-theme='dark']) .plab-yr,html:not([data-theme='dark']) .plab-tabs,html:not([data-theme='dark']) .plab-scard,html:not([data-theme='dark']) .plab-btn,html:not([data-theme='dark']) .plab-rowlbl{background:#12151a;}";
    var s = el("style"); s.id = "plab-css"; s.textContent = css; document.head.appendChild(s);
  }
})();

/* ImpliedLens — Projection Lab (v2)
   Year-by-year revenue → net income → EPS → price projection with independent
   Bear / Base / Bull scenarios, probability-weighted expected value, live
   recalculation, save, CSV, and image export.

   Architecture: ONE canonical model (window.ImpliedLensMath.plCreateModel shape)
   is the single source of truth. Every component — inputs, table, chart,
   outcome summary, scenario cards, expected value, save, CSV, image export —
   derives from plCalculateProjection / plCalculateOutlook on that model.
   Nothing reads cached seed data or keeps its own copy of a number. */
(function () {
  "use strict";

  var SCEN = ["bear", "base", "bull"];
  var SCEN_LABEL = { bear: "Bear", base: "Base", bull: "Bull" };
  var SCEN_DESC = {
    bear: "Growth slows and the market pays a lower multiple.",
    base: "Management trajectory with normalized multiples.",
    bull: "Sustained growth and operating leverage re-rate the stock.",
  };
  var LS_PREFIX_V2 = "il-projlab:v2:";
  var LS_PREFIX_V1 = "il-projlab:";

  var PL = {
    model: null,          // canonical model — the only financial state
    container: null,
    savedJson: null,      // snapshot of the last saved model (unsaved-change detection)
    lastOutlook: null,    // last successful plCalculateOutlook result
    loadingSeed: false,
    seedHintShown: false,
  };

  /* ───────────────────────── helpers ───────────────────────── */
  function M() { return window.ImpliedLensMath; }
  function el(tag, cls, html) { var n = document.createElement(tag); if (cls) n.className = cls; if (html != null) n.innerHTML = html; return n; }
  function esc(s) { return String(s == null ? "" : s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;"); }
  function q(sel) { return PL.container ? PL.container.querySelector(sel) : null; }
  function qa(sel) { return PL.container ? Array.prototype.slice.call(PL.container.querySelectorAll(sel)) : []; }

  function curSym() { var c = PL.model && PL.model.currency; return (!c || c === "USD") ? "$" : c + " "; }
  function fmtBig(n) {
    if (!Number.isFinite(n)) return "—";
    var neg = n < 0 ? "−" : ""; n = Math.abs(n);
    var s = curSym();
    if (n >= 1e12) return neg + s + (n / 1e12).toFixed(2) + "T";
    if (n >= 1e9) return neg + s + (n / 1e9).toFixed(2) + "B";
    if (n >= 1e6) return neg + s + (n / 1e6).toFixed(1) + "M";
    if (n >= 1e3) return neg + s + (n / 1e3).toFixed(0) + "K";
    return neg + s + n.toFixed(0);
  }
  function fmtPrice(n) { if (!Number.isFinite(n)) return "—"; return curSym() + n.toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 }); }
  function fmtEps(n) { return Number.isFinite(n) ? curSym() + n.toFixed(2) : "—"; }
  function fmtPct0(x) { return Number.isFinite(x) ? Math.round(x * 100) + "%" : "—"; }
  function fmtPct1(x) { return Number.isFinite(x) ? (x * 100).toFixed(1) + "%" : "—"; }
  function fmtPctSigned(x) { if (!Number.isFinite(x)) return "—"; var v = Math.round(x * 100); return (v > 0 ? "+" : "") + v + "%"; }
  function fmtSharesCompact(n) {
    if (!Number.isFinite(n)) return "—";
    if (n >= 1e9) return (n / 1e9).toFixed(3).replace(/\.?0+$/, "") + "B";
    if (n >= 1e6) return (n / 1e6).toFixed(1).replace(/\.0$/, "") + "M";
    return Math.round(n).toLocaleString("en-US");
  }
  function fmtExact(n) { return Number.isFinite(n) ? Math.round(n).toLocaleString("en-US") : "—"; }
  function fmtTimeAgo(iso) {
    var t = Date.parse(iso); if (!Number.isFinite(t)) return "";
    var mins = Math.max(0, Math.round((Date.now() - t) / 60000));
    if (mins < 1) return "just now";
    if (mins < 60) return mins + "m ago";
    if (mins < 1440) return Math.round(mins / 60) + "h ago";
    return Math.round(mins / 1440) + "d ago";
  }

  /* ─────────────────── model helpers (mutations funnel here) ─────────────────── */
  function touch() { PL.model.lastUpdated = new Date().toISOString(); }
  function setBaseField(key, value) { PL.model[key] = value; PL.model.userEdited[key] = true; touch(); }
  function resetBaseField(key) {
    var seedVals = PL.model.seed && PL.model.seed.values;
    if (!seedVals || !Number.isFinite(Number(seedVals[key]))) return false;
    PL.model[key] = Number(seedVals[key]);
    delete PL.model.userEdited[key];
    touch();
    return true;
  }
  function isUserModified() {
    return PL.model && (Object.keys(PL.model.userEdited || {}).length > 0 || PL.model.userEditedScenarios);
  }
  function hasUnsavedChanges() { return PL.model && JSON.stringify(PL.model) !== PL.savedJson; }

  /* ───────────────────────── field definitions ───────────────────────── */
  var FIELDS = [
    {
      key: "startPrice", label: "Starting share price", icon: "ti-tag",
      tip: "Today’s share price — the baseline every CAGR and upside figure is measured against. It does not change the company’s projected financials.",
      display: function (v) { return fmtPrice(v); },
      raw: function (v) { return String(v); },
      validate: function (n) { return Number.isFinite(n) && n > 0 ? null : "Must be above zero."; },
    },
    {
      key: "dilutedShares", label: "Diluted shares", icon: "ti-users",
      tip: "Fully diluted share count used to turn projected net income into EPS. Held constant across projected years (annual dilution assumptions can layer on later). Accepts 1.356B, 1355.98M, or the full number.",
      display: function (v) { return fmtSharesCompact(v); },
      title: function (v) { return fmtExact(v) + " shares"; },
      raw: function (v) { return String(Math.round(v)); },
      validate: function (n) { return Number.isFinite(n) && n > 0 ? null : "Share count must be above zero."; },
    },
    {
      key: "baseRevenue", label: "Base-year revenue", icon: "ti-chart-bar",
      tip: "Total revenue for the base year — the anchor every projected year compounds from. Accepts 4.655B, 4655M, or the full number.",
      display: function (v) { return fmtBig(v); },
      title: function (v) { return curSym() + fmtExact(v); },
      raw: function (v) { return String(Math.round(v)); },
      validate: function (n) { return Number.isFinite(n) && n > 0 ? null : "Revenue must be above zero."; },
    },
    {
      key: "baseNetIncome", label: "Base-year net income", icon: "ti-report-money",
      tip: "Net income for the base year. Sets the base net margin and base EPS shown in the table. Negative values are allowed. Accepts 825M, 0.825B, or the full number.",
      display: function (v) { return fmtBig(v); },
      title: function (v) { return curSym() + fmtExact(v); },
      raw: function (v) { return String(Math.round(v)); },
      validate: function (n) { return Number.isFinite(n) ? null : "Enter a number (negative is allowed)."; },
    },
  ];

  var ROW_TIPS = {
    revGrowth: "Year-over-year revenue growth. 30 means +30% vs the prior year.",
    netMargin: "Net income as a percent of that year’s revenue. 18.5 means 18.5%.",
    peLow: "Conservative price-to-earnings multiple applied to that year’s EPS.",
    peHigh: "Optimistic price-to-earnings multiple applied to that year’s EPS.",
    cagr: "Compound annual growth rate from the starting share price to that year’s modeled price.",
  };

  /* ───────────────────────── table row definitions ───────────────────────── */
  var TABLE_SECTIONS = [
    {
      label: "Operating forecast",
      rows: [
        { key: "revenue", label: "Revenue", type: "out", fmt: function (r) { return fmtBig(r.revenue); }, base: function (b) { return fmtBig(b.revenue); } },
        { key: "revGrowth", label: "Revenue growth", type: "in", suffix: "%", tip: ROW_TIPS.revGrowth },
        { key: "netIncome", label: "Net income", type: "out", fmt: function (r) { return fmtBig(r.netIncome); }, base: function (b) { return fmtBig(b.netIncome); } },
        { key: "netMargin", label: "Net margin", type: "in", suffix: "%", tip: ROW_TIPS.netMargin, baseOut: function (b) { return fmtPct1(b.netMargin); } },
        { key: "eps", label: "EPS", type: "out", fmt: function (r) { return fmtEps(r.eps); }, base: function (b) { return fmtEps(b.eps); } },
      ],
    },
    {
      label: "Valuation",
      rows: [
        { key: "peLow", label: "P/E low", type: "in", suffix: "×", tip: ROW_TIPS.peLow },
        { key: "peHigh", label: "P/E high", type: "in", suffix: "×", tip: ROW_TIPS.peHigh },
        { key: "priceLow", label: "Share price low", type: "out", band: "low", fmt: function (r) { return r.priceLow == null ? "n/m" : fmtPrice(r.priceLow); }, base: function (b) { return fmtPrice(b.price); } },
        { key: "priceHigh", label: "Share price high", type: "out", band: "high", fmt: function (r) { return r.priceHigh == null ? "n/m" : fmtPrice(r.priceHigh); }, base: function (b) { return fmtPrice(b.price); } },
      ],
    },
    {
      label: "Returns",
      rows: [
        { key: "cagrLow", label: "CAGR low", type: "out", band: "low", tip: ROW_TIPS.cagr, fmt: function (r) { return r.cagrLow == null ? "n/m" : fmtPct0(r.cagrLow); }, base: function () { return "—"; } },
        { key: "cagrHigh", label: "CAGR high", type: "out", band: "high", tip: ROW_TIPS.cagr, fmt: function (r) { return r.cagrHigh == null ? "n/m" : fmtPct0(r.cagrHigh); }, base: function () { return "—"; } },
      ],
    },
  ];

  /* ═══════════════════════════ RENDER ═══════════════════════════ */
  function render() {
    injectCSS();
    if (!PL.container) return;
    var m = PL.model;
    var horizons = M().PL_HORIZONS;
    var root = el("div", "plab2");
    root.setAttribute("data-scen", m.selectedScenario);

    /* ── 1 · identity + status ── */
    var head = el("div", "plab2-head");
    head.innerHTML =
      '<div class="plab2-id">' +
        '<div class="plab2-id-row"><span class="plab2-tk">' + esc(m.ticker) + '</span><span class="plab2-kicker">Projection Lab</span></div>' +
        (m.companyName ? '<div class="plab2-co">' + esc(m.companyName) + '</div>' : "") +
      '</div>' +
      '<div class="plab2-status" id="plab2-status" aria-live="polite"></div>';
    root.appendChild(head);

    var how = el("details", "plab2-how");
    how.innerHTML =
      '<summary>How this model works</summary>' +
      '<div class="plab2-how-body">Each year compounds revenue by your growth assumption, applies your net margin to get net income, divides by diluted shares for EPS, and multiplies EPS by your P/E low–high range for a share-price band. CAGR annualizes each band edge against the starting price. Bear, Base, and Bull are fully independent; the probability-weighted outlook blends their midpoints. This is an educational model output — not a price target or investment advice.</div>';
    root.appendChild(how);

    /* ── 2 · Model Foundation + Key outcome ── */
    var top = el("div", "plab2-top");
    var found = el("section", "plab2-found");
    found.setAttribute("aria-label", "Model Foundation inputs");
    var fh = el("div", "plab2-panel-h", '<span>Model Foundation</span><span class="plab2-panel-sub">Base year FY' + esc(m.baseYear) + '</span>');
    found.appendChild(fh);
    var grid = el("div", "plab2-fgrid");
    FIELDS.forEach(function (f) {
      var wrap = el("div", "plab2-field");
      var edited = !!m.userEdited[f.key];
      wrap.innerHTML =
        '<div class="plab2-flabel-row">' +
          '<label class="plab2-flabel" for="plab2-f-' + f.key + '">' + esc(f.label) + '</label>' +
          '<span class="plab2-ftip" tabindex="0" role="note" aria-label="' + esc(f.tip) + '" data-tip="' + esc(f.tip) + '"><i class="ti ti-info-circle" aria-hidden="true"></i></span>' +
        '</div>' +
        '<div class="plab2-fbox' + (edited ? " edited" : "") + '">' +
          '<input id="plab2-f-' + f.key + '" type="text" inputmode="decimal" autocomplete="off" spellcheck="false" data-fkey="' + f.key + '">' +
          '<button type="button" class="plab2-freset" data-fkey="' + f.key + '" aria-label="Reset ' + esc(f.label) + ' to seeded value" title="Reset to seeded value"' + (edited ? "" : " hidden") + '><i class="ti ti-restore" aria-hidden="true"></i></button>' +
        '</div>' +
        '<div class="plab2-fmeta"><span class="plab2-fstate" data-fstate="' + f.key + '">' + (edited ? "Edited" : "Seeded") + '</span><span class="plab2-ferr" data-ferr="' + f.key + '" role="alert"></span></div>';
      grid.appendChild(wrap);
    });
    found.appendChild(grid);
    found.appendChild(el("div", "plab2-derived", "")); // filled in recompute
    root.appendChild(top);
    top.appendChild(found);

    var outcome = el("section", "plab2-outcome");
    outcome.id = "plab2-outcome";
    outcome.setAttribute("aria-label", "Forecast summary for the selected scenario and horizon");
    top.appendChild(outcome);

    /* ── 3 · scenario + horizon controls ── */
    var ctrl = el("div", "plab2-ctrl");
    var tabs = el("div", "plab2-tabs");
    tabs.setAttribute("role", "group");
    tabs.setAttribute("aria-label", "Scenario");
    SCEN.forEach(function (k) {
      var b = el("button", "plab2-tab plab2-tab-" + k + (m.selectedScenario === k ? " active" : ""), '<span class="plab2-tab-dot" aria-hidden="true"></span>' + SCEN_LABEL[k]);
      b.type = "button";
      b.setAttribute("data-scen", k);
      b.setAttribute("aria-pressed", m.selectedScenario === k ? "true" : "false");
      b.onclick = function () { selectScenario(k); };
      tabs.appendChild(b);
    });
    ctrl.appendChild(tabs);
    ctrl.appendChild(el("div", "plab2-scen-desc", esc(SCEN_DESC[m.selectedScenario])));
    var horiz = el("div", "plab2-horizon");
    horiz.setAttribute("role", "group");
    horiz.setAttribute("aria-label", "Projection horizon");
    horiz.innerHTML = "<span>Horizon</span>";
    horizons.forEach(function (y) {
      var b = el("button", "plab2-yr" + (m.selectedHorizon === y ? " active" : ""), y + "y");
      b.type = "button";
      b.setAttribute("aria-pressed", m.selectedHorizon === y ? "true" : "false");
      b.onclick = function () { if (m.selectedHorizon !== y) { m.selectedHorizon = y; touch(); render(); } };
      horiz.appendChild(b);
    });
    ctrl.appendChild(horiz);
    root.appendChild(ctrl);

    /* error banner (validation) */
    var errBox = el("div", "plab2-error");
    errBox.id = "plab2-error";
    errBox.setAttribute("role", "alert");
    errBox.hidden = true;
    root.appendChild(errBox);

    /* ── 4 · chart ── */
    var chart = el("div", "plab2-chart");
    chart.id = "plab2-chart";
    root.appendChild(chart);

    /* ── 5 · table ── */
    root.appendChild(buildTable());

    /* ── 6 · scenario comparison + expected value ── */
    var cmp = el("div", "plab2-cmp");
    cmp.id = "plab2-cmp";
    root.appendChild(cmp);

    /* ── 7 · actions ── */
    var actions = el("div", "plab2-actions");
    actions.innerHTML =
      '<button type="button" class="plab2-btn" id="plab2-reseed" aria-label="Re-seed the model from the latest company data"><i class="ti ti-wand" aria-hidden="true"></i> Re-seed from data</button>' +
      '<span class="plab2-spacer"></span>' +
      '<button type="button" class="plab2-btn" id="plab2-save" aria-label="Save this projection model"><i class="ti ti-bookmark" aria-hidden="true"></i> Save</button>' +
      '<button type="button" class="plab2-btn" id="plab2-csv" aria-label="Export the full model as CSV"><i class="ti ti-table-export" aria-hidden="true"></i> CSV</button>' +
      '<button type="button" class="plab2-btn plab2-btn-gold" id="plab2-img" aria-label="Export a shareable image of this projection"><i class="ti ti-photo-down" aria-hidden="true"></i> Export image</button>';
    root.appendChild(actions);
    var confirmBox = el("div", "plab2-confirm");
    confirmBox.id = "plab2-confirm";
    confirmBox.hidden = true;
    root.appendChild(confirmBox);

    root.appendChild(el("div", "plab2-note",
      "Cells with a gold underline are editable assumptions — growth and margins in whole percents, P/E in multiples. Everything recalculates as you type. Educational model, not investment advice."));

    PL.container.innerHTML = "";
    PL.container.appendChild(root);

    wireFoundation();
    wireTable();
    q("#plab2-reseed").onclick = function () { requestReseed(); };
    q("#plab2-save").onclick = saveModel;
    q("#plab2-csv").onclick = exportCSV;
    q("#plab2-img").onclick = exportImage;

    syncFoundationInputs();
    recompute();
  }

  /* ───────────────────────── table build ───────────────────────── */
  function buildTable() {
    var m = PL.model;
    var years = [];
    for (var i = 1; i <= m.selectedHorizon; i += 1) years.push(m.baseYear + i);

    var wrap = el("div", "plab2-twrap");
    var table = el("table", "plab2-table");
    var cap = el("caption", "sr-only", "Year-by-year projection for the " + SCEN_LABEL[m.selectedScenario] + " scenario");
    table.appendChild(cap);

    var thead = el("thead");
    var hr = el("tr");
    var th0 = el("th", "plab2-rowlbl", "Metric");
    th0.scope = "col";
    hr.appendChild(th0);
    var thBase = el("th", "plab2-basecol", '<span class="plab2-baseyr">' + m.baseYear + '</span><small>base year</small>');
    thBase.scope = "col";
    thBase.title = "Starting point — derived from the Model Foundation inputs";
    hr.appendChild(thBase);
    years.forEach(function (y) { var th = el("th", null, String(y)); th.scope = "col"; hr.appendChild(th); });
    thead.appendChild(hr);
    table.appendChild(thead);

    var tbody = el("tbody");
    TABLE_SECTIONS.forEach(function (sec) {
      var secTr = el("tr", "plab2-sec");
      var secTd = el("td", null, sec.label);
      secTd.colSpan = years.length + 2;
      secTr.appendChild(secTd);
      tbody.appendChild(secTr);
      sec.rows.forEach(function (row) {
        var tr = el("tr", "plab2-r plab2-r-" + row.key + (row.band ? " plab2-band-" + row.band : ""));
        var lblTd = el("td", "plab2-rowlbl");
        lblTd.innerHTML = row.tip
          ? '<span class="plab2-ftip plab2-rowtip" tabindex="0" role="note" aria-label="' + esc(row.tip) + '" data-tip="' + esc(row.tip) + '">' + esc(row.label) + '</span>'
          : esc(row.label);
        tr.appendChild(lblTd);
        var baseTd = el("td", "plab2-basecol");
        baseTd.setAttribute("data-basecell", row.key);
        baseTd.textContent = "—";
        tr.appendChild(baseTd);
        for (var yi = 0; yi < years.length; yi += 1) {
          var td = el("td");
          if (row.type === "in") {
            td.className = "plab2-incell";
            var inp = el("input", "plab2-cin");
            inp.type = "text";
            inp.inputMode = "decimal";
            inp.autocomplete = "off";
            inp.setAttribute("data-field", row.key);
            inp.setAttribute("data-yi", String(yi));
            inp.setAttribute("aria-label", row.label + " for " + years[yi] + " (" + SCEN_LABEL[PL.model.selectedScenario] + " scenario)");
            td.appendChild(inp);
            td.appendChild(el("span", "plab2-sfx", row.suffix || ""));
          } else {
            td.className = "plab2-out";
            td.setAttribute("data-out", row.key + ":" + yi);
            td.textContent = "—";
          }
          tr.appendChild(td);
        }
        tbody.appendChild(tr);
      });
    });
    table.appendChild(tbody);
    wrap.appendChild(table);
    return wrap;
  }

  /* ───────────────────────── wiring ───────────────────────── */
  function wireFoundation() {
    FIELDS.forEach(function (f) {
      var inp = q("#plab2-f-" + f.key);
      if (!inp) return;
      inp.addEventListener("focus", function () {
        inp.value = f.raw(Number(PL.model[f.key]));
        inp.select();
      });
      inp.addEventListener("input", function () {
        var n = M().plParseNumber(inp.value);
        var err = f.validate(n);
        setFieldError(f.key, inp.value.trim() === "" ? null : err);
        if (!err && Number.isFinite(n) && n !== Number(PL.model[f.key])) {
          setBaseField(f.key, n);
          markFieldEdited(f.key);
          recompute();
        }
      });
      inp.addEventListener("blur", function () {
        setFieldError(f.key, null);
        syncFoundationInputs(); // restore formatted display (and discard invalid text)
      });
      inp.addEventListener("keydown", function (e) { if (e.key === "Enter") inp.blur(); });
    });
    qa(".plab2-freset").forEach(function (btn) {
      btn.onclick = function () {
        var key = btn.getAttribute("data-fkey");
        if (resetBaseField(key)) {
          markFieldEdited(key);
          syncFoundationInputs();
          recompute();
        }
      };
    });
  }

  function syncFoundationInputs() {
    FIELDS.forEach(function (f) {
      var inp = q("#plab2-f-" + f.key);
      if (!inp || document.activeElement === inp) return;
      var v = Number(PL.model[f.key]);
      inp.value = f.display(v);
      if (f.title) inp.title = f.title(v);
    });
  }

  function markFieldEdited(key) {
    var edited = !!PL.model.userEdited[key];
    var box = q("#plab2-f-" + key);
    if (box) box.parentElement.classList.toggle("edited", edited);
    var st = q('[data-fstate="' + key + '"]');
    if (st) st.textContent = edited ? "Edited" : "Seeded";
    var rst = q('.plab2-freset[data-fkey="' + key + '"]');
    if (rst) rst.hidden = !edited || !(PL.model.seed && PL.model.seed.values && Number.isFinite(Number(PL.model.seed.values[key])));
  }

  function setFieldError(key, msg) {
    var errEl = q('[data-ferr="' + key + '"]');
    var inp = q("#plab2-f-" + key);
    if (errEl) errEl.textContent = msg || "";
    if (inp) inp.parentElement.classList.toggle("invalid", !!msg);
  }

  function wireTable() {
    qa(".plab2-cin").forEach(function (inp) {
      inp.addEventListener("input", function () {
        var field = inp.getAttribute("data-field");
        var yi = +inp.getAttribute("data-yi");
        var n = M().plParseNumber(inp.value);
        if (Number.isFinite(n)) {
          inp.classList.remove("invalid");
          var arr = PL.model.scenarios[PL.model.selectedScenario][field];
          if (arr[yi] !== n) {
            arr[yi] = n;
            PL.model.userEditedScenarios = true;
            touch();
            recompute();
          }
        } else {
          inp.classList.toggle("invalid", inp.value.trim() !== "");
        }
      });
      inp.addEventListener("blur", function () {
        inp.classList.remove("invalid");
        syncTableInputs(); // empty/invalid text falls back to the canonical value
      });
      inp.addEventListener("keydown", function (e) { if (e.key === "Enter") inp.blur(); });
    });
  }

  function syncTableInputs() {
    var s = PL.model.scenarios[PL.model.selectedScenario];
    qa(".plab2-cin").forEach(function (inp) {
      if (document.activeElement === inp) return;
      var v = s[inp.getAttribute("data-field")][+inp.getAttribute("data-yi")];
      inp.value = Number.isFinite(Number(v)) ? String(v) : "";
    });
  }

  function selectScenario(k) {
    if (PL.model.selectedScenario === k) return;
    PL.model.selectedScenario = k;
    touch();
    render();
  }

  /* ═══════════════════════ RECOMPUTE (one source of truth) ═══════════════════════ */
  function recompute() {
    var outlook = M().plCalculateOutlook(PL.model);
    var errBox = q("#plab2-error");
    if (!outlook.ok) {
      if (errBox) {
        errBox.hidden = false;
        errBox.innerHTML = '<i class="ti ti-alert-triangle" aria-hidden="true"></i> ' + esc(outlook.error);
      }
      renderStatus();
      return; // keep last good outputs on screen instead of a NaN table
    }
    if (errBox) { errBox.hidden = true; errBox.textContent = ""; }
    PL.lastOutlook = outlook;

    var active = outlook.scenarios[PL.model.selectedScenario];

    /* table outputs + base column */
    TABLE_SECTIONS.forEach(function (sec) {
      sec.rows.forEach(function (row) {
        var baseTd = q('[data-basecell="' + row.key + '"]');
        if (baseTd) {
          if (row.baseOut) baseTd.textContent = row.baseOut(active.base);
          else if (row.base) baseTd.textContent = row.base(active.base);
          else if (row.type === "in") baseTd.textContent = "—";
        }
        if (row.type === "out") {
          active.rows.forEach(function (r, yi) {
            var td = q('[data-out="' + row.key + ":" + yi + '"]');
            if (td) {
              td.textContent = row.fmt(r);
              td.classList.toggle("negearn", !!r.negativeEarnings && (row.band || row.key === "eps" || row.key === "netIncome"));
            }
          });
        }
      });
    });

    renderOutcome(active, outlook);
    renderChart(active);
    renderComparison(outlook);
    renderDerived();
    renderStatus(outlook);
  }

  function renderDerived() {
    var box = q(".plab2-derived");
    if (!box) return;
    var d = M().plBaseDerived(PL.model);
    var derivedTag = PL.model.seed && PL.model.seed.netIncomeDerived ? ' <span class="plab2-dtag" title="Net income was derived from EPS × diluted shares">derived</span>' : "";
    box.innerHTML =
      '<span>Base net margin <strong>' + fmtPct1(d.netMargin) + "</strong>" + derivedTag + "</span>" +
      '<span class="plab2-dsep" aria-hidden="true">·</span>' +
      "<span>Base EPS <strong>" + fmtEps(d.eps) + "</strong></span>" +
      '<span class="plab2-dhint">calculated from the inputs above</span>';
  }

  function renderOutcome(active, outlook) {
    var box = q("#plab2-outcome");
    if (!box) return;
    var t = active.terminal;
    var m = PL.model;
    var scen = m.selectedScenario;
    if (t.negativeEarnings) {
      box.innerHTML =
        '<div class="plab2-oc-kicker">' + t.year + " " + SCEN_LABEL[scen] + " outlook</div>" +
        '<div class="plab2-oc-nm">No positive earnings by ' + t.year + '</div>' +
        '<div class="plab2-oc-sub">Net income is ' + fmtBig(t.netIncome) + " (" + fmtPct1(t.netMargin) + " margin) — a P/E-based valuation range isn’t meaningful. Raise the margin path or extend the horizon.</div>";
      return;
    }
    var upLow = t.priceLow / m.startPrice - 1;
    var upHigh = t.priceHigh / m.startPrice - 1;
    box.innerHTML =
      '<div class="plab2-oc-kicker">' + t.year + " " + SCEN_LABEL[scen] + " outlook <span class='plab2-oc-flag'>model output — not a price target</span></div>" +
      '<div class="plab2-oc-range">' + fmtPrice(t.priceLow) + " <span>–</span> " + fmtPrice(t.priceHigh) + "</div>" +
      '<div class="plab2-oc-mid">Midpoint <strong>' + fmtPrice(t.priceMid) + "</strong></div>" +
      '<div class="plab2-oc-cagr">' + fmtPct0(t.cagrLow) + " – " + fmtPct0(t.cagrHigh) + " annualized · " + fmtPctSigned(upLow) + " to " + fmtPctSigned(upHigh) + " vs " + fmtPrice(m.startPrice) + "</div>" +
      '<div class="plab2-oc-stats">' +
        "<span>Revenue " + fmtBig(t.revenue) + "</span><span>EPS " + fmtEps(t.eps) + "</span><span>Net margin " + fmtPct1(t.netMargin) + "</span>" +
      "</div>";
  }

  /* ───────────────────────── chart (pure SVG, from the same rows) ───────────────────────── */
  function renderChart(active) {
    var box = q("#plab2-chart");
    if (!box) return;
    var m = PL.model;
    var rows = active.rows;
    var pts = [{ year: active.baseYear, low: m.startPrice, high: m.startPrice, mid: m.startPrice, base: true }];
    rows.forEach(function (r) { if (r.priceLow != null) pts.push({ year: r.year, low: r.priceLow, high: r.priceHigh, mid: r.priceMid, row: r }); });
    if (pts.length < 2) {
      box.innerHTML = '<div class="plab2-chart-empty">Valuation band unavailable — the ' + SCEN_LABEL[m.selectedScenario] + " case has no positive-earnings years.</div>";
      return;
    }
    var W = 760, H = 235, padL = 52, padR = 16, padT = 16, padB = 26;
    var lo = m.startPrice, hi = m.startPrice;
    pts.forEach(function (p) { lo = Math.min(lo, p.low); hi = Math.max(hi, p.high); });
    var span = (hi - lo) || 1; lo -= span * 0.08; hi += span * 0.06;
    var x0 = active.baseYear, x1 = rows[rows.length - 1].year;
    function X(yr) { return padL + (yr - x0) / (x1 - x0) * (W - padL - padR); }
    function Y(v) { return padT + (1 - (v - lo) / (hi - lo)) * (H - padT - padB); }
    function pt(x, y) { return x.toFixed(1) + "," + y.toFixed(1); }

    var bandTop = pts.map(function (p) { return pt(X(p.year), Y(p.high)); }).join(" ");
    var bandBot = pts.slice().reverse().map(function (p) { return pt(X(p.year), Y(p.low)); }).join(" ");
    var midLine = pts.map(function (p) { return pt(X(p.year), Y(p.mid)); }).join(" ");

    var gridLines = "";
    var ticks = 4;
    for (var i = 0; i <= ticks; i += 1) {
      var v = lo + (hi - lo) * i / ticks;
      var y = Y(v);
      gridLines += '<line x1="' + padL + '" y1="' + y + '" x2="' + (W - padR) + '" y2="' + y + '" class="plab2-cgrid"/>' +
        '<text x="' + (padL - 7) + '" y="' + (y + 3.5) + '" class="plab2-clbl" text-anchor="end">' + curSym() + (v >= 100 ? Math.round(v) : v.toFixed(v < 10 ? 2 : 1)) + "</text>";
    }
    var xLabels = pts.map(function (p) {
      return '<text x="' + X(p.year) + '" y="' + (H - 7) + '" class="plab2-clbl" text-anchor="middle">' + p.year + "</text>";
    }).join("");
    var refY = Y(m.startPrice);
    var hoverZones = pts.map(function (p, idx) {
      var xa = idx === 0 ? padL : (X(pts[idx - 1].year) + X(p.year)) / 2;
      var xb = idx === pts.length - 1 ? W - padR : (X(p.year) + X(pts[idx + 1].year)) / 2;
      var label = p.base
        ? p.year + " base year — start price " + fmtPrice(m.startPrice)
        : p.year + ": revenue " + fmtBig(p.row.revenue) + ", EPS " + fmtEps(p.row.eps) + ", range " + fmtPrice(p.low) + " to " + fmtPrice(p.high);
      return '<rect data-ci="' + idx + '" x="' + xa + '" y="' + padT + '" width="' + Math.max(1, xb - xa) + '" height="' + (H - padT - padB) +
        '" fill="transparent" tabindex="0" role="img" aria-label="' + esc(label) + '"/>';
    }).join("");

    box.innerHTML =
      '<div class="plab2-chart-h"><span>Valuation band · ' + SCEN_LABEL[m.selectedScenario] + " case</span><span class='plab2-chart-leg'><i class='plab2-leg-band'></i> low–high <i class='plab2-leg-mid'></i> midpoint <i class='plab2-leg-ref'></i> start price</span></div>" +
      '<svg viewBox="0 0 ' + W + " " + H + '" preserveAspectRatio="xMidYMid meet" aria-hidden="false" role="group" aria-label="Projected share-price band by year">' +
        gridLines +
        '<polygon points="' + bandTop + " " + bandBot + '" class="plab2-cband"/>' +
        '<polyline points="' + midLine + '" class="plab2-cmid"/>' +
        '<line x1="' + padL + '" y1="' + refY + '" x2="' + (W - padR) + '" y2="' + refY + '" class="plab2-cref"/>' +
        pts.map(function (p) { return '<circle cx="' + X(p.year) + '" cy="' + Y(p.mid) + '" r="3" class="plab2-cdot"/>'; }).join("") +
        '<g class="plab2-czones">' + hoverZones + "</g>" +
      "</svg>" +
      '<div class="plab2-ctt" hidden></div>';

    var tt = box.querySelector(".plab2-ctt");
    qa("#plab2-chart rect[data-ci]").forEach(function (zone) {
      function show() {
        var p = pts[+zone.getAttribute("data-ci")];
        tt.innerHTML = p.base
          ? "<strong>" + p.year + " · base</strong>Start price " + fmtPrice(m.startPrice)
          : "<strong>" + p.year + "</strong>Revenue " + fmtBig(p.row.revenue) + "<br>EPS " + fmtEps(p.row.eps) + "<br>Range " + fmtPrice(p.low) + " – " + fmtPrice(p.high);
        tt.hidden = false;
        var rect = box.getBoundingClientRect();
        var xPct = (X(p.year) / W) * 100;
        tt.style.left = Math.min(88, Math.max(6, xPct)) + "%";
      }
      zone.addEventListener("mouseenter", show);
      zone.addEventListener("focus", show);
      zone.addEventListener("mouseleave", function () { tt.hidden = true; });
      zone.addEventListener("blur", function () { tt.hidden = true; });
    });
  }

  /* ───────────────────────── scenario cards + expected value ───────────────────────── */
  function renderComparison(outlook) {
    var box = q("#plab2-cmp");
    if (!box) return;
    var m = PL.model;
    var cards = SCEN.map(function (k) {
      var sc = outlook.scenarios[k];
      var t = sc.terminal;
      var g0 = sc.rows[0] ? sc.rows[0].revGrowth : NaN;
      var summary = "Growth " + fmtPct0(g0) + " → " + fmtPct0(t.revGrowth) + " · margin → " + fmtPct1(t.netMargin) + " · P/E " + (+t.peLow.toFixed(1)) + "–" + (+t.peHigh.toFixed(1)) + "×";
      var body = t.negativeEarnings
        ? '<div class="plab2-card-px plab2-card-nm">No positive earnings by ' + t.year + "</div>"
        : '<div class="plab2-card-px">' + fmtPrice(t.priceLow) + " – " + fmtPrice(t.priceHigh) + "</div>" +
          '<div class="plab2-card-cagr">' + fmtPct0(t.cagrLow) + " – " + fmtPct0(t.cagrHigh) + " <small>CAGR</small></div>";
      return '<button type="button" class="plab2-card plab2-card-' + k + (m.selectedScenario === k ? " active" : "") + '" data-scen="' + k +
        '" aria-pressed="' + (m.selectedScenario === k) + '" aria-label="Select the ' + SCEN_LABEL[k] + ' scenario">' +
        '<div class="plab2-card-h"><span class="plab2-tab-dot" aria-hidden="true"></span>' + SCEN_LABEL[k] + '<span class="plab2-card-yr">' + t.year + "</span></div>" +
        body +
        '<div class="plab2-card-stats"><span>Rev ' + fmtBig(t.revenue) + "</span><span>EPS " + fmtEps(t.eps) + "</span></div>" +
        '<div class="plab2-card-sum">' + esc(summary) + "</div>" +
      "</button>";
    }).join("");

    var w = m.scenarioWeights;
    var wTotal = (Number(w.bear) || 0) + (Number(w.base) || 0) + (Number(w.bull) || 0);
    var expHtml;
    if (outlook.expected) {
      expHtml =
        '<div class="plab2-exp-l">' +
          '<span class="plab2-exp-t">Probability-weighted outlook <span class="plab2-ftip" tabindex="0" role="note" data-tip="Expected value = bear midpoint × ' + w.bear + "% + base midpoint × " + w.base + "% + bull midpoint × " + w.bull + '%. Each midpoint is (price low + price high) ÷ 2 in the terminal year." aria-label="Expected value formula"><i class="ti ti-info-circle" aria-hidden="true"></i></span></span>' +
          '<span class="plab2-exp-w">Bear ' + w.bear + "% · Base " + w.base + "% · Bull " + w.bull + "%" +
          ' <button type="button" class="plab2-exp-edit" id="plab2-wedit" aria-expanded="false" aria-label="Edit scenario weights">edit</button></span>' +
        "</div>" +
        '<div class="plab2-exp-v">Expected ' + outlook.expected.year + " value <strong>" + fmtPrice(outlook.expected.price) + "</strong><span>" + fmtPct1(outlook.expected.cagr) + " annualized</span></div>";
    } else {
      expHtml = '<div class="plab2-exp-l"><span class="plab2-exp-t">Probability-weighted outlook</span></div>' +
        '<div class="plab2-exp-v plab2-exp-nm">Unavailable — a scenario has no positive earnings in ' + outlook.terminalYear + ".</div>";
    }
    var weditor =
      '<div class="plab2-weditor" id="plab2-weditor" hidden>' +
        SCEN.map(function (k) {
          return '<label>' + SCEN_LABEL[k] + ' <input type="text" inputmode="numeric" data-wkey="' + k + '" value="' + esc(w[k]) + '" aria-label="' + SCEN_LABEL[k] + ' weight percent"><span>%</span></label>';
        }).join("") +
        '<span class="plab2-wtotal" id="plab2-wtotal" role="status">Total ' + (+wTotal.toFixed(1)) + "%</span>" +
      "</div>";

    box.innerHTML = '<div class="plab2-cards">' + cards + '</div><div class="plab2-exp">' + expHtml + weditor + "</div>";

    qa(".plab2-card").forEach(function (c) { c.onclick = function () { selectScenario(c.getAttribute("data-scen")); }; });
    var weditBtn = q("#plab2-wedit");
    if (weditBtn) {
      weditBtn.onclick = function () {
        var ed = q("#plab2-weditor");
        ed.hidden = !ed.hidden;
        weditBtn.setAttribute("aria-expanded", String(!ed.hidden));
        if (!ed.hidden) { var first = ed.querySelector("input"); if (first) first.focus(); }
      };
    }
    qa("#plab2-weditor input").forEach(function (inp) {
      inp.addEventListener("input", function () {
        var k = inp.getAttribute("data-wkey");
        var n = M().plParseNumber(inp.value);
        var totalEl = q("#plab2-wtotal");
        var wm = PL.model.scenarioWeights;
        var candidate = { bear: wm.bear, base: wm.base, bull: wm.bull };
        candidate[k] = Number.isFinite(n) ? n : NaN;
        var total = (Number(candidate.bear) || 0) + (Number(candidate.base) || 0) + (Number(candidate.bull) || 0);
        if (totalEl) {
          totalEl.textContent = "Total " + (+total.toFixed(1)) + "%";
          totalEl.classList.toggle("bad", Math.abs(total - 100) > 0.01);
        }
        if (Number.isFinite(n) && n >= 0) {
          wm[k] = n;
          touch();
          if (Math.abs(total - 100) <= 0.01) {
            var keepOpen = true;
            recomputePreservingWeights(keepOpen);
          }
        }
      });
    });
  }

  function recomputePreservingWeights() {
    var ed = q("#plab2-weditor");
    var wasOpen = ed && !ed.hidden;
    var focusKey = document.activeElement && document.activeElement.getAttribute ? document.activeElement.getAttribute("data-wkey") : null;
    recompute();
    if (wasOpen) {
      var ed2 = q("#plab2-weditor");
      var btn = q("#plab2-wedit");
      if (ed2) ed2.hidden = false;
      if (btn) btn.setAttribute("aria-expanded", "true");
      if (focusKey) {
        var inp = q('#plab2-weditor input[data-wkey="' + focusKey + '"]');
        if (inp) { inp.focus(); var v = inp.value; inp.setSelectionRange(v.length, v.length); }
      }
    }
  }

  /* ───────────────────────── status chips ───────────────────────── */
  function renderStatus(outlook) {
    var box = q("#plab2-status");
    if (!box) return;
    var m = PL.model;
    var chips = [];
    var src = (m.seed && m.seed.source) || "defaults";
    chips.push('<span class="plab2-chip" title="Where the base-year numbers came from"><i class="ti ti-seedling" aria-hidden="true"></i> Seeded from ' + esc(src) + "</span>");
    if (isUserModified()) chips.push('<span class="plab2-chip plab2-chip-edit"><i class="ti ti-pencil" aria-hidden="true"></i> User modified</span>');
    if (PL.loadingSeed) chips.push('<span class="plab2-chip"><i class="ti ti-loader-2 plab2-spin" aria-hidden="true"></i> Loading fundamentals…</span>');
    if (PL.seedHintShown) chips.push('<span class="plab2-chip plab2-chip-gold"><i class="ti ti-refresh" aria-hidden="true"></i> Fresh fundamentals available — use Re-seed</span>');
    if (hasUnsavedChanges()) chips.push('<span class="plab2-chip plab2-chip-unsaved">Unsaved changes</span>');
    else if (PL.savedJson) chips.push('<span class="plab2-chip plab2-chip-saved"><i class="ti ti-check" aria-hidden="true"></i> Saved</span>');
    if (m.lastUpdated) chips.push('<span class="plab2-chip plab2-chip-dim">Updated ' + fmtTimeAgo(m.lastUpdated) + "</span>");
    var warn = outlook && outlook.warnings && outlook.warnings.length ? outlook.warnings[0] : null;
    box.innerHTML = chips.join("") + (warn ? '<span class="plab2-chip plab2-chip-warn"><i class="ti ti-alert-triangle" aria-hidden="true"></i> ' + esc(warn) + "</span>" : "");
  }

  /* ═══════════════════════ persistence ═══════════════════════ */
  function saveModel() {
    try {
      var json = JSON.stringify(PL.model);
      localStorage.setItem(LS_PREFIX_V2 + (PL.model.ticker || "GEN"), json);
      try { localStorage.removeItem(LS_PREFIX_V1 + (PL.model.ticker || "GEN")); } catch (e0) { /* legacy key may not exist */ }
      PL.savedJson = json;
      toastPL("Projection saved for " + PL.model.ticker);
      renderStatus(PL.lastOutlook);
    } catch (e) { toastPL("Could not save (storage unavailable)"); }
  }

  function loadSaved(ticker) {
    var raw = null;
    try {
      raw = localStorage.getItem(LS_PREFIX_V2 + ticker);
      if (!raw) raw = localStorage.getItem(LS_PREFIX_V1 + ticker); // legacy v1
    } catch (e) { return null; }
    if (!raw) return null;
    try {
      var model = M().plMigrateSavedModel(JSON.parse(raw));
      if (model) { model.ticker = ticker; return model; }
    } catch (e2) { /* corrupted save — fall through to reseed */ }
    return null;
  }

  /* ═══════════════════════ CSV export (canonical model → plBuildCsv) ═══════════════════════ */
  function exportCSV() {
    var built = M().plBuildCsv(PL.model);
    if (!built.ok) { toastPL("Fix the model first: " + built.error); return; }
    downloadBlob(built.csv, "text/csv", (PL.model.ticker || "projection") + "_projection_model.csv");
  }
  function downloadBlob(text, mime, filename) {
    var blob = new Blob([text], { type: mime });
    var url = URL.createObjectURL(blob);
    var a = document.createElement("a"); a.href = url; a.download = filename; document.body.appendChild(a); a.click();
    setTimeout(function () { document.body.removeChild(a); URL.revokeObjectURL(url); }, 100);
  }

  /* ═══════════════════════ image export ═══════════════════════ */
  function exportImage() {
    var outlook = M().plCalculateOutlook(PL.model);
    if (!outlook.ok) { toastPL("Fix the model before exporting: " + outlook.error); return; }
    var m = PL.model;
    var active = outlook.scenarios[m.selectedScenario];
    var t = active.terminal;
    var W = 1200, H = 675, sc = 2;
    var cv = document.createElement("canvas"); cv.width = W * sc; cv.height = H * sc;
    var g = cv.getContext("2d"); g.scale(sc, sc);

    /* surfaces: near-black ink with a soft radial gold illumination */
    g.fillStyle = "#0B0D0F"; g.fillRect(0, 0, W, H);
    var glow = g.createRadialGradient(W * 0.82, -60, 40, W * 0.82, -60, 620);
    glow.addColorStop(0, "rgba(216,154,55,.16)"); glow.addColorStop(1, "rgba(216,154,55,0)");
    g.fillStyle = glow; g.fillRect(0, 0, W, H);
    g.strokeStyle = "rgba(216,154,55,.28)"; g.lineWidth = 1; g.strokeRect(24.5, 24.5, W - 49, H - 49);

    var cream = "#F1EDE3", creamDim = "rgba(241,237,227,.62)", gold = "#E0A53C";
    g.fillStyle = gold; g.font = "700 14px 'DM Sans', Arial";
    g.fillText("IMPLIED LENS — PROJECTION LAB", 60, 74);
    g.fillStyle = cream; g.font = "800 52px 'Space Grotesk','DM Sans',Arial";
    g.fillText(m.ticker, 60, 130);
    if (m.companyName) {
      g.font = "500 19px 'DM Sans', Arial"; g.fillStyle = creamDim;
      g.fillText(m.companyName, 60 + g.measureText("x").width + 12 + measure(g, m.ticker, "800 52px 'Space Grotesk','DM Sans',Arial"), 130);
    }
    g.fillStyle = creamDim; g.font = "500 17px 'DM Sans', Arial";
    g.fillText(SCEN_LABEL[m.selectedScenario] + " case · " + outlook.horizonYears + "-year horizon to " + t.year + " · from " + fmtPrice(m.startPrice), 60, 162);

    /* left column — the outcome */
    if (t.negativeEarnings) {
      g.fillStyle = cream; g.font = "800 40px 'Space Grotesk','DM Sans',Arial";
      g.fillText("No positive earnings by " + t.year, 60, 280);
      g.fillStyle = creamDim; g.font = "500 18px 'DM Sans', Arial";
      g.fillText("A P/E-based valuation range is not meaningful for this scenario.", 60, 316);
    } else {
      g.fillStyle = creamDim; g.font = "600 15px 'DM Sans', Arial";
      g.fillText("MODELED " + t.year + " PRICE RANGE", 60, 240);
      g.fillStyle = cream; g.font = "800 58px 'Space Grotesk','DM Sans',Arial";
      g.fillText(fmtPrice(t.priceLow) + " – " + fmtPrice(t.priceHigh), 60, 298);
      g.fillStyle = gold; g.font = "700 24px 'DM Sans', Arial";
      g.fillText("Midpoint " + fmtPrice(t.priceMid), 60, 340);
      g.fillStyle = cream; g.font = "700 22px 'DM Sans', Arial";
      g.fillText(fmtPct0(t.cagrLow) + " – " + fmtPct0(t.cagrHigh) + " annualized (CAGR)", 60, 384);
      if (outlook.expected) {
        g.fillStyle = creamDim; g.font = "500 16px 'DM Sans', Arial";
        g.fillText("Probability-weighted (" + m.scenarioWeights.bear + "/" + m.scenarioWeights.base + "/" + m.scenarioWeights.bull + "): " + fmtPrice(outlook.expected.price) + " · " + fmtPct1(outlook.expected.cagr) + " annualized", 60, 420);
      }
    }

    /* key assumptions block */
    g.fillStyle = creamDim; g.font = "600 14px 'DM Sans', Arial";
    g.fillText("KEY ASSUMPTIONS (" + SCEN_LABEL[m.selectedScenario].toUpperCase() + ")", 60, 476);
    g.fillStyle = cream; g.font = "500 17px 'DM Sans', Arial";
    var g0 = active.rows[0], gN = t;
    g.fillText("Revenue growth " + fmtPct0(g0.revGrowth) + " → " + fmtPct0(gN.revGrowth) + "   ·   Net margin " + fmtPct1(active.base.netMargin) + " → " + fmtPct1(gN.netMargin) + "   ·   Exit P/E " + (+gN.peLow.toFixed(1)) + "–" + (+gN.peHigh.toFixed(1)) + "×", 60, 504);
    g.fillText("Base FY" + m.baseYear + ": revenue " + fmtBig(m.baseRevenue) + "  ·  net income " + fmtBig(m.baseNetIncome) + "  ·  " + fmtSharesCompact(m.dilutedShares) + " diluted shares", 60, 532);

    /* right — mini band chart from the same rows */
    var chartPts = [{ year: active.baseYear, low: m.startPrice, high: m.startPrice, mid: m.startPrice }];
    active.rows.forEach(function (r) { if (r.priceLow != null) chartPts.push({ year: r.year, low: r.priceLow, high: r.priceHigh, mid: r.priceMid }); });
    if (chartPts.length >= 2) {
      var cx = 760, cy = 210, cw = 380, ch = 250;
      var lo2 = Infinity, hi2 = -Infinity;
      chartPts.forEach(function (p) { lo2 = Math.min(lo2, p.low); hi2 = Math.max(hi2, p.high); });
      var span2 = (hi2 - lo2) || 1; lo2 -= span2 * 0.08; hi2 += span2 * 0.06;
      var xA = chartPts[0].year, xB = chartPts[chartPts.length - 1].year;
      function CX(yr) { return cx + (yr - xA) / (xB - xA) * cw; }
      function CY(v) { return cy + (1 - (v - lo2) / (hi2 - lo2)) * ch; }
      g.beginPath();
      chartPts.forEach(function (p, i) { i === 0 ? g.moveTo(CX(p.year), CY(p.high)) : g.lineTo(CX(p.year), CY(p.high)); });
      for (var bi = chartPts.length - 1; bi >= 0; bi -= 1) g.lineTo(CX(chartPts[bi].year), CY(chartPts[bi].low));
      g.closePath();
      g.fillStyle = "rgba(216,154,55,.14)"; g.fill();
      g.beginPath();
      chartPts.forEach(function (p, i2) { i2 === 0 ? g.moveTo(CX(p.year), CY(p.mid)) : g.lineTo(CX(p.year), CY(p.mid)); });
      g.strokeStyle = gold; g.lineWidth = 2.5; g.stroke();
      g.setLineDash([5, 5]); g.beginPath();
      g.moveTo(cx, CY(m.startPrice)); g.lineTo(cx + cw, CY(m.startPrice));
      g.strokeStyle = "rgba(241,237,227,.4)"; g.lineWidth = 1.2; g.stroke(); g.setLineDash([]);
      g.fillStyle = creamDim; g.font = "500 13px 'DM Sans', Arial";
      g.textAlign = "center";
      chartPts.forEach(function (p) { g.fillText(String(p.year), CX(p.year), cy + ch + 22); });
      g.textAlign = "left";
    }

    g.fillStyle = "rgba(241,237,227,.45)"; g.font = "500 13px 'DM Sans', Arial";
    g.fillText("Educational model · assumptions are the author’s · not investment advice · impliedlens.com", 60, H - 44);

    cv.toBlob(function (blob) {
      var url = URL.createObjectURL(blob);
      var a = document.createElement("a"); a.href = url; a.download = (m.ticker || "projection") + "_" + m.selectedScenario + "_" + t.year + ".png";
      document.body.appendChild(a); a.click();
      setTimeout(function () { document.body.removeChild(a); URL.revokeObjectURL(url); }, 100);
    });
  }
  function measure(g, text, font) { var prev = g.font; g.font = font; var w = g.measureText(text).width; g.font = prev; return w; }

  function toastPL(msg) {
    if (typeof window.toast === "function") { window.toast(msg); return; }
    var t = el("div", "plab2-toast", esc(msg));
    document.body.appendChild(t);
    setTimeout(function () { t.classList.add("show"); }, 10);
    setTimeout(function () { t.remove(); }, 2600);
  }

  /* ═══════════════════════ seeding from the app ═══════════════════════ */
  function rawNum(v) { if (v == null) return NaN; if (typeof v === "number") return v; if (typeof v === "object" && v.raw != null) return Number(v.raw); return Number(v); }

  function readSeedFromApp() {
    var S = window.S || {};
    var meta = (S.data && S.data.meta) || {};
    var seed = {
      ticker: S.ticker || meta.symbol || "—",
      companyName: meta.longName || meta.shortName || "",
      currency: meta.currency || "USD",
      baseYear: new Date().getFullYear(),
      seeded: false,
    };
    var price = rawNum(meta.regularMarketPrice);
    if (Number.isFinite(price) && price > 0) seed.startPrice = price;
    var pe = rawNum(meta.trailingPE);
    if (Number.isFinite(pe) && pe > 0) seed.currentPE = pe;

    var r = S.financialsRaw;
    var shares = NaN, netIncome = NaN, revenue = NaN, fyLabel = "";
    if (r) {
      var inc = (r.incomeStatementHistory && r.incomeStatementHistory.incomeStatementHistory) || [];
      var ks = r.defaultKeyStatistics || {};
      shares = rawNum(ks.sharesOutstanding);
      if (inc.length) {
        revenue = rawNum(inc[0].totalRevenue);
        netIncome = rawNum(inc[0].netIncome);
        var end = rawNum(inc[0].endDate);
        if (Number.isFinite(end) && end > 0) fyLabel = "FY" + new Date(end * 1000).getUTCFullYear();
        if (inc.length > 1) {
          var rev1 = rawNum(inc[1].totalRevenue);
          if (Number.isFinite(rev1) && rev1 > 0 && Number.isFinite(revenue)) seed.histGrowth = revenue / rev1 - 1;
        }
      }
    }
    if (!Number.isFinite(shares) || shares <= 0) {
      var mcap = rawNum(meta.marketCap);
      if (Number.isFinite(mcap) && mcap > 0 && Number.isFinite(price) && price > 0) shares = mcap / price;
    }
    if (Number.isFinite(shares) && shares > 0) seed.dilutedShares = shares;
    if (Number.isFinite(revenue) && revenue > 0) { seed.baseRevenue = revenue; seed.seeded = true; }
    // Deterministic net-income priority: statement net income first; else derive from EPS × shares and flag it.
    if (Number.isFinite(netIncome)) {
      seed.baseNetIncome = netIncome;
    } else {
      var eps = rawNum(meta.epsTrailingTwelveMonths);
      if (Number.isFinite(eps) && Number.isFinite(shares) && shares > 0) {
        seed.baseNetIncome = eps * shares;
        seed.netIncomeDerived = true;
      }
    }
    seed.source = seed.seeded ? ((fyLabel ? fyLabel + " " : "") + "reported financials") : "market quote (partial)";
    return seed;
  }

  function seedComplete(seed) { return !!seed.seeded && Number.isFinite(Number(seed.baseNetIncome)); }

  /* Re-seed with explicit user consent when edits exist. Never partial: the whole
     model is rebuilt in one step, optionally keeping scenario assumptions. */
  function requestReseed() {
    var box = q("#plab2-confirm");
    if (!box) return;
    if (!isUserModified()) { performReseed(false); return; }
    box.hidden = false;
    box.innerHTML =
      '<div class="plab2-confirm-t"><i class="ti ti-alert-triangle" aria-hidden="true"></i> Re-seeding replaces your inputs with fresh company data.</div>' +
      '<div class="plab2-confirm-b">' +
        '<button type="button" class="plab2-btn" id="plab2-rs-all">Replace everything</button>' +
        '<button type="button" class="plab2-btn" id="plab2-rs-keep">Keep my scenario assumptions</button>' +
        '<button type="button" class="plab2-btn" id="plab2-rs-cancel">Cancel</button>' +
      "</div>";
    q("#plab2-rs-all").onclick = function () { box.hidden = true; performReseed(false); };
    q("#plab2-rs-keep").onclick = function () { box.hidden = true; performReseed(true); };
    q("#plab2-rs-cancel").onclick = function () { box.hidden = true; };
    q("#plab2-rs-cancel").focus();
  }

  function performReseed(keepScenarios) {
    var prev = PL.model;
    var finish = function () {
      var seed = readSeedFromApp();
      seed.horizon = prev ? prev.selectedHorizon : 5;
      var fresh = M().plCreateModel(seed);
      if (keepScenarios && prev) {
        fresh.scenarios = JSON.parse(JSON.stringify(prev.scenarios));
        fresh.scenarioWeights = JSON.parse(JSON.stringify(prev.scenarioWeights));
        fresh.selectedScenario = prev.selectedScenario;
        fresh.userEditedScenarios = prev.userEditedScenarios;
      }
      PL.model = fresh;
      PL.seedHintShown = false;
      render();
      toastPL("Model re-seeded from " + ((fresh.seed && fresh.seed.source) || "available data"));
    };
    // Make sure fundamentals are actually loaded before reseeding.
    var S = window.S || {};
    if (!S.financialsRaw && S.ticker && typeof window.loadFinancials === "function") {
      PL.loadingSeed = true;
      renderStatus(PL.lastOutlook);
      Promise.resolve(window.loadFinancials(S.ticker)).catch(function () { /* seed from quote only */ }).then(function () {
        PL.loadingSeed = false;
        finish();
      });
      return;
    }
    finish();
  }

  /* ═══════════════════════ mount ═══════════════════════ */
  function mount(container, seed) {
    PL.container = typeof container === "string" ? document.getElementById(container) : container;
    if (!PL.container) return;
    var math = M();
    if (!math || typeof math.plCalculateOutlook !== "function") {
      PL.container.innerHTML = '<div class="plab2-error" style="display:block">Projection engine unavailable. Please reload the page.</div>';
      return;
    }
    try {
      var ticker = seed && seed.ticker ? seed.ticker : (window.S && window.S.ticker) || null;

      if (seed) {
        PL.model = math.plCreateModel(seed);
        PL.savedJson = null;
        render();
        return;
      }
      // Same ticker already mounted → keep the user's in-session edits intact.
      if (PL.model && ticker && PL.model.ticker === ticker) { render(); return; }

      PL.seedHintShown = false;
      if (ticker) {
        var saved = loadSaved(ticker);
        if (saved) {
          PL.model = saved;
          PL.savedJson = JSON.stringify(saved);
        } else {
          PL.model = math.plCreateModel(readSeedFromApp());
          PL.savedJson = null;
        }
        render();
        maybeCompleteSeedAsync(ticker);
      } else {
        PL.model = math.plCreateModel({});
        PL.savedJson = null;
        render();
      }
    } catch (e) {
      if (window.console && console.error) console.error("ProjectionLab mount error", e);
      PL.container.innerHTML = '<div class="plab2-error" style="display:block">Could not build the projection. ' + esc(e && e.message ? e.message : "") + "</div>";
    }
  }

  /* If the first seed was partial (financial statements not loaded yet), fetch them.
     Apply the completed seed ONLY while the model is untouched — a user edit or a
     restored save must never be clobbered by a late async response. */
  function maybeCompleteSeedAsync(ticker) {
    var S = window.S || {};
    var currentSeed = readSeedFromApp();
    if (seedComplete(currentSeed)) {
      // financials already cached but the current model was built without them → refresh if pristine
      if (!isUserModified() && !PL.savedJson && PL.model && PL.model.seed && PL.model.seed.source.indexOf("reported financials") < 0) {
        PL.model = M().plCreateModel(currentSeed);
        render();
      }
      return;
    }
    if (!S.ticker || typeof window.loadFinancials !== "function" || PL.loadingSeed) return;
    PL.loadingSeed = true;
    renderStatus(PL.lastOutlook);
    Promise.resolve(window.loadFinancials(S.ticker)).catch(function () { /* keep quote-only seed */ }).then(function () {
      PL.loadingSeed = false;
      if (!PL.model || PL.model.ticker !== ticker) return;
      var s2 = readSeedFromApp();
      if (!seedComplete(s2)) { renderStatus(PL.lastOutlook); return; }
      if (!isUserModified() && !PL.savedJson) {
        s2.horizon = PL.model.selectedHorizon;
        PL.model = M().plCreateModel(s2);
        render();
      } else {
        PL.seedHintShown = true; // offer, never overwrite
        renderStatus(PL.lastOutlook);
      }
    });
  }

  function seedFromApp(force) { if (force) performReseed(false); else if (window.S && window.S.ticker) mount(PL.container || "il-projlab-mount"); }

  window.ProjectionLab = {
    mount: mount,
    seedFromApp: seedFromApp,
    render: render,
    _state: function () { return PL.model; },
  };

  /* ═══════════════════════ styles — Implied Lens tokens, both themes ═══════════════════════ */
  function injectCSS() {
    if (document.getElementById("plab2-css")) return;
    var old = document.getElementById("plab-css");
    if (old) old.remove();
    var css = "" +
      ".plab2{--pl-bear:#C76B70;--pl-bull:#2F9C6A;color:var(--text);font-family:var(--sans,'DM Sans',Arial);}" +
      "html[data-theme='dark'] .plab2{--pl-bear:#E08A8F;--pl-bull:#4FD39A;}" +
      ".plab2 .sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0;}" +

      /* head */
      ".plab2-head{display:flex;flex-wrap:wrap;justify-content:space-between;align-items:flex-start;gap:10px 18px;margin-bottom:6px;}" +
      ".plab2-id-row{display:flex;align-items:baseline;gap:12px;}" +
      ".plab2-tk{font:800 2rem/1 var(--serif,'Space Grotesk');color:var(--gold-bright);letter-spacing:.01em;}" +
      ".plab2-kicker{font:700 .66rem var(--sans);letter-spacing:.16em;text-transform:uppercase;color:var(--text5);}" +
      ".plab2-co{font:500 .82rem var(--sans);color:var(--text4);margin-top:2px;}" +
      ".plab2-status{display:flex;flex-wrap:wrap;gap:6px;align-items:center;justify-content:flex-end;max-width:60%;}" +
      ".plab2-chip{display:inline-flex;align-items:center;gap:5px;font:600 .62rem var(--sans);letter-spacing:.03em;color:var(--text4);border:1px solid var(--border2);border-radius:999px;padding:3px 10px;background:var(--t-panel-bg,transparent);}" +
      ".plab2-chip i{font-size:.72rem;}" +
      ".plab2-chip-edit{color:var(--gold-bright);border-color:var(--gold-ring);}" +
      ".plab2-chip-unsaved{color:var(--gold-bright);border-style:dashed;border-color:var(--gold-ring);}" +
      ".plab2-chip-saved{color:var(--green);}" +
      ".plab2-chip-warn{color:var(--red);border-color:color-mix(in srgb,var(--red) 40%,transparent);}" +
      ".plab2-chip-gold{color:var(--gold-bright);border-color:var(--gold-ring);background:var(--gold-tint);}" +
      ".plab2-chip-dim{opacity:.7;}" +
      ".plab2-spin{display:inline-block;animation:plab2spin 1s linear infinite;}@keyframes plab2spin{to{transform:rotate(360deg)}}" +

      /* how it works */
      ".plab2-how{margin:0 0 14px;}" +
      ".plab2-how summary{cursor:pointer;font:600 .7rem var(--sans);letter-spacing:.04em;color:var(--text5);list-style:none;display:inline-flex;align-items:center;gap:5px;}" +
      ".plab2-how summary::before{content:'›';transition:transform .15s;display:inline-block;color:var(--gold-bright);}" +
      ".plab2-how[open] summary::before{transform:rotate(90deg);}" +
      ".plab2-how summary::-webkit-details-marker{display:none;}" +
      ".plab2-how-body{font:500 .74rem/1.6 var(--sans);color:var(--text4);max-width:70ch;padding:8px 0 2px 14px;border-left:2px solid var(--gold-tint2);margin-top:6px;}" +

      /* top grid: foundation + outcome */
      ".plab2-top{display:grid;grid-template-columns:minmax(0,1.15fr) minmax(0,1fr);gap:14px;margin-bottom:14px;align-items:stretch;}" +
      ".plab2-found{background:var(--card);border:1px solid var(--border2);border-radius:var(--r3,10px);padding:14px 16px 12px;box-shadow:var(--shadow-sm);}" +
      ".plab2-panel-h{display:flex;justify-content:space-between;align-items:baseline;font:700 .68rem var(--sans);letter-spacing:.12em;text-transform:uppercase;color:var(--gold-amber);margin-bottom:12px;}" +
      "html[data-theme='dark'] .plab2-panel-h{color:var(--gold-hi);}" +
      ".plab2-panel-sub{font:600 .6rem var(--sans);letter-spacing:.08em;color:var(--text5);text-transform:none;}" +
      ".plab2-fgrid{display:grid;grid-template-columns:1fr 1fr;gap:10px 12px;}" +
      ".plab2-flabel-row{display:flex;align-items:center;gap:6px;margin-bottom:4px;}" +
      ".plab2-flabel{font:600 .6rem var(--sans);letter-spacing:.08em;text-transform:uppercase;color:var(--text5);}" +
      ".plab2-fbox{position:relative;display:flex;align-items:center;border:1px solid var(--border2);border-radius:var(--r2,6px);background:var(--t-metric-bg);transition:border-color .15s,box-shadow .15s;}" +
      ".plab2-fbox:focus-within{border-color:var(--gold-bright);box-shadow:0 0 0 2px var(--gold-ring);}" +
      ".plab2-fbox.edited{border-color:var(--gold-ring);background:var(--gold-tint);}" +
      ".plab2-fbox.invalid{border-color:var(--red);}" +
      ".plab2-fbox input{flex:1;min-width:0;background:transparent;border:0;color:var(--text);font:700 .88rem var(--sans);font-variant-numeric:tabular-nums;padding:.5rem .6rem;outline:none;}" +
      ".plab2-freset{border:0;background:transparent;color:var(--gold-bright);font-size:.85rem;padding:.3rem .5rem;cursor:pointer;border-radius:var(--r2,6px);}" +
      ".plab2-freset:hover{background:var(--gold-tint2);}" +
      ".plab2-fmeta{display:flex;justify-content:space-between;gap:8px;margin-top:3px;min-height:.9em;}" +
      ".plab2-fstate{font:600 .56rem var(--sans);letter-spacing:.08em;text-transform:uppercase;color:var(--text5);}" +
      ".plab2-fbox.edited~.plab2-fmeta .plab2-fstate,.plab2-field .edited+.plab2-fmeta .plab2-fstate{color:var(--gold-bright);}" +
      ".plab2-ferr{font:600 .62rem var(--sans);color:var(--red);text-align:right;}" +
      ".plab2-derived{display:flex;flex-wrap:wrap;align-items:baseline;gap:8px;margin-top:12px;padding-top:10px;border-top:1px dashed var(--border2);font:500 .72rem var(--sans);color:var(--text4);}" +
      ".plab2-derived strong{color:var(--text);font-variant-numeric:tabular-nums;}" +
      ".plab2-dsep{color:var(--text5);}" +
      ".plab2-dhint{font:500 .6rem var(--sans);color:var(--text5);margin-left:auto;}" +
      ".plab2-dtag{font:700 .54rem var(--sans);letter-spacing:.06em;text-transform:uppercase;color:var(--gold-bright);border:1px solid var(--gold-ring);border-radius:4px;padding:0 4px;}" +

      /* tooltips */
      ".plab2-ftip{position:relative;display:inline-flex;color:var(--text5);cursor:help;border-radius:4px;}" +
      ".plab2-ftip:focus-visible{outline:2px solid var(--gold-ring);outline-offset:1px;}" +
      ".plab2-ftip::after{content:attr(data-tip);position:absolute;left:0;bottom:calc(100% + 7px);z-index:60;width:230px;background:var(--card);color:var(--text2);border:1px solid var(--border3);border-radius:var(--r2,6px);box-shadow:var(--shadow);padding:.55rem .65rem;font:500 .66rem/1.5 var(--sans);letter-spacing:0;text-transform:none;opacity:0;pointer-events:none;transform:translateY(3px);transition:opacity .12s,transform .12s;white-space:normal;}" +
      ".plab2-ftip:hover::after,.plab2-ftip:focus::after{opacity:1;transform:translateY(0);}" +
      ".plab2-rowtip{color:inherit;text-decoration:underline dotted var(--text5);text-underline-offset:3px;}" +

      /* outcome */
      ".plab2-outcome{border:1px solid var(--gold-ring);border-radius:var(--r3,10px);padding:16px 18px;background:radial-gradient(130% 150% at 88% -25%,var(--gold-tint2),transparent 55%),var(--card);box-shadow:var(--shadow-sm);display:flex;flex-direction:column;justify-content:center;gap:6px;min-height:170px;}" +
      ".plab2-oc-kicker{font:700 .64rem var(--sans);letter-spacing:.14em;text-transform:uppercase;color:var(--gold-amber);display:flex;flex-wrap:wrap;gap:8px;align-items:center;}" +
      "html[data-theme='dark'] .plab2-oc-kicker{color:var(--gold-hi);}" +
      ".plab2-oc-flag{font:600 .56rem var(--sans);letter-spacing:.05em;color:var(--text5);border:1px solid var(--border2);border-radius:999px;padding:1px 8px;text-transform:none;}" +
      ".plab2-oc-range{font:800 clamp(1.6rem,3.2vw,2.15rem)/1.1 var(--serif,'Space Grotesk');color:var(--text);font-variant-numeric:tabular-nums;letter-spacing:-.01em;}" +
      ".plab2-oc-range span{color:var(--text5);font-weight:500;}" +
      ".plab2-oc-mid{font:600 .84rem var(--sans);color:var(--text3);}" +
      ".plab2-oc-mid strong{color:var(--gold-bright);font-variant-numeric:tabular-nums;}" +
      ".plab2-oc-cagr{font:600 .78rem var(--sans);color:var(--text3);font-variant-numeric:tabular-nums;}" +
      ".plab2-oc-stats{display:flex;flex-wrap:wrap;gap:6px 16px;font:600 .7rem var(--sans);color:var(--text4);margin-top:4px;padding-top:8px;border-top:1px dashed var(--border2);font-variant-numeric:tabular-nums;}" +
      ".plab2-oc-nm{font:800 1.3rem var(--serif,'Space Grotesk');color:var(--text);}" +
      ".plab2-oc-sub{font:500 .76rem/1.5 var(--sans);color:var(--text4);}" +

      /* controls */
      ".plab2-ctrl{display:flex;flex-wrap:wrap;align-items:center;gap:10px 14px;margin-bottom:12px;}" +
      ".plab2-tabs{display:inline-flex;background:var(--t-panel-bg);border:1px solid var(--border2);border-radius:var(--r3,10px);padding:3px;gap:3px;}" +
      ".plab2-tab{display:inline-flex;align-items:center;gap:7px;border:1px solid transparent;background:transparent;color:var(--text4);font:700 .78rem var(--sans);padding:.48rem 1.05rem;border-radius:var(--r2,6px);cursor:pointer;transition:background .14s,color .14s;min-height:36px;}" +
      ".plab2-tab-dot{width:7px;height:7px;border-radius:50%;background:currentColor;opacity:.55;}" +
      ".plab2-tab-bear .plab2-tab-dot,.plab2-card-bear .plab2-tab-dot{background:var(--pl-bear);opacity:1;}" +
      ".plab2-tab-base .plab2-tab-dot,.plab2-card-base .plab2-tab-dot{background:var(--gold-bright);opacity:1;}" +
      ".plab2-tab-bull .plab2-tab-dot,.plab2-card-bull .plab2-tab-dot{background:var(--pl-bull);opacity:1;}" +
      ".plab2-tab.active{color:var(--text);background:var(--card);border-color:var(--border3);box-shadow:var(--shadow-sm);font-weight:800;}" +
      ".plab2-tab-bear.active{border-color:color-mix(in srgb,var(--pl-bear) 55%,transparent);}" +
      ".plab2-tab-base.active{border-color:var(--gold-ring);}" +
      ".plab2-tab-bull.active{border-color:color-mix(in srgb,var(--pl-bull) 55%,transparent);}" +
      ".plab2-scen-desc{font:500 .7rem var(--sans);color:var(--text5);flex:1;min-width:180px;}" +
      ".plab2-horizon{display:inline-flex;align-items:center;gap:6px;font:600 .6rem var(--sans);letter-spacing:.1em;text-transform:uppercase;color:var(--text5);margin-left:auto;}" +
      ".plab2-yr{border:1px solid var(--border2);background:var(--t-panel-bg);color:var(--text4);border-radius:var(--r2,6px);padding:.4rem .7rem;font:700 .72rem var(--sans);cursor:pointer;min-height:32px;}" +
      ".plab2-yr.active{background:var(--gold-bright);color:#17130C;border-color:var(--gold-bright);}" +

      ".plab2-error{display:flex;align-items:center;gap:8px;padding:.7rem .9rem;border:1px solid color-mix(in srgb,var(--red) 45%,transparent);background:var(--red-t,rgba(169,79,85,.08));border-radius:var(--r2,6px);color:var(--red);font:600 .78rem var(--sans);margin-bottom:12px;}" +
      ".plab2-error[hidden]{display:none;}" +

      /* chart */
      ".plab2-chart{position:relative;background:var(--card);border:1px solid var(--border2);border-radius:var(--r3,10px);padding:12px 14px 8px;margin-bottom:14px;box-shadow:var(--shadow-sm);}" +
      ".plab2-chart-h{display:flex;flex-wrap:wrap;justify-content:space-between;gap:6px;font:700 .64rem var(--sans);letter-spacing:.1em;text-transform:uppercase;color:var(--text5);margin-bottom:6px;}" +
      ".plab2-chart-leg{display:inline-flex;align-items:center;gap:6px;font:600 .58rem var(--sans);letter-spacing:.03em;text-transform:none;color:var(--text5);}" +
      ".plab2-leg-band,.plab2-leg-mid,.plab2-leg-ref{display:inline-block;width:14px;height:8px;border-radius:2px;}" +
      ".plab2-leg-band{background:var(--gold-tint2);}" +
      ".plab2-leg-mid{height:2px;background:var(--gold-bright);}" +
      ".plab2-leg-ref{height:0;border-top:2px dashed var(--text5);}" +
      ".plab2-chart svg{display:block;width:100%;height:auto;}" +
      ".plab2-cgrid{stroke:var(--border);stroke-width:1;}" +
      ".plab2-clbl{fill:var(--text5);font:500 11px var(--sans);}" +
      ".plab2-cband{fill:var(--gold-tint2);stroke:var(--gold-ring);stroke-width:1;}" +
      ".plab2-cmid{fill:none;stroke:var(--gold-bright);stroke-width:2.25;stroke-linejoin:round;}" +
      ".plab2-cref{stroke:var(--text5);stroke-width:1.2;stroke-dasharray:5 5;}" +
      ".plab2-cdot{fill:var(--gold-bright);}" +
      ".plab2-czones rect{outline:none;}" +
      ".plab2-czones rect:focus-visible{stroke:var(--gold-ring);stroke-width:2;}" +
      ".plab2-ctt{position:absolute;top:34px;transform:translateX(-50%);background:var(--card);border:1px solid var(--border3);border-radius:var(--r2,6px);box-shadow:var(--shadow);padding:.5rem .65rem;font:500 .68rem/1.5 var(--sans);color:var(--text2);pointer-events:none;z-index:50;font-variant-numeric:tabular-nums;white-space:nowrap;}" +
      ".plab2-ctt strong{display:block;color:var(--gold-bright);font-size:.62rem;letter-spacing:.06em;text-transform:uppercase;margin-bottom:2px;}" +
      ".plab2-chart-empty{padding:1.4rem .4rem;font:600 .78rem var(--sans);color:var(--text4);}" +

      /* table */
      ".plab2-twrap{overflow-x:auto;-webkit-overflow-scrolling:touch;border:1px solid var(--border2);border-radius:var(--r3,10px);background:var(--card);margin-bottom:14px;box-shadow:var(--shadow-sm);}" +
      ".plab2-table{border-collapse:separate;border-spacing:0;width:100%;min-width:max-content;font-variant-numeric:tabular-nums;}" +
      ".plab2-table th,.plab2-table td{padding:.48rem .75rem;text-align:right;white-space:nowrap;border-bottom:1px solid var(--border);font-size:.8rem;}" +
      ".plab2-table thead th{position:sticky;top:0;z-index:2;background:var(--panel);font:700 .7rem var(--sans);color:var(--gold-amber);border-bottom:1px solid var(--border2);}" +
      "html[data-theme='dark'] .plab2-table thead th{color:var(--gold-hi);}" +
      ".plab2-rowlbl{text-align:left!important;font:600 .66rem var(--sans);letter-spacing:.05em;text-transform:uppercase;color:var(--text4);position:sticky;left:0;z-index:1;background:var(--card);border-right:1px solid var(--border);max-width:170px;}" +
      ".plab2-table thead .plab2-rowlbl{background:var(--panel);z-index:3;}" +
      ".plab2-sec td{background:var(--t-panel-bg);color:var(--text5);font:700 .58rem var(--sans);letter-spacing:.14em;text-transform:uppercase;text-align:left;padding:.35rem .75rem;border-bottom:1px solid var(--border2);position:sticky;left:0;}" +
      ".plab2-basecol{background:var(--t-metric-bg);color:var(--text3);}" +
      ".plab2-baseyr{font-weight:800;color:var(--text2);}" +
      "th.plab2-basecol small{display:block;font-size:.52rem;letter-spacing:.1em;text-transform:uppercase;opacity:.65;}" +
      ".plab2-out{color:var(--text);font-weight:600;}" +
      ".plab2-r-revenue .plab2-out,.plab2-r-eps .plab2-out{font-weight:700;}" +
      ".plab2-band-low .plab2-out{color:var(--pl-bear);}" +
      ".plab2-band-high .plab2-out{color:var(--pl-bull);}" +
      ".plab2-r-cagrLow .plab2-out,.plab2-r-cagrHigh .plab2-out{font-weight:800;}" +
      ".plab2-out.negearn{color:var(--text5);font-weight:600;}" +
      ".plab2-incell{background:var(--gold-tint);}" +
      ".plab2-cin{width:64px;background:transparent;border:0;border-bottom:1.5px solid var(--gold-ring);color:var(--text);font:700 .8rem var(--sans);font-variant-numeric:tabular-nums;padding:.18rem .1rem;text-align:right;outline:none;transition:border-color .12s;border-radius:0;}" +
      ".plab2-cin:focus{border-bottom-color:var(--gold-bright);background:var(--gold-tint2);}" +
      ".plab2-cin.invalid{border-bottom-color:var(--red);color:var(--red);}" +
      ".plab2-sfx{font:600 .6rem var(--sans);color:var(--text5);margin-left:2px;}" +

      /* comparison cards + expected */
      ".plab2-cards{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px;margin-bottom:10px;}" +
      ".plab2-card{text-align:left;border:1px solid var(--border2);border-radius:var(--r3,10px);padding:.85rem .95rem;cursor:pointer;background:var(--card);transition:border-color .14s,box-shadow .14s;font-family:var(--sans);color:var(--text);box-shadow:var(--shadow-sm);}" +
      ".plab2-card:hover{border-color:var(--border3);}" +
      ".plab2-card.active{border-color:var(--gold-bright);box-shadow:0 0 0 1px var(--gold-bright) inset,var(--shadow-sm);}" +
      ".plab2-card-bear.active{border-color:var(--pl-bear);box-shadow:0 0 0 1px var(--pl-bear) inset,var(--shadow-sm);}" +
      ".plab2-card-bull.active{border-color:var(--pl-bull);box-shadow:0 0 0 1px var(--pl-bull) inset,var(--shadow-sm);}" +
      ".plab2-card-h{display:flex;align-items:center;gap:7px;font:700 .72rem var(--sans);letter-spacing:.04em;margin-bottom:6px;color:var(--text2);}" +
      ".plab2-card-yr{margin-left:auto;font:600 .6rem var(--sans);color:var(--text5);}" +
      ".plab2-card-px{font:800 1.12rem var(--serif,'Space Grotesk');color:var(--text);font-variant-numeric:tabular-nums;}" +
      ".plab2-card-px.plab2-card-nm{font:700 .85rem var(--sans);color:var(--text4);}" +
      ".plab2-card-cagr{font:700 .76rem var(--sans);color:var(--text3);margin-top:2px;font-variant-numeric:tabular-nums;}" +
      ".plab2-card-cagr small{font-weight:600;opacity:.55;}" +
      ".plab2-card-stats{display:flex;gap:12px;font:600 .66rem var(--sans);color:var(--text4);margin-top:7px;font-variant-numeric:tabular-nums;}" +
      ".plab2-card-sum{font:500 .6rem/1.5 var(--sans);color:var(--text5);margin-top:6px;padding-top:6px;border-top:1px dashed var(--border);}" +
      ".plab2-exp{border:1px dashed var(--gold-ring);border-radius:var(--r3,10px);padding:.75rem .95rem;display:flex;flex-wrap:wrap;align-items:center;gap:8px 18px;background:var(--gold-tint);margin-bottom:2px;}" +
      ".plab2-exp-l{display:flex;flex-direction:column;gap:2px;}" +
      ".plab2-exp-t{font:700 .62rem var(--sans);letter-spacing:.1em;text-transform:uppercase;color:var(--gold-amber);display:inline-flex;align-items:center;gap:6px;}" +
      "html[data-theme='dark'] .plab2-exp-t{color:var(--gold-hi);}" +
      ".plab2-exp-w{font:600 .68rem var(--sans);color:var(--text4);}" +
      ".plab2-exp-edit{border:0;background:transparent;color:var(--gold-bright);font:700 .62rem var(--sans);cursor:pointer;text-decoration:underline;text-underline-offset:2px;padding:2px 4px;border-radius:4px;}" +
      ".plab2-exp-v{margin-left:auto;font:800 1.05rem var(--serif,'Space Grotesk');color:var(--text);font-variant-numeric:tabular-nums;display:flex;align-items:baseline;gap:8px;}" +
      ".plab2-exp-v strong{color:var(--gold-bright);}" +
      ".plab2-exp-v span{font:600 .7rem var(--sans);color:var(--text4);}" +
      ".plab2-exp-nm{font:600 .8rem var(--sans);color:var(--text4);}" +
      ".plab2-weditor{display:flex;flex-wrap:wrap;align-items:center;gap:10px;width:100%;padding-top:8px;border-top:1px dashed var(--gold-ring);}" +
      ".plab2-weditor label{display:inline-flex;align-items:center;gap:5px;font:600 .66rem var(--sans);color:var(--text4);}" +
      ".plab2-weditor input{width:52px;background:var(--card);border:1px solid var(--border2);border-radius:var(--r2,6px);color:var(--text);font:700 .76rem var(--sans);padding:.3rem .4rem;text-align:right;font-variant-numeric:tabular-nums;}" +
      ".plab2-weditor input:focus{outline:none;border-color:var(--gold-bright);box-shadow:0 0 0 2px var(--gold-ring);}" +
      ".plab2-wtotal{font:700 .68rem var(--sans);color:var(--green);margin-left:auto;}" +
      ".plab2-wtotal.bad{color:var(--red);}" +

      /* actions */
      ".plab2-actions{display:flex;flex-wrap:wrap;align-items:center;gap:8px;margin-top:14px;}" +
      ".plab2-spacer{flex:1;}" +
      ".plab2-btn{display:inline-flex;align-items:center;gap:6px;border:1px solid var(--border2);background:var(--card);color:var(--text2);font:700 .74rem var(--sans);padding:.52rem .95rem;border-radius:var(--r2,6px);cursor:pointer;min-height:38px;transition:border-color .14s,background .14s;}" +
      ".plab2-btn:hover{border-color:var(--gold-ring);}" +
      ".plab2-btn:focus-visible{outline:2px solid var(--gold-ring);outline-offset:2px;}" +
      ".plab2-btn-gold{background:var(--gold-bright);color:#17130C;border-color:var(--gold-bright);}" +
      ".plab2-btn-gold:hover{background:var(--gold-hi);border-color:var(--gold-hi);}" +
      ".plab2-confirm{margin-top:10px;border:1px solid var(--gold-ring);background:var(--gold-tint);border-radius:var(--r2,6px);padding:.7rem .9rem;}" +
      ".plab2-confirm-t{font:600 .74rem var(--sans);color:var(--text2);display:flex;align-items:center;gap:7px;margin-bottom:8px;}" +
      ".plab2-confirm-b{display:flex;flex-wrap:wrap;gap:8px;}" +
      ".plab2-note{margin-top:10px;font:500 .64rem/1.6 var(--sans);color:var(--text5);}" +
      ".plab2-toast{position:fixed;left:50%;bottom:80px;transform:translateX(-50%) translateY(10px);background:var(--card);color:var(--text);border:1px solid var(--border3);padding:.6rem 1rem;border-radius:var(--r3,10px);font:600 .8rem var(--sans);opacity:0;transition:.2s;z-index:99999;box-shadow:var(--shadow);}" +
      ".plab2-toast.show{opacity:1;transform:translateX(-50%) translateY(0);}" +

      /* responsive */
      "@media(max-width:980px){.plab2-top{grid-template-columns:1fr;}.plab2-status{max-width:100%;justify-content:flex-start;}.plab2-horizon{margin-left:0;}}" +
      "@media(max-width:680px){" +
        ".plab2-fgrid{grid-template-columns:1fr;}" +
        ".plab2-cards{grid-template-columns:1fr;}" +
        ".plab2-tab{padding:.55rem .9rem;min-height:44px;}" +
        ".plab2-yr{min-height:40px;padding:.45rem .8rem;}" +
        ".plab2-cin{width:58px;font-size:.78rem;min-height:32px;}" +
        ".plab2-table th,.plab2-table td{padding:.44rem .55rem;}" +
        ".plab2-exp-v{margin-left:0;width:100%;}" +
        ".plab2-oc-range{font-size:1.5rem;}" +
      "}" +
      "@media(prefers-reduced-motion:reduce){.plab2 *,.plab2 *::before,.plab2 *::after{transition:none!important;animation:none!important;}}";
    var s = el("style"); s.id = "plab2-css"; s.textContent = css; document.head.appendChild(s);
  }
})();

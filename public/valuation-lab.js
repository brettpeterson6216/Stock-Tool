/* ImpliedLens — Valuation Lab (Phase 1: standard operating company)
   Projects the operating business (revenue → margins → EBIT → tax → net income,
   FCFF, dilution), then values it with DCF / exit P/E / exit EV/EBITDA, blends
   the methods, runs Bear/Base/Bull with probability weighting, and adds an
   interactive sensitivity grid plus reverse "what's priced in?" solving.
   Self-contained (injects its own CSS). Wires into #body-dcf. */
(function () {
  "use strict";
  var M = function () { return window.ImpliedLensMath; };
  var SCEN = ["bear", "base", "bull"], SLAB = { bear: "Bear", base: "Base", bull: "Bull" };
  var LS = "il-vlab:";
  var VL = { state: null, container: null, results: null };

  /* ---- helpers ---- */
  function el(t, c, h) { var n = document.createElement(t); if (c) n.className = c; if (h != null) n.innerHTML = h; return n; }
  function n(v) { var x = Number(v); return Number.isFinite(x) ? x : NaN; }
  function raw(v) { if (v == null) return NaN; if (typeof v === "number") return v; if (typeof v === "object" && v.raw != null) return Number(v.raw); return Number(v); }
  function fmtB(v) { if (!Number.isFinite(v)) return "—"; var s = v < 0 ? "-" : ""; v = Math.abs(v); if (v >= 1e12) return s + "$" + (v / 1e12).toFixed(2) + "T"; if (v >= 1e9) return s + "$" + (v / 1e9).toFixed(2) + "B"; if (v >= 1e6) return s + "$" + (v / 1e6).toFixed(1) + "M"; if (v >= 1e3) return s + "$" + (v / 1e3).toFixed(0) + "K"; return s + "$" + v.toFixed(0); }
  function fmt$(v, d) { if (!Number.isFinite(v)) return "—"; return "$" + v.toLocaleString("en-US", { minimumFractionDigits: d == null ? 2 : d, maximumFractionDigits: d == null ? 2 : d }); }
  function pctS(x, d) { if (x == null || !Number.isFinite(x)) return "—"; return (x >= 0 ? "" : "") + (x * 100).toFixed(d == null ? 1 : d) + "%"; }
  function signPct(x) { if (x == null || !Number.isFinite(x)) return "—"; return (x >= 0 ? "+" : "") + (x * 100).toFixed(1) + "%"; }

  /* ---- seeding from the app ---- */
  function readSeed() {
    var S = window.S || {}, meta = (S.data && S.data.meta) || {}, r = S.financialsRaw;
    var seed = { ticker: S.ticker || meta.symbol || "—", seeded: false };
    var price = raw(meta.regularMarketPrice); if (price > 0) seed.currentPrice = price;
    var pe = raw(meta.trailingPE); if (pe > 0) seed.trailingPE = pe;
    if (r) {
      var inc = (r.incomeStatementHistory && r.incomeStatementHistory.incomeStatementHistory) || [];
      var bal = (r.balanceSheetHistory && r.balanceSheetHistory.balanceSheetStatements) || [];
      var cf = (r.cashflowStatementHistory && r.cashflowStatementHistory.cashflowStatements) || [];
      var ks = r.defaultKeyStatistics || {};
      if (inc.length) {
        var a = inc[0];
        var rev = raw(a.totalRevenue), gp = raw(a.grossProfit), oi = raw(a.operatingIncome), pretax = raw(a.incomeBeforeTax), taxexp = raw(a.incomeTaxExpense), ni = raw(a.netIncome);
        if (rev > 0) { seed.startRevenue = rev; seed.seeded = true; }
        if (rev > 0 && gp > 0) seed.grossMargin = gp / rev;
        if (rev > 0 && Number.isFinite(oi)) seed.opMarginStart = oi / rev;
        if (Number.isFinite(pretax) && pretax !== 0 && Number.isFinite(taxexp)) seed.taxRate = Math.max(0, Math.min(0.5, taxexp / pretax));
        if (inc.length > 1) { var rev1 = raw(inc[1].totalRevenue); if (rev1 > 0 && rev > 0) seed.histGrowth = rev / rev1 - 1; }
        seed.hist = inc.slice(0, 4).map(function (row, i) { return { year: (r.__y || new Date().getFullYear() - i), rev: raw(row.totalRevenue), gp: raw(row.grossProfit), oi: raw(row.operatingIncome), ni: raw(row.netIncome), eps: raw(row.dilutedEPS) }; });
      }
      if (bal.length) { var b = bal[0]; var cash = raw(b.cash) + (raw(b.shortTermInvestments) || 0); var debt = (raw(b.shortLongTermDebt) || 0) + (raw(b.longTermDebt) || 0); if (Number.isFinite(cash)) seed.startCash = cash; if (Number.isFinite(debt)) seed.startDebt = debt; }
      if (cf.length) { var c = cf[0]; var dep = raw(c.depreciation), capex = Math.abs(raw(c.capitalExpenditures)); if (seed.startRevenue > 0) { if (Number.isFinite(dep)) seed.daPct = dep / seed.startRevenue; if (Number.isFinite(capex)) seed.capexPct = capex / seed.startRevenue; } }
      var sh = raw(ks.sharesOutstanding); if (sh > 0) seed.startShares = sh;
      var eb = raw(ks.ebitda); if (eb > 0 && seed.startRevenue > 0) seed.ebitdaMargin = eb / seed.startRevenue;
    }
    if (!(seed.startShares > 0) && raw(meta.marketCap) > 0 && seed.currentPrice > 0) seed.startShares = raw(meta.marketCap) / seed.currentPrice;
    return seed;
  }

  /* ---- default assumptions ---- */
  function clamp(v, a, b) { return Math.max(a, Math.min(b, v)); }
  function baseInputs(seed) {
    var gm = Number.isFinite(seed.grossMargin) ? seed.grossMargin : 0.6;
    var om = Number.isFinite(seed.opMarginStart) ? seed.opMarginStart : 0.15;
    var g = Number.isFinite(seed.histGrowth) ? clamp(seed.histGrowth, -0.1, 0.6) : 0.12;
    return {
      startRevenue: seed.startRevenue > 0 ? seed.startRevenue : 1e9,
      revGrowthEarly: +(g * 100).toFixed(1), revGrowthLate: +(g * 0.6 * 100).toFixed(1),
      grossMargin: +(gm * 100).toFixed(1),
      opMarginStart: +(om * 100).toFixed(1), opMarginTargetY5: +(clamp(om + 0.05, -0.2, 0.5) * 100).toFixed(1), opMarginLongTerm: +(clamp(om + 0.06, -0.2, 0.5) * 100).toFixed(1),
      taxRate: Number.isFinite(seed.taxRate) ? +(seed.taxRate * 100).toFixed(1) : 21,
      dilution: 1.5,
      capexPct: Number.isFinite(seed.capexPct) ? +(seed.capexPct * 100).toFixed(1) : 4,
      daPct: Number.isFinite(seed.daPct) ? +(seed.daPct * 100).toFixed(1) : 5,
      wcPct: 2, sbcPct: 3, interestRate: 5,
      startCash: seed.startCash > 0 ? Math.round(seed.startCash) : 0,
      startDebt: seed.startDebt > 0 ? Math.round(seed.startDebt) : 0,
      discountRate: 9, terminalGrowth: 3, exitPE: seed.trailingPE > 0 ? Math.round(clamp(seed.trailingPE, 8, 40)) : 20, exitEVEBITDA: 15,
      currentPrice: seed.currentPrice > 0 ? +seed.currentPrice.toFixed(2) : 100,
      currentDilutedShares: seed.startShares > 0 ? Math.round(seed.startShares) : 1e9,
      revGrowthPerYear: null, opMarginPerYear: null,
    };
  }
  function deriveScenario(baseRaw, kind) {
    var base = {}; Object.keys(baseRaw).forEach(function (k) { var v = baseRaw[k]; base[k] = (v !== null && v !== "" && !isNaN(v) && !Array.isArray(v)) ? Number(v) : v; });
    var s = Object.assign({}, base);
    if (kind === "bear") { s.revGrowthEarly = +(base.revGrowthEarly * 0.55).toFixed(1); s.revGrowthLate = +(base.revGrowthLate * 0.55).toFixed(1); s.opMarginTargetY5 = +(base.opMarginTargetY5 - 6).toFixed(1); s.opMarginLongTerm = +(base.opMarginLongTerm - 6).toFixed(1); s.exitPE = Math.max(6, Math.round(base.exitPE * 0.7)); s.exitEVEBITDA = Math.max(4, Math.round(base.exitEVEBITDA * 0.7)); s.discountRate = base.discountRate + 2; s.dilution = base.dilution + 1; }
    else if (kind === "bull") { s.revGrowthEarly = +(base.revGrowthEarly * 1.4).toFixed(1); s.revGrowthLate = +(base.revGrowthLate * 1.4).toFixed(1); s.opMarginTargetY5 = +(base.opMarginTargetY5 + 6).toFixed(1); s.opMarginLongTerm = +(base.opMarginLongTerm + 6).toFixed(1); s.exitPE = Math.round(base.exitPE * 1.3); s.exitEVEBITDA = Math.round(base.exitEVEBITDA * 1.3); s.discountRate = Math.max(5, base.discountRate - 1); s.dilution = Math.max(0, base.dilution - 0.5); }
    return s;
  }
  function defaultState(seed) {
    var base = baseInputs(seed);
    return {
      ticker: seed.ticker || "—", modelType: "standard", mode: "simple", years: 5, active: "base",
      hist: seed.hist || null,
      scenarios: { bear: deriveScenario(base, "bear"), base: base, bull: deriveScenario(base, "bull") },
      weights: { bear: 25, base: 50, bull: 25 },
      methodWeights: { dcf: 50, pe: 30, evebitda: 20 },
      sens: { x: "discountRate", y: "terminalGrowth" },
      reverse: "revGrowth",
      seeded: !!seed.seeded,
    };
  }

  /* ---- build engine input from a scenario ---- */
  function engInput(scKey) {
    var st = VL.state, s = st.scenarios[scKey];
    var p = function (x) { return n(x) / 100; };  // whole-number percent -> decimal
    var inp = {
      years: st.years, baseYear: new Date().getFullYear(),
      startRevenue: n(s.startRevenue), startShares: n(s.currentDilutedShares),
      grossMargin: p(s.grossMargin),
      opMarginStart: p(s.opMarginStart), opMarginTargetY5: p(s.opMarginTargetY5), opMarginLongTerm: p(s.opMarginLongTerm),
      taxRate: p(s.taxRate), dilution: p(s.dilution),
      capexPct: p(s.capexPct), daPct: p(s.daPct), wcPct: p(s.wcPct), sbcPct: p(s.sbcPct),
      startCash: n(s.startCash), startDebt: n(s.startDebt), interestRate: p(s.interestRate),
      discountRate: p(s.discountRate), terminalGrowth: p(s.terminalGrowth),
      exitPE: n(s.exitPE), exitEVEBITDA: n(s.exitEVEBITDA),
      currentPrice: n(s.currentPrice), currentDilutedShares: n(s.currentDilutedShares),
      methodWeights: st.methodWeights,
    };
    if (st.mode === "advanced" && Array.isArray(s.revGrowthPerYear) && s.revGrowthPerYear.length) inp.revGrowth = s.revGrowthPerYear.slice(0, st.years).map(p);
    else inp.revGrowth = { early: p(s.revGrowthEarly), late: p(s.revGrowthLate) };
    return inp;
  }
  function computeAll() {
    return M().runValuationScenarios({ scenarios: { bear: engInput("bear"), base: engInput("base"), bull: engInput("bull") }, weights: { bear: VL.state.weights.bear / 100, base: VL.state.weights.base / 100, bull: VL.state.weights.bull / 100 } });
  }

  /* ---- validation ---- */
  function validate() {
    var st = VL.state, w = [];
    SCEN.forEach(function (k) {
      var s = st.scenarios[k], L = SLAB[k];
      if (n(s.terminalGrowth) >= n(s.discountRate)) w.push({ sev: "err", t: L + ": terminal growth (" + s.terminalGrowth + "%) ≥ discount rate (" + s.discountRate + "%). Terminal value is invalid." });
      if (n(s.opMarginTargetY5) > 45) w.push({ sev: "warn", t: L + ": Year-5 operating margin above 45% is rare — verify it's achievable." });
      if (n(s.revGrowthLate) > 40) w.push({ sev: "warn", t: L + ": >40% growth sustained into Years 6–10 is extremely optimistic." });
      if (n(s.taxRate) < 0) w.push({ sev: "warn", t: L + ": negative tax rate — only valid with large loss carry-forwards." });
      if (n(s.dilution) < 0 && n(s.dilution) < -5) w.push({ sev: "warn", t: L + ": buybacks above 5%/yr are aggressive to sustain." });
      if (n(s.exitPE) > 60) w.push({ sev: "warn", t: L + ": exit P/E above 60x is far above typical mature multiples." });
    });
    var wt = st.weights.bear + st.weights.base + st.weights.bull;
    if (Math.abs(wt - 100) > 0.5) w.push({ sev: "warn", t: "Scenario probabilities total " + wt + "% (should be 100%)." });
    return w;
  }

  /* ---- persistence ---- */
  function save() { try { localStorage.setItem(LS + VL.state.ticker, JSON.stringify(VL.state)); saToast("Valuation saved for " + VL.state.ticker); if (typeof window.saveValuationToAnalyses === "function") window.saveValuationToAnalyses(VL.state); } catch (e) { saToast("Could not save."); } }
  function loadSaved(tk) { try { var r = localStorage.getItem(LS + tk); if (r) return JSON.parse(r); } catch (e) { } return null; }
  function saToast(m) { if (typeof window.toast === "function") { window.toast(m, "green"); return; } var t = el("div", "vlab-toast", m); document.body.appendChild(t); setTimeout(function () { t.classList.add("show"); }, 10); setTimeout(function () { t.remove(); }, 2400); }

  window.ValuationLab = {
    mount: function (container) {
      injectCSS();
      VL.container = typeof container === "string" ? document.getElementById(container) : container;
      if (!VL.container) return;
      if (!M() || typeof M().runValuationScenarios !== "function") { VL.container.innerHTML = '<div class="vlab-err">Valuation engine unavailable — please reload.</div>'; return; }
      try {
        var seed = readSeed();
        var saved = loadSaved(seed.ticker);
        VL.state = (saved && saved.scenarios) ? saved : defaultState(seed);
        VL.state.ticker = seed.ticker;
        render();
      } catch (e) { if (window.console) console.error("ValuationLab", e); VL.container.innerHTML = '<div class="vlab-err">Could not build the model. ' + (e && e.message || "") + '</div>'; }
    },
    reseed: function () { try { var seed = readSeed(); VL.state = defaultState(seed); render(); } catch (e) { } },
    _state: function () { return VL.state; },
  };

  /* =================== RENDER =================== */
  var GROUPS = null;
  function inputRow(scKey, key, label, suffix, tip, step) {
    var v = VL.state.scenarios[scKey][key];
    return '<label class="vlab-in" title="' + (tip || "") + '"><span>' + label + '</span>' +
      '<span class="vlab-inw"><input type="number" step="' + (step || "0.1") + '" data-k="' + key + '" value="' + v + '"><em>' + (suffix || "") + '</em></span></label>';
  }
  function render() {
    var st = VL.state;
    var root = el("div", "vlab");

    /* sticky summary */
    var sum = el("div", "vlab-summary"); sum.id = "vlab-summary";
    root.appendChild(sum);

    /* header: ticker + model type + mode */
    var head = el("div", "vlab-head");
    head.innerHTML =
      '<div class="vlab-title"><span class="vlab-tk">' + st.ticker + '</span><span class="vlab-sub">Valuation Lab</span></div>' +
      '<div class="vlab-head-ctrl">' +
      '<label class="vlab-sel">Company type<select id="vlab-mtype">' +
      '<option value="standard">Standard operating company</option>' +
      '<option value="bank" disabled>Bank / fintech lender (Phase 2)</option>' +
      '<option value="reit" disabled>REIT (Phase 2)</option>' +
      '<option value="insurance" disabled>Insurance (Phase 2)</option>' +
      '<option value="prerev" disabled>Pre-revenue (Phase 2)</option>' +
      '<option value="commodity" disabled>Commodity / resources (Phase 2)</option>' +
      '</select></label>' +
      '<div class="vlab-mode"><button class="' + (st.mode === "simple" ? "active" : "") + '" data-mode="simple">Simple</button><button class="' + (st.mode === "advanced" ? "active" : "") + '" data-mode="advanced">Advanced</button></div>' +
      '<div class="vlab-hz"><span>Horizon</span><button class="' + (st.years === 5 ? "active" : "") + '" data-yr="5">5y</button><button class="' + (st.years === 10 ? "active" : "") + '" data-yr="10">10y</button></div>' +
      '</div>';
    root.appendChild(head);

    /* historical strip */
    if (st.hist && st.hist.length) {
      var h = el("div", "vlab-hist");
      h.innerHTML = '<div class="vlab-sect-h"><span class="vlab-tag vlab-tag-hist">Historical</span> Reported results (auto-filled)</div>' +
        '<div class="vlab-hist-grid">' + st.hist.map(function (x) { return '<div class="vlab-hcard"><div class="vlab-hyr">' + (x.year || "") + '</div><div>Rev ' + fmtB(x.rev) + '</div><div>Op inc ' + fmtB(x.oi) + '</div><div>Net ' + fmtB(x.ni) + '</div></div>'; }).join("") + '</div>';
      root.appendChild(h);
    }

    /* scenario tabs */
    var tabs = el("div", "vlab-scentabs");
    tabs.innerHTML = SCEN.map(function (k) { return '<button class="vlab-stab vlab-stab-' + k + (st.active === k ? " active" : "") + '" data-scen="' + k + '">' + SLAB[k] + '<em>' + st.weights[k] + '%</em></button>'; }).join("") +
      '<span class="vlab-spacer"></span><button class="vlab-mini" id="vlab-dup">Duplicate Base → Bear & Bull</button>';
    root.appendChild(tabs);

    /* assumption groups */
    var scKey = st.active;
    var body = el("div", "vlab-body"); body.id = "vlab-inputs";
    body.appendChild(assumptionGroups(scKey));
    root.appendChild(body);

    /* probabilities + method weights */
    var wt = el("div", "vlab-weights");
    wt.innerHTML =
      '<div class="vlab-wcol"><div class="vlab-sect-h">Scenario probabilities</div>' +
      SCEN.map(function (k) { return '<label class="vlab-in"><span>' + SLAB[k] + '</span><span class="vlab-inw"><input type="number" step="5" data-wt="' + k + '" value="' + st.weights[k] + '"><em>%</em></span></label>'; }).join("") + '</div>' +
      '<div class="vlab-wcol"><div class="vlab-sect-h">Valuation method weights</div>' +
      [["dcf", "FCF DCF"], ["pe", "Exit P/E"], ["evebitda", "Exit EV/EBITDA"]].map(function (m) { return '<label class="vlab-in"><span>' + m[1] + '</span><span class="vlab-inw"><input type="number" step="5" data-mw="' + m[0] + '" value="' + st.methodWeights[m[0]] + '"><em>%</em></span></label>'; }).join("") + '</div>';
    root.appendChild(wt);

    /* results mount */
    var res = el("div", "vlab-results"); res.id = "vlab-results";
    root.appendChild(res);

    /* actions */
    var act = el("div", "vlab-actions");
    act.innerHTML = '<button class="vlab-btn" id="vlab-reseed"><i class="ti ti-wand"></i> Re-seed from data</button><span class="vlab-spacer"></span>' +
      '<button class="vlab-btn" id="vlab-reset"><i class="ti ti-refresh"></i> Reset</button>' +
      '<button class="vlab-btn vlab-gold" id="vlab-save"><i class="ti ti-bookmark"></i> Save to analyses</button>';
    root.appendChild(act);
    root.appendChild(el("div", "vlab-note", "Labels: Historical = reported · Assumption = your input · Calculated = model output. Educational tool — not investment advice."));

    VL.container.innerHTML = ""; VL.container.appendChild(root);
    VL.results = document.getElementById("vlab-results");

    /* wire */
    root.querySelector("#vlab-mtype").value = st.modelType;
    Array.prototype.forEach.call(root.querySelectorAll(".vlab-mode button"), function (b) { b.onclick = function () { st.mode = b.getAttribute("data-mode"); render(); }; });
    Array.prototype.forEach.call(root.querySelectorAll(".vlab-hz button"), function (b) { b.onclick = function () { st.years = +b.getAttribute("data-yr"); render(); }; });
    Array.prototype.forEach.call(root.querySelectorAll(".vlab-stab"), function (b) { b.onclick = function () { st.active = b.getAttribute("data-scen"); render(); }; });
    root.querySelector("#vlab-dup").onclick = function () { var base = st.scenarios.base; st.scenarios.bear = deriveScenario(base, "bear"); st.scenarios.bull = deriveScenario(base, "bull"); saToast("Bear & Bull duplicated from Base"); render(); };
    Array.prototype.forEach.call(body.querySelectorAll("input[data-k]"), function (i) { i.oninput = function () { st.scenarios[st.active][i.getAttribute("data-k")] = i.value; recompute(); }; });
    Array.prototype.forEach.call(body.querySelectorAll("input[data-yk]"), function (i) { i.oninput = function () { var arr = st.scenarios[st.active][i.getAttribute("data-arr")] || []; arr[+i.getAttribute("data-yi")] = i.value; st.scenarios[st.active][i.getAttribute("data-arr")] = arr; recompute(); }; });
    Array.prototype.forEach.call(root.querySelectorAll("input[data-wt]"), function (i) { i.oninput = function () { st.weights[i.getAttribute("data-wt")] = n(i.value) || 0; recompute(); updateTabWeights(); }; });
    Array.prototype.forEach.call(root.querySelectorAll("input[data-mw]"), function (i) { i.oninput = function () { st.methodWeights[i.getAttribute("data-mw")] = n(i.value) || 0; recompute(); }; });
    root.querySelector("#vlab-reseed").onclick = function () { window.ValuationLab.reseed(); };
    root.querySelector("#vlab-reset").onclick = function () { if (confirm("Reset all assumptions to auto-seeded defaults?")) window.ValuationLab.reseed(); };
    root.querySelector("#vlab-save").onclick = save;

    recompute();
  }

  function updateTabWeights() { SCEN.forEach(function (k) { var b = VL.container.querySelector('.vlab-stab-' + k + ' em'); if (b) b.textContent = VL.state.weights[k] + "%"; }); }

  function assumptionGroups(scKey) {
    var st = VL.state, wrap = el("div");
    function group(title, tag, rows, open) {
      return '<details class="vlab-group"' + (open ? " open" : "") + '><summary>' + title + '</summary><div class="vlab-grid">' + rows + '</div></details>';
    }
    var revRows;
    if (st.mode === "advanced") {
      var s = st.scenarios[scKey];
      if (!Array.isArray(s.revGrowthPerYear) || s.revGrowthPerYear.length < st.years) { var arr = []; for (var y = 0; y < st.years; y++) arr.push(y < 5 ? s.revGrowthEarly : s.revGrowthLate); s.revGrowthPerYear = arr; }
      revRows = inputRow(scKey, "startRevenue", "Starting revenue ($)", "", "Latest annual revenue (auto-filled).", "1000000") +
        '<div class="vlab-peryear"><span>Revenue growth by year</span><div class="vlab-yrgrid">' +
        s.revGrowthPerYear.slice(0, st.years).map(function (v, i) { return '<label>Y' + (i + 1) + '<input type="number" step="0.5" data-yk="1" data-arr="revGrowthPerYear" data-yi="' + i + '" value="' + v + '"></label>'; }).join("") + '</div></div>';
    } else {
      revRows = inputRow(scKey, "startRevenue", "Starting revenue ($)", "", "Latest annual revenue (auto-filled).", "1000000") +
        inputRow(scKey, "revGrowthEarly", "Revenue growth Yr 1–5", "%", "Annual revenue growth for the first five years.", "0.5") +
        inputRow(scKey, "revGrowthLate", "Revenue growth Yr 6–10", "%", "Annual revenue growth for years six to ten.", "0.5");
    }
    var out =
      group("① Revenue", "assumption", revRows + inputRow(scKey, "grossMargin", "Gross margin", "%", "Gross profit ÷ revenue.", "0.5"), true) +
      group("② Margins", "assumption",
        inputRow(scKey, "opMarginStart", "Current operating margin", "%", "Operating income ÷ revenue today (auto-filled).") +
        inputRow(scKey, "opMarginTargetY5", "Target operating margin by Yr 5", "%", "Margins ramp smoothly from current to this by year 5.") +
        inputRow(scKey, "opMarginLongTerm", "Long-term operating margin", "%", "Steady-state margin used for years 6–10.") +
        inputRow(scKey, "taxRate", "Effective tax rate", "%", "Applied to pre-tax income.")) +
      group("③ Cash flow & balance sheet", "assumption",
        inputRow(scKey, "capexPct", "Capex", "% rev", "Capital expenditures as a % of revenue (auto-filled).") +
        inputRow(scKey, "daPct", "D&A", "% rev", "Depreciation & amortization as a % of revenue (auto-filled).") +
        inputRow(scKey, "wcPct", "Working-capital investment", "% Δrev", "Investment in working capital as a % of each year's revenue growth.") +
        inputRow(scKey, "sbcPct", "Stock-based comp", "% rev", "SBC as a % of revenue — treated as a real cost in FCF.") +
        inputRow(scKey, "startCash", "Starting cash ($)", "", "Cash & short-term investments (auto-filled).", "1000000") +
        inputRow(scKey, "startDebt", "Starting debt ($)", "", "Short + long-term debt (auto-filled).", "1000000") +
        inputRow(scKey, "interestRate", "Interest rate on debt", "%", "Used to estimate interest expense.")) +
      group("④ Dilution", "assumption",
        inputRow(scKey, "dilution", "Diluted share-count growth", "%/yr", "Net annual change in diluted shares (negative = buybacks).") +
        inputRow(scKey, "currentDilutedShares", "Diluted shares outstanding", "", "Current diluted share count (auto-filled).", "1000000")) +
      group("⑤ Valuation", "assumption",
        inputRow(scKey, "discountRate", "Discount rate (WACC)", "%", "Rate used to discount future cash flows.") +
        inputRow(scKey, "terminalGrowth", "Terminal growth", "%", "Perpetual growth after the forecast (must be below discount rate).") +
        inputRow(scKey, "exitPE", "Exit P/E", "x", "Terminal P/E applied to final-year EPS.") +
        inputRow(scKey, "exitEVEBITDA", "Exit EV/EBITDA", "x", "Terminal EV/EBITDA applied to final-year EBITDA.") +
        inputRow(scKey, "currentPrice", "Current share price ($)", "", "Auto-filled from the quote.", "0.01"), true);
    wrap.innerHTML = out;
    return wrap;
  }

  /* =================== RECOMPUTE (results only) =================== */
  function recompute() {
    var res = VL.results; if (!res) return;
    var all = computeAll();
    var sumEl = document.getElementById("vlab-summary");
    if (!all.ok) { res.innerHTML = '<div class="vlab-err">' + (all.error || "Check assumptions.") + '</div>'; if (sumEl) sumEl.innerHTML = '<div class="vlab-err">' + (all.error || "Check assumptions.") + '</div>'; return; }
    var st = VL.state, price = all.currentPrice;
    var fvBear = all.scenarios.bear.valuation.fairValue, fvBase = all.scenarios.base.valuation.fairValue, fvBull = all.scenarios.bull.valuation.fairValue, fvW = all.weightedFairValue;
    /* sticky summary */
    if (sumEl) sumEl.innerHTML =
      '<div class="vlab-scell"><span>Current</span><strong>' + fmt$(price) + '</strong></div>' +
      '<div class="vlab-scell vlab-bear"><span>Bear</span><strong>' + fmt$(fvBear) + '</strong></div>' +
      '<div class="vlab-scell vlab-base"><span>Base</span><strong>' + fmt$(fvBase) + '</strong></div>' +
      '<div class="vlab-scell vlab-bull"><span>Bull</span><strong>' + fmt$(fvBull) + '</strong></div>' +
      '<div class="vlab-scell vlab-wt"><span>Weighted</span><strong>' + fmt$(fvW) + '</strong></div>' +
      '<div class="vlab-scell"><span>Upside</span><strong class="' + (all.weightedUpside >= 0 ? "up" : "dn") + '">' + signPct(all.weightedUpside) + '</strong></div>';

    /* validation */
    var warns = validate();
    var wHtml = warns.length ? '<div class="vlab-warns">' + warns.map(function (x) { return '<div class="vlab-w vlab-w-' + x.sev + '"><i class="ti ti-alert-triangle"></i> ' + x.t + '</div>'; }).join("") + '</div>' : "";

    /* method breakdown (active scenario) */
    var av = all.scenarios[st.active].valuation, am = all.scenarios[st.active].model, mrows = av.methods;
    var methodHtml = '<div class="vlab-block"><div class="vlab-sect-h">' + SLAB[st.active] + ' case — valuation methods <span class="vlab-tag vlab-tag-calc">Calculated</span></div><div class="vlab-methods">' +
      methodCard("FCF DCF", mrows.dcf, price) + methodCard("Exit P/E", mrows.pe, price) + methodCard("Exit EV/EBITDA", mrows.evebitda, price) +
      '<div class="vlab-mcard vlab-mcard-blend"><div class="vlab-mh">Blended</div><div class="vlab-mv">' + fmt$(av.fairValue) + '</div><div class="vlab-mu ' + (av.upside >= 0 ? "up" : "dn") + '">' + signPct(av.upside) + '</div></div>' +
      '</div>' +
      '<div class="vlab-facts">' +
      fact("Implied mkt cap", fmtB(av.impliedMktCap)) + fact("Implied EV", fmtB(av.impliedEV)) +
      fact("Final-yr revenue", fmtB(av.finalRevenue)) + fact("Final-yr EPS", fmt$(av.finalEps)) +
      fact("Final-yr FCF", fmtB(av.finalFcff)) + fact("Exp. annual return", av.expectedAnnualReturn == null ? "—" : signPct(av.expectedAnnualReturn)) +
      '</div></div>';

    /* projection table */
    var tbl = projTable(am);

    /* sensitivity */
    var sens = sensBlock();

    /* reverse */
    var rev = reverseBlock(price);

    /* explanation */
    var exp = explain(all);

    res.innerHTML = wHtml + methodHtml + tbl + sens + rev + exp;
    wireResults();
  }
  function methodCard(label, m, price) {
    if (!m || !m.ok) return '<div class="vlab-mcard vlab-mcard-off"><div class="vlab-mh">' + label + '</div><div class="vlab-mv">—</div><div class="vlab-mu">n/a</div></div>';
    var up = price > 0 ? m.fairValue / price - 1 : null;
    return '<div class="vlab-mcard"><div class="vlab-mh">' + label + '</div><div class="vlab-mv">' + fmt$(m.fairValue) + '</div><div class="vlab-mu ' + (up >= 0 ? "up" : "dn") + '">' + signPct(up) + '</div></div>';
  }
  function fact(l, v) { return '<div class="vlab-fact"><span>' + l + '</span><strong>' + v + '</strong></div>'; }

  function projTable(m) {
    var rows = m.rows;
    var head = '<th>Year</th>' + rows.map(function (r) { return "<th>" + r.year + "</th>"; }).join("");
    function line(label, fn, cls) { return '<tr class="' + (cls || "") + '"><td class="vlab-rowlbl">' + label + '</td>' + rows.map(function (r) { return "<td>" + fn(r) + "</td>"; }).join("") + "</tr>"; }
    var body =
      line("Revenue", function (r) { return fmtB(r.revenue); }, "strong") +
      line("Rev growth", function (r) { return pctS(r.revGrowth, 0); }) +
      line("Gross profit", function (r) { return fmtB(r.grossProfit); }) +
      line("Gross margin", function (r) { return pctS(r.grossMargin, 0); }) +
      line("Operating expenses", function (r) { return fmtB(r.opex); }) +
      line("Operating income", function (r) { return fmtB(r.ebit); }, "strong") +
      line("Operating margin", function (r) { return pctS(r.opMargin, 0); }) +
      line("EBITDA", function (r) { return fmtB(r.ebitda); }) +
      line("EBITDA margin", function (r) { return pctS(r.ebitdaMargin, 0); }) +
      line("Taxes", function (r) { return fmtB(r.tax); }) +
      line("Net income", function (r) { return fmtB(r.netIncome); }, "strong") +
      line("Diluted shares", function (r) { return fmtB(r.shares).replace("$", ""); }) +
      line("EPS", function (r) { return fmt$(r.eps); }, "strong") +
      line("Capex", function (r) { return fmtB(r.capex); }) +
      line("Working-capital inv.", function (r) { return fmtB(r.wcInvest); }) +
      line("Free cash flow", function (r) { return fmtB(r.fcff); }, "strong");
    return '<div class="vlab-block"><div class="vlab-sect-h">' + SLAB[VL.state.active] + ' case — projected financials <span class="vlab-tag vlab-tag-calc">Calculated</span></div>' +
      '<div class="vlab-table-wrap"><table class="vlab-table"><thead><tr>' + head + '</tr></thead><tbody>' + body + '</tbody></table></div></div>';
  }

  /* sensitivity */
  var SENS_DRIVERS = { discountRate: "Discount rate", terminalGrowth: "Terminal growth", opMarginTargetY5: "Yr-5 op margin", exitPE: "Exit P/E", exitEVEBITDA: "Exit EV/EBITDA", revGrowth: "Revenue growth" };
  function sensSteps(driver, s) {
    var base;
    if (driver === "discountRate") base = n(s.discountRate) / 100, def = [-0.02, -0.01, 0, 0.01, 0.02];
    else if (driver === "terminalGrowth") base = n(s.terminalGrowth) / 100, def = [-0.01, -0.005, 0, 0.005, 0.01];
    else if (driver === "opMarginTargetY5") base = n(s.opMarginTargetY5) / 100, def = [-0.06, -0.03, 0, 0.03, 0.06];
    else if (driver === "exitPE") base = n(s.exitPE), def = [-8, -4, 0, 4, 8];
    else if (driver === "exitEVEBITDA") base = n(s.exitEVEBITDA), def = [-4, -2, 0, 2, 4];
    else base = n(s.revGrowthEarly) / 100, def = [-0.06, -0.03, 0, 0.03, 0.06];
    var def; // eslint noop
    var steps = (driver === "exitPE" || driver === "exitEVEBITDA") ? [-8, -4, 0, 4, 8] : (driver === "discountRate" ? [-0.02, -0.01, 0, 0.01, 0.02] : (driver === "terminalGrowth" ? [-0.01, -0.005, 0, 0.005, 0.01] : [-0.06, -0.03, 0, 0.03, 0.06]));
    if (driver === "exitEVEBITDA") steps = [-4, -2, 0, 2, 4];
    return steps.map(function (d) { return base + d; });
  }
  function sensBlock() {
    var st = VL.state, s = st.scenarios[st.active];
    var xs = sensSteps(st.sens.x, s), ys = sensSteps(st.sens.y, s);
    var inp = engInput(st.active); inp.methodWeights = { dcf: 1 };
    // if using multiple-based axes, weight to those methods
    if (st.sens.x === "exitPE" || st.sens.y === "exitPE") inp.methodWeights = { pe: 1 };
    if (st.sens.x === "exitEVEBITDA" || st.sens.y === "exitEVEBITDA") inp.methodWeights = { evebitda: 1 };
    var grid = M().valuationSensitivityGrid(inp, st.sens.x, xs, st.sens.y, ys);
    var baseX = xs[2], baseY = ys[2];
    function optSel(id, sel) { return '<select id="' + id + '">' + Object.keys(SENS_DRIVERS).map(function (k) { return '<option value="' + k + '"' + (sel === k ? " selected" : "") + '>' + SENS_DRIVERS[k] + '</option>'; }).join("") + '</select>'; }
    function fmtAxis(driver, v) { return (driver === "exitPE" || driver === "exitEVEBITDA") ? v.toFixed(0) + "x" : (v * 100).toFixed(driver === "terminalGrowth" ? 1 : 0) + "%"; }
    var thead = '<th>' + SENS_DRIVERS[st.sens.y] + ' ＼ ' + SENS_DRIVERS[st.sens.x] + '</th>' + xs.map(function (x) { return "<th>" + fmtAxis(st.sens.x, x) + "</th>"; }).join("");
    var tbody = grid.rows.map(function (row) {
      return '<tr><th>' + fmtAxis(st.sens.y, row.y) + '</th>' + row.cells.map(function (c) {
        var cur = Math.abs(c.x - baseX) < 1e-9 && Math.abs(row.y - baseY) < 1e-9;
        return '<td class="' + (cur ? "current" : "") + '">' + (c.value == null ? "—" : fmt$(c.value, 0)) + '</td>';
      }).join("") + '</tr>';
    }).join("");
    return '<div class="vlab-block"><div class="vlab-sect-h">Sensitivity — fair value per share <span class="vlab-tag vlab-tag-calc">Calculated</span></div>' +
      '<div class="vlab-sens-ctrl">Rows: ' + optSel("vlab-sy", st.sens.y) + ' &nbsp; Cols: ' + optSel("vlab-sx", st.sens.x) + '</div>' +
      '<div class="vlab-table-wrap"><table class="vlab-table vlab-sens"><thead><tr>' + thead + '</tr></thead><tbody>' + tbody + '</tbody></table></div></div>';
  }

  /* reverse — what's priced in */
  var REV_DRIVERS = { revGrowth: "Revenue growth (per yr)", opMarginTargetY5: "Yr-5 operating margin", exitPE: "Exit P/E", exitEVEBITDA: "Exit EV/EBITDA" };
  function reverseBlock(price) {
    var st = VL.state;
    var inp = engInput(st.active);
    var out = "";
    Object.keys(REV_DRIVERS).forEach(function (d) {
      var r = M().reverseSolveValuation(inp, d, price);
      var val = r.ok ? ((d === "exitPE" || d === "exitEVEBITDA") ? r.value.toFixed(1) + "x" : (r.value * 100).toFixed(1) + "%") : "no solution in range";
      out += '<div class="vlab-rev-row"><span>' + REV_DRIVERS[d] + '</span><strong class="' + (r.ok ? "gold" : "") + '">' + val + '</strong></div>';
    });
    return '<div class="vlab-block"><div class="vlab-sect-h">What’s priced in? <span class="vlab-tag vlab-tag-calc">Reverse solve</span></div>' +
      '<p class="vlab-rev-sub">Holding the other ' + SLAB[st.active] + '-case assumptions fixed, this is what today’s ' + fmt$(price) + ' price implies for each driver on its own:</p>' +
      '<div class="vlab-rev">' + out + '</div></div>';
  }

  /* explanation */
  function explain(all) {
    var st = VL.state, b = all.scenarios.base.valuation, price = all.currentPrice;
    var dcfShare = b.methods.dcf ? b.methods.dcf.terminalShare : 0;
    var lines = [];
    lines.push("The blended base-case fair value is <strong>" + fmt$(b.fairValue) + "</strong> versus a current price of " + fmt$(price) + " — a " + signPct(b.upside) + " gap.");
    lines.push("The valuation is driven mostly by the revenue-growth path and the operating-margin ramp to " + st.scenarios.base.opMarginTargetY5 + "% by Year 5; the discount rate (" + st.scenarios.base.discountRate + "%) and terminal assumptions set how much of that is captured today.");
    if (dcfShare > 0.7) lines.push("A large share of the DCF value (" + (dcfShare * 100).toFixed(0) + "%) sits in the terminal value, so the result is sensitive to the discount and terminal-growth assumptions — check the sensitivity grid.");
    var dil = n(st.scenarios.base.dilution);
    if (dil >= 2) lines.push("Share-count growth of " + dil + "%/yr is material: it lowers per-share value even as the business grows, so buybacks or lower SBC would meaningfully change the result.");
    lines.push("For the bull case (" + fmt$(all.scenarios.bull.valuation.fairValue) + ") to play out, growth and margins both need to land near the high end; the bear case (" + fmt$(all.scenarios.bear.valuation.fairValue) + ") reflects slower growth, thinner margins, and a lower exit multiple.");
    lines.push("This is an educational model, not a recommendation.");
    return '<div class="vlab-block vlab-explain"><div class="vlab-sect-h">Plain-English summary</div>' + lines.map(function (l) { return "<p>" + l + "</p>"; }).join("") + '</div>';
  }

  function wireResults() {
    var sx = document.getElementById("vlab-sx"), sy = document.getElementById("vlab-sy");
    if (sx) sx.onchange = function () { VL.state.sens.x = sx.value; recompute(); };
    if (sy) sy.onchange = function () { VL.state.sens.y = sy.value; recompute(); };
  }

  /* =================== CSS =================== */
  function injectCSS() {
    if (document.getElementById("vlab-css")) return;
    var s = el("style"); s.id = "vlab-css";
    s.textContent = [
      ".vlab{--vl-line:rgba(230,188,99,.16);--vl-in:rgba(217,179,94,.08);color:var(--lens-text,#f5ebd7);font-family:var(--sans,'DM Sans',Arial);}",
      ".vlab-summary{position:sticky;top:0;z-index:20;display:flex;flex-wrap:wrap;gap:8px;padding:10px 12px;margin:-4px 0 14px;background:#0c0e10;border:1px solid var(--vl-line);border-radius:12px;box-shadow:0 8px 24px rgba(0,0,0,.28);}",
      ".vlab-scell{flex:1;min-width:88px;display:flex;flex-direction:column;gap:2px;}",
      ".vlab-scell span{font:600 .58rem var(--sans);letter-spacing:.08em;text-transform:uppercase;color:rgba(245,235,215,.5);}",
      ".vlab-scell strong{font:800 1.05rem var(--serif,'Space Grotesk');color:#f5ebd7;}",
      ".vlab-scell.vlab-wt strong{color:var(--lens-gold,#d9b35e);}.vlab-bear strong{color:#e08a8f;}.vlab-bull strong{color:#4fd39a;}",
      ".vlab-scell strong.up{color:#4fd39a;}.vlab-scell strong.dn{color:#e08a8f;}",
      ".vlab-head{display:flex;flex-wrap:wrap;justify-content:space-between;align-items:flex-end;gap:12px;margin-bottom:12px;}",
      ".vlab-title{display:flex;align-items:baseline;gap:10px;}.vlab-tk{font:800 1.7rem var(--serif,'Space Grotesk');color:var(--lens-gold,#d9b35e);}.vlab-sub{font:600 .7rem var(--sans);letter-spacing:.14em;text-transform:uppercase;color:rgba(245,235,215,.5);}",
      ".vlab-head-ctrl{display:flex;flex-wrap:wrap;gap:10px;align-items:center;}",
      ".vlab-sel{display:flex;flex-direction:column;gap:3px;font:600 .56rem var(--sans);letter-spacing:.06em;text-transform:uppercase;color:rgba(245,235,215,.5);}",
      ".vlab-sel select,.vlab-sens-ctrl select{background:#0c0e10;border:1px solid var(--vl-line);border-radius:7px;color:#f5ebd7;font:600 .8rem var(--sans);padding:.4rem .5rem;}",
      ".vlab-mode,.vlab-hz{display:inline-flex;align-items:center;gap:4px;background:#0c0e10;border:1px solid var(--vl-line);border-radius:9px;padding:3px;}",
      ".vlab-hz span{font:600 .56rem var(--sans);letter-spacing:.08em;text-transform:uppercase;color:rgba(245,235,215,.45);padding:0 4px;}",
      ".vlab-mode button,.vlab-hz button{border:0;background:transparent;color:rgba(245,235,215,.66);font:700 .76rem var(--sans);padding:.4rem .8rem;border-radius:7px;cursor:pointer;}",
      ".vlab-mode button.active,.vlab-hz button.active{background:var(--lens-gold,#d9b35e);color:#17130c;}",
      ".vlab-hist{margin-bottom:12px;}.vlab-hist-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:8px;}",
      ".vlab-hcard{background:rgba(255,255,255,.02);border:1px solid var(--vl-line);border-radius:10px;padding:.6rem .7rem;font:600 .72rem var(--sans);color:rgba(245,235,215,.8);}",
      ".vlab-hyr{font:800 .8rem var(--serif);color:var(--lens-gold,#d9b35e);margin-bottom:4px;}",
      ".vlab-sect-h{font:700 .8rem var(--sans);color:#f5ebd7;margin:0 0 8px;display:flex;align-items:center;gap:8px;}",
      ".vlab-tag{font:700 .54rem var(--sans);letter-spacing:.06em;text-transform:uppercase;padding:2px 6px;border-radius:5px;}",
      ".vlab-tag-hist{background:rgba(120,160,220,.16);color:#9fc0ec;}.vlab-tag-calc{background:rgba(217,179,94,.16);color:var(--lens-gold,#d9b35e);}",
      ".vlab-scentabs{display:flex;align-items:center;gap:6px;margin-bottom:12px;}",
      ".vlab-stab{border:1px solid var(--vl-line);background:#0c0e10;color:rgba(245,235,215,.7);font:700 .82rem var(--sans);padding:.5rem 1rem;border-radius:9px;cursor:pointer;display:flex;flex-direction:column;line-height:1.1;}",
      ".vlab-stab em{font:600 .58rem var(--sans);opacity:.6;font-style:normal;}",
      ".vlab-stab-bear.active{background:#c76b70;border-color:#c76b70;color:#fff;}.vlab-stab-base.active{background:var(--lens-gold,#d9b35e);border-color:var(--lens-gold,#d9b35e);color:#17130c;}.vlab-stab-bull.active{background:#2f9c6a;border-color:#2f9c6a;color:#fff;}",
      ".vlab-spacer{flex:1;}.vlab-mini{border:1px dashed var(--vl-line);background:transparent;color:var(--lens-gold,#d9b35e);font:700 .72rem var(--sans);padding:.45rem .8rem;border-radius:8px;cursor:pointer;}",
      ".vlab-group{border:1px solid var(--vl-line);border-radius:10px;margin-bottom:8px;background:rgba(255,255,255,.015);}",
      ".vlab-group summary{cursor:pointer;padding:.7rem .9rem;font:700 .82rem var(--sans);color:#f5ebd7;list-style:none;}",
      ".vlab-group summary::-webkit-details-marker{display:none;}.vlab-group[open] summary{border-bottom:1px solid var(--vl-line);}",
      ".vlab-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:8px 14px;padding:.8rem .9rem;}",
      ".vlab-in{display:flex;justify-content:space-between;align-items:center;gap:8px;font:600 .74rem var(--sans);color:rgba(245,235,215,.82);}",
      ".vlab-inw{display:inline-flex;align-items:center;gap:4px;}.vlab-inw input{width:82px;background:var(--vl-in);border:1px solid var(--vl-line);border-radius:6px;color:#f5ebd7;font:700 .78rem var(--sans);padding:.32rem .4rem;text-align:right;}",
      ".vlab-inw input:focus{outline:0;border-color:var(--lens-gold,#d9b35e);box-shadow:0 0 0 2px rgba(217,179,94,.2);}",
      ".vlab-inw em{font:600 .62rem var(--sans);color:rgba(245,235,215,.4);font-style:normal;min-width:26px;}",
      ".vlab-peryear{grid-column:1/-1;}.vlab-peryear>span{font:600 .74rem var(--sans);color:rgba(245,235,215,.82);}",
      ".vlab-yrgrid{display:flex;flex-wrap:wrap;gap:6px;margin-top:6px;}.vlab-yrgrid label{font:600 .6rem var(--sans);color:rgba(245,235,215,.6);display:flex;flex-direction:column;gap:2px;}",
      ".vlab-yrgrid input{width:52px;background:var(--vl-in);border:1px solid var(--vl-line);border-radius:5px;color:#f5ebd7;font:700 .72rem var(--sans);padding:.25rem;text-align:right;}",
      ".vlab-weights{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin:12px 0;}",
      ".vlab-wcol{border:1px solid var(--vl-line);border-radius:10px;padding:.7rem .9rem;background:rgba(255,255,255,.015);}",
      ".vlab-block{border:1px solid var(--vl-line);border-radius:12px;padding:.9rem;margin-bottom:12px;background:#0d0f12;}",
      ".vlab-methods{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:8px;margin-bottom:10px;}",
      ".vlab-mcard{border:1px solid var(--vl-line);border-radius:10px;padding:.6rem .7rem;text-align:center;}",
      ".vlab-mcard-blend{border-color:var(--lens-gold,#d9b35e);box-shadow:0 0 0 1px var(--lens-gold,#d9b35e) inset;}",
      ".vlab-mcard-off{opacity:.5;}.vlab-mh{font:700 .64rem var(--sans);letter-spacing:.04em;color:rgba(245,235,215,.6);text-transform:uppercase;}",
      ".vlab-mv{font:800 1.15rem var(--serif,'Space Grotesk');color:#f5ebd7;margin:3px 0;}.vlab-mu{font:700 .72rem var(--sans);}.vlab-mu.up{color:#4fd39a;}.vlab-mu.dn{color:#e08a8f;}",
      ".vlab-facts{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:6px;}",
      ".vlab-fact{background:rgba(255,255,255,.02);border-radius:8px;padding:.45rem .6rem;display:flex;flex-direction:column;gap:2px;}",
      ".vlab-fact span{font:600 .56rem var(--sans);letter-spacing:.05em;text-transform:uppercase;color:rgba(245,235,215,.5);}.vlab-fact strong{font:700 .86rem var(--sans);color:#f5ebd7;}",
      ".vlab-table-wrap{overflow-x:auto;-webkit-overflow-scrolling:touch;border:1px solid var(--vl-line);border-radius:10px;background:#0b0d10;}",
      ".vlab-table{border-collapse:collapse;width:100%;min-width:max-content;font-variant-numeric:tabular-nums;}",
      ".vlab-table th,.vlab-table td{padding:.42rem .7rem;text-align:right;white-space:nowrap;border-bottom:1px solid rgba(230,188,99,.07);font:600 .74rem var(--sans);}",
      ".vlab-table thead th{position:sticky;top:0;background:#12151a;color:var(--lens-gold,#d9b35e);font-weight:700;}",
      ".vlab-rowlbl{text-align:left!important;position:sticky;left:0;background:#0b0d10;color:rgba(245,235,215,.72);}",
      ".vlab-table tr.strong td,.vlab-table tr.strong .vlab-rowlbl{color:#f5ebd7;font-weight:800;}",
      ".vlab-sens td{cursor:default;}.vlab-sens td.current{background:var(--lens-gold,#d9b35e);color:#17130c;font-weight:800;}",
      ".vlab-sens th{color:rgba(245,235,215,.7);background:#12151a;}",
      ".vlab-sens-ctrl{font:600 .72rem var(--sans);color:rgba(245,235,215,.6);margin-bottom:8px;display:flex;flex-wrap:wrap;gap:6px;align-items:center;}",
      ".vlab-rev{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:8px;}",
      ".vlab-rev-row{display:flex;justify-content:space-between;align-items:center;padding:.6rem .8rem;border:1px solid var(--vl-line);border-radius:9px;background:rgba(255,255,255,.015);font:600 .78rem var(--sans);color:rgba(245,235,215,.82);}",
      ".vlab-rev-row strong{font:800 .95rem var(--serif);}.vlab-rev-row strong.gold{color:var(--lens-gold,#d9b35e);}",
      ".vlab-rev-sub,.vlab-explain p{font:500 .8rem/1.6 var(--sans);color:rgba(245,235,215,.72);}",
      ".vlab-explain p{margin:.4rem 0;}.vlab-explain strong{color:#f5ebd7;}",
      ".vlab-warns{margin-bottom:12px;display:flex;flex-direction:column;gap:6px;}",
      ".vlab-w{font:600 .76rem var(--sans);padding:.5rem .7rem;border-radius:8px;display:flex;gap:8px;align-items:center;}",
      ".vlab-w-warn{background:rgba(217,179,94,.1);border:1px solid rgba(217,179,94,.3);color:#e9c877;}",
      ".vlab-w-err{background:rgba(201,107,112,.12);border:1px solid rgba(201,107,112,.4);color:#e0a6a9;}",
      ".vlab-actions{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-top:8px;}",
      ".vlab-btn{display:inline-flex;align-items:center;gap:6px;border:1px solid var(--vl-line);background:#0c0e10;color:#f5ebd7;font:700 .76rem var(--sans);padding:.5rem .9rem;border-radius:8px;cursor:pointer;}",
      ".vlab-btn.vlab-gold{background:var(--lens-gold,#d9b35e);color:#17130c;border-color:var(--lens-gold,#d9b35e);}",
      ".vlab-note{margin-top:10px;font:500 .66rem var(--sans);color:rgba(245,235,215,.4);line-height:1.5;}",
      ".vlab-err{padding:.9rem;border:1px solid rgba(201,107,112,.4);background:rgba(201,107,112,.08);border-radius:10px;color:#e0a6a9;font:600 .82rem var(--sans);}",
      ".vlab-toast{position:fixed;left:50%;bottom:80px;transform:translateX(-50%) translateY(10px);background:#12151a;color:#f5ebd7;border:1px solid var(--vl-line);padding:.6rem 1rem;border-radius:10px;font:600 .8rem var(--sans);opacity:0;transition:.2s;z-index:99999;}.vlab-toast.show{opacity:1;transform:translateX(-50%) translateY(0);}",
      "@media(max-width:640px){.vlab-tk{font-size:1.35rem;}.vlab-weights{grid-template-columns:1fr;}.vlab-summary{gap:6px;}.vlab-scell{min-width:70px;}.vlab-scell strong{font-size:.9rem;}}",
      "#view-tool .vlab input,#view-tool .vlab select{background:var(--vl-in)!important;color:#f5ebd7!important;border-color:var(--vl-line)!important;-webkit-text-fill-color:#f5ebd7!important;}",
      "#view-tool .vlab input::placeholder{color:rgba(245,235,215,.42)!important;-webkit-text-fill-color:rgba(245,235,215,.42)!important;}",
      "html:not([data-theme='dark']) .vlab{background:#0d0f12;border:1px solid var(--vl-line);border-radius:14px;padding:14px;}",
      "html:not([data-theme='dark']) .vlab-group,html:not([data-theme='dark']) .vlab-wcol,html:not([data-theme='dark']) .vlab-hcard{background:#12151a;}",
    ].join("");
    document.head.appendChild(s);
  }
})();

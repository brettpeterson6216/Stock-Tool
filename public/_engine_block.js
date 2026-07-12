  // ════════ VALUATION LAB — operating model + multi-method valuation (Phase 1) ════════
  function pct(v) { return asDecimalRate(v); }
  function seriesFrom(v, years, early, late) {
    // v can be array (per-year), a single number, or {early,late} split at year 5
    if (Array.isArray(v)) { var a = []; for (var i = 0; i < years; i++) a.push(pct(v[i] != null ? v[i] : v[v.length - 1])); return a; }
    if (v && typeof v === "object" && ("early" in v || "late" in v)) {
      var e = pct(v.early), l = pct(v.late != null ? v.late : v.early), out = [];
      for (var j = 0; j < years; j++) out.push(j < 5 ? e : l); return out;
    }
    if (early != null) { var ee = pct(early), ll = pct(late != null ? late : early), o = []; for (var k = 0; k < years; k++) o.push(k < 5 ? ee : ll); return o; }
    var s = pct(v); return Array.from({ length: years }, function () { return s; });
  }
  function rampMargins(startM, targetY5, longTerm, years) {
    startM = pct(startM); targetY5 = pct(targetY5); longTerm = pct(longTerm != null ? longTerm : targetY5);
    var out = [];
    for (var i = 1; i <= years; i++) {
      var m;
      if (i <= 5) m = startM + (targetY5 - startM) * (i / 5);
      else if (years > 5) m = targetY5 + (longTerm - targetY5) * ((i - 5) / Math.max(1, years - 5));
      else m = targetY5;
      out.push(m);
    }
    return out;
  }

  // Build the projected operating statements. Rule order: revenue → margins → EBIT → tax → NI; shares separate; FCFF from NOPAT.
  function projectOperatingModel(input) {
    var years = Math.max(1, Math.min(10, Math.trunc(Number(input.years) || 5)));
    var rev0 = Number(input.startRevenue);
    var shares0 = Number(input.startShares);
    if (!finite(rev0) || rev0 <= 0) return { ok: false, error: "Starting revenue must be above zero." };
    if (!finite(shares0) || shares0 <= 0) return { ok: false, error: "Starting diluted share count must be above zero." };
    var g = seriesFrom(input.revGrowth, years, input.revGrowthEarly, input.revGrowthLate);
    var opM = rampMargins(input.opMarginStart, input.opMarginTargetY5, input.opMarginLongTerm, years);
    var grossM = seriesFrom(input.grossMargin != null ? input.grossMargin : 1, years);
    var tax = pct(input.taxRate);
    var dil = pct(input.dilution);
    var capexPct = pct(input.capexPct);
    var daPct = pct(input.daPct);
    var wcPct = pct(input.wcPct);
    var sbcPct = pct(input.sbcPct != null ? input.sbcPct : 0);
    var intRate = pct(input.interestRate != null ? input.interestRate : 0);
    var debt = Number(input.startDebt) || 0;
    var cash = Number(input.startCash) || 0;
    if (dil <= -1) return { ok: false, error: "Share-count growth must be greater than −100%." };
    var rows = [], prevRev = rev0, prevWC = null;
    for (var i = 1; i <= years; i++) {
      if (!finite(g[i - 1]) || g[i - 1] <= -1) return { ok: false, error: "Revenue growth must be greater than −100% for every year." };
      var revenue = prevRev * (1 + g[i - 1]);
      var grossMargin = grossM[i - 1];
      var grossProfit = revenue * grossMargin;
      var opMargin = opM[i - 1];
      var ebit = revenue * opMargin;
      var opex = grossProfit - ebit;
      var da = revenue * daPct;
      var ebitda = ebit + da;
      var interest = debt * intRate;
      var pretax = ebit - interest;
      var taxes = pretax > 0 ? pretax * tax : 0;
      var netIncome = pretax - taxes;
      var nopat = ebit * (1 - tax);
      var capex = revenue * capexPct;
      var deltaRev = revenue - prevRev;
      var wcInvest = deltaRev * wcPct;
      var sbc = revenue * sbcPct;
      // FCFF (unlevered): NOPAT + D&A − capex − ΔWC. SBC is a real cost captured via dilution; if user models SBC as cash add-back we subtract it back to avoid double count.
      var fcff = nopat + da - capex - wcInvest - sbc;
      var shares = shares0 * Math.pow(1 + dil, i);
      var eps = netIncome / shares;
      rows.push({
        year: (Number(input.baseYear) || new Date().getFullYear()) + i,
        revenue: revenue, revGrowth: g[i - 1], grossProfit: grossProfit, grossMargin: grossMargin,
        opex: opex, ebit: ebit, opMargin: opMargin, da: da, ebitda: ebitda, ebitdaMargin: ebitda / revenue,
        interest: interest, pretax: pretax, tax: taxes, netIncome: netIncome, netMargin: netIncome / revenue,
        nopat: nopat, capex: capex, wcInvest: wcInvest, sbc: sbc, fcff: fcff, shares: shares, eps: eps,
      });
      prevRev = revenue;
    }
    return { ok: true, years: years, startRevenue: rev0, startShares: shares0, startDebt: debt, startCash: cash, rows: rows };
  }

  // Value the projected model with several methods. Returns per-method fair value TODAY plus target-year figures.
  function valueOperatingModel(model, v) {
    if (!model || !model.ok) return { ok: false, error: (model && model.error) || "Invalid projection." };
    var rows = model.rows, N = rows.length, last = rows[N - 1];
    var wacc = pct(v.discountRate), tg = pct(v.terminalGrowth);
    var price = Number(v.currentPrice) || 0;
    var curShares = Number(v.currentDilutedShares) || model.startShares;
    var netDebt = (Number(v.netDebt) != null && finite(v.netDebt)) ? Number(v.netDebt) : (model.startDebt - model.startCash);
    if (!finite(wacc) || wacc <= 0) return { ok: false, error: "Discount rate must be above zero." };
    var out = { ok: true, methods: {}, warnings: [] };
    // ── DCF (FCFF) ──
    var pvFCFF = 0;
    for (var i = 0; i < N; i++) pvFCFF += rows[i].fcff / Math.pow(1 + wacc, i + 1);
    var tvGordon = null, dcfOk = wacc > tg;
    if (dcfOk) tvGordon = last.fcff * (1 + tg) / (wacc - tg);
    else out.warnings.push("Terminal growth ≥ discount rate — Gordon terminal value is invalid; using exit multiple if provided.");
    var tvExit = (v.exitEVEBITDA > 0) ? v.exitEVEBITDA * last.ebitda : null;
    var tvUsed = (tvGordon != null && tvGordon > 0) ? tvGordon : (tvExit != null ? tvExit : 0);
    var pvTV = tvUsed / Math.pow(1 + wacc, N);
    var ev = pvFCFF + pvTV;
    var equity = ev - netDebt;
    var fvDcf = equity / curShares;
    out.methods.dcf = { fairValue: fvDcf, ev: ev, equity: equity, pvFCFF: pvFCFF, pvTV: pvTV, terminalShare: ev > 0 ? pvTV / ev : 0, ok: fvDcf > 0 };
    // ── Exit P/E (equity method, uses projected diluted shares) ──
    if (v.exitPE > 0) {
      var targetPrice = v.exitPE * last.eps;
      var fvPe = targetPrice / Math.pow(1 + wacc, N);
      out.methods.pe = { fairValue: fvPe, targetPrice: targetPrice, impliedMktCap: targetPrice * last.shares, ok: fvPe > 0 };
    }
    // ── Exit EV/EBITDA (enterprise method → equity) ──
    if (v.exitEVEBITDA > 0) {
      var futureEV = v.exitEVEBITDA * last.ebitda;
      var futureEquity = futureEV - netDebt;
      var futurePx = futureEquity / last.shares;
      var fvEv = futurePx / Math.pow(1 + wacc, N);
      out.methods.evebitda = { fairValue: fvEv, futureEV: futureEV, targetPrice: futurePx, ok: fvEv > 0 };
    }
    // ── Price / Sales (exit) ──
    if (v.exitPS > 0) {
      var futMktCapPS = v.exitPS * last.revenue;
      var fvPs = (futMktCapPS / last.shares) / Math.pow(1 + wacc, N);
      out.methods.ps = { fairValue: fvPs, ok: fvPs > 0 };
    }
    // ── Blend ──
    var weights = v.methodWeights || { dcf: 1 };
    var wsum = 0, blended = 0;
    Object.keys(weights).forEach(function (k) {
      var w = Number(weights[k]) || 0;
      if (w > 0 && out.methods[k] && out.methods[k].ok) { blended += out.methods[k].fairValue * w; wsum += w; }
    });
    var fairValue = wsum > 0 ? blended / wsum : (out.methods.dcf.ok ? fvDcf : NaN);
    out.fairValue = fairValue;
    out.currentPrice = price;
    out.upside = price > 0 ? fairValue / price - 1 : null;
    out.annualizedReturn = (price > 0 && fairValue > 0) ? cagr(price, fairValue, 1) : null; // 1yr convergence proxy
    // annualized return to target over horizon (using PE target if present else fair value)
    var horizonTarget = out.methods.pe ? out.methods.pe.targetPrice : (out.methods.evebitda ? out.methods.evebitda.targetPrice : fairValue);
    out.expectedAnnualReturn = (price > 0 && horizonTarget > 0) ? cagr(price, horizonTarget, N) : null;
    out.finalRevenue = last.revenue; out.finalEps = last.eps; out.finalFcff = last.fcff; out.finalEbitda = last.ebitda;
    out.impliedMktCap = fairValue * curShares;
    out.impliedEV = out.impliedMktCap + netDebt;
    out.impliedFwdPE = last.eps > 0 ? fairValue / last.eps : null;
    return out;
  }

  function runValuation(input) {
    var model = projectOperatingModel(input);
    if (!model.ok) return model;
    var val = valueOperatingModel(model, input);
    if (!val.ok) return { ok: false, error: val.error };
    return { ok: true, model: model, valuation: val };
  }

  // Probability-weighted across scenarios: scenarios = {bear:{...full input},base,bull}, weights optional
  function runValuationScenarios(input) {
    var keys = ["bear", "base", "bull"], out = {}, w = input.weights || { bear: 0.25, base: 0.5, bull: 0.25 };
    for (var i = 0; i < keys.length; i++) {
      var k = keys[i]; if (!input.scenarios[k]) continue;
      var r = runValuation(input.scenarios[k]);
      if (!r.ok) return { ok: false, error: r.error, scenario: k };
      out[k] = r;
    }
    var wsum = keys.reduce(function (s, k) { return s + (out[k] ? (Number(w[k]) || 0) : 0); }, 0) || 1;
    var weighted = keys.reduce(function (s, k) { return s + (out[k] ? out[k].valuation.fairValue * (Number(w[k]) || 0) : 0); }, 0) / wsum;
    var price = out.base ? out.base.valuation.currentPrice : 0;
    return { ok: true, scenarios: out, weights: w, weightedFairValue: weighted, currentPrice: price, weightedUpside: price > 0 ? weighted / price - 1 : null };
  }

  // Reverse valuation: solve one driver so blended fair value == current price.
  function reverseSolveValuation(baseInput, driver, targetPrice) {
    var lo, hi;
    if (driver === "revGrowth") { lo = -0.5; hi = 1.0; }
    else if (driver === "opMarginTargetY5") { lo = -0.2; hi = 0.7; }
    else if (driver === "exitPE") { lo = 1; hi = 100; }
    else if (driver === "exitEVEBITDA") { lo = 1; hi = 60; }
    else if (driver === "fcffGrowth") { lo = -0.5; hi = 1.0; }
    else return { ok: false, error: "Unknown driver." };
    function fvFor(x) {
      var inp = Object.assign({}, baseInput);
      if (driver === "revGrowth") { inp.revGrowth = x; inp.revGrowthEarly = x; inp.revGrowthLate = x; }
      else if (driver === "opMarginTargetY5") { inp.opMarginTargetY5 = x; inp.opMarginLongTerm = x; }
      else if (driver === "exitPE") { inp.exitPE = x; inp.methodWeights = { pe: 1 }; }
      else if (driver === "exitEVEBITDA") { inp.exitEVEBITDA = x; inp.methodWeights = { evebitda: 1 }; }
      var r = runValuation(inp);
      return r.ok ? r.valuation.fairValue : null;
    }
    var flo = fvFor(lo), fhi = fvFor(hi);
    if (flo == null || fhi == null) return { ok: false, error: "No solution (model invalid at bounds)." };
    if ((flo - targetPrice) * (fhi - targetPrice) > 0) return { ok: false, error: "Current price is outside the solvable range for this driver." };
    for (var it = 0; it < 60; it++) {
      var mid = (lo + hi) / 2, fm = fvFor(mid);
      if (fm == null) return { ok: false, error: "Model became invalid while solving." };
      if ((flo - targetPrice) * (fm - targetPrice) <= 0) { hi = mid; fhi = fm; } else { lo = mid; flo = fm; }
    }
    return { ok: true, driver: driver, value: (lo + hi) / 2 };
  }

  // Sensitivity grid: fair value across two drivers.
  function valuationSensitivityGrid(baseInput, xDriver, xVals, yDriver, yVals) {
    function setD(inp, d, x) {
      if (d === "discountRate") inp.discountRate = x;
      else if (d === "terminalGrowth") inp.terminalGrowth = x;
      else if (d === "opMarginTargetY5") { inp.opMarginTargetY5 = x; inp.opMarginLongTerm = x; }
      else if (d === "exitPE") { inp.exitPE = x; }
      else if (d === "exitEVEBITDA") { inp.exitEVEBITDA = x; }
      else if (d === "revGrowth") { inp.revGrowth = x; inp.revGrowthEarly = x; inp.revGrowthLate = x; }
    }
    var rows = yVals.map(function (yv) {
      return {
        y: yv,
        cells: xVals.map(function (xv) {
          var inp = Object.assign({}, baseInput);
          setD(inp, xDriver, xv); setD(inp, yDriver, yv);
          var r = runValuation(inp);
          return { x: xv, value: r.ok ? r.valuation.fairValue : null };
        }),
      };
    });
    return { ok: true, xDriver: xDriver, yDriver: yDriver, xVals: xVals, yVals: yVals, rows: rows };
  }


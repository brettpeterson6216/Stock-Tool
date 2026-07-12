(function (root, factory) {
  "use strict";
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  if (root) root.ImpliedLensMath = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  function finite(value) {
    return Number.isFinite(Number(value));
  }

  function cagr(start, end, years) {
    start = Number(start);
    end = Number(end);
    years = Number(years);
    if (!finite(start) || !finite(end) || !finite(years) || start <= 0 || end <= 0 || years <= 0) return null;
    return Math.pow(end / start, 1 / years) - 1;
  }

  function cumulativeDividends(startPrice, dividendYield, growth, years) {
    startPrice = Number(startPrice);
    dividendYield = Number(dividendYield);
    growth = Number(growth);
    years = Number(years);
    if (![startPrice, dividendYield, growth, years].every(finite) || startPrice < 0 || dividendYield < 0 || growth <= -1 || years < 0) return null;
    let total = 0;
    for (let year = 1; year <= years; year += 1) total += startPrice * dividendYield * Math.pow(1 + growth, year - 1);
    return total;
  }

  function projectScenario(input) {
    const price = Number(input.price);
    const currentPE = Number(input.currentPE);
    const exitPE = Number(input.exitPE);
    const growth = Number(input.growth);
    const years = Number(input.years);
    const earningsMultiplier = Number(input.earningsMultiplier ?? 1);
    const dividendYield = Number(input.dividendYield ?? 0);
    const dividendGrowth = Number(input.dividendGrowth ?? growth);
    const annualDilution = Number(input.annualDilution ?? 0);
    if (![price, currentPE, exitPE, growth, years, earningsMultiplier, dividendYield, dividendGrowth, annualDilution].every(finite)) return { ok: false, error: "Enter valid numeric assumptions." };
    if (price <= 0 || currentPE <= 0 || exitPE <= 0 || years <= 0 || earningsMultiplier <= 0) return { ok: false, error: "Price, P/E ratios, horizon, and earnings multiplier must be above zero." };
    if (growth <= -1) return { ok: false, error: "Annual growth must be greater than -100%." };
    if (dividendGrowth <= -1) return { ok: false, error: "Dividend growth must be greater than -100%." };
    if (dividendYield < 0) return { ok: false, error: "Dividend yield cannot be negative." };
    if (annualDilution <= -1) return { ok: false, error: "Annual dilution must be greater than -100%. Use a negative value for buybacks." };
    const eps0 = price / currentPE;
    const pricePath = [price];
    const dividendPath = [0];
    const totalValuePath = [price];
    for (let year = 1; year <= years; year += 1) {
      const perShareFactor = Math.pow(1 + annualDilution, -year);
      const projectedPrice = eps0 * Math.pow(1 + growth, year) * perShareFactor * earningsMultiplier * exitPE;
      const dividends = cumulativeDividends(price, dividendYield, dividendGrowth, year);
      pricePath.push(projectedPrice);
      dividendPath.push(dividends);
      totalValuePath.push(projectedPrice + dividends);
    }
    const terminalPrice = pricePath[pricePath.length - 1];
    const dividends = dividendPath[dividendPath.length - 1];
    const totalValue = totalValuePath[totalValuePath.length - 1];
    return {
      ok: true,
      eps0,
      terminalPrice,
      dividends,
      totalValue,
      totalReturn: totalValue / price - 1,
      cagr: cagr(price, totalValue, years),
      pricePath,
      dividendPath,
      totalValuePath,
    };
  }

  function projectCases(input) {
    const price = Number(input.price);
    const currentPE = Number(input.currentPE);
    const years = Number(input.years);
    const scenarios = Array.isArray(input.scenarios) ? input.scenarios : [];
    if (![price, currentPE, years].every(finite) || price <= 0 || currentPE <= 0 || years <= 0) {
      return { ok: false, error: "Price, current P/E, and horizon must be above zero." };
    }
    if (scenarios.length < 2) return { ok: false, error: "Enter at least two scenarios." };
    const probabilities = scenarios.map(scenario => Number(scenario.probability));
    if (!probabilities.every(probability => finite(probability) && probability >= 0 && probability <= 1)) {
      return { ok: false, error: "Each scenario probability must be between 0% and 100%." };
    }
    const probabilityTotal = probabilities.reduce((sum, probability) => sum + probability, 0);
    if (Math.abs(probabilityTotal - 1) > 0.0001) return { ok: false, error: "Scenario probabilities must total 100%." };

    const results = scenarios.map((scenario, index) => {
      const model = projectScenario({ ...scenario, price, currentPE, years });
      return { ...scenario, probability: probabilities[index], model };
    });
    const invalid = results.find(result => !result.model.ok);
    if (invalid) return invalid.model;

    const weighted = key => results.reduce((sum, result) => sum + result.model[key] * result.probability, 0);
    const expectedTotalValue = weighted("totalValue");
    const expectedPricePath = Array.from({ length: years + 1 }, (_, index) =>
      results.reduce((sum, result) => sum + result.model.pricePath[index] * result.probability, 0)
    );
    const expectedTotalValuePath = Array.from({ length: years + 1 }, (_, index) =>
      results.reduce((sum, result) => sum + result.model.totalValuePath[index] * result.probability, 0)
    );
    return {
      ok: true,
      probabilityTotal,
      scenarios: results,
      expectedTerminalPrice: weighted("terminalPrice"),
      expectedDividends: weighted("dividends"),
      expectedTotalValue,
      expectedTotalReturn: expectedTotalValue / price - 1,
      expectedCagr: cagr(price, expectedTotalValue, years),
      expectedPricePath,
      expectedTotalValuePath,
    };
  }

  function asDecimalRate(value) {
    const number = Number(value);
    if (!finite(number)) return NaN;
    return Math.abs(number) > 1 ? number / 100 : number;
  }

  function validateProjectionContext(input) {
    const price = Number(input.currentPrice ?? input.price);
    const eps = Number(input.currentEps ?? input.eps);
    const currentPE = Number(input.currentPE ?? input.currentPe ?? (price > 0 && eps > 0 ? price / eps : NaN));
    const years = Number(input.years);
    const scenarios = input.scenarios || {};
    const scenarioList = Array.isArray(scenarios) ? scenarios : ["bear", "base", "bull"].map(key => ({ key, ...(scenarios[key] || {}) }));
    const items = [
      { key: "ticker", label: "Ticker loaded", ok: Boolean(input.ticker) },
      { key: "price", label: "Current price available or entered", ok: finite(price) && price > 0 },
      { key: "eps", label: "Positive starting EPS available or entered", ok: finite(eps) && eps > 0 },
      { key: "horizon", label: "Projection horizon selected", ok: finite(years) && years > 0 },
    ];
    scenarioList.forEach(scenario => {
      const key = scenario.key || String(scenario.name || "scenario").toLowerCase();
      const growth = asDecimalRate(scenario.growth);
      const exitPE = Number(scenario.exitPE);
      const probability = asDecimalRate(scenario.probability);
      items.push({ key: `${key}-growth`, label: `${scenario.name || key} growth entered`, ok: finite(growth) && growth > -1 });
      items.push({ key: `${key}-exit-pe`, label: `${scenario.name || key} exit P/E entered`, ok: finite(exitPE) && exitPE > 0 });
      items.push({ key: `${key}-probability`, label: `${scenario.name || key} probability entered`, ok: finite(probability) && probability >= 0 && probability <= 1 });
    });
    const probabilityTotal = scenarioList.reduce((sum, scenario) => sum + (finite(asDecimalRate(scenario.probability)) ? asDecimalRate(scenario.probability) : 0), 0);
    items.push({ key: "probability-total", label: "Scenario probabilities total 100%", ok: Math.abs(probabilityTotal - 1) < 0.0001 });
    items.push({ key: "reviewed", label: "Assumptions reviewed", ok: Boolean(input.reviewed) });
    const warnings = [];
    if (finite(eps) && eps <= 0) warnings.push("Projection needs positive EPS. Use a manual normalized EPS for unprofitable companies.");
    scenarioList.forEach(scenario => {
      const name = scenario.name || scenario.key || "Scenario";
      const growth = asDecimalRate(scenario.growth);
      const exitPE = Number(scenario.exitPE);
      const dividendGrowth = asDecimalRate(scenario.dividendGrowth ?? 0);
      const annualDilution = asDecimalRate(scenario.annualDilution ?? 0);
      if (finite(growth) && growth > 0.35) warnings.push(`${name} uses very high earnings growth.`);
      if (finite(exitPE) && exitPE > 60) warnings.push(`${name} uses an extreme exit P/E.`);
      if (finite(dividendGrowth) && dividendGrowth > 0.25) warnings.push(`${name} uses very high dividend growth.`);
      if (finite(annualDilution) && annualDilution > 0.10) warnings.push(`${name} assumes heavy annual dilution.`);
    });
    return { ok: items.every(item => item.ok), items, warnings, price, eps, currentPE, years, probabilityTotal };
  }

  function projectionSensitivity(input) {
    const price = Number(input.currentPrice ?? input.price);
    const eps = Number(input.currentEps ?? input.eps);
    const currentPE = Number(input.currentPE ?? input.currentPe ?? (price > 0 && eps > 0 ? price / eps : NaN));
    const years = Number(input.years);
    const baseGrowth = asDecimalRate(input.growth ?? 0.08);
    const baseExitPE = Number(input.exitPE ?? currentPE);
    if (![price, eps, currentPE, years, baseGrowth, baseExitPE].every(finite) || price <= 0 || eps <= 0 || currentPE <= 0 || years <= 0 || baseExitPE <= 0) {
      return { ok: false, error: "Sensitivity requires price, positive EPS, current P/E, horizon, growth, and exit P/E." };
    }
    const growthSteps = [-0.05, -0.025, 0, 0.025, 0.05].map(delta => Math.max(-0.95, baseGrowth + delta));
    const peSteps = [-10, -5, 0, 5, 10].map(delta => Math.max(1, baseExitPE + delta));
    const rows = growthSteps.map(growth => ({
      growth,
      cells: peSteps.map(exitPE => {
        const model = projectScenario({ price, currentPE, years, growth, exitPE });
        return { exitPE, value: model.ok ? model.terminalPrice : null, current: Math.abs(growth - baseGrowth) < 0.00001 && Math.abs(exitPE - baseExitPE) < 0.00001 };
      }),
    }));
    const flat = rows.flatMap(row => row.cells).map(cell => cell.value).filter(value => value !== null);
    const conclusionFlips = flat.some(value => value < price) && flat.some(value => value > price);
    return { ok: true, growthSteps, peSteps, rows, conclusionFlips };
  }

  function explainProjection(result) {
    if (!result || !result.ok) return { drivers: "Run a valid projection to see the drivers.", mostSensitive: "Unavailable", needsToBeTrue: "Unavailable", breakpoints: "Unavailable" };
    const scenarios = Array.isArray(result.scenarios) ? result.scenarios : Object.values(result.scenarios || {});
    const base = scenarios.find(s => /base/i.test(s.name || s.key || "")) || scenarios[Math.floor(scenarios.length / 2)] || scenarios[0];
    const currentPE = Number(result.currentPE || result.currentPe || 0);
    const exitPE = Number(base?.exitPE || 0);
    const growth = asDecimalRate(base?.growth || 0);
    const multipleText = currentPE && exitPE
      ? `exit multiple ${exitPE > currentPE ? "expansion" : exitPE < currentPE ? "compression" : "holding near today's level"} from ${currentPE.toFixed(1)}x to ${exitPE.toFixed(1)}x`
      : "the selected exit multiple";
    return {
      drivers: `The base case is mostly driven by ${multipleText} and ${(growth * 100).toFixed(1)}% annual EPS growth.`,
      mostSensitive: "The result is usually most sensitive to the exit P/E and earnings growth assumptions.",
      needsToBeTrue: "Earnings need to compound near the selected growth rate and the market needs to award the selected terminal multiple.",
      breakpoints: "The model can break if EPS is not durable, the company remains unprofitable, dilution rises, or the exit multiple falls toward the bear case.",
    };
  }

  function buildProjection(input) {
    const validation = validateProjectionContext(input);
    if (!validation.ok) return { ok: false, checklist: validation.items, warnings: validation.warnings };
    const scenarioInput = (Array.isArray(input.scenarios) ? input.scenarios : ["bear", "base", "bull"].map(key => ({ key, name: key[0].toUpperCase() + key.slice(1), ...(input.scenarios[key] || {}) }))).map(scenario => ({
      ...scenario,
      growth: asDecimalRate(scenario.growth),
      dividendYield: asDecimalRate(scenario.dividendYield ?? 0),
      dividendGrowth: asDecimalRate(scenario.dividendGrowth ?? scenario.growth ?? 0),
      annualDilution: asDecimalRate(scenario.annualDilution ?? 0),
      probability: asDecimalRate(scenario.probability),
    }));
    const projected = projectCases({ price: validation.price, currentPE: validation.currentPE, years: validation.years, scenarios: scenarioInput });
    if (!projected.ok) return { ok: false, error: projected.error, checklist: validation.items, warnings: validation.warnings };
    const scenarios = {};
    projected.scenarios.forEach(scenario => { scenarios[(scenario.key || scenario.name || "").toLowerCase()] = scenario; });
    const base = scenarioInput.find(scenario => /base/i.test(scenario.name || scenario.key || "")) || scenarioInput[1] || scenarioInput[0];
    const sensitivity = projectionSensitivity({ currentPrice: validation.price, currentEps: validation.eps, currentPE: validation.currentPE, years: validation.years, growth: base.growth, exitPE: base.exitPE });
    const output = {
      ok: true,
      scenarios,
      probabilityWeightedValue: projected.expectedTotalValue,
      currentPrice: validation.price,
      currentPE: validation.currentPE,
      upsideDownsidePercent: projected.expectedTotalValue / validation.price - 1,
      sensitivity,
      warnings: validation.warnings.concat(sensitivity.ok && sensitivity.conclusionFlips ? ["Small changes in growth or exit P/E can reverse the conclusion."] : []),
      raw: projected,
    };
    output.explanation = explainProjection(output);
    return output;
  }

  // ── Year-by-year revenue → EPS → price projection (Projection Lab) ──
  function perYearSeries(value, years) {
    if (Array.isArray(value)) {
      const out = [];
      for (let i = 0; i < years; i += 1) out.push(asDecimalRate(value[i] != null ? value[i] : value[value.length - 1]));
      return out;
    }
    const single = asDecimalRate(value);
    return Array.from({ length: years }, () => single);
  }

  function perYearRaw(value, years) {
    if (Array.isArray(value)) {
      const out = [];
      for (let i = 0; i < years; i += 1) out.push(Number(value[i] != null ? value[i] : value[value.length - 1]));
      return out;
    }
    const single = Number(value);
    return Array.from({ length: years }, () => single);
  }

  // Builds one scenario's year-by-year path. Growth/margin are % (accepts decimals or whole numbers).
  function projectRevenueModel(input) {
    const baseYear = Math.trunc(Number(input.baseYear));
    const years = Math.max(1, Math.min(10, Math.trunc(Number(input.years))));
    const startPrice = Number(input.startPrice);
    const startShares = Number(input.startShares);
    const baseRevenue = Number(input.baseRevenue);
    const shareChange = asDecimalRate(input.shareChange != null ? input.shareChange : 0); // +dilution / −buyback per yr
    if (![baseYear, startPrice, startShares, baseRevenue].every(finite)) return { ok: false, error: "Projection needs a base year, price, shares, and revenue." };
    if (startPrice <= 0 || startShares <= 0 || baseRevenue <= 0) return { ok: false, error: "Price, shares outstanding, and starting revenue must be above zero." };
    if (shareChange <= -1) return { ok: false, error: "Annual share change must be greater than −100%." };
    const revGrowth = perYearSeries(input.revGrowth, years);
    const netMargin = perYearSeries(input.netMargin, years);
    const peLow = perYearRaw(input.peLow, years);
    const peHigh = perYearRaw(input.peHigh, years);
    const rows = [];
    let revenue = baseRevenue;
    for (let i = 1; i <= years; i += 1) {
      const g = revGrowth[i - 1];
      const margin = netMargin[i - 1];
      const pL = peLow[i - 1];
      const pH = peHigh[i - 1];
      if (!finite(g) || g <= -1 || !finite(margin) || !finite(pL) || !finite(pH)) return { ok: false, error: "Enter valid growth, margin, and P/E assumptions for every year." };
      revenue = revenue * (1 + g);
      const netIncome = revenue * margin;
      const shares = startShares * Math.pow(1 + shareChange, i);
      const eps = shares > 0 ? netIncome / shares : NaN;
      const priceLow = eps * pL;
      const priceHigh = eps * pH;
      rows.push({
        year: baseYear + i,
        revenue,
        revGrowth: g,
        netIncome,
        netMargin: margin,
        eps,
        shares,
        peLow: pL,
        peHigh: pH,
        priceLow,
        priceHigh,
        cagrLow: cagr(startPrice, priceLow, i),
        cagrHigh: cagr(startPrice, priceHigh, i),
      });
    }
    const last = rows[rows.length - 1];
    return {
      ok: true,
      baseYear,
      years,
      startPrice,
      startShares,
      baseRevenue,
      rows,
      terminal: { year: last.year, priceLow: last.priceLow, priceHigh: last.priceHigh, priceMid: (last.priceLow + last.priceHigh) / 2, cagrLow: last.cagrLow, cagrHigh: last.cagrHigh, eps: last.eps },
    };
  }

  // Runs bear / base / bull together plus a blended expected outcome.
  function projectRevenueScenarios(input) {
    const shared = {
      baseYear: input.baseYear,
      years: input.years,
      startPrice: input.startPrice,
      startShares: input.startShares,
      baseRevenue: input.baseRevenue,
    };
    const cfg = input.scenarios || {};
    const order = ["bear", "base", "bull"];
    const out = {};
    for (const key of order) {
      const sc = cfg[key] || {};
      const model = projectRevenueModel({ ...shared, revGrowth: sc.revGrowth, netMargin: sc.netMargin, peLow: sc.peLow, peHigh: sc.peHigh, shareChange: sc.shareChange });
      if (!model.ok) return { ok: false, error: model.error, scenario: key };
      out[key] = model;
    }
    // Blended expected terminal (probability weighted; defaults 25/50/25)
    const weights = input.weights || { bear: 0.25, base: 0.5, bull: 0.25 };
    const wSum = order.reduce((s, k) => s + (Number(weights[k]) || 0), 0) || 1;
    const midOf = k => out[k].terminal.priceMid;
    const expectedPrice = order.reduce((s, k) => s + midOf(k) * ((Number(weights[k]) || 0) / wSum), 0);
    const expectedCagr = cagr(shared_startPrice(shared), expectedPrice, Number(input.years));
    return {
      ok: true,
      scenarios: out,
      envelope: { priceLow: out.bear.terminal.priceLow, priceHigh: out.bull.terminal.priceHigh, cagrLow: out.bear.terminal.cagrLow, cagrHigh: out.bull.terminal.cagrHigh },
  
      expected: { price: expectedPrice, cagr: expectedCagr, weights, year: out.base.terminal.year },
    };
  }
  function shared_startPrice(shared) { return Number(shared.startPrice); }

  function epsDcf(input) {
    const eps = Number(input.eps);
    const growth1 = Number(input.growth1);
    const growth2 = Number(input.growth2);
    const terminalGrowth = Number(input.terminalGrowth);
    const discountRate = Number(input.discountRate);
    if (![eps, growth1, growth2, terminalGrowth, discountRate].every(finite)) return { ok: false, error: "Enter valid numeric assumptions." };
    if (eps <= 0) return { ok: false, error: "The EPS-based model requires positive current EPS." };
    if (growth1 <= -1 || growth2 <= -1 || terminalGrowth <= -1) return { ok: false, error: "Growth assumptions must be greater than -100%." };
    if (discountRate <= 0) return { ok: false, error: "Discount rate must be above zero." };
    if (discountRate <= terminalGrowth) return { ok: false, error: "Discount rate must be greater than terminal growth." };
    let pvCF = 0;
    let epsValue = eps;
    for (let year = 1; year <= 5; year += 1) {
      epsValue *= 1 + growth1;
      pvCF += epsValue / Math.pow(1 + discountRate, year);
    }
    for (let year = 6; year <= 10; year += 1) {
      epsValue *= 1 + growth2;
      pvCF += epsValue / Math.pow(1 + discountRate, year);
    }
    const terminalValue = epsValue * (1 + terminalGrowth) / (discountRate - terminalGrowth);
    const pvTv = terminalValue / Math.pow(1 + discountRate, 10);
    const intrinsic = pvCF + pvTv;
    return { ok: true, pvCF, pvTv, intrinsic, terminalShare: intrinsic > 0 ? pvTv / intrinsic : 0 };
  }

  function annualizedVolatility(prices, periodsPerYear) {
    const clean = Array.isArray(prices) ? prices.map(Number).filter(value => finite(value) && value > 0) : [];
    const periods = Number(periodsPerYear ?? 252);
    if (clean.length < 3 || !finite(periods) || periods <= 0) return 0;
    const returns = clean.slice(1).map((value, index) => value / clean[index] - 1);
    const mean = returns.reduce((sum, value) => sum + value, 0) / returns.length;
    const variance = returns.reduce((sum, value) => sum + Math.pow(value - mean, 2), 0) / (returns.length - 1);
    return Math.sqrt(variance) * Math.sqrt(periods);
  }

  function futureValue(input) {
    const principal = Number(input.principal ?? 0);
    const monthlyContribution = Number(input.monthlyContribution ?? 0);
    const annualReturn = Number(input.annualReturn);
    const annualFee = Number(input.annualFee ?? 0);
    const taxDrag = Number(input.taxDrag ?? 0);
    const years = Number(input.years);
    if (![principal, monthlyContribution, annualReturn, annualFee, taxDrag, years].every(finite)) return { ok: false, error: "Enter valid numeric assumptions." };
    if (principal < 0 || monthlyContribution < 0 || years <= 0) return { ok: false, error: "Starting balance and contributions cannot be negative, and years must be above zero." };
    if (annualFee < 0 || taxDrag < 0) return { ok: false, error: "Annual fees and tax drag cannot be negative." };
    const effectiveAnnualReturn = annualReturn - annualFee - taxDrag;
    if (effectiveAnnualReturn <= -1) return { ok: false, error: "Return after fees and tax drag must be greater than -100%." };

    const months = Math.round(years * 12);
    const monthlyRate = Math.pow(1 + effectiveAnnualReturn, 1 / 12) - 1;
    const path = [{ month: 0, value: principal, contributions: principal }];
    let value = principal;
    let contributions = principal;
    for (let month = 1; month <= months; month += 1) {
      value *= 1 + monthlyRate;
      value += monthlyContribution;
      contributions += monthlyContribution;
      if (month % 12 === 0 || month === months) path.push({ month, value, contributions });
    }
    return { ok: true, value, contributions, growth: value - contributions, effectiveAnnualReturn, path };
  }

  function compoundScenarios(input) {
    const baseReturn = Number(input.baseReturn);
    const variance = Number(input.variance ?? 0);
    const inflation = Number(input.inflation ?? 0);
    if (![baseReturn, variance, inflation].every(finite) || variance < 0 || inflation <= -1) {
      return { ok: false, error: "Enter valid return, variance, and inflation assumptions." };
    }
    const build = annualReturn => futureValue({ ...input, annualReturn });
    const low = build(baseReturn - variance);
    const base = build(baseReturn);
    const high = build(baseReturn + variance);
    if (![low, base, high].every(result => result.ok)) return [low, base, high].find(result => !result.ok);
    const realValue = base.value / Math.pow(1 + inflation, Number(input.years));
    return { ok: true, low, base, high, realValue };
  }

  // ════════ VALUATION LAB — operating model + multi-method valuation (Phase 1) ════════
  function pct(v) { return Number(v); }  // operating model expects decimal fractions (0.15 = 15%)
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


  return { cagr, cumulativeDividends, projectScenario, projectCases, asDecimalRate, validateProjectionContext, projectionSensitivity, explainProjection, buildProjection, projectRevenueModel, projectRevenueScenarios, projectOperatingModel, valueOperatingModel, runValuation, runValuationScenarios, reverseSolveValuation, valuationSensitivityGrid, epsDcf, annualizedVolatility, futureValue, compoundScenarios };
});

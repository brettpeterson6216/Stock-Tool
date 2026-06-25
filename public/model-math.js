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

  return { cagr, cumulativeDividends, projectScenario, projectCases, asDecimalRate, validateProjectionContext, projectionSensitivity, explainProjection, buildProjection, epsDcf, annualizedVolatility, futureValue, compoundScenarios };
});

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
    if (![price, currentPE, exitPE, growth, years, earningsMultiplier, dividendYield].every(finite)) return { ok: false, error: "Enter valid numeric assumptions." };
    if (price <= 0 || currentPE <= 0 || exitPE <= 0 || years <= 0 || earningsMultiplier <= 0) return { ok: false, error: "Price, P/E ratios, horizon, and earnings multiplier must be above zero." };
    if (growth <= -1) return { ok: false, error: "Annual growth must be greater than -100%." };
    if (dividendYield < 0) return { ok: false, error: "Dividend yield cannot be negative." };
    const eps0 = price / currentPE;
    const pricePath = [price];
    const dividendPath = [0];
    const totalValuePath = [price];
    for (let year = 1; year <= years; year += 1) {
      const projectedPrice = eps0 * Math.pow(1 + growth, year) * earningsMultiplier * exitPE;
      const dividends = cumulativeDividends(price, dividendYield, growth, year);
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

  return { cagr, cumulativeDividends, projectScenario, epsDcf, annualizedVolatility };
});

"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const engine = require("../labs/lens-score/lens-score-engine");
const calibration = require("../lib/lens-calibration");

function makeBars(count = 360, options = {}) {
  const bars = [];
  let close = options.start ?? 100;
  const drift = options.drift ?? 0.0007;
  for (let i = 0; i < count; i += 1) {
    const wave = Math.sin(i / 13) * (options.wave ?? 0.008);
    const noise = Math.sin(i * 1.73) * (options.noise ?? 0.004);
    const open = close * (1 + Math.sin(i / 5) * 0.002);
    close = Math.max(2, close * (1 + drift + wave + noise));
    const spread = close * 0.012;
    bars.push({
      time: 1_700_000_000 + i * 86_400,
      open,
      high: Math.max(open, close) + spread,
      low: Math.min(open, close) - spread,
      close,
      volume: 10_000_000 + (i % 17) * 420_000,
    });
  }
  return bars;
}

function makeAlignedPullbackBars(count = 360, seed = 429) {
  let value = seed;
  const random = () => {
    let t = value += 0x6D2B79F5;
    t = Math.imul(t ^ t >>> 15, t | 1);
    t ^= t + Math.imul(t ^ t >>> 7, t | 61);
    return ((t ^ t >>> 14) >>> 0) / 4294967296;
  };
  const bars = [];
  let close = 100;
  for (let i = 0; i < count; i += 1) {
    let change = 0.0005 + (random() - 0.5) * 0.03;
    if (i > count - 15) change += (count - 10 - i) * 0.0005;
    const open = close;
    close = Math.max(5, close * (1 + change));
    const spread = close * (0.006 + random() * 0.012);
    bars.push({
      time: 1_700_000_000 + i * 86_400,
      open,
      high: Math.max(open, close) + spread,
      low: Math.min(open, close) - spread,
      close,
      volume: 10_000_000 * (0.6 + random() * 1.2),
    });
  }
  bars.at(-1).volume *= 3;
  return bars;
}

const healthyFundamentals = {
  revenueGrowth: 0.16,
  epsGrowth: 0.19,
  fcfMargin: 0.24,
  roic: 0.25,
  netDebtEbitda: 0.2,
  interestCoverage: 20,
  dilution: -0.01,
  forwardPE: 22,
  dcfUpside: 0.25,
  impliedGrowthGap: 0.01,
  bearDownside: -0.16,
};

test("LensScore returns one bounded 0-10 score with component transparency", () => {
  const result = engine.scoreLens({ bars: makeBars(), fundamentals: healthyFundamentals });
  assert.equal(result.status, "graded");
  assert.ok(result.score >= 0 && result.score <= 10);
  assert.equal(Object.keys(result.components).length, 5);
  assert.ok(result.lenses.setup.score >= 0 && result.lenses.setup.score <= 10);
  assert.ok(result.lenses.value.score >= 0 && result.lenses.value.score <= 10);
  assert.equal(result.lenses.combined.score, result.score);
  assert.ok(result.modelDetails.qualityScore >= 0 && result.modelDetails.qualityScore <= 100);
  assert.ok(result.modelDetails.qualityCap >= 0 && result.modelDetails.qualityCap <= 100);
  assert.match(result.label, /Exceptional Lens|Strong Lens|Constructive|Developing|Neutral|Unfavorable|Weak|Severe Risk/);
});

test("stronger fundamentals and valuation improve LensScore for the same chart", () => {
  const bars = makeBars();
  const strong = engine.scoreLens({ bars, fundamentals: healthyFundamentals });
  const weak = engine.scoreLens({
    bars,
    fundamentals: {
      revenueGrowth: -0.08,
      epsGrowth: -0.15,
      fcfMargin: 0.01,
      roic: 0.01,
      netDebtEbitda: 4.5,
      interestCoverage: 1.2,
      dilution: 0.07,
      forwardPE: 58,
      dcfUpside: -0.28,
      impliedGrowthGap: 0.14,
      bearDownside: -0.55,
    },
  });
  assert.ok(strong.score > weak.score, `${strong.score} should exceed ${weak.score}`);
  assert.ok(strong.components.fundamentals > weak.components.fundamentals);
  assert.ok(strong.components.valuation > weak.components.valuation);
  assert.ok(strong.components.risk > weak.components.risk);
});

test("a half-price strong company reaches exceptional LensValue while setup remains independent", () => {
  const bars = makeBars();
  const current = engine.scoreLens({
    bars,
    fundamentals: {
      ...healthyFundamentals,
      forwardPE: 32,
      dcfUpside: 0.12,
      impliedGrowthGap: 0.05,
      bearDownside: -0.25,
    },
  });
  const halfPriceAllElseEqual = engine.scoreLens({
    bars,
    fundamentals: {
      ...healthyFundamentals,
      forwardPE: 16,
      dcfUpside: 1.24,
      impliedGrowthGap: -0.075,
      bearDownside: 0.50,
    },
  });
  assert.ok(current.lenses.value.score >= 7, `Expected an already-attractive LensValue, received ${current.lenses.value.score}`);
  assert.ok(halfPriceAllElseEqual.lenses.value.score >= 9.5,
    `Expected exceptional LensValue, received ${halfPriceAllElseEqual.lenses.value.score}`);
  assert.ok(halfPriceAllElseEqual.score >= 7.5,
    `Expected a high combined LensScore, received ${halfPriceAllElseEqual.score}`);
  assert.equal(halfPriceAllElseEqual.lenses.setup.score, current.lenses.setup.score);
  assert.ok(halfPriceAllElseEqual.score > current.score);
});

test("Golden Lens requires both exceptional long-term value and an aligned tactical pullback", () => {
  const bars = makeAlignedPullbackBars();
  const aligned = engine.scoreLens({
    bars,
    fundamentals: {
      ...healthyFundamentals,
      forwardPE: 16,
      dcfUpside: 1.24,
      impliedGrowthGap: -0.075,
      bearDownside: 0.50,
    },
  });
  const expensive = engine.scoreLens({
    bars,
    fundamentals: {
      ...healthyFundamentals,
      forwardPE: 50,
      dcfUpside: -0.25,
      impliedGrowthGap: 0.14,
      bearDownside: -0.50,
    },
  });

  assert.ok(aligned.lenses.setup.score >= 8);
  assert.ok(aligned.lenses.value.score >= 8.5);
  assert.equal(aligned.lenses.goldenLens.active, true);
  assert.equal(expensive.lenses.goldenLens.active, false);
  assert.equal(expensive.lenses.setup.score, aligned.lenses.setup.score);
  assert.ok(expensive.lenses.value.score < aligned.lenses.value.score);
});

test("LensTiming is independent from LensTrend and penalizes an extended entry", () => {
  const bars = makeBars(360, { drift: 0.0008, wave: 0.002, noise: 0.001 });
  const technical = engine.analyzeTechnical(bars);
  assert.ok(technical.trendRegime.trendScore >= 8, "Expected a strong trend");
  assert.ok(technical.timing.timingScore <= 2, "Expected seller-side entry pressure");
  assert.ok(technical.setupGuardrails.some(item => /Extension guardrail/.test(item)));
});

test("a poor company cannot reach the top of the scale solely because it looks cheap", () => {
  const result = engine.scoreLens({
    bars: makeBars(),
    fundamentals: {
      revenueGrowth: -0.08,
      epsGrowth: -0.15,
      fcfMargin: 0.01,
      roic: 0.01,
      netDebtEbitda: 4.5,
      interestCoverage: 1.2,
      dilution: 0.07,
      forwardPE: 7,
      dcfUpside: 1.2,
      impliedGrowthGap: -0.08,
      bearDownside: 0.15,
    },
  });
  assert.ok(result.score <= 7);
  assert.ok(result.modelDetails.qualityCap <= 70);
});

test("going-concern and extreme leverage guardrails cap the score", () => {
  const goingConcern = engine.scoreLens({
    bars: makeBars(),
    fundamentals: { ...healthyFundamentals, goingConcern: true },
  });
  assert.ok(goingConcern.score <= 2.9);
  assert.match(goingConcern.caps.join(" "), /Going-concern/);

  const leveraged = engine.scoreLens({
    bars: makeBars(),
    fundamentals: { ...healthyFundamentals, netDebtEbitda: 7 },
  });
  assert.ok(leveraged.score <= 3.9);
  assert.match(leveraged.caps.join(" "), /leverage/);
});

test("insufficient chart history produces Not Rated instead of a fabricated score", () => {
  const result = engine.scoreLens({ bars: makeBars(40), fundamentals: healthyFundamentals });
  assert.equal(result.status, "not-rated");
  assert.equal(result.score, null);
  assert.equal(result.label, "Not Rated");
});

test("null fundamental fields are missing evidence, not zero-valued evidence", () => {
  const bars = makeBars(420, { start: 95, drift: 0.0007 });
  const result = engine.scoreLens({
    bars,
    fundamentals: {
      revenueGrowth: null,
      epsGrowth: null,
      fcfMargin: null,
      roic: null,
      netDebtEbitda: null,
      interestCoverage: null,
      dilution: null,
      forwardPE: null,
      dcfUpside: null,
      impliedGrowthGap: null,
      bearDownside: null,
    },
  });
  assert.equal(result.status, "not-rated");
  assert.match(result.reason, /fundamental|valuation|evidence/i);
  assert.equal(result.lenses.setup.status, "graded");
  assert.ok(result.lenses.setup.score >= 0 && result.lenses.setup.score <= 10);
  assert.equal(result.lenses.value.status, "not-rated");
  assert.equal(result.lenses.combined.score, null);
});

test("confirmed pivots expose confirmation indexes and never include the final unconfirmed bars", () => {
  const bars = makeBars(180, { wave: 0.018, noise: 0.002 });
  const pivots = engine.confirmedPivots(bars, 4, 4);
  assert.ok(pivots.lows.length > 0);
  assert.ok(pivots.highs.length > 0);
  for (const pivot of [...pivots.lows, ...pivots.highs]) {
    assert.equal(pivot.confirmedIndex, pivot.index + 4);
    assert.ok(pivot.confirmedIndex < bars.length);
  }
});

test("support and resistance zones are bounded and include traceable strength", () => {
  const zones = engine.detectZones(makeBars(360, { wave: 0.014 }));
  assert.ok(Array.isArray(zones.support));
  assert.ok(Array.isArray(zones.resistance));
  for (const zone of [...zones.support, ...zones.resistance]) {
    assert.ok(zone.lower < zone.upper);
    assert.ok(zone.strength >= 0 && zone.strength <= 100);
    assert.ok(zone.touches >= 1);
    assert.ok(zone.confirmedIndex <= zone.lastIndex + 4);
  }
});

test("indicator calculations remain finite on a valid daily series", () => {
  const bars = makeBars();
  const technical = engine.analyzeTechnical(bars);
  assert.equal(technical.status, "ok");
  assert.ok(Number.isFinite(technical.indicators.rsi));
  assert.ok(Number.isFinite(technical.indicators.stochasticRsi));
  assert.ok(Number.isFinite(technical.indicators.bollingerPosition));
  assert.ok(Number.isFinite(technical.indicators.atr));
  assert.ok(Number.isFinite(technical.indicators.macd.histogram));
  assert.ok(technical.trend >= 0 && technical.trend <= 100);
  assert.ok(technical.momentumVolume >= 0 && technical.momentumVolume <= 100);
});

test("LensTrend distinguishes persistent uptrends from downtrends on a 0-10 scale", () => {
  const uptrend = engine.calculateTrendRegime(makeBars(360, {
    drift: 0.0022,
    wave: 0.0015,
    noise: 0.0008,
  }));
  const downtrend = engine.calculateTrendRegime(makeBars(360, {
    drift: -0.0022,
    wave: 0.0015,
    noise: 0.0008,
  }));

  assert.equal(uptrend.status, "ok");
  assert.equal(downtrend.status, "ok");
  assert.ok(uptrend.trendScore >= 6.5, `Expected an uptrend regime, received ${uptrend.trendScore}`);
  assert.ok(downtrend.trendScore <= 3.5, `Expected a downtrend regime, received ${downtrend.trendScore}`);
  assert.ok(uptrend.agreement >= 3);
  assert.ok(downtrend.agreement >= 3);
  assert.ok(uptrend.trendScore >= 0 && uptrend.trendScore <= 10);
  assert.ok(downtrend.trendScore >= 0 && downtrend.trendScore <= 10);
});

test("historical trend readings use only information available at that date", () => {
  const bars = makeBars(360, { drift: 0.001, wave: 0.004, noise: 0.001 });
  const prefix = bars.slice(0, 300);
  const prefixRegime = engine.calculateTrendRegime(prefix);
  const fullRegime = engine.calculateTrendRegime(bars);
  const matchingPoint = fullRegime.series.find(point => point.time === prefix[prefix.length - 1].time);

  assert.ok(matchingPoint);
  assert.equal(prefixRegime.trendScore, matchingPoint.trendScore);
  assert.equal(prefixRegime.agreement, matchingPoint.agreement);
});

test("walk-forward LensSetup calibration never reads prices after the observation date", () => {
  const original = makeBars(520, { drift: 0.0008, wave: 0.004, noise: 0.001 });
  const changedFuture = original.map(bar => ({ ...bar }));
  for (let index = 400; index < changedFuture.length; index += 1) {
    changedFuture[index].open *= 0.25;
    changedFuture[index].high *= 0.25;
    changedFuture[index].low *= 0.25;
    changedFuture[index].close *= 0.25;
  }
  const first = calibration.calibrateSetupSeries({ TEST: original }, {
    minimumBars: 252, sampleEvery: 70, horizons: [21],
  });
  const second = calibration.calibrateSetupSeries({ TEST: changedFuture }, {
    minimumBars: 252, sampleEvery: 70, horizons: [21],
  });
  const beforeChange = first.observations.filter(item => item.time < changedFuture[400].time);
  assert.ok(beforeChange.length > 0);
  for (const observation of beforeChange) {
    const match = second.observations.find(item => item.time === observation.time);
    assert.ok(match);
    assert.equal(match.score, observation.score);
  }
  assert.equal(first.methodology.lookahead, false);
});

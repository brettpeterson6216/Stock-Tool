"use strict";

const engine = require("./lens-score-engine");

function finite(value) {
  return value !== null && value !== undefined && value !== "" && Number.isFinite(Number(value));
}

function mean(values) {
  const clean = values.filter(finite).map(Number);
  return clean.length ? clean.reduce((sum, value) => sum + value, 0) / clean.length : null;
}

function median(values) {
  const clean = values.filter(finite).map(Number).sort((a, b) => a - b);
  if (!clean.length) return null;
  const middle = Math.floor(clean.length / 2);
  return clean.length % 2 ? clean[middle] : (clean[middle - 1] + clean[middle]) / 2;
}

function correlation(pairs) {
  const clean = pairs.filter(pair => finite(pair.x) && finite(pair.y));
  if (clean.length < 3) return null;
  const xMean = mean(clean.map(pair => pair.x));
  const yMean = mean(clean.map(pair => pair.y));
  let numerator = 0;
  let xVariance = 0;
  let yVariance = 0;
  for (const pair of clean) {
    const xDelta = pair.x - xMean;
    const yDelta = pair.y - yMean;
    numerator += xDelta * yDelta;
    xVariance += xDelta ** 2;
    yVariance += yDelta ** 2;
  }
  return xVariance > 0 && yVariance > 0
    ? numerator / Math.sqrt(xVariance * yVariance)
    : null;
}

function forwardOutcome(bars, index, horizon) {
  if (!bars[index] || !bars[index + horizon]) return null;
  const entry = Number(bars[index].close);
  if (!(entry > 0)) return null;
  const future = bars.slice(index + 1, index + horizon + 1);
  const terminal = Number(future.at(-1)?.close);
  if (!(terminal > 0)) return null;
  let peak = entry;
  let maxDrawdown = 0;
  let maxAdverseExcursion = 0;
  let maxFavorableExcursion = 0;
  for (const bar of future) {
    const close = Number(bar.close);
    const low = Number(bar.low);
    const high = Number(bar.high);
    if (close > peak) peak = close;
    if (close > 0 && peak > 0) maxDrawdown = Math.min(maxDrawdown, close / peak - 1);
    if (low > 0) maxAdverseExcursion = Math.min(maxAdverseExcursion, low / entry - 1);
    if (high > 0) maxFavorableExcursion = Math.max(maxFavorableExcursion, high / entry - 1);
  }
  return {
    return: terminal / entry - 1,
    maxDrawdown,
    maxAdverseExcursion,
    maxFavorableExcursion,
  };
}

function bucketFor(score) {
  if (!finite(score)) return null;
  return Math.max(0, Math.min(9, Math.floor(Number(score))));
}

function summarizeBuckets(observations, horizon) {
  const groups = Array.from({ length: 10 }, (_, bucket) => ({ bucket, rows: [] }));
  for (const observation of observations) {
    const outcome = observation.outcomes[horizon];
    const bucket = bucketFor(observation.score);
    if (bucket !== null && outcome) groups[bucket].rows.push({ observation, outcome });
  }
  return groups.map(group => {
    const returns = group.rows.map(row => row.outcome.return);
    const drawdowns = group.rows.map(row => row.outcome.maxDrawdown);
    return {
      range: `${group.bucket}.0–${group.bucket + 0.9}`,
      observations: group.rows.length,
      averageReturn: mean(returns),
      medianReturn: median(returns),
      positiveRate: returns.length ? returns.filter(value => value > 0).length / returns.length : null,
      averageMaxDrawdown: mean(drawdowns),
    };
  });
}

function evaluateObservations(observations, horizons) {
  const result = {};
  for (const horizon of horizons) {
    const eligible = observations.filter(observation => observation.outcomes[horizon]);
    const pairs = eligible.map(observation => ({
      x: observation.score,
      y: observation.outcomes[horizon].return,
    }));
    const high = eligible.filter(observation => observation.score >= 8);
    const low = eligible.filter(observation => observation.score <= 4);
    result[horizon] = {
      observations: eligible.length,
      scoreReturnCorrelation: correlation(pairs),
      averageReturn: mean(eligible.map(item => item.outcomes[horizon].return)),
      highScoreAverageReturn: mean(high.map(item => item.outcomes[horizon].return)),
      highScorePositiveRate: high.length
        ? high.filter(item => item.outcomes[horizon].return > 0).length / high.length
        : null,
      lowScoreAverageReturn: mean(low.map(item => item.outcomes[horizon].return)),
      lowScorePositiveRate: low.length
        ? low.filter(item => item.outcomes[horizon].return > 0).length / low.length
        : null,
      buckets: summarizeBuckets(eligible, horizon),
    };
  }
  return result;
}

function calibrateSetupSeries(seriesByTicker, options = {}) {
  const minimumBars = options.minimumBars || 252;
  const sampleEvery = options.sampleEvery || 63;
  const horizons = options.horizons || [21, 63];
  const observations = [];

  for (const [ticker, rawBars] of Object.entries(seriesByTicker || {})) {
    const bars = engine.normalizeBars(rawBars);
    const maxHorizon = Math.max(...horizons);
    for (let index = minimumBars - 1; index + maxHorizon < bars.length; index += sampleEvery) {
      const prefix = bars.slice(0, index + 1);
      const technical = engine.analyzeTechnical(prefix);
      if (technical.status !== "ok" || !finite(technical.setupScore)) continue;
      const outcomes = {};
      for (const horizon of horizons) outcomes[horizon] = forwardOutcome(bars, index, horizon);
      observations.push({
        ticker,
        time: bars[index].time,
        score: technical.setupScore / 10,
        trendScore: technical.trendRegime.trendScore,
        outcomes,
      });
    }
  }

  return {
    methodology: {
      type: "walk-forward",
      lookahead: false,
      minimumBars,
      sampleEvery,
      horizons,
      note: "Every score is calculated from a price-history prefix ending on the observation date.",
    },
    observations,
    summary: evaluateObservations(observations, horizons),
  };
}

function calibrateCombinedSeries(seriesByTicker, pointInTimeFundamentals, options = {}) {
  const minimumBars = options.minimumBars || 252;
  const sampleEvery = options.sampleEvery || 63;
  const horizons = options.horizons || [126, 252];
  const observations = [];

  for (const [ticker, rawBars] of Object.entries(seriesByTicker || {})) {
    const bars = engine.normalizeBars(rawBars);
    const snapshots = [...(pointInTimeFundamentals?.[ticker] || [])]
      .filter(snapshot => finite(snapshot.availableAt))
      .sort((a, b) => a.availableAt - b.availableAt);
    if (!snapshots.length) continue;
    const maxHorizon = Math.max(...horizons);
    for (let index = minimumBars - 1; index + maxHorizon < bars.length; index += sampleEvery) {
      const time = bars[index].time;
      const eligible = snapshots.filter(snapshot => snapshot.availableAt <= time);
      const snapshot = eligible.at(-1);
      if (!snapshot) continue;
      const result = engine.scoreLens({
        bars: bars.slice(0, index + 1),
        fundamentals: snapshot.values,
        metadata: { ticker, historical: true, fundamentalAvailableAt: snapshot.availableAt },
      });
      if (result.status !== "graded") continue;
      const outcomes = {};
      for (const horizon of horizons) outcomes[horizon] = forwardOutcome(bars, index, horizon);
      observations.push({
        ticker,
        time,
        score: result.score,
        setupScore: result.lenses.setup.score,
        valueScore: result.lenses.value.score,
        goldenLens: result.lenses.goldenLens.active,
        fundamentalAvailableAt: snapshot.availableAt,
        outcomes,
      });
    }
  }

  return {
    methodology: {
      type: "point-in-time walk-forward",
      lookahead: false,
      minimumBars,
      sampleEvery,
      horizons,
      note: "A fundamental snapshot is eligible only after its reported availability timestamp.",
    },
    observations,
    summary: evaluateObservations(observations, horizons),
    goldenLens: Object.fromEntries(horizons.map(horizon => {
      const rows = observations.filter(item => item.goldenLens && item.outcomes[horizon]);
      return [horizon, {
        observations: rows.length,
        averageReturn: mean(rows.map(item => item.outcomes[horizon].return)),
        positiveRate: rows.length ? rows.filter(item => item.outcomes[horizon].return > 0).length / rows.length : null,
        averageMaxDrawdown: mean(rows.map(item => item.outcomes[horizon].maxDrawdown)),
      }];
    })),
  };
}

module.exports = {
  calibrateCombinedSeries,
  calibrateSetupSeries,
  correlation,
  evaluateObservations,
  forwardOutcome,
};

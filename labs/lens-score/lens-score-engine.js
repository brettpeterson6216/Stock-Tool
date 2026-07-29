(function (root, factory) {
  "use strict";
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  if (root) root.LensScoreEngine = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  const VERSION = "0.6.0";
  const MODEL = Object.freeze({
    qualityFundamentals: 0.75,
    qualityRisk: 0.25,
    baseQuality: 0.55,
    baseValuation: 0.45,
    alignmentBonusRate: 0.25,
    maxAlignmentBonus: 7.5,
    combinedValue: 0.70,
    combinedSetup: 0.30,
    crossLensBonusRate: 0.20,
    maxCrossLensBonus: 5,
    mismatchPenaltyRate: 0.10,
    maxMismatchPenalty: 5,
    goldenValueMinimum: 85,
    goldenSetupMinimum: 80,
    goldenCombinedMinimum: 85,
  });

  function finite(value) {
    return value !== null && value !== undefined && value !== "" && Number.isFinite(Number(value));
  }

  function clamp(value, min = 0, max = 100) {
    return Math.min(max, Math.max(min, Number(value)));
  }

  function round(value, places = 1) {
    const factor = 10 ** places;
    return Math.round(Number(value) * factor) / factor;
  }

  function scale(value, bad, good) {
    if (!finite(value) || bad === good) return null;
    return clamp(((Number(value) - bad) / (good - bad)) * 100);
  }

  function average(values) {
    const clean = values.filter(finite).map(Number);
    return clean.length ? clean.reduce((sum, value) => sum + value, 0) / clean.length : null;
  }

  function last(values) {
    for (let i = values.length - 1; i >= 0; i -= 1) {
      if (finite(values[i])) return Number(values[i]);
    }
    return null;
  }

  function normalizeBars(rawBars) {
    return (Array.isArray(rawBars) ? rawBars : [])
      .map((bar, index) => ({
        time: Number(bar.time ?? bar.t ?? index),
        open: Number(bar.open ?? bar.o),
        high: Number(bar.high ?? bar.h),
        low: Number(bar.low ?? bar.l),
        close: Number(bar.close ?? bar.c),
        volume: Number(bar.volume ?? bar.v ?? 0),
      }))
      .filter(bar =>
        finite(bar.time) && finite(bar.open) && finite(bar.high) &&
        finite(bar.low) && finite(bar.close) && bar.close > 0
      )
      .sort((a, b) => a.time - b.time);
  }

  function sma(values, period) {
    const output = Array(values.length).fill(null);
    let sum = 0;
    let valid = 0;
    for (let i = 0; i < values.length; i += 1) {
      if (finite(values[i])) {
        sum += Number(values[i]);
        valid += 1;
      }
      if (i >= period && finite(values[i - period])) {
        sum -= Number(values[i - period]);
        valid -= 1;
      }
      if (i >= period - 1 && valid === period) output[i] = sum / period;
    }
    return output;
  }

  function ema(values, period) {
    const output = Array(values.length).fill(null);
    const multiplier = 2 / (period + 1);
    let seed = [];
    let previous = null;
    for (let i = 0; i < values.length; i += 1) {
      if (!finite(values[i])) continue;
      const value = Number(values[i]);
      if (previous === null) {
        seed.push(value);
        if (seed.length === period) {
          previous = average(seed);
          output[i] = previous;
        }
      } else {
        previous = value * multiplier + previous * (1 - multiplier);
        output[i] = previous;
      }
    }
    return output;
  }

  function rsiSeries(values, period = 14) {
    const output = Array(values.length).fill(null);
    if (values.length <= period) return output;
    let gains = 0;
    let losses = 0;
    for (let i = 1; i <= period; i += 1) {
      const change = Number(values[i]) - Number(values[i - 1]);
      if (change >= 0) gains += change;
      else losses -= change;
    }
    let averageGain = gains / period;
    let averageLoss = losses / period;
    output[period] = averageLoss === 0
      ? 100
      : 100 - 100 / (1 + averageGain / averageLoss);
    for (let i = period + 1; i < values.length; i += 1) {
      const change = Number(values[i]) - Number(values[i - 1]);
      const gain = Math.max(0, change);
      const loss = Math.max(0, -change);
      averageGain = (averageGain * (period - 1) + gain) / period;
      averageLoss = (averageLoss * (period - 1) + loss) / period;
      output[i] = averageLoss === 0
        ? 100
        : 100 - 100 / (1 + averageGain / averageLoss);
    }
    return output;
  }

  function rsi(values, period = 14) {
    return last(rsiSeries(values, period));
  }

  function macdSeries(values) {
    const fast = ema(values, 12);
    const slow = ema(values, 26);
    const line = values.map((_, i) =>
      finite(fast[i]) && finite(slow[i]) ? fast[i] - slow[i] : null
    );
    const signal = ema(line, 9);
    const histogram = line.map((value, i) =>
      finite(value) && finite(signal[i]) ? value - signal[i] : null
    );
    return { line, signal, histogram };
  }

  function macd(values) {
    const series = macdSeries(values);
    return {
      line: last(series.line),
      signal: last(series.signal),
      histogram: last(series.histogram),
    };
  }

  function atr(bars, period = 14) {
    if (bars.length < 2) return null;
    const trueRanges = bars.map((bar, i) => {
      if (i === 0) return bar.high - bar.low;
      return Math.max(
        bar.high - bar.low,
        Math.abs(bar.high - bars[i - 1].close),
        Math.abs(bar.low - bars[i - 1].close)
      );
    });
    return last(ema(trueRanges, period));
  }

  function rateOfChange(values, period) {
    if (values.length <= period) return null;
    const current = Number(values[values.length - 1]);
    const previous = Number(values[values.length - 1 - period]);
    return previous > 0 ? current / previous - 1 : null;
  }

  function standardDeviation(values) {
    const mean = average(values);
    if (!finite(mean)) return null;
    return Math.sqrt(average(values.map(value => (Number(value) - mean) ** 2)));
  }

  function rollingStandardDeviation(values, period) {
    return values.map((_, index) => {
      if (index < period - 1) return null;
      const window = values.slice(index - period + 1, index + 1).filter(finite);
      return window.length === period ? standardDeviation(window) : null;
    });
  }

  function stochasticRsiSeries(values, rsiPeriod = 14, stochPeriod = 14, smoothing = 3) {
    const rsiValues = rsiSeries(values, rsiPeriod);
    const raw = rsiValues.map((value, index) => {
      if (!finite(value) || index < rsiPeriod + stochPeriod - 1) return null;
      const window = rsiValues
        .slice(index - stochPeriod + 1, index + 1)
        .filter(finite)
        .map(Number);
      if (window.length !== stochPeriod) return null;
      const low = Math.min(...window);
      const high = Math.max(...window);
      return high === low ? 50 : ((Number(value) - low) / (high - low)) * 100;
    });
    return sma(raw, smoothing);
  }

  function classifyTrendRegime(value) {
    if (!finite(value)) return { key: "unknown", label: "Not enough data", tone: "neutral" };
    if (value >= 3.25) return { key: "strong-uptrend", label: "Strong uptrend", tone: "bullish" };
    if (value >= 1.5) return { key: "uptrend", label: "Uptrend", tone: "bullish" };
    if (value >= 0.5) return { key: "developing-uptrend", label: "Developing uptrend", tone: "positive" };
    if (value > -0.5) return { key: "range", label: "Range / transition", tone: "neutral" };
    if (value > -1.5) return { key: "developing-downtrend", label: "Developing downtrend", tone: "weak" };
    if (value > -3.25) return { key: "downtrend", label: "Downtrend", tone: "bearish" };
    return { key: "strong-downtrend", label: "Strong downtrend", tone: "bearish" };
  }

  function calculateTrendRegime(rawBars) {
    const bars = normalizeBars(rawBars);
    if (bars.length < 60) {
      return {
        status: "insufficient",
        trendScore: null,
        score: null,
        label: "Not enough data",
        agreement: 0,
        inputs: {},
        series: [],
      };
    }

    const closes = bars.map(bar => bar.close);
    const ema20 = ema(closes, 20);
    const ema50 = ema(closes, 50);
    const ma200 = sma(closes, 200);
    const rsiValues = rsiSeries(closes, 14);
    const stochRsiValues = stochasticRsiSeries(closes, 14, 14, 3);
    const macdValues = macdSeries(closes);
    const macdVolatility = rollingStandardDeviation(macdValues.histogram, 100);
    const middleBand = sma(closes, 20);
    const bandVolatility = rollingStandardDeviation(closes, 20);

    const unsmoothed = bars.map((bar, index) => {
      const structureVotes = [];
      if (finite(ema20[index])) structureVotes.push(bar.close >= ema20[index] ? 1 : -1);
      if (finite(ema20[index]) && finite(ema50[index])) structureVotes.push(ema20[index] >= ema50[index] ? 1 : -1);
      if (finite(ema50[index]) && finite(ma200[index])) structureVotes.push(ema50[index] >= ma200[index] ? 1 : -1);
      if (index >= 20 && finite(ema20[index]) && finite(ema20[index - 20])) {
        structureVotes.push(clamp((ema20[index] / ema20[index - 20] - 1) * 20, -1, 1));
      }
      const structure = average(structureVotes);
      const rsiVote = finite(rsiValues[index])
        ? clamp((rsiValues[index] - 50) / 20, -1, 1)
        : null;
      const stochasticVote = finite(stochRsiValues[index])
        ? clamp((stochRsiValues[index] - 50) / 35, -1, 1)
        : null;
      const macdVote = finite(macdValues.histogram[index]) && finite(macdVolatility[index]) && macdVolatility[index] > 0
        ? clamp(macdValues.histogram[index] / (macdVolatility[index] * 1.5), -1, 1)
        : null;
      const bollingerVote = finite(middleBand[index]) && finite(bandVolatility[index]) && bandVolatility[index] > 0
        ? clamp((bar.close - middleBand[index]) / (bandVolatility[index] * 2), -1, 1)
        : null;
      const votes = { structure, rsi: rsiVote, stochasticRsi: stochasticVote, macd: macdVote, bollinger: bollingerVote };
      const value = average(Object.values(votes));
      return finite(value) ? { value: value * 5, votes } : null;
    });

    const smoothedValues = ema(unsmoothed.map(item => item?.value ?? null), 3);
    const series = bars.map((bar, index) => {
      const value = smoothedValues[index];
      const raw = unsmoothed[index];
      if (!finite(value) || !raw) return null;
      const direction = Math.sign(value);
      const voteValues = Object.values(raw.votes).filter(finite);
      const agreement = direction === 0
        ? 0
        : voteValues.filter(vote => Math.sign(vote) === direction).length;
      return {
        index,
        time: bar.time,
        trendScore: round(clamp(value + 5, 0, 10), 2),
        direction: value > 0.5 ? "bullish" : value < -0.5 ? "bearish" : "neutral",
        agreement,
        total: voteValues.length,
        ...classifyTrendRegime(value),
      };
    }).filter(Boolean);

    const current = series[series.length - 1] || null;
    const currentRaw = unsmoothed[unsmoothed.length - 1];
    const currentRsi = last(rsiValues);
    const currentStochastic = last(stochRsiValues);
    const currentBollinger = currentRaw?.votes?.bollinger;
    const extension = currentRsi >= 72 && currentStochastic >= 80 && currentBollinger >= 0.8
      ? "extended"
      : currentRsi <= 30 && currentStochastic <= 20 && currentBollinger <= -0.8
        ? "washed-out"
        : "normal";

    return {
      status: current ? "ok" : "insufficient",
      trendScore: current?.trendScore ?? null,
      score: current ? current.trendScore * 10 : null,
      label: current?.label || "Not enough data",
      key: current?.key || "unknown",
      tone: current?.tone || "neutral",
      agreement: current?.agreement || 0,
      total: current?.total || 0,
      extension,
      inputs: {
        structure: currentRaw?.votes?.structure ?? null,
        rsi: currentRaw?.votes?.rsi ?? null,
        stochasticRsi: currentRaw?.votes?.stochasticRsi ?? null,
        macd: currentRaw?.votes?.macd ?? null,
        bollinger: currentRaw?.votes?.bollinger ?? null,
      },
      indicators: {
        rsi: currentRsi,
        stochasticRsi: currentStochastic,
        bollingerPosition: currentBollinger,
      },
      series,
    };
  }

  function maxDrawdown(values) {
    let peak = -Infinity;
    let worst = 0;
    values.forEach(value => {
      const number = Number(value);
      if (!finite(number)) return;
      peak = Math.max(peak, number);
      if (peak > 0) worst = Math.min(worst, number / peak - 1);
    });
    return worst;
  }

  function confirmedPivots(bars, left = 4, right = 4) {
    const lows = [];
    const highs = [];
    for (let i = left; i < bars.length - right; i += 1) {
      const window = bars.slice(i - left, i + right + 1);
      const low = bars[i].low;
      const high = bars[i].high;
      if (window.every((bar, j) => j === left || low <= bar.low)) {
        lows.push({ index: i, price: low, time: bars[i].time, confirmedIndex: i + right });
      }
      if (window.every((bar, j) => j === left || high >= bar.high)) {
        highs.push({ index: i, price: high, time: bars[i].time, confirmedIndex: i + right });
      }
    }
    return { lows, highs };
  }

  function clusterPivotZones(pivots, bars, type, currentPrice, currentAtr) {
    const tolerance = Math.max(currentPrice * 0.008, (currentAtr || currentPrice * 0.015) * 0.7);
    const clusters = [];
    pivots.forEach(pivot => {
      let cluster = clusters.find(item => Math.abs(item.center - pivot.price) <= tolerance);
      if (!cluster) {
        cluster = { center: pivot.price, pivots: [] };
        clusters.push(cluster);
      }
      cluster.pivots.push(pivot);
      cluster.center = average(cluster.pivots.map(item => item.price));
    });
    return clusters.map(cluster => {
      const latestIndex = Math.max(...cluster.pivots.map(item => item.index));
      const age = bars.length - 1 - latestIndex;
      const touches = cluster.pivots.length;
      const recency = clamp(30 - age / 8, 0, 30);
      const touchScore = clamp(touches * 13, 13, 52);
      const distance = Math.abs(cluster.center / currentPrice - 1);
      const relevance = clamp(22 - distance * 120, 0, 22);
      const strength = clamp(touchScore + recency + relevance);
      return {
        type,
        center: cluster.center,
        lower: cluster.center - tolerance * 0.55,
        upper: cluster.center + tolerance * 0.55,
        touches,
        strength,
        lastIndex: latestIndex,
        lastTime: bars[latestIndex].time,
        confirmedIndex: Math.max(...cluster.pivots.map(item => item.confirmedIndex)),
        distancePct: (cluster.center / currentPrice - 1) * 100,
      };
    });
  }

  function detectZones(rawBars) {
    const bars = normalizeBars(rawBars);
    if (bars.length < 40) return { support: [], resistance: [], atr: null };
    const currentPrice = bars[bars.length - 1].close;
    const currentAtr = atr(bars);
    const pivots = confirmedPivots(bars);
    const support = clusterPivotZones(pivots.lows, bars, "support", currentPrice, currentAtr)
      .filter(zone => zone.center < currentPrice * 1.005)
      .sort((a, b) => Math.abs(a.distancePct) - Math.abs(b.distancePct) || b.strength - a.strength)
      .slice(0, 3);
    const resistance = clusterPivotZones(pivots.highs, bars, "resistance", currentPrice, currentAtr)
      .filter(zone => zone.center > currentPrice * 0.995)
      .sort((a, b) => Math.abs(a.distancePct) - Math.abs(b.distancePct) || b.strength - a.strength)
      .slice(0, 3);
    return { support, resistance, atr: currentAtr, pivots };
  }

  function scoreFundamentals(input = {}) {
    const cashGeneration = finite(input.fcfMargin)
      ? scale(input.fcfMargin, 0, 0.25)
      : scale(input.profitMargin, -0.05, 0.25);
    const capitalEfficiency = finite(input.roic)
      ? scale(input.roic, 0, 0.20)
      : scale(input.returnOnEquity, 0, 0.20);
    const leverageSafety = finite(input.netDebtEbitda)
      ? scale(input.netDebtEbitda, 4, 0)
      : scale(input.capitalRatio, 0.04, 0.14);
    const parts = {
      revenueGrowth: scale(input.revenueGrowth, -0.10, 0.20),
      epsGrowth: scale(input.epsGrowth, -0.20, 0.25),
      cashGeneration,
      capitalEfficiency,
      leverageSafety,
      interestCoverage: scale(input.interestCoverage, 1, 12),
      dilution: scale(input.dilution, 0.08, -0.02),
    };
    const score = average(Object.values(parts));
    return { score: finite(score) ? clamp(score) : null, parts };
  }

  function scoreValuation(input = {}) {
    const pe = Number(input.forwardPE);
    const peScore = finite(pe)
      ? pe <= 0 ? 15 : pe <= 12 ? 72 : pe <= 22 ? 88 : pe <= 35 ? 65 : pe <= 50 ? 38 : 15
      : null;
    const parts = {
      modeledUpside: scale(input.modeledUpside ?? input.dcfUpside, -0.35, 0.35),
      forwardPE: peScore,
      expectationsGap: scale(input.expectationsGap ?? input.impliedGrowthGap, 0.15, -0.05),
      downsideToBearValue: scale(input.downsideToBearValue ?? input.bearDownside, -0.60, -0.08),
    };
    const score = average(Object.values(parts));
    return { score: finite(score) ? clamp(score) : null, parts };
  }

  function analyzeTechnical(rawBars) {
    const bars = normalizeBars(rawBars);
    if (bars.length < 60) return { status: "insufficient", bars, score: null };
    const closes = bars.map(bar => bar.close);
    const volumes = bars.map(bar => bar.volume);
    const price = last(closes);
    const ma20 = last(sma(closes, 20));
    const ma50Series = sma(closes, 50);
    const ma200Series = sma(closes, 200);
    const ma50 = last(ma50Series);
    const ma200 = last(ma200Series);
    const ma50Past = ma50Series[Math.max(0, ma50Series.length - 21)];
    const ma200Past = ma200Series[Math.max(0, ma200Series.length - 21)];
    const currentRsi = rsi(closes);
    const currentMacd = macd(closes);
    const currentAtr = atr(bars);
    const atrPct = currentAtr / price;
    const roc21 = rateOfChange(closes, 21);
    const roc63 = rateOfChange(closes, 63);
    const vol20 = last(sma(volumes, 20));
    const relativeVolume = vol20 > 0 ? last(volumes) / vol20 : null;
    const recentVolatility = standardDeviation(
      closes.slice(-31).slice(1).map((value, i) => Math.log(value / closes.slice(-31)[i]))
    );
    const drawdown = maxDrawdown(closes.slice(-252));
    const zones = detectZones(bars);
    const trendRegime = calculateTrendRegime(bars);
    const nearestSupport = zones.support[0] || null;
    const nearestResistance = zones.resistance[0] || null;

    let trend = 50;
    if (finite(ma20)) trend += price > ma20 ? 8 : -8;
    if (finite(ma50)) trend += price > ma50 ? 12 : -12;
    if (finite(ma200)) trend += price > ma200 ? 14 : -14;
    if (finite(ma50) && finite(ma200)) trend += ma50 > ma200 ? 10 : -10;
    if (finite(ma50Past) && finite(ma50)) trend += ma50 > ma50Past ? 6 : -6;
    if (finite(ma200Past) && finite(ma200)) trend += ma200 > ma200Past ? 4 : -4;
    trend = clamp(trend);

    let structure = trend * 0.48 + 28;
    if (finite(trendRegime.score)) {
      structure += (trendRegime.score - 50) * 0.18;
    }
    if (nearestSupport) {
      const distance = Math.abs(nearestSupport.distancePct);
      structure += distance <= 4 ? 12 : distance <= 9 ? 7 : distance > 18 ? -8 : 0;
      structure += nearestSupport.strength >= 70 ? 8 : nearestSupport.strength >= 50 ? 4 : 0;
    }
    if (nearestResistance) {
      const distance = Math.abs(nearestResistance.distancePct);
      structure += distance <= 3 ? -12 : distance <= 7 ? -6 : 2;
    }
    structure = clamp(structure);

    let momentum = 50;
    const regimeMomentum = average([
      trendRegime.inputs.rsi,
      trendRegime.inputs.stochasticRsi,
      trendRegime.inputs.macd,
      trendRegime.inputs.bollinger,
    ]);
    if (finite(regimeMomentum)) momentum += regimeMomentum * 28;
    if (finite(roc21)) momentum += clamp(roc21 * 120, -8, 8);
    if (finite(roc63)) momentum += clamp(roc63 * 55, -7, 7);
    if (trendRegime.extension === "extended") momentum -= 12;
    if (trendRegime.extension === "washed-out") momentum -= 5;
    momentum = clamp(momentum);

    let volume = 50;
    if (finite(relativeVolume)) {
      const direction = finite(roc21) && roc21 >= 0 ? 1 : -1;
      volume += clamp((relativeVolume - 1) * 22 * direction, -15, 15);
    }
    const recentCloseSlope = rateOfChange(closes, 20);
    const recentVolumeSlope = rateOfChange(
      volumes.map((value, i) => i === 0 ? value : (volumes[i - 1] || value) + (closes[i] >= closes[i - 1] ? value : -value)),
      20
    );
    if (finite(recentCloseSlope) && finite(recentVolumeSlope)) {
      volume += Math.sign(recentCloseSlope) === Math.sign(recentVolumeSlope) ? 10 : -10;
    }
    volume = clamp(volume);

    let technicalRisk = 78;
    technicalRisk -= clamp((atrPct - 0.012) * 900, 0, 28);
    technicalRisk -= clamp((Math.abs(drawdown) - 0.15) * 70, 0, 25);
    if (finite(ma20) && currentAtr > 0) {
      const extension = Math.abs(price - ma20) / currentAtr;
      technicalRisk -= clamp((extension - 2) * 8, 0, 22);
    }
    technicalRisk = clamp(technicalRisk);

    let entryLocation = 50;
    if (nearestSupport) {
      const distance = Math.abs(nearestSupport.distancePct);
      entryLocation += distance <= 2 ? 24 : distance <= 5 ? 17 : distance <= 9 ? 9 : distance > 18 ? -10 : 0;
      entryLocation += nearestSupport.strength >= 75 ? 8 : nearestSupport.strength >= 50 ? 4 : 0;
    } else {
      entryLocation -= 8;
    }
    if (nearestResistance) {
      const distance = Math.abs(nearestResistance.distancePct);
      entryLocation += distance <= 2 ? -24 : distance <= 5 ? -15 : distance <= 9 ? -6 : 4;
    }
    if (trendRegime.extension === "extended") entryLocation -= 14;
    if (trendRegime.extension === "washed-out") entryLocation -= 8;
    entryLocation = clamp(entryLocation);

    const setupComponents = {
      trend: trendRegime.score,
      structure,
      momentum,
      volume,
      entryLocation,
      risk: technicalRisk,
    };
    const setupScore =
      setupComponents.trend * 0.24 +
      setupComponents.structure * 0.22 +
      setupComponents.momentum * 0.20 +
      setupComponents.volume * 0.10 +
      setupComponents.entryLocation * 0.18 +
      setupComponents.risk * 0.06;

    return {
      status: "ok",
      bars,
      price,
      score: structure,
      trend,
      momentum,
      volume,
      momentumVolume: average([momentum, volume]),
      technicalRisk,
      entryLocation,
      setupScore: clamp(setupScore),
      setupComponents,
      indicators: {
        ma20, ma50, ma200, rsi: currentRsi, macd: currentMacd,
        atr: currentAtr, atrPct, roc21, roc63, relativeVolume,
        recentVolatility, drawdown,
        stochasticRsi: trendRegime.indicators.stochasticRsi,
        bollingerPosition: trendRegime.indicators.bollingerPosition,
      },
      trendRegime,
      zones,
    };
  }

  function labelFor(score) {
    if (!finite(score)) return "Not Rated";
    if (score >= 9) return "Exceptional Lens";
    if (score >= 8) return "Strong Lens";
    if (score >= 7) return "Constructive";
    if (score >= 6) return "Developing";
    if (score >= 5) return "Neutral";
    if (score >= 4) return "Unfavorable";
    if (score >= 3) return "Weak";
    return "Severe Risk";
  }

  function gradeTone(score) {
    if (!finite(score)) return "unknown";
    if (score >= 8) return "strong";
    if (score >= 7) return "positive";
    if (score >= 5) return "neutral";
    if (score >= 3) return "weak";
    return "severe";
  }

  function setupLabel(score) {
    if (!finite(score)) return "Not Rated";
    if (score >= 8.5) return "Prime tactical setup";
    if (score >= 7) return "Constructive setup";
    if (score >= 5.5) return "Developing setup";
    if (score >= 4) return "Weak setup";
    return "Avoid tactically";
  }

  function valueLabel(score) {
    if (!finite(score)) return "Not Rated";
    if (score >= 8.5) return "Exceptional long-term value";
    if (score >= 7) return "Attractive long-term value";
    if (score >= 5.5) return "Fairly valued";
    if (score >= 4) return "Demanding valuation";
    return "Unattractive long-term value";
  }

  function scoreLens({ bars, fundamentals = {}, metadata = {} } = {}) {
    const technical = analyzeTechnical(bars);
    const fundamentalResult = scoreFundamentals(fundamentals);
    const valuationResult = scoreValuation(fundamentals);
    const fundamentalCoverage = Object.values(fundamentalResult.parts).filter(finite).length;
    const valuationCoverage = Object.values(valuationResult.parts).filter(finite).length;
    if (
      technical.status !== "ok" ||
      !finite(fundamentalResult.score) ||
      !finite(valuationResult.score) ||
      fundamentalCoverage < 5 ||
      valuationCoverage < 3
    ) {
      const setupRaw = technical.status === "ok" && finite(technical.setupScore)
        ? technical.setupScore
        : null;
      const setupScore = finite(setupRaw) ? round(setupRaw / 10, 1) : null;
      return {
        status: "not-rated",
        score: null,
        label: "Not Rated",
        confidence: "Low",
        price: technical.status === "ok" ? technical.price : null,
        reason: technical.status !== "ok"
          ? "At least 60 valid daily bars are required."
          : `Insufficient reported evidence (${fundamentalCoverage}/7 company fields and ${valuationCoverage}/4 valuation fields available).`,
        technical,
        lenses: {
          setup: {
            score: setupScore,
            rawScore: setupRaw,
            label: setupLabel(setupScore),
            status: finite(setupScore) ? "graded" : "not-rated",
          },
          value: {
            score: null,
            rawScore: null,
            label: "Not Rated",
            status: "not-rated",
          },
          combined: {
            score: null,
            rawScore: null,
            label: "Not Rated",
            status: "not-rated",
          },
          goldenLens: {
            active: false,
            reason: "Golden Lens requires both a rated LensValue and a rated LensSetup.",
          },
        },
        dataCoverage: {
          fundamentals: { available: fundamentalCoverage, required: 5, total: 7 },
          valuation: { available: valuationCoverage, required: 3, total: 4 },
        },
        version: VERSION,
      };
    }

    const riskParts = {
      balanceSheet: average([
        finite(fundamentals.netDebtEbitda)
          ? scale(fundamentals.netDebtEbitda, 4, 0)
          : scale(fundamentals.capitalRatio, 0.04, 0.14),
        scale(fundamentals.interestCoverage, 1, 12),
      ]),
      dilution: scale(fundamentals.dilution, 0.08, -0.02),
      bearCase: scale(fundamentals.bearDownside, -0.60, -0.08),
    };
    const riskScore = average(Object.values(riskParts));
    const components = {
      fundamentals: fundamentalResult.score,
      valuation: valuationResult.score,
      technical: technical.score,
      momentum: technical.momentumVolume,
      risk: riskScore,
    };
    // LensValue and LensSetup remain independently usable. LensScore combines
    // them while rewarding agreement and penalizing a large mismatch.
    const qualityScore =
      components.fundamentals * MODEL.qualityFundamentals +
      components.risk * MODEL.qualityRisk;
    const baseScore =
      qualityScore * MODEL.baseQuality +
      components.valuation * MODEL.baseValuation;
    const alignmentBonus = clamp(
      (Math.min(qualityScore, components.valuation) - 70) * MODEL.alignmentBonusRate,
      0,
      MODEL.maxAlignmentBonus
    );
    const qualityCap = qualityScore >= 85 ? 100
      : qualityScore >= 75 ? 95
        : qualityScore >= 65 ? 85
          : qualityScore >= 50 ? 70
            : 55;
    let valueRaw = Math.min(qualityCap, baseScore + alignmentBonus);
    const setupRaw = technical.setupScore;

    const caps = [];
    if (qualityCap < 100) {
      caps.push(`Company quality limits LensValue and LensScore to ${(qualityCap / 10).toFixed(1)}.`);
    }
    if (fundamentals.goingConcern === true) {
      valueRaw = Math.min(valueRaw, 29);
      caps.push("Going-concern flag caps LensValue and LensScore below 3.0.");
    }
    if (finite(fundamentals.netDebtEbitda) && Number(fundamentals.netDebtEbitda) >= 6) {
      valueRaw = Math.min(valueRaw, 39);
      caps.push("Extreme leverage caps LensValue and LensScore below 4.0.");
    }

    const crossLensBonus = clamp(
      (Math.min(valueRaw, setupRaw) - 75) * MODEL.crossLensBonusRate,
      0,
      MODEL.maxCrossLensBonus
    );
    const mismatchPenalty = clamp(
      (Math.abs(valueRaw - setupRaw) - 25) * MODEL.mismatchPenaltyRate,
      0,
      MODEL.maxMismatchPenalty
    );
    let raw =
      valueRaw * MODEL.combinedValue +
      setupRaw * MODEL.combinedSetup +
      crossLensBonus -
      mismatchPenalty;
    raw = Math.min(qualityCap, raw);
    if (fundamentals.goingConcern === true) raw = Math.min(raw, 29);
    if (finite(fundamentals.netDebtEbitda) && Number(fundamentals.netDebtEbitda) >= 6) {
      raw = Math.min(raw, 39);
    }

    const score = round(raw / 10, 1);
    const setupScore = round(setupRaw / 10, 1);
    const valueScore = round(valueRaw / 10, 1);
    const coverageValues = [
      ...Object.values(fundamentalResult.parts),
      ...Object.values(valuationResult.parts),
      technical.indicators.ma200,
      technical.indicators.rsi,
      technical.indicators.atr,
    ];
    const coverage = coverageValues.filter(finite).length / coverageValues.length;
    const confidence = coverage >= 0.90 && technical.bars.length >= 252
      ? "High" : coverage >= 0.72 ? "Medium" : "Low";
    const goldenLensActive =
      valueRaw >= MODEL.goldenValueMinimum &&
      setupRaw >= MODEL.goldenSetupMinimum &&
      raw >= MODEL.goldenCombinedMinimum &&
      caps.length === 0 &&
      confidence !== "Low";
    const goldenLensReason = goldenLensActive
      ? "LensValue and LensSetup are both exceptionally strong with no active quality cap."
      : valueRaw < MODEL.goldenValueMinimum
        ? `LensValue needs ${(MODEL.goldenValueMinimum / 10).toFixed(1)} or higher.`
        : setupRaw < MODEL.goldenSetupMinimum
          ? `LensSetup needs ${(MODEL.goldenSetupMinimum / 10).toFixed(1)} or higher.`
          : caps.length
            ? "An active quality or risk cap prevents Golden Lens status."
            : "The combined LensScore or confidence requirement is not yet met.";

    const support = technical.zones.support[0] || null;
    const resistance = technical.zones.resistance[0] || null;
    const strengths = [];
    const concerns = [];
    if (components.fundamentals >= 72) strengths.push("Business fundamentals are a positive contributor.");
    else if (components.fundamentals < 45) concerns.push("Business fundamentals materially weaken the setup.");
    if (components.valuation >= 72) strengths.push("Price and modeled expectations provide an attractive valuation contribution.");
    else if (components.valuation < 45) concerns.push("Current valuation requires demanding assumptions.");
    if (components.technical >= 72) strengths.push("Price structure and trend are constructive.");
    else if (components.technical < 45) concerns.push("Trend and price structure remain unfavorable.");
    if (technical.trendRegime.trendScore >= 6.5 && technical.trendRegime.agreement >= 4) {
      strengths.push(`${technical.trendRegime.agreement} of ${technical.trendRegime.total} trend signals confirm an uptrend.`);
    } else if (technical.trendRegime.trendScore <= 3.5 && technical.trendRegime.agreement >= 4) {
      concerns.push(`${technical.trendRegime.agreement} of ${technical.trendRegime.total} trend signals confirm a downtrend.`);
    }
    if (technical.trendRegime.extension === "extended") {
      concerns.push("The trend is strong, but momentum is extended and vulnerable to a pullback.");
    }
    if (components.momentum >= 68) strengths.push("Momentum and volume are confirming the move.");
    else if (components.momentum < 42) concerns.push("Momentum or volume confirmation is weak.");
    if (components.risk >= 72) strengths.push("Measured downside and balance-sheet risk are contained.");
    else if (components.risk < 45) concerns.push("Downside or balance-sheet risk requires caution.");
    if (support) strengths.push(`Nearest support is ${Math.abs(support.distancePct).toFixed(1)}% below price.`);
    if (resistance && Math.abs(resistance.distancePct) < 5) concerns.push("Price is close to a confirmed resistance zone.");
    if (goldenLensActive) strengths.unshift("Golden Lens: long-term value and tactical entry quality are exceptionally aligned.");

    return {
      status: "graded",
      score,
      rawScore: round(raw, 1),
      label: labelFor(score),
      tone: gradeTone(score),
      confidence,
      coverage: round(coverage * 100, 0),
      price: technical.price,
      components,
      componentDetails: {
        fundamentals: fundamentalResult,
        valuation: valuationResult,
        risk: { score: riskScore, parts: riskParts },
      },
      lenses: {
        setup: {
          score: setupScore,
          rawScore: round(setupRaw, 1),
          label: setupLabel(setupScore),
          horizon: "2–12 weeks",
          components: technical.setupComponents,
        },
        value: {
          score: valueScore,
          rawScore: round(valueRaw, 1),
          label: valueLabel(valueScore),
          horizon: "1–3 years",
          components: {
            quality: qualityScore,
            valuation: components.valuation,
            risk: components.risk,
          },
        },
        combined: {
          score,
          label: labelFor(score),
          horizon: "6–18 months",
        },
        goldenLens: {
          active: goldenLensActive,
          label: goldenLensActive ? "Golden Lens" : "Not active",
          reason: goldenLensReason,
        },
      },
      modelDetails: {
        qualityScore,
        baseScore,
        alignmentBonus,
        valueRaw,
        setupRaw,
        crossLensBonus,
        mismatchPenalty,
        qualityCap,
      },
      strengths: strengths.slice(0, 4),
      concerns: concerns.slice(0, 4),
      caps,
      technical,
      metadata,
      version: VERSION,
      model: MODEL,
    };
  }

  return {
    VERSION,
    MODEL,
    normalizeBars,
    sma,
    ema,
    rsi,
    rsiSeries,
    macd,
    macdSeries,
    atr,
    maxDrawdown,
    confirmedPivots,
    detectZones,
    calculateTrendRegime,
    analyzeTechnical,
    scoreFundamentals,
    scoreValuation,
    scoreLens,
    labelFor,
  };
});

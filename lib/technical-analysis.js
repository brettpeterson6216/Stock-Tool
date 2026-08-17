"use strict";

/* ═══════════════════════════════════════════════════════════════════════════
   Deterministic technical analysis.

   Every number the user is shown is computed here, from the same OHLCV the
   chart draws. Nothing in this module predicts, recommends, or scores — it
   states what the series currently is, plus the level that would change it.
   The optional narration layer is only ever allowed to describe this output.
   ═══════════════════════════════════════════════════════════════════════════ */

function sma(v, p) {
  const out = new Array(v.length).fill(null);
  let sum = 0;
  for (let i = 0; i < v.length; i++) {
    sum += v[i];
    if (i >= p) sum -= v[i - p];
    if (i >= p - 1) out[i] = sum / p;
  }
  return out;
}

function ema(v, p) {
  const out = new Array(v.length).fill(null);
  const k = 2 / (p + 1);
  let prev = null;
  for (let i = 0; i < v.length; i++) {
    if (i === p - 1) {
      let s = 0;
      for (let j = 0; j < p; j++) s += v[j];
      prev = s / p;
      out[i] = prev;
    } else if (i >= p) {
      prev = v[i] * k + prev * (1 - k);
      out[i] = prev;
    }
  }
  return out;
}

function rsi(v, p = 14) {
  const out = new Array(v.length).fill(null);
  if (v.length <= p) return out;
  let g = 0, l = 0;
  for (let i = 1; i <= p; i++) {
    const d = v[i] - v[i - 1];
    if (d >= 0) g += d; else l -= d;
  }
  g /= p; l /= p;
  out[p] = l === 0 ? 100 : 100 - 100 / (1 + g / l);
  for (let i = p + 1; i < v.length; i++) {
    const ch = v[i] - v[i - 1];
    g = (g * (p - 1) + Math.max(ch, 0)) / p;
    l = (l * (p - 1) + Math.max(-ch, 0)) / p;
    out[i] = l === 0 ? 100 : 100 - 100 / (1 + g / l);
  }
  return out;
}

function macd(v, f = 12, s = 26, sg = 9) {
  const ef = ema(v, f), es = ema(v, s);
  const line = v.map((_, i) => (ef[i] == null || es[i] == null ? null : ef[i] - es[i]));
  const compact = line.filter((x) => x != null);
  const sigC = ema(compact, sg);
  const signal = new Array(line.length).fill(null);
  let k = 0;
  for (let i = 0; i < line.length; i++) if (line[i] != null) signal[i] = sigC[k++];
  const hist = line.map((x, i) => (x == null || signal[i] == null ? null : x - signal[i]));
  return { line, signal, hist };
}

function atr(h, l, c, p = 14) {
  const tr = [];
  for (let i = 0; i < c.length; i++) {
    if (i === 0) { tr.push((h[i] ?? c[i]) - (l[i] ?? c[i])); continue; }
    const hi = h[i] ?? c[i], lo = l[i] ?? c[i];
    tr.push(Math.max(hi - lo, Math.abs(hi - c[i - 1]), Math.abs(lo - c[i - 1])));
  }
  return sma(tr, p);
}

/* Swing pivots: a bar that is the extreme of a +/- `w` window. Levels are then
   clustered so three touches of the same shelf read as one level, not three. */
function pivots(highs, lows, w = 5) {
  const hi = [], lo = [];
  for (let i = w; i < highs.length - w; i++) {
    let isH = true, isL = true;
    for (let j = i - w; j <= i + w; j++) {
      if (j === i) continue;
      if (highs[j] >= highs[i]) isH = false;
      if (lows[j] <= lows[i]) isL = false;
    }
    if (isH) hi.push({ i, price: highs[i] });
    if (isL) lo.push({ i, price: lows[i] });
  }
  return { hi, lo };
}

function cluster(points, tolerance) {
  const sorted = points.slice().sort((a, b) => a.price - b.price);
  const groups = [];
  for (const pt of sorted) {
    const g = groups[groups.length - 1];
    if (g && Math.abs(pt.price - g.price) <= tolerance) {
      g.touches += 1;
      g.price = (g.price * (g.touches - 1) + pt.price) / g.touches;
      g.lastIndex = Math.max(g.lastIndex, pt.i);
    } else {
      groups.push({ price: pt.price, touches: 1, lastIndex: pt.i });
    }
  }
  return groups;
}

function pct(a, b) { return b ? ((a - b) / b) * 100 : null; }
function round(v, d = 2) { return v == null || !isFinite(v) ? null : Number(v.toFixed(d)); }

/**
 * @param {{timestamp:number[], open:number[], high:number[], low:number[], close:number[], volume:number[]}} series
 * @param {{range?:string, interval?:string}} ctx
 */
function analyze(series, ctx = {}) {
  const c = (series.close || []).map(Number).filter(Number.isFinite);
  if (c.length < 30) {
    return { ok: false, reason: "Not enough price history to compute a technical read." };
  }
  const n = c.length;
  const h = series.high || c, l = series.low || c, v = series.volume || [];
  const t = series.timestamp || [];
  const last = c[n - 1];

  const s20 = sma(c, 20), s50 = sma(c, 50), s200 = sma(c, 200);
  const e21 = ema(c, 21);
  const r = rsi(c, 14);
  const m = macd(c);
  const a = atr(h, l, c, 14);

  const dateAt = (i) => (t[i] ? new Date(t[i] * 1000).toISOString().slice(0, 10) : null);

  /* ── Trend ───────────────────────────────────────────────────────────── */
  const above50 = s50[n - 1] != null ? last > s50[n - 1] : null;
  const above200 = s200[n - 1] != null ? last > s200[n - 1] : null;
  let crossLabel = null, crossDate = null;
  if (s50[n - 1] != null && s200[n - 1] != null) {
    const golden = s50[n - 1] > s200[n - 1];
    for (let i = n - 1; i > 1; i--) {
      if (s50[i] == null || s200[i] == null || s50[i - 1] == null || s200[i - 1] == null) break;
      const nowAbove = s50[i] > s200[i], prevAbove = s50[i - 1] > s200[i - 1];
      if (nowAbove !== prevAbove) { crossDate = dateAt(i); break; }
    }
    crossLabel = golden ? "50-day above 200-day" : "50-day below 200-day";
  }
  const slope50 = s50[n - 1] != null && s50[n - 21] != null ? pct(s50[n - 1], s50[n - 21]) : null;

  let trendState = "sideways";
  if (above50 && above200 && slope50 != null && slope50 > 0.5) trendState = "uptrend";
  else if (above50 === false && above200 === false && slope50 != null && slope50 < -0.5) trendState = "downtrend";
  else if (above50 && above200) trendState = "constructive";
  else if (above50 === false && above200 === false) trendState = "under pressure";
  else trendState = "mixed";

  /* ── Momentum ────────────────────────────────────────────────────────── */
  const rsiNow = r[n - 1];
  const rsiState = rsiNow == null ? null
    : rsiNow >= 70 ? "stretched" : rsiNow >= 55 ? "firm"
    : rsiNow > 45 ? "neutral" : rsiNow > 30 ? "soft" : "washed out";

  const histNow = m.hist[n - 1];
  let histBars = 0;
  if (histNow != null) {
    const sign = Math.sign(histNow);
    for (let i = n - 1; i > 0 && m.hist[i] != null && Math.sign(m.hist[i]) === sign; i--) histBars++;
  }
  let histTrend = null;
  if (histNow != null && m.hist[n - 6] != null) {
    histTrend = Math.abs(histNow) > Math.abs(m.hist[n - 6]) ? "widening" : "narrowing";
  }

  /* ── Levels ──────────────────────────────────────────────────────────── */
  const atrNow = a[n - 1];
  const tol = atrNow ? atrNow * 1.2 : last * 0.02;
  const pv = pivots(h, l, Math.max(3, Math.round(n / 60)));
  const resistances = cluster(pv.hi, tol).filter((g) => g.price > last * 1.002)
    .sort((x, y) => x.price - y.price);
  const supports = cluster(pv.lo, tol).filter((g) => g.price < last * 0.998)
    .sort((x, y) => y.price - x.price);
  const nearestRes = resistances[0] || null;
  const nearestSup = supports[0] || null;

  /* ── Volatility & range ──────────────────────────────────────────────── */
  const rets = [];
  for (let i = 1; i < n; i++) if (c[i - 1]) rets.push(Math.log(c[i] / c[i - 1]));
  const mean = rets.reduce((x, y) => x + y, 0) / (rets.length || 1);
  const varc = rets.reduce((x, y) => x + Math.pow(y - mean, 2), 0) / (rets.length || 1);
  const perYear = ctx.interval && /m|h/.test(ctx.interval) ? 252 * 78 : 252;
  const annVol = Math.sqrt(varc * perYear) * 100;

  const winHigh = Math.max(...h.slice(-Math.min(n, 252)));
  const winLow = Math.min(...l.slice(-Math.min(n, 252)));
  const rangePos = winHigh > winLow ? ((last - winLow) / (winHigh - winLow)) * 100 : null;

  /* ── Volume ──────────────────────────────────────────────────────────── */
  const vol20 = v.length >= 20 ? v.slice(-20).reduce((x, y) => x + (y || 0), 0) / 20 : null;
  const volNow = v.length ? v[v.length - 1] : null;
  const volRel = vol20 && volNow ? volNow / vol20 : null;

  const signals = [
    {
      key: "trend", label: "Trend", state: trendState,
      value: crossLabel,
      detail: [
        above50 != null ? `Price ${above50 ? "above" : "below"} the 50-day by ${Math.abs(round(pct(last, s50[n - 1]), 1))}%` : null,
        above200 != null ? `${above200 ? "above" : "below"} the 200-day by ${Math.abs(round(pct(last, s200[n - 1]), 1))}%` : null,
        crossDate ? `${crossLabel} since ${crossDate}` : null,
        slope50 != null ? `50-day slope ${slope50 >= 0 ? "+" : ""}${round(slope50, 1)}% over 20 bars` : null
      ].filter(Boolean)
    },
    {
      key: "momentum", label: "Momentum", state: rsiState,
      value: rsiNow != null ? `RSI ${round(rsiNow, 1)}` : null,
      detail: [
        histNow == null ? null
          : `MACD histogram ${histNow >= 0 ? "positive" : "negative"} for ${histBars} bar${histBars === 1 ? "" : "s"}` +
            (histTrend ? ` and ${histTrend}` : "")
      ].filter(Boolean)
    },
    {
      key: "levels",
      label: "Levels",
      state: nearestSup && nearestRes ? "bracketed"
           : nearestSup && !nearestRes ? "at range highs"
           : !nearestSup && nearestRes ? "at range lows"
           : "open",
      value: [
        nearestSup ? `Support ${round(nearestSup.price)}` : null,
        nearestRes ? `Resistance ${round(nearestRes.price)}` : null
      ].filter(Boolean).join(" · ") || null,
      detail: [
        nearestSup ? `Nearest support ${round(nearestSup.price)} (${nearestSup.touches} touch${nearestSup.touches === 1 ? "" : "es"}), ${Math.abs(round(pct(last, nearestSup.price), 1))}% below` : null,
        nearestRes ? `Nearest resistance ${round(nearestRes.price)} (${nearestRes.touches} touch${nearestRes.touches === 1 ? "" : "es"}), ${Math.abs(round(pct(last, nearestRes.price), 1))}% above` : null
      ].filter(Boolean)
    },
    {
      key: "volatility", label: "Volatility", state: annVol > 45 ? "high" : annVol > 25 ? "normal" : "low",
      value: `${round(annVol, 1)}% annualized`,
      detail: [
        atrNow ? `ATR(14) ${round(atrNow)} — about ${round((atrNow / last) * 100, 1)}% of price per bar` : null,
        rangePos != null ? `Sitting ${round(rangePos, 0)}% of the way up its ${Math.min(n, 252)}-bar range` : null
      ].filter(Boolean)
    },
    {
      key: "volume", label: "Participation", state: volRel == null ? "unknown" : volRel > 1.5 ? "elevated" : volRel > 0.75 ? "normal" : "light",
      value: volRel != null ? `${round(volRel, 2)}x its 20-bar average` : null,
      detail: []
    }
  ];

  /* The one number that would falsify the current read. */
  const invalidation = nearestSup
    ? { level: round(nearestSup.price), text: `A close below ${round(nearestSup.price)} breaks the nearest shelf and the trend read above no longer holds.` }
    : null;

  return {
    ok: true,
    asOf: t.length ? new Date(t[t.length - 1] * 1000).toISOString() : null,
    bars: n,
    range: ctx.range || null,
    interval: ctx.interval || null,
    price: round(last),
    signals,
    invalidation,
    facts: {
      sma20: round(s20[n - 1]), sma50: round(s50[n - 1]), sma200: round(s200[n - 1]),
      ema21: round(e21[n - 1]), rsi14: round(rsiNow, 1),
      macd: round(m.line[n - 1], 3), macdSignal: round(m.signal[n - 1], 3), macdHist: round(histNow, 3),
      atr14: round(atrNow), annualizedVolPct: round(annVol, 1),
      rangeHigh: round(winHigh), rangeLow: round(winLow), rangePositionPct: round(rangePos, 0),
      relativeVolume: round(volRel, 2)
    }
  };
}

module.exports = { analyze, sma, ema, rsi, macd, atr, pivots, cluster };

"use strict";

/* ═══════════════════════════════════════════════════════════════════════════
   LensSetup v2 — the technical half of LensScore.

   Design brief was "like the TH Toolkit, but ours". What that toolkit gets
   right is the shape of the problem, not the specific numbers: a single
   conviction reading for how stretched price is, auto-detected buyer and
   seller zones, momentum divergence, and a Fibonacci pullback area. Those are
   standard technical constructs, so we implement them from first principles
   and express the result the way LensScore already speaks — 0 to 10, with the
   components visible and an explicit level that would invalidate the read.

   Deliberate differences from that toolkit, so this is our own instrument:
     · One 0-10 scale, not a signed -5..+5 gauge. Extension is a *component*
       of the score rather than the headline.
     · Every sub-score is published with its inputs, so a user can disagree
       with a weighting rather than trusting a black box.
     · No buy/sell language anywhere. The output describes position and names
       the level that breaks it.
   ═══════════════════════════════════════════════════════════════════════════ */

const { sma, ema, rsi, macd, atr, pivots, cluster } = require("./technical-analysis");

const clamp = (v, lo, hi) => Math.max(lo, Math.min(hi, v));
const round = (v, d = 2) => (v == null || !isFinite(v) ? null : Number(v.toFixed(d)));

/* Map a value through a piecewise-linear curve of [input, output] points. */
function curve(value, points) {
  if (value == null || !isFinite(value)) return null;
  if (value <= points[0][0]) return points[0][1];
  for (let i = 1; i < points.length; i++) {
    const [x0, y0] = points[i - 1], [x1, y1] = points[i];
    if (value <= x1) return y0 + ((value - x0) / (x1 - x0)) * (y1 - y0);
  }
  return points[points.length - 1][1];
}

/* ── Buyer and seller zones ──────────────────────────────────────────────────
   A zone is a price shelf the market has actually reacted to more than once.
   Touch count and recency both matter: a level tested three times last month
   is more relevant than one tested twice two years ago. */
function zones(high, low, close, atrNow, lookbackWindow) {
  const n = close.length;
  const w = Math.max(3, Math.round(n / 55));
  const pv = pivots(high, low, w);
  const tol = (atrNow || close[n - 1] * 0.02) * 1.25;
  const score = (g) => {
    const recency = 1 - clamp((n - 1 - g.lastIndex) / Math.max(1, lookbackWindow), 0, 1);
    return g.touches * (0.55 + 0.45 * recency);
  };
  const buyer = cluster(pv.lo, tol).map((g) => ({ ...g, weight: score(g) }))
    .filter((g) => g.price < close[n - 1])
    .sort((a, b) => b.price - a.price);
  const seller = cluster(pv.hi, tol).map((g) => ({ ...g, weight: score(g) }))
    .filter((g) => g.price > close[n - 1])
    .sort((a, b) => a.price - b.price);
  return { buyer, seller, tolerance: tol };
}

/* ── Momentum divergence ─────────────────────────────────────────────────────
   Price makes a higher high while momentum makes a lower high (or the mirror).
   Only the two most recent qualifying swings are compared; older divergences
   are noise by the time they matter. */
function divergence(close, high, low, rsiSeries, w) {
  const pv = pivots(high, low, w || 5);
  const pick = (arr) => arr.slice(-2);
  const out = { bullish: null, bearish: null };

  const highs = pick(pv.hi);
  if (highs.length === 2) {
    const [a, b] = highs;
    const ra = rsiSeries[a.i], rb = rsiSeries[b.i];
    if (ra != null && rb != null && b.price > a.price && rb < ra - 1.5) {
      out.bearish = {
        fromIndex: a.i, toIndex: b.i,
        pricePrev: round(a.price), priceLast: round(b.price),
        momentumPrev: round(ra, 1), momentumLast: round(rb, 1),
        note: "Price made a higher high while RSI made a lower high."
      };
    }
  }
  const lows = pick(pv.lo);
  if (lows.length === 2) {
    const [a, b] = lows;
    const ra = rsiSeries[a.i], rb = rsiSeries[b.i];
    if (ra != null && rb != null && b.price < a.price && rb > ra + 1.5) {
      out.bullish = {
        fromIndex: a.i, toIndex: b.i,
        pricePrev: round(a.price), priceLast: round(b.price),
        momentumPrev: round(ra, 1), momentumLast: round(rb, 1),
        note: "Price made a lower low while RSI made a higher low."
      };
    }
  }
  return out;
}

/* ── Retracement band ────────────────────────────────────────────────────────
   The 0.5–0.618 band of the dominant recent swing. Widely watched, so worth
   naming; treated as context, never as a signal on its own. */
function retracement(high, low, close) {
  const n = close.length;
  const window = Math.min(n, 120);
  const seg = { hi: -Infinity, lo: Infinity, hiIdx: -1, loIdx: -1 };
  for (let i = n - window; i < n; i++) {
    if (high[i] > seg.hi) { seg.hi = high[i]; seg.hiIdx = i; }
    if (low[i] < seg.lo) { seg.lo = low[i]; seg.loIdx = i; }
  }
  if (!isFinite(seg.hi) || !isFinite(seg.lo) || seg.hi <= seg.lo) return null;
  const up = seg.hiIdx > seg.loIdx;
  const span = seg.hi - seg.lo;
  const band = up
    ? { upper: seg.hi - span * 0.5, lower: seg.hi - span * 0.618 }
    : { upper: seg.lo + span * 0.618, lower: seg.lo + span * 0.5 };
  const last = close[n - 1];
  return {
    direction: up ? "up" : "down",
    swingHigh: round(seg.hi), swingLow: round(seg.lo),
    upper: round(band.upper), lower: round(band.lower),
    priceInside: last <= band.upper && last >= band.lower
  };
}

/**
 * @param {{timestamp:number[],open:number[],high:number[],low:number[],close:number[],volume:number[]}} series
 */
function lensSetup(series) {
  const close = (series.close || []).map(Number).filter(Number.isFinite);
  const n = close.length;
  if (n < 60) return { ok: false, reason: "LensSetup needs at least 60 bars of price history." };

  const high = series.high || close;
  const low = series.low || close;
  const volume = series.volume || [];
  const last = close[n - 1];

  const e21 = ema(close, 21);
  const s50 = sma(close, 50);
  const s200 = sma(close, 200);
  const r = rsi(close, 14);
  const m = macd(close);
  const a = atr(high, low, close, 14);
  const atrNow = a[n - 1];

  /* ── 1 · Structure: are the moving averages in agreement? ───────────────── */
  const stack = [
    s50[n - 1] != null && s200[n - 1] != null ? (s50[n - 1] > s200[n - 1] ? 1 : -1) : 0,
    e21[n - 1] != null && s50[n - 1] != null ? (e21[n - 1] > s50[n - 1] ? 1 : -1) : 0,
    s50[n - 1] != null ? (last > s50[n - 1] ? 1 : -1) : 0,
    s200[n - 1] != null ? (last > s200[n - 1] ? 1 : -1) : 0
  ];
  const agreement = stack.reduce((x, y) => x + y, 0);
  const slope = s50[n - 1] != null && s50[n - 21] != null
    ? ((s50[n - 1] - s50[n - 21]) / s50[n - 21]) * 100 : 0;
  const structure = clamp(
    curve(agreement, [[-4, 0.5], [0, 5], [4, 9]]) + curve(slope, [[-6, -1], [0, 0], [6, 1]]),
    0, 10
  );

  /* ── 2 · Momentum: RSI level plus the MACD histogram's direction ────────── */
  const rsiNow = r[n - 1];
  const hist = m.hist[n - 1];
  const histPrev = m.hist[n - 6];
  const histImproving = hist != null && histPrev != null ? hist > histPrev : null;
  const momentum = clamp(
    curve(rsiNow, [[20, 2], [35, 4], [50, 5.6], [65, 7.6], [80, 6.5], [95, 4]]) +
    (hist == null ? 0 : (hist >= 0 ? 0.9 : -0.9)) +
    (histImproving == null ? 0 : (histImproving ? 0.6 : -0.6)),
    0, 10
  );

  /* ── 3 · Extension: how far price sits from its mean, in ATR units ───────
     This is the mean-reversion pressure. High extension is not bearish on its
     own — it means the entry is late, which is a different statement. */
  const meanRef = s50[n - 1] != null ? s50[n - 1] : e21[n - 1];
  const stretchAtr = meanRef != null && atrNow ? (last - meanRef) / atrNow : null;
  const extension = stretchAtr == null ? 5 : clamp(
    curve(Math.abs(stretchAtr), [[0, 9.5], [1, 8.5], [2, 6.5], [3.5, 4], [5, 2], [8, 0.5]]),
    0, 10
  );

  /* ── 4 · Location: where price sits between the nearest zones ───────────── */
  const z = zones(high, low, close, atrNow, Math.min(n, 180));
  const sup = z.buyer[0] || null;
  const res = z.seller[0] || null;
  let location = 5;
  if (sup && res) {
    const span = res.price - sup.price;
    const pos = span > 0 ? (last - sup.price) / span : 0.5;
    location = clamp(curve(pos, [[0, 8.8], [0.35, 7.4], [0.6, 5.4], [0.85, 3.2], [1, 2.4]]), 0, 10);
  } else if (sup && !res) {
    location = 4.2;
  } else if (!sup && res) {
    location = 6.2;
  }

  /* ── 5 · Participation: is volume confirming the recent move? ───────────── */
  let participation = 5;
  if (volume.length >= 40) {
    const avg20 = volume.slice(-20).reduce((x, y) => x + (y || 0), 0) / 20;
    const avg60 = volume.slice(-60).reduce((x, y) => x + (y || 0), 0) / Math.min(60, volume.length);
    const rel = avg60 ? avg20 / avg60 : 1;
    const move = close[n - 1] - close[Math.max(0, n - 20)];
    const confirming = (move >= 0 && rel >= 1) || (move < 0 && rel < 1);
    participation = clamp(curve(rel, [[0.5, 4], [1, 5.5], [1.6, 7], [3, 6]]) + (confirming ? 0.8 : -0.8), 0, 10);
  }

  /* ── 6 · Risk: volatility regime and depth of current drawdown ──────────── */
  const rets = [];
  for (let i = 1; i < n; i++) if (close[i - 1]) rets.push(Math.log(close[i] / close[i - 1]));
  const mean = rets.reduce((x, y) => x + y, 0) / (rets.length || 1);
  const variance = rets.reduce((x, y) => x + (y - mean) ** 2, 0) / (rets.length || 1);
  const annVol = Math.sqrt(variance * 252) * 100;
  const peak = Math.max(...close.slice(-Math.min(n, 252)));
  const drawdown = peak ? ((last - peak) / peak) * 100 : 0;
  const risk = clamp(
    curve(annVol, [[10, 8.6], [25, 7], [45, 4.6], [70, 2.4], [110, 1]]) +
    curve(drawdown, [[-45, -1.4], [-20, -0.6], [0, 0.4]]),
    0, 10
  );

  /* ── Modifiers ──────────────────────────────────────────────────────────── */
  const div = divergence(close, high, low, r, Math.max(3, Math.round(n / 55)));
  const fib = retracement(high, low, close);

  let modifier = 0;
  const notes = [];
  if (div.bearish) { modifier -= 0.7; notes.push("Bearish momentum divergence on the last two swing highs."); }
  if (div.bullish) { modifier += 0.7; notes.push("Bullish momentum divergence on the last two swing lows."); }
  if (fib && fib.priceInside) {
    modifier += fib.direction === "up" ? 0.4 : -0.2;
    notes.push(`Price is inside the 0.5–0.618 retracement of the recent ${fib.direction === "up" ? "advance" : "decline"}.`);
  }
  if (sup && atrNow && Math.abs(last - sup.price) < atrNow) {
    modifier += 0.3; notes.push("Price is within one ATR of the nearest buyer zone.");
  }
  if (res && atrNow && Math.abs(res.price - last) < atrNow) {
    modifier -= 0.3; notes.push("Price is within one ATR of the nearest seller zone.");
  }

  /* ── Composite ──────────────────────────────────────────────────────────── */
  const weights = { structure: 0.28, momentum: 0.24, extension: 0.16, location: 0.16, participation: 0.06, risk: 0.10 };
  const weighted =
    structure * weights.structure + momentum * weights.momentum +
    extension * weights.extension + location * weights.location +
    participation * weights.participation + risk * weights.risk;

  /* A plain weighted mean compresses everything toward 5: a name with every
     moving average against it still scored "Balanced" because calm volatility
     and a nearby shelf propped it up. Two corrections:

       1. Expand around the midpoint so the scale actually uses its range.
       2. Gate on structure. You cannot be well positioned against the trend,
          however tidy the other components look, so structure sets a ceiling. */
  const expanded = 5 + (weighted - 5) * 1.3;
  const structureCeiling = 3.2 + structure * 0.68;
  const score = clamp(Math.min(expanded + modifier, structureCeiling), 0, 10);

  const band =
    score >= 8.5 ? "Exceptional" : score >= 7 ? "Constructive" :
    score >= 5.5 ? "Balanced" : score >= 4 ? "Cautious" :
    score >= 2.5 ? "Poor" : "Severe";

  const coverage = clamp(n / 250, 0, 1);
  const agreementSpread = Math.abs(structure - momentum) + Math.abs(extension - location);
  const confidence = clamp(0.45 + coverage * 0.35 - (agreementSpread / 40), 0.2, 0.95);

  return {
    ok: true,
    version: "lens-setup/2.0",
    score: round(score, 1),
    band,
    confidence: round(confidence, 2),
    ceiling: round(structureCeiling, 1),
    components: [
      { key: "structure", label: "Structure", score: round(structure, 1), weight: weights.structure,
        detail: `Moving-average agreement ${agreement >= 0 ? "+" : ""}${agreement} of 4, 50-day slope ${round(slope, 1)}% over 20 bars.` },
      { key: "momentum", label: "Momentum", score: round(momentum, 1), weight: weights.momentum,
        detail: `RSI ${round(rsiNow, 1)}, MACD histogram ${hist == null ? "unavailable" : (hist >= 0 ? "positive" : "negative")}${histImproving == null ? "" : histImproving ? " and improving" : " and fading"}.` },
      { key: "extension", label: "Extension", score: round(extension, 1), weight: weights.extension,
        detail: stretchAtr == null ? "Not enough data to measure stretch."
          : `Price is ${round(Math.abs(stretchAtr), 1)} ATR ${stretchAtr >= 0 ? "above" : "below"} its 50-day mean.` },
      { key: "location", label: "Location", score: round(location, 1), weight: weights.location,
        detail: sup && res ? `Between buyer zone ${round(sup.price)} and seller zone ${round(res.price)}.`
          : sup ? `Above all mapped supply; nearest buyer zone ${round(sup.price)}.`
          : res ? `Below the nearest seller zone ${round(res.price)}.` : "No well-tested zones nearby." },
      { key: "participation", label: "Participation", score: round(participation, 1), weight: weights.participation,
        detail: volume.length >= 40 ? "Recent volume compared with its own 60-bar baseline." : "Volume history unavailable." },
      { key: "risk", label: "Risk", score: round(risk, 1), weight: weights.risk,
        detail: `${round(annVol, 1)}% annualised volatility, ${round(drawdown, 1)}% from the 252-bar high.` }
    ],
    zones: {
      buyer: z.buyer.slice(0, 3).map((g) => ({ price: round(g.price), touches: g.touches, weight: round(g.weight, 2) })),
      seller: z.seller.slice(0, 3).map((g) => ({ price: round(g.price), touches: g.touches, weight: round(g.weight, 2) }))
    },
    divergence: div,
    retracement: fib,
    modifiers: { total: round(modifier, 2), notes },
    invalidation: sup
      ? { level: round(sup.price), text: `A close below ${round(sup.price)} removes the nearest buyer zone and this reading no longer holds.` }
      : null,
    inputs: {
      bars: n, price: round(last), ema21: round(e21[n - 1]), sma50: round(s50[n - 1]), sma200: round(s200[n - 1]),
      rsi14: round(rsiNow, 1), macdHist: round(hist, 3), atr14: round(atrNow),
      stretchAtr: round(stretchAtr, 2), annualisedVolPct: round(annVol, 1), drawdownPct: round(drawdown, 1)
    }
  };
}

module.exports = { lensSetup, zones, divergence, retracement };

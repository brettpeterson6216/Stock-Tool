/* ═══════════════════════════════════════════════════════════════════════════
   Technical indicators: pure maths on daily (or weekly, monthly, intraday)
   bars. Every function takes bars oldest first, [{ time, open, high, low,
   close, volume }], and returns arrays the same length as the bars, with NaN
   where there is not yet enough history. Nothing here fetches or draws.

   Loaded in the browser as IL.ind, and in Node by the tests.

   Conventions follow the textbook definitions most charting sites use:
     · EMA seeded with the simple average of its first n values;
     · RSI, ATR and ADX use Wilder's smoothing (an EMA with alpha = 1/n);
     · Bollinger Bands use the population standard deviation;
     · Stochastic is the "slow" form: %K smoothed over 3, %D its 3-bar average.
   ═══════════════════════════════════════════════════════════════════════════ */
(function (root) {
  "use strict";
  var NaN_ = NaN;
  function fin(v) { return typeof v === "number" && isFinite(v); }
  function blank(n) { var a = new Array(n); for (var i = 0; i < n; i++) a[i] = NaN_; return a; }
  function closes(bars) { return bars.map(function (b) { return b.close; }); }

  /* Simple moving average of any series (NaN-aware: starts after the first
     run of n finite values). */
  function smaOf(values, n) {
    var out = blank(values.length), sum = 0, count = 0;
    for (var i = 0; i < values.length; i++) {
      var v = values[i];
      if (!fin(v)) { sum = 0; count = 0; continue; }
      sum += v; count += 1;
      if (count > n) { sum -= values[i - n]; count = n; }
      if (count === n) out[i] = sum / n;
    }
    return out;
  }
  /* Exponential moving average, seeded with the SMA of the first n finite values. */
  function emaOf(values, n, alpha) {
    var out = blank(values.length), k = alpha || 2 / (n + 1), prev = NaN_, seed = [], i;
    for (i = 0; i < values.length; i++) {
      var v = values[i];
      if (!fin(v)) continue;
      if (!fin(prev)) {
        seed.push(v);
        if (seed.length === n) { prev = seed.reduce(function (a, b) { return a + b; }, 0) / n; out[i] = prev; }
        continue;
      }
      prev = prev + k * (v - prev);
      out[i] = prev;
    }
    return out;
  }
  function wilder(values, n) { return emaOf(values, n, 1 / n); }

  function sma(bars, n) { return smaOf(closes(bars), n); }
  function ema(bars, n) { return emaOf(closes(bars), n); }

  /* Bollinger Bands: middle = SMA(n), upper/lower = middle ± k standard deviations. */
  function bollinger(bars, n, k) {
    n = n || 20; k = k || 2;
    var c = closes(bars), mid = smaOf(c, n), up = blank(c.length), lo = blank(c.length), pctB = blank(c.length), width = blank(c.length);
    for (var i = n - 1; i < c.length; i++) {
      if (!fin(mid[i])) continue;
      var s = 0;
      for (var j = i - n + 1; j <= i; j++) s += (c[j] - mid[i]) * (c[j] - mid[i]);
      var sd = Math.sqrt(s / n);
      up[i] = mid[i] + k * sd; lo[i] = mid[i] - k * sd;
      pctB[i] = up[i] === lo[i] ? NaN_ : (c[i] - lo[i]) / (up[i] - lo[i]);
      width[i] = mid[i] ? (up[i] - lo[i]) / mid[i] : NaN_;
    }
    return { mid: mid, upper: up, lower: lo, pctB: pctB, width: width };
  }

  /* RSI (Wilder). */
  function rsi(bars, n) {
    n = n || 14;
    var c = closes(bars), out = blank(c.length), g = 0, l = 0;
    for (var i = 1; i < c.length; i++) {
      var d = c[i] - c[i - 1], up = d > 0 ? d : 0, dn = d < 0 ? -d : 0;
      if (i <= n) { g += up; l += dn; if (i === n) { g /= n; l /= n; out[i] = l === 0 ? 100 : 100 - 100 / (1 + g / l); } continue; }
      g = (g * (n - 1) + up) / n; l = (l * (n - 1) + dn) / n;
      out[i] = l === 0 ? 100 : 100 - 100 / (1 + g / l);
    }
    return out;
  }

  /* MACD: EMA(fast) − EMA(slow), signal = EMA(signal) of that, histogram = the difference. */
  function macd(bars, fast, slow, signal) {
    fast = fast || 12; slow = slow || 26; signal = signal || 9;
    var c = closes(bars), f = emaOf(c, fast), s = emaOf(c, slow), line = blank(c.length);
    for (var i = 0; i < c.length; i++) if (fin(f[i]) && fin(s[i])) line[i] = f[i] - s[i];
    var sig = emaOf(line, signal), hist = blank(c.length);
    for (i = 0; i < c.length; i++) if (fin(line[i]) && fin(sig[i])) hist[i] = line[i] - sig[i];
    return { macd: line, signal: sig, hist: hist };
  }

  /* Slow stochastic: raw %K over n bars, smoothed over 3; %D = 3-bar average of %K. */
  function stochastic(bars, n, smooth, dLen) {
    n = n || 14; smooth = smooth || 3; dLen = dLen || 3;
    var raw = blank(bars.length);
    for (var i = n - 1; i < bars.length; i++) {
      var hh = -Infinity, ll = Infinity;
      for (var j = i - n + 1; j <= i; j++) { if (bars[j].high > hh) hh = bars[j].high; if (bars[j].low < ll) ll = bars[j].low; }
      raw[i] = hh === ll ? 50 : (bars[i].close - ll) / (hh - ll) * 100;
    }
    var k = smaOf(raw, smooth);
    return { k: k, d: smaOf(k, dLen) };
  }

  function trueRange(bars) {
    return bars.map(function (b, i) {
      if (!i) return b.high - b.low;
      var pc = bars[i - 1].close;
      return Math.max(b.high - b.low, Math.abs(b.high - pc), Math.abs(b.low - pc));
    });
  }
  /* Average True Range (Wilder). */
  function atr(bars, n) { return wilder(trueRange(bars), n || 14); }

  /* On-Balance Volume: running total of volume, added on up closes, taken away on down closes. */
  function obv(bars) {
    var out = blank(bars.length), t = 0;
    for (var i = 0; i < bars.length; i++) {
      if (i) { var d = bars[i].close - bars[i - 1].close; if (d > 0) t += bars[i].volume || 0; else if (d < 0) t -= bars[i].volume || 0; }
      out[i] = t;
    }
    return out;
  }

  /* ADX with +DI and −DI (Wilder, 14). */
  function adx(bars, n) {
    n = n || 14;
    var len = bars.length, pdm = blank(len), mdm = blank(len), tr = trueRange(bars);
    for (var i = 1; i < len; i++) {
      var up = bars[i].high - bars[i - 1].high, dn = bars[i - 1].low - bars[i].low;
      pdm[i] = up > dn && up > 0 ? up : 0;
      mdm[i] = dn > up && dn > 0 ? dn : 0;
    }
    tr[0] = NaN_;
    var str = wilder(tr, n), sp = wilder(pdm, n), sm = wilder(mdm, n);
    var pdi = blank(len), mdi = blank(len), dx = blank(len);
    for (i = 0; i < len; i++) {
      if (!fin(str[i]) || !fin(sp[i]) || !fin(sm[i]) || !str[i]) continue;
      pdi[i] = 100 * sp[i] / str[i]; mdi[i] = 100 * sm[i] / str[i];
      var s = pdi[i] + mdi[i];
      dx[i] = s ? 100 * Math.abs(pdi[i] - mdi[i]) / s : 0;
    }
    return { adx: wilder(dx, n), plusDI: pdi, minusDI: mdi };
  }

  /* Percent change from `back` bars ago to the last bar (NaN when too short). */
  function changeOver(bars, back) {
    var n = bars.length;
    if (n <= back || !(bars[n - 1 - back].close > 0)) return NaN_;
    return (bars[n - 1].close / bars[n - 1 - back].close - 1) * 100;
  }
  /* Annualised volatility of daily returns over the last n bars, in percent. */
  function histVol(bars, n, perYear) {
    n = n || 20; perYear = perYear || 252;
    var len = bars.length; if (len <= n) return NaN_;
    var r = [];
    for (var i = len - n; i < len; i++) if (bars[i - 1].close > 0) r.push(Math.log(bars[i].close / bars[i - 1].close));
    var m = r.reduce(function (a, b) { return a + b; }, 0) / r.length;
    var v = r.reduce(function (a, b) { return a + (b - m) * (b - m); }, 0) / Math.max(1, r.length - 1);
    return Math.sqrt(v * perYear) * 100;
  }
  /* The last finite value of a series, and how many bars back it is. */
  function last(series) { for (var i = series.length - 1; i >= 0; i--) if (fin(series[i])) return series[i]; return NaN_; }

  var api = { smaOf: smaOf, emaOf: emaOf, sma: sma, ema: ema, bollinger: bollinger, rsi: rsi, macd: macd, stochastic: stochastic,
    atr: atr, obv: obv, adx: adx, trueRange: trueRange, changeOver: changeOver, histVol: histVol, last: last };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else { root.IL = root.IL || {}; root.IL.ind = api; }
})(typeof window !== "undefined" ? window : this);

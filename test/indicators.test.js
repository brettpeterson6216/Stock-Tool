"use strict";
/* Technical indicator maths (public/app/indicators.js), checked against
   series whose answers are known in closed form, and against a hand-worked
   RSI. */
const test = require("node:test");
const assert = require("node:assert/strict");
const ind = require("../public/app/indicators.js");

const near = (a, b, eps = 1e-6, msg) => assert.ok(Math.abs(a - b) <= eps, `${msg || ""} ${a} ≈ ${b}`);
/* A steady climb: close t, high t + 1, low t − 1. */
const climb = n => Array.from({ length: n }, (_, i) => ({ time: i, open: i, high: i + 1, low: i - 1, close: i, volume: 100 }));

test("SMA and EMA: blank until there is enough history, then the textbook values", () => {
  const bars = climb(30);
  const s = ind.sma(bars, 5);
  assert.ok(Number.isNaN(s[3]));
  near(s[4], 2); near(s[29], 27);
  const e = ind.ema(bars, 5);
  assert.ok(Number.isNaN(e[3]));
  near(e[4], 2, 1e-9, "seeded with the SMA");
  near(e[29], 29 - 2, 1e-6, "on a straight line an EMA(n) lags by (n − 1) / 2");
});

test("MACD on a straight line settles at the lag difference, with a flat histogram", () => {
  const m = ind.macd(climb(200));
  near(m.macd[199], (26 - 1) / 2 - (12 - 1) / 2, 1e-6);
  near(m.signal[199], 7, 1e-6);
  near(m.hist[199], 0, 1e-6);
  assert.ok(Number.isNaN(m.macd[24]) && Number.isFinite(m.macd[25]), "starts on bar 26");
});

test("Bollinger Bands close up on a flat price and widen with its swing", () => {
  const flat = Array.from({ length: 25 }, (_, i) => ({ time: i, open: 10, high: 10, low: 10, close: 10, volume: 1 }));
  const b = ind.bollinger(flat);
  near(b.upper[24], 10); near(b.lower[24], 10); near(b.width[24], 0);
  const zig = Array.from({ length: 25 }, (_, i) => ({ time: i, open: 10, high: 11, low: 9, close: i % 2 ? 11 : 9, volume: 1 }));
  const z = ind.bollinger(zig);
  near(z.mid[24], 10, 1e-9, "ten nines and ten elevens in the last 20");
  near(z.upper[24], 12, 1e-9, "standard deviation 1, two of them above");
  near(z.lower[24], 8, 1e-9);
});

test("RSI: 100 on a steady climb, 50 when gains and losses balance, and a hand-worked value", () => {
  near(ind.rsi(climb(30))[29], 100);
  const alt = Array.from({ length: 40 }, (_, i) => ({ time: i, close: i % 2 ? 11 : 10, high: 11, low: 10, open: 10, volume: 1 }));
  near(ind.rsi(alt)[38], 50, 2);
  /* n = 2 by hand: closes 1,2,1,3 → after bar 2 avg gain 0.5, avg loss 0.5 →
     bar 3: gain 2 → g = (0.5 + 2) / 2 = 1.25, l = 0.25 → RSI = 100 − 100 / (1 + 5) */
  const hand = [1, 2, 1, 3].map((c, i) => ({ time: i, close: c, high: c, low: c, open: c, volume: 1 }));
  near(ind.rsi(hand, 2)[3], 100 - 100 / 6, 1e-9);
});

test("Stochastic, ATR, ADX and OBV on a steady climb", () => {
  const bars = climb(80);
  const st = ind.stochastic(bars);
  near(st.k[79], 14 / 15 * 100, 1e-9, "close sits 14 above the 14-bar low of a 15-wide range");
  near(st.d[79], 14 / 15 * 100, 1e-9);
  near(ind.atr(bars)[79], 2, 1e-9, "every bar spans 2");
  const a = ind.adx(bars);
  near(a.minusDI[79], 0); assert.ok(a.plusDI[79] > 40); assert.ok(a.adx[79] > 95, "one-way move: trend strength near 100");
  const o = ind.obv(bars);
  assert.equal(o[79], 79 * 100);
});

test("change over a window and historical volatility", () => {
  const bars = climb(30).map(b => ({ ...b, close: b.close + 100 }));
  near(ind.changeOver(bars, 10), (129 / 119 - 1) * 100, 1e-9);
  assert.ok(Number.isNaN(ind.changeOver(bars, 30)));
  const flat = Array.from({ length: 30 }, (_, i) => ({ close: 50 }));
  near(ind.histVol(flat, 20), 0);
});

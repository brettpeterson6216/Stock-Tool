"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const V = require("../public/app/valuation.js");

test("implied growth runs the projection backwards to today's price", () => {
  const base = { price: 200, revenue: 200e9, shares: 24e9, years: 5, margin: 0.5, exitPE: 25, shareChange: 0, required: 0.1 };
  const g = V.impliedGrowth(base);
  const out = V.project({ ...base, growth: g });
  assert.ok(Math.abs(out.valueToday - 200) < 1e-6);
  assert.ok(Math.abs(out.annualReturn - 0.1) < 1e-9);
});

test("buybacks lower the growth the price needs; dilution raises it", () => {
  const base = { price: 100, revenue: 10e9, shares: 1e9, margin: 0.2, exitPE: 20, required: 0.1 };
  const flat = V.impliedGrowth(base);
  assert.ok(V.impliedGrowth({ ...base, shareChange: -0.02 }) < flat);
  assert.ok(V.impliedGrowth({ ...base, shareChange: 0.02 }) > flat);
});

test("projection refuses incomplete inputs instead of inventing numbers", () => {
  assert.equal(V.project({ price: 0, revenue: 1, shares: 1, growth: 0.1, margin: 0.1, exitPE: 10 }), null);
  assert.equal(V.impliedGrowth({ price: 10, revenue: 1e9, shares: 1e8, margin: -0.1, exitPE: 10 }), null);
});

test("default cases bracket the base and mark unprofitable companies", () => {
  const d = V.defaults({ growth3y: 0.4, margin: 0.3, pe: 30 });
  assert.ok(d.bear.growth < d.base.growth && d.base.growth < d.bull.growth);
  assert.ok(d.base.growth <= 0.3);
  assert.equal(d.unprofitable, false);
  const loss = V.defaults({ growth1y: 0.2, margin: -0.05, pe: null });
  assert.equal(loss.unprofitable, true);
  assert.ok(loss.base.margin > 0);
});

/* Codex audit F02: a 0% required return used to fall back to 10%. */
test("a 0% required return is used as 0%, not swapped for 10%", () => {
  const i = { price: 10, revenue: 100, shares: 10, years: 5, growth: 0, margin: 0.1, exitPE: 10, shareChange: 0 };
  const near = (a, b) => Math.abs(a - b) < 1e-4;
  assert.ok(near(V.project({ ...i, required: 0 }).valueToday, 10));
  assert.ok(near(V.project({ ...i, required: 0.05 }).valueToday, 7.8353));
  assert.ok(near(V.project({ ...i, required: 0.1 }).valueToday, 6.2092));
  const g = (r) => V.impliedGrowth({ ...i, required: r });
  assert.ok(Math.abs(g(0)) < 1e-9);
  assert.ok(near(g(0.05), 0.05));
  assert.ok(near(g(0.1), 0.1));
  for (const r of [0, 0.05, 0.1, 0.2]) {
    const out = V.project({ ...i, required: r, growth: g(r) });
    assert.ok(near(out.valueToday, i.price), "round trip at " + r);
  }
});

/* Codex audit F07: impossible inputs must not produce Infinity or NaN. */
test("impossible inputs are refused with a reason, never Infinity", () => {
  const i = { price: 10, revenue: 100, shares: 10, years: 5, growth: 0.05, margin: 0.1, exitPE: 10, shareChange: 0, required: 0.1 };
  assert.equal(V.project({ ...i, shareChange: -1 }), null);
  assert.equal(V.validate({ ...i, shareChange: -1 }).field, "shareChange");
  assert.equal(V.project({ ...i, required: -1 }), null);
  assert.equal(V.validate({ ...i, required: -1.5 }).field, "required");
  assert.equal(V.project({ ...i, growth: NaN }), null);
  assert.equal(V.impliedGrowth({ ...i, shareChange: -1 }), null);
  assert.equal(V.validate(i), null);
  const shrinking = V.project({ ...i, growth: -0.2 });
  assert.ok(shrinking && Number.isFinite(shrinking.valueToday), "negative growth stays usable");
});

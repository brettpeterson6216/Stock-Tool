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

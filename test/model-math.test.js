"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const math = require("../public/model-math");

test("CAGR returns the annual compounded rate", () => {
  assert.ok(Math.abs(math.cagr(100, 161.051, 5) - 0.1) < 0.000001);
  assert.equal(math.cagr(0, 100, 5), null);
});

test("scenario projection compounds earnings and growing dividends", () => {
  const result = math.projectScenario({ price: 100, currentPE: 20, exitPE: 20, growth: 0.1, years: 2, dividendYield: 0.02 });
  assert.equal(result.ok, true);
  assert.ok(Math.abs(result.terminalPrice - 121) < 0.000001);
  assert.ok(Math.abs(result.dividends - 4.2) < 0.000001);
  assert.ok(Math.abs(result.totalValue - 125.2) < 0.000001);
});

test("scenario projection rejects impossible assumptions", () => {
  assert.equal(math.projectScenario({ price: 100, currentPE: 0, exitPE: 20, growth: 0.1, years: 5 }).ok, false);
  assert.equal(math.projectScenario({ price: 100, currentPE: 20, exitPE: 20, growth: -1, years: 5 }).ok, false);
});

test("EPS DCF discounts both forecast earnings and terminal value", () => {
  const result = math.epsDcf({ eps: 5, growth1: 0.1, growth2: 0.05, terminalGrowth: 0.03, discountRate: 0.1 });
  assert.equal(result.ok, true);
  assert.ok(result.intrinsic > result.pvCF);
  assert.ok(result.terminalShare > 0 && result.terminalShare < 1);
  assert.equal(math.epsDcf({ eps: 5, growth1: 0.1, growth2: 0.05, terminalGrowth: 0.1, discountRate: 0.1 }).ok, false);
});

test("annualized volatility uses sample standard deviation of returns", () => {
  const volatility = math.annualizedVolatility([100, 110, 99, 108.9], 1);
  assert.ok(Math.abs(volatility - 0.1154700538) < 0.000001);
  assert.equal(math.annualizedVolatility([100, 101], 252), 0);
});

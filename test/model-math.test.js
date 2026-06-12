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

test("scenario projection independently models dividend growth and dilution", () => {
  const result = math.projectScenario({
    price: 100,
    currentPE: 20,
    exitPE: 20,
    growth: 0.1,
    dividendYield: 0.02,
    dividendGrowth: 0,
    annualDilution: 0.05,
    years: 2,
  });
  assert.equal(result.ok, true);
  assert.ok(Math.abs(result.terminalPrice - (121 / Math.pow(1.05, 2))) < 0.000001);
  assert.ok(Math.abs(result.dividends - 4) < 0.000001);
});

test("project cases validates probabilities and returns a weighted outcome", () => {
  const result = math.projectCases({
    price: 100,
    currentPE: 20,
    years: 2,
    scenarios: [
      { name: "Bear", probability: 0.25, exitPE: 15, growth: 0 },
      { name: "Base", probability: 0.5, exitPE: 20, growth: 0.1 },
      { name: "Bull", probability: 0.25, exitPE: 25, growth: 0.2 },
    ],
  });
  assert.equal(result.ok, true);
  assert.equal(result.scenarios.length, 3);
  assert.ok(result.expectedTerminalPrice > result.scenarios[0].model.terminalPrice);
  assert.ok(result.expectedTerminalPrice < result.scenarios[2].model.terminalPrice);
  assert.ok(result.expectedCagr > 0);
  assert.equal(math.projectCases({
    price: 100,
    currentPE: 20,
    years: 2,
    scenarios: [
      { probability: 0.4, exitPE: 15, growth: 0 },
      { probability: 0.4, exitPE: 20, growth: 0.1 },
    ],
  }).ok, false);
});

test("project cases keeps bear, base, and bull assumptions independent", () => {
  const input = {
    price: 100,
    currentPE: 20,
    years: 3,
    scenarios: [
      { name: "Bear", probability: 0.25, exitPE: 15, growth: 0.02 },
      { name: "Base", probability: 0.5, exitPE: 20, growth: 0.1 },
      { name: "Bull", probability: 0.25, exitPE: 30, growth: 0.2 },
    ],
  };
  const first = math.projectCases(input);
  const changedBear = math.projectCases({
    ...input,
    scenarios: input.scenarios.map(scenario => scenario.name === "Bear" ? { ...scenario, exitPE: 50 } : scenario),
  });
  assert.equal(first.ok, true);
  assert.equal(changedBear.ok, true);
  assert.notEqual(first.scenarios[0].model.terminalPrice, changedBear.scenarios[0].model.terminalPrice);
  assert.equal(first.scenarios[1].model.terminalPrice, changedBear.scenarios[1].model.terminalPrice);
  assert.equal(first.scenarios[2].model.terminalPrice, changedBear.scenarios[2].model.terminalPrice);
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

test("future value compounds monthly and tracks contributions separately", () => {
  const result = math.futureValue({ principal: 10000, monthlyContribution: 500, annualReturn: 0.10, years: 10 });
  assert.equal(result.ok, true);
  assert.equal(result.contributions, 70000);
  assert.ok(result.value > result.contributions);
  assert.equal(result.path.length, 11);
});

test("compound scenarios calculate low, base, high, and inflation-adjusted values", () => {
  const result = math.compoundScenarios({
    principal: 25000,
    monthlyContribution: 750,
    baseReturn: 0.10,
    variance: 0.03,
    inflation: 0.025,
    years: 15,
  });
  assert.equal(result.ok, true);
  assert.ok(result.low.value < result.base.value);
  assert.ok(result.base.value < result.high.value);
  assert.ok(result.realValue < result.base.value);
});

test("future value rejects impossible assumptions", () => {
  assert.equal(math.futureValue({ principal: -1, monthlyContribution: 0, annualReturn: 0.1, years: 5 }).ok, false);
  assert.equal(math.futureValue({ principal: 1, monthlyContribution: 0, annualReturn: -1, years: 5 }).ok, false);
});

test("future value deducts optional annual fees and tax drag", () => {
  const gross = math.futureValue({ principal: 10000, monthlyContribution: 0, annualReturn: 0.1, years: 10 });
  const net = math.futureValue({ principal: 10000, monthlyContribution: 0, annualReturn: 0.1, annualFee: 0.01, taxDrag: 0.02, years: 10 });
  assert.equal(net.ok, true);
  assert.ok(net.value < gross.value);
  assert.ok(Math.abs(net.effectiveAnnualReturn - 0.07) < 0.000001);
});

"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

async function listen(app) {
  return new Promise((resolve, reject) => {
    const server = app.listen(0, "127.0.0.1", () => {
      resolve({
        server,
        baseUrl: `http://127.0.0.1:${server.address().port}`,
      });
    });
    server.on("error", reject);
  });
}

test("LensScore Lab is available with noindex/no-store headers outside production", async () => {
  const previousNodeEnv = process.env.NODE_ENV;
  process.env.NODE_ENV = "test";
  delete require.cache[require.resolve("../server")];
  const app = require("../server");
  const { server, baseUrl } = await listen(app);
  try {
    const response = await fetch(`${baseUrl}/__lab/lens-score`);
    const html = await response.text();
    assert.equal(response.status, 200);
    assert.equal(response.headers.get("x-robots-tag"), "noindex, nofollow, noarchive");
    assert.equal(response.headers.get("cache-control"), "no-store");
    assert.match(html, /LensScore Research/);
    assert.match(html, /\/__lab\/lens-score\/assets\/lens-score-engine\.js/);
  } finally {
    await new Promise(resolve => server.close(resolve));
    if (previousNodeEnv === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = previousNodeEnv;
  }
});

test("LensScore Lab route is absent in production", async () => {
  const previous = {
    NODE_ENV: process.env.NODE_ENV,
    FINNHUB_KEY: process.env.FINNHUB_KEY,
    SESSION_SECRET: process.env.SESSION_SECRET,
    STRIPE_SECRET_KEY: process.env.STRIPE_SECRET_KEY,
    STRIPE_WEBHOOK_SECRET: process.env.STRIPE_WEBHOOK_SECRET,
  };
  Object.assign(process.env, {
    NODE_ENV: "production",
    FINNHUB_KEY: "test-key",
    SESSION_SECRET: "test-session-secret-that-is-long-enough-for-the-route-contract",
    STRIPE_SECRET_KEY: "sk_test_lens_score_route_contract",
    STRIPE_WEBHOOK_SECRET: "whsec_lens_score_route_contract",
  });
  delete require.cache[require.resolve("../server")];
  const app = require("../server");
  const { server, baseUrl } = await listen(app);
  try {
    const response = await fetch(`${baseUrl}/__lab/lens-score`);
    assert.equal(response.status, 404);
    const production = await fetch(`${baseUrl}/lens-score`);
    const html = await production.text();
    assert.equal(production.status, 200);
    assert.match(html, /<meta name="robots" content="index,follow">/);
    assert.match(html, /\/lens-score\/assets\/lens-score-engine\.js/);
    assert.doesNotMatch(html, /Local prototype|sample assumptions/);
  } finally {
    await new Promise(resolve => server.close(resolve));
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
});

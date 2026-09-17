/* The test that should have existed before the warm-up shipped.
 *
 * A background walk over the 103 published tickers took production down with
 * exit 134 — SIGABRT, V8's "Reached heap limit", not the container's OOM
 * killer. The cause was not the fetching, which was paced and capped; it was
 * that every company read left its SEC companyfacts document in a 30-minute
 * cache whose limit counts ENTRIES, not bytes. About a hundred multi-megabyte
 * documents were therefore live at once.
 *
 * The tests I wrote at the time covered the walk's pacing and its error
 * handling and said nothing about what it accumulated, because I was thinking
 * about provider rate limits. These assert the thing that actually mattered:
 * a company read for a landing page is not retained afterwards.
 */
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

/* A stub with the SHAPE of the SEC endpoints. Size does not matter here —
 * retention does, and retention is what is asserted. */
let companyFactsFetches = 0;
const realFetch = global.fetch;

global.fetch = async (url) => {
  const target = String(url);
  if (target.includes("company_tickers.json")) {
    const rows = {};
    for (let i = 0; i < 20; i += 1) rows[i] = { cik_str: 2000 + i, ticker: `MEM${i}`, title: `Memory Test ${i}` };
    return { ok: true, status: 200, json: async () => rows };
  }
  if (target.includes("companyfacts")) {
    companyFactsFetches += 1;
    const cik = target.match(/CIK(\d+)/)[1];
    return {
      ok: true,
      status: 200,
      json: async () => ({
        cik,
        entityName: "Memory Test",
        facts: { "us-gaap": { Revenues: { units: { USD: [
          { end: "2026-06-30", val: 1000, filed: "2026-07-31", form: "10-Q" },
        ] } } } },
      }),
    };
  }
  throw new Error("unexpected fetch in this test: " + target);
};

const research = require("../lib/stock-research");

test.after(() => { global.fetch = realFetch; });

test("a company read once is handed back, not held for thirty minutes", async () => {
  companyFactsFetches = 0;

  await research.loadCompanyFacts("MEM1");
  assert.equal(companyFactsFetches, 1);

  // Cached: a second read inside the TTL must not go back to the SEC.
  await research.loadCompanyFacts("MEM1");
  assert.equal(companyFactsFetches, 1, "the app's own cache stopped working");

  // Released: the next read has to fetch again, which is the proof that the
  // document is no longer sitting in memory.
  const forgotten = await research.forgetCompanyFacts("MEM1");
  assert.equal(forgotten, true, "nothing was released");
  await research.loadCompanyFacts("MEM1");
  assert.equal(companyFactsFetches, 2, "the document was still cached after being released");

  // Leave nothing behind for the next test — which is the whole point.
  await research.forgetCompanyFacts("MEM1");
});

test("releasing is safe for a ticker that was never read, or is not a company", async () => {
  /* Called in a .finally, including on the failure path, so it must not throw
     for a symbol that never resolved. */
  assert.equal(await research.forgetCompanyFacts("MEM7"), false);
  assert.equal(await research.forgetCompanyFacts("NOT-A-TICKER"), false);
  assert.equal(await research.forgetCompanyFacts(""), false);
});

test("reading many companies in sequence retains none of them", async () => {
  companyFactsFetches = 0;
  for (let i = 0; i < 10; i += 1) {
    await research.loadCompanyFacts(`MEM${i}`);
    await research.forgetCompanyFacts(`MEM${i}`);
  }
  assert.equal(companyFactsFetches, 10);
  /* Every one of them must be gone. If any were retained, forgetting it now
     would report true — a walk over the published set would then be holding
     exactly what it held the day it aborted the process. */
  for (let i = 0; i < 10; i += 1) {
    assert.equal(
      await research.forgetCompanyFacts(`MEM${i}`),
      false,
      `MEM${i} was still cached after the walk`
    );
  }
});

test("the landing path releases the document on both the success and failure paths", () => {
  const source = require("node:fs").readFileSync(
    require("node:path").join(__dirname, "..", "lib", "stock-landing-facts.js"), "utf8"
  );
  const finallyBlock = source.slice(source.indexOf(".finally(() => {"));
  assert.match(finallyBlock.slice(0, 500), /forgetCompanyFacts\(ticker\)/,
    "release is not in the .finally, so a failed hydration still retains the document");
});

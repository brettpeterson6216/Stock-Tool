"use strict";
/* A closing price is never labelled with the opening bell (audit F15). */
const test = require("node:test");
const assert = require("node:assert");
const { quoteTimes } = require("../lib/quote-time");
const sec = iso => Date.parse(iso) / 1000;

test("a daily bar stamped at the open is dated at that day's 4 p.m. ET close", () => {
  const winter = quoteTimes({ latestTimestamp: sec("2026-11-02T14:30:00Z"), now: Date.parse("2026-11-03T12:00:00Z") });
  assert.equal(winter.barDate, "2026-11-02");
  assert.equal(winter.asOf, "2026-11-02T21:00:00.000Z");
  const summer = quoteTimes({ latestTimestamp: sec("2026-07-02T13:30:00Z"), now: Date.parse("2026-07-03T12:00:00Z") });
  assert.equal(summer.asOf, "2026-07-02T20:00:00.000Z");
});

test("the provider's own quote time wins, and mid-session uses the fetch time", () => {
  const q = quoteTimes({ latestTimestamp: sec("2026-11-02T14:30:00Z"), regularMarketTime: sec("2026-11-02T21:00:01Z") });
  assert.equal(q.quoteTime, "2026-11-02T21:00:01.000Z");
  assert.equal(q.asOf, q.quoteTime);
  const now = Date.parse("2026-11-03T16:00:00Z");
  const live = quoteTimes({ latestTimestamp: sec("2026-11-03T14:30:00Z"), now });
  assert.equal(live.asOf, new Date(now).toISOString());
});

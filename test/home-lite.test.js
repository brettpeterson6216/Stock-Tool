"use strict";
const test = require("node:test");
const assert = require("node:assert");
const path = require("path");
const { wantsLite, liteHtml, isPlainHomeQuery } = require("../lib/home-lite");
const { readStamped } = require("../lib/asset-stamp");

const full = readStamped(path.join(__dirname, "..", "index.html"));
const lite = liteHtml(full);

function scripts(html) {
  return [...html.matchAll(/<script\b[^>]*\bsrc="([^"]+)"/g)].map(m => m[1].split("?")[0]);
}

test("only a signed-out visitor on the plain home page gets the lite copy", () => {
  assert.equal(wantsLite({ method: "GET", query: {}, session: {} }), true);
  assert.equal(wantsLite({ method: "GET", query: { utm_source: "x", ref: "bio" }, session: {} }), true);
  assert.equal(wantsLite({ method: "GET", query: {}, session: { userId: 7 } }), false);
  for (const k of ["view", "section", "ticker", "symbol", "pricing", "market", "workspace_tab"]) {
    assert.equal(isPlainHomeQuery({ [k]: "1" }), false, k);
  }
});

test("the lite copy holds back the app and nothing the landing page uses", () => {
  assert.ok(lite, "markers found");
  const heavy = scripts(lite);
  for (const gone of ["/app-legacy.js", "/vendor/chart.umd.min.js",
    "/vendor/lightweight-charts.standalone.production.js", "/projection-lab.js", "/workspace-system.js"]) {
    assert.ok(!heavy.includes(gone), `${gone} still loads`);
    assert.ok(scripts(full).includes(gone), `${gone} missing from the full page`);
  }
  for (const kept of ["/theme-bootstrap.js", "/app-navigation.js", "/ticker-search.js", "/landing-demo.js",
    "/landing-market.js", "/il-ribbon.js", "/il-icons.js", "/site-nav.js", "/home-lite.js"]) {
    assert.ok(heavy.includes(kept), `${kept} should still load`);
  }
});

test("held-back URLs match the full page exactly, so the prefetch is a cache hit", () => {
  const attr = lite.match(/id="il-home-lite" data-bundle="([^"]*)"/)[1];
  const list = JSON.parse(attr.replace(/&quot;/g, '"').replace(/&lt;/g, "<").replace(/&amp;/g, "&"));
  const fullSrcs = [...full.matchAll(/<script\b[^>]*\bsrc="([^"]+)"/g)].map(m => m[1]);
  assert.ok(list.length >= 15);
  for (const href of list) assert.ok(fullSrcs.includes(href), href);
});

test("a template without markers serves the full page", () => {
  assert.equal(liteHtml("<html><body><script src=/a.js></script></body></html>"), null);
});

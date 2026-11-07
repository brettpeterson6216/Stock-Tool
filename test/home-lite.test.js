"use strict";
const test = require("node:test");
const assert = require("node:assert");
const path = require("path");
const { liteHtml } = require("../lib/home-lite");
const { readStamped } = require("../lib/asset-stamp");

const full = readStamped(path.join(__dirname, "..", "index.html"));
const lite = liteHtml(full);

function scripts(html) {
  return [...html.matchAll(/<script\b[^>]*\bsrc="([^"]+)"/g)].map(m => m[1].split("?")[0]);
}

test("the landing page loads only its own scripts; the retired app is gone", () => {
  assert.ok(lite);
  const loaded = scripts(lite);
  for (const gone of ["/app-legacy.js", "/vendor/chart.umd.min.js", "/vendor/lightweight-charts.standalone.production.js",
    "/projection-lab.js", "/workspace-system.js", "/home-member.js", "/index-chart.js"]) {
    assert.ok(!loaded.includes(gone), `${gone} still loads`);
  }
  for (const kept of ["/theme-bootstrap.js", "/app-navigation.js", "/ticker-search.js", "/landing-demo.js",
    "/landing-market.js", "/il-ribbon.js", "/il-icons.js", "/site-nav.js", "/home-lite.js"]) {
    assert.ok(loaded.includes(kept), `${kept} should still load`);
  }
});

test("any app bundle block left in a template is still held back", () => {
  const out = liteHtml("<html><body><!-- il:app-bundle --><script defer src=\"/a.js\"></script><!-- /il:app-bundle --><p>x</p></body></html>");
  assert.ok(!/src="\/a\.js"/.test(out));
  assert.match(out, /home-lite\.js/);
});

test("the landing page's routes into the retired app go to the pages that replaced it", () => {
  const src = require("node:fs").readFileSync(path.join(__dirname, "..", "public", "home-lite.js"), "utf8");
  assert.doesNotMatch(src, /go\("\/\?view=tool/);
  assert.match(src, /screener: "\/screener"/);
  assert.match(src, /reports: "\/saved"/);
});

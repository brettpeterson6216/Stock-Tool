"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const landing = require("../lib/landing-css");
const { liteHtml } = require("../lib/home-lite");

test("the landing page's trimmed stylesheet was cut from the bundle it uses today", () => {
  const s = landing.status();
  assert.ok(s.ok, `landing-lite.css is stale (${s.reason}). Run npm run build:styles, then npm run build:landing-css.`);
});

test("the trimmed stylesheet keeps the rules the landing page and the site bar rely on", () => {
  const css = fs.readFileSync(landing.LITE_FILE, "utf8");
  assert.ok(css.length < fs.statSync(landing.landingBundle().file).size * 0.8, "it should be meaningfully smaller than the bundle");
  for (const needle of ["@layer premium,heritage", "@font-face", "@keyframes", "[data-theme=", "@media"]) {
    assert.ok(css.includes(needle), `missing ${needle}`);
  }
});

test("only the signed-out landing copy links the trimmed stylesheet; it falls back when stale", () => {
  const bundle = landing.landingBundle().url;
  const page = `<html><head><link rel="stylesheet" href="${bundle}?v=1"></head><body>` +
    `<!-- il:app-bundle --><script src="/a.js"></script><!-- /il:app-bundle -->` +
    `<!-- il:app-bundle --><script src="/b.js"></script><!-- /il:app-bundle --></body></html>`;
  const lite = liteHtml(page);
  assert.match(lite, /href="\/bundles\/landing-lite\.css\?v=1"/);
  assert.doesNotMatch(lite, new RegExp(bundle.replace(/[.]/g, "\\.")));

  const prev = process.env.IL_LANDING_CSS;
  process.env.IL_LANDING_CSS = "full";
  try { assert.match(liteHtml(page), new RegExp(`href="${bundle.replace(/[.]/g, "\\.")}\\?v=1"`)); }
  finally { if (prev === undefined) delete process.env.IL_LANDING_CSS; else process.env.IL_LANDING_CSS = prev; }
});

test("no stylesheet bundle sits in public/bundles that nothing serves", () => {
  const served = new Set(Object.values(require("../lib/style-bundles.json")).map(u => path.basename(u)));
  served.add(path.basename(landing.LITE_URL));
  const dir = path.join(__dirname, "..", "public", "bundles");
  const orphans = fs.readdirSync(dir).filter(f => f.endsWith(".css") && !served.has(f));
  assert.deepEqual(orphans, []);
});

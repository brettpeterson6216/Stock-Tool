// Cache-busting that cannot be forgotten.
//
// Every stylesheet and script is served with `Cache-Control: public,
// max-age=604800` behind a hand-written `?v=` token, and there were eleven
// different tokens across the HTML with nothing to update them but memory.
// Two deploys in a row changed public/surface.css without changing its token,
// so every browser that had already loaded the page kept the old sheet for up
// to a week and neither fix reached anyone who had visited before.
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const { STAMP, stampHtml, readStamped } = require("../lib/asset-stamp");
const ROOT = path.join(__dirname, "..");

const localAssets = html => [...html.matchAll(/(?:href|src)="(\/[^"]*\.(?:css|js))(\?[^"]*)?"/g)]
  .map(m => ({ url: m[1], query: m[2] || "" }));

test("every local stylesheet and script carries the build's token", () => {
  for (const page of ["index.html", "public/blog.html", "public/about.html", "public/signup.html"]) {
    const html = readStamped(path.join(ROOT, page));
    const assets = localAssets(html);
    assert.ok(assets.length > 0, `${page} references no local assets at all`);

    const missing = assets.filter(a => !a.query.includes("?v="));
    assert.deepEqual(missing.map(a => a.url), [],
      `${page} serves these with no cache-busting token, so a deploy cannot reach a returning browser`);

    const tokens = new Set(assets.map(a => a.query.replace(/^\?v=/, "")));
    assert.equal(tokens.size, 1,
      `${page} carries ${tokens.size} different tokens: ${[...tokens].join(", ")} - the point is that one deploy moves all of them`);
    assert.equal([...tokens][0], STAMP);
  }
});

test("a ?v= that is not a local asset is left alone", () => {
  // A YouTube link is watch?v=... . Written without the leading-slash
  // requirement this rewrote one into watch?v=<commit> and broke it - which is
  // why the requirement is here and why this test is.
  const html = [
    '<a href="https://youtube.com/watch?v=abc123">clip</a>',
    '<link href="https://cdn.example.com/x.css?v=9" rel="stylesheet">',
    '<p>the query ?v=1 in copy</p>',
  ].join("\n");
  assert.equal(stampHtml(html), html);
});

test("a local asset is stamped whether or not it already had a token", () => {
  const out = stampHtml('<link href="/a.css?v=old"><script src="/b.js"></script>');
  assert.match(out, new RegExp(`/a\\.css\\?v=${STAMP}`));
  assert.match(out, new RegExp(`/b\\.js\\?v=${STAMP}`));
  assert.doesNotMatch(out, /v=old/);
});

test("the token is the build, not a date somebody typed", () => {
  const buildInfo = require("../lib/build-info");
  if (buildInfo.shortCommit && buildInfo.shortCommit !== "local") {
    assert.equal(STAMP, buildInfo.shortCommit, "in a real deploy the token has to be the commit");
  } else {
    // Locally there is no commit, so it is the boot time: still different on
    // every restart, which is what a developer needs.
    assert.match(STAMP, /^\d{10,}$/);
  }
});

test("pages are served revalidating, or the token never gets seen", () => {
  // The stamp only works because the HTML itself is not cached. If that
  // changes, the token in a stale page keeps pointing at the old assets.
  const server = require("fs").readFileSync(path.join(ROOT, "server.js"), "utf8");
  assert.match(server, /\.html"\)\)\s*res\.setHeader\("Cache-Control", "no-cache, must-revalidate"\)|no-cache, must-revalidate/,
    "HTML must be served no-cache for the asset stamp to reach a returning browser");
  const stamp = require("fs").readFileSync(path.join(ROOT, "lib", "asset-stamp.js"), "utf8");
  assert.match(stamp, /Cache-Control", "no-cache, must-revalidate"/);
});

// The LensToolkit page used to feel like a different product.
//
// Three separate causes, none of them cosmetic accidents:
//
//   The account chip showed a bare username where the app showed PRO. The
//   static pages build their own chip in static-auth.js and read `user.plan` —
//   the raw users.plan column — while the app reads `user.effectivePlan`. A
//   gifted or comped account sits at plan='free' with effectivePlan='pro'
//   (lib/plan.js), and a trial only ever exists as effectivePlan. Same session,
//   two different answers, depending on which page you were on.
//
//   The chip also pasted " · PRO" into its text instead of painting the gold
//   pill the app uses.
//
//   And the page never loaded surface.css — the last sheet index.html loads —
//   so the settled surface treatment stopped at the boundary of this document.
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");
const read = (...p) => fs.readFileSync(path.join(ROOT, ...p), "utf8");
const auth = read("public", "static-auth.js");

test("the static pages read the same plan the app reads", () => {
  assert.match(auth, /effectivePlan/,
    "static-auth still reads the raw users.plan column, so gifted and trial accounts show no badge");
  // Every plan decision must go through the one helper, or the cached hint and
  // the server reconcile can disagree on first paint.
  const reads = [...auth.matchAll(/user\.plan\b/g)].length;
  const inHelper = /function planOf\(user\)[\s\S]{0,220}user\.effectivePlan \|\| user\.plan/.test(auth);
  assert.ok(inHelper, "there is no single planOf() helper");
  assert.ok(reads <= 1, `user.plan is read ${reads} times outside the helper`);
});

test("the plan is painted as the app's badge, not pasted into the text", () => {
  assert.match(auth, /nav-acct-badge/, "the static chip does not build the badge element");
});

test("the toolkit page loads the site's last stylesheet", () => {
  assert.match(read("labs", "lens-score", "index.html"), /surface\.css/,
    "lens-score still stops short of surface.css, so its surfaces differ from every other page");
});

test("the tab is LensToolkit everywhere, and the metric is still LensScore", () => {
  const pages = ["index.html", ...fs.readdirSync(path.join(ROOT, "public"))
    .filter(f => f.endsWith(".html")).map(f => "public/" + f), "labs/lens-score/index.html"];
  for (const p of pages) {
    const html = read(p);
    if (!html.includes("nav-lensscore-link")) continue;
    assert.match(html, /id="nav-lensscore-link"[^>]*>LensToolkit</,
      `${p} still labels the tab LensScore`);
  }
  // The page renames the surface, not the score it computes.
  assert.match(read("labs", "lens-score", "index.html"), /LensScore/,
    "the metric's own name was renamed along with the tab");
  assert.match(read("labs", "lens-score", "index.html"), /<title>LensToolkit · ImpliedLens<\/title>/);
});

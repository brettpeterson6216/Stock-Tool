// The teaching content used to be the least reachable thing on the site.
//
// Every lesson lived inside a const in public/app-legacy.js, rendered into a
// panel at /?view=tool&section=education. That is a query string, not a URL:
// nothing could link to a lesson, no search engine could index one, and reading
// any of it meant loading the whole application first. For the part of the site
// meant to bring people in, that is exactly backwards.
//
// public/lessons-data.js is now the single source — loaded as a script in the
// browser and required by the server — and scripts/build-learn.js generates a
// real page per lesson from it. These tests hold that arrangement: one source,
// pages that exist, and a crawler that can find them.
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { execFileSync } = require("node:child_process");

const ROOT = path.join(__dirname, "..");
const P = (...p) => path.join(ROOT, ...p);
const read = (...p) => fs.readFileSync(P(...p), "utf8");
const { lessons } = require(P("public", "lessons-data.js"));

test("there are lessons, and each one is complete", () => {
  assert.ok(lessons.length >= 5, `only ${lessons.length} lessons`);
  for (const l of lessons) {
    for (const field of ["slug", "title", "group", "summary", "opening", "body", "formula", "example", "warning", "closing"]) {
      assert.ok(l[field] && String(l[field]).trim(), `${l.slug} is missing ${field}`);
    }
    assert.ok(Array.isArray(l.points) && l.points.length >= 3, `${l.slug} has too few points`);
    assert.match(l.slug, /^[a-z0-9-]+$/, `${l.slug} is not URL-safe`);
    // The summary is what a search result shows. A stub helps nobody.
    assert.ok(l.summary.length >= 40, `${l.slug}'s summary is too short to be a useful search snippet`);
  }
});

test("the generated pages are in sync with the data", () => {
  // The generator's own --check mode: a hand-edited lesson page fails here.
  try {
    execFileSync("node", [P("scripts", "build-learn.js"), "--check"], { stdio: "pipe" });
  } catch (e) {
    assert.fail(String(e.stderr || e.stdout || e.message).trim());
  }
});

test("every lesson has a page, and the index links to all of them", () => {
  const index = read("public", "learn.html");
  for (const l of lessons) {
    assert.ok(fs.existsSync(P("public", "learn", `${l.slug}.html`)), `no page for ${l.slug}`);
    assert.ok(index.includes(`/learn/${l.slug}`), `the index does not link to ${l.slug}`);
  }
});

test("a crawler can find them", () => {
  const { buildSitemapXml } = require(P("lib", "acquisition-tickers.js"));
  const xml = buildSitemapXml("https://impliedlens.com");
  assert.ok(xml.includes("<loc>https://impliedlens.com/learn</loc>"), "/learn is not in the sitemap");
  for (const l of lessons) {
    assert.ok(xml.includes(`/learn/${l.slug}</loc>`), `${l.slug} is not in the sitemap`);
  }
  // Lessons are free. A noindex here would undo the entire point.
  for (const l of lessons) {
    assert.doesNotMatch(read("public", "learn", `${l.slug}.html`), /name="robots"[^>]*noindex/,
      `${l.slug} is marked noindex`);
  }
});

test("the Learn tab goes to the lessons, and lights up when it gets there", () => {
  const pages = ["index.html", ...fs.readdirSync(P("public")).filter(f => f.endsWith(".html")).map(f => "public/" + f)];
  for (const p of pages) {
    const html = read(p);
    if (!html.includes("nav-news-link")) continue;
    assert.match(html, /href="\/learn" id="nav-news-link"/, `${p} still sends Learn to the blog`);
  }
  assert.match(read("public", "site-nav.js"), /path\.indexOf\("\/learn\/"\) === 0/,
    "a lesson page does not mark the Learn tab active");
  assert.match(read("server.js"), /app\.get\("\/learn\/:slug"/, "no route serves a lesson");
});

test("the pages carry their own identity, not the donor page's", () => {
  const charts = read("public", "learn", "charts.html");
  assert.match(charts, /<link rel="canonical" href="https:\/\/impliedlens\.com\/learn\/charts">/);
  assert.doesNotMatch(charts, /<title>About — ImpliedLens<\/title>/);
  assert.match(charts, /<title>Use technical indicators[^<]*<\/title>/);
});

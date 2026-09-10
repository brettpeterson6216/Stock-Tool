// The logo is one file. Everything the site serves as an icon is derived from
// brand/logo-source.png by scripts/build-brand.js, and these tests hold that
// arrangement together:
//
//   1. the derived files are actually in sync with the source, so nobody can
//      edit a favicon by hand and have it silently diverge from the mark;
//   2. every icon URL referenced from any page exists on disk, because a
//      missing favicon fails silently - the browser just shows its default
//      and a bookmark keeps the wrong picture for months;
//   3. the manifest still declares a maskable icon, which is the one Android
//      crops to a circle and the one that looks broken without padding.
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { execFileSync } = require("node:child_process");

const ROOT = path.join(__dirname, "..");
const P = (...p) => path.join(ROOT, ...p);

test("the brand source exists and is the only source", () => {
  assert.ok(fs.existsSync(P("brand", "logo-source.png")), "brand/logo-source.png is missing");
});

test("every derived icon matches the source artwork", () => {
  // The generator's own --check mode: it rebuilds each asset in memory and
  // compares the bytes, so a hand-edited favicon fails here.
  try {
    execFileSync("node", [P("scripts", "build-brand.js"), "--check"], { encoding: "utf8" });
  } catch (err) {
    assert.fail((err.stdout || "") + (err.stderr || "") || String(err));
  }
});

test("every icon the pages reference exists on disk", () => {
  const pages = ["index.html", ...fs.readdirSync(P("public")).filter((f) => f.endsWith(".html")).map((f) => "public/" + f)];
  const missing = [];
  for (const page of pages) {
    const html = fs.readFileSync(P(page), "utf8");
    for (const [, url] of html.matchAll(/(?:href|src|content)="(?:https:\/\/impliedlens\.com)?(\/[^"?]+\.(?:png|ico|svg|webmanifest))(?:\?[^"]*)?"/g)) {
      if (!fs.existsSync(P("public", url.slice(1)))) missing.push(`${page} -> ${url}`);
    }
  }
  assert.deepEqual([...new Set(missing)], [], "these referenced assets do not exist");
});

test("the manifest ships an any icon and a maskable one", () => {
  const m = JSON.parse(fs.readFileSync(P("public", "site.webmanifest"), "utf8"));
  const purposes = m.icons.map((i) => i.purpose);
  assert.ok(purposes.includes("any"), "no purpose:any icon");
  assert.ok(purposes.includes("maskable"), "no purpose:maskable icon — Android will crop the mark");
  for (const icon of m.icons) {
    assert.ok(fs.existsSync(P("public", icon.src.slice(1))), `manifest points at missing ${icon.src}`);
  }
  assert.equal(m.theme_color, m.background_color, "the manifest's two colours disagree");
});

test("the favicons keep their alpha and the platform tiles do not", () => {
  const png = (f) => fs.readFileSync(P("public", f));
  // PNG colour type lives at byte 25 of the IHDR; 6 is RGBA, 2 is RGB.
  const colourType = (buf) => buf[25];
  for (const f of ["favicon-16.png", "favicon-32.png", "favicon-48.png", "logo-mark.png"]) {
    assert.equal(colourType(png(f)), 6, `${f} lost its transparency — it will show as a box in a tab`);
  }
  for (const f of ["apple-touch-icon.png", "app-icon-192.png", "app-icon-maskable-512.png"]) {
    assert.equal(colourType(png(f)), 2, `${f} is transparent — iOS and Android composite it onto their own ground`);
  }
});

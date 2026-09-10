// An icon class that is not in the bundled Tabler subset renders as an empty
// box: the tile is still there, still tinted, still 34px, and completely
// blank. It looks like a loading failure and it ships silently, because
// nothing errors. Three of the six About cards did exactly this on the first
// pass of replacing the emoji, because ti-target-arrow, ti-building-community
// and ti-world are not in the subset this site bundles.
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");
const font = fs.readFileSync(path.join(ROOT, "public", "vendor", "tabler-icons.min.css"), "utf8");
const AVAILABLE = new Set(
  [...font.matchAll(/\.(ti-[a-z0-9-]+):before/g)].map((m) => m[1])
);

const PAGES = fs
  .readdirSync(path.join(ROOT, "public"))
  .filter((f) => f.endsWith(".html"))
  .map((f) => ["public/" + f, path.join(ROOT, "public", f)])
  .concat([["index.html", path.join(ROOT, "index.html")]]);

test("the icon subset actually contains glyphs", () => {
  assert.ok(AVAILABLE.size > 50, `only ${AVAILABLE.size} icons parsed from the font CSS`);
});

test("every icon class used in markup exists in the bundled subset", () => {
  const missing = [];
  for (const [label, file] of PAGES) {
    const html = fs.readFileSync(file, "utf8");
    for (const [, cls] of html.matchAll(/class="ti (ti-[a-z0-9-]+)"/g)) {
      if (!AVAILABLE.has(cls)) missing.push(`${label}: ${cls}`);
    }
  }
  assert.deepEqual(
    [...new Set(missing)],
    [],
    "these icon classes render as empty tiles because the glyph is not bundled"
  );
});

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

/* ── the font binary, not just the stylesheet ────────────────────────────────
   Subsetting the CSS to 5KB left tabler-icons.woff2 shipping all 5,108 glyphs
   at 451KB — the heaviest asset on the site, on the first load of every page,
   to draw 121 icons. It is subset to the glyphs the sheet emits now (15KB).

   The failure that needs catching is not a corrupt font; it is someone adding
   an icon to the sheet and not regenerating the binary, which ships a blank
   tile and errors nowhere. woff2 is brotli-compressed, so rather than parse it
   here, scripts/subset-icon-font.js records what it built and this compares
   that record against the sheet. */
test("the shipped icon font covers every glyph the stylesheet emits", () => {
  const manifestPath = path.join(ROOT, "brand", "fonts", "tabler-icons.subset.json");
  assert.ok(fs.existsSync(manifestPath), "the icon font subset manifest is missing");
  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));

  const sheetCodepoints = [...new Set(
    [...font.matchAll(/content:\s*"\\([0-9a-fA-F]{2,6})"/g)].map(m => m[1].toUpperCase())
  )].sort();

  assert.deepEqual(
    [...manifest.codepoints].sort(),
    sheetCodepoints,
    "the stylesheet and the subset font disagree — run `node scripts/subset-icon-font.js`"
  );

  const shipped = fs.statSync(path.join(ROOT, "public", "vendor", "fonts", "tabler-icons.woff2")).size;
  assert.equal(shipped, manifest.bytes,
    "the shipped icon font is not the one the manifest describes — regenerate it");
  /* A budget, not an exact size: 118 glyphs compress to ~15KB, and the full
     set is 451KB. Anything approaching the latter means the subset step was
     skipped and the full font got committed again. */
  assert.ok(shipped < 64 * 1024,
    `the icon font is ${(shipped / 1024).toFixed(0)}KB — the subset step did not run`);
});

test("the full icon font is kept as a source, so the subset can be rebuilt", () => {
  /* Subsetting an already-subset font looks like it worked and makes the next
     icon anyone adds unrecoverable. The input must always be the full set. */
  const full = path.join(ROOT, "brand", "fonts", "tabler-icons-full.woff2");
  assert.ok(fs.existsSync(full), "brand/fonts/tabler-icons-full.woff2 is missing");
  assert.ok(fs.statSync(full).size > 256 * 1024, "the kept source is not the full icon set");
});

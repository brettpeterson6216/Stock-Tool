/* Subset the Tabler icon FONT to the glyphs the stylesheet actually emits.
 *
 * scripts/subset-icons.js shrank the stylesheet from 211KB to 5KB and left the
 * binary alone: tabler-icons.woff2 shipped all 5,108 glyphs at 451KB, on the
 * first load of every page on the site, to draw 121 icons. Measured cold, it
 * was the single heaviest asset anywhere — larger than app-legacy.js (275KB),
 * larger than the chart library (196KB) — and 97% of it was glyphs nothing
 * references. Subsetting it to the 118 codepoints the sheet emits takes it to
 * 15KB.
 *
 * The full font stays at brand/fonts/tabler-icons-full.woff2 (brand/ is not
 * served) and is always the input, never the output. Subsetting an
 * already-subsetted font would look like it worked and quietly make the next
 * icon anyone adds unrecoverable.
 *
 * This is deliberately NOT part of subset-icons.js: that script rewrites the
 * stylesheet in place from itself, so it is destructive on a second run. This
 * one is idempotent — same source, same codepoint list, same output.
 *
 * pyftsubset (fonttools + brotli) does the work. It is a Python tool and this
 * is a Node script, so when it is absent the step is skipped with a note
 * rather than failing the build, the same way check:bar skips without
 * Playwright. test/icon-glyphs.test.js verifies the committed font either way,
 * so a missing tool cannot ship a font with a hole in it.
 */
"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");
const { execFileSync } = require("child_process");

const ROOT = path.join(__dirname, "..");
const SHEET = path.join(ROOT, "public", "vendor", "tabler-icons.min.css");
const SOURCE = path.join(ROOT, "brand", "fonts", "tabler-icons-full.woff2");
const TARGET = path.join(ROOT, "public", "vendor", "fonts", "tabler-icons.woff2");
const MANIFEST = path.join(ROOT, "brand", "fonts", "tabler-icons.subset.json");

function codepointsFromSheet() {
  const sheet = fs.readFileSync(SHEET, "utf8");
  return [...new Set(
    (sheet.match(/content:\s*"\\([0-9a-fA-F]{2,6})"/g) || [])
      .map(m => m.match(/\\([0-9a-fA-F]{2,6})/)[1].toUpperCase())
  )].sort();
}

function main() {
  if (!fs.existsSync(SOURCE)) {
    console.log("skipped — brand/fonts/tabler-icons-full.woff2 is missing");
    return;
  }
  const codepoints = codepointsFromSheet();
  if (codepoints.length < 50) {
    /* A sheet that emits almost nothing means something upstream went wrong.
       Building a near-empty font from it would replace every icon on the site
       with a blank box, and the source to rebuild from is one file away. */
    console.log(`refusing — the sheet emits only ${codepoints.length} glyphs, which is not a subset, it is a mistake`);
    process.exitCode = 1;
    return;
  }

  const listFile = path.join(os.tmpdir(), "il-icon-codepoints.txt");
  fs.writeFileSync(listFile, codepoints.map(c => "U+" + c).join(","));
  try {
    execFileSync("pyftsubset", [
      SOURCE,
      "--unicodes-file=" + listFile,
      "--flavor=woff2",
      "--layout-features=",
      "--no-hinting",
      "--desubroutinize",
      "--output-file=" + TARGET,
    ], { stdio: ["ignore", "ignore", "pipe"] });
  } catch (err) {
    console.log("skipped — pyftsubset unavailable (pip install fonttools brotli)");
    return;
  } finally {
    try { fs.unlinkSync(listFile); } catch (_) {}
  }

  /* A manifest, not a checksum, because the failure this has to catch is
     "someone added an icon to the sheet and did not regenerate the font".
     The test compares this list against the sheet's, so that gap fails in CI
     rather than shipping a blank tile. Kept out of public/ — it is build
     bookkeeping, not an asset. */
  fs.writeFileSync(MANIFEST, JSON.stringify({
    generatedFrom: "brand/fonts/tabler-icons-full.woff2",
    codepoints,
    bytes: fs.statSync(TARGET).size,
  }, null, 2) + "\n");

  console.log("glyphs kept :", codepoints.length);
  console.log("source      :", (fs.statSync(SOURCE).size / 1024).toFixed(0) + " KB (full set)");
  console.log("shipped     :", (fs.statSync(TARGET).size / 1024).toFixed(1) + " KB");
}

main();

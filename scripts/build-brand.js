/* Regenerates every icon the site serves from one source file.

   brand/logo-source.jpg is the logo as supplied: the lens frame with the
   candlesticks, gold on near-black. Everything below is derived from it, so
   the favicon, the PWA icons, the Apple touch icon, the header mark and the
   social card can never drift apart or away from the artwork again.

   Run:  npm run build:brand
   Check: npm run check:brand   (fails if any output is stale)

   Two forms are produced from the same source:

     tile        the mark on its own near-black ground. iOS composites Apple
                 touch icons onto white, so a transparent one would put a gold
                 ring on white and lose the whole design. Windows and Android
                 tiles want a solid ground too.

     transparent the mark keyed off its ground, for the header, where it has
                 to sit on cream in light theme and graphite in dark. The
                 subject is bright-on-dark, so luminance IS the matte: the
                 alpha is the source's own luma with the ground level
                 subtracted, which keeps the gold gradient and the soft glow
                 instead of cutting a hard edge round them.
*/
"use strict";
const fs = require("fs");
const path = require("path");
const zlib = require("zlib");

const ROOT = path.join(__dirname, "..");
const SRC = path.join(ROOT, "brand", "logo-source.png");
const OUT = path.join(ROOT, "public");
const CHECK = process.argv.includes("--check");

// ── minimal PNG/JPEG decode + encode, so this has no dependencies ──────────
const { execFileSync } = require("child_process");
function py(script, ...args) {
  return execFileSync("python3", ["-c", script, ...args], { maxBuffer: 1 << 28 });
}
const GEN = path.join(__dirname, "build-brand.py");
const res = execFileSync("python3", [GEN, SRC, OUT, CHECK ? "--check" : "--write"], {
  encoding: "utf8",
  maxBuffer: 1 << 28,
});
process.stdout.write(res);

// "Lots of areas with empty space and sloppy color boxes and borders and lots
// of colors that don't fit with the rest of the site."
//
// Measured across 14 routes in both themes, that complaint was:
//   39 distinct border colours, 38 backgrounds, 12 corner radii, and content
//   starting 56 / 64 / 126 / 129px below the bar depending on the page.
//
// None of it was a styling mistake. Twenty-three stylesheets from five design
// generations each shipped their own palette — --lp-*, --il-*, --rp-*, --sp-*,
// --lpf-* and fifteen more — and eight of them style .il-rail-item alone. Two
// of those palettes were explicitly COOL ("Ink surfaces — cool neutral" says
// premium-revamp.css's own comment) while the brand went warm, so #0d1519 and
// #14181F painted next to #151917 and read as a different site.
//
// The fix redefines the old tokens onto the --rp-* ramp rather than editing
// hundreds of rules other pages still depend on. This test holds that shape,
// because the cheapest way to undo it is to add one more palette.
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");
const premium = fs.readFileSync(path.join(ROOT, "public", "research-premium.css"), "utf8");

test("the radius scale has four steps and nothing else", () => {
  const radii = [...premium.matchAll(/border-radius:\s*(\d+)px/g)].map(m => m[1] + "px");
  const allowed = new Set(["8px", "12px", "14px", "999px", "0px"]);
  const stray = [...new Set(radii)].filter(r => !allowed.has(r));
  assert.deepEqual(stray, [],
    `these radii are outside the scale (8 controls / 12 surfaces / 14 modals / 999 pills): ${stray.join(", ")}`);
});

test("the cool palettes stay mapped onto the warm ramp", () => {
  // Whichever sheet declares them, these names must resolve to --rp-* here.
  for (const token of ["--lp-panel", "--lp-hover", "--lp-elev", "--lp-bg",
                       "--il-surface", "--il-surface-2", "--panel", "--card", "--sp-panel"]) {
    const re = new RegExp(token.replace(/[-]/g, "\\-") + ":\\s*var\\(--rp-[a-z0-9-]+\\)");
    assert.match(premium, re,
      `${token} is no longer mapped to the --rp-* ramp — the cool palette is back on that surface`);
  }
});

test("no cool-cast hex is introduced in the premium layer", () => {
  // A hex is "cool" when blue meaningfully exceeds red. The brand is warm;
  // #0d1519, #10191d, #14181f and #33373e are what this is guarding against.
  //
  // Two exemptions, both found by this test firing on its first run:
  //   Comments. The prose above explains the bug by naming the hexes it
  //   removed, and a scanner that reads comments flags the explanation.
  //   Chart series colours. --ilx-b #558fcc is the second line on the market
  //   chart. Multi-series charts need hues that separate, and blue against
  //   gold is the right pair; "warm everywhere" applies to surfaces, not to
  //   data. Flattening series colours to one ramp would be a worse chart.
  const code = premium.replace(/\/\*[\s\S]*?\*\//g, "");
  const CHART_SERIES = /--ilx-[a-z]\s*:\s*$/;
  const offenders = [];
  for (const m of code.matchAll(/#([0-9a-f]{6})\b/gi)) {
    if (CHART_SERIES.test(code.slice(Math.max(0, m.index - 24), m.index))) continue;
    const h = m[1];
    const r = parseInt(h.slice(0, 2), 16), g = parseInt(h.slice(2, 4), 16), b = parseInt(h.slice(4, 6), 16);
    if (b > r + 8 && b > g + 4) offenders.push("#" + h);
  }
  assert.deepEqual([...new Set(offenders)], [],
    "these are blue-cast values in a warm palette — the exact thing that read as \"doesn't fit\"");
});

test("every page opens at the same place", () => {
  assert.match(premium, /\.il-static-page > :is\(\.hero, \.wrap, \.section\), \.il-static-page > main \{[^}]*padding-top: 80px/,
    "the static pages lost their single opening gap; they were 56 / 126 / 129 before");
  assert.match(premium, /body\.il-lens-page > main#lab-main \{[^}]*padding-top: 80px/,
    "LensToolkit is back to its own 129px opening gap");
  // The selector that failed the first time. :first-of-type looked right and
  // matched the zero-height .lp-static-drawer instead of the hero.
  assert.doesNotMatch(premium, /\.il-static-page :is\([^)]*\):first-of-type/,
    ":first-of-type is back — it matches the invisible drawer, not the content");
});

test("one content column, one left edge", () => {
  assert.match(premium, /\.il-static-page :is\([^)]*\) \{\s*max-width: min\(calc\(100% - 40px\), 980px\)/,
    "the content pages no longer share one column; they were 980 / 1170 / 1240 before");
});

test("borders and gold edges resolve to tokens, not hand-mixed rgba", () => {
  const block = premium.slice(premium.indexOf("ONE BOX SYSTEM"));
  assert.match(block, /border-color: var\(--rp-line\)/, "the hairline is not tokenised");
  assert.match(block, /border-color: var\(--rp-line-strong\)/, "the emphasis edge is not tokenised");
  assert.match(block, /border-color: var\(--rp-gold-ring\)/, "the gold edge is not tokenised");
  // Six golds at eight alphas is what this replaced.
  const rawGold = [...block.matchAll(/border-color:\s*rgba\((2\d\d|1\d\d),\s*1\d\d/g)];
  assert.equal(rawGold.length, 0, "a hand-mixed gold border is back in the box system");
});

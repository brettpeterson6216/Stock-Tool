// surface.css is loaded after clean-pass.css, which means every rule in it
// wins ties on order. That is the point of the file — and it is also the trap
// it fell into.
//
// clean-pass.css makes the dashboard two columns below 1500px and one below
// 1000px, in media queries. An UNCONDITIONAL three-column rule in a later
// sheet, at the same specificity, outranks all of them at every width. The
// 900px dashboard kept the 240/1fr/336 grid: the market panel's head collapsed
// onto its own price, the timeframe buttons stacked into a vertical stripe,
// and the index tiles ran through each other.
//
// These tests hold the two halves of that contract: the layout rules stay
// inside their breakpoints, and the breakpoints stay the ones the earlier
// sheet already uses. A third breakpoint invented here would be a layout that
// changes shape twice on the way down.
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");
const surface = fs.readFileSync(path.join(ROOT, "public", "surface.css"), "utf8");
const clean = fs.readFileSync(path.join(ROOT, "public", "clean-pass.css"), "utf8");

// Split a sheet into (mediaQueryOrNull, body) chunks by brace depth.
function blocks(css) {
  const out = [];
  let i = 0;
  while (i < css.length) {
    const at = css.indexOf("@media", i);
    if (at === -1) { out.push([null, css.slice(i)]); break; }
    out.push([null, css.slice(i, at)]);
    const open = css.indexOf("{", at);
    let depth = 0, end = open;
    for (; end < css.length; end += 1) {
      if (css[end] === "{") depth += 1;
      else if (css[end] === "}") { depth -= 1; if (!depth) { end += 1; break; } }
    }
    out.push([css.slice(at, open).trim(), css.slice(open, end)]);
    i = end;
  }
  return out;
}

const parts = blocks(surface);
const unconditional = parts.filter(([q]) => q === null).map(([, body]) => body).join("\n");

test("the three-column grid is inside a breakpoint, not standing over one", () => {
  assert.doesNotMatch(unconditional, /\.ihm-grid \{[^}]*grid-template-columns/,
    "an unconditional .ihm-grid column rule outranks clean-pass.css's media queries at every width");
  const scoped = parts.some(([q, body]) =>
    q && /min-width:\s*1501px/.test(q) && /\.ihm-grid \{[^}]*grid-template-columns: 240px/.test(body));
  assert.ok(scoped, "the desktop grid is not scoped to min-width: 1501px");
});

test("nothing that assumes three real columns applies when there are not three", () => {
  for (const [rule, why] of [
    [/\.ihm-grid \{[^}]*align-items: stretch/, "columns cannot share a baseline when they are stacked"],
    [/\.ihm-col-tools > \.ihm-panel:last-child/, "the last panel only takes up slack inside a column"],
    [/\.ihm-col-tools \.ihm-tool \{[^}]*flex: 1 1 auto/, "below 1500px clean-pass gives tools flex: 1 1 200px in a row"],
  ]) {
    assert.doesNotMatch(unconditional, rule, why);
  }
});

test("the breakpoints match the ones the sheet before it already uses", () => {
  const known = new Set();
  for (const [q] of blocks(clean)) {
    if (!q) continue;
    for (const m of q.matchAll(/(max|min)-width:\s*(\d+)px/g)) known.add(Number(m[2]));
  }
  // A min-width breakpoint pairs with the max-width one a pixel below it.
  const paired = n => known.has(n) || known.has(n - 1) || known.has(n + 1);
  const used = new Set();
  for (const [q] of parts) {
    if (!q) continue;
    for (const m of q.matchAll(/(max|min)-width:\s*(\d+)px/g)) used.add(Number(m[2]));
  }
  const strays = [...used].filter(n => !paired(n));
  assert.deepEqual(strays, [],
    `breakpoints ${strays.join(", ")} exist only in surface.css, so the layout changes shape at a width nothing else knows about`);
});

test("the plot's viewport height is not itself trapped in a breakpoint", () => {
  // It is a clamp on 100vh; it has to hold at every width, or a narrow window
  // gets the desktop's chart height and the page scrolls for the wrong reason.
  assert.match(unconditional, /\.ilx-plot \{ height: clamp\(/,
    "the responsive plot height moved inside a media query");
});

// ── The hero card and the grid it was never in ────────────────────────────
// .il-landing-hero declares grid-template-areas "copy preview" / "features
// features". `grid-area: preview` was written for .il-landing-preview — the
// old hero illustration — and when that was replaced by the live market card
// the assignment did not come with it, so #il-hero-live was auto-placed, the
// row sized to the copy beside it rather than to the card, and the card
// overflowed its row by 107px: 54 above the hero and 54 straight onto the
// feature rail. Measured overlap ran 72px at 1000 down to 10px at 1400 — the
// whole laptop range — and it reproduced on the commit before this pass.
test("the hero card is placed in the hero grid, and the row is sized to it", () => {
  assert.match(surface, /#landing-page \.il-hero-live \{[^}]*grid-area: preview/,
    "the market card is not claiming the preview area, so it will be auto-placed again");
  assert.match(surface, /#landing-page \.il-landing-hero \{[^}]*grid-template-rows: max-content max-content/,
    "naming the area is not enough on its own — the row has to be allowed to size to the card");
});

test("the trust row is bounded by the column it sits in", () => {
  // Its own max-width (389-430px) was wider than the copy column (319-390px),
  // so it overhung by 55-75px and FRED was drawn under the market card at
  // every width from 1180 to 2560.
  assert.match(surface, /#landing-page \.il-trust \{ max-width: 100%/,
    "the trust row can overhang its column again");
});

// This is the second time an UNCONDITIONAL rule has silently beaten the media
// queries above it and broken the dashboard at narrow widths.
//
// The first was a three-column .ihm-grid in a later sheet (see
// surface-cascade.test.js). The second lived in research-premium.css itself:
//
//   @media (max-width: 1250px) { .ihm-grid { grid-template-columns: 1fr 280px } }
//   @media (max-width: 900px)  { .ihm-grid { grid-template-columns: 1fr } }
//   ...
//   .ihm-grid { grid-template-columns: 220px minmax(0,1fr) 330px !important; }
//
// The last line has no media query, so it applied at every width and the two
// above it never took effect. The breakpoints still reassigned grid-column,
// which pushed the main column and the tools column both into column one -
// 220px wide - while a phantom 330px column sat beside them. Measured at a
// 1100px viewport: .ihm-panel 102px, .ihm-panel-head 64px, and a 220px
// timeframe strip overflowing that 64px head, which is how the buttons ended
// up printed on top of the word "Market" on phones and on any desktop window
// under 1280.
//
// The rule this test holds: a multi-column template for the dashboard grid is
// a DESKTOP statement and must say so.
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");
// Comments in these files contain braces and even sample CSS, which desyncs a
// brace-counting parser and makes it report a comment as a selector. Strip
// them first.
const strip = (css) => css.replace(/\/\*[\s\S]*?\*\//g, "");
const SHEETS = ["research-premium.css", "clean-pass.css", "surface.css"]
  .filter((f) => fs.existsSync(path.join(ROOT, "public", f)))
  .map((f) => ({ name: f, css: strip(fs.readFileSync(path.join(ROOT, "public", f), "utf8")) }));

// Walk the file tracking @media nesting depth so we know whether a given
// declaration sits inside one.
function templateRules(css, selectorNeedle) {
  const out = [];
  let depth = 0;
  const mediaDepths = [];
  const re = /@media([^{]*)\{|\{|\}|([^{}]+)\{([^{}]*)\}/g;
  // simpler: scan brace by brace
  let i = 0, inMedia = 0, buf = "";
  const stack = [];
  while (i < css.length) {
    const ch = css[i];
    if (ch === "{") {
      const head = buf.trim();
      buf = "";
      if (/^@media/i.test(head)) { stack.push({ media: head }); inMedia += 1; }
      else stack.push({ sel: head });
      i += 1;
      continue;
    }
    if (ch === "}") {
      const top = stack.pop();
      if (top && top.media) inMedia -= 1;
      buf = "";
      i += 1;
      continue;
    }
    if (ch === ";") {
      const decl = buf.trim();
      const rule = [...stack].reverse().find((f) => f.sel);
      const media = [...stack].reverse().find((f) => f.media);
      if (rule && rule.sel.includes(selectorNeedle) && /grid-template-columns/.test(decl)) {
        out.push({ sel: rule.sel, decl, media: media ? media.media : null, at: i });
      }
      buf = "";
      i += 1;
      continue;
    }
    buf += ch;
    i += 1;
  }
  return out;
}

function columnCount(decl) {
  const value = decl.split(":").slice(1).join(":").replace(/!important/g, "").trim();
  // collapse functions so their internal commas/spaces don't count as tracks
  const flat = value.replace(/\w+\([^()]*\)/g, "X");
  return flat.split(/\s+/).filter(Boolean).length;
}

test("no dashboard grid template is declared after its own breakpoints", () => {
  // A base template BEFORE the media queries is correct - that is how the
  // cascade is meant to work. The bug is a template AFTER them, which nothing
  // below its own breakpoint can override.
  const offenders = [];
  for (const { name, css } of SHEETS) {
    const rules = templateRules(css, ".ihm-grid");
    const lastNarrow = Math.max(
      -1,
      ...rules.filter((r) => r.media && /max-width/.test(r.media)).map((r) => r.at)
    );
    if (lastNarrow < 0) continue;
    for (const r of rules) {
      if (!r.media && columnCount(r.decl) >= 2 && r.at > lastNarrow) {
        offenders.push(`${name}: ${r.decl.trim().slice(0, 74)}`);
      }
    }
  }
  assert.deepEqual(
    offenders,
    [],
    "this template sits after the max-width blocks that are supposed to override " +
      "it, so it wins at every width and collapses the dashboard when narrow"
  );
});

test("a narrow-width template for the dashboard grid still exists", () => {
  const narrow = SHEETS.flatMap(({ css }) => templateRules(css, ".ihm-grid"))
    .filter((r) => r.media && /max-width/.test(r.media));
  assert.ok(narrow.length >= 2, "the dashboard lost its narrow-width templates");
});

test("the market panel head does not ask three things to share one line when narrow", () => {
  const css = SHEETS.find((s) => s.name === "research-premium.css").css;
  const at = css.indexOf(".ihm-market-panel .ihm-panel-head");
  assert.notEqual(at, -1, "the market panel head rule is gone");
  // The three-across template is what collided; it must be behind a min-width.
  const threeAcross = css.indexOf("grid-template-columns: auto 1fr auto");
  if (threeAcross !== -1) {
    const before = css.slice(0, threeAcross);
    const lastMedia = before.lastIndexOf("@media");
    const lastClose = before.lastIndexOf("}\n}");
    assert.ok(
      lastMedia > lastClose && /min-width/.test(css.slice(lastMedia, lastMedia + 60)),
      "the three-across market head must be inside a min-width media query"
    );
  }
});

// Measured on the signed-out landing page at 1600px, before this rule existed:
//
//   il-landing-hero      content starts at x=144   max-width 1440, pad 64
//   il-startpaths                             188   max-width 1320, pad 48
//   il-market-strip                            85   max-width none, pad 42
//   il-capabilities                           188   max-width 1320, pad 48
//   il-workflow-visual                        188   max-width 1320, pad 48
//   il-landing-band                           243   max-width 1180, pad 32
//   il-landing-pricing                        188   max-width 1320, pad 48
//
// Four different max-widths and four different gutters stacked vertically, so
// the page's left edge visibly stepped in and out as you scrolled. This test
// holds the rule that gives them one rail — a new section that opts out by
// declaring its own max-width is the regression.
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");
const css = fs.readFileSync(path.join(ROOT, "public", "research-premium.css"), "utf8");

const SECTIONS = [
  ".il-landing-hero",
  ".il-startpaths",
  ".il-capabilities",
  ".il-workflow-visual",
  ".il-landing-band",
  ".il-landing-pricing",
];

function railRule() {
  const at = css.indexOf("ONE RAIL ON THE LANDING PAGE");
  assert.notEqual(at, -1, "the landing rail block is gone from research-premium.css");
  const open = css.indexOf("#landing-page > :is(", at);
  assert.notEqual(open, -1, "the railed selector list is gone");
  return { selector: css.slice(open, css.indexOf("{", open)), body: css.slice(css.indexOf("{", open), css.indexOf("}", open)) };
}

test("every top-level landing section is on the shared rail", () => {
  const { selector } = railRule();
  const missing = SECTIONS.filter((s) => !selector.includes(s));
  assert.deepEqual(missing, [], "these sections are not railed, so they will set their own left edge");
});

test("the rail states one max-width and one gutter", () => {
  const { body } = railRule();
  assert.match(body, /max-width:\s*1320px/, "the shared max-width is gone");
  assert.match(body, /padding-inline:\s*clamp\(/, "the shared gutter is gone");
  assert.match(body, /margin-inline:\s*auto/, "the rail is not centred");
});

test("the full-bleed strip aligns its contents to the same rail", () => {
  // Full-bleed is legitimate — the strip's BACKGROUND should span the
  // viewport. Its text must not.
  const at = css.indexOf("#landing-page > .il-market-strip > * {");
  assert.notEqual(at, -1, "the market strip's inner rail is gone");
  const body = css.slice(at, css.indexOf("}", at));
  assert.match(body, /max-width:\s*1320px/, "the strip's contents are not railed");
});

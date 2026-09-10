// Two rules on this site have now been broken by a LATER stylesheet quietly
// overriding an EARLIER one that was already correct. Both cost real users
// something, and neither showed up on a desktop browser.
//
//  1. The fixed header. index.html opts into viewport-fit=cover, which asks
//     iOS to paint the page underneath the status bar. legacy-app.css already
//     compensated for that:
//
//       #main-nav{height:calc(56px + env(safe-area-inset-top));
//                 padding-top:env(safe-area-inset-top)}
//
//     clean-pass.css later pinned the bar to a flat `height:63px` with
//     min/max to match and no top padding. On an iPhone the status bar is
//     59px of that 63px bar, so the wordmark printed through the clock and
//     the account control sat behind the battery icon, untappable, on every
//     page of the site.
//
//  2. The footer gutter. .footer-inner's only side padding came from being
//     centred inside its own max-width:1100px. Below 1100px there is no
//     centring left to do, so every link sat flush against x=0 with its
//     first glyph clipped by the viewport edge.
//
// These assertions are cheap and they are specifically the shape of the two
// regressions, not a restatement of the fix.
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");
const read = (f) => fs.readFileSync(path.join(ROOT, "public", f), "utf8");
const clean = read("clean-pass.css");

// The declaration block for the fixed bar, so the assertions below cannot be
// satisfied by an unrelated #main-nav rule elsewhere in the file.
function navBlock(css) {
  const at = css.indexOf("body:not(#cp6) #main-nav {");
  assert.notEqual(at, -1, "the pinned #main-nav rule is gone from clean-pass.css");
  return css.slice(at, css.indexOf("}", at));
}

test("the fixed header reserves the device's top inset", () => {
  const block = navBlock(clean);
  assert.match(
    block,
    /padding-top:\s*env\(safe-area-inset-top/,
    "#main-nav must pad for the status bar, or iOS paints the page under it"
  );
  for (const prop of ["height", "min-height", "max-height"]) {
    const m = block.match(new RegExp(`\\n\\s*${prop}:\\s*([^;]+);`));
    assert.ok(m, `#main-nav lost its ${prop}`);
    assert.match(
      m[1],
      /env\(safe-area-inset-top|var\(--nav-h\)/,
      `${prop} is pinned to a flat value again — that is the bug: ${m[1].trim()}`
    );
  }
});

test("what sits below the header offsets by the same amount", () => {
  // A bar that grows by the inset while the page below it does not is the
  // same defect wearing the opposite sign: content hidden under the bar.
  const bodyPad = clean.match(/body:not\(#cp6\) \{\s*padding-top:\s*([^;]+);/);
  assert.ok(bodyPad, "the body offset for the fixed bar is gone");
  assert.match(
    bodyPad[1],
    /env\(safe-area-inset-top/,
    `body offset must track the bar height, got: ${bodyPad[1].trim()}`
  );
});

test("the footer has a side gutter that does not depend on its max-width", () => {
  // There is more than one `> footer` rule; collect them all rather than
  // trusting the first one to be the padding rule.
  const blocks = [];
  for (let at = clean.indexOf("body:not(#cp6) > footer {"); at !== -1;
       at = clean.indexOf("body:not(#cp6) > footer {", at + 1)) {
    blocks.push(clean.slice(at, clean.indexOf("}", at)));
  }
  assert.ok(blocks.length, "the footer rules are gone from clean-pass.css");

  for (const block of blocks) {
    assert.doesNotMatch(
      block,
      /padding:\s*\d+(?:px|rem|em)?\s+0\s*(?:!important)?\s*;/,
      "a `padding: N 0` shorthand zeroes the side gutter — that is exactly how " +
        "every footer link ended up clipped at x=0 on a phone"
    );
  }
  assert.ok(
    blocks.some((b) => /padding-inline:/.test(b)),
    "the footer needs an explicit side gutter, not one inherited from centring"
  );
});

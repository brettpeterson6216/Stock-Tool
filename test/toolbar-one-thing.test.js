// "Use THE SAME top toolbar across the whole website."
//
// It already was, in the only sense the tests could see. header-contract.test.js
// SHA1s the <nav id="main-nav"> block across all fourteen documents and fails if
// a single byte differs, and it passed the entire time LensToolkit's bar looked
// wrong — because the markup was never the problem.
//
// Seventeen stylesheets carry rules for this bar. premium-revamp has 125 of
// them, site-shell 120, legacy-app 108, clean-pass 76. Every page gets a
// different subset, and LensToolkit loads its own sheet on top with this in it:
//
//     button, input { font: inherit; }
//
// A page-level reset, reaching into shared chrome. It resized every control in
// the toolbar from the 13.3px the other pages happened to render to that page's
// 16px body size: the account chip came out 108x30 instead of 85x21, sitting
// 5px higher. Identical markup styled by a different set of sheets is not one
// toolbar.
//
// Measured after the fix, with a real browser across all fourteen routes signed
// in as Pro: every part of the bar is identical on every page. These tests hold
// the three things that make that true, because none of them is visible to a
// test that reads markup.
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");
const premium = fs.readFileSync(path.join(ROOT, "public", "research-premium.css"), "utf8");
const SHEETS = [
  ...fs.readdirSync(path.join(ROOT, "public")).filter(f => f.endsWith(".css")).map(f => ["public/" + f, path.join(ROOT, "public", f)]),
  ["labs/lens-score/styles.css", path.join(ROOT, "labs", "lens-score", "styles.css")],
];

test("the bar has one authoritative definition, and it is in the sheet every page loads", () => {
  // research-premium.css is appended to every bundle by build-styles.js, so it
  // is the only sheet that can speak for all fourteen pages at once.
  const block = premium.slice(premium.indexOf("THE TOP BAR IS ONE THING"));
  assert.ok(block.length > 400, "the authoritative bar block is gone from research-premium.css");

  // The parts that drifted, pinned explicitly rather than inherited. 13.3px was
  // never a decision — it is Chrome's default button size, which is exactly why
  // one page's reset could silently replace it.
  for (const [sel, prop] of [
    ["#nav-acct-btn", "font-size"], ["#nav-acct-btn", "height"],
    ["#nav-acct-name", "font-size"], ["#nav-acct-badge", "font-size"],
    ["#theme-toggle-btn", "font-size"], ["#nav-ticker-input", "font-size"],
    [".nav-logo", "height"], [".il-global-actions", "font-size"],
  ]) {
    const re = new RegExp("#main-nav[^{]*" + sel.replace(/[.#]/g, "\\$&") + "[^{]*\\{[^}]*" + prop + ":", "s");
    assert.match(block, re, `the bar does not pin ${prop} on ${sel}, so a page sheet can still change it`);
  }
});

test("no page stylesheet resets the controls inside the shared chrome", () => {
  // The exact shape of the LensToolkit bug: a bare-element rule with no scope,
  // in a sheet only some pages load. `font` and `font-size` are what matters —
  // they cascade into the bar and change its geometry.
  const BARE = /(^|[}\n])\s*((?:button|input|select|textarea)(?:\s*,\s*(?:button|input|select|textarea))*)\s*\{([^}]*)\}/g;
  const offenders = [];
  for (const [name, file] of SHEETS) {
    if (name === "public/research-premium.css") continue;   // the authority
    const css = fs.readFileSync(file, "utf8").replace(/\/\*[\s\S]*?\*\//g, "");
    for (const m of css.matchAll(BARE)) {
      if (!/font(-size|-family)?\s*:/.test(m[3])) continue;
      /* One exemption, and it is a real one. legacy-app.css sets
         `input,select,textarea{font-size:16px!important}` inside its 640px
         query because mobile Safari zooms the viewport when a focused input
         renders below 16px. That is a functional floor, not a style choice;
         the bar matches it at the same breakpoint rather than overriding it.
         Scoping this rule away from the chrome would have put the zoom back. */
      if (/font-size\s*:\s*16px/.test(m[3]) && /input/.test(m[2])) continue;
      offenders.push(`${name}: ${m[2].trim()} { ${m[3].trim().slice(0, 40)} }`);
    }
  }
  assert.deepEqual(offenders, [],
    "these unscoped resets reach into #main-nav on the pages that load them, which is what made LensToolkit's bar a different size");
});

test("the you-are-here mark costs no layout", () => {
  // The active tab picked up a 1px left and right border the others did not
  // have, so the tab row, the search box and the account chip all shifted 2px
  // sideways every time you changed page.
  const block = premium.slice(premium.indexOf("THE TOP BAR IS ONE THING"));
  assert.match(block, /#main-nav \.nav-tab \{[^}]*border: 1px solid transparent/,
    "tabs no longer carry the same box at rest, so the active one changes the row's width");
  const active = block.match(/#main-nav \.nav-tab:is\(\.active-tab[^{]*\{([^}]*)\}/);
  assert.ok(active, "the active-tab rule is gone");
  assert.match(active[1], /box-shadow: inset/, "the indicator is not drawn with an inset shadow, so it takes up space");
  assert.doesNotMatch(active[1], /(^|;)\s*(padding|border-width|border-left|border-right|font-weight)\s*:/,
    "the active tab changes its own box again — the bar will shift when you navigate");
});

test("hidden means hidden", () => {
  // [hidden] is only a UA rule at display:none, so any author rule that sets
  // display beats it. Three bugs so far: the dashboard needed its own guard,
  // the duplicate account link drew beside the real chip, and the search
  // clear-x appeared on the auth pages with an empty field.
  assert.match(premium, /html body \[hidden\] \{ display: none !important; \}/,
    "the [hidden] guard is gone; anything that sets display will beat the attribute again");
});

test("LensToolkit's own reset stays out of the chrome", () => {
  const lens = fs.readFileSync(path.join(ROOT, "labs", "lens-score", "styles.css"), "utf8");
  const bare = lens.replace(/\/\*[\s\S]*?\*\//g, "").match(/(^|[}\n])\s*button\s*,\s*input\s*\{/);
  assert.equal(bare, null,
    "labs/lens-score/styles.css resets bare button+input again — that is the rule that resized the shared toolbar");
});

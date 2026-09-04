"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const PUBLIC_DIR = path.join(__dirname, "..", "public");
const shared = fs.readFileSync(path.join(PUBLIC_DIR, "lens-prime-shared.css"), "utf8");
const appLegacy = fs.readFileSync(path.join(PUBLIC_DIR, "app-legacy.js"), "utf8");
const toolLaunch = fs.readFileSync(path.join(PUBLIC_DIR, "tool-launch.js"), "utf8");

// Isolate the product-terminal rules. The static pages in this file are a
// separate, deliberate decision and are still dark-only.
const TERMINAL_PREFIX = "body.il-product-page.il-tool-active";
function terminalRules(css) {
  return css
    .split("}")
    .filter(chunk => chunk.includes(TERMINAL_PREFIX))
    .join("}");
}

// lens-prime-shared.css loads after every theme-aware stylesheet in the page
// and selects with three ids plus !important, so a literal colour here silently
// beats the light-mode rules those sheets define. That is how the terminal
// ended up painting dark text on pinned dark panels.
test("the terminal paints its surfaces from tokens, not literal colours", () => {
  const rules = terminalRules(shared);
  const surfaceProps = /(?:^|;|\{)\s*(background|background-color|background-image)\s*:\s*([^;!}]+)/g;
  const offenders = [];
  let m;
  while ((m = surfaceProps.exec(rules)) !== null) {
    const value = m[2].trim();
    if (/var\(--lp-/.test(value)) continue;
    if (/^(transparent|none|inherit|initial|unset)$/i.test(value)) continue;
    // Gold accents are intentionally the same in both themes.
    if (/#e[dbc]|#c9[89]|#edca79|#c98d2c/i.test(value)) continue;
    if (/^radial-gradient/.test(value)) continue;
    if (/#[0-9a-f]{3,8}\b/i.test(value) || /\brgba?\(/.test(value)) offenders.push(value.slice(0, 70));
  }
  assert.deepEqual(offenders, [], "literal surface colours in the terminal cannot follow the theme");
});

// A theme-aware terminal needs both halves of the palette present.
test("both halves of the terminal palette are defined", () => {
  assert.match(shared, /--lp-elev\s*:/, "dark palette missing --lp-elev");
  assert.match(
    shared,
    /html:not\(\[data-theme="dark"\]\) body\.il-product-page\s*\{[^}]*--lp-bg\s*:/,
    "light palette missing for the product terminal"
  );
});

// Measured on the rendered dashboard: 19 elements sat below 11px, the smallest
// at 7.5px. Keep the floor.
test("the terminal does not set type below 11px", () => {
  const rules = terminalRules(shared);
  const sizes = [...rules.matchAll(/font-size\s*:\s*([\d.]+)px/g)].map(m => parseFloat(m[1]));
  const tooSmall = sizes.filter(px => px < 11);
  assert.deepEqual(tooSmall, [], "font sizes below the 11px floor");
});

// An em dash is indistinguishable from a real value of nothing. Under a heading
// that reads "Live watchboard", eight of them look like a broken product.
test("a failed quote fetch says so instead of rendering a bare dash", () => {
  assert.match(
    appLegacy,
    /Live quotes are unavailable right now/,
    "the watchboard needs an explicit all-failed state"
  );
  assert.match(
    appLegacy,
    /fstock-chg--na[^`]*Unavailable/,
    "a single failed ticker needs to say it is unavailable"
  );
  assert.match(
    toolLaunch,
    /cell\(IDX\[i\]\.label,\s*"Unavailable"/,
    "the index strip needs to distinguish a failure from a value"
  );
  assert.match(
    toolLaunch,
    /"loading"/,
    "the index strip needs to distinguish loading from failure"
  );
});

// -webkit-text-fill-color paints over `color`; the Analyze button set a dark
// `color` for its gold fill and then had that fill repainted near-white in
// light mode, measured at 2.14:1 off the rendered pixels.
test("terminal controls take their text fill from color", () => {
  assert.match(
    shared,
    /#view-tool button[^{]*\{[^}]*-webkit-text-fill-color:\s*currentColor/,
    "controls in the terminal must inherit their fill so both themes work"
  );
});

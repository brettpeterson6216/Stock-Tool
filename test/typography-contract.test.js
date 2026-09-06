"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");
const SHEETS = fs.readdirSync(path.join(ROOT, "public"))
  .filter(f => f.endsWith(".css"))
  .map(f => ({ name: f, css: fs.readFileSync(path.join(ROOT, "public", f), "utf8") }));
SHEETS.push({
  name: "labs/lens-score/styles.css",
  css: fs.readFileSync(path.join(ROOT, "labs", "lens-score", "styles.css"), "utf8"),
});

// font-size on an icon element sizes the glyph, and sup/sub are meant to be
// small - the same carve-outs the fix itself used.
const ICON_OR_MATH = /(^|[\s,>+~.#[])(i|sup|sub)([\s,>+~.:[{]|$)|\.ti\b|ti-|icon|chevron|caret|arrow|glyph|\bsvg\b|::?before|::?after/i;

function declarations(css) {
  const out = [];
  const block = /([^{}]*)\{([^{}]*)\}/g;
  let m;
  while ((m = block.exec(css)) !== null) out.push({ sel: m[1], body: m[2] });
  return out;
}

// Measured across thirteen routes: 189 rendered elements sat below 11px, the
// smallest at 6px. 236 of the declarations behind them said exactly 10px - a
// whole tier of the UI, not scattered accidents.
test("no stylesheet sets body type below 11px", () => {
  const offenders = [];
  for (const { name, css } of SHEETS) {
    for (const { sel, body } of declarations(css)) {
      if (ICON_OR_MATH.test(sel)) continue;
      for (const m of body.matchAll(/font-size\s*:\s*([\d.]+)px/g)) {
        if (parseFloat(m[1]) < 11) offenders.push(`${name}: ${sel.trim().slice(0, 50)} -> ${m[1]}px`);
      }
      for (const m of body.matchAll(/font\s*:\s*(?:[^;{}]*?\s)?([\d.]+)px\s*\//g)) {
        if (parseFloat(m[1]) < 11) offenders.push(`${name}: ${sel.trim().slice(0, 50)} -> ${m[1]}px`);
      }
      // clamp() slipped past the first sweep because the number is not
      // adjacent to the colon.
      for (const m of body.matchAll(/font-size\s*:\s*clamp\(([^)]*)\)/g)) {
        for (const px of m[1].matchAll(/([\d.]+)px/g)) {
          if (parseFloat(px[1]) < 11) offenders.push(`${name}: ${sel.trim().slice(0, 50)} -> clamp ${px[1]}px`);
        }
      }
    }
  }
  assert.deepEqual(offenders.slice(0, 12), [], `${offenders.length} declarations below the 11px floor`);
});

test("the micro type token stays on the readable side of the floor", () => {
  const il = SHEETS.find(s => s.name === "il-system.css").css;
  const m = il.match(/--t-micro:\s*([\d.]+)px/);
  assert.ok(m, "--t-micro is gone");
  assert.ok(parseFloat(m[1]) >= 11, `--t-micro is ${m[1]}px; it feeds every micro label on the site`);
});

// The copy in the HTML was already sentence case - "Decision workflow",
// "Market overview", "Welcome back". text-transform was doing the shouting.
// The wordmark and ticker symbols are the legitimate exceptions.
test("uppercase is reserved for the wordmark and ticker symbols", () => {
  const ALLOWED = /wordmark|brand|logo|\bsym\b|fstock-sym|ticker-sym|abbr/i;
  const offenders = [];
  for (const { name, css } of SHEETS) {
    for (const { sel, body } of declarations(css)) {
      if (!/text-transform\s*:\s*uppercase/.test(body)) continue;
      if (ALLOWED.test(sel)) continue;
      offenders.push(`${name}: ${sel.trim().slice(0, 60)}`);
    }
  }
  assert.deepEqual(offenders.slice(0, 10), [], `${offenders.length} selectors still shout`);
});

// Every route measured zero contrast failures in dark and several in light,
// because literal colours were written when dark was the only theme.
/* Pin the property, not the literal. This test used to assert the exact hex
   and broke the moment the token was strengthened for a ground it had not been
   solved against - which is the wrong way round: the value is allowed to move,
   the guarantee is not. So the ratio is computed here against every ground the
   site actually paints. */
function relLum(hex) {
  const h = hex.replace("#", "");
  const [r, g, b] = [0, 2, 4].map(i => {
    const c = parseInt(h.slice(i, i + 2), 16) / 255;
    return c <= 0.04045 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4);
  });
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}
function contrast(a, b) {
  const [x, y] = [relLum(a), relLum(b)];
  return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05);
}

const LIGHT_GROUNDS = ["#ffffff", "#fbfaf6", "#f7f6f2", "#f3f0e8", "#efece4", "#e4e1da"];
const DARK_GROUNDS = ["#070b0e", "#0a1115", "#10191d", "#1a2226"];

test("the ink tokens clear 4.5:1 on every ground the site paints", () => {
  const cp = SHEETS.find(s => s.name === "clean-pass.css").css;
  const tokenIn = (scope, name) => {
    const block = cp.slice(cp.indexOf(scope));
    const m = block.slice(0, 400).match(new RegExp(name + ":\\s*(#[0-9a-f]{6})", "i"));
    assert.ok(m, `${name} is not defined in ${scope}`);
    return m[1];
  };

  const lightMuted = tokenIn('html:not([data-theme="dark"]) body', "--il-muted-ink");
  const lightGold = tokenIn('html:not([data-theme="dark"]) body', "--il-gold-ink");
  const darkMuted = tokenIn(":root {", "--il-muted-ink");

  for (const ground of LIGHT_GROUNDS) {
    for (const [name, hex] of [["muted", lightMuted], ["gold", lightGold]]) {
      const cr = contrast(hex, ground);
      assert.ok(cr >= 4.5, `light ${name} ink ${hex} is ${cr.toFixed(2)}:1 on ${ground}`);
    }
  }
  for (const ground of DARK_GROUNDS) {
    const cr = contrast(darkMuted, ground);
    assert.ok(cr >= 4.5, `dark muted ink ${darkMuted} is ${cr.toFixed(2)}:1 on ${ground}`);
  }

  assert.match(
    cp,
    /html:not\(\[data-theme="dark"\]\) body\s*\{[^}]*--il-gold-ink/,
    "the light values must be scoped to light mode"
  );
});

// Verified off rendered pixels: near-white on cream at 1.02:1.
test("the footer does not paint near-white on a light ground", () => {
  const cp = SHEETS.find(s => s.name === "clean-pass.css").css;
  for (const needle of ["footer a", ".f-logo", ".f-copy"]) {
    assert.ok(cp.includes(needle), `clean-pass.css no longer themes ${needle}`);
  }
  assert.match(cp, /\.f-copy[\s\S]{0,300}?--il-muted-ink/, "the footer copy must use the measured muted ink");
});

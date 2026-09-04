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
test("light mode has ink tokens that clear 4.5:1", () => {
  const cp = SHEETS.find(s => s.name === "clean-pass.css").css;
  assert.match(cp, /--il-gold-ink:\s*#8a6216/i, "the light gold ink was solved for 4.56:1 at worst");
  assert.match(cp, /--il-muted-ink:\s*#5f6866/i, "the light muted ink was solved for 4.79:1 at worst");
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

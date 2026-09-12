// Up is green, down is red, and it is the tile's own direction that decides.
//
// clean-pass.css declares the colour as a bare descendant selector - `.is-up i`
// / `.is-dn i` - and home-member.js puts `is-up`/`is-dn` on the page root,
// derived from the S&P. Every <i> on the dashboard therefore matched the root's
// rule as well as its own tile's, at identical specificity, and source order
// handed every one of them to `.is-dn i`. With the S&P down, the whole
// dashboard rendered red: Nasdaq up 0.4% was red, Volatility up was red over a
// green sparkline. The numbers were not wrong, but every colour was.
//
// The fix lives in the premium layer, scoped to the tile that owns the number.
// This test holds the shape of it: a direction rule that is not anchored to a
// tile is the bug coming back.
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");
const css = fs.readFileSync(path.join(ROOT, "public", "research-premium.css"), "utf8");

// Selectors only — comments in this file discuss `.is-up i` in prose.
const selectorsOf = (text) => text
  .replace(/\/\*[\s\S]*?\*\//g, "")
  .split("}")
  .map(b => b.split("{")[0].trim())
  .filter(Boolean);

const TILES = ["ihm-index", "ihm-pop", "ihm-sector", "ihm-fav-q", "ihl-sector", "ihm-quote", "ihm-spark", "ihl-change"];

test("no direction colour rule is left unanchored to the element that owns the number", () => {
  for (const sel of selectorsOf(css)) {
    for (const part of sel.split(",").map(s => s.trim())) {
      if (!/\.is-(up|dn)\b/.test(part)) continue;
      // A rule that only says "something up, somewhere inside" will also match
      // every number inside a root that carries the market's direction.
      const anchored = TILES.some(t => part.includes("." + t)) || part.includes(":not(.is-up)");
      assert.ok(anchored,
        `"${part}" colours by direction without naming the tile, so it will also `
        + `colour every number inside #il-home-member.is-dn — which is the original bug`);
    }
  }
});

test("both directions are declared, and they are not the same colour", () => {
  const up = css.match(/\.ihm-index\.is-up i[^{]*\{([^}]*)\}/);
  const dn = css.match(/\.ihm-index\.is-dn i[^{]*\{([^}]*)\}/);
  assert.ok(up, "no up rule for the index tiles");
  assert.ok(dn, "no down rule for the index tiles");
  assert.notEqual(up[1].trim(), dn[1].trim(), "up and down resolve to the same declaration");
  assert.match(up[1], /--rp-green/);
  assert.match(dn[1], /--rp-red/);
});

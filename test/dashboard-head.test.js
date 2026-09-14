"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");
const read = rel => fs.readFileSync(path.join(ROOT, rel), "utf8");
const rp = () => read("public/research-premium.css");

// surface.css still carries the flex-era rule that gave .ihm-search order:3 so
// it would drop onto its own row below 1500px. The head is a grid now: order
// survives, flex-basis does not, so the search took the third column and
// "Open workspace" was left in the middle of the 400px column meant for the
// search — 13px of bare text with 380px of space around it.
test("the dashboard head places all three of its parts", () => {
  const css = rp();
  for (const [sel, order] of [[".ihm-head-id", 1], [".ihm-search", 2], [".ihm-head-link", 3]]) {
    const re = new RegExp(sel.replace(".", "\\.") + "\\s*\\{[^}]*order:\\s*" + order + "\\s*!important", "s");
    assert.match(css, re, `${sel} has no explicit order, so the grid places it by luck`);
  }
});

test("the workspace link is shaped like a control, not left as bare text", () => {
  const css = rp();
  const rule = css.match(/\.ihm-head-link \{[^}]*\}/s);
  assert.ok(rule, ".ihm-head-link lost its rule");
  assert.match(rule[0], /border:\s*1px solid/, "no border: it reads as text, not something to press");
  assert.match(rule[0], /padding:/, "no padding: it has no hit area");
});

// The note names the three plotted indexes, which is worth saying. It was only
// clipped below 1100px, so at 1280 and 1440 it ran out of its column and
// printed over the timeframe buttons.
test("the market note is clipped at every width, not only on narrow screens", () => {
  const css = rp();
  // strip every media block, then look for the rule
  const unconditional = css.replace(/@media[^{]*\{(?:[^{}]*\{[^}]*\})*[^{}]*\}/gs, "");
  assert.match(
    unconditional,
    /\.ihm-market-panel \.ihm-panel-note \{[^}]*text-overflow:\s*ellipsis/s,
    "the note can still overflow its column on a desktop window"
  );
});

// 5,514.97 sitting above an axis that reads 0% to 16% looks like a value off
// that axis. The label has always been in the markup; a compact pass hid it.
test("the S&P price says what it is", () => {
  assert.doesNotMatch(rp(), /\.ihm-quote-label \{[^}]*display:\s*none/s, "the price is unlabelled again");
  assert.match(read("index.html"), /class="ihm-quote-label">S&amp;P 500 · today</, "the label markup is gone");
});

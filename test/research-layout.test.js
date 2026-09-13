"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");
const read = rel => fs.readFileSync(path.join(ROOT, rel), "utf8");

// Measured at 1440x900 on a loaded AAPL: the workspace shell was 617px tall
// around 155px of content, which put the chart 1393px down the page. The rule
// that did it is right for an empty tool page and wrong the moment a company
// is loaded.
test("the workspace shell only fills the viewport while the page is empty", () => {
  const css = read("public/research-premium.css");
  const rule = css.match(/#view-tool \.app-content-scroll,\s*\n#view-tool \.il-tool-shell \{[^}]*\}/);
  assert.ok(rule, "the sparse-page rule is gone; check what replaced it");
  assert.match(rule[0], /min-height:\s*calc\(100vh/, "the sparse-page rule no longer sets a viewport height");
  assert.match(
    css,
    /#view-tool\.has-stock \.il-tool-shell[\s\S]{0,160}min-height:\s*0\s*!important/,
    "nothing releases the shell's height once a company is loaded"
  );
});

// The declutter pass narrowed the strip to four columns but left five things
// to lay out - four data cells and the freshness button - so the button
// wrapped onto a second row and read as a stray band under the ticker line.
test("the ticker strip has a column for everything it puts on the row", () => {
  const css = read("public/product-system.css");
  const cols = css.match(/\.il-shell-ticker\{grid-template-columns:([^}]+)\}/);
  assert.ok(cols, "the ticker strip's columns are gone");
  // Count track definitions, expanding repeat(): minmax() nests parens, so
  // this walks the string rather than trusting a regex to find the right ")".
  const columns = (function countTracks(spec) {
    let depth = 0, token = "", total = 0;
    const flush = () => {
      const t = token.trim();
      token = "";
      if (!t) return;
      const rep = t.match(/^repeat\(\s*(\d+)\s*,([\s\S]*)\)$/);
      total += rep ? Number(rep[1]) * countTracks(rep[2]) : 1;
    };
    for (const ch of spec) {
      if (ch === "(") depth++;
      if (ch === ")") depth--;
      if (/\s/.test(ch) && depth === 0) { flush(); continue; }
      token += ch;
    }
    flush();
    return total;
  })(cols[1]);

  const shell = read("public/product-system.js");
  const strip = shell.match(/<div class="il-shell-ticker">([\s\S]*?)<\/div>\s*<div class="il-shell-preview/);
  assert.ok(strip, "the ticker strip markup moved");
  const cells = (strip[1].match(/<div>/g) || []).length;
  const buttons = (strip[1].match(/<button/g) || []).length;

  const hidden = css.match(/\.il-shell-ticker>div:nth-child\(n\+(\d+)\)\{display:none\}/);
  const shownCells = hidden ? Math.min(cells, Number(hidden[1]) - 1) : cells;

  assert.equal(
    columns, shownCells + buttons,
    `${columns} columns for ${shownCells} cells + ${buttons} button(s); the overflow wraps onto a second row`
  );
});

// Three search boxes, and the one inside the tool someone is actually using
// was the one that could not take a company name.
test("the workspace search is the same search as everywhere else", () => {
  assert.match(
    read("public/product-system.js"),
    /class="il-shell-search"><input[^>]*\bdata-ticker-search\b/,
    "the workspace search is not wired to the site's search behaviour"
  );
});

// A chart labelled 1Y that opens on three months looks broken. It is not - the
// opening view is sized so a candle is legible - but only the chart knows how
// much of the series that turned out to be, so it has to say.
test("the chart publishes how much of the range it put on screen", () => {
  const engine = read("public/chart-engine.js");
  assert.match(engine, /dataset\.ilVisibleBars\s*=/, "the chart no longer reports its opening window");
  assert.match(engine, /dataset\.ilTotalBars\s*=/, "the chart no longer reports the series length");
  assert.match(engine, /il:chart-view/, "nothing tells the page the view settled");

  const app = read("public/app-legacy.js");
  assert.match(app, /ilVisibleBars/, "the caption does not read the opening window");
  assert.match(app, /il:chart-view/, "the caption is never refreshed once the chart lays out");
  assert.match(app, /Showing the last \$\{shown\} of \$\{total\} sessions/, "the caption no longer states the numbers");
});

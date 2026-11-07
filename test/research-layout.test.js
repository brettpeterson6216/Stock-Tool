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

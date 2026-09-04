"use strict";

/* ═══════════════════════════════════════════════════════════════════════════
   The market chart, and the width the page is allowed to use.

   Three complaints produced this file, and each one is a test here:

     "The graph looks like it only has 15 points or so in a 1 month chart."
       The endpoint asked Yahoo for interval=1d&range=1mo and then kept the
       last 22 closes. Twenty-two points over a month is a sketch, not a
       chart. It now walks a ladder of resolutions and takes the first one
       that clears a real point count.

     "we can overlap multiple index charts into the same graph and make them
      traceable like trading view charts are."
       Several series on one set of axes only means anything if they share a
       scale, so every series is normalised to percent change and aligned on
       a shared time axis rather than by array position.

     "everything is condensed into the middle ... on a wide monitor only half
      the screen is being utilized."
       The dashboard was capped at 1120px - 44% of a 2560px monitor - and the
       header ran the full width regardless, so the logo and the first
       heading disagreed by 400px. Both now share one content column.
   ═══════════════════════════════════════════════════════════════════════════ */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");
const read = rel => fs.readFileSync(path.join(ROOT, rel), "utf8");

const api = read("routes/market-data.js");
const chart = read("public/index-chart.js");
const css = read("public/clean-pass.css");
const html = read("index.html");

test("the index series is fetched at a resolution worth plotting", () => {
  assert.match(api, /SERIES_LADDER\s*=\s*\[/, "the resolution ladder is gone");

  const block = api.slice(api.indexOf("SERIES_LADDER"), api.indexOf("SERIES_LADDER") + 400);
  const rungs = [...block.matchAll(/interval:\s*"([^"]+)".*?min:\s*(\d+)/g)]
    .map(m => ({ interval: m[1], min: Number(m[2]) }));

  assert.ok(rungs.length >= 2, "a ladder with one rung is not a ladder");
  assert.notEqual(rungs[0].interval, "1d", "the first rung must be intraday, not daily bars");
  assert.ok(
    rungs[0].min >= 60,
    `the first rung accepts ${rungs[0].min} points; a month of them needs at least 60`
  );

  // Nothing may re-truncate the series after the ladder has earned it. The
  // old code did exactly this with closes.slice(-22).
  assert.doesNotMatch(api, /closes\.slice\(-2\d\)/, "the series is being truncated back down again");
});

test("the payload carries what the chart needs to draw a real time axis", () => {
  for (const key of ["indexes", "stamps", "interval", "points"]) {
    assert.match(api, new RegExp("\\b" + key + "\\b"), `the response no longer exposes ${key}`);
  }
});

test("series are compared as percent change, not raw levels", () => {
  // The Dow sits near 41,000 and the S&P near 5,800. Plotted raw, two of the
  // three lines are flat against an edge.
  assert.match(chart, /\(\(c - base\) \/ base\) \* 100/, "the normalisation to percent is gone");
});

test("series are aligned by timestamp, not by array position", () => {
  // A holiday or a halt in one index is not a gap in another; lining them up
  // by index slides one series against the others by however many bars they
  // differ.
  assert.match(chart, /at:\s*s\.stamps\[i\]/, "points no longer carry their own timestamp");
  assert.match(chart, /frame\.lo \+ \(\(viewX - PAD_L\) \/ plotW\) \* frame\.span/,
    "the crosshair no longer maps x back to a time");
});

test("nothing is drawn inside the stretched SVG that a stretch would ruin", () => {
  // preserveAspectRatio="none" scales x and y by different factors. Text
  // drawn in it is distorted and runs past the viewBox edge - that is what
  // clipped "+9.13%" to "+9.13:". Circles become ellipses for the same
  // reason. Text lives in HTML now, and the dots are round line caps whose
  // size comes from a non-scaling stroke.
  assert.match(chart, /preserveAspectRatio: "none"/, "the chart no longer fills its container");
  assert.doesNotMatch(chart, /el\("text"/, "text is being drawn inside the stretched SVG again");
  assert.doesNotMatch(chart, /el\("circle"/, "a circle in a stretched SVG renders as an ellipse");
  assert.match(chart, /axis\.className = "ilx-axis"/, "the y-axis is no longer HTML");

  for (const cls of ["ilx-line", "ilx-grid", "ilx-zero", "ilx-cross", "ilx-dot-halo"]) {
    const rule = css.slice(css.indexOf("." + cls + ",") >= 0 ? css.indexOf("." + cls + ",") : css.indexOf("." + cls + " {"));
    assert.ok(rule, `.${cls} has no rule`);
    assert.match(rule.slice(0, 400), /vector-effect: non-scaling-stroke/,
      `.${cls} would be stroked unevenly by the aspect stretch`);
  }
});

test("the chart states its own resolution rather than implying one", () => {
  assert.match(read("public/home-member.js"), /" " \+ res \+ " points"/,
    "the chart no longer tells the reader what it is made of");
});

test("the chart script is loaded by the page that draws it", () => {
  assert.match(html, /src="\/index-chart\.js\?v=/, "index-chart.js is not on the page");
});

test("the dashboard and the header share one content column", () => {
  assert.match(css, /max-width: min\(1800px, 100%\)/,
    "the dashboard is capped somewhere other than the shared column width");
  assert.doesNotMatch(css, /max-width:\s*1120px !important/,
    "the old 1120px cap is back");

  // The header stays full-bleed - its background spans the viewport - but its
  // contents stop where the page's contents stop.
  assert.match(css, /padding: 0 calc\(max\(0px, \(100% - 1800px\) \/ 2\) \+ clamp\(16px, 3vw, 56px\)\)/,
    "the header no longer shares the content column, so the logo and the page heading disagree");

  const gutters = [...css.matchAll(/clamp\(16px, 3vw, 56px\)/g)].length;
  assert.ok(gutters >= 2, "the header and the page are using different gutters");
});

test("the header's fixed tracks still fit the bar at laptop widths", () => {
  // 200 + tabs + 236 + gaps came to 984px inside a 963px box at 1024, which
  // hung the account chip 22px past the right gutter.
  const m = css.match(/@media \(max-width: 1200px\) \{[\s\S]*?grid-template-columns: (\d+)px/);
  assert.ok(m, "the intermediate header breakpoint is gone");
  assert.ok(Number(m[1]) < 200, "the logo track is not narrowed at laptop widths");
});

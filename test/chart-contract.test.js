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

test("the interval is a property of the window, not a number to maximise", () => {
  // The first pass asked for a month of hourly bars on the theory that more
  // points is more chart. Measured on the live feed, the S&P changes
  // direction 81 times over that month at hourly resolution and 12 times at
  // daily, across the same 2.4 percentage points - identical shape, seven
  // times the zigzag. A one-month view is drawn from daily closes.
  assert.match(api, /const WINDOWS = \{/, "the window table is gone");
  const table = api.slice(api.indexOf("const WINDOWS = {"), api.indexOf("const DEFAULT_WINDOW"));

  for (const key of ["1D", "1W", "1M", "3M", "1Y"]) {
    assert.ok(table.includes(`"${key}":`), `the ${key} window is missing`);
  }

  const first = key => {
    const row = table.slice(table.indexOf(`"${key}":`));
    return (row.match(/interval: "([^"]+)"/) || [])[1];
  };
  // Rather than pin exact strings - the right density is a judgement that has
  // moved twice already - assert the invariant: the bars get coarser as the
  // window gets longer, and a one-day chart is never drawn from daily bars.
  const seconds = iv => {
    const n = parseFloat(iv);
    return iv.endsWith("m") ? n * 60 : iv.endsWith("h") ? n * 3600 : iv.endsWith("wk") ? n * 604800 : n * 86400;
  };
  const order = ["1D", "1W", "1M", "3M", "1Y"].map(first);
  assert.ok(seconds(order[0]) < 3600, "a one-day chart must not be drawn from hourly or daily bars");
  for (let i = 1; i < order.length; i += 1) {
    assert.ok(
      seconds(order[i]) >= seconds(order[i - 1]),
      `the bars get finer going from a shorter window to a longer one (${order[i - 1]} then ${order[i]})`
    );
  }

  // Each window keeps a ladder, because Yahoo does not guarantee every
  // interval for every symbol - but the first rung is the conventional one.
  assert.ok((table.match(/min:/g) || []).length >= 10, "the fallback rungs are gone");
  assert.doesNotMatch(api, /closes\.slice\(-2\d\)/, "the series is being truncated after the ladder earned it");
});


test("the series palette is validated, and light mode actually gets it", () => {
  // The previous set failed: green against blue measured a colour-vision
  // Delta E of 4.8 against a target of 8, and in light mode green against gold
  // measured 13.5 against a hard floor of 15.
  for (const hex of ["#3987e5", "#d1a03f", "#5fc4ad"]) {
    assert.ok(css.includes(hex), `the validated dark series colour ${hex} is gone`);
  }
  for (const hex of ["#2a78d6", "#a06a10", "#0f6b52"]) {
    assert.ok(css.includes(hex), `the validated light series colour ${hex} is gone`);
  }
  assert.doesNotMatch(css, /--ilx-a: #4ec879/, "the failing green is back");

  /* And the light override has to out-weigh the base rule. Written with four
     :not(#id) against the base rule's five it never applied, and light mode
     silently kept the dark palette - ID count is compared before anything
     else, so !important cannot rescue it. */
  const light = css.slice(css.indexOf('.ihm-chart {\n  --ilx-a: #2a78d6') - 400);
  const sel = light.slice(0, light.indexOf(".ihm-chart"));
  const baseIds = 6;
  const lightIds = (sel.match(/#cp\d/g) || []).length;
  assert.ok(
    lightIds >= baseIds,
    `the light palette carries ${lightIds} IDs against the base rule's ${baseIds}, so it never applies`
  );
});

test("the dashboard chart runs on the same engine as the rest of the site", () => {
  /* This was a hand-rolled SVG renderer until it turned out Lightweight
     Charts was already vendored and already driving the Analysis page - so
     the dashboard was maintaining a second, worse chart engine for no
     additional bytes. It is an adapter now, not a plotting library. */
  assert.match(chart, /window\.LightweightCharts/, "the dashboard chart is off the shared engine again");
  assert.match(chart, /LWC\.createChart\(plot,/, "no chart is being created");
  assert.match(chart, /LWC\.LineSeries/, "the index lines are gone");
  assert.ok(fs.existsSync(path.join(ROOT, "public/vendor/lightweight-charts.standalone.production.js")),
    "the vendored library is missing, and nothing else draws this chart");

  // Three indexes can only share an axis in percentage terms: the Dow near
  // 41,000 and the S&P near 5,800 have no common absolute scale.
  assert.match(chart, /mode: LWC\.PriceScaleMode\.Percentage/,
    "the price scale is back on absolute levels, which flattens two of three lines");

  // A dashboard chart that swallows the wheel traps the reader mid-page.
  assert.match(chart, /handleScroll: \{ mouseWheel: false/, "the chart is eating the page's scroll");
  assert.match(chart, /handleScale: \{ mouseWheel: false/, "the chart is eating the page's scroll");

  // A null close is not a price, and Number(null) is 0, which is finite.
  assert.match(chart, /c <= 0/, "a bar that never printed can plot as a -100% cliff again");
  // Lightweight Charts drops a whole series given out-of-order timestamps.
  assert.match(chart, /at <= lastAt/, "timestamps are no longer forced ascending and unique");

  // One chart per host, or a timeframe click stacks canvases.
  assert.match(chart, /host\.ilxChart\.remove\(\)/, "the previous chart is not torn down");

  // The renderer changed; the seam did not.
  assert.match(chart, /window\.ilRenderIndexChart = function \(host, indexes\)/,
    "the public shape changed, so home-member.js and the timeframe control break");
});

test("the TradingView attribution is present and not dimmed away", () => {
  /* Lightweight Charts is Apache-2.0 and its terms ask for the NOTICE
     attribution plus a link to tradingview.com "in a prominent place". The
     library injects the link itself; CSS was scaling it to 62% at 28% opacity
     on the landing page and 35% on the analysis chart. */
  assert.match(chart, /attributionLogo: true/, "the attribution logo is switched off");

  const engineCss = read("public/chart-engine.css");
  const dimming = engineCss.match(/a\[href\*="tradingview"\][^}]*\}/g) || [];
  for (const rule of dimming) {
    const op = rule.match(/opacity:\s*([\d.]+)/);
    assert.ok(!op || Number(op[1]) === 1, `the attribution is dimmed to ${op && op[1]}: ${rule}`);
    assert.doesNotMatch(rule, /transform:\s*scale/, `the attribution is scaled down: ${rule}`);
  }

  // And the NOTICE text has to appear somewhere a reader can reach.
  const notice = read("public/data-sources.html");
  assert.match(notice, /Lightweight Charts/, "the NOTICE attribution is nowhere on the site");
  assert.match(notice, /TradingView/, "the NOTICE attribution names no author");
  assert.match(notice, /https:\/\/www\.tradingview\.com\//, "the required link is missing");
  assert.match(html, /data-sources#charting-library/, "nothing links to the licence notice");
});

test("the reader can choose the window, and it is remembered", () => {
  assert.match(html, /class="ihm-tfs"/, "the timeframe control is gone from the market panel");
  for (const key of ["1D", "1W", "1M", "3M", "1Y"]) {
    assert.match(html, new RegExp('data-window="' + key + '"'), `the ${key} button is missing`);
  }
  const member = read("public/home-member.js");
  assert.match(member, /landing-summary\?window=/, "the window is not being asked for");
  assert.match(member, /il-mkt-window/, "the choice is not remembered between visits");
  // A slow answer for an abandoned window must not overwrite the current one.
  assert.match(member, /if \(asked !== currentWindow\) return;/, "a stale response can still land");
});

test("the payload carries what the chart needs to draw a real time axis", () => {
  for (const key of ["indexes", "stamps", "interval", "points"]) {
    assert.match(api, new RegExp("\\b" + key + "\\b"), `the response no longer exposes ${key}`);
  }
});



test("a bar that never printed is not treated as a price of zero", () => {
  // Number(null) is 0 and 0 is finite, so a null close survives a naive
  // isFinite filter as a price of zero, normalises to -100%, and pulls the
  // whole chart flat against the floor.
  assert.match(api, /rawCloses\[i\] == null \|\| rawStamps\[i\] == null/,
    "the server converts the null before it checks for one");
  assert.match(api, /close <= 0/, "a close of zero is still accepted as a price");
  assert.match(chart, /c <= 0/, "the chart still plots a zero close");
  assert.match(read("public/home-member.js"), /if \(v == null\) return;/,
    "the sparkline data still turns nulls into zeroes");
});

test("today's change is not measured from the edge of the chart range", () => {
  // chartPreviousClose is the close before the RANGE. Over a one-month range
  // it made every sector chip a monthly figure under a heading saying today:
  // Industrials read -6.08% on a day Yahoo had XLI at +0.30%.
  // Scoped to the landing-summary handler: /api/quote legitimately synthesises
  // a chartPreviousClose of its own for a one-day range, where it is correct.
  const summary = api.slice(api.indexOf("SERIES_LADDER"));
  assert.doesNotMatch(summary, /meta\.chartPreviousClose/, "chartPreviousClose is being used as a previous close again");
  assert.match(summary, /function priorSessionClose\(points\)/, "there is no fallback for a missing previousClose");
  assert.match(summary, /America\/New_York/, "the session boundary is being taken at UTC midnight, which is mid-session");
});


test("the chart states its own resolution rather than implying one", () => {
  assert.match(read("public/home-member.js"), /daily closes|weekly closes/,
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

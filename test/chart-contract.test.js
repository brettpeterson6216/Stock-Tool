"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const html = fs.readFileSync(path.join(__dirname, "..", "index.html"), "utf8");
const legacyCss = fs.readFileSync(path.join(__dirname, "..", "public", "legacy-app.css"), "utf8");
const productJs = fs.readFileSync(path.join(__dirname, "..", "public", "product-system.js"), "utf8");
const productCss = fs.readFileSync(path.join(__dirname, "..", "public", "product-system.css"), "utf8");
const htmlAndLegacyCss = `${html}\n${legacyCss}`;

test("chart rebuilds keep prices and timestamps on one aligned series", () => {
  assert.match(html, /function rebuildPriceChart\(\)/);
  assert.match(html, /S\.data=aligned\.result;/);
  assert.match(html, /buildPriceChart\(S\.data,aligned\.closes,aligned\.timestamps\)/);
  assert.doesNotMatch(html, /buildPriceChart\(S\.data,\s*S\.data\.indicators\.quote\[0\]\.close\.filter/);
});

test("price charts expose dependable zoom controls and mobile gestures", () => {
  assert.match(html, /function chartZoomOptions\(\)/);
  assert.match(html, /chartjs-plugin-zoom\.min\.js\?v=2\.2\.0/);
  assert.match(html, /pinch:\{enabled:true\}/);
  assert.match(html, /pan:\{enabled:true,mode:'x',threshold:8\}/);
  assert.match(html, /onclick="zoomPriceChart\(1\.25\)"/);
  assert.match(html, /Zoom price chart out or load older history/);
  assert.match(html, /onclick="resetPriceZoom\(\)"/);
  assert.match(html, /onclick="zoomExpandedChart\(1\.25\)"/);
  assert.match(html, /async function loadMorePriceHistory\(\)/);
  assert.match(html, /CHART_RANGE_ORDER=\['1d','5d','1mo','3mo','6mo','1y','2y','5y','max'\]/);
  assert.match(html, /minRange:4/);
  assert.match(htmlAndLegacyCss, /#price-chart\{touch-action:none\}/);
});

test("mobile chart headers reserve room for controls and explain unavailable indicators", () => {
  assert.match(html, /function syncIndicatorAvailability\(barCount\)/);
  assert.match(html, /50D Avg.*bars:50|ma50:\s*\{\s*bars:50/);
  assert.match(html, /ma200:\{\s*bars:200/);
  assert.match(html, /S\.inds\.ma50&&vc\.length>=INDICATOR_REQUIREMENTS\.ma50\.bars/);
  assert.match(htmlAndLegacyCss, /\.g2\{grid-template-columns:1fr!important\}/);
  assert.match(htmlAndLegacyCss, /\.chart-wrap \.chart-header \.ind-row,\.chart-wrap \.chart-header \.range-pills\{display:none!important\}/);
  assert.match(htmlAndLegacyCss, /\.chart-exp-btn\{\s*position:static/);
  assert.doesNotMatch(html, /<div class="chart-wrap">\s*<button class="chart-exp-btn"/);
});

test("invalid ticker errors are understandable and hide provider details", () => {
  assert.match(html, /Could not find "\$\{ticker\}"\. Check the ticker symbol and try again/);
  assert.match(html, /r\.status === 404 \? 'TICKER_NOT_FOUND'/);
  assert.doesNotMatch(html, /Could not load "\$\{ticker\}": \$\{e\.message\}/);
});

test("mobile tool pages keep the brand and theme control visible", () => {
  assert.match(htmlAndLegacyCss, /#main-nav\[data-view="tool"\] \.theme-toggle\{display:flex!important/);
  assert.doesNotMatch(htmlAndLegacyCss, /#main-nav\[data-view="tool"\] \.nav-logo\{[^}]*(font-size|gap|padding-right)/);
  assert.doesNotMatch(htmlAndLegacyCss, /#main-nav\[data-view="tool"\] \.theme-toggle\{[^}]*(scale|margin-right)/);
  assert.doesNotMatch(htmlAndLegacyCss, /#main-nav\[data-view="tool"\] \.nav-logo>span,\s*#main-nav\[data-view="tool"\] #nav-ticker-bar,\s*#main-nav\[data-view="tool"\] \.theme-toggle\{display:none!important\}/);
});

test("the fixed header covers the top device safe area", () => {
  assert.match(htmlAndLegacyCss, /height:calc\(56px \+ env\(safe-area-inset-top, 0px\)\)/);
  assert.match(htmlAndLegacyCss, /#view-home\{padding-top:calc\(56px \+ env\(safe-area-inset-top, 0px\)\)\}/);
  assert.match(htmlAndLegacyCss, /#view-tool \{[^}]*padding-top:calc\(56px \+ env\(safe-area-inset-top, 0px\)\)/);
});

test("mobile browser chrome follows the selected site theme", () => {
  assert.match(html, /dark\?'#0e1114':'#f9f8f5'/);
  assert.match(html, /dark\?'black-translucent':'default'/);
  assert.match(html, /<meta name="apple-mobile-web-app-status-bar-style" content="default">/);
  assert.match(html, /function updateThemeControl\(\) \{\s*window\.syncBrowserChrome\?\.\(\);/);
});

test("learning module stays in Learn and produces a saved thesis", () => {
  assert.match(html, /id="edu-workshop"/);
  assert.match(productJs, /The company loads here\. You stay inside the module\./);
  assert.match(productJs, /Use Apple example/);
  assert.match(productJs, /Save thesis and complete/);
  assert.match(productJs, /\/api\/workspace\/theses\/\$\{encodeURIComponent\(learnState\.ticker\)\}/);
  assert.doesNotMatch(html, /<div class="edu-side-title">Module exercise<\/div>/);
});

test("product spine presents one reviewable decision workflow", () => {
  assert.match(productJs, /const DECISION_PATH = \[/);
  assert.match(productJs, /label: "Search".*section: "analyze"/s);
  assert.match(productJs, /label: "Evidence".*section: "financials"/s);
  assert.match(productJs, /label: "Model".*section: "projection"/s);
  assert.match(productJs, /label: "Thesis".*section: "education"/s);
  assert.match(productJs, /label: "Review".*section: "workspace"/s);
  assert.match(productJs, /Turn a ticker into a reviewable investment record\./);
  assert.match(productJs, /window\.navGoTo\(section\)/);
});

test("primary navigation avoids duplicate tool destinations", () => {
  assert.doesNotMatch(html, /<span>Chart<\/span>/);
  assert.doesNotMatch(html, /Scenario Builder/);
  assert.match(html, /<span class="sb-item-label">Analyze<\/span>/);
  assert.match(html, /Start with a company/);
  assert.match(html, /Load a ticker, read the evidence, model the range, then save a reviewable thesis\./);
  assert.match(html, /Popular starting points/);
});

test("quote results make data trust visible before decisions", () => {
  assert.match(productJs, /function renderTrust\(result\)/);
  assert.match(productJs, /impliedLensProvenance/);
  assert.match(productJs, /Evidence quality/);
  assert.match(productJs, /Latest available context/);
  assert.match(productJs, /retrievedAt/);
  assert.match(productJs, /latestTimestamp/);
  assert.match(productJs, /trustField\("Range", range\)/);
  assert.match(productJs, /trustField\("Interval", interval\)/);
  assert.match(productJs, /Use this as latest available context, not a real-time trading signal/);
  assert.match(productJs, /href="\/data-sources"/);
  assert.match(productJs, /escapeHtml/);
  assert.match(productCss, /\.il-trust-panel\{/);
  assert.match(productCss, /\.il-trust-grid\{display:grid;grid-template-columns:repeat\(3,minmax\(0,1fr\)\)/);
  assert.match(productCss, /\.il-trust-note\{/);
});

test("charts and trade symbols use vivid market colors without repainting the site", () => {
  assert.match(legacyCss, /--brand-gold:#76521D/);
  assert.match(legacyCss, /--brand-gold:#B88937/);
  assert.doesNotMatch(legacyCss, /--brand-gold:#00A85A/);
  assert.doesNotMatch(legacyCss, /--brand-gold:#CCFF00/);
  assert.match(legacyCss, /--chart-price:#00A85A/);
  assert.match(legacyCss, /--chart-price:#CCFF00/);
  assert.match(legacyCss, /--chart-positive:#00C805/);
  assert.match(legacyCss, /--chart-negative:#EB5D2A/);
  assert.match(legacyCss, /--chart-negative:#FF6A3D/);
  assert.match(legacyCss, /--chart-ma50:#148BFF/);
  assert.match(legacyCss, /--chart-ma200:#8B5CF6/);
  assert.match(legacyCss, /\.price-chg\.up\{background:color-mix\(in srgb,var\(--chart-positive\) 14%,transparent\)!important\}/);
  assert.match(html, /const COLORS = \['#00A85A','#148BFF','#8B5CF6','#FFB020'\]/);
  assert.match(html, /price:get\('--chart-price','#00A85A'\)/);
  assert.match(html, /borderWidth:2\.4/);
  assert.match(html, /borderWidth:2\.7/);
  assert.match(html, /stop-color="var\(--chart-price\)"/);
});

test("analyze and projection share a research workspace shell", () => {
  assert.match(productJs, /function installToolShells\(\)/);
  assert.match(productJs, /Analyze Workspace/);
  assert.match(productJs, /Projection Builder/);
  assert.match(productJs, /data-il-current-ticker/);
  assert.match(productJs, /Sources and Freshness/);
  assert.match(productJs, /function openNotesPanel\(\)/);
  assert.match(productJs, /il-notes-/);
  assert.match(productJs, /function installResearchTrail\(\)/);
  assert.match(productJs, /Price action/);
  assert.match(productJs, /Thesis notes/);
  assert.match(productJs, /function syncToolUrl\(section, mode\)/);
  assert.match(productCss, /\.il-tool-shell\{/);
  assert.match(productCss, /\.il-shell-ticker\{/);
  assert.match(productCss, /\.il-research-drawer/);
  assert.match(productCss, /\.il-notes-panel/);
});

test("projection builder exposes evidence, checklist, templates, sensitivity, and explanation", () => {
  assert.match(productJs, /function renderProjectionWorkspace/);
  assert.match(productJs, /Evidence Panel/);
  assert.match(productJs, /Assumption Review Gate/);
  assert.match(productJs, /il-proj-eps-override/);
  assert.match(productJs, /Starting EPS override/);
  assert.match(productJs, /Templates are starting points, not recommendations/);
  assert.match(productJs, /Calculate Projection/);
  assert.match(productJs, /Probability-weighted value/);
  assert.match(productJs, /sensitivityHtml/);
  assert.match(productJs, /What drove the result/);
  assert.match(productCss, /\.il-projection-builder/);
  assert.match(productCss, /\.il-assumption-checklist/);
  assert.match(productCss, /\.il-sensitivity-table/);
});

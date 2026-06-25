"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const html = fs.readFileSync(path.join(__dirname, "..", "index.html"), "utf8");
const legacyCss = fs.readFileSync(path.join(__dirname, "..", "public", "legacy-app.css"), "utf8");
const staticCss = fs.readFileSync(path.join(__dirname, "..", "public", "static-polish.css"), "utf8");
const signupHtml = fs.readFileSync(path.join(__dirname, "..", "public", "signup.html"), "utf8");
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
  assert.match(html, /mode:'xy'/);
  assert.match(html, /overScaleMode:'xy'/);
  assert.match(html, /pan:\{enabled:true,mode:'xy',threshold:compact\?3:6\}/);
  assert.match(html, /limits:\{x:\{min:'original',max:'original',minRange:4\},y:\{min:'original',max:'original'\}\}/);
  assert.match(html, /onclick="zoomPriceChart\(1\.25\)"/);
  assert.match(html, /Zoom price chart out or load older history/);
  assert.match(html, /onclick="resetPriceZoom\(\)"/);
  assert.match(html, /onclick="zoomExpandedChart\(1\.25\)"/);
  assert.match(html, /async function loadMorePriceHistory\(\)/);
  assert.match(html, /CHART_RANGE_ORDER=\['1d','5d','1mo','3mo','6mo','1y','2y','5y','max'\]/);
  assert.match(html, /minRange:4/);
  assert.match(htmlAndLegacyCss, /#price-chart\{touch-action:none\}/);
  assert.match(legacyCss, /\.chart-wrap canvas,[\s\S]*\.cex-workspace canvas\{[\s\S]*touch-action:none!important/);
  assert.match(legacyCss, /Pinch\/drag to inspect · expand to annotate/);
  assert.match(legacyCss, /content:'Pinch \+ drag'/);
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
  assert.match(legacyCss, /--chart-price:#16C784/);
  assert.match(legacyCss, /--chart-price:#2EE59D/);
  assert.match(legacyCss, /--chart-positive:#16C784/);
  assert.match(legacyCss, /--chart-negative:#F45B5B/);
  assert.match(legacyCss, /--chart-negative:#FF6B6B/);
  assert.match(legacyCss, /--chart-ma50:#3B82F6/);
  assert.match(legacyCss, /--chart-ma200:#A78BFA/);
  assert.match(legacyCss, /\.price-chg\.up\{background:color-mix\(in srgb,var\(--chart-positive\) 14%,transparent\)!important\}/);
  assert.match(html, /const COLORS = \['#16C784','#3B82F6','#A78BFA','#F5B83D'\]/);
  assert.match(html, /price:get\('--chart-price','#16C784'\)/);
  assert.match(html, /borderWidth:2\.4/);
  assert.match(html, /borderWidth:2\.7/);
  assert.match(html, /stop-color="var\(--chart-price\)"/);
});

test("expanded charts look premium and support seamless annotation", () => {
  assert.match(html, /var _markup = \{tool:'cursor',color:'#16C784'/);
  assert.match(html, /data-markup-color="#16C784"/);
  assert.match(html, /data-markup-color="#3B82F6"/);
  assert.match(html, /data-markup-color="#F45B5B"/);
  assert.match(html, /ctx2\.shadowColor='rgba\(0,0,0,\.22\)'/);
  assert.match(html, /ctx2\.lineWidth=item\.type==='freehand'\?2\.5:3/);
  assert.match(legacyCss, /#chart-expand-modal\{[\s\S]*backdrop-filter:blur\(10px\)/);
  assert.match(legacyCss, /\.cex-box\{[\s\S]*border-radius:22px/);
  assert.match(legacyCss, /\.cex-body\{[\s\S]*radial-gradient\(900px 420px at 78% -10%,rgba\(217,179,94,\.12\),transparent 70%\)/);
  assert.match(legacyCss, /\.cex-tool\{[\s\S]*border-radius:10px/);
  assert.match(legacyCss, /\.cex-color\{[\s\S]*width:24px/);
});

test("homepage defaults to a beginner-friendly landing page before market tools", () => {
  assert.match(html, /id="landing-page"/);
  assert.match(html, /<div class="home-shell" id="market-page" style="display:none;">/);
  assert.match(html, /Find better stock ideas with a process you can follow/);
  assert.match(html, /New user offer: first month \$0\.99/);
  assert.match(html, /Get first month for \$0\.99/);
  assert.match(html, /src="\/landing-product-preview\.png"/);
  assert.match(html, /src="\/landing-workflow-strip\.png"/);
  assert.match(html, /Sample workspace/);
  assert.match(html, /\$0\.99 first month/);
  assert.doesNotMatch(html, /id="landingChartFill"/);
  assert.match(html, /function landingSearch\(\)/);
  assert.match(html, /id="market-page" style="display:none;"/);
  assert.match(html, /function showLandingPage\(\)/);
  assert.match(html, /function showMarketPage\(\)/);
  assert.match(html, /history\.replaceState\(null, '', '\/'\)/);
  assert.match(html, /\/\?view=home&amp;market=1/);
  assert.match(legacyCss, /#market-page \.home-hero,#market-page \.home-feat-strip,#market-page \.home-proof,#market-page \.home-guide-showcase,#market-page #pricing,#market-page \.cta-strip\{display:none!important\}/);
  assert.match(legacyCss, /\.il-landing-preview\.image-preview img\{/);
  assert.match(legacyCss, /Landing hero final composition: one clean headline row above the generated image/);
  assert.match(legacyCss, /\.il-landing-hero\{[\s\S]*flex-direction:column/);
  assert.match(legacyCss, /\.il-landing-copy\{[\s\S]*background:transparent!important/);
  assert.match(legacyCss, /\.il-landing-copy \.il-landing-kicker,[\s\S]*\.il-landing-copy \.il-offer-card\{[\s\S]*display:none!important/);
  assert.match(legacyCss, /white-space:nowrap/);
  assert.match(legacyCss, /object-fit:contain!important/);
  assert.match(legacyCss, /max-height:min\(610px,calc\(100vh - 290px\)\)/);
  assert.doesNotMatch(legacyCss, /height:min\(72vh,760px\)!important/);
  assert.match(legacyCss, /Landing readability \+ premium market finish/);
  assert.match(legacyCss, /html\[data-theme="dark"\] \.il-landing\{/);
  assert.match(legacyCss, /\.il-landing,[\s\S]*html\[data-theme="dark"\] \.il-landing\{[\s\S]*background-color:#FBF2DE!important/);
  assert.match(legacyCss, /\.il-landing-band \.il-landing-kicker,[\s\S]*\.il-landing-pricing \.il-landing-kicker\{[\s\S]*var\(--lens-gold-2\)!important/);
  assert.match(legacyCss, /\.il-landing-band,[\s\S]*\.il-landing-pricing\{[\s\S]*background-color:#0C0E10!important/);
  assert.match(legacyCss, /\.il-workflow-visual\{/);
});

test("premium landing visual system matches the generated product preview direction", () => {
  assert.match(legacyCss, /Premium screenshot visual system/);
  assert.match(legacyCss, /--lens-black:#090A0B/);
  assert.match(legacyCss, /--lens-gold:#D9B35E/);
  assert.match(legacyCss, /\.il-landing\{[\s\S]*#FBF2DE/);
  assert.match(legacyCss, /#view-tool,\.app-shell\{[\s\S]*var\(--lens-black\)/);
  assert.match(legacyCss, /\.app-section,\.chart-wrap,\.metric-card,\.panel-box,\.il-tool-shell/);
  assert.match(legacyCss, /green\/red only for market semantics|market green\/red|--chart-positive:#16C784/);
});

test("premium visual system is applied across app and static pages", () => {
  assert.match(html, /legacy-app\.css\?v=20260625-14/);
  assert.match(html, /product-system\.css\?v=20260625-1/);
  assert.match(signupHtml, /static-polish\.css\?v=20260625-2/);
  assert.match(html, /<a class="btn-nav" id="nav-signup" href="\/signup">Claim \$0\.99<\/a>/);
  assert.match(legacyCss, /Site-wide premium polish/);
  assert.match(legacyCss, /Gold theme harmonization/);
  assert.match(legacyCss, /\.il-landing-preview\{[\s\S]*linear-gradient\(180deg,#F6E3B7,#E9C986\)!important/);
  assert.match(legacyCss, /html\[data-theme="dark"\] \.app-section,[\s\S]*html\[data-theme="dark"\] \.il-learn-preview>div\{[\s\S]*linear-gradient\(180deg,rgba\(31,34,38,.96\),rgba\(14,16,18,.98\)\)!important/);
  assert.match(staticCss, /Static theme harmonization/);
  assert.match(legacyCss, /#market-page \.home-grid,[\s\S]*#market-page \.home-lower\{[\s\S]*gap:16px!important/);
  assert.match(legacyCss, /#market-page \.hc,[\s\S]*#market-page \.hl-report\{[\s\S]*border-radius:16px!important/);
  assert.match(legacyCss, /#market-page \.hc,[\s\S]*#market-page \.hg-market \.mo-bv2-card\{[\s\S]*rgba\(255,250,239,.94\)/);
  assert.match(legacyCss, /html\[data-theme="dark"\] #market-page \.hc,[\s\S]*html\[data-theme="dark"\] #market-page \.hg-market \.mo-bv2-card\{[\s\S]*rgba\(34,37,41,.96\)/);
  assert.match(legacyCss, /#market-page \.mo-tab\.on,[\s\S]*#market-page \.movers-tab\.active\{[\s\S]*linear-gradient\(180deg,var\(--lens-gold-2\),var\(--lens-gold\)\)/);
  assert.match(legacyCss, /\.home-ticker-strip,\s*\.ht-card,\s*\.hc,\s*\.hg-market/s);
  assert.match(legacyCss, /\.pricing-card,\s*\.pricing-compare,\s*\.modal,\s*\.nav-acct-menu/s);
  assert.match(legacyCss, /footer\{[\s\S]*#08090A!important/);
  assert.match(staticCss, /Static premium visual system/);
  assert.match(staticCss, /--sp-black:#090A0B/);
  assert.match(staticCss, /\.auth-card,\s*\.feat,\s*\.guide,\s*\.source-card/s);
  assert.match(staticCss, /\.btn-primary,\s*\.btn\.primary,\s*\.cta a/s);
});

test("gold ripple image is the default backdrop across landing, market, and tools", () => {
  assert.match(legacyCss, /Gold ripple default background/);
  assert.match(legacyCss, /--gold-ripple-bg:url\("\/gold-ripple-background\.jpg"\)/);
  assert.match(legacyCss, /body,[\s\S]*#view-home,[\s\S]*#view-tool,[\s\S]*\.il-landing,[\s\S]*\.home-shell,[\s\S]*\.app-content-scroll,[\s\S]*#market-page/);
  assert.match(legacyCss, /background-image:var\(--gold-ripple-overlay\),var\(--gold-ripple-bg\)!important/);
  assert.match(legacyCss, /background-attachment:fixed!important/);
  assert.match(legacyCss, /background-attachment:scroll!important/);
});

test("tool containers use premium rounded surfaces instead of sharp rectangles", () => {
  assert.match(legacyCss, /Premium tool surface polish/);
  assert.match(legacyCss, /--tool-radius-xl:22px/);
  assert.match(legacyCss, /#view-tool \.acc-body,[\s\S]*#view-tool \.chart-wrap,[\s\S]*#view-tool \.metric-card,[\s\S]*#view-tool \.panel-box/);
  assert.match(legacyCss, /#view-tool \.il-tool-shell,[\s\S]*#view-tool \.il-proj-evidence,[\s\S]*#view-tool \.il-learn-workshop/);
  assert.match(legacyCss, /border-radius:var\(--tool-radius-lg\)!important/);
  assert.match(legacyCss, /box-shadow:var\(--tool-shadow-light\)!important/);
  assert.match(legacyCss, /html\[data-theme="dark"\] #view-tool \.acc-body,[\s\S]*box-shadow:var\(--tool-shadow-dark\)!important/);
  assert.match(legacyCss, /#view-tool \.ticker-input,[\s\S]*#view-tool \.il-learn-nav button\{[\s\S]*border-radius:12px!important/);
  assert.match(legacyCss, /#view-tool \.app-section \.acc-body\{[\s\S]*background:transparent!important/);
});

test("tool guidance is collapsed so tutorials do not block tool use", () => {
  assert.match(productJs, /guide\.className = "il-tool-guide compact"/);
  assert.match(productJs, /class="il-tool-guide-toggle" aria-expanded="false"/);
  assert.match(productJs, /class="il-tool-guide-body" hidden/);
  assert.match(productJs, /panel\.hidden = open/);
  assert.match(productCss, /\.il-tool-guide-toggle\{/);
  assert.match(productCss, /\.il-tool-guide-body\[hidden\]\{display:none!important\}/);
  assert.doesNotMatch(productJs, /guide\.innerHTML = `<div><span>Start here<\/span>/);
});

test("analyze and projection share a research workspace shell", () => {
  assert.match(productJs, /function installToolShells\(\)/);
  assert.match(productJs, /Ticker workspace/);
  assert.match(productJs, /Projection builder/);
  assert.match(productJs, /data-il-current-ticker/);
  assert.match(productJs, /data-il-drawer="sources"/);
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

test("tool pages keep persistent chrome minimal and hide chart controls off chart pages", () => {
  assert.match(html, /id="view-tool" role="main" data-active-section="analyze"/);
  assert.match(html, /setAttribute\('data-active-section', id\)/);
  assert.match(legacyCss, /#view-tool:not\(\[data-active-section="analyze"\]\) #app-chart-toolbar,[\s\S]*#view-tool:not\(\[data-active-section="analyze"\]\) #app-tf-strip\{[\s\S]*display:none!important/);
  assert.match(legacyCss, /#view-tool \.app-section-hdr\{[\s\S]*display:none!important/);
  assert.match(legacyCss, /#view-tool \.tool-welcome,[\s\S]*#view-tool #il-tool-decision-path,[\s\S]*#view-tool \.tool-intro\{[\s\S]*display:none!important/);
  assert.match(productCss, /Product tool declutter/);
  assert.match(productCss, /\.il-shell-ticker>div:nth-child\(n\+5\)\{display:none\}/);
  assert.match(productCss, /\.il-shell-actions button span\{display:none\}/);
  assert.match(productCss, /\.il-guidance\{display:none\}/);
  assert.match(productJs, /Search a ticker/);
  assert.doesNotMatch(productJs, /Sources stay visible/);
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

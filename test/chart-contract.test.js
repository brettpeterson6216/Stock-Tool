"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const indexHtml = fs.readFileSync(path.join(__dirname, "..", "index.html"), "utf8");
const themeBootstrapJs = fs.readFileSync(path.join(__dirname, "..", "public", "theme-bootstrap.js"), "utf8");
const appNavigationJs = fs.readFileSync(path.join(__dirname, "..", "public", "app-navigation.js"), "utf8");
const appLegacyJs = fs.readFileSync(path.join(__dirname, "..", "public", "app-legacy.js"), "utf8");
const shareStudioJs = fs.readFileSync(path.join(__dirname, "..", "public", "share-studio.js"), "utf8");
const ilSystemCss = fs.readFileSync(path.join(__dirname, "..", "public", "il-system.css"), "utf8");
// Contract tests historically inspected index.html when the application code
// was inline. Preserve that coverage across the external-module boundary.
const html = `${indexHtml}\n${themeBootstrapJs}\n${appNavigationJs}\n${appLegacyJs}`;
const legacyCss = fs.readFileSync(path.join(__dirname, "..", "public", "legacy-app.css"), "utf8");
const premiumCss = fs.readFileSync(path.join(__dirname, "..", "public", "premium.css"), "utf8");
const staticCss = fs.readFileSync(path.join(__dirname, "..", "public", "static-polish.css"), "utf8");
const signupHtml = fs.readFileSync(path.join(__dirname, "..", "public", "signup.html"), "utf8");
const loginHtml = fs.readFileSync(path.join(__dirname, "..", "public", "login.html"), "utf8");
const loginJs = fs.readFileSync(path.join(__dirname, "..", "public", "login.js"), "utf8");
const signupJs = fs.readFileSync(path.join(__dirname, "..", "public", "signup.js"), "utf8");
const resetPasswordJs = fs.readFileSync(path.join(__dirname, "..", "public", "reset-password.js"), "utf8");
const staticAuthJs = fs.readFileSync(path.join(__dirname, "..", "public", "static-auth.js"), "utf8");
const premiumRevampCss = fs.readFileSync(path.join(__dirname, "..", "public", "premium-revamp.css"), "utf8");
const productJs = fs.readFileSync(path.join(__dirname, "..", "public", "product-system.js"), "utf8");
const workspaceJs = fs.readFileSync(path.join(__dirname, "..", "public", "workspace-system.js"), "utf8");
const productCss = fs.readFileSync(path.join(__dirname, "..", "public", "product-system.css"), "utf8");
const researchJs = fs.readFileSync(path.join(__dirname, "..", "public", "research-system.js"), "utf8");
const releaseCss = fs.readFileSync(path.join(__dirname, "..", "public", "release-polish.css"), "utf8");
const visualCss = fs.readFileSync(path.join(__dirname, "..", "public", "visual-refresh.css"), "utf8");
const lensAppJs = fs.readFileSync(path.join(__dirname, "..", "labs", "lens-score", "app.js"), "utf8");
const lensRouteJs = fs.readFileSync(path.join(__dirname, "..", "routes", "lens-score.js"), "utf8");
const stockResearchJs = fs.readFileSync(path.join(__dirname, "..", "lib", "stock-research.js"), "utf8");
const marketRouteJs = fs.readFileSync(path.join(__dirname, "..", "routes", "market-data.js"), "utf8");
const authRouteJs = fs.readFileSync(path.join(__dirname, "..", "routes", "auth.js"), "utf8");
const projectionJs = fs.readFileSync(path.join(__dirname, "..", "public", "projection-lab.js"), "utf8");
const siteShellCss = fs.readFileSync(path.join(__dirname, "..", "public", "site-shell.css"), "utf8");
const landingPolishCss = fs.readFileSync(path.join(__dirname, "..", "public", "landing-polish.css"), "utf8");
const beautyCss = fs.readFileSync(path.join(__dirname, "..", "public", "beauty-system.css"), "utf8");
const aboutHtml = fs.readFileSync(path.join(__dirname, "..", "public", "about.html"), "utf8");
const adminHtml = fs.readFileSync(path.join(__dirname, "..", "public", "admin-analytics.html"), "utf8");
const lensHtml = fs.readFileSync(path.join(__dirname, "..", "labs", "lens-score", "index.html"), "utf8");
const publicShellPages = [
  "about.html",
  "blog.html",
  "compound-calculator.html",
  "data-sources.html",
  "privacy.html",
  "research-process.html",
  "terms.html",
].map(file => [file, fs.readFileSync(path.join(__dirname, "..", "public", file), "utf8")]);
const stockLandingRoute = fs.readFileSync(path.join(__dirname, "..", "routes", "stock-landing.js"), "utf8");
const htmlAndLegacyCss = `${html}\n${legacyCss}`;

test("Share Studio exports an honest, branded social research frame", () => {
  assert.match(indexHtml, /share-studio\.js\?v=20260827-2/);
  assert.match(indexHtml, /id="share-studio-canvas" width="1600" height="900"/);
  assert.match(indexHtml, /onclick="openShareStudio\(\)"/);
  assert.match(shareStudioJs, /window\.__ilChart\?\.chart/);
  assert.match(shareStudioJs, /chart\.takeScreenshot\(\)/);
  assert.match(shareStudioJs, /canvas\.toDataURL\("image\/png"/);
  assert.match(shareStudioJs, /Educational research · Not investment advice/);
  assert.match(shareStudioJs, /quote-source/);
  assert.match(ilSystemCss, /Share Studio — a native publishing surface/);
});

test("research terminal switches cleanly between discovery and loaded-company layouts", () => {
  assert.match(appLegacyJs, /classList\.remove\('has-stock'\)/);
  assert.match(appLegacyJs, /classList\.add\('has-stock'\)/);
  assert.match(ilSystemCss, /#view-tool:not\(\.has-stock\) \.app-chart-toolbar/);
  assert.match(ilSystemCss, /#body-analyze:not\(\.has-stock\) > \.tool-welcome \{[\s\S]*grid-row: 1 \/ span 2/);
  assert.match(ilSystemCss, /#body-analyze\.has-stock > #tool-welcome/);
  assert.match(ilSystemCss, /#body-analyze:not\(\.has-stock\) > \.tool-welcome > \.il-onboarding \{[\s\S]*display: none/);
});

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
  assert.match(html, /mode:isPriceChart\?'x':'xy'/);
  assert.doesNotMatch(html, /overScaleMode:'xy'/);
  assert.match(html, /pan:\s*\{ enabled:true, mode:isPriceChart\?'x':'xy', threshold:0 \}/); // expanded price view never distorts its value axis
  assert.match(html, /zoom:\{ wheel:\{enabled:false\}, pinch:\{enabled:false\}, drag:\{enabled:false\}/); // inline charts static
  assert.match(html, /limits:\{x:\{min:'original',max:'original',minRange:4\},y:\{min:'original',max:'original'\}\}/);
  assert.match(html, /function fmtChartPrice\(raw\)/);
  assert.match(html, /label:ctx=>` \$\{ctx\.dataset\.label\|\|''\}: \$\{fmtChartPrice\(ctx\.raw\)\}`/);
  assert.match(html, /ticks:\{color:t\.text,font:\{size:10\},callback:v=>fmtChartPrice\(v\)\}/);
  assert.match(html, /function gcol\(\)\{ return 'rgba\(217,179,94,\.105\)'; \}/);
  assert.match(html, /ttBg:\s*'rgba\(1[06],/);
  assert.match(html, /text:\s*'rgba\(238,233,224,\.86\)'/);
  assert.match(html, /onclick="zoomPriceChart\(1\.25\)"/);
  assert.match(html, /Zoom price chart out or load older history/);
  assert.match(html, /onclick="resetPriceZoom\(\)"/);
  assert.match(html, /onclick="zoomExpandedChart\(1\.25\)"/);
  assert.match(html, /async function loadMorePriceHistory\(\)/);
  assert.match(html, /factor<1&&sourceId==='price-chart'&&chartAtFullHistory\(_expandedChart\)/);
  assert.match(html, /CHART_RANGE_ORDER=\['1d','5d','1mo','3mo','6mo','1y','2y','5y','max'\]/);
  assert.match(html, /minRange:4/);
  // Inline charts must never trap scroll: pan-y everywhere; gestures only in the expanded workspace
  assert.match(htmlAndLegacyCss, /#price-chart\{touch-action:pan-y\}/);
  assert.match(legacyCss, /\.chart-wrap canvas\{[\s\S]*touch-action:pan-y!important/);
  assert.match(legacyCss, /\.cex-workspace canvas\{[\s\S]*touch-action:none!important/);
  assert.match(legacyCss, /Expand to zoom, pan & inspect/);
  assert.match(legacyCss, /content:'Pinch \+ drag'/);
});

test("mobile chart headers reserve room for controls and explain unavailable indicators", () => {
  assert.match(html, /function syncIndicatorAvailability\(barCount\)/);
  assert.match(html, /50D Avg.*bars:50|ma50:\s*\{\s*bars:50/);
  assert.match(html, /ma200:\{\s*bars:200/);
  assert.match(html, /S\.inds\.ma50&&ma50v\.some\(v=>v!=null\)/);
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
  assert.match(siteShellCss, /#main-nav,[\s\S]*min-height: calc\(56px \+ env\(safe-area-inset-top, 0px\)\) !important;/);
  assert.match(siteShellCss, /height: calc\(56px \+ env\(safe-area-inset-top, 0px\)\) !important;/);
  assert.match(siteShellCss, /padding: env\(safe-area-inset-top, 0px\)[^;]+env\(safe-area-inset-right, 0px\)[^;]+env\(safe-area-inset-left, 0px\)/);
  assert.match(htmlAndLegacyCss, /#view-home\{padding-top:calc\(56px \+ env\(safe-area-inset-top, 0px\)\)\}/);
  assert.match(htmlAndLegacyCss, /#view-tool \{[^}]*padding-top:calc\(56px \+ env\(safe-area-inset-top, 0px\)\)/);
  assert.match(landingPolishCss, /padding-bottom: calc\(88px \+ env\(safe-area-inset-bottom, 0px\)\) !important/);
  assert.match(landingPolishCss, /height: calc\(64px \+ env\(safe-area-inset-bottom, 0px\)\) !important/);
});

test("expanded mobile price charts fit the evidence instead of anchoring to zero", () => {
  assert.match(appLegacyJs, /function expandedPriceBounds\(srcCfg\)/);
  assert.match(appLegacyJs, /const pad=span\*\.08/);
  assert.match(appLegacyJs, /\.\.\.\(priceBounds\|\|\{\}\),\s*beginAtZero:false/);
  assert.match(appLegacyJs, /position:isPriceChart\?'right'/);
  assert.match(appLegacyJs, /maxTicksLimit:compact\?4:10,maxRotation:0,minRotation:0/);
  assert.match(appLegacyJs, /function fmtChartAxisPrice\(raw\)/);
  assert.match(appLegacyJs, /legend: \{ display: !compact/);
  assert.match(appLegacyJs, /Open  \$\{fmtChartPrice\(quote\.open/);
  assert.doesNotMatch(appLegacyJs, /Range'}: \$\$\{f\(/);
});

test("expanded mobile chart controls preserve the plot area", () => {
  assert.match(workspaceJs, /class="il-cexc-row il-cexc-primary"/);
  assert.match(workspaceJs, /class="il-cexc-row il-cexc-ranges"/);
  assert.match(workspaceJs, /data-cexc-markup="1"/);
  assert.match(workspaceJs, /modal\.classList\.toggle\("markup-open"\)/);
  assert.match(premiumCss, /#chart-expand-modal \.cex-type-toggle\{ display:none!important; \}/);
  assert.match(premiumCss, /#chart-expand-modal \.cex-toolbar\{ display:none!important; \}/);
  assert.match(premiumCss, /#chart-expand-modal\.markup-open \.cex-toolbar/);
  assert.match(premiumCss, /#il-cex-controls \.il-cexc-row\{[\s\S]*overflow-x:auto/);
  assert.match(premiumCss, /#chart-expand-modal \.cex-body\{[\s\S]*padding:2px 0 4px!important/);
});

test("authenticated navigation cannot display contradictory login actions", () => {
  assert.match(indexHtml, /id="nav-login" href="\/login">Log in/);
  assert.match(indexHtml, /id="nav-signup" href="\/signup">Start trial/);
  assert.match(appNavigationJs, /const setAuthEntryVisibility = loggedIn =>/);
  assert.match(appNavigationJs, /if \(\$login\) \$login\.hidden = loggedIn/);
  assert.match(appNavigationJs, /if \(\$signup\) \$signup\.hidden = loggedIn/);
  assert.match(appNavigationJs, /if \(user\) \{[\s\S]*setAuthEntryVisibility\(true\)/);
  assert.match(appNavigationJs, /else \{\s*setAuthEntryVisibility\(false\)/);
  assert.match(siteShellCss, /#main-nav #nav-login\[hidden\],[\s\S]*display: none !important/);
  assert.match(staticAuthJs, /querySelectorAll\("\.il-global-login, \.il-global-trial"\)/);
  assert.match(staticAuthJs, /el\.hidden = !!signedIn/);

  /* The static pages are separate documents and re-resolve the session on load.
     A signed-in visitor seeing "Log in" next to their own account chip is the
     regression this guards, so assert the three things that prevent it rather
     than any one line of the implementation. */

  // 1. It must bind to the nav class every static page shares. Binding to
  //    .il-static-main-nav only reached 2 of the 8 pages.
  assert.match(staticAuthJs, /querySelector\("\.il-global-nav"\)/);

  // 2. Visibility is driven by an authoritative class, not by `hidden` alone —
  //    `#main-nav .btn-nav-outline { display:inline-flex !important }` at
  //    (0,1,1,0) outranks the [hidden] guard at (0,0,3,0).
  assert.match(staticAuthJs, /classList\.toggle\("il-auth-in"/);
  assert.match(staticAuthJs, /classList\.toggle\("il-auth-out"/);
  assert.match(premiumRevampCss, /nav#main-nav\.il-auth-in \.il-global-login[\s\S]{0,400}?display: none !important/);

  // 3. The pre-paint hint stops the guest links flashing at a signed-in user.
  assert.match(themeBootstrapJs, /il-auth-hint/);
  assert.match(themeBootstrapJs, /il-hint-in/);
  assert.match(premiumRevampCss, /html\.il-hint-in body nav#main-nav \.il-global-login/);

  // 4. Whatever else happens, the guest CTA must be recoverable — a stale hint
  //    that says "signed in" cannot be allowed to hide the signup path.
  assert.match(premiumRevampCss, /html\.il-hint-in body nav#main-nav\.il-auth-out \.il-global-login[\s\S]{0,400}?display: inline-flex !important/);
});

test("auth forms execute under the production content security policy", () => {
  assert.match(loginHtml, /<script src="\/login\.js\?v=\d{8}-\d+"><\/script>/);
  assert.match(signupHtml, /<script src="\/signup\.js\?v=\d{8}-\d+"><\/script>/);
  assert.match(loginJs, /fetch\("\/api\/auth\/login"/);
  assert.match(signupJs, /fetch\("\/api\/auth\/signup"/);
  assert.match(resetPasswordJs, /fetch\("\/api\/auth\/forgot-password"/);
  assert.doesNotMatch(loginHtml, /<script>(?![\s\S]*type="application\/ld\+json")/);
});

test("mobile workspace content stays ahead of the legal footer", () => {
  assert.match(workspaceJs, /const disclaimer = scroll\.querySelector\(":scope > \.tool-disclaimer"\)/);
  assert.match(workspaceJs, /disclaimer\.insertAdjacentHTML\("beforebegin", workspaceMarkup\)/);
});

test("mobile browser chrome follows the selected site theme", () => {
  assert.match(html, /dark\s*\?\s*["']#07080B["']\s*:\s*["']#F6F4EF["']/i);
  assert.match(html, /dark\s*\?\s*["']black-translucent["']\s*:\s*["']default["']/);
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
  assert.match(html, /data-lesson="site-tour"/);
  assert.match(html, /data-lesson="lens-score"/);
  assert.match(html, /data-lesson="charts"/);
  assert.match(html, /data-lesson="financials"/);
  assert.match(html, /data-lesson="thesis"/);
  assert.doesNotMatch(productJs, /window\.openLesson\s*=\s*window\.openLearnWorkshop/);
});

test("ticker deep links hydrate the requested data tab after quote loading", () => {
  assert.match(html, /const requestedDataSection = \[\.\.\.document\.querySelectorAll\('\.app-section\.open'\)\]/);
  assert.match(html, /requestedDataSection !== 'analyze'/);
  assert.match(html, /window\.navGoTo\(requestedDataSection\)/);
});

test("price scenarios explain why a large price move may not change a capped score", () => {
  assert.match(lensAppJs, /The tested price is/);
  assert.match(lensAppJs, /quality cap and chart setup remain in force/);
  assert.match(lensAppJs, /not a historical backtest/);
});

test("LensScore separates retrieval time, evidence dates, and technical-only coverage", () => {
  assert.match(lensRouteJs, /private, max-age=30, stale-while-revalidate=120/);
  assert.match(lensRouteJs, /X-Data-Retrieved-At/);
  assert.match(lensAppJs, /Retrieved \$\{retrieved\}/);
  assert.match(lensAppJs, /company evidence unavailable/);
  assert.match(lensAppJs, /function renderPartial\(result\)/);
  assert.match(lensAppJs, /LensSetup remains usable/);
  assert.match(lensAppJs, /replace\("\/", "-"\)/);
});

test("call research refreshes are idempotent and label reported data honestly", () => {
  assert.match(researchJs, /list\.dataset\.loading === current/);
  assert.match(researchJs, /list\.dataset\.loading = current/);
  assert.match(researchJs, /Recent quarters — reported EPS vs estimate/);
  assert.doesNotMatch(researchJs, /Recent quarters — EPS vs estimate \(Finnhub\)/);
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
  assert.doesNotMatch(html, /class="nav-tab"[^>]*>Chart</);
  assert.doesNotMatch(html, /Scenario Builder/);
  assert.match(html, /id="nav-analyze" class="nav-tab"[^>]*>Scanners</);
  assert.match(html, /id="nav-lensscore-link"[^>]*class="nav-tab"[^>]*>Analysis/);
  assert.match(html, /id="nav-saved-link"[^>]*>Watchlists/);
  assert.match(html, /id="nav-news-link"[^>]*>News/);
  assert.match(html, /id="nav-pricing-link"[^>]*>Pricing/);
  assert.match(html, /<div class="sb-group-label">Research<\/div>/);
  assert.match(html, /<span class="sb-item-label">Chart<\/span>/);
  assert.match(html, /Find what the price already assumes\./);
  assert.match(html, /Start with a company, then move from reported fundamentals/);
  assert.match(html, /Popular starting points/);
  assert.match(html, /href="\/lens-score" id="nav-lensscore-link"/);
});

test("About and LensScore use one global product navigation", () => {
  for (const page of [aboutHtml, lensHtml]) {
    assert.match(page, /class="[^"]*\bil-global-nav\b[^"]*"/);
    assert.match(page, /class="[^"]*\bil-global-tab\b[^"]*" href="\/\?view=tool&amp;section=reports">Watchlists/);
    assert.match(page, /class="[^"]*\bil-global-tab\b[^"]*" href="\/lens-score"[^>]*>Analysis/);
    assert.match(page, /class="[^"]*\bil-global-tab\b[^"]*" href="\/blog"[^>]*>News/);
    assert.match(page, /class="[^"]*\bil-global-tab\b[^"]*" href="\/signup"[^>]*>Pricing/);
    assert.match(page, /\/site-shell\.css\?v=/);
  }
  assert.match(lensHtml, /<header class="topbar" hidden>/);
  assert.match(lensHtml, /id="theme-button-old"/);
  assert.match(siteShellCss, /nav\.il-global-nav \{/);
  assert.match(siteShellCss, /@media \(max-width: 900px\)/);
});

test("saved research persists honestly and reopens real tools", () => {
  assert.match(html, /async function persistSavedEntry\(entry, successMessage\)/);
  assert.match(html, /Saved on this device — cloud sync failed\./);
  assert.match(html, /const remoteSignatures = new Set/);
  assert.match(html, /async function loadSavedAnalysis\(entry\)/);
  assert.match(html, /document\.getElementById\('main-ticker'\)/);
  assert.match(html, /await fetchAndRender\(\)/);
  assert.match(html, /await runCompare\(\)/);
  assert.match(html, /async function clearAllSaved\(\)/);
  assert.match(html, /Could not clear your cloud saves/);
  assert.match(html, /localStorage\.setItem\('il-projlab:v2:' \+ ticker/);
  assert.match(html, /localStorage\.setItem\('il-vlab:' \+ ticker/);
  assert.doesNotMatch(html, /document\.getElementById\('ticker-input'\)\.value = entry\.ticker/);
  assert.doesNotMatch(html, /document\.getElementById\('btn-analyze'\)\.click\(\)/);
  assert.match(projectionJs, /window\.saveProjectionToAnalyses\(PL\.model\)/);
  assert.match(authRouteJs, /"valuation"/);
});

test("the research entry point and quote summary stay unambiguous", () => {
  assert.match(html, /class="tool-welcome"[\s\S]*class="search-row"[\s\S]*id="main-ticker"/);
  assert.match(html, /id="main-ticker"[^>]*aria-label="Company ticker"/);
  assert.match(visualCss, /Desktop navigation search remains a shortcut, not the only way in/);
  assert.match(visualCss, /#view-tool #body-analyze \.tool-welcome \.search-row/);
  assert.match(html, /const previousBar=finiteCloses\.length>1/);
  assert.match(html, /Today \$\{chg>=0\?'\+':''\}/);
  assert.match(productJs, /const prev = meta\.previousClose \?\? window\.IL_STATE\?\.previousClose \?\? meta\.chartPreviousClose/);
  assert.doesNotMatch(productJs, /const prev = meta\.chartPreviousClose \?\? meta\.previousClose/);
  assert.match(productJs, /interval === "1d" && age < 4 \* 86400/);
  assert.match(productJs, /Latest daily bar/);
});

test("screener loading is race-safe and has a live provider fallback", () => {
  assert.match(html, /if\(loading\) loading\.style\.display='flex'/);
  assert.match(html, /if\(!peEl\|\|!pbEl\|\|!divEl\|\|!capEl\|\|!retEl\|\|!tbody\) return/);
  assert.match(html, /if\(!tbody\) return/);
  assert.match(marketRouteJs, /function loadYahooScreenerUniverse\(\)/);
  assert.match(marketRouteJs, /\["most_actives", "day_gainers", "day_losers"\]/);
  assert.match(marketRouteJs, /yahooUniverse\.length >= 10/);
  assert.match(marketRouteJs, /recordProvider\("Yahoo Finance", true/);
  assert.match(marketRouteJs, /dividendRatio <= 0\.25/);
  assert.match(html, /s\.dividendYield!=null\?s\.dividendYield\.toFixed\(2\)/);
});

test("desktop navigation is keyboard-operable and mobile controls are tappable", () => {
  assert.match(html, /item\.setAttribute\('role', 'button'\)/);
  assert.match(html, /item\.setAttribute\('tabindex', '0'\)/);
  assert.match(html, /e\.key === 'Enter' \|\| e\.key === ' '/);
  assert.match(visualCss, /Mobile controls meet a dependable tap-target floor/);
  assert.match(visualCss, /#view-tool #app-tf-strip button,[\s\S]*min-height: 44px !important/);
  assert.match(visualCss, /#view-tool \.il-shell-actions button \{[\s\S]*min-width: 44px !important/);
});

test("quote results make data trust visible before decisions", () => {
  assert.match(productJs, /function renderTrust\(result\)/);
  assert.match(productJs, /impliedLensProvenance/);
  assert.match(productJs, /Evidence quality/);
  assert.match(productJs, /Provider observation/);
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
  assert.match(releaseCss, /--chart-positive: #00a84f/);
  assert.match(releaseCss, /--chart-positive: #00e676/);
  assert.match(releaseCss, /--chart-negative: #e23d4f/);
  assert.match(releaseCss, /--chart-negative: #ff4d5a/);
});

test("earnings UI separates SEC GAAP actuals from consensus-compatible results", () => {
  assert.match(appLegacyJs, /Reported GAAP EPS/);
  assert.match(appLegacyJs, /Fiscal quarter end/);
  assert.match(appLegacyJs, /comparisonStatus === 'basis-mismatch'/);
  assert.match(appLegacyJs, /BASIS DIFF/);
  assert.match(appLegacyJs, /showDataSource\('earn-source', null, earningsSource/);
  assert.doesNotMatch(appLegacyJs, /showDataSource\('earn-source', estData\.impliedLens/);
});

test("release navigation controls keep identical geometry across active states", () => {
  assert.match(releaseCss, /grid-template-columns: repeat\(8, minmax\(68px, 1fr\)\)/);
  assert.match(siteShellCss, /#main-nav \.nav-links \{[\s\S]*display: flex !important/);
  assert.match(siteShellCss, /#main-nav \.nav-tab,[\s\S]*height: 38px !important/);
  assert.match(siteShellCss, /#main-nav\[data-view="tool"\] #nav-links \{[\s\S]*display: flex !important/);
  assert.match(siteShellCss, /@media \(min-width: 961px\) and \(max-width: 1100px\)/);
  assert.match(releaseCss, /#main-nav \.nav-tab\.active-tab,/);
  assert.match(releaseCss, /font-weight: 600 !important/);
  assert.match(releaseCss, /flex: 0 0 94px/);
  assert.match(releaseCss, /height: 40px/);
});

test("every public product region uses the shared navigation and skip link", () => {
  for (const [file, page] of publicShellPages) {
    assert.match(page, /viewport-fit=cover/, `${file} should expose device safe areas`);
    assert.match(page, /site-shell\.css\?v=\d{8}-\d+/, `${file} should load the shared shell`);
    assert.match(page, /class="il-skip-link"/, `${file} should provide keyboard bypass navigation`);
    assert.match(page, /<nav[^>]+class="[^"]*\bil-global-nav\b[^"]*"[^>]+aria-label="Primary navigation">/, `${file} should expose the product navigation`);
    assert.match(page, /class="top-bar" hidden/, `${file} should retire its legacy back-to-platform header`);
    assert.match(page, /class="[^"]*\bil-global-search\b[^"]*"/, `${file} should preserve the global ticker search`);
    assert.match(page, /class="[^"]*\bil-global-live\b[^"]*"/, `${file} should preserve the live status`);
    assert.match(page, /class="[^"]*\bil-global-login\b[^"]*"/, `${file} should preserve account entry`);
    assert.match(page, /class="[^"]*\bil-global-trial\b[^"]*"/, `${file} should preserve the trial action`);
  }
  assert.match(stockLandingRoute, /site-shell\.css\?v=\d{8}-\d+/);
  assert.match(stockLandingRoute, /viewport-fit=cover/);
  assert.match(stockLandingRoute, /class="il-skip-link"/);
  assert.match(stockLandingRoute, /<nav id="main-nav" class="il-global-nav il-static-main-nav" aria-label="Primary navigation">/);
  assert.match(stockLandingRoute, /class="top-bar" hidden/);
  assert.match(stockLandingRoute, /class="il-global-search"/);
  assert.match(lensHtml, /class="[^"]*\bil-global-search\b[^"]*"/);
  assert.match(lensHtml, /viewport-fit=cover/);
  assert.match(lensHtml, /id="methodology-button"/);
});

test("LensScore avoids repeated slow provider work and caps optional provider latency", () => {
  assert.match(lensRouteJs, /const responseCache = new Map\(\)/);
  assert.match(lensRouteJs, /const inFlight = new Map\(\)/);
  assert.match(lensRouteJs, /X-LensScore-Cache/);
  assert.match(lensRouteJs, /private, max-age=30, stale-while-revalidate=120/);
  assert.match(stockResearchJs, /OPTIONAL_RESEARCH_BUDGET_MS = 5500/);
  assert.match(stockResearchJs, /withinBudget\(loadCompanyFacts/);
  assert.match(stockResearchJs, /withinBudget\(loadFinnhubResearch/);
  assert.match(lensAppJs, /new AbortController\(\)/);
});

test("LensScore uses compact live transport, instant verified session evidence, and the shared research library", () => {
  assert.match(lensRouteJs, /function compactPayload\(payload\)/);
  assert.match(lensRouteJs, /X-LensScore-Mode/);
  assert.match(lensRouteJs, /req\.query\.compact === "1"/);
  assert.match(lensAppJs, /compact=1/);
  assert.match(lensAppJs, /function decodeBars\(rows\)/);
  assert.match(lensAppJs, /SESSION_CACHE_TTL_MS = 15 \* 60 \* 1000/);
  assert.match(lensAppJs, /Showing verified session evidence/);
  assert.match(lensAppJs, /function saveCurrentScenario\(\)/);
  assert.match(lensAppJs, /type: "lensscore"/);
  assert.match(authRouteJs, /"lensscore"/);
  assert.match(html, /data-type="lensscore">LensScore/);
  assert.match(html, /entry\.type === 'lensscore'/);
  assert.match(lensHtml, /Validate the score before committing capital/);
  assert.match(lensHtml, /data-research-section="financials"/);
  assert.match(siteShellCss, /font-family: Arial, "Helvetica Neue", sans-serif !important/);
});

test("mobile product controls preserve a 44 pixel interaction floor", () => {
  assert.match(siteShellCss, /Mobile interaction floor/);
  for (const selector of [
    "#view-home \\.mo-tab",
    "#view-home \\.movers-tab",
    "#view-tool \\.sa-pill",
    "#view-tool \\.il-ws-tab",
    "#view-tool \\.il-onboarding-close",
    "\\.quick-tickers button",
    "\\.company-nav button",
    "#open-chart-button",
    "#run",
  ]) {
    assert.match(siteShellCss, new RegExp(selector));
  }
  assert.match(siteShellCss, /min-height: 44px !important/);
  assert.match(siteShellCss, /min-width: 44px !important/);
});

test("expanded charts look premium and support seamless annotation", () => {
  assert.match(html, /var _markup = \{tool:'cursor',color:'#16C784'/);
  assert.match(html, /data-markup-color="#16C784"/);
  assert.match(html, /data-markup-color="#3B82F6"/);
  assert.match(html, /data-markup-color="#F45B5B"/);
  assert.match(html, /ctx2\.shadowColor='rgba\(0,0,0,\.22\)'/);
  assert.match(html, /ctx2\.lineWidth=item\.type==='freehand'\?2\.5:3/);
  assert.match(legacyCss, /#chart-expand-modal\{[\s\S]*backdrop-filter:blur\(10px\)/);
  // Radii come from the 4/8/999 scale now, not hand-picked per component.
  assert.match(legacyCss, /\.cex-box\{[\s\S]*border-radius: ?8px/);
  assert.match(legacyCss, /\.cex-body\{[\s\S]*radial-gradient\(900px 420px at 78% -10%,rgba\(217,179,94,\.12\),transparent 70%\)/);
  assert.match(legacyCss, /\.cex-tool\{[\s\S]*border-radius: ?8px/);
  assert.match(legacyCss, /\.cex-color\{[\s\S]*width:24px/);
});

test("homepage defaults to a beginner-friendly landing page before market tools", () => {
  assert.match(html, /id="landing-page"/);
  assert.match(html, /<div class="home-shell" id="market-page" style="display:none;">/);
  // The Lens Prime headline is split across two spans so the second line can
  // carry the gold editorial accent.
  assert.match(html, /<h1[^>]*class="[^"]*il-display/);
  assert.match(html, /Find the edge\./);
  assert.match(html, /See the <em>bigger picture\.<\/em>/);
  assert.match(html, /lens-prime-v2\.css/);
  // The live market strip renders /api/market/movers, so the hook must exist.
  assert.match(html, /id="il-movers"/);
  assert.match(html, /landing-market\.js/);
  assert.match(html, /Start with a 7-day free trial/);
  assert.match(html, /Start 7-day free trial/);
  assert.match(html, /class="il-hero-mock[^"]*" role="img"/);
  assert.match(html, /Illustrative workspace/);
  assert.match(html, /Discount codes accepted/);
  assert.doesNotMatch(html, /id="landingChartFill"/);
  assert.match(html, /function landingSearch\(\)/);
  assert.match(html, /id="market-page" style="display:none;"/);
  assert.match(html, /function showLandingPage\(\)/);
  assert.match(html, /function showMarketPage\(\)/);
  assert.match(html, /history\.replaceState\(null, '', '\/'\)/);
  assert.match(html, /\/\?view=home(?:&amp;|&)market=1/);
  assert.match(legacyCss, /#market-page \.home-hero,#market-page \.home-feat-strip,#market-page \.home-proof,#market-page \.home-guide-showcase,#market-page #pricing,#market-page \.cta-strip\{display:none!important\}/);
  assert.match(legacyCss, /\.il-landing-preview\.image-preview img\{/);
  assert.match(legacyCss, /\.il-theme-img-light\{[\s\S]*display:block!important/);
  assert.match(legacyCss, /html\[data-theme="dark"\] \.il-theme-img-light\{[\s\S]*display:none!important/);
  assert.match(legacyCss, /html\[data-theme="dark"\] \.il-theme-img-dark\{[\s\S]*display:block!important/);
  assert.match(legacyCss, /Landing hero final composition: one clean headline row above the generated image/);
  assert.match(legacyCss, /\.il-landing-hero\{[\s\S]*flex-direction:column/);
  assert.match(legacyCss, /\.il-landing-copy\{[\s\S]*background:transparent!important/);
  assert.match(legacyCss, /\.il-landing-copy \.il-landing-kicker,[\s\S]*\.il-landing-copy \.il-offer-card\{[\s\S]*display:none!important/);
  assert.match(legacyCss, /white-space:nowrap/);
  assert.match(legacyCss, /object-fit:contain!important/);
  assert.match(legacyCss, /max-height:min\(610px,calc\(100vh - 290px\)\)/);
  assert.match(legacyCss, /Homepage product preview cleanup: no awkward crop, readable sample-data label/);
  assert.match(legacyCss, /\.il-landing-hero \.il-landing-preview\.image-preview img\{[\s\S]*aspect-ratio:1463\/962!important;[\s\S]*object-position:center center!important/);
  assert.match(legacyCss, /\.il-landing-hero \.il-preview-caption\{[\s\S]*left:50%!important;[\s\S]*background:rgba\(10,11,12,\.88\)!important/);
  assert.match(legacyCss, /Homepage single-preview polish and shared product-surface finish/);
  assert.match(legacyCss, /\.il-landing-hero \.il-landing-preview\.image-preview img\.il-product-preview-img\{[\s\S]*clip-path:inset\(7px 9px 18px 9px round 28px\)!important/);
  assert.match(legacyCss, /\.il-landing-hero \.il-landing-actions\{[\s\S]*display:flex!important/);
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
  assert.match(html, /legacy-app\.css\?v=\d{8}(-\d+)?/);
  assert.match(html, /product-system\.css\?v=\d{8}(-\d+)?/);
  assert.match(signupHtml, /static-polish\.css\?v=\d{8}(-\d+)?/);
  assert.match(html, /<a class="btn-nav" id="nav-signup" href="\/signup">Start trial<\/a>/);
  assert.match(legacyCss, /Site-wide premium polish/);
  assert.match(legacyCss, /Gold theme harmonization/);
  assert.match(legacyCss, /\.il-landing-preview\{[\s\S]*linear-gradient\(180deg,#F6E3B7,#E9C986\)!important/);
  assert.match(legacyCss, /html\[data-theme="dark"\] \.app-section,[\s\S]*html\[data-theme="dark"\] \.il-learn-preview>div\{[\s\S]*linear-gradient\(180deg,rgba\(31,34,38,.96\),rgba\(14,16,18,.98\)\)!important/);
  assert.match(staticCss, /Static theme harmonization/);
  assert.match(legacyCss, /#market-page \.home-grid,[\s\S]*#market-page \.home-lower\{[\s\S]*gap:16px!important/);
  assert.match(legacyCss, /#market-page \.hc,[\s\S]*#market-page \.hl-report\{[\s\S]*border-radius: ?8px ?!important/);
  assert.match(legacyCss, /#market-page \.hc,[\s\S]*#market-page \.hg-market \.mo-bv2-card\{[\s\S]*rgba\(255,250,239,.94\)/);
  assert.match(legacyCss, /html\[data-theme="dark"\] #market-page \.hc,[\s\S]*html\[data-theme="dark"\] #market-page \.hg-market \.mo-bv2-card\{[\s\S]*rgba\(34,37,41,.96\)/);
  assert.match(legacyCss, /#market-page \.mo-tab\.on,[\s\S]*#market-page \.movers-tab\.active\{[\s\S]*linear-gradient\(180deg,var\(--lens-gold-2\),var\(--lens-gold\)\)/);
  assert.match(legacyCss, /\.home-ticker-strip,\s*\.ht-card,\s*\.hc,\s*\.hg-market/s);
  assert.match(html, /favicons\?sz=64&domain=apple\.com/);
  assert.match(legacyCss, /Market page readability and density pass/);
  assert.match(legacyCss, /#market-page \.home-ticker-strip\{[\s\S]*grid-template-columns:repeat\(8,minmax\(118px,1fr\)\)!important/);
  assert.match(legacyCss, /#market-page \.ht-logo\{[\s\S]*width:42px!important;[\s\S]*height:42px!important/);
  assert.match(legacyCss, /html\[data-theme="dark"\] #market-page \.hc,[\s\S]*html\[data-theme="dark"\] #market-page \.mo-bv2-card\{[\s\S]*linear-gradient\(180deg,#222529,#111315\)!important/);
  assert.match(legacyCss, /html\[data-theme="dark"\] #market-page \.mo-tab,[\s\S]*html\[data-theme="dark"\] #market-page \.movers-tab\{[\s\S]*background:#222529!important/);
  assert.match(legacyCss, /\.pricing-card,\s*\.pricing-compare,\s*\.modal,\s*\.nav-acct-menu/s);
  assert.match(legacyCss, /footer\{[\s\S]*#08090A!important/);
  assert.match(staticCss, /Static premium visual system/);
  assert.match(staticCss, /--sp-black:#090A0B/);
  assert.match(staticCss, /\.auth-card,\s*\.feat,\s*\.guide,\s*\.source-card/s);
  assert.match(staticCss, /\.btn-primary,\s*\.btn\.primary,\s*\.cta a/s);
});

test("calm premium visual refresh is the final site-wide theme layer", () => {
  assert.match(html, /release-polish\.css\?v=\d{8}-\d+[\s\S]*visual-refresh\.css\?v=\d{8}-\d+/);
  assert.match(signupHtml, /static-polish\.css\?v=\d{8}-\d+[\s\S]*visual-refresh\.css\?v=\d{8}-\d+/);
  assert.match(visualCss, /Implied Lens visual refresh/);
  assert.match(visualCss, /--cream: #f1f5f2/);
  assert.match(visualCss, /--cream: #080e0b/);
  assert.match(visualCss, /radial-gradient\(850px 520px at 86% -15%/);
  assert.match(visualCss, /:root:not\(\[data-theme="dark"\]\) nav#main-nav/);
  assert.match(visualCss, /#view-tool \.tool-welcome\s*\{/);
  assert.match(visualCss, /linear-gradient\(135deg, #14221b 0%, #0d1712 58%, #0a110e 100%\)/);
  assert.match(visualCss, /--chart-positive: #21ec85/);
  assert.match(visualCss, /--chart-negative: #ff6577/);
  assert.doesNotMatch(visualCss, /gold-ripple-background/);
});

test("canonical beauty system owns the final visual hierarchy sitewide", () => {
  assert.match(indexHtml, /landing-polish\.css\?v=\d{8}-\d+[\s\S]*beauty-system\.css\?v=\d{8}-\d+/);
  assert.match(indexHtml, /<body class="il-product-page">/);
  assert.match(lensHtml, /<body class="il-lens-page">/);
  assert.match(lensHtml, /beauty-system\.css\?v=\d{8}-\d+/);
  assert.match(adminHtml, /<body class="il-admin-page">/);
  assert.match(adminHtml, /beauty-system\.css\?v=\d{8}-\d+/);
  for (const [file, page] of publicShellPages) {
    assert.match(page, /<body class="il-static-page">/, `${file} should use the static visual scope`);
    assert.match(page, /beauty-system\.css\?v=\d{8}-\d+/, `${file} should load the canonical visual layer`);
  }
  assert.match(beautyCss, /--il-bg: #f3f5f2/);
  assert.match(beautyCss, /--il-bg: #090d0b/);
  assert.match(beautyCss, /--il-brass: #9b6b2d/);
  assert.match(beautyCss, /--il-green: #07864c/);
  assert.match(beautyCss, /#landing-page \.il-landing-search \{[\s\S]*display: grid !important/);
  assert.match(beautyCss, /#landing-page \.il-landing-actions #il-hero-primary \{ display: none !important; \}/);
  assert.match(beautyCss, /body::before \{ content: none !important; \}/);
});

test("landing visuals are honest CSS-built illustrations, not fake screenshots", () => {
  assert.doesNotMatch(html, /landing-product-preview/);
  assert.doesNotMatch(html, /landing-workflow-strip/);
  assert.doesNotMatch(html, /hero-process\.png/);
  assert.doesNotMatch(html, /has-hero-banner/);
  assert.match(html, /class="il-hero-mock[^"]*" role="img"/);
  // The hero is still a built illustration, not a screenshot, and still says so.
  assert.match(html, /aria-label="Illustration: a rising price chart under a magnifying lens/);
  // Strengthened: the illustrative quote panel must be labelled as sample data,
  // and the hero must not smuggle in a raster screenshot.
  assert.match(html, /class="ihx-r-foot">Sample data</);
  assert.doesNotMatch(html, /<img[^>]+class="[^"]*ihx/);
  assert.match(html, /class="il-workflow-panels"/);
  assert.match(html, /\/landing-polish\.css\?v=/);
  assert.match(landingPolishCss, /#landing-page\.il-landing \{[\s\S]*padding: 0 !important/);
  assert.match(landingPolishCss, /grid-template-columns: minmax\(360px, \.82fr\) minmax\(520px, 1\.18fr\)/);
  assert.doesNotMatch(html, /class="tw-score-preview"/);
  assert.doesNotMatch(html, /class="il-lensscore-launch"/);
  assert.match(html, /id="nav-lensscore-link"[^>]*class="nav-tab"[^>]*>Analysis/);
  assert.match(landingPolishCss, /#view-tool \.tool-welcome::after \{[\s\S]*content: none !important/);
  assert.match(legacyCss, /\.il-hero-mock\{/);
  assert.match(legacyCss, /\.il-workflow-panels\{/);
});

test("tool containers use premium rounded surfaces instead of sharp rectangles", () => {
  assert.match(legacyCss, /Premium tool surface polish/);
  // The three tool radius tokens collapsed onto the shared scale; they used to
  // be 13/16/22px and 14/18/22px in two competing definitions of the same names.
  assert.match(legacyCss, /--tool-radius-xl: ?8px/);
  assert.match(legacyCss, /--tool-radius-lg: ?8px/);
  assert.match(legacyCss, /--tool-radius-md: ?8px/);
  assert.match(legacyCss, /#view-tool \.acc-body,[\s\S]*#view-tool \.chart-wrap,[\s\S]*#view-tool \.metric-card,[\s\S]*#view-tool \.panel-box/);
  assert.match(legacyCss, /#view-tool \.il-tool-shell,[\s\S]*#view-tool \.il-proj-evidence,[\s\S]*#view-tool \.il-learn-workshop/);
  assert.match(legacyCss, /border-radius:var\(--tool-radius-lg\)!important/);
  assert.match(legacyCss, /box-shadow:var\(--tool-shadow-light\)!important/);
  assert.match(legacyCss, /html\[data-theme="dark"\] #view-tool \.acc-body,[\s\S]*box-shadow:var\(--tool-shadow-dark\)!important/);
  assert.match(legacyCss, /#view-tool \.ticker-input,[\s\S]*#view-tool \.il-learn-nav button\{[\s\S]*border-radius: ?8px ?!important/);
  assert.match(legacyCss, /#view-tool \.app-section \.acc-body\{[\s\S]*background:transparent!important/);
  assert.match(legacyCss, /Live tool workspace match to the generated sample/);
  assert.match(legacyCss, /--tool-sample-charcoal:#151310/);
  assert.match(legacyCss, /--tool-sample-green:#16C784/);
  assert.match(legacyCss, /--tool-sample-red:#F45B5B/);
  assert.match(legacyCss, /#view-tool \.search-row,[\s\S]*#view-tool \.chart-wrap,[\s\S]*#view-tool \.metric-card,[\s\S]*linear-gradient\(180deg,var\(--tool-sample-card-2\),var\(--tool-sample-card\)\)!important/);
  assert.match(legacyCss, /#view-tool \.btn-search,[\s\S]*#view-tool \.btn-run,[\s\S]*linear-gradient\(180deg,var\(--tool-sample-gold-2\),var\(--tool-sample-gold\)\)!important/);
  assert.match(legacyCss, /#view-tool \.price-chg\.up,[\s\S]*var\(--tool-sample-green-bright\)!important/);
  assert.match(legacyCss, /#view-tool \.price-chg\.dn,[\s\S]*var\(--tool-sample-red-bright\)!important/);
  assert.match(legacyCss, /Solid live workspace chrome and deeper chart panels/);
  assert.match(legacyCss, /#view-tool \.app-sidebar,[\s\S]*#view-tool \.app-chart-toolbar,[\s\S]*background:linear-gradient\(180deg,#24272B,#0C0E10\)!important/);
  assert.match(legacyCss, /#view-tool \.chart-wrap::before\{[\s\S]*background-size:100% 36px,72px 100%/);
  assert.match(legacyCss, /#view-tool \.chart-wrap canvas\{[\s\S]*filter:drop-shadow\(0 10px 18px rgba\(22,199,132,\.12\)\)/);
  assert.match(legacyCss, /#view-tool \.app-chart-toolbar \.act-btn,[\s\S]*#view-tool \.indicator-control\{[\s\S]*background:#161A1D!important/);
  assert.match(legacyCss, /Toolbar legibility and stronger brand recognition/);
  assert.match(legacyCss, /#main-nav \.nav-logo img,[\s\S]*width:34px!important;[\s\S]*box-shadow:0 0 0 3px rgba\(217,179,94,\.10\)/);
  assert.match(legacyCss, /#main-nav \.nav-tab\.active-tab,[\s\S]*color:#17120B!important/);
  assert.match(legacyCss, /#view-tool \.app-chart-toolbar \.act-btn\.on,[\s\S]*#view-tool \.app-tf-strip \.tf-pill\.on,[\s\S]*color:#17120B!important/);
  assert.match(legacyCss, /Final shared light\/dark ripple and toolbar fixes/);
  assert.match(legacyCss, /:root,[\s\S]*html\[data-theme="dark"\]\{[\s\S]*--gold-ripple-stack:var\(--gold-ripple-bg\)/);
  assert.match(legacyCss, /html,[\s\S]*body,[\s\S]*body::before,[\s\S]*html\[data-theme="dark"\],[\s\S]*html\[data-theme="dark"\] body::before\{[\s\S]*background-image:var\(--gold-ripple-stack\)!important/);
  assert.match(legacyCss, /#view-home,[\s\S]*#view-tool,[\s\S]*\.il-landing,[\s\S]*html\[data-theme="dark"\] #view-home,[\s\S]*html\[data-theme="dark"\] #view-tool,[\s\S]*background:transparent!important/);
  assert.match(legacyCss, /#main-nav,[\s\S]*#view-tool \.app-tf-strip,[\s\S]*border-color:rgba\(255,244,214,\.36\)!important/);
  assert.match(legacyCss, /#view-tool \.sb-item:hover,[\s\S]*#view-tool \.indicator-control:hover,[\s\S]*background:#202428!important/);
  assert.match(legacyCss, /#view-tool \.sb-item:hover \.sb-item-label,[\s\S]*#view-tool \.indicator-control:hover \*\{[\s\S]*color:#F8EED6!important/);
  assert.match(legacyCss, /#view-tool \.sb-item\.active \.sb-item-label,[\s\S]*#view-tool \.indicator-control\.active \*\{[\s\S]*color:#17120B!important/);
  assert.match(legacyCss, /Light mode top toolbar should sit on the gold system/);
  assert.match(legacyCss, /:root:not\(\[data-theme="dark"\]\) #main-nav,[\s\S]*background:linear-gradient\(180deg,rgba\(255,250,239,\.94\),rgba\(245,225,181,\.88\)\)!important/);
  assert.match(legacyCss, /:root:not\(\[data-theme="dark"\]\) #main-nav \.nav-tab\{[\s\S]*color:rgba\(23,18,11,\.72\)!important/);
  assert.match(legacyCss, /Light mode tool chrome: chart and side toolbars should be cream\/gold, not charcoal/);
  assert.match(legacyCss, /:root:not\(\[data-theme="dark"\]\) #view-tool \.app-sidebar,[\s\S]*#view-tool \.app-chart-toolbar,[\s\S]*background:linear-gradient\(180deg,rgba\(255,250,239,\.92\),rgba\(244,224,181,\.84\)\)!important/);
  assert.match(legacyCss, /:root:not\(\[data-theme="dark"\]\) #view-tool \.sb-item,[\s\S]*#view-tool \.app-chart-toolbar \.act-btn,[\s\S]*color:#2B2112!important/);
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

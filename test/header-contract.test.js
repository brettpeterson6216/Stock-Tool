"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");

const ROOT = path.join(__dirname, "..");

// Every document that renders a page to a visitor.
const PAGES = [
  "index.html",
  "public/about.html", "public/blog.html", "public/terms.html", "public/privacy.html",
  "public/data-sources.html", "public/research-process.html", "public/compound-calculator.html",
  "public/login.html", "public/signup.html", "public/reset-password.html",
  "public/admin-analytics.html", "labs/lens-score/index.html",
];

const read = rel => fs.readFileSync(path.join(ROOT, rel), "utf8");
const NAV_RE = /<nav id="main-nav"[\s\S]*?<\/nav>/;

// There were three different bars: #main-nav at 63px fixed on the landing page,
// .il-global-nav at 60px sticky on six static pages, a bare <nav> at 60px static
// with no tabs / no search / no account on the three auth pages, and nothing at
// all in the research terminal. Six copies of markup is six chances to drift, so
// the copies have to be identical and a test is what keeps them that way.
test("every page carries the same header markup, byte for byte", () => {
  const hashes = new Map();
  for (const rel of PAGES) {
    const m = read(rel).match(NAV_RE);
    assert.ok(m, `${rel} has no #main-nav header`);
    const h = crypto.createHash("sha1").update(m[0]).digest("hex");
    if (!hashes.has(h)) hashes.set(h, []);
    hashes.get(h).push(rel);
  }
  const variants = [...hashes.values()];
  assert.equal(
    variants.length, 1,
    "header markup differs between pages:\n" + variants.map(v => "  " + v.join(", ")).join("\n")
  );
});

test("the header carries every control on every page", () => {
  const REQUIRED = [
    ['id="nav-home"', "Dashboard tab"],
    ['id="nav-analyze"', "Scanners tab"],
    ['id="nav-lensscore-link"', "Analysis tab"],
    ['id="nav-saved-link"', "Watchlists tab"],
    ['id="nav-news-link"', "News tab"],
    ['id="nav-pricing-link"', "Pricing tab"],
    ['id="nav-search"', "ticker search"],
    ['id="nav-ticker-input"', "search field"],
    ['id="theme-toggle-btn"', "theme toggle"],
    ['id="nav-login"', "log in"],
    ['id="nav-signup"', "start trial"],
    ['id="nav-acct-wrap"', "account menu"],
  ];
  for (const rel of PAGES) {
    const nav = read(rel).match(NAV_RE)[0];
    for (const [needle, label] of REQUIRED) {
      assert.ok(nav.includes(needle), `${rel} header is missing the ${label}`);
    }
  }
});

// The bar must not be able to move, resize, or be painted over.
test("the header geometry is pinned in one place", () => {
  const css = read("public/clean-pass.css");
  const block = css.slice(css.indexOf("ONE HEADER, PINNED"));
  assert.ok(block, "the pinning block is gone");
  for (const decl of [
    /position:\s*fixed\s*!important/,
    /top:\s*0\s*!important/,
    /height:\s*63px\s*!important/,
    /min-height:\s*63px\s*!important/,
    /max-height:\s*63px\s*!important/,
    /z-index:\s*2147482000\s*!important/,
  ]) {
    assert.match(block, decl, `the header pin is missing ${decl}`);
  }
  // A fixed bar with nothing accounting for it is how content ends up beneath it.
  assert.match(block, /body:not\(#cp6\)\s*\{\s*padding-top:\s*63px\s*!important/,
    "the body offset for the fixed bar is missing");
});

// Media queries live later in the file but carry their own selector weight.
// Written with one :not(#id) fewer, the desktop display:flex won and six tabs
// stayed in a 390px bar.
test("the responsive header rules carry the same id weight as the desktop ones", () => {
  const css = read("public/clean-pass.css");
  const block = css.slice(css.indexOf("ONE HEADER, PINNED"));
  const ids = sel => (sel.match(/:not\(#|#[A-Za-z]/g) || []).length;
  const desktop = block.match(/^html:not\(#cp1\)[^{,]*#main-nav \.nav-links/m);
  assert.ok(desktop, "desktop .nav-links rule not found");
  const mq = block.slice(block.indexOf("@media (max-width: 900px)"));
  const mqNavLinks = mq.match(/^\s*(html:not\(#cp1\)[^{,]*#main-nav \.nav-links)/m);
  assert.ok(mqNavLinks, "responsive .nav-links rule not found");
  assert.ok(
    ids(mqNavLinks[1]) >= ids(desktop[0]),
    `responsive selector carries ${ids(mqNavLinks[1])} ids against the desktop rule's ${ids(desktop[0])}`
  );
});

// The header markup uses icon glyphs and the product type stack. Six of these
// pages never loaded either, which is how icons render as blank boxes.
test("every page loads what the header needs to render", () => {
  for (const rel of PAGES) {
    const src = read(rel);
    assert.match(src, /tabler-icons/, `${rel} does not load the icon font the header uses`);
    assert.match(src, /il-fonts\.css/, `${rel} does not load the header type stack`);
    assert.match(src, /clean-pass\.css/, `${rel} does not load the stylesheet that pins the header`);
    assert.match(src, /site-nav\.js/, `${rel} does not load the header behaviour`);
    assert.match(src, /theme-bootstrap\.js/, `${rel} does not resolve the theme before first paint`);
  }
});

// site-nav.js must never clobber the SPA implementations, which load first.
test("the shared header script defers to the product implementations", () => {
  const js = read("public/site-nav.js");
  for (const fn of ["toggleTheme", "_toggleMobileMenu", "navAccountTap"]) {
    const guard = new RegExp(`typeof window\\.${fn} !== "function"`);
    assert.match(js, guard, `site-nav.js assigns ${fn} without checking for an existing one`);
  }
  assert.match(js, /typeof window\.navGoTo !== "function"/, "tab handling must fall back to the href");
  const index = read("index.html");
  const navPos = index.indexOf("app-navigation.js");
  const legacyPos = index.indexOf("app-legacy.js");
  const sharedPos = index.indexOf("site-nav.js");
  assert.ok(sharedPos > navPos && sharedPos > legacyPos,
    "site-nav.js must load after the product scripts so its guards see them");
});

// The toggle wrote the choice to localStorage and theme-bootstrap.js ignored it,
// so picking light and clicking any tab put you back into dark.
test("the theme choice survives navigation", () => {
  const boot = read("public/theme-bootstrap.js");
  assert.match(boot, /localStorage\.getItem\("il-theme"\)/,
    "theme-bootstrap.js must read the stored preference");
  assert.match(boot, /savedTheme === "light"[\s\S]{0,80}removeAttribute\("data-theme"\)/,
    "a stored light preference must be applied before first paint");
  // Dark is still the default and still the fallback when storage is
  // unreadable; what must not come back is setting it before the preference
  // has been consulted.
  const firstRead = boot.indexOf('localStorage.getItem("il-theme")');
  const firstPin = boot.indexOf('setAttribute("data-theme", "dark")');
  assert.ok(
    firstRead !== -1 && firstRead < firstPin,
    "theme-bootstrap.js pins dark before reading the stored preference"
  );
});

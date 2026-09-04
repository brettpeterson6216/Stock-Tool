"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const PUBLIC_DIR = path.join(__dirname, "..", "public");
const ROOT = path.join(__dirname, "..");

// Narrow viewports legitimately collapse the nav into a hamburger and an
// account tap target, so @media blocks are not part of the desktop contract.
// Strip them (brace-balanced) before scanning.
function stripAtMediaBlocks(css) {
  let out = "";
  let i = 0;
  while (i < css.length) {
    const at = css.indexOf("@media", i);
    if (at === -1) {
      out += css.slice(i);
      break;
    }
    out += css.slice(i, at);
    let j = css.indexOf("{", at);
    if (j === -1) break;
    let depth = 0;
    for (; j < css.length; j += 1) {
      if (css[j] === "{") depth += 1;
      else if (css[j] === "}") {
        depth -= 1;
        if (depth === 0) { j += 1; break; }
      }
    }
    i = j;
  }
  return out;
}

const cssFiles = fs
  .readdirSync(PUBLIC_DIR)
  .filter(name => name.endsWith(".css"))
  .map(name => ({
    name,
    source: stripAtMediaBlocks(fs.readFileSync(path.join(PUBLIC_DIR, name), "utf8")),
  }));

const indexHtml = fs.readFileSync(path.join(ROOT, "index.html"), "utf8");
const appNavigationJs = fs.readFileSync(path.join(PUBLIC_DIR, "app-navigation.js"), "utf8");

// #nav-login is hidden the moment a session is found (setAuthEntryVisibility),
// so anything it renders is shown ONLY to logged-out visitors. Painting
// initials there presents a stranger's account to every new arrival, and the
// accessible name still says "Log in", so the control and its label disagree.
test("the logged-out nav does not render account initials", () => {
  assert.match(
    appNavigationJs,
    /\$login\.hidden\s*=\s*loggedIn/,
    "expected #nav-login to be the logged-out-only entry point"
  );

  for (const { name, source } of cssFiles) {
    const initialsOnLogin = new RegExp(
      String.raw`#nav-login\s*::?after[^}]*content\s*:\s*["'][A-Za-z]{1,3}["']`,
      "i"
    );
    assert.doesNotMatch(
      source,
      initialsOnLogin,
      `${name} draws hardcoded initials on the logged-out login control`
    );
  }
});

// A login control that is font-size:0 with transparent text is a control with
// no visible label. Sighted visitors get an unlabelled circle.
test("the login control keeps a visible label", () => {
  assert.match(
    indexHtml,
    /<a[^>]*id="nav-login"[^>]*>\s*Log in\s*<\/a>/,
    "expected #nav-login to carry visible text"
  );
  for (const { name, source } of cssFiles) {
    const blanked = new RegExp(
      String.raw`#nav-login\s*\{[^}]*font-size\s*:\s*0`,
      "i"
    );
    assert.doesNotMatch(source, blanked, `${name} blanks the login label to font-size:0`);
  }
});

// The trial CTA is the primary conversion path; a stylesheet had display:none
// on it, so the nav offered no way to start one.
test("the nav keeps the trial call to action reachable", () => {
  assert.match(indexHtml, /id="nav-signup"/, "expected a #nav-signup control in the nav");
  for (const { name, source } of cssFiles) {
    const hidden = new RegExp(
      String.raw`#nav-signup\s*,?[^{}]*\{[^}]*display\s*:\s*none[^}]*\}`,
      "i"
    );
    const match = source.match(hidden);
    if (!match) continue;
    // clean-pass.css legitimately hides it when the HTML sets [hidden].
    assert.match(
      match[0],
      /\[hidden\]/,
      `${name} hides #nav-signup unconditionally`
    );
  }
});

// -webkit-text-fill-color paints over `color`. A literal near-white fill is
// invisible on the light-theme bar; the fill has to follow the token.
test("nav text does not hardcode a light-theme-breaking fill colour", () => {
  const cleanPass = fs.readFileSync(path.join(PUBLIC_DIR, "clean-pass.css"), "utf8");
  assert.match(
    cleanPass,
    /#main-nav \.nav-tab \{[^}]*-webkit-text-fill-color:\s*currentColor/,
    "expected nav tabs to inherit their fill from `color` so both themes work"
  );
});

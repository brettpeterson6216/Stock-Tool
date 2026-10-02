"use strict";
const test = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const path = require("path");
const P = (...p) => path.join(__dirname, "..", ...p);
const html = fs.readFileSync(P("index.html"), "utf8");
const siteNav = fs.readFileSync(P("public", "site-nav.js"), "utf8");
const v5 = fs.readFileSync(P("public", "research-v5.css"), "utf8");
const theme = fs.readFileSync(P("public", "theme-v4.css"), "utf8");

test("opening the mobile menu never focuses the search field", () => {
  // Focusing an input on a phone raises the keyboard, and on iOS zooms the page.
  assert.doesNotMatch(siteNav, /appDrawer\.querySelector\('input/, "the drawer focuses its first input again");
  assert.match(siteNav, /sheet\.focus\(\{ preventScroll: true \}\)/, "the drawer no longer focuses the sheet");
});

test("every mobile menu row is a real destination", () => {
  const menu = html.slice(html.indexOf('id="mobile-more-menu"'), html.indexOf("</div>\n  </div>\n</div>", html.indexOf('id="mobile-more-menu"')));
  const rows = [...menu.matchAll(/<a class="il-mm-item[^"]*" href="([^"]+)"/g)].map(m => m[1]);
  assert.ok(rows.length >= 18, `only ${rows.length} rows`);
  for (const href of rows) assert.ok(href === "#" || href.startsWith("/"), href);
  for (const sec of [...menu.matchAll(/data-mm-sec="([a-z]+)"/g)].map(m => m[1])) {
    // Call Research and Wealth Planner build their own sections at load.
    const built = fs.readdirSync(P("public")).filter(f => f.endsWith(".js"))
      .some(f => fs.readFileSync(P("public", f), "utf8").includes('"sec-' + sec + '"') || fs.readFileSync(P("public", f), "utf8").includes("sec-" + sec + "'"));
    assert.ok(new RegExp('id="sec-' + sec + '"').test(html) || built, `menu points at a missing section: ${sec}`);
  }
  for (const hook of ["data-mm-account", "data-mm-feedback", "data-mm-logout", "data-mm-market", "data-mm-lensscore"]) {
    assert.match(menu, new RegExp(hook), hook + " row is missing");
    assert.match(siteNav, new RegExp(hook), hook + " has no handler");
  }
});

test("the header is solid and phone fields cannot trigger iOS zoom", () => {
  assert.match(theme, /#main-nav\.il-global-nav \{\s*background: var\(--rp-bg\) !important;/, "the header is translucent again");
  assert.match(v5, /:is\(input:not\(\[type="checkbox"\]\)[^)]*\)[^{]*\{ font-size: 16px !important; \}/, "phone inputs can be under 16px again");
});

test("account settings has no emoji, shouting labels or unlabeled fields", () => {
  const modal = html.slice(html.indexOf('id="acct-modal-bg"'), html.indexOf('class="il-acct-foot"'));
  assert.doesNotMatch(modal, /text-transform:uppercase|💳|⭐|✦/);
  for (const id of ["am-new-username", "am-cur-pw", "am-new-pw", "am-confirm-pw"]) assert.match(modal, new RegExp('for="' + id + '"'), id + " has no label");
});

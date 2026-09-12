// The account menu had a dead link in it on all thirteen pages.
//
// #nav-acct-billing ("Subscription") has been in the markup since the menu was
// built, and a repo-wide search for that id returned only the thirteen copies
// of the markup — no listener, anywhere. Clicking it did nothing at all, which
// is worse than not offering it: the chevron and the item both say something
// will happen. There is a real Stripe billing portal at POST /api/stripe/portal
// that nothing in the chrome ever called.
//
// These tests hold that every item in the menu leads somewhere.
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const glob = require("node:fs").readdirSync;

const ROOT = path.join(__dirname, "..");
const P = (...p) => path.join(ROOT, ...p);

const PAGES = ["index.html", ...glob(P("public")).filter(f => f.endsWith(".html")).map(f => "public/" + f),
               "labs/lens-score/index.html"];

const withMenu = PAGES.filter(p => fs.readFileSync(P(p), "utf8").includes("nav-acct-menu"));
const legacy = fs.readFileSync(P("public", "app-legacy.js"), "utf8");

test("the menu is on every page that has the header", () => {
  assert.ok(withMenu.length >= 13, `only ${withMenu.length} pages carry the account menu`);
});

test("every item in the menu has somewhere to go", () => {
  const html = fs.readFileSync(P(withMenu[0]), "utf8");
  const menu = html.slice(html.indexOf('id="nav-acct-menu"'), html.indexOf("</div>", html.indexOf('id="nav-acct-logout"')));
  // Only the anchors are items; the container and the header block are not.
  const ids = [...menu.matchAll(/<a\b[^>]*id="(nav-acct-[a-z]+)"/g)].map(m => m[1]);
  assert.ok(ids.length >= 4, `menu has only ${ids.length} items`);

  for (const id of ids) {
    const wired = legacy.includes(`getElementById('${id}')`) || legacy.includes(`getElementById("${id}")`);
    const isMailto = new RegExp(`id="${id}"[^>]*href="mailto:`).test(menu)
                  || new RegExp(`href="mailto:[^"]*"[^>]*id="${id}"`).test(menu);
    const inNav = fs.readFileSync(P("public", "app-navigation.js"), "utf8").includes(id);
    assert.ok(wired || isMailto || inNav,
      `${id} is in the menu on ${withMenu.length} pages but nothing listens for it — clicking it does nothing`);
  }
});

test("Subscription reaches the billing portal, and says so when it cannot", () => {
  assert.match(legacy, /nav-acct-billing/, "the Subscription item is still unwired");
  assert.match(legacy, /\/api\/stripe\/portal/, "Subscription does not call the billing portal");
  // The original fault was silence. A failure has to surface.
  const handler = legacy.slice(legacy.indexOf("nav-acct-billing"), legacy.indexOf("nav-acct-feedback"));
  assert.match(handler, /toast\(/, "a failed portal call is silent, which is the bug it replaced");
  assert.match(handler, /showUpgradeModal/, "a free member is sent to a Stripe error instead of the upgrade view");
});

test("Leave a review opens the prompt the product already builds", () => {
  const ps = fs.readFileSync(P("public", "product-system.js"), "utf8");
  assert.match(ps, /window\.ilOpenFeedback\s*=/, "the feedback prompt has no external opener");
  assert.match(legacy, /ilOpenFeedback/, "the menu item does not call it");
});

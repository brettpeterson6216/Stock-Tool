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
const legacy = "";

test("the menu is on every page that has the header", () => {
  assert.ok(withMenu.length >= 13, `only ${withMenu.length} pages carry the account menu`);
});

/* ── the gap that let the original bug survive its own fix ─────────────────
   Every test below this point reads app-legacy.js, and app-legacy.js is loaded
   by index.html and nothing else. So this suite went green while the menu was
   still inert on the thirteen OTHER pages that carry it — including /pricing,
   where a member goes to manage the subscription the menu offers to manage.
   Asserting "something listens" is not enough: it has to be something the page
   in question actually loads, and styling the page actually has. */
const siteNav = fs.readFileSync(P("public", "site-nav.js"), "utf8");
const staticAuth = fs.readFileSync(P("public", "static-auth.js"), "utf8");
const premium = fs.readFileSync(P("public", "research-premium.css"), "utf8");
const staticPages = withMenu.filter(p => !fs.readFileSync(P(p), "utf8").includes("app-legacy.js"));

test("the menu works on pages that never load the app", () => {
  assert.ok(staticPages.length >= 10, `expected the static pages to carry the menu, found ${staticPages.length}`);
  for (const page of staticPages) {
    assert.ok(fs.readFileSync(P(page), "utf8").includes("site-nav.js"),
      `${page} carries the account menu but loads no script that could drive it`);
  }
  // The button has to open the menu at all. That was the whole complaint.
  assert.match(siteNav, /getElementById\("nav-acct-btn"\)/,
    "site-nav.js does not touch the account button, so the menu cannot open off the app");
  assert.match(siteNav, /classList\.add\("open"\)/, "site-nav.js never opens the menu");

  const html = fs.readFileSync(P(staticPages[0]), "utf8");
  const menu = html.slice(html.indexOf('id="nav-acct-menu"'), html.indexOf("</div>", html.indexOf('id="nav-acct-logout"')));
  const ids = [...menu.matchAll(/<a\b[^>]*id="(nav-acct-[a-z]+)"/g)].map(m => m[1]);
  for (const id of ids) {
    const isMailto = new RegExp(`id="${id}"[^>]*href="mailto:`).test(menu)
                  || new RegExp(`href="mailto:[^"]*"[^>]*id="${id}"`).test(menu);
    assert.ok(siteNav.includes(`"${id}"`) || isMailto,
      `${id} does nothing on ${staticPages.length} pages that do not load app-legacy.js`);
  }
});

test("the menu is styled on pages that never load the app", () => {
  /* The popup rules lived in legacy-app.css, which only index.html loads. The
     first attempt at this fix revealed the wrap on a static page and the menu
     rendered EXPANDED and in flow — 253px tall, pushing its own button off the
     top of the window. Markup shared, behaviour shared, stylesheet not. */
  assert.match(premium, /\.nav-acct-menu\s*\{[^}]*display:\s*none\s*!important/,
    "the menu has no hide rule in a sheet the static pages load — it renders expanded");
  assert.match(premium, /\.nav-acct-wrap\.open \.nav-acct-menu\s*\{[^}]*display:\s*block/,
    "nothing opens the menu visually off the app");
  assert.match(premium, /\.nav-acct-menu\s*\{[^}]*position:\s*absolute\s*!important/,
    "the menu is in flow rather than a popup, so it displaces the header");
});

test("the static pages show the real menu, not a lookalike", () => {
  // They used to build their own <a class="il-global-account"> that navigated
  // to saved research, while the app showed a dropdown. Same chip, two
  // behaviours, depending only on which page you were standing on.
  assert.match(staticAuth, /getElementById\("nav-acct-wrap"\)/,
    "static-auth.js never reveals the shared menu, so these pages fall back to a lookalike link");
  assert.match(staticAuth, /nav-acct-name/, "the menu never gets the account name on static pages");
  assert.match(staticAuth, /window\.__ilPlan/,
    "nothing tells the billing item whether there is a subscription to manage");
  assert.match(staticAuth, /account\.hidden/,
    "the lookalike link is still drawn next to the real chip it duplicates");
});

test("billing and log out reach a real endpoint from a static page", () => {
  const billing = siteNav.slice(siteNav.indexOf("nav-acct-billing"), siteNav.indexOf("nav-acct-logout"));
  assert.match(billing, /\/api\/stripe\/portal/, "Subscription does not call the billing portal off the app");
  assert.match(billing, /X-CSRF-Token/, "the portal POST carries no CSRF token, so it will be rejected");
  assert.match(billing, /pricing|mailto/, "a failed or free-plan billing click is silent again");

  const logout = siteNav.slice(siteNav.indexOf("nav-acct-logout"));
  assert.match(logout, /\/api\/auth\/logout/, "Log out does not log anybody out on a static page");
  assert.match(logout, /X-CSRF-Token/, "the logout POST carries no CSRF token");
});


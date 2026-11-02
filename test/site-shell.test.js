"use strict";
/* One bar on every page: older pages get the shell injected and their own
   bar retired; the rebuilt app pages mount it themselves. */
const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");
const { injectShell } = require("../lib/asset-stamp");

const legacy = '<!DOCTYPE html><html lang="en"><head><title>x</title><link rel="stylesheet" href="/a.css"></head><body><nav id="main-nav" class="n" style="display:flex">old</nav><nav class="mobile-bottom-nav" id="mobile-bottom-nav" aria-label="m"></nav><div class="il-mm" id="mobile-more-menu" aria-hidden="true"></div></body></html>';

test("older pages get the shared bar, first stylesheet, and their own bar retired", () => {
  const out = injectShell(legacy);
  assert.match(out, /<html lang="en" class="il-shell-legacy">/);
  assert.ok(out.indexOf("/app/shell.css") < out.indexOf("/a.css"), "shell.css must be the first stylesheet");
  assert.match(out, /<body>\n<il-top id="il-top"><template shadowrootmode="open"><style>/);
  assert.match(out, /<il-tabbar id="il-bottom"><template shadowrootmode="open">[\s\S]*<\/il-tabbar>\n<\/body>/);
  assert.match(out, /<script defer src="\/app\/shell\.js" data-auto data-il-shell><\/script>/);
  for (const id of ["main-nav", "mobile-bottom-nav", "mobile-more-menu"]) {
    const tag = out.match(new RegExp('<[a-z]+[^>]*id="' + id + '"[^>]*>'))[0];
    assert.match(tag, /style="display:none!important" aria-hidden="true" inert>$/, id);
    assert.equal((tag.match(/aria-hidden=/g) || []).length, 1, id);
    assert.equal((tag.match(/style=/g) || []).length, 1, id);
  }
  assert.equal(injectShell(out), out, "injecting twice changes nothing");
});

test("the bar is in the HTML, current tab marked, before any script runs", () => {
  const out = injectShell(legacy, "learn");
  assert.match(out, /data-k="learn" aria-current="page">Learn<\/a>/);
  assert.equal((out.match(/aria-current="page">/g) || []).length, 2, "one tab in the top bar, one in the phone bar");
  // Every account state is in the markup; the page's CSS picks one.
  for (const part of ["guest", "free", "pro", "member", "upgrade", "sun", "moon"]) assert.match(out, new RegExp('part="' + part + '"'), part);
  const app = '<html><head><meta name="il-app" content="1"></head><body><il-top id="il-top"></il-top><main></main><il-tabbar id="il-bottom"></il-tabbar></body></html>';
  const drawn = injectShell(app, "screener");
  assert.match(drawn, /data-k="screener" aria-current="page">/);
  assert.doesNotMatch(drawn, /il-shell-legacy/);
});

test("rebuilt app pages and pages without a bar are left alone", () => {
  const app = '<html><head><meta name="il-app" content="1"></head><body><nav id="main-nav"></nav></body></html>';
  assert.equal(injectShell(app), app, "an app page is never treated as an older page");
  const bare = "<html><head></head><body>hi</body></html>";
  assert.equal(injectShell(bare), bare);
});

test("every app page loads the shell stylesheet before its own styles", () => {
  for (const name of ["home", "research", "screener", "watchlist", "compare"]) {
    const html = fs.readFileSync(path.join(__dirname, "..", "public", "app", name + ".html"), "utf8");
    const links = [...html.matchAll(/rel="stylesheet" href="([^"]+)"/g)].map(m => m[1]);
    assert.equal(links[0], "/app/shell.css", name);
    assert.match(html, /<il-top id="il-top"><\/il-top>/, name);
  }
});

test("sign-up prompts on content pages follow the shared rule", () => {
  const read = f => fs.readFileSync(path.join(__dirname, "..", f), "utf8");
  for (const f of ["public/learn.html", "public/pricing.html", "public/about.html", "index.html"]) {
    const html = read(f).replace(/<nav id="main-nav"[\s\S]*?<\/nav>/, "").replace(/<div class="il-mm"[\s\S]*$/, "");
    for (const m of html.matchAll(/<a\b[^>]*href="\/signup[^"]*"[^>]*>/g)) {
      if (/upgrade-signup-btn|id="nav-/.test(m[0])) continue;
      assert.match(m[0], /data-show="(guest|upgrade)"/, f + ": " + m[0]);
    }
  }
});

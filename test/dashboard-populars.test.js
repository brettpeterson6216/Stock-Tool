"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");
const read = rel => fs.readFileSync(path.join(ROOT, rel), "utf8");

// Someone who opens the dashboard is there to look at a company. The index
// chart is the backdrop to that, and it was taking the top of the column.
test("the companies come before the market chart in the main column", () => {
  const html = read("index.html");
  const column = html.slice(html.indexOf('<div class="ihm-col-main">'));
  const populars = column.indexOf('aria-label="Popular companies"');
  const market = column.indexOf("ihm-market-panel");
  assert.ok(populars > -1 && market > -1, "the dashboard panels moved");
  assert.ok(populars < market, "the market panel is above the companies again");
});

test("every popular company carries a mark, and a fallback when it has none", () => {
  const js = read("public/home-member.js");
  assert.match(js, /ihm-pop-logo/, "no logo tile is rendered");
  assert.match(js, /\/api\/logo\//, "the tile is not pointed at our own logo route");
  assert.match(js, /addEventListener\("error"/, "a missing logo would show a broken-image glyph");
  assert.match(js, /is-mono/, "there is no monogram fallback");

  const css = read("public/clean-pass.css");
  assert.match(css, /\.ihm-pop-logo\.is-mono::before \{\s*content: attr\(data-mono\)/, "the monogram has nothing to draw");
});

// Pointing an <img> straight at a logo host would hand that host the IP and
// user-agent of everyone who loads the dashboard, in exchange for decoration.
test("logos are proxied by us, not hotlinked by the browser", () => {
  const route = read("routes/logo.js");
  assert.doesNotMatch(route, /res\.redirect/, "the route redirects the browser to the provider");
  assert.match(route, /arrayBuffer\(\)/, "the route does not fetch the bytes itself");
  assert.match(route, /\/\^image\\\//, "the route does not check that it got an image");
  assert.match(route, /MAX_BYTES/, "the route has no size ceiling");
  assert.match(route, /remember\(ticker, \{ miss: true \}\)/, "a miss is not cached, so an outage costs a call per view");

  const html = read("index.html");
  assert.doesNotMatch(html, /<img[^>]+src="https?:\/\/(?!impliedlens)/, "a page hotlinks a third-party image");
});

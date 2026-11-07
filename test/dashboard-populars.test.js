"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");
const read = rel => fs.readFileSync(path.join(ROOT, rel), "utf8");

// Someone who opens the dashboard is there to look at a company. The index
// chart is the backdrop to that, and it was taking the top of the column.
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

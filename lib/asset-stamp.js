"use strict";

/* ═══════════════════════════════════════════════════════════════════════════
   Cache-busting that cannot be forgotten.

   Every stylesheet and script on this site is served with
   `Cache-Control: public, max-age=604800` and referenced with a hand-written
   `?v=` token. There are eleven distinct tokens across the HTML - ?v=20260906-8
   on 101 references, ?v=20260907-16 on 22, ?v=4 on 19 - and nothing updates
   them but somebody remembering to. Two deploys in a row changed the contents
   of public/surface.css without changing its token, so every browser that had
   already loaded the page kept serving the old sheet from cache, for up to a
   week, and the fixes did not reach anyone who had visited before.

   The token is now the build: the commit in production, the boot time
   locally. HTML is served with no-cache/must-revalidate already, so a deploy
   changes the token, the token changes every asset URL, and the browser
   fetches the new file. Nothing to remember.
   ═══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs");
const buildInfo = require("./build-info");

const STAMP = buildInfo.shortCommit && buildInfo.shortCommit !== "local"
  ? buildInfo.shortCommit
  : String(Date.parse(buildInfo.startedAt) || Date.now());

/* Only inside href="" and src="", and only for root-relative paths. Written
   without the leading-slash requirement this rewrote
   `https://youtube.com/watch?v=abc123` into `watch?v=<commit>` - a `?v=` is
   legitimate in a link, and an absolute URL is somebody else's cache to
   manage. */
const REPLACE_EXISTING = /(\s(?:href|src)=")(\/[^"?]*)\?v=[^"]*(")/g;
/* And local stylesheets and scripts that were never given a token at all
   still need one, or they keep their seven-day cache across a deploy. */
const ADD_MISSING = /(\s(?:href|src)=")(\/[^":?#]+\.(?:css|js))(")/g;

function stampHtml(html) {
  return String(html)
    .replace(REPLACE_EXISTING, (_m, lead, url, tail) => `${lead}${url}?v=${STAMP}${tail}`)
    .replace(ADD_MISSING, (_m, lead, url, tail) => `${lead}${url}?v=${STAMP}${tail}`);
}

// The files do not change while the process is running, so read once.
const cache = new Map();
function readStamped(absPath) {
  if (!cache.has(absPath)) cache.set(absPath, stampHtml(fs.readFileSync(absPath, "utf8")));
  return cache.get(absPath);
}

function sendPage(res, absPath, status) {
  /* Only if the caller has not already decided. The dev-only LensScore Lab
     sets `no-store` on purpose - it is a prototype that must never be held by
     anything - and overwriting that with the softer no-cache was a real
     regression, caught by the test that asserts it. */
  if (!res.getHeader("Cache-Control")) {
    res.setHeader("Cache-Control", "no-cache, must-revalidate");
  }
  return res.status(status || 200).type("html").send(readStamped(absPath));
}

module.exports = { STAMP, stampHtml, readStamped, sendPage };

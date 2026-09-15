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
const { bundleStyles } = require("./style-delivery");
const { renderProductTemplate } = require("./product-template");

const STAMP = buildInfo.shortCommit && buildInfo.shortCommit !== "local"
  ? buildInfo.shortCommit
  : String(Date.parse(buildInfo.startedAt) || Date.now());

/* Only inside href="" and src="", and only for root-relative paths. Written
   without the leading-slash requirement this rewrote
   `https://youtube.com/watch?v=abc123` into `watch?v=<commit>` - a `?v=` is
   legitimate in a link, and an absolute URL is somebody else's cache to
   manage. */
const REPLACE_EXISTING = /(\s(?:href|src)=")(\/[^"?]*)\?v=[^"]*(")/g;
/* And local stylesheets, scripts and brand images that were never given a
   token at all still need one, or they keep their seven-day cache across a
   deploy. The icons matter as much as the code here: a browser that has the
   old favicon cached will happily show it for a week after the logo changes,
   and a bookmark or a tab keeps it longer than that. */
const ADD_MISSING = /(\s(?:href|src)=")(\/[^":?#]+\.(?:css|js|svg|png|ico|webmanifest))(")/g;
/* And the social card, which lives in meta content="" rather than href="" and
   so was the one asset on the site whose URL could never change.

   Every scraper - X, LinkedIn, Slack, iMessage - caches og:image by URL and
   holds it for a long time. https://impliedlens.com/social-card.png is a fixed
   string, so when the card artwork was replaced, every platform that had ever
   scraped the site kept serving the old picture, and would have kept serving
   it indefinitely: there is no deploy that changes that URL and nothing to
   expire. A link posted to X in September still rendered the card from July.

   Restricted to our own origin and to real image extensions, for the same
   reason ADD_MISSING is restricted to root-relative paths: an absolute URL to
   somebody else's host is their cache to manage, not ours.

   Two origins count as ours, not one: the static pages hardcode the canonical
   https://impliedlens.com, while routes/stock-landing.js builds its tags from
   APP_URL, which is localhost under test and in dev. Match only one and the
   other set of pages goes unstamped - and an unstamped card that only shows up
   in production is exactly the kind of regression nobody sees until it has
   been posted. */
const escapeRe = (t) => t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const OURS = [...new Set([
  String(require("./config").APP_URL || "").replace(/\/+$/, ""),
  "https://impliedlens.com",
])].filter(Boolean);
const STAMP_META_IMAGE = new RegExp(
  '(<meta\\s[^>]*\\scontent=")((?:' + OURS.map(escapeRe).join("|") +
  ')?\\/[^":?#]+\\.(?:png|jpe?g|webp))(")', "gi");

/* ── The four faces the top bar is made of ──────────────────────────────────
   Measured, not guessed: every page's toolbar renders in Plus Jakarta Sans at
   400, 500, 600 and 600-italic, and nothing in it uses 700.

   The pages that preloaded anything preloaded 400 and 700 -- one face the bar
   needs and one it never asks for -- so on a cold load the bar painted in the
   system fallback and relaid out when 500 and 600 finally arrived. That is
   the toolbar "moving for a second" on a tab switch: the tab strip measured
   510px in the fallback and 535px once the real faces landed, a 25px reflow
   on every page in the site. index.html preloaded nothing at all.

   Declared here rather than in twenty heads, because a generated page (the
   Learn set) cannot carry a hand-written link and a hand-written one drifts.
   Unstamped on purpose: il-fonts.css references these files with no version
   query, and a preload whose URL does not match the @font-face src to the
   byte is a second download, not a head start. */
const TOOLBAR_FONTS = [
  "plus-jakarta-sans-latin-400-normal.woff2",
  "plus-jakarta-sans-latin-500-normal.woff2",
  "plus-jakarta-sans-latin-600-normal.woff2",
  "plus-jakarta-sans-latin-600-italic.woff2",
  /* Not in the bar, but it was already preloaded site-wide and the headings
     below the bar use it; dropping it would trade one reflow for another. */
  "plus-jakarta-sans-latin-700-normal.woff2",
];
const FONT_PRELOAD_TAGS = TOOLBAR_FONTS.map(f =>
  `<link rel="preload" as="font" type="font/woff2" crossorigin ` +
  `href="/vendor/fonts/plus-jakarta-sans-files/${f}">`).join("\n");
/* Any hand-written Plus Jakarta preload, stamped or not, so the injected set
   is the only one and a page cannot end up asking for 400 twice. */
const EXISTING_FONT_PRELOAD =
  /[ \t]*<link\b[^>]*\brel=["']preload["'][^>]*\bas=["']font["'][^>]*plus-jakarta[^>]*>\s*/gi;

function injectFontPreloads(html) {
  const stripped = String(html).replace(EXISTING_FONT_PRELOAD, "");
  /* First in <head>: a preload that arrives after the stylesheet link is
     racing the thing it exists to get ahead of. */
  return stripped.replace(/<head(\s[^>]*)?>/i, m => `${m}\n${FONT_PRELOAD_TAGS}`);
}

function stampHtml(html) {
  /* Product tokens first, then bundling and stamping.
     The policy pages state the price, the trial length and the provider names.
     Written as literals they drift the moment any of those change - and a
     Terms page quoting a price you no longer charge is the one page where
     being out of date is a legal problem rather than a cosmetic one. They are
     {{TOKENS}} now, resolved here, in the single funnel every page already
     passes through, so no page can ship raw braces and none can go stale. */
  const stamped = bundleStyles(renderProductTemplate(String(html)))
    .replace(REPLACE_EXISTING, (_m, lead, url, tail) => `${lead}${url}?v=${STAMP}${tail}`)
    .replace(ADD_MISSING, (_m, lead, url, tail) => `${lead}${url}?v=${STAMP}${tail}`)
    .replace(STAMP_META_IMAGE, (_m, lead, url, tail) => `${lead}${url}?v=${STAMP}${tail}`);
  /* Last, so the stamping passes above cannot version these URLs apart from
     the @font-face src they have to match. */
  return injectFontPreloads(stamped);
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

module.exports = { STAMP, TOOLBAR_FONTS, stampHtml, readStamped, sendPage };

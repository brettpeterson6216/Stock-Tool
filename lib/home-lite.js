/* The signed-out home page, without the application.

   index.html is one document for two jobs: the landing page a visitor sees at
   "/", and the research app behind ?view=tool. Every visitor used to download
   both - about 380KB of compressed script (Chart.js, Lightweight Charts, the
   valuation models, the 286KB application controller) for a page that draws
   none of it. On a phone that is most of what stands between the visitor and
   a working page.

   For a signed-out visitor on the plain home page, this serves a copy where
   the scripts between the <!-- il:app-bundle --> markers are held back.
   public/home-lite.js covers the few in-page routes into the app with real
   navigations (which get the full page), and warms the cache with the bundle
   once the landing page is idle, so that navigation is quick.

   Signed-in members, and any URL with a view/section/ticker in it, get the
   full page exactly as before. */
"use strict";

const { STAMP } = require("./asset-stamp");

const BLOCK = /<!--\s*il:app-bundle\b[\s\S]*?-->([\s\S]*?)<!--\s*\/il:app-bundle\s*-->/g;
const SCRIPT_SRC = /<script\b[^>]*\bsrc="([^"]+)"[^>]*><\/script>/g;

/* Query keys that only describe how the visitor arrived. Anything else might
   ask the page to do something (?pricing=1, ?market=1, ?view=tool), so it
   gets the full page. */
const PASSIVE_KEY = /^(utm_[a-z_]+|ref|source|src|s|fbclid|gclid|twclid|mc_cid|mc_eid)$/i;

function isPlainHomeQuery(query) {
  return Object.keys(query || {}).every(k => PASSIVE_KEY.test(k));
}

function wantsLite(req) {
  if (!req || req.method !== "GET") return false;
  if (req.session && req.session.userId) return false;
  return isPlainHomeQuery(req.query);
}

/* html: the already-stamped full page. Returns null when the markers are
   missing, so a template change can never serve a page with no app at all. */
function liteHtml(html) {
  const src = String(html);
  const held = [];
  let found = 0;
  const out = src.replace(BLOCK, (_m, body) => {
    found += 1;
    let m;
    SCRIPT_SRC.lastIndex = 0;
    while ((m = SCRIPT_SRC.exec(body))) held.push(m[1]);
    return "";
  });
  if (found < 2 || !held.length) return null;
  /* An attribute rather than a JSON <script> block: the homepage carries no
     inline script blocks at all (test/smoke.test.js, and the CSP). */
  const list = JSON.stringify(held).replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;");
  const tag = `<script defer src="/home-lite.js?v=${STAMP}" id="il-home-lite" data-bundle="${list}"></script>\n`;
  const at = out.lastIndexOf("</body>");
  if (at < 0) return null;
  return out.slice(0, at) + tag + out.slice(at);
}

module.exports = { wantsLite, liteHtml, isPlainHomeQuery };

/* The signed-out home page.

   index.html used to be one document for two jobs: the landing page and the
   original research app behind ?view=tool. The app has been retired (every
   old link redirects to the page that replaced it, see server.js), so
   index.html is the landing page alone. This adds public/home-lite.js, which
   turns the landing page's few in-page routes into real navigations and
   prefetches the research page on intent, and swaps in the trimmed landing
   stylesheet. Any leftover il:app-bundle block is still held back. */
"use strict";

const { STAMP } = require("./asset-stamp");
const { useLandingCss } = require("./landing-css");

const BLOCK = /<!--\s*il:app-bundle\b[\s\S]*?-->([\s\S]*?)<!--\s*\/il:app-bundle\s*-->/g;
const SCRIPT_SRC = /<script\b[^>]*\bsrc="([^"]+)"[^>]*><\/script>/g;

/* html: the already-stamped landing page. */
function liteHtml(html) {
  const src = String(html);
  const held = [];
  const out = src.replace(BLOCK, (_m, body) => {
    let m;
    SCRIPT_SRC.lastIndex = 0;
    while ((m = SCRIPT_SRC.exec(body))) held.push(m[1]);
    return "";
  });
  /* An attribute rather than a JSON <script> block: the homepage carries no
     inline script blocks at all (test/smoke.test.js, and the CSP). */
  const list = JSON.stringify(held).replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;");
  const tag = `<script defer src="/home-lite.js?v=${STAMP}" id="il-home-lite" data-bundle="${list}"></script>\n`;
  const at = out.lastIndexOf("</body>");
  if (at < 0) return null;
  /* Without the app, the page only needs the landing page's own rules. */
  return useLandingCss(out.slice(0, at) + tag + out.slice(at));
}

module.exports = { liteHtml };

"use strict";

/* ═══════════════════════════════════════════════════════════════════════════
   One header, read from one place.

   Fourteen HTML documents carry the shared <nav id="main-nav"> block, and
   test/header-contract.test.js SHA1s it across all of them so the copies
   cannot drift. The ~103 /stock/:ticker acquisition pages were not one of the
   fourteen: routes/stock-landing.js hand-wrote its own bar, and it had drifted
   badly — nine tabs with retired names (Home, Market, Projections, Planner,
   Saved, and "LensScore", which has been LensToolkit since d82ef52), a "⌕"
   character where the icon goes, a different theme toggle, no account menu at
   all, and none of the stylesheets that make the bar theme-aware.

   Those are the pages Google sends new visitors to. They were the worst copy
   of the header on the site and the most likely to be someone's first
   impression of it.

   Rather than add a fifteenth copy to keep in sync, this reads the canonical
   block out of a document the contract already pins. Any of the fourteen would
   do — they are byte-identical by test — so the choice of file is arbitrary
   and the content is not.
   ═══════════════════════════════════════════════════════════════════════════ */

const fs = require("node:fs");
const path = require("node:path");

const SOURCE = path.join(__dirname, "..", "public", "about.html");
const NAV_RE = /<nav id="main-nav"[\s\S]*?<\/nav>/;

/* The stylesheets and scripts the bar needs to look and behave like itself.
   Taken from the same source document, so a page that adopts the header
   adopts what the header depends on and cannot end up with the markup but
   none of the styling - which is the state /stock/ was in.

   Stylesheets are read with styleLinks(), the same parser lib/style-delivery
   uses to choose a bundle. A hand-rolled regex here found ten of about.html's
   eleven sheets: it missed `<link href="..." rel="stylesheet">`, where the
   attributes are the other way round. Ten of eleven is a set that matches no
   bundle, so every /stock/ page would have shipped eleven separate uncompiled
   requests instead of one. Two parsers, two answers. Use one. */
const { styleLinks } = require("./style-delivery");
const SCRIPT_RE = /<script[^>]*src="\/(?:theme-bootstrap|static-auth|premium-motion|site-nav|ticker-search)[^"]*"[^>]*><\/script>/g;

function readSource() {
  return fs.readFileSync(SOURCE, "utf8");
}

let cache = null;
function header() {
  if (cache) return cache;
  const html = readSource();
  const nav = html.match(NAV_RE);
  if (!nav) throw new Error(`site-header: no #main-nav in ${SOURCE}`);
  cache = {
    nav: nav[0],
    styles: styleLinks(html).map(link => link.tag).join("\n  "),
    scripts: (html.match(SCRIPT_RE) || []).join("\n  "),
  };
  return cache;
}

module.exports = {
  /** The canonical <nav id="main-nav"> block, byte for byte. */
  get nav() { return header().nav; },
  /** Every <link rel="stylesheet"> the shared header expects. */
  get styles() { return header().styles; },
  /** The scripts that give the header its behaviour. */
  get scripts() { return header().scripts; },
  SOURCE,
};

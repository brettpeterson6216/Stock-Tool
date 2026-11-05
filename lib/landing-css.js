"use strict";
/* The signed-out landing page's trimmed stylesheet (scripts/build-landing-css.js).

   It is served in place of the full bundle only while it was cut from exactly
   the bundle index.html uses today: its first line records that bundle's
   sha256. Any stylesheet edit changes the hash, and the landing page goes back
   to the full bundle until the trimmed copy is rebuilt. Never stale, at worst
   slower. */
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { styleLinks } = require("./style-delivery");
const manifest = require("./style-bundles.json");

const ROOT = path.join(__dirname, "..");
const LITE_URL = "/bundles/landing-lite.css";
const LITE_FILE = path.join(ROOT, "public", LITE_URL);
const HEADER = /^\/\* landing-lite from (\S+) sha256=([0-9a-f]{64}) /;

/* Git may check text out with CRLF on Windows; line endings alone do not
   make the trimmed copy stale. */
function hashOf(text) { return crypto.createHash("sha256").update(String(text).replace(/\r\n/g, "\n")).digest("hex"); }

function landingBundle() {
  const links = styleLinks(fs.readFileSync(path.join(ROOT, "index.html"), "utf8"));
  const url = manifest[links.map(l => l.href).join("|")];
  return url ? { url, file: path.join(ROOT, "public", url) } : null;
}

/* { ok, url, reason } — ok when the trimmed copy matches the current bundle. */
function status() {
  try {
    const bundle = landingBundle();
    if (!bundle) return { ok: false, reason: "index.html has no bundle" };
    if (!fs.existsSync(LITE_FILE)) return { ok: false, reason: "landing-lite.css is missing" };
    const head = fs.readFileSync(LITE_FILE, "utf8").slice(0, 300).match(HEADER);
    if (!head) return { ok: false, reason: "landing-lite.css has no source header" };
    if (head[1] !== bundle.url) return { ok: false, reason: `cut from ${head[1]}, the page now uses ${bundle.url}` };
    if (head[2] !== hashOf(fs.readFileSync(bundle.file, "utf8"))) return { ok: false, reason: `${bundle.url} changed since it was cut` };
    return { ok: true, url: LITE_URL, bundle: bundle.url };
  } catch (e) { return { ok: false, reason: e.message }; }
}

/* html: the stamped landing page. Swaps the full bundle's link for the trimmed
   one when it is current; otherwise returns html untouched. */
function useLandingCss(html) {
  if (process.env.IL_LANDING_CSS === "full") return html;
  const s = status();
  if (!s.ok) return html;
  const re = new RegExp(`(<link rel="stylesheet" href=")${s.bundle.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(\\?v=[^"]*)?(")`);
  return html.replace(re, `$1${LITE_URL}$2$3`);
}

module.exports = { status, useLandingCss, landingBundle, hashOf, LITE_URL, LITE_FILE };

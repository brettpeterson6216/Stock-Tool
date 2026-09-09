"use strict";

// The HTML remains the ordered source of truth. The release build combines its
// stylesheets without changing their cascade or moving relative font/image URLs.
const manifest = require("./style-bundles.json");
const LINK = /<link\b[^>]*>/gi;
function styleLinks(html) {
  return [...String(html).matchAll(LINK)].flatMap(match => {
    const tag = match[0];
    if (!/\brel\s*=\s*["']stylesheet["']/i.test(tag) || /\b(?:media|disabled|alternate)\b/i.test(tag)) return [];
    const href = tag.match(/\bhref\s*=\s*["']([^"']+)["']/i)?.[1];
    if (!href || !href.startsWith("/") || href.startsWith("//")) return [];
    return [{ tag, href: href.split("?")[0].replace("/__lab/lens-score/assets/", "/lens-score/assets/") }];
  });
}
function bundleStyles(html) {
  const links = styleLinks(html);
  const bundle = manifest[links.map(link => link.href).join("|")];
  if (!bundle) return html;
  let first = true;
  for (const link of links) {
    html = html.replace(link.tag, first ? `<link rel="stylesheet" href="${bundle}">` : "");
    first = false;
  }
  return html;
}
module.exports = { styleLinks, bundleStyles };

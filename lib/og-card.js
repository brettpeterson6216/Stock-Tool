"use strict";
/* ═══════════════════════════════════════════════════════════════════════════
   The share image for a stock: what X, iMessage, Slack and the rest show when
   someone posts impliedlens.com/research/TICKER.

   It is the Lens Report card from the stock page, drawn on the server so a
   link preview gets it without running any script: the engraved plate, the
   ticker and company, the price, the past year and market cap, and on the
   right the LensScore with its sector rank and the five grades set as type.

   Rendered from an SVG with resvg (no browser, no system fonts: the fonts in
   assets/og-fonts are the site's own, converted to TrueType). Only figures
   we hold are drawn; anything missing is left out, never estimated.
   ═══════════════════════════════════════════════════════════════════════════ */
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.join(__dirname, "..", "assets");
const FONT_DIR = path.join(ROOT, "og-fonts");
const W = 1200, H = 630;

let Resvg = null, fontFiles = null, plate = null;
function engine() {
  if (!Resvg) {
    ({ Resvg } = require("@resvg/resvg-js"));
    fontFiles = fs.readdirSync(FONT_DIR).filter(f => f.endsWith(".ttf")).map(f => path.join(FONT_DIR, f));
    plate = "data:image/jpeg;base64," + fs.readFileSync(path.join(ROOT, "og-engraved.jpg")).toString("base64");
  }
  return Resvg;
}

const C = {
  text: "#EDEEF0", t2: "#A3A9B1", t3: "#7D848D", gold: "#E5B65A", gain: "#4CC38A", loss: "#E06A6A",
};
const SANS = "Inter", NUM = "IBM Plex Sans", SERIF = "Instrument Serif";

function esc(s) { return String(s == null ? "" : s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])); }
function finite(v) { return typeof v === "number" && Number.isFinite(v); }
function money(v) {
  if (!finite(v)) return "";
  return "$" + v.toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 });
}
function bigMoney(v) {
  if (!finite(v) || v <= 0) return "";
  const u = [[1e12, "T"], [1e9, "B"], [1e6, "M"]].find(([n]) => v >= n);
  return u ? "$" + (v / u[0]).toFixed(v / u[0] >= 100 ? 0 : v / u[0] >= 10 ? 1 : 2) + u[1] : "$" + Math.round(v).toLocaleString("en-US");
}
function signed(v, d) { return (v >= 0 ? "+" : "−") + Math.abs(v).toFixed(d) + "%"; }
/* Rough width of a string in Inter, for fitting long names. */
function approxWidth(s, px) { return String(s).length * px * 0.56; }
function fitName(name, px, max) {
  const full = String(name || "").replace(/\s+(Common Stock|Ordinary Shares|Class [A-Z]\b).*$/i, "").trim();
  if (approxWidth(full, px) <= max) return full;
  let s = "";
  for (const w of full.split(/\s+/)) { if (approxWidth((s ? s + " " : "") + w + "\u2026", px) > max) break; s = s ? s + " " + w : w; }
  return (s || full.slice(0, Math.floor(max / (px * 0.56)) - 1)).replace(/[\s,.&-]+$/, "") + "\u2026";
}

function text(x, y, str, { size, weight = 500, family = SANS, fill = C.text, anchor = "start", spacing = 0, italic = false } = {}) {
  if (str === "" || str == null) return "";
  return `<text x="${x}" y="${y}" font-family="${family}" font-size="${size}" font-weight="${weight}"${italic ? ' font-style="italic"' : ""} fill="${fill}" text-anchor="${anchor}"${spacing ? ` letter-spacing="${spacing}"` : ""}>${esc(str)}</text>`;
}

const GRADE_FILL = { A: C.text, B: "#CDD1D6", C: C.t2, D: C.t3, F: C.t3 };
const FACTORS = [["value", "Value"], ["growth", "Growth"], ["profitability", "Profit"], ["health", "Health"], ["momentum", "Momentum"]];

/* d: { ticker, name, sectorName, price, changePct, yearPct, marketCap, score, label, rank: {position, of}, grades, asOf, url } */
function svgFor(d) {
  engine();
  const date = new Date(d.asOf || Date.now()).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric", timeZone: "America/New_York" }).toUpperCase();
  const tickerPx = d.ticker.length > 5 ? 60 : 72;
  const name = fitName(d.name, 24, 400);
  const parts = [];

  // Plate and the veils that keep both text columns readable.
  parts.push(`<image href="${plate}" x="0" y="0" width="${W}" height="${H}" preserveAspectRatio="xMidYMid slice"/>`);
  parts.push(`<defs>
    <linearGradient id="vl" x1="0" x2="1" y1="0" y2="0"><stop offset="0" stop-color="#10110F" stop-opacity=".88"/><stop offset=".62" stop-color="#10110F" stop-opacity=".74"/><stop offset=".86" stop-color="#10110F" stop-opacity=".28"/><stop offset="1" stop-color="#10110F" stop-opacity="0"/></linearGradient>
    <linearGradient id="vr" x1="0" x2="1" y1="0" y2="0"><stop offset="0" stop-color="#10110F" stop-opacity="0"/><stop offset=".3" stop-color="#10110F" stop-opacity=".6"/><stop offset=".55" stop-color="#10110F" stop-opacity=".82"/><stop offset="1" stop-color="#10110F" stop-opacity=".88"/></linearGradient>
    <linearGradient id="vb" x1="0" x2="0" y1="0" y2="1"><stop offset="0" stop-color="#10110F" stop-opacity="0"/><stop offset=".45" stop-color="#10110F" stop-opacity=".8"/><stop offset="1" stop-color="#10110F" stop-opacity=".94"/></linearGradient>
  </defs>`);
  parts.push(`<rect x="0" y="0" width="600" height="${H}" fill="url(#vl)"/>`);
  parts.push(`<rect x="740" y="0" width="${W - 740}" height="${H}" fill="url(#vr)"/>`);
  parts.push(`<rect x="0" y="540" width="${W}" height="${H - 540}" fill="url(#vb)"/>`);

  // Header.
  parts.push(`<text x="48" y="56" font-family="${SANS}" font-size="23" font-weight="700" fill="${C.text}">Implied<tspan font-family="${SERIF}" font-style="italic" font-weight="400" font-size="27" fill="${C.gold}">Lens</tspan></text>`);
  parts.push(text(1152, 54, "LENS REPORT  ·  " + date, { size: 13, weight: 500, fill: C.t2, anchor: "end", spacing: 1 }));

  // Identity.
  parts.push(text(48, 92, String(d.sectorName || "").toUpperCase(), { size: 12, weight: 500, fill: C.t2, spacing: 1.2 }));
  parts.push(text(46, 92 + tickerPx + 4, d.ticker, { size: tickerPx, weight: 700, spacing: -1.5 }));
  parts.push(text(48, 204, name, { size: 24, weight: 500, fill: C.t2 }));

  // Price and today's move.
  if (finite(d.price)) {
    const p = money(d.price);
    parts.push(text(48, 262, p, { size: 40, weight: 600, family: NUM }));
    if (finite(d.changePct)) parts.push(text(48 + approxWidth(p, 40) * 1.02 + 14, 258, signed(d.changePct, 2) + " today", { size: 20, weight: 500, family: NUM, fill: d.changePct >= 0 ? C.gain : C.loss }));
  }

  // Past year and size.
  const stats = [];
  if (finite(d.yearPct)) stats.push(["PAST YEAR", signed(d.yearPct, 1), d.yearPct >= 0 ? C.gain : C.loss]);
  if (finite(d.marketCap) && d.marketCap > 0) stats.push(["MARKET CAP", bigMoney(d.marketCap), C.text]);
  stats.forEach(([k, v, fill], i) => {
    const x = 48 + i * 204;
    parts.push(text(x, 330, k, { size: 13, weight: 600, fill: C.t2, spacing: 1.1 }));
    parts.push(text(x, 378, v, { size: 38, weight: 600, family: NUM, fill }));
  });
  parts.push(text(48, 416, "Five grades against sector peers, from SEC filings and a year of prices.", { size: 13, weight: 400, fill: C.t3 }));

  // Right column: the LensScore, its rank, the five grades.
  const cx = 1000;
  parts.push(text(cx, 140, "LENSSCORE", { size: 14, weight: 600, fill: C.t2, anchor: "middle", spacing: 1.6 }));
  if (finite(d.score)) {
    parts.push(`<text x="${cx - 6}" y="262" font-family="${NUM}" font-size="128" font-weight="600" fill="${C.gold}" text-anchor="middle" letter-spacing="-3">${esc(d.score.toFixed(1))}</text>`);
    parts.push(text(cx + 100, 262, "/10", { size: 24, weight: 500, family: NUM, fill: C.t2 }));
  }
  if (d.label) parts.push(text(cx, 312, d.label, { size: 22, weight: 600, anchor: "middle" }));
  if (d.rank && d.rank.position && d.rank.of) parts.push(text(cx, 344, `#${d.rank.position} of ${d.rank.of}  ·  ${d.sectorName || ""}`, { size: 17, weight: 500, fill: C.t2, anchor: "middle" }));
  parts.push(`<rect x="840" y="384" width="312" height="1" fill="#FFFFFF" fill-opacity=".12"/>`);
  FACTORS.forEach(([k, label], i) => {
    const x = 844 + i * 68;
    const g = d.grades && d.grades[k] ? String(d.grades[k]) : "—";
    parts.push(text(x + 14, 420, label, { size: 12, weight: 500, fill: C.t2, anchor: "middle" }));
    parts.push(text(x + 14, 456, g.replace("-", "−"), { size: 24, weight: 600, family: NUM, fill: GRADE_FILL[g.charAt(0)] || C.t3, anchor: "middle" }));
  });

  // Footer.
  parts.push(`<rect x="48" y="566" width="1104" height="1" fill="#FFFFFF" fill-opacity=".1"/>`);
  parts.push(text(48, 604, d.url, { size: 20, weight: 600 }));
  parts.push(text(1152, 602, "Educational research · not investment advice", { size: 14, weight: 400, fill: C.t2, anchor: "end" }));

  return `<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}"><rect width="${W}" height="${H}" fill="#10110F"/>${parts.join("")}</svg>`;
}

function render(d) {
  const R = engine();
  const svg = svgFor(d);
  const r = new R(svg, {
    font: { fontFiles, loadSystemFonts: false, defaultFontFamily: SANS },
    fitTo: { mode: "width", value: W },
  });
  return r.render().asPng();
}

module.exports = { render, svgFor, bigMoney };

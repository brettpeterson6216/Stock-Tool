"use strict";
/* GET /og/research/:ticker.png — the link-preview image for a stock page
   (lib/og-card.js). Built from figures the server already holds: the graded
   universe for the score, rank and grades, the screener's daily snapshot for
   the price and day move, the SEC-derived metrics for the past year and size.
   A ticker we do not grade gets the site's general card instead. */
const express = require("express");
const { normalizeTicker } = require("../lib/plan");
const universeGrades = require("../lib/universe-grades");
const peers = require("../lib/peer-universe");
const og = require("../lib/og-card");

const router = express.Router();
const TTL_MS = 6 * 3600 * 1000;
const MAX = 40;                         // each image is about 1 MB; keep the busy ones
const cache = new Map();

function dataFor(ticker, base) {
  const g = universeGrades.get(ticker);
  if (!g || !Number.isFinite(g.score)) return null;
  const peer = peers.get(ticker) || {};
  const m = peer.m || {};
  let snap = null;
  try { snap = require("./market-data").snapshotFor(ticker); } catch (_) {}
  const nameFromIndex = (() => { try { return require("../lib/ticker-index").nameFor(ticker); } catch (_) { return ""; } })();
  return {
    ticker,
    name: nameFromIndex || g.name || ticker,
    sectorName: g.sectorName,
    groupName: g.groupName || g.sectorName,
    price: snap && Number.isFinite(snap.price) ? snap.price : (Number.isFinite(g.price) ? g.price : null),
    changePct: snap && Number.isFinite(snap.change1D) ? snap.change1D : null,
    yearPct: Number.isFinite(m["52WeekPriceReturnDaily"]) ? m["52WeekPriceReturnDaily"] : (snap && Number.isFinite(snap.change1Y) ? snap.change1Y : null),
    marketCap: Number.isFinite(g.marketCap) ? g.marketCap : null,
    score: g.score,
    label: g.label,
    rank: g.groupRank ? { position: g.groupRank, of: g.groupCount } : null,
    grades: g.grades,
    url: `${base.replace(/^https?:\/\//, "")}/research/${ticker}`,
  };
}

router.get("/og/research/:file", (req, res) => {
  const ticker = normalizeTicker(String(req.params.file || "").replace(/\.png$/i, ""));
  if (!ticker) return res.status(404).end();
  const base = String(process.env.APP_URL || "https://impliedlens.com").replace(/\/$/, "");
  const hit = cache.get(ticker);
  if (hit && Date.now() - hit.at < TTL_MS) return send(res, hit.png);
  const d = dataFor(ticker, base);
  if (!d) return res.redirect(302, "/social-card.png");
  try {
    const png = og.render(d);
    if (cache.size >= MAX) cache.delete(cache.keys().next().value);
    cache.set(ticker, { at: Date.now(), png });
    return send(res, png);
  } catch (error) {
    console.warn("[og-image]", ticker, String(error?.message || error).slice(0, 160));
    return res.redirect(302, "/social-card.png");
  }
});
function send(res, png) {
  res.set("Content-Type", "image/png");
  res.set("Cache-Control", "public, max-age=21600");
  return res.send(png);
}

module.exports = router;
module.exports.dataFor = dataFor;

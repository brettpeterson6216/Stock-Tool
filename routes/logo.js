// ============================================================
//  Company logos
//    GET /api/logo/:ticker      (free, cached, proxied)
// ============================================================
// The popular-companies row was eight ticker strings in a column. A logo is
// what makes a list of companies scannable rather than read.
//
// The image is proxied rather than hotlinked. Pointing an <img> at a logo host
// would hand that host the IP and user-agent of every visitor who loads the
// dashboard, for decoration; and it would put a third party in the render path
// of the first screen after sign-in. Fetching it here means one request per
// ticker per day from one machine, and a 404 the client can style around.
const express = require("express");

const { FINNHUB_KEY } = require("../lib/config");
const { normalizeTicker } = require("../lib/plan");

const router = express.Router();

const TTL_MS = 24 * 60 * 60 * 1000;
const MAX_ENTRIES = 300;
const MAX_BYTES = 256 * 1024;
const cache = new Map();               // ticker -> { buf, type, ts } | { miss: true, ts }

function remember(key, value) {
  if (cache.size >= MAX_ENTRIES) {
    const oldest = cache.keys().next().value;
    if (oldest) cache.delete(oldest);
  }
  cache.set(key, Object.assign({ ts: Date.now() }, value));
}

async function withTimeout(url, options, ms) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ms);
  try { return await fetch(url, Object.assign({ signal: controller.signal }, options)); }
  finally { clearTimeout(timer); }
}

/** The provider's logo URL for a ticker, or "" — never anything but https. */
async function logoUrlFor(ticker) {
  if (!FINNHUB_KEY) return "";
  const response = await withTimeout(
    `https://finnhub.io/api/v1/stock/profile2?symbol=${encodeURIComponent(ticker)}&token=${FINNHUB_KEY}`,
    {}, 4000
  );
  if (!response.ok) return "";
  const profile = await response.json();
  const url = String((profile && profile.logo) || "").trim();
  return /^https:\/\/[^\s"']+$/i.test(url) ? url : "";
}

router.get("/logo/:ticker", async (req, res) => {
  const ticker = normalizeTicker(req.params.ticker);
  if (!ticker) return res.status(400).json({ error: "Invalid ticker." });

  const hit = cache.get(ticker);
  if (hit && Date.now() - hit.ts < TTL_MS) {
    if (hit.miss) return res.status(404).end();
    res.set("Content-Type", hit.type);
    res.set("Cache-Control", "public, max-age=86400");
    return res.send(hit.buf);
  }

  try {
    const url = await logoUrlFor(ticker);
    if (!url) { remember(ticker, { miss: true }); return res.status(404).end(); }

    const image = await withTimeout(url, {}, 5000);
    const type = String(image.headers.get("content-type") || "");
    if (!image.ok || !/^image\//i.test(type)) { remember(ticker, { miss: true }); return res.status(404).end(); }

    const buf = Buffer.from(await image.arrayBuffer());
    // A logo is a few KB. Anything much larger is not what was asked for.
    if (!buf.length || buf.length > MAX_BYTES) { remember(ticker, { miss: true }); return res.status(404).end(); }

    remember(ticker, { buf, type: type.split(";")[0] });
    res.set("Content-Type", type.split(";")[0]);
    res.set("Cache-Control", "public, max-age=86400");
    res.send(buf);
  } catch {
    // A miss is cached too: without that, a provider outage means one upstream
    // call per ticker per page view for as long as it lasts.
    remember(ticker, { miss: true });
    res.status(404).end();
  }
});

module.exports = router;
module.exports._cache = cache;

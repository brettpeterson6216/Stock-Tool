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
const MAX_ENTRIES = 1200;              // the graded universe plus room; a logo is a few KB
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

/* Logo source, in order:
     1. Logo.dev by ticker, when LOGO_DEV_TOKEN is set (a publishable "pk_"
        key from logo.dev). Their terms let us cache the image and serve it
        ourselves, which this route does: one fetch per ticker per day, and
        visitors never connect to a third party. The free plan asks for an
        attribution link, which the app footer carries.
     2. Finnhub's company profile, only where Finnhub is licensed.
   fallback=404 makes Logo.dev answer "no logo" instead of drawing its own
   lettermark, so the page can show ours. */
function logoDevToken() {
  const t = String(process.env.LOGO_DEV_TOKEN || "").trim();
  return /^pk_[A-Za-z0-9_-]{8,}$/.test(t) ? t : "";
}
function logoSource() { return logoDevToken() ? "logo.dev" : (FINNHUB_KEY && require("../lib/data-policy").finnhubAllowed() ? "finnhub" : null); }

/** The provider's logo URL for a ticker, or "" — never anything but https. */
async function logoUrlFor(ticker) {
  const token = logoDevToken();
  if (token) {
    return `https://img.logo.dev/ticker/${encodeURIComponent(ticker)}?token=${encodeURIComponent(token)}&size=128&format=png&retina=true&fallback=404`;
  }
  if (!FINNHUB_KEY || !require("../lib/data-policy").finnhubAllowed()) return "";
  const response = await withTimeout(
    `https://finnhub.io/api/v1/stock/profile2?symbol=${encodeURIComponent(ticker)}&token=${FINNHUB_KEY}`,
    {}, 4000
  );
  if (!response.ok) return "";
  const profile = await response.json();
  const url = String((profile && profile.logo) || "").trim();
  return /^https:\/\/[^\s"']+$/i.test(url) ? url : "";
}

/* Whether logos are switched on, so pages do not ask for hundreds of
   images that can only 404. */
router.get("/logo-status", (_req, res) => {
  res.set("Cache-Control", "public, max-age=3600");
  res.json({ enabled: Boolean(logoSource()), source: logoSource() });
});

/* A miss is remembered by the browser for a day too. */
function notFound(res) { res.set("Cache-Control", "public, max-age=86400"); return res.status(404).end(); }

router.get("/logo/:ticker", async (req, res) => {
  const ticker = normalizeTicker(req.params.ticker);
  if (!ticker) return res.status(400).json({ error: "Invalid ticker." });
  if (!logoSource()) return notFound(res);

  const hit = cache.get(ticker);
  if (hit && Date.now() - hit.ts < TTL_MS) {
    if (hit.miss) return notFound(res);
    res.set("Content-Type", hit.type);
    res.set("Cache-Control", "public, max-age=86400");
    return res.send(hit.buf);
  }

  try {
    const url = await logoUrlFor(ticker);
    if (!url) { remember(ticker, { miss: true }); return notFound(res); }

    const image = await withTimeout(url, {}, 5000);
    const type = String(image.headers.get("content-type") || "");
    if (!image.ok || !/^image\//i.test(type)) { remember(ticker, { miss: true }); return notFound(res); }

    const buf = Buffer.from(await image.arrayBuffer());
    // A logo is a few KB. Anything much larger is not what was asked for.
    if (!buf.length || buf.length > MAX_BYTES) { remember(ticker, { miss: true }); return notFound(res); }

    remember(ticker, { buf, type: type.split(";")[0] });
    res.set("Content-Type", type.split(";")[0]);
    res.set("Cache-Control", "public, max-age=86400");
    res.send(buf);
  } catch {
    // A miss is cached too: without that, a provider outage means one upstream
    // call per ticker per page view for as long as it lasts.
    remember(ticker, { miss: true });
    notFound(res);
  }
});

module.exports = router;
module.exports._cache = cache;
module.exports.logoSource = logoSource;

"use strict";
/* ═══════════════════════════════════════════════════════════════════════════
   What a company's SEC filings tell us beyond the numbers:

     · insider trades: officers', directors' and 10% owners' open-market buys
       and sales, parsed from their Form 4 filings (last 12 months);
     · the next earnings date, estimated from when the company published
       results before (8-K Item 2.02 "Results of Operations", or the 10-Q/10-K
       when it files no such 8-K). It is labelled as an estimate everywhere.

   Both come from SEC EDGAR, which is public and free to use commercially.
   ═══════════════════════════════════════════════════════════════════════════ */

const sec = require("./sec-fundamentals");

const MS_DAY = 864e5;
const finite = v => v !== null && v !== undefined && v !== "" && Number.isFinite(Number(v));

/* ── next earnings (pure) ──────────────────────────────────────────────── */
function weekday(dayStr) {
  let d = new Date(dayStr + "T12:00:00Z");
  while ([0, 6].includes(d.getUTCDay())) d = new Date(d.getTime() + MS_DAY);
  return d.toISOString().slice(0, 10);
}
/* Estimate the next results date from past release dates: the release one
   year before the next one (same weekday, 52 weeks on) is the best guide;
   failing that, about 13 weeks after the latest release. */
function estimateNextEarnings(filings, today = new Date().toISOString().slice(0, 10)) {
  const releases = (filings || [])
    .filter(f => (f.form === "8-K" && /(^|,)\s*2\.02/.test(f.items || "")))
    .map(f => f.filingDate).filter(Boolean);
  const periodic = (filings || []).filter(f => /^(10-Q|10-K)$/.test(f.form || "")).map(f => f.filingDate).filter(Boolean);
  const dates = [...new Set(releases.length >= 2 ? releases : periodic)].sort();
  if (!dates.length) return null;
  const t0 = Date.parse(today + "T12:00:00Z");
  const plus = (d, days) => new Date(Date.parse(d + "T12:00:00Z") + days * MS_DAY).toISOString().slice(0, 10);
  const candidates = dates.map(d => plus(d, 364)).filter(d => d >= today).sort();
  // A release a year ago that is still ahead of us this year, within ~5 months.
  let date = candidates.find(d => (Date.parse(d + "T12:00:00Z") - t0) / MS_DAY <= 150) || null;
  const latest = dates.at(-1);
  if (!date) {
    date = plus(latest, 91);
    while (date < today) date = plus(date, 91);
  }
  // Not before 30 days after the latest release (the next quarter isn't done).
  if ((Date.parse(date + "T12:00:00Z") - Date.parse(latest + "T12:00:00Z")) / MS_DAY < 30) date = plus(latest, 91);
  date = weekday(date);
  const days = Math.round((Date.parse(date + "T12:00:00Z") - t0) / MS_DAY);
  return { date, days, estimated: true, basis: releases.length >= 2 ? "past earnings releases (8-K Item 2.02)" : "past 10-Q/10-K filing dates", lastRelease: latest, when: null };
}

/* ── Form 4 (pure parser) ──────────────────────────────────────────────── */
/* Text of the first <name> element: its <value> child when it has one
   (footnote references may sit beside it), else its own text. */
function tag(xml, name) {
  const block = new RegExp(`<${name}(?:\\s[^>]*)?>([\\s\\S]*?)</${name}>`, "i").exec(xml || "");
  if (!block) return null;
  const inner = block[1];
  const v = /<value>([\s\S]*?)<\/value>/i.exec(inner);
  const text = (v ? v[1] : inner.replace(/<[^>]+>/g, "")).trim();
  return text || null;
}
function decodeXml(s) {
  return String(s || "").replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#39;|&apos;/g, "'");
}
/* Open-market purchases (P) and sales (S) from one Form 4 document. */
function parseForm4(xml) {
  const owner = decodeXml(tag(xml, "rptOwnerName")) || null;
  const rel = /<reportingOwnerRelationship>([\s\S]*?)<\/reportingOwnerRelationship>/i.exec(xml || "")?.[1] || "";
  const flag = n => /^(1|true)$/i.test(tag(rel, n) || "");
  const title = decodeXml(tag(rel, "officerTitle")) || null;
  const role = flag("isOfficer") ? (title || "Officer") : flag("isDirector") ? "Director" : flag("isTenPercentOwner") ? "10% owner" : (flag("isOther") ? "Other" : null);
  const out = [];
  const re = /<nonDerivativeTransaction>([\s\S]*?)<\/nonDerivativeTransaction>/gi;
  let m;
  while ((m = re.exec(xml || ""))) {
    const t = m[1];
    const code = tag(t, "transactionCode");
    if (code !== "P" && code !== "S") continue;
    const shares = Number(tag(t, "transactionShares"));
    const priceText = tag(t, "transactionPricePerShare");
    const price = priceText == null ? NaN : Number(priceText);
    const ad = tag(t, "transactionAcquiredDisposedCode");
    const date = tag(t, "transactionDate");
    if (!finite(shares) || shares <= 0 || !date) continue;
    out.push({
      name: owner, role, code, date: date.slice(0, 10),
      change: ad === "D" || code === "S" ? -shares : shares,
      price: finite(price) && price > 0 ? price : null,
      share: tag(t, "sharesOwnedFollowingTransaction") != null && finite(tag(t, "sharesOwnedFollowingTransaction")) ? Number(tag(t, "sharesOwnedFollowingTransaction")) : null,
    });
  }
  return out;
}

/* Raw XML location of a Form 4 listed in the submissions index. The listed
   primaryDocument is the XSL-rendered view ("xslF345X05/form4.xml"); the raw
   file has the same name without the style-sheet folder. */
function form4Url(cik, filing) {
  const acc = String(filing.accession || "").replace(/-/g, "");
  const doc = String(filing.primaryDocument || "").split("/").pop();
  if (!acc || !doc) return null;
  return `https://www.sec.gov/Archives/edgar/data/${Number(cik)}/${acc}/${doc}`;
}

const insiderCache = new Map();
async function insiderTrades(ticker, { maxFilings = 40 } = {}) {
  const t = String(ticker || "").toUpperCase();
  const hit = insiderCache.get(t);
  if (hit && Date.now() - hit.at < 6 * 3600 * 1000) return hit.data;
  const id = await sec.cikFor(t);
  if (!id) throw new Error("No SEC filer for this ticker.");
  const sub = await sec.submissions(t);
  const since = new Date(Date.now() - 365 * MS_DAY).toISOString().slice(0, 10);
  const form4s = sec.recentFilings(sub).filter(f => f.form === "4" && f.filingDate >= since).slice(0, maxFilings);
  const trades = [];
  for (const f of form4s) {
    const url = form4Url(id.cik, f);
    if (!url) continue;
    try { trades.push(...parseForm4(await sec.secText(url)).map(x => ({ ...x, filed: f.filingDate, source: url }))); }
    catch (_) { /* skip one unreadable filing */ }
  }
  trades.sort((a, b) => b.date.localeCompare(a.date));
  const buys = trades.filter(x => x.code === "P"), sells = trades.filter(x => x.code === "S");
  const value = list => list.reduce((s, x) => s + (x.price ? Math.abs(x.change) * x.price : 0), 0);
  const data = {
    insiders: trades,
    insiderSummary: { buys: buys.length, sells: sells.length, buyValue: value(buys), sellValue: value(sells), since },
    filingsRead: form4s.length,
    truncated: sec.recentFilings(sub).filter(f => f.form === "4" && f.filingDate >= since).length > form4s.length,
  };
  insiderCache.set(t, { at: Date.now(), data });
  if (insiderCache.size > 300) insiderCache.delete(insiderCache.keys().next().value);
  return data;
}

async function nextEarnings(ticker) {
  const sub = await sec.submissions(ticker);
  return estimateNextEarnings(sec.recentFilings(sub));
}

module.exports = { estimateNextEarnings, parseForm4, form4Url, insiderTrades, nextEarnings };

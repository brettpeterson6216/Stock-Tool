"use strict";
/* ═══════════════════════════════════════════════════════════════════════════
   Earnings materials from SEC EDGAR.

   Every US-listed company files its quarterly results press release with the
   SEC: an 8-K with Item 2.02 ("Results of Operations"), the release attached
   as Exhibit 99.1. This module lists those releases, puts each one beside the
   quarter it reports (revenue, net income and diluted EPS from XBRL, with the
   change from a year earlier) and the 10-Q or 10-K that followed, and reads
   the release text so it can be shown on the page.

   It also maps any quarter end to the 10-Q/10-K that reported it, which the
   quarterly statement tables use for their filing links.

   SEC EDGAR filings are public and free to use commercially.
   ═══════════════════════════════════════════════════════════════════════════ */

const sec = require("./sec-fundamentals");
const { buildQuarterlyHistory, adjustForSplits } = require("./fundamentals-history");

const MS_DAY = 864e5;
const daysBetween = (a, b) => (Date.parse(b + "T12:00:00Z") - Date.parse(a + "T12:00:00Z")) / MS_DAY;
const finite = v => typeof v === "number" && Number.isFinite(v);

function archiveBase(cik, accession) {
  return `https://www.sec.gov/Archives/edgar/data/${Number(cik)}/${String(accession).replace(/-/g, "")}`;
}
function filingUrl(cik, f) {
  return f.primaryDocument ? `${archiveBase(cik, f.accession)}/${f.primaryDocument}` : `${archiveBase(cik, f.accession)}/`;
}

/* Pure: the 10-Q/10-K whose period is this quarter end (reportDate within a
   week of it; 52/53-week years end a few days off the calendar). Amendments
   are used only when no original is listed. */
function periodicFilingFor(filings, end) {
  const near = (filings || []).filter(f => /^10-[QK]/.test(f.form || "") && f.reportDate && Math.abs(daysBetween(f.reportDate, end)) <= 7);
  return near.find(f => !/\/A$/.test(f.form)) || near[0] || null;
}

/* Pure: the quarter a results release reports: the latest quarter that ended
   before the release, no more than ~100 days before it. */
function quarterForRelease(quarters, releaseDate) {
  let best = null;
  for (const q of quarters || []) {
    const gap = daysBetween(q.end, releaseDate);
    if (gap >= 0 && gap <= 100 && (!best || q.end > best.end)) best = q;
  }
  return best;
}

function yoy(quarters, q, key) {
  const idx = quarters.indexOf(q);
  const ago = idx >= 4 ? quarters[idx - 4] : null;
  if (!ago || !finite(q[key]) || !finite(ago[key]) || ago[key] === 0) return null;
  // A change from a loss is not a percentage anyone can read.
  if (ago[key] < 0) return null;
  return (q[key] / ago[key] - 1) * 100;
}

/* Pure: rows for the page. */
function buildReleases({ cik, filings, quarters, limit = 12 }) {
  const releases = (filings || [])
    .filter(f => f.form === "8-K" && /(^|,)\s*2\.02/.test(f.items || ""))
    .slice(0, limit);
  return releases.map(f => {
    const q = quarterForRelease(quarters, f.filingDate);
    const report = q ? periodicFilingFor(filings, q.end) : null;
    return {
      id: f.accession,
      date: f.filingDate,
      title: q ? `${q.label} results` : "Results release",
      indexUrl: `${archiveBase(cik, f.accession)}/`,
      quarter: q ? {
        label: q.label, end: q.end,
        revenue: q.revenue, netIncome: q.netIncome, eps: q.eps,
        revenueYoY: yoy(quarters, q, "revenue"),
        netIncomeYoY: yoy(quarters, q, "netIncome"),
        epsYoY: yoy(quarters, q, "eps"),
      } : null,
      report: report ? { form: report.form, filed: report.filingDate, url: filingUrl(cik, report) } : null,
    };
  });
}

/* ── release text (pure) ──────────────────────────────────────────────── */
const ENTITIES = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " ", rsquo: "’", lsquo: "‘", rdquo: "”", ldquo: "“", mdash: "—", ndash: "–", bull: "•", hellip: "…", reg: "®", trade: "™", copy: "©" };
function decodeHtml(s) {
  return String(s || "")
    .replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCodePoint(parseInt(h, 16)))
    .replace(/&#(\d+);/g, (_, d) => String.fromCodePoint(Number(d)))
    .replace(/&([a-z]+);/gi, (m, n) => (ENTITIES[n.toLowerCase()] != null ? ENTITIES[n.toLowerCase()] : m));
}
/* The release's prose as paragraphs: tables (the financial statements, which
   the page shows from XBRL instead), scripts and styles are dropped; block
   elements become paragraph breaks. */
function releaseParagraphs(html, { max = 60 } = {}) {
  const body = String(html || "")
    .replace(/<(script|style|table|head)[\s\S]*?<\/\1>/gi, " ")
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/<\/(p|div|li|h[1-6]|tr)>/gi, "\n\n")
    .replace(/<li[^>]*>/gi, "\n• ")
    .replace(/<[^>]+>/g, " ");
  const out = [];
  for (const raw of decodeHtml(body).split(/\n\s*\n/)) {
    const p = raw.replace(/[ \t ]+/g, " ").replace(/\s*\n\s*/g, " ").trim();
    if (p.length < 25) continue;                      // page furniture, lone labels
    if (/^(exhibit|ex-)\s*99/i.test(p) && p.length < 60) continue;
    out.push(p.slice(0, 2000));
    if (out.length >= max) break;
  }
  return out;
}
/* Pure: which file in a filing folder is the press release. */
function pickExhibit(items, primaryDocument) {
  const htm = (items || []).filter(i => /\.html?$/i.test(i.name || "") && i.name !== primaryDocument && !/index/i.test(i.name));
  const named = htm.find(i => /ex[-_]?99[-_.]?0?1|ex991|dex991|exhibit99|99[-_.]1|press|earnings|release/i.test(i.name));
  if (named) return named.name;
  return htm.sort((a, b) => Number(b.size || 0) - Number(a.size || 0))[0]?.name || null;
}

/* ── loading ───────────────────────────────────────────────────────────── */
const factsCache = new Map();
async function quartersFor(cik) {
  const hit = factsCache.get(cik);
  if (hit && Date.now() - hit.at < 6 * 3600 * 1000) return hit.rows;
  const facts = await sec.secJson(`https://data.sec.gov/api/xbrl/companyfacts/CIK${cik}.json`, 20000);
  const rows = adjustForSplits(buildQuarterlyHistory(facts, { maxQuarters: 24 }));
  factsCache.set(cik, { at: Date.now(), rows, name: facts?.entityName || null });
  if (factsCache.size > 200) factsCache.delete(factsCache.keys().next().value);
  return rows;
}

async function releasesFor(ticker, { limit = 12 } = {}) {
  const id = await sec.cikFor(ticker);
  if (!id) throw Object.assign(new Error("No SEC filer for this ticker."), { status: 404 });
  const sub = await sec.submissions(ticker);
  const filings = sec.recentFilings(sub);
  let quarters = [];
  try { quarters = await quartersFor(id.cik); } catch (_) { /* releases still list without numbers */ }
  return {
    ticker: String(ticker).toUpperCase(),
    company: sub?.name || id.name || ticker,
    cik: id.cik,
    website: /^https?:\/\//.test(sub?.website || "") ? sub.website : null,
    releases: buildReleases({ cik: id.cik, filings, quarters, limit }),
    filingsUrl: `https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&CIK=${id.cik}&type=8-K&dateb=&owner=include&count=40`,
  };
}

const textCache = new Map();
async function releaseText(ticker, accession) {
  if (!/^\d{10}-\d{2}-\d{6}$/.test(String(accession))) throw Object.assign(new Error("Invalid filing id."), { status: 400 });
  if (textCache.has(accession)) return textCache.get(accession);
  const id = await sec.cikFor(ticker);
  if (!id) throw Object.assign(new Error("No SEC filer for this ticker."), { status: 404 });
  const sub = await sec.submissions(ticker);
  const f = sec.recentFilings(sub).find(x => x.accession === accession);
  if (!f) throw Object.assign(new Error("That filing is not one of this company's recent filings."), { status: 404 });
  const base = archiveBase(id.cik, accession);
  const idx = await sec.secJson(`${base}/index.json`);
  const name = pickExhibit(idx?.directory?.item, f.primaryDocument);
  if (!name) throw Object.assign(new Error("No press release is attached to this filing."), { status: 404 });
  const html = await sec.secText(`${base}/${name}`, 20000);
  const out = { id: accession, date: f.filingDate, url: `${base}/${name}`, paragraphs: releaseParagraphs(html) };
  textCache.set(accession, out);
  if (textCache.size > 300) textCache.delete(textCache.keys().next().value);
  return out;
}

/* Quarter end → 10-Q/10-K link, for the statement tables. */
async function filingLinks(ticker, ends) {
  const id = await sec.cikFor(ticker);
  if (!id) return {};
  const filings = sec.recentFilings(await sec.submissions(ticker));
  const out = {};
  for (const end of ends || []) {
    const f = periodicFilingFor(filings, end);
    if (f) out[end] = { form: f.form, filed: f.filingDate, url: filingUrl(id.cik, f) };
  }
  return out;
}

module.exports = { releasesFor, releaseText, filingLinks, buildReleases, periodicFilingFor, quarterForRelease, releaseParagraphs, pickExhibit, decodeHtml };

"use strict";
/* ═══════════════════════════════════════════════════════════════════════════
   Famous investors' holdings, from their SEC Form 13F filings.

   Every investment manager with more than $100M in US stocks files a 13F each
   quarter (within 45 days of quarter end) listing what it held. We track a
   short list of well-known managers, read their two latest 13F-HR filings,
   and answer "which of them own this stock, and did they buy or sell last
   quarter?". SEC EDGAR data is public and free to use commercially.

   13F tables name the company ("APPLE INC", "BANK AMER CORP", "OCCIDENTAL
   PETE CORP") rather than the ticker, so a stock is matched to a holding by
   comparing names (abbreviations allowed, see namesMatch()).

   Each manager's CIK is checked against the name SEC has on file before its
   filings are used; a manager whose CIK does not match, or who has stopped
   filing, is left out rather than shown wrongly.
   ═══════════════════════════════════════════════════════════════════════════ */

const sec = require("./sec-fundamentals");

const MS_DAY = 864e5;
const finite = v => v !== null && v !== undefined && v !== "" && Number.isFinite(Number(v));

/* who: one plain line a beginner can place. Kept to facts that stay true. */
const FUNDS = [
  { cik: "0001067983", name: "Berkshire Hathaway", who: "Warren Buffett's company", expect: /BERKSHIRE HATHAWAY/i },
  { cik: "0001336528", name: "Pershing Square", who: "Bill Ackman", expect: /PERSHING SQUARE/i },
  { cik: "0001656456", name: "Appaloosa", who: "David Tepper", expect: /APPALOOSA/i },
  { cik: "0001536411", name: "Duquesne Family Office", who: "Stanley Druckenmiller", expect: /DUQUESNE/i },
  { cik: "0001040273", name: "Third Point", who: "Dan Loeb", expect: /THIRD POINT/i },
  { cik: "0001079114", name: "Greenlight Capital", who: "David Einhorn", expect: /GREENLIGHT/i },
  { cik: "0001061768", name: "Baupost Group", who: "Seth Klarman", expect: /BAUPOST/i },
  { cik: "0000921669", name: "Icahn Capital", who: "Carl Icahn", expect: /ICAHN/i },
  { cik: "0001649339", name: "Scion Asset Management", who: "Michael Burry", expect: /SCION/i },
  { cik: "0000949509", name: "Oaktree Capital", who: "Howard Marks", expect: /OAKTREE/i },
  { cik: "0001697748", name: "ARK Invest", who: "Cathie Wood", expect: /ARK INV/i },
  { cik: "0001569205", name: "Fundsmith", who: "Terry Smith", expect: /FUNDSMITH/i },
  { cik: "0001709323", name: "Himalaya Capital", who: "Li Lu", expect: /HIMALAYA/i },
  { cik: "0001549575", name: "Dalal Street", who: "Mohnish Pabrai", expect: /DALAL STREET/i },
  { cik: "0001647251", name: "TCI Fund Management", who: "Chris Hohn", expect: /TCI FUND/i },
  { cik: "0001029160", name: "Soros Fund Management", who: "George Soros's family office", expect: /SOROS/i },
  { cik: "0001350694", name: "Bridgewater Associates", who: "Founded by Ray Dalio", expect: /BRIDGEWATER/i },
  { cik: "0001037389", name: "Renaissance Technologies", who: "Quant fund founded by Jim Simons", expect: /RENAISSANCE TECH/i },
  { cik: "0001167483", name: "Tiger Global", who: "Chase Coleman", expect: /TIGER GLOBAL/i },
  { cik: "0001135730", name: "Coatue Management", who: "Philippe Laffont", expect: /COATUE/i },
  { cik: "0001103804", name: "Viking Global", who: "Andreas Halvorsen", expect: /VIKING GLOBAL/i },
  { cik: "0001061165", name: "Lone Pine Capital", who: "Tiger Cub hedge fund", expect: /LONE PINE/i },
  { cik: "0001418814", name: "ValueAct", who: "Activist investor", expect: /VALUEACT/i },
  { cik: "0001791786", name: "Elliott Investment Management", who: "Paul Singer", expect: /ELLIOTT/i },
  { cik: "0001096343", name: "Markel Group", who: "Tom Gayner", expect: /MARKEL/i },
  { cik: "0001112520", name: "Akre Capital", who: "Long-term quality investor", expect: /AKRE/i },
  { cik: "0001720792", name: "Ruane, Cunniff & Goldfarb", who: "The Sequoia Fund's managers", expect: /RUANE/i },
  { cik: "0000783412", name: "Daily Journal", who: "Charlie Munger's former company", expect: /DAILY JOURNAL/i },
  { cik: "0001166559", name: "Gates Foundation Trust", who: "The Gates Foundation's endowment", expect: /GATES FOUNDATION/i },
  { cik: "0000813917", name: "Harris Associates (Oakmark)", who: "Bill Nygren's firm", expect: /HARRIS ASSOCIATES/i },
];

/* ── names ─────────────────────────────────────────────────────────────── */
const DROP = new Set(["INC", "INCORPORATED", "CORP", "CORPORATION", "CO", "COMPANY", "LTD", "LIMITED", "PLC", "LLC", "LP", "L P", "SA", "NV", "N V", "AG", "SE",
  "THE", "OF", "AND", "NEW", "DEL", "DE", "MD", "NY", "CL", "CLASS", "A", "B", "C", "COM", "ORD", "SHS", "ADR", "SPONSORED", "REIT"]);
/* "Apple Inc." → ["APPLE"]; "Bank of America Corp /DE/" → ["BANK","AMERICA"];
   "AMAZON COM INC" → ["AMAZON"]. Trailing location tags and suffixes go. */
function nameTokens(name) {
  const s = String(name || "").toUpperCase()
    .replace(/\/[A-Z]{2,3}\/?/g, " ")            // "/DE/" state tags in SEC titles
    .replace(/['’]/g, "")                        // MOODY'S → MOODYS
    .replace(/&/g, " AND ")
    .replace(/[^A-Z0-9]+/g, " ").trim();
  const tokens = s.split(" ").filter(Boolean);
  while (tokens.length > 1 && DROP.has(tokens.at(-1))) tokens.pop();
  return tokens.filter((t, i) => i === 0 || !["THE", "OF", "AND"].includes(t));
}
/* Is `a` an abbreviation of `b` (same first letter, letters in order)?
   FINL ⊂ FINANCIAL, HLDGS ⊂ HOLDINGS, PETE ⊂ PETROLEUM, AMER ⊂ AMERICA. */
function abbrev(a, b) {
  if (a === b) return true;
  if (!a || !b || a[0] !== b[0] || a.length > b.length) return false;
  if (/^\d/.test(a) || /^\d/.test(b)) return false;
  let j = 0;
  for (const ch of b) if (ch === a[j]) j += 1;
  return j === a.length && a.length >= Math.min(3, b.length);
}
function namesMatch(holdingName, companyName) {
  const a = nameTokens(holdingName), b = nameTokens(companyName);
  if (!a.length || a.length !== b.length) return false;
  // One-word names allow only a cut-off ending (VISA must not match VISTA).
  if (a.length === 1) { const [x, y] = a[0].length <= b[0].length ? [a[0], b[0]] : [b[0], a[0]]; return x === y || (x.length >= 4 && y.startsWith(x)); }
  return a.every((t, i) => abbrev(t, b[i]) || abbrev(b[i], t));
}

/* ── 13F information table (pure) ──────────────────────────────────────── */
function field(block, name) {
  const m = new RegExp(`<(?:\\w+:)?${name}>([\\s\\S]*?)</(?:\\w+:)?${name}>`, "i").exec(block);
  return m ? m[1].replace(/<[^>]+>/g, "").trim() : null;
}
function decode(s) { return String(s || "").replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#39;|&apos;/g, "'"); }
/* Share positions only: options (putCall) and bonds (PRN amounts) are left
   out. Rows for the same security (one per sub-manager) are added up.
   `thousands`: filings before 2023 reported value in $1,000s. */
function parseInfoTable(xml, { thousands = false } = {}) {
  const rows = new Map();
  const re = /<(?:\w+:)?infoTable>([\s\S]*?)<\/(?:\w+:)?infoTable>/gi;
  let m;
  while ((m = re.exec(xml || ""))) {
    const b = m[1];
    if (field(b, "putCall")) continue;
    if ((field(b, "sshPrnamtType") || "SH").toUpperCase() !== "SH") continue;
    const cusip = (field(b, "cusip") || "").toUpperCase();
    const shares = Number(field(b, "sshPrnamt"));
    let value = Number(field(b, "value"));
    if (!cusip || !finite(shares)) continue;
    if (finite(value) && thousands) value *= 1000;
    const prev = rows.get(cusip);
    if (prev) { prev.shares += shares; prev.value += finite(value) ? value : 0; }
    else rows.set(cusip, { cusip, issuer: decode(field(b, "nameOfIssuer")), cls: decode(field(b, "titleOfClass")), shares, value: finite(value) ? value : 0 });
  }
  return [...rows.values()];
}

/* Compare one security across two quarters (pure). */
function changeOf(cur, prev) {
  if (!prev || !prev.shares) return { change: "new", changePct: null };
  if (!cur || !cur.shares) return { change: "sold", changePct: -100 };
  const pct = (cur.shares / prev.shares - 1) * 100;
  if (Math.abs(pct) < 0.5) return { change: "unchanged", changePct: 0 };
  return { change: pct > 0 ? "added" : "reduced", changePct: pct };
}

/* ── loading ───────────────────────────────────────────────────────────── */
const state = { funds: new Map(), at: 0, running: null, skipped: [] };
const tableCache = new Map();   // accession -> rows

function filingsOf(sub) {
  return sec.recentFilings(sub)
    .filter(f => f.form === "13F-HR")
    .sort((a, b) => String(b.reportDate || b.filingDate).localeCompare(String(a.reportDate || a.filingDate)));
}
async function infoTable(cik, filing) {
  if (tableCache.has(filing.accession)) return tableCache.get(filing.accession);
  const acc = String(filing.accession).replace(/-/g, "");
  const base = `https://www.sec.gov/Archives/edgar/data/${Number(cik)}/${acc}`;
  const idx = await sec.secJson(`${base}/index.json`);
  const files = (idx?.directory?.item || []).map(x => x.name).filter(n => /\.xml$/i.test(n) && !/primary_doc/i.test(n));
  if (!files.length) throw new Error("No information table in this 13F.");
  const xml = await sec.secText(`${base}/${files[0]}`, 45000);
  const rows = parseInfoTable(xml, { thousands: String(filing.filingDate) < "2023-01-01" });
  tableCache.set(filing.accession, rows);
  if (tableCache.size > 120) tableCache.delete(tableCache.keys().next().value);
  return rows;
}
async function loadFund(f, today = new Date().toISOString().slice(0, 10)) {
  const sub = await sec.secJson(`https://data.sec.gov/submissions/CIK${f.cik}.json`);
  if (!f.expect.test(String(sub?.name || ""))) return { skip: `CIK ${f.cik} is "${sub?.name}", not ${f.name}` };
  const list = filingsOf(sub);
  const latest = list[0];
  if (!latest) return { skip: `${f.name}: no 13F-HR on file` };
  // A manager who stopped filing (no 13F in ~7 months) is not "holding" anything now.
  if ((Date.parse(today) - Date.parse(latest.filingDate)) / MS_DAY > 200) return { skip: `${f.name}: last 13F filed ${latest.filingDate}` };
  const previous = list.find(x => x.reportDate && latest.reportDate && x.reportDate < latest.reportDate) || null;
  const cur = await infoTable(f.cik, latest);
  const prev = previous ? await infoTable(f.cik, previous).catch(() => null) : null;
  const total = cur.reduce((s, r) => s + r.value, 0);
  const ranked = [...cur].sort((a, b) => b.value - a.value);
  const rank = new Map(ranked.map((r, i) => [r.cusip, i + 1]));
  return {
    fund: {
      cik: f.cik, name: f.name, who: f.who,
      period: latest.reportDate || null, filed: latest.filingDate,
      prevPeriod: previous?.reportDate || null,
      url: `https://www.sec.gov/Archives/edgar/data/${Number(f.cik)}/${String(latest.accession).replace(/-/g, "")}/`,
      total, positions: cur.length,
      rows: cur.map(r => ({ ...r, rank: rank.get(r.cusip), weight: total > 0 ? (r.value / total) * 100 : null })),
      prevRows: prev || null,
    },
  };
}
async function refresh() {
  if (state.running) return state.running;
  state.running = (async () => {
    const skipped = [];
    for (const f of FUNDS) {
      try {
        const r = await loadFund(f);
        if (r.skip) { skipped.push(r.skip); state.funds.delete(f.cik); }
        else state.funds.set(f.cik, r.fund);
      } catch (e) { skipped.push(`${f.name}: ${String(e.message || e).slice(0, 80)}`); }
    }
    state.skipped = skipped;
    state.at = Date.now();
    if (skipped.length) console.log(`[13f] ${state.funds.size} managers loaded; skipped: ${skipped.join(" | ")}`);
  })().finally(() => { state.running = null; });
  return state.running;
}
function start({ firstDelayMs = 2 * 60 * 1000, everyMs = 12 * 3600 * 1000 } = {}) {
  const run = () => refresh().catch(e => console.warn("[13f] refresh failed:", String(e.message || e).slice(0, 160)));
  setTimeout(run, firstDelayMs).unref?.();
  setInterval(run, everyMs).unref?.();
}

/* ── answers ───────────────────────────────────────────────────────────── */
/* Pure: which loaded managers hold a company (by name). */
function holdersOf(companyName, funds) {
  const holders = [], soldOut = [];
  for (const f of funds) {
    const mine = f.rows.filter(r => namesMatch(r.issuer, companyName));
    const before = (f.prevRows || []).filter(r => namesMatch(r.issuer, companyName));
    const sum = list => list.reduce((s, r) => ({ shares: s.shares + r.shares, value: s.value + r.value }), { shares: 0, value: 0 });
    const cur = sum(mine), prev = sum(before);
    if (cur.shares > 0) {
      const ch = f.prevRows ? changeOf(cur, prev) : { change: null, changePct: null };
      holders.push({
        fund: f.name, who: f.who, cik: f.cik, period: f.period, filed: f.filed, url: f.url,
        shares: cur.shares, value: cur.value,
        weight: f.total > 0 ? (cur.value / f.total) * 100 : null,
        rank: Math.min(...mine.map(r => r.rank)), positions: f.positions,
        classes: [...new Set(mine.map(r => r.cls).filter(Boolean))],
        prevShares: f.prevRows ? prev.shares : null, ...ch,
      });
    } else if (prev.shares > 0) {
      soldOut.push({ fund: f.name, who: f.who, cik: f.cik, period: f.period, prevPeriod: f.prevPeriod, prevShares: prev.shares, url: f.url });
    }
  }
  holders.sort((a, b) => (b.weight ?? 0) - (a.weight ?? 0));
  return { holders, soldOut };
}
async function forTicker(ticker) {
  if (!state.at && !state.running) refresh().catch(() => {});
  const id = await sec.cikFor(ticker);
  if (!id) throw new Error("No SEC filer for this ticker.");
  const funds = [...state.funds.values()];
  const { holders, soldOut } = holdersOf(id.name, funds);
  const periods = funds.map(f => f.period).filter(Boolean).sort();
  return {
    ticker: String(ticker).toUpperCase(), company: id.name,
    holders, soldOut,
    managersTracked: funds.length, loading: !state.at,
    latestPeriod: periods.at(-1) || null,
    note: "13F filings show positions at quarter end and are filed up to 45 days later. They list US-listed shares only; short positions are not reported.",
  };
}
const status = () => ({ loaded: state.funds.size, at: state.at ? new Date(state.at).toISOString() : null, running: Boolean(state.running), skipped: state.skipped });

module.exports = { FUNDS, forTicker, refresh, start, status, holdersOf, namesMatch, nameTokens, parseInfoTable, changeOf, _state: state, _loadFund: loadFund };

"use strict";
/* Famous investors' holdings from SEC 13F filings (lib/sec-13f.js). */
const test = require("node:test");
const assert = require("node:assert/strict");
const f13 = require("../lib/sec-13f");

const TABLE = `<?xml version="1.0" encoding="UTF-8"?>
<ns1:informationTable xmlns:ns1="http://www.sec.gov/edgar/document/thirteenf/informationtable">
  <ns1:infoTable><ns1:nameOfIssuer>APPLE INC</ns1:nameOfIssuer><ns1:titleOfClass>COM</ns1:titleOfClass><ns1:cusip>037833100</ns1:cusip>
    <ns1:value>60000000000</ns1:value><ns1:shrsOrPrnAmt><ns1:sshPrnamt>280000000</ns1:sshPrnamt><ns1:sshPrnamtType>SH</ns1:sshPrnamtType></ns1:shrsOrPrnAmt>
    <ns1:investmentDiscretion>DFND</ns1:investmentDiscretion><ns1:otherManager>4</ns1:otherManager></ns1:infoTable>
  <ns1:infoTable><ns1:nameOfIssuer>APPLE INC</ns1:nameOfIssuer><ns1:titleOfClass>COM</ns1:titleOfClass><ns1:cusip>037833100</ns1:cusip>
    <ns1:value>1000000000</ns1:value><ns1:shrsOrPrnAmt><ns1:sshPrnamt>5000000</ns1:sshPrnamt><ns1:sshPrnamtType>SH</ns1:sshPrnamtType></ns1:shrsOrPrnAmt></ns1:infoTable>
  <ns1:infoTable><ns1:nameOfIssuer>BANK AMER CORP</ns1:nameOfIssuer><ns1:titleOfClass>COM</ns1:titleOfClass><ns1:cusip>060505104</ns1:cusip>
    <ns1:value>29000000000</ns1:value><ns1:shrsOrPrnAmt><ns1:sshPrnamt>680000000</ns1:sshPrnamt><ns1:sshPrnamtType>SH</ns1:sshPrnamtType></ns1:shrsOrPrnAmt></ns1:infoTable>
  <ns1:infoTable><ns1:nameOfIssuer>APPLE INC</ns1:nameOfIssuer><ns1:titleOfClass>CALL</ns1:titleOfClass><ns1:cusip>037833100</ns1:cusip>
    <ns1:value>5000000</ns1:value><ns1:shrsOrPrnAmt><ns1:sshPrnamt>20000</ns1:sshPrnamt><ns1:sshPrnamtType>SH</ns1:sshPrnamtType></ns1:shrsOrPrnAmt><ns1:putCall>Call</ns1:putCall></ns1:infoTable>
  <ns1:infoTable><ns1:nameOfIssuer>SOME CO</ns1:nameOfIssuer><ns1:titleOfClass>NOTE 2.5% 2030</ns1:titleOfClass><ns1:cusip>999999AA1</ns1:cusip>
    <ns1:value>100000</ns1:value><ns1:shrsOrPrnAmt><ns1:sshPrnamt>100000</ns1:sshPrnamt><ns1:sshPrnamtType>PRN</ns1:sshPrnamtType></ns1:shrsOrPrnAmt></ns1:infoTable>
</ns1:informationTable>`;

test("13F table: share positions summed per security; options and bonds left out", () => {
  const rows = f13.parseInfoTable(TABLE);
  assert.equal(rows.length, 2);
  const aapl = rows.find(r => r.cusip === "037833100");
  assert.equal(aapl.shares, 285000000);
  assert.equal(aapl.value, 61000000000);
  assert.equal(aapl.issuer, "APPLE INC");
  const plain = f13.parseInfoTable(TABLE.replace(/ns1:/g, ""));
  assert.equal(plain.length, 2, "tables without a namespace prefix parse the same");
  assert.equal(f13.parseInfoTable(TABLE, { thousands: true }).find(r => r.cusip === "060505104").value, 29000000000000, "pre-2023 values were in $1,000s");
});

test("13F issuer names match SEC company names, abbreviations included", () => {
  const yes = [["APPLE INC", "Apple Inc."], ["BANK AMER CORP", "BANK OF AMERICA CORP /DE/"], ["OCCIDENTAL PETE CORP", "OCCIDENTAL PETROLEUM CORP /DE/"],
    ["INTL BUSINESS MACHS", "INTERNATIONAL BUSINESS MACHINES CORP"], ["ALLY FINL INC", "Ally Financial Inc."], ["NU HLDGS LTD", "Nu Holdings Ltd."],
    ["MOODYS CORP", "MOODYS CORP /DE/"], ["DOMINOS PIZZA INC", "Domino's Pizza Inc"], ["AMAZON COM INC", "AMAZON COM INC"], ["CHEVRON CORP NEW", "CHEVRON CORP"],
    ["GENERAL MTRS CO", "General Motors Co"], ["AT&T INC", "AT&T INC."]];
  const no = [["VISA INC", "Vista Inc"], ["MICROSOFT CORP", "Microchip Technology Inc"], ["GENERAL MTRS CO", "General Mills Inc"],
    ["CONSTELLATION BRANDS INC", "Constellation Energy Corp"], ["AMERICAN EXPRESS CO", "AMERIPRISE FINANCIAL INC"], ["APPLE INC", "Applied Materials Inc"]];
  for (const [a, b] of yes) assert.equal(f13.namesMatch(a, b), true, `${a} ~ ${b}`);
  for (const [a, b] of no) assert.equal(f13.namesMatch(a, b), false, `${a} !~ ${b}`);
});

test("quarter-over-quarter change", () => {
  assert.equal(f13.changeOf({ shares: 100 }, null).change, "new");
  assert.equal(f13.changeOf({ shares: 120 }, { shares: 100 }).change, "added");
  assert.equal(Math.round(f13.changeOf({ shares: 70 }, { shares: 100 }).changePct), -30);
  assert.equal(f13.changeOf({ shares: 100.2 }, { shares: 100 }).change, "unchanged");
  assert.equal(f13.changeOf({ shares: 0 }, { shares: 100 }).change, "sold");
});

test("holders of a company: weight, rank, change, and who sold out", () => {
  const fund = (name, rows, prevRows) => {
    const total = rows.reduce((s, r) => s + r.value, 0);
    const ranked = [...rows].sort((a, b) => b.value - a.value);
    return { cik: name, name, who: "", period: "2026-06-30", filed: "2026-08-14", url: "u", total, positions: rows.length,
      rows: rows.map(r => ({ ...r, rank: ranked.indexOf(r) + 1 })), prevRows };
  };
  const a = fund("Alpha", [{ cusip: "1", issuer: "APPLE INC", cls: "COM", shares: 120, value: 600 }, { cusip: "2", issuer: "COCA COLA CO", cls: "COM", shares: 10, value: 400 }],
    [{ cusip: "1", issuer: "APPLE INC", cls: "COM", shares: 100, value: 500 }]);
  const b = fund("Beta", [{ cusip: "2", issuer: "COCA COLA CO", cls: "COM", shares: 10, value: 400 }],
    [{ cusip: "1", issuer: "APPLE INC", cls: "COM", shares: 50, value: 250 }]);
  const { holders, soldOut } = f13.holdersOf("Apple Inc.", [a, b]);
  assert.equal(holders.length, 1);
  assert.equal(holders[0].fund, "Alpha");
  assert.equal(holders[0].weight, 60);
  assert.equal(holders[0].rank, 1);
  assert.equal(holders[0].change, "added");
  assert.deepEqual(soldOut.map(s => s.fund), ["Beta"]);
  const coke = f13.holdersOf("COCA COLA CO", [a, b]);
  assert.equal(coke.holders.find(h => h.fund === "Alpha").change, "new");
});

test("every tracked manager has a CIK and a name check", () => {
  assert.ok(f13.FUNDS.length >= 20);
  const ciks = new Set();
  for (const f of f13.FUNDS) {
    assert.match(f.cik, /^\d{10}$/, f.name);
    assert.ok(f.expect instanceof RegExp && f.expect.test(f.name.toUpperCase()) || f.expect.source.length > 2, f.name);
    assert.ok(!ciks.has(f.cik), `duplicate ${f.cik}`);
    ciks.add(f.cik);
  }
});

test("a manager is used only when SEC's name matches and the filings are current", async () => {
  const realFetch = global.fetch;
  const sub = (name, filed) => ({ name, filings: { recent: {
    form: ["13F-HR", "4", "13F-HR"], filingDate: [filed, filed, "2026-05-15"], reportDate: ["2026-06-30", null, "2026-03-31"],
    accessionNumber: ["0000950123-26-000001", "x", "0000950123-26-000002"], primaryDocument: ["primary_doc.xml", "", "primary_doc.xml"],
  } } });
  let subject = sub("BERKSHIRE HATHAWAY INC", "2026-08-14");
  global.fetch = async url => {
    const u = String(url);
    if (u.includes("/submissions/")) return { ok: true, json: async () => subject };
    if (u.endsWith("index.json")) return { ok: true, json: async () => ({ directory: { item: [{ name: "primary_doc.xml" }, { name: "50240.xml" }] } }) };
    if (u.endsWith("50240.xml")) return { ok: true, text: async () => TABLE };
    return { ok: false, status: 404 };
  };
  try {
    const brk = f13.FUNDS.find(f => /Berkshire/.test(f.name));
    const ok = await f13._loadFund(brk, "2026-10-19");
    assert.ok(ok.fund, ok.skip);
    assert.equal(ok.fund.period, "2026-06-30");
    assert.equal(ok.fund.prevPeriod, "2026-03-31");
    assert.equal(ok.fund.positions, 2);
    subject = sub("SOMEONE ELSE LLC", "2026-08-14");
    assert.match((await f13._loadFund(brk, "2026-10-19")).skip, /not Berkshire/);
    subject = sub("BERKSHIRE HATHAWAY INC", "2025-11-14");
    assert.match((await f13._loadFund(brk, "2026-10-19")).skip, /last 13F filed/);
  } finally { global.fetch = realFetch; }
});

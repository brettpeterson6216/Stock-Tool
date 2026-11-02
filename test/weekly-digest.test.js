"use strict";
const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const testDbPath = path.join(os.tmpdir(), `il-weekly-test-${process.pid}.db`).replace(/\\/g, "/");
try { fs.unlinkSync(testDbPath); } catch (_) {}
process.env.NODE_ENV = "test";
process.env.TURSO_URL = `file:${testDbPath}`;
process.env.TURSO_AUTH_TOKEN = "";
process.env.SESSION_SECRET = "weekly-test-secret";
process.env.PORT = "0";

const { stmtToHrana } = require(path.join(path.dirname(require.resolve("@libsql/client")), "hrana.js"));
const { db, initDb } = require("../lib/db");
const universeGrades = require("../lib/universe-grades");
const W = require("../lib/weekly-digest");

let encodeError = null, userId, optedOutId;
before(async () => {
  await initDb();
  const real = db.execute.bind(db);
  db.execute = (s, a) => {
    try { stmtToHrana(typeof s === "string" ? { sql: s, args: a || [] } : s); } catch (e) { encodeError = encodeError || e.message; }
    return real(s, a);
  };
  await db.execute({ sql: "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)", args: ["weekly", "weekly@example.com", "x"] });
  await db.execute({ sql: "INSERT INTO users (username, email, password_hash, digest_opt_out) VALUES (?, ?, ?, 1)", args: ["quiet", "quiet@example.com", "x"] });
  userId = (await db.execute({ sql: "SELECT id FROM users WHERE username=?", args: ["weekly"] })).rows[0].id;
  optedOutId = (await db.execute({ sql: "SELECT id FROM users WHERE username=?", args: ["quiet"] })).rows[0].id;
  for (const [u, t] of [[userId, "NVDA"], [userId, "ZZZZ"], [optedOutId, "NVDA"]]) {
    await db.execute({ sql: "INSERT INTO watchlist_items (user_id, ticker) VALUES (?, ?)", args: [u, t] });
  }
  universeGrades.get = t => (t === "NVDA" ? { ticker: "NVDA", name: "NVIDIA", score: 9.9, grades: { value: "B-", growth: "A+", profitability: "A+", health: "B+", momentum: "B-" } } : null);
});
after(() => { try { fs.unlinkSync(testDbPath); } catch (_) {} });

test("only sends on Saturday morning, New York time", () => {
  assert.equal(W.dueWeek(new Date("2026-11-07T14:00:00Z")), "2026-11-07"); // Sat 9am ET
  assert.equal(W.dueWeek(new Date("2026-11-07T11:00:00Z")), null);         // Sat 6am ET
  assert.equal(W.dueWeek(new Date("2026-11-06T15:00:00Z")), null);         // Friday
});

test("one email per member per week, never to someone who unsubscribed", async () => {
  const sent = [];
  const send = async m => { sent.push(m); return { sent: true }; };
  const first = await W.runWeeklyDigest({ now: new Date("2026-11-07T14:00:00Z"), send });
  assert.equal(first.sent, 1);
  assert.equal(sent.length, 1);
  assert.equal(sent[0].to, "weekly@example.com");
  assert.match(sent[0].html, /NVDA/);
  assert.match(sent[0].html, /\/unsubscribe\/weekly\?u=\d+&amp;t=|\/unsubscribe\/weekly\?u=\d+&t=/);
  assert.match(sent[0].headers["List-Unsubscribe"], /^<https?:\/\/.+\/unsubscribe\/weekly\?u=/);
  const again = await W.runWeeklyDigest({ now: new Date("2026-11-07T15:00:00Z"), send });
  assert.equal(again.sent, 0, "a second run the same Saturday sends nothing");
  assert.equal(sent.length, 1);
});

test("a failed send is retried on the next run", async () => {
  let n = 0;
  const failing = async () => { n++; return { sent: false }; };
  await W.runWeeklyDigest({ now: new Date("2026-11-14T14:00:00Z"), send: failing });
  const ok = [];
  await W.runWeeklyDigest({ now: new Date("2026-11-14T15:00:00Z"), send: async m => { ok.push(m); return { sent: true }; } });
  assert.equal(n, 1);
  assert.equal(ok.length, 1);
});

test("unsubscribe links are signed per user", () => {
  const t = W.unsubscribeToken(userId);
  assert.equal(W.verifyUnsubscribe(userId, t), true);
  assert.equal(W.verifyUnsubscribe(userId + 1, t), false);
  assert.equal(W.verifyUnsubscribe(userId, "nope"), false);
});

test("the email names score and letter-grade changes", () => {
  const mail = W.buildEmail({ username: "Sam", userId: 1, since: "2026-10-31", movers: null, rows: [
    { ticker: "NVDA", name: "NVIDIA", score: 9.9, change: 0.4, grades: { value: "B-", growth: "A+" }, before: { value: "C+", growth: "A+" } },
    { ticker: "ZZZZ" },
  ] });
  assert.equal(mail.count, 1);
  assert.match(mail.subject, /NVDA up 0\.4/);
  assert.match(mail.html, /Value C\+ → <b[^>]*>B-<\/b>/);
});

test("every statement is valid for the production driver", () => {
  assert.equal(encodeError, null, encodeError);
});

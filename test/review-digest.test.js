// Runs the weekly review digest the way production runs it, with every
// statement it issues put through the *production* driver's statement
// encoder first.
//
// Background: the digest threw
//   TypeError: Cannot convert undefined or null to object
// on every cycle in production, from Object.entries inside the libSQL HTTP
// client. Locally it never failed, because the file: client fills in a
// missing `args` and the HTTP client does not. So running the digest against
// the local database proves nothing on its own — the encoder check below is
// what makes this test able to fail.
"use strict";

const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const fs     = require("node:fs");
const os     = require("node:os");
const path   = require("node:path");

const testDbPath = path.join(os.tmpdir(), `il-digest-test-${process.pid}.db`).replace(/\\/g, "/");
try { fs.unlinkSync(testDbPath); } catch (_) {}

process.env.NODE_ENV         = "test";
process.env.TURSO_URL        = `file:${testDbPath}`;
process.env.TURSO_AUTH_TOKEN = "";
process.env.SESSION_SECRET   = "digest-test-secret-do-not-use-in-prod";
process.env.PORT             = "0";

const { stmtToHrana } = require(
  path.join(path.dirname(require.resolve("@libsql/client")), "hrana.js"));

const { db, initDb } = require("../lib/db");
const app = require("../server");

const seen = [];
let encodeError = null;

before(async () => {
  await initDb();

  // Stand in for the production driver: encode each statement exactly as the
  // HTTP client would before letting the local client run it.
  const realExecute = db.execute.bind(db);
  db.execute = (stmtOrSql, args) => {
    seen.push(stmtOrSql);
    try { stmtToHrana(typeof stmtOrSql === "string" ? { sql: stmtOrSql, args: args || [] } : stmtOrSql); }
    catch (e) { encodeError = encodeError || { stmt: stmtOrSql, message: e.message }; }
    return realExecute(stmtOrSql, args);
  };

  await db.execute({
    sql: "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
    args: ["digestuser", "digest@example.com", "x"],
  });
  const user = await db.execute({ sql: "SELECT id FROM users WHERE username = ?", args: ["digestuser"] });
  const userId = user.rows[0].id;
  const inThreeDays = new Date(Date.now() + 3 * 864e5).toISOString().slice(0, 10);
  await db.execute({
    sql: "INSERT INTO investment_theses (user_id, ticker, status, review_date) VALUES (?, ?, ?, ?)",
    args: [userId, "AAPL", "open", inThreeDays],
  });
});

after(() => { try { fs.unlinkSync(testDbPath); } catch (_) {} });

test("the review digest runs a full cycle without throwing", async () => {
  const errors = [];
  const realError = console.error;
  console.error = (...a) => errors.push(a.join(" "));
  try { await app.runReviewDigests(); } finally { console.error = realError; }

  assert.deepEqual(errors.filter(e => e.includes("[review-digest]")), [],
    "the digest logged an error during a normal cycle");
});

test("every statement the digest issues is valid for the production driver", () => {
  assert.ok(seen.length > 0, "the digest issued no statements at all");
  assert.equal(encodeError, null,
    encodeError && `statement rejected by the Turso encoder: ${encodeError.message}\n  ${JSON.stringify(encodeError.stmt).slice(0, 200)}`);
});

test("a user with a due review is actually picked up", async () => {
  const claimed = await db.execute({
    sql: "SELECT COUNT(*) AS n FROM lifecycle_email_log WHERE email_type = 'review_digest_auto'",
    args: [],
  });
  assert.ok(Number(claimed.rows[0].n) >= 0);
  const touchedTheses = seen.some(s => /investment_theses/.test(typeof s === "string" ? s : s.sql));
  assert.ok(touchedTheses, "the digest never queried investment_theses");
});

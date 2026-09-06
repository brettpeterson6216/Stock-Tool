// Guards the failure that took down the weekly review digest in production:
// `db.execute({ sql })` with no `args`.
//
// The local `file:` libSQL client fills that gap in; the HTTP client used
// against Turso does not — it calls Object.entries(stmt.args) and throws
// "Cannot convert undefined or null to object". So the bug is invisible to
// every test that runs against the local database, and only appears once
// deployed. These tests therefore check the two things that *are* checkable
// locally: the driver contract itself, and the shape of every statement
// literal in the source.
const test   = require("node:test");
const assert = require("node:assert/strict");
const fs     = require("node:fs");
const path   = require("node:path");

const ROOT = path.join(__dirname, "..");

// The package blocks deep imports through "exports", so reach the CommonJS
// build the same way Node resolved the entry point.
const { stmtToHrana } = require(
  path.join(path.dirname(require.resolve("@libsql/client")), "hrana.js"));

test("the libSQL HTTP driver really does reject an object statement with no args", () => {
  // If a future upgrade makes the driver tolerant, this test fails loudly and
  // the guard below can be reconsidered — rather than quietly becoming theatre.
    assert.throws(() => stmtToHrana({ sql: "SELECT 1" }), /undefined or null to object/);
  assert.doesNotThrow(() => stmtToHrana({ sql: "SELECT 1", args: [] }));
  assert.doesNotThrow(() => stmtToHrana("SELECT 1"));
});

test("normaliseStmt makes a missing args safe for the production driver", () => {
  const { normaliseStmt, db } = require("../lib/db");

  assert.doesNotThrow(() => stmtToHrana(normaliseStmt({ sql: "SELECT 1" })));
  assert.doesNotThrow(() => stmtToHrana(normaliseStmt({ sql: "SELECT ?", args: null })));

  // Statements that are already well formed are passed through untouched.
  const withArgs = { sql: "SELECT ?", args: [1] };
  assert.equal(normaliseStmt(withArgs), withArgs);
  const named = { sql: "SELECT :a", args: { a: 1 } };
  assert.equal(normaliseStmt(named), named);
  assert.equal(normaliseStmt("SELECT 1"), "SELECT 1");

  // And the wrapper is actually installed on the exported client.
  assert.equal(typeof db.execute, "function");
});

test("every object-form execute()/batch() statement in the source carries args", () => {
  const files = [];
  const skip = new Set(["node_modules", ".git", "_to_delete", "Claude outputs", "audits", "design-references"]);
  (function walk(dir) {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if (skip.has(entry.name)) continue;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.name.endsWith(".js")) files.push(full);
    }
  })(ROOT);

  const offenders = [];
  for (const file of files) {
    // Strip comments so prose describing the bug is not mistaken for the bug.
    const src = fs.readFileSync(file, "utf8")
      .replace(/\/\*[\s\S]*?\*\//g, "")
      .replace(/(^|[^:])\/\/[^\n]*/g, "$1");
    const re = /\.(?:execute|batch)\s*\(\s*\{/g;
    let match;
    while ((match = re.exec(src))) {
      const open = match.index + match[0].length - 1;
      let depth = 0, end = open;
      for (; end < src.length; end += 1) {
        if (src[end] === "{") depth += 1;
        else if (src[end] === "}") { depth -= 1; if (!depth) { end += 1; break; } }
      }
      const body = src.slice(open, end);
      if (!/\bargs\s*:/.test(body)) {
        offenders.push(`${path.relative(ROOT, file)}:${src.slice(0, match.index).split("\n").length}`);
      }
    }
  }

  assert.deepEqual(offenders, [],
    `object-form statements missing "args" (they throw against Turso, not locally):\n  ${offenders.join("\n  ")}`);
});

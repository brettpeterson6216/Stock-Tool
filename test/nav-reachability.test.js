// "No page should be a maze to get to from the dashboard. 3 clicks max."
//
// The structural guarantee behind that number: every tool belongs to a group
// that a top tab actually opens, and every section in a group appears in that
// group's sidebar. When both hold, any tool is at most
//   dashboard → top tab → sidebar item  = 2 clicks.
//
// It did not hold. Projection Lab, Valuation Lab, Compare and the Wealth
// Planner sat in groups called `projections`, `comparison` and `planner` that
// no top tab opened, so renderSidebarGroup() hid them from every research
// page. The sidebar items were in the markup all along. Measured with a BFS
// over the real click graph before the fix: Projection Lab, Valuation Lab and
// Compare were 2 clicks from Financials but only via the dashboard, and the
// Wealth Planner was unreachable from any research page. After: every tool is
// 1 click from any research page and 2 from the dashboard.
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");
const nav = fs.readFileSync(path.join(ROOT, "public", "app-navigation.js"), "utf8");
const index = fs.readFileSync(path.join(ROOT, "index.html"), "utf8");
const research = fs.readFileSync(path.join(ROOT, "public", "research-system.js"), "utf8");

function block(name) {
  const at = nav.indexOf("const " + name);
  assert.notEqual(at, -1, `${name} is gone from app-navigation.js`);
  const open = nav.indexOf("{", at);
  let depth = 0, i = open;
  for (; i < nav.length; i += 1) {
    if (nav[i] === "{") depth += 1;
    else if (nav[i] === "}") { depth -= 1; if (!depth) break; }
  }
  return nav.slice(open, i + 1);
}

const GROUPS = {};
for (const [, key, list] of block("NAV_GROUPS").matchAll(/(\w+)\s*:\s*\[([^\]]*)\]/g)) {
  GROUPS[key] = [...list.matchAll(/'([^']+)'/g)].map((m) => m[1]);
}
const TABS = {};
for (const [, key, id] of block("NAV_GROUP_TAB").matchAll(/(\w+)\s*:\s*'([^']+)'/g)) TABS[key] = id;

const SUBS = {};
{
  const src = block("SIDEBAR_SUBGROUPS");
  for (const [, key, body] of src.matchAll(/(\w+)\s*:\s*\[([\s\S]*?)\]\s*,\s*(?=\w+\s*:|\s*\}$)/g)) {
    SUBS[key] = [...body.matchAll(/'([^']+)'/g)].map((m) => m[1]);
  }
}

test("every group is opened by a top tab that exists", () => {
  for (const g of Object.keys(GROUPS)) {
    assert.ok(TABS[g], `group "${g}" has no top tab, so nothing in it can be reached by clicking`);
    assert.ok(index.includes(`id="${TABS[g]}"`), `group "${g}" points at #${TABS[g]}, not a tab in index.html`);
  }
});

test("every tool section has a sidebar item", () => {
  // Some items are injected at runtime by research-system.js rather than
  // living in index.html; both count.
  const has = (sec) =>
    index.includes(`data-sec="${sec}"`) || research.includes(`data-sec="${sec}"`);
  const missing = Object.values(GROUPS).flat().filter((s) => !has(s));
  assert.deepEqual(missing, [], "these sections are in a nav group but have no sidebar item to click");
});

test("the research rail lists every research tool", () => {
  // A section in the group but absent from SIDEBAR_SUBGROUPS renders nowhere,
  // which is exactly how the Wealth Planner went missing.
  for (const [group, secs] of Object.entries(GROUPS)) {
    const listed = SUBS[group] || [];
    const missing = secs.filter((s) => !listed.includes(s));
    assert.deepEqual(missing, [], `group "${group}" hides these from its own sidebar: ${missing.join(", ")}`);
  }
});

test("the scenario tools live behind Research, not a group of their own", () => {
  for (const sec of ["projection", "dcf", "compare", "wealth"]) {
    assert.ok(
      GROUPS.research.includes(sec),
      `${sec} is not in the research group, so it disappears from the rail on every research page`
    );
  }
});

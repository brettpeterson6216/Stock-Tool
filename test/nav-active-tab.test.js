// The top nav tells you where you are. It was lying on four routes.
//
// NAV_GROUP_TAB maps a section group to the top tab that should light up.
// Every entry except `saved` pointed at the LensScore tab, so:
//
//   /education      (Learn)          highlighted  LensScore
//   /dcf            (Valuation Lab)  highlighted  LensScore
//   /projection     (Projection Lab) highlighted  LensScore
//   /compare        (Compare)        highlighted  LensScore
//
// The research tools belong behind Research, the lessons behind Learn, and
// the LensScore tab belongs to LensScore alone. These tests read the two
// tables out of the controller and check them against the tabs that actually
// exist in index.html, so a renamed tab id fails here rather than silently
// highlighting nothing.
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");
const nav = fs.readFileSync(path.join(ROOT, "public", "app-navigation.js"), "utf8");
const index = fs.readFileSync(path.join(ROOT, "index.html"), "utf8");

function table(name) {
  const at = nav.indexOf(`const ${name}`);
  assert.notEqual(at, -1, `${name} is gone from app-navigation.js`);
  const body = nav.slice(nav.indexOf("{", at) + 1, nav.indexOf("};", at));
  const out = {};
  for (const [, key, value] of body.matchAll(/(\w+)\s*:\s*(\[[^\]]*\]|'[^']*')/g)) {
    out[key] = value.startsWith("[")
      ? [...value.matchAll(/'([^']+)'/g)].map((m) => m[1])
      : value.slice(1, -1);
  }
  return out;
}

const GROUPS = table("NAV_GROUPS");
const TABS = table("NAV_GROUP_TAB");

test("every group maps to a tab that exists in the markup", () => {
  for (const [group, id] of Object.entries(TABS)) {
    assert.ok(
      index.includes(`id="${id}"`),
      `${group} points at #${id}, which is not a tab in index.html`
    );
  }
});

test("every group of sections has a tab", () => {
  for (const group of Object.keys(GROUPS)) {
    assert.ok(TABS[group], `group "${group}" has no top tab, so nothing lights up`);
  }
});

test("the LensScore tab belongs to LensScore alone", () => {
  const claiming = Object.entries(TABS)
    .filter(([, id]) => id === "nav-lensscore-link")
    .map(([group]) => group);
  assert.deepEqual(
    claiming,
    [],
    `these groups highlight the LensScore tab but are not LensScore: ${claiming.join(", ")}`
  );
});

test("the research tools sit behind Research and the lessons behind Learn", () => {
  // Named routes rather than group names, so renaming a group cannot quietly
  // move Valuation Lab back under the wrong tab.
  const expected = {
    analyze: "nav-analyze",
    dcf: "nav-analyze",
    projection: "nav-analyze",
    compare: "nav-analyze",
    screener: "nav-analyze",
    education: "nav-news-link",
    workspace: "nav-saved-link",
    reports: "nav-saved-link",
  };
  for (const [section, wantTab] of Object.entries(expected)) {
    const group = Object.keys(GROUPS).find((g) => GROUPS[g].includes(section));
    assert.ok(group, `section "${section}" is in no nav group`);
    assert.equal(
      TABS[group],
      wantTab,
      `/${section} highlights #${TABS[group]}, expected #${wantTab}`
    );
  }
});

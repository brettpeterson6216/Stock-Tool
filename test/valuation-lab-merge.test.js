// Projection Lab and Valuation Lab were two rail entries sitting next to each
// other under Modeling. That put a methodology question in front of the reader
// before they had asked a valuation question — and for almost every company the
// honest answer is that you want both numbers. A multiple-based projection says
// what the market might pay in five years; a DCF says what the cash flows are
// worth today. When those two disagree, the gap is the analysis.
//
// They are one tool now: one rail entry, one section title, one launcher tile,
// and a segmented control inside that moves between the two panes. The section
// ids stay `projection` and `dcf` deliberately, so every deep link, every saved
// analysis type and both mount paths keep working untouched.
//
// This test exists because the split was easy to reintroduce: adding a rail item
// is one line, and nothing else in the codebase would have objected.
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");
const read = (...p) => fs.readFileSync(path.join(ROOT, ...p), "utf8");

const html = read("index.html");
const legacy = read("public", "app-legacy.js");
const navjs = read("public", "app-navigation.js");
const launch = read("public", "tool-launch.js");
const css = read("public", "research-premium.css");

test("the rail offers one Valuation Lab, not two labs", () => {
  // `dcf` stays in NAV_GROUPS on purpose: it is still a research section and
  // must still light the Research tab. What keeps it out of the rail is
  // RAIL_PANES, which renderSidebarGroup() filters on. Dropping it from the
  // group would also have hidden it, and would have broken the rule that
  // every section belongs to a group — nav-reachability.test.js catches that.
  assert.match(navjs, /const RAIL_PANES = \{[^}]*dcf:\s*'projection'/,
    "RAIL_PANES no longer declares dcf as a pane, so it draws its own rail entry again");
  assert.match(navjs, /it\.style\.display = \(items\.includes\(sec\) && !RAIL_PANES\[sec\]\)/,
    "renderSidebarGroup stopped filtering panes out of the rail");

  const modeling = navjs.match(/\['Modeling',\s*\[([^\]]*)\]\]/);
  assert.ok(modeling, "the Modeling subgroup not found");
  assert.doesNotMatch(modeling[1], /'dcf'/,
    "dcf is listed under Modeling again — two entries for one tool");
  assert.match(modeling[1], /'projection'/,
    "the Valuation Lab lost its rail entry entirely");
});

test("both panes carry the same title, so the header never changes tool on you", () => {
  const meta = legacy.match(/const SECTION_META = \{([\s\S]*?)\n\};/);
  assert.ok(meta, "SECTION_META not found");
  const titleOf = (sec) => {
    const m = meta[1].match(new RegExp(sec + ":\\s*\\{[^}]*title:\\s*'([^']+)'"));
    return m && m[1];
  };
  assert.equal(titleOf("projection"), "Valuation Lab");
  assert.equal(titleOf("dcf"), "Valuation Lab");
});

test("the rail stays lit on the pane that has no rail item of its own", () => {
  assert.match(legacy, /const LAB_PANES = \{[^}]*dcf:\s*'projection'/,
    "LAB_PANES no longer maps dcf back to the projection rail item");
  assert.match(legacy, /const railId = LAB_PANES\[id\] \|\| id;/,
    "openSection went back to matching data-sec against the raw id, so the whole rail goes dark on Intrinsic value");
  assert.match(legacy, /el\.dataset\.sec === railId/,
    "the active-state check no longer uses railId");
});

test("the switch is wired to the same entry point the rail uses", () => {
  assert.match(legacy, /function labMode\(which\)/, "labMode is gone");
  assert.match(legacy, /window\.labMode = labMode;/, "labMode is not exposed, so the inline onclick throws");
  // It must go through openSection, which is what runs the Pro gate, the mount
  // and the seed. A switch that only toggled CSS would show an unmounted pane.
  const fn = legacy.match(/function labMode\(which\)[\s\S]*?\n\}/)[0];
  assert.match(fn, /openSection\(which\)/, "labMode stopped calling openSection");
});

test("both panes render the switch, each marking its own side", () => {
  const panes = {
    projection: html.match(/id="sec-projection"[\s\S]*?<!-- \/sec-projection -->/),
    dcf: html.match(/id="sec-dcf"[\s\S]*?<!-- \/sec-dcf -->/),
  };
  for (const [name, m] of Object.entries(panes)) {
    assert.ok(m, `the ${name} section markup was not found`);
    const body = m[0];
    assert.match(body, /class="lab-modes"/, `the ${name} pane lost the method switch`);
    for (const mode of ["projection", "dcf"]) {
      assert.ok(body.includes(`labMode('${mode}')`), `the ${name} pane cannot reach ${mode}`);
    }
    // Exactly one segment is on, and it is this pane's own.
    const on = [...body.matchAll(/class="lab-mode is-on"[^>]*data-mode="([a-z]+)"/g)].map(x => x[1]);
    assert.deepEqual(on, [name], `the ${name} pane marks the wrong segment as current`);
  }
});

test("one launcher tile, on the dashboard and in the workspace", () => {
  const tools = launch.match(/var tools = \[([\s\S]*?)\];/);
  assert.ok(tools, "the launcher tile list was not found");
  assert.doesNotMatch(tools[1], /"dcf"/,
    "the workspace launcher offers the two labs separately again");

  const panel = html.match(/<div class="ihm-tools">([\s\S]*?)<\/div>\s*<\/section>/);
  assert.ok(panel, "the dashboard tool panel was not found");
  assert.doesNotMatch(panel[1], /section=dcf/,
    "the dashboard still sends people to a separate Valuation Lab tile");
  assert.match(panel[1], /section=projection/,
    "the dashboard lost its link into the lab");
});

test("the switch is styled, not left as two bare buttons", () => {
  assert.match(css, /\.lab-modes\s*\{/, ".lab-modes has no styles");
  assert.match(css, /\.lab-mode\.is-on\s*\{/, "the current segment is indistinguishable from the other one");
  // It must survive a phone: the pair is wider than a narrow column otherwise.
  assert.match(css, /@media \(max-width: 560px\)[\s\S]*?\.lab-mode \{[^}]*flex: 1/,
    "the switch does not stack or fill on a narrow screen");
});

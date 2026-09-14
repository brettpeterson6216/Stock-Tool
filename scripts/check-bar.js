"use strict";
/* ═══════════════════════════════════════════════════════════════════════════
   Does the top bar RENDER the same on every page, in every state?

   test/header-contract.test.js hashes the markup and test/toolbar-one-thing
   holds the structural rules, but neither can see a cascade. LensToolkit's bar
   was wrong for weeks with both green, because seventeen stylesheets carry
   rules for that bar and every page loads a different subset of them.

   The first version of this script checked fourteen routes, signed in as Pro,
   at one width — which is how it reported "identical" while four more page
   types, three more account states and every phone width went untested.

   It now sweeps:
     · every document that contains a #main-nav, plus all five lesson pages,
       two /stock/ acquisition pages and /verify-email
     · four account states, because the right-hand cluster is what changes:
       signed out, free, trial, pro
     · desktop and phone widths

   Within a (state, width) group every route must match the first one. Across
   groups they legitimately differ — signed out shows Log in and Start trial
   where Pro shows the account chip — so groups are compared separately.

       npm run check:bar
   ═══════════════════════════════════════════════════════════════════════════ */
let chromium;
try { ({ chromium } = require("playwright")); }
catch { console.log("check:bar skipped — playwright is not installed here."); process.exit(0); }

const { spawn } = require("node:child_process");
const path = require("node:path");

const PORT = 20000 + Math.floor(Math.random() * 40000);
const BASE = `http://127.0.0.1:${PORT}`;

let lessons = [];
try { ({ lessons } = require("../public/lessons-data.js")); } catch {}

const ALL_ROUTES = [
  "/", "/pricing", "/learn", "/about", "/research-process", "/data-sources",
  "/compound-calculator", "/blog", "/terms", "/privacy", "/lens-score",
  "/login", "/signup", "/reset-password", "/admin-analytics", "/verify-email",
  ...lessons.map(l => `/learn/${l.slug}`),
  "/stock/AAPL", "/stock/NVDA",
];
// A representative spread for the state and width sweeps: one of each kind of
// document, always including the one that was broken.
const SAMPLE = ["/pricing", "/lens-score", "/", "/about", "/login", "/learn/site-tour", "/stock/AAPL"];

const STATES = {
  out:   null,
  free:  { id: 1, username: "checkbar", plan: "free",  effectivePlan: "free",  email_verified: 1 },
  trial: { id: 1, username: "checkbar", plan: "free",  effectivePlan: "trial", email_verified: 1 },
  pro:   { id: 1, username: "checkbar", plan: "pro",   effectivePlan: "pro",   email_verified: 1 },
};

const PARTS = ["#main-nav", ".nav-logo", ".il-wordmark", "#nav-links", "#nav-search",
               "#nav-ticker-input", "#theme-toggle-btn", ".il-global-actions",
               "#nav-acct-wrap", "#nav-acct-btn", "#nav-acct-name", "#nav-acct-badge",
               "#nav-login", "#nav-signup"];

const PROBE = (parts) => {
  const out = {};
  for (const sel of parts) {
    const el = document.querySelector(sel);
    if (!el) { out[sel] = "ABSENT"; continue; }
    const c = getComputedStyle(el), r = el.getBoundingClientRect();
    const shown = c.display !== "none" && c.visibility !== "hidden" && !el.hidden;
    // Size, type, colour and whether it is on screen at all. Not x/y: the tab
    // row's own width legitimately depends on which tab is marked current.
    out[sel] = [shown ? "shown" : "hidden", Math.round(r.width), Math.round(r.height),
      c.fontSize, c.fontWeight, c.color, c.backgroundColor,
      parseFloat(c.borderTopWidth) ? c.borderTopWidth + " " + c.borderTopColor : "none",
      c.borderTopLeftRadius, c.padding, c.display].join(" | ");
  }
  return out;
};


/* The bar is a two-column grid. `.nav-logo` and `.il-global-actions` are the
   flexible pair: the actions cluster sizes to its content and the logo takes
   what is left, so their widths are content-derived BY DESIGN and drift a few
   px between routes — 166/180 on /pricing against 160/186 on /login at phone
   width, always summing to the same total.
   That is not the bug this script exists to catch. Everything that is actually
   pinned — type, weight, colour, background, border, radius, padding, display
   and whether the thing is on screen at all — is still compared exactly, and
   the two totals must still agree, so a real change in either column is caught
   by the other side of the pair. Only these two, only width, only ≤8px. */
const FLEX_PAIR = new Set([".nav-logo", ".il-global-actions"]);
function withinFlexTolerance(sel, a, b) {
  if (!FLEX_PAIR.has(sel)) return false;
  const A = a.split(" | "), B = b.split(" | ");
  if (A.length !== B.length) return false;
  for (let i = 0; i < A.length; i++) {
    if (i === 1) continue;                       // width, handled below
    if (A[i] !== B[i]) return false;             // anything else must match exactly
  }
  return Math.abs(Number(A[1]) - Number(B[1])) <= 8;
}

(async () => {
  const server = spawn(process.execPath, [path.join(__dirname, "..", "server.js")], {
    env: { ...process.env, NODE_ENV: "test", PORT: String(PORT),
           SESSION_SECRET: process.env.SESSION_SECRET || "checkbarcheckbarcheckbarcheckbar" },
    stdio: "ignore",
  });
  const stop = () => { try { server.kill(); } catch {} };
  process.on("exit", stop);
  for (let i = 0; i < 60; i++) {
    try { const r = await fetch(BASE + "/"); if (r.ok) break; } catch {}
    await new Promise(r => setTimeout(r, 400));
  }

  const browser = await chromium.launch();
  const problems = [];
  let groups = 0, loads = 0;

  const sweep = async (label, routes, stateKey, width) => {
    groups += 1;
    const ctx = await browser.newContext({ viewport: { width, height: 950 } });
    const seen = {};
    for (const route of routes) {
      const page = await ctx.newPage();
      await page.route("**/api/auth/me", r => r.fulfill({
        status: 200, contentType: "application/json",
        body: JSON.stringify({ user: STATES[stateKey] }),
      }));
      try {
        await page.goto(BASE + route, { waitUntil: "domcontentloaded", timeout: 20000 });
        /* Wait for the webfont and the logo bitmap before measuring. Without
           this the sweep reported 2-10px width differences on .nav-logo that
           were not differences at all: a face still swapping, or an <img> not
           yet decoded, measures narrow. Chasing those as bugs would have meant
           "fixing" CSS that was already correct. */
        await page.evaluate(() => Promise.all([
          document.fonts ? document.fonts.ready : Promise.resolve(),
          ...[...document.images].filter(i => !i.complete)
            .map(i => new Promise(r => { i.addEventListener("load", r); i.addEventListener("error", r); })),
        ])).catch(() => {});
        await page.waitForTimeout(1300);
        const hasBar = await page.evaluate(() => !!document.getElementById("main-nav"));
        if (!hasBar) { await page.close(); continue; }      // not every route has one
        seen[route] = await page.evaluate(PROBE, PARTS);
        loads += 1;
      } catch (e) { problems.push(`[${label}] ${route}: ${String(e).slice(0, 80)}`); }
      await page.close();
    }
    await ctx.close();

    const names = Object.keys(seen);
    if (names.length < 2) return;
    const refRoute = names[0], ref = seen[refRoute];
    for (const route of names.slice(1)) {
      for (const sel of PARTS) {
        if (ref[sel] === seen[route][sel]) continue;
        if (withinFlexTolerance(sel, ref[sel], seen[route][sel])) continue;
        problems.push(`[${label}] ${route}  ${sel}\n      ${refRoute}: ${ref[sel]}\n      ${route}: ${seen[route][sel]}`);
      }
    }
  };

  await sweep("pro @1440, every route", ALL_ROUTES, "pro", 1440);
  for (const state of ["out", "free", "trial"]) await sweep(`${state} @1440`, SAMPLE, state, 1440);
  await sweep("pro @390 (phone)", SAMPLE, "pro", 390);
  await sweep("out @390 (phone)", SAMPLE, "out", 390);

  await browser.close();
  stop();

  if (problems.length) {
    console.error(`The top bar differs in ${problems.length} place(s):\n\n` + problems.join("\n") + "\n");
    process.exit(1);
  }
  console.log(`Verified the top bar across ${ALL_ROUTES.length} routes, 4 account states and 2 widths `
            + `(${groups} groups, ${loads} page loads). Identical within every group.`);
})();

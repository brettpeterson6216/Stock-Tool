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

   Since November 2026 there is one bar, drawn by public/app/shell.js inside a
   shadow root (<il-top>), on the rebuilt app pages and the older pages alike.
   This sweep measures that bar from inside the shadow root, including its
   position on the page, and fails if any older page still shows #main-nav.

   It sweeps:
     · the app pages, every older document, all lesson pages,
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
  "/research", "/research/AAPL", "/screener", "/watchlist", "/compare",
];
// A representative spread for the state and width sweeps: one of each kind of
// document, always including the one that was broken.
const SAMPLE = ["/pricing", "/lens-score", "/", "/about", "/login", "/learn/site-tour", "/stock/AAPL", "/research", "/watchlist"];

const STATES = {
  out:   null,
  free:  { id: 1, username: "checkbar", plan: "free",  effectivePlan: "free",  email_verified: 1 },
  trial: { id: 1, username: "checkbar", plan: "free",  effectivePlan: "trial", email_verified: 1 },
  pro:   { id: 1, username: "checkbar", plan: "pro",   effectivePlan: "pro",   email_verified: 1 },
};

const PARTS = ["host", ".bar", ".in", ".brand", ".nav", ".search", ".box", "#il-q", ".acct",
               ".acct .gold", ".acct .ghost", ".plan", "#theme", "#avatar", "OLD #main-nav"];

const PROBE = (parts) => {
  const out = {};
  const host = document.querySelector("il-top");
  const root = host && host.shadowRoot;
  for (const sel of parts) {
    let el;
    if (sel === "host") el = host;
    else if (sel.startsWith("OLD ")) {
      el = document.querySelector(sel.slice(4));
      out[sel] = el && el.getClientRects().length ? "VISIBLE" : "retired";
      continue;
    } else el = root && root.querySelector(sel);
    if (!el) { out[sel] = "ABSENT"; continue; }
    const c = getComputedStyle(el), r = el.getBoundingClientRect();
    const shown = c.display !== "none" && c.visibility !== "hidden" && !el.hidden;
    // Position and size included: with one bar there is no excuse for it to
    // sit even a pixel differently from one page to the next.
    out[sel] = [shown ? "shown" : "hidden", Math.round(r.left), Math.round(r.top), Math.round(r.width), Math.round(r.height),
      c.fontFamily.split(",")[0], c.fontSize, c.fontWeight, c.color, c.backgroundColor,
      parseFloat(c.borderTopWidth) ? c.borderTopWidth + " " + c.borderTopColor : "none",
      c.borderTopLeftRadius, c.padding, c.display].join(" | ");
  }
  return out;
};

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
        const hasBar = await page.evaluate(() => !!document.querySelector("il-top"));
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

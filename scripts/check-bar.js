"use strict";
/* ═══════════════════════════════════════════════════════════════════════════
   Does the top bar RENDER the same on every page?

   test/header-contract.test.js hashes the markup and test/toolbar-one-thing
   holds the structural rules, but neither can see a cascade. LensToolkit's bar
   was wrong for weeks with both of those green, because seventeen stylesheets
   carry rules for that bar and every page loads a different subset of them.

   This boots the real server, loads every route in a real browser signed in as
   Pro, and compares the computed geometry, type and colour of each part of the
   bar against the first page. It is not in `npm test` because Playwright is not
   a dependency of this project; it skips cleanly when it is absent, so running
   it is always safe.

       npm run check:bar
   ═══════════════════════════════════════════════════════════════════════════ */
let chromium;
try { ({ chromium } = require("playwright")); }
catch { console.log("check:bar skipped — playwright is not installed here."); process.exit(0); }

const { spawn } = require("node:child_process");
const path = require("node:path");

const PORT = 20000 + Math.floor(Math.random() * 40000);
const BASE = `http://127.0.0.1:${PORT}`;
const PAGES = ["/", "/pricing", "/learn", "/learn/site-tour", "/about", "/research-process",
               "/data-sources", "/compound-calculator", "/blog", "/terms", "/privacy",
               "/lens-score", "/login", "/signup"];
const PARTS = ["#main-nav", ".nav-logo", ".il-wordmark", "#nav-links", "#nav-search",
               "#nav-ticker-input", "#theme-toggle-btn", ".il-global-actions",
               "#nav-acct-wrap", "#nav-acct-btn", "#nav-acct-name", "#nav-acct-badge"];

const PROBE = (parts) => {
  const out = {};
  for (const sel of parts) {
    const el = document.querySelector(sel);
    if (!el) { out[sel] = "ABSENT"; continue; }
    const c = getComputedStyle(el), r = el.getBoundingClientRect();
    // Size, type and colour. Not x/y: the tab row's own width legitimately
    // depends on which tab is marked current.
    out[sel] = [Math.round(r.width), Math.round(r.height), c.fontSize, c.fontWeight,
      c.color, c.backgroundColor,
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
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 950 } });
  const seen = {};
  for (const route of PAGES) {
    const page = await ctx.newPage();
    await page.route("**/api/auth/me", r => r.fulfill({
      status: 200, contentType: "application/json",
      body: JSON.stringify({ user: { id: 1, username: "checkbar", plan: "pro", effectivePlan: "pro", email_verified: 1 } }),
    }));
    try {
      await page.goto(BASE + route, { waitUntil: "domcontentloaded", timeout: 20000 });
      await page.waitForTimeout(2200);
      seen[route] = await page.evaluate(PROBE, PARTS);
    } catch (e) { seen[route] = { error: String(e).slice(0, 90) }; }
    await page.close();
  }
  await browser.close();
  stop();

  const refRoute = PAGES[1];
  const ref = seen[refRoute];
  const problems = [];
  for (const [route, got] of Object.entries(seen)) {
    if (route === refRoute) continue;
    if (got.error) { problems.push(`${route}: ${got.error}`); continue; }
    for (const sel of PARTS) {
      if (ref[sel] !== got[sel]) {
        problems.push(`${route}  ${sel}\n    ${refRoute}: ${ref[sel]}\n    ${route}: ${got[sel]}`);
      }
    }
  }
  if (problems.length) {
    console.error("The top bar renders differently on these pages:\n\n" + problems.join("\n") + "\n");
    process.exit(1);
  }
  console.log(`Verified the top bar renders identically on ${PAGES.length} routes.`);
})();

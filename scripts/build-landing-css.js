"use strict";
/* ═══════════════════════════════════════════════════════════════════════════
   The landing page's own stylesheet.

   The signed-out home page links the same 1.3MB stylesheet bundle as the old
   research app it shares index.html with. Most of those rules can never
   match anything on the landing page. This script keeps only the rules that
   can, judged in a real browser rather than guessed:

   1. Start the server, open "/" signed out with synthetic market data, at
      phone, tablet and desktop widths, in both themes, scrolled to the end
      so everything that draws on scroll has drawn, every <details> opened.
   2. A rule is kept when any of its selectors, with hover/focus/pseudo-element
      parts removed, matches an element on the page; or when every class and
      id it names appears in the landing page's scripts or on the page (so
      menus, dialogs and states that scripts add later keep their styles).
   3. Empty @media/@supports blocks are dropped. @keyframes, @font-face,
      @layer order and custom properties are kept as they are.

   The result is public/bundles/landing-lite.css. Its first line records the
   bundle it was cut from and that bundle's sha256; lib/home-lite.js only
   serves it while the hash still matches, and test/landing-css.test.js fails
   when it does not. So a stylesheet edit can never leave the landing page on
   stale styles: it falls back to the full bundle until this is run again.

   Dev only: needs Playwright (npm i -g playwright, or NODE_PATH to it).
     npm run build:styles && npm run build:landing-css
   ═══════════════════════════════════════════════════════════════════════════ */
const fs = require("node:fs");
const path = require("node:path");
const { spawn } = require("node:child_process");
const csstree = require("css-tree");
const { landingBundle, LITE_FILE, hashOf } = require("../lib/landing-css");
const fixtures = require("./landing-fixtures");

const ROOT = path.join(__dirname, "..");
const PORT = Number(process.env.LANDING_CSS_PORT || 4391);
const BASE = `http://127.0.0.1:${PORT}`;
const STATES = [[390, "dark"], [390, "light"], [820, "dark"], [1440, "dark"], [1440, "light"]];
/* The scripts the signed-out landing page loads. Class and id names they
   mention keep their rules even when nothing on the page has them yet. */
const LANDING_JS = ["landing-demo.js", "landing-market.js", "home-lite.js", "site-nav.js", "il-ribbon.js", "static-auth.js",
  "theme-bootstrap.js", "premium-motion.js", "app-navigation.js", "ticker-search.js", "il-icons.js", "app/shell.js"];
const DYNAMIC = /:(hover|focus|focus-visible|focus-within|active|visited|checked|disabled|enabled|indeterminate|placeholder-shown|target|empty|valid|invalid|default|autofill|-webkit-autofill|user-invalid|open|popover-open|modal)\b|::?(before|after|placeholder|selection|marker|backdrop|first-letter|first-line|-webkit-[\w-]+|-moz-[\w-]+|file-selector-button|part\([^)]*\))/g;

function playwright() {
  try { return require("playwright"); } catch (_) {
    console.error("Playwright is needed for this dev-only build: npm i -g playwright, then run with NODE_PATH=$(npm root -g).");
    process.exit(1);
  }
}

async function startServer() {
  const child = spawn(process.execPath, ["server.js"], {
    cwd: ROOT, stdio: ["ignore", "ignore", "pipe"],
    env: { ...process.env, PORT: String(PORT), NODE_ENV: "development", IL_LANDING_CSS: "full" },
  });
  let err = "";
  child.stderr.on("data", d => { err += d; });
  for (let i = 0; i < 80; i++) {
    try { const r = await fetch(BASE + "/healthz"); if (r.status < 500) return child; } catch (_) {}
    try { const r = await fetch(BASE + "/"); if (r.ok) return child; } catch (_) {}
    await new Promise(r => setTimeout(r, 250));
  }
  child.kill();
  throw new Error("The server did not start:\n" + err.slice(-2000));
}

async function usedSelectors(selectors) {
  const { chromium } = playwright();
  const browser = await chromium.launch();
  const used = new Set(), seen = new Set();
  try {
    for (const [width, theme] of STATES) {
      const ctx = await browser.newContext({ viewport: { width, height: 900 } });
      await ctx.addInitScript(t => { try { localStorage.setItem("il-theme", t); } catch (_) {} }, theme);
      const page = await ctx.newPage();
      await page.route("**/api/**", async r => {
        const u = new URL(r.request().url());
        const res = fixtures(u.pathname + u.search, null);
        await r.fulfill({ status: res.status, contentType: "application/json", body: JSON.stringify(res.body) });
      });
      await page.goto(BASE + "/", { waitUntil: "load" });
      await page.waitForTimeout(1500);
      for (let y = 0; y < 14000; y += 500) { await page.evaluate(yy => window.scrollTo(0, yy), y); await page.waitForTimeout(100); }
      await page.waitForTimeout(600);
      const res = await page.evaluate(([list, dyn]) => {
        const DYN = new RegExp(dyn, "g");
        document.querySelectorAll("details").forEach(d => { d.open = true; });
        const out = [], toks = new Set();
        document.querySelectorAll("*").forEach(el => { el.classList.forEach(c => toks.add(c)); if (el.id) toks.add(el.id); });
        for (const s of list) {
          const t = s.replace(DYN, "").replace(/:(where|is|not|has)\(\s*\)/g, "").trim() || "*";
          try { if (document.querySelector(t)) out.push(s); } catch (_) { out.push(s); } // unparseable here: keep
        }
        return { out, toks: [...toks] };
      }, [selectors, DYNAMIC.source]);
      res.out.forEach(s => used.add(s));
      res.toks.forEach(t => seen.add(t));
      await ctx.close();
    }
  } finally { await browser.close(); }
  return { used, seen };
}

(async () => {
  const bundle = landingBundle();
  if (!bundle) throw new Error("index.html has no stylesheet bundle. Run npm run build:styles first.");
  const src = fs.readFileSync(bundle.file, "utf8");
  const ast = csstree.parse(src, { parseValue: false, parseAtrulePrelude: false, parseRulePrelude: false, parseCustomProperty: false });
  const split = node => csstree.generate(node.prelude).split(/,(?![^()]*\))/).map(s => s.trim()).filter(Boolean);
  const inKeyframes = ctx => ctx.atrule && /keyframes$/i.test(ctx.atrule.name);

  const all = new Set();
  csstree.walk(ast, { visit: "Rule", enter(node) { if (!inKeyframes(this)) split(node).forEach(s => all.add(s)); } });

  const jsTokens = new Set(LANDING_JS.map(f => { try { return fs.readFileSync(path.join(ROOT, "public", f), "utf8"); } catch (_) { return ""; } })
    .join("\n").match(/[A-Za-z_][\w-]*/g));

  const server = await startServer();
  let judged;
  try { judged = await usedSelectors([...all]); } finally { server.kill(); }
  const { used, seen } = judged;
  const keep = s => used.has(s) || (() => {
    const names = (s.match(/[.#][A-Za-z_][\w-]*/g) || []).map(x => x.slice(1));
    return names.length > 0 && names.every(n => jsTokens.has(n) || seen.has(n));
  })();

  let before = 0, kept = 0;
  csstree.walk(ast, {
    visit: "Rule",
    enter(node, item, list) {
      if (inKeyframes(this)) return;
      before++;
      const parts = split(node), k = parts.filter(keep);
      if (!k.length) { list.remove(item); return csstree.walk.skip; }
      kept++;
      if (k.length < parts.length) node.prelude = { type: "Raw", value: k.join(",") };
      return csstree.walk.skip;
    },
  });
  for (let pass = 0; pass < 3; pass++) {
    csstree.walk(ast, { visit: "Atrule", leave(node, item, list) {
      if (list && node.block && node.block.children && node.block.children.isEmpty && /^(media|supports|container)$/i.test(node.name)) list.remove(item);
    } });
  }
  const css = `/* landing-lite from ${bundle.url} sha256=${hashOf(src)} | Generated by npm run build:landing-css; do not edit. */\n` + csstree.generate(ast) + "\n";
  fs.writeFileSync(LITE_FILE, css);
  console.log(`Landing stylesheet: kept ${kept} of ${before} rules, ${(src.length / 1024).toFixed(0)}KB to ${(css.length / 1024).toFixed(0)}KB.`);
})().catch(e => { console.error(e); process.exit(1); });

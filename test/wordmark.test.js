// The brand is ImpliedLens — one word. That was a deliberate decision, and the
// markup has always honoured it: a single span with no space in it,
//   <span class="il-wordmark">Implied<span class="il-wordmark-b">Lens</span></span>
//
// It rendered as "I M P L I E D   L E N S" anyway, on every page, for weeks.
// THREE rules were undoing it at paint time and not one of them mentions the
// brand:
//
//   lens-prime-shared.css:75  body .il-global-brand>span { text-transform: uppercase }
//   research-premium.css      #main-nav .il-wordmark     { letter-spacing: .1em }
//   clean-pass.css:22         .il-wordmark > .il-wordmark-b { margin-left: .34em }
//
// Uppercase removes the camel-case seam that is the ONLY thing making
// "ImpliedLens" readable as one word; .1em tracking pushes the halves apart;
// and the .34em margin is a literal 5px gap. Fixing any two of the three still
// rendered "Implied Lens" — which is how the first attempt at this fix was
// caught, by measuring the gap rather than reading the markup.
//
// So these assert the rendered intent, not the markup.
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");
const premium = fs.readFileSync(path.join(ROOT, "public", "research-premium.css"), "utf8");
const pages = ["index.html", ...fs.readdirSync(path.join(ROOT, "public"))
  .filter(f => f.endsWith(".html")).map(f => "public/" + f)];

test("the wordmark is one word in the markup, on every page", () => {
  const bad = [];
  for (const p of pages) {
    const html = fs.readFileSync(path.join(ROOT, p), "utf8");
    if (!html.includes("il-wordmark")) continue;
    if (!/Implied<span class="il-wordmark-b">Lens<\/span>/.test(html)) bad.push(p);
    if (/Implied\s+Lens/i.test(html)) bad.push(p + " (literal space)");
  }
  assert.deepEqual(bad, [], "these pages split the brand into two words");
});

/* The case-insensitive match above is the whole point of this test, and it was
   added late. The original was case-SENSITIVE, so it read past four
   <span>IMPLIED LENS</span> in the signed-in app shell -- the dashboard
   sidebar, the research sidebar, the mobile dashboard header and the mobile
   app bar -- for as long as they existed. They were invisible to every check
   because they only render once you sign in, and they were three different
   typefaces at three different sizes besides. */
test("the app shell's brand marks use the canonical wordmark", () => {
  const html = fs.readFileSync(path.join(ROOT, "index.html"), "utf8");
  for (const brand of ["prime-dash-brand", "prime-sidebar-brand", "prime-mobile-brand", "prime-mobile-appbar"]) {
    const region = html.slice(html.indexOf(brand), html.indexOf(brand) + 900);
    assert.match(
      region,
      /<span class="il-wordmark">Implied<span class="il-wordmark-b">Lens<\/span><\/span>/,
      `.${brand} does not use the canonical wordmark span`
    );
  }
  // And the premium layer has to undo lens-prime-shared's uppercase for them,
  // or the markup is one word and the render is two -- the original bug.
  for (const sel of [".prime-dash-brand .il-wordmark", ".prime-sidebar-brand .il-wordmark",
                     ".prime-mobile-brand .il-wordmark", ".prime-mobile-appbar a .il-wordmark"]) {
    assert.ok(premium.includes(sel), `${sel} is not covered by the premium wordmark rules`);
  }
  const block = premium.slice(premium.indexOf(".prime-dash-brand .il-wordmark"));
  assert.match(block.slice(0, 700), /text-transform: none !important/);
  assert.match(block.slice(0, 700), /font-family: "Plus Jakarta Sans", var\(--rp-sans\) !important/);
  /* Same weight as the nav renders, or the five marks do not match on screen. */
  assert.match(block.slice(0, 700), /font-weight: 600 !important/);
});

test("nothing uppercases the wordmark back into two words", () => {
  // The premium layer is the last word on this site (build-styles.js declares
  // `premium` before `heritage`, which inverts !important order). So the reset
  // has to live here, and it has to be explicit.
  const rule = premium.match(/#main-nav \.il-wordmark,[^{]*\{([^}]*)\}/);
  assert.ok(rule, "the wordmark has no rule in the premium layer, so lens-prime-shared wins");
  assert.match(rule[1], /text-transform:\s*none\s*!important/,
    "the uppercase from lens-prime-shared.css is not reset — the brand renders as IMPLIED LENS");

  const ls = rule[1].match(/letter-spacing:\s*(-?[\d.]+)em/);
  assert.ok(ls, "the wordmark sets no letter-spacing, so it inherits tracking meant for eyebrow labels");
  assert.ok(parseFloat(ls[1]) <= 0.01,
    `wordmark tracking is ${ls[1]}em; anything loose pulls "Implied" and "Lens" apart into two words`);
});

test("the accent half stays gold and italic, and stays attached", () => {
  const accent = premium.match(/#main-nav \.il-wordmark-b, #main-nav \.il-wordmark em,[\s\S]*?\{([^}]*)\}/);
  assert.ok(accent, "the gold italic accent has no rule in the premium layer");
  assert.match(accent[1], /font-style:\s*italic\s*!important/, "the accent is no longer italic");
  assert.match(accent[1], /color:\s*var\(--rp-gold\)\s*!important/, "the accent is no longer gold");
  /* The third rule, and the one that survived fixing the other two: a 5px gap
     at nav size reads as a word break even with the uppercase gone. */
  assert.match(accent[1], /margin-left:\s*0\s*!important/,
    "the .34em gap from clean-pass.css is back — the brand renders as two words");
  assert.match(premium, /\.il-global-brand em/,
    "the `em` spelling of the accent is uncovered, so lens-prime-shared flattens it wherever it is used");
});

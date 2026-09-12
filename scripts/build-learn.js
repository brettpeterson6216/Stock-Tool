/* Generates the public Learn pages from public/lessons-data.js.

   The lessons used to exist only inside the application, behind
   /?view=tool&section=education — a query string, not a URL. Nothing could
   link to a lesson, no search engine could index one, and reading any of it
   meant loading the whole app first. For the part of the site meant to bring
   people IN, it was the least reachable thing on it.

   These are generated as real files rather than rendered per request for the
   same reason the other static pages are files: they go through
   lib/asset-stamp.js like everything else, the header stays byte-identical to
   every other page (test/header-contract.test.js hashes it), and there is no
   template engine to keep in sync with a shell that changes.

   Run:  npm run build:learn
   Check: npm run check:learn
*/
"use strict";

const fs = require("fs");
const path = require("path");

const ROOT = path.join(__dirname, "..");
const P = (...p) => path.join(ROOT, ...p);
const CHECK = process.argv.includes("--check");
const { lessons } = require(P("public", "lessons-data.js"));

const esc = (s) => String(s)
  .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

/* The shell comes from a page that already exists, so the header cannot drift.
   Everything between the nav and the footer is ours. */
const donor = fs.readFileSync(P("public", "about.html"), "utf8");
const HEAD = donor.slice(0, donor.indexOf('<aside class="static-rail"'));
const TAIL = donor.slice(donor.indexOf("  <footer>"));

function head(title, description, canonical) {
  return HEAD
    .replace(/<title>[^<]*<\/title>/, `<title>${esc(title)}</title>`)
    .replace(/(<meta name="description" content=")[^"]*(">)/, `$1${esc(description)}$2`)
    .replace(/(<meta property="og:title" content=")[^"]*(">)/, `$1${esc(title)}$2`)
    .replace(/(<meta name="twitter:title" content=")[^"]*(">)/, `$1${esc(title)}$2`)
    .replace(/(<meta property="og:description" content=")[^"]*(">)/, `$1${esc(description)}$2`)
    .replace(/(<meta name="twitter:description" content=")[^"]*(">)/, `$1${esc(description)}$2`)
    .replace(/https:\/\/impliedlens\.com\/about/g, `https://impliedlens.com${canonical}`);
}

function rail(active) {
  const rows = lessons.map(l =>
    `  <a href="/learn/${l.slug}"${l.slug === active ? ' class="active"' : ""}>${esc(l.title.split(":")[0])}</a>`
  ).join("\n");
  return `<aside class="static-rail" aria-label="Lessons">\n`
    + `  <div class="static-rail-label">Learn</div>\n`
    + `  <a href="/learn"${active ? "" : ' class="active"'}>All lessons</a>\n${rows}\n</aside>\n`;
}

function indexPage() {
  const groups = [];
  for (const l of lessons) {
    let g = groups.find(x => x.name === l.group);
    if (!g) groups.push(g = { name: l.group, items: [] });
    g.items.push(l);
  }
  const sections = groups.map(g => `
    <h2>${esc(g.name)}</h2>
    <ul class="learn-list">
${g.items.map(l => `      <li><a href="/learn/${l.slug}"><strong>${esc(l.title)}</strong>`
      + `<span>${esc(l.summary)}</span>`
      + `<em>${l.minutes} min read</em></a></li>`).join("\n")}
    </ul>`).join("\n");

  return head("Learn — ImpliedLens",
      "Free lessons on reading charts, financial statements and valuation, and on building a stock thesis you can check later.",
      "/learn")
    + rail(null)
    + `
  <div class="hero" id="learn-main" role="main">
    <div class="tagline">Free. All of it.</div>
    <h1>Learn to research a company <em>properly</em>.</h1>
    <p class="hero-sub">Short, plain lessons on reading a chart, reading a filing, valuing a business and writing down a thesis you can check later. No account needed, nothing held back for subscribers.</p>
  </div>

  <div class="prose">
${sections}

    <h2>Glossary</h2>
    <p>Every term the tool uses, defined in one place: <a href="/?view=tool&amp;section=education">open the glossary</a>.</p>

    <div class="cta-row" style="margin-top:2rem;">
      <a href="/learn/${lessons[0].slug}" class="btn-primary">Start with the first lesson →</a>
      <a href="/signup" class="btn-ghost">Create a free account</a>
    </div>
  </div>

`
    + TAIL;
}

function lessonPage(l, i) {
  const prev = lessons[i - 1], next = lessons[i + 1];
  const nav = [
    prev ? `<a href="/learn/${prev.slug}">← ${esc(prev.title)}</a>` : "",
    next ? `<a href="/learn/${next.slug}">${esc(next.title)} →</a>` : "",
  ].filter(Boolean).join("\n      ");

  return head(`${l.title} — ImpliedLens`, l.summary, `/learn/${l.slug}`)
    + rail(l.slug)
    + `
  <div class="hero" id="lesson-main" role="main">
    <div class="tagline">${esc(l.group)} · ${l.minutes} min read</div>
    <h1>${esc(l.title)}</h1>
    <p class="hero-sub">${esc(l.summary)}</p>
  </div>

  <div class="prose">
    <p>${esc(l.opening)}</p>
    <p>${esc(l.body)}</p>

    <h2>What to look at</h2>
    <ul>
${l.points.map(p => `      <li>${esc(p)}</li>`).join("\n")}
    </ul>

    <h2>The shape of it</h2>
    <p class="learn-formula"><code>${esc(l.formula)}</code></p>

    <h2>An example</h2>
    <p>${esc(l.example)}</p>

    <h2>Where people go wrong</h2>
    <p class="learn-warning">${esc(l.warning)}</p>

    <p>${esc(l.closing)}</p>

    <div class="cta-row" style="margin-top:2rem;">
      <a href="/?view=tool&amp;section=${encodeURIComponent(l.tool)}" class="btn-primary">${esc(l.toolLabel)} →</a>
      <a href="/learn" class="btn-ghost">All lessons</a>
    </div>

    <nav class="learn-seq" aria-label="Lessons">
      ${nav}
    </nav>
  </div>

`
    + TAIL;
}

const written = [];
function emit(rel, html) {
  const file = P("public", rel);
  if (CHECK) {
    const cur = fs.existsSync(file) ? fs.readFileSync(file, "utf8") : null;
    if (cur === null || cur.replace(/\r\n/g, "\n") !== html.replace(/\r\n/g, "\n")) {
      throw new Error(`Learn pages are out of date: public/${rel}. Run npm run build:learn.`);
    }
  } else {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, html);
  }
  written.push(rel);
}

emit("learn.html", indexPage());
lessons.forEach((l, i) => emit(path.join("learn", `${l.slug}.html`), lessonPage(l, i)));
console.log(`${CHECK ? "Verified" : "Built"} ${written.length} Learn pages from public/lessons-data.js`);

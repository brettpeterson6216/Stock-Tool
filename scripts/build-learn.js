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

const LEVEL_BLURB = {
  1: "What a stock is, how trading works, and how much risk to take.",
  2: "Read the three financial statements and judge business quality.",
  3: "Multiples, discounted cash flow, and what the price already assumes.",
  4: "Trends, support and resistance, indicators, and LensScore.",
  5: "Earnings season, writing a thesis, running a portfolio, and avoiding the classic mistakes.",
};
const PROGRESS_SCRIPT = `  <script defer src="/learn-progress.js?v=20261001-1"></script>\n`;

function levels() {
  const out = [];
  for (const l of lessons) {
    let g = out.find(x => x.level === l.level);
    if (!g) out.push(g = { level: l.level, name: l.group, items: [] });
    g.items.push(l);
  }
  return out;
}

function indexPage() {
  const total = lessons.length;
  const minutes = lessons.reduce((a, l) => a + l.minutes, 0);
  const sections = levels().map(g => `
    <section class="lxl-level" aria-labelledby="lxl-level-${g.level}">
      <header class="lxl-level-head">
        <span class="lxl-level-num">${g.level}</span>
        <div>
          <h2 id="lxl-level-${g.level}">${esc(g.name.replace(/^Level \d+ · /, ""))}</h2>
          <p>${esc(LEVEL_BLURB[g.level] || "")}</p>
        </div>
        <span class="lxl-level-count" data-level-count="${g.level}">${g.items.length} lessons</span>
      </header>
      <ol class="lxl-list">
${g.items.map(l => `        <li><a href="/learn/${l.slug}" data-lesson="${l.slug}">`
      + `<span class="lxl-check" aria-hidden="true"></span>`
      + `<span class="lxl-text"><strong>${esc(l.title)}</strong><span>${esc(l.summary)}</span></span>`
      + `<em>${l.minutes} min</em></a></li>`).join("\n")}
      </ol>
    </section>`).join("\n");
  return head("Learn to invest — free stock market course | ImpliedLens",
      "A free, structured course from your first stock to building a valuation: financial statements, valuation, charts, earnings and portfolio process, with quizzes.",
      "/learn")
    + rail(null)
    + `
  <main class="lxl" id="learn-main">
    <header class="lxl-hero">
      <span class="lxl-kicker">ImpliedLens Academy · Free</span>
      <h1>From your first stock to a <em>professional process</em>.</h1>
      <p>${total} short lessons in five levels, about ${Math.round(minutes / 5) * 5} minutes in total. Each one ends with a quick quiz and an exercise on a real company. No account needed, nothing held back for subscribers.</p>
      <div class="lxl-progress" id="lxl-progress" data-total="${total}" hidden>
        <div class="lxl-progress-bar"><i id="lxl-progress-fill"></i></div>
        <span id="lxl-progress-label">0 of ${total} complete</span>
      </div>
      <div class="lxl-hero-actions">
        <a href="/learn/${lessons[0].slug}" class="lxl-btn lxl-btn-gold" id="lxl-continue">Start lesson 1 →</a>
        <a href="/signup?source=learn_index" class="lxl-btn lxl-btn-ghost">Create a free account</a>
      </div>
    </header>
${sections}
    <aside class="lxl-cta">
      <div>
        <h2>Practise on real companies</h2>
        <p>Every lesson links to the tool it teaches. A free account gives you ${"{{FREE_DAILY_LIMIT}}"} analyses a day, SEC financial statements and watchlists.</p>
      </div>
      <a href="/signup?source=learn_index_cta" class="lxl-btn lxl-btn-gold">Create free account</a>
    </aside>
  </main>
`
    + PROGRESS_SCRIPT
    + TAIL;
}

function quizHtml(l) {
  if (!Array.isArray(l.quiz) || !l.quiz.length) return "";
  return `
    <section class="lxl-quiz" aria-labelledby="lxl-quiz-title">
      <h2 id="lxl-quiz-title">Check your understanding</h2>
${l.quiz.map((q, i) => `      <div class="lxl-q" data-answer="${q.answer}">
        <p class="lxl-q-text"><b>${i + 1}.</b> ${esc(q.q)}</p>
        <ol class="lxl-opts" type="A">
${q.options.map((o, j) => `          <li><button type="button" data-opt="${j}">${esc(o)}</button></li>`).join("\n")}
        </ol>
        <details class="lxl-why"><summary>Show answer</summary><p><b>${esc(q.options[q.answer])}.</b> ${esc(q.why)}</p></details>
      </div>`).join("\n")}
    </section>`;
}

function lessonPage(l, i) {
  const prev = lessons[i - 1], next = lessons[i + 1];
  const nav = [
    prev ? `<a href="/learn/${prev.slug}" class="lxl-prev"><span>Previous</span>${esc(prev.title)}</a>` : "<span></span>",
    next ? `<a href="/learn/${next.slug}" class="lxl-next"><span>Next</span>${esc(next.title)}</a>` : `<a href="/learn" class="lxl-next"><span>Finished</span>Back to all lessons</a>`,
  ].join("\n      ");
  return head(`${l.title} — ImpliedLens`, l.summary, `/learn/${l.slug}`)
    + rail(l.slug)
    + `
  <main class="lxl lxl-lesson" id="lesson-main" data-lesson="${l.slug}" data-index="${i + 1}" data-total="${lessons.length}">
    <header class="lxl-hero">
      <a class="lxl-crumb" href="/learn">Academy</a>
      <span class="lxl-kicker">${esc(l.group)} · Lesson ${i + 1} of ${lessons.length} · ${l.minutes} min</span>
      <h1>${esc(l.title)}</h1>
      <p>${esc(l.summary)}</p>
    </header>
    <article class="prose lxl-body">
    <p class="lxl-lede">${esc(l.opening)}</p>
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
    </article>
${quizHtml(l)}
    <section class="lxl-try" aria-labelledby="lxl-try-title">
      <h2 id="lxl-try-title">Try it now</h2>
      <p>${esc(l.tryIt)}</p>
      <div class="lxl-try-actions">
        <a href="/?view=tool&amp;section=${encodeURIComponent(l.tool)}" class="lxl-btn lxl-btn-gold">${esc(l.toolLabel)} →</a>
        <button type="button" class="lxl-btn lxl-btn-ghost" id="lxl-complete" hidden>Mark lesson complete</button>
      </div>
    </section>
    <nav class="lxl-seq" aria-label="Lessons">
      ${nav}
    </nav>
  </main>
`
    + PROGRESS_SCRIPT
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

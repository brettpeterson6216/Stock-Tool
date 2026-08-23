/* Subset the Tabler icon stylesheet to the icons this site actually uses.
 *
 * The shipped sheet defines 5,193 icon classes at 211KB. ImpliedLens uses 121
 * of them, all as literal class names in markup (no dynamic `'ti-' + name`
 * construction — checked), so a subset is safe.
 *
 * Everything that is not an .ti-<name>::before rule is preserved verbatim:
 * the @font-face, the base .ti sizing/rendering rules, and any modifier
 * classes. Only per-icon glyph rules are filtered.
 */
const fs = require('fs');

const CSS = require('path').join(__dirname,'..','public','vendor','tabler-icons.min.css');
const used = new Set(require('child_process').execSync("grep -rhoE '\\bti-[a-z0-9-]+' index.html public/*.html public/*.js labs/lens-score/*.html labs/lens-score/*.js 2>/dev/null | sort -u", {cwd: require('path').join(__dirname,'..'), encoding:'utf8'}).split('\n').map(s => s.trim()).filter(Boolean));

const src = fs.readFileSync(CSS, 'utf8');

// Split into top-level rules. The file is minified: `selector{decls}` repeated.
const rules = src.match(/[^{}]+\{[^{}]*\}/g) || [];
const kept = [];
let dropped = 0, keptIcons = 0;

for (const rule of rules) {
  const sel = rule.slice(0, rule.indexOf('{')).trim();
  // A per-icon glyph rule looks like `.ti-foo:before` (possibly a comma list).
  const iconNames = sel.match(/\.ti-[a-z0-9-]+(?=:{1,2}before\b|,|$)/g);
  const isIconRule = /^\s*\.ti-[a-z0-9-]+\s*:{1,2}before/.test(sel) ||
                     (iconNames && iconNames.length && /:{1,2}before/.test(sel));
  if (!isIconRule) { kept.push(rule); continue; }

  // Keep the rule if ANY selector in its list is an icon we use, narrowing the
  // selector list to just those.
  const parts = sel.split(',').map(s => s.trim());
  const keepParts = parts.filter(pt => {
    const m = pt.match(/\.ti-([a-z0-9-]+)/);
    return m && used.has('ti-' + m[1]);
  });
  if (keepParts.length) {
    kept.push(keepParts.join(',') + rule.slice(rule.indexOf('{')));
    keptIcons += keepParts.length;
  } else dropped++;
}

/* Three names used in markup have no glyph in this sheet — they are "filled"
   variants that live in a separate Tabler stylesheet we do not ship, plus one
   that simply does not exist. They have been rendering as blank boxes in
   production. Alias each onto the nearest glyph that does exist, so the fix
   applies everywhere the class appears without editing markup or JS. */
const ALIASES = {
  'ti-star-filled':         '\\eb2e',  // star
  'ti-circle-check-filled': '\\ea67',  // circle-check
  'ti-database-check':      '\\ea88'   // database
};
let aliasCss = '';
for (const [cls, cp] of Object.entries(ALIASES)) {
  if (used.has(cls)) aliasCss += `.${cls}:before{content:"${cp}"}`;
}

// Preserve the leading license comment.
const banner = (src.match(/^\/\*![\s\S]*?\*\//) || [''])[0];
const out = banner +
  '\n/* Subset for ImpliedLens: ' + keptIcons + ' of ' + (keptIcons + dropped) +
  ' icon glyphs. Regenerate with scripts/subset-icons.js after adding icons. */\n' +
  kept.join('') + aliasCss;

fs.writeFileSync(CSS, out);
console.log('icons kept   :', keptIcons);
console.log('icons dropped:', dropped);
console.log('before       :', (src.length / 1024).toFixed(0) + ' KB');
console.log('after        :', (out.length / 1024).toFixed(0) + ' KB');

// Report any used icon that the sheet did not define — a typo would silently
// render as a blank box, which is exactly the class of bug we just fixed.
const defined = new Set((out.match(/\.ti-[a-z0-9-]+(?=:{1,2}before)/g) || []).map(s => s.slice(1)));
const missing = [...used].filter(u => !defined.has(u) && u !== 'ti-');
if (missing.length) console.log('WARNING — used but undefined:', missing.join(', '));
else console.log('every used icon is defined ✓');

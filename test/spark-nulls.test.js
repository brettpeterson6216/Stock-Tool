// The guest page's hero chart, and the conversion that has now produced the
// same broken chart three times in this codebase.
//
//   Number(null) === 0, and 0 passes Number.isFinite
//
// so `values.map(Number).filter(Number.isFinite)` keeps every missing bar as
// a price of zero. On a normalised chart each one drops the line to the floor
// and back — the flat-then-cliff shape that was reported against the market
// chart, and the sawtooth the hero chart drew when handed the same data.
//
// This test runs the function's ACTUAL SHIPPED SOURCE, lifted out of
// public/landing-market.js by brace matching, rather than a copy of it — a
// copy would keep passing after the file changed.
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

function lift(file, name) {
  const src = fs.readFileSync(path.join(__dirname, "..", file), "utf8");
  const start = src.indexOf("function " + name + "(");
  assert.notEqual(start, -1, `${name} is no longer defined in ${file}`);
  const open = src.indexOf("{", start);
  let depth = 0, end = open;
  for (; end < src.length; end += 1) {
    if (src[end] === "{") depth += 1;
    else if (src[end] === "}") { depth -= 1; if (!depth) { end += 1; break; } }
  }
  // eslint-disable-next-line no-new-func
  return new Function(`${src.slice(start, end)}; return ${name};`)();
}

const sparkPath = lift("public/landing-market.js", "sparkPath");

// Every y in "M12.00 40.00 L..." — the shape the chart actually draws.
const ys = d => (d.match(/-?\d+\.\d+(?= |$)/g) || []).map(Number).filter((_, i) => i % 2 === 1);

test("a null close is dropped, not drawn as a price of zero", () => {
  const clean = [100, 101, 102, 103, 104, 105];
  const holed = [100, 101, null, 103, 104, 105];

  const a = ys(sparkPath(clean.filter(v => v !== null), 260, 62));
  const b = ys(sparkPath(holed, 260, 62));

  assert.equal(b.length, 5, "the null should be dropped, leaving five points");
  // Same five prices in, same five heights out: the hole changed nothing but
  // the point count.
  assert.deepEqual(b, ys(sparkPath([100, 101, 103, 104, 105], 260, 62)));
  assert.ok(a.length > 0);
});

test("a hole does not put a cliff in a line that only rises", () => {
  // Measuring the spread is not enough: with a zero in the set the spread is
  // huge — that IS the cliff. The shape is the assertion. Prices that only
  // rise must produce y values that only fall, with no spike to the floor.
  const heights = ys(sparkPath([100, 101, null, 103, 104, 105], 260, 62));
  for (let i = 1; i < heights.length; i += 1) {
    assert.ok(heights[i] <= heights[i - 1],
      `prices only rise, so y must only fall; got ${heights.join(", ")}`);
  }
  // And the real prices still use the box rather than compressing into its
  // top few pixels, which is what a phantom zero at the bottom would do.
  const spread = Math.max(...heights) - Math.min(...heights);
  assert.ok(spread > 40,
    `five prices should use most of a 62px box; got ${spread.toFixed(1)}px`);
});

test("undefined, empty string and non-positive prices are all rejected", () => {
  for (const bad of [undefined, "", 0, -4, NaN, "abc"]) {
    const heights = ys(sparkPath([100, bad, 102], 260, 62));
    assert.equal(heights.length, 2, `${String(bad)} should not become a point`);
  }
});

test("a clean series is untouched", () => {
  const d = sparkPath([10, 20, 30], 100, 50);
  assert.ok(d.startsWith("M"), "still draws a path");
  assert.equal(ys(d).length, 3);
});
